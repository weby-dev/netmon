// SPDX-License-Identifier: GPL-2.0
#include "security_engine.h"
#include "config.h"
#include "net_util.h"
#include <functional>
#include <cmath>

namespace netmon {

const char* severity_name(Severity s) {
    switch (s) {
    case Severity::Critical: return "critical";
    case Severity::High:     return "high";
    case Severity::Medium:   return "medium";
    case Severity::Low:      return "low";
    default:                 return "info";
    }
}

SecurityEngine::SecurityEngine(const Config& cfg) : cfg_(cfg) {}

bool SecurityEngine::is_suspicious_port(uint16_t port) {
    // Ports commonly associated with backdoors / RATs / mining / abused svcs.
    switch (port) {
    case 23:     // telnet
    case 445:    // SMB (worm vector)
    case 1080:   // socks
    case 3389:   // RDP exposed
    case 4444:   // metasploit default
    case 5555:   // adb / misc
    case 6667:   // IRC C2
    case 9001:   // tor
    case 31337:  // elite backdoor
    case 23231:
        return true;
    default:
        return false;
    }
}

bool SecurityEngine::should_emit(const std::string& key, uint64_t now, uint64_t cooldown) {
    auto it = last_alert_.find(key);
    if (it != last_alert_.end() && now - it->second < cooldown)
        return false;
    last_alert_[key] = now;
    return true;
}

static uint64_t hash_ip(const std::string& ip) {
    return std::hash<std::string>{}(ip);
}

std::vector<SecurityEvent>
SecurityEngine::analyze(const std::vector<FlowSample>& flows,
                        double interval_sec, uint64_t now_unix) {
    std::vector<SecurityEvent> out;
    if (interval_sec <= 0) interval_sec = 1;

    const uint64_t window = (uint64_t)cfg_.security_window;

    // Reset windows that have aged out.
    for (auto it = src_.begin(); it != src_.end(); ) {
        if (now_unix - it->second.window_start >= window) it = src_.erase(it);
        else ++it;
    }
    for (auto it = dst_.begin(); it != dst_.end(); ) {
        if (now_unix - it->second.window_start >= window) it = dst_.erase(it);
        else ++it;
    }

    // Accumulate this interval into the rolling windows.
    for (const auto& f : flows) {
        if (f.d_packets == 0 && !f.is_new) continue;

        auto& s = src_[f.src_ip];
        if (s.window_start == 0) s.window_start = now_unix;
        uint16_t dport = f.dst_port;
        uint32_t pcompact = (uint32_t)((hash_ip(f.dst_ip) & 0xFFFF) << 16 | dport);
        s.dst_ports.insert(pcompact);
        s.dst_hosts.insert(hash_ip(f.dst_ip));
        s.syn_total += f.stats.syn_count;   // absolute is fine for window-ish
        s.bytes_total += f.d_bytes;

        auto& d = dst_[f.dst_ip];
        if (d.window_start == 0) d.window_start = now_unix;
        d.packets += f.d_packets;
        d.bytes += f.d_bytes;
        d.syns += f.stats.syn_count;
        d.src_hosts.insert(hash_ip(f.src_ip));

        // --- Per-flow heuristics (immediate) ---------------------------- //

        // Suspicious destination port from an internal host -> external.
        if (f.is_new && is_suspicious_port(f.dst_port) &&
            f.src_internal && !f.dst_internal) {
            std::string k = "suspport:" + f.src_ip + ":" + f.dst_ip + ":" +
                            std::to_string(f.dst_port);
            if (should_emit(k, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::Medium;
                e.category = "suspicious_conn";
                e.src_ip = f.src_ip; e.dst_ip = f.dst_ip;
                e.dst_port = f.dst_port; e.proto = f.proto;
                e.detail = "internal host connecting out on suspicious port " +
                           std::to_string(f.dst_port);
                out.push_back(std::move(e));
            }
        }

        // Possible data exfiltration: large internal->external transfer.
        if (f.src_internal && !f.dst_internal && f.d_bytes > 50ull * 1024 * 1024) {
            std::string k = "exfil:" + f.src_ip + ":" + f.dst_ip;
            if (should_emit(k, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::Medium;
                e.category = "anomaly";
                e.src_ip = f.src_ip; e.dst_ip = f.dst_ip;
                e.dst_port = f.dst_port; e.proto = f.proto;
                e.metric = f.d_bytes;
                e.detail = "large outbound transfer (" +
                           std::to_string(f.d_bytes / (1024 * 1024)) + " MiB) this interval";
                out.push_back(std::move(e));
            }
        }
    }

    // --- Window-level detections ---------------------------------------- //

    // Port scan: one src touching many distinct dst ports.
    for (auto& [ip, s] : src_) {
        if (s.dst_ports.size() >= cfg_.scan_port_threshold) {
            if (should_emit("portscan:" + ip, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::High;
                e.category = "port_scan"; e.src_ip = ip;
                e.metric = s.dst_ports.size();
                e.threshold = cfg_.scan_port_threshold;
                e.detail = "source probed " + std::to_string(s.dst_ports.size()) +
                           " distinct ports in " + std::to_string(window) + "s window";
                out.push_back(std::move(e));
            }
        }
        // Host sweep: one src touching many distinct hosts.
        if (s.dst_hosts.size() >= cfg_.scan_host_threshold) {
            if (should_emit("sweep:" + ip, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::High;
                e.category = "host_sweep"; e.src_ip = ip;
                e.metric = s.dst_hosts.size();
                e.threshold = cfg_.scan_host_threshold;
                e.detail = "source contacted " + std::to_string(s.dst_hosts.size()) +
                           " distinct hosts in " + std::to_string(window) + "s window";
                out.push_back(std::move(e));
            }
        }
    }

    // DDoS / volumetric: high pps or SYN rate toward one destination.
    for (auto& [ip, d] : dst_) {
        double age = std::max(1.0, (double)(now_unix - d.window_start));
        uint64_t pps = (uint64_t)(d.packets / age);
        uint64_t sps = (uint64_t)(d.syns / age);

        if (pps >= cfg_.ddos_pps_threshold) {
            if (should_emit("ddos_pps:" + ip, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::Critical;
                e.category = "ddos"; e.dst_ip = ip;
                e.metric = pps; e.threshold = cfg_.ddos_pps_threshold;
                e.detail = "volumetric flood: " + std::to_string(pps) +
                           " pps from " + std::to_string(d.src_hosts.size()) +
                           " sources";
                out.push_back(std::move(e));
            }
        }
        if (sps >= cfg_.ddos_syn_threshold) {
            if (should_emit("ddos_syn:" + ip, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::Critical;
                e.category = "ddos"; e.dst_ip = ip;
                e.metric = sps; e.threshold = cfg_.ddos_syn_threshold;
                e.detail = "SYN flood: " + std::to_string(sps) + " SYN/s toward host";
                out.push_back(std::move(e));
            }
        }
    }

    return out;
}

} // namespace netmon
