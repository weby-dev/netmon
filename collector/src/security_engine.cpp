// SPDX-License-Identifier: GPL-2.0
#include "security_engine.h"
#include "config.h"
#include "net_util.h"
#include <functional>
#include <algorithm>
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

// Login/credential-bearing services targeted by brute force / stuffing.
bool SecurityEngine::is_service_port(uint16_t port) {
    switch (port) {
    case 21:    // FTP
    case 22:    // SSH
    case 23:    // telnet
    case 25: case 587: case 110: case 143: case 993: case 995:  // mail
    case 389: case 636:   // LDAP
    case 445:   // SMB
    case 1433:  // MSSQL
    case 3306:  // MySQL
    case 3389:  // RDP
    case 5432:  // PostgreSQL
    case 5900:  // VNC
    case 5985: case 5986: // WinRM
    case 6379:  // Redis
    case 27017: // MongoDB
        return true;
    default:
        return false;
    }
}

// Remote-administration ports whose internal fan-out signals lateral movement.
bool SecurityEngine::is_admin_port(uint16_t port) {
    switch (port) {
    case 22:    // SSH
    case 23:    // telnet
    case 135: case 139: case 445:   // RPC / NetBIOS / SMB
    case 1433: case 3306:           // DB admin
    case 3389:                      // RDP
    case 5900:                      // VNC
    case 5985: case 5986:           // WinRM
        return true;
    default:
        return false;
    }
}

// Common crypto-mining pool / stratum ports.
bool SecurityEngine::is_mining_port(uint16_t port) {
    switch (port) {
    case 3032: case 3333: case 4444: case 5555: case 7777:
    case 8333: case 9999: case 14444: case 45560:
        return true;
    default:
        return false;
    }
}

// UDP services abused as reflection/amplification sources (seen as src_port
// on inbound traffic toward a victim).
bool SecurityEngine::is_amp_port(uint16_t port) {
    switch (port) {
    case 19:    // chargen
    case 53:    // DNS
    case 111:   // portmap
    case 123:   // NTP
    case 137:   // NetBIOS
    case 161:   // SNMP
    case 389:   // CLDAP
    case 1900:  // SSDP
    case 11211: // memcached
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

// Mix a destination-host hash with a port into one 64-bit key so distinct
// (host, port) pairs are counted without the truncation collisions of the old
// 16-bit packing.
static inline uint64_t host_port_key(uint64_t host_hash, uint16_t port) {
    return host_hash ^ (((uint64_t)port + 1) * 0x9E3779B97F4A7C15ull);
}

// Insert only while under cap. We only need to observe a set cross its
// detection threshold, so bounding cardinality a small multiple above the
// threshold preserves detection while keeping memory finite under attack.
static inline void capped_insert(std::unordered_set<uint64_t>& s, uint64_t v,
                                 size_t cap) {
    if (s.size() < cap) s.insert(v);
}

// Sustained inbound bytes/sec from amplifier source ports toward one victim
// that we treat as a reflection/amplification flood.
static constexpr uint64_t kAmpBytesPerSec = 5ull * 1024 * 1024;

std::vector<SecurityEvent>
SecurityEngine::analyze(const std::vector<FlowSample>& flows,
                        double interval_sec, uint64_t now_unix) {
    std::vector<SecurityEvent> out;
    if (interval_sec <= 0) interval_sec = 1;

    const uint64_t window = (uint64_t)cfg_.security_window;

    // Per-key cardinality caps (a small multiple of each detection threshold):
    // enough headroom to fire and report, but bounded so one source cannot
    // grow a set without limit.
    const size_t port_cap  = std::max<size_t>((size_t)cfg_.scan_port_threshold * 2, 64);
    const size_t host_cap  = std::max<size_t>((size_t)cfg_.scan_host_threshold * 2, 64);
    const size_t admin_cap = std::max<size_t>((size_t)cfg_.lateral_host_threshold * 2, 32);
    constexpr size_t kSrcAttackerCap = 4096;   // distinct-source count (reporting)
    constexpr size_t kMaxTrackedSrc  = 65536;  // bound the persistent source map
    constexpr size_t kMaxTrackedAuth = 65536;  // bound the brute-force map

    // Age out persistent windowed state (fixed window).
    for (auto it = src_.begin(); it != src_.end(); ) {
        if (now_unix - it->second.window_start >= window) it = src_.erase(it);
        else ++it;
    }
    for (auto it = auth_.begin(); it != auth_.end(); ) {
        if (now_unix - it->second.window_start >= window) it = auth_.erase(it);
        else ++it;
    }
    // Prune the de-dupe table so it cannot grow without bound over uptime.
    const uint64_t alert_ttl = window * 4 + 1;
    for (auto it = last_alert_.begin(); it != last_alert_.end(); ) {
        if (now_unix - it->second >= alert_ttl) it = last_alert_.erase(it);
        else ++it;
    }

    // Per-interval rate aggregation (transient; rates use the real interval).
    struct DstRate {
        uint64_t pkts = 0, syns = 0, icmp = 0, amp_bytes = 0;
        std::unordered_set<uint64_t> srcs;   // distinct attackers (capped)
    };
    struct SrcRate { uint64_t pkts = 0, syns = 0; };
    std::unordered_map<std::string, DstRate> drate;
    std::unordered_map<std::string, SrcRate> srate;   // internal sources only

    // Accumulate this interval.
    for (const auto& f : flows) {
        if (f.d_packets == 0 && !f.is_new) continue;

        const bool is_icmp = (f.proto == "ICMP" || f.proto == "ICMPv6");
        const uint64_t dst_hash = hash_ip(f.dst_ip);

        // ---- Persistent windowed cardinality (bounded) ----------------- //
        SrcState* sp = nullptr;
        if (auto it = src_.find(f.src_ip); it != src_.end()) {
            sp = &it->second;
        } else if (src_.size() < kMaxTrackedSrc) {   // refuse new keys when full
            sp = &src_[f.src_ip];
            sp->window_start = now_unix;
        }
        if (sp) {
            sp->internal = f.src_internal;
            capped_insert(sp->dst_ports, host_port_key(dst_hash, f.dst_port), port_cap);
            capped_insert(sp->dst_hosts, dst_hash, host_cap);
            if (f.src_internal && f.proto == "UDP" && f.dst_port == 53)
                sp->dns_queries += (f.d_packets ? f.d_packets : 1);   // ~1 query/pkt
            if (f.src_internal && f.dst_internal && is_admin_port(f.dst_port))
                capped_insert(sp->admin_hosts, dst_hash, admin_cap);
        }

        // ---- Brute force: connection attempts per (src,dst,svc-port) --- //
        if (f.is_new && f.proto == "TCP" && is_service_port(f.dst_port)) {
            std::string ak = f.src_ip + "|" + f.dst_ip + "|" + std::to_string(f.dst_port);
            AuthState* ap = nullptr;
            if (auto it = auth_.find(ak); it != auth_.end()) {
                ap = &it->second;
            } else if (auth_.size() < kMaxTrackedAuth) {
                ap = &auth_[ak];
                ap->window_start = now_unix;
                ap->src = f.src_ip; ap->dst = f.dst_ip; ap->port = f.dst_port;
            }
            if (ap) ap->attempts++;
        }

        // ---- Per-interval rate aggregation ----------------------------- //
        DstRate& dr = drate[f.dst_ip];
        dr.pkts += f.d_packets;
        if (f.is_new) dr.syns += f.stats.syn_count;   // new-flow SYNs ~ SYN rate
        if (is_icmp)  dr.icmp += f.d_packets;
        capped_insert(dr.srcs, hash_ip(f.src_ip), kSrcAttackerCap);
        if (!f.src_internal && f.dst_internal && f.proto == "UDP" &&
            is_amp_port(f.src_port))
            dr.amp_bytes += f.d_bytes;

        if (f.src_internal) {
            SrcRate& sr = srate[f.src_ip];
            sr.pkts += f.d_packets;
            if (f.is_new) sr.syns += f.stats.syn_count;
        }

        // --- Per-flow heuristics (immediate) ---------------------------- //

        // TCP stealth scan: NULL / FIN / XMAS flag patterns. A real connection
        // always carries a SYN, so require syn_count == 0 to cut false positives
        // (tcp_flags is OR-accumulated across the flow, so this only fires
        // cleanly on the short, SYN-less flows that scanners produce).
        if (f.proto == "TCP" && f.is_new && f.d_packets <= 3 &&
            f.stats.syn_count == 0) {
            uint32_t fl = f.stats.tcp_flags & 0x3f;   // FIN..URG flag bits
            const char* kind = nullptr;
            if      (fl == 0)                              kind = "NULL";
            else if (fl == TCP_FIN)                        kind = "FIN";
            else if (fl == (TCP_FIN | TCP_PSH | TCP_URG)) kind = "XMAS";
            if (kind) {
                std::string k = std::string("stealth:") + kind + ":" + f.src_ip;
                if (should_emit(k, now_unix, window)) {
                    SecurityEvent e;
                    e.ts_unix = now_unix; e.severity = Severity::Medium;
                    e.category = "stealth_scan";
                    e.src_ip = f.src_ip; e.dst_ip = f.dst_ip;
                    e.dst_port = f.dst_port; e.proto = f.proto;
                    e.detail = std::string(kind) + " scan packet (no/abnormal TCP flags)";
                    out.push_back(std::move(e));
                }
            }
        }

        // Crypto-mining: internal host dialing out to a known pool port.
        if (f.is_new && f.src_internal && !f.dst_internal && is_mining_port(f.dst_port)) {
            std::string k = "mining:" + f.src_ip + ":" + f.dst_ip + ":" +
                            std::to_string(f.dst_port);
            if (should_emit(k, now_unix, window)) {
                SecurityEvent e;
                e.ts_unix = now_unix; e.severity = Severity::High;
                e.category = "cryptomining";
                e.src_ip = f.src_ip; e.dst_ip = f.dst_ip;
                e.dst_port = f.dst_port; e.proto = f.proto;
                e.detail = "outbound connection to crypto-mining pool port " +
                           std::to_string(f.dst_port);
                out.push_back(std::move(e));
            }
        }

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

    // --- Per-source window detections (cardinality + outbound rate) ----- //
    for (auto& [ip, s] : src_) {
        // Port scan: one src touching many distinct dst ports.
        if (s.dst_ports.size() >= cfg_.scan_port_threshold &&
            should_emit("portscan:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "port_scan"; e.src_ip = ip;
            e.metric = s.dst_ports.size();
            e.threshold = cfg_.scan_port_threshold;
            e.detail = "source probed >= " + std::to_string(s.dst_ports.size()) +
                       " distinct ports in " + std::to_string(window) + "s window";
            out.push_back(std::move(e));
        }
        // Host sweep: one src touching many distinct hosts.
        if (s.dst_hosts.size() >= cfg_.scan_host_threshold &&
            should_emit("sweep:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "host_sweep"; e.src_ip = ip;
            e.metric = s.dst_hosts.size();
            e.threshold = cfg_.scan_host_threshold;
            e.detail = "source contacted >= " + std::to_string(s.dst_hosts.size()) +
                       " distinct hosts in " + std::to_string(window) + "s window";
            out.push_back(std::move(e));
        }
        // DNS abuse / tunnelling: query-rate spike from one internal source.
        if (s.dns_queries >= cfg_.dns_rate_threshold &&
            should_emit("dnsabuse:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::Medium;
            e.category = "dns_abuse"; e.src_ip = ip;
            e.dst_port = 53; e.proto = "UDP";
            e.metric = s.dns_queries; e.threshold = cfg_.dns_rate_threshold;
            e.detail = "high DNS query volume (" + std::to_string(s.dns_queries) +
                       " in " + std::to_string(window) + "s) - possible tunnelling/DGA";
            out.push_back(std::move(e));
        }
        // Lateral movement: internal host fanning out on admin ports.
        if (s.admin_hosts.size() >= cfg_.lateral_host_threshold &&
            should_emit("lateral:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "lateral_movement"; e.src_ip = ip;
            e.metric = s.admin_hosts.size();
            e.threshold = cfg_.lateral_host_threshold;
            e.detail = "internal host reached >= " + std::to_string(s.admin_hosts.size()) +
                       " internal hosts on admin ports (RDP/SMB/SSH/WinRM)";
            out.push_back(std::move(e));
        }

        // Outbound DDoS attributed to the offending internal host / VM,
        // using this interval's real rate.
        if (s.internal) {
            auto rit = srate.find(ip);
            if (rit != srate.end()) {
                uint64_t opps = (uint64_t)(rit->second.pkts / interval_sec);
                uint64_t osps = (uint64_t)(rit->second.syns / interval_sec);
                if (opps >= cfg_.ddos_out_pps_threshold &&
                    should_emit("ddos_out_pps:" + ip, now_unix, window)) {
                    SecurityEvent e;
                    e.ts_unix = now_unix; e.severity = Severity::Critical;
                    e.category = "ddos_outbound"; e.src_ip = ip;
                    e.metric = opps; e.threshold = cfg_.ddos_out_pps_threshold;
                    e.detail = "internal host emitting outbound flood: " +
                               std::to_string(opps) + " pps toward " +
                               std::to_string(s.dst_hosts.size()) + " hosts";
                    out.push_back(std::move(e));
                }
                if (osps >= cfg_.ddos_out_syn_threshold &&
                    should_emit("ddos_out_syn:" + ip, now_unix, window)) {
                    SecurityEvent e;
                    e.ts_unix = now_unix; e.severity = Severity::Critical;
                    e.category = "ddos_outbound"; e.src_ip = ip;
                    e.metric = osps; e.threshold = cfg_.ddos_out_syn_threshold;
                    e.detail = "internal host emitting outbound SYN flood: " +
                               std::to_string(osps) + " SYN/s";
                    out.push_back(std::move(e));
                }
            }
        }
    }

    // --- Per-destination interval-rate detections ----------------------- //
    for (auto& [ip, dr] : drate) {
        uint64_t pps  = (uint64_t)(dr.pkts / interval_sec);
        uint64_t sps  = (uint64_t)(dr.syns / interval_sec);
        uint64_t ipps = (uint64_t)(dr.icmp / interval_sec);
        uint64_t abps = (uint64_t)(dr.amp_bytes / interval_sec);

        if (pps >= cfg_.ddos_pps_threshold &&
            should_emit("ddos_pps:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::Critical;
            e.category = "ddos"; e.dst_ip = ip;
            e.metric = pps; e.threshold = cfg_.ddos_pps_threshold;
            e.detail = "volumetric flood: " + std::to_string(pps) +
                       " pps from " + std::to_string(dr.srcs.size()) + " sources";
            out.push_back(std::move(e));
        }
        if (sps >= cfg_.ddos_syn_threshold &&
            should_emit("ddos_syn:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::Critical;
            e.category = "ddos"; e.dst_ip = ip;
            e.metric = sps; e.threshold = cfg_.ddos_syn_threshold;
            e.detail = "SYN flood: " + std::to_string(sps) + " SYN/s toward host";
            out.push_back(std::move(e));
        }
        if (ipps >= cfg_.icmp_flood_threshold &&
            should_emit("icmpflood:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "icmp_flood"; e.dst_ip = ip; e.proto = "ICMP";
            e.metric = ipps; e.threshold = cfg_.icmp_flood_threshold;
            e.detail = "ICMP flood: " + std::to_string(ipps) + " pps toward host from " +
                       std::to_string(dr.srcs.size()) + " sources";
            out.push_back(std::move(e));
        }
        // Reflection/amplification: sustained inbound from amplifier ports.
        if (abps >= kAmpBytesPerSec &&
            should_emit("ampl:" + ip, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "amplification"; e.dst_ip = ip; e.proto = "UDP";
            e.metric = abps; e.threshold = kAmpBytesPerSec;
            e.detail = "sustained inbound from amplifier ports (" +
                       std::to_string(abps / (1024 * 1024)) +
                       " MiB/s) - reflection/amplification";
            out.push_back(std::move(e));
        }
    }

    // --- Brute force / credential stuffing ------------------------------ //
    // Note: counts per (src,dst,service-port); a NAT gateway or busy
    // connection pool shares one src_ip and may need a higher threshold.
    for (auto& [k, a] : auth_) {
        if (a.attempts >= cfg_.bruteforce_threshold &&
            should_emit("brute:" + k, now_unix, window)) {
            SecurityEvent e;
            e.ts_unix = now_unix; e.severity = Severity::High;
            e.category = "bruteforce";
            e.src_ip = a.src; e.dst_ip = a.dst; e.dst_port = a.port; e.proto = "TCP";
            e.metric = a.attempts; e.threshold = cfg_.bruteforce_threshold;
            e.detail = std::to_string(a.attempts) + " connection attempts to service port " +
                       std::to_string(a.port) + " (brute force / credential stuffing)";
            out.push_back(std::move(e));
        }
    }

    return out;
}

} // namespace netmon
