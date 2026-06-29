// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include "types.h"

namespace netmon {

struct Config;

// Stateful detector run once per scrape interval over the interval's flow
// samples. Rate-based detections (volumetric / SYN / ICMP floods, outbound
// flood, reflection) are computed per scrape interval from the interval's
// deltas; cardinality detections (scans, sweeps, lateral movement, brute
// force, DNS abuse) accumulate over a short fixed window. All persistent state
// is bounded (capped map sizes, capped per-key cardinality, pruned de-dupe
// table) so the engine cannot be exhausted by the very floods it detects.
// Together they catch a broad set of network-observable attacks:
//   - inbound volumetric DDoS (pps / SYN flood toward a victim)
//   - OUTBOUND DDoS attributed to the offending internal host / VM
//   - ICMP flood
//   - port scan (vertical) and host sweep (horizontal)
//   - TCP stealth scans (NULL / FIN / XMAS flag patterns)
//   - brute force / credential stuffing against service ports
//   - lateral movement (internal host fanning out on admin ports)
//   - DNS abuse / tunnelling (query-rate spike)
//   - reflection / amplification (inbound responses from amplifier ports)
//   - cryptomining pool connections, suspicious ports, data exfiltration
class SecurityEngine {
public:
    explicit SecurityEngine(const Config& cfg);

    // Feed one interval. `interval_sec` is the wall time the deltas cover.
    // Returns any events detected during this interval.
    std::vector<SecurityEvent> analyze(const std::vector<FlowSample>& flows,
                                       double interval_sec,
                                       uint64_t now_unix);

private:
    const Config& cfg_;

    // Per-source cardinality within the fixed security window. Each distinct-set
    // is capped (see analyze) so a single source cannot grow it without bound.
    struct SrcState {
        std::unordered_set<uint64_t> dst_ports;   // distinct (dst-host,port) pairs
        std::unordered_set<uint64_t> dst_hosts;   // distinct hashed dst ips
        std::unordered_set<uint64_t> admin_hosts; // internal hosts hit on admin ports
        // Real dst IPs this source contacted (bounded) so scan/sweep alerts can
        // name the actual target(s) instead of leaving dst_ip empty.
        std::unordered_map<std::string, uint32_t> dst_hits;
        uint64_t dns_queries = 0;                 // DNS abuse / tunnelling
        bool     internal = false;                // src is an internal host / VM
        uint64_t window_start = 0;
    };
    std::unordered_map<std::string, SrcState> src_;

    // Per (src -> dst:service-port) connection-attempt counter (brute force).
    struct AuthState {
        uint64_t    attempts = 0;
        uint64_t    window_start = 0;
        std::string src, dst;
        uint16_t    port = 0;
    };
    std::unordered_map<std::string, AuthState> auth_;

    // De-dupe: suppress repeating the same alert every interval.
    std::unordered_map<std::string, uint64_t> last_alert_;
    bool should_emit(const std::string& dedup_key, uint64_t now, uint64_t cooldown);

    static bool is_suspicious_port(uint16_t port);  // backdoors / RATs / abused svcs
    static bool is_service_port(uint16_t port);     // auth/login-bearing services
    static bool is_admin_port(uint16_t port);       // remote admin (lateral movement)
    static bool is_mining_port(uint16_t port);      // crypto-mining pools
    static bool is_amp_port(uint16_t port);         // reflection/amplification sources
};

} // namespace netmon
