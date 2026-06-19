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
// samples. Maintains short sliding windows per source/destination to catch
// port scans, host sweeps, SYN floods / volumetric DDoS, and a handful of
// heuristic anomalies (beaconing, exfil, suspicious ports).
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

    // Per-source rolling activity within the security window.
    struct SrcState {
        std::unordered_set<uint32_t> dst_ports;   // (dst_ip_hash<<16|port) compact
        std::unordered_set<uint64_t> dst_hosts;   // hashed dst ip
        uint64_t syn_total = 0;
        uint64_t bytes_total = 0;
        uint64_t window_start = 0;
        // Beaconing: remember recent inter-arrival gaps to one dst.
    };
    std::unordered_map<std::string, SrcState> src_;

    // Per-destination volumetric counters within the window.
    struct DstState {
        uint64_t packets = 0;
        uint64_t syns = 0;
        uint64_t bytes = 0;
        uint64_t window_start = 0;
        std::unordered_set<uint64_t> src_hosts;   // distinct attackers
    };
    std::unordered_map<std::string, DstState> dst_;

    // De-dupe: suppress repeating the same alert every interval.
    std::unordered_map<std::string, uint64_t> last_alert_;
    bool should_emit(const std::string& dedup_key, uint64_t now, uint64_t cooldown);

    static bool is_suspicious_port(uint16_t port);
};

} // namespace netmon
