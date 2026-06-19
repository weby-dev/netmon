// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include "types.h"
#include "bpf_loader.h"

namespace netmon {

// Aggregated, per-interval rollups derived from the flow samples plus the
// kernel interface counters. These map directly onto ClickHouse rows and the
// live web stream payload.
struct HostBandwidth {
    std::string ip;
    uint64_t    rx_bytes = 0;   // bytes where host is destination
    uint64_t    tx_bytes = 0;   // bytes where host is source
    uint64_t    rx_packets = 0;
    uint64_t    tx_packets = 0;
    bool        internal = false;
};

struct AppBandwidth {
    std::string app;            // service name e.g. "https"
    std::string category;       // coarse category e.g. "web-tls"
    uint64_t    bytes = 0;
    uint64_t    packets = 0;
    uint64_t    flows = 0;
};

struct TopTalker {
    std::string ip;
    uint64_t    total_bytes = 0;
    uint64_t    total_packets = 0;
};

struct IfaceUtil {
    std::string iface;
    uint32_t    ifindex = 0;
    uint64_t    d_bytes = 0;
    uint64_t    d_packets = 0;
    uint64_t    dropped = 0;
    double      bps = 0.0;       // bits per second this interval
    double      pps = 0.0;
};

struct AggSnapshot {
    uint64_t                   ts_unix = 0;
    double                     interval_sec = 0;
    std::vector<HostBandwidth> hosts;
    std::vector<AppBandwidth>  apps;
    std::vector<TopTalker>     top_talkers;
    std::vector<IfaceUtil>     ifaces;

    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;
    uint64_t active_flows = 0;
    uint64_t east_west_bytes = 0;
    uint64_t north_south_bytes = 0;
};

class Aggregator {
public:
    AggSnapshot build(const std::vector<FlowSample>& flows,
                      const std::vector<BpfLoader::IfCounters>& ifs,
                      double interval_sec,
                      uint64_t now_unix,
                      size_t top_n = 20);
private:
    // Remembers previous absolute interface counters to compute deltas.
    std::unordered_map<uint32_t, if_stats> prev_if_;
};

} // namespace netmon
