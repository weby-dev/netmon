// SPDX-License-Identifier: GPL-2.0
#include "aggregator.h"
#include <algorithm>

namespace netmon {

AggSnapshot Aggregator::build(const std::vector<FlowSample>& flows,
                              const std::vector<BpfLoader::IfCounters>& ifs,
                              double interval_sec,
                              uint64_t now_unix,
                              size_t top_n) {
    AggSnapshot snap;
    snap.ts_unix = now_unix;
    snap.interval_sec = interval_sec > 0 ? interval_sec : 1.0;

    std::unordered_map<std::string, HostBandwidth> hosts;
    std::unordered_map<std::string, AppBandwidth>  apps;

    for (const auto& f : flows) {
        snap.total_bytes += f.d_bytes;
        snap.total_packets += f.d_packets;
        if (f.d_packets > 0 || f.is_new) snap.active_flows++;

        if (f.direction == "east-west") snap.east_west_bytes += f.d_bytes;
        else                            snap.north_south_bytes += f.d_bytes;

        // Per-host: source = tx, destination = rx.
        auto& hs = hosts[f.src_ip];
        hs.ip = f.src_ip; hs.internal = f.src_internal;
        hs.tx_bytes += f.d_bytes; hs.tx_packets += f.d_packets;

        auto& hd = hosts[f.dst_ip];
        hd.ip = f.dst_ip; hd.internal = f.dst_internal;
        hd.rx_bytes += f.d_bytes; hd.rx_packets += f.d_packets;

        // Per-application.
        auto& ap = apps[f.app.name];
        ap.app = f.app.name;
        ap.category = app_category_name(f.app.category);
        ap.bytes += f.d_bytes; ap.packets += f.d_packets;
        if (f.is_new) ap.flows++;
    }

    snap.hosts.reserve(hosts.size());
    for (auto& [k, v] : hosts) snap.hosts.push_back(v);
    snap.apps.reserve(apps.size());
    for (auto& [k, v] : apps) snap.apps.push_back(v);

    // Top talkers by total (tx+rx) bytes.
    snap.top_talkers.reserve(snap.hosts.size());
    for (auto& h : snap.hosts) {
        TopTalker t;
        t.ip = h.ip;
        t.total_bytes = h.tx_bytes + h.rx_bytes;
        t.total_packets = h.tx_packets + h.rx_packets;
        snap.top_talkers.push_back(t);
    }
    std::sort(snap.top_talkers.begin(), snap.top_talkers.end(),
              [](const TopTalker& a, const TopTalker& b) {
                  return a.total_bytes > b.total_bytes;
              });
    if (snap.top_talkers.size() > top_n) snap.top_talkers.resize(top_n);

    std::sort(snap.apps.begin(), snap.apps.end(),
              [](const AppBandwidth& a, const AppBandwidth& b) {
                  return a.bytes > b.bytes;
              });

    // Interface utilisation from kernel counter deltas.
    for (const auto& ic : ifs) {
        IfaceUtil u;
        u.iface = ic.name.empty() ? std::to_string(ic.ifindex) : ic.name;
        u.ifindex = ic.ifindex;
        u.dropped = ic.st.dropped;

        auto prev = prev_if_.find(ic.ifindex);
        if (prev != prev_if_.end()) {
            uint64_t db = ic.st.rx_bytes   >= prev->second.rx_bytes
                        ? ic.st.rx_bytes   -  prev->second.rx_bytes : 0;
            uint64_t dp = ic.st.rx_packets >= prev->second.rx_packets
                        ? ic.st.rx_packets -  prev->second.rx_packets : 0;
            u.d_bytes = db;
            u.d_packets = dp;
            u.bps = (double)db * 8.0 / snap.interval_sec;
            u.pps = (double)dp / snap.interval_sec;
        }
        prev_if_[ic.ifindex] = ic.st;
        snap.ifaces.push_back(u);
    }

    return snap;
}

} // namespace netmon
