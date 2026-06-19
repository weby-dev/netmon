// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

extern "C" {
#include "common.h"
}

struct xdp_monitor_bpf;   // forward decl of the generated skeleton type
struct ring_buffer;

namespace netmon {

struct Config;

// One scraped entry from the kernel flow_map.
struct FlowEntry {
    flow_key   key;
    flow_stats stats;
};

// Owns the loaded/attached BPF objects and exposes typed access to the maps.
class BpfLoader {
public:
    explicit BpfLoader(const Config& cfg);
    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;

    // Load the skeleton and attach XDP to every configured interface.
    bool load_and_attach();
    void detach();

    // Snapshot the entire flow map. If `delete_idle` keys are supplied they
    // are removed from the kernel map after the snapshot.
    std::vector<FlowEntry> scrape_flows();
    void delete_flows(const std::vector<flow_key>& keys);

    // Sum the per-CPU global counters into out[__STAT_MAX].
    void read_global_stats(uint64_t out[__STAT_MAX]);

    // Per-interface counters keyed by ifindex.
    struct IfCounters { uint32_t ifindex; if_stats st; std::string name; };
    std::vector<IfCounters> read_if_stats();

    // Inline DDoS mitigation control.
    bool blocklist_add(uint32_t ipv4_be);
    bool blocklist_del(uint32_t ipv4_be);

    // Ring-buffer consumption for L7 samples. The callback receives a pointer
    // to an l7_event living in the ring buffer (valid only during the call).
    using L7Callback = std::function<void(const l7_event*)>;
    bool open_l7_ringbuf(L7Callback cb);
    int  poll_l7(int timeout_ms);   // returns events consumed, <0 on error

private:
    const Config& cfg_;
    xdp_monitor_bpf* skel_ = nullptr;
    ring_buffer* rb_ = nullptr;
    L7Callback l7_cb_;

    struct Attachment { int ifindex; std::string name; };
    std::vector<Attachment> attached_;

    static int l7_trampoline(void* ctx, void* data, size_t len);
};

} // namespace netmon
