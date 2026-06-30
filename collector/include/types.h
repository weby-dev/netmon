// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>
#include "app_classifier.h"

extern "C" {
#include "common.h"
}

namespace netmon {

// A per-interval view of one flow, enriched by the collector before it is
// handed to the aggregator / security engine / ClickHouse writer.
struct FlowSample {
    flow_key      key;
    nm_flow_stats stats;       // absolute kernel counters at scrape time

    uint64_t   d_packets = 0;  // delta since previous scrape
    uint64_t   d_bytes   = 0;

    bool       is_new    = false;
    bool       is_closed = false;   // idle-expired this interval

    // Enrichment.
    std::string src_ip, dst_ip;
    uint16_t    src_port = 0, dst_port = 0;   // host order
    std::string proto;                         // TCP/UDP/ICMP/...
    AppInfo     app;
    bool        src_internal = false, dst_internal = false;
    // IP reputation: src/dst matched the operator blocklist (known-bad) or the
    // trusted allowlist (backup/monitoring/resolver/etc. — exempt from the
    // false-positive-prone behavioural detectors).
    bool        src_bad = false, dst_bad = false;
    bool        src_trusted = false, dst_trusted = false;
    std::string direction;       // "north-south" | "east-west"

    // Wall-clock derived from boot time + ktime (UTC unix seconds).
    uint64_t    first_seen_unix = 0;
    uint64_t    last_seen_unix  = 0;
};

// Security findings emitted by SecurityEngine.
enum class Severity { Info, Low, Medium, High, Critical };
const char* severity_name(Severity s);

struct SecurityEvent {
    uint64_t    ts_unix = 0;
    Severity    severity = Severity::Info;
    std::string category;     // "ddos" | "ddos_outbound" | "icmp_flood" |
                              // "port_scan" | "host_sweep" | "stealth_scan" |
                              // "bruteforce" | "lateral_movement" | "dns_abuse" |
                              // "amplification" | "cryptomining" | "blacklist" |
                              // "suspicious_conn" | "anomaly"
    std::string src_ip;
    std::string dst_ip;
    uint16_t    dst_port = 0;
    std::string proto;
    std::string detail;       // human-readable explanation
    uint64_t    metric = 0;   // the measured value that tripped the rule
    uint64_t    threshold = 0;
};

} // namespace netmon
