// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace netmon {

// Runtime configuration for the collector. Populated from CLI flags
// (see Config::parse) with sensible defaults for a Proxmox host.
struct Config {
    // Interfaces to attach XDP to. On Proxmox attach to the physical uplink
    // for north-south traffic AND to every VM tap / veth interface for full
    // east-west visibility (XDP at the NIC cannot see VM<->VM traffic that
    // stays on the local bridge).
    std::vector<std::string> interfaces;

    // XDP attach mode. "native" (driver) is fastest; "skb"/generic works on
    // any interface incl. tap/veth/bridges and is the safe default for mixed
    // Proxmox setups. "hw" for offload-capable NICs.
    std::string xdp_mode = "skb";

    // ClickHouse HTTP endpoint and target database.
    std::string clickhouse_url = "http://127.0.0.1:8123";
    std::string clickhouse_db  = "netmon";
    std::string clickhouse_user = "default";
    std::string clickhouse_pass = "";

    // How often (seconds) to scrape the BPF flow map and flush to ClickHouse.
    int flow_poll_interval = 2;

    // --- Real-time stream (ntop-style live push, bypasses the DB) -------- //
    // Machine-consumable SSE event stream only (no GUI). Consume /live from
    // your own project.
    bool        stream_enable = true;
    std::string stream_bind   = "0.0.0.0";
    uint16_t    stream_port    = 8090;
    // Fast live tick (seconds) for throughput/interface KPIs pushed to the
    // stream. L7 records and security alerts are pushed instantly regardless.
    int         live_interval = 1;
    // How many top flows / talkers to include in each live update.
    int         live_top_n = 25;

    // A flow with no packets for this many seconds is considered finished:
    // its final record is exported (with flow end time) and it is evicted
    // from the kernel map to reclaim space.
    int flow_idle_timeout = 30;

    // Insert batching.
    size_t batch_max_rows = 5000;

    // Security thresholds (see SecurityEngine).
    uint64_t ddos_pps_threshold     = 50000; // inbound packets/sec to one dst
    uint64_t ddos_syn_threshold     = 10000; // inbound SYN/sec to one dst
    uint64_t ddos_out_pps_threshold = 20000; // OUTBOUND pps from one internal src (VM)
    uint64_t ddos_out_syn_threshold = 5000;  // OUTBOUND SYN/sec from one internal src
    uint64_t icmp_flood_threshold   = 5000;  // ICMP packets/sec to one dst
    uint32_t scan_port_threshold    = 50;    // distinct dst ports / src / window
    uint32_t scan_host_threshold    = 50;    // distinct dst hosts / src / window
    uint32_t bruteforce_threshold   = 40;    // conn attempts / (src->dst:svc) / window
    uint32_t dns_rate_threshold     = 300;   // DNS queries / src / window (tunnel/DGA)
    uint32_t lateral_host_threshold = 10;    // internal hosts on admin ports / src / win
    int      security_window        = 10;    // seconds

    // --- Real-time event webhook (the client's own endpoint) ------------- //
    // High-severity security events (attacks, scans, floods) are POSTed here
    // as they happen so the client is alerted immediately. Everything is still
    // written to ClickHouse — this is an additional "important only" channel.
    // Empty url disables it.
    std::string event_webhook_url;           // e.g. https://acme.com/api/webhook
    std::string event_webhook_token;         // optional shared secret (X-Netmon-Token)
    // Minimum severity to forward: Info=0 Low=1 Medium=2 High=3 Critical=4.
    // Default High → attacks/scans/floods go out; Medium-and-below stay in DB.
    int      event_webhook_min_severity = 3;

    // Network ranges considered "internal" for east-west classification
    // (CIDR strings). Defaults cover RFC1918.
    std::vector<std::string> internal_cidrs = {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"
    };

    bool verbose = false;

    static Config parse(int argc, char** argv);
    static void print_usage(const char* prog);
};

} // namespace netmon
