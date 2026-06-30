// SPDX-License-Identifier: GPL-2.0
//
// netmon-collector: userspace control plane for the XDP flow monitor.
//
//   thread 1 (main):  a fast "live tick" every --live-interval seconds pushes
//                     throughput + interface KPIs to the real-time stream;
//                     every --interval seconds it additionally scrapes the
//                     kernel flow map, aggregates, runs security analysis,
//                     pushes top talkers/flows to the stream, and batch-writes
//                     to ClickHouse for history.
//   thread 2 (l7):    drains the L7 ring buffer continuously, parses HTTP/TLS/
//                     DNS/SMTP/DB samples, pushes each to the stream instantly,
//                     and queues it for ClickHouse.
//   thread 3 (stream):embedded SSE reactor (StreamServer) serving /live.
//
// The real-time path (stream) bypasses the database entirely — ntop-style.
//
#include "config.h"
#include "bpf_loader.h"
#include "net_util.h"
#include "app_classifier.h"
#include "l7_parser.h"
#include "security_engine.h"
#include "aggregator.h"
#include "clickhouse_client.h"
#include "stream_server.h"
#include "webhook.h"
#include "json.h"

#include <atomic>
#include <thread>
#include <chrono>
#include <memory>
#include <csignal>
#include <ctime>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>

using namespace netmon;

static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running = false; }

// Liveness heartbeat: the main scrape loop stamps this every tick. A watchdog
// thread aborts the process if the loop wedges (e.g. a stuck flow scrape or a
// blocked ClickHouse write) so systemd's Restart=always can recover it — a
// crashed collector restarts, but a *hung* one would silently go blind.
static std::atomic<uint64_t> g_heartbeat{0};

// ----- monotonic(ktime) -> unix wall-clock conversion -------------------- //
static int64_t g_clock_offset_ns = 0;   // unix_ns = ktime_ns + offset
static void refresh_clock_offset() {
    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    int64_t mono_ns = (int64_t)mono.tv_sec * 1000000000ll + mono.tv_nsec;
    int64_t real_ns = (int64_t)real.tv_sec * 1000000000ll + real.tv_nsec;
    g_clock_offset_ns = real_ns - mono_ns;
}
static uint64_t ktime_to_unix(uint64_t kt_ns) {
    if (kt_ns == 0) return 0;
    int64_t v = (int64_t)kt_ns + g_clock_offset_ns;
    return v > 0 ? (uint64_t)(v / 1000000000ll) : 0;
}
static uint64_t now_unix() { return (uint64_t)time(nullptr); }
static uint64_t now_ktime_ns() {   // same clock as bpf_ktime_get_ns()
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}
static double steady_now() {
    return (double)now_ktime_ns() / 1e9;
}

// ----- JSON builders for the live stream --------------------------------- //
static std::string l7_to_json(const L7Record& r, uint64_t ts_unix) {
    JsonRow j;
    j.num("ts", ts_unix).str("src_ip", r.src_ip).str("dst_ip", r.dst_ip)
     .num("src_port", r.src_port).num("dst_port", r.dst_port)
     .str("proto", r.proto).str("l7_proto", r.l7_proto)
     .str("http_method", r.http_method).str("http_host", r.http_host)
     .str("http_path", r.http_path).str("http_status", r.http_status)
     .str("tls_sni", r.tls_sni).str("dns_qname", r.dns_qname)
     .str("dns_qtype", r.dns_qtype).str("smtp_command", r.smtp_command)
     .str("db_system", r.db_system);
    return j.done();
}
static std::string sec_to_json(const SecurityEvent& e) {
    JsonRow j;
    j.num("ts", e.ts_unix).str("severity", severity_name(e.severity))
     .str("category", e.category).str("src_ip", e.src_ip)
     .str("dst_ip", e.dst_ip).num("dst_port", e.dst_port)
     .str("proto", e.proto).str("detail", e.detail)
     .num("metric", e.metric).num("threshold", e.threshold);
    return j.done();
}

// ----- read schema.sql from the usual install locations ------------------ //
static std::string load_schema() {
    const char* env = getenv("NETMON_SCHEMA");
    const char* candidates[] = {
        env, "./clickhouse/schema.sql",
        "/etc/netmon/schema.sql", "/usr/share/netmon/schema.sql"
    };
    for (const char* c : candidates) {
        if (!c) continue;
        std::ifstream f(c);
        if (f) {
            std::stringstream ss; ss << f.rdbuf();
            std::fprintf(stderr, "loaded schema from %s\n", c);
            return ss.str();
        }
    }
    std::fprintf(stderr, "warning: schema.sql not found; assuming tables exist\n");
    return {};
}

// Load an IP/CIDR list file (one entry per line, '#' comments, blanks ignored).
static std::vector<std::string> load_cidr_file(const std::string& path) {
    std::vector<std::string> out;
    if (path.empty()) return out;
    std::ifstream f(path);
    if (!f) { std::fprintf(stderr, "warning: could not open IP list %s\n", path.c_str()); return out; }
    std::string line;
    while (std::getline(f, line)) {
        auto h = line.find('#'); if (h != std::string::npos) line = line.substr(0, h);
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        out.push_back(line.substr(a, b - a + 1));
    }
    std::fprintf(stderr, "loaded %zu IP-list entries from %s\n", out.size(), path.c_str());
    return out;
}

struct PrevState {
    nm_flow_stats stats;
    bool          seen_this_round = false;
};

int main(int argc, char** argv) {
    Config cfg = Config::parse(argc, argv);
    refresh_clock_offset();

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);    // stream writes use MSG_NOSIGNAL anyway

    CidrSet internal(cfg.internal_cidrs);
    CidrSet blocklist(load_cidr_file(cfg.blocklist_path));   // known-bad IPs
    CidrSet allowlist(load_cidr_file(cfg.allowlist_path));   // trusted IPs

    BpfLoader bpf(cfg);
    if (!bpf.load_and_attach()) {
        std::fprintf(stderr, "fatal: could not attach XDP to any interface\n");
        return 1;
    }

    ClickHouseClient ch(cfg);
    std::string schema = load_schema();
    if (!schema.empty() && !ch.init_schema(schema))
        std::fprintf(stderr, "warning: schema init reported errors\n");

    SecurityEngine sec(cfg);
    Aggregator agg;

    // ---- real-time event webhook to the client's endpoint --------------- //
    // High-severity events (attacks/scans/floods) are pushed here instantly;
    // all events are still persisted to ClickHouse below.
    std::unique_ptr<WebhookSender> event_hook;
    if (!cfg.event_webhook_url.empty()) {
        event_hook = std::make_unique<WebhookSender>(
            cfg.event_webhook_url, cfg.event_webhook_token, cfg.verbose);
        std::fprintf(stderr, "event webhook: forwarding severity>=%d to %s\n",
                     cfg.event_webhook_min_severity, cfg.event_webhook_url.c_str());
    }

    // ---- real-time stream server ---------------------------------------- //
    std::unique_ptr<StreamServer> stream;
    if (cfg.stream_enable) {
        stream = std::make_unique<StreamServer>(cfg.stream_bind, cfg.stream_port);
        if (!stream->start()) {
            std::fprintf(stderr, "warning: stream server failed to start\n");
            stream.reset();
        }
    }

    // ---- L7 ring-buffer consumer thread (instant L7 push) --------------- //
    bpf.open_l7_ringbuf([&](const l7_event* ev) {
        L7Record r = parse_l7(ev);
        if (!r.valid) return;
        uint64_t ts = ktime_to_unix(ev->ts_ns);
        r.ts_ns = ts * 1000000000ull;
        ch.add_l7(r);
        if (stream) stream->broadcast("l7", l7_to_json(r, ts));
    });
    std::thread l7_thread([&]() {
        while (g_running.load()) {
            int n = bpf.poll_l7(200 /*ms*/);
            if (n < 0 && errno != EINTR) {
                std::fprintf(stderr, "ring buffer poll error: %d\n", n);
                break;
            }
        }
    });

    // ---- liveness watchdog: restart-on-hang ----------------------------- //
    // Comfortably longer than the worst-case (now bounded) ClickHouse flush, so a
    // merely-slow DB is a self-recovering stall, not a watchdog abort. Only a true
    // hang (no scrape tick for this long) trips it -> abort -> systemd restart.
    const uint64_t watchdog_timeout =
        std::max<uint64_t>(180, (uint64_t)cfg.flow_poll_interval * 30);
    g_heartbeat.store(now_unix());
    std::thread watchdog([&]() {
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!g_running.load()) break;   // don't fire during clean shutdown
            uint64_t hb = g_heartbeat.load();
            if (hb && now_unix() - hb > watchdog_timeout) {
                std::fprintf(stderr,
                    "fatal: main loop stalled for >%llus (last tick %llus ago); "
                    "aborting for supervisor restart\n",
                    (unsigned long long)watchdog_timeout,
                    (unsigned long long)(now_unix() - hb));
                std::abort();
            }
        }
    });

    std::unordered_map<flow_key, PrevState, FlowKeyHash, FlowKeyEq> prev;

    // Live-tick interface state (independent of the slower aggregator prev).
    std::unordered_map<uint32_t, if_stats> live_prev_if;
    double   live_prev_t = steady_now();
    AggSnapshot last_snap;     // reused for active_flows/east-west between scrapes
    uint64_t last_full_scrape = 0;

    std::fprintf(stderr,
        "netmon-collector running; scrape=%ds live=%ds idle=%ds stream=%s\n",
        cfg.flow_poll_interval, cfg.live_interval, cfg.flow_idle_timeout,
        stream ? "on" : "off");

    while (g_running.load()) {
        // Sleep one live-interval in small slices for responsive signals.
        int slices = std::max(1, cfg.live_interval) * 10;
        for (int i = 0; i < slices && g_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!g_running.load()) break;

        refresh_clock_offset();
        uint64_t ts = now_unix();
        g_heartbeat.store(ts);   // liveness for the watchdog thread

        // ============ FAST LIVE TICK: interfaces + throughput ============ //
        double tnow = steady_now();
        double live_dt = tnow - live_prev_t;
        if (live_dt <= 0) live_dt = cfg.live_interval;
        live_prev_t = tnow;

        auto ifs = bpf.read_if_stats();
        uint64_t tick_bytes = 0, tick_pkts = 0;
        JsonArr ifarr;
        for (const auto& ic : ifs) {
            uint64_t db = 0, dp = 0;
            auto p = live_prev_if.find(ic.ifindex);
            if (p != live_prev_if.end()) {
                db = ic.st.rx_bytes   >= p->second.rx_bytes
                   ? ic.st.rx_bytes   -  p->second.rx_bytes : 0;
                dp = ic.st.rx_packets >= p->second.rx_packets
                   ? ic.st.rx_packets -  p->second.rx_packets : 0;
            }
            live_prev_if[ic.ifindex] = ic.st;
            tick_bytes += db; tick_pkts += dp;

            JsonRow r;
            r.str("iface", ic.name.empty() ? std::to_string(ic.ifindex) : ic.name)
             .dbl("bps", (double)db * 8.0 / live_dt)
             .dbl("pps", (double)dp / live_dt)
             .num("d_bytes", db).num("d_packets", dp)
             .num("dropped", ic.st.dropped);
            ifarr.add(r.done());
        }

        if (stream) {
            double bps = (double)tick_bytes * 8.0 / live_dt;
            double pps = (double)tick_pkts / live_dt;
            JsonRow s;
            s.num("ts", ts)
             .dbl("bps", bps).dbl("pps", pps)
             .num("interval_bytes", tick_bytes).num("interval_packets", tick_pkts)
             .num("active_flows", last_snap.active_flows)
             .num("east_west_bytes", last_snap.east_west_bytes)
             .num("north_south_bytes", last_snap.north_south_bytes)
             .num("clients", stream->client_count());
            stream->broadcast("stats", s.done());
            stream->broadcast("ifaces", ifarr.done());
        }

        // ============ FULL SCRAPE: flows + security + DB ================= //
        if (ts - last_full_scrape < (uint64_t)cfg.flow_poll_interval)
            continue;
        double interval = last_full_scrape ? (double)(ts - last_full_scrape)
                                           : (double)cfg.flow_poll_interval;
        if (interval <= 0) interval = cfg.flow_poll_interval;
        last_full_scrape = ts;

        uint64_t now_kt = now_ktime_ns();
        uint64_t idle_ns = (uint64_t)cfg.flow_idle_timeout * 1000000000ull;

        auto entries = bpf.scrape_flows();
        for (auto& kv : prev) kv.second.seen_this_round = false;

        std::vector<FlowSample> samples;
        samples.reserve(entries.size());
        std::vector<flow_key> to_delete;

        for (auto& e : entries) {
            FlowSample s;
            s.key = e.key;
            s.stats = e.stats;

            auto pit = prev.find(e.key);
            if (pit == prev.end()) {
                s.is_new = true;
                s.d_packets = e.stats.packets;
                s.d_bytes = e.stats.bytes;
            } else {
                pit->second.seen_this_round = true;
                s.d_packets = e.stats.packets >= pit->second.stats.packets
                            ? e.stats.packets - pit->second.stats.packets : e.stats.packets;
                s.d_bytes   = e.stats.bytes >= pit->second.stats.bytes
                            ? e.stats.bytes - pit->second.stats.bytes : e.stats.bytes;
            }

            if (now_kt > e.stats.last_seen_ns &&
                now_kt - e.stats.last_seen_ns > idle_ns) {
                s.is_closed = true;
                to_delete.push_back(e.key);
            }

            s.src_ip = ip_to_string(e.key.src_addr, e.key.family);
            s.dst_ip = ip_to_string(e.key.dst_addr, e.key.family);
            s.src_port = ntoh16(e.key.src_port);
            s.dst_port = ntoh16(e.key.dst_port);
            s.proto = proto_name(e.key.protocol);
            s.app = classify_app(e.key.protocol, s.src_port, s.dst_port);
            s.src_internal = internal.contains(e.key.src_addr, e.key.family);
            s.dst_internal = internal.contains(e.key.dst_addr, e.key.family);
            s.src_bad     = blocklist.contains(e.key.src_addr, e.key.family);
            s.dst_bad     = blocklist.contains(e.key.dst_addr, e.key.family);
            s.src_trusted = allowlist.contains(e.key.src_addr, e.key.family);
            s.dst_trusted = allowlist.contains(e.key.dst_addr, e.key.family);
            s.direction = (s.src_internal && s.dst_internal) ? "east-west" : "north-south";
            s.first_seen_unix = ktime_to_unix(e.stats.first_seen_ns);
            s.last_seen_unix  = ktime_to_unix(e.stats.last_seen_ns);

            samples.push_back(s);
            prev[e.key].stats = e.stats;
            prev[e.key].seen_this_round = true;
        }

        for (auto it = prev.begin(); it != prev.end(); ) {
            if (!it->second.seen_this_round) it = prev.erase(it);
            else ++it;
        }
        for (const auto& k : to_delete) prev.erase(k);

        for (const auto& s : samples)
            if (s.d_packets > 0 || s.is_new || s.is_closed) ch.add_flow(s);

        AggSnapshot snap = agg.build(samples, ifs, interval, ts, cfg.live_top_n);
        ch.add_snapshot(snap);
        last_snap = snap;

        // ---- push top talkers + top flows to the stream ---------------- //
        if (stream) {
            JsonArr talkers;
            for (const auto& t : snap.top_talkers) {
                JsonRow r;
                r.str("ip", t.ip).num("total_bytes", t.total_bytes)
                 .num("total_packets", t.total_packets);
                talkers.add(r.done());
            }
            stream->broadcast("talkers", talkers.done());

            // Top active flows by bytes this interval.
            std::vector<const FlowSample*> active;
            active.reserve(samples.size());
            for (const auto& s : samples)
                if (s.d_bytes > 0) active.push_back(&s);
            size_t topn = std::min((size_t)cfg.live_top_n, active.size());
            std::partial_sort(active.begin(), active.begin() + topn, active.end(),
                [](const FlowSample* a, const FlowSample* b){ return a->d_bytes > b->d_bytes; });
            JsonArr flows;
            for (size_t i = 0; i < topn; ++i) {
                const FlowSample* s = active[i];
                JsonRow r;
                r.str("src_ip", s->src_ip).num("src_port", s->src_port)
                 .str("dst_ip", s->dst_ip).num("dst_port", s->dst_port)
                 .str("proto", s->proto).str("app", s->app.name)
                 .str("direction", s->direction)
                 .num("d_bytes", s->d_bytes).num("d_packets", s->d_packets)
                 .num("bytes", s->stats.bytes).num("packets", s->stats.packets);
                flows.add(r.done());
            }
            stream->broadcast("flows", flows.done());
        }

        // ---- security analysis (push instantly + persist) -------------- //
        auto events = sec.analyze(samples, interval, ts);
        for (auto& ev : events) {
            ch.add_security(ev);                                  // always persist
            if (stream) stream->broadcast("security", sec_to_json(ev));
            // Forward only the important ones to the client's webhook.
            if (event_hook && (int)ev.severity >= cfg.event_webhook_min_severity)
                event_hook->enqueue(sec_to_json(ev), ev.category);
            std::fprintf(stderr, "[SECURITY/%s] %s %s%s%s %s\n",
                         severity_name(ev.severity), ev.category.c_str(),
                         ev.src_ip.c_str(),
                         ev.dst_ip.empty() ? "" : " -> ",
                         ev.dst_ip.c_str(), ev.detail.c_str());
        }

        if (!to_delete.empty()) bpf.delete_flows(to_delete);
        ch.flush();

        if (cfg.verbose) {
            std::fprintf(stderr,
                "scrape: flows=%zu active=%llu ew=%llu ns=%llu stream_clients=%zu\n",
                samples.size(),
                (unsigned long long)snap.active_flows,
                (unsigned long long)snap.east_west_bytes,
                (unsigned long long)snap.north_south_bytes,
                stream ? stream->client_count() : 0);
        }
    }

    std::fprintf(stderr, "\nshutting down...\n");
    if (stream) stream->stop();
    l7_thread.join();
    watchdog.join();
    ch.flush();
    bpf.detach();
    return 0;
}
