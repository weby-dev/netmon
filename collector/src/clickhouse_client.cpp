// SPDX-License-Identifier: GPL-2.0
#include "clickhouse_client.h"
#include "config.h"
#include "net_util.h"
#include "json.h"
#include <curl/curl.h>
#include <cstdio>
#include <sstream>

namespace netmon {

namespace {
size_t write_sink(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}
} // namespace

ClickHouseClient::ClickHouseClient(const Config& cfg) : cfg_(cfg) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}
ClickHouseClient::~ClickHouseClient() {
    flush();
    curl_global_cleanup();
}

bool ClickHouseClient::execute(const std::string& sql) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string resp;
    // skip-unknown-fields lets an INSERT tolerate a table that predates newer
    // columns (e.g. src_bad/dst_bad) instead of failing the whole batch.
    std::string url = cfg_.clickhouse_url + "/?input_format_skip_unknown_fields=1";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, sql.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sql.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_sink);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    // Bound how long a slow/stuck ClickHouse can block the caller. NOSIGNAL is
    // required because the collector is multi-threaded (libcurl otherwise uses
    // signals for timeouts, which is unsafe off the main thread).
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    struct curl_slist* hdrs = nullptr;
    if (!cfg_.clickhouse_user.empty()) {
        hdrs = curl_slist_append(hdrs, ("X-ClickHouse-User: " + cfg_.clickhouse_user).c_str());
        hdrs = curl_slist_append(hdrs, ("X-ClickHouse-Key: " + cfg_.clickhouse_pass).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }

    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http >= 400) {
        std::fprintf(stderr, "clickhouse error (%ld): %s\n", http,
                     resp.empty() ? curl_easy_strerror(rc) : resp.c_str());
        return false;
    }
    return true;
}

bool ClickHouseClient::init_schema(const std::string& schema_sql) {
    // Split on ';' and run each statement. ClickHouse HTTP runs one stmt/req.
    std::stringstream ss(schema_sql);
    std::string stmt, line;
    while (std::getline(ss, line)) {
        // strip line comments
        auto cpos = line.find("--");
        if (cpos != std::string::npos) line = line.substr(0, cpos);
        stmt += line + "\n";
        if (line.find(';') != std::string::npos) {
            // trim
            size_t a = stmt.find_first_not_of(" \t\r\n");
            if (a != std::string::npos) {
                std::string s = stmt.substr(a);
                // drop trailing ';'
                auto semi = s.rfind(';');
                if (semi != std::string::npos) s = s.substr(0, semi);
                if (!s.empty() && !execute(s)) return false;
            }
            stmt.clear();
        }
    }
    return true;
}

bool ClickHouseClient::post(const std::string& sql_prefix,
                            const std::vector<std::string>& rows) {
    if (rows.empty()) return true;
    std::string body = sql_prefix + " FORMAT JSONEachRow\n";
    for (const auto& r : rows) { body += r; body += '\n'; }
    return execute(body);
}

void ClickHouseClient::add_flow(const FlowSample& f) {
    JsonRow j;
    j.num("ts", f.last_seen_unix ? f.last_seen_unix : f.first_seen_unix);
    j.str("src_ip", f.src_ip);
    j.str("dst_ip", f.dst_ip);
    j.num("src_port", f.src_port);
    j.num("dst_port", f.dst_port);
    j.str("protocol", f.proto);
    j.str("app", f.app.name);
    j.str("app_category", app_category_name(f.app.category));
    j.str("direction", f.direction);
    j.num("packets", f.stats.packets);
    j.num("bytes", f.stats.bytes);
    j.num("d_packets", f.d_packets);
    j.num("d_bytes", f.d_bytes);
    j.num("tcp_flags", f.stats.tcp_flags);
    j.num("syn_count", f.stats.syn_count);
    j.num("flow_start", f.first_seen_unix);
    j.num("flow_end", f.last_seen_unix);
    j.num("closed", f.is_closed ? 1 : 0);
    j.num("src_bad", f.src_bad ? 1 : 0);   // IP reputation: source on blocklist
    j.num("dst_bad", f.dst_bad ? 1 : 0);   // IP reputation: dest on blocklist

    std::lock_guard<std::mutex> lk(mtx_);
    flows_.push_back(j.done());
    if (flows_.size() >= cfg_.batch_max_rows)
        post("INSERT INTO " + cfg_.clickhouse_db + ".flows", flows_), flows_.clear();
}

void ClickHouseClient::add_l7(const L7Record& r) {
    JsonRow j;
    j.num("ts", r.ts_ns / 1000000000ull);  // best-effort; main may overwrite
    j.str("src_ip", r.src_ip);
    j.str("dst_ip", r.dst_ip);
    j.num("src_port", r.src_port);
    j.num("dst_port", r.dst_port);
    j.str("protocol", r.proto);
    j.str("l7_proto", r.l7_proto);
    j.str("http_method", r.http_method);
    j.str("http_host", r.http_host);
    j.str("http_path", r.http_path);
    j.str("http_status", r.http_status);
    j.str("user_agent", r.http_user_agent);
    j.str("tls_sni", r.tls_sni);
    j.str("tls_version", r.tls_version);
    j.str("dns_qname", r.dns_qname);
    j.str("dns_qtype", r.dns_qtype);
    j.str("smtp_command", r.smtp_command);
    j.str("db_system", r.db_system);
    j.str("db_query", r.db_query);

    std::lock_guard<std::mutex> lk(mtx_);
    l7_.push_back(j.done());
    if (l7_.size() >= cfg_.batch_max_rows)
        post("INSERT INTO " + cfg_.clickhouse_db + ".l7_events", l7_), l7_.clear();
}

void ClickHouseClient::add_security(const SecurityEvent& e) {
    JsonRow j;
    j.num("ts", e.ts_unix);
    j.str("severity", severity_name(e.severity));
    j.str("category", e.category);
    j.str("src_ip", e.src_ip);
    j.str("dst_ip", e.dst_ip);
    j.num("dst_port", e.dst_port);
    j.str("protocol", e.proto);
    j.str("detail", e.detail);
    j.num("metric", e.metric);
    j.num("threshold", e.threshold);

    std::lock_guard<std::mutex> lk(mtx_);
    sec_.push_back(j.done());
}

void ClickHouseClient::add_snapshot(const AggSnapshot& s) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (const auto& h : s.hosts) {
        JsonRow j;
        j.num("ts", s.ts_unix); j.str("ip", h.ip);
        j.num("rx_bytes", h.rx_bytes); j.num("tx_bytes", h.tx_bytes);
        j.num("rx_packets", h.rx_packets); j.num("tx_packets", h.tx_packets);
        j.num("internal", h.internal ? 1 : 0);
        host_bw_.push_back(j.done());
    }
    for (const auto& a : s.apps) {
        JsonRow j;
        j.num("ts", s.ts_unix); j.str("app", a.app); j.str("category", a.category);
        j.num("bytes", a.bytes); j.num("packets", a.packets); j.num("flows", a.flows);
        app_bw_.push_back(j.done());
    }
    for (const auto& u : s.ifaces) {
        JsonRow j;
        j.num("ts", s.ts_unix); j.str("iface", u.iface);
        j.num("d_bytes", u.d_bytes); j.num("d_packets", u.d_packets);
        j.num("dropped", u.dropped); j.dbl("bps", u.bps); j.dbl("pps", u.pps);
        iface_.push_back(j.done());
    }
    {
        JsonRow j;
        j.num("ts", s.ts_unix);
        j.num("total_bytes", s.total_bytes);
        j.num("total_packets", s.total_packets);
        j.num("active_flows", s.active_flows);
        j.num("east_west_bytes", s.east_west_bytes);
        j.num("north_south_bytes", s.north_south_bytes);
        summary_.push_back(j.done());
    }
}

bool ClickHouseClient::flush() {
    std::lock_guard<std::mutex> lk(mtx_);
    const std::string db = cfg_.clickhouse_db;
    bool ok = true;
    ok &= post("INSERT INTO " + db + ".flows", flows_);          flows_.clear();
    ok &= post("INSERT INTO " + db + ".l7_events", l7_);         l7_.clear();
    ok &= post("INSERT INTO " + db + ".security_events", sec_);  sec_.clear();
    ok &= post("INSERT INTO " + db + ".host_bandwidth", host_bw_); host_bw_.clear();
    ok &= post("INSERT INTO " + db + ".app_bandwidth", app_bw_);  app_bw_.clear();
    ok &= post("INSERT INTO " + db + ".iface_util", iface_);      iface_.clear();
    ok &= post("INSERT INTO " + db + ".summary", summary_);       summary_.clear();
    return ok;
}

} // namespace netmon
