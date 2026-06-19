// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <string>
#include <vector>
#include <mutex>
#include "types.h"
#include "l7_parser.h"
#include "aggregator.h"

namespace netmon {

struct Config;

// Thin ClickHouse writer over the HTTP interface. Rows are buffered as
// JSONEachRow lines and flushed in batches. Thread-safe: the ring-buffer
// thread and the scrape thread can both enqueue.
class ClickHouseClient {
public:
    explicit ClickHouseClient(const Config& cfg);
    ~ClickHouseClient();

    // Create database + tables if they do not exist (runs schema.sql inline).
    bool init_schema(const std::string& schema_sql);

    // Enqueue rows (thread-safe). Flushed by flush() or when batch is full.
    void add_flow(const FlowSample& f);
    void add_l7(const L7Record& r);
    void add_security(const SecurityEvent& e);
    void add_snapshot(const AggSnapshot& s);   // host/app/iface/summary rows

    // Force-flush all buffers to ClickHouse. Returns false on any failure.
    bool flush();

private:
    const Config& cfg_;

    std::mutex mtx_;
    std::vector<std::string> flows_, l7_, sec_, host_bw_, app_bw_, iface_, summary_;

    bool post(const std::string& sql_prefix,
              const std::vector<std::string>& rows);
    bool execute(const std::string& sql);   // DDL / arbitrary statement
};

} // namespace netmon
