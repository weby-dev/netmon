-- ClickHouse schema for the XDP traffic monitor.
-- Applied automatically by the collector at startup (see ClickHouseClient::init_schema).
-- ts columns are unix seconds; JSONEachRow inserts numbers into DateTime fine.

CREATE DATABASE IF NOT EXISTS netmon;

-- =========================================================================
-- Raw flow records (one row per active/closed flow per scrape interval).
-- =========================================================================
CREATE TABLE IF NOT EXISTS netmon.flows
(
    ts            DateTime,
    src_ip        String,
    dst_ip        String,
    src_port      UInt16,
    dst_port      UInt16,
    protocol      LowCardinality(String),
    app           LowCardinality(String),
    app_category  LowCardinality(String),
    direction     LowCardinality(String),     -- east-west / north-south
    packets       UInt64,                      -- absolute flow counter
    bytes         UInt64,
    d_packets     UInt64,                      -- delta this interval
    d_bytes       UInt64,
    tcp_flags     UInt32,
    syn_count     UInt32,
    flow_start    DateTime,
    flow_end      DateTime,
    closed        UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, src_ip, dst_ip, dst_port)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- =========================================================================
-- Application visibility: parsed L7 metadata (HTTP/TLS/DNS/SMTP/DB).
-- =========================================================================
CREATE TABLE IF NOT EXISTS netmon.l7_events
(
    ts           DateTime,
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    protocol     LowCardinality(String),
    l7_proto     LowCardinality(String),
    http_method  LowCardinality(String),
    http_host    String,
    http_path    String,
    http_status  LowCardinality(String),
    user_agent   String,
    tls_sni      String,
    tls_version  LowCardinality(String),
    dns_qname    String,
    dns_qtype    LowCardinality(String),
    smtp_command String,
    db_system    LowCardinality(String),
    db_query     String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, l7_proto, dst_ip)
TTL ts + INTERVAL 30 DAY;

-- =========================================================================
-- Security events.
-- =========================================================================
CREATE TABLE IF NOT EXISTS netmon.security_events
(
    ts         DateTime,
    severity   LowCardinality(String),
    category   LowCardinality(String),
    src_ip     String,
    dst_ip     String,
    dst_port   UInt16,
    protocol   LowCardinality(String),
    detail     String,
    metric     UInt64,
    threshold  UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, severity, category)
TTL ts + INTERVAL 90 DAY;

-- =========================================================================
-- Per-interval rollups written by the aggregator.
-- =========================================================================
CREATE TABLE IF NOT EXISTS netmon.host_bandwidth
(
    ts          DateTime,
    ip          String,
    rx_bytes    UInt64,
    tx_bytes    UInt64,
    rx_packets  UInt64,
    tx_packets  UInt64,
    internal    UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, ip)
TTL ts + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS netmon.app_bandwidth
(
    ts        DateTime,
    app       LowCardinality(String),
    category  LowCardinality(String),
    bytes     UInt64,
    packets   UInt64,
    flows     UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, app)
TTL ts + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS netmon.iface_util
(
    ts         DateTime,
    iface      LowCardinality(String),
    d_bytes    UInt64,
    d_packets  UInt64,
    dropped    UInt64,
    bps        Float64,
    pps        Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, iface)
TTL ts + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS netmon.summary
(
    ts                 DateTime,
    total_bytes        UInt64,
    total_packets      UInt64,
    active_flows       UInt64,
    east_west_bytes    UInt64,
    north_south_bytes  UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY ts
TTL ts + INTERVAL 90 DAY;

-- =========================================================================
-- Convenience materialized view: per-minute top-talker rollup so the
-- dashboard can query long ranges cheaply.
-- =========================================================================
CREATE TABLE IF NOT EXISTS netmon.host_bandwidth_1m
(
    minute    DateTime,
    ip        String,
    rx_bytes  UInt64,
    tx_bytes  UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, ip)
TTL minute + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netmon.host_bandwidth_1m_mv
TO netmon.host_bandwidth_1m AS
SELECT
    toStartOfMinute(ts) AS minute,
    ip,
    sum(rx_bytes)       AS rx_bytes,
    sum(tx_bytes)       AS tx_bytes
FROM netmon.host_bandwidth
GROUP BY minute, ip;
