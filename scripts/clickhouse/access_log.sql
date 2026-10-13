-- Quayel Gateway access log table (schema_version 1) for the `clickhouse`
-- log sink. Every key of the log line is a column with the same name, so
-- `INSERT ... FORMAT JSONEachRow` loads lines as they are.
--
--   clickhouse-client --multiquery < scripts/clickhouse/access_log.sql
--
-- Change the database name (qg) and the TTL to suit; the sink's `database`
-- and `table` must match. For a cluster, create this as the local table on
-- every shard (ReplicatedMergeTree) plus a Distributed table to insert into.

CREATE DATABASE IF NOT EXISTS qg;

CREATE TABLE IF NOT EXISTS qg.access_log
(
    schema_version  UInt8,
    -- The line's `ts` is Unix milliseconds (JSONEachRow would read an integer
    -- as seconds if this were a DateTime64). `time` is built from it on
    -- insert: query and filter on `time`.
    ts              UInt64 CODEC(Delta, ZSTD(1)),
    time            DateTime64(3, 'UTC') MATERIALIZED fromUnixTimestamp64Milli(toInt64(ts)),
    gateway_id      LowCardinality(String),
    request_id      UUID,

    client_ip       IPv6,             -- IPv4 is stored as ::ffff:a.b.c.d
    method          LowCardinality(String),
    scheme          LowCardinality(String),
    host            LowCardinality(String),
    path            String,
    user_agent      String CODEC(ZSTD(3)),

    status          UInt16,
    bytes           UInt64,
    req_bytes       UInt64,
    dur_us          UInt32,

    country         LowCardinality(String),
    region          LowCardinality(String),
    asn             UInt32,
    provider        LowCardinality(String),
    datacenter      Bool,
    vpn             Bool,
    proxy           Bool,
    tor             Bool,
    risk            UInt8,

    block           Tuple(
                        type   LowCardinality(String),
                        action LowCardinality(String),
                        rule   LowCardinality(String),
                        key    String),
    allow_rule      LowCardinality(String),
    cache           LowCardinality(String),

    upstream        LowCardinality(String),
    upstream_addr   LowCardinality(String),
    upstream_status UInt16,
    upstream_us     UInt32,
    error           String,
    user            String,
    sample_rate     UInt32 DEFAULT 1
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (host, time)
TTL toDate(time) + INTERVAL 30 DAY
-- Lets the sink's insert_deduplication_token drop a retried batch that had
-- already landed (Replicated* tables deduplicate without this setting).
SETTINGS non_replicated_deduplication_window = 1000;
