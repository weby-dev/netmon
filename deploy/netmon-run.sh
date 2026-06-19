#!/usr/bin/env bash
# Wrapper that expands NETMON_IFACES into repeated --iface flags and launches
# the collector. Installed to /usr/local/bin/netmon-run.sh.
set -euo pipefail

: "${NETMON_IFACES:?set NETMON_IFACES in /etc/netmon/collector.env}"

args=()
for ifc in $NETMON_IFACES; do
  args+=(--iface "$ifc")
done

args+=(--mode "${NETMON_XDP_MODE:-skb}")
args+=(--clickhouse "${NETMON_CLICKHOUSE_URL:-http://127.0.0.1:8123}")
args+=(--db "${NETMON_CLICKHOUSE_DB:-netmon}")
args+=(--ch-user "${NETMON_CLICKHOUSE_USER:-default}")
[ -n "${NETMON_CLICKHOUSE_PASS:-}" ] && args+=(--ch-pass "${NETMON_CLICKHOUSE_PASS}")
args+=(--interval "${NETMON_INTERVAL:-2}")
args+=(--idle "${NETMON_IDLE:-30}")

# Real-time stream.
if [ "${NETMON_STREAM_ENABLE:-1}" = "0" ]; then
  args+=(--no-stream)
else
  args+=(--stream-bind "${NETMON_STREAM_BIND:-0.0.0.0}")
  args+=(--stream-port "${NETMON_STREAM_PORT:-8090}")
  args+=(--live-interval "${NETMON_LIVE_INTERVAL:-1}")
  [ -n "${NETMON_WEB_ROOT:-}" ] && args+=(--web-root "${NETMON_WEB_ROOT}")
fi

args+=(--ddos-pps "${NETMON_DDOS_PPS:-50000}")
args+=(--ddos-syn "${NETMON_DDOS_SYN:-10000}")
args+=(--scan-ports "${NETMON_SCAN_PORTS:-50}")
args+=(--scan-hosts "${NETMON_SCAN_HOSTS:-50}")

export NETMON_SCHEMA="${NETMON_SCHEMA:-/etc/netmon/schema.sql}"
exec /usr/local/bin/netmon-collector "${args[@]}"
