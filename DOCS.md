# netmon — Project Documentation

Flow-level network monitoring and threat detection for Proxmox/Linux hosts,
built on **XDP/eBPF** (kernel data path) + a C++ userspace collector, with
**ClickHouse** for history, a **real-time SSE stream**, and **outbound webhooks**
for alerts and registration.

> **What it is:** a *passive* monitor / lightweight IDS. It observes traffic via
> XDP (`XDP_PASS`) and *reports* — it does **not** drop or block packets. If the
> collector dies, traffic is unaffected; you lose visibility, not connectivity.
> The only "firewall" it manages is an nftables rule that restricts access to its
> own ClickHouse port (see [Security](#7-clickhouse-access--security-model)).

---

## Table of contents
1. [Architecture](#1-architecture)
2. [Deployment model](#2-deployment-model)
3. [Installation](#3-installation)
4. [Configuration reference](#4-configuration-reference)
5. [Detection engine](#5-detection-engine)
6. [Data model (ClickHouse)](#6-data-model-clickhouse)
7. [ClickHouse access & security model](#7-clickhouse-access--security-model)
8. [Real-time stream (SSE)](#8-real-time-stream-sse)
9. [Webhooks](#9-webhooks)
10. [IP reputation & allowlist](#10-ip-reputation--allowlist)
11. [Operations](#11-operations)
12. [Reliability & hang-safety](#12-reliability--hang-safety)
13. [Troubleshooting](#13-troubleshooting)
14. [File & directory layout](#14-file--directory-layout)
15. [Production checklist](#15-production-checklist)

---

## 1. Architecture

```
        NIC / VM taps / CT veth
                 │  (XDP at the driver/generic hook)
        ┌────────▼─────────┐
        │  eBPF program     │  ebpf/xdp_monitor.bpf.c
        │  - flow_map (LRU) │  per-flow counters (pkts/bytes/flags/SYN)
        │  - if_stats_map   │  per-interface counters
        │  - l7 ringbuf     │  sampled payload for HTTP/TLS/DNS/SMTP/DB
        └────────┬─────────┘
                 │ maps + ring buffer
        ┌────────▼───────────────────────────────────────────┐
        │  netmon-collector (userspace, C++)                  │
        │                                                     │
        │  main thread:  scrape flow_map every --interval,    │
        │                enrich, run SecurityEngine,          │
        │                aggregate, write to ClickHouse,      │
        │                push KPIs to the stream              │
        │  L7 thread:    drain ringbuf, parse L7, push/persist│
        │  stream thread:epoll SSE server (/live, /healthz)   │
        │  webhook thread:async POST important events out     │
        │  watchdog:     abort-on-hang -> systemd restart     │
        └───┬───────────────┬─────────────────┬──────────────┘
            │               │                 │
     ┌──────▼─────┐  ┌──────▼──────┐   ┌──────▼─────────────┐
     │ ClickHouse │  │ SSE stream  │   │ Webhooks (HTTPS)   │
     │ (history)  │  │ :8090/live  │   │ - vormox (register)│
     │ localhost  │  │             │   │ - client (events)  │
     └────────────┘  └─────────────┘   └────────────────────┘
```

**Threads in the collector** (`collector/src/main.cpp`):
- **main** — fast "live tick" every `--live-interval` (throughput/iface KPIs to the
  stream); every `--interval` it scrapes the flow map, enriches each flow,
  runs the `SecurityEngine`, aggregates top-talkers/bandwidth, writes to
  ClickHouse, and pushes top flows to the stream.
- **L7** — continuously drains the L7 ring buffer, parses HTTP/TLS-SNI/DNS/SMTP/DB
  metadata, pushes each to the stream instantly and queues for ClickHouse.
- **stream** — an epoll, non-blocking SSE reactor (`StreamServer`).
- **webhook** — a background sender with a bounded queue (`WebhookSender`).
- **watchdog** — restarts the process if the main loop stalls (see §12).

The real-time path (stream + webhooks) **bypasses the database** — alerts are
delivered in seconds; ClickHouse is the historical store.

---

## 2. Deployment model

Everything runs **bare-metal on the Proxmox host** — no Docker, no VM:
- The collector must be on the host (XDP needs the host kernel + NICs), attached
  to the uplink(s) **and** every VM `tap`/CT `veth` interface for east-west
  visibility.
- ClickHouse is installed natively alongside it (localhost).
- Kernel requirement: **≥ 5.18** (XDP + ring buffer + `bpf_xdp_load_bytes`).
  Proxmox VE 8/9 kernels qualify.

---

## 3. Installation

Two scripts:

- **`setup.sh`** — first-touch bootstrap for a fresh host that only has `curl`.
  It repairs APT, installs `git` + the build toolchain, clones the repo into a
  dedicated dir, then hands off to `install.sh`.
- **`install.sh`** — builds + installs the collector, ClickHouse, users,
  firewall, retention, webhooks, and credentials.

### One-line install
```bash
curl -fsSL https://raw.githubusercontent.com/weby-dev/netmon/main/setup.sh -o setup.sh
bash setup.sh --domain console.example.com --webhook-secret <shared-secret>
```

### What `setup.sh` does
1. **Proxmox APT repair** (idempotent, re-run safe):
   - disables the subscription-only **enterprise** repos (the ones that 401),
   - enables the free **`pve-no-subscription`** repo,
   - de-duplicates the Debian sources into one clean deb822 file,
   - completes a half-finished release upgrade (`apt full-upgrade`) if it detects
     a mixed bookworm/trixie state,
   - clean re-index (`rm -rf /var/lib/apt/lists/*` + `apt update`).
2. Installs `git` + build deps (`clang llvm libbpf-dev bpftool libelf-dev
   zlib1g-dev libcurl4-openssl-dev cmake build-essential pkg-config`).
3. Clones to `/opt/netmon`, removes `.git`.
4. `exec install.sh --skip-os-setup` with any pass-through flags.

### What `install.sh` does
1. (unless `--skip-os-setup`) the APT repair + deps above.
2. Deploys the repo to `/opt/netmon` (drops `.git`).
3. Installs ClickHouse, configures the [two-user model](#7-clickhouse-access--security-model),
   makes the native port reachable, sets the schema with the chosen retention.
4. Applies the **firewall** (nftables: HTTP `:8123` blocked from the network).
5. `make` builds the collector; installs the binary + wrapper + hardened systemd
   unit; stops/removes any prior install first.
6. Writes `/etc/netmon/collector.env`, seeds `blocklist.txt`/`allowlist.txt`.
7. Starts `netmon-collector`.
8. If `--domain` is set, POSTs a registration webhook (see §9).
9. Writes all credentials to `/opt/netmon/clickhouse.md` (chmod 600).

### `install.sh` flags
`--dir PATH` · `--repo URL` · `--retention-days N` (default 7) · `--domain D` ·
`--webhook-url URL` (default `https://vormox.com/api/webhook`) · `--webhook-secret S` ·
`--event-webhook-url URL` · `--event-token S` · `--event-min-severity LEVEL` ·
`--no-clickhouse` · `--skip-os-setup` · `--no-start`

`setup.sh` accepts `--domain`, `--webhook-secret`, `--webhook-url`, `--dir`,
`--repo`, `--clone-only`, and forwards any other flag to `install.sh`.

---

## 4. Configuration reference

The systemd unit loads `/etc/netmon/collector.env`; `deploy/netmon-run.sh`
turns those env vars into CLI flags for `netmon-collector`.

| Env var | CLI flag | Default | Meaning |
|---|---|---|---|
| `NETMON_IFACES` | `--iface` (repeated) | `vmbr0 eno1` | interfaces to attach XDP to |
| `NETMON_XDP_MODE` | `--mode` | `skb` | `skb` (generic) / `native` / `hw` |
| `NETMON_CLICKHOUSE_URL` | `--clickhouse` | `http://127.0.0.1:8123` | CH HTTP endpoint |
| `NETMON_CLICKHOUSE_DB` | `--db` | `netmon` | database |
| `NETMON_CLICKHOUSE_USER` | `--ch-user` | `netmon` | collector DB user |
| `NETMON_CLICKHOUSE_PASS` | `--ch-pass` | (generated) | collector DB password |
| `NETMON_INTERVAL` | `--interval` | `2` | flow scrape interval (s) |
| `NETMON_IDLE` | `--idle` | `30` | idle flow eviction (s) |
| `NETMON_STREAM_ENABLE` | `--no-stream` | `1` | enable SSE stream |
| `NETMON_STREAM_BIND` | `--stream-bind` | `0.0.0.0` | stream bind addr |
| `NETMON_STREAM_PORT` | `--stream-port` | `8090` | stream port |
| `NETMON_LIVE_INTERVAL` | `--live-interval` | `1` | live KPI cadence (s) |
| `NETMON_DDOS_PPS` | `--ddos-pps` | `50000` | inbound flood pps |
| `NETMON_DDOS_SYN` | `--ddos-syn` | `10000` | inbound SYN/s |
| `NETMON_DDOS_OUT_PPS` | `--ddos-out-pps` | `20000` | outbound pps from one VM |
| `NETMON_DDOS_OUT_SYN` | `--ddos-out-syn` | `5000` | outbound SYN/s from one VM |
| `NETMON_ICMP_FLOOD` | `--icmp-flood` | `5000` | ICMP pps |
| `NETMON_DDOS_MIN_PEERS` | `--ddos-min-peers` | `5` | min distinct peers for a *distributed* flood |
| `NETMON_SCAN_PORTS` | `--scan-ports` | `50` | distinct dst ports → port scan |
| `NETMON_SCAN_HOSTS` | `--scan-hosts` | `50` | distinct dst hosts → sweep |
| `NETMON_BRUTEFORCE` | `--bruteforce` | `40` | conn attempts → brute force |
| `NETMON_DNS_RATE` | `--dns-rate` | `300` | DNS queries/window → abuse |
| `NETMON_LATERAL_HOSTS` | `--lateral-hosts` | `10` | internal hosts on admin ports → lateral |
| `NETMON_EVENT_WEBHOOK_URL` | `--event-webhook-url` | (from `--domain`) | client event endpoint |
| `NETMON_EVENT_WEBHOOK_TOKEN` | `--event-webhook-token` | (generated) | `X-Netmon-Token` |
| `NETMON_EVENT_WEBHOOK_MIN_SEVERITY` | `--event-webhook-min-severity` | `high` | min severity to forward |
| `NETMON_BLOCKLIST` | `--blocklist` | `/etc/netmon/blocklist.txt` | known-bad IPs |
| `NETMON_ALLOWLIST` | `--allowlist` | `/etc/netmon/allowlist.txt` | trusted IPs |
| `NETMON_SCHEMA` | (env) | `/etc/netmon/schema.sql` | schema applied at startup |

The detection **window** (`security_window`) is fixed at **10 s** and the alert
**dedup cooldown** equals that window (see §5).

---

## 5. Detection engine

`SecurityEngine::analyze()` runs once per scrape over that interval's flow
samples. It mixes three styles:
- **per-interval rates** (pps/SYN/s/ICMP) computed from the interval's deltas;
- **fixed-window cardinality** (distinct ports/hosts/queries over the 10 s window);
- **per-flow heuristics** (immediate).

All per-source/dest state is **bounded** (capped maps + capped sets + pruned
dedup table) so the engine can't be exhausted by the very floods it detects.

### Event categories

| Category | Severity | Webhooked* | Trigger (default) | Notes |
|---|---|---|---|---|
| `ddos` | Critical | ✅ | ≥50k pps **or** 10k SYN/s to one host | **and** ≥ `ddos_min_peers` distinct sources (distributed) |
| `ddos_outbound` | Critical | ✅ | a VM emits ≥20k pps **or** 5k SYN/s | **and** fan-out to ≥ `ddos_min_peers` hosts |
| `icmp_flood` | High | ✅ | ≥5k ICMP pps to one host | |
| `amplification` | High | ✅ | sustained inbound from amplifier src-ports (DNS/NTP/SSDP/memcached…) | |
| `port_scan` | High | ✅ | one src probes ≥50 distinct ports | names the main target |
| `host_sweep` | High | ✅ | one src touches ≥50 distinct hosts | |
| `bruteforce` | High | ✅ | ≥40 conn attempts to a service port (SSH/RDP/SQL…) | |
| `lateral_movement` | High | ✅ | internal host fans out on admin ports (RDP/SMB/SSH/WinRM) to ≥10 hosts | |
| `cryptomining` | High | ✅ | internal host → known mining-pool port | |
| `blacklist` | High | ✅ | any flow touching a blocklisted IP | IP reputation (§10) |
| `stealth_scan` | Medium | ❌ | NULL/FIN/XMAS TCP flag packet | DB-only |
| `dns_abuse` | Medium | ❌ | ≥300 DNS queries/window from one src (tunnel/DGA) | DB-only |
| `suspicious_conn` | Medium | ❌ | internal → external on a backdoor/RAT port | DB-only |
| `anomaly` | Medium | ❌ | >50 MiB internal→external transfer (exfil) | DB-only |

*\*Webhooked when severity ≥ `NETMON_EVENT_WEBHOOK_MIN_SEVERITY` (default `high`).
Everything is always written to ClickHouse regardless.*

### Key design points
- **Distributed gate (`ddos_min_peers`):** volumetric DDoS only fires when traffic
  is actually distributed (many sources inbound / fan-out outbound). This is what
  keeps **backups, speedtests, and big downloads** (1–2 endpoints) from being
  flagged as floods. SYN-rate and ICMP detections are *not* gated.
- **Re-alert cadence:** a sustained attack re-fires the same alert roughly every
  **10 s** (the window) for its full duration — not once, not after a long delay.
  There is no explicit "ended" event; absence of alerts = cleared.
- **Target naming:** per-source alerts (`port_scan`, `host_sweep`, `dns_abuse`,
  `lateral_movement`, `ddos_outbound`) populate `dst_ip` with the most-contacted
  destination so you can see the actual target.
- **Allowlist suppression:** trusted IPs are exempt from the noisy behavioural
  detectors (see §10).

### Event fields
`ts`, `severity`, `category`, `src_ip`, `dst_ip`, `dst_port`, `proto`,
`detail` (human-readable), `metric` (the measured value), `threshold`.

---

## 6. Data model (ClickHouse)

Database **`netmon`** (schema in `clickhouse/schema.sql`, applied at install).
Every table is `MergeTree`, partitioned by day, with a TTL set to the retention
(`--retention-days`, default **7 days**).

| Table | Contents |
|---|---|
| `flows` | one row per active/closed flow per scrape: 5-tuple, app, direction, abs+delta packets/bytes, `tcp_flags`, `syn_count`, flow start/end, `closed`, **`src_bad`/`dst_bad`** (reputation) |
| `l7_events` | parsed app metadata: HTTP method/host/path/status/UA, TLS SNI/version, DNS qname/qtype, SMTP command, DB system/query |
| `security_events` | detector output: severity, category, src/dst, detail, metric, threshold |
| `host_bandwidth` | per-host rx/tx bytes & packets, internal flag |
| `app_bandwidth` | per-application bytes/packets/flows |
| `iface_util` | per-interface deltas, dropped, bps/pps |
| `summary` | global KPIs: totals, active flows, east-west / north-south bytes |
| `host_bandwidth_1m` (+ MV) | per-minute top-talker rollup for cheap long-range queries |

**Privacy note:** `l7_events` records real hostnames/paths, TLS SNI, DNS query
names, and sampled DB queries — treat it per your data policy.

---

## 7. ClickHouse access & security model

Two operator users (plus the built-in `default`):

| User | Access | Reachable from | Used by |
|---|---|---|---|
| `netmon` (the "root") | full: read/write/DDL + user mgmt | **localhost only** | the collector + admin/CLI on the box |
| `netmon_ro` | **read-only** (`readonly=2`: SELECT only, no writes/DDL) | **anywhere** | vormox / remote clients |
| `default` | password-less | localhost only | — |

ClickHouse listens on `0.0.0.0`, but each user's `<networks>` ACL decides who can
use it — the powerful `netmon` user is rejected from non-loopback addresses, so
only the read-only user works remotely.

**Ports & firewall** (nftables table `netmon_fw`, service `netmon-firewall`):
- **`:8123` HTTP** (and the `/play` console) — **blocked from the network**;
  loopback only (the collector uses it locally).
- **`:9000` native** — open; remote clients (vormox) connect here with the
  read-only user.
- **SSH (22)** and the **stream (:8090)** are never touched. Re-running the
  installer re-applies the firewall.

> ⚠️ The native protocol on `:9000` is **plaintext** by default. For remote reads
> over an untrusted network, terminate over TLS (`:9440`) or a VPN — see §15.

All generated passwords/tokens are in `/opt/netmon/clickhouse.md` (chmod 600).

---

## 8. Real-time stream (SSE)

`StreamServer` serves Server-Sent Events at **`http://<host>:8090/live`** and a
health endpoint at **`/healthz`**. It pushes, in real time and bypassing the DB:
- `stats` / `ifaces` — throughput & per-interface KPIs (every live tick)
- `talkers` / `flows` — top talkers & top flows (every scrape)
- `l7` — each parsed HTTP/TLS/DNS/… record instantly
- `security` — each security event instantly

It is a machine-consumable event stream (no GUI). The reactor is epoll +
non-blocking; slow clients are dropped (per-client send-buffer cap), and the
broadcast queue is bounded — it can never block the collector.

---

## 9. Webhooks

Two outbound HTTPS webhooks (the agent always *pushes*; nothing connects in).

### 9.1 Registration → vormox (install-time, once)
When `--domain` is set, after install the script POSTs the ClickHouse connection
details to `--webhook-url` (default `https://vormox.com/api/webhook`).
- Headers: `Content-Type: application/json`, `X-Netmon-Domain`,
  `X-Netmon-Signature: sha256=<hmac>` (when `--webhook-secret` is set).
- Body includes `clickhouse` (host, `native_port` 9000, `http_remote:false`, db,
  the **read-only** `netmon_ro` user + password) and the `event_webhook` block.
- Full contract: **`docs/vormox-webhook.md`**.

### 9.2 Events → client domain (runtime, real-time)
High-severity events are POSTed to `https://<domain>/api/webhook` as they happen.
- One POST per event; headers `X-Netmon-Event: <category>` and `X-Netmon-Token`.
- Only severity ≥ `min-severity` (default `high`) is sent; everything is in CH.
- Fire-and-forget, bounded queue (drops oldest if the endpoint is down — the DB
  remains source of truth), ~8 s timeout, no retry.
- Full contract for the client endpoint: **`docs/event-webhook.md`**.

---

## 10. IP reputation & allowlist

Two operator-controlled files (one IP or CIDR per line, `#` comments):

- **`/etc/netmon/blocklist.txt`** — known-bad IPs (populate from a threat-intel
  feed, e.g. a cron that rewrites the file). Any flow touching a listed address
  raises a **`blacklist`** event (High → webhooked) and sets `src_bad`/`dst_bad`
  on the `flows` row.
- **`/etc/netmon/allowlist.txt`** — trusted IPs (backup servers, monitoring, DNS
  resolvers, app servers). Listed addresses are **exempt** from the
  false-positive-prone behavioural detectors:

| Allowlist a… | …to stop false |
|---|---|
| backup server / cloud target | `anomaly` (exfil), volumetric |
| monitoring / vuln scanner | `port_scan`, `host_sweep` |
| config-mgmt / orchestration host | `lateral_movement` |
| internal DNS resolver | `dns_abuse` |
| app server (DB connection pools) | `bruteforce` |
| host on a port like 8333/4444 | `cryptomining`, `suspicious_conn` |

Both files are read at startup — edit and `systemctl restart netmon-collector`.

---

## 11. Operations

### Services (systemd)
- `netmon-collector.service` — the collector (`Restart=always`, hardened caps:
  `CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE`).
- `netmon-firewall.service` — applies the nft rule on boot (`netmon_fw` table).
- `clickhouse-server.service` — the database.

### Day-to-day
```bash
systemctl status netmon-collector
journalctl -u netmon-collector -f          # live logs incl. [SECURITY/...] lines
systemctl restart netmon-collector          # reload config / reputation lists

curl -s http://127.0.0.1:8090/healthz       # collector liveness
nft list table inet netmon_fw               # active firewall rules

# local admin query (full user, localhost):
clickhouse-client --user netmon --password '<from clickhouse.md>' --database netmon
```

### Common queries
```sql
SELECT ts, severity, category, src_ip, dst_ip, dst_port, detail
FROM netmon.security_events ORDER BY ts DESC LIMIT 50;

SELECT category, count() FROM netmon.security_events
WHERE ts > now() - INTERVAL 1 HOUR GROUP BY category ORDER BY 2 DESC;

SELECT ts, src_ip, dst_ip, dst_port FROM netmon.flows
WHERE src_bad OR dst_bad ORDER BY ts DESC;          -- reputation hits
```

### Updating the collector (rebuild after a code change)
```bash
cd /tmp && rm -rf netmon && git clone --depth 1 https://github.com/weby-dev/netmon.git
cp -a /tmp/netmon/. /opt/netmon/ && rm -rf /opt/netmon/.git
cd /opt/netmon && make
install -D -m0755 build/collector/netmon-collector /usr/local/bin/netmon-collector
systemctl restart netmon-collector
```
This does **not** touch ClickHouse or regenerate passwords.

### Proxmox VM/CT taps
`deploy/refresh-taps.sh` (installable as a systemd timer) regenerates
`NETMON_IFACES` from current VM/CT interfaces and restarts the collector, so
east-west visibility follows VMs as they come and go.

---

## 12. Reliability & hang-safety

- **Liveness watchdog:** the main loop updates a heartbeat each tick; a watchdog
  thread aborts the process if it stalls beyond `max(180s, interval×30)`, and
  systemd (`Restart=always`) brings it back. Recovers from a true hang with no
  admin action.
- **Bounded ClickHouse I/O:** inserts use `CONNECTTIMEOUT=5`, `TIMEOUT=10`,
  `NOSIGNAL=1`, so a slow/stuck DB is a *bounded, self-recovering* stall, not a
  hang — and never long enough to trip the watchdog.
- **Bounded memory:** the security engine caps per-source/dest maps, per-key
  sets, and prunes the dedup table; the `prev` flow map is pruned each scrape;
  the stream and webhook queues are bounded (drop-oldest).
- **Non-blocking I/O:** the SSE server and webhook sender never block the scrape
  loop.
- **Insert compatibility:** inserts set `input_format_skip_unknown_fields=1`, so a
  newer collector won't break inserts against an older table (and the installer
  runs `ADD COLUMN IF NOT EXISTS` to migrate).

---

## 13. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `apt` says packages have "no installation candidate" | Proxmox enterprise repo 401 and/or a mixed bookworm+trixie state. `setup.sh`/`install.sh` repair this automatically; re-run, or fix the Debian sources to one release + `apt full-upgrade`. |
| ClickHouse service won't start (`CANNOT_LOAD_CONFIG`, "Access to file denied") | the `users.d`/`config.d` files must be readable by the `clickhouse` user — the installer `chown`s them. |
| ClickHouse won't start, `Type=notify`/"protocol" failure | usually a listen-bind issue; the installer sets `<listen_try>1</listen_try>` so an un-bindable IPv6 address is tolerated. |
| `dst_ip` empty / a fix "didn't apply" | the collector is a **compiled binary** — a C++ change only takes effect after a rebuild + `systemctl restart`. Old rows are immutable; only new events change. Verify the running build: `strings /usr/local/bin/netmon-collector \| grep -c "main target"`. |
| Backups/speedtests flagged as DDoS | fixed by the `ddos_min_peers` distributed gate; for edge cases add the hosts to `allowlist.txt`. |
| collector not active after install | almost always `NETMON_IFACES` doesn't match the host — check `journalctl -u netmon-collector`. |

---

## 14. File & directory layout

```
ebpf/                     XDP/eBPF program + shared common.h
collector/
  include/                headers (config, types, security_engine, webhook, …)
  src/                    main.cpp, security_engine.cpp, clickhouse_client.cpp,
                          stream_server.cpp, webhook.cpp, config.cpp, …
clickhouse/schema.sql     ClickHouse schema (TTL rewritten at install)
deploy/
  netmon-collector.service  systemd unit
  netmon-run.sh             env → CLI wrapper (ExecStart)
  refresh-taps.sh           Proxmox tap refresher
  install-clickhouse.sh     standalone CH installer
config/collector.env      env template (installed to /etc/netmon/collector.env)
docs/
  vormox-webhook.md         registration webhook contract
  event-webhook.md          client event webhook contract
setup.sh                  curl-able bootstrap (APT repair + git + clone)
install.sh                full installer
Makefile                  build orchestration (ebpf → skeleton → collector)

# On an installed host:
/usr/local/bin/netmon-collector        the binary
/usr/local/bin/netmon-run.sh           the wrapper
/etc/netmon/collector.env              config (chmod 600)
/etc/netmon/schema.sql                 applied schema
/etc/netmon/blocklist.txt              reputation: known-bad IPs
/etc/netmon/allowlist.txt              reputation: trusted IPs
/opt/netmon/                           deployed source (no .git)
/opt/netmon/clickhouse.md              credentials (chmod 600)
```

---

## 15. Production checklist

Implemented: bounded memory, liveness watchdog, two-user DB model, firewall,
distributed-DDoS gate, IP reputation + allowlist, async webhooks, safe schema
migration.

Recommended next (not yet done):
1. **Git + CI + versioned builds** — stop compiling on prod; ship a tested,
   versioned artifact (and add a `--version`/git-SHA flag).
2. **Encrypt remote ClickHouse** — `:9000` native is plaintext; use TLS (`:9440`)
   or a VPN for vormox, and firewall `:9000` to that path.
3. **"Sensor went dark" alerting** — heartbeat + alert when the collector stops,
   so a crash-loop / kernel-XDP break is noticed.
4. **Detection-engine tests** — synthetic-flow unit tests.
5. **Read-only query limits** — `max_execution_time`/`max_memory_usage` on the
   `netmon_readonly` profile.
6. **Resource/disk guardrails** — `MemoryHigh=` on the unit; cap CH table/parts.
7. **Alert-storm policy** — aggregate/rate-limit re-fires; idempotent client endpoint.
8. **Secret/list file perms** — keep `*.env`, `clickhouse.md`, and the reputation
   lists root-only.
