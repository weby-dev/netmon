# netmon — XDP/eBPF traffic monitor for Proxmox

Flow-level network monitoring built on **XDP/eBPF** (kernel data path) and a
**C++ collector** (userspace) that exposes the data two ways:

1. **A real-time web stream** (Server-Sent Events) served directly by the
   collector — consume it from your own project. No GUI, no dashboard.
2. **ClickHouse** storage for history/analytics.

```
        ┌─────────────┐  flow_map / ringbuf   ┌────────────────────┐
 NIC ───▶  XDP/eBPF   │ ────────────────────▶ │   C++ collector     │
 tap ───▶  (kernel)   │  per-CPU stat maps    │  - delta + enrich   │
 veth──▶  xdp_monitor │                       │  - app classify     │
        └─────────────┘                       │  - L7 DPI parse     │
                                              │  - security engine   │
                                              │  - aggregator        │
                                              └─────┬───────────┬────┘
                       REAL-TIME (no DB)            │           │  batched
                  embedded SSE server  ◀────────────┘           ▼  JSONEachRow
                  http://host:8090/live                 ┌────────────────┐
                          │                             │   ClickHouse   │
                          ▼                             │  (history/SQL) │
                 ┌──────────────────┐                  └────────────────┘
                 │   YOUR PROJECT   │
                 │ (EventSource /   │
                 │  curl / consumer)│
                 └──────────────────┘
```

> ⚠️ This is Linux/Proxmox code — XDP needs a recent Linux kernel. It is **not**
> meant to build or run on macOS. Build and run it on the Proxmox host.

---

## Feature coverage

| Requirement | Where it's implemented |
|---|---|
| **Real-time web stream** (consume in your project, no DB in the path) | `collector/src/stream_server.cpp` — SSE on `:8090/live` |
| **Traffic statistics** (src/dst IP, src/dst port, protocol, packet & byte counts, flow start/end) | `ebpf/xdp_monitor.bpf.c` (`flow_map`) → stream `flows` + `flows` table |
| **Bandwidth per host** | `Aggregator` → stream `talkers` + `host_bandwidth` table |
| **Bandwidth per application** | `app_classifier.cpp` + `Aggregator` → `app_bandwidth` table |
| **Top talkers** | `Aggregator::build` → stream `talkers` |
| **Interface utilisation** | `if_stats_map` + `Aggregator` → stream `ifaces` + `iface_util` table |
| **DDoS detection (inbound)** | `SecurityEngine` (pps + SYN/s per destination) → stream `security` |
| **DDoS detection (outbound, per VM)** | `SecurityEngine` (pps + SYN/s per internal source → names the offending VM) |
| **ICMP flood** | `SecurityEngine` (ICMP pps per destination) |
| **Port scanning detection** | `SecurityEngine` (distinct dst ports per source) |
| **Stealth scans (NULL/FIN/XMAS)** | `SecurityEngine` (TCP flag-pattern heuristics) |
| **Host sweep** | `SecurityEngine` (distinct hosts per source) |
| **Brute force / credential stuffing** | `SecurityEngine` (conn attempts per src→service port) |
| **Lateral movement** | `SecurityEngine` (internal fan-out on admin ports RDP/SMB/SSH/WinRM) |
| **DNS abuse / tunnelling** | `SecurityEngine` (DNS query-rate spike per source) |
| **Reflection / amplification** | `SecurityEngine` (large inbound from amplifier ports) |
| **Cryptomining** | `SecurityEngine` (outbound to known mining-pool ports) |
| **Suspicious connections / exfil** | `SecurityEngine` (known-bad ports, large internal→external) |
| **East-west visibility** | attach XDP to VM `tap`/CT `veth` interfaces; `direction` field |
| **HTTP/HTTPS** | kernel payload sampling + `l7_parser` (method, host, path, **TLS SNI**) |
| **DNS** | `l7_parser` (qname, qtype) |
| **SMTP** | `l7_parser` (EHLO/MAIL/RCPT/banner) |
| **Database traffic** | `l7_parser` (MySQL/PostgreSQL/MongoDB/Redis fingerprints) |
| **Custom application flows** | extend the port tables in `app_classifier.cpp` / hints in `l7_hint_for` |
| **Inline DDoS mitigation** | `blocklist_map` → `XDP_DROP` (optional) |

---

## How it works

### 1. XDP/eBPF data path (`ebpf/xdp_monitor.bpf.c`)
Runs on every received packet **before** the kernel network stack:

- Parses Ethernet (+ up to two VLAN tags) / IPv4 / IPv6 / TCP / UDP / ICMP.
- Maintains a 5-tuple **flow table** (`BPF_MAP_TYPE_LRU_HASH`, 1M entries) with
  packet/byte counters, first/last timestamps and accumulated TCP flags.
- Maintains **per-interface** counters (`if_stats_map`) and **global per-CPU**
  counters for utilisation.
- For the first few packets of L7-interesting flows (HTTP/TLS/DNS/SMTP/DB
  ports) it copies up to 256 payload bytes into a **ring buffer** for userspace
  DPI — this is where TLS SNI / HTTP Host / DNS qname come from.
- Optional **inline mitigation**: any source IPv4 present in `blocklist_map` is
  `XDP_DROP`'d at line rate; everything else is `XDP_PASS`.

### 2. C++ collector (`collector/`)
- Loads & attaches the program with **libbpf** (skeleton generated by
  `bpftool gen skeleton`).
- A **ring-buffer thread** drains L7 samples and parses them (`l7_parser.cpp`),
  pushing each to the stream **instantly** and queuing it for ClickHouse.
- The **main loop** has two cadences:
  - a fast **live tick** (`--live-interval`, default 1s) reads the cheap
    interface/global counters and pushes throughput KPIs to the stream;
  - a **full scrape** (`--interval`, default 2s) reads the flow map, computes
    per-flow deltas, classifies the application, tags east-west vs north-south,
    runs the aggregator + security engine, pushes top talkers/flows + alerts to
    the stream, and **batch-inserts** to ClickHouse.

### 3. Real-time stream (`collector/src/stream_server.cpp`)
An embedded, dependency-free **epoll/SSE server** inside the collector
(default port `8090`):

- `GET /live` → `text/event-stream` with the named events documented below.
- `GET /healthz` → `{"ok":true,"clients":N}`.
- One reactor thread owns all sockets + per-client buffers; collector threads
  call `broadcast()` (queue + `eventfd` wakeup). Slow consumers that exceed an
  8 MiB buffer are dropped, so a stuck client can't stall the collector.
- `Access-Control-Allow-Origin: *` so a browser `EventSource` on another origin
  can read it. **No GUI is served — this is a pure event stream.**

### 4. ClickHouse storage (`clickhouse/schema.sql`)
`MergeTree` tables partitioned by day with TTLs: `flows`, `l7_events`,
`security_events`, `host_bandwidth`, `app_bandwidth`, `iface_util`, `summary`,
plus a `host_bandwidth_1m` rollup materialized view. The collector applies the
schema automatically at startup, then batch-inserts via the HTTP interface.

---

## The web stream — consuming it in your project

Connect to `http://<host>:8090/live`. It's standard SSE: each message has an
`event:` name and a single-line JSON `data:` payload. Event types:

| Event | Cadence | Payload |
|---|---|---|
| `stats` | every `--live-interval` (1s) | object — overall throughput KPIs |
| `ifaces` | every live tick (1s) | array — per-interface utilisation |
| `talkers` | every `--interval` (2s) | array — top talkers by bytes |
| `flows` | every `--interval` (2s) | array — top active flows this interval |
| `l7` | **instant** (as parsed) | object — one HTTP/TLS/DNS/SMTP/DB record |
| `security` | **instant** (as detected) | object — one security alert |

### Payload schemas

`stats`
```json
{"ts":1718870400,"bps":48213000.0,"pps":5120.0,"interval_bytes":6026625,
 "interval_packets":5120,"active_flows":318,"east_west_bytes":104857,
 "north_south_bytes":5921768,"clients":2}
```

`ifaces` (array)
```json
[{"iface":"eno1","bps":40112000.0,"pps":4200.0,"d_bytes":5014000,
  "d_packets":4200,"dropped":0}]
```

`talkers` (array)
```json
[{"ip":"10.0.0.21","total_bytes":94371840,"total_packets":68000}]
```

`flows` (array)
```json
[{"src_ip":"10.0.0.21","src_port":51514,"dst_ip":"1.1.1.1","dst_port":443,
  "proto":"TCP","app":"https","direction":"north-south","d_bytes":1048576,
  "d_packets":820,"bytes":20971520,"packets":16000}]
```

`l7` (object — only the fields relevant to `l7_proto` are populated)
```json
{"ts":1718870400,"src_ip":"10.0.0.21","dst_ip":"8.8.8.8","src_port":40012,
 "dst_port":53,"proto":"UDP","l7_proto":"dns","http_method":"","http_host":"",
 "http_path":"","http_status":"","tls_sni":"","dns_qname":"example.com",
 "dns_qtype":"A","smtp_command":"","db_system":""}
```

`security` (object)
```json
{"ts":1718870400,"severity":"critical","category":"ddos","src_ip":"",
 "dst_ip":"10.0.0.5","dst_port":0,"proto":"","detail":"SYN flood: 14200 SYN/s toward host",
 "metric":14200,"threshold":10000}
```

### Example consumers

**curl** (quick check):
```bash
curl -N http://<host>:8090/live
```

**Browser / Node (EventSource):**
```js
const es = new EventSource("http://<host>:8090/live");
es.addEventListener("stats",    e => console.log("stats", JSON.parse(e.data)));
es.addEventListener("flows",    e => render(JSON.parse(e.data)));
es.addEventListener("l7",       e => onDpi(JSON.parse(e.data)));
es.addEventListener("security", e => alertUser(JSON.parse(e.data)));
```

**Python** (no extra deps — parse the SSE framing yourself):
```python
import json, urllib.request
with urllib.request.urlopen("http://<host>:8090/live") as r:
    event = None
    for raw in r:
        line = raw.decode().rstrip("\n")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data = json.loads(line[5:].strip())
            print(event, data)
```

---

## Build (on the Proxmox host)

Proxmox VE 8 ships a 6.x kernel which satisfies the XDP/ring-buffer/
`bpf_xdp_load_bytes` requirements (kernel ≥ 5.18).

```bash
apt-get update
apt-get install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
                   libcurl4-openssl-dev cmake build-essential pkg-config

# generate the BTF header for THIS kernel, build eBPF + skeleton + collector
make            # = make vmlinux (if missing) -> ebpf -> skeleton -> collector

# binary lands at build/collector/netmon-collector
```

If `/sys/kernel/btf/vmlinux` is absent (no `CONFIG_DEBUG_INFO_BTF`), install
`pve-headers` / a matching `vmlinux.h` and run `make vmlinux`.

---

## Run

> **Deployment model:** everything runs **bare-metal on the Proxmox host** — no
> Docker, no VM. The collector must be on the host (XDP needs the host kernel +
> NICs), and ClickHouse is installed natively alongside it.

### ClickHouse (storage, native)
Uses ClickHouse's own APT repo, so it works on any Proxmox/Debian release
(bookworm, trixie, …) regardless of the host's other repos:
```bash
sudo bash deploy/install-clickhouse.sh        # adds repo, installs, starts, caps RAM
```
The script refreshes **only** the ClickHouse source list, so a broken or
unauthenticated host repo (e.g. the Proxmox *enterprise* repo returning `401`
without a subscription) won't block it.
This listens on `127.0.0.1:8123` (HTTP) and `:9000` (native), with the default
user and no password — matching the collector defaults. The collector creates
the `netmon` database + tables on startup.

> ClickHouse can be RAM-hungry; the install script drops a
> `config.d/netmon-limits.xml` capping server memory (default 2 GiB) since this
> is a hypervisor. Tune it for your host. If you'd rather not run storage on the
> host at all, point `--clickhouse` at a ClickHouse on another machine — only
> the collector has to live on the Proxmox host.

### Collector (on the host, as root)
```bash
sudo NETMON_SCHEMA=clickhouse/schema.sql \
  build/collector/netmon-collector \
    --iface vmbr0 --iface eno1 \
    --iface tap101i0 --iface tap102i0 \      # ← east-west: one per VM
    --clickhouse http://127.0.0.1:8123 --db netmon \
    --interval 2 --live-interval 1 \
    --stream-port 8090 --verbose
```

- **Web stream:** `http://<host>:8090/live` — point your project at it.
- **History:** query ClickHouse directly (`clickhouse-client`, or the HTTP
  interface on `:8123`). See `clickhouse/schema.sql` for table layouts.

### Stream-only, no database
The live path needs no DB. Run without ClickHouse (insert errors are logged and
ignored; the stream is unaffected):
```bash
sudo build/collector/netmon-collector --iface vmbr0 --iface tap101i0 \
     --stream-port 8090 --live-interval 1 --interval 2
```

### As a service
```bash
sudo make install                          # binary + schema + unit + env
sudo install -m0755 deploy/netmon-run.sh        /usr/local/bin/netmon-run.sh
sudo install -m0755 deploy/refresh-taps.sh      /usr/local/bin/netmon-refresh-taps.sh
sudoedit /etc/netmon/collector.env         # set NETMON_IFACES, stream port, etc.
sudo systemctl enable --now netmon-collector
```

---

## East-west traffic visibility on Proxmox (important)

XDP attached to the **physical NIC only sees north-south** traffic. VM-to-VM
traffic on the same Linux bridge never reaches the NIC, so to see it you must
attach to the **per-VM `tap` interfaces** (and per-CT `veth`). Each tap carries
exactly one guest's traffic in both directions, so attaching to all taps gives
full east-west visibility; the collector tags each flow `east-west` (both
endpoints internal per `--internal_cidrs`) or `north-south`.

Because VMs start/stop, `deploy/refresh-taps.sh` rediscovers `tap*/veth*`
interfaces and restarts the collector. Wire it to a systemd timer or a Proxmox
hookscript.

Attach mode is `skb` (generic) by default because tap/veth/bridge devices don't
support native XDP; use `--mode native` only on capable physical NICs.

---

## Inline DDoS mitigation (optional)

The security engine only *detects* by default. To also *block*, push offending
source IPv4s into `blocklist_map` — the XDP program then drops them in-kernel:
```bash
# block 203.0.113.7 (hex, network byte order key)
bpftool map update name blocklist_map key hex 07 71 00 cb value hex 01
```

---

## Security note on the stream endpoint

The SSE server binds `0.0.0.0:8090` with open CORS and **no authentication** —
fine on a trusted management network. For exposed deployments, restrict
`--stream-bind`, firewall the port, or front it with a reverse proxy
(nginx/Caddy) that adds TLS + auth.

---

## Tuning & extension

- **More applications / custom flows** — add ports to the tables in
  `collector/src/app_classifier.cpp` and DPI hints in `l7_hint_for()`
  (`ebpf/xdp_monitor.bpf.c`).
- **Detection thresholds** — `--ddos-pps/--ddos-syn/--ddos-out-pps/--ddos-out-syn/
  --icmp-flood/--scan-ports/--scan-hosts/--bruteforce/--dns-rate/--lateral-hosts`
  or the matching `NETMON_*` env vars in `collector.env`.
- **Stream cadence** — `--live-interval` (KPIs) and `--interval` (flows/DB).
- **Retention** — adjust the `TTL` clauses in `clickhouse/schema.sql`.
- **Flow table size** — `MAX_FLOWS` in `ebpf/common.h` (LRU evicts oldest).

---

## Layout

```
ebpf/        xdp_monitor.bpf.c, common.h (shared kernel/user types), vmlinux.h*
collector/   C++ control plane:
             include/ , src/
               bpf_loader        libbpf load/attach + map access
               app_classifier    port -> application/category
               l7_parser         HTTP / TLS-SNI / DNS / SMTP / DB DPI
               security_engine    DDoS / scan / sweep / anomaly detection
               aggregator         top talkers, per-host/app bw, iface util
               stream_server      embedded SSE web stream (/live)
               clickhouse_client  batched JSONEachRow inserts
               json               shared single-line JSON builder
clickhouse/  schema.sql           tables + rollup MV (auto-applied)
deploy/      systemd unit, run wrapper, tap refresher, install-clickhouse.sh
config/      collector.env
Makefile     eBPF + skeleton + collector orchestration
```
`*` generated per-kernel.
