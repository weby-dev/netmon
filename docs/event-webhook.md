# netmon → client real-time event webhook

In addition to writing everything to ClickHouse, the collector POSTs **important
security events** (attacks, scans, floods) to the client's own endpoint in real
time — by default `https://<domain>/api/webhook` (the `--domain` passed to the
installer). Lower-severity findings are **not** sent here; they stay in the DB.

This is the contract the client endpoint must implement. (It is separate from
the install-time registration webhook to vormox — see `vormox-webhook.md`.)

---

## 1. Request

- **Method:** `POST`, one request **per event** (real time, as detected).
- **URL:** `https://<domain>/api/webhook` (override with `--event-webhook-url`).
- **Headers:**
  | Header | Description |
  |--------|-------------|
  | `Content-Type` | `application/json` |
  | `X-Netmon-Event` | the event category (e.g. `port_scan`, `ddos`) |
  | `X-Netmon-Token` | shared secret — **verify this** to authenticate the sender |
- **Body:** a single JSON event object:

```jsonc
{
  "ts": 1782561600,         // unix seconds (UTC)
  "severity": "high",       // low | medium | high | critical
  "category": "port_scan",  // see list below
  "src_ip": "203.0.113.9",
  "dst_ip": "10.0.0.5",     // may be empty for some categories
  "dst_port": 22,
  "proto": "TCP",
  "detail": "source probed 120 distinct ports in 10s window",
  "metric": 120,            // the measured value that tripped the rule
  "threshold": 50           // the configured threshold
}
```

### Which events arrive here

Only events at/above the configured minimum severity (default **high**):

| Sent (high/critical) | category |
|---|---|
| volumetric DDoS (inbound) | `ddos` |
| outbound DDoS (a VM flooding out) | `ddos_outbound` |
| ICMP flood | `icmp_flood` |
| port scan | `port_scan` |
| host sweep | `host_sweep` |
| brute force / credential stuffing | `bruteforce` |
| lateral movement | `lateral_movement` |
| cryptomining pool connection | `cryptomining` |
| reflection / amplification | `amplification` |

Lower-severity findings (`stealth_scan`, `dns_abuse`, `suspicious_conn`,
`anomaly`) are **DB-only** unless you lower `--event-min-severity`.

---

## 2. Authenticate (verify the token)

Compare `X-Netmon-Token` to the shared secret (from the install's
`clickhouse.md` / `NETMON_EVENT_WEBHOOK_TOKEN`) in constant time; reject if it
doesn't match. Always serve the endpoint over **HTTPS**.

**Node.js (Express):**
```js
app.post('/api/webhook', express.json(), (req, res) => {
  const token = req.get('X-Netmon-Token') || '';
  const ok = token.length === SECRET.length &&
             crypto.timingSafeEqual(Buffer.from(token), Buffer.from(SECRET));
  if (!ok) return res.sendStatus(401);
  const e = req.body;              // { ts, severity, category, src_ip, ... }
  // alert / store / forward to your UI here
  return res.sendStatus(200);
});
```

**Python (Flask):**
```python
@app.post("/api/webhook")
def hook():
    import hmac
    if not hmac.compare_digest(request.headers.get("X-Netmon-Token",""), SECRET):
        abort(401)
    e = request.get_json()         # dict with the event fields
    return ("", 200)
```

---

## 3. Delivery semantics

- **Best-effort, fire-and-forget.** The collector queues events on a background
  thread; it does **not** block monitoring and does **not** retry a failed POST.
- **At-most-once.** If your endpoint is down, events are dropped from the send
  queue (capped at 1000) — but they are **always** in ClickHouse, so treat the DB
  as the source of truth and this webhook as a low-latency alert feed.
- **Respond fast:** the client times out at ~8s (5s connect). Return `2xx` and do
  heavy work asynchronously.
- **De-dupe at the source already happens** (repeated identical alerts are
  suppressed for the detection window), but make your handler idempotent on
  `(category, src_ip, dst_ip, ts)` to be safe.

---

## 4. Security checklist
- HTTPS only; verify `X-Netmon-Token`.
- Don't log the token. Rotate it by re-running the installer with `--event-token`.
- The body contains IPs and detection details — handle per your data policy.
