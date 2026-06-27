# netmon → vormox registration webhook

When a netmon collector is installed with a `--domain`, the installer sends a
one-time HTTP **POST** to a webhook URL (default `https://vormox.com/api/webhook`)
with the ClickHouse connection details for that deployment. vormox stores these
and uses them to connect to the customer's ClickHouse and read the netmon data.

This document is the contract vormox must implement on the receiving end.

---

## 1. Request

- **Method:** `POST`
- **URL:** your endpoint, e.g. `https://vormox.com/api/webhook`
- **Headers:**
  | Header | Always | Description |
  |--------|--------|-------------|
  | `Content-Type` | yes | `application/json` |
  | `X-Netmon-Domain` | yes | the deployment domain (same as `domain` in body) |
  | `X-Netmon-Signature` | only if a shared secret is configured | `sha256=<hex>` — HMAC-SHA256 of the **raw request body** using the shared secret |

- **Body:** a single-line JSON object (UTF-8). Treat the **raw bytes** as the
  thing that was signed — do not re-serialize before verifying the signature.

### Body schema

```jsonc
{
  "event": "netmon.installed",      // string  - event type
  "domain": "acme.com",             // string  - customer domain (--domain)
  "installed_at": "2026-06-28T12:00:00Z", // string - UTC ISO-8601 timestamp
  "clickhouse": {
    "host": "203.0.113.10",         // string  - server IP advertised by the installer
    "native_port": 9000,            // number  - ClickHouse native protocol (USE THIS)
    "http_port": 8123,              // number  - HTTP port
    "http_remote": false,           // bool    - is HTTP reachable from the network?
    "database": "netmon",           // string  - database name
    "user": "netmon",               // string  - username
    "password": "•••••••"           // string  - password (secret)
  }
}
```

### Field notes

- **`clickhouse.native_port` (9000)** is the one to connect with. By default the
  installer firewalls the HTTP port from the network (`http_remote: false`), so
  connect using the **native protocol**, not HTTP, unless `http_remote` is `true`.
- **`host`** is the IP the server detected for itself. If the customer reaches
  the box via the domain instead, you may connect to `domain:native_port`.
- **`password`** is a secret — store encrypted, never log it.

---

## 2. Verifying the signature (recommended)

If the installer is run with `--webhook-secret <S>` (a value you share with the
customer out-of-band), the request includes:

```
X-Netmon-Signature: sha256=<hex>
```

where `<hex>` = `HMAC_SHA256(secret = S, message = raw_request_body)`.

Compute the same HMAC over the raw body and compare in constant time. Reject the
request if they differ (or if the header is missing while you require it).

**Node.js (Express):**
```js
const crypto = require('crypto');
// IMPORTANT: capture the raw body, e.g. express.json({ verify:(req,_,buf)=>{req.rawBody=buf;} })
app.post('/api/webhook', (req, res) => {
  const sig = (req.get('X-Netmon-Signature') || '').replace(/^sha256=/, '');
  const expected = crypto.createHmac('sha256', SECRET).update(req.rawBody).digest('hex');
  const ok = sig.length === expected.length &&
             crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) return res.status(401).json({ error: 'bad signature' });

  const { domain, clickhouse } = JSON.parse(req.rawBody.toString('utf8'));
  // upsert by domain; store clickhouse creds encrypted
  return res.status(200).json({ ok: true });
});
```

**Python (Flask):**
```python
import hmac, hashlib
from flask import request, abort, jsonify

@app.post("/api/webhook")
def webhook():
    raw = request.get_data()  # raw bytes, do not re-serialize
    sig = request.headers.get("X-Netmon-Signature", "").removeprefix("sha256=")
    expected = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        abort(401)
    data = request.get_json()
    # upsert by data["domain"]; store data["clickhouse"] encrypted
    return jsonify(ok=True), 200
```

If no secret is configured the `X-Netmon-Signature` header is absent; in that
case authenticate by other means (allow-list the source IP, mTLS, etc.).

---

## 3. Response & retries

- Return **HTTP 200** (any 2xx) on success. The installer treats non-2xx /
  timeout as failure and logs a retry hint; it does **not** auto-retry.
- Be **idempotent**: key on `domain`. The same domain may be sent again if the
  install is re-run (e.g. after a failed delivery) — and the **credentials may
  change** on a re-run, so always overwrite the stored creds with the latest.
- Respond within ~20s (installer timeout).

---

## 4. Connecting to ClickHouse from vormox

Use the native protocol on `native_port` (9000):

- **clickhouse-client:** `clickhouse-client --host <host> --port 9000 --user <user> --password <pw> --database netmon`
- **Python (clickhouse-driver):** `Client(host, port=9000, user=user, password=pw, database='netmon')`
- **Go (clickhouse-go):** DSN `clickhouse://user:pw@host:9000/netmon`
- **Node (@clickhouse/client):** that client speaks HTTP (8123) — which is
  firewalled by default; either use a native-protocol driver, or ask the
  customer to allow your IP to `http_port` and set `http_remote: true`.

Tables available in the `netmon` database: `flows`, `l7_events`,
`security_events`, `host_bandwidth`, `app_bandwidth`, `iface_util`, `summary`,
`host_bandwidth_1m`. Data is retained ~7 days (configurable).

Example read:
```sql
SELECT category, count() FROM netmon.security_events
WHERE ts > now() - INTERVAL 1 HOUR GROUP BY category ORDER BY 2 DESC;
```

---

## 5. Security checklist

- Serve the webhook over **HTTPS** only.
- Require and verify `X-Netmon-Signature` (set a per-customer `--webhook-secret`).
- Store the ClickHouse password **encrypted at rest**; never log the body.
- Restrict ClickHouse exposure: the customer should firewall `native_port` to
  vormox's egress IPs (see the security note in their `clickhouse.md`).
