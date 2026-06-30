# Firewall — view & modify

netmon manages a small, reversible **nftables** firewall whose only job is to
protect ClickHouse. This guide explains what it does and how to change it.

> netmon is a passive monitor — this firewall is **not** about blocking attack
> traffic. It only controls who can reach the ClickHouse ports on this host.

---

## What it does (default)

| Item | Value |
|---|---|
| nftables table | `inet netmon_fw` |
| systemd service | `netmon-firewall.service` (oneshot, `RemainAfterExit`) |
| ruleset file | `/opt/netmon/firewall.nft` |
| Rule | drop inbound **TCP :8123** on every interface **except loopback** |

Effect:
- **`:8123` HTTP** (and the `/play` console) — **blocked from the network**, usable
  only over loopback (the collector). 
- **`:9000` native** — **open** to the network; remotely only the read-only
  `netmon_ro` user works (the full `netmon` user is localhost-only by ACL).
- **SSH (22)** and the **SSE stream (:8090)** — **untouched**, so this can never
  lock you out.

It is re-applied on boot and **every time you re-run the installer**.

---

## View it

```bash
systemctl status netmon-firewall
nft list table inet netmon_fw          # the live rules
cat /opt/netmon/firewall.nft           # the source ruleset
```

---

## Modify it

> ⚠️ **`/opt/netmon/firewall.nft` is overwritten every time you run the
> installer.** For changes that must survive an upgrade, use the
> [durable custom rules](#durable-custom-rules-survive-reinstall) approach below
> instead of editing that file.

For a quick/temporary change you can edit the file and reload:
```bash
nano /opt/netmon/firewall.nft
nft -c -f /opt/netmon/firewall.nft     # validate first (never apply a broken set)
systemctl restart netmon-firewall      # apply
```

### Lock the native port :9000 to specific source IPs
By default `:9000` is open (password + read-only protected). To allow it only
from trusted sources (e.g. your vormox egress IP), add a `netmon_custom` table
(see durable approach) with:
```
table inet netmon_custom {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr { 203.0.113.10, 198.51.100.0/24 } tcp dport 9000 accept
        ip6 saddr { 2001:db8::/48 }                 tcp dport 9000 accept
        tcp dport 9000 drop
    }
}
```
(IPv6 line optional — drop it if you have no v6 sources.)

### Also restrict the SSE stream :8090
Add inside the same custom chain:
```
        ip saddr { <your.app.cidr> } tcp dport 8090 accept
        tcp dport 8090 drop
```

### Open :8123 again (e.g. you want HTTP access)
Either disable the netmon firewall entirely (below), or remove just the 8123
drop by editing `/opt/netmon/firewall.nft` and reloading.

### Disable / remove the firewall completely
```bash
systemctl disable --now netmon-firewall      # removes the netmon_fw table
```
This reopens `:8123`. To put it back: `systemctl enable --now netmon-firewall`.

---

## Durable custom rules (survive reinstall)

Because the installer rewrites `/opt/netmon/firewall.nft`, keep your own rules in
a **separate table and service** so they aren't clobbered:

```bash
# 1. your own ruleset, in its own table
cat > /etc/netmon/firewall-custom.nft <<'NFT'
#!/usr/sbin/nft -f
add table inet netmon_custom
delete table inet netmon_custom
table inet netmon_custom {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr { 203.0.113.10 } tcp dport 9000 accept   # allow vormox only
        tcp dport 9000 drop
    }
}
NFT

# 2. validate
nft -c -f /etc/netmon/firewall-custom.nft

# 3. a tiny service to apply it on boot
cat > /etc/systemd/system/netmon-firewall-custom.service <<'EOF'
[Unit]
Description=netmon custom firewall rules
After=nftables.service network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/netmon/firewall-custom.nft
ExecStop=/usr/sbin/nft delete table inet netmon_custom
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable --now netmon-firewall-custom
```

Both tables evaluate independently; in nftables a **`drop` in any chain wins**, so
your custom drops take effect alongside the netmon table (and alongside the
Proxmox `pve-firewall`, if enabled).

---

## Notes & safety

- **Validate before applying:** always `nft -c -f <file>` first. A bad ruleset is
  rejected and nothing changes.
- **You can't lock yourself out via netmon:** it never adds rules for SSH (22).
- **Reversible:** every table is removed cleanly by stopping its service
  (`ExecStop=nft delete table …`).
- **IPv6:** if IPv6 is disabled on the host, drop the `ip6 …` lines.
- **Native `:9000` is plaintext.** Restricting source IPs helps, but for remote
  access over an untrusted network prefer TLS (`:9440`) or a VPN — see the
  Production checklist in [README.md](README.md#15-production-checklist).
```
