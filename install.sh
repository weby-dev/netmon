#!/usr/bin/env bash
# install.sh — one-shot bootstrap for netmon on a fresh Proxmox VE (Debian) host.
#
# Designed to be fetched and run on the server. Two equivalent ways:
#
#   # A) clone then run (recommended)
#   apt-get install -y git 2>/dev/null || true
#   git clone https://github.com/weby-dev/netmon.git && cd netmon && ./install.sh
#
#   # B) curl the script standalone — it clones the repo itself
#   curl -fsSL https://raw.githubusercontent.com/weby-dev/netmon/main/install.sh -o install.sh
#   bash install.sh
#
# What it does, in order:
#   1. Fixes Proxmox APT (disables the 401 enterprise repos, enables the free
#      pve-no-subscription repo, de-duplicates Debian sources into one clean
#      deb822 file, completes a half-finished release upgrade, clean re-index).
#   2. Installs build + tooling dependencies.
#   3. Places the project in a dedicated dir (/opt/netmon) and removes .git.
#   4. Builds and installs the collector (binary, wrapper, hardened systemd unit).
#   5. Installs ClickHouse with two users: a full "root" user (localhost only) and
#      a read-only user reachable remotely (what vormox uses, native :9000). Sets
#      7-day retention.
#   6. Firewall (nftables): blocks HTTP :8123 from the network (native :9000 stays
#      open; no IP allowlist). SSH/stream untouched; re-applied on every run.
#   7. Writes all credentials to <dir>/clickhouse.md (chmod 600).
#
# Options:
#   --dir PATH            install dir (default: /opt/netmon)
#   --repo URL            git URL (default: https://github.com/weby-dev/netmon.git)
#   --retention-days N    DB retention in days (default: 7)
#   --domain DOMAIN       this deployment's domain; saved and sent to the webhook
#   --webhook-url URL     registration webhook (default: https://vormox.com/api/webhook)
#   --webhook-secret S    HMAC-SHA256 the webhook body with this shared secret
#   --event-webhook-url U where to POST important events (default: https://<domain>/api/webhook)
#   --event-token S       shared token sent as X-Netmon-Token (generated if unset)
#   --event-min-severity  info|low|medium|high|critical (default: high)
#   --no-clickhouse       skip the ClickHouse install/config
#   --skip-os-setup       skip APT repo fix + dependency install
#   --no-start            install but don't start the collector
#   -h, --help            this help
#
# When --domain is given, after install the script POSTs the ClickHouse
# connection details (host, ports, db, user, password) + domain to the webhook
# so the upstream service (vormox.com) can connect. See docs/vormox-webhook.md.
#
# Run as root.
set -euo pipefail

# --- defaults --------------------------------------------------------------- #
REPO_URL="${NETMON_REPO_URL:-https://github.com/weby-dev/netmon.git}"
INSTALL_DIR="${NETMON_DIR:-/opt/netmon}"
RETENTION_DAYS="${NETMON_RETENTION_DAYS:-7}"
DOMAIN="${NETMON_DOMAIN:-}"
WEBHOOK_URL="${NETMON_WEBHOOK_URL:-https://vormox.com/api/webhook}"
WEBHOOK_SECRET="${NETMON_WEBHOOK_SECRET:-}"
# Real-time event webhook to the CLIENT's own endpoint (important events only).
# URL defaults to https://<domain>/api/webhook; token is generated if unset.
EVENT_WEBHOOK_URL="${NETMON_EVENT_WEBHOOK_URL:-}"
EVENT_WEBHOOK_TOKEN="${NETMON_EVENT_WEBHOOK_TOKEN:-}"
EVENT_MIN_SEVERITY="${NETMON_EVENT_WEBHOOK_MIN_SEVERITY:-high}"
WITH_CLICKHOUSE=1
SKIP_OS_SETUP=0
NO_START=0

CH_DB="netmon"
# Two ClickHouse users:
#   - CH_DB_USER  : full access (read/write/DDL) but LOCALHOST ONLY. Used by the
#                   collector (local writes) and for admin/CLI on the box. This is
#                   the "root" — never reachable from the network.
#   - CH_RO_USER  : SELECT-only, reachable REMOTELY. This is what vormox uses.
CH_DB_USER="netmon"
CH_RO_USER="netmon_ro"

# install destinations
BIN_DST="/usr/local/bin/netmon-collector"
WRAP_DST="/usr/local/bin/netmon-run.sh"
TAPS_DST="/usr/local/bin/netmon-refresh-taps.sh"
ENV_DST="/etc/netmon/collector.env"
SCHEMA_DST="/etc/netmon/schema.sql"
UNIT_DST="/etc/systemd/system/netmon-collector.service"

# --- helpers ---------------------------------------------------------------- #
log()  { printf '\033[1;32m>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "${BASH_SOURCE[0]}"; exit 0; }

gen_pass() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 28 || true; }
sha256_hex() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }

# Distinct Debian codenames currently enabled across the APT sources.
enabled_codenames() {
  { grep -rhsE '^[[:space:]]*Suites:' /etc/apt/sources.list.d/*.sources 2>/dev/null \
      | sed 's/^[[:space:]]*Suites:[[:space:]]*//' || true
    grep -rhsE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null \
      | awk '{print $3}' || true; } \
    | grep -oE '(bullseye|bookworm|trixie|forky)' | sort -u || true
}
codename_rank() { case "$1" in bullseye) echo 1;; bookworm) echo 2;; trixie) echo 3;; forky) echo 4;; *) echo 0;; esac; }

# --- args ------------------------------------------------------------------- #
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)            INSTALL_DIR="$2"; shift ;;
    --repo)           REPO_URL="$2"; shift ;;
    --retention-days) RETENTION_DAYS="$2"; shift ;;
    --domain)            DOMAIN="$2"; shift ;;
    --webhook-url)       WEBHOOK_URL="$2"; shift ;;
    --webhook-secret)    WEBHOOK_SECRET="$2"; shift ;;
    --event-webhook-url) EVENT_WEBHOOK_URL="$2"; shift ;;
    --event-token)       EVENT_WEBHOOK_TOKEN="$2"; shift ;;
    --event-min-severity) EVENT_MIN_SEVERITY="$2"; shift ;;
    --no-clickhouse)  WITH_CLICKHOUSE=0 ;;
    --skip-os-setup)  SKIP_OS_SETUP=1 ;;
    --no-start)       NO_START=1 ;;
    -h|--help)        usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# --- preflight -------------------------------------------------------------- #
[ "$(id -u)" = "0" ]        || die "run as root"
[ "$(uname -s)" = "Linux" ] || die "netmon is Linux/XDP only; this host is $(uname -s)"
command -v apt-get >/dev/null 2>&1 || die "this installer targets Debian/Proxmox (no apt-get found)"

TARGET_CODENAME="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")" || true
[ -n "$TARGET_CODENAME" ] || die "cannot read VERSION_CODENAME from /etc/os-release"

# Event webhook (client endpoint): derive from --domain, auto-generate a token.
if [ -n "$DOMAIN" ] && [ -z "$EVENT_WEBHOOK_URL" ]; then
  EVENT_WEBHOOK_URL="https://${DOMAIN}/api/webhook"
fi
if [ -n "$EVENT_WEBHOOK_URL" ] && [ -z "$EVENT_WEBHOOK_TOKEN" ]; then
  EVENT_WEBHOOK_TOKEN="$(gen_pass)"
fi

#############################################################################
# 1. OS / APT setup
#############################################################################
setup_os() {
  local f keyring c best="" r rank=0 mixed=0

  # Pick the newest codename among the OS and anything still enabled, so a
  # half-finished upgrade consolidates forward, not backward.
  best="$TARGET_CODENAME"; rank="$(codename_rank "$best")"
  for c in $(enabled_codenames); do
    r="$(codename_rank "$c")"
    if [ "$r" -gt "$rank" ]; then rank="$r"; best="$c"; fi
  done
  TARGET_CODENAME="$best"
  if [ "$(enabled_codenames | wc -l | tr -d ' ')" -gt 1 ]; then mixed=1; fi
  log "target Debian release: $TARGET_CODENAME"

  shopt -s nullglob

  # Proxmox repos: disable subscription-only enterprise, enable no-subscription.
  if command -v pveversion >/dev/null 2>&1 || grep -rqs 'proxmox\.com' /etc/apt/ 2>/dev/null; then
    log "normalizing Proxmox APT repositories"
    for f in /etc/apt/sources.list.d/*.sources; do
      if grep -qs 'enterprise\.proxmox\.com' "$f"; then mv "$f" "$f.disabled"; log "  disabled $(basename "$f")"; fi
    done
    for f in /etc/apt/sources.list.d/*.list; do
      if grep -qs 'enterprise\.proxmox\.com' "$f"; then
        cp -n "$f" "$f.netmon-bak" 2>/dev/null || true
        sed -i '/enterprise\.proxmox\.com/ s/^[[:space:]]*deb/#&/' "$f"
        log "  commented enterprise entries in $(basename "$f")"
      fi
    done
    keyring="/usr/share/keyrings/proxmox-archive-keyring.gpg"
    if [ ! -f "$keyring" ]; then
      curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-$TARGET_CODENAME.gpg" \
        -o "$keyring" 2>/dev/null || warn "  could not fetch Proxmox key (relying on trusted.gpg.d)"
    fi
    if ! grep -rqs 'download\.proxmox\.com/debian/pve' /etc/apt/ 2>/dev/null; then
      cat > /etc/apt/sources.list.d/pve-no-subscription.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: $TARGET_CODENAME
Components: pve-no-subscription
Signed-By: $keyring
EOF
      log "  enabled pve-no-subscription ($TARGET_CODENAME)"
    fi
  fi

  # De-duplicate Debian sources: one clean deb822 file, empty the legacy list.
  log "writing a single clean Debian '$TARGET_CODENAME' source (deb822)"
  cp -n /etc/apt/sources.list /root/netmon-sources.list.bak 2>/dev/null || true
  cp -n /etc/apt/sources.list.d/debian.sources /root/netmon-debian.sources.bak 2>/dev/null || true
  cat > /etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: http://deb.debian.org/debian
Suites: $TARGET_CODENAME $TARGET_CODENAME-updates
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: $TARGET_CODENAME-security
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
  : > /etc/apt/sources.list   # now covered by debian.sources

  # Clean re-index (drops any stale/partial lists from the churn above).
  log "refreshing package indexes"
  rm -rf /var/lib/apt/lists/*
  apt-get update || warn "apt-get update reported errors (continuing)"

  if [ "$mixed" = "1" ]; then
    log "half-finished release upgrade detected — running 'apt full-upgrade' (this can take a while)"
    DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
    warn "a reboot is recommended after this run so the new kernel is active"
  fi

  log "installing dependencies"
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git sudo rsync ca-certificates curl gnupg \
    clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
    libcurl4-openssl-dev cmake build-essential pkg-config
}

if [ "$SKIP_OS_SETUP" = "0" ]; then setup_os; else log "skipping OS setup (--skip-os-setup)"; fi

#############################################################################
# 2. Obtain sources -> dedicated dir -> drop .git
#############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/Makefile" ] && [ -d "$SCRIPT_DIR/collector" ]; then
  SRC="$SCRIPT_DIR"
else
  command -v git >/dev/null 2>&1 || die "git is required to fetch the repo (run without --skip-os-setup, or apt-get install git)"
  TMP="$(mktemp -d)"
  log "cloning $REPO_URL"
  git clone --depth 1 "$REPO_URL" "$TMP/netmon"
  SRC="$TMP/netmon"
fi

if [ "$SRC" != "$INSTALL_DIR" ]; then
  log "deploying to $INSTALL_DIR (dedicated dir, .git removed)"
  mkdir -p "$INSTALL_DIR"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude='.git' --exclude='build' "$SRC"/ "$INSTALL_DIR"/
  else
    cp -a "$SRC"/. "$INSTALL_DIR"/
  fi
fi
rm -rf "$INSTALL_DIR/.git"
cd "$INSTALL_DIR"

#############################################################################
# 3. ClickHouse: install, secure, make remote, create users
#############################################################################
CH_DB_PASS=""; CH_RO_PASS=""
install_clickhouse() {
  CH_DB_PASS="$(gen_pass)"; CH_RO_PASS="$(gen_pass)"

  if ! command -v clickhouse-server >/dev/null 2>&1; then
    log "installing ClickHouse (official APT repo)"
    curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
      | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
    local arch; arch="$(dpkg --print-architecture)"
    echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${arch}] https://packages.clickhouse.com/deb stable main" \
      > /etc/apt/sources.list.d/clickhouse.list
    apt-get update \
      -o Dir::Etc::sourcelist="sources.list.d/clickhouse.list" \
      -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
    DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client
  else
    log "ClickHouse already installed — reconfiguring"
  fi

  # Server config: listen on all interfaces (remote access) + keep it light.
  install -d /etc/clickhouse-server/config.d
  cat > /etc/clickhouse-server/config.d/netmon.xml <<'XML'
<clickhouse>
    <listen_host>0.0.0.0</listen_host>
    <!-- tolerate an un-bindable address (e.g. IPv6 ::1 when IPv6 is disabled) -->
    <listen_try>1</listen_try>
    <max_server_memory_usage>2000000000</max_server_memory_usage>
    <mark_cache_size>268435456</mark_cache_size>
    <uncompressed_cache_size>0</uncompressed_cache_size>
</clickhouse>
XML

  # Users:
  #   default      - password-less, localhost only (built-in; kept harmless)
  #   ${CH_DB_USER}  - full access incl. DDL, LOCALHOST ONLY (collector + admin/root)
  #   ${CH_RO_USER}  - SELECT-only, reachable from anywhere (vormox / remote reads)
  # ClickHouse listens on 0.0.0.0, but each user's <networks> ACL decides who can
  # actually use it: the root user is rejected from non-loopback addresses.
  install -d /etc/clickhouse-server/users.d
  cat > /etc/clickhouse-server/users.d/netmon.xml <<XML
<clickhouse>
    <profiles>
        <netmon_readonly>
            <!-- readonly=2: SELECT + per-session SET, but no INSERT/CREATE/ALTER/
                 DROP and the user cannot lower its own readonly. Works with normal
                 clients (readonly=1 rejects clients that send any setting). -->
            <readonly>2</readonly>
            <allow_ddl>0</allow_ddl>
        </netmon_readonly>
    </profiles>
    <users>
        <default>
            <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
        </default>
        <${CH_DB_USER}>
            <password_sha256_hex>$(sha256_hex "$CH_DB_PASS")</password_sha256_hex>
            <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </${CH_DB_USER}>
        <${CH_RO_USER}>
            <password_sha256_hex>$(sha256_hex "$CH_RO_PASS")</password_sha256_hex>
            <networks><ip>::/0</ip></networks>
            <profile>netmon_readonly</profile>
            <quota>default</quota>
        </${CH_RO_USER}>
    </users>
</clickhouse>
XML
  # ClickHouse runs as the 'clickhouse' user — it must be able to read these,
  # or startup fails with "Access to file denied" (CANNOT_LOAD_CONFIG).
  chown clickhouse:clickhouse /etc/clickhouse-server/config.d/netmon.xml \
                              /etc/clickhouse-server/users.d/netmon.xml 2>/dev/null || true
  chmod 640 /etc/clickhouse-server/users.d/netmon.xml

  systemctl enable clickhouse-server >/dev/null 2>&1 || true
  systemctl restart clickhouse-server || true   # don't die here; diagnose below
  log "waiting for ClickHouse to come up"
  local i ok=0
  for i in $(seq 1 60); do
    if clickhouse-client --user "$CH_DB_USER" --password "$CH_DB_PASS" --query "SELECT 1" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" != "1" ]; then
    warn "ClickHouse did not become ready — last errors:"
    tail -n 25 /var/log/clickhouse-server/clickhouse-server.err.log 2>/dev/null \
      || journalctl -u clickhouse-server -n 25 --no-pager 2>/dev/null || true
    die "ClickHouse failed to start (see errors above); fix the cause and re-run: bash $INSTALL_DIR/install.sh --skip-os-setup"
  fi
}

apply_schema_and_retention() {
  log "applying schema with ${RETENTION_DAYS}-day retention"
  mkdir -p "$(dirname "$SCHEMA_DST")"   # /etc/netmon may not exist yet
  # Rewrite every TTL in the schema to the requested retention, install it.
  sed -E "s/INTERVAL[[:space:]]+[0-9]+[[:space:]]+DAY/INTERVAL ${RETENTION_DAYS} DAY/g" \
    "$INSTALL_DIR/clickhouse/schema.sql" > "$SCHEMA_DST"
  clickhouse-client --user "$CH_DB_USER" --password "$CH_DB_PASS" --multiquery < "$SCHEMA_DST" \
    || warn "schema apply reported errors (collector will retry at startup)"

  # Force retention on any pre-existing tables too (CREATE IF NOT EXISTS won't).
  local t
  for t in flows l7_events security_events host_bandwidth app_bandwidth iface_util summary; do
    clickhouse-client --user "$CH_DB_USER" --password "$CH_DB_PASS" \
      --query "ALTER TABLE ${CH_DB}.${t} MODIFY TTL ts + INTERVAL ${RETENTION_DAYS} DAY" 2>/dev/null || true
  done
  clickhouse-client --user "$CH_DB_USER" --password "$CH_DB_PASS" \
    --query "ALTER TABLE ${CH_DB}.host_bandwidth_1m MODIFY TTL minute + INTERVAL ${RETENTION_DAYS} DAY" 2>/dev/null || true

  # Add IP-reputation columns to a pre-existing flows table (no-op if present).
  local col
  for col in "src_bad UInt8 DEFAULT 0" "dst_bad UInt8 DEFAULT 0"; do
    clickhouse-client --user "$CH_DB_USER" --password "$CH_DB_PASS" \
      --query "ALTER TABLE ${CH_DB}.flows ADD COLUMN IF NOT EXISTS ${col}" 2>/dev/null || true
  done
}

# Firewall (nftables). Keep the ClickHouse HTTP port (:8123, incl. the /play
# console) OFF the network — the collector uses it only over loopback, and vormox
# connects with its native client on :9000. Native :9000 stays open, protected by
# the password + the read-only user; there is no IP allowlist. SSH (22) and the
# stream (:8090) are never touched. Applied via a reversible boot-time oneshot and
# re-applied on every run, so re-running setup.sh refreshes the firewall.
setup_firewall() {
  log "configuring firewall (nftables): ClickHouse HTTP :8123 off the network, native :9000 open"
  # Drop any older iptables-based service from a previous version.
  if [ -f /etc/systemd/system/netmon-chfw.service ]; then
    systemctl disable --now netmon-chfw.service 2>/dev/null || true
    rm -f /etc/systemd/system/netmon-chfw.service /usr/local/bin/netmon-chfw.sh
  fi
  if ! command -v nft >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables 2>/dev/null || true
  fi
  command -v nft >/dev/null 2>&1 || { warn "  nft unavailable; skipping firewall"; return 0; }

  # Idempotent ruleset: drop inbound :8123 on every interface except loopback.
  cat > "$INSTALL_DIR/firewall.nft" <<'NFT'
#!/usr/sbin/nft -f
add table inet netmon_fw
delete table inet netmon_fw
table inet netmon_fw {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname != "lo" tcp dport 8123 drop
    }
}
NFT
  if ! nft -c -f "$INSTALL_DIR/firewall.nft" >/tmp/netmon-nft.err 2>&1; then
    warn "  generated nft ruleset failed validation; not applying:"
    sed 's/^/    /' /tmp/netmon-nft.err >&2
    return 0
  fi
  cat > /etc/systemd/system/netmon-firewall.service <<EOF
[Unit]
Description=netmon firewall (block ClickHouse HTTP :8123 from the network)
After=nftables.service network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft) -f ${INSTALL_DIR}/firewall.nft
ExecStop=$(command -v nft) delete table inet netmon_fw

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable netmon-firewall >/dev/null 2>&1 || true
  if systemctl restart netmon-firewall 2>/dev/null; then
    log "  firewall applied — :8123 blocked from network; :9000 open (read-only user remotely)"
  else
    warn "  could not apply firewall (see: systemctl status netmon-firewall)"
  fi
}

if [ "$WITH_CLICKHOUSE" = "1" ]; then install_clickhouse; fi
# Re-apply the firewall on every run where ClickHouse is present (so re-running
# the installer refreshes/restores it), even with --no-clickhouse.
if [ "$WITH_CLICKHOUSE" = "1" ] || command -v clickhouse-server >/dev/null 2>&1; then setup_firewall; fi

#############################################################################
# 4. Build + install the collector
#############################################################################
log "building the collector (make)"
make -C "$INSTALL_DIR"
[ -x "$INSTALL_DIR/build/collector/netmon-collector" ] || die "build failed: collector binary missing"

# Stop/remove a previous install so we deploy cleanly (config preserved).
if [ -f "$UNIT_DST" ] || [ -x "$BIN_DST" ] || systemctl is-enabled --quiet netmon-collector 2>/dev/null; then
  log "existing collector detected — stopping for clean reinstall"
  systemctl stop netmon-collector 2>/dev/null || true
fi

log "installing collector binary, wrapper, and systemd unit"
install -D -m 0755 "$INSTALL_DIR/build/collector/netmon-collector" "$BIN_DST"
install -D -m 0755 "$INSTALL_DIR/deploy/netmon-run.sh"             "$WRAP_DST"
install -D -m 0755 "$INSTALL_DIR/deploy/refresh-taps.sh"           "$TAPS_DST"
install -D -m 0644 "$INSTALL_DIR/deploy/netmon-collector.service"  "$UNIT_DST"

# Now apply schema/retention (needs ClickHouse + binary present is fine).
if [ "$WITH_CLICKHOUSE" = "1" ]; then apply_schema_and_retention; fi

#############################################################################
# 5. Collector config (env)
#############################################################################
set_env() {  # key value
  local k="$1" v="$2"
  if grep -qE "^${k}=" "$ENV_DST" 2>/dev/null; then
    sed -i "s|^${k}=.*|${k}=\"${v}\"|" "$ENV_DST"
  else
    echo "${k}=\"${v}\"" >> "$ENV_DST"
  fi
}

[ -f "$ENV_DST" ] || install -D -m 0644 "$INSTALL_DIR/config/collector.env" "$ENV_DST"

# Sensible interface default if the seeded one wasn't edited.
DETECTED_IFACES="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' \
  | grep -E '^(vmbr[0-9]+|eno[0-9]+|enp[0-9a-z]+|ens[0-9a-z]+|eth[0-9]+)$' | sort -u | tr '\n' ' ' | sed 's/ *$//' || true)"
[ -n "$DETECTED_IFACES" ] && set_env NETMON_IFACES "$DETECTED_IFACES"

if [ "$WITH_CLICKHOUSE" = "1" ]; then
  set_env NETMON_CLICKHOUSE_URL  "http://127.0.0.1:8123"
  set_env NETMON_CLICKHOUSE_DB   "$CH_DB"
  set_env NETMON_CLICKHOUSE_USER "$CH_DB_USER"
  set_env NETMON_CLICKHOUSE_PASS "$CH_DB_PASS"
fi
set_env NETMON_SCHEMA "$SCHEMA_DST"

# IP reputation lists: seed empty templates (operator fills the blocklist from a
# threat feed; allowlist with backup/monitoring/resolver/app-server IPs).
for f in /etc/netmon/blocklist.txt /etc/netmon/allowlist.txt; do
  [ -f "$f" ] || printf '# %s — one IP or CIDR per line; "#" comments allowed.\n' "$(basename "$f")" > "$f"
done
set_env NETMON_BLOCKLIST /etc/netmon/blocklist.txt
set_env NETMON_ALLOWLIST /etc/netmon/allowlist.txt

if [ -n "$DOMAIN" ]; then set_env NETMON_DOMAIN "$DOMAIN"; fi
if [ -n "$EVENT_WEBHOOK_URL" ]; then
  set_env NETMON_EVENT_WEBHOOK_URL          "$EVENT_WEBHOOK_URL"
  set_env NETMON_EVENT_WEBHOOK_TOKEN        "$EVENT_WEBHOOK_TOKEN"
  set_env NETMON_EVENT_WEBHOOK_MIN_SEVERITY "$EVENT_MIN_SEVERITY"
fi
chmod 600 "$ENV_DST"

#############################################################################
# 6. Enable + start
#############################################################################
systemctl daemon-reload
systemctl enable netmon-collector >/dev/null 2>&1 || true
if [ "$NO_START" = "0" ]; then
  log "starting netmon-collector"
  systemctl restart netmon-collector || true
  sleep 1
  if systemctl is-active --quiet netmon-collector; then
    log "netmon-collector is running"
  else
    warn "collector not active — likely NETMON_IFACES in $ENV_DST. Check: journalctl -u netmon-collector -n 40"
  fi
else
  log "installed but not started (--no-start)"
fi

#############################################################################
# 7. Write credentials file
#############################################################################
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -n "$PRIMARY_IP" ] || PRIMARY_IP="<server-ip>"
CRED_FILE="$INSTALL_DIR/clickhouse.md"

if [ "$WITH_CLICKHOUSE" = "1" ]; then
  cat > "$CRED_FILE" <<EOF
# netmon ClickHouse credentials

> Generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC'). Keep this file private.

## CLI access
\`\`\`bash
# on the server: full access (this user is LOCALHOST ONLY)
clickhouse-client --user ${CH_DB_USER} --password '${CH_DB_PASS}' --database ${CH_DB}

# from a remote machine (e.g. vormox): READ-ONLY user
clickhouse-client --host ${PRIMARY_IP} --port 9000 \\
  --user ${CH_RO_USER} --password '${CH_RO_PASS}' --database ${CH_DB}

# then, e.g.:  SHOW TABLES;   SELECT * FROM security_events ORDER BY ts DESC LIMIT 20;
\`\`\`

## Ports
- Native TCP : ${PRIMARY_IP}:9000  — OPEN to the network (vormox / native clients).
                                     Remotely only the read-only user works.
- HTTP       : 127.0.0.1:8123      — BLOCKED from the network by the firewall
                                     (collector + local admin only; no /play remotely).

## Database
- Name       : ${CH_DB}
- Retention  : ${RETENTION_DAYS} days (rows older than this are auto-deleted via table TTL)

## Users
| User            | Access                | Reachable from | Password       |
|-----------------|-----------------------|----------------|----------------|
| ${CH_DB_USER}   | full (read/write/DDL) | localhost only | ${CH_DB_PASS}  |
| ${CH_RO_USER}   | SELECT-only (read)    | anywhere       | ${CH_RO_PASS}  |

- \`${CH_DB_USER}\` is the "root" — used by the collector and for admin on the box.
  It is rejected from non-loopback addresses, so it can't be used remotely.
- \`${CH_RO_USER}\` is what vormox / remote clients use: read-only, no writes/DDL.
- The built-in password-less \`default\` user is also restricted to localhost.

## ⚠️ Security / firewall (managed: nftables \`netmon_fw\`, service \`netmon-firewall\`)
- HTTP :8123 (and the /play console) is **blocked from the network** — loopback
  only. Vormox uses the native protocol, so HTTP isn't needed remotely.
- Native :9000 is **open** (no IP allowlist), but remotely only the read-only
  \`${CH_RO_USER}\` user works; the full \`${CH_DB_USER}\` ("root") and \`default\`
  are localhost-only. A leaked read-only password can read data, not modify it.
- SSH (22) and the stream (:8090) are never touched. Re-running the installer
  re-applies this firewall.
\`\`\`bash
nft list table inet netmon_fw            # show the rule
systemctl disable --now netmon-firewall  # remove it (reopen :8123)
\`\`\`
Keep all passwords secret.
EOF
  if [ -n "$EVENT_WEBHOOK_URL" ]; then
    cat >> "$CRED_FILE" <<EOF

## Real-time event webhook (important events → your endpoint)
- Endpoint     : ${EVENT_WEBHOOK_URL}
- Auth header  : X-Netmon-Token: ${EVENT_WEBHOOK_TOKEN}
- Min severity : ${EVENT_MIN_SEVERITY}  (attacks / scans / floods; lower severities are stored in ClickHouse only)
- The collector POSTs one JSON event per important alert. Your endpoint must
  accept POST application/json and return 2xx. See docs/event-webhook.md.
EOF
  fi
  chmod 600 "$CRED_FILE"
  log "credentials written to $CRED_FILE"
fi

#############################################################################
# 8. Register with the webhook (vormox.com) — only when --domain is given
#############################################################################
# Posts the ClickHouse connection details + domain so the upstream service can
# connect. Body is JSON; if --webhook-secret is set, an HMAC-SHA256 of the exact
# body is sent in X-Netmon-Signature for verification. See docs/vormox-webhook.md.
send_webhook() {
  [ -n "$DOMAIN" ] || { log "no --domain given; skipping webhook registration"; return 0; }
  if [ "$WITH_CLICKHOUSE" != "1" ]; then
    warn "webhook skipped: --domain set but ClickHouse was not installed (--no-clickhouse)"; return 0
  fi
  local ts payload sig
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Compact single-line JSON (kept byte-exact for signing).
  # vormox connects remotely → it gets the READ-ONLY user, never the root.
  payload="{\"event\":\"netmon.installed\",\"domain\":\"${DOMAIN}\",\"installed_at\":\"${ts}\",\"clickhouse\":{\"host\":\"${PRIMARY_IP}\",\"native_port\":9000,\"http_port\":8123,\"http_remote\":false,\"database\":\"${CH_DB}\",\"user\":\"${CH_RO_USER}\",\"password\":\"${CH_RO_PASS}\",\"access\":\"read-only\"},\"event_webhook\":{\"url\":\"${EVENT_WEBHOOK_URL}\",\"token\":\"${EVENT_WEBHOOK_TOKEN}\",\"min_severity\":\"${EVENT_MIN_SEVERITY}\"}}"

  local hdr=(-H "Content-Type: application/json" -H "X-Netmon-Domain: ${DOMAIN}")
  if [ -n "$WEBHOOK_SECRET" ] && command -v python3 >/dev/null 2>&1; then
    sig="$(printf '%s' "$payload" | S="$WEBHOOK_SECRET" python3 -c \
      'import sys,os,hmac,hashlib; print(hmac.new(os.environ["S"].encode(), sys.stdin.buffer.read(), hashlib.sha256).hexdigest())')"
    hdr+=(-H "X-Netmon-Signature: sha256=${sig}")
  elif [ -n "$WEBHOOK_SECRET" ]; then
    warn "  python3 missing — sending webhook UNSIGNED"
  fi

  log "registering with ${WEBHOOK_URL} (domain: ${DOMAIN})"
  if curl -fsS --max-time 20 -X POST "${WEBHOOK_URL}" "${hdr[@]}" --data-binary "$payload" >/dev/null; then
    log "  webhook delivered"
  else
    warn "  webhook POST failed (check connectivity to ${WEBHOOK_URL})."
    warn "  re-run later to regenerate creds + resend: bash $INSTALL_DIR/install.sh --skip-os-setup --domain $DOMAIN"
  fi
}
send_webhook

#############################################################################
# Done
#############################################################################
cat <<EOF

$(log "install complete")

  install dir : $INSTALL_DIR   (.git removed)
  collector   : systemctl status netmon-collector   |  journalctl -u netmon-collector -f
  live stream : http://${PRIMARY_IP}:8090/live
EOF
if [ "$WITH_CLICKHOUSE" = "1" ]; then
cat <<EOF
  ClickHouse  : local admin '${CH_DB_USER}' (localhost) · remote read-only '${CH_RO_USER}'
  retention   : ${RETENTION_DAYS} days (creds in $CRED_FILE)
EOF
fi
cat <<EOF

Next steps:
  1. Verify NETMON_IFACES in $ENV_DST matches this host's uplinks/bridges/taps.
  2. If you ran a release upgrade above, reboot, then: systemctl restart netmon-collector
  3. Vormox connects to ${PRIMARY_IP}:9000 (native) as the read-only user in
     $CRED_FILE. HTTP :8123 is firewalled off the network (local only).
     Re-running this installer re-applies the firewall.
EOF
