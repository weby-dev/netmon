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
#   5. Installs ClickHouse, makes it remotely accessible, creates a DB user and
#      a GUI/admin user with generated passwords, and sets 7-day retention.
#   6. Writes all credentials to <dir>/clickhouse.md (chmod 600).
#
# Options:
#   --dir PATH            install dir (default: /opt/netmon)
#   --repo URL            git URL (default: https://github.com/weby-dev/netmon.git)
#   --retention-days N    DB retention in days (default: 7)
#   --no-clickhouse       skip the ClickHouse install/config
#   --skip-os-setup       skip APT repo fix + dependency install
#   --no-start            install but don't start the collector
#   -h, --help            this help
#
# Run as root.
set -euo pipefail

# --- defaults --------------------------------------------------------------- #
REPO_URL="${NETMON_REPO_URL:-https://github.com/weby-dev/netmon.git}"
INSTALL_DIR="${NETMON_DIR:-/opt/netmon}"
RETENTION_DAYS="${NETMON_RETENTION_DAYS:-7}"
WITH_CLICKHOUSE=1
SKIP_OS_SETUP=0
NO_START=0

CH_DB="netmon"
CH_DB_USER="netmon"     # used by the collector
CH_GUI_USER="admin"     # used for the web GUI / SQL admin

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
CH_DB_PASS=""; CH_GUI_PASS=""
install_clickhouse() {
  CH_DB_PASS="$(gen_pass)"; CH_GUI_PASS="$(gen_pass)"

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

  # Users: lock the password-less 'default' user to localhost; create a
  # collector user and an admin/GUI user reachable remotely (with passwords).
  install -d /etc/clickhouse-server/users.d
  cat > /etc/clickhouse-server/users.d/netmon.xml <<XML
<clickhouse>
    <users>
        <default>
            <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
        </default>
        <${CH_DB_USER}>
            <password_sha256_hex>$(sha256_hex "$CH_DB_PASS")</password_sha256_hex>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
        </${CH_DB_USER}>
        <${CH_GUI_USER}>
            <password_sha256_hex>$(sha256_hex "$CH_GUI_PASS")</password_sha256_hex>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </${CH_GUI_USER}>
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
    if clickhouse-client --user "$CH_GUI_USER" --password "$CH_GUI_PASS" --query "SELECT 1" >/dev/null 2>&1; then ok=1; break; fi
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
  clickhouse-client --user "$CH_GUI_USER" --password "$CH_GUI_PASS" --multiquery < "$SCHEMA_DST" \
    || warn "schema apply reported errors (collector will retry at startup)"

  # Force retention on any pre-existing tables too (CREATE IF NOT EXISTS won't).
  local t
  for t in flows l7_events security_events host_bandwidth app_bandwidth iface_util summary; do
    clickhouse-client --user "$CH_GUI_USER" --password "$CH_GUI_PASS" \
      --query "ALTER TABLE ${CH_DB}.${t} MODIFY TTL ts + INTERVAL ${RETENTION_DAYS} DAY" 2>/dev/null || true
  done
  clickhouse-client --user "$CH_GUI_USER" --password "$CH_GUI_PASS" \
    --query "ALTER TABLE ${CH_DB}.host_bandwidth_1m MODIFY TTL minute + INTERVAL ${RETENTION_DAYS} DAY" 2>/dev/null || true
}

if [ "$WITH_CLICKHOUSE" = "1" ]; then install_clickhouse; fi

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

## Endpoints (remotely accessible — bound to 0.0.0.0)
- HTTP / API : http://${PRIMARY_IP}:8123
- Native     : ${PRIMARY_IP}:9000
- Web GUI    : http://${PRIMARY_IP}:8123/play   (built-in ClickHouse "Play" SQL UI)
- Dashboard  : http://${PRIMARY_IP}:8123/dashboard

## Database
- Name       : ${CH_DB}
- Retention  : ${RETENTION_DAYS} days (rows older than this are auto-deleted via table TTL)

## Users
| Purpose                | Username        | Password           |
|------------------------|-----------------|--------------------|
| Collector (DB read/write) | ${CH_DB_USER}   | ${CH_DB_PASS}      |
| GUI / admin (full)        | ${CH_GUI_USER}  | ${CH_GUI_PASS}     |

The default password-less \`default\` user is restricted to localhost only.

## Quick checks
\`\`\`bash
# from the server
clickhouse-client --user ${CH_GUI_USER} --password '${CH_GUI_PASS}' \\
  --query "SELECT count() FROM ${CH_DB}.flows"

# from a remote host over HTTP
curl "http://${PRIMARY_IP}:8123/?user=${CH_GUI_USER}&password=${CH_GUI_PASS}" \\
  --data-binary "SELECT category, count() FROM ${CH_DB}.security_events GROUP BY category"
\`\`\`

## ⚠️ Security
ClickHouse is exposed on 0.0.0.0:8123/9000. Restrict access to trusted IPs with
the Proxmox/host firewall, e.g.:
\`\`\`bash
# allow only your office/VPN subnet to reach ClickHouse
iptables -A INPUT -p tcp -m multiport --dports 8123,9000 -s <your.cidr/24> -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 8123,9000 -j DROP
\`\`\`
EOF
  chmod 600 "$CRED_FILE"
  log "credentials written to $CRED_FILE"
fi

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
  ClickHouse  : http://${PRIMARY_IP}:8123/play   (creds in $CRED_FILE)
  retention   : ${RETENTION_DAYS} days
EOF
fi
cat <<EOF

Next steps:
  1. Verify NETMON_IFACES in $ENV_DST matches this host's uplinks/bridges/taps.
  2. If you ran a release upgrade above, reboot, then: systemctl restart netmon-collector
  3. Firewall ClickHouse (8123/9000) to trusted IPs — see $CRED_FILE.
EOF
