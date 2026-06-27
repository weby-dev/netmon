#!/usr/bin/env bash
# install.sh — one-shot installer for the netmon XDP collector on a
# Debian/Proxmox host (bare-metal; no Docker, no VM).
#
# Run as root from the repo root:
#
#   sudo ./install.sh                     # deps + build + install + start
#   sudo ./install.sh --with-clickhouse   # also install ClickHouse natively
#   sudo ./install.sh --skip-deps         # skip apt build dependencies
#   sudo ./install.sh --skip-build        # install an already-built binary
#   sudo ./install.sh --no-start          # install + enable but don't start
#   sudo ./install.sh --with-taps-timer   # also install the tap-refresh timer
#   sudo ./install.sh --skip-repo-fix     # don't touch Proxmox APT repos
#   sudo ./install.sh --fix-release       # finish a half-done Debian release upgrade
#
# On Proxmox VE the subscription-only "enterprise" APT repos return HTTP 401,
# which makes `apt update` fail and leaves even Debian packages (git, sudo, the
# build deps) with "no installation candidate". This script disables those repos
# and enables the free "pve-no-subscription" repo so apt works cleanly. Use
# --skip-repo-fix if you have a valid subscription and manage repos yourself.
#
# If the host has a half-finished Debian upgrade (e.g. both bookworm and trixie
# repos enabled), dependency installs break on a libc6/libc6-dev mismatch. The
# script detects this and stops with guidance; pass --fix-release to consolidate
# the APT suites to the newest release and run 'apt full-upgrade' automatically.
#
# Idempotent: safe to re-run for upgrades. A previously installed collector
# (service + binary) is stopped and removed first, and an existing
# /etc/netmon/collector.env is always preserved (never overwritten).
set -euo pipefail

# --- locations -------------------------------------------------------------- #
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="$REPO/build/collector/netmon-collector"
BIN_DST="/usr/local/bin/netmon-collector"
WRAP_DST="/usr/local/bin/netmon-run.sh"
TAPS_DST="/usr/local/bin/netmon-refresh-taps.sh"
ENV_DST="/etc/netmon/collector.env"
SCHEMA_DST="/etc/netmon/schema.sql"
UNIT_DST="/etc/systemd/system/netmon-collector.service"

# --- options ---------------------------------------------------------------- #
WITH_CLICKHOUSE=0
SKIP_DEPS=0
SKIP_BUILD=0
NO_START=0
WITH_TAPS_TIMER=0
SKIP_REPO_FIX=0
FIX_RELEASE=0

# --- helpers ---------------------------------------------------------------- #
log()  { printf '\033[1;32m>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "${BASH_SOURCE[0]}"; exit 0; }

# On Proxmox VE the subscription-only enterprise repos return HTTP 401 and make
# `apt update` fail, which leaves even Debian packages (git, sudo, our build
# deps) with "no installation candidate". Disable those repos, enable the free
# no-subscription repo, and ensure the signing key is present.
fix_apt_repos() {
  local codename="" keyring="" f k
  codename="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")" || true

  # Only act on Proxmox hosts (pveversion present, or a proxmox.com apt source).
  if ! command -v pveversion >/dev/null 2>&1 && \
     ! grep -rqs 'proxmox\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    return 0
  fi
  log "Proxmox host detected — normalizing APT repositories"
  [ -n "$codename" ] || { warn "  cannot determine Debian codename; skipping repo fix"; return 0; }

  shopt -s nullglob

  # 1) Disable subscription-only enterprise repos (legacy .list + deb822 .sources).
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] || continue
    if grep -q 'enterprise\.proxmox\.com' "$f"; then
      cp -n "$f" "$f.netmon-bak" 2>/dev/null || true
      sed -i '/enterprise\.proxmox\.com/ s/^[[:space:]]*deb/#&/' "$f"
      log "  commented enterprise entries in $f"
    fi
  done
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    if grep -q 'enterprise\.proxmox\.com' "$f"; then
      mv "$f" "$f.disabled"
      log "  disabled $(basename "$f") (apt ignores *.disabled)"
    fi
  done

  # 2) Ensure a Proxmox signing key exists for the no-subscription repo.
  for k in /usr/share/keyrings/proxmox-archive-keyring.gpg \
           "/etc/apt/trusted.gpg.d/proxmox-release-$codename.gpg" \
           /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg; do
    [ -f "$k" ] && { keyring="$k"; break; }
  done
  if [ -z "$keyring" ]; then
    keyring="/usr/share/keyrings/proxmox-archive-keyring.gpg"
    log "  fetching Proxmox release key"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-$codename.gpg" \
        -o "$keyring" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$keyring" \
        "https://enterprise.proxmox.com/debian/proxmox-release-$codename.gpg" 2>/dev/null || true
    fi
    [ -s "$keyring" ] || { keyring=""; warn "  could not fetch Proxmox key; relying on trusted.gpg.d"; }
  fi

  # 3) Enable the free no-subscription repo (idempotent).
  if ! grep -rqs 'download\.proxmox\.com/debian/pve' \
        /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    {
      echo "Types: deb"
      echo "URIs: http://download.proxmox.com/debian/pve"
      echo "Suites: $codename"
      echo "Components: pve-no-subscription"
      [ -n "$keyring" ] && echo "Signed-By: $keyring"
    } > /etc/apt/sources.list.d/pve-no-subscription.sources
    log "  enabled pve-no-subscription repo ($codename)"
  fi

  # 4) Best-effort: ensure the Debian base repo enables 'main' (git/sudo live there).
  if [ -f /etc/apt/sources.list.d/debian.sources ] && \
     ! grep -qiE '^Components:.*\bmain\b' /etc/apt/sources.list.d/debian.sources; then
    cp -n /etc/apt/sources.list.d/debian.sources \
          /etc/apt/sources.list.d/debian.sources.netmon-bak 2>/dev/null || true
    sed -i -E 's/^([Cc]omponents:.*)$/\1 main/' /etc/apt/sources.list.d/debian.sources
    warn "  added 'main' component to debian.sources"
  fi
}

# --- Debian release consistency --------------------------------------------- #
# A half-finished release upgrade leaves >1 Debian codename enabled across the
# APT sources (e.g. bookworm + trixie). The installed libc6 then mismatches the
# only available libc6-dev and every -dev build package becomes uninstallable.

# Print the distinct Debian codenames currently enabled (one per line).
enabled_codenames() {
  { grep -rhsE '^[[:space:]]*Suites:' /etc/apt/sources.list.d/*.sources 2>/dev/null \
      | sed 's/^[[:space:]]*Suites:[[:space:]]*//' || true
    grep -rhsE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null \
      | awk '{print $3}' || true; } \
    | grep -oE '(bullseye|bookworm|trixie|forky)' | sort -u || true
}

# Newest enabled codename — the consolidation target.
newest_codename() {
  local c r best="" rank=0
  for c in $(enabled_codenames); do
    case "$c" in bullseye) r=1;; bookworm) r=2;; trixie) r=3;; forky) r=4;; *) r=0;; esac
    if [ "$r" -gt "$rank" ]; then rank="$r"; best="$c"; fi
  done
  printf '%s' "$best"
}

is_mixed_release() { [ "$(enabled_codenames | wc -l | tr -d ' ')" -gt 1 ]; }

# Rewrite the suite/codename in one APT source file (deb822 Suites: lines, or
# the suite field of legacy `deb` lines only — never URLs or Signed-By paths).
rewrite_suite() {  # <file> <old> <target>
  local f="$1" old="$2" target="$3"
  cp -n "$f" "$f.netmon-bak" 2>/dev/null || true
  case "$f" in
    *.sources) sed -i -E "/^[[:space:]]*Suites:/ s/\\b$old\\b/$target/g" "$f" ;;
    *)         sed -i -E "/^[[:space:]]*deb/     s/\\b$old\\b/$target/g" "$f" ;;
  esac
}

# Consolidate every APT suite to the newest release and complete the upgrade.
fix_mixed_release() {
  local target old f
  target="$(newest_codename)"
  [ -n "$target" ] || die "could not determine the Debian codename to upgrade to"
  warn "consolidating APT sources to '$target' and running 'apt full-upgrade'"
  for old in bullseye bookworm trixie forky; do
    [ "$old" = "$target" ] && continue
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources \
             /etc/apt/sources.list.d/*.list; do
      [ -f "$f" ] || continue
      case "$f" in *.bak|*.disabled|*.netmon-bak) continue;; esac
      grep -qsE "\\b$old\\b" "$f" || continue
      rewrite_suite "$f" "$old" "$target"
      log "  $f: $old -> $target"
    done
  done
  log "updating package lists"
  apt-get update || warn "apt-get update reported errors"
  log "running 'apt full-upgrade' to $target (this can take a while; a reboot may be needed)"
  DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
}

# Stop and remove a previously installed collector so we reinstall cleanly.
# Operator config (collector.env) and schema are preserved.
remove_existing() {
  if [ -f "$UNIT_DST" ] || [ -x "$BIN_DST" ] \
     || systemctl is-enabled --quiet netmon-collector 2>/dev/null; then
    log "existing netmon install detected — removing before reinstall (config kept)"
    systemctl stop netmon-collector 2>/dev/null || true
    systemctl disable netmon-collector 2>/dev/null || true
    rm -f "$BIN_DST" "$WRAP_DST" "$UNIT_DST"
    systemctl daemon-reload 2>/dev/null || true
    log "  stopped service; removed old binary, wrapper, and unit"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --with-clickhouse) WITH_CLICKHOUSE=1 ;;
    --skip-deps)       SKIP_DEPS=1 ;;
    --skip-build)      SKIP_BUILD=1 ;;
    --no-start)        NO_START=1 ;;
    --with-taps-timer) WITH_TAPS_TIMER=1 ;;
    --skip-repo-fix)   SKIP_REPO_FIX=1 ;;
    --fix-release)     FIX_RELEASE=1 ;;
    -h|--help)         usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# --- preflight -------------------------------------------------------------- #
[ "$(id -u)" = "0" ]      || die "run as root (sudo ./install.sh)"
[ "$(uname -s)" = "Linux" ] || die "netmon is Linux/XDP only; this host is $(uname -s)"

KREL="$(uname -r)"
KMAJ="${KREL%%.*}"; KREST="${KREL#*.}"; KMIN="${KREST%%.*}"
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "${KMIN:-0}" -lt 18 ]; }; then
  warn "kernel $KREL < 5.18 — XDP/ring-buffer features may be unavailable"
fi
[ -r /sys/kernel/btf/vmlinux ] || [ -f "$REPO/ebpf/vmlinux.h" ] || \
  warn "no /sys/kernel/btf/vmlinux and no ebpf/vmlinux.h — install pve-headers or run 'make vmlinux'"

HAVE_APT=0; command -v apt-get >/dev/null 2>&1 && HAVE_APT=1

# --- 1. APT repos + dependencies -------------------------------------------- #
if [ "$SKIP_DEPS" = "0" ]; then
  if [ "$HAVE_APT" = "1" ]; then
    if [ "$SKIP_REPO_FIX" = "0" ]; then fix_apt_repos; fi

    if is_mixed_release; then
      if [ "$FIX_RELEASE" = "1" ]; then
        fix_mixed_release
      else
        die "Mixed Debian release in APT sources: $(enabled_codenames | tr '\n' ' ').
  This is a half-finished Debian upgrade (e.g. bookworm + trixie) and will break
  dependency installation (libc6 vs libc6-dev mismatch).
  Re-run with --fix-release to consolidate to the newest release and complete the
  upgrade (back up/snapshot first; a reboot may be needed), or fix it manually:
    grep -rl bookworm /etc/apt/sources.list /etc/apt/sources.list.d/ | xargs -r sed -i.bak 's/bookworm/trixie/g'
    apt update && apt full-upgrade -y
  On a production Proxmox host, prefer the official 'pve8to9' procedure."
      fi
    fi

    log "updating package lists"
    apt-get update || warn "apt-get update reported errors (continuing)"
    log "installing base tools + build dependencies via apt"
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      git sudo ca-certificates curl gnupg \
      clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
      libcurl4-openssl-dev cmake build-essential pkg-config
  else
    warn "no apt-get found; skipping dependency install (ensure clang/libbpf/bpftool/cmake/libcurl are present)"
  fi
else
  log "skipping APT repo fix + dependencies (--skip-deps)"
fi

# --- 2. ClickHouse (optional) ----------------------------------------------- #
if [ "$WITH_CLICKHOUSE" = "1" ]; then
  log "installing ClickHouse (deploy/install-clickhouse.sh)"
  bash "$REPO/deploy/install-clickhouse.sh"
fi

# --- 3. build --------------------------------------------------------------- #
if [ "$SKIP_BUILD" = "0" ]; then
  log "building eBPF object, skeleton, and collector (make)"
  make -C "$REPO"
else
  log "skipping build (--skip-build)"
fi
[ -x "$BIN_SRC" ] || die "collector binary not found at $BIN_SRC (build failed or --skip-build with no prior build)"

# --- 3b. remove any previous install (clean reinstall; keeps collector.env) -- #
remove_existing

# --- 4. install artifacts --------------------------------------------------- #
log "installing binary, wrapper, schema, and unit"
install -D -m 0755 "$BIN_SRC"                          "$BIN_DST"
install -D -m 0755 "$REPO/deploy/netmon-run.sh"        "$WRAP_DST"
install -D -m 0644 "$REPO/clickhouse/schema.sql"       "$SCHEMA_DST"
install -D -m 0644 "$REPO/deploy/netmon-collector.service" "$UNIT_DST"
install -D -m 0755 "$REPO/deploy/refresh-taps.sh"      "$TAPS_DST"

# Preserve operator config; only seed defaults on a fresh install.
if [ -f "$ENV_DST" ]; then
  log "keeping existing $ENV_DST (not overwritten)"
  warn "new tunables may exist in $REPO/config/collector.env (e.g. NETMON_DDOS_OUT_PPS,"
  warn "  NETMON_ICMP_FLOOD, NETMON_BRUTEFORCE, NETMON_DNS_RATE, NETMON_LATERAL_HOSTS) —"
  warn "  the wrapper applies safe defaults for any you don't set."
else
  install -D -m 0644 "$REPO/config/collector.env" "$ENV_DST"
  log "seeded default config at $ENV_DST — edit NETMON_IFACES before relying on it"
fi

# --- 5. optional tap-refresh timer ------------------------------------------ #
if [ "$WITH_TAPS_TIMER" = "1" ]; then
  log "installing tap-refresh timer (every 1 min)"
  cat > /etc/systemd/system/netmon-refresh-taps.service <<EOF
[Unit]
Description=Refresh netmon XDP interface set (Proxmox VM/CT taps)
After=netmon-collector.service

[Service]
Type=oneshot
ExecStart=$TAPS_DST
EOF
  cat > /etc/systemd/system/netmon-refresh-taps.timer <<'EOF'
[Unit]
Description=Periodically refresh the netmon interface set

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
fi

# --- 6. enable & start ------------------------------------------------------ #
log "reloading systemd"
systemctl daemon-reload
systemctl enable netmon-collector >/dev/null 2>&1 || true
[ "$WITH_TAPS_TIMER" = "1" ] && systemctl enable --now netmon-refresh-taps.timer >/dev/null 2>&1 || true

if [ "$NO_START" = "1" ]; then
  log "service installed and enabled but NOT started (--no-start)"
else
  log "starting netmon-collector"
  systemctl restart netmon-collector || true
  sleep 1
  if systemctl is-active --quiet netmon-collector; then
    log "netmon-collector is running"
  else
    warn "netmon-collector did not stay active. Most likely NETMON_IFACES in"
    warn "  $ENV_DST does not match this host's interfaces. Check:"
    warn "    journalctl -u netmon-collector -n 40 --no-pager"
  fi
fi

# --- done ------------------------------------------------------------------- #
cat <<EOF

$(log "install complete")

  config   : $ENV_DST   (set NETMON_IFACES to your uplinks/bridges/taps)
  binary   : $BIN_DST
  service  : systemctl status netmon-collector
  logs     : journalctl -u netmon-collector -f
  stream   : http://<host>:\${NETMON_STREAM_PORT:-8090}/live   (if enabled)

Next steps:
  1. Edit $ENV_DST (at minimum NETMON_IFACES).
$( [ "$WITH_CLICKHOUSE" = "1" ] || echo "  2. Ensure ClickHouse is reachable, or re-run with --with-clickhouse." )
  3. sudo systemctl restart netmon-collector
EOF
