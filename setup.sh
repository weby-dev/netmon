#!/usr/bin/env bash
# setup.sh — first-touch bootstrap for a fresh Proxmox VE host that has only
# curl (no git). It repairs APT, installs git + the build toolchain, clones the
# netmon repo into a dedicated dir, then hands off to its install.sh.
#
#   curl -fsSL https://raw.githubusercontent.com/weby-dev/netmon/main/setup.sh -o setup.sh
#   bash setup.sh                 # full bootstrap + install
#   bash setup.sh --clone-only    # just fix APT + install git + clone, then stop
#
# Register this install with vormox.com (sends ClickHouse connection details):
#   bash setup.sh --domain acme.com
#   bash setup.sh --domain acme.com --webhook-secret <shared-secret>
#
# Any extra flags are passed straight through to install.sh, e.g.:
#   bash setup.sh --no-clickhouse --retention-days 14
#
# Run as root.
set -euo pipefail

REPO_URL="${NETMON_REPO_URL:-https://github.com/weby-dev/netmon.git}"
INSTALL_DIR="${NETMON_DIR:-/opt/netmon}"
CLONE_ONLY=0
PASSTHRU=()

log()  { printf '\033[1;32m>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "${BASH_SOURCE[0]}"; exit 0; }

# Collect our own flags; forward everything else to install.sh.
while [ $# -gt 0 ]; do
  case "$1" in
    --clone-only)     CLONE_ONLY=1 ;;
    --dir)            INSTALL_DIR="$2"; PASSTHRU+=(--dir "$2"); shift ;;
    --repo)           REPO_URL="$2"; shift ;;
    --domain)         PASSTHRU+=(--domain "$2"); shift ;;
    --webhook-url)    PASSTHRU+=(--webhook-url "$2"); shift ;;
    --webhook-secret) PASSTHRU+=(--webhook-secret "$2"); shift ;;
    -h|--help)        usage ;;
    *)                PASSTHRU+=("$1") ;;
  esac
  shift
done

# --- preflight -------------------------------------------------------------- #
[ "$(id -u)" = "0" ]        || die "run as root"
[ "$(uname -s)" = "Linux" ] || die "Proxmox/Debian only; this host is $(uname -s)"
command -v apt-get >/dev/null 2>&1 || die "no apt-get — this targets Debian/Proxmox"

TARGET_CODENAME="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")" || true
[ -n "$TARGET_CODENAME" ] || die "cannot read VERSION_CODENAME from /etc/os-release"

enabled_codenames() {
  { grep -rhsE '^[[:space:]]*Suites:' /etc/apt/sources.list.d/*.sources 2>/dev/null \
      | sed 's/^[[:space:]]*Suites:[[:space:]]*//' || true
    grep -rhsE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null \
      | awk '{print $3}' || true; } \
    | grep -oE '(bullseye|bookworm|trixie|forky)' | sort -u || true
}
codename_rank() { case "$1" in bullseye) echo 1;; bookworm) echo 2;; trixie) echo 3;; forky) echo 4;; *) echo 0;; esac; }

#############################################################################
# 1. Repair APT (enterprise -> no-subscription, de-dup, finish upgrade)
#############################################################################
fix_apt() {
  local f keyring c r rank best mixed=0
  best="$TARGET_CODENAME"; rank="$(codename_rank "$best")"
  for c in $(enabled_codenames); do
    r="$(codename_rank "$c")"
    if [ "$r" -gt "$rank" ]; then rank="$r"; best="$c"; fi
  done
  TARGET_CODENAME="$best"
  if [ "$(enabled_codenames | wc -l | tr -d ' ')" -gt 1 ]; then mixed=1; fi
  log "target Debian release: $TARGET_CODENAME"

  shopt -s nullglob

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
  : > /etc/apt/sources.list

  log "refreshing package indexes"
  rm -rf /var/lib/apt/lists/*
  apt-get update || warn "apt-get update reported errors (continuing)"

  if [ "$mixed" = "1" ]; then
    log "half-finished release upgrade detected — running 'apt full-upgrade'"
    DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
    warn "a reboot is recommended afterwards so the new kernel is active"
  fi
}

fix_apt

#############################################################################
# 2. Install git + the build toolchain (so install.sh can skip OS setup)
#############################################################################
log "installing git and build dependencies"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git sudo rsync ca-certificates curl gnupg \
  clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
  libcurl4-openssl-dev cmake build-essential pkg-config

#############################################################################
# 3. Clone into the dedicated dir and drop .git
#############################################################################
log "cloning $REPO_URL into $INSTALL_DIR"
TMP="$(mktemp -d)"
git clone --depth 1 "$REPO_URL" "$TMP/netmon"
mkdir -p "$INSTALL_DIR"
cp -a "$TMP/netmon/." "$INSTALL_DIR/"
rm -rf "$INSTALL_DIR/.git" "$TMP"
chmod +x "$INSTALL_DIR/install.sh" 2>/dev/null || true

#############################################################################
# 4. Hand off to the installer (OS already prepared)
#############################################################################
if [ "$CLONE_ONLY" = "1" ]; then
  log "clone-only done. Next: cd $INSTALL_DIR && ./install.sh"
  exit 0
fi

log "handing off to install.sh"
exec bash "$INSTALL_DIR/install.sh" --skip-os-setup "${PASSTHRU[@]}"
