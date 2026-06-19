#!/usr/bin/env bash
# Install ClickHouse natively on the Proxmox host (Debian-based: bookworm/trixie).
# No Docker, no VM. Run as root on the host.
#
#   sudo bash deploy/install-clickhouse.sh
#
# Uses ClickHouse's own APT repo, so it's independent of the Proxmox/Debian
# release. It also updates ONLY the ClickHouse source list, so a broken/unrelated
# repo on the host (e.g. the Proxmox *enterprise* repo returning 401 without a
# subscription) cannot block this install.
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "run as root" >&2; exit 1
fi

# --- prerequisites (almost always already present on a Proxmox host) -------- #
missing=""
command -v curl >/dev/null 2>&1 || missing="$missing curl"
command -v gpg  >/dev/null 2>&1 || missing="$missing gnupg"
if [ -n "$missing" ]; then
  echo ">> installing prerequisites:$missing"
  apt-get update || true   # tolerate failures from other (e.g. enterprise) repos
  apt-get install -y ca-certificates apt-transport-https $missing
fi

# --- add the official ClickHouse APT repository ---------------------------- #
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
  | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

ARCH="$(dpkg --print-architecture)"
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" \
  > /etc/apt/sources.list.d/clickhouse.list

# Refresh ONLY the ClickHouse list — ignore every other configured repo so a
# 401 on the Proxmox enterprise repo (or any other) can't abort us.
apt-get update \
  -o Dir::Etc::sourcelist="sources.list.d/clickhouse.list" \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup="0"

# --- install ---------------------------------------------------------------- #
# DEBIAN_FRONTEND=noninteractive keeps the default-user password prompt empty.
DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client

# --- keep ClickHouse lightweight on a hypervisor --------------------------- #
install -d /etc/clickhouse-server/config.d
cat > /etc/clickhouse-server/config.d/netmon-limits.xml <<'XML'
<clickhouse>
    <!-- Keep ClickHouse lightweight on a Proxmox host. Tune for your box. -->
    <max_server_memory_usage>2000000000</max_server_memory_usage>
    <mark_cache_size>268435456</mark_cache_size>
    <uncompressed_cache_size>0</uncompressed_cache_size>
    <!-- Listen on localhost only; the collector runs on the same host. -->
    <listen_host>127.0.0.1</listen_host>
</clickhouse>
XML

systemctl enable --now clickhouse-server
sleep 2
clickhouse-client --query "SELECT version()" \
  && echo ">> ClickHouse is up on 127.0.0.1:8123 (HTTP) / :9000 (native)"
echo ">> The collector will create the 'netmon' database + tables on startup."
