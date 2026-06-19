#!/usr/bin/env bash
# Install ClickHouse natively on the Proxmox host (Debian 12 / bookworm).
# No Docker, no VM. Run as root on the host.
#
#   sudo bash deploy/install-clickhouse.sh
#
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "run as root" >&2; exit 1
fi

apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

# Add the official ClickHouse APT repository (keyring + source).
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
  | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

ARCH="$(dpkg --print-architecture)"
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" \
  > /etc/apt/sources.list.d/clickhouse.list

apt-get update
# DEBIAN_FRONTEND=noninteractive keeps the default-user password prompt empty.
DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client

# Cap memory use — this is a hypervisor, keep ClickHouse from eating host RAM.
# Adjust to taste (here: 2 GiB server cap, small caches).
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
