#!/usr/bin/env bash
# Regenerate NETMON_IFACES to include all current Proxmox VM/CT interfaces and
# restart the collector so XDP is (re)attached to them. VMs come and go, so run
# this from a systemd timer (e.g. every minute) or a Proxmox hookscript.
#
#   install -m0755 deploy/refresh-taps.sh /usr/local/bin/netmon-refresh-taps.sh
#
set -euo pipefail
ENV_FILE=/etc/netmon/collector.env

# Always-monitored interfaces (uplinks + management bridges). Edit to taste.
BASE_IFACES="vmbr0 eno1"

# Discover VM tap interfaces, CT veth/fwln interfaces, and SDN bridges.
DYN_IFACES=$(ip -o link show \
  | awk -F': ' '{print $2}' \
  | sed 's/@.*//' \
  | grep -E '^(tap[0-9]+i[0-9]+|veth[0-9]+i[0-9]+|fwln[0-9]+i[0-9]+|vmbr[0-9]+)$' \
  | sort -u | tr '\n' ' ')

NEW="$BASE_IFACES $DYN_IFACES"
NEW=$(echo "$NEW" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ *$//')

CUR=$(grep -E '^NETMON_IFACES=' "$ENV_FILE" 2>/dev/null | cut -d'"' -f2 || true)

if [ "$(echo "$CUR" | tr ' ' '\n' | sort -u)" != "$(echo "$NEW" | tr ' ' '\n' | sort -u)" ]; then
  echo "interface set changed; updating and restarting collector"
  echo "  old: $CUR"
  echo "  new: $NEW"
  sed -i "s|^NETMON_IFACES=.*|NETMON_IFACES=\"$NEW\"|" "$ENV_FILE"
  systemctl restart netmon-collector
else
  echo "no change ($NEW)"
fi
