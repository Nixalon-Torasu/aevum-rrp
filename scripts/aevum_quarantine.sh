#!/usr/bin/env bash
set -euo pipefail

systemctl stop 'aevum-*' >/dev/null 2>&1 || true
nmcli networking off >/dev/null 2>&1 || true
ip link set down dev eth0 >/dev/null 2>&1 || true
ip link set down dev enp0s3 >/dev/null 2>&1 || true

echo "Aevum is in QUARANTINE mode (moved/unbound). Run: sudo aevum-appliance rebind (only if you prepared a move)"       | systemd-cat -t aevum-quarantine || true
