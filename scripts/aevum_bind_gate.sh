#!/usr/bin/env bash
set -euo pipefail

BIND_DIR="/etc/aevum/appliance/bind"
TOKEN_JSON="${BIND_DIR}/move_token.json"
TOKEN_SIG="${BIND_DIR}/move_token.sig.b64"

fingerprint() {
  local mid uuid board prod
  mid="$(cat /etc/machine-id 2>/dev/null || true)"
  uuid="$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || true)"
  board="$(cat /sys/class/dmi/id/board_serial 2>/dev/null || true)"
  prod="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
  printf '%s\n' "${mid}|${uuid}|${board}|${prod}" | sha256sum | awk '{print $1}'
}

mkdir -p "${BIND_DIR}"
CUR_FP="$(fingerprint)"

BOUND_JSON="${BIND_DIR}/bound_host.json"
if [[ ! -f "${BOUND_JSON}" ]]; then
  systemctl stop 'aevum-*' >/dev/null 2>&1 || true
  exit 0
fi

BOUND_FP="$(jq -r '.fingerprint_sha256 // ""' "${BOUND_JSON}" 2>/dev/null || true)"
if [[ -n "${BOUND_FP}" && "${CUR_FP}" == "${BOUND_FP}" ]]; then
  exit 0
fi

if [[ -f "${TOKEN_JSON}" && -f "${TOKEN_SIG}" ]]; then
  if /usr/local/sbin/aevum_token.py verify --token "${TOKEN_JSON}" --sig "${TOKEN_SIG}" >/dev/null 2>&1; then
    systemctl stop 'aevum-*' >/dev/null 2>&1 || true
    exit 0
  fi
fi

systemctl stop 'aevum-*' >/dev/null 2>&1 || true
systemctl isolate aevum-quarantine.target >/dev/null 2>&1 || true
exit 0
