#!/usr/bin/env bash
set -euo pipefail

AEVUM_ROOT="/var/lib/aevum"
REC_DIR="$AEVUM_ROOT/ledger/receipts"
WORKSTATION_BASE="$AEVUM_ROOT/workstation"
WORKSTATION_REC_DIR_1="$WORKSTATION_BASE/accurate/receipts"
WORKSTATION_REC_DIR_2="$WORKSTATION_BASE/receipts"
STATE_DIR="$AEVUM_ROOT/attest/state"
ART_DIR="$AEVUM_ROOT/artifacts/daily_roots"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ART_DIR/daily_root_${STAMP}.json"

mkdir -p "$ART_DIR" "$STATE_DIR"

hash_dir() {
  local d="$1"
  if [[ -d "$d" ]]; then
    (cd "$d" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}'
  else
    echo ""
  fi
}

nft_sha="$(nft list ruleset 2>/dev/null | sha256sum | awk '{print $1}' || true)"
receipts_sha="$(hash_dir "$REC_DIR")"
workstation_receipts_sha="$(hash_dir "$WORKSTATION_REC_DIR_1")"
[[ -z "$workstation_receipts_sha" ]] && workstation_receipts_sha="$(hash_dir "$WORKSTATION_REC_DIR_2")"
state_sha="$(hash_dir "$STATE_DIR")"
etc_sha="$( (cd /etc/aevum 2>/dev/null && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}' ) || true)"

cat > "$OUT" <<EOF
{
  "timestamp_utc": "$STAMP",
  "nft_ruleset_sha256": "$nft_sha",
  "receipts_tree_sha256": "$receipts_sha",
  "workstation_receipts_tree_sha256": "$workstation_receipts_sha",
  "state_tree_sha256": "$state_sha",
  "etc_aevum_tree_sha256": "$etc_sha"
}
EOF

if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
  /opt/aevum-tools/bin/aevum-receipt note "daily root" component=attest file="$OUT" nft_sha="$nft_sha" receipts_sha="$receipts_sha" state_sha="$state_sha" etc_sha="$etc_sha" || true workstation_receipts_sha="$workstation_receipts_sha"
fi

echo "$OUT"
