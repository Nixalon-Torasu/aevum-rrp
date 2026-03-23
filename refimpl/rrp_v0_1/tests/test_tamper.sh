#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT_DIR/src"
STATE_DIR="$ROOT_DIR/state"
IDENTITY_DIR="$STATE_DIR/identity"
CHAIN_DIR="$STATE_DIR/chain"
CHAIN_FILE="$CHAIN_DIR/aeo_chain.jsonl"
BROKEN_DIR="$STATE_DIR/broken"

mkdir -p "$CHAIN_DIR" "$BROKEN_DIR"

echo "[1/7] Resetting local state"
rm -rf "$STATE_DIR"
mkdir -p "$IDENTITY_DIR" "$CHAIN_DIR" "$BROKEN_DIR"

echo "[2/7] Generating identity"
python3 -m aevum_rrp.keygen --out-dir "$IDENTITY_DIR"

echo "[3/7] Emitting clean events"
python3 -m aevum_rrp.emit --state-dir "$STATE_DIR" --identity-dir "$IDENTITY_DIR" --event-type SYSTEM --input-class SYSTEM --payload-json '{"message":"boot"}'
python3 -m aevum_rrp.emit --state-dir "$STATE_DIR" --identity-dir "$IDENTITY_DIR" --event-type USER_INPUT --input-class USER_INPUT --payload-json '{"message":"user typed hello"}'
python3 -m aevum_rrp.emit --state-dir "$STATE_DIR" --identity-dir "$IDENTITY_DIR" --event-type APPLICATION --input-class APPLICATION --payload-json '{"message":"application updated state"}'

echo "[4/7] Verifying clean chain"
python3 -m aevum_rrp.verifier --chain "$CHAIN_FILE"

echo "[5/7] Creating tampered chain"
python3 "$ROOT_DIR/tests/break_chain.py" --chain "$CHAIN_FILE" --out "$BROKEN_DIR/tampered.jsonl" tamper --index 1 --field event_type --value '"MALICIOUS_EDIT"'

echo "[5b/7] Verifying tampered chain"
python3 -m aevum_rrp.verifier --chain "$BROKEN_DIR/tampered.jsonl" || true

echo "[6/7] Creating gapped chain"
python3 "$ROOT_DIR/tests/break_chain.py" --chain "$CHAIN_FILE" --out "$BROKEN_DIR/gapped.jsonl" gap --index 1

echo "[6b/7] Verifying gapped chain"
python3 -m aevum_rrp.verifier --chain "$BROKEN_DIR/gapped.jsonl" || true

echo "[7/7] Creating forked chain"
python3 "$ROOT_DIR/tests/break_chain.py" --chain "$CHAIN_FILE" --out "$BROKEN_DIR/forked.jsonl" fork --index 1 --identity-dir "$IDENTITY_DIR"

echo "[7b/7] Verifying forked chain"
python3 -m aevum_rrp.verifier --chain "$BROKEN_DIR/forked.jsonl" || true

echo
echo "Done."
echo "Clean:    $CHAIN_FILE"
echo "Broken:   $BROKEN_DIR"
