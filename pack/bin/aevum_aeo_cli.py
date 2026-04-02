#!/usr/bin/env python3
"""
aevum_aeo_cli.py (v0.1)

Minimal "receipt printer" for your AevumEventObject (AEO) atom.

It writes events into the Interaction chain (I) as EventEnvelope receipts (JSONL),
and stores the AEO payload separately (prunable) while committing its payload_hash
in the envelope.

This aligns with:
- Your AEO atom field set (event_id, timestamps, source, content/context, deps, signatures, etc.)
- The spec posture that envelopes commit to payload_hash and payload can be stored separately
"""
from __future__ import annotations

import argparse
import os
import pathlib
import time
import uuid
import datetime as dt
import json

from aevum_common import (
    compute_event_hash_v2,
    resolve_storage_dirs,
    ensure_dirs,
    load_identity,
    load_device_private_key,
    derive_subject_id_hex,
    capture_device_hex,
    load_chain_state,
    save_chain_state,
    write_payload,
    compute_event_hash,
    sign_event_hash,
    b64e,
)


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum", help="Base directory (default /var/lib/aevum)")
    ap.add_argument("--identity", default="", help="Path to identity.json")
    ap.add_argument("--key", default="", help="Path to device private key PEM")
    ap.add_argument("--source-id", default="manual", help="source_id for the AEO")
    ap.add_argument("--source-method", default="cli", help="source_method for the AEO")
    ap.add_argument("--content", default="", help="content (kept in payload; consider using content_ref later)")
    ap.add_argument("--context", default="{}", help="JSON object string for context_map")
    ap.add_argument("--deps", default="[]", help="JSON array string for dependencies")
    ap.add_argument("--confidence", type=float, default=0.5, help="confidence_score_initial")
    ap.add_argument("--validation-state", default="UNVERIFIED", help="validation_state (bounded enum later)")
    ap.add_argument("--time-block-id", type=int, default=None, help="time_block_id to bind; default = latest T seq-1 if available, else 0")
    args = ap.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Run as root.")

    base = pathlib.Path(args.base)

    # If identity/key not explicitly provided, prefer <base>/identity/* (instance-local).
    if not args.identity:
        cand = base.parent / "identity" if str(base).endswith("/accurate") else base / "identity"
        # For base like /var/lib/aevum/workstation, prefer /var/lib/aevum/workstation/identity.
        args.identity = str((cand / "identity.json"))
        if not pathlib.Path(args.identity).exists():
            args.identity = "/var/lib/aevum/identity/identity.json"
    if not args.key:
        cand = base.parent / "identity" if str(base).endswith("/accurate") else base / "identity"
        args.key = str((cand / "device_ed25519_sk.pem"))
        if not pathlib.Path(args.key).exists() and not pathlib.Path(args.key).is_symlink():
            args.key = "/var/lib/aevum/identity/device_ed25519_sk.pem"

    dirs = ensure_dirs(base)

    identity = load_identity(pathlib.Path(args.identity))
    sk = load_device_private_key(pathlib.Path(args.key))

    machine_id = identity.get("device", {}).get("machine_id", "")
    kid = identity.get("keys", {}).get("device_signing_key", {}).get("kid", "unknown")
    pub_b64 = identity.get("keys", {}).get("device_signing_key", {}).get("public_key_b64", "")
    import base64
    pub_raw = base64.b64decode(pub_b64) if pub_b64 else b""
    # Prefer identity-defined derivations (stable) if present
    subject_id_hex = identity.get('device', {}).get('subject_id_hex') or derive_subject_id_hex(pub_raw)
    capture_dev_hex = identity.get('device', {}).get('capture_device_hex') or capture_device_hex(machine_id, pub_raw)

    # Choose time_block_id: latest TimeChain block if exists
    if args.time_block_id is None:
        t_state = (dirs["state"] / "chain_T.json")
        if t_state.exists():
            st = json.loads(t_state.read_text(encoding="utf-8"))
            args.time_block_id = max(0, int(st.get("seq_no", 1)) - 1)
        else:
            args.time_block_id = 0

    # Parse JSON fields
    try:
        context_map = json.loads(args.context) if args.context else {}
        deps = json.loads(args.deps) if args.deps else []
    except Exception as e:
        raise SystemExit(f"Invalid JSON in --context or --deps: {e}")

    # Build AEO payload (AEOv0)
    ts_wall = int(time.time())
    ts_mono_ns = time.monotonic_ns()
    aeo = {
        "type": "AevumEventObject",
        "schema_version": "AEOv0",
        "event_id": str(uuid.uuid4()),  # replace with UUIDv7 later if desired
        "timestamp_local": ts_wall,
        "timestamp_monotonic_ns": ts_mono_ns,
        "source_id": args.source_id,
        "source_method": args.source_method,
        "content": args.content,
        "context_map": context_map,
        "dependencies": deps,
        "confidence_score_initial": args.confidence,
        "attestation_hash": None,      # optional: set to payload hash or separate attestation object later
        "signatures": [],              # payload-level signatures optional (envelope signature is authoritative in v0)
        "causality_links": [],
        "validation_state": args.validation_state,
        "revisions": [],
    }

    payload_hash, payload_ref = write_payload(dirs["payloads"], aeo)

    # Interaction Chain receipt
    chain_state_path = dirs["state"] / "chain_I.json"
    state = load_chain_state(chain_state_path)

    seq_no = int(state.get("seq_no", 0)) + 1
    prev_event_hash = state.get("prev_event_hash", "sha256:" + "00"*32)

    
    if args.envelope_version == "v1":
        envelope_unsigned = {
            "schema": "AEVUM:EVENT_ENVELOPE:V1",
            "chain_id": "I",
            "subject_id_hex": subject_id_hex,
            "seq_no": seq_no,
            "time_block_id": int(args.time_block_id),
            "local_monotime_ns": ts_mono_ns,
            "capture_device_hex": capture_dev_hex,
            "prev_event_hash": prev_event_hash,
            "payload_hash": payload_hash,
            "payload_ref": payload_ref,
            "event_hash": None,
        }
        event_hash = compute_event_hash({k: v for k, v in envelope_unsigned.items() if k != "event_hash"})
        envelope_unsigned["event_hash"] = event_hash
    else:
        envelope_unsigned = {
            "schema": "AEVUM:EVENT_ENVELOPE:V2",
            "chain_id_u8": 4,
            "chain_label": "I",
            "subject_id_hex": subject_id_hex,
            "seq_no": seq_no,
            "time_block_id": int(args.time_block_id),
            "local_monotime_ns": ts_mono_ns,
            "capture_device_hex": capture_dev_hex,
            "prev_event_hash": prev_event_hash,
            "payload_hash": payload_hash,
            "payload_ref": payload_ref,
            "event_hash": None,
        }
        event_hash = compute_event_hash_v2(
            chain_id_u8=4,
            subject_id_hex=subject_id_hex,
            seq_no=seq_no,
            time_block_id=int(args.time_block_id),
            local_monotime_ns=ts_mono_ns,
            capture_device_hex=capture_dev_hex,
            prev_event_hash=prev_event_hash,
            payload_hash=payload_hash,
        )
        envelope_unsigned["event_hash"] = event_hash
    

    sig_raw = sign_event_hash(sk, event_hash)
    envelope = dict(envelope_unsigned)
    envelope["signature"] = {
        "alg": "Ed25519",
        "kid": kid,
        "sig_b64": b64e(sig_raw),
        "signed_at": utc_now_iso(),
        "canonicalization": "json(sort_keys=true,separators=(',',':'),utf8)",
    }

    receipts_path = dirs["receipts"] / "I.jsonl"
    from aevum_common import append_line
    append_line(receipts_path, json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n", mode=0o600)

    state = {"seq_no": seq_no, "prev_event_hash": event_hash}
    save_chain_state(chain_state_path, state)

    print("OK: wrote AEO receipt")
    print(f"    chain=I seq_no={seq_no} time_block_id={args.time_block_id}")
    print(f"    receipt: {receipts_path}")
    print(f"    payload: {base / payload_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
