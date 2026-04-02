#!/usr/bin/env python3
"""
aevum_recover_chain.py (v0.1)

Rebuild chain state from receipts (JSONL). Intended for crash recovery, migration validation, and operator repair.

Non-blocking posture:
- This tool is OPTIONAL. Receipts never gate processing.
- Use it when you want deterministic restart tails (seq_no/prev_event_hash) and health reporting.

What it does
- Scans receipts log for a chain (T/I/P/R/PHI).
- Verifies hash-chaining and event_hash recomputation (V1 and V2).
- Optionally verifies Ed25519 signatures if identity public key is provided.
- Writes base/{state}/chain_<CHAIN>.json with reconstructed tail state.

Supports explicit TimeChain gap payloads:
- GAP placeholders: uses payload.time_block_id
- Coalesced summaries: uses payload.gap_end_time_block_id as last_time_block_id

Safety
- Tolerates a partially-written last line (common after crash). It will stop at last valid record unless --strict.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict, Optional, Tuple

from aevum_common import (
    resolve_storage_dirs,
    load_identity,
    compute_event_hash,
    compute_event_hash_v2,
    sha256_tagged,
    b64d,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    print("ERROR: Missing dependency 'cryptography'. Install with: python3 -m pip install cryptography", file=sys.stderr)
    raise

ZERO_HASH = "sha256:" + ("00" * 32)

CHAIN_LABELS = {"P": 1, "R": 2, "PHI": 3, "I": 4, "T": 5}


def load_pubkey(identity_path: pathlib.Path) -> Optional[bytes]:
    try:
        ident = json.loads(identity_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    pub_b64 = None
    # full identity.json
    pub_b64 = (ident.get("keys", {}) or {}).get("device_signing_key", {}).get("public_key_b64")
    # public view
    if not pub_b64:
        pub_b64 = (ident.get("key", {}) or {}).get("public_key_b64")
    if not pub_b64:
        return None
    try:
        return b64d(pub_b64)
    except Exception:
        return None


def verify_sig(pub_raw: bytes, sig_b64: str, event_hash_tagged: str) -> None:
    if not event_hash_tagged.startswith("sha256:"):
        raise ValueError("event_hash must be sha256:<hex>")
    h = bytes.fromhex(event_hash_tagged.split(":", 1)[1])
    sig = b64d(sig_b64)
    Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, h)


def recompute_event_hash(ev: Dict[str, Any]) -> str:
    schema = ev.get("schema", "")
    if schema == "AEVUM:EVENT_ENVELOPE:V2":
        # compute_event_hash_v2 expects fields, not full record
        return compute_event_hash_v2(
            chain_id_u8=int(ev["chain_id_u8"]),
            subject_id_hex=ev["subject_id_hex"],
            seq_no=int(ev["seq_no"]),
            time_block_id=int(ev["time_block_id"]),
            local_monotime_ns=int(ev["local_monotime_ns"]),
            capture_device_hex=ev["capture_device_hex"],
            prev_event_hash=ev["prev_event_hash"],
            payload_hash=ev["payload_hash"],
        )
    # v1
    unsigned = dict(ev)
    unsigned.pop("signature", None)
    unsigned.pop("event_hash", None)
    return compute_event_hash(unsigned)


def read_payload_json(payloads_dir: pathlib.Path, payload_ref: str) -> Optional[Dict[str, Any]]:
    try:
        p = payloads_dir.parent / payload_ref if "payloads/" in payload_ref else payloads_dir / pathlib.Path(payload_ref).name
        if not p.exists():
            # Try direct under payloads_dir
            p2 = payloads_dir / payload_ref
            if not p2.exists():
                return None
            p = p2
        raw = p.read_bytes().strip()
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover chain state from receipts (Year-1).")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Instance base (workstation/core/user).")
    ap.add_argument("--chain", required=True, choices=["P","R","PHI","I","T"], help="Chain label to recover.")
    ap.add_argument("--identity", default="", help="Path to identity.json or identity.public.json for signature verification (optional).")
    ap.add_argument("--strict", action="store_true", help="Fail on any parse error (including partial last line).")
    ap.add_argument("--write-state", action="store_true", help="Write reconstructed chain_state file (default).")
    ap.add_argument("--no-write-state", dest="write_state", action="store_false", help="Do not write chain state; report only.")
    ap.add_argument("--report", default="", help="Write a JSON report to this path (optional).")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    receipts_dir = dirs["receipts"]
    payloads_dir = dirs["payloads"]
    state_dir = dirs["state"]
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except Exception:
        pass

    log_path = receipts_dir / f"{args.chain}.jsonl"
    if not log_path.exists():
        print(f"ERROR: receipts log not found: {log_path}", file=sys.stderr)
        return 2

    pub_raw = load_pubkey(pathlib.Path(args.identity)) if args.identity else None
    sig_checked = 0
    records = 0
    warnings = []
    last_event_hash = None
    last_seq = 0
    last_time_block_id = -1
    last_wallclock = None
    last_monotime = None

    with log_path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception as e:
                msg = f"line {lineno}: JSON parse error: {e}"
                if args.strict:
                    print("ERROR:", msg, file=sys.stderr)
                    return 3
                warnings.append(msg)
                break  # treat as partial tail
            records += 1

            # Basic required fields
            if ev.get("schema") == "AEVUM:EVENT_ENVELOPE:V2":
                req = ["schema","chain_id_u8","subject_id_hex","seq_no","time_block_id","local_monotime_ns",
                       "capture_device_hex","prev_event_hash","payload_hash","payload_ref","event_hash","signature"]
            else:
                req = ["schema","chain_id","subject_id_hex","seq_no","time_block_id","local_monotime_ns",
                       "capture_device_hex","prev_event_hash","payload_hash","payload_ref","event_hash","signature"]
            missing = [k for k in req if k not in ev]
            if missing:
                msg = f"line {lineno}: missing fields: {missing}"
                if args.strict:
                    print("ERROR:", msg, file=sys.stderr)
                    return 4
                warnings.append(msg)
                break

            # Sequence
            seq = int(ev["seq_no"])
            if seq != last_seq + 1:
                msg = f"line {lineno}: seq_no jump: expected {last_seq+1}, got {seq}"
                if args.strict:
                    print("ERROR:", msg, file=sys.stderr)
                    return 5
                warnings.append(msg)
                break
            last_seq = seq

            # Prev hash
            prev = ev["prev_event_hash"]
            if seq == 1:
                if prev != ZERO_HASH:
                    msg = f"line {lineno}: genesis prev_event_hash must be {ZERO_HASH}"
                    if args.strict:
                        print("ERROR:", msg, file=sys.stderr)
                        return 6
                    warnings.append(msg)
                    break
            else:
                if last_event_hash and prev != last_event_hash:
                    msg = f"line {lineno}: prev_event_hash mismatch"
                    if args.strict:
                        print("ERROR:", msg, file=sys.stderr)
                        return 7
                    warnings.append(msg)
                    break

            # event_hash
            expected = recompute_event_hash(ev)
            if ev["event_hash"] != expected:
                msg = f"line {lineno}: event_hash mismatch"
                if args.strict:
                    print("ERROR:", msg, file=sys.stderr)
                    return 8
                warnings.append(msg)
                break

            # signature (optional)
            if pub_raw:
                try:
                    sig = ev.get("signature", {})
                    verify_sig(pub_raw, sig.get("sig_b64", ""), ev["event_hash"])
                    sig_checked += 1
                except Exception as e:
                    msg = f"line {lineno}: signature verify failed: {e}"
                    if args.strict:
                        print("ERROR:", msg, file=sys.stderr)
                        return 9
                    warnings.append(msg)
                    break

            last_event_hash = ev["event_hash"]

            # TimeChain-specific last_time_block_id improvements from payload
            tb = int(ev.get("time_block_id", -1))
            payload = read_payload_json(payloads_dir, ev.get("payload_ref", ""))
            if payload:
                if payload.get("type") == "TimeGapSummaryPayload":
                    end_tb = payload.get("gap_end_time_block_id")
                    if isinstance(end_tb, int):
                        last_time_block_id = max(last_time_block_id, end_tb)
                elif payload.get("type") == "TimeBlockPayload":
                    ptb = payload.get("time_block_id")
                    if isinstance(ptb, int):
                        last_time_block_id = max(last_time_block_id, ptb)
                # wallclock/monotime extraction (best-effort)
                wc = payload.get("wallclock_approx")
                if isinstance(wc, int):
                    last_wallclock = wc
                mn = payload.get("monotime_end_ns") or payload.get("monotime_start_ns")
                if isinstance(mn, int):
                    last_monotime = mn
            else:
                last_time_block_id = max(last_time_block_id, tb)

    # Construct recovered state
    state = {
        "seq_no": last_seq,
        "prev_event_hash": last_event_hash or ZERO_HASH,
        "last_time_block_id": last_time_block_id,
        "last_wallclock_unix": last_wallclock,
        "last_monotime_ns": last_monotime,
        "recovered_from": str(log_path),
    }

    report = {
        "schema": "AEVUM:RECOVERY_REPORT:V1",
        "base": str(base),
        "chain": args.chain,
        "records_scanned": records,
        "sig_checked": sig_checked,
        "tail": {"seq_no": last_seq, "event_hash": last_event_hash, "last_time_block_id": last_time_block_id},
        "warnings": warnings,
    }

    if args.write_state:
        out_path = state_dir / f"chain_{args.chain}.json"
        out_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(out_path, 0o600)
        except Exception:
            pass
        report["state_written_to"] = str(out_path)

    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("OK")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
