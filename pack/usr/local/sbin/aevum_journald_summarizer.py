#!/usr/bin/env python3
"""
aevum_journald_summarizer.py (v0.1)

Summarize journald into thin-fact receipts (counts + hashes), not raw logs.

Why
- Workstation is "pure reality" => journald is a source of evidence.
- Do NOT dump full messages into receipts; produce minimal, privacy-preserving summaries.
- Receipts remain non-governing: this tool is best-effort and does not gate anything.

Mechanism
- Uses `journalctl -o json --cursor-file <cursor>` so it only reads new entries since last run.
- Aggregates:
  - counts by PRIORITY
  - counts by _SYSTEMD_UNIT
  - counts by SYSLOG_IDENTIFIER
  - special counts: kernel warnings, nftables drops (by MESSAGE prefix)
- Emits one receipt per run into chain R (Reality), chain_id_u8=2

Requires
- identity.json (private) in <base>/identity (workstation instance)
"""

from __future__ import annotations

import os, argparse
import json
import pathlib
import subprocess
import time
import sys
from typing import Any, Dict, List, Optional

from aevum_common import (
    resolve_storage_dirs,
    load_identity_private,
    load_chain_state,
    save_chain_state,
    write_payload,
    compute_event_hash_v2,
    sign_event_hash,
    b64e,
    utc_now_iso,
    append_line_best_effort,
)

ZERO32_HEX = "00" * 32
ZERO_HASH = "sha256:" + ZERO32_HEX

CHAIN_ID_U8 = 2  # R (Reality)


def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()


def norm_entry(e: Dict[str, Any]) -> Dict[str, Any]:
    # Keep only a minimal stable subset (thin facts).
    return {
        "PRIORITY": e.get("PRIORITY"),
        "SYSLOG_IDENTIFIER": e.get("SYSLOG_IDENTIFIER"),
        "_SYSTEMD_UNIT": e.get("_SYSTEMD_UNIT"),
        "MESSAGE": e.get("MESSAGE"),
    }


def journal_iter(cursor_file: pathlib.Path, max_entries: int) -> List[Dict[str, Any]]:
    cmd = [
        "journalctl",
        "-o", "json",
        "--cursor-file", str(cursor_file),
        "--no-pager",
    ]
    # We intentionally do NOT use -n because we want "since cursor". The cursor-file controls it.
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or "journalctl failed")
    out: List[Dict[str, Any]] = []
    for line in cp.stdout.splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
            if max_entries and len(out) >= max_entries:
                break
        except Exception:
            continue
    return out


def current_time_block_id(dirs: Dict[str, pathlib.Path]) -> int:
    t_state = load_chain_state(dirs["state"] / "chain_T.json")
    tb = t_state.get("last_time_block_id")
    if isinstance(tb, int) and tb >= 0:
        return tb
    if isinstance(t_state.get("seq_no"), int) and t_state["seq_no"] > 0:
        return int(t_state["seq_no"])
    return 0


def emit_receipt(
    *,
    dirs: Dict[str, pathlib.Path],
    sk,
    kid: str,
    subject_id_hex: str,
    capture_dev_hex: str,
    seq_no: int,
    time_block_id: int,
    prev_event_hash: str,
    payload: Dict[str, Any],
) -> str:
    payload_hash, payload_ref = write_payload(dirs["payloads"], payload)
    event_hash = compute_event_hash_v2(
        chain_id_u8=CHAIN_ID_U8,
        subject_id_hex=subject_id_hex,
        seq_no=seq_no,
        time_block_id=time_block_id,
        local_monotime_ns=int(payload.get("monotime_ns", 0)),
        capture_device_hex=capture_dev_hex,
        prev_event_hash=prev_event_hash,
        payload_hash=payload_hash,
    )
    sig_raw = sign_event_hash(sk, event_hash)
    envelope = {
        "schema": "AEVUM:EVENT_ENVELOPE:V2",
        "chain_id_u8": CHAIN_ID_U8,
        "chain_label": "R",
        "subject_id_hex": subject_id_hex,
        "seq_no": seq_no,
        "time_block_id": time_block_id,
        "local_monotime_ns": int(payload.get("monotime_ns", 0)),
        "capture_device_hex": capture_dev_hex,
        "prev_event_hash": prev_event_hash,
        "payload_hash": payload_hash,
        "payload_ref": payload_ref,
        "event_hash": event_hash,
        "signature": {
            "alg": "Ed25519",
            "kid": kid,
            "sig_b64": b64e(sig_raw),
            "signed_at": utc_now_iso(),
            "canonicalization": "WIRE_EVENT_HASH_CANON_V1",
        },
    }
    line = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    append_line_best_effort(dirs["receipts"] / "R.jsonl", line, mode=0o600)
    return event_hash


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation instance base.")
    ap.add_argument("--cursor-file", default="", help="Cursor file path. Default: <state>/journald.cursor")
    ap.add_argument("--max-entries", type=int, default=20000, help="Max journald entries per run.")
    ap.add_argument("--sample-max", type=int, default=50, help="Max hashed samples to include.")
    ap.add_argument("--once", action="store_true", help="Run once and exit (default).")
    args = ap.parse_args()

    if os.geteuid() != 0 and str(args.base).startswith('/var/lib/'):
        print('Run as root.', file=sys.stderr)
        return 2

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    ident = load_identity_private(base / "identity" / "identity.json")
    sk = ident["sk"]
    kid = ident["kid"]
    subject_id_hex = ident["subject_id_hex"]
    capture_dev_hex = ident["capture_device_hex"]

    chain_state_path = dirs["state"] / "chain_R.json"
    state = load_chain_state(chain_state_path)
    seq_no = int(state.get("seq_no", 0))
    prev_event_hash = state.get("prev_event_hash", ZERO_HASH)

    cursor_file = pathlib.Path(args.cursor_file) if args.cursor_file else (dirs["state"] / "journald.cursor")
    cursor_file.parent.mkdir(parents=True, exist_ok=True)

    t0 = int(time.time())
    try:
        entries = journal_iter(cursor_file, args.max_entries)
    except Exception as e:
        print(f"SKIP: journalctl failed: {e}", file=sys.stderr)
        return 0
    t1 = int(time.time())

    # Aggregate counts
    by_pri: Dict[str, int] = {}
    by_unit: Dict[str, int] = {}
    by_ident: Dict[str, int] = {}
    nft_drops = 0
    kernel_warn = 0

    samples: List[str] = []
    for e in entries:
        pri = str(e.get("PRIORITY", "NA"))
        by_pri[pri] = by_pri.get(pri, 0) + 1
        unit = str(e.get("_SYSTEMD_UNIT", "NA"))
        by_unit[unit] = by_unit.get(unit, 0) + 1
        ident = str(e.get("SYSLOG_IDENTIFIER", "NA"))
        by_ident[ident] = by_ident.get(ident, 0) + 1

        msg = str(e.get("MESSAGE", ""))
        if "AEVUM_NFT" in msg or msg.startswith("AEVUM_DROP_"):
            nft_drops += 1
        if ident == "kernel" and (("warn" in msg.lower()) or ("error" in msg.lower())):
            kernel_warn += 1

        if len(samples) < args.sample_max:
            ne = norm_entry(e)
            h = sha256_hex(json.dumps(ne, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            samples.append("sha256:" + h)

    payload = {
        "type": "JournaldSummaryPayload",
        "schema_version": "JSPv1",
        "wallclock_start_unix": t0,
        "wallclock_end_unix": t1,
        "monotime_ns": int(time.monotonic_ns()),
        "entries_scanned": len(entries),
        "counts_by_priority": by_pri,
        "counts_by_systemd_unit": by_unit,
        "counts_by_syslog_identifier": by_ident,
        "signals": {
            "nft_drop_entries": nft_drops,
            "kernel_warnlike_entries": kernel_warn,
        },
        "hashed_samples": samples,
        "note": "Thin-fact summary: counts + hashed samples only (no raw journald dumping).",
    }

    seq_no += 1
    tbid = current_time_block_id(dirs)
    event_hash = emit_receipt(
        dirs=dirs, sk=sk, kid=kid, subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
        seq_no=seq_no, time_block_id=tbid, prev_event_hash=prev_event_hash, payload=payload,
    )

    state.update({"seq_no": seq_no, "prev_event_hash": event_hash})
    save_chain_state(chain_state_path, state)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())