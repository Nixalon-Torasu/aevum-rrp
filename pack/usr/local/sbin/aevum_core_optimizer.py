#!/usr/bin/env python3
"""
aevum_core_optimizer.py (v0.1)

Reads workstation receipts and writes checkpoints under core.
This is an OPTIMIZER only: it MUST NOT gate processing.

Checkpoints store:
- last_verified_seq_no
- last_event_hash
- byte offset (so verifier/indexers can resume without rescanning)

This is deliberately simple.
"""
from __future__ import annotations

import argparse, json, pathlib, os
from typing import Dict, Any

def find_receipts_dir(base: pathlib.Path) -> pathlib.Path:
    legacy = base / "receipts"
    seam = base / "accurate" / "receipts"
    return legacy if legacy.exists() else seam

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workstation-base", default="/var/lib/aevum/workstation")
    ap.add_argument("--core-base", default="/var/lib/aevum/core")
    ap.add_argument("--chain", default="T", help="Which chain to checkpoint (T/I/P/R/PHI)")
    args = ap.parse_args()

    wbase = pathlib.Path(args.workstation_base)
    cbase = pathlib.Path(args.core_base)

    rdir = find_receipts_dir(wbase)
    log = rdir / f"{args.chain}.jsonl"
    if not log.exists():
        print(f"SKIP: no receipts yet: {log}")
        return 0

    # Scan from start (Year-1). Later: use stored offsets.
    last_seq = 0
    last_hash = None
    last_pos = 0
    with log.open("rb") as f:
        for line in f:
            last_pos = f.tell()
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line.decode("utf-8"))
            except Exception:
                break
            last_seq = int(ev.get("seq_no", last_seq))
            last_hash = ev.get("event_hash", last_hash)

    outdir = cbase / "accurate" / "indexes"
    outdir.mkdir(parents=True, exist_ok=True)
    ck = {
        "schema": "AEVUM:CHECKPOINT:CHAIN_TAIL:V1",
        "source": str(log),
        "chain": args.chain,
        "last_verified_seq_no": last_seq,
        "last_event_hash": last_hash,
        "byte_offset": last_pos,
    }
    (outdir / f"workstation_{args.chain}_tail.json").write_text(json.dumps(ck, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
