#!/usr/bin/env python3
"""
aevum_prune_payloads.py (v0.1)

Prune payload files while keeping receipts intact (payloads are optional/prunable).

Default behavior is SAFE:
- Dry-run unless --apply
- Keeps payloads referenced by the last N receipts across selected chains
- Deletes other payload files in payloads/

This supports your “pointers over payloads” model: receipts remain verifiable commitments; payloads can be retained as desired.
"""

from __future__ import annotations
import argparse, pathlib, json, os
from typing import Set

from aevum_common import resolve_storage_dirs

def scan_keep_set(receipts_dir: pathlib.Path, chain: str, keep_last: int) -> Set[str]:
    log = receipts_dir / f"{chain}.jsonl"
    keep = set()
    if not log.exists():
        return keep
    # read tail chunk and collect payload_refs; stop when collected keep_last records
    with log.open("rb") as f:
        try:
            f.seek(max(0, log.stat().st_size - 2_000_000), os.SEEK_SET)
        except Exception:
            f.seek(0)
        lines = f.read().splitlines()
    cnt = 0
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line.decode("utf-8"))
        except Exception:
            continue
        pref = ev.get("payload_ref")
        if isinstance(pref, str):
            keep.add(pathlib.Path(pref).name)  # store basename only
        cnt += 1
        if cnt >= keep_last:
            break
    return keep

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--chains", default="T,I,P,R,PHI", help="Comma-separated chains to consider for keep set.")
    ap.add_argument("--keep-last", type=int, default=10000, help="Keep payloads referenced by last N receipts per chain.")
    ap.add_argument("--apply", action="store_true", help="Actually delete files (otherwise dry-run).")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    d = resolve_storage_dirs(base)
    receipts_dir = d["receipts"]
    payloads_dir = d["payloads"]

    chains = [c.strip() for c in args.chains.split(",") if c.strip()]
    keep = set()
    for c in chains:
        keep |= scan_keep_set(receipts_dir, c, args.keep_last)

    removed = 0
    kept = 0
    missing = 0

    for p in payloads_dir.glob("*.json"):
        name = p.name
        if name in keep:
            kept += 1
            continue
        if args.apply:
            try:
                p.unlink()
                removed += 1
            except Exception:
                missing += 1
        else:
            removed += 1

    mode = "APPLY" if args.apply else "DRY_RUN"
    print(json.dumps({
        "mode": mode,
        "payloads_dir": str(payloads_dir),
        "keep_payload_files": len(keep),
        "would_remove_or_removed": removed,
        "kept": kept,
        "errors": missing,
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
