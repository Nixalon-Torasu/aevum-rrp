#!/usr/bin/env python3
"""
aevum_tail.py (v0.1)

Print last N receipt records for a chain log. Convenience tool.
"""

from __future__ import annotations
import argparse, pathlib, os, json
from aevum_common import resolve_storage_dirs

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--chain", required=True, choices=["P","R","PHI","I","T"])
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    d = resolve_storage_dirs(base)
    log = d["receipts"] / f"{args.chain}.jsonl"
    if not log.exists():
        print(f"missing: {log}")
        return 2

    with log.open("rb") as f:
        try:
            f.seek(max(0, log.stat().st_size - 262144), os.SEEK_SET)
        except Exception:
            f.seek(0)
        lines = f.read().splitlines()

    out = []
    for line in reversed(lines):
        if not line.strip():
            continue
        out.append(line.decode("utf-8", errors="replace"))
        if len(out) >= args.n:
            break
    for s in reversed(out):
        if args.pretty:
            try:
                print(json.dumps(json.loads(s), indent=2, sort_keys=True))
            except Exception:
                print(s)
        else:
            print(s)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
