#!/usr/bin/env python3
"""aevum_receipts.py (v0.2)

Read-only operator CLI for receipt logs.

Segment-aware:
If manifests exist under `<base>/accurate/segments/<CHAIN>/manifest_*.json`,
the log is treated as `(segments in manifest order) + (active receipts/<CHAIN>.jsonl)`.
"""
from __future__ import annotations
import argparse, json, pathlib
from typing import Any, Dict, Optional, List
from aevum_common import resolve_storage_dirs

def seg_files(base: pathlib.Path, chain: str) -> List[pathlib.Path]:
    seg_root = base/"accurate"/"segments"/chain
    mans = sorted(seg_root.glob("manifest_*.json"))
    out: List[pathlib.Path] = []
    for m in mans:
        try:
            obj = json.loads(m.read_text(encoding="utf-8"))
            rel = obj.get("segment_file") or ""
            if rel:
                p = base/rel
                if p.exists():
                    out.append(p)
        except Exception:
            continue
    return out

def log_files(base: pathlib.Path, dirs: Dict[str, pathlib.Path], chain: str) -> List[pathlib.Path]:
    out: List[pathlib.Path] = []
    out.extend(seg_files(base, chain))
    active = dirs["receipts"]/f"{chain}.jsonl"
    if active.exists():
        out.append(active)
    if not out:
        raise FileNotFoundError(str(active))
    return out

def read_payload(dirs: Dict[str, pathlib.Path], payload_ref: str) -> Optional[Dict[str, Any]]:
    p = dirs["base"] / payload_ref
    if not p.exists():
        p2 = dirs["payloads"] / pathlib.Path(payload_ref).name
        if p2.exists():
            p = p2
        else:
            return None
    try:
        raw = p.read_bytes().strip()
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def iter_events(files: List[pathlib.Path]):
    for fp in files:
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield fp, line

def cmd_stats(args) -> int:
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    files = log_files(base, dirs, args.chain)
    count = 0
    first = None
    last = None
    for fp, line in iter_events(files):
        count += 1
        try:
            ev = json.loads(line)
        except Exception:
            break
        if first is None:
            first = ev
        last = ev
    print(json.dumps({"chain": args.chain, "count": count, "first_seq": (first or {}).get("seq_no"), "last_seq": (last or {}).get("seq_no")}, indent=2))
    return 0

def cmd_get(args) -> int:
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    files = log_files(base, dirs, args.chain)
    target = int(args.seq)
    for fp, line in iter_events(files):
        try:
            ev = json.loads(line)
        except Exception:
            break
        if int(ev.get("seq_no") or 0) == target:
            print(json.dumps(ev, indent=2, sort_keys=True))
            return 0
    print("NOT FOUND")
    return 2

def cmd_range(args) -> int:
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    files = log_files(base, dirs, args.chain)
    lo = int(args.from_tb)
    hi = int(args.to_tb)
    for fp, line in iter_events(files):
        try:
            ev = json.loads(line)
        except Exception:
            break
        tb = int(ev.get("time_block_id") or 0)
        if lo <= tb <= hi:
            print(line)
    return 0

def cmd_grep(args) -> int:
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    files = log_files(base, dirs, args.chain)
    needle = args.text
    for fp, line in iter_events(files):
        if needle in line:
            print(line)
    return 0

def cmd_payload(args) -> int:
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    obj = read_payload(dirs, args.ref)
    if obj is None:
        print("MISSING")
        return 3
    print(json.dumps(obj, indent=2, sort_keys=True))
    return 0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    sp = ap.add_subparsers(dest="cmd", required=True)

    s1 = sp.add_parser("stats"); s1.add_argument("--chain", required=True)
    s2 = sp.add_parser("get"); s2.add_argument("--chain", required=True); s2.add_argument("--seq", required=True)
    s3 = sp.add_parser("range"); s3.add_argument("--chain", required=True); s3.add_argument("--from", dest="from_tb", required=True); s3.add_argument("--to", dest="to_tb", required=True)
    s4 = sp.add_parser("grep"); s4.add_argument("--chain", required=True); s4.add_argument("--text", required=True)
    s5 = sp.add_parser("payload"); s5.add_argument("--ref", required=True)

    args = ap.parse_args()
    if args.cmd == "stats": return cmd_stats(args)
    if args.cmd == "get": return cmd_get(args)
    if args.cmd == "range": return cmd_range(args)
    if args.cmd == "grep": return cmd_grep(args)
    if args.cmd == "payload": return cmd_payload(args)
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
