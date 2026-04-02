#!/usr/bin/env python3
"""Aevum Segmenter (v0.2)

Deterministic segmentation by canonical time_block windows.

Best-effort: never blocks producers. If an active log contains corruption at tail,
segmenter only operates on the prefix that parses as valid JSON.
"""
from __future__ import annotations
import argparse, json, pathlib, os, hashlib
from typing import Dict, Any, List, Tuple, Optional

from aevum_common import resolve_storage_dirs, atomic_write_text

ZERO_HASH = "sha256:" + ("00"*32)

def load_policy() -> Dict[str, Any]:
    p = pathlib.Path("/etc/aevum/registry/segment_policy.json")
    if not p.exists():
        return {"enabled": False}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": False}

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def file_sha256_tagged(path: pathlib.Path) -> str:
    return "sha256:" + sha256_bytes(path.read_bytes())

def compute_merkle_root_sha256(leaves_hex: List[str]) -> str:
    """Pairwise SHA256 Merkle root over event_hash raw32 leaves.
    leaves_hex are 64-hex sha256 strings (no 'sha256:' prefix).
    """
    if not leaves_hex:
        return ZERO_HASH
    level = [bytes.fromhex(x) for x in leaves_hex]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i+1 < len(level):
                nxt.append(hashlib.sha256(level[i] + level[i+1]).digest())
            else:
                nxt.append(hashlib.sha256(level[i] + level[i]).digest())
        level = nxt
    return "sha256:" + level[0].hex()

def timechain_last_tb(base: pathlib.Path) -> int:
    st = base/"accurate"/"state"/"chain_T.json"
    if not st.exists():
        return 0
    try:
        obj = json.loads(st.read_text(encoding="utf-8"))
        tb = obj.get("last_time_block_id")
        if isinstance(tb, int) and tb >= 0:
            return tb
    except Exception:
        pass
    return 0

def cutoff_tb(now_tb: int, window: int) -> int:
    if window <= 0:
        return -1
    return (now_tb // window) * window - 1

def iter_valid_lines(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                break
            yield line, ev

def split_by_cutoff(active: pathlib.Path, cutoff: int) -> Tuple[List[str], List[str], Dict[str, Any]]:
    seg_lines: List[str] = []
    keep_lines: List[str] = []
    meta: Dict[str, Any] = {"line_count": 0}
    first_seq=last_seq=0
    first_tb=last_tb=0
    first_hash=last_hash=""
    leaves: List[str] = []

    for line, ev in iter_valid_lines(active):
        tb = int(ev.get("time_block_id") or 0)
        if tb <= cutoff:
            seg_lines.append(line)
            meta["line_count"] += 1
            seq = int(ev.get("seq_no") or 0)
            eh = str(ev.get("event_hash") or "")
            if meta["line_count"] == 1:
                first_seq, first_tb, first_hash = seq, tb, eh
            last_seq, last_tb, last_hash = seq, tb, eh
            if isinstance(eh, str) and eh.startswith("sha256:") and len(eh)==71:
                leaves.append(eh.split(":",1)[1])
        else:
            keep_lines.append(line)

    meta.update({
        "first_seq_no": first_seq,
        "last_seq_no": last_seq,
        "first_time_block_id": first_tb,
        "last_time_block_id": last_tb,
        "first_event_hash": first_hash,
        "last_event_hash": last_hash,
        "merkle_root_sha256": compute_merkle_root_sha256(leaves),
    })
    return seg_lines, keep_lines, meta

def seg_root(base: pathlib.Path, chain: str) -> pathlib.Path:
    p = base/"accurate"/"segments"/chain
    p.mkdir(parents=True, exist_ok=True)
    return p

def next_index(segroot: pathlib.Path) -> int:
    mx = 0
    for m in segroot.glob("manifest_*.json"):
        try:
            # manifest_<INDEX>...
            stem = m.stem
            part = stem.split("_",2)[1]
            mx = max(mx, int(part))
        except Exception:
            pass
    return mx+1

def last_manifest_sha(segroot: pathlib.Path) -> str:
    mans = sorted(segroot.glob("manifest_*.json"))
    if not mans:
        return ""
    return "sha256:" + sha256_bytes(mans[-1].read_bytes())

def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--chain", default="", help="Rotate only this chain")
    ap.add_argument("--force", action="store_true", help="Ignore cutoff and force rotate all valid lines")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    base = pathlib.Path(args.base)
    pol = load_policy()
    out: Dict[str, Any] = {"base": str(base), "enabled": bool(pol.get("enabled", False)), "results": []}

    if not bool(pol.get("enabled", False)):
        if args.json:
            print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    dirs = resolve_storage_dirs(base)
    chains = pol.get("chains") or ["T","I"]
    if args.chain:
        chains = [args.chain]

    now_tb = timechain_last_tb(base)
    window = int(pol.get("window_seconds", 3600) or 3600)
    cutoff = cutoff_tb(now_tb, window)

    for chain in chains:
        active = dirs["receipts"]/f"{chain}.jsonl"
        if not active.exists():
            out["results"].append({"chain": chain, "rotated": False, "reason": "active_missing"})
            continue

        if args.force:
            seg_lines, keep_lines, meta = split_by_cutoff(active, 10**18)
        else:
            if cutoff < 0:
                out["results"].append({"chain": chain, "rotated": False, "reason": "cutoff_negative", "now_tb": now_tb})
                continue
            seg_lines, keep_lines, meta = split_by_cutoff(active, cutoff)

        if not seg_lines:
            out["results"].append({"chain": chain, "rotated": False, "reason": "nothing_to_segment"})
            continue

        min_lines = int(pol.get("min_segment_lines", 0) or 0)
        if (not args.force) and min_lines and meta["line_count"] < min_lines:
            out["results"].append({"chain": chain, "rotated": False, "reason": "too_few_lines", "lines": meta["line_count"]})
            continue

        segroot = seg_root(base, chain)
        idx = next_index(segroot)

        first_tb = meta["first_time_block_id"]; last_tb = meta["last_time_block_id"]
        first_seq = meta["first_seq_no"]; last_seq = meta["last_seq_no"]

        seg_file = segroot / f"seg_{idx:08d}_tb_{first_tb}_{last_tb}__seq_{first_seq}_{last_seq}.jsonl"
        man_file = segroot / f"manifest_{idx:08d}_tb_{first_tb}_{last_tb}__seq_{first_seq}_{last_seq}.json"

        # write segment
        seg_bytes = ("\n".join(seg_lines) + "\n").encode("utf-8")
        atomic_write_text(seg_file, seg_bytes.decode("utf-8"), mode=0o600)

        # write new active with kept lines
        new_active = ("\n".join(keep_lines) + ("\n" if keep_lines else "")).encode("utf-8")
        atomic_write_text(active, new_active.decode("utf-8"), mode=0o600)

        seg_sha = file_sha256_tagged(seg_file)
        prev_man = last_manifest_sha(segroot)

        manifest = {
            "schema": pol.get("manifest_schema", "AEVUM:SEGMENT_MANIFEST:V1"),
            "chain": chain,
            "segment_index": idx,
            "segment_file": str(seg_file.relative_to(base)),
            "segment_sha256": seg_sha,
            "line_count": meta["line_count"],
            "first_seq_no": first_seq,
            "last_seq_no": last_seq,
            "first_time_block_id": first_tb,
            "last_time_block_id": last_tb,
            "first_event_hash": meta["first_event_hash"],
            "last_event_hash": meta["last_event_hash"],
            "merkle_root_sha256": meta["merkle_root_sha256"],
            "prev_manifest_sha256": prev_man,
        }
        atomic_write_text(man_file, json.dumps(manifest, indent=2, sort_keys=True)+"\n", mode=0o600)
        man_sha = "sha256:" + sha256_bytes(man_file.read_bytes())

        out["results"].append({"chain": chain, "rotated": True, "manifest_sha256": man_sha, "segment_sha256": seg_sha, "segment_file": str(seg_file)})

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        for r in out["results"]:
            print(("OK" if r.get("rotated") else "SKIP"), r["chain"], r.get("reason",""), r.get("manifest_sha256",""))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
