#!/usr/bin/env python3
"""
aevum_canon_digest.py

Build a stable canon_digest from a list of files.
Method:
- Compute sha256 for each file
- Create a manifest JSON: {"generated_at": ..., "files":[{"path":..., "sha256":...}, ...]}
- canon_digest = sha256( canonical_json(manifest) )

This aligns with Seam: canon_digest identifies a normative bundle but MUST NOT be required for basic function.
"""

from __future__ import annotations
import argparse, hashlib, json, pathlib, datetime as dt

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output manifest path (json).")
    ap.add_argument("files", nargs="+", help="Files to include in canon bundle.")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    manifest = {"generated_at": utc_now_iso(), "files": []}
    for f in args.files:
        p = pathlib.Path(f)
        manifest["files"].append({"path": str(p), "sha256": sha256_hex(p.read_bytes())})
    manifest["files"].sort(key=lambda x: x["path"])

    digest = "sha256:" + sha256_hex(canonical_json_bytes(manifest))
    manifest["canon_digest"] = digest

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(digest)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
