#!/usr/bin/env python3
"""
aevum_export_bundle.py (v0.1)

Create an export bundle (tar.gz) for moving an Aevum instance between machines.
Non-blocking: does not mutate receipts.

Includes (configurable):
- identity.public.json
- receipts/*.jsonl
- optional: policies/registries (if present under accurate/policies)

Also writes a MANIFEST.json with sha256 hashes for quick integrity checking.
"""

from __future__ import annotations
import argparse, pathlib, tarfile, json, hashlib, os
from typing import List, Dict

from aevum_common import resolve_storage_dirs, sha256_hex

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def add_file(tf: tarfile.TarFile, root: pathlib.Path, p: pathlib.Path, arc_prefix: str, manifest: List[Dict[str,str]]):
    rel = p.relative_to(root)
    arcname = str(pathlib.Path(arc_prefix) / rel)
    tf.add(p, arcname=arcname, recursive=False)
    manifest.append({"path": arcname, "sha256": sha256_file(p)})

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Instance base to export.")
    ap.add_argument("--out", required=True, help="Output .tar.gz path")
    ap.add_argument("--include-policies", action="store_true", help="Include accurate/policies if present.")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    d = resolve_storage_dirs(base)
    receipts_dir = d["receipts"]
    out = pathlib.Path(args.out)

    manifest = []
    out.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(out, "w:gz") as tf:
        # identity public
        ip = base / "identity" / "identity.public.json"
        if ip.exists():
            add_file(tf, base, ip, "aevum_instance", manifest)
        # receipts
        if receipts_dir.exists():
            for p in sorted(receipts_dir.glob("*.jsonl")):
                add_file(tf, receipts_dir, p, "aevum_instance/receipts", manifest)

        # optional policies
        if args.include_policies:
            pol = base / "accurate" / "policies"
            if pol.exists():
                for p in sorted(pol.rglob("*")):
                    if p.is_file():
                        add_file(tf, pol, p, "aevum_instance/policies", manifest)

        # manifest itself
        man_obj = {"schema": "AEVUM:EXPORT:MANIFEST:V1", "files": sorted(manifest, key=lambda x: x["path"])}
        man_bytes = json.dumps(man_obj, indent=2, sort_keys=True).encode("utf-8")
        man_hash = hashlib.sha256(man_bytes).hexdigest()
        man_obj["manifest_sha256"] = man_hash
        tmp = out.parent / (out.name + ".MANIFEST.json")
        tmp.write_text(json.dumps(man_obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tf.add(tmp, arcname="aevum_instance/MANIFEST.json", recursive=False)
        tmp.unlink(missing_ok=True)

    print(str(out))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
