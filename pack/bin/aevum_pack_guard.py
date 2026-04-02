#!/usr/bin/env python3
"""
conical_guard.py

Pack conicality enforcement: prevent silent drift by requiring new packs to include a required path set.
Supports explicit deprecations (must be signed by the registry mechanism on target systems).

This tool is used in two places:
- Pre-install: gitops/verify_pack.sh
- Optional operator invocation: /opt/aevum-tools/bin/aevum-pack-guard

Inputs:
- --pack-root: directory of unpacked pack (default: repo root)
- --required-paths: JSON file listing required paths (default: gitops/release_cone_required_paths.json)
- --deprecations: optional registry file listing deprecated paths (default: etc/aevum/registry/registry_deprecations.json)

Exit codes:
0 pass
2 missing required paths
"""
from __future__ import annotations
import argparse, json, pathlib, sys

def load_json(p: pathlib.Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack-root", default="", help="Unpacked pack root (default: auto-detect from this script).")
    ap.add_argument("--required-paths", default="gitops/release_cone_required_paths.json", help="Required path set.")
    ap.add_argument("--deprecations", default="etc/aevum/registry/registry_deprecations.json", help="Deprecated path list (optional).")
    ap.add_argument("--json", action="store_true", help="Emit JSON report.")
    args = ap.parse_args()

    if args.pack_root:
        root = pathlib.Path(args.pack_root).resolve()
    else:
        root = pathlib.Path(args.pack_root).resolve() if args.pack_root else pathlib.Path("/opt/aevum-pack").resolve()
    req_path = (root / args.required_paths).resolve() if not pathlib.Path(args.required_paths).is_absolute() else pathlib.Path(args.required_paths)
    dep_path = (root / args.deprecations).resolve() if not pathlib.Path(args.deprecations).is_absolute() else pathlib.Path(args.deprecations)

    req = load_json(req_path)
    paths = req.get("required_paths") or []
    if not isinstance(paths, list) or not paths:
        print(f"WARN: required path set missing/empty: {req_path}", file=sys.stderr)
        return 0

    deprec = set()
    dep = load_json(dep_path) if dep_path.exists() else {}
    for e in dep.get("entries") or []:
        try:
            p = str(e.get("path","")).strip()
            if p:
                deprec.add(p)
        except Exception:
            pass

    missing = []
    for p in paths:
        p = str(p)
        if p in deprec:
            continue
        if not (root / p).exists():
            missing.append(p)

    report = {
        "schema": "AEVUM:PACK:CONE_REPORT:V1",
        "pack_root": str(root),
        "required_count": len(paths),
        "deprecated_count": len(deprec),
        "missing_count": len(missing),
        "missing": missing[:500],
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if missing:
            print(f"FAIL: conical guard missing {len(missing)} required paths")
            for p in missing[:50]:
                print("  - " + p)
            if len(missing) > 50:
                print(f"  ... ({len(missing)-50} more)")
        else:
            print(f"PASS: conical guard (required paths present: {len(paths) - len(deprec)})")

    return 0 if not missing else 2

if __name__ == "__main__":
    raise SystemExit(main())
