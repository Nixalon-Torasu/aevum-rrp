#!/usr/bin/env python3
"""
aevum_verify_evidence.py (v0.1)

Verifies Aevum evidence bundles by recomputing sha256 hashes of referenced artifacts.

Supported:
- aevum_boot_unlock_evidence_v2 JSON

Exit:
 0 PASS
 2 FAIL
"""

from __future__ import annotations
import argparse, json, pathlib, hashlib, os, sys
from typing import Dict, Any, List



def enforce_unlock_invariant(data: Dict[str, Any], strict: bool, policy_path: str) -> List[str]:
    """
    Proof-grade rule:
    If luks_policy.unlock_mode == "tpm2_only", then evidence MUST show method tpm2_proof for unlocked volumes.
    """
    # fails initialized above
    pp = pathlib.Path(policy_path)
    if not pp.exists():
        return ["missing luks_policy.json"] if strict else []
    try:
        pol = json.loads(pp.read_text(encoding="utf-8"))
    except Exception as e:
        return [f"invalid luks_policy.json: {e}"] if strict else []
    if str(pol.get("unlock_mode","tpm2_prefer")).lower() != "tpm2_only":
        return []

    vols = data.get("volumes", []) or []
    for v in vols:
        name = str(v.get("name",""))
        unlocked = bool(v.get("unlocked", False))
        method = (v.get("method_claim") or v.get("method_inferred") or v.get("method") or v.get("unlock_method") or "unknown")
        method = str(method)
        if not unlocked:
            fails.append(f"{name}: not unlocked (tpm2_only requires unlocked)")
            continue
        if method != "tpm2_proof":
            fails.append(f"{name}: method={method} (requires tpm2_proof in tpm2_only mode)")
    return fails

def sha256_path(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="", help="Evidence JSON file path")
    ap.add_argument("--dir", default="", help="Directory to scan for evidence files (boot_unlock_evidence_*.json)")
    ap.add_argument("--strict", action="store_true", help="Fail on any policy/invariant violation")
    ap.add_argument("--policy", default="/etc/aevum/registry/luks_policy.json", help="LUKS policy path")
    args = ap.parse_args()

    files: List[pathlib.Path] = []
    if args.dir:
        d = pathlib.Path(args.dir)
        if not d.exists():
            print("FAIL: missing dir", file=sys.stderr)
            return 2
        files = sorted(d.glob("boot_unlock_evidence_*.json"))
        if not files:
            print("FAIL: no evidence files found", file=sys.stderr)
            return 2 if args.strict else 0
    else:
        if not args.file:
            print("FAIL: provide --file or --dir", file=sys.stderr)
            return 2
        p = pathlib.Path(args.file)
        if not p.exists():
            print("FAIL: missing file", file=sys.stderr)
            return 2
        files = [p]

    data_list: List[Dict[str, Any]] = []
    for fp in files:
        try:
            data_list.append(json.loads(fp.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"FAIL: unreadable json: {fp}: {e}", file=sys.stderr)
            return 2


    etype = data.get("type","")

    fails: List[str] = []

    if etype == "aevum_boot_unlock_evidence_v2":
        for a in data.get("artifacts", []):
            apath = pathlib.Path(a.get("path",""))
            want = a.get("sha256","")
            if not apath.exists():
                fails.append(f"missing artifact: {apath}")
                continue
            got = sha256_path(apath)
            if want and got != want:
                fails.append(f"hash mismatch: {apath} want={want} got={got}")
    else:
        fails.append(f"unsupported evidence type: {etype}")

    if fails:
        print("FAIL:")
        for f in fails:
            print("  - " + f)
        return 2

    print("PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
