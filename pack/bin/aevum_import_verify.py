#!/usr/bin/env python3
"""
aevum_import_verify.py (v0.1)

Safe import workflow for an Aevum instance export bundle.

Goal
- Never "adopt" foreign receipts blindly.
- Import into a staging directory, verify, recover chain state, then allow operator promotion.

Inputs
- export bundle: tar.gz created by aevum_export_bundle.py
  expected to contain:
    aevum_instance/MANIFEST.json
    aevum_instance/identity/identity.public.json (optional)
    aevum_instance/receipts/*.jsonl
    aevum_instance/policies/... (optional)

What it does
1) Extract bundle to staging dir
2) Validate MANIFEST.json hashes (integrity check)
3) Run verifier on each receipts log present (hash chain + event_hash recompute)
   - Signature check optional: if identity.public.json exists, verify signatures too.
4) Run recovery to reconstruct chain state tails (chain_<CHAIN>.json)
5) Outputs a summary report JSON

Non-blocking posture
- This tool is operator workflow only.
- Runtime daemons do not depend on it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import tarfile
import hashlib
import os
import shutil
import subprocess
import sys
from typing import Dict, Any, List, Optional

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_extract(tar: tarfile.TarFile, path: pathlib.Path) -> None:
    path = path.resolve()
    for member in tar.getmembers():
        member_path = (path / member.name).resolve()
        if not str(member_path).startswith(str(path) + os.sep) and member_path != path:
            raise RuntimeError(f"Unsafe path in tar: {member.name}")
    tar.extractall(path)

def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def main() -> int:
    ap = argparse.ArgumentParser(description="Import and verify an Aevum export bundle into staging.")
    ap.add_argument("--bundle", required=True, help="Path to export tar.gz")
    ap.add_argument("--staging", required=True, help="Directory to extract and verify into")
    ap.add_argument("--keep-staging", action="store_true", help="Do not delete staging on failure")
    ap.add_argument("--strict-manifest", action="store_true", help="Fail if any manifest file is missing")
    ap.add_argument("--skip-signatures", action="store_true", help="Do not verify signatures even if identity.public.json exists")
    args = ap.parse_args()

    bundle = pathlib.Path(args.bundle)
    staging = pathlib.Path(args.staging)

    if staging.exists():
        # require empty staging for safety
        if any(staging.iterdir()):
            print("ERROR: staging dir must be empty (or not exist).", file=sys.stderr)
            return 2
    staging.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "schema": "AEVUM:IMPORT_VERIFY_REPORT:V1",
        "bundle": str(bundle),
        "staging": str(staging),
        "steps": {},
        "verifier": {},
        "recovery": {},
        "ok": False,
        "errors": [],
        "warnings": [],
    }

    try:
        # 1) Extract
        with tarfile.open(bundle, "r:gz") as tf:
            safe_extract(tf, staging)
        report["steps"]["extract"] = "ok"

        root = staging / "aevum_instance"
        manifest_path = root / "MANIFEST.json"
        if not manifest_path.exists():
            report["errors"].append("missing MANIFEST.json")
            raise RuntimeError("missing manifest")

        # 2) Validate manifest hashes
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = man.get("files") or []
        missing = 0
        bad = 0
        checked = 0

        for ent in files:
            rel = ent.get("path")
            expected = ent.get("sha256")
            if not rel or not expected:
                continue
            checked += 1
            p = staging / rel
            if not p.exists():
                missing += 1
                if args.strict_manifest:
                    bad += 1
                continue
            got = sha256_file(p)
            if got != expected:
                bad += 1

        report["steps"]["manifest"] = {"checked": checked, "missing": missing, "bad": bad}
        if bad > 0:
            report["errors"].append(f"manifest check failed (bad={bad}, missing={missing})")
            raise RuntimeError("manifest failed")

        # 3) Run verifier
        receipts_dir = root / "receipts"
        ident_pub = root / "identity" / "identity.public.json"
        chains_present = []
        for p in sorted(receipts_dir.glob("*.jsonl")):
            chains_present.append(p.stem)

        if not chains_present:
            report["errors"].append("no receipts logs found in bundle")
            raise RuntimeError("no logs")

        # Ensure local verifier scripts are installed; otherwise fallback to bundled copy if available
        verifier_bin = shutil.which("aevum_verify.py") or shutil.which("aevum_verify")
        recover_bin = shutil.which("aevum_recover_chain.py") or shutil.which("aevum_recover_chain")

        # If not installed, attempt to run from same directory as this script
        here = pathlib.Path(__file__).resolve().parent
        if not verifier_bin:
            local = here / "aevum_verify.py"
            if local.exists():
                verifier_bin = str(local)
        if not recover_bin:
            local = here / "aevum_recover_chain.py"
            if local.exists():
                recover_bin = str(local)

        if not verifier_bin or not recover_bin:
            report["errors"].append("missing aevum_verify.py or aevum_recover_chain.py in PATH or script dir")
            raise RuntimeError("missing tools")

        verifier_results = {}
        for ch in chains_present:
            cmd = [verifier_bin, "--base", str(root), "--log", str(receipts_dir / f"{ch}.jsonl")]
            if ident_pub.exists() and not args.skip_signatures:
                cmd += ["--identity", str(ident_pub)]
            cp = run(cmd)
            verifier_results[ch] = {
                "returncode": cp.returncode,
                "stdout": cp.stdout.strip(),
                "stderr": cp.stderr.strip(),
            }
            if cp.returncode != 0:
                report["errors"].append(f"verifier failed for {ch}")
                raise RuntimeError("verifier failed")

        report["verifier"] = verifier_results

        # 4) Recovery: create state files under root/accurate/state (seam layout)
        recovery_results = {}
        for ch in chains_present:
            if ch not in ["P","R","PHI","I","T"]:
                # ignore unknown chain logs in Year-1 import
                report["warnings"].append(f"skipping unknown chain log {ch}")
                continue
            cmd = [recover_bin, "--base", str(root), "--chain", ch, "--write-state"]
            if ident_pub.exists() and not args.skip_signatures:
                cmd += ["--identity", str(ident_pub)]
            cp = run(cmd)
            recovery_results[ch] = {
                "returncode": cp.returncode,
                "stdout": cp.stdout.strip(),
                "stderr": cp.stderr.strip(),
            }
            if cp.returncode != 0:
                report["errors"].append(f"recovery failed for {ch}")
                raise RuntimeError("recovery failed")

        report["recovery"] = recovery_results

        report["ok"] = True
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    except Exception as e:
        report["errors"].append(str(e))
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        if not args.keep_staging:
            try:
                shutil.rmtree(staging)
            except Exception:
                pass
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
