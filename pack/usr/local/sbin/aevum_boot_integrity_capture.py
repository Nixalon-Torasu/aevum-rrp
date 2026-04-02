#!/usr/bin/env python3
"""
aevum_boot_integrity_capture.py (v0.1)

Produces a *single* bounded boot-integrity snapshot that ties together:
- Secure Boot posture report
- TPM measured-boot eventlog manifest (if present)
- TPM PCR snapshot (if present)
- Current boot_id + cmdline hash

This is evidence for Aevum-Core to build DAGs from. It is non-gating.
Receipts are minted by the workstation printer layer and automatically include registry-binding.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
from typing import Any, Dict, Optional, Tuple

def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_file(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def latest_glob(dirp: pathlib.Path, pattern: str) -> Optional[pathlib.Path]:
    if not dirp.exists():
        return None
    items = sorted(dirp.glob(pattern), key=lambda p: p.name)
    return items[-1] if items else None

def read_text(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")

def cmdline_hash() -> str:
    try:
        c = pathlib.Path("/proc/cmdline").read_text(encoding="utf-8").strip().encode("utf-8")
        return "sha256:" + hashlib.sha256(c).hexdigest()
    except Exception:
        return "sha256:" + hashlib.sha256(b"").hexdigest()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum")
    ap.add_argument("--instance", default="workstation")
    ap.add_argument("--secureboot", default="", help="Path to secureboot_*.json (default: latest)")
    ap.add_argument("--eventlog", default="", help="Path to eventlog manifest_*.json (default: latest)")
    ap.add_argument("--pcr", default="", help="Path to pcr_*.json (default: latest)")
    args = ap.parse_args()

    root = pathlib.Path(args.base) / args.instance
    boot_dir = root / "boot"
    outdir = boot_dir / "boot_integrity"
    outdir.mkdir(parents=True, exist_ok=True)
    os.chmod(outdir, 0o700)

    sb_dir = boot_dir / "secureboot"
    ev_dir = boot_dir / "eventlog"

    sb = pathlib.Path(args.secureboot) if args.secureboot else latest_glob(sb_dir, "secureboot_*.json")
    ev = pathlib.Path(args.eventlog) if args.eventlog else latest_glob(ev_dir, "manifest_*.json")
    pcr = pathlib.Path(args.pcr) if args.pcr else latest_glob(boot_dir, "pcr_*.json")

    # boot_id
    try:
        boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        boot_id = ""

    # machine-id hash (do not leak raw)
    mid = pathlib.Path("/etc/machine-id")
    midh = ""
    if mid.exists():
        try:
            midh = "sha256:" + hashlib.sha256(mid.read_text(encoding="utf-8").strip().encode("utf-8")).hexdigest()
        except Exception:
            midh = ""

    snapshot: Dict[str, Any] = {
        "type": "aevum_boot_integrity_snapshot_v1",
        "timestamp_utc": utc(),
        "instance": args.instance,
        "boot_id": boot_id,
        "machine_id_sha256": midh,
        "kernel": os.uname().release,
        "cmdline_sha256": cmdline_hash(),
        "uefi": bool(pathlib.Path("/sys/firmware/efi").exists()),
        "references": {},
    }

    def add_ref(key: str, path: Optional[pathlib.Path]) -> None:
        if not path or not path.exists():
            snapshot["references"][key] = {"present": False}
            return
        try:
            snapshot["references"][key] = {
                "present": True,
                "path": str(path),
                "sha256": "sha256:" + sha256_file(path),
                "size_bytes": int(path.stat().st_size),
            }
        except Exception as e:
            snapshot["references"][key] = {"present": True, "path": str(path), "error": str(e)}

    add_ref("secureboot_report", sb)
    add_ref("tpm_eventlog_manifest", ev)
    add_ref("tpm_pcr_snapshot", pcr)

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = outdir / f"boot_integrity_{ts}.json"
    out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)

    h = "sha256:" + sha256_file(out)

    receipt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if receipt.exists() and os.access(receipt, os.X_OK):
        subprocess.run([str(receipt), "note", "boot integrity snapshot", "component=boot", "file=" + str(out), "manifest=" + h],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"OK: {out} {h}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
