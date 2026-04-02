#!/usr/bin/env python3
"""aevum_status.py (v0.1)

Lightweight, read-mostly status for the workstation boundary.
Focus: liveness, receipt spine progress, and anchor health.
"""
from __future__ import annotations
import argparse, json, pathlib, subprocess, time
from typing import Dict, Any, Optional
from aevum_common import resolve_storage_dirs

UNITS = [
  "aevum-controlplane.service",
  "aevum-firewall.service",
  "aevum-timechain.service",
  "aevum-rrp-printer.service",
  "aevum-segment.timer",
  "aevum-binary-harvest.timer",
]

def systemd_unit_state(unit: str) -> Dict[str, Any]:
    # best effort; no hard failure if systemctl not available
    try:
        p = subprocess.run(["systemctl","is-active",unit], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        active = p.stdout.strip()
    except Exception:
        active = "unknown"
    return {"unit": unit, "active": active}

def read_json(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def file_stat(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False}
    st = path.stat()
    return {"path": str(path), "exists": True, "bytes": st.st_size, "mtime": st.st_mtime}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    status: Dict[str, Any] = {"base": str(base), "ts": time.time(), "services": [], "chains": {}, "files": {}}

    # services
    status["services"] = [systemd_unit_state(u) for u in UNITS]

    # chain spines
    for ch in ["T","I","P","R","F"]:
        st = read_json(dirs["state"]/f"chain_{ch}.json") or {}
        status["chains"][ch] = {
            "seq_no": st.get("seq_no"),
            "prev_event_hash": st.get("prev_event_hash"),
            "last_time_block_id": st.get("last_time_block_id"),
        }
        status["files"][f"active_{ch}"] = file_stat(dirs["receipts"]/f"{ch}.jsonl")

    # TPM anchor presence
    status["files"]["tpm_pub"] = file_stat(base/"tpm_sign"/"sign.pub.pem")
    status["files"]["tpm_state"] = file_stat(base/"tpm_sign"/"tpm_state.json")

    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print(f"Base: {base}")
        t = status["chains"]["T"]
        print(f"TimeChain: seq={t.get('seq_no')} tb={t.get('last_time_block_id')}")
        for s in status["services"]:
            print(f"{s['active']:>8}  {s['unit']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
