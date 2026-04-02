#!/usr/bin/env python3
"""
aevum_hw_inventory.py — Capture hardware inventory snapshot and mint a receipt (pointers-over-payloads).

Produces JSON snapshot under:
  /var/lib/aevum/workstation/hw/inventory_<utc>.json

Then mints a receipt with:
  - sha256 of the snapshot file
  - key stable identifiers (cpu model, total mem, gpu uuids) in bounded form
"""

import argparse, datetime, hashlib, json, os, pathlib, subprocess, sys
from typing import Dict, Any, List, Optional

def run(cmd: List[str], timeout: int = 10) -> str:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def sha256_file(p: pathlib.Path) -> str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for ch in iter(lambda:f.read(65536), b""):
            h.update(ch)
    return h.hexdigest()

def maybe_json(out: str) -> Any:
    try:
        return json.loads(out)
    except Exception:
        return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    outdir = base/"hw"
    outdir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    snap_path = outdir/f"inventory_{ts}.json"

    snap: Dict[str, Any] = {
        "type": "aevum_hw_inventory_v1",
        "captured_at_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": run(["hostname"]),
        "kernel": run(["uname","-a"]),
        "lscpu": maybe_json(run(["lscpu","-J"], timeout=15)),
        "lsmem": maybe_json(run(["lsmem","--json"], timeout=15)),
        "lspci": run(["lspci","-nn"], timeout=15),
        "lsblk": run(["lsblk","-J","-O"], timeout=20),
        "dmidecode_memory": run(["dmidecode","-t","memory"], timeout=20),
        "nvidia_smi_xml": "",
        "nvidia_smi_query": "",
    }

    # NVIDIA (optional)
    if shutil.which("nvidia-smi"):
        snap["nvidia_smi_xml"] = run(["nvidia-smi","-q","-x"], timeout=20)
        snap["nvidia_smi_query"] = run(["nvidia-smi","--query-gpu=index,uuid,name,pci.bus_id,driver_version,memory.total,compute_cap","--format=csv,noheader"], timeout=20)

    # Write snapshot
    snap_path.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(snap_path, 0o600)
    digest = sha256_file(snap_path)

    # Extract bounded hints
    cpu_model = ""
    try:
        cpu_model = snap.get("lscpu",{}).get("lscpu",[{}])[0].get("data","")
    except Exception:
        pass
    total_mem = ""
    try:
        total_mem = str(snap.get("lsmem",{}).get("total_memory",""))
    except Exception:
        pass

    # Mint receipt (best-effort)
    rcpt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if rcpt.exists():
        subprocess.call([
            str(rcpt),"note","hardware inventory snapshot",
            "component=hw",
            f"inventory_path={snap_path}",
            f"inventory_sha256=sha256:{digest}",
            f"cpu_hint={str(cpu_model)[:120]}",
            f"mem_hint={str(total_mem)[:64]}",
        ])
    print(f"OK: inventory_sha256=sha256:{digest} path={snap_path}")
    return 0

if __name__ == "__main__":
    import shutil
    raise SystemExit(main())
