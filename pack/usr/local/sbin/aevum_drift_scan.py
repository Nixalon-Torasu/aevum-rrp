#!/usr/bin/env python3

"""
aevum_drift_scan.py (v0.1)

Compute and compare hashes of control surfaces to detect drift.
- Non-gating: never blocks system changes; it records drift for later audit.

Outputs:
<base>/<instance>/drift/drift_<ts>.json
and emits a receipt note.

Drift is a comparison against the most recent prior drift report (if any).
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, subprocess, fnmatch
from typing import Dict, Any, List, Tuple

def utc()->str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_file(p:pathlib.Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def walk_files(root:pathlib.Path)->List[pathlib.Path]:
    out=[]
    if root.is_file():
        return [root]
    for p in root.rglob("*"):
        if p.is_file():
            out.append(p)
    return out

def load_prev(dirp:pathlib.Path)->Dict[str,Any]|None:
    if not dirp.exists():
        return None
    prev=sorted([p for p in dirp.iterdir() if p.is_file() and p.name.startswith("drift_") and p.name.endswith(".json")])
    if not prev:
        return None
    try:
        return json.loads(prev[-1].read_text(encoding="utf-8"))
    except Exception:
        return None

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum")
    ap.add_argument("--instance", default="workstation")
    ap.add_argument("--paths", default="", help="Space-separated list of paths; defaults to /etc/aevum/hardening.conf AEVUM_DRIFT_PATHS")
    ap.add_argument("--max-files", type=int, default=20000)
    args=ap.parse_args()

    # load default paths from hardening.conf if present
    paths=args.paths.strip().split() if args.paths.strip() else []
    hc=pathlib.Path("/etc/aevum/hardening.conf")
    if not paths and hc.exists():
        txt=hc.read_text(encoding="utf-8", errors="ignore")
        for line in txt.splitlines():
            if line.startswith("AEVUM_DRIFT_PATHS="):
                val=line.split("=",1)[1].strip().strip('"')
                if val:
                    paths=val.split()
    if not paths:
        paths=["/etc/aevum","/etc/systemd/system","/usr/local/sbin","/opt/aevum-tools/bin","/etc/audit/rules.d","/etc/sysctl.d"]

    base=pathlib.Path(args.base)/args.instance
    outdir=base/"drift"
    outdir.mkdir(parents=True, exist_ok=True)
    ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    files=[]
    for p in paths:
        rp=pathlib.Path(p)
        if rp.exists():
            files.extend(walk_files(rp))
    # filter out volatile files
    files=[f for f in files if not f.name.endswith("~") and ".swp" not in f.name]
    files=sorted(set(files), key=lambda x: str(x))
    if len(files) > args.max_files:
        files = files[:args.max_files]

    snap={}
    for f in files:
        try:
            snap[str(f)]="sha256:"+sha256_file(f)
        except Exception:
            continue

    prev=load_prev(outdir)
    drift={"added":{}, "removed":{}, "changed":{}}
    if prev and isinstance(prev.get("snapshot"), dict):
        old=prev["snapshot"]
        for k,v in snap.items():
            if k not in old:
                drift["added"][k]=v
            elif old.get(k)!=v:
                drift["changed"][k]={"old":old.get(k), "new":v}
        for k,v in old.items():
            if k not in snap:
                drift["removed"][k]=v

    report={"type":"aevum_drift_report_v1","timestamp_utc":utc(),"instance":args.instance,"paths":paths,"snapshot":snap,"drift":drift}
    out=outdir/f"drift_{ts}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    os.chmod(out, 0o600)

    # receipt
    receipt=pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if receipt.exists() and os.access(receipt, os.X_OK):
        subprocess.run([str(receipt),"note","drift scan","component=drift","file="+str(out),"changed="+str(len(drift["changed"]))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"OK: {out} changed={len(drift['changed'])} added={len(drift['added'])} removed={len(drift['removed'])}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
