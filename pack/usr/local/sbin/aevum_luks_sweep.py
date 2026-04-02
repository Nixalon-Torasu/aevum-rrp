#!/usr/bin/env python3
"""
aevum_luks_sweep.py
Reads /etc/aevum/registry/luks_devices.json and snapshots each device (best-effort).
Non-gating; failures are receipted as notes.
"""
import json, pathlib, subprocess, sys, time, os

REG=pathlib.Path("/etc/aevum/registry/luks_devices.json")
SNAP=pathlib.Path("/usr/local/sbin/aevum_luks_snapshot.py")
CTL=pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")

def receipt(msg, kv):
    if not CTL.exists():
        return
    args=[sys.executable, str(CTL), "note", msg] + [f"{k}={v}" for k,v in kv.items()]
    subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def main():
    if not REG.exists() or not SNAP.exists():
        return 0
    try:
        cfg=json.loads(REG.read_text(encoding="utf-8"))
    except Exception as e:
        receipt("LUKS sweep cannot parse registry", {"component":"luks_sweep","error":str(e)})
        return 0
    devs=cfg.get("devices",[])
    for d in devs:
        try:
            subprocess.run([sys.executable, str(SNAP), "--device", d], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            receipt("LUKS sweep snapshot failed", {"component":"luks_sweep","device":d,"error":str(e)})
    return 0

if __name__=="__main__":
    raise SystemExit(main())
