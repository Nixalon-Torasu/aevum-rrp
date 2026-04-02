#!/usr/bin/env python3

"""
aevum_secureboot_capture.py (v0.1)

Capture Secure Boot posture (best-effort evidence, non-gating).
Writes artifacts under <base>/<instance>/boot/secureboot and emits a receipt note.

Collected:
- mokutil --sb-state
- SecureBoot EFI var (if present)
- bootctl status (if systemd-boot)
- kernel cmdline
"""
from __future__ import annotations
import argparse, datetime as dt, os, pathlib, subprocess, json, hashlib

def run(cmd:list[str]) -> tuple[int,str,str]:
    try:
        p=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 127, "", str(e)

def sha256_file(p:pathlib.Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def utc()->str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum")
    ap.add_argument("--instance", default="workstation")
    args=ap.parse_args()

    root=pathlib.Path(args.base)/args.instance
    outdir=root/"boot"/"secureboot"
    outdir.mkdir(parents=True, exist_ok=True)
    ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    report={"type":"aevum_secureboot_report_v1","timestamp_utc":utc(),"instance":args.instance,"checks":{}}

    rc, so, se = run(["mokutil","--sb-state"])
    report["checks"]["mokutil_sb_state"]={"rc":rc,"stdout":so.strip(),"stderr":se.strip()}

    # EFI var read (if accessible)
    efivar = pathlib.Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if efivar.exists():
        try:
            b=efivar.read_bytes()
            report["checks"]["efi_SecureBoot"]={"present":True,"raw_hex":b.hex(),"sha256":hashlib.sha256(b).hexdigest()}
        except Exception as e:
            report["checks"]["efi_SecureBoot"]={"present":True,"error":str(e)}
    else:
        report["checks"]["efi_SecureBoot"]={"present":False}

    rc, so, se = run(["bootctl","status"])
    report["checks"]["bootctl_status"]={"rc":rc,"stdout":so.strip()[:20000],"stderr":se.strip()}

    try:
        cmdline=pathlib.Path("/proc/cmdline").read_text(encoding="utf-8").strip()
    except Exception:
        cmdline=""
    report["checks"]["kernel_cmdline"]=cmdline

    out = outdir / f"secureboot_{ts}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)

    h = "sha256:" + sha256_file(out)

    # Emit receipt note if available
    receipt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if receipt.exists() and os.access(receipt, os.X_OK):
        subprocess.run([str(receipt),"note","secureboot posture","component=boot","file="+str(out),"manifest="+h], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"OK: {out} {h}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
