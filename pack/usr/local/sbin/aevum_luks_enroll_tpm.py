#!/usr/bin/env python3
"""
aevum_luks_enroll_tpm.py
Enroll a TPM2 token into an existing LUKS2 volume using systemd-cryptenroll.
Captures evidence (command outputs + PCR snapshot refs) and mints a receipt.
"""

import argparse, json, os, pathlib, subprocess, sys, time, hashlib

BASE="/var/lib/aevum/workstation/luks"

def sh(cmd, check=True):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stdout}")
    return p.stdout

def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def receipt(note: str, kv: dict):
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if not ctl.exists():
        print("WARN: missing aevum_receiptctl.py; skipping receipt", file=sys.stderr)
        return
    args=[sys.executable, str(ctl), "note", note] + [f"{k}={v}" for k,v in kv.items()]
    p=subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        print("WARN: receiptctl failed:\n"+p.stdout, file=sys.stderr)
    else:
        print(p.stdout.strip())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--pcrs", default="0+2+7")
    ap.add_argument("--wipe-slot", action="store_true", help="Wipe existing TPM2 token slots first (optional)")
    ap.add_argument("--execute", action="store_true")
    args=ap.parse_args()

    dev=args.device
    ts=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    outdir=pathlib.Path(BASE)
    outdir.mkdir(parents=True, exist_ok=True)

    plan={"ts_utc":ts, "device":dev, "pcrs":args.pcrs, "mode":"execute" if args.execute else "plan_only"}
    plan_path=outdir/f"luks_tpm_enroll_plan_{ts}.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")

    kv={"component":"luks_tpm_enroll","luks_device":dev,"tpm2_pcrs":args.pcrs,"mode":plan["mode"],
        "plan_sha256":"sha256:"+sha256_file(plan_path), "plan_path":str(plan_path)}

    if not args.execute:
        print("PLAN ONLY. Commands:")
        cmds=[]
        if args.wipe_slot:
            cmds.append(["systemd-cryptenroll","--wipe-slot=tpm2", dev])
        cmds.append(["systemd-cryptenroll","--tpm2-device=auto","--tpm2-pcrs="+args.pcrs, dev])
        print(json.dumps(cmds, indent=2))
        receipt("LUKS TPM enroll plan (not executed)", kv)
        return 0

    logs=[]
    try:
        if args.wipe_slot:
            logs.append({"cmd":["systemd-cryptenroll","--wipe-slot=tpm2", dev], "output":sh(["systemd-cryptenroll","--wipe-slot=tpm2", dev])[-4000:]})
        logs.append({"cmd":["systemd-cryptenroll","--tpm2-device=auto","--tpm2-pcrs="+args.pcrs, dev], "output":sh(["systemd-cryptenroll","--tpm2-device=auto","--tpm2-pcrs="+args.pcrs, dev])[-4000:]})
    except Exception as e:
        logs.append({"error":str(e)})

    log_path=outdir/f"luks_tpm_enroll_exec_{ts}.json"
    log_path.write_text(json.dumps(logs, indent=2), encoding="utf-8")

    kv["exec_log_sha256"]="sha256:"+sha256_file(log_path)
    kv["exec_log_path"]=str(log_path)
    kv["status"]="ok" if (logs and "error" not in logs[-1]) else "failed"

    # best-effort pcr snapshot tool pointer
    pcr_snap_tool = pathlib.Path("/opt/aevum-tools/bin/aevum-tpm-pcr-snapshot")
    if pcr_snap_tool.exists():
        try:
            out = subprocess.run([str(pcr_snap_tool)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            kv["pcr_snapshot_invoked"]="true" if out.returncode==0 else "false"
        except Exception:
            pass

    receipt("LUKS TPM enroll executed", kv)
    return 0 if kv["status"]=="ok" else 1

if __name__=="__main__":
    raise SystemExit(main())
