#!/usr/bin/env python3
"""
aevum_luks_init.py
Plan/execute helper for creating a LUKS2 volume and opening it.
Default is PLAN-ONLY. Use --execute and --i-understand-this-wipes-data to run destructive actions.
Mints a receipt describing the plan/result (printer-layer adds sealed registry binding automatically).
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
    ap.add_argument("--device", required=True, help="/dev/nvme0n1pX or /dev/sdXN")
    ap.add_argument("--name", default="aevum_crypt", help="mapper name (crypttab name)")
    ap.add_argument("--label", default="AEVUM", help="LUKS label")
    ap.add_argument("--header-bytes", type=int, default=16*1024*1024)
    ap.add_argument("--mkfs", choices=["ext4","xfs","btrfs","none"], default="none")
    ap.add_argument("--mount", default="", help="mountpoint to create and mount (optional)")
    ap.add_argument("--execute", action="store_true", help="Actually run commands")
    ap.add_argument("--i-understand-this-wipes-data", action="store_true")
    args=ap.parse_args()

    dev=args.device
    ts=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    outdir=pathlib.Path(BASE)
    outdir.mkdir(parents=True, exist_ok=True)
    plan_path=outdir/f"luks_init_plan_{ts}.json"

    plan={
        "ts_utc": ts,
        "device": dev,
        "name": args.name,
        "label": args.label,
        "header_region_bytes": args.header_bytes,
        "mkfs": args.mkfs,
        "mount": args.mount,
        "mode": "execute" if args.execute else "plan_only",
        "commands": [
            ["cryptsetup","luksFormat","--type","luks2","--label",args.label, dev],
            ["cryptsetup","open", dev, args.name],
        ]
    }
    if args.mkfs != "none":
        plan["commands"].append(["mkfs."+args.mkfs, f"/dev/mapper/{args.name}"])
    if args.mount:
        plan["commands"].append(["mkdir","-p", args.mount])
        plan["commands"].append(["mount", f"/dev/mapper/{args.name}", args.mount])

    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")

    kv={
        "component":"luks_init",
        "luks_device": dev,
        "luks_name": args.name,
        "luks_label": args.label,
        "mode": plan["mode"],
        "plan_sha256": "sha256:"+sha256_file(plan_path),
        "plan_path": str(plan_path),
    }

    if not args.execute:
        print(json.dumps(plan, indent=2))
        receipt("LUKS init plan (not executed)", kv)
        return 0

    if not args.i_understand_this_wipes_data:
        print("ERROR: --execute requires --i-understand-this-wipes-data", file=sys.stderr)
        receipt("LUKS init refused (missing confirmation)", {**kv, "refused":"true"})
        return 2

    # Execute commands; note that cryptsetup luksFormat will prompt for passphrase.
    logs=[]
    for c in plan["commands"]:
        try:
            out=sh(c, check=True)
        except Exception as e:
            logs.append({"cmd":c, "error":str(e)})
            break
        logs.append({"cmd":c, "output":out[-4000:]})
    log_path=outdir/f"luks_init_exec_{ts}.json"
    log_path.write_text(json.dumps(logs, indent=2), encoding="utf-8")

    kv["exec_log_sha256"]="sha256:"+sha256_file(log_path)
    kv["exec_log_path"]=str(log_path)
    kv["status"]="ok" if (logs and "error" not in logs[-1]) else "failed"
    receipt("LUKS init executed", kv)
    return 0 if kv["status"]=="ok" else 1

if __name__=="__main__":
    raise SystemExit(main())
