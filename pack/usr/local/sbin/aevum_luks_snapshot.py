#!/usr/bin/env python3
"""
aevum_luks_snapshot.py
Creates a bounded evidence snapshot of a LUKS2 device:
- SHA256 over header region (default 16 MiB)
- cryptsetup luksDump output (artifact)
- systemd-cryptenroll --dump output (artifact)
- device size, UUID, label
Mints a receipt referencing these artifacts (printer-layer adds registry binding).
"""

import argparse, json, os, pathlib, subprocess, sys, time, hashlib

BASE=os.environ.get("AEVUM_LUKS_BASE","/var/lib/aevum/workstation/luks")

def sh(cmd, check=False):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stdout}")
    return p.returncode, p.stdout

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def header_sha256(dev: str, nbytes: int) -> str:
    # Read first nbytes using dd for block devices
    cmd=["dd", f"if={dev}", "bs=1M", f"count={(nbytes + (1024*1024-1))//(1024*1024)}", "status=none"]
    p=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data=p.stdout[:nbytes]
    return sha256_bytes(data)

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
    if os.geteuid() != 0 and str(BASE).startswith("/var/lib/"):
        print("Run as root.", file=sys.stderr)
        return 2

    ap=argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--header-bytes", type=int, default=16*1024*1024)
    args=ap.parse_args()

    dev=args.device
    ts=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    outdir=pathlib.Path(BASE)
    outdir.mkdir(parents=True, exist_ok=True)

    # Gather facts
    size_rc, size_out = sh(["blockdev","--getsize64", dev])
    dev_size = size_out.strip() if size_rc==0 else ""
    uuid_rc, uuid_out = sh(["cryptsetup","luksUUID", dev])
    luks_uuid = uuid_out.strip() if uuid_rc==0 else ""

    hdr = header_sha256(dev, args.header_bytes)

    dump_rc, dump_out = sh(["cryptsetup","luksDump", dev])
    dump_path=outdir/f"luksDump_{ts}.txt"
    dump_path.write_text(dump_out, encoding="utf-8")

    enr_rc, enr_out = sh(["systemd-cryptenroll","--dump", dev])
    enr_path=outdir/f"cryptenroll_dump_{ts}.txt"
    enr_path.write_text(enr_out, encoding="utf-8")

    snap={
        "ts_utc": ts,
        "device": dev,
        "device_size_bytes": dev_size,
        "luks_uuid": luks_uuid,
        "header_region_bytes": args.header_bytes,
        "luks_header_region_sha256": "sha256:"+hdr,
        "artifacts": {
            "luksDump": {"path": str(dump_path), "sha256": "sha256:"+sha256_file(dump_path)},
            "cryptenroll_dump": {"path": str(enr_path), "sha256": "sha256:"+sha256_file(enr_path)},
        }
    }
    snap_path=outdir/f"luks_snapshot_{ts}.json"
    snap_path.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")

    kv={
        "component":"luks_snapshot",
        "luks_device": dev,
        "luks_uuid": luks_uuid,
        "device_size": dev_size,
        "header_bytes": str(args.header_bytes),
        "luks_header_sha256": "sha256:"+hdr,
        "snapshot_path": str(snap_path),
        "snapshot_sha256": "sha256:"+sha256_file(snap_path),
    }
    receipt("LUKS snapshot captured", kv)
    print(json.dumps(snap, indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
