#!/usr/bin/env python3
"""
aevum_ima_snapshot.py — Measure-only IMA snapshot anchoring.

Reads:
- /sys/kernel/security/ima/ascii_runtime_measurements

Writes:
- /var/lib/aevum/workstation/ima/ima_snapshot_<bootid>_<ts>.json  (small)
Optionally stores a compressed copy of the measurement list if requested (off by default).

Mints:
- A receipt via aevum_receiptctl.py note, with pointers to the snapshot file.

Non-gating: if IMA isn't present, exits non-zero with clear error.
"""

import argparse, hashlib, json, pathlib, subprocess, sys, datetime, gzip

MEAS = pathlib.Path("/sys/kernel/security/ima/ascii_runtime_measurements")
CMDLINE = pathlib.Path("/proc/cmdline")
BOOTID = pathlib.Path("/proc/sys/kernel/random/boot_id")

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--store-measurements-gz", action="store_true",
                    help="Store gzip copy of measurement list (can grow large). Off by default.")
    ap.add_argument("--max-bytes", type=int, default=262144, help="Max snapshot JSON bytes (safety).")
    args = ap.parse_args()

    if not MEAS.exists():
        print("SKIP: IMA measurements file missing (kernel may not support IMA).", file=sys.stderr)
        return 0

    base = pathlib.Path(args.base)
    outdir = base / "ima"
    outdir.mkdir(parents=True, exist_ok=True)

    boot = BOOTID.read_text().strip()
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # compute digest + line count cheaply
    meas_sha = sha256_file(MEAS)
    try:
        # line count without loading whole file
        p = subprocess.run(["/usr/bin/wc", "-l", str(MEAS)], stdout=subprocess.PIPE, text=True, check=True)
        lines = int(p.stdout.strip().split()[0])
    except Exception:
        lines = -1

    cmd_sha = hashlib.sha256(CMDLINE.read_bytes()).hexdigest()

    snap = {
        "type": "aevum_ima_snapshot_v1",
        "ts_utc": ts,
        "boot_id": boot,
        "kernel_cmdline_sha256": "sha256:" + cmd_sha,
        "ima_measurements_sha256": "sha256:" + meas_sha,
        "ima_measurements_lines": lines,
        "measurements_path": str(MEAS),
    }

    # add small sample (first 5 + last 5 lines) for debugging without huge payload
    try:
        head = subprocess.run(["/usr/bin/head", "-n", "5", str(MEAS)], stdout=subprocess.PIPE, text=True).stdout.splitlines()
        tail = subprocess.run(["/usr/bin/tail", "-n", "5", str(MEAS)], stdout=subprocess.PIPE, text=True).stdout.splitlines()
        snap["sample_head"] = head
        snap["sample_tail"] = tail
    except Exception:
        pass

    snap_json = json.dumps(snap, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(snap_json) > args.max_bytes:
        print("FAIL: snapshot JSON too large (unexpected).", file=sys.stderr)
        return 2

    snap_path = outdir / f"ima_snapshot_{boot}_{ts}.json"
    snap_path.write_bytes(snap_json)

    meas_gz_path = ""
    if args.store_measurements_gz:
        meas_gz_path = str(outdir / f"ima_measurements_{boot}_{ts}.txt.gz")
        with MEAS.open("rb") as src, gzip.open(meas_gz_path, "wb") as dst:
            shutil_copyfileobj(src, dst)

    # mint receipt via receiptctl
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if not ctl.exists():
        print("FAIL: missing aevum_receiptctl.py", file=sys.stderr)
        return 2

    kv = [
        f"component=aevum_ima",
        f"ima_boot_id={boot}",
        f"ima_snapshot_path={snap_path}",
        f"ima_snapshot_sha256=sha256:{hashlib.sha256(snap_path.read_bytes()).hexdigest()}",
        f"ima_measurements_sha256=sha256:{meas_sha}",
        f"ima_measurements_lines={lines}",
        f"kernel_cmdline_sha256=sha256:{cmd_sha}",
    ]
    if meas_gz_path:
        kv.append(f"ima_measurements_gz_path={meas_gz_path}")

    args2 = [sys.executable, str(ctl), "note", "IMA snapshot anchor"] + kv
    p2 = subprocess.run(args2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p2.returncode != 0:
        print("FAIL: receiptctl note failed", file=sys.stderr)
        print(p2.stdout)
        return 2

    print(p2.stdout.strip())
    return 0

def shutil_copyfileobj(fsrc, fdst, length=16*1024*1024):
    while True:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)

if __name__ == "__main__":
    raise SystemExit(main())
