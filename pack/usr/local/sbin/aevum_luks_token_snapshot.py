#!/usr/bin/env python3
"""
aevum_luks_token_snapshot.py (v0.1)

Proof-grade evidence capture for LUKS2 token metadata (TPM2 enrollment evidence).

Captures:
- cryptsetup token list
- per-token export (if supported) OR luksDump JSON metadata (best-effort)
- device resolution (UUIDs)
- hashes of all artifacts

Writes:
  /var/lib/aevum/workstation/luks/tokens/token_snapshot_<deviceid>_<ts>.json

Mints:
  a note receipt referencing snapshot digest (via /opt/aevum-tools/bin/aevum-receipt)
"""

from __future__ import annotations
import argparse, json, pathlib, subprocess, hashlib, datetime, re, os, sys
from typing import Dict, Any, List

def run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.stdout

def sha256_path(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def best_device_id(dev: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", dev.strip())
    return s[:120] if s else "device"

def try_token_ids(token_list: str) -> List[int]:
    ids: List[int] = []
    for ln in token_list.splitlines():
        m = re.match(r"\s*Token\s+(\d+)\s*:", ln)
        if m:
            ids.append(int(m.group(1)))
    return sorted(set(ids))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True, help="LUKS device path, e.g. /dev/nvme0n1p3")
    ap.add_argument("--outdir", default="/var/lib/aevum/workstation/luks/tokens")
    ap.add_argument("--no-receipt", action="store_true")
    args = ap.parse_args()

    dev = args.device
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dev_id = best_device_id(dev)

    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        return 2

    if subprocess.run(["cryptsetup", "isLuks", dev], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        print(f"INFO: {dev} is not LUKS. Skip.")
        return 0

    token_list = run(["cryptsetup", "token", "list", dev])
    token_list_path = outdir / f"token_list_{dev_id}_{ts}.txt"
    token_list_path.write_text(token_list, encoding="utf-8")

    artifacts: List[Dict[str, Any]] = [{"kind":"token_list", "path": str(token_list_path), "sha256": sha256_path(token_list_path)}]
    token_ids = try_token_ids(token_list)

    for tid in token_ids:
        exp_path = outdir / f"token_{dev_id}_{tid}_{ts}.txt"
        out = run(["cryptsetup", "token", "export", "--token-id", str(tid), dev])
        exp_path.write_text(out, encoding="utf-8")
        artifacts.append({"kind":"token_export", "token_id": tid, "path": str(exp_path), "sha256": sha256_path(exp_path)})

    meta_path = outdir / f"luks_metadata_{dev_id}_{ts}.txt"
    meta = run(["cryptsetup", "luksDump", dev, "--dump-json-metadata"])
    if ("Unknown option" in meta) or ("unrecognized option" in meta.lower()) or (meta.strip() == ""):
        meta = run(["cryptsetup", "luksDump", dev])
    meta_path.write_text(meta, encoding="utf-8")
    artifacts.append({"kind":"luks_metadata", "path": str(meta_path), "sha256": sha256_path(meta_path)})

    luks_uuid = run(["cryptsetup", "luksUUID", dev]).strip()

    snap = {
        "type": "aevum_luks_token_snapshot_v1",
        "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device": dev,
        "luks_uuid": luks_uuid,
        "token_ids": token_ids,
        "artifacts": artifacts,
    }
    snap_path = outdir / f"token_snapshot_{dev_id}_{ts}.json"
    snap_path.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
    snap_sha = sha256_path(snap_path)

    if not args.no_receipt:
        r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
        if r.exists():
            subprocess.run([str(r), "note", "luks token snapshot",
                            "component=crypto",
                            f"device={dev}",
                            f"luks_uuid={luks_uuid}",
                            f"snapshot_sha256={snap_sha}",
                            f"snapshot_path={str(snap_path)}"], check=False)

    print(str(snap_path))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
