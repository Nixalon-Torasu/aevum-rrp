#!/usr/bin/env python3
"""
aevum_luks_expected_tokens.py (v0.1)

Maintains the "expected" LUKS token metadata digests for proof-grade unlock classification.

Rationale:
- Boot evidence captures a LUKS metadata artifact hash per volume (cryptsetup luksDump metadata).
- Enroll-time captures a token snapshot containing the corresponding metadata hash.
- If expected metadata hash matches boot metadata hash AND passphrase prompting is disabled, then
  "boot success implies TPM unlock" (proof-grade within Aevum's defined boundary).

State file (NOT registry):
- /var/lib/aevum/workstation/luks/tokens/expected_tokens.json

This is state because it changes when you enroll/rotate tokens; registry remains policy.
"""

from __future__ import annotations
import argparse, json, pathlib, subprocess, datetime, hashlib, os, sys
from typing import Dict, Any, List, Optional

STATE_PATH = pathlib.Path("/var/lib/aevum/workstation/luks/tokens/expected_tokens.json")

def load_json(p: pathlib.Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))

def atomic_write_json(p: pathlib.Path, obj: Dict[str, Any]):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)

def find_latest_token_snapshot(outdir: pathlib.Path) -> Optional[pathlib.Path]:
    if not outdir.exists():
        return None
    snaps = sorted(outdir.glob("token_snapshot_*_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    return snaps[0] if snaps else None

def sha256_path(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def extract_luks_meta_sha(snapshot: Dict[str, Any]) -> str:
    for a in snapshot.get("artifacts", []) or []:
        if a.get("kind") == "luks_metadata" and a.get("sha256"):
            return str(a["sha256"])
    return ""

def mint_receipt(note: str, kv: List[str]):
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        subprocess.run([str(r), "note", note] + kv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cmd_set(args):
    outdir = pathlib.Path(args.token_snapshot_dir)
    snap_path = pathlib.Path(args.snapshot) if args.snapshot else find_latest_token_snapshot(outdir)
    if not snap_path or not snap_path.exists():
        print("ERROR: token snapshot not found. Provide --snapshot or ensure snapshots exist.", file=sys.stderr)
        return 2

    snap = load_json(snap_path)
    luks_uuid = str(snap.get("luks_uuid","")).strip()
    if not luks_uuid:
        print("ERROR: token snapshot missing luks_uuid", file=sys.stderr)
        return 2

    meta_sha = extract_luks_meta_sha(snap)
    snap_sha = sha256_path(snap_path)

    st = {"type":"aevum_expected_tokens_v1", "version":"1.0.0", "updated_utc": None, "expected": {}}
    if STATE_PATH.exists():
        try:
            st = load_json(STATE_PATH)
        except Exception:
            pass

    st.setdefault("expected", {})
    st["expected"][luks_uuid] = {
        "luks_metadata_sha256": meta_sha,
        "token_snapshot_sha256": snap_sha,
        "token_snapshot_path": str(snap_path),
        "set_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pcrs": args.pcrs or "",
    }
    st["updated_utc"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    atomic_write_json(STATE_PATH, st)

    mint_receipt("luks expected token set", [
        "component=crypto",
        f"luks_uuid={luks_uuid}",
        f"expected_luks_metadata_sha256={meta_sha}",
        f"expected_token_snapshot_sha256={snap_sha}",
        f"expected_state_path={str(STATE_PATH)}",
    ])

    print(str(STATE_PATH))
    return 0

def cmd_show(args):
    if not STATE_PATH.exists():
        print("{}", end="")
        return 0
    print(STATE_PATH.read_text(encoding="utf-8"), end="")
    return 0

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("set")
    s.add_argument("--token-snapshot-dir", default="/var/lib/aevum/workstation/luks/tokens")
    s.add_argument("--snapshot", default="")
    s.add_argument("--pcrs", default="")
    s.set_defaults(fn=cmd_set)

    sh = sub.add_parser("show")
    sh.set_defaults(fn=cmd_show)

    args = ap.parse_args()
    return args.fn(args)

if __name__ == "__main__":
    raise SystemExit(main())
