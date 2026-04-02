#!/usr/bin/env python3
"""
aevum_promote_instance.py (v0.1)

Atomically promote a verified staging instance into a target instance directory.

Typical flow
1) Create export bundle from source machine:
   aevum_export_bundle.py --base /var/lib/aevum/workstation --out /tmp/ws.tar.gz --include-policies

2) Import+verify into staging:
   aevum_import_verify.py --bundle /tmp/ws.tar.gz --staging /tmp/ws_stage

3) Promote into live target:
   aevum_promote_instance.py --staging /tmp/ws_stage/aevum_instance --target /var/lib/aevum/workstation

Guarantees
- Uses rename() operations (atomic on same filesystem).
- Keeps a timestamped backup of the previous target.
- Writes a PROMOTION_NOTE.json into target/accurate/state (non-gating, operator record).

Safety
- Refuses to promote if staging doesn't look like an Aevum instance root.
- Refuses to overwrite a non-empty target unless you pass --allow-nonempty-target.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sys
import datetime as dt
from typing import Dict, Any

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def is_aevum_instance_root(p: pathlib.Path) -> bool:
    # Minimal expected structure from our packs
    if (p / "receipts").exists() or (p / "accurate" / "receipts").exists():
        return True
    # also accept bundled import layout: identity + receipts + MANIFEST.json nearby
    if (p / "identity").exists() and (p / "receipts").exists():
        return True
    return False

def same_filesystem(a: pathlib.Path, b: pathlib.Path) -> bool:
    return a.resolve().anchor == b.resolve().anchor and os.stat(a).st_dev == os.stat(b).st_dev

def ensure_parent(p: pathlib.Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def write_promotion_note(target: pathlib.Path, note: Dict[str, Any]) -> None:
    state_dir = target / "accurate" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    out = state_dir / "PROMOTION_NOTE.json"
    out.write_text(json.dumps(note, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(out, 0o600)
    except Exception:
        pass

def main() -> int:
    ap = argparse.ArgumentParser(description="Promote staging Aevum instance into live target (atomic).")
    ap.add_argument("--staging", required=True, help="Path to staging instance root (usually <staging>/aevum_instance).")
    ap.add_argument("--target", required=True, help="Live instance directory (e.g., /var/lib/aevum/workstation).")
    ap.add_argument("--backup-dir", default="", help="Directory to store backups. Default: <target_parent>/.aevum_backups")
    ap.add_argument("--allow-nonempty-target", action="store_true", help="Allow promoting over a non-empty target (will backup first).")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without modifying filesystem.")
    args = ap.parse_args()

    staging = pathlib.Path(args.staging).resolve()
    target = pathlib.Path(args.target).resolve()

    if not staging.exists():
        print(f"ERROR: staging path not found: {staging}", file=sys.stderr)
        return 2
    if not is_aevum_instance_root(staging):
        print(f"ERROR: staging does not look like an Aevum instance root: {staging}", file=sys.stderr)
        return 3

    # Target parent must exist so st_dev can be compared (if target doesn't exist yet, compare with parent)
    target_parent = target.parent
    if not target_parent.exists():
        print(f"ERROR: target parent does not exist: {target_parent}", file=sys.stderr)
        return 4

    # Ensure atomic rename possible: staging and target parent must be same filesystem
    if not same_filesystem(staging, target_parent):
        print("ERROR: staging and target are on different filesystems; atomic promote not possible.", file=sys.stderr)
        print("Hint: place staging under the same mount as target (e.g., /var/lib/aevum/.staging).", file=sys.stderr)
        return 5

    # Determine backup dir
    backup_root = pathlib.Path(args.backup_dir).resolve() if args.backup_dir else (target_parent / ".aevum_backups")
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_root / f"{target.name}.{ts}.bak"

    # Check target emptiness
    if target.exists():
        if not args.allow_nonempty_target:
            # only allow if empty
            if any(target.iterdir()):
                print("ERROR: target exists and is not empty. Use --allow-nonempty-target to backup and replace.", file=sys.stderr)
                return 6

    actions = []

    # Plan
    actions.append({"op": "mkdir", "path": str(backup_root)})
    if target.exists() and any(target.iterdir()):
        actions.append({"op": "rename", "from": str(target), "to": str(backup_path)})
    else:
        # if target empty or doesn't exist, remove it first (so rename staging -> target works)
        if target.exists():
            actions.append({"op": "rmtree_empty_target", "path": str(target)})
        else:
            actions.append({"op": "ensure_parent", "path": str(target_parent)})
    actions.append({"op": "rename", "from": str(staging), "to": str(target)})

    note = {
        "schema": "AEVUM:PROMOTION_NOTE:V1",
        "promoted_at": utc_now_iso(),
        "staging": str(staging),
        "target": str(target),
        "backup": str(backup_path) if (target.exists() and any(target.iterdir())) else None,
    }

    if args.dry_run:
        print(json.dumps({"dry_run": True, "actions": actions, "note": note}, indent=2, sort_keys=True))
        return 0

    # Execute
    backup_root.mkdir(parents=True, exist_ok=True)

    if target.exists() and any(target.iterdir()):
        target.rename(backup_path)
    else:
        if target.exists():
            # must be empty
            shutil.rmtree(target)
        ensure_parent(target)

    staging.rename(target)

    write_promotion_note(target, note)

    print("OK")
    print(json.dumps(note, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
