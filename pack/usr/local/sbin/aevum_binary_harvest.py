#!/usr/bin/env python3
"""
aevum_binary_harvest.py (v0.1)

Goal: mint non-redundant receipts for binaries that have *executed* on the workstation.
This is after-the-fact evidence, not a governor.

How it works (Year-1 pragmatic):
- Reads auditd logs since a cursor (epoch seconds) and extracts exe paths from execve events.
- For each unique exe path:
  - Computes sha256 of the binary on disk
  - Records only if new or changed since last seen (non-redundant)
- Writes batch payloads to a dedicated chain "B" (Binary) under the workstation instance.

Defaults:
- Uses audit key "aevum_root_exec" (root-only execve) to avoid overwhelming auditd.
- You can switch to "all" mode by changing /etc/aevum/binary_harvest.conf.

Artifacts:
- State index:   <base>/state/binary_index.json
- Cursor:        <base>/binaries/cursor_epoch
- Chain log:     <base>/receipts/B.jsonl (or Seam layout equivalent)
- Payloads:      <base>/payloads/<hash>.json

Design:
- Batch up to N entries per receipt payload.
- Include a merkle root of the batch leaves for fast canopy building later.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import shutil
import time
from typing import Any, Dict, List, Tuple

from aevum_common import (
    resolve_storage_dirs,
    load_identity_private,
    load_chain_state,
    save_chain_state,
    write_payload,
    compute_event_hash_v2,
    sign_event_hash,
    b64e,
    utc_now_iso,
    append_line_best_effort,
)

ZERO32_HEX = "00" * 32
ZERO_HASH = "sha256:" + ZERO32_HEX

CHAIN_LABEL = "B"
CHAIN_ID_U8 = 6  # unused in this pack (TimeChain uses 5)


def _sha256_file(p: pathlib.Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _leaf_hash(path: str, file_sha256_hex: str) -> bytes:
    # Stable leaf: sha256( path + NUL + sha256hex )
    data = path.encode("utf-8", errors="surrogateescape") + b"\x00" + file_sha256_hex.encode("ascii")
    return hashlib.sha256(data).digest()


def _merkle_root(leaves: List[bytes]) -> str:
    if not leaves:
        return "sha256:" + ("00" * 32)
    lvl = leaves[:]
    while len(lvl) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(lvl), 2):
            a = lvl[i]
            b = lvl[i + 1] if i + 1 < len(lvl) else lvl[i]
            nxt.append(hashlib.sha256(a + b).digest())
        lvl = nxt
    return "sha256:" + lvl[0].hex()


def _load_json(path: pathlib.Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    return default


def _save_json(path: pathlib.Path, obj: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def _current_time_block_id(dirs: Dict[str, pathlib.Path]) -> int:
    # mirror receiptctl logic: use TimeChain state if present
    t_state = load_chain_state(dirs["state"] / "chain_T.json")
    tb = t_state.get("last_time_block_id")
    if isinstance(tb, int) and tb >= 0:
        return tb
    if isinstance(t_state.get("seq_no"), int) and t_state["seq_no"] > 0:
        return int(t_state["seq_no"])
    return 0


def _read_conf() -> Dict[str, str]:
    conf = pathlib.Path("/etc/aevum/binary_harvest.conf")
    out: Dict[str, str] = {}
    if conf.exists():
        for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _ausearch_since_epoch(epoch: int, key: str) -> str:
    if not shutil.which("ausearch"):
        return ""
    start_iso = _dt.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    try:
        # -i yields interpreted output; still contains exe="...".
        return subprocess.check_output(["ausearch", "-k", key, "-ts", start_iso, "-i", "--input-logs"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def _extract_exe_paths(audit_text: str) -> List[str]:
    # Capture exe="..."; fall back to exe=...
    paths: List[str] = []
    for m in re.finditer(r'exe=\\"([^\\"]+)\\"', audit_text):
        paths.append(m.group(1))
    if not paths:
        for m in re.finditer(r'\bexe=([^\s]+)', audit_text):
            v = m.group(1).strip()
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            paths.append(v)
    # Normalize and filter obvious junk
    out: List[str] = []
    seen = set()
    for p in paths:
        if not p.startswith("/"):
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Harvest executed binaries (non-redundant) into chain B.")
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--max", type=int, default=800, help="Max exe paths to consider per run.")
    ap.add_argument("--batch", type=int, default=200, help="Max entries per receipt payload.")
    ap.add_argument("--audit-key", default="aevum_root_exec")
    args = ap.parse_args()

    conf = _read_conf()
    audit_key = conf.get("AEVUM_BINARY_AUDIT_KEY", args.audit_key)
    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    # Load identity
    ident = load_identity_private(base / "identity" / "identity.json")
    sk = ident["sk"]
    kid = ident["kid"]
    subject_id_hex = ident["subject_id_hex"]
    capture_dev_hex = ident["capture_device_hex"]

    # Cursor
    cursor_path = base / "binaries" / "cursor_epoch"
    now_epoch = int(time.time())
    last_epoch = int(_load_json(cursor_path, 0) or 0)
    # Advance cursor early to avoid duplication
    _save_json(cursor_path, now_epoch, mode=0o600)

    # Index
    index_path = dirs["state"] / "binary_index.json"
    index = _load_json(index_path, {}) or {}

    audit_text = ""
    try:
        audit_text = subprocess.check_output(["ausearch", "-k", audit_key, "-ts", _dt.datetime.utcfromtimestamp(last_epoch).strftime("%Y-%m-%d %H:%M:%S"), "-i", "--input-logs"],
                                             text=True, stderr=subprocess.DEVNULL)
    except Exception:
        # no audit or no events; keep quiet
        return 0

    exe_paths = _extract_exe_paths(audit_text)[: max(0, args.max)]
    if not exe_paths:
        return 0

    changes: List[Dict[str, Any]] = []
    for p in exe_paths:
        pp = pathlib.Path(p)
        try:
            st = pp.stat()
            if not pp.is_file():
                continue
        except Exception:
            continue
        # Quick check against index: inode+mtime+size
        key = p
        prev = index.get(key) or {}
        inode = int(getattr(st, "st_ino", 0))
        mtime = int(st.st_mtime)
        size = int(st.st_size)
        if prev.get("inode") == inode and prev.get("mtime") == mtime and prev.get("size") == size and isinstance(prev.get("sha256"), str) and len(prev["sha256"]) == 64:
            continue
        try:
            file_sha = _sha256_file(pp)
        except Exception:
            continue
        if prev.get("sha256") == file_sha:
            # update metadata anyway
            index[key] = {"sha256": file_sha, "inode": inode, "mtime": mtime, "size": size}
            continue
        entry = {
            "path": p,
            "sha256": "sha256:" + file_sha,
            "inode": inode,
            "mtime": mtime,
            "size": size,
            "mode": oct(st.st_mode & 0o7777),
            "uid": int(st.st_uid),
            "gid": int(st.st_gid),
        }
        changes.append(entry)
        index[key] = {"sha256": file_sha, "inode": inode, "mtime": mtime, "size": size}

    if not changes:
        _save_json(index_path, index, mode=0o600)
        return 0

    # Chain state
    chain_state_path = dirs["state"] / "chain_B.json"
    state = load_chain_state(chain_state_path)
    seq_no = int(state.get("seq_no", 0))
    prev_event_hash = state.get("prev_event_hash", ZERO_HASH)

    tbid = _current_time_block_id(dirs)

    # Batch receipts
    i = 0
    while i < len(changes):
        batch = changes[i : i + max(1, args.batch)]
        i += max(1, args.batch)
        # merkle root over leaf hashes (path+sha)
        leaves = [_leaf_hash(e["path"], e["sha256"].split(":", 1)[1]) for e in batch]
        mr = _merkle_root(leaves)

        payload: Dict[str, Any] = {
            "type": "BinaryExecBatchPayload",
            "schema_version": "BEBPv1",
            "wallclock_unix": now_epoch,
            "monotime_ns": int(time.monotonic_ns()),
            "audit_key": audit_key,
            "since_epoch": last_epoch,
            "to_epoch": now_epoch,
            "time_block_id_hint": tbid,
            "count": len(batch),
            "batch_merkle_root": mr,
            "entries": batch,
        }

        payload_hash, payload_ref = write_payload(dirs["payloads"], payload)

        seq_no += 1
        event_hash = compute_event_hash_v2(
            chain_id_u8=CHAIN_ID_U8,
            subject_id_hex=subject_id_hex,
            seq_no=seq_no,
            time_block_id=tbid,
            local_monotime_ns=int(payload["monotime_ns"]),
            capture_device_hex=capture_dev_hex,
            prev_event_hash=prev_event_hash,
            payload_hash=payload_hash,
        )
        sig_raw = sign_event_hash(sk, event_hash)

        envelope = {
            "schema": "AEVUM:EVENT_ENVELOPE:V2",
            "chain_id_u8": CHAIN_ID_U8,
            "chain_label": CHAIN_LABEL,
            "subject_id_hex": subject_id_hex,
            "seq_no": seq_no,
            "time_block_id": tbid,
            "local_monotime_ns": int(payload["monotime_ns"]),
            "capture_device_hex": capture_dev_hex,
            "prev_event_hash": prev_event_hash,
            "payload_hash": payload_hash,
            "payload_ref": payload_ref,
            "event_hash": event_hash,
            "signature": {
                "alg": "Ed25519",
                "kid": kid,
                "sig_b64": b64e(sig_raw),
                "signed_at": utc_now_iso(),
                "canonicalization": "WIRE_EVENT_HASH_CANON_V1",
            },
        }

        line = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        append_line_best_effort(dirs["receipts"] / "B.jsonl", line, mode=0o600)

        prev_event_hash = event_hash

    # Save state + index
    state.update({"seq_no": seq_no, "prev_event_hash": prev_event_hash})
    save_chain_state(chain_state_path, state)
    _save_json(index_path, index, mode=0o600)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
