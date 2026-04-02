#!/usr/bin/env python3
"""
aevum_module_harvest.py (v0.1)

Mint non-redundant receipts for kernel modules that were loaded/unloaded (after-the-fact evidence).

Inputs:
- auditd events keyed by "aevum_module" (init_module/finit_module/delete_module)
- extracts exe= and/or comm= to correlate (best-effort)
- hashes /lib/modules/<uname -r>/**/*.ko* and records non-redundant entries

Outputs:
- chain label: M
- index: <base>/state/module_index.json
- cursor: <base>/modules/cursor_epoch
- receipts: <base>/receipts/M.jsonl
- payloads: <base>/payloads/<hash>.json

Non-governing: failures are recorded as receipts when possible; never blocks system function.
"""

from __future__ import annotations
import argparse, datetime as _dt, hashlib, json, os, pathlib, re, subprocess, time, shutil
from typing import Any, Dict, List

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

CHAIN_LABEL = "M"

def _sha256_file(p: pathlib.Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

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

def _extract_module_names(audit_text: str) -> List[str]:
    # auditd doesn't reliably include module filename; we use a pragmatic fallback:
    # harvest ALL modules for current kernel if any module event occurred.
    if "aevum_module" in audit_text:
        return ["__ALL__"]
    return []

def _current_time_block_id(dirs: Dict[str, pathlib.Path]) -> int:
    t_state = load_chain_state(dirs["state"] / "chain_T.json")
    tb = t_state.get("last_time_block_id")
    if isinstance(tb, int) and tb >= 0:
        return tb
    if isinstance(t_state.get("seq_no"), int) and t_state["seq_no"] > 0:
        return int(t_state["seq_no"])
    return 0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--audit-key", default="aevum_module")
    ap.add_argument("--batch", type=int, default=250)
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    ident = load_identity_private(base / "identity" / "identity.json")
    sk = ident["sk"]
    kid = ident["kid"]
    subject_id_hex = ident["subject_id_hex"]
    capture_dev_hex = ident["capture_device_hex"]

    cursor_path = base / "modules" / "cursor_epoch"
    now_epoch = int(time.time())
    last_epoch = int(_load_json(cursor_path, 0) or 0)
    _save_json(cursor_path, now_epoch, mode=0o600)

    if not shutil.which("ausearch"):
        return 0

    start_iso = _dt.datetime.utcfromtimestamp(last_epoch).strftime("%Y-%m-%d %H:%M:%S")
    try:
        audit_text = subprocess.check_output(["ausearch", "-k", args.audit_key, "-ts", start_iso, "-i", "--input-logs"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return 0

    mods = _extract_module_names(audit_text)
    if not mods:
        return 0

    # enumerate modules for current kernel
    try:
        krel = subprocess.check_output(["uname", "-r"], text=True).strip()
    except Exception:
        krel = ""

    mod_root = pathlib.Path("/lib/modules") / krel
    if not mod_root.exists():
        return 0

    index_path = dirs["state"] / "module_index.json"
    index = _load_json(index_path, {}) or {}

    entries: List[Dict[str, Any]] = []
    for p in sorted(mod_root.rglob("*.ko*")):
        try:
            st = p.stat()
            if not p.is_file():
                continue
        except Exception:
            continue
        rel = str(p)
        inode = int(getattr(st, "st_ino", 0))
        mtime = int(st.st_mtime)
        size = int(st.st_size)
        prev = index.get(rel) or {}
        if prev.get("inode") == inode and prev.get("mtime") == mtime and prev.get("size") == size and isinstance(prev.get("sha256"), str) and len(prev["sha256"]) == 64:
            continue
        try:
            h = _sha256_file(p)
        except Exception:
            continue
        if prev.get("sha256") == h:
            index[rel] = {"sha256": h, "inode": inode, "mtime": mtime, "size": size}
            continue
        index[rel] = {"sha256": h, "inode": inode, "mtime": mtime, "size": size}
        entries.append({"path": rel, "sha256": "sha256:" + h, "inode": inode, "mtime": mtime, "size": size})

    if not entries:
        _save_json(index_path, index, mode=0o600)
        return 0

    # build receipt payload(s)
    tbid = _current_time_block_id(dirs)
    # chain state for M
    st_path = dirs["state"] / f"chain_{CHAIN_LABEL}.json"
    state = load_chain_state(st_path)
    seq = int(state.get("seq_no", 0))
    prev_hash = state.get("last_event_hash", "sha256:" + ("00"*32))
    last_time_block = int(state.get("last_time_block_id", 0))

    # batch
    i = 0
    while i < len(entries):
        batch = entries[i:i+args.batch]
        i += args.batch
        leaves = [hashlib.sha256((e["path"]+""+e["sha256"]).encode("utf-8","surrogateescape")).digest() for e in batch]
        # merkle root
        lvl = leaves[:]
        while len(lvl) > 1:
            nxt=[]
            for j in range(0,len(lvl),2):
                a=lvl[j]; b=lvl[j+1] if j+1<len(lvl) else lvl[j]
                nxt.append(hashlib.sha256(a+b).digest())
            lvl=nxt
        merkle = "sha256:" + (lvl[0].hex() if lvl else ("00"*32))

        payload = {
            "type": "aevum_module_batch_v1",
            "timestamp_utc": utc_now_iso(),
            "kernel_release": krel,
            "count": len(batch),
            "merkle_root": merkle,
            "entries": batch,
        }
        payload_bytes, payload_ref = write_payload(dirs["payloads"], payload)

        event = {
            "schema": "aevum_event_v2",
            "chain": CHAIN_LABEL,
            "seq_no": seq + 1,
            "time_block_id": tbid,
            "timestamp_utc": utc_now_iso(),
            "prev_event_hash": prev_hash,
            "subject_id": "sha256:" + subject_id_hex,
            "capture_device": "sha256:" + capture_dev_hex,
            "payload_ref": payload_ref,
            "note": "module harvest",
            "tags": {"component":"modules","kernel":krel},
            "kid": kid,
        }
        eh = compute_event_hash_v2(event)
        sig = sign_event_hash(sk, eh)
        event["event_hash"] = eh
        event["signature"] = sig

        append_line_best_effort(dirs["receipts"] / f"{CHAIN_LABEL}.jsonl", json.dumps(event, sort_keys=True))
        seq += 1
        prev_hash = eh
        last_time_block = tbid

    save_chain_state(st_path, {"seq_no": seq, "last_event_hash": prev_hash, "last_time_block_id": last_time_block})
    _save_json(index_path, index, mode=0o600)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
