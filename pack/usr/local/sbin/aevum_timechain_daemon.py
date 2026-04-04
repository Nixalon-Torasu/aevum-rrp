#!/usr/bin/env python3
"""
aevum_timechain_daemon.py (v0.2)

Aevum-workstation TimeChain (T) daemon.
- Writes exactly one TimeChain EventEnvelope per second (best-effort cadence).
- Does NOT govern the system. When overloaded, it records explicit gaps instead of blocking work.

Core idea (Foundation stop-line):
- Workstation produces origin receipts + deterministic commitments.
- This daemon anchors each 1-second epoch by committing to *delta Merkle roots* of other chains.

Delta-root model (pragmatic and stable):
- For each committed chain, maintain a byte-offset cursor into <receipts>/<CHAIN>.jsonl.
- Each second, read new lines since the cursor, extract event_hash leaves, and compute a Merkle root over them.
- Store per-chain {count, delta_merkle_root, cursor_bytes} in the TimeBlock payload.
- Update cursors in chain_T state.

This makes TimeChain independent of other chains' time_block_id usage and avoids circularity.

Payload schema:
- TimeBlockPayload TBV1 (commitments-only), or gap payloads when needed.

TPM anchoring:
- Optionally references the latest TPM anchor artifact + eventlog hash if present (non-gating).

"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import pathlib
import time
import subprocess
import base64
from typing import Any, Dict, List, Tuple, Optional

from aevum_common import (
    ensure_dirs,
    resolve_storage_dirs,
    load_identity,
    load_device_private_key,
    derive_subject_id_hex,
    capture_device_hex,
    load_chain_state,
    save_chain_state,
    write_payload,
    compute_event_hash_v2,
    sign_event_hash,
    b64e,
    ZERO32_HEX,
    append_line,
    sha256_hex,
)

ZERO_HASH = "sha256:" + ("00" * 32)

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

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

def _load_policy_hash(policy_path: pathlib.Path) -> Optional[str]:
    try:
        if not policy_path.exists():
            return None
        raw = policy_path.read_bytes().strip()
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    except Exception:
        return None

def _find_latest_file(dirpath: pathlib.Path, prefix: str, suffix: str) -> Optional[pathlib.Path]:
    try:
        if not dirpath.exists():
            return None
        cand = sorted([p for p in dirpath.iterdir() if p.is_file() and p.name.startswith(prefix) and p.name.endswith(suffix)])
        return cand[-1] if cand else None
    except Exception:
        return None

def _best_effort_tpm_refs(base: pathlib.Path) -> Dict[str, Any]:
    # Non-gating: include latest anchor + eventlog hashes if present.
    out: Dict[str, Any] = {}
    state_anchor = base / "accurate" / "state" / "CURRENT_BOOT_ANCHOR.json"
    if state_anchor.exists():
        try:
            out["tpm_anchor_ref"] = str(state_anchor)
            out["tpm_anchor_sha256"] = "sha256:" + sha256_file(state_anchor)
            return out
        except Exception:
            pass

    anchors = base / "tpm_sign" / "anchors"
    latest_anchor = _find_latest_file(anchors, "anchor_", ".json")
    if latest_anchor:
        try:
            out["tpm_anchor_ref"] = str(latest_anchor)
            out["tpm_anchor_sha256"] = "sha256:" + sha256_file(latest_anchor)
        except Exception:
            pass
    evdir = base / "boot" / "eventlog"
    latest_ev = _find_latest_file(evdir, "eventlog_bios_", ".bin") or _find_latest_file(evdir, "eventlog_", ".bin")
    if latest_ev:
        try:
            out["eventlog_ref"] = str(latest_ev)
            out["eventlog_sha256"] = "sha256:" + sha256_file(latest_ev)
        except Exception:
            pass

    # PCR snapshot: written by aevum_pcr_capture.py at boot time
    latest_pcr = _find_latest_file(base / "boot", "pcr_", ".json")
    if latest_pcr:
        try:
            out["pcr_snapshot_ref"] = str(latest_pcr)
            out["pcr_snapshot_sha256"] = "sha256:" + sha256_file(latest_pcr)
        except Exception:
            pass

    return out

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
def _try_tpm_sign(event_hash: str, instance_base: pathlib.Path) -> Optional[Dict[str, Any]]:
    """Best-effort TPM signature over the raw32 bytes of event_hash (sha256:...)."""
    try:
        # locate handle
        handle_file = instance_base / "tpm_sign" / "sign.handle"
        pub_pem = instance_base / "tpm_sign" / "sign.pub.pem"
        if not handle_file.exists():
            return None
        handle = handle_file.read_text(encoding="utf-8").strip()
        if not handle:
            return None
        if not shutil.which("tpm2_sign"):
            return None
        if not (isinstance(event_hash, str) and event_hash.startswith("sha256:") and len(event_hash) == 71):
            return None
        raw32 = bytes.fromhex(event_hash.split(":", 1)[1])
        # tpm2_sign expects digest file
        import tempfile
        with tempfile.TemporaryDirectory(prefix="aevum_tpm_sign_") as td:
            d = pathlib.Path(td) / "digest.bin"
            s = pathlib.Path(td) / "sig.bin"
            d.write_bytes(raw32)
            # Sign digest using sha256 scheme
            subprocess.run(["tpm2_sign", "-c", handle, "-g", "sha256", "-f", "plain", "-d", str(d), "-o", str(s)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if not s.exists():
                return None
            sig_b64 = base64.b64encode(s.read_bytes()).decode("ascii")
        pub_sha = None
        if pub_pem.exists():
            pub_sha = "sha256:" + hashlib.sha256(pub_pem.read_bytes()).hexdigest()
        return {
            "alg": "TPM2_ECC_P256_SHA256",
            "handle": handle,
            "signed_over": "event_hash_raw32",
            "sig_b64": sig_b64,
            "sig_fmt": "plain",
            "hash_alg": "sha256",
            "tpm_sign_pubkey_sha256": pub_sha or "",
        }
    except Exception:
        return None


def _delta_root_for_chain(log_path: pathlib.Path, cursor_bytes: int) -> Tuple[str, int, int]:
    """
    Returns (delta_merkle_root, count, new_cursor_bytes).
    Leaves are SHA256(event_hash_raw32) for stability across JSON formatting.
    """
    if not log_path.exists():
        return "sha256:" + ("00"*32), 0, cursor_bytes

    st = log_path.stat()
    if cursor_bytes < 0 or cursor_bytes > st.st_size:
        cursor_bytes = 0

    leaves: List[bytes] = []
    count = 0
    new_cursor = cursor_bytes
    with log_path.open("rb") as f:
        f.seek(cursor_bytes, os.SEEK_SET)
        chunk = f.read()
        new_cursor = cursor_bytes + len(chunk)
        if not chunk:
            return "sha256:" + ("00"*32), 0, new_cursor
        for raw_line in chunk.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                ev = json.loads(raw_line.decode("utf-8", errors="strict"))
                eh = ev.get("event_hash")
                if isinstance(eh, str) and eh.startswith("sha256:") and len(eh) == 71:
                    raw32 = bytes.fromhex(eh.split(":",1)[1])
                    leaves.append(hashlib.sha256(raw32).digest())
                    count += 1
            except Exception:
                # stop at first parse error to avoid committing garbage as "new" content;
                # do not advance cursor past the bad line (so recovery can handle it).
                new_cursor = cursor_bytes  # rewind to prior cursor
                return "sha256:" + ("00"*32), 0, new_cursor

    return _merkle_root(leaves), count, new_cursor

def _emit_envelope_v2(
    dirs: Dict[str, pathlib.Path],
    receipts_path: pathlib.Path,
    sk,
    kid: str,
    subject_id_hex: str,
    capture_dev_hex: str,
    seq_no: int,
    time_block_id: int,
    monotime_ns: int,
    prev_event_hash: str,
    payload: Dict[str, Any],
    tpm_sig: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    payload_hash, payload_ref = write_payload(dirs["payloads"], payload)
    event_hash = compute_event_hash_v2(
        chain_id_u8=5,
        subject_id_hex=subject_id_hex,
        seq_no=seq_no,
        time_block_id=time_block_id,
        local_monotime_ns=monotime_ns,
        capture_device_hex=capture_dev_hex,
        prev_event_hash=prev_event_hash,
        payload_hash=payload_hash,
    )

    # Optional TPM signature over event_hash (amortized: 1/sec)
    tpm_sig_out = None
    if isinstance(tpm_sig, dict) and tpm_sig.get("__auto__"):
        ib = tpm_sig.get("instance_base")
        if isinstance(ib, pathlib.Path):
            tpm_sig_out = _try_tpm_sign(event_hash, ib)
    elif isinstance(tpm_sig, dict):
        tpm_sig_out = tpm_sig
    sig_raw = sign_event_hash(sk, event_hash)
    env = {
        "schema": "AEVUM:EVENT_ENVELOPE:V2",
        "chain_id_u8": 5,
        "chain_label": "T",
        "subject_id_hex": subject_id_hex,
        "seq_no": seq_no,
        "time_block_id": time_block_id,
        "local_monotime_ns": monotime_ns,
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
        "tpm_signature": tpm_sig_out or None,
    }
    line = json.dumps(env, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    append_line(receipts_path, line, mode=0o600)
    upd = {
        "seq_no": seq_no,
        "prev_event_hash": event_hash,
        "last_time_block_id": time_block_id,
        "last_wallclock_unix": int(payload.get("wallclock_unix", 0) or 0),
        "last_monotime_ns": int(monotime_ns),
    }
    return event_hash, upd

def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum TimeChain daemon (workstation).")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Instance base directory.")
    ap.add_argument("--identity", default="", help="Path to identity.json (optional).")
    ap.add_argument("--key", default="", help="Path to device_ed25519_sk.pem (optional).")
    ap.add_argument("--once", action="store_true", help="Write exactly one block and exit.")
    ap.add_argument("--gap-mode", choices=["coalesce","per_second"], default="coalesce")
    ap.add_argument("--gap-cap", type=int, default=120, help="Max per-second placeholders before coalescing.")
    ap.add_argument("--commit-chains", default="B,M,I,P,R,PHI", help="Comma list of chain logs to delta-commit each second.")
    ap.add_argument("--policy-path", default="/etc/aevum/registry/mint_policy.json", help="Path to mint policy file to hash into blocks.")
    ap.add_argument("--tpm-policy-path", default="/etc/aevum/registry/tpm_pcr_policy.json", help="Path to TPM PCR policy file to hash into blocks.")
    ap.add_argument("--tpm-receipt-policy-path", default="/etc/aevum/registry/tpm_receipt_sign_policy.json", help="Path to TPM receipt signing allowlist policy file to hash into blocks.")
    ap.add_argument("--tpm-sign-timeblocks", action="store_true", help="Best-effort TPM-sign each TimeChain envelope via persistent signing handle (amortized 1/sec).")
    args = ap.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Run as root.")

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    # resolve identity/key defaults
    if not args.identity:
        args.identity = str((base / "identity" / "identity.json"))
        if not pathlib.Path(args.identity).exists():
            args.identity = "/var/lib/aevum/workstation/identity/identity.json"
    if not args.key:
        args.key = str((base / "identity" / "device_ed25519_sk.pem"))
        if not pathlib.Path(args.key).exists():
            args.key = "/var/lib/aevum/workstation/identity/device_ed25519_sk.pem"

    identity = load_identity(pathlib.Path(args.identity))
    sk = load_device_private_key(pathlib.Path(args.key))

    machine_id = identity.get("device", {}).get("machine_id", "")
    kid = identity.get("keys", {}).get("device_signing_key", {}).get("kid", "unknown")
    pub_b64 = identity.get("keys", {}).get("device_signing_key", {}).get("public_key_b64", "")
    import base64
    pub_raw = base64.b64decode(pub_b64) if pub_b64 else b""
    subject_id_hex = identity.get("device", {}).get("subject_id_hex") or derive_subject_id_hex(pub_raw)
    capture_dev_hex = identity.get("device", {}).get("capture_device_hex") or capture_device_hex(machine_id, pub_raw)

    chain_state_path = dirs["state"] / "chain_T.json"
    state = load_chain_state(chain_state_path)
    receipts_path = dirs["receipts"] / "T.jsonl"

    # cursors
    cursors: Dict[str, int] = state.get("commit_cursors") or {}
    if not isinstance(cursors, dict):
        cursors = {}

    commit_chains = [c.strip() for c in args.commit_chains.split(",") if c.strip()]
    policy_hash = _load_policy_hash(pathlib.Path(args.policy_path))
    tpm_policy_hash = _load_policy_hash(pathlib.Path(args.tpm_policy_path))
    tpm_receipt_policy_hash = _load_policy_hash(pathlib.Path(args.tpm_receipt_policy_path))

    next_tick = time.monotonic()
    while True:
        now_wall = int(time.time())
        now_mono_ns = int(time.monotonic_ns())

        seq_no = int(state.get("seq_no", 0))
        prev_event_hash = state.get("prev_event_hash", ZERO_HASH)
        last_tb = int(state.get("last_time_block_id", -1))
        last_wall = state.get("last_wallclock_unix")

        # detect wallclock gap (best-effort)
        missing = 0
        if isinstance(last_wall, int) and last_wall > 0:
            delta = now_wall - int(last_wall)
            if delta > 1:
                missing = delta - 1
            elif delta < 0:
                # clock went backwards - record as anomaly in flags of the next block
                missing = 0

        # emit gap placeholders or coalesced gap summary
        if missing > 0:
            if args.gap_mode == "per_second" and missing <= max(0, args.gap_cap):
                for k in range(1, missing + 1):
                    seq_no += 1
                    tb = last_tb + k
                    payload = {
                        "type": "TimeBlockPayload",
                        "schema_version": "TBV1",
                        "time_block_id": tb,
                        "wallclock_unix": int(last_wall) + k if isinstance(last_wall, int) else now_wall,
                        "monotime_ns": now_mono_ns,
                        "mint_policy_sha256": policy_hash,
            "tpm_pcr_policy_sha256": tpm_policy_hash,
            "tpm_receipt_sign_policy_sha256": tpm_receipt_policy_hash,
                        "commit_delta": {},
                        "flags": ["GAP_PLACEHOLDER","WALLCLOCK_ESTIMATED","TBV1_DELTA_ROOTS"],
                        "gap": {"kind":"PROCESS_DOWN_OR_DELAY","detected_at_wallclock": now_wall, "detected_at_monotime_ns": now_mono_ns, "missing_seconds": missing},
                    }
                    _, upd = _emit_envelope_v2(
                        dirs=dirs, receipts_path=receipts_path, sk=sk, kid=kid,
                        subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
                        seq_no=seq_no, time_block_id=tb, monotime_ns=now_mono_ns,
                        prev_event_hash=prev_event_hash, payload=payload, tpm_sig={"__auto__": True, "instance_base": base} if args.tpm_sign_timeblocks else None
                    )
                    prev_event_hash = upd["prev_event_hash"]
                    state.update(upd)
                last_tb = int(state.get("last_time_block_id", last_tb))
            else:
                seq_no += 1
                gap_start = last_tb + 1
                gap_end = last_tb + missing
                payload = {
                    "type": "TimeGapSummaryPayload",
                    "schema_version": "TGSv1",
                    "gap_start_time_block_id": gap_start,
                    "gap_end_time_block_id": gap_end,
                    "gap_count": missing,
                    "detected_at_wallclock": now_wall,
                    "detected_at_monotime_ns": now_mono_ns,
                    "mint_policy_sha256": policy_hash,
            "tpm_pcr_policy_sha256": tpm_policy_hash,
            "tpm_receipt_sign_policy_sha256": tpm_receipt_policy_hash,
                    "flags": ["GAP_COALESCED","TBV1_DELTA_ROOTS"],
                }
                _, upd = _emit_envelope_v2(
                    dirs=dirs, receipts_path=receipts_path, sk=sk, kid=kid,
                    subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
                    seq_no=seq_no, time_block_id=gap_start, monotime_ns=now_mono_ns,
                    prev_event_hash=prev_event_hash, payload=payload, tpm_sig={"__auto__": True, "instance_base": base} if args.tpm_sign_timeblocks else None
                )
                # jump TB to end of represented gap
                upd["last_time_block_id"] = gap_end
                state.update(upd)
                prev_event_hash = upd["prev_event_hash"]
                last_tb = gap_end

        # normal block
        seq_no = int(state.get("seq_no", seq_no))
        prev_event_hash = state.get("prev_event_hash", prev_event_hash)
        last_tb = int(state.get("last_time_block_id", last_tb))
        time_block_id = last_tb + 1
        seq_no += 1

        commit_delta: Dict[str, Any] = {}
        for c in commit_chains:
            log = dirs["receipts"] / f"{c}.jsonl"
            cur = int(cursors.get(c, 0) or 0)
            root, count, newcur = _delta_root_for_chain(log, cur)
            commit_delta[c] = {"count": count, "delta_merkle_root": root, "cursor_bytes": newcur}
            cursors[c] = newcur

        payload = {
            "type": "TimeBlockPayload",
            "schema_version": "TBV1",
            "time_block_id": time_block_id,
            "wallclock_unix": now_wall,
            "monotime_ns": now_mono_ns,
            "mint_policy_sha256": policy_hash,
            "tpm_pcr_policy_sha256": tpm_policy_hash,
            "tpm_receipt_sign_policy_sha256": tpm_receipt_policy_hash,
            "commit_delta": commit_delta,
            "flags": ["TBV1_DELTA_ROOTS","DEVICE_AWAKE"],
        }
        # best-effort extra refs (TPM)
        payload.update(_best_effort_tpm_refs(base))

        _, upd = _emit_envelope_v2(
            dirs=dirs, receipts_path=receipts_path, sk=sk, kid=kid,
            subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
            seq_no=seq_no, time_block_id=time_block_id, monotime_ns=now_mono_ns,
            prev_event_hash=prev_event_hash, payload=payload
        )
        state.update(upd)
        state["commit_cursors"] = cursors
        save_chain_state(chain_state_path, state)

        if args.once:
            break

        next_tick += 1.0
        time.sleep(max(0.0, next_tick - time.monotonic()))

    print(f"OK: wrote TimeChain block seq_no={state.get('seq_no')}, time_block_id={state.get('last_time_block_id')}")
    print(f"    receipt: {receipts_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())