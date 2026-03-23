#!/usr/bin/env python3
"""
aevum_workstation_observer.py (v0.1)

Layer-1 workstation telemetry receipts: non-redundant, best-effort, non-gating.

What it does
- Periodically samples a small set of kernel-provided counters (no extra deps):
  - loadavg
  - meminfo summary
  - total disk bytes read/written (summed from /proc/diskstats)
  - total net bytes rx/tx (summed from /proc/net/dev excluding lo)
  - thermal zones temps (if present)
- Emits a receipt ONLY when:
  - values change beyond thresholds, OR
  - periodic heartbeat interval is reached (default 60s), OR
  - startup snapshot (always once)

Where it writes
- Chain: P (Perception) with chain_id_u8=1 (registry)
- Receipts: <base>/accurate/receipts/P.jsonl (Seam) or <base>/receipts/P.jsonl (legacy)
- Payloads: <base>/accurate/payloads/

Dependencies
- Uses existing Aevum bootstrap common helpers for signing + storage.
- Requires identity bootstrap for private key (workstation instance).

Non-blocking
- If writing fails, it logs to stderr and continues.
"""

from __future__ import annotations

import argparse
import sys
import json
import os
import pathlib
import time
from typing import Any, Dict, Optional, Tuple, List

from aevum_common import (
    resolve_storage_dirs,
    load_identity_private,
    load_chain_state,
    save_chain_state,
    append_line,
    write_payload,
    compute_event_hash_v2,
    sign_event_hash,
    b64e,
    utc_now_iso,
)

ZERO32_HEX = "00" * 32
ZERO_HASH = "sha256:" + ZERO32_HEX

CHAIN_ID_U8 = 1  # P (Perception)


def read_loadavg() -> Dict[str, float]:
    try:
        a, b, c = open("/proc/loadavg", "r").read().split()[:3]
        return {"1m": float(a), "5m": float(b), "15m": float(c)}
    except Exception:
        return {"1m": 0.0, "5m": 0.0, "15m": 0.0}


def read_meminfo() -> Dict[str, int]:
    out = {}
    try:
        for line in open("/proc/meminfo", "r"):
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            parts = v.strip().split()
            if not parts:
                continue
            val_kib = int(parts[0])
            out[k] = val_kib * 1024
    except Exception:
        pass
    # common derived fields
    total = out.get("MemTotal", 0)
    avail = out.get("MemAvailable", out.get("MemFree", 0))
    return {"mem_total_bytes": total, "mem_avail_bytes": avail}


def read_diskstats_total() -> Dict[str, int]:
    # /proc/diskstats sectors (typically 512B). Use kernel-reported sector size? too hard; assume 512.
    # This is a best-effort monotonic counter summary, useful for "machine did IO".
    SECTOR = 512
    rd_sectors = 0
    wr_sectors = 0
    try:
        for line in open("/proc/diskstats", "r"):
            parts = line.split()
            if len(parts) < 14:
                continue
            name = parts[2]
            # Skip partitions? keep everything except loop/ram to reduce noise
            if name.startswith("loop") or name.startswith("ram"):
                continue
            # fields: reads completed(3), reads merged(4), sectors read(5), time reading(6)
            # writes completed(7), writes merged(8), sectors written(9), time writing(10)
            rd_sectors += int(parts[5])
            wr_sectors += int(parts[9])
    except Exception:
        pass
    return {"disk_read_bytes_total": rd_sectors * SECTOR, "disk_write_bytes_total": wr_sectors * SECTOR}


def read_netdev_total() -> Dict[str, int]:
    rx = 0
    tx = 0
    try:
        lines = open("/proc/net/dev", "r").read().splitlines()[2:]
        for line in lines:
            if ":" not in line:
                continue
            iface, rest = line.split(":", 1)
            iface = iface.strip()
            if iface == "lo":
                continue
            cols = rest.split()
            if len(cols) >= 16:
                rx += int(cols[0])
                tx += int(cols[8])
    except Exception:
        pass
    return {"net_rx_bytes_total": rx, "net_tx_bytes_total": tx}


def read_temps() -> Dict[str, Any]:
    temps = []
    base = pathlib.Path("/sys/class/thermal")
    try:
        for z in sorted(base.glob("thermal_zone*/temp")):
            try:
                t_milli = int(z.read_text().strip())
                temps.append({"zone": z.parent.name, "temp_c": t_milli / 1000.0})
            except Exception:
                continue
    except Exception:
        pass
    return {"temps": temps}


def make_payload() -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": "WorkstationTelemetryPayload",
        "schema_version": "WTPv1",
        "wallclock_unix": int(time.time()),
        "monotime_ns": int(time.monotonic_ns()),
        "loadavg": read_loadavg(),
    }
    payload.update(read_meminfo())
    payload.update(read_diskstats_total())
    payload.update(read_netdev_total())
    payload.update(read_temps())
    return payload


def changed_enough(prev: Optional[Dict[str, Any]], cur: Dict[str, Any], *, thresholds: Dict[str, float]) -> bool:
    if prev is None:
        return True
    # Compare a small set with thresholds
    # disk/net are totals => use delta threshold in bytes
    for k, thr in thresholds.items():
        # nested keys support: "loadavg.1m"
        if "." in k:
            a, b = k.split(".", 1)
            pv = (prev.get(a) or {}).get(b)
            cv = (cur.get(a) or {}).get(b)
        else:
            pv = prev.get(k)
            cv = cur.get(k)
        try:
            if pv is None:
                return True
            if abs(float(cv) - float(pv)) >= float(thr):
                return True
        except Exception:
            continue
    return False


def emit_receipt(
    *,
    dirs: Dict[str, pathlib.Path],
    sk,
    kid: str,
    subject_id_hex: str,
    capture_dev_hex: str,
    seq_no: int,
    time_block_id: int,
    prev_event_hash: str,
    payload: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    payload_hash, payload_ref = write_payload(dirs["payloads"], payload)
    event_hash = compute_event_hash_v2(
        chain_id_u8=CHAIN_ID_U8,
        subject_id_hex=subject_id_hex,
        seq_no=seq_no,
        time_block_id=time_block_id,
        local_monotime_ns=int(payload.get("monotime_ns", 0)),
        capture_device_hex=capture_dev_hex,
        prev_event_hash=prev_event_hash,
        payload_hash=payload_hash,
    )
    sig_raw = sign_event_hash(sk, event_hash)
    envelope = {
        "schema": "AEVUM:EVENT_ENVELOPE:V2",
        "chain_id_u8": CHAIN_ID_U8,
        "chain_label": "P",
        "subject_id_hex": subject_id_hex,
        "seq_no": seq_no,
        "time_block_id": time_block_id,
        "local_monotime_ns": int(payload.get("monotime_ns", 0)),
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
    append_line(dirs["receipts"] / "P.jsonl", line, mode=0o600)
    return event_hash, {"seq_no": seq_no, "prev_event_hash": event_hash}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation instance base.")
    ap.add_argument("--interval", type=float, default=5.0, help="Sample interval seconds.")
    ap.add_argument("--periodic", type=int, default=60, help="Force emit at least once every N seconds.")
    ap.add_argument("--disk-delta-bytes", type=int, default=50_000_000, help="Emit if disk totals change by >= this delta.")
    ap.add_argument("--net-delta-bytes", type=int, default=5_000_000, help="Emit if net totals change by >= this delta.")
    ap.add_argument("--load-delta", type=float, default=0.25, help="Emit if loadavg.1m changes by >= this delta.")
    ap.add_argument("--once", action="store_true", help="Emit a single sample and exit.")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    # Identity must exist (workstation/core always-identified). If it doesn't, exit loudly.
    ident = load_identity_private(base / "identity" / "identity.json")
    sk = ident["sk"]
    kid = ident["kid"]
    subject_id_hex = ident["subject_id_hex"]
    capture_dev_hex = ident["capture_device_hex"]

    # Chain state for P
    chain_state_path = dirs["state"] / "chain_P.json"
    state = load_chain_state(chain_state_path)
    seq_no = int(state.get("seq_no", 0))
    prev_event_hash = state.get("prev_event_hash", ZERO_HASH)

    prev_payload: Optional[Dict[str, Any]] = None
    last_emit = 0.0

    thresholds = {
        "disk_read_bytes_total": float(args.disk_delta_bytes),
        "disk_write_bytes_total": float(args.disk_delta_bytes),
        "net_rx_bytes_total": float(args.net_delta_bytes),
        "net_tx_bytes_total": float(args.net_delta_bytes),
        "loadavg.1m": float(args.load_delta),
    }

    # Best-effort time_block_id: use current TimeChain tail if present, else 0.
    def current_time_block_id() -> int:
        t_state = load_chain_state(dirs["state"] / "chain_T.json")
        tb = t_state.get("last_time_block_id")
        if isinstance(tb, int) and tb >= 0:
            return tb
        # fallback: last seq_no as proxy (not ideal but monotonic within instance)
        if isinstance(t_state.get("seq_no"), int) and t_state["seq_no"] > 0:
            return int(t_state["seq_no"])
        return 0

    # Startup snapshot always emits
    payload = make_payload()
    seq_no += 1
    tbid = current_time_block_id()
    event_hash, upd = emit_receipt(
        dirs=dirs, sk=sk, kid=kid, subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
        seq_no=seq_no, time_block_id=tbid, prev_event_hash=prev_event_hash, payload=payload,
    )
    prev_event_hash = event_hash
    state.update(upd)
    save_chain_state(chain_state_path, state)
    prev_payload = payload
    last_emit = time.time()

    if args.once:
        return 0

    while True:
        time.sleep(args.interval)
        payload = make_payload()
        now = time.time()
        force = (now - last_emit) >= float(args.periodic)
        if force or changed_enough(prev_payload, payload, thresholds=thresholds):
            seq_no += 1
            tbid = current_time_block_id()
            try:
                event_hash, upd = emit_receipt(
                    dirs=dirs, sk=sk, kid=kid, subject_id_hex=subject_id_hex, capture_dev_hex=capture_dev_hex,
                    seq_no=seq_no, time_block_id=tbid, prev_event_hash=prev_event_hash, payload=payload,
                )
                prev_event_hash = event_hash
                state.update(upd)
                save_chain_state(chain_state_path, state)
                prev_payload = payload
                last_emit = now
            except Exception as e:
                print(f"observer write failed: {e}", file=sys.stderr)  # best-effort

if __name__ == "__main__":
    raise SystemExit(main())
