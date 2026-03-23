#!/usr/bin/env python3
from __future__ import annotations

"""
aevum_recover.py (v0.1)

Proof-oriented recovery assistant for append-only receipt logs.

Goals (Year-1):
- Detect tail truncation/partial JSON line writes in *.jsonl chains
- Optionally truncate only the damaged tail back to the last valid newline
- Reconcile chain_* state files to the last valid event (best-effort)
- Always produce evidence artifacts and a recovery receipt (unless --no-receipt)

This tool DOES NOT "repair corruption" in the middle of the log.
If corruption is detected mid-file, it reports and stops.
"""

import argparse, json, pathlib, os, sys, hashlib, datetime
from typing import Dict, Any, List, Tuple, Optional

# Local imports installed alongside this script
from aevum_common import resolve_storage_dirs, load_chain_state, save_chain_state, sha256_hex

def utc_now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def atomic_write(p: pathlib.Path, data: str, mode: int = 0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, p)

def run_receipt(kind: str, msg: str, kv: List[str], base: pathlib.Path) -> Tuple[int, str]:
    # Prefer operator wrapper
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        import subprocess
        p = subprocess.run([str(r), kind, msg] + kv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout.strip()
    # Fallback to receiptctl via python
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if ctl.exists():
        import subprocess
        p = subprocess.run([sys.executable, str(ctl), "--base", str(base), "--kind", kind, "--message", msg] + kv,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout.strip()
    return 127, "no receipt tool available"

def scan_jsonl(path: pathlib.Path) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "bytes": 0,
        "lines": 0,
        "ok_lines": 0,
        "tail_json_error": None,
        "midfile_json_error": None,
        "tail_truncation_candidate": False,
        "last_valid_seq_no": None,
        "last_valid_event_hash": None,
        "last_valid_time_block_id": None,
        "last_valid_wallclock_unix": None,
        "last_valid_monotime_ns": None,
        "last_valid_line_no": None,
        "last_valid_line_offset": None,
    }
    if not path.exists():
        return res
    b = path.read_bytes()
    res["bytes"] = len(b)
    if not b:
        return res
    # Ensure we can locate a last newline boundary if needed
    offs = 0
    last_good_offset = None
    last_good = None
    line_no = 0
    # iterate line-by-line over bytes (avoid huge memory decode churn)
    for raw_line in b.splitlines(keepends=True):
        line_no += 1
        res["lines"] = line_no
        try:
            s = raw_line.decode("utf-8", errors="strict").strip()
        except Exception as e:
            res["midfile_json_error"] = f"utf8_error_line={line_no}:{e}"
            break
        if not s:
            offs += len(raw_line)
            continue
        try:
            obj = json.loads(s)
        except Exception as e:
            # If this is the last line and file does not end with newline, treat as tail candidate.
            is_last = (offs + len(raw_line) == len(b))
            if is_last:
                res["tail_json_error"] = f"json_error_line={line_no}:{e}"
                res["tail_truncation_candidate"] = True
                res["last_valid_line_offset"] = last_good_offset
                res["last_valid_line_no"] = last_good.get("_line_no") if last_good else None
            else:
                res["midfile_json_error"] = f"json_error_line={line_no}:{e}"
            break
        res["ok_lines"] += 1
        # track last valid
        last_good_offset = offs + len(raw_line)
        last_good = {
            "_line_no": line_no,
            "seq_no": obj.get("seq_no"),
            "event_hash": obj.get("event_hash"),
            "time_block_id": obj.get("time_block_id"),
            "wallclock_unix": obj.get("wallclock_unix") or obj.get("payload", {}).get("wallclock_unix"),
            "local_monotime_ns": obj.get("local_monotime_ns"),
        }
        offs += len(raw_line)

    if last_good:
        res["last_valid_seq_no"] = last_good.get("seq_no")
        res["last_valid_event_hash"] = last_good.get("event_hash")
        res["last_valid_time_block_id"] = last_good.get("time_block_id")
        res["last_valid_wallclock_unix"] = last_good.get("wallclock_unix")
        res["last_valid_monotime_ns"] = last_good.get("local_monotime_ns")
        res["last_valid_line_no"] = last_good.get("_line_no")

    return res

def truncate_to_offset(path: pathlib.Path, new_size: int) -> Tuple[str, str]:
    before = sha256_file(path)
    b = path.read_bytes()
    if new_size < 0 or new_size > len(b):
        raise ValueError("bad truncate size")
    tail = b[new_size:]
    # write back truncated
    path.write_bytes(b[:new_size])
    after = sha256_file(path)
    return before, after, tail[-4096:]  # last 4KB of removed tail for evidence

def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum recovery CLI (proof-oriented)")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation base directory")
    ap.add_argument("--outdir", default="", help="Diagnostics output directory (default: <base>/diagnostics)")
    ap.add_argument("--json", action="store_true", help="Emit JSON report")
    ap.add_argument("--repair", action="store_true", help="Truncate tail if candidate truncation is detected")
    ap.add_argument("--no-receipt", action="store_true", help="Do not mint recovery receipts")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero if any mid-file corruption is detected")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)
    receipts_dir = dirs["receipts"]
    state_dir = dirs["state"]

    outdir = pathlib.Path(args.outdir) if args.outdir else (base / "diagnostics")
    outdir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "schema": "AEVUM:RECOVERY:REPORT:V1",
        "ts_utc": utc_now(),
        "base": str(base),
        "receipts_dir": str(receipts_dir),
        "repair_enabled": bool(args.repair),
        "chains": {},
        "actions": [],
        "midfile_corruption": [],
        "tail_truncations": [],
    }

    jsonls = sorted(receipts_dir.glob("*.jsonl"))
    for fp in jsonls:
        chain = fp.stem
        scan = scan_jsonl(fp)
        report["chains"][chain] = scan
        if scan.get("midfile_json_error"):
            report["midfile_corruption"].append({"chain": chain, "error": scan["midfile_json_error"]})
        if scan.get("tail_truncation_candidate"):
            report["tail_truncations"].append({"chain": chain, "error": scan.get("tail_json_error"), "truncate_to": scan.get("last_valid_line_offset")})

    # Repairs (tail truncation only)
    if args.repair:
        for item in report["tail_truncations"]:
            chain = item["chain"]
            fp = receipts_dir / f"{chain}.jsonl"
            new_size = item.get("truncate_to")
            if new_size is None:
                continue
            try:
                before, after, tail = truncate_to_offset(fp, int(new_size))
                tail_path = outdir / f"recover_truncated_tail_{chain}_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.bin"
                tail_path.write_bytes(tail)
                os.chmod(tail_path, 0o600)
                tail_sha = sha256_file(tail_path)
                report["actions"].append({
                    "action": "truncate_tail",
                    "chain": chain,
                    "file": str(fp),
                    "new_size": int(new_size),
                    "sha256_before": before,
                    "sha256_after": after,
                    "tail_artifact": str(tail_path),
                    "tail_sha256": tail_sha,
                })
            except Exception as e:
                report["actions"].append({"action": "truncate_tail_failed", "chain": chain, "error": str(e)})

    # Reconcile chain state files (best-effort)
    for chain, scan in report["chains"].items():
        st_path = state_dir / f"chain_{chain}.json"
        if not st_path.exists():
            continue
        try:
            st = load_chain_state(st_path)
            last_seq = scan.get("last_valid_seq_no")
            last_hash = scan.get("last_valid_event_hash")
            if last_seq is None or last_hash is None:
                continue
            # If state appears ahead, reset back
            if int(st.get("seq_no", 0)) > int(last_seq):
                st["seq_no"] = int(last_seq)
                st["prev_event_hash"] = str(last_hash)
                if scan.get("last_valid_time_block_id") is not None:
                    st["last_time_block_id"] = int(scan["last_valid_time_block_id"])
                if scan.get("last_valid_wallclock_unix") is not None:
                    try: st["last_wallclock_unix"] = int(scan["last_valid_wallclock_unix"])
                    except Exception: pass
                if scan.get("last_valid_monotime_ns") is not None:
                    try: st["last_monotime_ns"] = int(scan["last_valid_monotime_ns"])
                    except Exception: pass
                save_chain_state(st_path, st)
                report["actions"].append({"action":"reconcile_state","chain":chain,"state_path":str(st_path),"new_seq_no":int(last_seq)})
        except Exception as e:
            report["actions"].append({"action":"reconcile_state_failed","chain":chain,"state_path":str(st_path),"error":str(e)})

    # Write report artifact
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    rpt_path = outdir / f"aevum_recover_{ts}.json"
    atomic_write(rpt_path, json.dumps(report, indent=2, sort_keys=True), mode=0o600)
    rpt_sha = sha256_file(rpt_path)

    # Mint recovery receipt referencing report hash
    if not args.no_receipt:
        rc, out = run_receipt("note", "aevum-recover report", [
            "component=recover",
            f"recover_report_sha256={rpt_sha}",
            f"recover_report_path={str(rpt_path)}",
            f"repair_enabled={bool(args.repair)}",
            f"midfile_corruption={len(report['midfile_corruption'])}",
            f"tail_truncations={len(report['tail_truncations'])}",
            f"actions={len(report['actions'])}",
        ], base=base)
        report["receipt"] = {"rc": rc, "output": out[:2000]}

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"recover_report={rpt_path}")
        print(f"recover_report_sha256={rpt_sha}")
        print(f"midfile_corruption={len(report['midfile_corruption'])} tail_truncations={len(report['tail_truncations'])} actions={len(report['actions'])}")
        if report["midfile_corruption"]:
            for m in report["midfile_corruption"][:10]:
                print("CRITICAL:", m["chain"], m["error"])

    if args.strict and report["midfile_corruption"]:
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
