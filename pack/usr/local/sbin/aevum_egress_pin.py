#!/usr/bin/env python3
from __future__ import annotations

"""
aevum_egress_pin.py (v0.1)

Minimal "observe -> propose" helper for egress pinning.
It does NOT modify firewall rules.

It collects recent nftables-related log lines from journald (best-effort),
extracts destination IP/domain hints when present, and writes an artifact report.
Then it mints a receipt referencing the artifact hash (unless --no-receipt).

This is intentionally conservative; promotion to allowlists is a separate step.
"""

import argparse, json, pathlib, os, sys, subprocess, datetime, hashlib, re
from typing import Dict, Any, List, Tuple

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

def run(cmd: List[str], timeout: int = 30) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 127, f"{type(e).__name__}: {e}"

def mint_receipt(kind: str, msg: str, kv: List[str], base: pathlib.Path) -> Tuple[int, str]:
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        return run([str(r), kind, msg] + kv, timeout=25)
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if ctl.exists():
        return run([sys.executable, str(ctl), "--base", str(base), "--kind", kind, "--message", msg] + kv, timeout=25)
    return 127, "no receipt tool"

def extract_hints(lines: List[str]) -> Dict[str, Any]:
    ips = set()
    ifaces = set()
    ports = set()
    for ln in lines:
        # common nft log fragments: "SRC=... DST=... DPT=... IN=..."
        m = re.search(r"\bDST=([0-9\.]+)\b", ln)
        if m: ips.add(m.group(1))
        m = re.search(r"\bDPT=(\d+)\b", ln)
        if m: ports.add(m.group(1))
        m = re.search(r"\bIN=([A-Za-z0-9\-\._]+)\b", ln)
        if m: ifaces.add(m.group(1))
    return {"dst_ips": sorted(ips)[:500], "dst_ports": sorted(ports)[:200], "in_ifaces": sorted(ifaces)[:50]}

def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum egress pin observer (no firewall modification)")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation base directory")
    ap.add_argument("--since", default="2h", help="journalctl --since (e.g., '30min', '2h', 'today')")
    ap.add_argument("--outdir", default="", help="Output dir (default <base>/diagnostics)")
    ap.add_argument("--no-receipt", action="store_true", help="Do not mint a receipt")
    ap.add_argument("--json", action="store_true", help="Emit JSON report")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    outdir = pathlib.Path(args.outdir) if args.outdir else (base / "diagnostics")
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # Collect logs (best-effort)
    rc, out = run(["journalctl", "-S", args.since, "-o", "short-iso", "--no-pager"], timeout=45)
    lines = []
    if rc == 0 and out:
        # Filter likely nft/firewall lines
        for ln in out.splitlines():
            if "nft" in ln.lower() or "aevum-firewall" in ln.lower() or "IN=" in ln or "DST=" in ln:
                lines.append(ln)
    hints = extract_hints(lines)

    report: Dict[str, Any] = {
        "schema": "AEVUM:EGRESS:OBSERVE_REPORT:V1",
        "ts_utc": utc_now(),
        "since": args.since,
        "log_lines_collected": len(lines),
        "hints": hints,
        "sample_lines": lines[:200],
    }

    rpt = outdir / f"aevum_egress_observe_{ts}.json"
    atomic_write(rpt, json.dumps(report, indent=2, sort_keys=True), mode=0o600)
    rpt_sha = sha256_file(rpt)

    if not args.no_receipt:
        rrc, rout = mint_receipt("note", "aevum-egress observe report", [
            "component=egress_observe",
            f"since={args.since}",
            f"egress_observe_report_sha256={rpt_sha}",
            f"egress_observe_report_path={str(rpt)}",
            f"log_lines={len(lines)}",
            f"dst_ips={len(hints.get('dst_ips',[]))}",
        ], base=base)
        report["receipt"] = {"rc": rrc, "output": rout[:2000]}

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"egress_observe_report={rpt}")
        print(f"egress_observe_report_sha256={rpt_sha}")
        print(f"dst_ips={len(hints.get('dst_ips',[]))} ports={len(hints.get('dst_ports',[]))}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
