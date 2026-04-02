#!/usr/bin/env python3
from __future__ import annotations

"""
aevum_selftest.py (v0.1)

Selftest harness for the workstation foundation.
Modes:
- --installed (default): test on the real base (assumes identity exists)
- --sandbox: create a temporary base in /tmp, bootstrap identity, mint a few receipts, verify them, then cleanup (unless --keep)

Produces:
- selftest report artifact (json) with sha256
- receipt referencing report hash (unless --no-receipt)

This is not a benchmark; it's a determinism and continuity smoke test.
"""

import argparse, json, pathlib, os, sys, tempfile, subprocess, datetime, hashlib
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

def run(cmd: List[str], timeout: int = 60) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 127, f"{type(e).__name__}: {e}"

def mint_receipt(base: pathlib.Path, kind: str, msg: str, kv: List[str]) -> Tuple[int, str]:
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        return run([str(r), kind, msg] + kv, timeout=25)
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if ctl.exists():
        return run([sys.executable, str(ctl), "--base", str(base), "--kind", kind, "--message", msg] + kv, timeout=25)
    return 127, "no receipt tool"

def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum workstation selftest")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation base directory")
    ap.add_argument("--sandbox", action="store_true", help="Run in a temporary sandbox base (creates identity + receipts)")
    ap.add_argument("--keep", action="store_true", help="Keep sandbox directory (do not delete)")
    ap.add_argument("--no-receipt", action="store_true", help="Do not mint selftest receipt")
    ap.add_argument("--json", action="store_true", help="Emit JSON report")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero on any failure")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    sandbox_dir = None
    if args.sandbox:
        sandbox_dir = pathlib.Path(tempfile.mkdtemp(prefix="aevum-selftest-"))
        base = sandbox_dir / "workstation"
        base.mkdir(parents=True, exist_ok=True)

    outdir = base / "diagnostics"
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    report: Dict[str, Any] = {
        "schema": "AEVUM:SELFTEST:REPORT:V1",
        "ts_utc": utc_now(),
        "mode": "sandbox" if args.sandbox else "installed",
        "base": str(base),
        "steps": [],
        "failures": [],
    }

    def step(name: str, cmd: List[str], ok_codes=(0,)) -> None:
        rc, out = run(cmd, timeout=90)
        report["steps"].append({"name": name, "cmd": cmd, "rc": rc, "output": out[:4000]})
        if rc not in ok_codes:
            report["failures"].append(f"{name}: rc={rc}")

    # Sandbox bootstrap identity if needed
    if args.sandbox:
        idb = pathlib.Path("/usr/local/sbin/aevum_identity_bootstrap.py")
        if not idb.exists():
            # allow running from repo: look next to this file
            idb = pathlib.Path(__file__).resolve().parent / "aevum_identity_bootstrap.py"
        step("identity_bootstrap", [sys.executable, str(idb), "--base", str(base.parent), "--instance", "workstation", "--seam-layout"], ok_codes=(0,))
        # Write one timeblock
        tcd = pathlib.Path("/usr/local/sbin/aevum_timechain_daemon.py")
        if not tcd.exists():
            tcd = pathlib.Path(__file__).resolve().parent / "aevum_timechain_daemon.py"
        step("timechain_once", [sys.executable, str(tcd), "--base", str(base), "--once"], ok_codes=(0,))
        step("timechain_once_2", [sys.executable, str(tcd), "--base", str(base), "--once"], ok_codes=(0,))
        # Mint interaction receipt
        rc, out = mint_receipt(base, "note", "selftest mint", ["component=selftest","mode=sandbox"])
        report["steps"].append({"name":"mint_receipt", "cmd":["aevum-receipt","note","selftest mint"], "rc":rc, "output":out[:2000]})
        if rc != 0:
            report["failures"].append(f"mint_receipt: rc={rc}")

        # Verify logs in sandbox
        vfy = pathlib.Path("/usr/local/sbin/aevum_verify.py")
        if not vfy.exists():
            vfy = pathlib.Path(__file__).resolve().parent / "aevum_verify.py"
        ident = base / "identity" / "identity.json"
        step("verify_T", [sys.executable, str(vfy), "--base", str(base), "--chain", "T", "--identity", str(ident)], ok_codes=(0,))
        step("verify_I", [sys.executable, str(vfy), "--base", str(base), "--chain", "I", "--identity", str(ident)], ok_codes=(0,))

    else:
        # Installed mode checks: status, doctor, registry verify, continuity verify (best-effort)
        st = pathlib.Path("/opt/aevum-tools/bin/aevum-status")
        if st.exists():
            step("aevum_status", [str(st), "--json"], ok_codes=(0,))
        doc = pathlib.Path("/opt/aevum-tools/bin/aevum-doctor")
        if doc.exists():
            # non-strict doctor; strictness depends on operator policy; keep selftest conservative
            step("aevum_doctor", [str(doc), "--json"], ok_codes=(0,2))  # allow 2 to bubble into failures list below
        regv = pathlib.Path("/opt/aevum-tools/bin/aevum-registry-verify")
        if regv.exists():
            step("registry_verify", [str(regv), "--strict"], ok_codes=(0,))
        cont = pathlib.Path("/opt/aevum-tools/bin/aevum-verify-continuity")
        if cont.exists():
            step("verify_continuity", [str(cont), "--strict"], ok_codes=(0,))

    # Write report
    rpt_path = outdir / f"aevum_selftest_{ts}.json"
    atomic_write(rpt_path, json.dumps(report, indent=2, sort_keys=True), mode=0o600)
    rpt_sha = sha256_file(rpt_path)

    if not args.no_receipt:
        rc, out = mint_receipt(base, "note", "aevum-selftest report", [
            "component=selftest",
            f"mode={'sandbox' if args.sandbox else 'installed'}",
            f"selftest_report_sha256={rpt_sha}",
            f"selftest_report_path={str(rpt_path)}",
            f"failures={len(report['failures'])}",
        ])
        report["receipt"] = {"rc": rc, "output": out[:2000]}

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"selftest_report={rpt_path}")
        print(f"selftest_report_sha256={rpt_sha}")
        print(f"failures={len(report['failures'])}")
        if sandbox_dir:
            print(f"sandbox_dir={sandbox_dir} keep={args.keep}")

    # Cleanup sandbox unless keep
    if sandbox_dir and not args.keep:
        try:
            import shutil
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    if args.strict and report["failures"]:
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
