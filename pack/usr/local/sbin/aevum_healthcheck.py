#!/usr/bin/env python3
"""aevum_healthcheck.py

Non-gating periodic health checks. Emits a receipt note on WARN/FAIL conditions.
Checks:
- critical systemd units active (auditd + key aevum units)
- disk space for /var/lib/aevum (min free %)
- rasdaemon corrected errors (best-effort)

Exit code:
0 always (non-gating). Writes to stdout for logs.

"""
from __future__ import annotations
import json, os, pathlib, shutil, subprocess, sys
from datetime import datetime, timezone

CRIT_UNITS = [
  "auditd.service",
  "aevum-workstation-timechain.service",
  "aevum-workstation-observer.service",
  "aevum-firewall.service",
]

def is_active(unit: str) -> bool:
    try:
        subprocess.check_call(["systemctl","is-active","--quiet",unit])
        return True
    except Exception:
        return False

def disk_free_pct(path: str) -> float:
    st = shutil.disk_usage(path)
    return (st.free / st.total) * 100.0 if st.total else 0.0

def rasdaemon_summary() -> dict:
    # best-effort; ras-mc-ctl outputs human text. We'll just count lines mentioning "Corrected" in journal.
    try:
        out = subprocess.check_output(["journalctl","-u","rasdaemon.service","--since","1 day ago","--no-pager"], text=True, stderr=subprocess.DEVNULL)
        cnt = sum(1 for line in out.splitlines() if "Corrected" in line or "corrected" in line)
        return {"rasdaemon_corrected_lines_24h": cnt}
    except Exception:
        return {}

def receipt_note(note: str, tags: dict):
    tool = "/opt/aevum-tools/bin/aevum-receipt"
    if os.path.exists(tool) and os.access(tool, os.X_OK):
        kv = " ".join([f'{k}={v}' for k,v in tags.items()])
        subprocess.call([tool,"note",note] + [f"{k}={v}" for k,v in tags.items()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    findings = {"timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    status = "PASS"
    unit_status = {u: is_active(u) for u in CRIT_UNITS}
    findings["units"] = unit_status
    for u, ok in unit_status.items():
        if not ok:
            status = "FAIL"
    # disk
    try:
        pct = disk_free_pct("/var/lib/aevum")
        findings["disk_free_pct_var_lib_aevum"] = round(pct,2)
        if pct < 8.0:
            status = "FAIL"
        elif pct < 15.0 and status == "PASS":
            status = "WARN"
    except Exception:
        pass

    findings.update(rasdaemon_summary())
    findings["status"] = status

    print(json.dumps(findings, sort_keys=True))
    if status != "PASS":
        receipt_note("healthcheck "+status.lower(), {"component":"health", "status":status})

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
