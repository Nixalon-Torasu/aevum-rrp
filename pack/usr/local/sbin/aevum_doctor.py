#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, os, pathlib, platform, subprocess, sys, datetime, hashlib, shutil, time, socket
from typing import Dict, Any, List, Tuple

def run(cmd: List[str], timeout: int = 20) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 127, f"{type(e).__name__}: {e}"

def exists_cmd(name: str) -> bool:
    return shutil.which(name) is not None

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

def read_json(p: pathlib.Path) -> Dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def rrp_policy_require_live(policy_path: str = "/etc/aevum/registry/rrp_policy.json") -> tuple[bool, str]:
    """
    Policy-driven requirement for RRP printer liveness.
    Returns (require_live, unit_name).
    """
    try:
        p = pathlib.Path(policy_path)
        if not p.exists():
            return False, "aevum-rrp-printerd.service"
        data = json.loads(p.read_text(encoding="utf-8"))
        req = bool(data.get("require_printerd_live", False))
        unit = str(data.get("printerd_unit", "aevum-rrp-printerd.service"))
        return req, unit
    except Exception:
        return False, "aevum-rrp-printerd.service"



def check_path_writable(p: pathlib.Path) -> Dict[str, Any]:
    info = {"path": str(p), "exists": p.exists()}
    try:
        p.mkdir(parents=True, exist_ok=True)
        test = p / ".aevum_write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        info["writable"] = True
    except Exception as e:
        info["writable"] = False
        info["error"] = str(e)
    return info

def mint_receipt(kind: str, msg: str, kv: List[str]) -> Tuple[int, str]:
    # Prefer operator wrapper if present (writes via aevum_receiptctl)
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        rc, out = run([str(r), kind, msg] + kv, timeout=25)
        return rc, out[:4000]
    # Fallback to receiptctl
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if ctl.exists():
        rc, out = run([sys.executable, str(ctl), "--base", "/var/lib/aevum/workstation", "--kind", kind, "--message", msg] + kv, timeout=25)
        return rc, out[:4000]
    return 127, "no receipt tool found"

def rrp_ping(sock_path: str, timeout_s: float = 1.5) -> Dict[str, Any]:
    """
    Printer liveness probe:
    - connect to unix socket
    - send a minimal PROTO-correct object (will be rejected client_not_allowed, which is fine)
    - treat any JSON response as alive
    """
    PROTO = "AEVUM:PROTO:RRP:LOCAL_STRICT:V1_0"
    req = {"proto": PROTO, "req_id": "doctor_ping", "ts_client_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "ttl_ms": 1000}
    data = json.dumps(req, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect(sock_path)
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        out = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        if not out:
            return {"ok": False, "error": "no_response"}
        # accept first JSON object (printer may not newline-terminate on reject)
        try:
            txt = out.decode("utf-8", errors="replace").strip()
            obj = json.loads(txt.splitlines()[0])
            return {"ok": True, "response": obj}
        except Exception as e:
            return {"ok": True, "response_raw": out.decode("utf-8", errors="replace")[:500], "parse_error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            s.close()
        except Exception:
            pass

def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum Workstation doctor (deep diagnostic report)")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Aevum base directory")
    ap.add_argument("--outdir", default="", help="Where to write report artifacts (default: <base>/diagnostics)")
    ap.add_argument("--json", action="store_true", help="emit JSON only (still writes artifact files)")
    ap.add_argument("--no-receipt", action="store_true", help="do not mint receipts (doctor + auto-failure receipts)")
    ap.add_argument("--strict", action="store_true", help="return non-zero if any critical failures are found")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    accurate = base / "accurate"
    receipts = accurate / "receipts"
    payloads = accurate / "payloads"
    state = accurate / "state"

    outdir = pathlib.Path(args.outdir) if args.outdir else (base / "diagnostics")
    outdir.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.utcnow()
    ts = now.strftime("%Y%m%dT%H%M%SZ")

    report: Dict[str, Any] = {
        "type": "aevum_doctor_report_v2",
        "ts_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": platform.node(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "checks": {},
        "artifacts": [],
        "critical_failures": [],
        "warnings": [],
        "auto_failure_receipts": [],
    }

    # Core directories
    report["checks"]["dirs"] = {
        "base": check_path_writable(base),
        "accurate_receipts": check_path_writable(receipts),
        "accurate_payloads": check_path_writable(payloads),
        "accurate_state": check_path_writable(state),
    }
    for k,v in report["checks"]["dirs"].items():
        if not v.get("writable", False):
            report["critical_failures"].append(f"dir_not_writable:{k}:{v.get('path')}")

    # OS release
    osr = pathlib.Path("/etc/os-release")
    report["checks"]["os_release"] = {"exists": osr.exists(), "content": osr.read_text(encoding="utf-8", errors="replace")[:2000] if osr.exists() else ""}

    # Disk space
    if exists_cmd("df"):
        rc, txt = run(["df", "-h", str(base)], timeout=10)
        report["checks"]["disk"] = {"rc": rc, "df": txt}
    else:
        report["checks"]["disk"] = {"rc": 127, "df": "df missing"}

    # TPM and PCR read (best-effort)
    tpm = {
        "tpmrm0": pathlib.Path("/dev/tpmrm0").exists(),
        "tpm0": pathlib.Path("/dev/tpm0").exists(),
        "sysfs_tpm": pathlib.Path("/sys/class/tpm").exists(),
    }
    if exists_cmd("tpm2_getcap"):
        rc, txt = run(["tpm2_getcap", "properties-fixed"], timeout=10)
        tpm["getcap_properties_fixed"] = {"rc": rc, "output": txt[:2000]}
    if exists_cmd("tpm2_pcrread"):
        rc, txt = run(["tpm2_pcrread", "sha256:0,2,7"], timeout=12)
        tpm["pcrread_0_2_7"] = {"rc": rc, "output": txt[:2000]}
    report["checks"]["tpm"] = tpm
    if not (tpm["tpmrm0"] or tpm["tpm0"]):
        report["warnings"].append("tpm_device_missing")

    # Secure boot
    if exists_cmd("mokutil"):
        rc, txt = run(["mokutil", "--sb-state"], timeout=10)
        report["checks"]["secure_boot"] = {"rc": rc, "output": txt}
    else:
        report["checks"]["secure_boot"] = {"rc": 127, "output": "mokutil missing"}

    # GPUs (best-effort)
    if exists_cmd("nvidia-smi"):
        rc, txt = run(["nvidia-smi", "-L"], timeout=10)
        report["checks"]["gpus"] = {"nvidia_smi_rc": rc, "nvidia_smi_L": txt}
    elif exists_cmd("lspci"):
        rc, txt = run(["lspci"], timeout=10)
        gpu_lines = [l for l in txt.splitlines() if "vga" in l.lower() or "3d controller" in l.lower()]
        report["checks"]["gpus"] = {"lspci_rc": rc, "lspci_gpu_lines": gpu_lines}
    else:
        report["checks"]["gpus"] = {"rc": 127, "output": "no nvidia-smi or lspci"}

    # Services status
    units = [
        "aevum-timechain.service",
        "aevum-rrp-printerd.service",
        "aevum-boot-unlock-evidence.service",
        "auditd.service",
        "nftables.service",
    ]
    svc = {}
    if exists_cmd("systemctl"):
        for u in units:
            rc1, a = run(["systemctl", "is-active", u], timeout=6)
            rc2, e = run(["systemctl", "is-enabled", u], timeout=6)
            svc[u] = {"active": a, "enabled": e, "rc_active": rc1, "rc_enabled": rc2}
        report["checks"]["services"] = svc
        if svc.get("aevum-timechain.service", {}).get("active") != "active":
            report["critical_failures"].append("timechain_not_active")
    else:
        report["checks"]["services"] = {"rc": 127, "output": "systemctl missing"}
        report["warnings"].append("systemctl_missing")

    # Registry verify
    reg_verify = pathlib.Path("/opt/aevum-tools/bin/aevum-registry-verify")
    if reg_verify.exists():
        rc, txt = run([str(reg_verify), "--strict"], timeout=25)
        report["checks"]["registry_verify"] = {"rc": rc, "output": txt[:4000]}
        if rc != 0:
            report["critical_failures"].append("registry_verify_failed")
    else:
        report["checks"]["registry_verify"] = {"rc": 127, "output": "aevum-registry-verify missing"}
        report["warnings"].append("registry_verify_tool_missing")

    # Timechain freshness
    tfile = receipts / "T.jsonl"
    tc = {"path": str(tfile), "exists": tfile.exists()}
    if tfile.exists():
        st = tfile.stat()
        age = time.time() - st.st_mtime
        tc.update({
            "bytes": st.st_size,
            "mtime_utc": datetime.datetime.utcfromtimestamp(st.st_mtime).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "age_seconds": int(age),
        })
        if age > 10:
            report["warnings"].append(f"timechain_stale:{int(age)}s")
    else:
        report["critical_failures"].append("timechain_missing_T.jsonl")
    report["checks"]["timechain"] = tc

    # ------------------- RRP printer liveness -------------------
    sock_path = "/run/aevum/rrp.sock"
    rrp_require_live, rrp_unit = rrp_policy_require_live()

    rrp = {
        "service_unit": rrp_unit,
        "socket_path": sock_path,
        "socket_exists": pathlib.Path(sock_path).exists(),
    }
    # service state from svc if available
    if isinstance(report["checks"].get("services"), dict) and rrp_unit in report["checks"]["services"]:
        rrp["service_active"] = report["checks"]["services"][rrp_unit].get("active")
        rrp["service_enabled"] = report["checks"]["services"][rrp_unit].get("enabled")
    else:
        rrp["service_active"] = ""
        rrp["service_enabled"] = ""

    ping = rrp_ping(sock_path) if rrp["socket_exists"] else {"ok": False, "error": "socket_missing"}
    rrp["ping"] = ping
    rrp["live"] = bool(ping.get("ok", False))
    report["checks"]["rrp_printer"] = rrp

    # Failure semantics:
    # - If service not active OR socket missing OR ping fails => warn + auto receipt immediately (unless --no-receipt)
    rrp_failed = False
    reasons = []
    if rrp.get("service_active") and rrp.get("service_active") != "active":
        rrp_failed = True
        reasons.append(f"service_active={rrp.get('service_active')}")
    if not rrp.get("socket_exists", False):
        rrp_failed = True
        reasons.append("socket_missing")
    if not rrp.get("live", False):
        rrp_failed = True
        reasons.append(f"ping_failed:{ping.get('error','')}".strip(":"))

    if rrp_failed:
        report["warnings"].append("rrp_printer_not_live:" + ",".join([r for r in reasons if r]))

        # Policy-driven strictness: if policy requires printer live, treat as critical in --strict
        if args.strict and rrp_require_live:
            report["critical_failures"].append("rrp_printer_policy_violation:not_live")

        # Write a proof-bound evidence artifact (payload) for this failure, then reference it by hash in the receipt.
        evid = {
            "type": "aevum_rrp_printer_liveness_failure_v1",
            "ts_utc": report["ts_utc"],
            "host": report["host"],
            "socket_path": sock_path,
            "service_active": rrp.get("service_active",""),
            "service_enabled": rrp.get("service_enabled",""),
            "socket_exists": bool(rrp.get("socket_exists", False)),
            "ping_ok": bool(ping.get("ok", False)),
            "ping_error": str(ping.get("error","")),
            "ping_response": ping.get("response", None),
            "reasons": reasons,
        }
        evid_path = outdir / f"rrp_printer_failure_{platform.node()}_{ts}.json"
        atomic_write(evid_path, json.dumps(evid, indent=2, sort_keys=True), mode=0o600)
        evid_sha = sha256_file(evid_path)
        report["artifacts"].append({"kind": "rrp_printer_failure_evidence", "path": str(evid_path), "sha256": evid_sha})
        report["checks"]["rrp_printer"]["failure_evidence"] = {"path": str(evid_path), "sha256": evid_sha}

        # Mint an immediate failure receipt (workstation direct path), independent of RRP itself.
        if not args.no_receipt:
            rc, outt = mint_receipt("warn", "RRP printer liveness failure", [
                "component=doctor",
                "subsystem=rrp_printer",
                "socket=/run/aevum/rrp.sock",
                f"service_active={rrp.get('service_active','')}",
                f"service_enabled={rrp.get('service_enabled','')}",
                f"printerd_unit={rrp_unit}",
                f"socket_exists={rrp.get('socket_exists', False)}",
                f"ping_ok={ping.get('ok', False)}",
                f"ping_error={ping.get('error','')}",
                f"evidence_sha256={evid_sha}",
                f"evidence_path={str(evid_path)}",
            ])
            report["auto_failure_receipts"].append({"kind":"warn","rc":rc,"output":outt[:1200], "evidence_sha256": evid_sha, "evidence_path": str(evid_path)})
        else:
            report["auto_failure_receipts"].append({"kind":"warn","rc":0,"output":"skipped (--no-receipt)", "evidence_sha256": evid_sha, "evidence_path": str(evid_path)})




    # Write artifacts
    report_path = outdir / f"aevum_doctor_{platform.node()}_{ts}.json"
    atomic_write(report_path, json.dumps(report, indent=2, sort_keys=True), mode=0o600)
    report_sha = sha256_file(report_path)
    report["artifacts"].append({"kind":"doctor_report_json", "path": str(report_path), "sha256": report_sha})

    # Human-readable summary
    summary = []
    summary.append(f"utc={report['ts_utc']} host={report['host']} kernel={report['kernel']}")
    summary.append(f"base={base}")
    summary.append(f"critical_failures={len(report['critical_failures'])} warnings={len(report['warnings'])}")
    if report["critical_failures"]:
        summary.append("CRITICAL:")
        summary.extend(["  - " + x for x in report["critical_failures"]])
    if report["warnings"]:
        summary.append("WARN:")
        summary.extend(["  - " + x for x in report["warnings"]])
    summary_txt = "\n".join(summary) + "\n"

    summary_path = outdir / f"aevum_doctor_{platform.node()}_{ts}.txt"
    atomic_write(summary_path, summary_txt, mode=0o600)
    summary_sha = sha256_file(summary_path)
    report["artifacts"].append({"kind":"doctor_summary_txt", "path": str(summary_path), "sha256": summary_sha})

    # Mint doctor report receipt (normal path)
    if not args.no_receipt:
        rc, outt = mint_receipt("note", "aevum-doctor report", [
            "component=doctor",
            f"doctor_report_sha256={report_sha}",
            f"doctor_report_path={str(report_path)}",
            f"doctor_summary_sha256={summary_sha}",
            f"doctor_summary_path={str(summary_path)}",
            f"critical_failures={len(report['critical_failures'])}",
            f"warnings={len(report['warnings'])}",
        ])
        report["checks"]["doctor_receipt_minted"] = {"rc": rc, "output": outt}
    else:
        report["checks"]["doctor_receipt_minted"] = {"rc": 0, "output": "skipped (--no-receipt)"}

    # Emit output
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(summary_txt.strip())
        print(f"report_json={report_path}")
        print(f"report_sha256={report_sha}")

    if args.strict and report["critical_failures"]:
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
