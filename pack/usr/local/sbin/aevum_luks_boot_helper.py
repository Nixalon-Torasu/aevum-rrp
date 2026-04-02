#!/usr/bin/env python3
"""
aevum_luks_boot_helper.py (v0.1)

Plan-first helper to configure /etc/crypttab for TPM2-unsealed LUKS2 volumes,
then rebuild initramfs.

Default: PLAN ONLY (no changes).
Apply requires: --apply --i-understand

Registry:
- /etc/aevum/registry/luks_devices.json
- /etc/aevum/registry/luks_policy.json

Artifacts:
- /var/lib/aevum/workstation/boot/crypttab/

Mints receipts (note) for plan/apply.
"""

from __future__ import annotations
import argparse, json, pathlib, subprocess, hashlib, datetime, os, re, sys, shutil
from typing import Dict, Any, List, Tuple, Optional

def run(cmd: List[str]) -> Tuple[int, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def sha256_path(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def load_json(p: pathlib.Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))

def normalize_pcrs(p: str) -> str:
    s = p.replace("+", ",")
    toks = []
    for t in s.split(","):
        t = t.strip()
        if not t:
            continue
        try:
            toks.append(str(int(t)))
        except Exception:
            pass
    toks = sorted(set(toks), key=lambda x: int(x))
    return ",".join(toks)

def devices_list(devs: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if isinstance(devs, list):
        for d in devs:
            if isinstance(d, str):
                out.append({"device": d})
            elif isinstance(d, dict) and "device" in d:
                out.append({"device": str(d["device"]), "name": str(d.get("name","")).strip() or None})
    return out

def crypttab_line(name: str, luks_uuid: str, policy: Dict[str, Any]) -> str:
    pcrs = normalize_pcrs(str(policy.get("default_pcrs","0,2,7")))
    opts = ["luks"]
    if policy.get("require_tpm2_device_auto", True):
        opts.append("tpm2-device=auto")
    opts.append(f"tpm2-pcrs={pcrs}")
    if policy.get("require_x_initrd_attach", True):
        opts.append("x-initrd.attach")
    for extra in policy.get("crypttab_options_extra", []) or []:
        if isinstance(extra, str) and extra.strip():
            opts.append(extra.strip())
    optstr = ",".join(opts)
    # keyfile 'none' is standard for systemd token usage
    return f"{name}\tUUID={luks_uuid}\tnone\t{optstr}"

def pick_name(entry: Dict[str, str], luks_uuid: str) -> str:
    if entry.get("name"):
        return entry["name"]
    # stable name from uuid prefix
    return "luks-" + luks_uuid.split("-")[0]

def ensure_root():
    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        raise SystemExit(2)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", default="/etc/aevum/registry/luks_devices.json")
    ap.add_argument("--policy", default="/etc/aevum/registry/luks_policy.json")
    ap.add_argument("--crypttab", default="/etc/crypttab")
    ap.add_argument("--outdir", default="/var/lib/aevum/workstation/boot/crypttab")
    ap.add_argument("--apply", action="store_true", help="Apply changes to /etc/crypttab and rebuild initramfs")
    ap.add_argument("--i-understand", action="store_true", help="Required with --apply")
    ap.add_argument("--kernel", default="all", help="Kernel for update-initramfs (-k). Default: all")
    args = ap.parse_args()
    ensure_root()

    devs_p = pathlib.Path(args.devices)
    pol_p = pathlib.Path(args.policy)
    ct_p = pathlib.Path(args.crypttab)

    if not devs_p.exists() or not pol_p.exists():
        print("ERROR: missing luks_devices.json or luks_policy.json in registry", file=sys.stderr)
        return 3

    devs = load_json(devs_p)
    policy = load_json(pol_p)
    dev_entries = devices_list(devs.get("devices", []))
    if not dev_entries:
        print("INFO: no devices listed in luks_devices.json; nothing to do")
        return 0

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    current = ct_p.read_text(encoding="utf-8", errors="replace") if ct_p.exists() else ""
    before_path = outdir / f"crypttab_before_{ts}.txt"
    before_path.write_text(current, encoding="utf-8")

    proposed_lines: List[str] = []
    plan_devices: List[Dict[str, Any]] = []
    for d in dev_entries:
        dev = d["device"]
        # Must be LUKS and have UUID
        rc, out = run(["cryptsetup", "isLuks", dev])
        if rc != 0:
            plan_devices.append({"device": dev, "status": "not_luks"})
            continue
        rc, luks_uuid = run(["cryptsetup", "luksUUID", dev])
        luks_uuid = luks_uuid.strip()
        if rc != 0 or not luks_uuid:
            plan_devices.append({"device": dev, "status": "no_uuid"})
            continue
        name = pick_name(d, luks_uuid)
        line = crypttab_line(name, luks_uuid, policy)
        proposed_lines.append(line)
        plan_devices.append({"device": dev, "luks_uuid": luks_uuid, "name": name, "crypttab_line": line, "status": "ok"})

    # Merge strategy: keep existing non-managed entries, replace managed names
    existing_lines = current.splitlines()
    managed_names = {pd["name"] for pd in plan_devices if pd.get("status") == "ok"}
    merged: List[str] = []
    for ln in existing_lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            merged.append(ln)
            continue
        name = re.split(r"\s+", s)[0]
        if name in managed_names:
            continue
        merged.append(ln)
    # Append managed at end
    merged.append("")
    merged.append("# --- AEVUM MANAGED (LUKS/TPM2) ---")
    merged.extend(proposed_lines)
    merged_txt = "\n".join(merged).rstrip() + "\n"

    proposed_path = outdir / f"crypttab_proposed_{ts}.txt"
    proposed_path.write_text(merged_txt, encoding="utf-8")

    plan = {
        "type": "aevum_luks_boot_plan_v1",
        "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "devices": plan_devices,
        "artifacts": {
            "crypttab_before": {"path": str(before_path), "sha256": sha256_path(before_path)},
            "crypttab_proposed": {"path": str(proposed_path), "sha256": sha256_path(proposed_path)},
            "luks_devices_registry": {"path": str(devs_p), "sha256": "sha256:" + hashlib.sha256(devs_p.read_bytes()).hexdigest()},
            "luks_policy_registry": {"path": str(pol_p), "sha256": "sha256:" + hashlib.sha256(pol_p.read_bytes()).hexdigest()},
        }
    }
    plan_path = outdir / f"crypttab_plan_{ts}.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    plan_sha = sha256_path(plan_path)

    # Receipt the plan
    r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if r.exists():
        subprocess.run([str(r), "note", "luks crypttab plan",
                        "component=boot",
                        f"plan_sha256={plan_sha}",
                        f"plan_path={str(plan_path)}"], check=False)

    if not args.apply:
        print(str(plan_path))
        return 0

    if not args.i_understand:
        print("ERROR: --apply requires --i-understand", file=sys.stderr)
        return 4

    # Apply
    backup_path = outdir / f"crypttab_backup_{ts}.txt"
    backup_path.write_text(current, encoding="utf-8")
    ct_p.write_text(merged_txt, encoding="utf-8")

    # Update initramfs
    init_log = outdir / f"update_initramfs_{ts}.log"
    if shutil.which("update-initramfs") is None:
        init_log.write_text("update-initramfs not found\n", encoding="utf-8")
    else:
        rc, out = run(["update-initramfs", "-u", "-k", args.kernel])
        init_log.write_text(out, encoding="utf-8")

    apply = {
        "type": "aevum_luks_boot_apply_v1",
        "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plan_sha256": plan_sha,
        "artifacts": {
            "crypttab_backup": {"path": str(backup_path), "sha256": sha256_path(backup_path)},
            "crypttab_written": {"path": str(ct_p), "sha256": "sha256:" + hashlib.sha256(ct_p.read_bytes()).hexdigest()},
            "update_initramfs_log": {"path": str(init_log), "sha256": sha256_path(init_log)}
        }
    }
    apply_path = outdir / f"crypttab_apply_{ts}.json"
    apply_path.write_text(json.dumps(apply, indent=2, sort_keys=True), encoding="utf-8")
    apply_sha = sha256_path(apply_path)

    if r.exists():
        subprocess.run([str(r), "note", "luks crypttab apply",
                        "component=boot",
                        f"apply_sha256={apply_sha}",
                        f"apply_path={str(apply_path)}"], check=False)

    print(str(apply_path))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
