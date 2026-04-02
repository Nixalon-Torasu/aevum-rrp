#!/usr/bin/env python3
"""
aevum_uki_build.py — Optional UKI builder and signer (non-gating)

- Builds a Unified Kernel Image (UKI) for the currently running kernel (or specified uname -r).
- Prefer `ukify` if available.
- Optionally signs with sbsign (RSA key/cert).
- Writes a manifest JSON under /var/lib/aevum/workstation/boot/uki and mints a receipt pointer.

This tool does NOT change firmware boot order by default.
"""

from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Tuple

def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 127, "", str(e)

def sha256_file(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read_cmdline(max_len: int) -> str:
    # Prefer /etc/kernel/cmdline if present (systemd-boot style)
    p = pathlib.Path("/etc/kernel/cmdline")
    if p.exists():
        s = p.read_text(encoding="utf-8", errors="replace").strip()
    else:
        s = pathlib.Path("/proc/cmdline").read_text(encoding="utf-8", errors="replace").strip()
        # remove BOOT_IMAGE to reduce churn
        parts = [x for x in s.split() if not x.startswith("BOOT_IMAGE=")]
        s = " ".join(parts)
    if len(s) > max_len:
        s = s[:max_len]
    return s

def ensure_efi_mounted() -> bool:
    efi = pathlib.Path("/boot/efi")
    return efi.exists() and any(efi.iterdir())

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum")
    ap.add_argument("--instance", default="workstation")
    ap.add_argument("--uname-r", default="")
    ap.add_argument("--unsigned", action="store_true", help="Build unsigned UKI")
    ap.add_argument("--sign", action="store_true", help="Build and sign UKI")
    ap.add_argument("--policy", default="/etc/aevum/registry/uki_policy.json")
    ap.add_argument("--output-dir", default="")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    pol: Dict[str, Any] = {}
    try:
        pol = json.loads(pathlib.Path(args.policy).read_text(encoding="utf-8"))
    except Exception:
        pol = {}

    uname_r = args.uname_r or ""
    if not uname_r:
        rc, out, _ = run(["uname","-r"])
        uname_r = out.strip() if rc == 0 else ""

    if not uname_r:
        print("ERROR: could not determine uname -r", file=sys.stderr)
        return 2

    if not ensure_efi_mounted():
        print("ERROR: /boot/efi not mounted or empty. UKI output requires mounted ESP.", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.output_dir or pol.get("output_dir") or "/boot/efi/EFI/Linux")
    out_dir.mkdir(parents=True, exist_ok=True)

    max_cmdline = int(pol.get("max_cmdline_len", 4096))
    cmdline = read_cmdline(max_cmdline)

    kernel = pathlib.Path(f"/boot/vmlinuz-{uname_r}")
    initrd = pathlib.Path(f"/boot/initrd.img-{uname_r}")
    if not kernel.exists() or not initrd.exists():
        print(f"ERROR: kernel/initrd not found for {uname_r}: {kernel} {initrd}", file=sys.stderr)
        return 2

    ukify = shutil.which("ukify")
    if not ukify:
        # Some distros install as /usr/lib/systemd/ukify
        alt = pathlib.Path("/usr/lib/systemd/ukify")
        if alt.exists():
            ukify = str(alt)
    if not ukify:
        print("ERROR: ukify not found. Install a ukify provider (often `systemd-ukify`).", file=sys.stderr)
        return 2

    unsigned_name = (pol.get("unsigned_name_template","aevum-uki-{uname_r}.efi")).format(uname_r=uname_r)
    signed_name = (pol.get("signed_name_template","aevum-uki-{uname_r}.signed.efi")).format(uname_r=uname_r)

    unsigned_path = out_dir / unsigned_name
    signed_path = out_dir / signed_name

    tmp_unsigned = unsigned_path.with_suffix(".tmp.efi")
    tmp_signed = signed_path.with_suffix(".tmp.efi")

    osrel = pathlib.Path("/etc/os-release")
    stub = None
    # common stub locations
    for cand in ["/usr/lib/systemd/boot/efi/linuxx64.efi.stub","/usr/lib/systemd/boot/efi/linuxaa64.efi.stub"]:
        if pathlib.Path(cand).exists():
            stub = cand
            break

    cmd = [ukify, "build", "--linux", str(kernel), "--initrd", str(initrd), "--cmdline", cmdline, "--output", str(tmp_unsigned)]
    if osrel.exists():
        cmd += ["--os-release", str(osrel)]
    if stub:
        cmd += ["--stub", stub]

    manifest: Dict[str, Any] = {
        "type": "aevum_uki_manifest_v1",
        "generated_at_utc": utc(),
        "uname_r": uname_r,
        "cmdline_sha256": "sha256:" + hashlib.sha256(cmdline.encode("utf-8")).hexdigest(),
        "kernel": {"path": str(kernel), "sha256": "sha256:" + sha256_file(kernel)},
        "initrd": {"path": str(initrd), "sha256": "sha256:" + sha256_file(initrd)},
        "ukify_path": ukify,
        "ukify_cmd": cmd,
        "output_dir": str(out_dir),
        "unsigned": {"path": str(unsigned_path)},
        "signed": {"path": str(signed_path)},
        "signing": {"enabled": bool(args.sign)},
        "errors": [],
    }

    if args.dry_run:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    # build
    rc, o, e = run(cmd)
    manifest["ukify_rc"] = rc
    manifest["ukify_stdout"] = o[-2000:]
    manifest["ukify_stderr"] = e[-2000:]
    if rc != 0 or not tmp_unsigned.exists():
        manifest["errors"].append("ukify_failed")
    else:
        tmp_unsigned.replace(unsigned_path)
        manifest["unsigned"]["sha256"] = "sha256:" + sha256_file(unsigned_path)
        manifest["unsigned"]["size_bytes"] = unsigned_path.stat().st_size

    # sign if requested
    if args.sign and "ukify_failed" not in manifest["errors"]:
        keyp = pathlib.Path(pol.get("key_path","/etc/aevum/secureboot/keys/uki_signing.key"))
        certp = pathlib.Path(pol.get("cert_path","/etc/aevum/secureboot/keys/uki_signing.crt"))
        if not keyp.exists() or not certp.exists():
            manifest["errors"].append("missing_signing_key_or_cert")
        else:
            sbsign = shutil.which("sbsign")
            sbverify = shutil.which("sbverify")
            if not sbsign:
                manifest["errors"].append("missing_sbsign")
            else:
                scmd = [sbsign, "--key", str(keyp), "--cert", str(certp), "--output", str(tmp_signed), str(unsigned_path)]
                rc2, o2, e2 = run(scmd)
                manifest["sbsign_rc"] = rc2
                manifest["sbsign_stdout"] = o2[-2000:]
                manifest["sbsign_stderr"] = e2[-2000:]
                if rc2 != 0 or not tmp_signed.exists():
                    manifest["errors"].append("sbsign_failed")
                else:
                    tmp_signed.replace(signed_path)
                    manifest["signed"]["sha256"] = "sha256:" + sha256_file(signed_path)
                    manifest["signed"]["size_bytes"] = signed_path.stat().st_size
                    # best-effort verify
                    if sbverify:
                        vcmd = [sbverify, "--list", str(signed_path)]
                        rc3, o3, e3 = run(vcmd)
                        manifest["sbverify_rc"] = rc3
                        manifest["sbverify_stdout"] = o3[-2000:]
                        manifest["sbverify_stderr"] = e3[-2000:]
                        if rc3 != 0:
                            manifest["errors"].append("sbverify_failed")

    # write manifest
    base = pathlib.Path(args.base) / args.instance / "boot" / "uki"
    base.mkdir(parents=True, exist_ok=True)
    mp = base / f"uki_manifest_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    mp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # mint receipt (pointer to manifest)
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if ctl.exists():
        msha = "sha256:" + sha256_file(mp)
        kv = [
            f"component=secureboot",
            f"uki_manifest_sha256={msha}",
            f"uki_uname_r={uname_r}",
        ]
        if "sha256" in manifest.get("unsigned", {}):
            kv.append(f"uki_unsigned_sha256={manifest['unsigned']['sha256']}")
        if "sha256" in manifest.get("signed", {}):
            kv.append(f"uki_signed_sha256={manifest['signed']['sha256']}")
        msg = "secureboot: uki build"
        subprocess.run([sys.executable, str(ctl), "note", msg] + kv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    print(str(mp))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
