#!/usr/bin/env python3
"""
aevum_luks_crypttab_verify.py (v0.1)

Strict verifier for /etc/crypttab alignment with:
- /etc/aevum/registry/luks_devices.json
- /etc/aevum/registry/luks_policy.json

This prevents silent drift between 'what we think boot unlock policy is' and what the OS actually does.

Exit codes:
 0 PASS
 2 FAIL
"""

from __future__ import annotations
import argparse, json, pathlib, re, sys, subprocess, os
from typing import Dict, Any, List, Tuple

def load_json(p: pathlib.Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))

def parse_crypttab(p: pathlib.Path) -> List[Dict[str, str]]:
    entries = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = re.split(r"\s+", s)
        if len(parts) < 2:
            continue
        name = parts[0]
        source = parts[1]
        keyfile = parts[2] if len(parts) >= 3 else "none"
        opts = parts[3] if len(parts) >= 4 else ""
        entries.append({"name": name, "source": source, "keyfile": keyfile, "options": opts})
    return entries

def normalize_pcrs(pcrs: str) -> str:
    s = pcrs.replace("+", ",")
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

def optmap(opts: str) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    for tok in [t.strip() for t in opts.split(",") if t.strip()]:
        if "=" in tok:
            k,v = tok.split("=",1)
            m[k.strip()] = v.strip()
        else:
            m[tok] = True
    return m

def devices_list(devs: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if isinstance(devs, list):
        for d in devs:
            if isinstance(d, str):
                out.append({"device": d})
            elif isinstance(d, dict) and "device" in d:
                out.append({"device": str(d["device"]), "name": str(d.get("name","")).strip() or None})
    return out

def luks_uuid(dev: str) -> str:
    try:
        p = subprocess.run(["cryptsetup","luksUUID",dev], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
    except Exception:
        pass
    return ""

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", default="/etc/aevum/registry/luks_devices.json")
    ap.add_argument("--policy", default="/etc/aevum/registry/luks_policy.json")
    ap.add_argument("--crypttab", default="/etc/crypttab")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        return 2

    devs_p = pathlib.Path(args.devices)
    pol_p = pathlib.Path(args.policy)
    ct_p = pathlib.Path(args.crypttab)

    if not devs_p.exists() or not pol_p.exists() or not ct_p.exists():
        print("FAIL: missing required files")
        for p in [devs_p, pol_p, ct_p]:
            if not p.exists():
                print(f"  missing: {p}")
        return 2

    devs = load_json(devs_p)
    policy = load_json(pol_p)
    required = devices_list(devs.get("devices", []))
    if not required:
        print("WARN: no devices listed in luks_devices.json; nothing to verify")
        return 0

    entries = parse_crypttab(ct_p)
    by_name = {e["name"]: e for e in entries}

    want_pcrs = normalize_pcrs(str(policy.get("default_pcrs","0,2,7")))
    failures: List[str] = []
    checked = 0

    for d in required:
        dev = d["device"]
        uuid = luks_uuid(dev)
        if not uuid:
            failures.append(f"{dev}: cannot resolve luksUUID (is it LUKS? does cryptsetup see it?)")
            continue
        name = d.get("name") or ("luks-" + uuid.split("-")[0])
        e = by_name.get(name)
        if not e:
            failures.append(f"{dev}: missing crypttab entry name='{name}' (expected source UUID={uuid})")
            continue
        checked += 1
        if not e["source"].startswith("UUID="):
            failures.append(f"{dev}: crypttab source should be UUID=... (got {e['source']})")
        else:
            got = e["source"].split("=",1)[1].strip()
            if got != uuid:
                failures.append(f"{dev}: crypttab UUID mismatch (want {uuid}, got {got})")

        om = optmap(e.get("options",""))
        if "luks" not in om:
            failures.append(f"{dev}: missing 'luks' option in crypttab ({name})")
        if policy.get("require_tpm2_device_auto", True):
            if "tpm2-device" not in om:
                failures.append(f"{dev}: missing 'tpm2-device=auto' in crypttab ({name})")
            else:
                if str(om.get("tpm2-device")) != "auto":
                    failures.append(f"{dev}: tpm2-device must be 'auto' (got {om.get('tpm2-device')})")
        if "tpm2-pcrs" not in om:
            failures.append(f"{dev}: missing tpm2-pcrs (want {want_pcrs})")
        else:
            got_pcrs = normalize_pcrs(str(om.get("tpm2-pcrs")))
            if got_pcrs != want_pcrs:
                failures.append(f"{dev}: tpm2-pcrs mismatch (want {want_pcrs}, got {got_pcrs})")
        if policy.get("require_x_initrd_attach", True):
            if "x-initrd.attach" not in om:
                failures.append(f"{dev}: missing x-initrd.attach in crypttab ({name})")

    if failures and args.strict:
        print("FAIL: crypttab does not match registry policy")
        for f in failures:
            print("  - " + f)
        return 2
    if failures:
        print("WARN: crypttab mismatches (non-strict)")
        for f in failures:
            print("  - " + f)
        return 0

    print(f"PASS: crypttab verified for {checked}/{len(required)} devices")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
