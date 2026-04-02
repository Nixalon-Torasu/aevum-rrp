#!/usr/bin/env python3
"""
aevum_boot_unlock_evidence.py (v0.2)

Proof-grade boot unlock evidence capture for crypttab-managed LUKS volumes.

This does NOT "prove" TPM usage cryptographically (Linux doesn't expose that as a signed primitive),
but it captures an operator-verifiable evidence bundle:
- systemd-cryptsetup unit properties
- full unit journal excerpt (hashed)
- systemd ask-password journal excerpt (hashed)
- LUKS token metadata snapshot at boot (hashed)
- mapper presence

From those, it derives a classification with explicit evidence anchors.

Writes:
  /var/lib/aevum/workstation/boot/unlock/boot_unlock_evidence_<bootid>_<ts>.json

Mints:
  a note receipt referencing the evidence digest (per boot)
"""

from __future__ import annotations
import argparse, json, os, pathlib, re, subprocess, sys, hashlib, datetime, shutil
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

def parse_crypttab(p: pathlib.Path) -> List[Dict[str, str]]:
    entries = []
    if not p.exists():
        return entries
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = re.split(r"\s+", s)
        if len(parts) < 2:
            continue
        name = parts[0]
        source = parts[1]
        opts = parts[3] if len(parts) >= 4 else ""
        entries.append({"name": name, "source": source, "options": opts})
    return entries

def optmap(opts: str) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    for tok in [t.strip() for t in opts.split(",") if t.strip()]:
        if "=" in tok:
            k,v = tok.split("=",1)
            m[k.strip()] = v.strip()
        else:
            m[tok] = True
    return m

def normalize_marker(s: str) -> str:
    return s.lower().strip()

def load_policy(path: pathlib.Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def resolve_source_to_device(source: str) -> Optional[str]:
    # Supports UUID=<luks_uuid> (LUKS uuid is visible to blkid on the underlying block device).
    if source.startswith("UUID="):
        uuid = source.split("=",1)[1].strip()
        if shutil.which("blkid"):
            rc, out = run(["blkid", "-t", f"UUID={uuid}", "-o", "device"])
            dev = out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else ""
            return dev or None
        return None
    if source.startswith("/dev/"):
        return source
    return None

def classify(method_inputs: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Return (claim, rationale)."""
    ask_markers = [normalize_marker(x) for x in policy.get("ask_password_markers", [])]
    tpm_markers = [normalize_marker(x) for x in policy.get("tpm_markers", [])]

    unit_log = normalize_marker(method_inputs.get("unit_log_text",""))
    ask_log = normalize_marker(method_inputs.get("ask_log_text",""))
    token_meta = normalize_marker(method_inputs.get("token_meta_text",""))

    mapper_present = bool(method_inputs.get("mapper_present", False))
    has_ask = any(m in ask_log for m in ask_markers) if ask_log else False
    has_tpm = any(m in unit_log for m in tpm_markers) if unit_log else False
    has_token_tpm = ("tpm2" in token_meta) or ("systemd-tpm2" in token_meta)

    # Proof-grade claim rules (explicitly conservative)
    if has_ask:
        return "passphrase", {"rule": "ask-password markers present", "mapper_present": mapper_present}
    if mapper_present and has_tpm and has_token_tpm:
        return "tpm2", {"rule": "mapper present + tpm markers in unit log + tpm token in luks metadata", "mapper_present": mapper_present}
    if mapper_present:
        return "unknown", {"rule": "mapper present but evidence insufficient to classify", "mapper_present": mapper_present}
    return "locked", {"rule": "mapper not present", "mapper_present": mapper_present}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="/var/lib/aevum/workstation/boot/unlock")
    ap.add_argument("--crypttab", default="/etc/crypttab")
    ap.add_argument("--policy", default="/etc/aevum/registry/unlock_method_policy.json")
    ap.add_argument("--no-receipt", action="store_true")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        return 2

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    boot_id = ""
    if pathlib.Path("/proc/sys/kernel/random/boot_id").exists():
        boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    policy = load_policy(pathlib.Path(args.policy))

    crypts = parse_crypttab(pathlib.Path(args.crypttab))
    # Track only entries that look managed for TPM2
    managed = []
    for e in crypts:
        om = optmap(e.get("options",""))
        if "tpm2-device" in om or "tpm2-pcrs" in om:
            managed.append(e)

    artifacts: List[Dict[str, Any]] = []
    volumes: List[Dict[str, Any]] = []

    for e in managed:
        name = e["name"]
        source = e["source"]
        unit = f"systemd-cryptsetup@{name}.service"
        mapper = f"/dev/mapper/{name}"
        mapper_present = pathlib.Path(mapper).exists()

        # Unit properties (operator-verifiable)
        props_rc, props = run(["systemctl","show",unit,"-p","Result","-p","ActiveState","-p","SubState","-p","ExecMainStatus","-p","ExecMainCode","-p","InvocationID"])
        props_path = outdir / f"unit_props_{name}_{ts}.txt"
        props_path.write_text(props, encoding="utf-8")
        artifacts.append({"kind":"unit_props", "name": name, "path": str(props_path), "sha256": sha256_path(props_path)})

        # Unit journal excerpt
        unit_log_text = ""
        unit_log_path = outdir / f"journal_unit_{name}_{ts}.txt"
        if shutil.which("journalctl"):
            rc, out = run(["journalctl","-b","-u",unit,"--no-pager","-o","cat"])
            unit_log_text = out
            unit_log_path.write_text(out, encoding="utf-8")
            artifacts.append({"kind":"unit_journal", "name": name, "path": str(unit_log_path), "sha256": sha256_path(unit_log_path)})

        # Ask-password journal excerpt (global, filtered)
        ask_log_text = ""
        ask_log_path = outdir / f"journal_ask_{name}_{ts}.txt"
        if shutil.which("journalctl"):
            # Pull ask-password lines; filter for our unit/name
            rc, out = run(["journalctl","-b","_COMM=systemd-ask-password","--no-pager","-o","cat"])
            # filter
            flt = []
            for ln in out.splitlines():
                if name in ln or unit in ln or "cryptsetup" in ln.lower():
                    flt.append(ln)
            ask_log_text = "\n".join(flt) + ("\n" if flt else "")
            ask_log_path.write_text(ask_log_text, encoding="utf-8")
            artifacts.append({"kind":"ask_journal", "name": name, "path": str(ask_log_path), "sha256": sha256_path(ask_log_path)})

        # Token metadata snapshot at boot
        token_meta_text = ""
        token_meta_path = outdir / f"luks_meta_{name}_{ts}.txt"
        dev = resolve_source_to_device(source)
        if dev and shutil.which("cryptsetup"):
            rc, out = run(["cryptsetup","luksDump",dev,"--dump-json-metadata"])
            if ("Unknown option" in out) or ("unrecognized option" in out.lower()) or (out.strip() == ""):
                rc, out = run(["cryptsetup","luksDump",dev])
            token_meta_text = out
            token_meta_path.write_text(out, encoding="utf-8")
            artifacts.append({"kind":"luks_metadata_boot", "name": name, "device": dev, "path": str(token_meta_path), "sha256": sha256_path(token_meta_path)})

        claim, rationale = classify({
            "unit_log_text": unit_log_text,
            "ask_log_text": ask_log_text,
            "token_meta_text": token_meta_text,
            "mapper_present": mapper_present
        }, policy)

        volumes.append({
            "name": name,
            "source": source,
            "device_resolved": dev,
            "mapper_present": mapper_present,
            "claim": claim,
            "rationale": rationale
        })

    summary = {
        "type": "aevum_boot_unlock_evidence_v2",
        "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boot_id": boot_id,
        "managed_count": len(volumes),
        "volumes": volumes,
        "artifacts": artifacts,
        "policy_sha256": ("sha256:" + hashlib.sha256(pathlib.Path(args.policy).read_bytes()).hexdigest()) if pathlib.Path(args.policy).exists() else None,
    }

    summary_path = outdir / f"boot_unlock_evidence_{boot_id}_{ts}.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    summary_sha = sha256_path(summary_path)

    if not args.no_receipt:
        r = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
        if r.exists():
            subprocess.run([str(r), "note", "boot unlock proof",
                            "component=boot",
                            f"boot_id={boot_id}",
                            f"evidence_sha256={summary_sha}",
                            f"evidence_path={str(summary_path)}"], check=False)

    print(str(summary_path))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
