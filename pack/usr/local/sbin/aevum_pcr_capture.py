#!/usr/bin/env python3
"""
aevum_pcr_capture.py (v0.1)

Capture TPM PCR values (banks: sha256, sha1, sha384) for PCRs 0-23.
Writes pcr_<YYYYMMDDTHHMMSSZ>.json to <base>/<instance>/boot/
and emits a best-effort receipt so the event appears in chain I.

Run once at boot (e.g. from a systemd service before the timechain daemon).

Usage:
    python3 aevum_pcr_capture.py [--base /var/lib/aevum] [--instance workstation]
                                  [--banks sha256,sha1,sha384] [--pcrs 0-23]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional


BANKS_DEFAULT = ["sha256", "sha1", "sha384"]
PCRS_DEFAULT = list(range(24))   # 0-23


def utc_ts() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _pcr_selector(banks: List[str], pcrs: List[int]) -> str:
    """
    Build tpm2_pcrread selector string, e.g.
      sha256:0,1,2,...,23+sha1:0,1,...,23
    """
    pcr_list = ",".join(str(p) for p in sorted(pcrs))
    return "+".join(f"{b}:{pcr_list}" for b in banks)


def _parse_pcrread_output(output: str) -> Dict[str, Dict[int, str]]:
    """
    Parse tpm2_pcrread YAML-like output:

      sha256:
        0 : 0xAABBCC...
        1 : 0x...
      sha1:
        0 : 0x...

    Returns {bank: {pcr_index: hex_value_without_0x}}.
    """
    result: Dict[str, Dict[int, str]] = {}
    current_bank: Optional[str] = None

    # Detect bank headers and PCR value lines
    bank_re = re.compile(r"^([a-zA-Z0-9_]+)\s*:\s*$")
    pcr_re  = re.compile(r"^\s+(\d+)\s*:\s*0x([0-9a-fA-F]+)\s*$")

    for line in output.splitlines():
        bm = bank_re.match(line)
        if bm:
            current_bank = bm.group(1).lower()
            if current_bank not in result:
                result[current_bank] = {}
            continue
        pm = pcr_re.match(line)
        if pm and current_bank is not None:
            pcr_idx = int(pm.group(1))
            pcr_val = pm.group(2).lower()
            result[current_bank][pcr_idx] = pcr_val

    return result


def capture_pcrs(banks: List[str], pcrs: List[int]) -> Dict[str, Any]:
    """
    Run tpm2_pcrread and return structured PCR data.
    Returns a capture dict with raw values + per-bank SHA256 digests.
    Falls back gracefully if tpm2_pcrread is not present.
    """
    if not any(
        pathlib.Path(d).joinpath("tpm2_pcrread").exists()
        for d in (os.environ.get("PATH", "").split(":") + ["/usr/bin", "/usr/local/bin"])
    ):
        return {
            "error": "tpm2_pcrread not found in PATH",
            "banks": {},
            "bank_digests": {},
        }

    selector = _pcr_selector(banks, pcrs)
    try:
        proc = subprocess.run(
            ["tpm2_pcrread", selector],
            capture_output=True, text=True, timeout=15,
        )
        raw_output = proc.stdout
        rc = proc.returncode
    except FileNotFoundError:
        return {
            "error": "tpm2_pcrread binary not found",
            "banks": {},
            "bank_digests": {},
        }
    except subprocess.TimeoutExpired:
        return {
            "error": "tpm2_pcrread timed out",
            "banks": {},
            "bank_digests": {},
        }
    except Exception as e:
        return {
            "error": f"tpm2_pcrread failed: {e}",
            "banks": {},
            "bank_digests": {},
        }

    if rc != 0:
        return {
            "error": f"tpm2_pcrread exited {rc}: {proc.stderr.strip()[:200]}",
            "banks": {},
            "bank_digests": {},
        }

    parsed = _parse_pcrread_output(raw_output)

    # Build a stable per-bank digest: sha256(concat of sorted pcr values in hex)
    bank_digests: Dict[str, str] = {}
    for bank, pcrmap in sorted(parsed.items()):
        flat = "".join(pcrmap[k] for k in sorted(pcrmap.keys()))
        bank_digests[bank] = "sha256:" + sha256_hex(flat.encode("ascii"))

    return {
        "error": None,
        "banks": {bank: {str(k): v for k, v in sorted(pcrmap.items())} for bank, pcrmap in sorted(parsed.items())},
        "bank_digests": bank_digests,
        "raw_output_sha256": "sha256:" + sha256_hex(raw_output.encode("utf-8")),
    }


def write_pcr_snapshot(boot_dir: pathlib.Path, snapshot: Dict[str, Any], ts: str) -> pathlib.Path:
    boot_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(boot_dir, 0o700)
    except Exception:
        pass
    out = boot_dir / f"pcr_{ts}.json"
    out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)
    return out


def emit_receipt_best_effort(out_path: pathlib.Path, sha256_tagged: str) -> None:
    """
    Emit a chain-I receipt via the aevum-receipt binary (best-effort).
    Silently skips if the binary doesn't exist or fails.
    """
    receipt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if not (receipt.exists() and os.access(receipt, os.X_OK)):
        # Try common install locations
        for candidate in [
            pathlib.Path("/usr/local/bin/aevum-receipt"),
            pathlib.Path("/usr/bin/aevum-receipt"),
        ]:
            if candidate.exists() and os.access(candidate, os.X_OK):
                receipt = candidate
                break
        else:
            return  # not available yet, silently skip

    try:
        subprocess.run(
            [
                str(receipt),
                "note",
                "tpm pcr snapshot captured",
                "component=boot_integrity",
                f"file={out_path}",
                f"manifest={sha256_tagged}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Capture TPM PCR values and write pcr_<TS>.json to the Aevum boot directory."
    )
    ap.add_argument("--base", default="/var/lib/aevum", help="Aevum base directory.")
    ap.add_argument("--instance", default="workstation", help="Instance name (default: workstation).")
    ap.add_argument(
        "--banks",
        default=",".join(BANKS_DEFAULT),
        help="Comma-separated list of PCR hash banks to read (default: sha256,sha1,sha384).",
    )
    ap.add_argument(
        "--pcrs",
        default="0-23",
        help="PCR range/list to read. Use 'N-M' for range or 'N,M,...' for list (default: 0-23).",
    )
    ap.add_argument("--no-receipt", action="store_true", help="Skip emitting a chain-I receipt.")
    args = ap.parse_args()

    # Parse banks
    banks = [b.strip().lower() for b in args.banks.split(",") if b.strip()]
    if not banks:
        banks = list(BANKS_DEFAULT)

    # Parse pcrs: accepts "0-23" or "0,1,2,7"
    raw_pcrs = args.pcrs.strip()
    if "-" in raw_pcrs and "," not in raw_pcrs:
        lo, hi = raw_pcrs.split("-", 1)
        pcrs = list(range(int(lo.strip()), int(hi.strip()) + 1))
    else:
        pcrs = [int(x.strip()) for x in raw_pcrs.split(",") if x.strip()]
    if not pcrs:
        pcrs = list(PCRS_DEFAULT)

    ts = utc_ts()
    base = pathlib.Path(args.base)
    instance_root = base / args.instance
    boot_dir = instance_root / "boot"

    # Capture
    capture = capture_pcrs(banks, pcrs)

    snapshot: Dict[str, Any] = {
        "schema_id": "AEVUM:TPM_PCR_SNAPSHOT:V1",
        "captured_at": ts,
        "instance": args.instance,
        "base": str(base),
        "requested_banks": banks,
        "requested_pcrs": pcrs,
        "tpm_pcr_capture": capture,
    }

    # Write to disk
    out_path = write_pcr_snapshot(boot_dir, snapshot, ts)
    sha256_tagged = "sha256:" + sha256_file(out_path)

    if capture.get("error"):
        print(f"WARN: PCR capture partial/failed: {capture['error']}", file=sys.stderr)
    else:
        n_banks = len(capture.get("banks", {}))
        total_pcrs = sum(len(v) for v in capture.get("banks", {}).values())
        print(f"OK: captured {total_pcrs} PCR values across {n_banks} banks")

    print(f"OK: wrote {out_path} {sha256_tagged}")

    # Emit receipt
    if not args.no_receipt:
        emit_receipt_best_effort(out_path, sha256_tagged)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
