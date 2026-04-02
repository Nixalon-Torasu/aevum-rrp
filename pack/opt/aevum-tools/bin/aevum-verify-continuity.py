#!/usr/bin/env python3
"""Aevum continuity verifier (v0.2)

Non-gating continuity checks for TimeChain (T):

1) Cryptographic integrity via bundled verifier (Ed25519 envelope chain).
2) Presence of TPM anchor references in early time blocks (bounded window).
3) Optional: verify TPM signatures on timeblocks when present.

Exit codes:
0 PASS/SKIP
2 FAIL
"""

import argparse, json, pathlib, subprocess, sys, tempfile, os
from typing import Dict, Any, List, Optional, Tuple

def run(cmd: List[str]) -> Tuple[int, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def load_jsonl(path: pathlib.Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out

def resolve_receipts_root(base: pathlib.Path) -> pathlib.Path:
    seam = base / "accurate" / "receipts"
    legacy = base / "receipts"
    try:
        if seam.exists():
            return seam
    except PermissionError:
        pass
    return legacy

def resolve_payload_path(base: pathlib.Path, payload_ref: str) -> Optional[pathlib.Path]:
    if not payload_ref:
        return None
    if payload_ref.startswith("/"):
        p = pathlib.Path(payload_ref)
        return p if p.exists() else None
    cands = [
        base / payload_ref,
        base / "accurate" / payload_ref,
        base / "payloads" / pathlib.Path(payload_ref).name,
        base / "accurate" / "payloads" / pathlib.Path(payload_ref).name,
    ]
    for p in cands:
        if p.exists():
            return p
    return None

def load_payload(base: pathlib.Path, env: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # V2 envelopes store payload_ref; some tools may embed payload for convenience
    p = env.get("payload")
    if isinstance(p, dict) and p:
        return p
    pref = env.get("payload_ref") or ""
    pp = resolve_payload_path(base, pref)
    if not pp:
        return None
    try:
        raw = pp.read_bytes().strip()
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Instance base (workstation)")
    ap.add_argument("--timechain", default="", help="Path to timechain JSONL (auto-detect if empty)")
    ap.add_argument("--anchor-window", type=int, default=60, help="Blocks from start within which an anchor must appear")
    ap.add_argument("--check-tpm", action="store_true", help="Verify TPM signatures when present")
    args = ap.parse_args()

    base = pathlib.Path(args.base)

    if os.geteuid() != 0 and str(base).startswith('/var/lib/'):
        print('Run as root.', file=sys.stderr)
        return 2
    receipts_root = resolve_receipts_root(base)
    default_tc = receipts_root / "T.jsonl"
    tc_path = pathlib.Path(args.timechain) if args.timechain else default_tc

    if not tc_path.exists():
        print(f"SKIP: timechain log missing: {tc_path}")
        return 0

    # 1) Ed25519 verification
    verifier = pathlib.Path("/opt/aevum-tools/bin/aevum-verify")
    if verifier.exists():
        code, out = run([str(verifier), "--chain", "T", "--base", str(base)])
        if code != 0:
            print("FAIL: TimeChain Ed25519 verification failed")
            print(out)
            return 2
    else:
        print("WARN: /opt/aevum-tools/bin/aevum-verify missing; skipping Ed25519 check")

    blocks = load_jsonl(tc_path)
    if not blocks:
        print("SKIP: empty timechain")
        return 0

    # 2) Find first anchor reference within window
    anchors: List[Tuple[int, str, str, str, Any]] = []
    window = max(1, int(args.anchor_window))
    for i, b in enumerate(blocks[:window]):
        payload = load_payload(base, b) or {}
        aref = payload.get("tpm_anchor_ref") or payload.get("tpm_anchor_path") or ""
        asha = payload.get("tpm_anchor_sha256") or ""
        if aref or asha:
            anchors.append((i, aref, asha, b.get("event_hash", ""), b.get("tpm_signature")))

    if not anchors:
        print(f"FAIL: no TPM anchor reference found within first {window} blocks")
        return 2

    print(f"OK: anchor reference present at block #{anchors[0][0]}")

    # 3) Verify TPM signatures when present (optional)
    if args.check_tpm:
        pub = base / "tpm_sign" / "sign.pub.pem"
        if not pub.exists():
            print("FAIL: missing TPM signing public key: " + str(pub))
            return 2
        sigver = pathlib.Path("/opt/aevum-tools/bin/aevum-tpm-verify-sig.py")
        if not sigver.exists():
            print("FAIL: missing TPM signature verifier tool: " + str(sigver))
            return 2

        checked = 0
        for i, aref, asha, evh, tpmsig in anchors[:10]:
            if tpmsig:
                with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
                    tf.write(json.dumps(tpmsig))
                    tf.flush()
                    code, out = run([str(sigver), "--event-hash", evh, "--sig-json", "@" + tf.name, "--pub", str(pub)])
                if code != 0:
                    print(f"FAIL: TPM signature verification failed at block {i}")
                    print(out)
                    return 2
                checked += 1
        if checked == 0:
            print("WARN: no tpm_signature fields found to verify (check_tpm requested)")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
