#!/usr/bin/env python3
"""
aevum_verify.py (v0.1)

Year-1 verifier for Aevum receipt logs (JSONL).
Validates:
- JSON parse
- required fields
- seq_no monotonic increments
- prev_event_hash hash-chain integrity
- event_hash recomputation (canonical JSON hashing of unsigned envelope fields)
- Ed25519 signature verification over raw event_hash bytes (32 bytes)

Optional:
- payload hash verification (if payload file is present) --check-payloads

Design alignment:
- EventEnvelope core fields: chain_id, subject_id, seq_no, time_block_id, local_monotime, capture_device, prev_event_hash, payload_hash, event_hash, signature
  (See Aevum Spec 1: EventEnvelope and integrity rules.)
- Payload retention is optional; missing payload is OK unless explicitly requested to check.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import struct
import json
import pathlib
import sys
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except Exception as e:
    print("ERROR: Missing dependency 'cryptography'. Install with: python3 -m pip install cryptography", file=sys.stderr)
    raise



ZERO_HASH = "sha256:" + ("00" * 32)


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")



def check_boot_unlock_dir(evidence_dir: str, policy_path: str, strict: bool) -> tuple[bool, str]:
    import pathlib, json
    ed = pathlib.Path(evidence_dir)
    if not ed.exists():
        return (False, f"boot-unlock: missing dir {evidence_dir}") if strict else (True, "boot-unlock: missing dir (skip)")
    files = sorted(ed.glob("boot_unlock_evidence_*.json"))
    if not files:
        return (False, "boot-unlock: no evidence files found") if strict else (True, "boot-unlock: no evidence files (skip)")
    # Load policy
    pp = pathlib.Path(policy_path)
    if not pp.exists():
        return (False, "boot-unlock: missing luks_policy.json") if strict else (True, "boot-unlock: missing policy (skip)")
    pol = json.loads(pp.read_text(encoding="utf-8"))
    if str(pol.get("unlock_mode","tpm2_prefer")).lower() != "tpm2_only":
        return True, "boot-unlock: unlock_mode != tpm2_only (skip)"

    fails = []
    for fp in files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as e:
            fails.append(f"{fp.name}: unreadable json: {e}")
            continue
        for v in data.get("volumes", []) or []:
            name = str(v.get("name",""))
            unlocked = bool(v.get("unlocked", False))
            method = (v.get("method_claim") or v.get("method_inferred") or v.get("method") or v.get("unlock_method") or "unknown")
            method = str(method)
            if not unlocked:
                fails.append(f"{fp.name}:{name}: not unlocked")
            elif method != "tpm2_proof":
                fails.append(f"{fp.name}:{name}: method={method}")
    if fails:
        return False, "boot-unlock invariant FAIL:\n  - " + "\n  - ".join(fails)
    return True, "boot-unlock invariant PASS (tpm2_only)"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



def verify_tpm_signature_plain(event_hash: str, tpm_sig: dict, pub_pem_path: pathlib.Path) -> bool:
    try:
        if not (isinstance(event_hash, str) and event_hash.startswith("sha256:") and len(event_hash) == 71):
            return False
        if not isinstance(tpm_sig, dict):
            return False
        if tpm_sig.get("sig_fmt") != "plain":
            return False
        if tpm_sig.get("hash_alg") != "sha256":
            return False
        sig_b64 = tpm_sig.get("sig_b64", "")
        if not isinstance(sig_b64, str) or not sig_b64:
            return False
        sig_plain = base64.b64decode(sig_b64)
        if len(sig_plain) != 64:
            return False
        r = int.from_bytes(sig_plain[:32], "big")
        s = int.from_bytes(sig_plain[32:], "big")
        der = encode_dss_signature(r, s)
        digest32 = bytes.fromhex(event_hash.split(":", 1)[1])
        pub = load_pem_public_key(pub_pem_path.read_bytes())
        pub.verify(der, digest32, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False

def compute_event_hash(envelope: Dict[str, Any]) -> str:
    """V1: sha256(canonical_json(unsigned_envelope))"""
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    unsigned.pop("event_hash", None)
    return "sha256:" + sha256_hex(canonical_json_bytes(unsigned))


def _u8(x: int) -> bytes:
    return struct.pack(">B", x & 0xFF)

def _u64(x: int) -> bytes:
    return struct.pack(">Q", x & 0xFFFFFFFFFFFFFFFF)

def _i64(x: int) -> bytes:
    return struct.pack(">q", int(x))

def _b16_from_hex(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != 16:
        raise ValueError("capture_device_hex must be 16 bytes (32 hex)")
    return b

def _b32_from_hex(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError("subject_id_hex must be 32 bytes (64 hex)")
    return b

def _sha256_bytes_from_tagged(tagged: str) -> bytes:
    if not tagged.startswith("sha256:"):
        raise ValueError("hash must be sha256:<hex>")
    return bytes.fromhex(tagged.split(":", 1)[1])


def segment_files(base: pathlib.Path, chain: str) -> List[pathlib.Path]:
    seg_root = base / "accurate" / "segments" / chain
    mans = sorted(seg_root.glob("manifest_*.json"))
    out: List[pathlib.Path] = []
    for m in mans:
        try:
            obj = json.loads(m.read_text(encoding="utf-8"))
            rel = obj.get("segment_file") or ""
            if rel:
                p = base / rel
                if p.exists():
                    out.append(p)
        except Exception:
            continue
    return out

def chain_log_files(base: pathlib.Path, receipts_dir: pathlib.Path, chain: str) -> List[pathlib.Path]:
    files = []
    files.extend(segment_files(base, chain))
    active = receipts_dir / f"{chain}.jsonl"
    if active.exists():
        files.append(active)
    return files

def compute_event_hash_v2_from_record(ev: Dict[str, Any]) -> str:
    cid = int(ev["chain_id_u8"])
    msg = b"".join([
        _u8(cid),
        _b32_from_hex(ev["subject_id_hex"]),
        _u64(int(ev["seq_no"])),
        _u64(int(ev["time_block_id"])),
        _i64(int(ev["local_monotime_ns"])),
        _b16_from_hex(ev["capture_device_hex"]),
        _sha256_bytes_from_tagged(ev["prev_event_hash"]),
        _sha256_bytes_from_tagged(ev["payload_hash"]),
    ])
    return "sha256:" + sha256_hex(msg)


def parse_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def kid_from_pub(pub_raw: bytes) -> str:
    return "ed25519:sha256:" + sha256_hex(pub_raw)[:16]


def load_pubkey_from_identity(identity_path: pathlib.Path) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Accepts either identity.json (full) or identity.public.json (shareable).
    Returns (pub_raw, kid)
    """
    try:
        ident = json.loads(identity_path.read_text(encoding="utf-8"))
    except Exception:
        return None, None

    # full identity.json
    pub_b64 = (ident.get("keys", {}) or {}).get("device_signing_key", {}).get("public_key_b64")
    kid = (ident.get("keys", {}) or {}).get("device_signing_key", {}).get("kid")

    # public view
    if not pub_b64:
        pub_b64 = (ident.get("key", {}) or {}).get("public_key_b64")
    if not kid:
        kid = (ident.get("key", {}) or {}).get("kid")

    if not pub_b64:
        return None, kid

    try:
        pub_raw = base64.b64decode(pub_b64.encode("ascii"))
        return pub_raw, kid
    except Exception:
        return None, kid


def verify_sig(pub_raw: bytes, sig_b64: str, event_hash_tagged: str) -> bool:
    if not event_hash_tagged.startswith("sha256:"):
        return False
    h = bytes.fromhex(event_hash_tagged.split(":", 1)[1])
    sig_raw = parse_b64(sig_b64)
    Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, h)
    return True



def resolve_payload_path(base: pathlib.Path, payload_ref: str) -> Optional[pathlib.Path]:
    if not payload_ref:
        return None
    try:
        # payload_ref is typically "payloads/<sha>.json"
        pref = payload_ref
        # absolute path is allowed (rare)
        if pref.startswith("/"):
            p = pathlib.Path(pref)
            return p if p.exists() else None
        cands = [
            base / pref,
            base / "accurate" / pref,
        ]
        # extra fallbacks in case payload_ref is "payloads/<file>" but stored elsewhere
        bname = pathlib.Path(pref).name
        cands.extend([
            base / "payloads" / bname,
            base / "accurate" / "payloads" / bname,
        ])
        for p in cands:
            if p.exists():
                return p
    except Exception:
        return None
    return None


def read_payload_json(base: pathlib.Path, payload_ref: str) -> Optional[Dict[str, Any]]:
    try:
        p = resolve_payload_path(base, payload_ref)
        if not p:
            return None
        raw = p.read_bytes().strip()
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def gap_kind(payload: Dict[str, Any]) -> Optional[str]:
    flags = payload.get("flags") or []
    if "GAP_PLACEHOLDER" in flags:
        return "PLACEHOLDER"
    if payload.get("type") == "TimeGapSummaryPayload" or "GAP_COALESCED" in flags:
        return "COALESCED"
    return None


def payload_ok(base: pathlib.Path, payload_ref: str, payload_hash: str) -> Tuple[bool, str]:
    """
    Verify payload hash if payload exists.
    """
    p = resolve_payload_path(base, payload_ref)
    if not p:
        return False, f"missing payload file: {payload_ref}"
    raw = p.read_bytes().strip()
    h = "sha256:" + sha256_hex(raw)
    if h != payload_hash:
        return False, f"payload_hash mismatch: expected {payload_hash}, got {h}"
    return True, "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify Aevum receipt logs (Year-1).")
    ap.add_argument("--base", default="/var/lib/aevum", help="Base directory (default /var/lib/aevum)")
    ap.add_argument("--identity", default="", help="Path to identity.json or identity.public.json for signature verification.")
    ap.add_argument("--log", default="", help="Path to a JSONL log file (e.g., /var/lib/aevum/receipts/T.jsonl).")
    ap.add_argument("--chain", default="", help="Convenience: choose chain log under base/receipts (P,R,PHI,I,T).")
    ap.add_argument("--strict", action="store_true", help="Fail on any policy/invariant violation (e.g., tpm2_only unlock invariant).")
    ap.add_argument("--check-boot-unlock", action="store_true", help="Verify boot unlock evidence files against policy (proof-grade).")
    ap.add_argument("--boot-unlock-dir", default="/var/lib/aevum/workstation/boot/unlock", help="Directory containing boot_unlock_evidence_*.json")
    ap.add_argument("--luks-policy", default="/etc/aevum/registry/luks_policy.json", help="LUKS policy path")
    ap.add_argument("--check-payloads", action="store_true", help="Also verify payload bytes hash if payload files exist.")
    ap.add_argument("--check-tpm", action="store_true", help="If tpm_signature is present, verify it using base/tpm_sign/sign.pub.pem.")
    ap.add_argument("--warn-gaps", action="store_true", help="Scan payloads (if present) for TimeChain gap markers and print a short report.")
    ap.add_argument("--gap-report-max", type=int, default=10, help="Max number of individual gap samples to print (default 10).")
    args = ap.parse_args()

    base = pathlib.Path(args.base)

    if not args.log:
        if not args.chain:
            print("ERROR: Provide --log or --chain.", file=sys.stderr)
            return 2
        legacy = base / "receipts"
        seam = base / "accurate" / "receipts"
        root = seam if seam.exists() else legacy
        log_path = root / f"{args.chain}.jsonl"
    else:
        log_path = pathlib.Path(args.log)

    if not log_path.exists():
        print(f"ERROR: log not found: {log_path}", file=sys.stderr)
        return 3

    pub_raw = None
    expected_kid = None
    if args.identity:
        pub_raw, expected_kid = load_pubkey_from_identity(pathlib.Path(args.identity))
        if not pub_raw:
            print("WARN: identity provided but public key not found/parseable; signature checks will be SKIPPED.", file=sys.stderr)

    last_event_hash = None
    last_seq = 0
    failures = 0
    checked = 0
    sig_checked = 0
    payload_checked = 0
    gap_placeholders = 0
    gap_coalesced = 0
    gap_samples = []
    receipts_dir = log_path.parent
    if args.log:
        log_files = [log_path]
    else:
        log_files = chain_log_files(base, receipts_dir, args.chain)
    if not log_files:
        print(f"ERROR: log not found: {log_path}", file=sys.stderr)
        return 3

    for i, line in enumerate(iter_lines_from_files(log_files), start=1):
        line = line.strip()
        if not line:
            continue
        checked += 1
        try:
            ev = json.loads(line)
        except Exception as e:
            print(f"FAIL line {i}: invalid JSON: {e}")
            failures += 1
            break

        # Minimal required fields (keep strict and boring)
        # Required fields (V1 vs V2)
        if ev.get("schema") == "AEVUM:EVENT_ENVELOPE:V2":
            req = ["schema","chain_id_u8","subject_id_hex","seq_no","time_block_id","local_monotime_ns",
                   "capture_device_hex","prev_event_hash","payload_hash","payload_ref","event_hash","signature"]
        else:
            req = ["schema","chain_id","subject_id_hex","seq_no","time_block_id","local_monotime_ns",
                   "capture_device_hex","prev_event_hash","payload_hash","payload_ref","event_hash","signature"]
        missing = [k for k in req if k not in ev]
        if missing:
            print(f"FAIL line {i}: missing fields: {missing}")
            failures += 1
            break

        # seq checks
        seq = int(ev["seq_no"])
        if seq != last_seq + 1:
            print(f"FAIL line {i}: seq_no jump: expected {last_seq+1}, got {seq}")
            failures += 1
            break
        last_seq = seq

        # prev hash checks
        prev = ev["prev_event_hash"]
        if seq == 1:
            if prev != ZERO_HASH:
                print(f"FAIL line {i}: first record prev_event_hash must be {ZERO_HASH}")
                failures += 1
                break
        else:
            if last_event_hash and prev != last_event_hash:
                print(f"FAIL line {i}: prev_event_hash mismatch: expected {last_event_hash}, got {prev}")
                failures += 1
                break

        # event hash recompute
        schema = ev.get("schema", "")
        if schema == "AEVUM:EVENT_ENVELOPE:V2":
            expected_hash = compute_event_hash_v2_from_record(ev)
        else:
            expected_hash = compute_event_hash(ev)
        if ev["event_hash"] != expected_hash:
            print(f"FAIL line {i}: event_hash mismatch: expected {expected_hash}, got {ev['event_hash']}")
            failures += 1
            break

        # signature
        if pub_raw:
            try:
                sig = ev.get("signature", {})
                sig_b64 = sig.get("sig_b64")
                if not sig_b64:
                    raise ValueError("missing signature.sig_b64")
                # optional kid sanity
                kid = sig.get("kid")
                if expected_kid and kid and expected_kid != kid:
                    # not fatal in v0.1 (kid registries can evolve), but warn loudly
                    print(f"WARN line {i}: signature.kid mismatch vs identity kid: {kid} != {expected_kid}", file=sys.stderr)
                verify_sig(pub_raw, sig_b64, ev["event_hash"])
                # Optional TPM signature verification (hard-fail if present and invalid)
                if args.check_tpm:
                    tpm_sig = ev.get("tpm_signature", None)
                    if tpm_sig is not None:
                        pub_pem = base / "tpm_sign" / "sign.pub.pem"
                        if not pub_pem.exists():
                            raise RuntimeError(f"missing TPM signing public key: {pub_pem}")
                        if not verify_tpm_signature_plain(ev.get("event_hash",""), tpm_sig, pub_pem):
                            raise RuntimeError("TPM signature invalid")

                sig_checked += 1
            except Exception as e:
                print(f"FAIL line {i}: signature verify failed: {e}")
                failures += 1
                break

        # payload verification (optional)
        if args.check_payloads:
            ok, msg = payload_ok(base, ev["payload_ref"], ev["payload_hash"])
            if not ok:
                print(f"FAIL line {i}: payload check failed: {msg}")
                failures += 1
                break
            payload_checked += 1

        # gap scanning (optional; does not require payload hash checks)
        if args.warn_gaps:
            payload = read_payload_json(base, ev.get("payload_ref", ""))
            if payload:
                gk = gap_kind(payload)
                if gk == "PLACEHOLDER":
                    gap_placeholders += 1
                    if len(gap_samples) < args.gap_report_max:
                        gap_samples.append({"line": i, "time_block_id": payload.get("time_block_id"), "kind": gk})
                elif gk == "COALESCED":
                    gap_coalesced += 1
                    if len(gap_samples) < args.gap_report_max:
                        gap_samples.append({"line": i, "gap_start": payload.get("gap_start_time_block_id"), "gap_end": payload.get("gap_end_time_block_id"), "count": payload.get("gap_count"), "kind": gk})

        last_event_hash = ev["event_hash"]

    if failures == 0:
        print("PASS")
        print(f"  log: {log_path}")
        print(f"  records: {checked}")
        print(f"  signature_checked: {sig_checked}" + (" (SKIPPED)" if not pub_raw else ""))
        print(f"  payload_checked: {payload_checked}" + (" (disabled)" if not args.check_payloads else ""))
        if args.warn_gaps:
            print("  gap_report:")
            print(f"    placeholders: {gap_placeholders}")
            print(f"    coalesced: {gap_coalesced}")
            if gap_samples:
                for s in gap_samples:
                    print(f"    sample: {s}")
            else:
                print("    sample: none (payloads missing or no gaps)")
        return 0

    print("FAIL")
    print(f"  log: {log_path}")
    return 1



def iter_lines_from_files(files: List[pathlib.Path]):
    for fp in files:
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                yield line

if __name__ == "__main__":
    raise SystemExit(main())


