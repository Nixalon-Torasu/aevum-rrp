#!/usr/bin/env python3
"""
aevum_receiptctl.py (v0.3)

Create an operator/system note receipt (Interaction chain I) in the Aevum envelope format.
Used as a compatibility target for older controlplane scripts that call /opt/aevum-tools/bin/aevum-receipt.

Inputs
- --kind: short label ("note", "warn", "info", ...)
- --message: human text
- key=value pairs (positional): added to kv map

Output
- Writes a receipt into chain I (Interaction) as a payload:
  { type: "OperatorNotePayload", kind, message, kv, ... }

Non-governing, best-effort
- If receipt writing fails, exit non-zero (so callers can show an error),
  but this tool is never used to gate runtime daemons.
"""

from __future__ import annotations
import argparse, json, pathlib, sys, time
import base64, os, subprocess, hashlib, shutil, tempfile
from typing import Dict, Any, List

from aevum_common import (
    resolve_storage_dirs,
    load_identity_private,
    load_chain_state,
    save_chain_state,
    write_payload,
    compute_event_hash_v2,
    sign_event_hash,
    b64e,
    utc_now_iso,
    append_line_best_effort,
)

ZERO32_HEX = "00" * 32
ZERO_HASH = "sha256:" + ZERO32_HEX

CHAIN_LABEL = "I"
CHAIN_ID_U8 = 4  # Interaction


def parse_kv(pairs: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"Bad kv '{p}' (expected key=value)")
        k, v = p.split("=", 1)
        k = k.strip()
        if not k:
            raise ValueError(f"Bad kv '{p}' (empty key)")
        out[k] = v
    return out



def _load_tpm_receipt_policy() -> Dict[str, Any]:
    p = pathlib.Path("/etc/aevum/registry/tpm_receipt_sign_policy.json")
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _policy_sha256() -> str:
    p = pathlib.Path("/etc/aevum/registry/tpm_receipt_sign_policy.json")
    try:
        if p.exists():
            return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    except Exception:
        pass
    return ""

def _rate_limit_ok(policy: Dict[str, Any]) -> bool:
    try:
        maxps = int(policy.get("max_per_second", 0) or 0)
    except Exception:
        maxps = 0
    if maxps <= 0:
        return True
    state_path = pathlib.Path(policy.get("rate_limit_state") or "/run/aevum/tpm/receipt_sign_rate.json")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    try:
        st = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    except Exception:
        st = {}
    sec = int(st.get("sec", now))
    count = int(st.get("count", 0))
    if sec != now:
        sec = now
        count = 0
    if count >= maxps:
        st2 = {"sec": sec, "count": count}
        try:
            state_path.write_text(json.dumps(st2, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
        except Exception:
            pass
        return False
    count += 1
    st2 = {"sec": sec, "count": count}
    try:
        state_path.write_text(json.dumps(st2, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass
    return True

def _should_tpm_sign(policy: Dict[str, Any], kind: str, kv: Dict[str, str]) -> bool:
    if not policy:
        return False
    if not bool(policy.get("enabled", False)):
        return False
    match = policy.get("match") or {}
    allow_kinds = match.get("allow_kinds") or []
    if allow_kinds and kind not in allow_kinds:
        return False
    kv_key = match.get("kv_key", "component")
    comp = kv.get(kv_key, "")
    allow = match.get("allow_components") or []
    if allow and comp not in allow:
        return False
    return _rate_limit_ok(policy)

def _try_tpm_sign_event_hash(event_hash: str, policy: Dict[str, Any]) -> Dict[str, Any] | None:
    # Best-effort: TPM signature over event_hash raw32 using persistent signing handle.
    try:
        if not (isinstance(event_hash, str) and event_hash.startswith("sha256:") and len(event_hash) == 71):
            return None
        handle_file = pathlib.Path(policy.get("tpm_sign", {}).get("handle_file", "/var/lib/aevum/workstation/tpm_sign/sign.handle"))
        pub_pem = pathlib.Path(policy.get("tpm_sign", {}).get("pubkey_pem", "/var/lib/aevum/workstation/tpm_sign/sign.pub.pem"))
        if not handle_file.exists():
            return None
        handle = handle_file.read_text(encoding="utf-8").strip()
        if not handle:
            return None
        if shutil.which("tpm2_sign") is None:
            return None
        raw32 = bytes.fromhex(event_hash.split(":", 1)[1])
        with tempfile.TemporaryDirectory(prefix="aevum_tpm_receipt_sign_") as td:
            d = pathlib.Path(td) / "digest.bin"
            s = pathlib.Path(td) / "sig.bin"
            d.write_bytes(raw32)
            args = ["tpm2_sign", "-c", handle] + (policy.get("tpm_sign", {}).get("tpm2_sign_args") or ["-g", "sha256"]) + ["-d", str(d), "-o", str(s)]
            subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if not s.exists():
                return None
            sig_b64 = base64.b64encode(s.read_bytes()).decode("ascii")
        pub_sha = ""
        if pub_pem.exists():
            pub_sha = "sha256:" + hashlib.sha256(pub_pem.read_bytes()).hexdigest()
        return {
            "alg": "TPM2_ECC_P256_SHA256",
            "handle": handle,
            "signed_over": "event_hash_raw32",
            "sig_b64": sig_b64,
            "sig_fmt": "plain",
            "hash_alg": "sha256",
            "tpm_sign_pubkey_sha256": pub_sha,
            "tpm_receipt_sign_policy_sha256": _policy_sha256(),
        }
    except Exception:
        return None


def current_time_block_id(dirs: Dict[str, pathlib.Path]) -> int:
    t_state = load_chain_state(dirs["state"] / "chain_T.json")
    tb = t_state.get("last_time_block_id")
    if isinstance(tb, int) and tb >= 0:
        return tb
    if isinstance(t_state.get("seq_no"), int) and t_state["seq_no"] > 0:
        return int(t_state["seq_no"])
    return 0


def _sha256_path(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def load_registry_binding(strict: bool = True) -> Dict[str, str]:
    """Return kv fields that bind a receipt to the sealed registry manifest.

    Strict mode:
      - manifest and Ed25519 signature MUST exist, else raise.
    Non-strict:
      - if missing, returns registry_binding_state=unsealed only.
    """
    reg = pathlib.Path("/etc/aevum/registry")
    manifest = reg / "REGISTRY_MANIFEST.json"
    sig_ed = reg / "REGISTRY_MANIFEST.sig.ed25519.b64"
    sig_tpm = reg / "REGISTRY_MANIFEST.sig.tpm_p256_plain.b64"

    if not manifest.exists() or not sig_ed.exists():
        if strict:
            missing = []
            if not manifest.exists(): missing.append(str(manifest))
            if not sig_ed.exists(): missing.append(str(sig_ed))
            raise RuntimeError("registry not sealed (missing: " + ", ".join(missing) + ")")
        return {"registry_binding_state": "unsealed"}

    kv: Dict[str, str] = {
        "registry_binding_state": "sealed",
        "registry_manifest_sha256": _sha256_path(manifest),
        "registry_manifest_sig_ed25519_sha256": _sha256_path(sig_ed),
    }
    if sig_tpm.exists():
        kv["registry_manifest_sig_tpm_sha256"] = _sha256_path(sig_tpm)
    return kv





def main() -> int:
    ap = argparse.ArgumentParser(description="Create an operator note receipt (chain I).")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Instance base.")
    ap.add_argument("--kind", required=True)
    ap.add_argument("--message", required=True)
    ap.add_argument("--source", default="operator", help="Source label (operator/system/service).")
    ap.add_argument("--allow-unsealed", action="store_true", help="Allow minting notes when registry is not sealed (default: strict).")
    ap.add_argument("kv", nargs="*", help="key=value pairs")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    dirs = resolve_storage_dirs(base)

    ident = load_identity_private(base / "identity" / "identity.json")
    sk = ident["sk"]
    kid = ident["kid"]
    subject_id_hex = ident["subject_id_hex"]
    capture_dev_hex = ident["capture_device_hex"]

    chain_state_path = dirs["state"] / "chain_I.json"
    state = load_chain_state(chain_state_path)
    seq_no = int(state.get("seq_no", 0))
    prev_event_hash = state.get("prev_event_hash", ZERO_HASH)

    kv = parse_kv(list(args.kv))

    strict_registry = not (args.allow_unsealed or os.environ.get('AEVUM_ALLOW_UNSEALED') == '1')
    try:
        kv.update(load_registry_binding(strict=strict_registry))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    payload: Dict[str, Any] = {
        "type": "OperatorNotePayload",
        "schema_version": "ONPv1",
        "wallclock_unix": int(time.time()),
        "monotime_ns": int(time.monotonic_ns()),
        "kind": args.kind,
        "message": args.message,
        "source": args.source,
        "kv": kv,
    }

    payload_hash, payload_ref = write_payload(dirs["payloads"], payload)
    seq_no += 1
    tbid = current_time_block_id(dirs)

    event_hash = compute_event_hash_v2(
        chain_id_u8=CHAIN_ID_U8,
        subject_id_hex=subject_id_hex,
        seq_no=seq_no,
        time_block_id=tbid,
        local_monotime_ns=int(payload["monotime_ns"]),
        capture_device_hex=capture_dev_hex,
        prev_event_hash=prev_event_hash,
        payload_hash=payload_hash,
    )
    sig_raw = sign_event_hash(sk, event_hash)

    tpm_policy = _load_tpm_receipt_policy()
    tpm_sig = None
    if _should_tpm_sign(tpm_policy, args.kind, kv):
        tpm_sig = _try_tpm_sign_event_hash(event_hash, tpm_policy)

    envelope = {
        "schema": "AEVUM:EVENT_ENVELOPE:V2",
        "chain_id_u8": CHAIN_ID_U8,
        "chain_label": CHAIN_LABEL,
        "subject_id_hex": subject_id_hex,
        "seq_no": seq_no,
        "time_block_id": tbid,
        "local_monotime_ns": int(payload["monotime_ns"]),
        "capture_device_hex": capture_dev_hex,
        "prev_event_hash": prev_event_hash,
        "payload_hash": payload_hash,
        "payload_ref": payload_ref,
        "event_hash": event_hash,
        "signature": {
            "alg": "Ed25519",
            "kid": kid,
            "sig_b64": b64e(sig_raw),
            "signed_at": utc_now_iso(),
            "canonicalization": "WIRE_EVENT_HASH_CANON_V1",
        },
        "tpm_signature": tpm_sig,
    }

    line = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    append_line_best_effort(dirs["receipts"] / "I.jsonl", line, mode=0o600)

    state.update({"seq_no": seq_no, "prev_event_hash": event_hash})
    save_chain_state(chain_state_path, state)

    print(json.dumps({"ok": True, "event_hash": event_hash, "payload_ref": payload_ref}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
