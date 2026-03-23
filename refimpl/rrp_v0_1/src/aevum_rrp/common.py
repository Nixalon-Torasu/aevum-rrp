from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = "AEO-RRP-v0.1.1"
EVENT_TYPES = {"HEARTBEAT", "SYSTEM", "USER_INPUT", "APPLICATION", "EXTERNAL", "KEY_ROTATION"}
INPUT_CLASSES = {"SYSTEM", "USER_INPUT", "APPLICATION", "EXTERNAL"}
PCR_SELECTION = "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
REQUIRED_FIELDS = {
    "aeo_id",
    "prev_aeo_id",
    "sequence",
    "timestamp",
    "pcr_snapshot",
    "device_id",
    "device_pubkey",
    "event_type",
    "input_class",
    "event_hash",
    "payload",
    "signature",
    "schema_version",
}


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_b64(pub: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key_bytes(pub)).decode("ascii")


def public_key_from_b64(data: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(data))


def device_id_from_public_key(pub: Ed25519PublicKey) -> str:
    return sha256_hex(public_key_bytes(pub))


def payload_hash(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def canonical_event_bytes(event: Dict[str, Any]) -> bytes:
    event_wo_sig = {k: v for k, v in event.items() if k != "signature"}
    return canonical_json(event_wo_sig)


def aeo_id_from_event(event: Dict[str, Any]) -> str:
    event_wo_id_sig = {k: v for k, v in event.items() if k not in {"aeo_id", "signature"}}
    return sha256_hex(canonical_json(event_wo_id_sig))


def sign_event(sk: Ed25519PrivateKey, event: Dict[str, Any]) -> str:
    return base64.b64encode(sk.sign(canonical_event_bytes(event))).decode("ascii")


def verify_event_signature(event: Dict[str, Any]) -> bool:
    try:
        pub = public_key_from_b64(event["device_pubkey"])
        sig = base64.b64decode(event["signature"], validate=True)
        pub.verify(sig, canonical_event_bytes(event))
        return True
    except Exception:
        return False


def ensure_dirs(state_dir: Path) -> Tuple[Path, Path, Path]:
    chain_dir = state_dir / "chain"
    identity_dir = state_dir / "identity"
    broken_dir = state_dir / "broken"
    for d in (chain_dir, identity_dir, broken_dir):
        d.mkdir(parents=True, exist_ok=True)
    return chain_dir, identity_dir, broken_dir


def read_last_aeo(chain_path: Path) -> Dict[str, Any] | None:
    if not chain_path.exists() or chain_path.stat().st_size == 0:
        return None
    last = chain_path.read_text(encoding="utf-8").strip().splitlines()[-1]
    return json.loads(last)


def load_chain(path: Path) -> list[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")


def collect_pcr_snapshot(provider: str = "mock") -> Dict[str, Any]:
    if provider == "mock":
        raw = {str(i): hashlib.sha256(f"mock-pcr-{i}".encode()).hexdigest() for i in range(16)}
        composite = sha256_hex(canonical_json(raw))
        return {
            "provider": "mock",
            "selection": PCR_SELECTION,
            "composite_hash": composite,
            "raw": raw,
        }
    if provider == "tpm2_pcrread":
        proc = subprocess.run(
            ["tpm2_pcrread", PCR_SELECTION],
            capture_output=True,
            text=True,
            check=True,
        )
        raw: Dict[str, str] = {}
        for line in proc.stdout.splitlines():
            parts = line.strip().split(":", 1)
            if len(parts) != 2:
                continue
            idx = parts[0].strip()
            if idx.isdigit():
                raw[idx] = parts[1].strip().replace(" ", "")
        composite = sha256_hex(canonical_json(raw))
        return {
            "provider": "tpm2_pcrread",
            "selection": PCR_SELECTION,
            "composite_hash": composite,
            "raw": raw,
        }
    raise ValueError(f"Unsupported PCR provider: {provider}")


def build_event(
    *,
    previous: Dict[str, Any] | None,
    device_id: str,
    device_pubkey: str,
    event_type: str,
    input_class: str,
    payload: Dict[str, Any],
    pcr_snapshot: Dict[str, Any],
    timestamp: int | None = None,
) -> Dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unsupported event_type: {event_type}")
    if input_class not in INPUT_CLASSES:
        raise ValueError(f"Unsupported input_class: {input_class}")
    if timestamp is None:
        timestamp = time.time_ns()
    sequence = 1 if previous is None else int(previous["sequence"]) + 1
    prev_aeo_id = None if previous is None else previous["aeo_id"]
    event = {
        "schema_version": SCHEMA_VERSION,
        "prev_aeo_id": prev_aeo_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "pcr_snapshot": pcr_snapshot,
        "device_id": device_id,
        "device_pubkey": device_pubkey,
        "event_type": event_type,
        "input_class": input_class,
        "event_hash": payload_hash(payload),
        "payload": payload,
        "signature": "",
    }
    event["aeo_id"] = aeo_id_from_event(event)
    return event
