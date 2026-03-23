from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .common import (
    EVENT_TYPES,
    INPUT_CLASSES,
    REQUIRED_FIELDS,
    SCHEMA_VERSION,
    aeo_id_from_event,
    load_chain,
    payload_hash,
    verify_event_signature,
)


class VerifyResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    GAP_DETECTED = "GAP_DETECTED"
    FORK_DETECTED = "FORK_DETECTED"


EXIT_CODES = {
    VerifyResult.VALID: 0,
    VerifyResult.INVALID: 1,
    VerifyResult.GAP_DETECTED: 2,
    VerifyResult.FORK_DETECTED: 3,
}


def load_chain_safe(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Chain not found: {path}")
    return load_chain(path)


def is_hex_string(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        int(value, 16)
        return True
    except Exception:
        return False


def is_base64_string(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        base64.b64decode(value.encode("utf-8"), validate=True)
        return True
    except Exception:
        return False


def check_structure(event: Dict[str, Any]) -> bool:
    if not REQUIRED_FIELDS.issubset(event.keys()):
        return False
    if event.get("schema_version") != SCHEMA_VERSION:
        return False
    if event.get("event_type") not in EVENT_TYPES:
        return False
    if event.get("input_class") not in INPUT_CLASSES:
        return False
    if not is_hex_string(event.get("aeo_id")):
        return False
    if event.get("prev_aeo_id") is not None and not is_hex_string(event.get("prev_aeo_id")):
        return False
    if not is_hex_string(event.get("device_id")):
        return False
    if not is_hex_string(event.get("event_hash")):
        return False
    if not isinstance(event.get("pcr_snapshot"), dict):
        return False
    if not is_base64_string(event.get("device_pubkey")):
        return False
    if not is_base64_string(event.get("signature")):
        return False
    if not isinstance(event.get("payload"), dict):
        return False
    try:
        int(event["sequence"])
        int(event["timestamp"])
    except Exception:
        return False
    return True


def check_device_identity(event: Dict[str, Any]) -> bool:
    try:
        pubkey = base64.b64decode(event["device_pubkey"], validate=True)
        expected = hashlib.sha256(pubkey).hexdigest()
        return event["device_id"] == expected
    except Exception:
        return False


def check_event_cryptographic_integrity(event: Dict[str, Any]) -> bool:
    return (
        aeo_id_from_event(event) == event.get("aeo_id")
        and event.get("event_hash") == payload_hash(event.get("payload"))
        and check_device_identity(event)
        and verify_event_signature(event)
    )


def has_gap(events: List[Dict[str, Any]]) -> bool:
    expected = None
    for event in events:
        seq = int(event["sequence"])
        if expected is None:
            expected = seq
        if seq != expected:
            return True
        expected += 1
    return False


def has_fork(events: List[Dict[str, Any]]) -> bool:
    children_by_prev: Dict[str, str] = {}
    for event in events:
        prev_id = event.get("prev_aeo_id")
        if prev_id is None:
            continue
        existing = children_by_prev.get(prev_id)
        if existing is None:
            children_by_prev[prev_id] = event["aeo_id"]
        elif existing != event["aeo_id"]:
            return True
    return False


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[VerifyResult, str]:
    if not events:
        return VerifyResult.INVALID, "empty_chain"

    for index, event in enumerate(events):
        if not check_structure(event):
            return VerifyResult.INVALID, f"structure_invalid@{index}"
        if not check_event_cryptographic_integrity(event):
            return VerifyResult.INVALID, f"crypto_invalid@{index}"

    if has_fork(events):
        return VerifyResult.FORK_DETECTED, "fork_detected"

    if has_gap(events):
        return VerifyResult.GAP_DETECTED, "sequence_gap"

    for index, event in enumerate(events):
        if index == 0:
            if event.get("prev_aeo_id") is not None:
                return VerifyResult.INVALID, "genesis_prev_not_null"
            continue
        if event.get("prev_aeo_id") != events[index - 1].get("aeo_id"):
            return VerifyResult.INVALID, f"link_invalid@{index}"

    return VerifyResult.VALID, "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description="Aevum RRP strict verifier")
    ap.add_argument("--chain", required=True, help="Path to chain jsonl")
    ap.add_argument("--verbose", action="store_true", help="Print failure reason")
    args = ap.parse_args()

    try:
        events = load_chain_safe(Path(args.chain))
        result, reason = verify_chain(events)
    except Exception as exc:
        result, reason = VerifyResult.INVALID, f"exception:{type(exc).__name__}"

    print(result.value)
    if args.verbose:
        print(f"reason={reason}")
    return EXIT_CODES[result]


if __name__ == "__main__":
    raise SystemExit(main())
