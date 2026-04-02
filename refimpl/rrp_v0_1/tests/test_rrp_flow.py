from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aevum_rrp.common import (
    aeo_id_from_event,
    build_event,
    collect_pcr_snapshot,
    device_id_from_public_key,
    public_key_b64,
    sign_event,
)
from aevum_rrp.verifier import VerifyResult, verify_chain


def make_signed_chain_pair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    e1 = build_event(previous=None, device_id=device_id_from_public_key(pk), device_pubkey=public_key_b64(pk), event_type="SYSTEM", input_class="SYSTEM", payload={"message":"event-1"}, pcr_snapshot=collect_pcr_snapshot("mock"), timestamp=1)
    e1["signature"] = sign_event(sk, e1)
    e2 = build_event(previous=e1, device_id=device_id_from_public_key(pk), device_pubkey=public_key_b64(pk), event_type="USER_INPUT", input_class="USER_INPUT", payload={"message":"event-2"}, pcr_snapshot=collect_pcr_snapshot("mock"), timestamp=2)
    e2["signature"] = sign_event(sk, e2)
    return sk, pk, e1, e2


def test_verify_chain_empty_invalid() -> None:
    result, reason = verify_chain([])
    assert result == VerifyResult.INVALID
    assert reason == "empty_chain"


def test_verify_chain_valid() -> None:
    _, _, e1, e2 = make_signed_chain_pair()
    result, _ = verify_chain([e1, e2])
    assert result == VerifyResult.VALID


def test_verify_chain_event_hash_mismatch_invalid() -> None:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    e1 = build_event(previous=None, device_id=device_id_from_public_key(pk), device_pubkey=public_key_b64(pk), event_type="SYSTEM", input_class="SYSTEM", payload={"message":"event-1"}, pcr_snapshot=collect_pcr_snapshot("mock"), timestamp=1)
    e1["event_hash"] = "0" * 64
    e1["aeo_id"] = aeo_id_from_event(e1)
    e1["signature"] = sign_event(sk, e1)
    result, reason = verify_chain([e1])
    assert result == VerifyResult.INVALID
    assert reason == "crypto_invalid@0"


def test_verify_chain_gap_detected() -> None:
    sk, pk, e1, e2 = make_signed_chain_pair()
    e2["sequence"] = 3
    e2["aeo_id"] = aeo_id_from_event(e2)
    e2["signature"] = sign_event(sk, e2)
    result, reason = verify_chain([e1, e2])
    assert result == VerifyResult.GAP_DETECTED
    assert reason == "sequence_gap"


def test_verify_chain_fork_detected() -> None:
    sk, pk, e1, e2 = make_signed_chain_pair()
    e2_fork = build_event(previous=e1, device_id=device_id_from_public_key(pk), device_pubkey=public_key_b64(pk), event_type="APPLICATION", input_class="APPLICATION", payload={"message":"fork"}, pcr_snapshot=collect_pcr_snapshot("mock"), timestamp=3)
    e2_fork["sequence"] = 2
    e2_fork["aeo_id"] = aeo_id_from_event(e2_fork)
    e2_fork["signature"] = sign_event(sk, e2_fork)
    result, reason = verify_chain([e1, e2, e2_fork])
    assert result == VerifyResult.FORK_DETECTED
    assert reason == "fork_detected"


def test_verify_chain_device_id_mismatch_invalid() -> None:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    e1 = build_event(previous=None, device_id=device_id_from_public_key(pk), device_pubkey=public_key_b64(pk), event_type="SYSTEM", input_class="SYSTEM", payload={"message":"event-1"}, pcr_snapshot=collect_pcr_snapshot("mock"), timestamp=1)
    e1["device_id"] = "f" * 64
    e1["aeo_id"] = aeo_id_from_event(e1)
    e1["signature"] = sign_event(sk, e1)
    result, reason = verify_chain([e1])
    assert result == VerifyResult.INVALID
    assert reason == "crypto_invalid@0"
