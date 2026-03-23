#!/usr/bin/env python3
"""
Common helpers for Aevum Year-1 receipt printing.

Design goals:
- Deterministic canonical JSON hashing/signing
- Append-only, hash-chained event envelopes
- Payloads stored separately (prunable) with payload_hash commitments

This is intentionally minimal.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import tempfile
import struct
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import datetime as dt


ZERO32_HEX = "00" * 32
ZERO16_HEX = "00" * 16


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_tagged(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def kid_from_pub(pub_raw: bytes) -> str:
    return "ed25519:sha256:" + sha256_hex(pub_raw)[:16]


def atomic_write_bytes(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        # fsync directory entry
        dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def atomic_write_text(path: pathlib.Path, text: str, mode: int = 0o600) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def append_line(path: pathlib.Path, line: str, mode: int = 0o600) -> None:
    # Append-only best effort. For stronger durability, fsync after each line.
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.exists()
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())
    if not existed:
        os.chmod(path, mode)


def load_identity(identity_path: pathlib.Path) -> Dict[str, Any]:
    return json.loads(identity_path.read_text(encoding="utf-8"))


def load_device_private_key(pem_path: pathlib.Path) -> Ed25519PrivateKey:
    sk = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Private key is not Ed25519")
    return sk



def load_ed25519_private(private_key_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from base64-encoded raw 32-byte seed."""
    raw = base64.b64decode(private_key_b64.encode("ascii"))
    if len(raw) != 32:
        raise ValueError(f"ed25519 private key must be 32 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def derive_subject_id_hex(pub_raw: bytes) -> str:
    # Aevum Spec: subject_id = H(PK_s) (bytes32). We'll use sha256(PK_raw).
    return sha256_hex(pub_raw)


def capture_device_hex(machine_id: str, pub_raw: bytes) -> str:
    # bytes16 best-effort stable: first 16 bytes of sha256(machine_id || pub_raw)
    m = (machine_id or "").encode("utf-8", "ignore") + b"|" + pub_raw
    return sha256_hex(m)[:32]  # 16 bytes = 32 hex chars


def ensure_dirs(base: pathlib.Path) -> Dict[str, pathlib.Path]:
    d = {
        "base": base,
        "identity": base / "identity",
        "receipts": base / "receipts",
        "payloads": base / "payloads",
        "state": base / "state",
    }
    for p in d.values():
        p.mkdir(parents=True, exist_ok=True)
        os.chmod(p, 0o700)
    return d


def resolve_storage_dirs(base: pathlib.Path) -> Dict[str, pathlib.Path]:
    """
    Seam-aware directory resolver.

    Preference order:
      1) If base/accurate/receipts exists -> use Seam layout (accurate/*)
      2) Else use legacy base/{receipts,payloads,state}

    Returns a dict matching ensure_dirs keys: base, identity, receipts, payloads, state.
    """
    seam_receipts = base / "accurate" / "receipts"
    seam_payloads = base / "accurate" / "payloads"
    seam_state = base / "accurate" / "state"
    if seam_receipts.exists():
        d = {
            "base": base,
            "identity": base / "identity",
            "receipts": seam_receipts,
            "payloads": seam_payloads,
            "state": seam_state,
        }
        for p in d.values():
            p.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(p, 0o700)
            except Exception:
                pass
        return d
    # legacy
    return ensure_dirs(base)


def load_chain_state(state_path: pathlib.Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {"seq_no": 0, "prev_event_hash": "sha256:" + "00"*32, "last_time_block_id": -1, "last_wallclock_unix": None, "last_monotime_ns": None}
    return json.loads(state_path.read_text(encoding="utf-8"))


def save_chain_state(state_path: pathlib.Path, state: Dict[str, Any]) -> None:
    atomic_write_text(state_path, json.dumps(state, sort_keys=True, indent=2) + "\n", mode=0o600)


def write_payload(payload_dir: pathlib.Path, payload_obj: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns (payload_hash, payload_relpath).
    payload file name is sha256 of canonical bytes.
    """
    payload_bytes = canonical_json_bytes(payload_obj)
    h = sha256_hex(payload_bytes)
    fname = f"{h}.json"
    path = payload_dir / fname
    if not path.exists():
        atomic_write_bytes(path, payload_bytes + b"\n", mode=0o600)
    return "sha256:" + h, f"payloads/{fname}"


def compute_event_hash(envelope_unsigned: Dict[str, Any]) -> str:
    """V1: sha256(canonical_json(unsigned_envelope))"""
    return sha256_tagged(canonical_json_bytes(envelope_unsigned))


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

def compute_event_hash_v2(
    *,
    chain_id_u8: int,
    subject_id_hex: str,
    seq_no: int,
    time_block_id: int,
    local_monotime_ns: int,
    capture_device_hex: str,
    prev_event_hash: str,
    payload_hash: str,
) -> str:
    """
    AEVUM:WIRE:EVENT_HASH_CANON:V1

    event_hash = SHA256( chain_id(u8) || subject_id(32B) || seq_no(u64) || time_block_id(u64) ||
                         local_monotime(i64) || capture_device(16B) || prev_event_hash(32B) || payload_hash(32B) )
    """
    msg = b"".join([
        _u8(chain_id_u8),
        _b32_from_hex(subject_id_hex),
        _u64(int(seq_no)),
        _u64(int(time_block_id)),
        _i64(int(local_monotime_ns)),
        _b16_from_hex(capture_device_hex),
        _sha256_bytes_from_tagged(prev_event_hash),
        _sha256_bytes_from_tagged(payload_hash),
    ])
    return sha256_tagged(msg)


def sign_event_hash(sk: Ed25519PrivateKey, event_hash_tagged: str) -> bytes:
    """Sign the 32-byte event hash (sha256) to match the spec posture."""
    if not event_hash_tagged.startswith('sha256:'):
        raise ValueError('event_hash must be sha256:...')
    raw = bytes.fromhex(event_hash_tagged.split(':', 1)[1])
    return sk.sign(raw)



def load_identity_private(path: pathlib.Path) -> Dict[str, Any]:
    """
    Load private identity (identity.json) and return:
      sk (Ed25519PrivateKey), kid, subject_id_hex, capture_device_hex

    Supported identity key storage formats:
      A) Legacy (embedded): `private_key_b64` (seed/raw)
      B) Current (disk): `keys.device_signing_key.storage.private_key_path` (PKCS8 PEM, unencrypted)

    Hardening / mismatch tolerance:
      - Accepts several path field aliases (private_key_path/path/file)
      - Resolves relative key paths relative to identity.json directory
      - If key path missing, falls back to identity_dir/device_ed25519_sk.pem if present
      - If kid missing, derives kid from loaded public key (ed25519:sha256:<first16>)
    """
    obj = json.loads(path.read_text(encoding="utf-8"))
    identity_dir = path.parent

    def _as_dict(x):
        return x if isinstance(x, dict) else {}

    # IDs (support current 'device.*' + older 'subject.*'/'machine.*')
    device = _as_dict(obj.get("device"))
    machine = _as_dict(obj.get("machine"))
    subject = _as_dict(obj.get("subject"))

    capture_device_hex = (
        device.get("capture_device_hex")
        or machine.get("capture_device_hex")
        or obj.get("capture_device_hex")
        or obj.get("machine_id_hex")
    )
    subject_id_hex = (
        device.get("subject_id_hex")
        or subject.get("subject_id_hex")
        or obj.get("subject_id_hex")
        or obj.get("subject_id")
    )

    # Key container(s)
    keys = _as_dict(obj.get("keys"))
    dsk = _as_dict(keys.get("device_signing_key"))
    key_legacy = _as_dict(obj.get("key"))

    # kid (optional; we can derive if missing)
    kid = (
        key_legacy.get("kid")
        or dsk.get("kid")
        or _as_dict(keys.get("signing_key")).get("kid")
        or obj.get("kid")
    )

    # Private key: try common locations
    pk_b64 = (
        dsk.get("private_key_b64")
        or dsk.get("seed_b64")
        or key_legacy.get("private_key_b64")
        or key_legacy.get("seed_b64")
        or obj.get("private_key_b64")
        or obj.get("seed_b64")
    )

    pk_path = (
        dsk.get("private_key_path")
        or dsk.get("path")
        or _as_dict(dsk.get("storage")).get("private_key_path")
        or _as_dict(dsk.get("storage")).get("path")
        or _as_dict(dsk.get("storage")).get("file")
        or key_legacy.get("private_key_path")
        or key_legacy.get("path")
        or key_legacy.get("file")
        or obj.get("private_key_path")
        or obj.get("path")
    )

    # If no explicit pk_path but standard file exists beside identity.json, use it.
    if not pk_path:
        default_pem = identity_dir / "device_ed25519_sk.pem"
        if default_pem.exists():
            pk_path = str(default_pem)

    # Load private key
    if pk_b64:
        sk = load_ed25519_private(pk_b64)
    elif pk_path:
        p = pathlib.Path(pk_path)
        if not p.is_absolute():
            p = (identity_dir / p).resolve()
        try:
            pem = p.read_bytes()
        except PermissionError as e:
            raise ValueError(f"private key at {p} not readable (run as root / fix perms): {e}") from e
        except FileNotFoundError as e:
            raise ValueError(f"private key file not found: {p}") from e
        k = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(k, Ed25519PrivateKey):
            raise ValueError(f"private key at {p} is not Ed25519")
        sk = k
    else:
        raise ValueError("private key missing in identity.json (private_key_b64 or storage.private_key_path required)")

    # Derive kid if missing
    if not kid:
        pk_raw = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        kid = "ed25519:sha256:" + hashlib.sha256(pk_raw).hexdigest()[:16]

    return {"sk": sk, "kid": kid, "subject_id_hex": subject_id_hex, "capture_device_hex": capture_device_hex}


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()



def try_flock(fd: int) -> bool:
    """
    Best-effort non-blocking advisory lock.
    Returns True if lock acquired, False otherwise.
    """
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except Exception:
        return False




def append_line_best_effort(path: pathlib.Path, line: str, mode: int = 0o600) -> None:
    """
    Append a single line to a log in best-effort mode:
    - O_APPEND write
    - tries to acquire a non-blocking flock; if lock can't be acquired, still writes (no gating).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, mode)
    try:
        _ = try_flock(fd)
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

