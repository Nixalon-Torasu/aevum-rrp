#!/usr/bin/env python3
import argparse, base64, json, os, pathlib, hashlib, socket, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def sha256hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def read_machine_id() -> bytes:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return pathlib.Path(p).read_text().strip().encode("utf-8")
        except Exception:
            pass
    return os.urandom(16)

def utcnow_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    ident_dir = base / "identity"
    ident_path = ident_dir / "identity.json"

    ident_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ident_dir, 0o700)
    except Exception:
        pass

    if ident_path.exists() and not args.force:
        try:
            obj = json.loads(ident_path.read_text())
            # Accept either legacy flat key or nested keys.device_signing_key
            if ("private_key_b64" in obj) or ("keys" in obj and "device_signing_key" in obj["keys"] and "private_key_b64" in obj["keys"]["device_signing_key"]):
                return 0
        except Exception:
            pass

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    sk_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    mid = read_machine_id()
    subject_id_hex = sha256hex(mid + b":subject")
    capture_device_hex = sha256hex(mid + b":capture_device")
    kid = f"devsign:ed25519:{sha256hex(pk_raw)[:32]}"

    obj = {
        "schema": "aevum.identity.v1",
        "created_utc": utcnow_iso(),
        "hostname": socket.gethostname(),
        "subject_id_hex": subject_id_hex,
        "capture_device_hex": capture_device_hex,
        "keys": {
            "device_signing_key": {
                "alg": "ed25519",
                "kid": kid,
                "public_key_b64": b64e(pk_raw),
                "private_key_b64": b64e(sk_raw),
            }
        }
    }

    ident_path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    os.chmod(ident_path, 0o600)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
