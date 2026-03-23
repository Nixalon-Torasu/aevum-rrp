from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .common import device_id_from_public_key, public_key_b64


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Ed25519 device identity for RRP")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (out_dir / "device_ed25519_sk.pem").write_bytes(sk_pem)
    (out_dir / "device_ed25519_pk.pem").write_bytes(pk_pem)
    (out_dir / "device_identity.json").write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "device_id": device_id_from_public_key(pk),
                "device_pubkey": public_key_b64(pk),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(device_id_from_public_key(pk))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
