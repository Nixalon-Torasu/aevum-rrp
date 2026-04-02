#!/usr/bin/env python3
"""Aevum TPM signature verifier (offline, public-key based).

Verifies TPM-produced ECDSA P-256 signatures that were generated over a SHA-256 digest
using tpm2_sign with '-d <digest>' and '-f plain'.

Signature format 'plain' is expected to be r||s (64 bytes) for P-256.
"""

import argparse, base64, json, pathlib, sys
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def _load_pubkey(pub_pem: pathlib.Path):
    data = pub_pem.read_bytes()
    return load_pem_public_key(data)


def _verify_plain_ecdsa_p256_sha256(pubkey, digest32: bytes, sig_plain: bytes) -> bool:
    if len(digest32) != 32:
        return False
    if len(sig_plain) != 64:
        return False
    r = int.from_bytes(sig_plain[:32], "big")
    s = int.from_bytes(sig_plain[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        pubkey.verify(der, digest32, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def verify_tpm_signature(event_hash: str, tpm_sig: Dict[str, Any], pub_pem: pathlib.Path) -> bool:
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
    digest32 = bytes.fromhex(event_hash.split(":", 1)[1])
    sig_plain = base64.b64decode(sig_b64)
    pubkey = _load_pubkey(pub_pem)
    return _verify_plain_ecdsa_p256_sha256(pubkey, digest32, sig_plain)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-hash", required=True, help="sha256:<hex> event_hash")
    ap.add_argument("--sig-json", required=True, help="TPM signature JSON (string or @file)")
    ap.add_argument("--pub", required=True, help="TPM signing public key PEM path")
    args = ap.parse_args()

    sig_in = args.sig_json
    if sig_in.startswith("@"):
        sig = json.loads(pathlib.Path(sig_in[1:]).read_text(encoding="utf-8"))
    else:
        sig = json.loads(sig_in)

    ok = verify_tpm_signature(args.event_hash, sig, pathlib.Path(args.pub))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
