#!/usr/bin/env python3
"""
Aevum appliance move-token helper (signed, minimal).

- create: generates token JSON + signature using appliance Ed25519 key
- verify: verifies token signature using appliance public key

Keys are stored at:
  /var/lib/aevum/appliance/identity/device_signing_key.pem
  /var/lib/aevum/appliance/identity/device_signing_key_pub.pem
"""

from __future__ import annotations

import argparse, base64, json, pathlib, sys, datetime as dt, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_sk(p: pathlib.Path) -> Ed25519PrivateKey:
    sk = serialization.load_pem_private_key(p.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Not Ed25519 private key")
    return sk

def load_pk(p: pathlib.Path) -> Ed25519PublicKey:
    pk = serialization.load_pem_public_key(p.read_bytes())
    if not isinstance(pk, Ed25519PublicKey):
        raise TypeError("Not Ed25519 public key")
    return pk

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def utc_plus(hours: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).replace(microsecond=0).isoformat()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("--out", required=True)
    c.add_argument("--sig", required=True)
    c.add_argument("--expires-hours", type=int, default=24)
    c.add_argument("--reason", default="operator move authorization")

    v = sub.add_parser("verify")
    v.add_argument("--token", required=True)
    v.add_argument("--sig", required=True)

    args = ap.parse_args()

    base = pathlib.Path("/var/lib/aevum/appliance/identity")
    sk_p = base / "device_signing_key.pem"
    pk_p = base / "device_signing_key_pub.pem"

    if args.cmd == "create":
        sk = load_sk(sk_p)
        token = {
            "schema_id": "AEVUM:APPLIANCE:MOVE_TOKEN:V1",
            "created_at": utc_now(),
            "expires_at": utc_plus(args.expires_hours),
            "reason": args.reason,
            "nonce": sha256_hex((utc_now() + args.reason).encode("utf-8"))[:32],
            "allow_rebind": True
        }
        msg = canonical(token)
        sig = sk.sign(hashlib.sha256(msg).digest())
        pathlib.Path(args.out).write_bytes(msg)
        pathlib.Path(args.sig).write_text(base64.b64encode(sig).decode("ascii") + "\n", encoding="utf-8")
        print("OK: token created")
        return

    if args.cmd == "verify":
        pk = load_pk(pk_p)
        token_b = pathlib.Path(args.token).read_bytes()
        sig_b64 = pathlib.Path(args.sig).read_text(encoding="utf-8").strip()
        sig = base64.b64decode(sig_b64.encode("ascii"))
        pk.verify(sig, hashlib.sha256(token_b).digest())
        token = json.loads(token_b.decode("utf-8"))
        exp = dt.datetime.fromisoformat(token["expires_at"])
        if exp < dt.datetime.now(dt.timezone.utc):
            print("FAIL: token expired", file=sys.stderr)
            sys.exit(3)
        print("OK: token verified and not expired")
        return

if __name__ == "__main__":
    main()
