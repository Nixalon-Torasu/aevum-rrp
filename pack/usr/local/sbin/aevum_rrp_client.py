#!/usr/bin/env python3
"""
aevum_rrp_client.py — Core-side client for Aevum RRP (Local STRICT)
"""

import argparse, base64, json, os, pathlib, socket, sys, time, hashlib, uuid, datetime
from typing import Any, Dict, List

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key
except Exception as e:
    print("ERROR: Missing dependency 'cryptography'. Install with: python3 -m pip install cryptography", file=sys.stderr)
    raise

PROTO = "AEVUM:PROTO:RRP:LOCAL_STRICT:V1_0"

def canon_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def uuidv7_like() -> str:
    t = int(time.time() * 1000)
    return f"{t:x}-{uuid.uuid4().hex}"

def load_sk(path: pathlib.Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        return load_pem_private_key(raw, password=None)

def save_keypair(dirp: pathlib.Path):
    dirp.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_raw = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    (dirp/"core_ed25519_sk.raw").write_bytes(sk_raw)
    (dirp/"core_ed25519_pk.raw").write_bytes(pk_raw)
    os.chmod(dirp/"core_ed25519_sk.raw", 0o600)
    os.chmod(dirp/"core_ed25519_pk.raw", 0o644)
    print("core_pub_b64=" + base64.b64encode(pk_raw).decode("ascii"))

def sign_request(req: Dict[str, Any], sk: Ed25519PrivateKey) -> Dict[str, Any]:
    tmp = dict(req)
    tmp.pop("sig", None)
    sig = sk.sign(canon_bytes(tmp))
    req["sig"] = base64.b64encode(sig).decode("ascii")
    return req

def send(sock_path: str, obj: Dict[str, Any]) -> str:
    data = canon_bytes(obj)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    return out.decode("utf-8", errors="replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", default="/run/aevum/rrp.sock")
    ap.add_argument("--client-id", default="localcore")
    ap.add_argument("--sk", default="/var/lib/aevum/core/identity/core_ed25519_sk.raw")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen")
    g.add_argument("--dir", default="/var/lib/aevum/core/identity")

    r = sub.add_parser("request")
    r.add_argument("--receipt-class", required=True)
    r.add_argument("--component", default="aevum_core_job")
    r.add_argument("--ttl-ms", type=int, default=5000)
    r.add_argument("--idem", default="")
    r.add_argument("--claim", action="append", default=[], help="k=v (scalar)")
    r.add_argument("--ptr", action="append", default=[], help="ref_type,ref,hash")

    args = ap.parse_args()

    if args.cmd == "keygen":
        save_keypair(pathlib.Path(args.dir))
        return 0

    sk_path = pathlib.Path(args.sk)
    if not sk_path.exists():
        print("ERROR: missing core private key. Run: aevum-rrp-client keygen", file=sys.stderr)
        return 2
    sk = load_sk(sk_path)

    claims: Dict[str, Any] = {}
    for kv in args.claim:
        if "=" not in kv:
            continue
        k,v = kv.split("=",1)
        if v.lower() in ("true","false"):
            claims[k]= (v.lower()=="true")
        else:
            try:
                claims[k]= int(v)
            except Exception:
                claims[k]= v

    pointers: List[Dict[str,str]] = []
    for p in args.ptr:
        parts = p.split(",",2)
        if len(parts) != 3:
            continue
        pointers.append({"ref_type":parts[0], "ref":parts[1], "hash":parts[2]})

    nonce = os.urandom(32)
    idem = args.idem or hashlib.sha256(os.urandom(32)).hexdigest()

    req = {
        "proto": PROTO,
        "req_id": uuidv7_like(),
        "client_id": args.client_id,
        "ts_client_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ttl_ms": int(args.ttl_ms),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "idempotency_key": idem,
        "receipt_class": args.receipt_class,
        "component": args.component,
        "claims": claims,
        "pointers": pointers,
        "sig": ""
    }
    req = sign_request(req, sk)
    out = send(args.socket, req)
    print(out.strip())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
