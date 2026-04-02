#!/usr/bin/env python3
"""
aevum_registry_seal.py — Seal /etc/aevum/registry into a signed manifest (device-bound).

Creates:
  /etc/aevum/registry/REGISTRY_MANIFEST.json
  /etc/aevum/registry/REGISTRY_MANIFEST.sig.ed25519.b64
Optionally:
  /etc/aevum/registry/REGISTRY_MANIFEST.sig.tpm_p256_plain.b64

The Ed25519 signature uses the workstation device key (device_ed25519_sk.pem) so the
running registry state is bound to the device identity.

This is not "governance"; it's provenance. The system can run without sealing, but strict mode will refuse.
"""

import argparse, base64, datetime, hashlib, json, os, pathlib, subprocess, sys
from typing import Dict, Any, List

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canon_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def iter_registry_files(reg_dir: pathlib.Path) -> List[pathlib.Path]:
    out=[]
    for p in sorted(reg_dir.rglob("*")):
        if not p.is_file():
            continue
        name=p.name
        if name.startswith("."):
            continue
        # exclude manifests and signatures
        if name in ("REGISTRY_MANIFEST.json", "REGISTRY_MANIFEST.sig.ed25519.b64", "REGISTRY_MANIFEST.sig.tpm_p256_plain.b64"):
            continue
        # exclude detached gpg sigs (still allowed)
        if name.endswith(".asc"):
            continue
        out.append(p)
    return out

def file_sha256(p: pathlib.Path) -> str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def load_device_sk(base: pathlib.Path) -> Ed25519PrivateKey:
    key_path = base / "identity" / "device_ed25519_sk.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"missing device key: {key_path}")
    sk = load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("device key is not Ed25519")
    return sk

def tpm_sign_digest(base: pathlib.Path, digest_hex: str) -> str:
    """
    Returns base64(signature plain r||s 64 bytes) if TPM signing context exists.
    """
    ctx = base.parent / "tpm_sign" / "sign.ctx"
    pub = base.parent / "tpm_sign" / "sign.pub"
    if not ctx.exists() or not pub.exists():
        raise FileNotFoundError("missing TPM sign context/pub")
    # create raw digest file
    dg = bytes.fromhex(digest_hex)
    tmpd = pathlib.Path("/tmp/aevum_registry_manifest_digest.bin")
    tmpo = pathlib.Path("/tmp/aevum_registry_manifest_sig.bin")
    tmpd.write_bytes(dg)
    try:
        # '-f plain' -> r||s; sign digest directly using -d
        subprocess.check_call(["tpm2_sign", "-c", str(ctx), "-g", "sha256", "-f", "plain", "-o", str(tmpo), "-d", str(tmpd)])
        sig = tmpo.read_bytes()
        if len(sig) != 64:
            # Still return, but flag format mismatch upstream
            pass
        return base64.b64encode(sig).decode("ascii")
    finally:
        try: tmpd.unlink()
        except: pass
        try: tmpo.unlink()
        except: pass

def emit_receipt(note: str, **kv):
    rcpt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if not rcpt.exists():
        return
    args=[str(rcpt), "note", note] + [f"{k}={v}" for k,v in kv.items()]
    subprocess.call(args)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="/etc/aevum/registry")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="instance base (contains identity/)")
    ap.add_argument("--tpm", action="store_true", help="also sign manifest digest with TPM signing key (if available)")
    args = ap.parse_args()

    reg = pathlib.Path(args.registry)
    base = pathlib.Path(args.base)

    reg.mkdir(parents=True, exist_ok=True)

    files = iter_registry_files(reg)
    entries=[]
    for p in files:
        rel=str(p.relative_to(reg))
        entries.append({"path": rel, "sha256": "sha256:"+file_sha256(p)})

    manifest = {
        "type": "aevum_registry_manifest_v1",
        "generated_at_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registry_path": str(reg),
        "entries": entries,
    }
    mbytes = canon_bytes(manifest)
    mdigest = sha256_hex(mbytes)

    sk = load_device_sk(base)
    sig = sk.sign(mbytes)
    sig_b64 = base64.b64encode(sig).decode("ascii")

    (reg/"REGISTRY_MANIFEST.json").write_bytes(mbytes + b"\n")
    (reg/"REGISTRY_MANIFEST.sig.ed25519.b64").write_text(sig_b64+"\n", encoding="utf-8")
    os.chmod(reg/"REGISTRY_MANIFEST.sig.ed25519.b64", 0o600)
    os.chmod(reg/"REGISTRY_MANIFEST.json", 0o644)

    tpm_b64 = ""
    if args.tpm:
        try:
            tpm_b64 = tpm_sign_digest(base, mdigest)
            (reg/"REGISTRY_MANIFEST.sig.tpm_p256_plain.b64").write_text(tpm_b64+"\n", encoding="utf-8")
            os.chmod(reg/"REGISTRY_MANIFEST.sig.tpm_p256_plain.b64", 0o600)
        except Exception as e:
            # optional; receipt warning
            emit_receipt("registry manifest TPM sign skipped", component="registry", reason=str(e)[:200])

    emit_receipt("registry manifest sealed", component="registry", manifest_sha256="sha256:"+mdigest, tpm=("yes" if tpm_b64 else "no"))
    print("OK: sealed registry manifest sha256=sha256:"+mdigest)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
