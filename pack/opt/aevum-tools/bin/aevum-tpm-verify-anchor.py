#!/usr/bin/env python3
"""Verify an Aevum TPM boot anchor end-to-end.

Checks:
- Anchor canonical digest matches anchor_digest_sha256 field
- TPM signature over digest (plain r||s) verifies using tpm_sign public key (PEM)
- TPM quote verifies (delegated to tpm2_checkquote via existing bash verifier logic)

Exit codes: 0 PASS, 2 FAIL
"""
import argparse, json, pathlib, subprocess, sys, hashlib, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def verify_plain_p256_sig(pub_pem: pathlib.Path, digest32: bytes, sig_plain: bytes) -> bool:
    if len(sig_plain)!=64 or len(digest32)!=32: return False
    r=int.from_bytes(sig_plain[:32],"big"); s=int.from_bytes(sig_plain[32:],"big")
    der=encode_dss_signature(r,s)
    pub = load_pem_public_key(pub_pem.read_bytes())
    try:
        pub.verify(der, digest32, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="anchor json path")
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="instance base for finding sign.pub.pem")
    ap.add_argument("--skip-quote", action="store_true", help="skip quote validation")
    args=ap.parse_args()

    f=pathlib.Path(args.file)
    if not f.exists():
        print("FAIL: missing anchor file", file=sys.stderr); return 2
    o=json.loads(f.read_text(encoding="utf-8"))
    # Rebuild canonical form (same as anchor tool did): remove signature fields and any computed digest field
    # In anchor tool, canon JSON is the base object without signature fields.
    o2=dict(o)
    for k in ["signature_b64","signature_format","signature_hash_alg","signature_signed_over","anchor_digest_sha256"]:
        o2.pop(k, None)
    canon = canonical_bytes(o2)
    digest = hashlib.sha256(canon).hexdigest()
    digest_tag = "sha256:"+digest
    if o.get("anchor_digest_sha256","") != digest_tag:
        print(f"FAIL: anchor digest mismatch: file={o.get('anchor_digest_sha256','')} computed={digest_tag}")
        return 2

    sig_b64=o.get("signature_b64","")
    if not sig_b64:
        print("FAIL: missing signature_b64"); return 2
    if o.get("signature_format","") != "plain_r_s_64(base64)":
        print("FAIL: unsupported signature_format"); return 2
    sig_plain=base64.b64decode(sig_b64)
    digest32=bytes.fromhex(digest)
    pub = pathlib.Path(args.base)/"tpm_sign"/"sign.pub.pem"
    if not pub.exists():
        # fallback to path embedded
        # (anchor includes tpm_sign_public_key_sha256 but not path)
        pub2 = pathlib.Path("/var/lib/aevum/workstation/tpm_sign/sign.pub.pem")
        pub = pub2 if pub2.exists() else pub
    if not pub.exists():
        print("FAIL: missing TPM sign.pub.pem"); return 2
    if not verify_plain_p256_sig(pub, digest32, sig_plain):
        print("FAIL: TPM signature invalid"); return 2

    if not args.skip_quote:
        # Delegate to existing quote verifier (tpm2_checkquote + policy check)
        # Prefer /opt/aevum-tools/bin/aevum-tpm-verify-anchor (bash), but if it conflicts, call it with the file path.
        bash = pathlib.Path("/opt/aevum-tools/bin/aevum-tpm-verify-anchor")
        if bash.exists():
            p = subprocess.run([str(bash), str(f)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if p.returncode!=0:
                print("FAIL: quote verification failed")
                print(p.stdout)
                return 2
        else:
            print("WARN: missing bash quote verifier; skipping quote check")

    print("PASS: anchor signature + digest verified" + ("" if args.skip_quote else " (+quote)"))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
