#!/usr/bin/env python3
"""
Aevum Machine Identity Bootstrap (v0.2)

Goal (Year-1 demo):
- Create a stable, local machine identity for an Aevum Workstation.
- Generate an Ed25519 signing keypair (device signing key).
- Write identity.json (self-signed) + identity.seal.
- Be idempotent (safe to re-run).
- Refuse destructive actions if receipts already exist (to avoid "burning" history).

Security posture (Year-1):
- Private key stored on disk, root-owned, mode 0400.
- Upgrade path: TPM2 sealing, offline root-policy signatures, encrypted key unlock, KMLC-derived chain keys.

Tested intent: Ubuntu 24.04 Server (Python 3 + cryptography).
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import shutil
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import uuid

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("ERROR: Missing dependency 'cryptography'. Install with: python3 -m pip install cryptography", file=sys.stderr)
    raise

SCHEMA_ID = "AEVUM:IDENTITY:DEVICE:V1"
TOOL_NAME = "aevum-identity-bootstrap"
TOOL_VERSION = "0.2.0"


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def kid_from_pub(pub_raw: bytes) -> str:
    # Stable key id: "ed25519:sha256:<first16>"
    return "ed25519:sha256:" + sha256_hex(pub_raw)[:16]


def canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
        # fsync directory entry for stronger durability
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


def ensure_root_if_system_path(base: pathlib.Path) -> None:
    """
    If writing under /var, /etc, /usr, require root. Otherwise allow user-space installs.
    """
    system_prefixes = (pathlib.Path("/var"), pathlib.Path("/etc"), pathlib.Path("/usr"), pathlib.Path("/opt"))
    try:
        resolved = base.resolve()
    except Exception:
        resolved = base
    if any(str(resolved).startswith(str(p) + os.sep) or str(resolved) == str(p) for p in system_prefixes):
        if os.geteuid() != 0:
            print("ERROR: Must run as root for system install paths (e.g., /var/lib/aevum).", file=sys.stderr)
            sys.exit(2)


def tighten_dir_permissions(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def read_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return None


def gather_platform_facts() -> dict:
    machine_id = read_text(pathlib.Path("/etc/machine-id")) or ""
    hostname = socket.gethostname()

    os_release = {}
    try:
        for line in pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_release[k] = v.strip().strip('"')
    except Exception:
        pass

    product_uuid = read_text(pathlib.Path("/sys/class/dmi/id/product_uuid")) or ""
    board_name = read_text(pathlib.Path("/sys/class/dmi/id/board_name")) or ""
    sys_vendor = read_text(pathlib.Path("/sys/class/dmi/id/sys_vendor")) or ""

    # Hardware fingerprint should be "best effort", not a single point of failure.
    fp_material = (machine_id + "|" + product_uuid + "|" + board_name + "|" + sys_vendor).encode("utf-8", "ignore")
    hw_fp = "sha256:" + sha256_hex(fp_material)

    return {
        "machine_id": machine_id,
        "hostname": hostname,
        "os_release": os_release,
        "dmi": {
            "product_uuid": product_uuid,
            "board_name": board_name,
            "sys_vendor": sys_vendor,
        },
        "hardware_fingerprint": hw_fp,
    }


def _tpm_pubkey_sha256(handle: str) -> str | None:
    """
    Read the public key for a TPM persistent object at <handle> and return
    'sha256:<hex>' of its PEM-encoded bytes.  Best-effort: returns None on
    any failure (tpm2-tools not installed, handle not provisioned, etc.).
    """
    try:
        if not shutil.which("tpm2_readpublic"):
            return None
        with tempfile.TemporaryDirectory(prefix="aevum_tpm_id_") as td:
            pem_out = pathlib.Path(td) / "key.pem"
            proc = subprocess.run(
                ["tpm2_readpublic", "-c", handle, "-f", "pem", "-o", str(pem_out)],
                capture_output=True, timeout=15,
            )
            if proc.returncode != 0 or not pem_out.exists():
                return None
            pem_bytes = pem_out.read_bytes()
            return "sha256:" + sha256_hex(pem_bytes)
    except Exception:
        return None


def gather_tpm_identity() -> list[dict]:
    """
    Probe standard persistent TPM handles for EK (0x81010001) and AK (0x81010002).
    Returns a list of trust_anchor dicts; empty list if TPM is unavailable.

    Each entry:
        {
          "type":       "TPM2_PERSISTENT_KEY",
          "handle":     "0x81010001",
          "role":       "EK" | "AK",
          "alg":        "ECC_P256" | "RSA_2048" (best-effort from tool output),
          "pubkey_sha256": "sha256:<hex>",    # sha256 of DER-encoded PEM bytes
          "captured_at": "<ISO-8601>",
        }

    Silently skips handles that are not provisioned or on which tpm2-tools fails.
    """
    anchors: list[dict] = []
    probes = [
        ("0x81010001", "EK"),
        ("0x81010002", "AK"),
    ]
    ts = utc_now_iso()
    for handle, role in probes:
        sha = _tpm_pubkey_sha256(handle)
        if sha is None:
            continue
        anchors.append({
            "type": "TPM2_PERSISTENT_KEY",
            "handle": handle,
            "role": role,
            "pubkey_sha256": sha,
            "captured_at": ts,
        })
    return anchors


def emit_provisioning_receipt_best_effort(base: pathlib.Path, identity_id: str) -> None:
    """
    After identity.json is written, emit a chain-I receipt recording the
    provisioning event.  Best-effort: silently skips if aevum-receipt is
    not yet installed (first-boot before the toolchain is deployed).
    """
    receipt = pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if not (receipt.exists() and os.access(receipt, os.X_OK)):
        for candidate in [
            pathlib.Path("/usr/local/bin/aevum-receipt"),
            pathlib.Path("/usr/bin/aevum-receipt"),
        ]:
            if candidate.exists() and os.access(candidate, os.X_OK):
                receipt = candidate
                break
        else:
            return  # toolchain not yet installed — skip silently
    try:
        subprocess.run(
            [
                str(receipt),
                "note",
                "machine identity provisioned",
                "component=identity",
                f"identity_id={identity_id}",
                f"base={base}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env={**os.environ, "AEVUM_ALLOW_UNSEALED": "1"},
        )
    except Exception:
        pass


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk_raw


def write_private_key_pem(sk: Ed25519PrivateKey, path: pathlib.Path) -> None:
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    atomic_write_bytes(path, pem, mode=0o400)  # 0400 root read-only


def load_private_key_pem(path: pathlib.Path) -> Ed25519PrivateKey:
    sk = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")
    return sk


def load_existing_identity(identity_path: pathlib.Path) -> dict | None:
    try:
        return json.loads(identity_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def verify_self_signature(identity: dict) -> bool:
    """
    Verify identity['self_signature'] over the canonical JSON of the identity object
    with self_signature removed.
    """
    try:
        sig = identity.get("self_signature", {})
        sig_b64 = sig.get("sig_b64")
        kid = sig.get("kid")

        keys = identity.get("keys", {})
        dk = keys.get("device_signing_key", {})
        pub_b64 = dk.get("public_key_b64")

        if not (sig_b64 and kid and pub_b64):
            return False

        pub_raw = b64d(pub_b64)
        unsigned = dict(identity)
        unsigned.pop("self_signature", None)

        unsigned_bytes = canonical_json_bytes(unsigned)
        sig_raw = b64d(sig_b64)

        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, unsigned_bytes)

        return kid == kid_from_pub(pub_raw)
    except Exception:
        return False


def receipts_exist(base: pathlib.Path) -> bool:
    """
    Detect if ANY receipt/state exists (to prevent accidental key invalidation).
    """
    candidates = [
        base / "receipts",
        base / "accurate" / "receipts",   # Seam two-rails layout
        base / "state",
        base / "accurate" / "state",
    ]
    for c in candidates:
        if c.exists():
            # any jsonl or chain state indicates history exists
            for p in c.rglob("*"):
                if p.is_file() and (p.suffix in (".jsonl", ".json") or p.name.startswith("chain_")):
                    return True
    return False


def ensure_seam_layout(base: pathlib.Path) -> None:
    """
    Seam two-rail layout:
      base/accurate/receipts  (thin facts / receipts)
      base/accurate/payloads  (private payload blobs; prunable)
      base/narrative/         (optional narrative rail; not used by receipt daemons)
    Back-compat symlinks:
      base/receipts -> base/accurate/receipts
      base/payloads -> base/accurate/payloads
    """
    accurate = base / "accurate"
    narrative = base / "narrative"
    (accurate / "receipts").mkdir(parents=True, exist_ok=True)
    (accurate / "payloads").mkdir(parents=True, exist_ok=True)
    narrative.mkdir(parents=True, exist_ok=True)
    # Tight perms for accurate; narrative can be looser later
    try:
        os.chmod(accurate, 0o700)
        os.chmod(accurate / "receipts", 0o700)
        os.chmod(accurate / "payloads", 0o700)
        os.chmod(narrative, 0o700)
    except Exception:
        pass

    # Create symlinks if missing and not occupied
    link_map = {
        base / "receipts": accurate / "receipts",
        base / "payloads": accurate / "payloads",
    }
    for link, target in link_map.items():
        if link.exists() or link.is_symlink():
            continue
        try:
            link.symlink_to(target, target_is_directory=True)
        except Exception:
            # If symlinks not allowed, we simply rely on accurate paths.
            pass


def copy_packaged_policies(pack_root: pathlib.Path, base: pathlib.Path) -> None:
    """
    Copy packaged default policy files into base/accurate/policies.
    This is OPTIONAL and MUST NOT be required for basic function.
    """
    src = pack_root / "policies"
    if not src.exists():
        return
    dst = base / "accurate" / "policies"
    dst.mkdir(parents=True, exist_ok=True)
    for p in src.rglob("*"):
        if p.is_file():
            rel = p.relative_to(src)
            out = dst / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(out, p.read_bytes(), mode=0o600)

    # Write a simple manifest with sha256 hashes for pinning
    manifest = {"generated_at": utc_now_iso(), "files": []}
    for p in dst.rglob("*"):
        if p.is_file():
            manifest["files"].append({
                "path": str(p.relative_to(dst)),
                "sha256": sha256_hex(p.read_bytes())
            })
    manifest["files"].sort(key=lambda x: x["path"])
    atomic_write_text(dst / "POLICIES_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n", mode=0o600)



def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap Aevum machine identity (Year-1).")
    ap.add_argument("--base", default="/var/lib/aevum", help="Base directory (default: /var/lib/aevum)")
    ap.add_argument("--instance", default="", help="Optional instance name (e.g., workstation, core, user). If set, base becomes <base>/<instance>.")
    ap.add_argument("--dir", default=None, help="(Deprecated) Identity directory. Use --base instead.")
    ap.add_argument("--force", action="store_true", help="Overwrite existing identity.json (DANGEROUS).")
    ap.add_argument("--regen-key", action="store_true", help="Regenerate signing key (BREAKS continuity; only before producing receipts).")
    ap.add_argument("--allow-break-history", action="store_true", help="Acknowledge you are OK invalidating continuity if receipts exist.")
    ap.add_argument("--policy-version", default="AEVUM:WORKSTATION:BOOTSTRAP:V1", help="Optional policy identifier string.")
    ap.add_argument("--seam-layout", action="store_true", help="Create Seam two-rail layout under base (accurate/ + narrative/) with compatibility symlinks.")
    ap.add_argument("--install-policies", action="store_true", help="Copy packaged default policy JSONs into base/accurate/policies (optional; not required).")
    ap.add_argument("--pack-root", default="", help="Path to this bootstrap pack root (for packaged policies). If empty, uses script directory.")
    ap.add_argument("--canon-digest", default="", help="Optional canon bundle digest (sha256:...) if you want identity to claim a canon.")
    ap.add_argument("--print", action="store_true", help="Print identity.json after creation/validation.")
    ap.add_argument("--status", action="store_true", help="Print a one-line status and exit.")
    args = ap.parse_args()

    base = pathlib.Path(args.base)
    if args.instance:
        base = base / args.instance

    if args.dir:
        # Backward compat
        identity_dir = pathlib.Path(args.dir)
        base = identity_dir.parent
    else:
        identity_dir = base / "identity"

    ensure_root_if_system_path(base)

    # Strong umask: no group/other permissions on new files
    os.umask(0o077)

    tighten_dir_permissions(identity_dir)

    pack_root = pathlib.Path(args.pack_root).resolve() if args.pack_root else pathlib.Path(__file__).resolve().parent
    if args.seam_layout:
        ensure_seam_layout(base)
    if args.install_policies:
        copy_packaged_policies(pack_root, base)

    identity_path = identity_dir / "identity.json"
    seal_path = identity_dir / "identity.seal"
    pub_path = identity_dir / "identity.public.json"
    sk_path = identity_dir / "device_ed25519_sk.pem"

    hist_exists = receipts_exist(base)

    if args.status:
        if identity_path.exists():
            ident = load_existing_identity(identity_path) or {}
            ok = verify_self_signature(ident)
            print("OK" if ok else "BAD", str(identity_path))
        else:
            print("MISSING", str(identity_path))
        return 0

    # Prevent destructive actions if history exists
    if hist_exists and (args.force or args.regen_key) and not args.allow_break_history:
        print("ERROR: Receipts/state appear to exist under base path. Refusing --force/--regen-key without --allow-break-history.", file=sys.stderr)
        print(f"    base: {base}", file=sys.stderr)
        print("    If you haven't started printing receipts yet, delete the receipts/state directories and re-run.", file=sys.stderr)
        return 20

    # If identity exists and not forcing, validate and exit
    if identity_path.exists() and not args.force:
        identity = load_existing_identity(identity_path)
        if not identity:
            print(f"ERROR: {identity_path} exists but is not valid JSON. Use --force to overwrite.", file=sys.stderr)
            return 3
        if not verify_self_signature(identity):
            print(f"ERROR: Existing identity failed self-signature verification: {identity_path}", file=sys.stderr)
            # Best-effort repair: preserve existing signing key and re-emit a fresh identity.json.
            # This preserves identity_id continuity as long as device_ed25519_sk.pem exists.
            ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
            try:
                bad = identity_path.with_name(f"identity.bad.{ts}.json")
                shutil.copy2(identity_path, bad)
                print(f"WARN: saved broken identity to {bad}", file=sys.stderr)
            except Exception as e:
                print(f"WARN: could not preserve broken identity: {e}", file=sys.stderr)
            if not sk_path.exists() and not args.regen_key:
                if not hist_exists:
                    print("WARN: identity.json exists but signing key is missing and no receipts history exists; regenerating key material.", file=sys.stderr)
                    args.regen_key = True
                else:
                    print("ERROR: cannot repair without device_ed25519_sk.pem; rerun with --force --regen-key", file=sys.stderr)
                    return 4
            print("WARN: continuing: will (re)emit identity.json using current signing key material.", file=sys.stderr)
        else:
            if args.print:
                print(json.dumps(identity, indent=2, sort_keys=True))
            print("OK: identity already exists and self-signature verifies.")
            return 0

    # Key handling
    if sk_path.exists() and not args.regen_key:
        try:
            sk = load_private_key_pem(sk_path)
            pk_raw = sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except Exception as e:
            print(f"ERROR: Failed to load existing key {sk_path}: {e}", file=sys.stderr)
            return 5
    else:
        sk, pk_raw = generate_ed25519_keypair()
        write_private_key_pem(sk, sk_path)

    # Identity derivations (match the spec posture: ID_s = H(PK_s))
    subject_id_hex = sha256_hex(pk_raw)                    # bytes32 as hex
    capture_device_hex = sha256(pk_raw).hex()[:32]         # bytes16 as hex (stable across OS reinstalls)
    kid = kid_from_pub(pk_raw)

    facts = gather_platform_facts()
    identity_id = "aevum:device:" + subject_id_hex[:32]
    instance_id = str(uuid.uuid4())
    bootstrap_id = str(uuid.uuid4())

    unsigned_identity = {
        "schema": SCHEMA_ID,
        "version": "1.0.0",
        "created_at": utc_now_iso(),
        "policy_version": args.policy_version,
        "canon_digest": args.canon_digest or None,
        "device": {
            "identity_id": identity_id,
            "instance_id": instance_id,
            "subject_id_hex": subject_id_hex,
            "capture_device_hex": capture_device_hex,
            "hostname": facts.get("hostname", ""),
            "machine_id": facts.get("machine_id", ""),
            "hardware_fingerprint": facts.get("hardware_fingerprint", ""),
            "platform": {
                "os_release": facts.get("os_release", {}),
                "dmi": facts.get("dmi", {}),
            },
        },
        "keys": {
            "device_signing_key": {
                "kid": kid,
                "alg": "Ed25519",
                "public_key_b64": b64e(pk_raw),
                "created_at": utc_now_iso(),
                "usage": ["SIGN_RECEIPTS", "SIGN_IDENTITY"],
                "storage": {
                    "private_key_path": str(sk_path),
                    "private_key_format": "PKCS8-PEM",
                    "protection": "root-fs-perms-only",
                },
            }
        },
        "derivation_policy": {
            "year1_note": "Year-1 demo uses the device_signing_key for all chains. Future: derive per-chain keys from a sealed subject root (KMLC)."
        },
        "bootstrap": {
            "bootstrap_id": bootstrap_id,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "run_as": {"user": getpass.getuser(), "euid": os.geteuid()},
            "notes": "Self-signed identity + disk key. Optional canon_digest identifies a rule-set but MUST NOT be required for use.",
        },
        "trust_anchors": gather_tpm_identity(),
    }

    sig_raw = sk.sign(canonical_json_bytes(unsigned_identity))
    identity = dict(unsigned_identity)
    identity["self_signature"] = {
        "alg": "Ed25519",
        "kid": kid,
        "sig_b64": b64e(sig_raw),
        "signed_fields": "ALL_FIELDS_EXCEPT_self_signature",
        "canonicalization": "json(sort_keys=true,separators=(',',':'),utf8)",
        "signed_at": utc_now_iso(),
    }

    # Persist identity.json
    pretty = json.dumps(identity, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(identity_path, pretty, mode=0o600)

    # Public view (shareable)
    public_view = {
        "schema": "AEVUM:IDENTITY:DEVICE_PUBLIC:V1",
        "created_at": identity["created_at"],
        "device": {
            "identity_id": identity["device"]["identity_id"],
            "subject_id_hex": identity["device"]["subject_id_hex"],
            "capture_device_hex": identity["device"]["capture_device_hex"],
        },
        "key": {
            "kid": identity["keys"]["device_signing_key"]["kid"],
            "alg": identity["keys"]["device_signing_key"]["alg"],
            "public_key_b64": identity["keys"]["device_signing_key"]["public_key_b64"],
        },
        "seal": None,  # filled below
    }

    # Seal: sha256 over canonical JSON WITH self_signature included
    seal = "sha256:" + sha256_hex(canonical_json_bytes(identity))
    atomic_write_text(seal_path, seal + "\n", mode=0o600)
    public_view["seal"] = seal
    atomic_write_text(pub_path, json.dumps(public_view, sort_keys=True, indent=2) + "\n", mode=0o644)

    # Re-verify
    loaded = load_existing_identity(identity_path) or {}
    if not verify_self_signature(loaded):
        print("ERROR: Post-write self-signature verification failed (unexpected).", file=sys.stderr)
        return 6

    if args.print:
        print(identity_path.read_text(encoding="utf-8"))

    print(f"OK: Bootstrapped identity at {identity_path}")
    print(f"    Private key: {sk_path} (mode 0400 expected)")
    print(f"    Seal:        {seal_path}")
    print(f"    Public:      {pub_path}")

    # Report TPM trust_anchors that were captured
    anchors = unsigned_identity.get("trust_anchors") or []
    if anchors:
        print(f"    TPM anchors: {len(anchors)} captured")
        for a in anchors:
            print(f"      [{a.get('role','')}] {a.get('handle','')} -> {a.get('pubkey_sha256','')}")
    else:
        print("    TPM anchors: none captured (tpm2-tools not installed or handles not provisioned)")

    # Best-effort: emit a chain-I receipt for the provisioning event
    emit_provisioning_receipt_best_effort(base, identity_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
