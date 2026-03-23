#!/usr/bin/env python3
"""
aevum_rrp_printerd.py — Workstation Receipt Request Protocol server (Local STRICT)
"""

import argparse, base64, json, os, pathlib, socket, sys, time, hashlib, sqlite3, subprocess, threading, re, datetime, struct
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except Exception as e:
    print("ERROR: Missing dependency 'cryptography'. Install with: python3 -m pip install cryptography", file=sys.stderr)
    raise

PROTO = "AEVUM:PROTO:RRP:LOCAL_STRICT:V1_0"

def canon_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_json(path: pathlib.Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_sha256(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def registry_manifest_binding(reg_dir: pathlib.Path) -> Dict[str, str]:
    """Return manifest binding fields that must be embedded into minted receipts.

    Requires:
      REGISTRY_MANIFEST.json
      REGISTRY_MANIFEST.sig.ed25519.b64
    Optional:
      REGISTRY_MANIFEST.sig.tpm_p256_plain.b64
    """
    man = reg_dir / "REGISTRY_MANIFEST.json"
    sig_ed = reg_dir / "REGISTRY_MANIFEST.sig.ed25519.b64"
    sig_tpm = reg_dir / "REGISTRY_MANIFEST.sig.tpm_p256_plain.b64"

    if not man.exists() or not sig_ed.exists():
        raise FileNotFoundError("registry manifest not sealed (missing REGISTRY_MANIFEST.json or .sig.ed25519.b64)")

    # digest over canonical JSON (not raw file bytes) to match seal tool semantics
    obj = json.loads(man.read_text(encoding="utf-8"))
    mbytes = canon_bytes(obj)
    mdigest = sha256_hex(mbytes)

    out = {
        "registry_manifest_digest": "sha256:" + mdigest,
        "registry_manifest_sig_ed25519_sha256": "sha256:" + file_sha256(sig_ed),
    }
    if sig_tpm.exists():
        out["registry_manifest_sig_tpm_sha256"] = "sha256:" + file_sha256(sig_tpm)
    return out

def _parse_iso_utc(s: str) -> datetime.datetime:
    # Accept Z suffix
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)

def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def _peer_uid(conn: socket.socket) -> int:
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return int(uid)
    except Exception:
        return -1

def _peer_allowed(conn: socket.socket, policy: Dict[str, Any]) -> bool:
    allow = policy.get("peer_uids_allow") or ["root", "aevum-core"]
    uids = set([0])
    for item in allow:
        if isinstance(item, int):
            uids.add(int(item))
        elif isinstance(item, str):
            if item == "root":
                uids.add(0)
            else:
                try:
                    import pwd
                    uids.add(pwd.getpwnam(item).pw_uid)
                except Exception:
                    pass
    return _peer_uid(conn) in uids

def _enforce_time_bounds(req: Dict[str, Any], policy: Dict[str, Any]) -> Optional[str]:
    ts = str(req.get("ts_client_utc",""))
    if not ts:
        return "missing_ts_client_utc"
    try:
        tsc = _parse_iso_utc(ts)
    except Exception:
        return "bad_ts_client_utc"
    ttl_ms = int(req.get("ttl_ms", 5000))
    skew_ms = int(policy.get("reject_on_clock_skew_ms", 300000))
    now = _utc_now()
    skew = abs((now - tsc).total_seconds() * 1000.0)
    if skew > skew_ms:
        return "clock_skew_reject"
    if now > (tsc + datetime.timedelta(milliseconds=ttl_ms)):
        return "ttl_expired"
    return None

def _nonce_hash(nonce_b64: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        nb = base64.b64decode(nonce_b64.encode("utf-8"), validate=True)
    except Exception:
        return None, "bad_nonce_b64"
    if len(nb) != 32:
        return None, "bad_nonce_len"
    return sha256_hex(nb), None

def _nonce_check_and_record(con: sqlite3.Connection, req: Dict[str, Any], policy: Dict[str, Any]) -> Optional[str]:
    nonce_b64 = str(req.get("nonce_b64",""))
    if not nonce_b64:
        return "missing_nonce_b64"
    nh, err = _nonce_hash(nonce_b64)
    if err:
        return err
    # expire at ts + ttl
    tsc = _parse_iso_utc(str(req.get("ts_client_utc")))
    ttl_ms = int(req.get("ttl_ms", 5000))
    expires = (tsc + datetime.timedelta(milliseconds=ttl_ms)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    # cleanup old
    try:
        con.execute("DELETE FROM rrp_nonces WHERE expires_utc < ?", (now,))
        con.commit()
    except Exception:
        pass
    row = con.execute("SELECT expires_utc FROM rrp_nonces WHERE nonce_hash=?", (nh,)).fetchone()
    if row:
        return "replay_detected"
    con.execute("INSERT OR REPLACE INTO rrp_nonces(nonce_hash, first_seen_utc, expires_utc) VALUES (?,?,?)", (nh, now, expires))
    con.commit()
    return None

class RateLimiter:
    def __init__(self, max_per_sec: int):
        self.max = max_per_sec
        self.lock = threading.Lock()
        self.bucket = {}  # client_id -> (sec, count)

    def allow(self, client_id: str) -> bool:
        now_sec = int(time.time())
        with self.lock:
            sec, cnt = self.bucket.get(client_id, (now_sec, 0))
            if sec != now_sec:
                sec, cnt = now_sec, 0
            if cnt >= self.max:
                self.bucket[client_id] = (sec, cnt)
                return False
            self.bucket[client_id] = (sec, cnt + 1)
            return True

def ensure_dirs(base: pathlib.Path):
    pathlib.Path("/run/aevum").mkdir(parents=True, exist_ok=True)
    (base/"rrp").mkdir(parents=True, exist_ok=True)


def db_open(base: pathlib.Path) -> sqlite3.Connection:
    dbp = base/"rrp"/"rrp.sqlite"
    con = sqlite3.connect(str(dbp))
    con.execute("""CREATE TABLE IF NOT EXISTS rrp_requests (
        req_id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        idem TEXT NOT NULL,
        received_utc TEXT NOT NULL,
        status TEXT NOT NULL,
        receipt_event_hash TEXT,
        receipt_path TEXT,
        error TEXT
    )""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_rrp_idem ON rrp_requests(idem)")
    try:
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rrp_idem_client ON rrp_requests(client_id, idem)")
    except Exception:
        pass
    con.execute("CREATE TABLE IF NOT EXISTS rrp_nonces (nonce_hash TEXT PRIMARY KEY, first_seen_utc TEXT NOT NULL, expires_utc TEXT NOT NULL)")
    con.commit()
    return con

def find_client(clients: Dict[str, Any], client_id: str) -> Optional[Dict[str, Any]]:
    for c in clients.get("clients", []):
        if c.get("client_id") == client_id:
            return c
    return None

def verify_request_sig(req: Dict[str, Any], client_pub_b64: str) -> bool:
    sig_b64 = req.get("sig", "")
    if not sig_b64:
        return False
    tmp = dict(req)
    tmp.pop("sig", None)
    msg = canon_bytes(tmp)
    sig = base64.b64decode(sig_b64)
    pub = base64.b64decode(client_pub_b64)
    pk = Ed25519PublicKey.from_public_bytes(pub)
    try:
        pk.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

def reject(req_id: str, reason: str) -> Dict[str, Any]:
    return {"status": "rejected", "req_id": req_id, "reason": reason}

def workstation_sign_result(result: Dict[str, Any], base: pathlib.Path) -> Dict[str, Any]:
    key_path = base / "identity" / "device_ed25519_sk.pem"
    sk = load_pem_private_key(key_path.read_bytes(), password=None)
    tmp = dict(result)
    tmp.pop("workstation_sig", None)
    sig = sk.sign(canon_bytes(tmp))
    result["workstation_sig"] = base64.b64encode(sig).decode("ascii")
    return result

def mint_receipt(req: Dict[str, Any]) -> Tuple[bool, str, str]:
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if not ctl.exists():
        return False, "", "missing aevum_receiptctl.py"

    req_id = req["req_id"]
    client_id = req["client_id"]
    receipt_class = req.get("receipt_class", "core_request")
    component = req.get("component", "aevum_rrp")
    idem = req.get("idempotency_key", "")

    req_hash = "sha256:" + sha256_hex(canon_bytes({k:v for k,v in req.items() if k != "sig"})).lower()

    kv = {
        "component": component,
        "rrp_proto": PROTO,
        "rrp_req_id": req_id,
        "rrp_client_id": client_id,
        "rrp_receipt_class": receipt_class,
        "rrp_idem": idem,
        "rrp_req_hash": req_hash,
    }

    pointers = req.get("pointers", [])[:8]
    for i, p in enumerate(pointers):
        kv[f"rrp_ptr{i}_type"] = str(p.get("ref_type",""))[:32]
        kv[f"rrp_ptr{i}_ref"] = str(p.get("ref",""))[:256]
        kv[f"rrp_ptr{i}_hash"] = str(p.get("hash",""))[:128]

    claims = req.get("claims", {}) or {}
    n = 0
    for k, v in claims.items():
        if n >= 16:
            break
        if isinstance(v, (str,int,float,bool)) or v is None:
            kk = re.sub(r"[^a-zA-Z0-9_\\-]", "_", str(k))[:32]
            kv[f"rrp_claim_{kk}"] = str(v)[:256]
            n += 1

    args = [sys.executable, str(ctl), "note", f"RRP mint: {receipt_class}"] + [f"{k}={v}" for k,v in kv.items()]
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        return False, "", p.stdout.strip()

    evh = ""
    rpath = ""
    try:
        j = json.loads(p.stdout.strip().splitlines()[-1])
        evh = j.get("event_hash", "")
        rpath = j.get("receipt_path","")
    except Exception:
        pass
    return True, evh, rpath

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum/workstation", help="Workstation instance base")
    ap.add_argument("--socket", default="/run/aevum/rrp.sock")
    ap.add_argument("--policy", default="/etc/aevum/registry/rrp_policy.json")
    ap.add_argument("--clients", default="/etc/aevum/registry/core_clients.json")
    args = ap.parse_args()

    base = pathlib.Path(args.base)

    ensure_dirs(base)
    policy = load_json(pathlib.Path(args.policy))
    clients = load_json(pathlib.Path(args.clients))

    limiter = RateLimiter(int(policy.get("max_requests_per_sec", 20)))
    con = db_open(base)

    sock_path = args.socket
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    os.chmod(sock_path, 0o660)
    s.listen(16)

    print(f"RRP printer listening: {sock_path}", file=sys.stderr)

    while True:
        conn, _ = s.accept()
        with conn:
            if not _peer_allowed(conn, policy):
                conn.sendall(json.dumps(reject("","peer_not_allowed")).encode("utf-8"))
                continue
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > int(policy.get("max_request_bytes", 65536)):
                    conn.sendall(json.dumps(reject("","oversize")).encode("utf-8"))
                    data = b""
                    break
            if not data:
                continue

            try:
                req = json.loads(data.decode("utf-8"))
            except Exception:
                conn.sendall(json.dumps(reject("", "invalid_json")).encode("utf-8"))
                continue

            req_id = str(req.get("req_id", ""))[:128]
            if req.get("proto") != PROTO:
                conn.sendall(json.dumps(reject(req_id, "bad_proto")).encode("utf-8"))
                continue

            client_id = str(req.get("client_id",""))[:128]
            c = find_client(clients, client_id)
            if not c or not c.get("enabled", False):
                conn.sendall(json.dumps(reject(req_id, "client_not_allowed")).encode("utf-8"))
                continue

            if not limiter.allow(client_id):
                conn.sendall(json.dumps(reject(req_id, "rate_limited")).encode("utf-8"))
                continue

            rc = str(req.get("receipt_class",""))[:64]
            if rc not in (c.get("allowed_receipt_classes") or []):
                conn.sendall(json.dumps(reject(req_id, "receipt_class_not_allowed")).encode("utf-8"))
                continue

            if policy.get("require_signature", True):
                pub_b64 = c.get("ed25519_pub_b64", "")
                if not pub_b64:
                    conn.sendall(json.dumps(reject(req_id, "missing_client_pubkey")).encode("utf-8"))
                    continue
                if not verify_request_sig(req, pub_b64):
                    conn.sendall(json.dumps(reject(req_id, "bad_signature")).encode("utf-8"))
                    continue

            ttl_ms = int(req.get("ttl_ms", 5000))
            if ttl_ms <= 0 or ttl_ms > 600000:
                conn.sendall(json.dumps(reject(req_id, "bad_ttl")).encode("utf-8"))
                continue

            idem = str(req.get("idempotency_key",""))[:128]
            cur = con.execute("SELECT status, receipt_event_hash, receipt_path, error FROM rrp_requests WHERE client_id=? AND idem=? ORDER BY received_utc DESC LIMIT 1", (client_id, idem)).fetchone()
            if cur and cur[0] == "minted" and cur[1]:
                ack = {"status":"accepted","req_id":req_id}
                conn.sendall((json.dumps(ack)+"\n").encode("utf-8"))
                res = {"status":"minted","req_id":req_id,"receipt_event_hash":cur[1],"receipt_path":cur[2] or "","timechain_hint":""}
                res = workstation_sign_result(res, base)
                conn.sendall((json.dumps(res)+"\n").encode("utf-8"))
                continue

            received = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            con.execute("INSERT OR REPLACE INTO rrp_requests(req_id, client_id, idem, received_utc, status) VALUES(?,?,?,?,?)",
                        (req_id, client_id, idem, received, "accepted"))
            con.commit()

            ack = {"status":"accepted","req_id":req_id}
            conn.sendall((json.dumps(ack)+"\n").encode("utf-8"))

            ok, evh, rpath_or_err = mint_receipt(req)
            if ok:
                con.execute("UPDATE rrp_requests SET status=?, receipt_event_hash=?, receipt_path=? WHERE req_id=?",
                            ("minted", evh, rpath_or_err, req_id))
                con.commit()
                res = {"status":"minted","req_id":req_id,"receipt_event_hash":evh,"receipt_path":rpath_or_err,"timechain_hint":""}
            else:
                con.execute("UPDATE rrp_requests SET status=?, error=? WHERE req_id=?",
                            ("failed", rpath_or_err, req_id))
                con.commit()
                res = {"status":"failed","req_id":req_id,"error":rpath_or_err,"timechain_hint":""}

            res = workstation_sign_result(res, base)
            conn.sendall((json.dumps(res)+"\n").encode("utf-8"))

if __name__ == "__main__":
    raise SystemExit(main())
