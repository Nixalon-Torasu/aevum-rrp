    #!/usr/bin/env bash
    set -euo pipefail

    echo "[Aevum] RRP smoketest starting..."

    CORE_USER="aevum-core"
    CORE_DIR="/var/lib/aevum/core/identity"
    CLIENT="/opt/aevum-tools/bin/aevum-rrp-client"
    CLIENTS_JSON="/etc/aevum/registry/core_clients.json"

    if ! id -u "${CORE_USER}" >/dev/null 2>&1; then
      echo "ERROR: user ${CORE_USER} does not exist. Installer must create it."
      exit 1
    fi

    sudo -u "${CORE_USER}" mkdir -p "${CORE_DIR}"

    echo "[1/4] Generate keypair (if missing)..."
    if [ ! -f "${CORE_DIR}/core_ed25519_sk.raw" ]; then
      PUB_LINE="$(sudo -u "${CORE_USER}" "${CLIENT}" keygen --dir "${CORE_DIR}" | grep -E '^core_pub_b64=' || true)"
    else
      # regenerate pub from stored pk
      PUB_B64="$(base64 -w0 "${CORE_DIR}/core_ed25519_pk.raw" 2>/dev/null || base64 "${CORE_DIR}/core_ed25519_pk.raw" | tr -d '\n\r')"
      PUB_LINE="core_pub_b64=${PUB_B64}"
    fi

    CORE_PUB_B64="${PUB_LINE#core_pub_b64=}"
    if [ -z "${CORE_PUB_B64}" ]; then
      echo "ERROR: could not obtain core_pub_b64"
      exit 1
    fi

    echo "[2/4] Enable localcore and set pubkey in core_clients.json..."
    python3 - <<'PY' "${CORE_PUB_B64}"
import json, sys
pub = sys.argv[1]
path = "/etc/aevum/registry/core_clients.json"
with open(path, "r", encoding="utf-8") as f:
    obj = json.load(f)
found = False
for c in obj.get("clients", []):
    if c.get("client_id") == "localcore":
        c["enabled"] = True
        c["ed25519_pub_b64"] = pub
        found = True
        break
if not found:
    obj.setdefault("clients", []).append({
        "client_id": "localcore",
        "enabled": True,
        "role": "core",
        "ed25519_pub_b64": pub,
        "allowed_receipt_classes": ["user_request"]
    })
with open(path, "w", encoding="utf-8") as f:
    json.dump(obj, f, indent=2)
    f.write("\n")
print("ok")
PY

    echo "[3/4] Restart printer daemon..."
    systemctl daemon-reload || true
    systemctl restart aevum-rrp-printerd.service
    sleep 1

    echo "[4/4] Request a mint as ${CORE_USER}..."
    sudo -u "${CORE_USER}" "${CLIENT}" request       --receipt-class user_request       --component aevum_core_job       --claim intent="smoketest_mint"       --ptr file,/etc/hostname,sha256:dummy

    echo "[Aevum] RRP smoketest complete."
