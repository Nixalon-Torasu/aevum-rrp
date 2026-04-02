#!/usr/bin/env bash
set -euo pipefail

# Systemd gate: verify that all ExecStart/ExecStartPre targets referenced by Aevum unit files exist.
#
# Modes:
#   AEVUM_SYSTEMD_GATE_MODE=pack   -> check the unit files shipped in this pack and map absolute paths into the pack tree
#   AEVUM_SYSTEMD_GATE_MODE=system -> check the unit files installed in /etc/systemd/system and verify executables exist on the host
#
# In pack mode, an ExecStart absolute path is considered satisfied if it exists either:
#   - inside the pack at ${PACK_ROOT}${path}
#   - or already on the host at ${path}
#
# This prevents false failures on fresh installs where the files have not been installed yet.

MODE="${AEVUM_SYSTEMD_GATE_MODE:-pack}"
ALLOW_MISSING="${ALLOW_MISSING:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${MODE}" == "pack" ]]; then
  UNIT_DIR="${AEVUM_UNIT_DIR:-${PACK_ROOT}/systemd}"
else
  UNIT_DIR="${AEVUM_UNIT_DIR:-/etc/systemd/system}"
fi

FAIL=0

log(){ echo "$*"; }

# Extract the first token of an ExecStart-like value (strip leading '-' and handle quotes minimally).
first_token() {
  local s="$1"
  # Drop leading '-' (ExecStart may begin with '-' to ignore failures)
  s="${s#-}"
  # Trim leading whitespace
  s="${s#"${s%%[![:space:]]*}"}"
  # If quoted, strip the leading quote and take up to the next matching quote
  if [[ "$s" == \"*\" ]]; then
    s="${s#\"}"
    s="${s%%\"*}"
  elif [[ "$s" == \'*\' ]]; then
    s="${s#\'}"
    s="${s%%\'*}"
  fi
  # First token by whitespace
  echo "${s%%[[:space:]]*}"
}

check_exec() {
  local bin="$1"
  [[ -z "$bin" ]] && return 0

  # bare command (no slash): must exist on host PATH
  if [[ "$bin" != /* ]]; then
    if command -v "$bin" >/dev/null 2>&1; then
      log "OK: command present: $bin"
      return 0
    fi
    if [[ "$ALLOW_MISSING" == "1" ]]; then
      log "WARN: missing command: $bin"
      return 0
    fi
    log "FAIL: missing command: $bin"
    FAIL=1
    return 0
  fi

  # absolute path
  if [[ "${MODE}" == "pack" && -e "${PACK_ROOT}${bin}" ]]; then
    log "OK: exec present (pack): ${bin}"
    return 0
  fi
  if [[ -e "${bin}" ]]; then
    log "OK: exec present (host): ${bin}"
    return 0
  fi

  if [[ "$ALLOW_MISSING" == "1" ]]; then
    log "WARN: missing executable: ${bin}"
    return 0
  fi
  log "FAIL: missing executable: ${bin}"
  FAIL=1
  return 0
}

[[ -d "$UNIT_DIR" ]] || { echo "ERROR: unit dir not found: $UNIT_DIR" >&2; exit 2; }

# Collect unit files: in pack mode, use ${PACK_ROOT}/systemd/*.service; in system mode, /etc/systemd/system/*.service.
mapfile -t UNITS < <(find "$UNIT_DIR" -maxdepth 1 -type f -name 'aevum-*.service' -print | sort)

if [[ ${#UNITS[@]} -eq 0 ]]; then
  echo "ERROR: no aevum-*.service unit files found under $UNIT_DIR" >&2
  exit 2
fi

for unit in "${UNITS[@]}"; do
  # Parse ExecStart and ExecStartPre lines.
  while IFS= read -r line; do
    [[ "$line" =~ ^ExecStartPre= ]] || [[ "$line" =~ ^ExecStart= ]] || continue
    val="${line#*=}"
    bin="$(first_token "$val")"
    check_exec "$bin"
  done < "$unit"
done

if [[ "$FAIL" -ne 0 ]]; then
  echo "ERROR: systemd gate failed (MODE=${MODE})." >&2
  exit 1
fi

echo "OK: systemd gate passed (MODE=${MODE})."
