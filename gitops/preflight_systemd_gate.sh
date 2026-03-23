#!/usr/bin/env bash
set -euo pipefail

# Aevum Workstation systemd preflight gate
# Purpose: Refuse to enable timers/services if any referenced ExecStart* targets are missing.
#
# Controls:
#   AEVUM_SYSTEMD_GATE=1 (default)  -> gate ON
#   AEVUM_SYSTEMD_GATE=0            -> gate OFF (operator override)
#   AEVUM_ALLOW_MISSING_SYSTEMD_TARGETS=1 -> do not fail (prints FAIL lines but exits 0)

GATE="${AEVUM_SYSTEMD_GATE:-1}"
ALLOW="${AEVUM_ALLOW_MISSING_SYSTEMD_TARGETS:-0}"
UNIT_DIR="/etc/systemd/system"

if [[ "${GATE}" != "1" ]]; then
  echo "WARN: systemd gate disabled (AEVUM_SYSTEMD_GATE=${GATE})."
  exit 0
fi

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

declare -A SEEN=()
UNITS=()

add_unit() {
  local u="$1"
  [[ -n "$u" ]] || return 0
  # normalize: accept bare name or full path
  u="${u##*/}"
  if [[ -z "${SEEN[$u]+x}" ]]; then
    SEEN["$u"]=1
    UNITS+=("$u")
  fi
}

# initial units from args, else discover
if [[ $# -gt 0 ]]; then
  for u in "$@"; do add_unit "$u"; done
else
  while IFS= read -r f; do
    add_unit "$(basename "$f")"
  done < <(find "${UNIT_DIR}" -maxdepth 1 -type f \( -name 'aevum-*.service' -o -name 'aevum-*.timer' \) 2>/dev/null | sort)
fi

# Expand timers -> their service units
for u in "${UNITS[@]}"; do
  if [[ "$u" == *.timer ]]; then
    local_file="${UNIT_DIR}/${u}"
    svc=""
    if [[ -f "$local_file" ]]; then
      svc="$(awk -F= '/^[[:space:]]*Unit=/{svc=$2} END{print svc}' "$local_file" 2>/dev/null || true)"
      svc="$(trim "$svc")"
    fi
    if [[ -z "$svc" ]]; then
      svc="${u%.timer}.service"
    fi
    add_unit "$svc"
  fi
done

FAIL=0

fail() { echo "FAIL: $*" >&2; FAIL=1; }
pass() { echo "PASS: $*"; }

check_exec() {
  local p="$1"
  if [[ ! -e "$p" ]]; then fail "missing executable: $p"; return 0; fi
  if [[ ! -x "$p" ]]; then fail "not executable: $p"; return 0; fi
  pass "exec present: $p"
}

check_file() {
  local p="$1"
  if [[ ! -e "$p" ]]; then fail "missing file: $p"; return 0; fi
  if [[ ! -f "$p" ]]; then fail "not a file: $p"; return 0; fi
  pass "file present: $p"
}

check_cmd_line() {
  local raw="$1"
  raw="$(trim "$raw")"
  [[ -n "$raw" ]] || return 0
  # allow multiple commands separated by ';' (systemd)
  raw="${raw%%;*}"
  raw="$(trim "$raw")"
  # strip systemd prefix characters: -, +, !, @ (ignore failure, run as root, etc.)
  raw="${raw#-}"; raw="${raw#+}"; raw="${raw#!}"; raw="${raw#@}"
  raw="$(trim "$raw")"
  [[ -n "$raw" ]] || return 0

  # naive tokenization (sufficient for our unit style: absolute paths, no quoting)
  read -r -a TOK <<< "$raw" || true
  [[ ${#TOK[@]} -gt 0 ]] || return 0

  local exe="${TOK[0]}"
  if [[ "$exe" == /* ]]; then
    check_exec "$exe"
  fi

  # If invoked via interpreter, check likely script path args too.
  if [[ "$exe" == */python3 || "$exe" == */python3.* || "$exe" == */bash || "$exe" == */sh ]]; then
    local arg
    for arg in "${TOK[@]:1}"; do
      [[ "$arg" == /* ]] || continue
      # Only enforce script-like args (avoid config-only false positives)
      if [[ "$arg" == *.py || "$arg" == *.sh || "$arg" == /usr/local/sbin/* || "$arg" == /opt/aevum-tools/bin/* ]]; then
        check_file "$arg"
      fi
    done
  fi
}

check_unit() {
  local u="$1"
  local f="${UNIT_DIR}/${u}"
  if [[ ! -f "$f" ]]; then
    fail "unit missing from ${UNIT_DIR}: ${u}"
    return 0
  fi

  # Parse ExecStart*, ExecStop*, ExecReload directives
  local line rhs
  while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -n "$line" ]] || continue
    [[ "$line" == \#* ]] && continue

    case "$line" in
      ExecStart=*|ExecStartPre=*|ExecStartPost=*|ExecStop=*|ExecReload=*)
        rhs="${line#*=}"
        rhs="$(trim "$rhs")"
        check_cmd_line "$rhs"
        ;;
      *)
        ;;
    esac
  done < "$f"
}

echo "== Aevum systemd preflight gate =="
echo "units=${#UNITS[@]} gate=${GATE} allow_missing=${ALLOW}"

for u in "${UNITS[@]}"; do
  check_unit "$u"
done

if [[ "$FAIL" -ne 0 ]]; then
  if [[ "$ALLOW" == "1" ]]; then
    echo "WARN: systemd gate detected problems but ALLOW is set; continuing." >&2
    exit 0
  fi
  echo "ERROR: systemd gate failed. Refusing to enable services/timers." >&2
  exit 6
fi

echo "OK: systemd gate passed."
