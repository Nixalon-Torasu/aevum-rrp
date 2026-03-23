#!/usr/bin/env bash
set -euo pipefail

echo "VERIFY: no public listening ports (basic heuristic)"
# Show listeners bound to 0.0.0.0 or :::
# This doesn't prove "no WAN", but it catches common mistakes (published Docker ports).
listeners="$(ss -lntup | awk 'NR==1 || $5 ~ /(^0\.0\.0\.0:|^\[::\]:)/ {print}')"
echo "$listeners"

# Fail if any obvious web ports are open publicly.
if echo "$listeners" | grep -E '(^|:)(80|443)\b' >/dev/null 2>&1; then
  echo "FAIL: Detected public bind on 80/443. This is usually a bug (unless deliberately LAN-only with firewall)."
  exit 1
fi

echo "OK: no obvious public 80/443 listeners"
