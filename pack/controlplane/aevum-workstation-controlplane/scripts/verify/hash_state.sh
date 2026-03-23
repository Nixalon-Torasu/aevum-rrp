#!/usr/bin/env bash
set -euo pipefail

echo "VERIFY: state hashing"
if [[ -x /opt/aevum-tools/bin/aevum-state-snapshot ]]; then
  /opt/aevum-tools/bin/aevum-state-snapshot
else
  echo "SKIP: /opt/aevum-tools/bin/aevum-state-snapshot not found"
fi
