#!/usr/bin/env bash
set -euo pipefail
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: not a git repo"
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: worktree not clean. Commit or stash changes first."
  git status --porcelain
  exit 3
fi

echo "OK: worktree clean"
