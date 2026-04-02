#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y python3 python3-venv git

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install ansible ansible-lint

echo "Ready. Run: make apply"
