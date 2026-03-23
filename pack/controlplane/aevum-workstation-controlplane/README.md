# Aevum Workstation Control Plane (Executable Skeleton)

This repo turns the workstation plan into something you can **apply** and **verify**.
It is intentionally opinionated and default-safe.

## What this gives you
- Ansible roles that enforce the **Aevum filesystem layout**, baseline packages, and optional hardening hooks
- A Compose stack layout under `/opt/ai-stack` with explicit volumes under `/var/lib/aevum/services/`
- A daily “root receipt” ritual via a systemd timer (hash + sign state)
- Verification scripts that prove: no WAN exposure, compose health, nft state hashed, receipts minted

## Assumptions
- Host: Ubuntu 24.04
- You already have `/opt/aevum-tools` (receipt printer + ingress/egress controllers). This repo can **patch** the known nft comment bug safely.

## Quick start (localhost)
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install ansible

# Apply baseline
ansible-playbook -i inventory/localhost.yml playbooks/site.yml

# Deploy stacks (choose what you want)
sudo make up-observability
sudo make up-core
sudo make up-knowledge
sudo make up-rnd
sudo make up-ai

# Verify
sudo make verify
```

## Edit these first
- `inventory/localhost.yml` variables (paths, enforcement toggles)
- `compose/*/.env` files (domains, passwords, secrets)

## Safety switches (default-safe)
This repo will NOT hard-drop your egress unless you enable it:
- `aevum_enforce_egress_deny: false` (default)
- `aevum_enforce_ingress_lanonly: false` (default)

Flip these to `true` once you are ready.

## Design rule
If it changes the system, it produces a receipt (or at minimum a signed state snapshot).
