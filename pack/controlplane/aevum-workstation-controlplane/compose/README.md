# Compose Layout

These directories are intended to be installed to `/opt/ai-stack`.

Conventions:
- No anonymous volumes
- All data under `/var/lib/aevum/services/<service>/`
- No published ports by default (use ingressctl + reverse proxy)

Install to `/opt/ai-stack`:
```bash
bash scripts/install_compose_layout.sh
```
Then bring up what you want:
```bash
cd /opt/ai-stack/observability && docker compose up -d
```
