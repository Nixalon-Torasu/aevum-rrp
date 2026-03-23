Aevum Receipt Printer v0.2 (Year-1 minimum)

What you get
- TimeChain daemon: writes 1 signed TimeBlock per second to /var/lib/aevum/receipts/T.jsonl
- AEO CLI: writes signed Interaction-chain events with AEO payloads (stored separately) to /var/lib/aevum/receipts/I.jsonl
- Payloads stored in /var/lib/aevum/payloads/<sha256>.json (prunable later while keeping receipt commitments)

Prereqs
- Run machine identity bootstrap first (creates /var/lib/aevum/identity/*)
- Python3 + cryptography: sudo python3 -m pip install cryptography

Install
1) Copy scripts:
   sudo install -m 0755 aevum_common.py /usr/local/sbin/aevum_common.py
   sudo install -m 0755 aevum_timechain_daemon.py /usr/local/sbin/aevum_timechain_daemon.py
   sudo install -m 0755 aevum_aeo_cli.py /usr/local/sbin/aevum_aeo_cli.py

   (Or keep them together and call via python3; systemd assumes /usr/local/sbin.)

2) Test one tick:
   sudo /usr/local/sbin/aevum_timechain_daemon.py --once

3) Start daemon:
   sudo install -m 0644 aevum-timechain.service /etc/systemd/system/aevum-timechain.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now aevum-timechain.service

4) Print an AEO receipt:
   sudo /usr/local/sbin/aevum_aeo_cli.py --content "hello world" --context '{"kind":"demo"}'

Notes
- TBV0 uses zeroed chain_roots (upgrade later to TBV1 with real per-second Merkle roots).
- Envelopes are canonical-json hashed + Ed25519 signed.
- Changing canonicalization or fields breaks verification. Add new fields only in new schema_version(s).


v0.2 note
- capture_device_hex and subject_id_hex will be taken from identity.json when present.
