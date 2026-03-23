AEVUM:POLICY:WORKSTATION_LAYER1:V1

Principle
- Workstation receipts attest what already happened.
- They are not kernel hooks, not governors, and must not block operation.

Posture
- Prefer thin facts (counters, deltas, summaries) over raw logs.
- Prefer non-redundant emission (only on material change or periodic heartbeat).
- Privacy-by-minimization: hash samples when possible.

Firewall
- Default deny.
- Log drops with stable prefixes so they can be receipted after-the-fact.
- Firewall does not depend on receipts; receipts depend on logs.


Container egress allowlist
- Optional mode where only specific docker networks/ifaces/labels may egress during bounded windows.
- Implemented via nft sets populated from docker state.
