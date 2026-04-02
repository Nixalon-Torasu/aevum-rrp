# Aevum Workstation Plan (Core Build File)
This is the descriptive plan. The executable implementation is in:
- `playbooks/` + `roles/` (Ansible)
- `compose/` (Compose stacks)
- `scripts/verify/` and `scripts/attest/` (verification + proof spine)

The plan’s invariants are implemented as:
- filesystem layout role: `roles/aevum_layout`
- change pipeline hooks: `roles/daily_root`
- ingress/egress controller patch + state hashing: `roles/aevum_tools_patch`
- observability: `compose/observability`
- tenant + service stacks: `compose/*`

Keep this file in Git. If reality changes, update the plan and the code together.


## Container egress policy
- Docker bridge forwarding is governed by the Aevum egress forward chain (priority -100, policy drop).
- `aevum-egressctl run` opens BOTH host output and container forward for DNS + HTTP(S) within the window.
