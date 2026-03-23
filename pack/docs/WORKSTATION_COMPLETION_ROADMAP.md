# Aevum-Workstation Completion Roadmap

**Pack baseline:** v2_70

This is the “finish line” definition for the workstation foundation layer and the checklist to reach it.

## Boundary

The Aevum-Workstation foundation stops at **facts and commitments**:

- Append-only receipt logs (JSONL) per chain (T/I now; others later).
- Content-addressed payload store (`sha256`-named JSON artifacts).
- Per-second TimeChain blocks (1Hz) that commit to other chains via bounded roots/cursors.
- Boot/TPM/UKI/LUKS evidence artifacts + hashes.
- Strict registry signature enforcement for anything treated as policy/registry.

Everything above that (DAG/canopy, optimization, inference, UI) belongs to **Aevum-Core**.

## “Complete” means (Year‑1 definition)

A fresh Ubuntu 24.04 Server (minimal) install can run one script and end up with:

1. **Pack integrity verified** (hash manifest + conical guard).
2. **Workstation identity created** (sealed keys, stable machine identifier).
3. **Registry sealed + strict enforcement on** (no unsigned policy drift).
4. **TimeChain running** (1 block/sec) and anchored to identity; TPM signature best-effort.
5. **Receipt printer running** (RRP daemon) and reachable.
6. **Operator tools available** (`status`, `doctor`, `recover`, `selftest`, `verify`).
7. **Recovery deterministic** for tail truncation/partial writes (evidence + receipt).

## Gates and pass criteria

### Gate A — Pack integrity + conicality

From the unpacked repo root:

- `bash gitops/verify_pack.sh`
  - PASS: `PACK_MANIFEST.sha256` matches
  - PASS: conical guard confirms all required paths exist

### Gate B — Identity + registry

After install (or in sandbox):

- `aevum-status --json`
  - identity: present
  - registry: sealed / verified
- `aevum-registry-verify --strict`
  - PASS

### Gate C — TimeChain continuity

- `systemctl status aevum-timechain --no-pager`
  - active
- `aevum-verify --base /var/lib/aevum/workstation --chain T --identity /var/lib/aevum/workstation/identity/identity.json`
  - PASS

### Gate D — RRP printer liveness

- `systemctl status aevum-rrp-printerd --no-pager`
  - active
- `aevum-rrp-smoketest`
  - PASS

### Gate E — Recovery + selftest

- `aevum-recover --strict`
  - PASS (reports written)
- `aevum-selftest --sandbox --strict`
  - PASS (identity + 2 time blocks + 1 receipt + verify)

## Operator CLIs you should rely on

- `aevum-status` — machine snapshot/status summary
- `aevum-doctor` — strict diagnostics, emits evidence receipts on failure
- `aevum-verify` — verifies hash-chain + signatures for a given chain log
- `aevum-verify-continuity` — continuity checks (strict mode recommended)
- `aevum-recover` — detects/repairs tail truncations (evidence + receipt)
- `aevum-selftest` — sandbox or installed smoke test (evidence + receipt)
- `aevum-egress-pin` — observe-only egress hints to help build allowlists (no firewall modification)
- `aevum-firewallctl` — set baseline firewall mode (install vs locked)

## Milestones to reach “foundation complete”

### M1 — Release coherence (no drift)
- All version strings match pack version.
- No scripts reference missing commands.
- Installer leaves a deterministic “installed components list”.

### M2 — Custody-chain continuity
- TimeChain includes registry binding fields consistently.
- Every second has a stable identity anchor; TPM signature best-effort but verifiable when present.
- Strict verifier can produce PASS/FAIL without ambiguity.

### M3 — Deterministic recovery
- Tail truncations are corrected in a single, auditable step.
- Recovery always emits an artifact report + receipt.
- No silent “fixes.”

### M4 — Selftest + golden vectors
- Sandbox selftest passes reproducibly.
- Add golden vectors for verifier + recoverer.

## What is still “future” (belongs in Core, not Workstation)
- DAG/canopy construction and traversal algorithms
- optimization and forecasting
- user interaction semantics (Aevum-User)
- semantic expansion and “non-reduction” enforcement

