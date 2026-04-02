# Aevum RRP v0.1.1 Reference Implementation

Aevum RRP is a reference implementation of a receipt-based event protocol that produces a cryptographically verifiable chain of device-bound events with enforced continuity and explicit provenance.

## What it proves

- Event lineage integrity
- Device-bound authorship (Ed25519)
- Chain continuity or explicit break
- Detectable divergent lineage, classified before generic gap errors

## What it does not prove

- Truth of events
- Trustworthiness of inputs
- Absence of host compromise
- Secure time or TPM attestation

## Quick start

```bash
cd refimpl/rrp_v0_1
./run_demo.sh
```

Expected terminal outcomes:

```text
VALID
INVALID
GAP_DETECTED
FORK_DETECTED
```

## Notes

- Signature verification is real in v0.1.1 using Ed25519.
- TPM binding, anti-rollback, and anchoring are future work.
