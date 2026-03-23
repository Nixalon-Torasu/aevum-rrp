# Implementation Notes — RRP v0.1.1

- The reference implementation uses Python and `cryptography` for Ed25519 signing and verification.
- The verifier emits exactly one terminal result and stable exit codes.
- `pcr_snapshot` is mock by default and exists to preserve schema shape for future TPM integration.
- Test mutation scripts intentionally do not recompute signatures or hashes; verifier failure is the expected result.

- The verifier classifies forks before gaps so divergent lineage is not collapsed into a generic continuity failure.
