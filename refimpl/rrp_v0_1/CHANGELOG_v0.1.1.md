# Changelog — v0.1.1

- Added real Ed25519 signature verification
- Flattened signature model to `signature` string plus `device_pubkey`
- Added strict verifier outcomes and exit codes
- Added tamper, gap, and fork test scripts
- Updated spec and notes to v0.1.1


## v0.1.2
- verifier now recomputes `event_hash` from `payload` and rejects mismatches
- expanded pytest coverage for valid, gap, fork, device-id mismatch, and event-hash mismatch cases
- added EC/GAP report for the patched reference implementation
