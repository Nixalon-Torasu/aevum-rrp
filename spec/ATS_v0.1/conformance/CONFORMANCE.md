# CONFORMANCE — ATS-v0.1

This document is NORMATIVE.

Vector files are committed by conformance/vectors/manifest.v1.json. The manifest includes per-file hashes:
- sha256 = HASHSTR(H("conformance_file.v1", raw_bytes))

Runner contract:
- aevum conformance --packet <ATS_v0.1 path> --profile <profile-id> [--vector <id>] --format json
- stdout JSON kind: conformance.run.v1
- exit codes follow ATS CLI rules.
