# Bundle Manifest + Compatibility Contract (V1)

This release introduces a **bundle-aware** update/apply pipeline. The operator drops a *set* of artifacts (bootkit + workstation bootstrap + gitops) into an airlock; the system stages a bundle manifest; then applies the bundle atomically.

## Terminology
- **Artifact**: one ZIP file of a specific type (bootkit/bootstrap/gitops).
- **Bundle**: exactly one of each artifact type that share a `bundle_id`.

## Artifact Identity File
Each ZIP MUST contain `AEVUM_ARTIFACT.json` at the ZIP root:

```json
{
  "schema_id": "AEVUM:ARTIFACT:V1",
  "artifact_type": "bootstrap",
  "artifact_version": "v2_93",
  "bundle_id": "AEVUM_BUNDLE_20260209",
  "bundle_seq": 2026020901,
  "compat": {
    "requires": {
      "bootkit_min": "v0_8",
      "bootstrap_min": "v2_93",
      "gitops_min": "v2_92"
    },
    "allows": {
      "gitops_max_delta_minor": 1
    }
  },
  "created_at": "2026-02-09T06:41:48Z"
}
```

## Bundle Manifest
`aevum-bootstrap-update` stages a directory:
`/srv/aevum-hot/bootstrap/stage/<bundle_id>__<timestamp>/`

It writes `BUNDLE_MANIFEST.json`:

- sha256 of each ZIP
- parsed artifact identity fields
- verification results for internal pack manifests
- mode policy requirements (e.g., signed-only in locked mode)

## Compatibility Rules (V1)
- All three artifacts MUST share the same `bundle_id`.
- In **locked** mode:
  - `BUNDLE_MANIFEST.json` MUST be signed (future extension; currently enforced as “signature required” if enabled).
- In **install/maintenance** modes:
  - unsigned bundle manifests are allowed but logged.

## Mode gate behavior
- `update` is always non-destructive (staging only).
- `apply` is gated:
  - `estop` ⇒ refuse apply
  - `locked` ⇒ require signatures (configurable)
  - `install/maintenance` ⇒ allowed

## Security note
A bundle is only as trustworthy as:
- your airlock discipline (what files you allow into the folder),
- your signature verification policy (locked mode),
- and your root-of-trust configuration (TPM/secure boot).

