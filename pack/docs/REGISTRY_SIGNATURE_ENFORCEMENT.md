# Registry Signature Enforcement (Device-Bound) — STRICT

This workstation uses a **device-bound registry manifest** to prevent silent drift in `/etc/aevum/registry`.

Artifacts:
- `/etc/aevum/registry/REGISTRY_MANIFEST.json`
- `/etc/aevum/registry/REGISTRY_MANIFEST.sig.ed25519.b64`
- Optional: `/etc/aevum/registry/REGISTRY_MANIFEST.sig.tpm_p256_plain.b64`

Sealing:
- `/opt/aevum-tools/bin/aevum-registry-seal`

Verification:
- `/opt/aevum-tools/bin/aevum-registry-verify --strict`

Strict boot:
- Core services (TimeChain, RRP) require `aevum-registry-verify --strict` to pass before starting.

This binds receipts to the *exact* registry state in effect on the device.
