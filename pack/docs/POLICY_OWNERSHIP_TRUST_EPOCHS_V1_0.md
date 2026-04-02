# AEVUM Policy: Ownership, Trust Epochs, Operator Actions (V1)

**Schema IDs**
- Ownership map: `AEVUM:OWNERSHIP:PREFIX_OWNERS:V1`
- Operator action record: `aevum.operator.action_record.v1`
- Epoch state: `aevum.operator.epoch_state.v1`

## Non-negotiable design: immutable collectors vs mutable control planes
Aevum MUST NOT attempt to collect strict evidence using collectors that the control plane can silently mutate.
Therefore, ownership is explicit by prefix:

- **Bootkit** owns: `/etc/aevum/mode`, `/etc/aevum/trust/`, and all **destructive operator actions**.
- **Bootstrap** owns: toolchain + systemd units (`/opt/aevum-tools`, `/usr/local/*`, `/etc/systemd/system/aevum-*`).
- **GitOps** owns: policy registry (`/etc/aevum/registry/`, `/etc/aevum/bundles.d/`, `/etc/aevum/egress_profiles.d/`).

Bootstrap MAY seed GitOps-owned policy dirs only if absent; it MUST NOT overwrite them.

## Epochs
Three monotonic epochs exist:
- Trust Epoch (TE): changes on release pubkey rotation.
- Evidence Epoch (EE): changes on receipts wipe/factory reset.
- Identity Epoch (IE): changes on identity wipe.

Epoch files:
- `/etc/aevum/trust/trust_epoch.json`
- `/var/lib/aevum/operator/evidence_epoch.json`
- `/var/lib/aevum/operator/identity_epoch.json`

## Out-of-band operator log (must survive wipes)
All destructive actions MUST append a JSONL record to:
- `/var/lib/aevum/operator/actions.jsonl`

This log MUST NOT be deleted by default wipes/resets. If receipts are down, operator actions MUST still log out-of-band.

## Locked mode signed-pack enforcement
If mode is `locked`, bootkit MUST require valid Ed25519 signatures for pack manifests before apply:
- pubkey: `/etc/aevum/trust/release_pubkey.ed25519.b64`
- manifests: `PACK_MANIFEST.sha256`
- signatures: `PACK_MANIFEST.sig.ed25519.b64` (signature over the manifest bytes)

If cryptography verification tooling is missing in locked mode, bootkit MUST fail closed.
