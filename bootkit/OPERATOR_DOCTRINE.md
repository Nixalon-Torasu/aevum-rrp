# Aevum Bootstrap Operator Doctrine (v1)

This package set delivers a **minimum-viable “printer in the void”**: a workstation-side receipt engine that anchors itself to hardware time and attestation (TPM), then continuously emits verifiable receipts about its own posture and bounded observability surfaces.

This doctrine tells an operator **how to safely update/apply**, and what the four operating modes mean.

## Mental model (where we are)
- **Aevum-Workstation = the printer.** It prints append-only receipts and preserves them as the evidence library.
- **The tether points today:** system clock + monotonic clock + TPM state (PCRs/eventlog) + OS audit surfaces.
- **Depth right now:** “root observability” only. We are hardening correctness, continuity, and recoverability before expanding to deeper I/O mapping.

## The 3-zip update pipeline
You will typically handle **three artifacts together**:

1) **Bootkit (external boot kit)** — base operator tooling + transfer “airlock” conventions.
2) **Workstation Bootstrap** — the workstation receipt spine (services, tools, schemas, policies).
3) **GitOps bundle** — controlplane repo + update/apply timers and policies.

### Operator procedure
1. Copy the **three ZIPs** into the airlock folder:
   - Preferred: `/srv/aevum-hot/transfer/airlock/`
   - Compatible: `/srv/aevum-hot/transfer/bootstrap/`
2. Run:
   - `sudo aevum-bootstrap-update`
     - This validates, classifies, and stages a *bundle manifest* (no system changes).
   - `sudo aevum-bootstrap-apply`
     - This applies the staged bundle in the correct order (Bootkit → Bootstrap → GitOps).

If `update` refuses to stage, nothing changed on the host. Fix the error, then retry.

## Mode state machine
Aevum has four high-level modes. The mode controls **what actions are permitted**.

- **install**
  - bring-up mode; permissive; bootstrap/install allowed; firewall not forced locked.
- **maintenance**
  - controlled operator work; update/apply allowed; diagnostics allowed.
- **locked**
  - steady-state hardened mode; default-deny egress; updates require signed bundle manifests.
- **estop**
  - emergency stop; Aevum services are stopped/disabled as fast as possible.

Mode is stored at: `/etc/aevum/mode` (simple text value).

Use: `sudo aevum-modectl status|set <install|maintenance|locked|estop>`

## Bundle verification (what “cross-verify” means here)
At update-time, the system builds a **Bundle Manifest** that cross-links:
- each artifact’s declared identity (`AEVUM_ARTIFACT.json`)
- each artifact’s internal manifest (`PACK_MANIFEST.*` where applicable)
- the observed ZIP sha256 and the extracted-tree verification

At apply-time, the bundle manifest is re-verified before any install step runs.

## Design intent: “singularity”
The printer must be **boringly reliable**:
- failures should degrade to “prints less” rather than “bricks the box”
- continuity violations produce explicit seam/scar receipts
- mode changes are explicit, receipted, and reversible (except e-stop, by design)

