# Aevum RRP — OpenSSF Edition

**Receipt-first provenance for systems, events, and AI-adjacent evidence.**

**OpenSSF Edition:** This repo is the trust root, verifier, and receipt engine for the Aevum stack. The workstation is a profile the printer verifies and applies — not an equal sibling.

See [OpenSSF integration](#openssf-integration) below for what changed.

---

Aevum RRP is a protocol and implementation stack for requesting, minting, transporting, and verifying **receipts** about observed events. The goal is simple:

> move from narrative claims to verifiable evidence.

This repository is the public source for the current **RRP spec**, **reference implementation**, **schemas**, **policies**, **test vectors**, and the surrounding **workstation / boot / packaging** machinery used to produce and verify signed release artifacts.

---

## Why this exists

Most software systems can tell you what they *say* happened. Very few can prove what they observed, when they observed it, what policy governed the observation, and whether continuity was preserved across time.

Aevum RRP exists to close that gap.

It is aimed at a world where:
- systems emit machine-verifiable receipts instead of loose logs,
- continuity matters,
- tamper, fork, and gap conditions must be detectable,
- and downstream tooling — including AI systems — should consume **bounded evidence**, not just prose or unverified state.

---

## What this repo contains

This repo is not just a README and a toy script. It includes:

- **RRP reference implementation**
- **protocol/spec material**
- **schemas and policies**
- **test vectors and verification tooling**
- **bootkit / pack / workstation support artifacts**
- **release manifests and signature material**

At the repo root you currently expose directories such as `bootkit`, `pack`, `refimpl`, `scripts`, `systemd`, `tools`, and supporting manifest/security files, which makes this much broader than a simple “bootstrap” repo :contentReference[oaicite:4]{index=4}

The current package also includes:
- `refimpl/rrp_v0_1/SPEC_RRP_v0.1.1.md`
- `refimpl/rrp_v0_1/run_demo.sh`
- example payloads
- schemas such as `rrp_receipt_request.schema.json` and `rrp_receipt_result.schema.json`
- policies under `pack/policies`
- test runners and vectors under `pack/tests` :contentReference[oaicite:5]{index=5} :contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7}

---

## Current status

**Status:** pre-1.0 / active R&D

This is a serious public work-in-progress, not a finished product.

What is already here:
- a protocol direction,
- a reference implementation,
- verification logic,
- schemas and policies,
- release packaging structure,
- and evidence-oriented workflow pieces.

What is not claimed here:
- full production hardening,
- final protocol stability,
- complete documentation coverage,
- or complete install simplicity.

If you are looking for a polished consumer product, this is not that.
If you care about provenance, continuity, attestation, and evidence boundaries, this repo is the right place to start.

---

## Repo map

### `refimpl/`
Reference implementation for the current RRP work, including the spec, verifier, keygen, emitter, demo runner, and tests.

### `pack/`
Release-oriented packaging, schemas, policies, tests, and workstation-facing bundle material.

### `bootkit/`
Bootstrapping and release-key / trust-chain related operator material.

### `scripts/`, `systemd/`, `tools/`
Operational utilities, automation, and verification/build helpers.

### `etc/`, `gitops/`, `os/`
Supporting system configuration, update flow, and install scaffolding.

---

## Suggested reading order

1. Start with the repo root for structure and intent.
2. Read the RRP material under `refimpl/rrp_v0_1/`
3. Inspect the schemas and policies under `pack/`
4. Review the tests and vectors
5. Only then move into workstation / boot / packaging details

That order will save you from confusing the protocol with the surrounding appliance machinery.

---

## What “receipt-first” means here

A receipt, in this context, is not just a log line.

It is intended to be a bounded, policy-shaped, machine-verifiable artifact tied to:
- an observed event,
- an identity context,
- a continuity context,
- and a verification path.

That distinction matters.

A log can be edited, reinterpreted, or divorced from policy.
A receipt is supposed to preserve verification boundaries.

---

## Why the AI angle matters

The strongest strategic angle here is not “yet another logging system.”

It is this:

**Aevum RRP is infrastructure for evidence-bearing machine context.**

That matters for AI because current AI pipelines are weak on provenance. They ingest text, summaries, and claims, but often cannot distinguish:
- observed fact vs inferred narrative,
- intact continuity vs broken history,
- verified evidence vs convenient assertion.

RRP is a step toward feeding systems — including future AI layers — with receipts that are explicit about source, continuity, and verification boundaries.

---

## Security posture

This repository should be treated as a development and research source tree.

Do not assume:
- every artifact in every historical package is publish-clean,
- every generated state file belongs in Git,
- or every release bundle is equivalent to a safe runtime deployment path.

Use signed manifests, verification tooling, and a clean release discipline.
Treat private material, runtime state, and generated debris as hostile to a public repo unless explicitly intended.

See `SECURITY.md` for project security guidance.

---

## Contributing

This project is still being shaped.

Useful contributions are the ones that increase:
- protocol clarity,
- verifier strictness,
- schema precision,
- policy explicitness,
- reproducibility,
- and operator comprehension.

Low-value contributions are cosmetic churn, vague abstractions, and anything that weakens verification boundaries.

If you open an issue or PR, bias toward:
- concrete claims,
- exact failure cases,
- reproducible vectors,
- and bounded language.

---

## Design stance

Aevum RRP takes a hard position:

**If a claim matters, it should survive verification.**

That means this work is biased toward:
- explicit formats,
- continuity checks,
- strict verifier outcomes,
- provenance over narrative,
- and evidence over vibes.

---

## Roadmap direction

Near-term direction includes:
- tightening the public protocol surface,
- improving verifier semantics,
- clarifying schemas and policy boundaries,
- cleaning repo/release separation,
- and making the public documentation strong enough that outsiders can understand the protocol without already knowing the whole Aevum project.

---

## License

Licensed under Apache 2.0.

See `LICENSE`.

---

## OpenSSF integration

Added in this edition:

| File | Purpose |
|---|---|
| `bootkit/bin/aevum-provenance-verify` | Verifies Sigstore signatures, in-toto layout, and SLSA provenance before any apply |
| `etc/aevum/registry/supply_chain_policy.json` | Allowed signers, SLSA floor, Rekor requirement, receipt policy |
| `refimpl/rrp_v0_1/schemas/supply_chain_receipt.schema.json` | Schema for supply chain receipt types |

`aevum-bootstrap-apply` calls `aevum-provenance-verify` before any install step. In `locked` mode, provenance verification is a hard gate. In `install` and `maintenance` modes it runs and logs but does not block.

`aevum-bootstrap-update` now writes a `provenance` section into `BUNDLE_MANIFEST.json` linking the paths to SLSA, in-toto, and Sigstore materials when present.

Supply chain receipts reference OpenSSF materials **by digest only** — pointers over payloads. The combined statement is: *"This workstation profile was built by this verified supply-chain process, and this exact machine with this exact local identity and state accepted and applied it at this point in continuity."*

---

## Final note

This repo is public because the core idea is real enough to expose:
**verifiable receipts as a first-class substrate for continuity, provenance, and machine-readable evidence.**

It is not finished.
It is not pretending to be finished.
But it is no longer vapor.