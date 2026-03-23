# Aevum Receipt Request Protocol (RRP) — Local STRICT
**Canonical ID:** AEVUM:PROTO:RRP:LOCAL_STRICT:V1_0  
**Version:** 1.0.0  
**Date:** 2026-02-04  
**Status:** Normative (Implementation-grade)  
**Audience:** Engineers implementing Aevum-Workstation (printer) and Aevum-Core (requester)

## 0. Purpose
RRP lets **Aevum-Core** request minting of receipts without granting it write authority over the receipt ledger.
Only **Aevum-Workstation** writes/signs/anchors receipts.

## 1. Core Principle
**Core can propose; Workstation can seal.**

## 2. Transport
Local-only **Unix Domain Socket (UDS)**:
- Socket path: `/run/aevum/rrp.sock`
- Owner: `root:aevum-printer`
- Mode: `0660`
- Core client must be in group `aevum-core`.

## 3. Canonicalization and Signature Scope
All request/response objects are canonicalized as UTF-8 JSON bytes:
- `sort_keys=true`
- `separators=(",",":")`
- `ensure_ascii=false`

### 3.1 Signed bytes (ReceiptRequest)
Workstation verifies an Ed25519 signature over the canonicalized JSON of `ReceiptRequest` **excluding** the `sig` field.

### 3.2 Signed bytes (ReceiptResult)
Workstation signs `ReceiptResult` with the **Workstation device Ed25519 key** over the canonicalized JSON excluding `workstation_sig`.

## 4. Message Types
### 4.1 ReceiptRequest
Fields (required unless stated):
- `proto`: `"AEVUM:PROTO:RRP:LOCAL_STRICT:V1_0"`
- `req_id`: UUIDv7 string
- `client_id`: stable client label (must exist in core client allowlist registry)
- `ts_client_utc`: ISO-8601 UTC
- `ttl_ms`: integer (request validity window)
- `nonce_b64`: base64(32 bytes)
- `idempotency_key`: hex string (sha256 recommended)
- `receipt_class`: bounded enum (policy-controlled)
- `component`: string (used for TPM-sign allowlists and policy decisions)
- `claims`: small structured map (bounded by size policy)
- `pointers`: list of `{ref_type, ref, hash}`
- `sig`: base64(Ed25519 signature) over canonical request bytes excluding `sig`

### 4.2 ReceiptAck
- `status`: `accepted|rejected`
- `req_id`
- `reason` (optional)

### 4.3 ReceiptResult
- `status`: `minted|failed`
- `req_id`
- `receipt_event_hash` (on minted)
- `receipt_path` (on minted, best-effort)
- `timechain_hint` (best-effort: last known timechain hash at mint)
- `workstation_sig` (base64 Ed25519 signature, excludes this field)

## 5. Policies (Workstation-enforced)
- Allowlisted `client_id` and `client_pubkey` registry.
- Allowed `receipt_class` per client role.
- Rate limit: `max_requests_per_sec`.
- Max request size.
- Max pointers.
- Optional per-receipt TPM signing remains governed by TPM receipt signing policy (allowlist+rate limit).

## 6. Non-gating
If RRP is unavailable, the system still runs. RRP is an interface, not a boot dependency.


## 7. Registry binding (STRICT)
Every receipt minted via RRP MUST embed the currently sealed registry manifest digest (device-bound):
- `registry_manifest_digest`
- `registry_manifest_sig_ed25519_sha256`
- optional `registry_manifest_sig_tpm_sha256`

If the manifest is missing or unsealed, RRP minting fails.
