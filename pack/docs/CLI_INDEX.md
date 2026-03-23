# Operator CLIs (foundation layer)

## aevum-status
Fast snapshot of TPM/SecureBoot, registry verify, LUKS policy, boot evidence, timechain freshness, and core service status.

- `aevum-status`
- `aevum-status --json`

## aevum-doctor
Deep diagnostic report. Writes artifacts into `/var/lib/aevum/workstation/diagnostics/` by default.

- `aevum-doctor`
- `aevum-doctor --strict`
- `aevum-doctor --no-receipt`
- `aevum-doctor --json`

### RRP liveness check (auto-failure receipt)
Doctor verifies RRP printer daemon liveness by checking:
- `systemctl is-active aevum-rrp-printerd.service`
- `/run/aevum/rrp.sock` exists
- socket accepts a PROTO-correct ping and returns JSON

If liveness fails and receipts are enabled, doctor automatically mints a **warn** receipt:
`"RRP printer liveness failure"` with subsystem details.



### RRP liveness failure evidence
If the printer is not live, `aevum-doctor` writes an evidence artifact:
- `<outdir>/rrp_printer_failure_<host>_<ts>.json`
The auto-failure receipt includes `evidence_sha256` and `evidence_path`.


### RRP strict policy
`/etc/aevum/registry/rrp_policy.json` may include:
- `require_printerd_live` (bool): if true, `aevum-doctor --strict` treats printer not-live as a CRITICAL failure.
- `printerd_unit` (string): systemd unit name.


## aevum-recover
Scan and (optionally) truncate only tail-partial writes in receipt logs. Writes evidence artifacts and mints a recovery receipt.

- `aevum-recover --strict`
- `aevum-recover --repair --strict`


## aevum-selftest
Installed smoke test (or sandbox) for determinism. Writes report artifact and mints a receipt.

- `aevum-selftest --strict`
- `aevum-selftest --sandbox --strict`


## aevum-egress-pin
Observe-only helper that collects recent firewall/nft-related log hints and writes an artifact + receipt. Does NOT modify firewall.

- `aevum-egress-pin --since 2h`


## aevum-pack-guard
Runs the conical guard for an unpacked pack directory.

- `aevum-pack-guard /opt/aevum-pack`
