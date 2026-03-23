# IMA/EVM Minimal (Measure-Only) — Workstation Layer Add-On
**Status:** Implementation-grade (bootstrap add-on)  
**Goal:** Provide *binary-level provenance anchors* without turning the workstation into a self-bricking compliance engine.

## What you get (in Aevum terms)
- **IMA measurement list** = a kernel-generated, append-only record of *which binaries were executed / measured*.
- Aevum-Workstation mints **receipt anchors** over that list (digest + line count + boot id), so Aevum-Core can:
  - ground provenance to the physical machine and its boot epoch
  - avoid “trust me bro” about which executables ran
  - build derived DAG/canopy indexes from stable evidence

## What you do NOT get (yet)
- **Appraisal enforcement** (IMA appraisal can deny execution). That’s powerful but dangerous.
- **EVM xattr integrity** enforcement. Also dangerous without careful rollouts.

This pack is **measure-first**: evidence before control.

---

## Kernel prerequisites
Ubuntu kernels may or may not have IMA enabled. Check:

- `/sys/kernel/security/ima/ascii_runtime_measurements` exists
- `dmesg | grep -i ima` shows IMA initialized

Tool:
- `aevum-ima-status`

---

## Enablement (measure-only)
This pack provides a safe enablement path:
- Adds kernel cmdline parameters through `/etc/default/grub.d/99-aevum-ima.cfg`
- Runs `update-grub`

Recommended parameters (measure-only):
- `ima_tcb`
- `ima_hash=sha256`

Command:
```bash
sudo /opt/aevum-tools/bin/aevum-ima-enable --measure-only
sudo reboot
```

**Why `ima_tcb`?** It enables a reasonable built-in measurement policy (no appraisal).

---

## Snapshot & receipting
We **do not** try to “receipt every instruction.” We take periodic *anchors* of the kernel’s measurement list.

Tool:
- `aevum-ima-snapshot`

What it does:
- reads `/sys/kernel/security/ima/ascii_runtime_measurements`
- computes `sha256` + line count
- writes a small JSON snapshot to:
  - `/var/lib/aevum/workstation/ima/ima_snapshot_<bootid>_<ts>.json`
- mints a receipt referencing the snapshot (pointers-over-payload)

Systemd:
- `aevum-ima-snapshot.timer` (hourly; non-gating)

---

## Verification expectations
- The snapshot receipt includes the **sealed registry manifest digest** (because receiptctl injects it globally).
- The snapshot JSON includes:
  - `boot_id`
  - `kernel_cmdline_sha256`
  - `ima_measurements_sha256`
  - `ima_measurements_lines`

This lets you prove:
- “On boot epoch X, under registry state Y, the IMA measurement list had digest Z.”

---

## Roadmap (hardening order)
1) Measure-only (this pack)
2) Add **daily digest chain** of IMA snapshots (bounded)
3) Controlled appraisal in staged environments
4) Optional EVM integration (xattrs) when ready
