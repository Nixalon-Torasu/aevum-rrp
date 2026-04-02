# Hardware Inventory Receipts

`aevum-hw-inventory` captures a bounded hardware snapshot and mints a receipt with a pointer to the snapshot JSON.

- Snapshot stored under: `/var/lib/aevum/workstation/hw/`
- Receipt includes: `inventory_sha256`, `inventory_path`, plus small hints (CPU/mem).

This provides a stable mapping surface for CPU/RAM/GPU identity for later KG/DAG indexing by Aevum-Core.
