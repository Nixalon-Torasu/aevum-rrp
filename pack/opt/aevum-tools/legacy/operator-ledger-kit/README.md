# Legacy Operator Ledger Kit (Optional)

This is the older, *human-signed* operator ledger:

- receipts → `.leaf` → SSH signature (`ssh-keygen -Y sign`) → 1-minute blocks → `chain.log`
- default storage: `/var/lib/aevum/ledger/*`

It is **separate** from the v2 workstation receipt rails under `/var/lib/aevum/workstation/*`.

Why keep it?
- Extremely readable "human.md" pages per minute
- Operator attestation using your personal SSH key (good for audits)
- Great for Git gating workflows

How to use (optional)
1) Make sure you have an SSH signing key and allowed_signers:
   - `ssh-keygen -t ed25519 -f ~/.ssh/aevum_ledger_ed25519 -C "aevum-ledger" -N ""`
   - `mkdir -p ~/.config/aevum-ledger`
   - `printf "torasu %s
" "$(cat ~/.ssh/aevum_ledger_ed25519.pub)" > ~/.config/aevum-ledger/allowed_signers`

2) Install the kit (manual copy), *or* just run it in-place from here:
   - `sudo /opt/aevum-tools/legacy/operator-ledger-kit/aevum-ledger-finalize`
   - ` /opt/aevum-tools/legacy/operator-ledger-kit/aevum-receipt note "..." component=... result=pass`

Set `AEVUM_STACK_DIR=/opt/ai-stack` if your controlplane repo is still at /opt/ai-stack.
