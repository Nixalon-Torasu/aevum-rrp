# Ubuntu Autoinstall scaffold (external-boot)

This is a scaffold to automate installing Ubuntu 24.04 Server onto the **external SSD**.

Hard safety rule:
- You MUST explicitly set the target disk by **/dev/disk/by-id/**.
  Never auto-pick “largest” or “removable” because it will eventually wipe the wrong disk.

Workflow
1) Boot Ubuntu installer ISO (from USB).
2) Provide a NoCloud seed (USB partition labeled CIDATA) containing:
   - user-data
   - meta-data
3) The installer runs unattended and installs to the specified disk.

Files
- autoinstall/user-data.template.yaml : fill DISK_BY_ID and USERNAME/PW hash.
- autoinstall/meta-data              : NoCloud metadata stub.

Next step for you:
- After you provide hardware + your preferred disk id, we lock the user-data.
