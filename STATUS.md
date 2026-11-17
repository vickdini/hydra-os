# Group H - USB storage (branch i-usb)
Current step: WAITING - WSL (runs all VMs and builds for every group) has been frozen since 01:29; nothing can be tested until it is back. The fix for the stall (a kernel scheduling bug with two driver calls at once on two CPUs) is written, built and committed (bba48c0), not yet tested in a VM
Works so far:
- a virtual USB stick is recognized as a disk next to the USB keyboard and tablet (VM, "usbdisk list")
- writing, reading back and comparing data works, also for a stick behind a USB hub (VM, "usbdisk test": all data matched)
- unplugging a stick while the system runs: noticed, the other stick keeps working, nothing crashes (VM)
- Hydra with its WHOLE pool on a USB stick (no other disk): boots, Linux runs, files written and saved, KDE login screen appears and the USB tablet works on it (VM, screenshot)
- speed in the VM: reading 128 MiB/s from the USB stick vs 177 MiB/s from the SATA disk; Linux writes 48 MB/s on the USB pool
- host unit tests pass; full regression suite 73/73 passed with the USB code merged with Group E's disk work
Next: boot from the freshly installed USB stick (with a SATA disk also in the PC), then hot-plug and speed checks
