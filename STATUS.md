# Group H - USB storage (branch i-usb)
Current step: STOPPED for now - WSL (runs every VM and build) has been frozen since 01:29, so my last fix could not be tested; final report written
Works so far:
- a USB stick is recognized as a disk next to the USB keyboard and tablet (VM, "usbdisk list")
- writing, reading back and comparing data works, also for a stick behind a USB hub (VM, "usbdisk test": all data matched)
- unplugging a stick while the system runs: noticed, the other stick keeps working, nothing crashes (VM, QEMU device_del)
- Hydra with its WHOLE pool on a USB stick (no other disk): boots, Linux runs, files saved, KDE login screen appears, USB tablet works on it (VM, screenshot)
- the USB stick shows up in Linux as /dev/sdc; partitioning (sgdisk), FAT formatting (mkfs.vfat) and copying the kernel onto it (mtools) worked (VM)
- speed in the VM: reading 128 MiB/s from the USB stick vs 177 MiB/s from the SATA disk; Linux writes 48 MB/s on the USB pool
- host unit tests pass; full regression suite 73/73 passed with the USB code merged with Group E's disk work
NOT yet working / not tested:
- copying the 16 GiB pool image from a SATA disk onto the USB stick stalled twice after 5-8 GiB; cause found (kernel scheduling bug with two driver calls at once on two CPUs), fix committed (bba48c0) but NOT tested in a VM yet
- booting a VM from the freshly installed USB stick (the real "live stick" case) - not reached
Next: when WSL is back: rebuild the ISO, rerun the install-to-USB test, boot from the stick, rerun the regression suite
