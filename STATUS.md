# Group H - USB storage (branch i-usb)
Current step: waiting in line for a test VM (only 2 VMs may run at once) to boot Hydra with its whole pool on a virtual USB stick
Works so far:
- a virtual USB stick is recognized as a disk next to the USB keyboard and tablet (VM, "usbdisk list")
- writing, reading back and comparing data works, also for a stick behind a USB hub (VM, "usbdisk test": all data matched)
- unplugging a stick while the system runs: the driver notices it, the other stick keeps working, nothing crashes (VM, QEMU device_del)
- speed in the VM: reading 128 MiB/s from the USB stick vs 177 MiB/s from the SATA disk
- host unit tests pass
Next: boot Hydra with the pool on the USB stick (shell, then KDE login screen)
