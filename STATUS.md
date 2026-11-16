# Group H - USB storage (branch i-usb)
Current step: testing USB sticks behind a USB hub and unplugging/replugging a stick while the system runs
Works so far:
- a virtual USB stick (USB 3) is recognized as a disk next to the keyboard and tablet (VM, "usbdisk list")
- writing, reading back and comparing data on it works (VM, "usbdisk test": all data matched)
- speed in the VM: reading 128 MiB/s from the USB stick vs 177 MiB/s from the SATA disk
Next: put a whole Hydra pool on a USB stick and boot from it to the KDE login
