# Group H - USB storage (branch i-usb)
Current step: first version of USB stick support written and compiling; waiting to test it in a VM (the Linux helper (WSL) on this laptop is not responding at the moment)
Works so far:
- USB driver code for USB sticks (Bulk-Only Transport + SCSI commands) and USB hubs, compiles (not yet tested)
- kernel side: USB disks get their own service number next to the keyboard/mouse one; a "usbdisk" test command in the Hydra shell
Next: boot a test VM with a virtual USB stick and run "usbdisk list" / "usbdisk test 0"
