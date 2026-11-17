# Group H - USB storage (branch i-usb)
Current step: DONE - final report sent
Works so far:
- a USB stick is recognized as a disk next to the USB keyboard and tablet (VM, "usbdisk list")
- writing, reading back and comparing data works, also for a stick behind a USB hub (VM, "usbdisk test": all data matched)
- unplugging a stick while the system runs: noticed, the other stick keeps working, nothing crashes (VM)
- Hydra with its whole pool on a USB stick: boots, Linux runs, KDE login screen appears, USB tablet works on it (VM, screenshot)
- installing Hydra onto a blank USB stick from inside Hydra (partitions, FAT, kernel, 16 GiB pool image in 208 s) (VM)
- booting a PC from that USB stick alone, with a SATA disk also inside: the system runs from the stick, pool grows to fill it (VM)
- speed in the VM: USB stick reads 128 MiB/s vs 177 MiB/s for the SATA disk
- full regression suite: 72/73 passed; the one failure (smp, a timing check) passed 4 out of 4 times when rerun on the same build
Next: real hardware (the 2014 NUC) - not possible here
