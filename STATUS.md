# Group E - Disks & boot (branch i-disk)
Current step: done (final report sent); all work committed on branch i-disk
Works so far:
- A second disk shows up as /dev/sdb (VM test): lsblk, /dev/sdX nodes, sysfs; the pool's disk /dev/sda is readable but refuses writes (EBUSY)
- sfdisk and sgdisk partition the second disk, the new /dev/sdb1, /dev/sdb2 appear at once; mkfs.vfat, blkid, mtools, dd all work (VM test on IDE; the same test without those tools also passes on SATA/AHCI disks)
- UEFI boot entries: efibootmgr lists, creates "Hydra" and puts it first (VM test)
- Whole hand install in a VM (partition, format, copy kernel, write 16 GiB pool image in ~2.5 min, boot entry), then the VM booted from that disk alone through the new "Hydra" boot entry: the pool was found on partition 2, grew from 16 to 24 GiB, got a new ID once (not again on the next boot), and the KDE login screen came up, also with the disk on a SATA (AHCI) controller like the NUC (screenshot D:\os-e\scratch\e\boot3.png)
- Full regression suite: 74 of 74 tests pass (73 old + the new blockdev test), no errors in the log (run with 2 CPUs, the new limit)
- GPT reader checked by host unit tests; all host tests pass
- Interface notes for the other groups: D:\os-install-shared\LAYOUT.md (section E)
Next: nothing; waiting for the coordinator to merge
