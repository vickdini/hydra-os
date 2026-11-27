# Plan: Hydra Live as a diagnostic and rescue stick (like Hiren's BootCD)

*Written 2026-11-27. Status: **parked**. The user wants it later. The order agreed on 2026-11-27 is: finish wave 11 (11-C fixes), then FreeBSD (wave 12), then this.*

## Goal

The live Hydra USB stick should be able to fully diagnose a PC, the way Hiren's BootCD does: hardware inventory, memory test, disk health, temperatures and stress tests, data recovery, backup, Windows repair, malware scan, network diagnostics, and secure wipe.

## The key constraint

Hydra runs Linux programs but is not a Linux kernel. The rescue programs themselves are ordinary Debian packages installed into the live image, so they are cheap. The real work is the kernel interfaces those programs expect for reaching the hardware. In the code as of 2026-11-27, Hydra has:

| Interface | State |
|---|---|
| SATA disks (AHCI), USB disks | present: the NUC's Samsung 840 EVO and the USB stick were seen |
| FUSE | partial support |
| EFI variables | present |
| SMART / ATA pass-through (`SG_IO`, `HDIO_DRIVE_CMD`) | missing |
| NVMe (driver and admin ioctls) | missing: most PCs from about 2016 on boot from NVMe |
| Temperature/fan sensors (`/sys/class/hwmon`, coretemp, ACPI thermal zones) | missing |
| DMI tables (`/sys/firmware/dmi/tables`) | missing |
| USB device tree (`/sys/bus/usb`, `/dev/bus/usb`) | missing |
| SMBus (i801) for memory-module details | missing |
| Packet capture (`AF_PACKET`) for Wireshark and nmap | barely started |

## What the stick offers, mapped from Hiren's BootCD

| Area | Hiren's (Windows tools) | Hydra Live (Linux equivalents) | Hydra work needed |
|---|---|---|---|
| Memory test | MemTest86 | **Memtest86+** as its own start-menu entry: it runs instead of Hydra, the only way to test all memory. **memtester** inside Hydra for a quick test. | Small: add it to the ESP and the start menu |
| Hardware info | HWiNFO, CPU-Z | **inxi, lshw, hwinfo, dmidecode, lspci, lsusb**, KDE Info Center, plus a "Hydra hardware report" saved to one file | Medium: DMI tables, PCI and USB device lists, a complete `/proc/cpuinfo` |
| Temperatures, fans, stress test | HWiNFO, Prime95, OCCT | **lm-sensors, s-tui, stress-ng**, KDE System Monitor | Medium: a temperature service (CPU thermal MSRs, PCH thermal, ACPI thermal zones) exposed as hwmon; System Monitor's CPU reading fixed |
| Disk health | CrystalDiskInfo, HD Tune, Victoria | **smartmontools + GSmartControl, nvme-cli, hdparm, badblocks**, KDiskMark, fio | Medium-large: ATA pass-through in ahci-driver and usb-driver (SAT), NVMe admin commands, drive identify commands |
| NVMe SSDs | built into Windows | | **Large: a new NVMe driver** |
| Partitions and filesystems | partition managers | **GParted, KDE Partition Manager**, parted, gdisk | Medium: raw access to whole disks and partitions, `BLKRRPART`, device-list refresh |
| Reading other disks | built into Windows | **ntfs-3g**, FAT, exFAT, ext4, BitLocker via **dislocker**, LUKS via cryptsetup | Medium: mount through FUSE; foreign disks mount **read-only by default** |
| Data recovery | Recuva, TestDisk, PhotoRec | **TestDisk, PhotoRec, ddrescue**, ext4magic | Small once raw disk access works |
| Backup and cloning | Macrium, AOMEI | **partclone, fsarchiver**, a simple "back up this disk to an image" helper | Small to medium |
| Windows repair | NT password reset, registry editors | **chntpw** (reset or unlock local accounts), **hivex/reged**, boot-entry repair with **efibootmgr** | Small: needs NTFS mounting |
| Malware scan | offline antivirus | **ClamAV** with a signature update at boot when online; scans a read-only mounted Windows disk | Small |
| Network | browser, network tools | Firefox (works since NUC run 16), **nmap, mtr, iperf3, ethtool**, Wireshark, a speed test (`hydra-nettest` exists) | Medium: `AF_PACKET`/raw sockets, NIC statistics through ethtool ioctls |
| Firmware | BIOS tools | **efibootmgr**, an EFI variable viewer, fwupd (information only at first) | Small |
| Secure wipe | disk wipers | **nwipe**, ATA secure erase, NVMe sanitize | Small, behind a clear warning screen |

**Wine is no help here.** CPU-Z, HWiNFO and CrystalDiskInfo load their own Windows kernel drivers to reach the hardware, so they cannot run under Wine. The Linux tools above cover the same ground.

## The user's view

- **Diagnostics launcher** on the desktop, with categories: Hardware, Disks, Memory, Recovery, Windows repair, Network.
- **One-click "Full checkup":** hardware inventory, SMART health of every disk, temperatures, a short stress test, a network test and a quick memory test. It writes one readable report, saved to a USB disk if one is chosen and also written to the boot log.
- **Safety:**
  - Every tool that can change a disk (partitioning, wiping, the password reset) says so, names the disk and asks before running.
  - The internal disks are never written unless the user chooses a "change" action.
  - Foreign filesystems mount read-only by default.

## Phases (at most 2 agent groups at once, per the credit budget)

| Phase | Content | Size |
|---|---|---|
| D1: platform | raw disk and partition access, SMART pass-through (SATA and USB), DMI/PCI/USB device information, `/proc/cpuinfo` | ~4–5 agent-days |
| D2: sensors and NVMe | the temperature service (hwmon), the NVMe driver (identify, I/O, admin/SMART), `AF_PACKET` | ~5–6 agent-days |
| D3: tools and image | packages, the Memtest86+ entry, foreign-disk mounting (NTFS, BitLocker), the launcher, the Full checkup report, the safety prompts; QEMU tests with emulated NVMe and SATA disks and sensors | ~4 agent-days |
| D4: real hardware | one or two stick runs on the user's NUC | the user's time + ~1 day |

**Total:** about 13–16 agent-days, roughly one wave with 2 groups in parallel.

**Stick size:** the image grows by about 1.5 GB, from 6.7 to about 8.2 GB. The user's 128 GB stick has plenty of room. The copy-to-RAM live mode from the to-do list becomes less attractive on small-memory PCs.

## Open decisions for the user, when this is scheduled

1. **Wi-Fi:** the user's adapter is a TP-Link Archer T2UB Nano (RTL8821CU, about 6–8 agent-days by itself; see the plan's "Alongside the waves" list). Do it in the same wave, or separately?
2. **Windows repair tools** (password reset, registry editing): include them, behind the warning prompt?
3. **Split or whole:** do the cheap parts first (Memtest86+, the packages, hardware info), then NVMe and the sensors?

## Related

- `docs/microkernel-plan.md`, "Alongside the waves": the Wi-Fi driver and the copy-to-RAM live mode.
- `docs/nuc-checklist.md`: how the user runs a stick on the NUC.
- The NVMe driver is also needed for Hydra to install on most modern PCs.
