# Boot log, start menu and power on real hardware (wave 11, Group H)

Machines without a serial port (the user's NUC) need the log another way. Source:
`src/arch/bootlog.rs`, `src/arch/logring.rs`, `src/fs/fat32.rs`, `src/arch/bootopts.rs`,
`src/arch/bootwords.rs`, `src/arch/acpi_s5.rs`, `src/arch/power.rs`.

## The boot log file

Everything that goes to COM1 (kernel, services, the console's mirror) also goes into a memory
region at a fixed physical address (`PLACES`: 4.25 GiB, then 1.75 GiB, then 768 MiB): a header,
a 1 MiB head (the start of the boot, kept) and a 1 MiB ring (the latest text).

When Hydra started from a GPT partition (stick or installed disk; never from the ISO the test
harnesses boot), that partition gets `\logs\bootNNN.txt`:

1. **Before `ExitBootServices`** the firmware's FAT driver creates the file at its full size
   (2,162,688 bytes of empty lines), deletes the oldest beyond 10, and writes the log so far.
2. **After the takeover** the task `bootlog` finds the file's clusters (read-only FAT32 walk
   through `fs::blockdev`) and rewrites the new part every 20 s. The file's size and the FAT
   never change, so the volume stays consistent.
3. **At power-off / restart** (`power.rs`) a last write with an end line, before the stick
   prompt; then the writer stops.
4. **Kernel panic** (or the pool's disk never came): the screen says so, the machine restarts
   warm after 60 s (the RAM keeps the log), and the next start writes the old log into the old
   boot's file before anything else ("saved by the next start ... after a kernel panic").
   A second panic in a row does not restart again.

On the live stick, the start also copies an installed Hydra's `\logs\boot*.txt` (any other
EFI volume with `\EFI\hydra\hydra.efi` and no `\hydra\live`) into `\logs\disk\`, so one stick
brings every log to Windows. It first connects the firmware's drivers for the mass-storage
controllers on the root PCI bus and the disks (at most 16 each, never every controller), and
copies a file only when its fingerprint differs from the one in `\logs\disk\index.txt`
(written last). Writes after the takeover stay inside the file's clusters and the partition
(checked against the partition's length and the boot sector), and stop if the boot partition
is no longer at the disk index found at boot. The writer's lock is taken with a deadline,
never spun for.

## Start menu and boot words

`bootopts::init` runs first at boot. Words come from the load options, `\hydra\options.txt`
(lines of words, `#` comments) and, when `\hydra\menu` exists (`timeout=N`; the stick: 5 s,
an installed disk: 3 s), a text menu: 1 normal, 2 safe mode
(`safe iommu=off pcid=off cpus=1 verbose`), 3 safe mode without the desktop (`nodesktop`).
New words: `cpus=N` (processors started), `nodesktop`. The menu never waits for ever: keys
already waiting are dropped, special keys (F-keys, arrows) do not stop the countdown, and after
any other key entry 1 starts after 30 s without a key.

## Power

`power::discover` reads the FADT and the DSDT's `\_S5` before `ExitBootServices`. Power-off
writes SLP_TYP|SLP_EN to PM1a/PM1b (asking the firmware for ACPI mode first when SCI_EN is
clear), then the firmware's ResetSystem; QEMU's and VirtualBox's ports (and SMI port 0xB2)
only inside a VM. Restart tries the FADT reset register first. The live stick's "remove the
stick" prompt ends when Enter is pressed or when the stick is gone; a stick pulled before
Restart means no prompt at all.

## Testing in QEMU

`scratch/h/` (not committed): `live.sh` boots an overlay of a stick with this tree's EFI
partition (`build-image.sh espimg`), `inst.sh` runs the installer (`MODE=prompt|wait`),
`disk.sh` boots an installed disk, `esp.sh` reads `\logs` back, `menukey.sh NAME 2` presses a
menu key through QMP. `tools/hydra_run.py --allow-reboot` lets a restart restart the VM
(the panic test).
