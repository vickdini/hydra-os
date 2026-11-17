//! ZFS and disks: `zpool`, `zfs`, `disks`, `usbdisk`.

use crate::proto::*;
use crate::sys::*;
use crate::{normalize_path, report, usage, Shell};
use hydra_rt::{print, println};

pub fn zpool(_sh: &mut Shell, args: &[&str]) {
    let sub = args.first().copied().unwrap_or("status");
    let st: PoolStatus = match admin_rec(ADMIN_POOL_STATUS, [0; 4], &[]) {
        Ok(s) => s,
        Err(e) => return report(&e, "zpool"),
    };
    let on_disk = st.on_disk != 0;
    match sub {
        "status" => {
            color(LIGHT_CYAN);
            println!("  pool: hydrapool");
            color(WHITE);
            println!(" state: ONLINE");
            println!("status: The pool is operating normally via the Microkernel ZFS File Server.");
            println!("config:");
            println!("        NAME                 STATE     READ WRITE CKSUM");
            println!("        hydrapool            ONLINE       0     0     0");
            if on_disk {
                println!("          vdev-ata-0         ONLINE       0     0     0 (Persistent ATA Hard Disk)");
            } else {
                println!("          vdev-ramdisk-0     ONLINE       0     0     0 (Volatile RAM Fallback)");
            }
            if st.metrics_valid != 0 {
                color(YELLOW);
                println!("\nPool Properties & Metrics:");
                color(WHITE);
                println!("  - Capacity:           {} MiB", st.total_mib);
                println!("  - Allocated:          {} KiB", st.alloc_kib);
                println!("  - Free Space:         {} KiB", st.free_kib);
                println!("  - Persistence Mode:   {}", if on_disk { "Hardware ATA Sector I/O (ACID Durable)" } else { "In-Memory RAM Buffer" });
                println!("  - Active Uberblock:   TXG #{}", st.txg);
                println!("  - Checksum Algorithm: Fletcher-4 (4x 64-bit words)");
                println!("  - Allocation Policy:  Copy-on-Write (CoW) Merkle Tree");
            }
        }
        "list" => {
            color(YELLOW);
            println!("{:<14} {:>8} {:>8} {:>8} {:>6} {:>6} {:<8}", "NAME", "SIZE", "ALLOC", "FREE", "CAP", "DEDUP", "HEALTH");
            println!("------------------------------------------------------------------");
            if st.metrics_valid != 0 {
                let total_kib = st.total_mib * 1024;
                let cap = if total_kib > 0 { (st.alloc_kib * 100) / total_kib } else { 0 };
                color(WHITE);
                println!("{:<14} {:>7}M {:>7}K {:>7}K {:>5}% {:>6} {:<8}", "hydrapool", st.total_mib, st.alloc_kib, st.free_kib, cap, "1.00x", "ONLINE");
            }
        }
        _ => {
            color(LIGHT_RED);
            println!("Unknown sub-command: '{}'. Usage: zpool <status|list>", sub);
        }
    }
}

pub fn zfs(sh: &mut Shell, args: &[&str]) {
    let Some(&sub) = args.first() else {
        color(LIGHT_RED);
        println!("Usage: zfs <list | snap <id> | cat <path> | write <name> <text...>>");
        return;
    };
    match sub {
        "list" => {
            color(YELLOW);
            println!("{:<24} {:>8} {:>8} {:<16}", "NAME", "USED", "AVAIL", "MOUNTPOINT");
            println!("------------------------------------------------------------------");
            let Ok(a) = admin(ADMIN_DATASET_LIST, [0; 4], &[]) else { return };
            let h: DatasetHeader = read_record(&a, 0).unwrap_or_default();
            let sets = records::<DatasetRecord>(&a, core::mem::size_of::<DatasetHeader>(), h.count as usize);
            for d in sets.iter().filter(|d| d.snapshot == 0) {
                color(LIGHT_CYAN);
                print!("{:<24} ", name_str(&d.name));
                color(WHITE);
                println!("{:>7}K {:>7}K {:<16}", h.allocated / 1024, h.free / 1024, name_str(&d.mount));
            }
            let mut first = true;
            for d in sets.iter().filter(|d| d.snapshot != 0) {
                if first {
                    println!("\nSnapshots:");
                    first = false;
                }
                color(LIGHT_GREEN);
                println!("  {} (Created at TXG #{})", name_str(&d.name), d.txg);
            }
        }
        "snap" | "snapshot" => {
            if args.len() < 2 {
                return usage("zfs snap <dataset_id>");
            }
            match admin_u64(ADMIN_FS_OP, [FS_SNAPSHOT, 0, 0, 0], &[]) {
                Ok(txg) => {
                    color(LIGHT_GREEN);
                    println!("[+] Snapshot created successfully at TXG #{}!", txg);
                }
                Err(e) => {
                    color(LIGHT_RED);
                    println!("[!] Failed to create snapshot: {}", e.text());
                }
            }
        }
        "cat" => {
            let Some(&t) = args.get(1) else { return usage("zfs cat <filename>") };
            match read_file(&normalize_path(&sh.cwd, t), 1024) {
                Ok(d) => {
                    color(WHITE);
                    match core::str::from_utf8(&d) {
                        Ok(s) => println!("{}", s),
                        Err(_) => println!("[Binary content: {} bytes, Fletcher-4 verified]", d.len()),
                    }
                }
                Err(e) => {
                    color(LIGHT_RED);
                    println!("[!] File '{}' not found: {}", t, e);
                }
            }
        }
        // Run by the file server; their output appears on the console
        "selftest" | "verify" | "fsck" => {
            let code = match sub {
                "selftest" => ZFSDIAG_SELFTEST,
                "verify" => ZFSDIAG_VERIFY,
                _ => ZFSDIAG_FSCK,
            };
            let dir = args.get(1).copied().unwrap_or("/");
            let repair = args.get(2).copied() == Some("repair");
            if let Err(e) = admin(ADMIN_ZFS_DIAG, [code, repair as u64, 0, 0], dir.as_bytes()) {
                report(&e, "zfs");
            }
        }
        "write" => {
            if args.len() < 3 {
                return usage("zfs write <name> <content...>");
            }
            let path = alloc::format!("/bin/{}", args[1]);
            let content = args[2..].join(" ");
            match admin_u64(ADMIN_FS_OP, [FS_WRITE, 0, 0, 0], &two(&path, content.as_bytes())) {
                Ok(txg) => {
                    color(LIGHT_GREEN);
                    println!("[+] CoW write committed to ZFS File Server!");
                    println!("    - File: '{}' ({} bytes)", path, content.len());
                    println!("    - Merkle Root Updated to TXG #{}", txg);
                    println!("    - Fletcher-4 Checksum computed & stored");
                }
                Err(e) => {
                    color(LIGHT_RED);
                    println!("[!] CoW write failed: {}", e.text());
                }
            }
        }
        _ => {
            color(LIGHT_RED);
            println!("Unknown sub-command: '{}'. Usage: zfs <list|snap|cat|write|selftest|verify|fsck>", sub);
        }
    }
}

pub fn disks(_sh: &mut Shell, _args: &[&str]) {
    let d: DiskInfo = admin_rec(ADMIN_DISK_INFO, [0; 4], &[]).unwrap_or_default();
    color(LIGHT_CYAN);
    println!("=== Hydra OS Storage Subsystem & Block Devices ===");
    if d.present != 0 {
        let bytes = d.sectors * 512;
        color(LIGHT_GREEN);
        println!("\nDevice: /dev/hda (Primary Master ATA/IDE)");
        color(WHITE);
        println!("  - Model:             {}", name_str(&d.model));
        println!("  - Driven by:         ata-driver (Ring 3 process, `service status`)");
        println!("  - Capacity:          {} MiB ({} bytes)", bytes / (1024 * 1024), bytes);
        println!("  - Total Sectors:     {} (512 bytes/sector)", d.sectors);
        println!("  - Addressing:        {}", if d.lba48 != 0 { "LBA48 (48-bit Logical Block Addressing)" } else { "LBA28 (28-bit Logical Block Addressing)" });
        println!("  - I/O Mode:          {}", if d.dma != 0 { "Bus-master DMA" } else { "Programmed I/O (polled)" });
        println!("  - Vdev Association:  vdev-ata-0 -> Backs OpenZFS pool 'hydrapool'");
        println!("  - Persistence:       ENABLED (Durably saved across reboots)");
    } else {
        color(YELLOW);
        println!("\nNo physical or virtual ATA hard disks detected on Primary Master (0x1F0).");
        color(WHITE);
        println!("  - Fallback Vdev:     vdev-ramdisk-0 (32 MiB In-Memory Volatile RAM Disk)");
        println!("  - Persistence:       DISABLED (Data will reset upon system reboot)");
        println!("  - Tip: Attach an IDE hard disk at IDE-0-0 in VirtualBox or -hda in QEMU.");
    }
    color(WHITE);
}

pub fn usbdisk(_sh: &mut Shell, args: &[&str]) {
    let num = |i: usize, d: u64| args.get(i).and_then(|a| a.parse::<u64>().ok()).unwrap_or(d);
    let a = match args.first().copied().unwrap_or("list") {
        "list" => [USBDISK_LIST, 0, 0, 0],
        "test" => [USBDISK_TEST, num(1, 0), num(2, 2048), 0],
        "speed" => {
            let disk = if args.get(1) == Some(&"ahci") { u64::MAX } else { num(1, 0) };
            [USBDISK_SPEED, disk, num(2, 64), args.contains(&"write") as u64]
        }
        _ => return println!("usage: usbdisk [list | test <n> [blocks] | speed <n|ahci> [MiB] [write]]"),
    };
    if let Err(e) = admin(ADMIN_USBDISK, a, &[]) {
        report(&e, "usbdisk");
    }
}
