//! # Shell Commands: OpenZFS Storage Pool & Dataset Management (`zpool`, `zfs`)
//!
//! Provides CLI tools to inspect storage pools, manage datasets, and create point-in-time snapshots.

use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::ZfsClient;
use crate::fs::zfs::server::ZFS_SERVER;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command managing OpenZFS storage pools (`status`, `list`).
pub struct ZpoolCommand;

impl Command for ZpoolCommand {
    fn name(&self) -> &'static str {
        "zpool"
    }

    fn description(&self) -> &'static str {
        "Manage ZFS storage pools (e.g. 'zpool status', 'zpool list')"
    }

    fn usage(&self) -> &'static str {
        "zpool <status|list>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let subcmd = if args.is_empty() { "status" } else { args[0] };

        match subcmd {
            "status" => {
                set_color(Color::LightCyan, Color::Black);
                println!("  pool: hydrapool");
                set_color(Color::White, Color::Black);
                println!(" state: ONLINE");
                println!("status: The pool is operating normally via the Microkernel ZFS File Server.");
                let is_disk = crate::arch::ata::is_drive_present();
                println!("config:");
                println!("        NAME                 STATE     READ WRITE CKSUM");
                println!("        hydrapool            ONLINE       0     0     0");
                if is_disk {
                    println!("          vdev-ata-0         ONLINE       0     0     0 (Persistent ATA Hard Disk)");
                } else {
                    println!("          vdev-ramdisk-0     ONLINE       0     0     0 (Volatile RAM Fallback)");
                }

                if let Ok((total_mb, alloc_kb, free_kb, txg)) = ZfsClient::pool_status() {
                    set_color(Color::Yellow, Color::Black);
                    println!("\nPool Properties & Metrics:");
                    set_color(Color::White, Color::Black);
                    println!("  - Capacity:           {} MiB", total_mb);
                    println!("  - Allocated:          {} KiB", alloc_kb);
                    println!("  - Free Space:         {} KiB", free_kb);
                    println!("  - Persistence Mode:   {}", if is_disk { "Hardware ATA Sector I/O (ACID Durable)" } else { "In-Memory RAM Buffer" });
                    println!("  - Active Uberblock:   TXG #{}", txg);
                    println!("  - Checksum Algorithm: Fletcher-4 (4x 64-bit words)");
                    println!("  - Allocation Policy:  Copy-on-Write (CoW) Merkle Tree");
                }
            }

            "list" => {
                set_color(Color::Yellow, Color::Black);
                println!("{:<14} {:>8} {:>8} {:>8} {:>6} {:>6} {:<8}",
                         "NAME", "SIZE", "ALLOC", "FREE", "CAP", "DEDUP", "HEALTH");
                println!("------------------------------------------------------------------");

                if let Ok((total_mb, alloc_kb, free_kb, _)) = ZfsClient::pool_status() {
                    let total_kb = total_mb * 1024;
                    let cap_pct = if total_kb > 0 { (alloc_kb * 100) / total_kb } else { 0 };
                    set_color(Color::White, Color::Black);
                    println!("{:<14} {:>7}M {:>7}K {:>7}K {:>5}% {:>6} {:<8}",
                             "hydrapool", total_mb, alloc_kb, free_kb, cap_pct, "1.00x", "ONLINE");
                }
            }

            _ => {
                set_color(Color::LightRed, Color::Black);
                println!("Unknown sub-command: '{}'. Usage: zpool <status|list>", subcmd);
            }
        }
    }
}

/// Shell command managing OpenZFS datasets and snapshots (`list`, `create`, `destroy`, `snapshot`).
pub struct ZfsCommand;

impl Command for ZfsCommand {
    fn name(&self) -> &'static str {
        "zfs"
    }

    fn description(&self) -> &'static str {
        "Configure ZFS datasets, snapshots, and files (e.g. 'zfs list', 'zfs snap', 'zfs cat')"
    }

    fn usage(&self) -> &'static str {
        "zfs <list|snap|cat|write> [args...]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: zfs <list | snap <id> | cat <path> | write <name> <text...>>");
            return;
        }

        match args[0] {
            "list" => {
                set_color(Color::Yellow, Color::Black);
                println!("{:<24} {:>8} {:>8} {:<16}", "NAME", "USED", "AVAIL", "MOUNTPOINT");
                println!("------------------------------------------------------------------");

                let guard = ZFS_SERVER.lock();
                if let Some(server) = guard.as_ref() {
                    let used_k = server.dmu.spa.allocated_bytes() / 1024;
                    let avail_k = server.dmu.spa.free_bytes() / 1024;
                    for ds in server.datasets.iter().filter(|d| d.is_snapshot == 0) {
                        set_color(Color::LightCyan, Color::Black);
                        print!("{:<24} ", ds.name_str());
                        set_color(Color::White, Color::Black);
                        println!("{:>7}K {:>7}K {:<16}", used_k, avail_k, ds.mountpoint_str());
                    }
                    let mut has_snaps = false;
                    for snap in server.datasets.iter().filter(|d| d.is_snapshot != 0) {
                        if !has_snaps {
                            println!("
Snapshots:");
                            has_snaps = true;
                        }
                        set_color(Color::LightGreen, Color::Black);
                        println!("  {} (Created at TXG #{})", snap.name_str(), snap.txg);
                    }
                }
            }

            "snap" | "snapshot" => {
                if args.len() < 2 {
                    set_color(Color::LightRed, Color::Black);
                    println!("Usage: zfs snap <dataset_id>");
                    return;
                }
                match ZfsClient::snapshot(0) {
                    Ok(txg) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Snapshot created successfully at TXG #{}!", txg);
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] Failed to create snapshot: {}", e);
                    }
                }
            }

            "cat" => {
                if args.len() < 2 {
                    set_color(Color::LightRed, Color::Black);
                    println!("Usage: zfs cat <filename>");
                    return;
                }
                let target = args[1];
                match ZfsClient::lookup(target) {
                    Ok((obj_id, _)) => {
                        let mut buf = [0u8; 1024];
                        let cap = state.cap_table.get(1).cloned();
                        match ZfsClient::read_file(obj_id, &mut buf, cap) {
                            Ok(n) => {
                                set_color(Color::White, Color::Black);
                                if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                                    println!("{}", s);
                                } else {
                                    println!("[Binary content: {} bytes, Fletcher-4 verified]", n);
                                }
                            }
                            Err(e) => {
                                set_color(Color::LightRed, Color::Black);
                                println!("[!] Error reading file: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] File '{}' not found: {}", target, e);
                    }
                }
            }

            "selftest" => crate::fs::zfs::selftest::run_selftest(),
            "verify" => crate::fs::zfs::selftest::run_verify(),

            "write" => {
                if args.len() < 3 {
                    set_color(Color::LightRed, Color::Black);
                    println!("Usage: zfs write <name> <content...>");
                    return;
                }
                let name = args[1];
                let mut content_buf = [0u8; 512];
                let mut content_len = 0;
                for (i, word) in args[2..].iter().enumerate() {
                    if i > 0 && content_len < content_buf.len() {
                        content_buf[content_len] = b' ';
                        content_len += 1;
                    }
                    for &b in word.as_bytes() {
                        if content_len < content_buf.len() {
                            content_buf[content_len] = b;
                            content_len += 1;
                        }
                    }
                }
                let content_bytes = &content_buf[..content_len];
                let _cap = state.cap_table.get(1).cloned();

                let path = alloc::format!("/bin/{}", name);
                match ZfsClient::write_file_by_path(&path, content_bytes) {
                    Ok(new_txg) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] CoW write committed to ZFS File Server!");
                        println!("    - File: '{}' ({} bytes)", path, content_bytes.len());
                        println!("    - Merkle Root Updated to TXG #{}", new_txg);
                        println!("    - Fletcher-4 Checksum computed & stored");
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] CoW write failed: {}", e);
                    }
                }
            }

            _ => {
                set_color(Color::LightRed, Color::Black);
                println!("Unknown sub-command: '{}'. Usage: zfs <list|snap|cat|write>", args[0]);
            }
        }
    }
}

/// Shell command to inspect attached physical and virtual block storage devices.
pub struct DisksCommand;

impl Command for DisksCommand {
    fn name(&self) -> &'static str {
        "disks"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["storage", "lsblk", "fdisk"]
    }

    fn description(&self) -> &'static str {
        "Inspect attached physical/virtual block storage devices and ATA controllers"
    }

    fn usage(&self) -> &'static str {
        "disks"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::LightCyan, Color::Black);
        println!("=== Hydra OS Storage Subsystem & Block Devices ===");

        let is_present = crate::arch::ata::is_drive_present();
        if is_present {
            let mut model_buf = [0u8; 40];
            let model = crate::arch::ata::get_drive_model(&mut model_buf).unwrap_or("ATA Hard Disk");
            let info = crate::arch::ata::drive_info();

            set_color(Color::LightGreen, Color::Black);
            println!("\nDevice: /dev/hda (Primary Master ATA/IDE)");
            set_color(Color::White, Color::Black);
            println!("  - Model:             {}", model);
            println!("  - Controller Port:   I/O Base 0x1F0, Control 0x3F6");
            if let Some((cap_bytes, sectors, is_lba48)) = info {
                let cap_mb = cap_bytes / (1024 * 1024);
                println!("  - Capacity:          {} MiB ({} bytes)", cap_mb, cap_bytes);
                println!("  - Total Sectors:     {} (512 bytes/sector)", sectors);
                println!("  - Addressing:        {}", if is_lba48 { "LBA48 (48-bit Logical Block Addressing)" } else { "LBA28 (28-bit Logical Block Addressing)" });
            }
            println!("  - I/O Mode:          Programmed I/O (Polled PIO, nIEN=1)");
            println!("  - Cache Flushing:    Hardware ATA CACHE FLUSH supported");
            println!("  - Vdev Association:  vdev-ata-0 -> Backs OpenZFS pool 'hydrapool'");
            println!("  - Persistence:       ENABLED (Durably saved across reboots)");
        } else {
            set_color(Color::Yellow, Color::Black);
            println!("\nNo physical or virtual ATA hard disks detected on Primary Master (0x1F0).");
            set_color(Color::White, Color::Black);
            println!("  - Fallback Vdev:     vdev-ramdisk-0 (32 MiB In-Memory Volatile RAM Disk)");
            println!("  - Persistence:       DISABLED (Data will reset upon system reboot)");
            println!("  - Tip: Attach an IDE hard disk at IDE-0-0 in VirtualBox or -hda in QEMU.");
        }
        set_color(Color::White, Color::Black);
    }
}

