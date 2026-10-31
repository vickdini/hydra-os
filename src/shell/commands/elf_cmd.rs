//! # Shell Command: ELF64 Binary Inspector and Runner (`elf`)
//!
//! Provides interactive command-line inspection of 64-bit ELF headers and executes
//! standalone userland binaries directly from the OpenZFS storage pool in unprivileged Ring 3.
//!
//! ## Architectural Role & Design Rationale
//!
//! The `elf` command bridges the OpenZFS filesystem, the ELF64 parser/loader, and the
//! preemptive task scheduler. Users can inspect ELF binary metadata (program headers, segment
//! virtual addresses, `.bss` allocation sizes, and permission flags) or trigger unprivileged
//! execution in Ring 3 without embedding the target binary into the kernel firmware image.
//!
//! ## Key Types & Interfaces
//!
//! - [`ElfCommand`]: Command implementation registered in the shell command table.
//!
//! ## Hardware & Dependency Context
//!
//! - CPU Privilege Level: Transitions from Ring 0 (Kernel) to Ring 3 (Userland) upon execution.
//! - Hardware Interaction: Reads binaries via [`crate::fs::client::ZfsClient`] and schedules Ring 3 tasks via [`crate::task`].
//! - Concurrency: Supports synchronous foreground wait (`wait_task`) or asynchronous background execution (`--bg`).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::ZfsClient;
use crate::shell::command::Command;
use crate::shell::state::ShellState;
use crate::task::elf::{
    ElfBinary, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_NOTE,
    PT_PHDR, PT_SHLIB, PT_TLS,
};
use crate::task::{self, TaskPriority};

/// Maximum size of an ELF binary read into memory for inspection and execution (2 MiB).
const MAX_ELF_BUFFER: usize = 2 * 1024 * 1024;

/// Inspects and executes standalone ELF64 userland binaries from ZFS.
pub struct ElfCommand;

impl Command for ElfCommand {
    fn name(&self) -> &'static str {
        "elf"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["elf64", "runelf"]
    }

    fn description(&self) -> &'static str {
        "Inspect headers or execute standalone ELF64 userland binaries in Ring 3"
    }

    fn usage(&self) -> &'static str {
        "elf [-i|--info] <file.elf> [--bg]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::Yellow, Color::Black);
            println!("Usage: {}", self.usage());
            println!("Examples:");
            println!("  elf /bin/hello.elf            - Load and execute standalone binary");
            println!("  elf --info /bin/hello.elf     - Inspect ELF64 headers and segments");
            println!("  elf /bin/counter.elf --bg     - Run binary in background (Ring 3)");
            return;
        }

        let mut info_only = false;
        let mut bg_mode = false;
        let mut target_path: Option<&str> = None;

        for &arg in args {
            match arg {
                "-i" | "--info" => info_only = true,
                "--bg" | "-b" | "&" => bg_mode = true,
                path if !path.starts_with('-') && target_path.is_none() => {
                    target_path = Some(path);
                }
                _ => {}
            }
        }

        let path = match target_path {
            Some(p) => p,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error: No ELF target path specified.");
                return;
            }
        };

        // 1. Read binary data from OpenZFS File Server
        let mut buffer = alloc::vec![0u8; MAX_ELF_BUFFER];
        let mut bytes_read = 0;
        let mut resolved_path = String::from(path);

        if let Ok(n) = ZfsClient::read_file_by_path(path, &mut buffer) {
            bytes_read = n;
        } else if !path.starts_with('/') {
            // Try prefixing with /bin/
            let bin_path = format!("/bin/{}", path);
            if let Ok(n) = ZfsClient::read_file_by_path(&bin_path, &mut buffer) {
                bytes_read = n;
                resolved_path = bin_path;
            }
        }

        if bytes_read == 0 {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Error: ELF file '{}' not found in ZFS storage pool.", path);
            println!("    Use 'ls /bin' to inspect available files in hydrapool/bin.");
            return;
        }

        // 2. Parse ELF64 Binary Headers
        let elf = match ElfBinary::parse(&buffer[..bytes_read]) {
            Ok(e) => e,
            Err(err) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to parse ELF binary '{}': {}", resolved_path, err.as_str());
                return;
            }
        };

        let header = elf.header();

        // 3. Display diagnostic information
        set_color(Color::LightGreen, Color::Black);
        println!("\n============================================================");
        println!(" [+] HYDRA MICROKERNEL: ELF64 BINARY INSPECTOR & LOADER     ");
        println!("============================================================");

        set_color(Color::White, Color::Black);
        println!("  File Path       : {}", resolved_path);
        println!("  File Size       : {} bytes (Verified via ZFS Fletcher-4)", bytes_read);

        let type_str = match header.e_type {
            ET_EXEC => "Executable (ET_EXEC - Fixed Virtual Address)",
            ET_DYN => "Shared Object / PIE (ET_DYN - Position-Independent)",
            _ => "Unknown / Other",
        };
        println!("  Object Type     : {}", type_str);
        println!("  Architecture    : AMD x86-64 (EM_X86_64, 64-bit Little-Endian)");
        println!("  Entry Point     : {:#018x}", header.e_entry);
        println!("  Program Headers : {} entries (at file offset {:#x})", header.e_phnum, header.e_phoff);

        println!("\n  Program Headers Table (Segments):");
        println!("    {:<4} {:<10} {:<18} {:<18} {:<10} {:<10} {:<6}",
            "IDX", "TYPE", "FILE_OFFSET", "VIRT_ADDR", "FILE_SZ", "MEM_SZ", "FLAGS");
        println!("    {:-<80}", "");

        for (idx, ph) in elf.program_headers().enumerate() {
            let type_name = match ph.p_type {
                PT_LOAD => "PT_LOAD",
                PT_DYNAMIC => "DYNAMIC",
                PT_INTERP => "INTERP",
                PT_NOTE => "NOTE",
                PT_SHLIB => "SHLIB",
                PT_PHDR => "PHDR",
                PT_TLS => "TLS",
                _ => "OTHER",
            };

            let mut flags_str = [b'-', b'-', b'-'];
            if (ph.p_flags & PF_R) != 0 { flags_str[0] = b'R'; }
            if (ph.p_flags & PF_W) != 0 { flags_str[1] = b'W'; }
            if (ph.p_flags & PF_X) != 0 { flags_str[2] = b'X'; }
            let flags = core::str::from_utf8(&flags_str).unwrap_or("---");

            println!("    {:<4} {:<10} {:#018x} {:#018x} {:#010x} {:#010x} {:<6}",
                idx, type_name, ph.p_offset, ph.p_vaddr, ph.p_filesz, ph.p_memsz, flags);
        }

        println!("============================================================\n");

        if info_only {
            return;
        }

        // 4. Check hardware takeover requirement
        if !crate::arch::boot_services::is_hardware_takeover_complete() {
            set_color(Color::Yellow, Color::Black);
            println!(
                "[*] Auto-transitioning to bare-metal hardware mode to launch Ring 3 ELF '{}'...",
                resolved_path
            );
            let _ = crate::arch::boot_services::take_hardware_ownership();
        }

        // 5. Spawn Unprivileged Ring 3 Process
        let is_linux_elf = elf.interp_path().is_some()
            || resolved_path.contains("linux")
            || resolved_path.contains("plasmashell")
            || resolved_path.contains("krunner")
            || resolved_path.contains("wlclient")
            || resolved_path.contains("wlseat")
            || resolved_path.contains("dynclient");
        let leaked_name: &'static str = Box::leak(resolved_path.into_boxed_str());
        let spawn_res = if is_linux_elf {
            let app_args = [leaked_name];
            task::spawn_linux_elf(
                leaked_name,
                &buffer[..bytes_read],
                &app_args,
                TaskPriority::Normal,
                _state.current_uid,
                _state.current_gid,
            )
        } else {
            task::spawn_elf(leaked_name, &buffer[..bytes_read], TaskPriority::Normal)
        };
        match spawn_res {
            Ok(pid) => {
                set_color(Color::LightGreen, Color::Black);
                println!(
                    "[+] Spawned Ring 3 {} ELF process #{} ('{}').",
                    if is_linux_elf { "Linux" } else { "Native" },
                    pid.0,
                    leaked_name
                );
                println!("    Privilege: Unprivileged Ring 3 (CS=0x23, SS=0x1B, RFLAGS=0x202)");

                if bg_mode {
                    println!("    Running in background. Type 'ps' to inspect execution.");
                } else {
                    task::wait_task(pid);
                    set_color(Color::LightCyan, Color::Black);
                    println!("[*] ELF process #{} completed and exited cleanly.", pid.0);
                }
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to spawn ELF binary: {}", e);
            }
        }
    }
}
