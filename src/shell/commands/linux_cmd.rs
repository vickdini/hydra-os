//! # Linux ABI Shell Command
//!
//! Provides CLI diagnostics, statistics, and execution control for the
//! Hydra Linux Binary Compatibility Layer (`src/compat/linux`).

use uefi::proto::console::text::Color;

use crate::console;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

pub struct LinuxCommand;

impl Command for LinuxCommand {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn description(&self) -> &'static str {
        "Linux ABI compatibility layer control, diagnostics, and binary launcher"
    }

    fn usage(&self) -> &'static str {
        "linux [status|info|test|run <path> [args...]|chroot <dir> <program> [args...]|rootfs install [archive] [dir]]"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["linux64", "lx"]
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let sub = if args.is_empty() { "status" } else { args[0] };

        match sub {
            "status" | "info" => {
                let stats = crate::compat::linux::LINUX_STATS.lock();
                console::set_color(Color::LightCyan, Color::Black);
                println!("============================================================");
                println!("           HYDRA OS - LINUX ABI COMPATIBILITY SUBSYSTEM      ");
                println!("============================================================");
                console::set_color(Color::White, Color::Black);
                println!("  Emulation Profile:    Linux 6.8.0-hydra (x86_64)");
                println!("  Target C-Runtime:     musl-libc, glibc, Alpine userspace");
                println!("  Syscall Interface:    Fast hardware SYSCALL / SYSRET");
                println!("  TLS Subsystem:        MSR IA32_FS_BASE (arch_prctl)");
                println!("  Memory Subsystem:     Page-backed brk + anonymous mmap");
                println!("  Pseudo Filesystems:   /dev/null, /dev/urandom, /proc/version");
                println!("------------------------------------------------------------");
                console::set_color(Color::LightGreen, Color::Black);
                println!("  Total Syscalls Dispatched: {:10}", stats.total_calls);
                println!("  File & Terminal I/O Calls: {:10}", stats.io_calls);
                println!("  Memory / mmap / brk Calls: {:10}", stats.memory_calls);
                println!("  Process & Signals Calls:   {:10}", stats.process_calls);
                println!("  arch_prctl (TLS) Calls:    {:10}", stats.arch_prctl_calls);
                println!("  Time / Clock Calls:        {:10}", stats.time_calls);
                if stats.unknown_calls > 0 {
                    console::set_color(Color::LightRed, Color::Black);
                    println!("  Unsupported Syscalls:      {:10}", stats.unknown_calls);
                } else {
                    console::set_color(Color::LightGreen, Color::Black);
                    println!("  Unsupported Syscalls:               0");
                }
                console::set_color(Color::LightCyan, Color::Black);
                println!("============================================================");
                console::set_color(Color::White, Color::Black);
            }

            "test" => {
                console::set_color(Color::Yellow, Color::Black);
                println!("[*] Running Linux ABI compatibility self-tests...");

                // 1. Test uname
                let uts = crate::compat::linux::LinuxUtsname::default();
                let sysname = core::str::from_utf8(&uts.sysname).unwrap_or("").trim_matches('\0');
                let release = core::str::from_utf8(&uts.release).unwrap_or("").trim_matches('\0');
                console::set_color(Color::LightGreen, Color::Black);
                println!("  [+] sys_uname: {} {}", sysname, release);

                // 2. Test pseudo /proc/version
                let pseudo = crate::compat::linux::fs::PseudoFile::ProcVersion;
                let mut buf = [0u8; 128];
                let n = pseudo.read(0, &mut buf);
                if n > 0 {
                    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                    println!("  [+] /proc/version: {}", text.trim());
                }

                // 3. Test pseudo /dev/urandom
                let urand = crate::compat::linux::fs::PseudoFile::DevUrandom;
                let mut rand_bytes = [0u8; 8];
                urand.read(0, &mut rand_bytes);
                println!("  [+] /dev/urandom: {:02x?}", rand_bytes);

                // 4. Test MSR IA32_FS_BASE (arch_prctl)
                let test_tls_addr: u64 = 0x7FFF_0000_1000;
                unsafe {
                    crate::arch::syscall::wrmsr(0xC000_0100, test_tls_addr);
                    let read_back = crate::arch::syscall::rdmsr(0xC000_0100);
                    if read_back == test_tls_addr {
                        println!("  [+] arch_prctl(ARCH_SET_FS): MSR 0xC0000100 read/write verified");
                    } else {
                        console::set_color(Color::LightRed, Color::Black);
                        println!("  [!] arch_prctl MSR test failed (mismatch: {:#x})", read_back);
                    }
                    // Reset to 0
                    crate::arch::syscall::wrmsr(0xC000_0100, 0);
                }

                console::set_color(Color::LightCyan, Color::Black);
                println!("[+] Linux ABI self-tests completed successfully.");
                console::set_color(Color::White, Color::Black);
            }

            "run" => {
                if args.len() < 2 {
                    console::set_color(Color::LightRed, Color::Black);
                    println!("Usage: linux run <path_to_elf> [args...]");
                    console::set_color(Color::White, Color::Black);
                    return;
                }

                let raw_path = args[1];
                let app_args = &args[1..];

                // 2 MiB buffer to accommodate larger Linux binaries such as genuine plasmashell.elf (941 KiB)
                let mut buffer = alloc::vec![0u8; 2 * 1024 * 1024];
                let mut bytes_read = 0;
                let mut resolved_path = alloc::string::String::from(raw_path);

                if let Ok(n) = crate::fs::ZfsClient::read_file_by_path(raw_path, &mut buffer) {
                    bytes_read = n;
                } else if !raw_path.starts_with('/') {
                    let bin_path = alloc::format!("/bin/{}", raw_path);
                    if let Ok(n) = crate::fs::ZfsClient::read_file_by_path(&bin_path, &mut buffer) {
                        bytes_read = n;
                        resolved_path = bin_path;
                    } else if !raw_path.ends_with(".elf") {
                        let bin_elf = alloc::format!("/bin/{}.elf", raw_path);
                        if let Ok(n) = crate::fs::ZfsClient::read_file_by_path(&bin_elf, &mut buffer) {
                            bytes_read = n;
                            resolved_path = bin_elf;
                        }
                    }
                }

                if bytes_read == 0 && !crate::arch::boot_services::is_hardware_takeover_complete() {
                    // Fallback to boot media (FAT volume /bin/<file> or /<file>)
                    let clean = raw_path.trim_start_matches('/').trim_start_matches('\\');
                    let fat_paths = [
                        alloc::format!("\\bin\\{}", clean),
                        alloc::format!("\\bin\\{}.elf", clean),
                        alloc::format!("\\{}", clean),
                    ];
                    for fp in &fat_paths {
                        if let Ok(data) = crate::shell::fs::read_boot_file(fp) {
                            let copy_n = data.len().min(buffer.len());
                            buffer[..copy_n].copy_from_slice(&data[..copy_n]);
                            bytes_read = copy_n;
                            resolved_path = alloc::format!("boot:{}", fp);
                            break;
                        }
                    }
                }

                if bytes_read == 0 {
                    console::set_color(Color::LightRed, Color::Black);
                    println!("[!] Failed to read file '{}' from OpenZFS storage pool or boot media.", raw_path);
                    console::set_color(Color::White, Color::Black);
                    return;
                }

                if !crate::arch::boot_services::is_hardware_takeover_complete() {
                    console::set_color(Color::Yellow, Color::Black);
                    println!(
                        "[*] Auto-transitioning to bare-metal hardware mode to launch Ring 3 Linux ELF '{}'...",
                        resolved_path
                    );
                    let _ = crate::arch::boot_services::take_hardware_ownership();
                }

                println!("[+] Read {} bytes from OpenZFS ({}). Spawning Linux process...", bytes_read, resolved_path);
                match crate::task::spawn_linux_elf(
                    "linux_app",
                    &buffer[..bytes_read],
                    app_args,
                    crate::task::TaskPriority::Normal,
                    state.current_uid,
                    state.current_gid,
                ) {
                    Ok(tid) => {
                        println!("[+] Linux process spawned with Task ID {} (UID {}, GID {}). Executing...", tid.0, state.current_uid, state.current_gid);
                        run_in_foreground(tid);
                    }
                    Err(e) => {
                        console::set_color(Color::LightRed, Color::Black);
                        println!("[!] Failed to spawn Linux binary: {}", e);
                        console::set_color(Color::White, Color::Black);
                    }
                }
            }

            "trace" => {
                // linux trace on [exe-substring] | off
                let on = args.get(1).copied() != Some("off");
                *crate::compat::linux::TRACE_FILTER.lock() = alloc::string::String::from(*args.get(2).unwrap_or(&""));
                crate::compat::linux::TRACE_SYSCALLS.store(on, core::sync::atomic::Ordering::Relaxed);
                println!("[+] Linux syscall tracing {}", if on { "enabled" } else { "disabled" });
            }

            "wayland" => {
                // linux wayland [root]: start the compositor for clients in a Linux root
                let root = args.get(1).copied().unwrap_or("/ubuntu");
                if !crate::arch::boot_services::is_hardware_takeover_complete() {
                    let _ = crate::arch::boot_services::take_hardware_ownership();
                }
                let root_ino = match crate::fs::ZfsClient::resolve(0, root.as_bytes(), true) {
                    Ok(i) => i,
                    Err(_) => {
                        println!("[!] linux wayland: no such directory: {}", root);
                        return;
                    }
                };
                prepare_runtime_dir(root, state.current_uid, state.current_gid);
                let path = alloc::format!("/run/user/{}/wayland-0", state.current_uid);
                match crate::wayland::start(root_ino, &path, state.current_uid, state.current_gid) {
                    Ok(()) => println!("[+] Wayland compositor started: WAYLAND_DISPLAY=wayland-0 in {} (Ctrl+Alt+F1 console, Ctrl+Alt+F2 desktop)", root),
                    Err(e) => println!("[!] linux wayland: {}", e),
                }
            }

            "chroot" => {
                if args.len() < 3 {
                    println!("Usage: linux chroot <dir> <program> [args...]   e.g. linux chroot /ubuntu /usr/bin/bash -c 'ls /'");
                    return;
                }
                if !crate::arch::boot_services::is_hardware_takeover_complete() {
                    let _ = crate::arch::boot_services::take_hardware_ownership();
                }
                prepare_network_files(args[1]);
                prepare_runtime_dir(args[1], state.current_uid, state.current_gid);
                let program = args[2];
                let argv: alloc::vec::Vec<&str> = args[2..].iter().copied().collect();
                match crate::task::spawn_linux_chroot(args[1], program, &argv, state.current_uid, state.current_gid) {
                    Ok(tid) => run_in_foreground(tid),
                    Err(e) => {
                        console::set_color(Color::LightRed, Color::Black);
                        println!("[!] linux chroot: {}", e);
                        console::set_color(Color::White, Color::Black);
                    }
                }
            }

            "rootfs" => {
                if args.get(1).copied() != Some("install") {
                    println!("Usage: linux rootfs install [boot-archive-path] [target-dir]");
                    return;
                }
                let archive = args.get(2).copied().unwrap_or(r"\rootfs\ubuntu-base.tar.gz");
                let dest = args.get(3).copied().unwrap_or("/ubuntu");
                if crate::arch::boot_services::is_hardware_takeover_complete() {
                    println!("[!] The boot volume is only readable before hardware takeover; reboot and run this first.");
                    return;
                }
                let data = match crate::shell::fs::read_media_file(archive) {
                    Ok(d) => d,
                    Err(e) => {
                        console::set_color(Color::LightRed, Color::Black);
                        println!("[!] Cannot read {} from the boot volume: {:?}", archive, e);
                        console::set_color(Color::White, Color::Black);
                        return;
                    }
                };
                match crate::pkg::rootfs::install(&data, dest) {
                    Ok(sum) => {
                        console::set_color(Color::LightGreen, Color::Black);
                        println!(
                            "[+] Root filesystem installed in {}: {} files ({} MiB), {} dirs, {} symlinks, {} hard links, {} devices, {} skipped",
                            dest, sum.files, sum.bytes / (1024 * 1024), sum.dirs, sum.symlinks, sum.hardlinks, sum.devices, sum.skipped
                        );
                        console::set_color(Color::White, Color::Black);
                    }
                    Err(e) => {
                        console::set_color(Color::LightRed, Color::Black);
                        println!("[!] rootfs install failed: {}", e);
                        console::set_color(Color::White, Color::Black);
                    }
                }
            }

            "click" => {
                let x = if args.len() > 1 { args[1].parse::<usize>().unwrap_or(640) } else { 640 };
                let y = if args.len() > 2 { args[2].parse::<usize>().unwrap_or(400) } else { 400 };
                crate::compat::linux::inject_simulated_click(x, y);
                println!("[+] Injected simulated mouse click at ({}, {})", x, y);
            }

            _ => {
                console::set_color(Color::LightRed, Color::Black);
                println!("Invalid subcommand. Usage: linux [status|info|test|run <path>|click <x> <y>]");
                console::set_color(Color::White, Color::Black);
            }
        }
    }
}

/// Runs a Linux process started from the Hydra shell in the foreground: it leads its own
/// session and owns the console (keyboard, Ctrl+C) until it exits; then its exit status is
/// reported and the console returns to the shell.
fn run_in_foreground(tid: crate::task::TaskId) {
    crate::compat::linux::tty::attach_session(tid.0, tid.0);
    while crate::task::is_task_alive(tid) {
        crate::task::preemptible(|| crate::task::sleep_ms(20));
    }
    crate::compat::linux::tty::detach_session();
    match crate::compat::linux::proc::take_status(tid.0) {
        Some(s) if s & 0x7f != 0 => println!("[+] Linux process {} killed by signal {}.", tid.0, s & 0x7f),
        Some(s) => println!("[+] Linux process {} exited with status {}.", tid.0, (s >> 8) & 0xff),
        None => println!("[+] Linux process {} exited.", tid.0),
    }
}

/// Fills in a Linux root's empty `/etc/resolv.conf` and `/etc/hosts` (as WSL does), so the
/// C library resolves names through the DNS server from the DHCP lease. Files that already
/// have content, or are symbolic links, are left alone.
/// Creates `/run/user/<uid>` in the target root (mode 0700, owned by the user), the
/// per-user runtime directory (`XDG_RUNTIME_DIR`) that logind provides on a real system
/// and D-Bus, Wayland and KDE expect.
fn prepare_runtime_dir(root: &str, uid: u32, gid: u32) {
    let path = alloc::format!("{}/run/user/{}", root.trim_end_matches('/'), uid);
    if let Ok(ino) = crate::fs::ZfsClient::create_dir_all(&path) {
        let _ = crate::fs::ZfsClient::setattr(
            ino,
            crate::fs::zfs::zpl::SetAttr { mode: Some(0o700), uid: Some(uid), gid: Some(gid), ..Default::default() },
        );
    }
}

fn prepare_network_files(root: &str) {
    let dns = crate::net::GLOBAL_INTERFACE.lock().dns_server();
    let resolv = if dns != [0, 0, 0, 0] {
        alloc::format!(
            "# Generated by Hydra from the DHCP lease\nnameserver {}.{}.{}.{}\n",
            dns[0], dns[1], dns[2], dns[3]
        )
    } else {
        alloc::string::String::new()
    };
    let hosts = alloc::string::String::from("127.0.0.1\tlocalhost\n127.0.1.1\thydra\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    for (name, content) in [("etc/resolv.conf", resolv), ("etc/hosts", hosts)] {
        if content.is_empty() {
            continue;
        }
        let path = alloc::format!("{}/{}", root.trim_end_matches('/'), name);
        let is_empty_file = match crate::fs::ZfsClient::resolve(0, path.as_bytes(), false)
            .and_then(crate::fs::ZfsClient::getattr)
        {
            Ok(attr) => attr.mode & 0o170000 == 0o100000 && attr.size == 0,
            Err(_) => true,
        };
        if is_empty_file {
            let _ = crate::fs::ZfsClient::write_file_by_path(&path, content.as_bytes());
        }
    }
}
