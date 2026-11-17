//! `linux`: the Linux root. Programs (`chroot`, `run`) through the admin interface's Linux
//! group (0x8_), the requests the Linux server will answer once the Linux layer leaves
//! the kernel; statistics, self-test, tracing, the profiler and the desktop.

use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::{report, Shell};
use hydra_rt::println;

/// Starts a Linux program in the foreground (it gets the console) and waits for it.
fn foreground(sh: &mut Shell, kind: u64, words: &[&str], verbose: bool) {
    let r: RunResult = match admin_rec(ADMIN_LINUX_RUN, [kind | RUN_FOREGROUND, 0, 0, 0], &nul_join(words)) {
        Ok(r) => r,
        Err(e) => {
            color(LIGHT_RED);
            if kind == RUN_CHROOT {
                println!("[!] linux chroot: {}", e.text());
            } else {
                println!("[!] Failed to spawn Linux binary: {}", e.text());
            }
            color(WHITE);
            sh.status = 1;
            return;
        }
    };
    if verbose {
        println!("[+] Read {} bytes from OpenZFS ({}). Spawning Linux process...", r.size, name_str(&r.path));
        println!("[+] Linux process spawned with Task ID {} (UID {}, GID {}). Executing...", r.pid, r.uid, r.gid);
    }
    let w: WaitResult = admin_rec(ADMIN_LINUX_WAIT, [r.pid, 0, 0, 0], &[]).unwrap_or_default();
    color(WHITE);
    if w.known == 0 {
        println!("[+] Linux process {} exited.", r.pid);
        sh.status = 0;
    } else if w.status & 0x7f != 0 {
        println!("[+] Linux process {} killed by signal {}.", r.pid, w.status & 0x7f);
        sh.status = 128 + (w.status & 0x7f) as i32;
    } else {
        println!("[+] Linux process {} exited with status {}.", r.pid, (w.status >> 8) & 0xff);
        sh.status = ((w.status >> 8) & 0xff) as i32;
    }
}

pub fn linux(sh: &mut Shell, args: &[&str]) {
    let sub = args.first().copied().unwrap_or("status");
    match sub {
        "status" | "info" => status(),
        "test" => {
            if let Err(e) = admin(ADMIN_LINUX_TEST, [0; 4], &[]) {
                report(&e, "linux test");
            }
        }
        "run" => {
            if args.len() < 2 {
                color(LIGHT_RED);
                println!("Usage: linux run <path_to_elf> [args...]");
                color(WHITE);
                return;
            }
            foreground(sh, RUN_FILE, &args[1..], true);
        }
        "chroot" => {
            if args.len() < 3 {
                println!("Usage: linux chroot <dir> <program> [args...]   e.g. linux chroot /ubuntu /usr/bin/bash -c 'ls /'");
                return;
            }
            foreground(sh, RUN_CHROOT, &args[1..], false);
        }
        "plasma" => {
            let root = args.get(1).copied().unwrap_or("/ubuntu");
            let nologin = args.get(2).copied() == Some("nologin");
            if let Err(e) = admin(ADMIN_LINUX_PLASMA, [nologin as u64, 0, 0, 0], root.as_bytes()) {
                report(&e, "linux plasma");
            }
        }
        "trace" => {
            let on = args.get(1).copied() != Some("off");
            let filter = args.get(2).copied().unwrap_or("");
            match admin(ADMIN_LINUX_TRACE, [on as u64, 0, 0, 0], filter.as_bytes()) {
                Ok(_) => println!("[+] Linux syscall tracing {}", if on { "enabled" } else { "disabled" }),
                Err(e) => report(&e, "linux trace"),
            }
        }
        "prof" => prof(&args[1..]),
        "rootfs" => {
            color(LIGHT_RED);
            println!("[!] linux rootfs install: the boot volume is unreachable after the hardware takeover at boot; install Linux roots with the installer.");
            color(WHITE);
        }
        _ => {
            color(LIGHT_RED);
            println!("Invalid subcommand. Usage: linux [status|info|test|run <path>|chroot <dir> <program>|plasma|trace|prof]");
            color(WHITE);
        }
    }
}

/// `linux status`.
fn status() {
    let s: LinuxStats = match admin_rec(ADMIN_LINUX_STATUS, [0; 4], &[]) {
        Ok(s) => s,
        Err(e) => return report(&e, "linux status"),
    };
    let c = s.calls;
    color(LIGHT_CYAN);
    println!("============================================================");
    println!("           HYDRA OS - LINUX ABI COMPATIBILITY SUBSYSTEM      ");
    println!("============================================================");
    color(WHITE);
    println!("  Emulation Profile:    Linux 6.8.0-hydra (x86_64)");
    println!("  Target C-Runtime:     musl-libc, glibc, Alpine userspace");
    println!("  Syscall Interface:    Fast hardware SYSCALL / SYSRET");
    println!("  TLS Subsystem:        MSR IA32_FS_BASE (arch_prctl)");
    println!("  Memory Subsystem:     Page-backed brk + anonymous mmap");
    println!("  Pseudo Filesystems:   /dev/null, /dev/urandom, /proc/version");
    println!("------------------------------------------------------------");
    color(LIGHT_GREEN);
    println!("  Total Syscalls Dispatched: {:10}", c[0]);
    println!("  File & Terminal I/O Calls: {:10}", c[1]);
    println!("  Memory / mmap / brk Calls: {:10}", c[2]);
    println!("  Process & Signals Calls:   {:10}", c[3]);
    println!("  arch_prctl (TLS) Calls:    {:10}", c[4]);
    println!("  Time / Clock Calls:        {:10}", c[5]);
    if c[6] > 0 {
        color(LIGHT_RED);
        println!("  Unsupported Syscalls:      {:10}", c[6]);
    } else {
        println!("  Unsupported Syscalls:               0");
    }
    color(LIGHT_CYAN);
    println!("============================================================");
    color(WHITE);
}

/// `linux prof on | off | reset | show [N] | tune defer on|off | tune poll <us> | waits <ms> |
/// waits show | sample <task> [all] | sample stop | sample show [N]`.
fn prof(args: &[&str]) {
    let num = |i: usize, d: u64| args.get(i).and_then(|a| a.parse::<u64>().ok()).unwrap_or(d);
    let mut name: &str = "";
    let a: [u64; 4] = match args.first().copied().unwrap_or("show") {
        "on" => [PROF_ON, 0, 0, 0],
        "off" => [PROF_OFF, 0, 0, 0],
        "reset" => [PROF_RESET, 0, 0, 0],
        "tune" => match (args.get(1).copied(), args.get(2).copied()) {
            (Some("defer"), Some(v)) => [PROF_TUNE, 0, (v == "on") as u64, 0],
            (Some("poll"), Some(v)) => match v.parse::<u64>() {
                Ok(us) => [PROF_TUNE, 1, us, 0],
                Err(_) => [PROF_TUNE, 2, 0, 0],
            },
            _ => [PROF_TUNE, 2, 0, 0],
        },
        "waits" if args.get(1).copied() == Some("show") => [PROF_WAITS_SHOW, 0, 0, 0],
        "waits" => [PROF_WAITS, num(1, 0), 0, 0],
        "sample" => match args.get(1).copied() {
            Some("show") => [PROF_SAMPLE_SHOW, num(2, 40), 0, 0],
            Some("stop") | None => [PROF_SAMPLE_STOP, 0, 0, 0],
            Some(task) => {
                name = task;
                [PROF_SAMPLE, (args.get(2).copied() == Some("all")) as u64, 0, 0]
            }
        },
        _ => [PROF_SHOW, num(1, 25), 0, 0],
    };
    let _: Vec<u8> = admin(ADMIN_LINUX_PROF, a, name.as_bytes()).unwrap_or_default();
}
