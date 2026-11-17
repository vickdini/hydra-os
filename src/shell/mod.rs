//! # The emergency prompt: a tiny console inside the kernel
//!
//! The console shell is the ring-3 program `hydra-shell` (see `crate::admin::boot`). This
//! prompt is what is left of the old kernel shell, for when user space is broken: it runs
//! when `hydra-shell` cannot start or keeps dying, or when asked for at boot (the boot
//! option `emergency`; see `crate::admin::boot` for the list).
//!
//! It keeps only what repairs a system: list, read and copy files, see and end tasks,
//! memory, restart services, the pool's status, a program of the Linux root (a root shell
//! of the installed system: `linux chroot /ubuntu /bin/bash`), power, and `ushell` to go
//! back to `hydra-shell`. Everything else is in `hydra-shell`.
//!
//! It asks for the console login when the installed system can check passwords (the rules
//! of `crate::admin::session`: root and members of `sudo` only).
//!
//! ## Context
//! - Ring 0, the kernel's main thread (task 0); reads keys with `console::read_key`.

use alloc::string::String;
use alloc::vec::Vec;
use uefi::proto::console::text::{Color, Key};

use crate::admin::proto::{LOGIN_NOT_ADMIN, LOGIN_OK, LOGIN_UNPROTECTED};
use crate::admin::session;
use crate::console::set_color;
use crate::fs::ZfsClient;

/// The commands, with a line of help each.
const HELP: &[(&str, &str)] = &[
    ("help", "this list"),
    ("cd <dir> | ls [dir]", "change or list a directory of the pool"),
    ("cat <file>", "print a file (first 64 KiB)"),
    ("cp <from> <to>", "copy a file in the pool"),
    ("ps | kill <pid>", "list tasks, end one"),
    ("mem", "physical memory"),
    ("service [restart|start <name>]", "supervised drivers and servers"),
    ("zpool", "the pool's status"),
    ("linux chroot <root> <program> [args]", "e.g. linux chroot /ubuntu /bin/bash"),
    ("ushell", "leave this prompt, start hydra-shell again"),
    ("shutdown | reboot | halt", "power"),
];

/// Reads a line from the keyboard, echoing it unless `secret`. Ctrl+C clears it.
fn read_input(prompt: &str, secret: bool) -> String {
    crate::print!("{}", prompt);
    let mut line = String::new();
    loop {
        match crate::console::read_key() {
            Some(Key::Printable(ch)) => match u16::from(ch) {
                13 | 10 => {
                    crate::println!();
                    return line;
                }
                3 => {
                    crate::println!("^C");
                    line.clear();
                    crate::print!("{}", prompt);
                }
                8 | 127 => {
                    if line.pop().is_some() && !secret {
                        crate::print!("\x08 \x08");
                    }
                }
                c if c >= 32 && line.len() < 512 => {
                    if let Some(ch) = char::from_u32(c as u32) {
                        line.push(ch);
                        if !secret {
                            crate::print!("{}", ch);
                        }
                    }
                }
                _ => {}
            },
            Some(_) => {}
            None => crate::task::sleep_ms(10),
        }
    }
}

/// Asks for a login until an administrator logs in (when passwords can be checked).
fn login() {
    session::begin();
    while !session::logged_in() {
        let name = read_input("login: ", false);
        let password = read_input("Password: ", true);
        match session::login(&name, &password) {
            LOGIN_OK | LOGIN_UNPROTECTED => crate::println!("[+] Logged in as '{}'.\n", session::user().2),
            LOGIN_NOT_ADMIN => crate::println!("'{}' is not an administrator (not in 'sudo').\n", name),
            _ => {
                crate::println!("Login incorrect\n");
                crate::task::sleep_ms(2000);
            }
        }
    }
}

/// Splits a command line into words (double and single quotes group).
fn split(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let (mut quote, mut in_word) = (None, false);
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(core::mem::take(&mut cur));
                    in_word = false;
                }
            }
            None => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Runs one command line of the emergency prompt.
///
/// # Returns
/// `false` to leave the prompt (`ushell`).
fn execute(w: &[&str], cwd: &mut String) -> bool {
    let path = |p: &str| {
        let mut b = [0u8; 128];
        String::from(crate::fs::client::normalize_path(cwd, p, &mut b))
    };
    match w {
        ["help" | "?", ..] => {
            for (c, about) in HELP {
                crate::println!("  {:<38} {}", c, about);
            }
        }
        ["cd", rest @ ..] => {
            let p = path(rest.first().copied().unwrap_or("/"));
            match ZfsClient::file_stat(&p) {
                Ok(st) if st.obj_type == crate::fs::zfs::types::DnodeType::Directory => *cwd = p,
                _ => crate::println!("cd: not a directory: {}", p),
            }
        }
        ["ls", rest @ ..] => match ZfsClient::list_dir(&path(rest.first().copied().unwrap_or("."))) {
            Ok((entries, _, _)) => {
                for e in entries.iter().filter(|e| e.is_valid) {
                    let dir = e.obj_type == crate::fs::zfs::types::DnodeType::Directory;
                    crate::println!("  {}{}", e.name, if dir { "/" } else { "" });
                }
            }
            Err(e) => crate::println!("ls: {}", e),
        },
        ["cat", f, ..] => {
            let mut buf = alloc::vec![0u8; 65536];
            match ZfsClient::read_file_by_path(&path(f), &mut buf) {
                Ok(n) => crate::println!("{}", String::from_utf8_lossy(&buf[..n])),
                Err(e) => crate::println!("cat: {}", e),
            }
        }
        ["cp", from, to, ..] => match ZfsClient::copy_file(&path(from), &path(to)) {
            Ok(txg) => crate::println!("[+] Copied '{}' -> '{}' (Committed TXG #{})", from, path(to), txg),
            Err(e) => crate::println!("cp: failed to copy '{}' to '{}': {}", from, to, e),
        },
        ["ps", ..] => {
            for t in crate::task::get_task_snapshots() {
                crate::println!("  {:<5} {:<5} {:<16} {:?}", t.id.0, t.uid, t.name, t.state);
            }
        }
        ["kill", pid, ..] => match pid.parse::<u64>() {
            Ok(pid) if pid > 1 && crate::task::kill(crate::task::TaskId(pid)) => crate::println!("[+] Task #{} terminated.", pid),
            _ => crate::println!("kill: no such task (or not allowed)"),
        },
        ["mem", ..] => {
            let m = crate::admin::system::mem_info();
            crate::println!("  RAM {} MiB, free {} MiB; kernel heap {} KiB used of {} KiB", m.total >> 20, m.free >> 20, m.heap_used >> 10, m.heap_total >> 10);
        }
        ["service", "restart", name, ..] => crate::println!("{:?}", crate::task::supervisor::restart_service_by_name(name).map(|t| t.0)),
        ["service", "start", name, ..] => crate::println!("{:?}", crate::task::supervisor::SUPERVISOR.lock().start_service(name).map(|t| t.0)),
        ["service", ..] => {
            for s in crate::task::supervisor::get_service_snapshots() {
                crate::println!("  {:<16} pid {:<6} {:?}, {} restarts", s.name, s.task_id.map_or(-1, |p| p as i64), s.state, s.restart_count);
            }
        }
        ["zpool", ..] => {
            let disk = if crate::fs::zfs::disk_info().is_some() { "on disk" } else { "RAM fallback" };
            match ZfsClient::pool_status() {
                Ok((mib, alloc_kib, free_kib, txg)) => crate::println!("  hydrapool {}: {} MiB, {} KiB used, {} KiB free, TXG #{}", disk, mib, alloc_kib, free_kib, txg),
                Err(e) => crate::println!("zpool: {}", e),
            }
        }
        ["linux", "chroot", root, argv @ ..] if !argv.is_empty() => {
            let (uid, gid, _) = session::user();
            crate::admin::linux::run_chroot(root, argv, uid, gid);
        }
        ["ushell" | "exit", ..] => return false,
        ["shutdown" | "poweroff", ..] => {
            crate::println!("[*] Powering down system...");
            crate::arch::power::power_off();
        }
        ["reboot", ..] => {
            crate::println!("[*] Rebooting system...");
            crate::arch::power::reboot();
        }
        ["halt", ..] => {
            crate::println!("[*] Halting CPU. Hardware interrupts disabled.");
            x86_64::instructions::interrupts::disable();
            loop {
                x86_64::instructions::hlt();
            }
        }
        [cmd, ..] => crate::println!("'{}': not an emergency command, or arguments missing; type 'help'", cmd),
        [] => {}
    }
    true
}

/// Runs the emergency prompt until `ushell`.
///
/// # Arguments
/// * `reason` - Why it runs (shown at the top).
pub fn run(reason: &str) {
    set_color(Color::LightRed, Color::Black);
    crate::println!("\n[!] EMERGENCY PROMPT: {}", reason);
    set_color(Color::White, Color::Black);
    crate::println!("    A tiny console inside the kernel: 'help' lists its commands, 'ushell' starts hydra-shell again.\n");
    login();
    let mut cwd = String::from("/");
    loop {
        set_color(Color::LightRed, Color::Black);
        let line = read_input(&alloc::format!("emergency:{}# ", cwd), false);
        set_color(Color::White, Color::Black);
        let words = split(&line);
        let w: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        if !execute(&w, &mut cwd) {
            return;
        }
    }
}
