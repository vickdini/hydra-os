//! # hydra-shell: Hydra's console shell, in Ring 3
//!
//! The kernel shell (`src/shell`) is moving out of the kernel (microkernel plan, group 4).
//! This is its ring-3 successor. It asks the kernel for what it needs through the admin
//! interface (`src/admin`, the native system call `SYS_ADMIN`; design in
//! `docs/shell-admin-interface.md`) and reads files through the native `open`/`read` calls.
//!
//! Part 1 (now): a first subset of commands with the kernel shell's output, started from the
//! kernel shell with `ushell` for testing; `exit` (or Ctrl+D) goes back to the kernel shell.
//! Part 2: every command, and the console starts it instead of the kernel shell.
//!
//! Arguments (from `ushell`): `--cwd=DIR --uid=N --user=NAME`.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../../../src/admin/proto.rs"]
#[allow(dead_code)]
mod proto;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use hydra_rt::{print, println, sys};
use proto::*;

hydra_rt::entry!(main);

// ---------------------------------------------------------------------------
// System calls the runtime does not wrap
// ---------------------------------------------------------------------------

/// Native `open` (`rdi` path, `rsi` length, `rdx` flags: 0 read).
const SYS_OPEN: u64 = 9;
/// Native `close`.
const SYS_CLOSE: u64 = 10;
/// Native `read` (`rdi` fd, `rsi` buffer, `rdx` count).
const SYS_READ: u64 = 11;

/// A native system call with three arguments.
fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

/// An admin call failure: the errno and the kernel's message, if any.
struct AdminError {
    errno: i64,
    message: String,
}

/// Calls admin operation `op`; answers its bytes.
fn admin(op: u32, args: [u64; 4], input: &[u8]) -> Result<Vec<u8>, AdminError> {
    let mut cap = 4096usize;
    loop {
        let mut out = alloc::vec![0u8; cap];
        let mut call = AdminCall {
            op,
            flags: 0,
            args,
            in_ptr: input.as_ptr() as u64,
            in_len: input.len() as u64,
            out_ptr: out.as_mut_ptr() as u64,
            out_cap: cap as u64,
            err_len: 0,
        };
        let r = syscall3(SYS_ADMIN, &mut call as *mut AdminCall as u64, 0, 0);
        if r < 0 {
            let n = (call.err_len as usize).min(cap);
            let message = String::from(core::str::from_utf8(&out[..n]).unwrap_or(""));
            return Err(AdminError { errno: -r, message });
        }
        let need = r as usize;
        if need <= cap {
            out.truncate(need);
            return Ok(out);
        }
        cap = need + 4096;
    }
}

// UEFI text colours (as `uefi::proto::console::text::Color`)
const BLACK: u64 = 0;
const LIGHT_GRAY: u64 = 7;
const DARK_GRAY: u64 = 8;
const LIGHT_GREEN: u64 = 10;
const LIGHT_CYAN: u64 = 11;
const LIGHT_RED: u64 = 12;
const LIGHT_MAGENTA: u64 = 13;
const YELLOW: u64 = 14;
const WHITE: u64 = 15;

/// Sets the console colours (as the kernel shell's `set_color(fg, Black)`).
fn color(fg: u64) {
    let _ = admin(ADMIN_CONSOLE_COLOR, [fg, BLACK, 0, 0], &[]);
}

// ---------------------------------------------------------------------------
// Shell state, input and words
// ---------------------------------------------------------------------------

/// The session: working directory and user.
struct Shell {
    cwd: String,
    uid: u32,
    running: bool,
}

impl Shell {
    /// The prompt, as the kernel shell's `format_prompt`.
    fn prompt(&self) -> String {
        format!("hydra:{}{}", self.cwd, if self.uid == 0 { "# " } else { "$ " })
    }

    /// The prompt colour: light cyan for root, light green for others.
    fn prompt_color(&self) -> u64 {
        if self.uid == 0 { LIGHT_CYAN } else { LIGHT_GREEN }
    }
}

/// Reads one byte of console input, waiting for it.
fn read_byte() -> u8 {
    let mut b = [0u8; 1];
    loop {
        if syscall3(SYS_READ, 0, b.as_mut_ptr() as u64, 1) == 1 {
            return b[0];
        }
        sys::sleep_ms(10);
    }
}

/// Reads a line with echo, backspace, Ctrl+C (cancel) and Ctrl+D (end, on an empty line).
///
/// # Returns
/// The line, or `None` at the end of input.
fn read_line(sh: &Shell) -> Option<String> {
    let mut line = String::new();
    loop {
        match read_byte() {
            b'\r' | b'\n' => {
                println!();
                return Some(line);
            }
            3 => {
                color(LIGHT_GRAY);
                println!("^C");
                line.clear();
                color(sh.prompt_color());
                print!("{}", sh.prompt());
                color(WHITE);
            }
            4 if line.is_empty() => return None,
            8 | 0x7f => {
                if line.pop().is_some() {
                    print!("\x08 \x08");
                }
            }
            c if (0x20..0x7f).contains(&c) => {
                line.push(c as char);
                let s = [c];
                sys::write(1, &s);
            }
            _ => {}
        }
    }
}

/// Splits a command line into words (the kernel shell's `split_words`: POSIX quoting).
fn split_words(line: &str) -> Vec<String> {
    const SQ: char = '\'';
    const BS: char = '\\';
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == SQ {
            in_word = true;
            for q in chars.by_ref() {
                if q == SQ {
                    break;
                }
                cur.push(q);
            }
        } else if c == '"' {
            in_word = true;
            while let Some(q) = chars.next() {
                if q == '"' {
                    break;
                }
                if q == BS {
                    if let Some(n) = chars.next() {
                        if !(n == '"' || n == BS || n == '$' || n == '`') {
                            cur.push(BS);
                        }
                        cur.push(n);
                    }
                } else {
                    cur.push(q);
                }
            }
        } else if c == BS {
            in_word = true;
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c.is_whitespace() {
            if in_word {
                words.push(core::mem::take(&mut cur));
                in_word = false;
            }
        } else {
            in_word = true;
            cur.push(c);
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Normalizes `path` against `cwd` (the kernel's `fs::client::normalize_path`: `.` and `..`,
/// backslashes, at most 16 components).
fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let absolute = path.starts_with('/') || path.starts_with('\\');
    if !absolute {
        for t in cwd.split(['/', '\\']) {
            if !t.is_empty() && t != "." && parts.len() < 16 {
                parts.push(t);
            }
        }
    }
    for t in path.split(['/', '\\']) {
        if t.is_empty() || t == "." {
            continue;
        } else if t == ".." {
            parts.pop();
        } else if parts.len() < 16 {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        return String::from("/");
    }
    let mut out = String::new();
    for p in parts {
        out.push('/');
        out.push_str(p);
    }
    // As the kernel's 128-byte buffer
    out.truncate(128);
    out
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// A command: name, aliases, one-line description, handler.
struct Command {
    name: &'static str,
    aliases: &'static [&'static str],
    about: &'static str,
    run: fn(&mut Shell, &[&str]),
}

/// The commands ported so far (part 1). Each prints what the kernel shell's does.
static COMMANDS: &[Command] = &[
    Command { name: "help", aliases: &["?"], about: "List the commands of this shell", run: cmd_help },
    Command { name: "echo", aliases: &[], about: "Print the arguments", run: cmd_echo },
    Command { name: "pwd", aliases: &[], about: "Print the working directory", run: cmd_pwd },
    Command { name: "cd", aliases: &["chdir"], about: "Change the working directory", run: cmd_cd },
    Command { name: "ls", aliases: &["dir"], about: "List a ZFS directory (-l sizes, -a all)", run: cmd_ls },
    Command { name: "cat", aliases: &["type"], about: "Print a file", run: cmd_cat },
    Command { name: "uname", aliases: &[], about: "Print system information (-a, -s, -n, -r, -v, -m)", run: cmd_uname },
    Command { name: "ps", aliases: &["tasks", "threads"], about: "List tasks", run: cmd_ps },
    Command { name: "mem", aliases: &["memory"], about: "Physical memory and kernel heap statistics", run: cmd_mem },
    Command { name: "service", aliases: &["rs", "daemon", "daemons"], about: "Supervised services (status|list)", run: cmd_service },
    Command { name: "zpool", aliases: &[], about: "Pool status (status|list)", run: cmd_zpool },
    Command { name: "shutdown", aliases: &["poweroff"], about: "Power off", run: cmd_shutdown },
    Command { name: "reboot", aliases: &["restart"], about: "Restart the computer", run: cmd_reboot },
    Command { name: "exit", aliases: &["logout"], about: "Leave hydra-shell (back to the kernel shell)", run: cmd_exit },
];

fn cmd_help(_sh: &mut Shell, _args: &[&str]) {
    color(LIGHT_CYAN);
    println!("hydra-shell (Ring 3) commands:");
    color(WHITE);
    for c in COMMANDS {
        println!("  {:<10} {}", c.name, c.about);
    }
}

fn cmd_echo(_sh: &mut Shell, args: &[&str]) {
    let mut line = String::new();
    for (i, w) in args.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        line.push_str(w);
    }
    println!("{}", line);
}

fn cmd_pwd(sh: &mut Shell, _args: &[&str]) {
    color(WHITE);
    println!("{}", sh.cwd);
}

fn cmd_cd(sh: &mut Shell, args: &[&str]) {
    let target = if args.is_empty() || args[0] == "~" { "/root" } else { args[0] };
    let path = normalize_path(&sh.cwd, target);
    match admin(ADMIN_LOOKUP, [0; 4], path.as_bytes()).ok().and_then(|a| read_record::<LookupRecord>(&a, 0)) {
        Some(r) if r.kind == KIND_DIR as u64 => sh.cwd = path,
        Some(_) => {
            color(LIGHT_RED);
            println!("cd: '{}' is not a directory", target);
        }
        None => {
            if target == "/root" {
                sh.cwd = String::from("/");
            } else {
                color(LIGHT_RED);
                println!("cd: no such file or directory: '{}'", target);
            }
        }
    }
}

fn cmd_ls(sh: &mut Shell, args: &[&str]) {
    let (mut long, mut all, mut target) = (false, false, "");
    for &a in args {
        if a.starts_with('-') && a.len() > 1 {
            for c in a.chars().skip(1) {
                match c {
                    'l' => long = true,
                    'a' => all = true,
                    _ => {}
                }
            }
        } else if target.is_empty() {
            target = a;
        }
    }
    let raw = if target.is_empty() { sh.cwd.clone() } else { String::from(target) };
    let path = normalize_path(&sh.cwd, &raw);
    let answer = match admin(ADMIN_DIR_LIST, [0; 4], path.as_bytes()) {
        Ok(a) => a,
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Failed to list directory '{}': {}", path, e.message);
            return;
        }
    };
    let header: DirHeader = read_record(&answer, 0).unwrap_or_default();
    color(YELLOW);
    println!("ZFS Directory listing for '{}' (Dataset: {}):", path, name_str(&header.dataset));
    if long {
        println!("{:<24} {:<10} {:>10} {:>10} {:>10}", "NAME", "TYPE", "SIZE", "CHECKSUM", "STATUS");
    } else {
        println!("{:<24} {:<10} {:>10} {:>10}", "NAME", "TYPE", "CHECKSUM", "STATUS");
    }
    println!("------------------------------------------------------------");
    let mut printed = 0;
    let size = core::mem::size_of::<DirRecord>();
    for i in 0..header.count as usize {
        let Some(e) = read_record::<DirRecord>(&answer, core::mem::size_of::<DirHeader>() + i * size) else { break };
        if e.kind == KIND_INVALID {
            continue;
        }
        let name = name_str(&e.name);
        if !all && name.starts_with('.') && name != "." && name != ".." {
            continue;
        }
        let is_dir = e.kind == KIND_DIR;
        let kind = if is_dir { "<DIR>" } else { "<FILE>" };
        color(if is_dir { LIGHT_CYAN } else { WHITE });
        if long {
            let item = normalize_path(&path, name);
            let size = admin(ADMIN_LOOKUP, [0; 4], item.as_bytes())
                .ok()
                .and_then(|a| read_record::<LookupRecord>(&a, 0))
                .map_or(0, |r| r.size);
            println!("{:<24} {:<10} {:>10} {:>10} {:>10}", name, kind, size, "Fletcher4", "ONLINE");
        } else {
            println!("{:<24} {:<10} {:>10} {:>10}", name, kind, "Fletcher4", "ONLINE");
        }
        printed += 1;
    }
    if printed == 0 {
        color(DARK_GRAY);
        println!("  (empty directory)");
    }
    color(LIGHT_GREEN);
    println!("------------------------------------------------------------");
    println!("Total entries: {} (ZFS pool: hydrapool, CoW enabled)\n", header.count);
}

fn cmd_cat(sh: &mut Shell, args: &[&str]) {
    let Some(&target) = args.first() else {
        color(LIGHT_RED);
        println!("cat: reading standard input is not ported yet");
        return;
    };
    let path = normalize_path(&sh.cwd, target);
    // The kernel's checks first (its messages), then the file through the native calls
    let fail = |msg: &str| {
        color(LIGHT_RED);
        println!("[!] Cannot read file '{}': {}", path, msg);
    };
    match admin(ADMIN_LOOKUP, [0; 4], path.as_bytes()) {
        Err(e) => return fail(&e.message),
        Ok(a) => match read_record::<LookupRecord>(&a, 0) {
            Some(r) if r.kind == KIND_FILE as u64 => {}
            _ => return fail("Target path is not a regular file"),
        },
    }
    let fd = syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0);
    if fd < 0 {
        return fail("ZFS I/O error");
    }
    // As the kernel shell: the first 4 KiB
    let mut buf = alloc::vec![0u8; 4096];
    let mut n = 0;
    while n < buf.len() {
        let r = syscall3(SYS_READ, fd as u64, buf[n..].as_mut_ptr() as u64, (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    syscall3(SYS_CLOSE, fd as u64, 0, 0);
    color(WHITE);
    match core::str::from_utf8(&buf[..n]) {
        Ok(text) => {
            for line in text.lines() {
                println!("{}", line);
            }
        }
        Err(_) => println!("[Binary data: {} bytes, Fletcher-4 checksum verified]", n),
    }
}

fn cmd_uname(_sh: &mut Shell, args: &[&str]) {
    let (mut s, mut n, mut r, mut v, mut m) = (false, false, false, false, false);
    for &a in args {
        if a.starts_with('-') && a.len() > 1 {
            for c in a.chars().skip(1) {
                match c {
                    'a' => (s, n, r, v, m) = (true, true, true, true, true),
                    's' => s = true,
                    'n' => n = true,
                    'r' => r = true,
                    'v' => v = true,
                    'm' => m = true,
                    _ => {}
                }
            }
        }
    }
    if !(s || n || r || v || m) {
        s = true;
    }
    let mut parts: Vec<&str> = Vec::new();
    if s { parts.push("Hydra"); }
    if n { parts.push("hydra-node-0"); }
    if r { parts.push("0.1.0"); }
    if v { parts.push("#1 SMP UEFI 64-bit Long Mode"); }
    if m { parts.push("x86_64"); }
    color(WHITE);
    println!("{}", parts.join(" "));
}

/// Prints an admin failure as the kernel shell would print the condition.
fn report(e: &AdminError, what: &str) {
    if e.errno == EIO && !e.message.is_empty() {
        color(YELLOW);
        println!("[-] {}", e.message);
    } else {
        color(LIGHT_RED);
        println!("[!] {}: {}", what, if e.message.is_empty() { errno_name(e.errno) } else { &e.message });
    }
}

/// A short name of an admin errno.
fn errno_name(e: i64) -> &'static str {
    match e {
        EPERM => "not an authorized admin console",
        ENOENT => "not found",
        EFAULT => "bad address",
        EINVAL => "invalid argument",
        ENOSYS => "operation not supported by this kernel",
        _ => "error",
    }
}

fn cmd_ps(_sh: &mut Shell, _args: &[&str]) {
    let answer = match admin(ADMIN_TASK_LIST, [0; 4], &[]) {
        Ok(a) => a,
        Err(e) => return report(&e, "ps"),
    };
    let header: TaskListHeader = read_record(&answer, 0).unwrap_or_default();
    color(LIGHT_CYAN);
    println!("{:<5} {:<5} {:<14} {:<8} {:<11} {:<9} {:>8} {:>18}", "PID", "UID", "NAME", "MODE", "STATE", "PRIORITY", "TICKS", "STACK (RSP)");
    println!("{:-<84}", "");
    let size = core::mem::size_of::<TaskRecord>();
    for i in 0..header.count as usize {
        let Some(t) = read_record::<TaskRecord>(&answer, core::mem::size_of::<TaskListHeader>() + i * size) else { break };
        let (state, c) = match t.state {
            STATE_RUNNING => ("Running", LIGHT_GREEN),
            STATE_READY => ("Ready", WHITE),
            STATE_SLEEPING => ("Sleeping", YELLOW),
            STATE_BLOCKED => ("Blocked", LIGHT_MAGENTA),
            _ => ("Dead", DARK_GRAY),
        };
        color(c);
        let mode = if t.mode == MODE_KERNEL { "Kernel" } else { "User" };
        let prio = PRIORITY_NAMES.get(t.priority as usize).copied().unwrap_or("?");
        println!("{:<5} {:<5} {:<14} {:<8} {:<11} {:<9} {:>8} {:#018x}", t.pid, t.uid, name_str(&t.name), mode, state, prio, t.ticks, t.rsp);
    }
    color(LIGHT_CYAN);
    println!("{:-<78}", "");
    println!("Total tasks: {} | Timeslice: {} ms | Worker counter: {}", header.count, header.timeslice_ms, header.worker_counter);
}

fn cmd_mem(_sh: &mut Shell, _args: &[&str]) {
    let m: MemInfo = match admin(ADMIN_MEM_INFO, [0; 4], &[]) {
        Ok(a) => read_record(&a, 0).unwrap_or_default(),
        Err(e) => return report(&e, "mem"),
    };
    color(LIGHT_CYAN);
    println!("\nPhysical Memory Manager Statistics:");
    color(WHITE);
    println!("  Total Usable RAM:   {} bytes ({} MiB)", m.total, m.total / (1024 * 1024));
    println!("  Allocated Frames:   {} bytes ({} KiB, {} frames)", m.allocated, m.allocated / 1024, m.allocated / m.page_size.max(1));
    println!("  Free Memory:        {} bytes ({} MiB)", m.free, m.free / (1024 * 1024));
    println!("  Base Page Size:     {} bytes (4 KiB)", m.page_size);
    color(LIGHT_CYAN);
    println!("\nDynamic Kernel Heap Allocator:");
    color(WHITE);
    if m.heap_initialized != 0 {
        println!("  Heap Status:        ONLINE");
        println!("  Start Address:      {:#x}", m.heap_start);
        println!("  Total Heap Size:    {} bytes ({} MiB)", m.heap_total, m.heap_total / (1024 * 1024));
        println!("  Used Heap Memory:   {} bytes ({} KiB)", m.heap_used, m.heap_used / 1024);
        println!("  Free Heap Memory:   {} bytes ({} KiB)", m.heap_free, m.heap_free / 1024);
    } else {
        println!("  Heap Status:        OFFLINE (not initialized)");
    }
    println!();
}

fn cmd_service(_sh: &mut Shell, args: &[&str]) {
    let sub = args.first().copied().unwrap_or("status");
    if sub != "status" && sub != "list" {
        color(LIGHT_RED);
        println!("[!] service {}: not ported yet (hydra-shell has status and list)", sub);
        color(WHITE);
        return;
    }
    let services = match admin(ADMIN_SERVICE_LIST, [0; 4], &[]) {
        Ok(a) => a,
        Err(e) => return report(&e, "service"),
    };
    let irqs = admin(ADMIN_IRQ_LIST, [0; 4], &[]).unwrap_or_default();
    color(LIGHT_CYAN);
    println!("\n=========================================================================================");
    println!(" HYDRA PROCESS SUPERVISOR & REINCARNATION SERVER (MINIX 3 ARCHITECTURE)                  ");
    println!("=========================================================================================");
    color(YELLOW);
    println!("{:<16} {:<8} {:<10} {:<12} {:<10} {:<12} {:<10}", "NAME", "PID", "ENDPOINT", "STATE", "RESTARTS", "MISSED PING", "HEALTH");
    color(DARK_GRAY);
    println!("-----------------------------------------------------------------------------------------");
    let size = core::mem::size_of::<ServiceRecord>();
    let count = services.len() / size;
    if count == 0 {
        color(LIGHT_GRAY);
        println!("  No microkernel services currently registered.");
    }
    for i in 0..count {
        let Some(s) = read_record::<ServiceRecord>(&services, i * size) else { break };
        let pid = if s.pid == u64::MAX { String::from("-") } else { format!("{}", s.pid) };
        let (state, c) = match s.state {
            SVC_RUNNING => ("Running", LIGHT_GREEN),
            SVC_RESTARTING => ("Restarting", LIGHT_MAGENTA),
            SVC_FAULTED => ("Faulted", LIGHT_RED),
            _ => ("Stopped", DARK_GRAY),
        };
        let health = if s.state == SVC_RUNNING {
            if s.unanswered_pings == 0 { "Healthy" } else { "Degraded" }
        } else {
            "-"
        };
        color(WHITE);
        print!("{:<16} {:<8} {:<#10x} ", name_str(&s.name), pid, s.endpoint);
        color(c);
        print!("{:<12} ", state);
        color(WHITE);
        println!("{:<10} {:<12} {:<10}", s.restarts, s.unanswered_pings, health);
    }
    let size = core::mem::size_of::<IrqRecord>();
    for i in 0..irqs.len() / size {
        let Some(q) = read_record::<IrqRecord>(&irqs, i * size) else { break };
        color(LIGHT_GRAY);
        println!(
            "  IRQ {:<3} -> process {:<6} {} interrupts, {} client wakes, {} pending, {}",
            q.irq, q.owner, q.count, q.notified, q.pending, if q.masked != 0 { "masked" } else { "unmasked" }
        );
    }
    color(LIGHT_CYAN);
    println!("=========================================================================================\n");
    color(WHITE);
}

fn cmd_zpool(_sh: &mut Shell, args: &[&str]) {
    let sub = args.first().copied().unwrap_or("status");
    let st: PoolStatus = match admin(ADMIN_POOL_STATUS, [0; 4], &[]) {
        Ok(a) => read_record(&a, 0).unwrap_or_default(),
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

fn cmd_shutdown(_sh: &mut Shell, _args: &[&str]) {
    color(YELLOW);
    println!("[*] Powering down system...");
    if let Err(e) = admin(ADMIN_POWER, [POWER_OFF, 0, 0, 0], &[]) {
        report(&e, "shutdown");
    }
}

fn cmd_reboot(_sh: &mut Shell, _args: &[&str]) {
    color(YELLOW);
    println!("[*] Rebooting system...");
    if let Err(e) = admin(ADMIN_POWER, [POWER_REBOOT, 0, 0, 0], &[]) {
        report(&e, "reboot");
    }
}

fn cmd_exit(sh: &mut Shell, _args: &[&str]) {
    sh.running = false;
}

/// Runs one command line.
fn execute(sh: &mut Shell, line: &str) {
    let words = split_words(line.trim());
    let Some(first) = words.first() else { return };
    let args: Vec<&str> = words[1..].iter().map(|s| s.as_str()).collect();
    match COMMANDS.iter().find(|c| c.name == first.as_str() || c.aliases.contains(&first.as_str())) {
        Some(c) => (c.run)(sh, &args),
        None => {
            color(LIGHT_RED);
            println!("hydra-shell: '{}' is not ported yet (part 2). Type 'help', or 'exit' for the kernel shell.", first);
        }
    }
}

fn main(args: &[&str]) {
    let mut sh = Shell { cwd: String::from("/"), uid: 0, running: true };
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("--cwd=") {
            sh.cwd = String::from(v);
        } else if let Some(v) = a.strip_prefix("--uid=") {
            sh.uid = v.parse().unwrap_or(0);
        }
    }
    // The interface must be there and ours (the kernel authorizes only its console)
    match admin(ADMIN_VERSION, [0; 4], &[]) {
        Ok(a) if a.len() >= 4 && u32::from_le_bytes([a[0], a[1], a[2], a[3]]) == ADMIN_ABI_VERSION => {}
        Ok(_) => {
            println!("hydra-shell: admin interface version mismatch");
            return;
        }
        Err(e) => {
            println!("hydra-shell: no admin interface: {}", errno_name(e.errno));
            return;
        }
    }
    color(LIGHT_CYAN);
    println!("hydra-shell (Ring 3, pid {}): 'help' lists the ported commands, 'exit' returns.", sys::getpid());
    while sh.running {
        color(sh.prompt_color());
        print!("{}", sh.prompt());
        color(WHITE);
        let Some(line) = read_line(&sh) else { break };
        if !line.trim().is_empty() {
            execute(&mut sh, &line);
        }
    }
    color(WHITE);
}
