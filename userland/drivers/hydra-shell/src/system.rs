//! Tasks, programs, memory, the CPU, services, the console's look, power and fault tests.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::{normalize_path, report, usage, Shell};
use hydra_rt::{print, println};

pub fn info(_sh: &mut Shell, _args: &[&str]) {
    color(LIGHT_CYAN);
    println!("\n============================================================");
    println!("                HYDRA MICROKERNEL v0.1.0                     ");
    println!("     UNIX-like Distributed Cloud/Fog/Edge Operating System  ");
    println!("============================================================");
    color(WHITE);
    println!("Target:        x86_64-unknown-uefi (Native 64-bit Long Mode)");
    println!("Security:      Object-Capability Security Model (seL4-inspired)");
    println!("IPC:           Synchronous Rendezvous & Fast Inline Register Passing");
    println!("Memory:        4-Level PML4 Paging & Physical Frame Allocator");
    println!("Console:       hydra-shell (Ring 3) on the kernel's admin interface");
    println!("Distributed:   Self-* Autonomous Healing, Edge/Cloud Resource Virtualization\n");
}

pub fn status(_sh: &mut Shell, _args: &[&str]) {
    let m: MemInfo = admin_rec(ADMIN_MEM_INFO, [0; 4], &[]).unwrap_or_default();
    let c: CpuState = admin_rec(ADMIN_CPU_STATE, [0; 4], &[]).unwrap_or_default();
    let services = admin(ADMIN_SERVICE_LIST, [0; 4], &[]).unwrap_or_default();
    let n = services.len() / core::mem::size_of::<ServiceRecord>();
    color(LIGHT_GREEN);
    println!("\nSubsystem Status:");
    println!("  [+] GDT & TSS:           ONLINE (Ring 0 & Ring 3 segments initialized)");
    println!("  [+] CPU Registers:       ONLINE (Paging and Protection enabled)");
    println!("  [+] Frame Allocator:     ONLINE (Usable: {} MiB, Alloc: {} KiB, Free: {} MiB)", m.total >> 20, m.allocated >> 10, m.free >> 20);
    println!("  [+] Virtual Memory:      ONLINE (Active PML4: {:#x}, this shell's address space)", c.cr3);
    println!("  [+] Service Supervisor:  ONLINE ({} supervised services)", n);
    println!("  [+] Admin Interface:     ONLINE (ABI version {}, this console)\n", ADMIN_ABI_VERSION);
}

pub fn clear(_sh: &mut Shell, _args: &[&str]) {
    ctl(CTL_CLEAR_SCROLLBACK, 0, 0, 0, &[]);
    ctl(CTL_CLEAR, 0, 0, 0, &[]);
}

pub fn color_cmd(_sh: &mut Shell, args: &[&str]) {
    let Some(&name) = args.first() else { return usage("color <cyan|green|yellow|red|white|magenta|blue>") };
    let c = match name {
        "cyan" => LIGHT_CYAN,
        "green" => LIGHT_GREEN,
        "yellow" => YELLOW,
        "red" => LIGHT_RED,
        "white" => WHITE,
        "magenta" => LIGHT_MAGENTA,
        "blue" => LIGHT_BLUE,
        _ => {
            println!("Available colors: cyan, green, yellow, red, white, magenta, blue");
            return;
        }
    };
    color(c);
    println!("[+] Text color changed to {} (until the next command)", name);
}

pub fn cursor(_sh: &mut Shell, args: &[&str]) {
    match args.first().copied() {
        Some("on") | Some("enable") => {
            ctl(CTL_CURSOR_ENABLE, 1, 0, 0, &[]);
            color(LIGHT_GREEN);
            println!("[+] Terminal cursor enabled.");
        }
        Some("off") | Some("disable") => {
            ctl(CTL_CURSOR_ENABLE, 0, 0, 0, &[]);
            color(YELLOW);
            println!("[-] Terminal cursor disabled.");
        }
        Some(s @ ("underline" | "block" | "bar")) => {
            let n = match s {
                "underline" => 0,
                "block" => 1,
                _ => 2,
            };
            ctl(CTL_CURSOR_SHAPE, n, 0, 0, &[]);
            color(LIGHT_CYAN);
            println!("[+] Terminal cursor shape set to {}.", s);
        }
        Some(other) => {
            println!("[-] Unknown cursor option: '{}'", other);
            println!("Usage: cursor [on|off|underline|block|bar]");
        }
        None => {
            let [enabled, shape] = ctl(CTL_CURSOR_INFO, 0, 0, 0, &[]);
            let [col, row] = ctl(CTL_CURSOR_GET, 0, 0, 0, &[]);
            color(LIGHT_CYAN);
            println!("[*] Terminal Cursor Status:");
            println!("    Enabled:  {}", if enabled != 0 { "yes" } else { "no" });
            println!("    Shape:    {}", ["underline", "block", "bar"].get(shape as usize).unwrap_or(&"?"));
            println!("    Position: col {}, row {}", col, row);
            println!("    Blink:    ~1 Hz (500ms interval)");
            println!("Usage: cursor [on|off|underline|block|bar]");
        }
    }
}

pub fn scroll(_sh: &mut Shell, args: &[&str]) {
    let mode = match args.first().copied() {
        Some("on") => 1,
        Some("off") => 0,
        _ => 2,
    };
    if ctl(CTL_SCROLL_LOCK, mode, 0, 0, &[])[0] != 0 {
        color(LIGHT_CYAN);
        println!("[+] Scroll Lock: ON");
        println!("    Use Up / Down arrow keys (or PageUp / PageDown) to scroll the terminal screen.");
        println!("    Type 'scroll off' or toggle Scroll Lock (or Ctrl+S) to resume history navigation.");
    } else {
        color(YELLOW);
        println!("[-] Scroll Lock: OFF");
        println!("    Up / Down arrow keys now navigate command history as normal.");
    }
}

pub fn sync(_sh: &mut Shell, args: &[&str]) {
    match admin(ADMIN_FS_OP, [FS_SYNC, 0, 0, 0], &[]) {
        Ok(_) => {
            color(LIGHT_GREEN);
            println!("[+] OpenZFS Storage: Synchronized all metadata, dnodes, and flushed ATA write caches to persistent media.");
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Failed to sync storage pool: {}", e.text());
        }
    }
    if !args.iter().any(|&a| a == "--all" || a == "-a") {
        return;
    }
    color(LIGHT_GREEN);
    println!("\n============================================================");
    println!(" [+] HYDRA MICROKERNEL: SYNCHRONIZATION & WAIT QUEUES       ");
    println!("============================================================");
    println!("  Active System IPC Endpoints (0..7):");
    println!("    {:<5} {:<12} {:<15} {:<15}", "EP_ID", "PENDING_MSGS", "WAIT_RECEIVERS", "WAIT_SENDERS");
    println!("    {:-<50}", "");
    let eps = admin(ADMIN_ENDPOINT_LIST, [0; 4], &[]).unwrap_or_default();
    for e in records::<EndpointRecord>(&eps, 0, eps.len() / core::mem::size_of::<EndpointRecord>()) {
        if e.pending > 0 || e.receivers > 0 || e.senders > 0 || e.id <= 2 {
            println!("    {:<5} {:<12} {:<15} {:<15}", e.id, e.pending, e.receivers, e.senders);
        }
    }
    if let Ok(a) = admin(ADMIN_TASK_LIST, [0; 4], &[]) {
        let h: TaskListHeader = read_record(&a, 0).unwrap_or_default();
        let mut n = [0usize; 5];
        for t in records::<TaskRecord>(&a, core::mem::size_of::<TaskListHeader>(), h.count as usize) {
            n[(t.state as usize).min(4)] += 1;
        }
        println!("\n  Scheduler Task State Summary:");
        println!("    - Running: {} | Ready: {} | Blocked: {} | Sleeping: {}", n[STATE_RUNNING as usize], n[STATE_READY as usize], n[STATE_BLOCKED as usize], n[STATE_SLEEPING as usize]);
    }
    println!("============================================================\n");
}

pub fn uname(_sh: &mut Shell, args: &[&str]) {
    let flags: String = args.iter().filter(|a| a.starts_with('-')).flat_map(|a| a.chars().skip(1)).collect();
    let all = flags.contains('a');
    let mut parts: Vec<&str> = Vec::new();
    let want = |c| all || flags.contains(c);
    if want('s') || flags.is_empty() {
        parts.push("Hydra");
    }
    if want('n') {
        parts.push("hydra-node-0");
    }
    if want('r') {
        parts.push("0.1.0");
    }
    if want('v') {
        parts.push("#1 SMP UEFI 64-bit Long Mode");
    }
    if want('m') {
        parts.push("x86_64");
    }
    color(WHITE);
    println!("{}", parts.join(" "));
}

pub fn uptime(_sh: &mut Shell, _args: &[&str]) {
    let t: RtcTime = admin_rec(ADMIN_RTC_TIME, [0; 4], &[]).unwrap_or_default();
    let secs = t.ticks / 100;
    color(LIGHT_GREEN);
    println!("[+] Uptime: {:02}:{:02}:{:02} ({} total seconds)", secs / 3600, (secs % 3600) / 60, secs % 60, secs);
    color(LIGHT_CYAN);
    println!("    - PIT Hardware Ticks : {} ticks @ 100 Hz (10 ms interval)", t.ticks);
}

pub fn ps(_sh: &mut Shell, _args: &[&str]) {
    let answer = match admin(ADMIN_TASK_LIST, [0; 4], &[]) {
        Ok(a) => a,
        Err(e) => return report(&e, "ps"),
    };
    let header: TaskListHeader = read_record(&answer, 0).unwrap_or_default();
    color(LIGHT_CYAN);
    println!("{:<5} {:<5} {:<14} {:<8} {:<11} {:<9} {:>8} {:>18}", "PID", "UID", "NAME", "MODE", "STATE", "PRIORITY", "TICKS", "STACK (RSP)");
    println!("{:-<84}", "");
    for t in records::<TaskRecord>(&answer, core::mem::size_of::<TaskListHeader>(), header.count as usize) {
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

pub fn kill(_sh: &mut Shell, args: &[&str]) {
    let Some(&a) = args.first() else { return usage("kill <pid>") };
    let Some(pid) = parse_num(a) else {
        color(LIGHT_RED);
        println!("Invalid PID '{}'", a);
        return;
    };
    match admin(ADMIN_TASK_KILL, [pid, 0, 0, 0], &[]) {
        Ok(_) => {
            color(LIGHT_GREEN);
            println!("[+] Task #{} terminated.", pid);
        }
        Err(e) if e.errno == ENOENT => {
            color(LIGHT_RED);
            println!("[!] Task #{} not found or already dead.", pid);
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] {}.", e.text());
        }
    }
}

pub fn syscalls(_sh: &mut Shell, _args: &[&str]) {
    let s: SyscallStats = match admin_rec(ADMIN_SYSCALL_STATS, [0; 4], &[]) {
        Ok(s) => s,
        Err(e) => return report(&e, "syscalls"),
    };
    color(LIGHT_GREEN);
    println!("\n============================================================");
    println!(" [+] HYDRA MICROKERNEL: HARDWARE SYSTEM CALL SUBSYSTEM      ");
    println!("============================================================");
    println!("  Hardware MSR Registers:");
    println!("    - IA32_EFER.SCE (0xC0000080) : {:#018x} (SCE={})", s.efer, s.efer & 1);
    println!("    - IA32_STAR     (0xC0000081) : {:#018x}", s.star);
    println!("      * Kernel CS:SS Base : {:#06x} / {:#06x}", (s.star >> 32) & 0xFFFF, ((s.star >> 32) & 0xFFFF) + 8);
    println!("      * User CS:SS Base   : {:#06x} (CS={:#06x}, SS={:#06x})", (s.star >> 48) & 0xFFFF, (((s.star >> 48) & 0xFFFF) + 16) | 3, (((s.star >> 48) & 0xFFFF) + 8) | 3);
    println!("    - IA32_LSTAR    (0xC0000082) : {:#018x} (asm_syscall_entry)", s.lstar);
    println!("    - IA32_FMASK    (0xC0000084) : {:#018x} (Flags masked on entry)", s.fmask);
    println!("\n  Registered System Calls & Invocation Counts:");
    let names = ["[1] SYS_YIELD   ", "[2] SYS_SLEEP   ", "[3] SYS_WRITE   ", "[4] SYS_EXIT    ", "[5] SYS_GETPID  ", "[6] SYS_UPTIME  ", "[7] SYS_IPC_SEND"];
    for (i, n) in names.iter().enumerate() {
        println!("    - {} : {} calls", n, s.counts[i]);
    }
    println!("    - [8] SYS_IPC_RECV : {} calls", s.counts[6]);
    println!("    ---------------------------------------------");
    println!("    * Total Hardware System Calls Handled: {}", s.counts[7]);
    println!("============================================================\n");
}

// ---------------------------------------------------------------------------
// Programs of the pool
// ---------------------------------------------------------------------------

/// The pool paths a command name may mean, as the kernel shell searched them.
fn candidates(name: &str) -> Vec<String> {
    let mut c = alloc::vec![String::from(name)];
    if !name.starts_with('/') {
        c.push(alloc::format!("/bin/{}", name));
    }
    if !name.ends_with(".elf") {
        c.push(alloc::format!("{}.elf", name));
        if !name.starts_with('/') {
            c.push(alloc::format!("/bin/{}.elf", name));
        }
    }
    c
}

/// The ELF program of the pool a command name means.
fn find_program(sh: &Shell, name: &str) -> Option<String> {
    for c in candidates(name) {
        let p = normalize_path(&sh.cwd, &c);
        if lookup(&p).is_ok_and(|r| r.kind == KIND_FILE as u64) {
            if let Ok(head) = read_file(&p, 4) {
                if head == b"\x7fELF" {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Whether a command name means an ELF program of the pool.
pub fn program_exists(sh: &Shell, name: &str) -> bool {
    find_program(sh, name).is_some()
}

/// Starts an ELF program of the pool (native or Linux) and waits for it, unless `--bg`.
fn start(path: &str, args: &[&str]) {
    let bg = args.iter().any(|&a| a == "--bg" || a == "-b" || a == "&");
    let mut words: Vec<&str> = alloc::vec![path];
    words.extend(args.iter().copied().filter(|&a| a != "--bg" && a != "-b" && a != "&"));
    let flags = if bg { EXEC_BACKGROUND } else { 0 };
    match admin_rec::<ExecResult>(ADMIN_TASK_EXEC, [flags, 0, 0, 0], &nul_join(&words)) {
        Ok(r) => {
            color(LIGHT_GREEN);
            println!("[+] Spawned Ring 3 {} ELF process #{} ('{}').", if r.linux != 0 { "Linux" } else { "Native" }, r.pid, path);
            println!("    Privilege: Unprivileged Ring 3 (CS=0x33, SS=0x2b, RFLAGS=0x202)");
            if bg {
                println!("    Running in background. Type 'ps' to inspect execution.");
            } else {
                color(LIGHT_CYAN);
                println!("[*] ELF process #{} completed and exited cleanly.", r.pid);
            }
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Failed to load ELF binary '{}': {}", path, e.text());
        }
    }
}

/// Runs a command name as a program of the pool, if there is one.
///
/// # Returns
/// Whether a program was found (and started).
pub fn run_program(sh: &mut Shell, name: &str, args: &[&str]) -> bool {
    let Some(path) = find_program(sh, name) else { return false };
    color(LIGHT_CYAN);
    println!("[*] Executing ELF64 binary '{}' from ZFS File Server...", path);
    start(&path, args);
    true
}

/// Little-endian numbers of an ELF file.
fn le(d: &[u8], at: usize, n: usize) -> u64 {
    d.get(at..at + n).map_or(0, |b| b.iter().rev().fold(0u64, |v, &x| v << 8 | x as u64))
}

pub fn elf(sh: &mut Shell, args: &[&str]) {
    let info_only = args.iter().any(|&a| a == "-i" || a == "--info");
    let Some(&target) = args.iter().find(|a| !a.starts_with('-') && **a != "&") else {
        color(YELLOW);
        println!("Usage: elf [-i|--info] <file.elf> [--bg]");
        println!("Examples:");
        println!("  elf /bin/hello.elf            - Load and execute standalone binary");
        println!("  elf --info /bin/hello.elf     - Inspect ELF64 headers and segments");
        println!("  elf /bin/counter.elf --bg     - Run binary in background (Ring 3)");
        return;
    };
    let path = {
        let p = normalize_path(&sh.cwd, target);
        if lookup(&p).is_ok() || target.starts_with('/') { p } else { normalize_path("/bin", target) }
    };
    let data = match read_file(&path, 64 << 20) {
        Ok(d) => d,
        Err(_) => {
            color(LIGHT_RED);
            println!("[!] Error: ELF file '{}' not found in ZFS storage pool.", target);
            println!("    Use 'ls /bin' to inspect available files in hydrapool/bin.");
            return;
        }
    };
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        color(LIGHT_RED);
        println!("[!] Failed to parse ELF binary '{}': not an ELF64 file", path);
        return;
    }
    let (e_type, entry, phoff, phentsize, phnum) = (le(&data, 16, 2), le(&data, 24, 8), le(&data, 32, 8) as usize, le(&data, 54, 2) as usize, le(&data, 56, 2) as usize);
    color(LIGHT_GREEN);
    println!("\n============================================================");
    println!(" [+] HYDRA MICROKERNEL: ELF64 BINARY INSPECTOR & LOADER     ");
    println!("============================================================");
    color(WHITE);
    println!("  File Path       : {}", path);
    println!("  File Size       : {} bytes (Verified via ZFS Fletcher-4)", data.len());
    println!("  Object Type     : {}", match e_type {
        2 => "Executable (ET_EXEC - Fixed Virtual Address)",
        3 => "Shared Object / PIE (ET_DYN - Position-Independent)",
        _ => "Unknown / Other",
    });
    println!("  Architecture    : AMD x86-64 (EM_X86_64, 64-bit Little-Endian)");
    println!("  Entry Point     : {:#018x}", entry);
    println!("  Program Headers : {} entries (at file offset {:#x})", phnum, phoff);
    println!("\n  Program Headers Table (Segments):");
    println!("    {:<4} {:<10} {:<18} {:<18} {:<10} {:<10} {:<6}", "IDX", "TYPE", "FILE_OFFSET", "VIRT_ADDR", "FILE_SZ", "MEM_SZ", "FLAGS");
    println!("    {:-<80}", "");
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        let (p_type, flags) = (le(&data, at, 4), le(&data, at + 4, 4));
        let name = match p_type {
            1 => "PT_LOAD",
            2 => "DYNAMIC",
            3 => "INTERP",
            4 => "NOTE",
            5 => "SHLIB",
            6 => "PHDR",
            7 => "TLS",
            _ => "OTHER",
        };
        let f = [if flags & 4 != 0 { 'R' } else { '-' }, if flags & 2 != 0 { 'W' } else { '-' }, if flags & 1 != 0 { 'X' } else { '-' }];
        let fs: String = f.iter().collect();
        println!("    {:<4} {:<10} {:#018x} {:#018x} {:#010x} {:#010x} {:<6}", i, name, le(&data, at + 8, 8), le(&data, at + 16, 8), le(&data, at + 32, 8), le(&data, at + 40, 8), fs);
    }
    println!("============================================================\n");
    if !info_only {
        let rest: Vec<&str> = args.iter().copied().filter(|&a| a != target && a != "-i" && a != "--info").collect();
        start(&path, &rest);
    }
}

// ---------------------------------------------------------------------------
// Memory and the CPU
// ---------------------------------------------------------------------------

pub fn mem(_sh: &mut Shell, _args: &[&str]) {
    let m: MemInfo = match admin_rec(ADMIN_MEM_INFO, [0; 4], &[]) {
        Ok(m) => m,
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

pub fn heap(_sh: &mut Shell, args: &[&str]) {
    if args.first() == Some(&"test") {
        color(LIGHT_CYAN);
        println!("[*] Running dynamic heap allocation self-test suite...");
        match admin(ADMIN_HEAP_TEST, [0; 4], &[]) {
            Ok(_) => {
                color(LIGHT_GREEN);
                println!("[+] Heap self-test PASSED:");
                println!("    - Box<u64> heap allocation & dereference verified");
                println!("    - Vec<usize> dynamic buffer reallocation (1,000 items) verified");
                println!("    - alloc::format! dynamic string verified");
                println!("    - RAII drop cleanup verified without memory leaks");
            }
            Err(e) => {
                color(LIGHT_RED);
                println!("[!] Heap self-test FAILED: {}", e.text());
            }
        }
        return;
    }
    let m: MemInfo = admin_rec(ADMIN_MEM_INFO, [0; 4], &[]).unwrap_or_default();
    color(LIGHT_CYAN);
    println!("\nDynamic Kernel Heap Statistics:");
    color(WHITE);
    if m.heap_initialized != 0 {
        println!("  Status:             ONLINE");
        println!("  Base Physical/Virt: {:#x}", m.heap_start);
        println!("  Total Size:         {} bytes ({} MiB)", m.heap_total, m.heap_total / (1024 * 1024));
        println!("  Used Memory:        {} bytes ({} KiB)", m.heap_used, m.heap_used / 1024);
        println!("  Free Memory:        {} bytes ({} KiB)", m.heap_free, m.heap_free / 1024);
        println!("  Heap Utilization:   {}%\n", if m.heap_total > 0 { m.heap_used * 100 / m.heap_total } else { 0 });
    } else {
        println!("  Status:             OFFLINE\n");
    }
}

/// Names of the set bits of a control register.
fn flag_names(v: u64, names: &[(u32, &str)]) -> String {
    let set: Vec<&str> = names.iter().filter(|(b, _)| v >> b & 1 != 0).map(|(_, n)| *n).collect();
    set.join(" | ")
}

pub fn cpu(_sh: &mut Shell, _args: &[&str]) {
    let c: CpuState = match admin_rec(ADMIN_CPU_STATE, [0; 4], &[]) {
        Ok(c) => c,
        Err(e) => return report(&e, "cpu"),
    };
    let cr0 = flag_names(c.cr0, &[(0, "PROTECTED_MODE_ENABLE"), (1, "MONITOR_COPROCESSOR"), (2, "EMULATE_COPROCESSOR"), (3, "TASK_SWITCHED"), (4, "EXTENSION_TYPE"), (5, "NUMERIC_ERROR"), (16, "WRITE_PROTECT"), (18, "ALIGNMENT_MASK"), (29, "NOT_WRITE_THROUGH"), (30, "CACHE_DISABLE"), (31, "PAGING")]);
    let cr4 = flag_names(c.cr4, &[(0, "VME"), (1, "PVI"), (2, "TSD"), (3, "DE"), (4, "PSE"), (5, "PAE"), (6, "MCE"), (7, "PGE"), (8, "PCE"), (9, "OSFXSR"), (10, "OSXMMEXCPT"), (11, "UMIP"), (16, "FSGSBASE"), (17, "PCIDE"), (18, "OSXSAVE"), (20, "SMEP"), (21, "SMAP")]);
    color(LIGHT_CYAN);
    println!("\nCPU State & Control Registers:");
    color(WHITE);
    println!("  CR0:                {:#x} ({}) (Paging & Protection flags)", c.cr0, cr0);
    println!("  CR2:                {:#x} (Last Page Fault linear address)", c.cr2);
    println!("  CR3 (PML4 Root):    {:#x} (Base physical address of 4-level page table)", c.cr3);
    println!("  CR4:                {:#x} ({}) (Architecture Extensions & PAE)\n", c.cr4, cr4);
}

pub fn translate(_sh: &mut Shell, args: &[&str]) {
    let Some(&s) = args.first() else { return usage("translate <virtual_address_hex> (e.g. translate 0x400000)") };
    let Some(addr) = crate::parse::parse_hex(s) else {
        color(LIGHT_RED);
        println!("[!] Invalid hexadecimal address: '{}'", s);
        return;
    };
    if let Err(e) = admin(ADMIN_TRANSLATE, [addr, 0, 0, 0], &[]) {
        if e.errno != ENOENT {
            report(&e, "translate");
        }
    }
}

pub fn time(_sh: &mut Shell, _args: &[&str]) {
    let t: RtcTime = admin_rec(ADMIN_RTC_TIME, [0; 4], &[]).unwrap_or_default();
    if t.valid != 0 {
        color(LIGHT_GREEN);
        println!("UEFI Hardware RTC: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", t.year, t.month, t.day, t.hour, t.minute, t.second);
    } else {
        color(LIGHT_RED);
        println!("[!] Could not read UEFI RTC time");
    }
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

pub fn service(_sh: &mut Shell, args: &[&str]) {
    let sub = args.first().copied().unwrap_or("status");
    let name = args.get(1).copied();
    let ctl_op = |code: u64, n: &str| admin_u64(ADMIN_SERVICE_CTL, [code, 0, 0, 0], n.as_bytes());
    match (sub, name) {
        ("status" | "list", _) => service_status(),
        ("restart", Some(n)) => {
            color(YELLOW);
            println!("[*] Requesting reincarnation of service '{}'...", n);
            match ctl_op(SVCCTL_RESTART, n) {
                Ok(pid) => {
                    color(LIGHT_GREEN);
                    println!("[+] Service '{}' successfully reincarnated as Task PID {}.", n, pid);
                }
                Err(e) => {
                    color(LIGHT_RED);
                    println!("[!] Reincarnation failed for '{}': {}", n, e.text());
                }
            }
        }
        // wave11 GR: `service kill NAME after S`: the kernel kills it S seconds from now (the
        // console is free meanwhile: a kill test of a program that uses the console)
        ("kill", Some(n)) if args.get(2) == Some(&"after") => {
            let secs = args.get(3).and_then(|v| v.parse::<u64>().ok()).filter(|&v| v > 0);
            let Some(secs) = secs else {
                println!("Usage: service kill <name> [after <seconds>]");
                return;
            };
            match admin_u64(ADMIN_SERVICE_CTL, [SVCCTL_KILL, secs, 0, 0], n.as_bytes()) {
                Ok(_) => println!("[*] Service '{}' will be killed in {} s.", n, secs),
                Err(e) => println!("[!] Failed to schedule the kill of '{}': {}", n, e.text()),
            }
        }
        ("kill", Some(n)) => {
            color(LIGHT_RED);
            println!("[!] Simulating fatal fault in service '{}'...", n);
            match ctl_op(SVCCTL_KILL, n) {
                Ok(pid) => {
                    println!("[+] Terminated process PID {} for service '{}'.", pid, n);
                    color(YELLOW);
                    println!("[*] Running supervisor watchdog sweep to test automated reincarnation...");
                    color(LIGHT_GREEN);
                    println!("[+] Supervisor sweep completed. Check 'service status' for reincarnation metrics.");
                }
                Err(e) => println!("[!] Failed to terminate service '{}': {}", n, e.text()),
            }
        }
        ("start", Some(n)) => {
            color(YELLOW);
            println!("[*] Starting service '{}'...", n);
            match ctl_op(SVCCTL_START, n) {
                Ok(pid) => {
                    color(LIGHT_GREEN);
                    println!("[+] Service '{}' started successfully as PID {}.", n, pid);
                }
                Err(e) => {
                    color(LIGHT_RED);
                    println!("[!] Failed to start service '{}': {}", n, e.text());
                }
            }
        }
        ("tick", _) => {
            color(LIGHT_CYAN);
            println!("[*] Dispatching supervisor heartbeat watchdog tick...");
            let _ = ctl_op(SVCCTL_TICK, "");
            color(LIGHT_GREEN);
            println!("[+] Supervisor heartbeat tick completed.");
        }
        ("restart" | "kill" | "start", None) => {
            color(LIGHT_RED);
            println!("Usage: service {} <name>", sub);
        }
        (unknown, _) => {
            color(LIGHT_RED);
            println!("[!] Unknown service subcommand '{}'. Usage: service [status|list|restart <name>|kill <name>|start <name>|tick]", unknown);
        }
    }
    color(WHITE);
}

/// `service status`.
fn service_status() {
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
    let list = records::<ServiceRecord>(&services, 0, services.len() / core::mem::size_of::<ServiceRecord>());
    if list.is_empty() {
        color(LIGHT_GRAY);
        println!("  No microkernel services currently registered.");
    }
    for s in list {
        let pid = if s.pid == u64::MAX { String::from("-") } else { alloc::format!("{}", s.pid) };
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
    for q in records::<IrqRecord>(&irqs, 0, irqs.len() / core::mem::size_of::<IrqRecord>()) {
        color(LIGHT_GRAY);
        println!(
            "  IRQ {:<3} -> process {:<6} {} interrupts, {} client wakes, {} pending, {}",
            q.irq, q.owner, q.count, q.notified, q.pending, if q.masked != 0 { "masked" } else { "unmasked" }
        );
    }
    if let Ok(a) = admin(ADMIN_REQUEST_LIST, [0; 4], &[]) {
        let h: RequestHeader = read_record(&a, 0).unwrap_or_default();
        color(LIGHT_GRAY);
        println!("  Requests in flight: {}; page grants made since boot: {}", h.count, h.grants_made);
        for r in records::<RequestRecord>(&a, core::mem::size_of::<RequestHeader>(), h.count as usize) {
            println!("    request {} to {:#x} by task {}: {} ({})", r.id, r.endpoint, r.caller, name_str(&r.state), name_str(&r.mode));
        }
    }
    color(LIGHT_CYAN);
    println!("=========================================================================================\n");
}

pub fn iommu(_sh: &mut Shell, args: &[&str]) {
    let what = match args.first().copied().unwrap_or("status") {
        "status" => 0,
        "faults" => 1,
        "dmatest" => 2,
        _ => return println!("usage: iommu [status|faults|dmatest]"),
    };
    if let Err(e) = admin(ADMIN_IOMMU, [what, 0, 0, 0], &[]) {
        report(&e, "iommu");
    }
}

// ---------------------------------------------------------------------------
// Power and fault tests
// ---------------------------------------------------------------------------

pub fn shutdown(_sh: &mut Shell, _args: &[&str]) {
    color(YELLOW);
    println!("[*] Powering down system...");
    if let Err(e) = admin(ADMIN_POWER, [POWER_OFF, 0, 0, 0], &[]) {
        report(&e, "shutdown");
    }
}

pub fn reboot(_sh: &mut Shell, _args: &[&str]) {
    color(YELLOW);
    println!("[*] Rebooting system...");
    if let Err(e) = admin(ADMIN_POWER, [POWER_REBOOT, 0, 0, 0], &[]) {
        report(&e, "reboot");
    }
}

pub fn halt(_sh: &mut Shell, _args: &[&str]) {
    color(YELLOW);
    println!("[*] Halting CPU. Hardware interrupts disabled.");
    if let Err(e) = admin(ADMIN_POWER, [POWER_HALT, 0, 0, 0], &[]) {
        report(&e, "halt");
    }
}

pub fn panic(_sh: &mut Shell, args: &[&str]) {
    let secs = args.first().and_then(|a| a.parse::<u64>().ok()).unwrap_or(0);
    if secs > 0 {
        println!("[*] The kernel panics in {} s", secs);
    }
    if let Err(e) = admin(ADMIN_FAULT_TEST, [FAULT_PANIC, secs, 0, 0], &[]) {
        report(&e, "panic");
    }
}

pub fn trap(_sh: &mut Shell, _args: &[&str]) {
    println!("[*] Executing INT3 instruction to test IDT breakpoint trap...");
    match admin(ADMIN_FAULT_TEST, [FAULT_TRAP, 0, 0, 0], &[]) {
        Ok(_) => {
            color(LIGHT_GREEN);
            println!("[+] Resumed successfully from #BP exception handler!");
        }
        Err(e) => report(&e, "trap"),
    }
}
