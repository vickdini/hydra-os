//! The text of the `/proc` files lx-proc serves, from the kernel's info primitives (plain
//! Rust, host-tested in `tests/host-w7-40`; wave 10 Group 7b-2 moved it from linux-server).
//! Each layout is the in-kernel copy's (`src/compat/linux/fs.rs`, `limits.rs`), so a file
//! reads the same whoever serves it.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::proto::{LxMapEntry, LxSysInfo, LxTaskInfo, LX_INFO_CPUS, LX_MAP_R, LX_MAP_SHARED, LX_MAP_W, LX_MAP_X};

/// `/proc/version`.
pub const VERSION: &[u8] = b"Linux version 6.8.0-hydra (gcc-13 / rustc-1.80) #1 SMP PREEMPT Hydra Microkernel\n";

/// The `comm` bytes of `i` (up to the first NUL).
pub fn comm(i: &LxTaskInfo) -> &[u8] {
    let n = i.comm.iter().position(|&b| b == 0).unwrap_or(i.comm.len());
    &i.comm[..n]
}

fn comm_str(i: &LxTaskInfo) -> String {
    String::from_utf8_lossy(comm(i)).into_owned()
}

/// `/proc/<pid>/comm`.
pub fn comm_file(i: &LxTaskInfo) -> Vec<u8> {
    let mut v = comm(i).to_vec();
    v.push(b'\n');
    v
}

/// `/proc/<pid>/stat`: the 52 fields of proc(5) (those Hydra does not keep are 0).
pub fn stat(i: &LxTaskInfo) -> Vec<u8> {
    let mut t = String::new();
    let _ = write!(
        t,
        "{} ({}) {} {} {} {} 0 -1 4194304 0 0 0 0 {} {} {} {} {} {} {} 0 {}",
        i.pid,
        comm_str(i),
        i.state as u8 as char,
        i.ppid,
        i.pgid,
        i.sid,
        i.utime,
        i.stime,
        i.cutime,
        i.cstime,
        20 + i.nice,
        i.nice,
        i.threads,
        i.start
    );
    let _ = write!(t, " {} {}", i.vsize, i.rss_anon + i.rss_file);
    for _ in 25..=52 {
        t.push_str(" 0");
    }
    t.push('\n');
    t.into_bytes()
}

/// `/proc/<pid>/statm` (pages: size resident shared text lib data dt).
pub fn statm(i: &LxTaskInfo) -> Vec<u8> {
    alloc::format!("{} {} {} 0 0 {} 0\n", i.vsize / 4096, i.rss_anon + i.rss_file, i.rss_file, i.rss_anon).into_bytes()
}

/// `id` in each PID namespace the process is in, outermost first (`NStgid`, `NSpid`).
fn ns_ids(i: &LxTaskInfo, id: u64) -> String {
    let mut s = alloc::format!("{}", id);
    for init in &i.ns_inits[..(i.ns_depth as usize).min(i.ns_inits.len())] {
        let _ = write!(s, "\t{}", if *init == id { 1 } else { id });
    }
    s
}

/// `/proc/<pid>/status` (the fields tools read).
pub fn status(i: &LxTaskInfo) -> Vec<u8> {
    let kib = |pages: u64| pages * 4;
    let ids = i.ids;
    alloc::format!(
        "Name:\t{}\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nNStgid:\t{}\nNSpid:\t{}\nVmLck:\t{} kB\n\
VmPeak:\t{} kB\nVmSize:\t{} kB\nVmHWM:\t{} kB\nVmRSS:\t{} kB\nRssAnon:\t{} kB\nRssFile:\t{} kB\nVmSwap:\t0 kB\nNoNewPrivs:\t{}\nSeccomp:\t{}\n",
        comm_str(i),
        i.pid,
        i.tid,
        i.ppid,
        i.tracer,
        ids[0],
        ids[1],
        ids[2],
        ids[1],
        ids[3],
        ids[4],
        ids[5],
        ids[4],
        ns_ids(i, i.pid),
        ns_ids(i, i.tid),
        i.locked_kib,
        i.vsize / 1024,
        i.vsize / 1024,
        kib(i.rss_anon + i.rss_file),
        kib(i.rss_anon + i.rss_file),
        kib(i.rss_anon),
        kib(i.rss_file),
        i.nnp,
        i.seccomp
    )
    .into_bytes()
}

/// The CPUs of `s` that have entries.
fn cpus(s: &LxSysInfo) -> usize {
    (s.ncpu.max(1) as usize).min(LX_INFO_CPUS)
}

/// `/proc/stat`.
pub fn proc_stat(s: &LxSysInfo) -> Vec<u8> {
    let n = cpus(s);
    let line = |name: &str, t: [u64; 3]| alloc::format!("{} {} 0 {} {} 0 0 0 0 0 0\n", name, t[0], t[1], t[2]);
    let total = s.cpu[..n].iter().fold([0u64; 3], |a, t| [a[0] + t[0], a[1] + t[1], a[2] + t[2]]);
    let mut text = line("cpu ", total);
    for (i, t) in s.cpu[..n].iter().enumerate() {
        text.push_str(&line(&alloc::format!("cpu{}", i), *t));
    }
    let _ = write!(text, "intr 0\nctxt 0\nbtime {}\nprocesses {}\nprocs_running {}\nprocs_blocked 0\n", s.boot_time, s.procs, s.running.max(1));
    text.into_bytes()
}

/// `/proc/uptime`: seconds since boot and idle seconds summed over the CPUs.
pub fn uptime(s: &LxSysInfo) -> Vec<u8> {
    let up = s.now_ns / 10_000_000;
    let idle: u64 = s.cpu[..cpus(s)].iter().map(|t| t[2]).sum();
    alloc::format!("{}.{:02} {}.{:02}\n", up / 100, up % 100, idle / 100, idle % 100).into_bytes()
}

/// `/proc/loadavg`.
pub fn loadavg(s: &LxSysInfo) -> Vec<u8> {
    let f = |v: u64| alloc::format!("{}.{:02}", v >> 11, ((v & 2047) * 100) >> 11);
    alloc::format!("{} {} {} {}/{} {}\n", f(s.load[0]), f(s.load[1]), f(s.load[2]), s.running, s.tasks, s.last_pid).into_bytes()
}

/// `/proc/meminfo`.
pub fn meminfo(s: &LxSysInfo) -> Vec<u8> {
    let available = (s.mem_free + s.reclaimable).min(s.mem_total);
    let mut text = alloc::format!("MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\n", s.mem_total, s.mem_free, available);
    for field in ["Buffers", "Cached", "SwapCached", "SwapTotal", "SwapFree", "Shmem", "SReclaimable", "SUnreclaim"] {
        let v = match field {
            "Cached" => s.cached,
            "SwapTotal" => s.swap_total,
            "SwapFree" => s.swap_free,
            _ => 0,
        };
        let _ = writeln!(text, "{:<16}{:8} kB", alloc::format!("{}:", field), v);
    }
    text.into_bytes()
}

/// `/proc/cpuinfo` for `n` CPUs.
pub fn cpuinfo(n: u64) -> Vec<u8> {
    let mut text = String::new();
    for i in 0..n {
        let _ = write!(
            text,
            "processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 1\nmodel name\t: x86_64 Hydra Virtual CPU\nphysical id\t: 0\nsiblings\t: {n}\ncore id\t\t: {i}\ncpu cores\t: {n}\napicid\t\t: {i}\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx lm\n\n"
        );
    }
    text.into_bytes()
}

// wave10 G7b-2 begin
/// The resource limits (`RLIMIT_*` order).
pub const NLIMITS: usize = 16;
/// `RLIM_INFINITY`.
const RLIM_INFINITY: u64 = u64::MAX;

/// `/proc/<pid>/limits` from the (soft, hard) pairs in `RLIMIT_*` order (the kernel's
/// `limits::limits_text` layout).
pub fn limits(l: &[(u64, u64); NLIMITS]) -> Vec<u8> {
    const NAMES: [(&str, &str); NLIMITS] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let v = |x: u64| if x == RLIM_INFINITY { String::from("unlimited") } else { alloc::format!("{}", x) };
    let mut s = alloc::format!("{:<25} {:<20} {:<20} {:<10}\n", "Limit", "Soft Limit", "Hard Limit", "Units");
    for (i, (name, unit)) in NAMES.iter().enumerate() {
        s.push_str(&alloc::format!("{:<25} {:<20} {:<20} {:<10}\n", name, v(l[i].0), v(l[i].1), unit));
    }
    s.into_bytes()
}
// wave10 G7b-2 end

/// `/proc/<pid>/maps` from `LX_INFO_MAPS` records (`data`, as many bytes as were written).
pub fn maps(data: &[u8]) -> Vec<u8> {
    let hdr = core::mem::size_of::<LxMapEntry>();
    let mut out = String::new();
    let mut at = 0;
    while at + hdr <= data.len() {
        // SAFETY: `hdr` bytes are there; `LxMapEntry` is plain integers
        let e: LxMapEntry = unsafe { core::ptr::read_unaligned(data[at..].as_ptr() as *const LxMapEntry) };
        // (a record longer than the kernel writes, or cut short, ends the list)
        let name_len = e.name_len as usize;
        if name_len > 4095 || at + hdr + name_len > data.len() {
            break;
        }
        let name = &data[at + hdr..at + hdr + name_len];
        let c = |bit: u32, ch: char| if e.flags & bit != 0 { ch } else { '-' };
        let mut line = alloc::format!(
            "{:08x}-{:08x} {}{}{}{} {:08x} 00:00 0",
            e.start,
            e.end,
            c(LX_MAP_R, 'r'),
            c(LX_MAP_W, 'w'),
            c(LX_MAP_X, 'x'),
            if e.flags & LX_MAP_SHARED != 0 { 's' } else { 'p' },
            e.offset
        );
        if name_len != 0 {
            while line.len() < 72 {
                line.push(' ');
            }
            line.push(' ');
            line.push_str(&String::from_utf8_lossy(name));
        }
        line.push('\n');
        out.push_str(&line);
        at += (hdr + name_len + 7) & !7;
    }
    out.into_bytes()
}

// wave11 GP begin: the rest of `/proc`
/// `DT_DIR`, `DT_REG`, `DT_LNK` (a directory entry's type).
pub const DT_DIR: u8 = 4;
/// See [`DT_DIR`].
pub const DT_REG: u8 = 8;
/// See [`DT_DIR`].
pub const DT_LNK: u8 = 10;

/// A directory snapshot's text (`LX_PSNAP_DIRENT_HEAD`): per entry `ino` (8 bytes), type,
/// name length, name. Names longer than 255 bytes are left out.
pub fn dir_text(entries: &[(u64, u8, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for &(ino, t, name) in entries {
        if name.is_empty() || name.len() > 255 {
            continue;
        }
        v.extend_from_slice(&ino.to_le_bytes());
        v.push(t);
        v.push(name.len() as u8);
        v.extend_from_slice(name);
    }
    v
}

/// `/proc/<pid>/fdinfo/<fd>` from `LX_PX_FDINFO`'s words: position, flags (octal), mount
/// id, inode, and a pidfd's `Pid:`/`NSpid:` (`pidfd`: its process + 1, `u64::MAX` gone).
pub fn fdinfo(out: &[u64]) -> Vec<u8> {
    let mut t = String::new();
    let _ = write!(t, "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n", out[0], out[1], out[2], out[3]);
    match out[4] {
        0 => {}
        u64::MAX => t.push_str("Pid:\t-1\nNSpid:\t-1\n"),
        p => {
            let _ = write!(t, "Pid:\t{}\nNSpid:\t{}\n", p - 1, p - 1);
        }
    }
    t.into_bytes()
}

/// `/proc/<pid>/cgroup` (cgroup v2 only) of a process in control group `path`.
pub fn cgroup(path: &[u8]) -> Vec<u8> {
    let mut v = b"0::".to_vec();
    v.extend_from_slice(if path.is_empty() { b"/" } else { path });
    v.push(b'\n');
    v
}

/// `/proc/<pid>/ns/<kind>`'s link text (`pid_for_children` shows as `pid`).
pub fn ns_link(kind: &str, ino: u64) -> String {
    let shown = match kind {
        "pid_for_children" => "pid",
        "time_for_children" => "time",
        k => k,
    };
    alloc::format!("{}:[{}]", shown, ino)
}

/// A number and a newline (`oom_score_adj`, `oom_score`).
pub fn number_line(n: i64) -> Vec<u8> {
    alloc::format!("{}\n", n).into_bytes()
}

/// The IDs of an `LX_PX_FDS`/`TASKS`/`PIDS` answer.
pub fn u32s(raw: &[u8]) -> Vec<u64> {
    raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64).collect()
}
// wave11 GP end
