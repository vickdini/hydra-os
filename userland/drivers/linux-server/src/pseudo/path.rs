//! Which pseudo file a redirected path names (plain Rust, host-tested in
//! `tests/host-w7-40`).
//!
//! The file service redirects a lookup that ends under a served mount here with the mount's
//! object and the rest of the path (the *tail*: `self/stat` for `/proc/self/stat`).
//! [`classify`] decides whether linux-server serves it ([`Target::File`], [`Target::SelfLink`])
//! or the kernel's in-kernel code answers ([`Target::Kernel`]): everything not listed here,
//! `..` inside the tail, directories, and the links that lead out of `/proc`.

use crate::proto::{LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};

/// Whose `/proc/<pid>` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    /// `self` or `thread-self`: the caller's process.
    Caller,
    /// A process ID as the caller names it.
    Pid(u64),
}

/// A file in a `/proc/<pid>` (or `/proc/<pid>/task/<tid>`) directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidFile {
    /// `stat`.
    Stat,
    /// `status`.
    Status,
    /// `statm`.
    Statm,
    /// `comm`.
    Comm,
    /// `cmdline`.
    Cmdline,
    /// `maps`.
    Maps,
}

/// A pseudo file linux-server serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    /// Fixed text (`/proc/sys/...` limits).
    Static(&'static [u8]),
    /// `/proc/version`.
    Version,
    /// `/proc/uptime`.
    Uptime,
    /// `/proc/loadavg`.
    Loadavg,
    /// `/proc/stat`.
    Stat,
    /// `/proc/meminfo`.
    Meminfo,
    /// `/proc/cpuinfo`.
    Cpuinfo,
    /// `/sys/devices/system/cpu/{online,possible,present}`.
    CpuRange,
    /// `/sys/firmware/efi/efivars/<Name>-<GUID>`: a UEFI variable (the file name is the
    /// tail's last component).
    Efivar,
    /// wave10 G8-2: `/proc/sysvipc/{shm,sem,msg}` (0, 1, 2): the IPC service's info call.
    SysvIpc(u8),
    /// `/proc/<who>/<file>`, or `/proc/<who>/task/<tid>/<file>` (`tid` != 0).
    Pid {
        /// The process.
        who: Who,
        /// The thread (0: the process).
        tid: u64,
        /// The file.
        file: PidFile,
    },
}

impl File {
    /// The file system the file is in: `true` for `/sys`.
    pub fn in_sys(&self) -> bool {
        matches!(self, File::CpuRange | File::Efivar)
    }
}

/// What a redirected path is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A file served here.
    File(File),
    /// `/proc/self` (`false`) or `/proc/thread-self` (`true`) itself: a symbolic link.
    SelfLink(bool),
    /// The kernel answers.
    Kernel,
    /// Nothing there (`ENOENT`): a process or thread number with leading zeros (Linux's
    /// /proc has no `01`; the in-kernel copy would take it as 1).
    Missing,
}

/// `/proc/sys/...` and other fixed files: `(path below /proc, text)` (the kernel's
/// `compat::linux::fs::match_pseudo_path` constants).
pub const STATIC: &[(&str, &[u8])] = &[
    ("sys/kernel/dmesg_restrict", b"1\n"),
    ("sys/net/ipv4/conf/default/forwarding", b"0\n"),
    ("sys/net/ipv6/conf/default/forwarding", b"0\n"),
    ("sys/net/ipv4/ip_forward", b"0\n"),
    ("sys/net/ipv4/ip_default_ttl", b"64\n"),
    ("sys/net/ipv6/conf/default/hop_limit", b"64\n"),
    ("sys/fs/inotify/max_user_watches", b"1048576\n"),
    ("sys/fs/inotify/max_user_instances", b"1024\n"),
    ("sys/fs/inotify/max_queued_events", b"16384\n"),
    ("sys/kernel/overflowuid", b"65534\n"),
    ("sys/kernel/overflowgid", b"65534\n"),
    ("sys/fs/overflowuid", b"65534\n"),
    ("sys/fs/overflowgid", b"65534\n"),
    ("sys/kernel/random/entropy_avail", b"256\n"),
    ("sys/kernel/random/poolsize", b"256\n"),
    ("sys/fs/mqueue/msg_max", b"10\n"),
    ("sys/fs/mqueue/msg_default", b"10\n"),
    ("sys/fs/mqueue/msgsize_max", b"8192\n"),
    ("sys/fs/mqueue/msgsize_default", b"8192\n"),
    ("sys/fs/mqueue/queues_max", b"256\n"),
    ("sys/kernel/shmmax", b"1099511627776\n"),
    ("sys/kernel/shmall", b"268435456\n"),
    ("sys/kernel/shmmni", b"4096\n"),
    ("sys/kernel/sem", b"32000\t1024000000\t500\t32000\n"),
    ("sys/kernel/msgmax", b"8192\n"),
    ("sys/kernel/msgmnb", b"16384\n"),
    ("sys/kernel/msgmni", b"32000\n"),
    ("sys/kernel/yama/ptrace_scope", b"3\n"),
    ("sys/kernel/perf_event_paranoid", b"2\n"),
];

/// The components of `tail` (no empty ones, no `.`); `None` if one is `..` (it may climb
/// out of the mount: the kernel decides) or not UTF-8.
pub fn components(tail: &[u8]) -> Option<alloc::vec::Vec<&str>> {
    let mut v = alloc::vec::Vec::new();
    for c in tail.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => return None,
            c => v.push(core::str::from_utf8(c).ok()?),
        }
    }
    Some(v)
}

/// Whether `name` has the shape of an efivarfs file name: `<Name>-<GUID>` (a GUID of 36
/// characters, hex digits and dashes at 8, 13, 18, 23).
pub fn efivar_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 38 || b[b.len() - 37] != b'-' {
        return false;
    }
    let g = &b[b.len() - 36..];
    g.iter().enumerate().all(|(i, &c)| if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() })
}

/// A decimal number of at most 10 digits (no sign, no leading `+`) that fits in 31 bits
/// (process and thread IDs travel in 32-bit halves of the info primitives' words).
fn number(s: &str) -> Option<u64> {
    // (no leading zeros: Linux's /proc has no `01` entry)
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok().filter(|&n: &u64| n <= i32::MAX as u64)
}

/// Digits with a leading zero (`01`, `00`).
fn zero_led(s: &str) -> bool {
    s.len() > 1 && s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit())
}

/// `access` of a served file (mode 0444) or, `dir`, of `/proc/self` (0555), for real or
/// effective user `uid`: `mode` bits beyond `R_OK | W_OK | X_OK` and `faccessat2` flags beyond
/// `AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH` are `EINVAL`; writing is root's only
/// (it overrides the mode bits); executing needs an `x` bit, which only directories have
/// (root too needs one).
pub fn access_rule(mode: u64, flags: u64, uid: u32, dir: bool) -> Result<(), i64> {
    const EINVAL: i64 = -22;
    const EACCES: i64 = -13;
    if mode & !7 != 0 || flags & !(0x100 | 0x200 | 0x1000) != 0 {
        return Err(EINVAL);
    }
    if mode & 2 != 0 && uid != 0 {
        return Err(EACCES);
    }
    if mode & 1 != 0 && !dir {
        return Err(EACCES);
    }
    Ok(())
}

fn pid_file(name: &str, in_task: bool) -> Option<PidFile> {
    Some(match name {
        "stat" => PidFile::Stat,
        "status" => PidFile::Status,
        "comm" => PidFile::Comm,
        "statm" if !in_task => PidFile::Statm,
        "cmdline" if !in_task => PidFile::Cmdline,
        "maps" if !in_task => PidFile::Maps,
        _ => return None,
    })
}

/// What `tail` names under the served mount of object `obj` (`LX_VFS_PSEUDO_*`).
/// `trailing`: the path ended with `/` (a file then is the kernel's: `ENOTDIR` rules).
pub fn classify(obj: u64, tail: &[u8]) -> Target {
    let Some(c) = components(tail) else { return Target::Kernel };
    // (a path ending in `/` or `/.` must name a directory: the kernel's rules)
    let trailing = tail.last() == Some(&b'/') || tail.ends_with(b"/.") || tail == b".";
    let file = |f: File| if trailing { Target::Kernel } else { Target::File(f) };
    match obj & 0xFFFF_FFFF {
        LX_VFS_PSEUDO_PROC => {}
        LX_VFS_PSEUDO_SYS => {
            return match c.as_slice() {
                ["devices", "system", "cpu", "online" | "possible" | "present"] => file(File::CpuRange),
                ["firmware", "efi", "efivars", name] if efivar_name(name) => file(File::Efivar),
                _ => Target::Kernel,
            };
        }
        _ => return Target::Kernel,
    }
    match c.as_slice() {
        ["version"] => file(File::Version),
        ["uptime"] => file(File::Uptime),
        ["loadavg"] => file(File::Loadavg),
        ["stat"] => file(File::Stat),
        ["meminfo"] => file(File::Meminfo),
        ["cpuinfo"] => file(File::Cpuinfo),
        // wave10 G8-2
        ["sysvipc", k @ ("shm" | "sem" | "msg")] => file(File::SysvIpc(match *k {
            "shm" => 0,
            "sem" => 1,
            _ => 2,
        })),
        ["self"] if !trailing => Target::SelfLink(false),
        ["thread-self"] if !trailing => Target::SelfLink(true),
        [who, rest @ ..] if !rest.is_empty() => {
            let who = match *who {
                "self" | "thread-self" => Who::Caller,
                n => match number(n) {
                    Some(p) if p != 0 => Who::Pid(p),
                    _ if zero_led(n) => return Target::Missing,
                    _ => {
                        let joined = c.join("/");
                        return match STATIC.iter().find(|(p, _)| *p == joined) {
                            Some((_, t)) => file(File::Static(t)),
                            None => Target::Kernel,
                        };
                    }
                },
            };
            match rest {
                [f] => pid_file(f, false).map_or(Target::Kernel, |f| file(File::Pid { who, tid: 0, file: f })),
                ["task", t, f] => match (number(t), pid_file(f, true)) {
                    (Some(tid), Some(f)) if tid != 0 => file(File::Pid { who, tid, file: f }),
                    _ if zero_led(t) => Target::Missing,
                    _ => Target::Kernel,
                },
                _ => Target::Kernel,
            }
        }
        _ => Target::Kernel,
    }
}

/// An inode number for a pseudo file (FNV-1a of its tail, never 0 or 1).
pub fn ino_of(obj: u64, tail: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (obj & 0xFFFF_FFFF);
    for &b in tail {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h >> 1) | 2
}
