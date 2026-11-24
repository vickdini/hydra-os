//! Which `/proc` file a redirected path names (plain Rust, host-tested in
//! `tests/host-w7-40`; wave 10 Group 7b-2 moved it from linux-server to lx-proc).
//!
//! The file service redirects a lookup that ends under `/proc` here with the mount's
//! object and the rest of the path (the *tail*: `self/stat` for `/proc/self/stat`).
//! [`classify`] decides whether lx-proc serves it ([`Target::File`], [`Target::SelfLink`])
//! or the kernel's in-kernel code answers ([`Target::Kernel`]): everything not listed here,
//! `..` inside the tail, directories, and the links that lead out of `/proc`.

use crate::proto::LX_VFS_PSEUDO_PROC;

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
    /// wave10 G7b-2: `environ` (the `ptrace` read rule, mode 0400).
    Environ,
    /// wave10 G7b-2: `limits`.
    Limits,
}

/// A `/proc` file lx-proc serves.
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
    /// Its permission bits: 0444, `environ` 0400 (as Linux).
    pub fn mode(&self) -> u32 {
        match self {
            File::Pid { file: PidFile::Environ, .. } => 0o400,
            _ => 0o444,
        }
    }
}

// wave10 G7b-2 begin: the identity of an open file, kept by the kernel with its snapshot
// and given back when the text is made again (`LxSnapIo::ident`)

/// The per-process files in [`ident`]'s code order (code `PID_BASE + index`).
const PID_FILES: [PidFile; 8] = [PidFile::Stat, PidFile::Status, PidFile::Statm, PidFile::Comm, PidFile::Cmdline, PidFile::Maps, PidFile::Environ, PidFile::Limits];
/// The first per-process code.
const PID_BASE: u64 = 16;

/// The identity of `file` (opened with the process start time `start`): `[code, process,
/// thread, start]`. Code 0 (fixed text: `/proc/sys/...`, `version`) is never made again.
/// A process file must name its process by system-wide ID (`Who::Pid`).
pub fn ident(file: File, start: u64) -> [u64; 4] {
    let code = |c: u64| [c, 0, 0, 0];
    match file {
        File::Static(_) | File::Version => code(0),
        File::Uptime => code(1),
        File::Loadavg => code(2),
        File::Stat => code(3),
        File::Meminfo => code(4),
        File::Cpuinfo => code(5),
        File::SysvIpc(k) => code(6 + k as u64),
        File::Pid { who, tid, file } => {
            let i = PID_FILES.iter().position(|f| *f == file).unwrap_or(0) as u64;
            let pid = match who {
                Who::Caller => 0,
                Who::Pid(p) => p,
            };
            [PID_BASE + i, pid, tid, start]
        }
    }
}

/// The file (and the process start time it was opened with) of identity `id` ([`ident`]);
/// `None` for code 0 and codes that name nothing.
pub fn of_ident(id: [u64; 4]) -> Option<(File, u64)> {
    let f = match id[0] {
        1 => File::Uptime,
        2 => File::Loadavg,
        3 => File::Stat,
        4 => File::Meminfo,
        5 => File::Cpuinfo,
        6..=8 => File::SysvIpc((id[0] - 6) as u8),
        c if (PID_BASE..PID_BASE + PID_FILES.len() as u64).contains(&c) => {
            // (process and thread IDs travel in 32-bit halves: kept below 2^31)
            if id[1] == 0 || id[1] > i32::MAX as u64 || id[2] > i32::MAX as u64 {
                return None;
            }
            let file = PID_FILES[(c - PID_BASE) as usize];
            return Some((File::Pid { who: Who::Pid(id[1]), tid: id[2], file }, id[3]));
        }
        _ => return None,
    };
    Some((f, 0))
}
// wave10 G7b-2 end

/// wave10 G7b-2: a process directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// `/proc/<pid>`.
    Pid(Who),
    /// `/proc/<pid>/task` (its link count is 2 + the threads, as Linux).
    Task(Who),
    /// `/proc/<pid>/task/<tid>`.
    Thread(Who, u64),
}

impl Dir {
    /// The process.
    pub fn who(&self) -> Who {
        match *self {
            Dir::Pid(w) | Dir::Task(w) | Dir::Thread(w, _) => w,
        }
    }
}

/// What a redirected path is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A file served here.
    File(File),
    /// `/proc/self` (`false`) or `/proc/thread-self` (`true`) itself: a symbolic link.
    SelfLink(bool),
    /// wave10 G7b-2: a process's directory (`stat` and `access` are served; listing it and
    /// opening it are the kernel's).
    Dir(Dir),
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

/// `access` of a served file or directory of permission bits `perm` (0444, `environ` 0400,
/// directories 0555) owned by `owner`, for real or effective user `uid`: `mode` bits beyond
/// `R_OK | W_OK | X_OK` and `faccessat2` flags beyond `AT_SYMLINK_NOFOLLOW | AT_EACCESS |
/// AT_EMPTY_PATH` are `EINVAL`; root may read and write whatever the bits say but execute
/// only with an `x` bit; anyone else gets the owner's bits when it is the owner, the others'
/// bits otherwise (wave10 G7b-2: `environ` is its owner's alone).
pub fn access_rule(mode: u64, flags: u64, uid: u32, perm: u32, owner: u32) -> Result<(), i64> {
    const EINVAL: i64 = -22;
    const EACCES: i64 = -13;
    if mode & !7 != 0 || flags & !(0x100 | 0x200 | 0x1000) != 0 {
        return Err(EINVAL);
    }
    let want = (mode & 7) as u32;
    let ok = if uid == 0 {
        want & 1 == 0 || perm & 0o111 != 0
    } else {
        let bits = if uid == owner { (perm >> 6) & 7 } else { perm & 7 };
        want & !bits == 0
    };
    if ok {
        Ok(())
    } else {
        Err(EACCES)
    }
}

fn pid_file(name: &str, in_task: bool) -> Option<PidFile> {
    Some(match name {
        "stat" => PidFile::Stat,
        "status" => PidFile::Status,
        "comm" => PidFile::Comm,
        "statm" if !in_task => PidFile::Statm,
        "cmdline" if !in_task => PidFile::Cmdline,
        "maps" if !in_task => PidFile::Maps,
        "environ" if !in_task => PidFile::Environ,
        "limits" if !in_task => PidFile::Limits,
        _ => return None,
    })
}

/// What `tail` names under the `/proc` mount (object `LX_VFS_PSEUDO_PROC`; any other
/// object: the kernel's). A path ending with `/` names a directory (a file then is the
/// kernel's: `ENOTDIR` rules).
pub fn classify(obj: u64, tail: &[u8]) -> Target {
    let Some(c) = components(tail) else { return Target::Kernel };
    // (a path ending in `/` or `/.` must name a directory: the kernel's rules)
    let trailing = tail.last() == Some(&b'/') || tail.ends_with(b"/.") || tail == b".";
    let file = |f: File| if trailing { Target::Kernel } else { Target::File(f) };
    if obj & 0xFFFF_FFFF != LX_VFS_PSEUDO_PROC {
        return Target::Kernel;
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
        // wave10 G7b-2: a process's directory (`self/`: the caller's)
        ["self"] => Target::Dir(Dir::Pid(Who::Caller)),
        [n] => match number(n) {
            Some(p) if p != 0 => Target::Dir(Dir::Pid(Who::Pid(p))),
            _ if zero_led(n) => Target::Missing,
            _ => Target::Kernel,
        },
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
                // wave10 G7b-2: the process's thread directories
                ["task"] => Target::Dir(Dir::Task(who)),
                ["task", t] => match number(t) {
                    Some(tid) if tid != 0 => Target::Dir(Dir::Thread(who, tid)),
                    _ if zero_led(t) => Target::Missing,
                    _ => Target::Kernel,
                },
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
