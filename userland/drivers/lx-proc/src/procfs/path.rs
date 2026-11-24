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
    // wave11 GP begin
    /// `auxv` (the `ptrace` read rule, mode 0400).
    Auxv,
    /// `cgroup`.
    Cgroup,
    /// `mountinfo` (its mount namespace's table).
    Mountinfo,
    /// `mounts`.
    Mounts,
    /// `uid_map` (0644: writes are the kernel's mechanism).
    UidMap,
    /// `gid_map`.
    GidMap,
    /// `setgroups`.
    Setgroups,
    /// `oom_score_adj` (0644).
    OomScoreAdj,
    /// `oom_score`.
    OomScore,
    // wave11 GP end
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
    /// wave11 GP: `/proc/filesystems`.
    Filesystems,
    /// wave11 GP: `/proc/swaps`.
    Swaps,
    /// wave11 GP: `/proc/locks`.
    Locks,
    /// wave11 GP: `/proc/sys/kernel/random/boot_id` (one per boot).
    BootId,
    /// wave11 GP: `/proc/sys/kernel/random/uuid` (a new one at every read from the start).
    Uuid,
    /// wave11 GP: `/proc/asound/<name>` ([`ASOUND`] index): the sound card's state.
    Asound(u8),
    /// wave11 GP: `/proc/<who>/fdinfo/<fd>` (the `ptrace` read rule).
    FdInfo {
        /// The process.
        who: Who,
        /// The descriptor.
        fd: u64,
    },
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
    /// Its permission bits: 0444, `environ` and `auxv` 0400, the files the kernel's
    /// mechanism takes writes for 0644 (as Linux).
    pub fn mode(&self) -> u32 {
        match self {
            File::Pid { file: PidFile::Environ | PidFile::Auxv, .. } => 0o400,
            File::Pid { file: PidFile::UidMap | PidFile::GidMap | PidFile::Setgroups | PidFile::OomScoreAdj, .. } => 0o644,
            _ => 0o444,
        }
    }

    /// wave11 GP: whether writes to it are taken (by the kernel's mechanism, after a
    /// redirect): the namespace maps and `oom_score_adj`.
    pub fn writable(&self) -> bool {
        matches!(self, File::Pid { tid: 0, file: PidFile::UidMap | PidFile::GidMap | PidFile::Setgroups | PidFile::OomScoreAdj, .. })
    }
}

// wave10 G7b-2 begin: the identity of an open file, kept by the kernel with its snapshot
// and given back when the text is made again (`LxSnapIo::ident`)

/// The per-process files in [`ident`]'s code order (code `PID_BASE + index`).
const PID_FILES: [PidFile; 17] = [
    PidFile::Stat,
    PidFile::Status,
    PidFile::Statm,
    PidFile::Comm,
    PidFile::Cmdline,
    PidFile::Maps,
    PidFile::Environ,
    PidFile::Limits,
    // wave11 GP (codes 24..)
    PidFile::Auxv,
    PidFile::Cgroup,
    PidFile::Mountinfo,
    PidFile::Mounts,
    PidFile::UidMap,
    PidFile::GidMap,
    PidFile::Setgroups,
    PidFile::OomScoreAdj,
    PidFile::OomScore,
];
/// wave11 GP: the code of `fdinfo/<fd>` (`[FDINFO_CODE, process, fd, start]`).
const FDINFO_CODE: u64 = 48;
/// wave11 GP: the first directory code (`DIR_BASE + kind`, `[code, process, thread, start]`).
const DIR_BASE: u64 = 64;
/// wave11 GP: the first code of the system files added in wave 11.
const SYS_BASE: u64 = 9;
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
        // wave11 GP begin
        File::BootId => code(0),
        File::Filesystems => code(SYS_BASE),
        File::Swaps => code(SYS_BASE + 1),
        File::Locks => code(SYS_BASE + 2),
        File::Uuid => code(SYS_BASE + 3),
        File::Asound(i) => [SYS_BASE + 4, i as u64, 0, 0],
        File::FdInfo { who, fd } => [FDINFO_CODE, pid_of(who), fd, start],
        // wave11 GP end
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
        // wave11 GP begin
        c if c == SYS_BASE => File::Filesystems,
        c if c == SYS_BASE + 1 => File::Swaps,
        c if c == SYS_BASE + 2 => File::Locks,
        c if c == SYS_BASE + 3 => File::Uuid,
        c if c == SYS_BASE + 4 && (id[1] as usize) < ASOUND.len() => File::Asound(id[1] as u8),
        FDINFO_CODE => {
            if id[1] == 0 || id[1] > i32::MAX as u64 || id[2] > i32::MAX as u64 {
                return None;
            }
            return Some((File::FdInfo { who: Who::Pid(id[1]), fd: id[2] }, id[3]));
        }
        // wave11 GP end
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

// wave11 GP begin
fn pid_of(who: Who) -> u64 {
    match who {
        Who::Caller => 0,
        Who::Pid(p) => p,
    }
}

/// The identity of directory `d` (opened with the process start time `start`; 0 for the
/// directories of no process), and back ([`dir_of_ident`]).
pub fn dir_ident(d: Dir, start: u64) -> [u64; 4] {
    match d {
        Dir::Root => [DIR_BASE, 0, 0, 0],
        Dir::Pid(w) => [DIR_BASE + 1, pid_of(w), 0, start],
        Dir::Task(w) => [DIR_BASE + 2, pid_of(w), 0, start],
        Dir::Thread(w, t) => [DIR_BASE + 3, pid_of(w), t, start],
        Dir::Fd(w) => [DIR_BASE + 4, pid_of(w), 0, start],
        Dir::FdInfo(w) => [DIR_BASE + 5, pid_of(w), 0, start],
        Dir::Ns(w) => [DIR_BASE + 6, pid_of(w), 0, start],
        Dir::Static(i) => [DIR_BASE + 7, i as u64, 0, 0],
        Dir::SysvIpc => [DIR_BASE + 8, 0, 0, 0],
        Dir::Asound => [DIR_BASE + 9, 0, 0, 0],
    }
}

/// The directory (and its process start time) of identity `id` ([`dir_ident`]).
pub fn dir_of_ident(id: [u64; 4]) -> Option<(Dir, u64)> {
    let k = id[0].checked_sub(DIR_BASE)?;
    let pid = id[1];
    let who = || if pid == 0 || pid > i32::MAX as u64 { None } else { Some(Who::Pid(pid)) };
    let d = match k {
        0 => Dir::Root,
        1 => Dir::Pid(who()?),
        2 => Dir::Task(who()?),
        3 if id[2] != 0 && id[2] <= i32::MAX as u64 => Dir::Thread(who()?, id[2]),
        4 => Dir::Fd(who()?),
        5 => Dir::FdInfo(who()?),
        6 => Dir::Ns(who()?),
        7 if (pid as usize) < static_dirs().len() => Dir::Static(pid as u16),
        8 => Dir::SysvIpc,
        9 => Dir::Asound,
        _ => return None,
    };
    Some((d, id[3]))
}

/// The tail (below `/proc`) of directory `d`, with process IDs as given.
pub fn dir_tail(d: Dir) -> alloc::string::String {
    use alloc::format;
    let w = |w: Who| match w {
        Who::Caller => alloc::string::String::from("self"),
        Who::Pid(p) => format!("{}", p),
    };
    match d {
        Dir::Root => alloc::string::String::new(),
        Dir::Pid(x) => w(x),
        Dir::Task(x) => format!("{}/task", w(x)),
        Dir::Thread(x, t) => format!("{}/task/{}", w(x), t),
        Dir::Fd(x) => format!("{}/fd", w(x)),
        Dir::FdInfo(x) => format!("{}/fdinfo", w(x)),
        Dir::Ns(x) => format!("{}/ns", w(x)),
        Dir::Static(i) => alloc::string::String::from(static_dirs().get(i as usize).copied().unwrap_or("sys")),
        Dir::SysvIpc => alloc::string::String::from("sysvipc"),
        Dir::Asound => alloc::string::String::from("asound"),
    }
}

/// The directories below `/proc` that hold [`STATIC`] files (`sys`, `sys/kernel`,
/// `sys/kernel/random`, ...), in a fixed order (their index is [`Dir::Static`]'s).
pub fn static_dirs() -> alloc::vec::Vec<&'static str> {
    let mut v: alloc::vec::Vec<&'static str> = alloc::vec::Vec::new();
    for (p, _) in STATIC.iter().chain(MORE_SYS.iter()) {
        let mut at = 0;
        while let Some(i) = p[at..].find('/') {
            let d = &p[..at + i];
            if !v.contains(&d) {
                v.push(d);
            }
            at += i + 1;
        }
    }
    v
}

/// The files below `/proc/sys` lx-proc serves besides [`STATIC`] (made, not fixed).
pub const MORE_SYS: [(&str, &[u8]); 2] = [("sys/kernel/random/boot_id", b""), ("sys/kernel/random/uuid", b"")];

/// The `/proc/asound` files (`snd::proc_text` of the kernel's sound card).
pub const ASOUND: [&str; 6] = ["cards", "version", "devices", "pcm", "card0/id", "card0/codec#0"];

/// A magic link of a process: what it leads to is a kernel handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// `fd/<n>`.
    Fd(u64),
    /// `exe`.
    Exe,
    /// `cwd`.
    Cwd,
    /// `root`.
    Root,
    /// `ns/<kind>` (index in `LX_PX_NS_NAMES`).
    Ns(u8),
}
// wave11 GP end

/// wave10 G7b-2: a process directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// `/proc/<pid>`.
    Pid(Who),
    /// `/proc/<pid>/task` (its link count is 2 + the threads, as Linux).
    Task(Who),
    /// `/proc/<pid>/task/<tid>`.
    Thread(Who, u64),
    // wave11 GP begin
    /// `/proc` itself.
    Root,
    /// `/proc/<pid>/fd` (0500: the `ptrace` read rule).
    Fd(Who),
    /// `/proc/<pid>/fdinfo` (0500).
    FdInfo(Who),
    /// `/proc/<pid>/ns` (0511).
    Ns(Who),
    /// A directory of [`STATIC`] files ([`static_dirs`] index).
    Static(u16),
    /// `/proc/sysvipc`.
    SysvIpc,
    /// `/proc/asound`.
    Asound,
    // wave11 GP end
}

impl Dir {
    /// The process (`Who::Caller` for the directories of no process).
    pub fn who(&self) -> Who {
        match *self {
            Dir::Pid(w) | Dir::Task(w) | Dir::Thread(w, _) | Dir::Fd(w) | Dir::FdInfo(w) | Dir::Ns(w) => w,
            _ => Who::Caller,
        }
    }

    /// wave11 GP: whether it is a process's directory (it must exist; it is the process's).
    pub fn of_process(&self) -> bool {
        matches!(self, Dir::Pid(_) | Dir::Task(_) | Dir::Thread(..) | Dir::Fd(_) | Dir::FdInfo(_) | Dir::Ns(_))
    }

    /// wave11 GP: its permission bits (Linux: `fd/` and `fdinfo/` 0500, `ns/` 0511).
    pub fn mode(&self) -> u32 {
        match self {
            Dir::Fd(_) | Dir::FdInfo(_) => 0o500,
            Dir::Ns(_) => 0o511,
            _ => 0o555,
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
    /// wave11 GP: a magic link of a process (`fd/N`, `exe`, `cwd`, `root`, `ns/<kind>`):
    /// `readlink`, `lstat` here; following it is the kernel's (the handle it names).
    Link(Who, Link),
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
    ("sys/kernel/yama/ptrace_scope", b"0\n"), // wave10 G8-1: Yama scope 0, what Hydra enforces
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
        // wave11 GP
        "auxv" if !in_task => PidFile::Auxv,
        "cgroup" if !in_task => PidFile::Cgroup,
        "mountinfo" if !in_task => PidFile::Mountinfo,
        "mounts" if !in_task => PidFile::Mounts,
        "uid_map" if !in_task => PidFile::UidMap,
        "gid_map" if !in_task => PidFile::GidMap,
        "setgroups" if !in_task => PidFile::Setgroups,
        "oom_score_adj" if !in_task => PidFile::OomScoreAdj,
        "oom_score" if !in_task => PidFile::OomScore,
        _ => return None,
    })
}

/// What `tail` names under the `/proc` mount (object `LX_VFS_PSEUDO_PROC`; any other
/// object: the kernel's). A path ending with `/` names a directory (a file then is the
/// kernel's: `ENOTDIR` rules). wave11 GP: `/proc` itself, the process directories (`fd/`,
/// `fdinfo/`, `ns/`, `task/`), the `/proc/sys` directories, the magic links and the rest of
/// the files are lx-proc's too; what still goes to the kernel: a walk through a magic link
/// (`fd/3/x`, `cwd/...`, `root/...`), `..`, `thread-self/` as a directory, `net/`, and names
/// that do not exist (the kernel answers `ENOENT` as before).
pub fn classify(obj: u64, tail: &[u8]) -> Target {
    let Some(c) = components(tail) else { return Target::Kernel };
    // (a path ending in `/` or `/.` must name a directory: the kernel's rules)
    let trailing = tail.last() == Some(&b'/') || tail.ends_with(b"/.") || tail == b".";
    let file = |f: File| if trailing { Target::Kernel } else { Target::File(f) };
    if obj & 0xFFFF_FFFF != LX_VFS_PSEUDO_PROC {
        return Target::Kernel;
    }
    match c.as_slice() {
        // wave11 GP: `/proc` itself
        [] => Target::Dir(Dir::Root),
        ["version"] => file(File::Version),
        ["uptime"] => file(File::Uptime),
        ["loadavg"] => file(File::Loadavg),
        ["stat"] => file(File::Stat),
        ["meminfo"] => file(File::Meminfo),
        ["cpuinfo"] => file(File::Cpuinfo),
        // wave11 GP begin
        ["filesystems"] => file(File::Filesystems),
        ["swaps"] => file(File::Swaps),
        ["locks"] => file(File::Locks),
        ["mounts"] => file(File::Pid { who: Who::Caller, tid: 0, file: PidFile::Mounts }),
        ["sysvipc"] => Target::Dir(Dir::SysvIpc),
        ["asound"] => Target::Dir(Dir::Asound),
        ["asound", rest @ ..] => {
            let joined = rest.join("/");
            match ASOUND.iter().position(|n| *n == joined) {
                Some(i) => file(File::Asound(i as u8)),
                None => Target::Missing,
            }
        }
        // wave11 GP end
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
        // (`thread-self/` as a directory: the kernel's)
        ["thread-self"] => Target::Kernel,
        [n] => match number(n) {
            Some(p) if p != 0 => Target::Dir(Dir::Pid(Who::Pid(p))),
            _ if zero_led(n) => Target::Missing,
            // wave11 GP: `/proc/sys` and its directories; the kernel's `net`, `keys`;
            // nothing else is there
            _ => match static_dirs().iter().position(|d| d == n) {
                Some(i) => Target::Dir(Dir::Static(i as u16)),
                None => kernel_or_missing(&c),
            },
        },
        [who, rest @ ..] if !rest.is_empty() => {
            let who = match *who {
                "self" | "thread-self" => Who::Caller,
                n => match number(n) {
                    Some(p) if p != 0 => Who::Pid(p),
                    _ if zero_led(n) => return Target::Missing,
                    _ => {
                        let joined = c.join("/");
                        if let Some((_, t)) = STATIC.iter().find(|(p, _)| *p == joined) {
                            return file(File::Static(t));
                        }
                        // wave11 GP: the made `/proc/sys` files and the directories
                        return match joined.as_str() {
                            "sys/kernel/random/boot_id" => file(File::BootId),
                            "sys/kernel/random/uuid" => file(File::Uuid),
                            j => match static_dirs().iter().position(|d| *d == j) {
                                Some(i) => Target::Dir(Dir::Static(i as u16)),
                                None => kernel_or_missing(&c),
                            },
                        };
                    }
                },
            };
            match rest {
                // wave10 G7b-2: the process's thread directories
                ["task"] => Target::Dir(Dir::Task(who)),
                ["task", t] => match number(t) {
                    Some(tid) if tid != 0 => Target::Dir(Dir::Thread(who, tid)),
                    _ => Target::Missing,
                },
                // wave11 GP begin: the descriptor and namespace directories, the links
                ["fd"] => Target::Dir(Dir::Fd(who)),
                ["fdinfo"] => Target::Dir(Dir::FdInfo(who)),
                ["ns"] => Target::Dir(Dir::Ns(who)),
                ["fd", n] if !trailing => match number(n) {
                    Some(fd) => Target::Link(who, Link::Fd(fd)),
                    _ if zero_led(n) => Target::Missing,
                    _ => Target::Kernel,
                },
                ["fdinfo", n] => match number(n) {
                    Some(fd) => file(File::FdInfo { who, fd }),
                    _ => Target::Missing,
                },
                ["ns", k] if !trailing => match crate::proto::LX_PX_NS_NAMES.iter().position(|n| n == k) {
                    Some(i) => Target::Link(who, Link::Ns(i as u8)),
                    None => Target::Missing,
                },
                ["exe"] if !trailing => Target::Link(who, Link::Exe),
                ["cwd"] if !trailing => Target::Link(who, Link::Cwd),
                ["root"] if !trailing => Target::Link(who, Link::Root),
                // wave11 GP end
                // wave11 GP: the kernel's: another process's memory (`mem`), its network
                // view (`net/`), and walks through a magic link (into a directory it names)
                ["mem"] | ["net", ..] | ["task", _, "mem"] => Target::Kernel,
                ["fd", _, _, ..] | ["cwd" | "root" | "exe", _, ..] => Target::Kernel,
                [f] => pid_file(f, false).map_or_else(|| if trailing { Target::Kernel } else { Target::Missing }, |f| file(File::Pid { who, tid: 0, file: f })),
                ["task", t, f] => match (number(t), pid_file(f, true)) {
                    (Some(tid), Some(f)) if tid != 0 => file(File::Pid { who, tid, file: f }),
                    _ => Target::Missing,
                },
                // (wave11 GP: anything else below a process is not there)
                _ if trailing => Target::Kernel,
                _ => Target::Missing,
            }
        }
        _ => Target::Kernel,
    }
}

// wave11 GP begin
/// A name below `/proc` that is neither a process nor a file lx-proc serves: the kernel's
/// `net/`, `keys` and `sys/user/max_user_namespaces` (its tables, read and written there);
/// anything else does not exist (`ENOENT`, as the kernel answered).
fn kernel_or_missing(c: &[&str]) -> Target {
    match c {
        ["net", ..] | ["keys"] | ["sys", "user", "max_user_namespaces"] => Target::Kernel,
        _ => Target::Missing,
    }
}

/// A call relative to a `/proc` directory descriptor
/// The tail (below `/proc`) a path names when it is relative to the directory whose
/// descriptor shows `dir_name` (`/proc/123/fd`, `/proc`): `None` if that is not a `/proc`
/// directory or `path` is absolute (the kernel's then).
pub fn relative_tail(dir_name: &[u8], path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if path.first() == Some(&b'/') {
        return None;
    }
    let base = if dir_name == b"/proc" {
        &b""[..]
    } else {
        dir_name.strip_prefix(b"/proc/")?
    };
    let mut t = base.to_vec();
    if !t.is_empty() && !path.is_empty() {
        t.push(b'/');
    }
    t.extend_from_slice(path);
    Some(t)
}
// wave11 GP end

/// An inode number for a pseudo file (FNV-1a of its tail, never 0 or 1).
pub fn ino_of(obj: u64, tail: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (obj & 0xFFFF_FFFF);
    for &b in tail {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h >> 1) | 2
}
