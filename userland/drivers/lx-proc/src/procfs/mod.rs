//! # `/proc` served by lx-proc (wave 10, Group 7b-2; from linux-server's wave 7 Group 7-4)
//!
//! The file service (vfs-server) answers a path call whose walk ends under `/proc` with a
//! redirect to `LXS_PROC` (`docs/vfs-design.md` section 5): the same call arrives here with
//! `redir_obj` = the mount's object (`LX_VFS_PSEUDO_PROC`) and `redir_tail` = where the
//! part below the mount starts in the path argument.
//!
//! - [`path::classify`] decides what the tail names. What lx-proc does not serve goes on to
//!   the kernel (the redirect to service 0): its in-kernel code answers as before.
//! - `stat`/`lstat`/`newfstatat`/`statx`, `access`/`faccessat`/`faccessat2`, `readlink`
//!   (`/proc/self`, `/proc/thread-self`) and `open`/`openat` (read-only) are served.
//! - An open file is a **kernel-held snapshot** (`src/lx/procsnap.rs`): its text is made
//!   here at open from the kernel's info primitives (`LX_INFO_TASK`, `_SYS`, `_ARGS`,
//!   `_MAPS`; op 75 for the limits; lx-ipc's info call for `sysvipc`) and handed to the
//!   kernel with `LX_OBJ_PSNAP(LX_PSNAP_INSTALL)`. Reads, seeks, `fstat` and close never come
//!   here; a rewind or a `pread` at 0 comes back as `LX_KCALL_PREMAKE` with the file's
//!   identity ([`remake`]), so nothing is kept here per open file (restarts lose nothing).
//! - wave11 GP: also `/proc` itself and the process directories (listed into a kernel-held
//!   *directory snapshot*: `getdents64` and `rewinddir` as a file's reads and rewinds), the
//!   `/proc/sys` directories, the magic links (`readlink`, `lstat`; following one is the
//!   kernel's: it holds the handle), `fdinfo/N`, `auxv`, `cgroup`, `mountinfo`, `mounts`,
//!   the namespace maps, the OOM numbers, `filesystems`, `swaps`, `locks`, `asound`, the
//!   random UUIDs; and callers in a PID or user namespace of their own (the primitives
//!   translate their IDs). Calls relative to a `/proc` directory descriptor come here
//!   straight from the kernel (`LX_PROC_AT_DIRFD`).
//!
//! `pseudo=0` among the program's arguments sends every redirected call to the kernel.

pub mod path;
pub mod text;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Cx};
use hydra_rt::sys;

use path::{Dir, File, Link, PidFile, Target, Who};

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const ENOTDIR: i64 = -20;

const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;

const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000 | O_DIRECTORY;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
/// The size `stat` reports for a generated file (as the in-kernel copy does).
const GEN_SIZE: u64 = 512;

/// `pseudo=0`: everything goes to the kernel.
static OFF: AtomicBool = AtomicBool::new(false);
/// Redirected calls served here, and sent on to the kernel.
pub static SERVED: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL: AtomicU64 = AtomicU64::new(0);

/// Reads the program's arguments (`pseudo=0`).
pub fn init(args: &[&str]) {
    if args.iter().any(|a| *a == "pseudo=0") {
        OFF.store(true, Ordering::Relaxed);
    }
}

/// Whether `nr` is a path call this module serves when redirected here.
pub fn is_path_call(nr: u64) -> bool {
    matches!(nr, 4 | 6 | 262 | 332 | 21 | 269 | 439 | 89 | 267 | 2 | 257)
}

/// The answer that sends the call on to the kernel's own code.
fn kernel(cx: &Cx) -> Answer {
    TO_KERNEL.fetch_add(1, Ordering::Relaxed);
    svcrt::redirect(cx.page(), 0, 0, 0)
}

fn done(r: i64) -> Answer {
    let n = SERVED.fetch_add(1, Ordering::Relaxed) + 1;
    // (the first one, then at every power of two from 1024: the logs show the split)
    if n == 1 || (n >= 1024 && n.is_power_of_two()) {
        hydra_rt::println!("[lx-proc] /proc: {} calls served, {} sent to the kernel", n, TO_KERNEL.load(Ordering::Relaxed));
    }
    (r, 0)
}

/// The path argument of path call `cx`.
fn path_arg(cx: &Cx) -> u64 {
    match cx.nr {
        4 | 6 | 21 | 89 | 2 => cx.args[0],
        _ => cx.args[1],
    }
}

/// Serves a path call the file service redirected here (wave11 GP: or the kernel sent here,
/// relative to a `/proc` directory descriptor).
pub fn redirected(cx: &Cx) -> Answer {
    let c = &cx.c;
    if OFF.load(Ordering::Relaxed) || c.redir_tail == u32::MAX {
        return kernel(cx);
    }
    let Ok(p) = cx.user_cstr(path_arg(cx)) else { return kernel(cx) };
    // wave11 GP: relative to a `/proc` directory snapshot: its path, then the call's
    let owned;
    let tail: &[u8] = if c.redir_obj & LX_PROC_AT_DIRFD != 0 {
        let mut d = LxSnapIo::EMPTY;
        d.ident[0] = cx.args[0];
        if sys::lx_obj(LX_OBJ_PSNAP, cx.id, LX_PSNAP_IDENT, &mut d as *mut LxSnapIo as u64).is_err() {
            return kernel(cx);
        }
        match path::relative_tail(&d.name[..(d.name_len as usize).min(d.name.len())], &p) {
            Some(t) => {
                owned = t;
                &owned
            }
            None => return kernel(cx),
        }
    } else {
        match p.get(c.redir_tail as usize..) {
            Some(t) => t,
            None => return kernel(cx),
        }
    };
    let obj = c.redir_obj & 0xFFFF_FFFF;
    let target = path::classify(obj, tail);
    if target == Target::Kernel {
        return kernel(cx);
    }
    if target == Target::Missing {
        return done(ENOENT);
    }
    // wave10 G8-2: /proc/sysvipc/* only while an IPC service answers the info call (with
    // `lx.ipc=kernel` the kernel decides: there is no such file then)
    if matches!(target, Target::File(File::SysvIpc(_))) && hydra_rt::svccall::dcall(LXS_IPC, LX_DCALL_OP_NULL, &[], &mut []) < 0 {
        return kernel(cx);
    }
    let r = match cx.nr {
        4 | 6 | 262 | 332 => stat(cx, obj, tail, target),
        21 | 269 | 439 => access(cx, target),
        89 | 267 => readlink(cx, target),
        2 | 257 => open(cx, obj, tail, target),
        _ => None,
    };
    match r {
        Some(v) => done(v),
        None => kernel(cx),
    }
}

/// The `stat` family: a served file is a read-only regular file; `/proc/self` a link
/// (`lstat`; followed it is a directory: the kernel's).
fn stat(cx: &Cx, obj: u64, tail: &[u8], target: Target) -> Option<i64> {
    let a = cx.args;
    let (flags, out, x) = match cx.nr {
        4 => (0, a[1], false),
        6 => (0x100, a[1], false),
        262 => (a[3], a[2], false),
        _ => (a[2], a[4], true),
    };
    let nofollow = flags & 0x100 != 0;
    // (`/proc/self` followed: the caller's directory)
    let target = match target {
        Target::SelfLink(false) if !nofollow => Target::Dir(path::Dir::Pid(Who::Caller)),
        t => t,
    };
    let (mode, size) = match target {
        Target::File(f) => (S_IFREG | f.mode(), size_of(f)),
        Target::SelfLink(_) if nofollow => (S_IFLNK | 0o777, 0),
        // (wave11 GP: a magic link itself; followed it is the kernel's: the handle's file,
        // except a namespace: it stats as the namespace, an nsfs file)
        Target::Link(..) if nofollow => (S_IFLNK | 0o777, 0),
        Target::Link(who, Link::Ns(k)) => {
            return Some(match link_ino(cx.id, who, k) {
                Ok(ino) => {
                    let st = Stat { dev: NSFS_DEV, ino, mode: S_IFREG | 0o444, size: 0, uid: 0, gid: 0, nlink: 1 };
                    let r = if x { cx.copy_out(out, &st.statx()) } else { cx.copy_out(out, &st.stat()) };
                    r.err().unwrap_or(0)
                }
                Err(e) => e,
            });
        }
        // (the kernel's numbers for a /proc directory: 0555, 4096 bytes)
        Target::Dir(d) => (S_IFDIR | d.mode(), 4096),
        _ => return None,
    };
    // A process's files and directories: the process must exist; they belong to its
    // effective user and group
    let (uid, gid, nlink) = match target {
        Target::Dir(d) => match dir_facts(cx.id, d) {
            Ok(f) => f,
            Err(e) => return Some(e),
        },
        // wave11 GP: a link belongs to its process (which must exist); an `fd/N` link to a
        // descriptor that is open
        Target::Link(who, l) => match link_text(cx.id, who, l) {
            Ok(_) => match task(cx.id, who, LX_INFO_TASK_NOMEM >> 32) {
                Ok(i) => (i.ids[1], i.ids[4], 1),
                Err(_) => return Some(ENOENT),
            },
            Err(e) => return Some(e),
        },
        _ => match owner(cx.id, target) {
            Ok((u, g)) => (u, g, 1),
            Err(e) => return Some(e),
        },
    };
    let st = Stat { dev: LX_PSEUDO_DEV_PROC, ino: path::ino_of(obj, tail), mode, size, uid, gid, nlink };
    let r = if x { cx.copy_out(out, &st.statx()) } else { cx.copy_out(out, &st.stat()) };
    Some(r.err().unwrap_or(0))
}

/// The size `stat` (and `fstat`) report for `f`.
fn size_of(f: File) -> u64 {
    match f {
        File::Static(t) => t.len() as u64,
        // (wave11 GP: the files added in wave 11 say 0, as Linux's `/proc`)
        File::Filesystems | File::Swaps | File::Locks | File::BootId | File::Uuid | File::Asound(_) | File::FdInfo { .. } => 0,
        File::Pid { file: PidFile::Auxv | PidFile::Cgroup | PidFile::Mountinfo | PidFile::Mounts | PidFile::UidMap | PidFile::GidMap | PidFile::Setgroups | PidFile::OomScoreAdj | PidFile::OomScore, .. } => 0,
        _ => GEN_SIZE,
    }
}

/// A process directory's owner and link count (2; `task/`: 2 + the threads, which Chromium
/// counts this way); the process (and the thread) must exist: `ENOENT`. wave11 GP: the
/// directories of no process are root's.
fn dir_facts(id: u64, d: path::Dir) -> Result<(u32, u32, u64), i64> {
    if !d.of_process() {
        return Ok((0, 0, 2));
    }
    let tid = match d {
        path::Dir::Thread(_, t) => t,
        _ => 0,
    };
    match task(id, d.who(), tid | LX_INFO_TASK_NOMEM >> 32) {
        Ok(i) => Ok((i.ids[1], i.ids[4], if matches!(d, path::Dir::Task(_)) { 2 + i.threads } else { 2 })),
        Err(_) => Err(ENOENT),
    }
}

/// The owner of a served file: a process's files are its effective user's and group's (and
/// the process must exist: `ENOENT`); the others are root's.
fn owner(id: u64, target: Target) -> Result<(u32, u32), i64> {
    match target {
        Target::File(File::Pid { who, tid, .. }) => match task(id, who, tid | LX_INFO_TASK_NOMEM >> 32) {
            Ok(i) => Ok((i.ids[1], i.ids[4])),
            Err(_) => Err(ENOENT),
        },
        _ => Ok((0, 0)),
    }
}

/// `access`, `faccessat`, `faccessat2` of a served file or of `/proc/self` (a directory,
/// 0555): `path::access_rule`, after the process exists. A magic link is followed: the
/// kernel's (`None`).
fn access(cx: &Cx, target: Target) -> Option<i64> {
    if matches!(target, Target::Link(..)) {
        return None;
    }
    Some(access_of(cx, target))
}

fn access_of(cx: &Cx, target: Target) -> i64 {
    let a = cx.args;
    let (mode, flags) = match cx.nr {
        21 => (a[1], 0),
        269 => (a[2], 0),
        _ => (a[2], a[3]),
    };
    let c = &cx.c;
    // (faccessat2's AT_EACCESS: the effective ids)
    let uid = if flags & 0x200 != 0 { c.euid } else { c.uid };
    // The process must exist; its files and directories are its effective user's
    let (perm, owner_uid) = match target {
        Target::Dir(d) => match dir_facts(cx.id, d) {
            Ok((u, _, _)) => (d.mode(), u),
            Err(e) => return e,
        },
        Target::SelfLink(_) => (0o555, c.euid),
        Target::File(f) => match owner(cx.id, target) {
            Ok((u, _)) => (f.mode(), u),
            Err(e) => return e,
        },
        _ => return EINVAL,
    };
    path::access_rule(mode, if cx.nr == 439 { flags } else { 0 }, uid, perm, owner_uid).err().unwrap_or(0)
}

/// The fields of a pseudo file's `stat`.
struct Stat {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    uid: u32,
    gid: u32,
    nlink: u64,
}

impl Stat {
    /// `struct stat` (x86-64, 144 bytes).
    fn stat(&self) -> [u8; 144] {
        let mut b = [0u8; 144];
        b[0..8].copy_from_slice(&self.dev.to_le_bytes());
        b[8..16].copy_from_slice(&self.ino.to_le_bytes());
        b[16..24].copy_from_slice(&self.nlink.to_le_bytes());
        b[24..28].copy_from_slice(&self.mode.to_le_bytes());
        b[28..32].copy_from_slice(&self.uid.to_le_bytes());
        b[32..36].copy_from_slice(&self.gid.to_le_bytes());
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..64].copy_from_slice(&4096u64.to_le_bytes());
        b
    }

    /// `struct statx` (256 bytes), as the kernel's `write_statx` fills it.
    fn statx(&self) -> [u8; 256] {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(&0x17FFu32.to_le_bytes());
        b[4..8].copy_from_slice(&4096u32.to_le_bytes());
        b[16..20].copy_from_slice(&(self.nlink as u32).to_le_bytes());
        b[20..24].copy_from_slice(&self.uid.to_le_bytes());
        b[24..28].copy_from_slice(&self.gid.to_le_bytes());
        b[28..30].copy_from_slice(&(self.mode as u16).to_le_bytes());
        b[32..40].copy_from_slice(&self.ino.to_le_bytes());
        b[40..48].copy_from_slice(&self.size.to_le_bytes());
        b[136..140].copy_from_slice(&(((self.dev >> 8) & 0xFFF) as u32).to_le_bytes());
        b[140..144].copy_from_slice(&((self.dev & 0xFF) as u32).to_le_bytes());
        b[144..152].copy_from_slice(&(20 + (self.dev & 0xFFFF)).to_le_bytes());
        b
    }
}

/// `readlink` of `/proc/self` (`<pid>`) and `/proc/thread-self` (`<pid>/task/<tid>`);
/// wave11 GP: and of the magic links (`fd/N`, `exe`, `cwd`, `root`, `ns/<kind>`), under the
/// `ptrace` read rule; anything else is not a link (`EINVAL`).
fn readlink(cx: &Cx, target: Target) -> Option<i64> {
    let (buf, size) = if cx.nr == 89 { (cx.args[1], cx.args[2]) } else { (cx.args[2], cx.args[3]) };
    if (size as i64) <= 0 {
        return Some(EINVAL);
    }
    let t = match target {
        Target::SelfLink(thread) => {
            // (the IDs as the caller's PID namespace shows them)
            let (pid, tid) = own_ids(cx);
            if thread {
                alloc::format!("{}/task/{}", pid, tid).into_bytes()
            } else {
                alloc::format!("{}", pid).into_bytes()
            }
        }
        Target::Link(who, l) => match link_text(cx.id, who, l) {
            Ok(t) => t,
            Err(e) => return Some(e),
        },
        Target::File(_) | Target::Dir(_) => return Some(EINVAL),
        _ => return None,
    };
    let n = t.len().min(size as usize);
    Some(cx.copy_out(buf, &t[..n]).err().unwrap_or(n as i64))
}

// wave11 GP begin
/// The caller's process and thread IDs as its PID namespace shows them.
fn own_ids(cx: &Cx) -> (u64, u64) {
    if cx.c.pid_ns == 0 {
        return (cx.c.tgid, cx.c.tid);
    }
    match task(cx.id, Who::Caller, LX_INFO_TASK_NOMEM >> 32) {
        Ok(i) => (i.pid, cx.c.tid),
        Err(_) => (cx.c.tgid, cx.c.tid),
    }
}

/// A buffer answer of `LX_INFO_PROCX` operation `what` about `pid` (as the caller names
/// it), with `arg`: the bytes and the words.
fn procx(id: u64, what: u64, pid: u64, arg: u64, input: &[u8]) -> Result<(Vec<u8>, [u64; 11]), i64> {
    let mut cap = 4096usize.max(input.len());
    loop {
        let mut v = alloc::vec![0u8; cap];
        v[..input.len()].copy_from_slice(input);
        let mut io = LxProcxIo { pid, tid: 0, arg, buf: v.as_mut_ptr() as u64, cap: cap as u64, out: [0; 11] };
        let n = sys::lx_obj(LX_INFO_PROCX, id, what, &mut io as *mut LxProcxIo as u64)? as usize;
        if n <= cap {
            v.truncate(n);
            return Ok((v, io.out));
        }
        if n > 16 << 20 {
            return Err(EINVAL);
        }
        cap = n.next_power_of_two();
    }
}

/// `st_dev` of a namespace file (Linux's nsfs, 0:4; the kernel's descriptor of an opened
/// one says the same).
const NSFS_DEV: u64 = 4;

/// The inode number of namespace `k` of `who` (`ENOENT`: none of that kind).
fn link_ino(id: u64, who: Who, k: u8) -> Result<u64, i64> {
    let out = procx(id, LX_PX_NSINO, pid_word(who), 0, &[])?.1;
    match out[k as usize] {
        0 => Err(ENOENT),
        ino => Ok(ino),
    }
}

/// The text of magic link `l` of `who` (`fd/N`: `ENOENT` when not open).
fn link_text(id: u64, who: Who, l: Link) -> Result<Vec<u8>, i64> {
    let pid = pid_word(who);
    match l {
        Link::Fd(fd) => Ok(procx(id, LX_PX_FDLINK, pid, fd, &[])?.0),
        Link::Exe => Ok(procx(id, LX_PX_LINK, pid, 0, &[])?.0),
        Link::Cwd => Ok(procx(id, LX_PX_LINK, pid, 1, &[])?.0),
        Link::Root => Ok(procx(id, LX_PX_LINK, pid, 2, &[])?.0),
        Link::Ns(k) => Ok(text::ns_link(LX_PX_NS_NAMES[k as usize], link_ino(id, who, k)?).into_bytes()),
    }
}

/// The inode numbers of a directory's entries (as `stat` shows them: [`path::ino_of`] of
/// the entry's tail).
fn entry_ino(dir_tail: &str, name: &str) -> u64 {
    if dir_tail.is_empty() {
        path::ino_of(LX_VFS_PSEUDO_PROC, name.as_bytes())
    } else {
        path::ino_of(LX_VFS_PSEUDO_PROC, alloc::format!("{}/{}", dir_tail, name).as_bytes())
    }
}

/// The names a process directory lists (besides `fd`, `fdinfo`, `ns`, `task`).
const PID_NAMES: [(&str, u8); 23] = [
    ("fd", text::DT_DIR),
    ("fdinfo", text::DT_DIR),
    ("ns", text::DT_DIR),
    ("task", text::DT_DIR),
    ("net", text::DT_DIR),
    ("auxv", text::DT_REG),
    ("cgroup", text::DT_REG),
    ("cmdline", text::DT_REG),
    ("comm", text::DT_REG),
    ("environ", text::DT_REG),
    ("gid_map", text::DT_REG),
    ("limits", text::DT_REG),
    ("maps", text::DT_REG),
    ("mountinfo", text::DT_REG),
    ("mounts", text::DT_REG),
    ("oom_score", text::DT_REG),
    ("oom_score_adj", text::DT_REG),
    ("setgroups", text::DT_REG),
    ("stat", text::DT_REG),
    ("statm", text::DT_REG),
    ("status", text::DT_REG),
    ("uid_map", text::DT_REG),
    ("exe", text::DT_LNK),
];

/// The listing of directory `d` (its tail `tail`, IDs as the opener names them).
fn list(id: u64, d: Dir) -> Result<Vec<u8>, i64> {
    let tail = path::dir_tail(d);
    let mut names: Vec<(alloc::string::String, u8)> = Vec::new();
    let mut push = |n: &str, t: u8| names.push((alloc::string::String::from(n), t));
    match d {
        Dir::Root => {
            for p in text::u32s(&procx(id, LX_PX_PIDS, 0, 0, &[])?.0) {
                names.push((alloc::format!("{}", p), text::DT_DIR));
            }
            let mut push = |n: &str, t: u8| names.push((alloc::string::String::from(n), t));
            push("self", text::DT_LNK);
            push("thread-self", text::DT_LNK);
            for n in ["asound", "net", "sys", "sysvipc"] {
                push(n, text::DT_DIR);
            }
            for n in ["cpuinfo", "filesystems", "loadavg", "locks", "meminfo", "mounts", "stat", "swaps", "uptime", "version"] {
                push(n, text::DT_REG);
            }
        }
        Dir::Pid(_) => {
            for (n, t) in PID_NAMES {
                push(n, t);
            }
            push("cwd", text::DT_LNK);
            push("root", text::DT_LNK);
        }
        Dir::Task(w) => {
            for t in text::u32s(&procx(id, LX_PX_TASKS, pid_word(w), 0, &[])?.0) {
                names.push((alloc::format!("{}", t), text::DT_DIR));
            }
        }
        Dir::Thread(..) => {
            for n in ["comm", "stat", "status"] {
                push(n, text::DT_REG);
            }
        }
        Dir::Fd(w) | Dir::FdInfo(w) => {
            let t = if matches!(d, Dir::Fd(_)) { text::DT_LNK } else { text::DT_REG };
            for fd in text::u32s(&procx(id, LX_PX_FDS, pid_word(w), 0, &[])?.0) {
                names.push((alloc::format!("{}", fd), t));
            }
        }
        Dir::Ns(w) => {
            let out = procx(id, LX_PX_NSINO, pid_word(w), 0, &[])?.1;
            for (k, n) in LX_PX_NS_NAMES.iter().enumerate() {
                if out[k] != 0 {
                    push(n, text::DT_LNK);
                }
            }
        }
        Dir::Static(i) => {
            let dirs = path::static_dirs();
            let here = dirs.get(i as usize).copied().ok_or(ENOENT)?;
            let mut seen: Vec<&str> = Vec::new();
            for (p, _) in path::STATIC.iter().chain(path::MORE_SYS.iter()) {
                let Some(rest) = p.strip_prefix(here).and_then(|r| r.strip_prefix('/')) else { continue };
                let (first, deeper) = match rest.find('/') {
                    Some(k) => (&rest[..k], true),
                    None => (rest, false),
                };
                if !seen.contains(&first) {
                    seen.push(first);
                    names.push((alloc::string::String::from(first), if deeper { text::DT_DIR } else { text::DT_REG }));
                }
            }
        }
        Dir::SysvIpc => {
            for n in ["msg", "sem", "shm"] {
                push(n, text::DT_REG);
            }
        }
        Dir::Asound => {
            for n in path::ASOUND {
                if !n.contains('/') && make(id, File::Asound(path::ASOUND.iter().position(|x| *x == n).unwrap_or(0) as u8), u64::MAX).is_ok() {
                    push(n, text::DT_REG);
                }
            }
        }
    }
    let entries: Vec<(u64, u8, &[u8])> = names.iter().map(|(n, t)| (entry_ino(&tail, n), *t, n.as_bytes())).collect();
    Ok(text::dir_text(&entries))
}
// wave11 GP end

/// The process facts for `who`/`tid` as the caller of request `id` names them.
fn task(id: u64, who: Who, tid: u64) -> Result<LxTaskInfo, i64> {
    let pid = pid_word(who);
    // (IDs travel in 32-bit halves; `path::classify` keeps them below 2^31)
    if pid > i32::MAX as u64 || (tid & !(LX_INFO_TASK_NOMEM >> 32)) > i32::MAX as u64 {
        return Err(EINVAL);
    }
    let mut i = LxTaskInfo::default();
    sys::lx_obj(LX_INFO_TASK, id, pid | tid << 32, &mut i as *mut LxTaskInfo as u64)?;
    Ok(i)
}

/// The system facts `what` names (`LX_INFO_SYS_MEM`, `LX_INFO_SYS_CPU`; the time and the
/// CPU count always).
fn sysinfo(what: u64) -> Result<LxSysInfo, i64> {
    let mut s = LxSysInfo::default();
    sys::lx_obj(LX_INFO_SYS, &mut s as *mut LxSysInfo as u64, what, 0)?;
    Ok(s)
}

/// A buffer answer of an info primitive taking `(id, pid | len << 32, buf)` (`pid` may carry
/// `LX_INFO_ARGS_ENV`): grows the buffer until the answer fits.
fn buffer(op: u64, id: u64, pid: u64) -> Result<Vec<u8>, i64> {
    if pid > u32::MAX as u64 {
        return Err(EINVAL);
    }
    let mut cap = 4096usize;
    loop {
        let mut v = alloc::vec![0u8; cap];
        let n = sys::lx_obj(op, id, pid | (cap as u64) << 32, v.as_mut_ptr() as u64)? as usize;
        if n <= cap {
            v.truncate(n);
            return Ok(v);
        }
        if n > 16 << 20 {
            return Err(EINVAL);
        }
        cap = n.next_power_of_two();
    }
}

/// The resource limits of `who` (soft, hard), through the process primitives (op 75).
fn limits(id: u64, who: Who) -> Result<[(u64, u64); text::NLIMITS], i64> {
    let mut l = [(0u64, 0u64); text::NLIMITS];
    for (r, v) in l.iter_mut().enumerate() {
        let mut io = LxProcIo::EMPTY;
        io.a[0] = pid_word(who);
        io.a[1] = r as u64;
        sys::lx_obj(LX_OBJ_PROCID, id, LXP_LIMIT_GET, &mut io as *mut LxProcIo as u64)?;
        *v = (io.a[0], io.a[1]);
    }
    Ok(l)
}

// wave10 G8-2 begin
/// `/proc/sysvipc/<kind>` for the caller of the request being served: the IPC service's
/// info call (`LX_IPC_OP_SYSVIPC`, a delegated direct call: lx-ipc finds the reader's IPC
/// namespace), chunk by chunk. `ENOENT` when the IPC calls are the kernel's (`lx.ipc=kernel`:
/// `ipcs` then asks with `shmctl`).
fn sysvipc(kind: u8, ns: u64) -> Result<Vec<u8>, i64> {
    let mut text = Vec::new();
    let mut cursor = 0u64;
    let mut out = alloc::vec![0u8; 2048];
    for _ in 0..4096 {
        let mut input = [0u8; 24];
        input[..8].copy_from_slice(&(kind as u64).to_le_bytes());
        input[8..16].copy_from_slice(&cursor.to_le_bytes());
        input[16..].copy_from_slice(&ns.to_le_bytes());
        let n = hydra_rt::svccall::dcall(LXS_IPC, LX_IPC_OP_SYSVIPC, &input, &mut out);
        if n < 8 {
            return Err(ENOENT);
        }
        let n = (n as usize).min(out.len());
        text.extend_from_slice(&out[8..n]);
        cursor = u64::from_le_bytes(out[..8].try_into().unwrap());
        if cursor == 0 {
            break;
        }
    }
    Ok(text)
}
// wave10 G8-2 end

/// The text of `file` for the caller of request `id` (`ipc_ns`: the IPC namespace for
/// `sysvipc`, `u64::MAX`: the caller's).
fn make(id: u64, file: File, ipc_ns: u64) -> Result<Vec<u8>, i64> {
    Ok(match file {
        File::Static(t) => t.to_vec(),
        File::Version => text::VERSION.to_vec(),
        File::Uptime | File::Loadavg | File::Stat => {
            let s = sysinfo(LX_INFO_SYS_CPU)?;
            match file {
                File::Uptime => text::uptime(&s),
                File::Loadavg => text::loadavg(&s),
                _ => text::proc_stat(&s),
            }
        }
        File::Meminfo => text::meminfo(&sysinfo(LX_INFO_SYS_MEM)?),
        File::SysvIpc(kind) => sysvipc(kind, ipc_ns)?,
        File::Cpuinfo => text::cpuinfo(sysinfo(0)?.ncpu.max(1)),
        // wave11 GP begin
        File::Filesystems => procx(id, LX_PX_TEXT, 0, LX_PX_T_FILESYSTEMS, &[])?.0,
        File::Swaps => procx(id, LX_PX_TEXT, 0, LX_PX_T_SWAPS, &[])?.0,
        File::Locks => procx(id, LX_PX_TEXT, 0, LX_PX_T_LOCKS, &[])?.0,
        File::BootId => procx(id, LX_PX_TEXT, 0, LX_PX_T_BOOTID, &[])?.0,
        File::Uuid => procx(id, LX_PX_TEXT, 0, LX_PX_T_UUID, &[])?.0,
        File::Asound(i) => {
            let mut name = path::ASOUND.get(i as usize).ok_or(ENOENT)?.as_bytes().to_vec();
            name.push(0);
            procx(id, LX_PX_TEXT, 0, LX_PX_T_ASOUND, &name)?.0
        }
        File::FdInfo { who, fd } => {
            let (extra, out) = procx(id, LX_PX_FDINFO, pid_word(who), fd, &[])?;
            let mut t = text::fdinfo(&out);
            t.extend_from_slice(&extra);
            t
        }
        // wave11 GP end
        File::Pid { who, tid, file } => match file {
            PidFile::Stat => text::stat(&task(id, who, tid)?),
            PidFile::Status => text::status(&task(id, who, tid)?),
            PidFile::Statm => text::statm(&task(id, who, tid)?),
            PidFile::Comm => text::comm_file(&task(id, who, tid | LX_INFO_TASK_NOMEM >> 32)?),
            PidFile::Cmdline => buffer(LX_INFO_ARGS, id, pid_word(who))?,
            PidFile::Environ => buffer(LX_INFO_ARGS, id, pid_word(who) | LX_INFO_ARGS_ENV)?,
            PidFile::Maps => text::maps(&buffer(LX_INFO_MAPS, id, pid_word(who))?),
            PidFile::Limits => text::limits(&limits(id, who)?),
            // wave11 GP begin
            PidFile::Auxv => procx(id, LX_PX_AUXV, pid_word(who), 0, &[])?.0,
            PidFile::Cgroup => text::cgroup(&procx(id, LX_PX_CGROUP, pid_word(who), 0, &[])?.0),
            PidFile::Mountinfo => procx(id, LX_PX_TEXT, pid_word(who), LX_PX_T_MOUNTINFO, &[])?.0,
            PidFile::Mounts => procx(id, LX_PX_TEXT, pid_word(who), LX_PX_T_MOUNTS, &[])?.0,
            PidFile::UidMap => procx(id, LX_PX_IDMAP, pid_word(who), 0, &[])?.0,
            PidFile::GidMap => procx(id, LX_PX_IDMAP, pid_word(who), 1, &[])?.0,
            PidFile::Setgroups => procx(id, LX_PX_IDMAP, pid_word(who), 2, &[])?.0,
            PidFile::OomScoreAdj => text::number_line(procx(id, LX_PX_OOM, pid_word(who), 0, &[])?.1[0] as i64),
            PidFile::OomScore => text::number_line(procx(id, LX_PX_OOM, pid_word(who), 0, &[])?.1[1] as i64),
            // wave11 GP end
        },
    })
}

fn pid_word(who: Who) -> u64 {
    match who {
        Who::Caller => 0,
        Who::Pid(p) => p,
    }
}

/// `open`/`openat` of a served file, read-only: a kernel-held snapshot of its text.
/// wave11 GP: a directory: a snapshot of its listing; a magic link (followed) and a write
/// open of a file the kernel's mechanism takes writes for: the kernel's.
fn open(cx: &Cx, obj: u64, tail: &[u8], target: Target) -> Option<i64> {
    let flags = if cx.nr == 2 { cx.args[1] } else { cx.args[2] };
    if let Target::Dir(d) = target {
        return open_dir(cx, obj, tail, d, flags);
    }
    // (`/proc/self` and `/proc/thread-self` followed: the caller's directory; the link
    // itself, `O_NOFOLLOW`, is the kernel's)
    const O_NOFOLLOW: u64 = 0o400000;
    if let Target::SelfLink(thread) = target {
        if flags & O_NOFOLLOW != 0 {
            return None;
        }
        let d = if thread { Dir::Thread(Who::Caller, own_ids(cx).1) } else { Dir::Pid(Who::Caller) };
        return open_dir(cx, obj, tail, d, flags);
    }
    let Target::File(mut file) = target else { return None };
    if flags & (O_CREAT | O_DIRECTORY | O_PATH | O_TMPFILE) != 0 || flags & O_ACCMODE == 3 {
        // (wave11 GP: opening a file as a directory: ENOTDIR, as Linux)
        if flags & O_DIRECTORY != 0 && flags & O_CREAT == 0 && flags & O_TMPFILE != O_TMPFILE {
            return Some(ENOTDIR);
        }
        return None;
    }
    // wave11 GP: written through the kernel's mechanism (namespace maps, oom_score_adj)
    if flags & O_ACCMODE != 0 && file.writable() {
        return None;
    }
    // Writing: the files are read-only (0444, `environ` 0400): refused for everyone but root
    // (as Linux: root's open works, its writes fail with `EIO`)
    if flags & O_ACCMODE != 0 && cx.c.euid != 0 {
        return Some(EACCES);
    }
    // A process's file: the process (its start time pins it for later remakes) and owner;
    // no such process: the kernel answers (as before). `stat`, `status` and `statm` are made
    // from the same facts (one request, with the memory figures; wave9 GP2)
    let once = match file {
        File::Pid { who, tid, file: pf @ (PidFile::Stat | PidFile::Status | PidFile::Statm) } => task(cx.id, who, tid).ok().map(|i| {
            let t = match pf {
                PidFile::Stat => text::stat(&i),
                PidFile::Status => text::status(&i),
                _ => text::statm(&i),
            };
            (i.start.max(1), i.ids[1], i.ids[4], Some(t))
        }),
        _ => None,
    };
    let (start, uid, gid, made) = match (once, file) {
        (Some(o), _) => o,
        (None, File::Pid { who, tid, .. }) => {
            let i = task(cx.id, who, tid | LX_INFO_TASK_NOMEM >> 32).ok()?;
            (i.start.max(1), i.ids[1], i.ids[4], None)
        }
        // (wave11 GP: fdinfo: the process's, pinned as its other files)
        (None, File::FdInfo { who, .. }) => {
            let i = task(cx.id, who, LX_INFO_TASK_NOMEM >> 32).ok()?;
            (i.start.max(1), i.ids[1], i.ids[4], None)
        }
        _ => (0, 0, 0, None),
    };
    // Denied (maps or environ of a process the ptrace read rule hides): answered here, never
    // left to a laxer rule; other errors (the process went meanwhile) are the kernel's
    let text = match made {
        Some(t) => t,
        None => match make(cx.id, file, u64::MAX) {
            Ok(t) => t,
            Err(EACCES) => return Some(EACCES),
            // (wave11 GP: no such descriptor, not a sound card: as Linux)
            Err(ENOENT) if matches!(file, File::FdInfo { .. } | File::Asound(_)) => return Some(ENOENT),
            Err(_) => return None,
        },
    };
    // The process by its ID from now on (reads may come from another process): the
    // system-wide one, or (wave11 GP) the one the caller's PID namespace shows, as the
    // remake asks with the opener's rights
    let mut shown = alloc::string::String::from("/proc/");
    shown.push_str(&alloc::string::String::from_utf8_lossy(tail));
    let me = own_ids(cx).0;
    let named = match file {
        File::Pid { who: Who::Caller, tid, file: f } => {
            file = File::Pid { who: Who::Pid(me), tid, file: f };
            true
        }
        File::FdInfo { who: Who::Caller, fd } => {
            file = File::FdInfo { who: Who::Pid(me), fd };
            true
        }
        _ => false,
    };
    if named {
        if let Some(rest) = shown.strip_prefix("/proc/self/").or_else(|| shown.strip_prefix("/proc/thread-self/")) {
            shown = alloc::format!("/proc/{}/{}", me, rest);
        }
    }
    let mut d = LxSnapIo::EMPTY;
    d.text = text.as_ptr() as u64;
    d.len = text.len() as u64;
    d.ident = path::ident(file, start);
    d.flags = (flags & (O_NONBLOCK | O_CLOEXEC | O_ACCMODE)) as u32;
    d.mode = S_IFREG | file.mode();
    d.uid = uid;
    d.gid = gid;
    d.ino = path::ino_of(obj, tail);
    d.dev = LX_PSEUDO_DEV_PROC;
    // (wave11 GP: an open file's `fstat` says the length of its text: D-Bus reads
    // `/proc/self/fdinfo/N` up to `st_size` and takes an early end as an error)
    d.size = text.len() as u64;
    let n = shown.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&shown.as_bytes()[..n]);
    d.name_len = n as u32;
    Some(match sys::lx_obj(LX_OBJ_PSNAP, cx.id, LX_PSNAP_INSTALL, &d as *const LxSnapIo as u64) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    })
}

// wave11 GP begin
/// `open` of a directory: a snapshot of its listing (`O_PATH` too: a descriptor to walk
/// from); writing: `EISDIR`. A process's directory pins its process (start time).
fn open_dir(cx: &Cx, obj: u64, tail: &[u8], d: Dir, flags: u64) -> Option<i64> {
    // (`O_TMPFILE` holds `O_DIRECTORY`: only the whole of it is a temporary file)
    if flags & O_CREAT != 0 || flags & O_TMPFILE == O_TMPFILE {
        return None;
    }
    if flags & O_ACCMODE != 0 {
        return Some(-21); // EISDIR
    }
    // The process (its start time pins it) and its ids; the caller's own by its ID
    let me = own_ids(cx).0;
    let resolve = |w: Who| match w {
        Who::Caller => Who::Pid(me),
        p => p,
    };
    let d = match d {
        Dir::Pid(w) => Dir::Pid(resolve(w)),
        Dir::Task(w) => Dir::Task(resolve(w)),
        Dir::Thread(w, t) => Dir::Thread(resolve(w), t),
        Dir::Fd(w) => Dir::Fd(resolve(w)),
        Dir::FdInfo(w) => Dir::FdInfo(resolve(w)),
        Dir::Ns(w) => Dir::Ns(resolve(w)),
        other => other,
    };
    let (start, uid, gid) = if d.of_process() {
        let tid = if let Dir::Thread(_, t) = d { t } else { 0 };
        match task(cx.id, d.who(), tid | LX_INFO_TASK_NOMEM >> 32) {
            Ok(i) => (i.start.max(1), i.ids[1], i.ids[4]),
            Err(_) => return Some(ENOENT),
        }
    } else {
        (0, 0, 0)
    };
    let text = match list(cx.id, d) {
        Ok(t) => t,
        Err(EACCES) => return Some(EACCES),
        Err(ENOENT) | Err(ESRCH) => return Some(ENOENT),
        Err(_) => return None,
    };
    let shown = if d == Dir::Root { alloc::string::String::from("/proc") } else { alloc::format!("/proc/{}", path::dir_tail(d)) };
    let mut s = LxSnapIo::EMPTY;
    s.text = text.as_ptr() as u64;
    s.len = text.len() as u64;
    s.ident = path::dir_ident(d, start);
    s.flags = (flags & (O_NONBLOCK | O_CLOEXEC | O_ACCMODE)) as u32;
    s.mode = S_IFDIR | d.mode();
    s.uid = uid;
    s.gid = gid;
    s.ino = path::ino_of(obj, tail);
    s.dev = LX_PSEUDO_DEV_PROC;
    s.size = 0;
    let n = shown.len().min(LX_OBJ_NAME_MAX);
    s.name[..n].copy_from_slice(&shown.as_bytes()[..n]);
    s.name_len = n as u32;
    Some(match sys::lx_obj(LX_OBJ_PSNAP, cx.id, LX_PSNAP_INSTALL, &s as *const LxSnapIo as u64) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    })
}
// wave11 GP end

/// `LX_KCALL_PREMAKE`: the text of a snapshot made again for the reader (a rewind, a
/// `pread` at 0), from its identity in `args[0]`, `args[3..6]`: written to the kernel's
/// buffer (`args[1]`, `args[2]` bytes) when it fits (answer: its length + 1), else given
/// with `LX_PSNAP_FILL` (answer 0). A process file whose process ended, or
/// whose ID now names another process (start time), fails with `ESRCH`; a reader the
/// primitives do not answer for (another namespace) gets their error.
pub fn remake(cx: &Cx) -> Answer {
    let ident = [cx.args[0], cx.args[3], cx.args[4], cx.args[5]];
    // wave11 GP: a directory's listing (rewinddir), its process pinned
    if let Some((d, start)) = path::dir_of_ident(ident) {
        if d.of_process() {
            let tid = if let Dir::Thread(_, t) = d { t } else { 0 };
            match task(cx.id, d.who(), tid | LX_INFO_TASK_NOMEM >> 32) {
                Ok(i) if i.start.max(1) == start => {}
                Ok(_) => return (ESRCH, 0),
                Err(e) => return (e, 0),
            }
        }
        return match list(cx.id, d) {
            Ok(t) => give(cx, t),
            Err(e) => (e, 0),
        };
    }
    let Some((file, start)) = path::of_ident(ident) else { return (EINVAL, 0) };
    // wave11 GP: fdinfo: the process pinned (before and after)
    if let File::FdInfo { who, .. } = file {
        let pinned = |cx: &Cx| matches!(task(cx.id, who, LX_INFO_TASK_NOMEM >> 32), Ok(i) if i.start.max(1) == start);
        if !pinned(cx) {
            return (ESRCH, 0);
        }
        let t = match make(cx.id, file, cx.c.ipc_ns) {
            Ok(t) => t,
            Err(e) => return (e, 0),
        };
        if !pinned(cx) {
            return (ESRCH, 0);
        }
        return give(cx, t);
    }
    // (the kernel answers this request with the rights of the process that opened the file,
    // and names the opener's IPC namespace in the call)
    let text = match file {
        // A process's file: pinned by its start time. stat/status/statm/comm are made from
        // the very lookup that checks it; the others check it before and after making the
        // text (process and thread IDs are never reused: the kernel counts them up, so a
        // thread of `task/<tid>` is the one opened while the lookup finds it in the process)
        File::Pid { who, tid, file: pf } => {
            let mem = matches!(pf, PidFile::Stat | PidFile::Status | PidFile::Statm);
            let i = match task(cx.id, who, if mem { tid } else { tid | LX_INFO_TASK_NOMEM >> 32 }) {
                Ok(i) if i.start.max(1) == start => i,
                Ok(_) => return (ESRCH, 0),
                Err(e) => return (e, 0),
            };
            let made = match pf {
                PidFile::Stat => Ok(text::stat(&i)),
                PidFile::Status => Ok(text::status(&i)),
                PidFile::Statm => Ok(text::statm(&i)),
                PidFile::Comm => Ok(text::comm_file(&i)),
                _ => make(cx.id, file, cx.c.ipc_ns),
            };
            let t = match made {
                Ok(t) => t,
                Err(e) => return (e, 0),
            };
            if !mem && pf != PidFile::Comm {
                match task(cx.id, who, tid | LX_INFO_TASK_NOMEM >> 32) {
                    Ok(j) if j.start.max(1) == start => {}
                    Ok(_) => return (ESRCH, 0),
                    Err(e) => return (e, 0),
                }
            }
            t
        }
        _ => match make(cx.id, file, cx.c.ipc_ns) {
            Ok(t) => t,
            Err(e) => return (e, 0),
        },
    };
    give(cx, text)
}

/// The answer of a remake: `text` in the kernel's buffer when it fits, else handed over.
fn give(cx: &Cx, text: Vec<u8>) -> Answer {
    if text.len() as u64 <= cx.args[2] {
        return match cx.copy_out_any(cx.args[1], &text) {
            Ok(()) => (text.len() as i64 + 1, 0),
            Err(e) => (e, 0),
        };
    }
    let mut d = LxSnapIo::EMPTY;
    d.text = text.as_ptr() as u64;
    d.len = text.len() as u64;
    match sys::lx_obj(LX_OBJ_PSNAP, cx.id, LX_PSNAP_FILL, &d as *const LxSnapIo as u64) {
        Ok(_) => (0, 0),
        Err(e) => (if e == 0 { EIO } else { e }, 0),
    }
}
