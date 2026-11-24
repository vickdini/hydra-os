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
//! - Callers in a PID or user namespace of their own go to the kernel (their IDs need its
//!   translation).
//!
//! `pseudo=0` among the program's arguments sends every redirected call to the kernel.

pub mod path;
pub mod text;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Cx};
use hydra_rt::sys;

use path::{File, PidFile, Target, Who};

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;

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

// wave10 G8-2: lx-ipc's info call for `/proc/sysvipc/*` (8-2's `LX_IPC_OP_SYSVIPC` in
// `ipc/protocol.rs` once their branch is merged: then this local copy goes)
const LX_IPC_OP_SYSVIPC: u64 = 32;

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

/// Serves a path call the file service redirected here.
pub fn redirected(cx: &Cx) -> Answer {
    let c = &cx.c;
    if OFF.load(Ordering::Relaxed) || c.pid_ns != 0 || c.user_ns != 0 || c.redir_tail == u32::MAX {
        return kernel(cx);
    }
    let Ok(p) = cx.user_cstr(path_arg(cx)) else { return kernel(cx) };
    let Some(tail) = p.get(c.redir_tail as usize..) else { return kernel(cx) };
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
        21 | 269 | 439 => Some(access(cx, target)),
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
        // (the kernel's numbers for a /proc directory: 0555, 4096 bytes)
        Target::Dir(_) => (S_IFDIR | 0o555, 4096),
        _ => return None,
    };
    // A process's files and directories: the process must exist; they belong to its
    // effective user and group
    let (uid, gid, nlink) = match target {
        Target::Dir(d) => match dir_facts(cx.id, d) {
            Ok(f) => f,
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
        _ => GEN_SIZE,
    }
}

/// A process directory's owner and link count (2; `task/`: 2 + the threads, which Chromium
/// counts this way); the process (and the thread) must exist: `ENOENT`.
fn dir_facts(id: u64, d: path::Dir) -> Result<(u32, u32, u64), i64> {
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
/// 0555): `path::access_rule`, after the process exists.
fn access(cx: &Cx, target: Target) -> i64 {
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
            Ok((u, _, _)) => (0o555, u),
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

/// `readlink` of `/proc/self` (`<pid>`) and `/proc/thread-self` (`<pid>/task/<tid>`).
fn readlink(cx: &Cx, target: Target) -> Option<i64> {
    let Target::SelfLink(thread) = target else { return None };
    let (buf, size) = if cx.nr == 89 { (cx.args[1], cx.args[2]) } else { (cx.args[2], cx.args[3]) };
    if (size as i64) <= 0 {
        return Some(EINVAL);
    }
    let t = if thread { alloc::format!("{}/task/{}", cx.c.tgid, cx.c.tid) } else { alloc::format!("{}", cx.c.tgid) };
    let n = t.len().min(size as usize);
    Some(cx.copy_out(buf, &t.as_bytes()[..n]).err().unwrap_or(n as i64))
}

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
        File::Pid { who, tid, file } => match file {
            PidFile::Stat => text::stat(&task(id, who, tid)?),
            PidFile::Status => text::status(&task(id, who, tid)?),
            PidFile::Statm => text::statm(&task(id, who, tid)?),
            PidFile::Comm => text::comm_file(&task(id, who, tid | LX_INFO_TASK_NOMEM >> 32)?),
            PidFile::Cmdline => buffer(LX_INFO_ARGS, id, pid_word(who))?,
            PidFile::Environ => buffer(LX_INFO_ARGS, id, pid_word(who) | LX_INFO_ARGS_ENV)?,
            PidFile::Maps => text::maps(&buffer(LX_INFO_MAPS, id, pid_word(who))?),
            PidFile::Limits => text::limits(&limits(id, who)?),
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
fn open(cx: &Cx, obj: u64, tail: &[u8], target: Target) -> Option<i64> {
    let Target::File(mut file) = target else { return None };
    let flags = if cx.nr == 2 { cx.args[1] } else { cx.args[2] };
    if flags & (O_CREAT | O_DIRECTORY | O_PATH | O_TMPFILE) != 0 || flags & O_ACCMODE == 3 {
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
        _ => (0, 0, 0, None),
    };
    // Denied (maps or environ of a process the ptrace read rule hides): answered here, never
    // left to a laxer rule; other errors (the process went meanwhile) are the kernel's
    let text = match made {
        Some(t) => t,
        None => match make(cx.id, file, u64::MAX) {
            Ok(t) => t,
            Err(EACCES) => return Some(EACCES),
            Err(_) => return None,
        },
    };
    // The process by its system-wide ID from now on (reads may come from another process)
    let mut shown = alloc::string::String::from("/proc/");
    shown.push_str(&alloc::string::String::from_utf8_lossy(tail));
    if let File::Pid { who: Who::Caller, tid, file: f } = file {
        file = File::Pid { who: Who::Pid(cx.c.tgid), tid, file: f };
        if let Some(rest) = shown.strip_prefix("/proc/self/").or_else(|| shown.strip_prefix("/proc/thread-self/")) {
            shown = alloc::format!("/proc/{}/{}", cx.c.tgid, rest);
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
    d.size = size_of(file);
    let n = shown.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&shown.as_bytes()[..n]);
    d.name_len = n as u32;
    Some(match sys::lx_obj(LX_OBJ_PSNAP, cx.id, LX_PSNAP_INSTALL, &d as *const LxSnapIo as u64) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    })
}

/// `LX_KCALL_PREMAKE`: the text of a snapshot made again for the reader (a rewind, a
/// `pread` at 0), from its identity in `args[0]`, `args[3..6]`: written to the kernel's
/// buffer (`args[1]`, `args[2]` bytes) when it fits (answer: its length + 1), else given
/// with `LX_PSNAP_FILL` (answer 0). A process file whose process ended, or
/// whose ID now names another process (start time), fails with `ESRCH`; a reader the
/// primitives do not answer for (another namespace) gets their error.
pub fn remake(cx: &Cx) -> Answer {
    let Some((file, start)) = path::of_ident([cx.args[0], cx.args[3], cx.args[4], cx.args[5]]) else { return (EINVAL, 0) };
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
