//! # Pseudo file systems: `/proc` and `/sys` served by linux-server (wave 7, Group 7-4)
//!
//! The file service (vfs-server) answers a path call whose walk ends under `/proc` or
//! `/sys` with a redirect here (`docs/vfs-design.md` section 5): the same call arrives with
//! `LxCall::svc` = `LXS_PROC`/`LXS_LINUX`, `redir_obj` = the mount's object
//! (`LX_VFS_PSEUDO_PROC`/`_SYS`) and `redir_tail` = where the part below the mount starts
//! in the path argument.
//!
//! - [`path::classify`] decides what the tail names. What linux-server does not serve yet
//!   goes on to the kernel (the redirect to service 0): its in-kernel code answers as
//!   before, so files move one at a time without losing anything.
//! - `stat`/`lstat`/`newfstatat`/`statx`, `access`/`faccessat`/`faccessat2`, `readlink`
//!   (`/proc/self`, `/proc/thread-self`) and `open`/`openat` (read-only) are served.
//! - An open file is a server object of kind `LX_OBJ_KIND_PSEUDO` whose text is made at
//!   open from the kernel's info primitives (`src/lx/info.rs`: `LX_INFO_TASK`, `_SYS`,
//!   `_ARGS`, `_MAPS`); `read`/`readv` come here as for any server object, `lseek` and
//!   `pread64` as the kernel's calls `LX_KCALL_PSEEK`/`LX_KCALL_PREAD`. A seek to 0 or a
//!   `pread` at 0 makes the text again (as Linux's seq_file does on a read from 0).
//! - Callers in a PID or user namespace of their own go to the kernel (their IDs need its
//!   translation).
//!
//! `pseudo=0` among the program's arguments sends every redirected call to the kernel.

pub mod path;
pub mod text;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer};
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;
use path::{File, PidFile, Target, Who};

const ENXIO: i64 = -6;
const EBADF: i64 = -9;
const ENOTTY: i64 = -25;
const EINVAL: i64 = -22;

const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000 | O_DIRECTORY;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
/// `POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM`: a regular file is always ready.
const READY: u32 = 0x1 | 0x4 | 0x40 | 0x100;
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

/// An open pseudo file.
struct Open {
    /// What it is (a `/proc/<pid>` file names its process by system-wide ID).
    file: File,
    /// The path below the mount (an efivars file's name).
    tail: Vec<u8>,
    /// The text as made at open (or at the last read from 0).
    text: Vec<u8>,
    /// The position of `read`.
    pos: u64,
}

/// The open pseudo files, by object slot.
static OPENS: YLock<BTreeMap<u32, Open>> = YLock::new(BTreeMap::new());

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
        hydra_rt::println!("[linux-server] pseudo: {} /proc and /sys calls served, {} sent to the kernel", n, TO_KERNEL.load(Ordering::Relaxed));
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
    // (an efivars file exists in the pool too: its stat and access are the kernel's; only
    // a read-only open is served here)
    if target == Target::Kernel || (target == Target::File(File::Efivar) && !matches!(cx.nr, 2 | 257)) {
        return kernel(cx);
    }
    let r = match cx.nr {
        4 | 6 | 262 | 332 => stat(cx, obj, tail, target),
        21 | 269 | 439 => Some(0),
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
    let (mode, size) = match target {
        Target::File(File::Static(t)) => (S_IFREG | 0o444, t.len() as u64),
        Target::File(_) => (S_IFREG | 0o444, GEN_SIZE),
        Target::SelfLink(_) if nofollow => (S_IFLNK | 0o777, 0),
        _ => return None,
    };
    let dev = match target {
        Target::File(f) if f.in_sys() => LX_PSEUDO_DEV_SYS,
        _ => LX_PSEUDO_DEV_PROC,
    };
    let st = Stat { dev, ino: path::ino_of(obj, tail), mode, size };
    let r = if x { cx.copy_out(out, &st.statx()) } else { cx.copy_out(out, &st.stat()) };
    Some(r.err().unwrap_or(0))
}

/// The fields of a pseudo file's `stat`.
struct Stat {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
}

impl Stat {
    /// `struct stat` (x86-64, 144 bytes).
    fn stat(&self) -> [u8; 144] {
        let mut b = [0u8; 144];
        b[0..8].copy_from_slice(&self.dev.to_le_bytes());
        b[8..16].copy_from_slice(&self.ino.to_le_bytes());
        b[16..24].copy_from_slice(&1u64.to_le_bytes());
        b[24..28].copy_from_slice(&self.mode.to_le_bytes());
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..64].copy_from_slice(&4096u64.to_le_bytes());
        b
    }

    /// `struct statx` (256 bytes), as the kernel's `write_statx` fills it.
    fn statx(&self) -> [u8; 256] {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(&0x17FFu32.to_le_bytes());
        b[4..8].copy_from_slice(&4096u32.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
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
    let pid = match who {
        Who::Caller => 0,
        Who::Pid(p) => p,
    };
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

/// A buffer answer of an info primitive taking `(id, pid | len << 32, buf)`: grows the
/// buffer until the answer fits (`fit`: the answer only needs what was written).
fn buffer(op: u64, id: u64, pid: u64) -> Result<Vec<u8>, i64> {
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

/// The text of `file` for the caller of request `id`.
fn make(id: u64, file: File, tail: &[u8]) -> Result<Vec<u8>, i64> {
    Ok(match file {
        File::Efivar => {
            // (the attributes and the data, as efivarfs shows them)
            let name = tail.rsplit(|&b| b == b'/').find(|c| !c.is_empty()).unwrap_or(b"");
            let mut cap = 1024usize;
            loop {
                let mut v = alloc::vec![0u8; cap];
                let n = sys::lx_obj(LX_INFO_EFIVAR, name.as_ptr() as u64, name.len() as u64 | (cap as u64) << 32, v.as_mut_ptr() as u64)? as usize;
                if n <= cap {
                    v.truncate(n);
                    break v;
                }
                if n > 1 << 20 {
                    return Err(EINVAL);
                }
                cap = n;
            }
        }
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
        File::Cpuinfo => text::cpuinfo(sysinfo(0)?.ncpu.max(1)),
        File::CpuRange => text::cpu_range(sysinfo(0)?.ncpu.max(1)),
        File::Pid { who, tid, file } => match file {
            PidFile::Stat => text::stat(&task(id, who, tid)?),
            PidFile::Status => text::status(&task(id, who, tid)?),
            PidFile::Statm => text::statm(&task(id, who, tid)?),
            PidFile::Comm => text::comm_file(&task(id, who, tid | LX_INFO_TASK_NOMEM >> 32)?),
            PidFile::Cmdline => buffer(LX_INFO_ARGS, id, pid_word(who))?,
            PidFile::Maps => text::maps(&buffer(LX_INFO_MAPS, id, pid_word(who))?),
        },
    })
}

fn pid_word(who: Who) -> u64 {
    match who {
        Who::Caller => 0,
        Who::Pid(p) => p,
    }
}

/// `open`/`openat` of a served file, read-only: a pseudo-file object with its text.
fn open(cx: &Cx, obj: u64, tail: &[u8], target: Target) -> Option<i64> {
    let Target::File(mut file) = target else { return None };
    let flags = if cx.nr == 2 { cx.args[1] } else { cx.args[2] };
    if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC | O_DIRECTORY | O_PATH | O_TMPFILE) != 0 {
        return None;
    }
    // Errors (no such process, maps of another user's process) are the kernel's to answer
    let text = make(cx.id, file, tail).ok()?;
    // The process by its system-wide ID from now on (reads may come from another process)
    let mut shown = alloc::string::String::from(if file.in_sys() { "/sys/" } else { "/proc/" });
    shown.push_str(&alloc::string::String::from_utf8_lossy(tail));
    if let File::Pid { who: Who::Caller, tid, file: f } = file {
        file = File::Pid { who: Who::Pid(cx.c.tgid), tid, file: f };
        if let Some(rest) = shown.strip_prefix("/proc/self/").or_else(|| shown.strip_prefix("/proc/thread-self/")) {
            shown = alloc::format!("/proc/{}/{}", cx.c.tgid, rest);
        }
    }
    let slot = crate::obj::alloc(LX_OBJ_KIND_PSEUDO).ok()?;
    let size = text.len() as u64;
    OPENS.lock().insert(slot, Open { file, tail: tail.to_vec(), text, pos: 0 });
    crate::obj::set_ready(slot, READY, size.max(GEN_SIZE));
    let dev = if file.in_sys() { LX_PSEUDO_DEV_SYS } else { LX_PSEUDO_DEV_PROC };
    let mut d = LxObjDesc {
        slot,
        kind: LX_OBJ_KIND_PSEUDO,
        flags: (flags & (O_NONBLOCK | O_CLOEXEC)) as u32,
        mode: S_IFREG | if file == File::Efivar { 0o644 } else { 0o444 },
        uid: 0,
        gid: 0,
        name_len: 0,
        pad: 0,
        name: [0; LX_OBJ_NAME_MAX],
        tag: path::ino_of(obj, tail),
        key: dev,
    };
    let n = shown.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&shown.as_bytes()[..n]);
    d.name_len = n as u32;
    match sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0) {
        Ok(fd) => Some(fd as i64),
        Err(e) => {
            OPENS.lock().remove(&slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            Some(e)
        }
    }
}

/// Copies the text of `slot` from `at` into the caller's pieces `iov` (at most `max`);
/// remakes the text first when `at` is 0 and `fresh`.
fn read_at(cx: &Cx, slot: u32, at: u64, iov: &crate::fdio::Iov, fresh: bool) -> i64 {
    if fresh && at == 0 {
        let (file, tail) = match OPENS.lock().get(&slot) {
            Some(o) => (o.file, o.tail.clone()),
            None => return EBADF,
        };
        if let Ok(t) = make(cx.id, file, &tail) {
            if let Some(o) = OPENS.lock().get_mut(&slot) {
                o.text = t;
            }
        }
    }
    let chunk: Vec<u8> = {
        let g = OPENS.lock();
        let Some(o) = g.get(&slot) else { return EBADF };
        let start = (at as usize).min(o.text.len());
        let end = start.saturating_add(iov.total()).min(o.text.len());
        o.text[start..end].to_vec()
    };
    match iov.scatter(cx, &chunk) {
        Ok(()) => chunk.len() as i64,
        Err(e) => e,
    }
}

/// A call on a pseudo-file object: `read`, `readv`, the kernel's `lseek` and `pread64`.
pub fn io(cx: &Cx) -> (i64, u64) {
    let slot = cx.c.obj as u32;
    let r = match cx.nr {
        0 | 19 => {
            let iov = match crate::fdio::Iov::of_call(cx) {
                Ok(v) => v,
                Err(e) => return (e, 0),
            };
            let pos = match OPENS.lock().get(&slot) {
                Some(o) => o.pos,
                None => return (EBADF, 0),
            };
            let n = read_at(cx, slot, pos, &iov, false);
            if n > 0 {
                if let Some(o) = OPENS.lock().get_mut(&slot) {
                    o.pos += n as u64;
                }
            }
            n
        }
        LX_KCALL_PREAD => read_at(cx, slot, cx.args[3], &crate::fdio::Iov::one(cx.args[1], cx.args[2]), true),
        LX_KCALL_PSEEK => {
            let (off, whence) = (cx.args[3] as i64, cx.args[4]);
            let new = {
                let g = OPENS.lock();
                let Some(o) = g.get(&slot) else { return (EBADF, 0) };
                match whence {
                    0 => off,
                    1 => (o.pos as i64).checked_add(off).unwrap_or(-1),
                    2 => (o.text.len() as i64).checked_add(off).unwrap_or(-1),
                    _ => -1,
                }
            };
            if new < 0 {
                EINVAL
            } else {
                if new == 0 {
                    // (a rewind reads fresh text, as seq_file does)
                    let file = OPENS.lock().get(&slot).map(|o| (o.file, o.tail.clone()));
                    if let Some(Ok(t)) = file.map(|(f, tail)| make(cx.id, f, &tail)) {
                        if let Some(o) = OPENS.lock().get_mut(&slot) {
                            o.text = t;
                        }
                    }
                }
                match OPENS.lock().get_mut(&slot) {
                    Some(o) => {
                        o.pos = new as u64;
                        new
                    }
                    None => EBADF,
                }
            }
        }
        1 | 20 => EBADF,
        16 => ENOTTY,
        LX_KCALL_REOPEN => ENXIO,
        _ => EINVAL,
    };
    (r, 0)
}

/// The last descriptor of pseudo file `slot` went away.
pub fn closed(slot: u32) {
    OPENS.lock().remove(&slot);
}
