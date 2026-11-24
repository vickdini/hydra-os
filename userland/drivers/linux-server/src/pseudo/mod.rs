//! # Pseudo file systems: `/sys` served by linux-server (wave 7, Group 7-4)
//!
//! The file service (vfs-server) answers a path call whose walk ends under `/sys` with a
//! redirect here (`docs/vfs-design.md` section 5): the same call arrives with
//! `LxCall::svc` = `LXS_LINUX`, `redir_obj` = the mount's object (`LX_VFS_PSEUDO_SYS`) and
//! `redir_tail` = where the part below the mount starts in the path argument.
//!
//! wave10 G7b-2: `/proc` moved to lx-proc (`lx-proc/src/procfs/`, with kernel-held
//! snapshots of open files). What stays here is the `/sys` part:
//!
//! - [`sys::classify`] decides what the tail names: the CPU range files and efivarfs
//!   variables; everything else goes on to the kernel (the redirect to service 0).
//! - `stat`/`lstat`/`newfstatat`/`statx` and `access`/`faccessat`/`faccessat2` of the CPU
//!   range files, and read-only `open`/`openat` of both, are served (an efivarfs file
//!   exists in the pool too: its stat and access are the kernel's).
//! - An open file is a server object of kind `LX_OBJ_KIND_PSEUDO` whose text is made at
//!   open (`LX_INFO_SYS`, `LX_INFO_EFIVAR`); `read`/`readv` come here as for any server
//!   object, `lseek` and `pread64` as the kernel's calls `LX_KCALL_PSEEK`/`LX_KCALL_PREAD`. A
//!   seek to 0 or a `pread` at 0 makes the text again.
//! - Callers in a PID or user namespace of their own go to the kernel.
//!
//! `pseudo=0` among the program's arguments sends every redirected call to the kernel.

pub mod sys;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer};

use crate::client::Cx;
use crate::lock::YLock;
use sys::File;

const ENXIO: i64 = -6;
const EBADF: i64 = -9;
const ENOTTY: i64 = -25;
const EINVAL: i64 = -22;

const S_IFREG: u32 = 0o100000;
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
    /// What it is.
    file: File,
    /// The path below the mount (an efivars file's name).
    tail: Vec<u8>,
    /// The text as made at open (or at the last rewind).
    text: Vec<u8>,
    /// The position of `read`.
    pos: u64,
    /// This open's number (a slot freed and taken again meanwhile is not this open).
    seq: u64,
}

/// The next [`Open::seq`].
static SEQ: AtomicU64 = AtomicU64::new(1);

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
        hydra_rt::println!("[linux-server] pseudo: {} /sys calls served, {} sent to the kernel", n, TO_KERNEL.load(Ordering::Relaxed));
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
    let Some(file) = sys::classify(obj, tail) else { return kernel(cx) };
    // (an efivars file exists in the pool too: its stat and access are the kernel's; only
    // a read-only open is served here)
    let r = match (cx.nr, file) {
        (4 | 6 | 262 | 332, File::CpuRange) => stat(cx, obj, tail),
        (21 | 269 | 439, File::CpuRange) => Some(access(cx)),
        (2 | 257, _) => open(cx, obj, tail, file),
        _ => None,
    };
    match r {
        Some(v) => done(v),
        None => kernel(cx),
    }
}

/// The `stat` family of a CPU range file: a read-only regular file of root's.
fn stat(cx: &Cx, obj: u64, tail: &[u8]) -> Option<i64> {
    let a = cx.args;
    let (out, x) = match cx.nr {
        4 | 6 => (a[1], false),
        262 => (a[2], false),
        _ => (a[4], true),
    };
    let (dev, ino, mode, size) = (LX_PSEUDO_DEV_SYS, sys::ino_of(obj, tail), S_IFREG | 0o444, GEN_SIZE);
    let r = if x {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(&0x17FFu32.to_le_bytes());
        b[4..8].copy_from_slice(&4096u32.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
        b[32..40].copy_from_slice(&ino.to_le_bytes());
        b[40..48].copy_from_slice(&size.to_le_bytes());
        b[136..140].copy_from_slice(&(((dev >> 8) & 0xFFF) as u32).to_le_bytes());
        b[140..144].copy_from_slice(&((dev & 0xFF) as u32).to_le_bytes());
        b[144..152].copy_from_slice(&(20 + (dev & 0xFFFF)).to_le_bytes());
        cx.copy_out(out, &b)
    } else {
        let mut b = [0u8; 144];
        b[0..8].copy_from_slice(&dev.to_le_bytes());
        b[8..16].copy_from_slice(&ino.to_le_bytes());
        b[16..24].copy_from_slice(&1u64.to_le_bytes());
        b[24..28].copy_from_slice(&mode.to_le_bytes());
        b[48..56].copy_from_slice(&size.to_le_bytes());
        b[56..64].copy_from_slice(&4096u64.to_le_bytes());
        cx.copy_out(out, &b)
    };
    Some(r.err().unwrap_or(0))
}

/// `access`, `faccessat`, `faccessat2` of a CPU range file (mode 0444): bits beyond
/// `R_OK | W_OK | X_OK` and `faccessat2` flags beyond `AT_SYMLINK_NOFOLLOW | AT_EACCESS |
/// AT_EMPTY_PATH` are `EINVAL`; writing is root's only; executing is never allowed.
fn access(cx: &Cx) -> i64 {
    const EACCES: i64 = -13;
    let a = cx.args;
    let (mode, flags) = match cx.nr {
        21 => (a[1], 0),
        269 => (a[2], 0),
        _ => (a[2], a[3]),
    };
    let uid = if flags & 0x200 != 0 { cx.c.euid } else { cx.c.uid };
    if mode & !7 != 0 || flags & !(0x100 | 0x200 | 0x1000) != 0 {
        return EINVAL;
    }
    if (mode & 2 != 0 && uid != 0) || mode & 1 != 0 {
        return EACCES;
    }
    0
}

/// The text of `file`.
fn make(file: File, tail: &[u8]) -> Result<Vec<u8>, i64> {
    Ok(match file {
        File::Efivar => {
            // (the attributes and the data, as efivarfs shows them)
            let name = tail.rsplit(|&b| b == b'/').find(|c| !c.is_empty()).unwrap_or(b"");
            let mut cap = 1024usize;
            loop {
                let mut v = alloc::vec![0u8; cap];
                let n = hydra_rt::sys::lx_obj(LX_INFO_EFIVAR, name.as_ptr() as u64, name.len() as u64 | (cap as u64) << 32, v.as_mut_ptr() as u64)? as usize;
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
        File::CpuRange => {
            let mut s = LxSysInfo::default();
            hydra_rt::sys::lx_obj(LX_INFO_SYS, &mut s as *mut LxSysInfo as u64, 0, 0)?;
            sys::cpu_range(s.ncpu.max(1))
        }
    })
}

/// `open`/`openat` of a served file, read-only: a pseudo-file object with its text.
fn open(cx: &Cx, obj: u64, tail: &[u8], file: File) -> Option<i64> {
    let flags = if cx.nr == 2 { cx.args[1] } else { cx.args[2] };
    if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC | O_DIRECTORY | O_PATH | O_TMPFILE) != 0 {
        return None;
    }
    // (errors: the kernel answers)
    let text = make(file, tail).ok()?;
    let mut shown = alloc::string::String::from("/sys/");
    shown.push_str(&alloc::string::String::from_utf8_lossy(tail));
    let slot = crate::obj::alloc(LX_OBJ_KIND_PSEUDO).ok()?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    OPENS.lock().insert(slot, Open { file, tail: tail.to_vec(), text, pos: 0, seq });
    crate::obj::set_ready(slot, READY, GEN_SIZE);
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
        tag: sys::ino_of(obj, tail),
        key: LX_PSEUDO_DEV_SYS,
    };
    let n = shown.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&shown.as_bytes()[..n]);
    d.name_len = n as u32;
    match hydra_rt::sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0) {
        Ok(fd) => Some(fd as i64),
        Err(e) => {
            OPENS.lock().remove(&slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            Some(e)
        }
    }
}

/// The text of open file `slot` made again (a rewind, a `pread` at 0), with the open's
/// number. Nothing is kept on failure.
fn remake(slot: u32) -> Result<(Vec<u8>, u64), i64> {
    let (file, tail, seq) = match OPENS.lock().get(&slot) {
        Some(o) => (o.file, o.tail.clone(), o.seq),
        None => return Err(EBADF),
    };
    Ok((make(file, &tail)?, seq))
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
            // The piece and the new position under one lock (concurrent reads of one open
            // file never get the same bytes); given back if the copy to the caller fails
            let (chunk, at, seq) = {
                let mut g = OPENS.lock();
                let Some(o) = g.get_mut(&slot) else { return (EBADF, 0) };
                let start = (o.pos.min(usize::MAX as u64) as usize).min(o.text.len());
                let end = start.saturating_add(iov.total()).min(o.text.len());
                let chunk = o.text[start..end].to_vec();
                let at = o.pos;
                o.pos += chunk.len() as u64;
                (chunk, at, o.seq)
            };
            match iov.scatter(cx, &chunk) {
                Ok(()) => chunk.len() as i64,
                Err(e) => {
                    if let Some(o) = OPENS.lock().get_mut(&slot).filter(|o| o.seq == seq && o.pos == at + chunk.len() as u64) {
                        o.pos = at;
                    }
                    e
                }
            }
        }
        LX_KCALL_PREAD => {
            let (at, iov) = (cx.args[3], crate::fdio::Iov::one(cx.args[1], cx.args[2]));
            // (at 0: fresh text for this read only; the open's own text and position stay)
            let chunk = if at == 0 {
                match remake(slot) {
                    Ok((t, _)) => t[..t.len().min(iov.total())].to_vec(),
                    Err(e) => return (e, 0),
                }
            } else {
                let g = OPENS.lock();
                let Some(o) = g.get(&slot) else { return (EBADF, 0) };
                let start = (at.min(usize::MAX as u64) as usize).min(o.text.len());
                let end = start.saturating_add(iov.total()).min(o.text.len());
                o.text[start..end].to_vec()
            };
            match iov.scatter(cx, &chunk) {
                Ok(()) => chunk.len() as i64,
                Err(e) => e,
            }
        }
        LX_KCALL_PSEEK => {
            let (off, whence) = (cx.args[3] as i64, cx.args[4]);
            // A rewind reads fresh text: made first, then text and position set together
            let fresh = if whence == 0 && off == 0 {
                match remake(slot) {
                    Ok(t) => Some(t),
                    Err(e) => return (e, 0),
                }
            } else {
                None
            };
            let mut g = OPENS.lock();
            let Some(o) = g.get_mut(&slot) else { return (EBADF, 0) };
            let new = match whence {
                0 => off,
                1 => (o.pos as i64).checked_add(off).unwrap_or(-1),
                2 => (o.text.len() as i64).checked_add(off).unwrap_or(-1),
                _ => -1,
            };
            if new < 0 {
                EINVAL
            } else {
                if let Some((t, seq)) = fresh {
                    if seq == o.seq {
                        o.text = t;
                    }
                }
                o.pos = new as u64;
                new
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
