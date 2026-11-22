//! signalfd (`signalfd`, `signalfd4`), moved here from the kernel's
//! `src/compat/linux/signalfd.rs` (wave 5, step 4).
//!
//! A descriptor that receives signals as data: reading it takes pending signals of its
//! mask (normally blocked with `sigprocmask`) from the reader's thread or process with the
//! kernel's `sig_take` (`SYS_LX_SIGTAKE`), one 128-byte `struct signalfd_siginfo` each. The
//! kernel answers `poll`/`select`/`epoll` on it itself, from the process's pending signals
//! (`LX_OBJ_SIGMASK` tells it the mask), since posting a signal wakes the process's waits.
//! A blocking read with nothing pending answers "pending"; the main thread looks for the
//! signals again at every tick (and a signal the reader may take interrupts it as usual).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::fdio::kbuf;
use crate::lock::YLock;

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ERESTARTSYS: i64 = -512;

const SFD_NONBLOCK: u64 = 0o4000;
const SFD_CLOEXEC: u64 = 0o2000000;
const SIGINFO: usize = 128;
/// SIGKILL and SIGSTOP cannot be received through a signalfd.
const NEVER: u64 = (1 << 8) | (1 << 18);

/// A reader waiting (its call is pending).
struct Reader {
    c: LxCall,
    slot: u32,
    buf: u64,
    len: usize,
}

struct Sfd {
    masks: BTreeMap<u32, u64>,
    readers: Vec<Reader>,
}

static S: YLock<Sfd> = YLock::new(Sfd { masks: BTreeMap::new(), readers: Vec::new() });

fn read_mask(cx: &Cx) -> Result<u64, i64> {
    if cx.args[2] != 8 {
        return Err(EINVAL);
    }
    let raw = cx.copy_in(cx.args[1], 8)?;
    Ok(u64::from_le_bytes(raw[..8].try_into().unwrap()) & !NEVER)
}

/// `signalfd(fd, mask, size)` (282) and `signalfd4(fd, mask, size, flags)` (289): a new
/// signalfd (`fd` -1) or a new mask for one.
pub fn signalfd(cx: &Cx) -> (i64, u64) {
    let flags = if cx.nr == 289 { cx.args[3] } else { 0 };
    if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return (EINVAL, 0);
    }
    let mask = match read_mask(cx) {
        Ok(m) => m,
        Err(e) => return (e, 0),
    };
    let fd = cx.args[0] as i32;
    if fd >= 0 {
        if cx.c.obj == LX_OBJ_NONE || crate::obj::kind_of(cx.c.obj as u32) != LX_OBJ_KIND_SIGNALFD {
            return (EINVAL, 0);
        }
        let slot = cx.c.obj as u32;
        S.lock().masks.insert(slot, mask);
        let _ = sys::lx_obj(LX_OBJ_SIGMASK, slot as u64, mask, 0);
        return (fd as i64, 0);
    }
    if fd != -1 {
        return (EBADF, 0);
    }
    let slot = match crate::obj::alloc(LX_OBJ_KIND_SIGNALFD) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    S.lock().masks.insert(slot, mask);
    match crate::obj::install_tag(cx, slot, LX_OBJ_KIND_SIGNALFD, (flags & (SFD_NONBLOCK | SFD_CLOEXEC)) as u32, 0o600, cx.c.euid, cx.c.egid, b"anon_inode:[signalfd]", cx.c.tgid) {
        Ok(fd) => {
            let _ = sys::lx_obj(LX_OBJ_SIGMASK, slot as u64, mask, 0);
            (fd, 0)
        }
        Err(e) => {
            S.lock().masks.remove(&slot);
            crate::obj::free(slot);
            (e, 0)
        }
    }
}

/// Takes pending signals of `mask` for request `id`'s caller into records, as many as fit.
fn take(id: u64, mask: u64, len: usize) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    while out.len() + SIGINFO <= len {
        let mut rec = [0u8; SIGINFO];
        let n = sys::lx_sigtake(id, mask, rec.as_mut_ptr() as u64, 0);
        if n < 0 {
            if out.is_empty() {
                return Err(n);
            }
            break;
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&rec);
    }
    Ok(out)
}

/// `read` on a signalfd (slot `cx.c.obj`).
pub fn io(cx: &Cx) -> (i64, u64) {
    if cx.nr != 0 {
        return (EINVAL, 0);
    }
    let slot = cx.c.obj as u32;
    let len = cx.args[2] as usize;
    if len < SIGINFO {
        return (EINVAL, 0);
    }
    let Some(mask) = S.lock().masks.get(&slot).copied() else { return (EBADF, 0) };
    match take(cx.id, mask, len) {
        Err(e) => (e, 0),
        Ok(recs) if !recs.is_empty() => match cx.copy_out(cx.args[1], &recs) {
            Ok(()) => (recs.len() as i64, 0),
            Err(e) => (if e == 0 { EFAULT } else { e }, 0),
        },
        Ok(_) if cx.nonblock() || kbuf(cx) => (EAGAIN, 0),
        Ok(_) => {
            S.lock().readers.push(Reader { c: cx.c, slot, buf: cx.args[1], len });
            crate::timeout::kick();
            (0, LX_REPLY_PENDING)
        }
    }
}

/// The main thread, at every tick while readers wait: hands them signals that came.
/// Returns the next time to look (`Some(now + 1)` while readers wait).
pub fn tick(now: u64) -> Option<u64> {
    let mut done = Vec::new();
    {
        let mut s = S.lock();
        if s.readers.is_empty() {
            return None;
        }
        let masks = s.masks.clone();
        s.readers.retain(|r| {
            let Some(&mask) = masks.get(&r.slot) else {
                done.push((r.c.id, EBADF));
                return false;
            };
            match take(r.c.id, mask, r.len) {
                Ok(recs) if recs.is_empty() => true,
                Ok(recs) => {
                    let res = match sys::lx_write(r.c.id, r.buf, &recs) {
                        Ok(()) => recs.len() as i64,
                        Err(e) => e,
                    };
                    done.push((r.c.id, res));
                    false
                }
                Err(e) => {
                    done.push((r.c.id, e));
                    false
                }
            }
        });
    }
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
    if S.lock().readers.is_empty() {
        None
    } else {
        Some(now + 1)
    }
}

/// A signal for the caller of pending call `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    let found = {
        let mut s = S.lock();
        let n = s.readers.len();
        s.readers.retain(|r| r.c.id != id);
        s.readers.len() != n
    };
    if found {
        let _ = sys::lx_complete(id, ERESTARTSYS);
    }
    found
}

/// Process `tgid` ended: its waiting calls are gone.
pub fn on_exit(tgid: u64) {
    S.lock().readers.retain(|r| r.c.tgid != tgid);
}

/// The last descriptor of signalfd `slot` went away.
pub fn closed(slot: u32) {
    S.lock().masks.remove(&slot);
}
