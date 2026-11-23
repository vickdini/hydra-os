//! pidfd (`pidfd_open`, `clone(CLONE_PIDFD)`, `SO_PEERPIDFD`), moved here from the
//! kernel's `src/compat/linux/pidfd.rs` (wave 5, step 4).
//!
//! A pidfd names a process; it is readable once the process has exited (the kernel's
//! `LX_NOTE_EXIT`). The kernel reads the process back from the descriptor
//! (`LxObjDesc::tag`) for the calls that act on it and stay in the kernel:
//! `pidfd_send_signal`, `pidfd_getfd`, `waitid(P_PIDFD)`, `setns`, `process_madvise`.

use alloc::collections::BTreeMap;

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;

const ESRCH: i64 = -3;
const EINVAL: i64 = -22;

const PIDFD_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u32 = 0o2000000;

/// wave9 GX3: a pidfd's kernel object carries its process in its key (no record): this
/// tag | the pid.
pub const KEY_TAG: u64 = 1 << 40;

/// Slot -> (process, exited).
static PIDFDS: YLock<BTreeMap<u32, (u64, bool)>> = YLock::new(BTreeMap::new());

/// Whether process `pid` exists (`Some(exited)`), from the kernel.
fn state(pid: u64) -> Option<bool> {
    match sys::lx_obj(LX_OBJ_PROC, pid, 0, 0) {
        Ok(1) => Some(false),
        Ok(2) => Some(true),
        _ => None,
    }
}

/// A new pidfd for process `pid` in the caller's table (always close-on-exec, as Linux).
pub fn open_for(cx: &Cx, pid: u64, flags: u64) -> i64 {
    if state(pid).is_none() {
        return ESRCH;
    }
    let slot = match crate::obj::alloc(LX_OBJ_KIND_PIDFD) {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Listed before the process's state is read: an exit from now on finds the pidfd
    // ([`on_exit`]), an earlier one shows in the state. (Reading the state first lost the
    // exit of a process that ended in between: its pidfd never became readable, and a
    // GLib child watch on it waited for ever.)
    PIDFDS.lock().insert(slot, (pid, false));
    // (gone meanwhile: reaped, so it exited)
    let exited = state(pid).unwrap_or(true);
    {
        let mut m = PIDFDS.lock();
        if let Some(e) = m.get_mut(&slot) {
            e.1 |= exited;
            // Under the lock, as `on_exit` publishes: the word ends up as the flag says
            crate::obj::set_ready(slot, if e.1 { 0x41 } else { 0 }, 0);
        }
    }
    let f = O_CLOEXEC | (flags & PIDFD_NONBLOCK) as u32;
    let key = if crate::kstore::active() { KEY_TAG | pid } else { 0 };
    match crate::obj::install_keyed(cx, slot, LX_OBJ_KIND_PIDFD, f, 0o600, cx.c.euid, cx.c.egid, b"anon_inode:[pidfd]", pid, key) {
        Ok(fd) => fd,
        Err(e) => {
            PIDFDS.lock().remove(&slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            e
        }
    }
}

/// `pidfd_open(pid, flags)` (434) and the kernel's `LX_KCALL_PIDFD(pid, flags)`.
pub fn open(cx: &Cx) -> (i64, u64) {
    let (pid, flags) = (cx.args[0], cx.args[1]);
    if flags & !PIDFD_NONBLOCK != 0 || pid as i64 <= 0 {
        return (EINVAL, 0);
    }
    (open_for(cx, pid, flags), 0)
}

/// Process `tgid` ended: its pidfds become readable.
pub fn on_exit(tgid: u64) {
    let mut m = PIDFDS.lock();
    for (&slot, e) in m.iter_mut() {
        if e.0 == tgid {
            e.1 = true;
            crate::obj::set_ready_ev(slot, 0x41, 0, true);
        }
    }
}

/// The last descriptor of pidfd `slot` went away.
pub fn closed(slot: u32) {
    PIDFDS.lock().remove(&slot);
}

/// wave9 GX3: a restarted lx-ipc takes pidfd `slot` (key `key`) back; whether the process
/// ended meanwhile is asked from the kernel (its exit note went with the old instance).
#[allow(dead_code)] // (linux-server never restores)
pub fn restore(slot: u32, key: u64) -> bool {
    if key & !(KEY_TAG - 1) != KEY_TAG || !crate::obj::reserve(slot, LX_OBJ_KIND_PIDFD) {
        return false;
    }
    let pid = key & (KEY_TAG - 1);
    let mut m = PIDFDS.lock();
    m.insert(slot, (pid, false));
    let exited = state(pid).unwrap_or(true);
    m.insert(slot, (pid, exited));
    crate::obj::set_ready(slot, if exited { 0x41 } else { 0 }, 0);
    true
}
