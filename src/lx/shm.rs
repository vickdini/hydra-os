//! # System V shared memory in lx-ipc: the kernel's half (wave 10, Group 8-2)
//!
//! lx-ipc keeps the segments (`shmget`, `shmctl`: ids, keys, IPC namespaces, owners and
//! modes, `shm_ctime`, `IPC_RMID`) and the memory of each one: a kept memory object of its
//! own (`lx_shm_key(id)`), so the pages outlive an lx-ipc restart. The kernel keeps what
//! only it sees: the **attachments** ([`super::shm_table`]), because it maps and unmaps them
//! and `fork`, `execve` and exit change them, with what they decide (`shm_nattch`,
//! `shm_atime`, `shm_dtime`, `shm_lpid`).
//!
//! - **`shmat`** is routed to lx-ipc like any forwarded call (the lock-free path): lx-ipc
//!   checks permission and namespace and answers with a redirect to `LX_REDIR_SHM` naming
//!   the segment's kept object ([`answer`]: only lx-ipc's host may, and only for a segment
//!   key). The kernel takes the object out of the kept registry at once and maps it into the
//!   caller right there when it can ([`map`]: no address asked for and the address space's
//!   lock free: the usual case); otherwise it keeps the object for this thread and the call
//!   goes on to the kernel's own code ([`forward_kept`], then `compat/linux/sysv.rs` ->
//!   [`shmat`]). The mapping is as the in-kernel copy's (shared; `SHM_RND`, `SHM_REMAP`,
//!   `SHM_RDONLY` with no later `mprotect` to writable, `SHM_EXEC`).
//! - The attachment is counted before the mapping is made, and only while the segment's
//!   object is still in the kept registry (checked under the table's lock): lx-ipc lets a
//!   segment go by unkeeping its object first and telling the kernel (`LX_SHM_FORGET`)
//!   after, so a segment it let go is never counted again.
//! - **`shmdt`** ([`shmdt`]) runs here alone, and unmaps only a mapping that still is the
//!   segment; `munmap`, `mremap` and `MAP_FIXED` over an attachment drop it when nothing of
//!   the segment stays mapped in its range ([`after_unmap`], as Linux's `shm_close`; a
//!   mapping `mremap` moved elsewhere counts as gone);
//!   exits and `execve` ([`forget`]) and `fork` ([`on_fork`]) too. lx-ipc hears only of the
//!   last attachment of a removed segment ([`LX_NOTE_SHM`]: it then lets the segment go; it
//!   also looks again now and then, in case a note was lost).
//! - lx-ipc asks with `SYS_LX_OBJ` op [`LX_OBJ_SHM`](crate::ipc::protocol::LX_OBJ_SHM)
//!   ([`ctl`], lx-ipc's host only): the counts and times (`IPC_STAT`, `/proc/sysvipc/shm`),
//!   `IPC_RMID`, a gone segment, a fresh start.
//!
//! `shmget` and `shmctl` are ordinary forwarded calls. With `lx=kernel` or `lx.ipc=kernel`
//! none of this runs: `compat/linux/sysv.rs` (the in-kernel copy, until 10-C) answers all
//! four calls.
//!
//! A segment removed while an attach is between lx-ipc's answer and the counting goes at
//! once; the attach then fails with `EIDRM` (as if the removal had come first).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;

use super::shm_table::{Note, Table};
use super::svc::Host;
use crate::ipc::protocol::{
    lx_shm_key, LxCall, LxShmStat, LXS_IPC, LX_NOTE_SHM, LX_SHM_FORGET, LX_SHM_IPCNS, LX_SHM_NATTCH, LX_SHM_RESET, LX_SHM_RMID, LX_SHM_STAT, NOTIFY_LX_NOTES,
};
use crate::memory::vm::{Backing, MappedObject, MemObject, Mm};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EIDRM: i64 = -43;
const ENOSYS: i64 = -38;
/// Internal: the mapping could not be made without waiting (the ordinary path makes it).
const LATER: i64 = i64::MIN;

const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;

static TABLE: Mutex<Table> = Mutex::new(Table::new());

fn table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TABLE.lock()))
}

/// Seconds since 1970 (`shm_atime`, `shm_dtime`).
fn now() -> i64 {
    crate::arch::rtc::now().0 as i64
}

/// Whether the System V shared memory calls go to the IPC service now (they are routed
/// with `shmget`'s entry: `lx=kernel` and `lx.ipc=kernel` leave it empty).
pub fn active() -> bool {
    super::entry(29) & super::T_SERVER != 0
}

/// Whether `key` is a segment's kept-object key ([`lx_shm_key`]).
fn is_segment_key(key: u64) -> bool {
    key >> 32 == lx_shm_key(0) >> 32
}

/// The identity of a segment's object as attachments record it.
fn obj_id(obj: &Arc<MemObject>) -> usize {
    Arc::as_ptr(obj) as *const u8 as usize
}

/// Whether a mapping of `m` backed by the object `obj` (an [`obj_id`]) lies in
/// `[start, end)`; `exact`: one that starts at `start`.
fn maps_obj(m: &Mm, obj: usize, start: u64, end: u64, exact: bool) -> bool {
    m.vmas().any(|v| {
        (if exact { v.start == start } else { v.start < end && v.end > start })
            && matches!(&v.backing, Backing::Object { obj: o, .. } if Arc::as_ptr(o) as *const u8 as usize == obj)
    })
}

// ----------------------------------------------------------------------
// lx-ipc's answers to shmat
// ----------------------------------------------------------------------

/// An answer kept for the thread's kernel half: the thread, the call's arguments, the
/// segment's object and key, and when.
struct Kept {
    tid: u64,
    args: [u64; 3],
    obj: Option<Arc<MemObject>>,
    key: u64,
    tick: u64,
}

const NKEPT: usize = 64;
const KEPT_FREE: Kept = Kept { tid: 0, args: [0; 3], obj: None, key: 0, tick: 0 };
static KEPT: Mutex<[Kept; NKEPT]> = Mutex::new([KEPT_FREE; NKEPT]);

fn kept<R>(f: impl FnOnce(&mut [Kept; NKEPT]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut KEPT.lock()))
}

/// lx-ipc answered `shmat` call `c` of host `x` with a redirect to
/// [`LX_REDIR_SHM`](crate::ipc::protocol::LX_REDIR_SHM) (`redir.1` = the segment's kept
/// object key): the object is mapped now when that needs no wait (the result is the
/// address), else kept for the calling thread and the call goes on to the kernel
/// (`LX_TO_KERNEL`). Only the IPC service's host may answer so, and only with a segment's
/// key. Runs on the lock-free path too: nothing here waits for a lock.
pub(super) fn answer(x: &Host, c: &LxCall, redir: (u64, u64)) -> i64 {
    let key = redir.1;
    if c.nr != 30 || x.id != super::svc::host_of(LXS_IPC) || !is_segment_key(key) {
        return EIO;
    }
    let ep = x.endpoint.load(Ordering::Acquire);
    let Some(obj) = super::mem::kept_of_endpoint(ep, key) else { return EIDRM };
    let (id, addr, flags) = (c.args[0] as i32, c.args[1], c.args[2]);
    // (a fixed address may replace mappings, whose pages need a TLB flush: the ordinary path)
    if addr == 0 {
        let r = map(&obj, ep, key, id, 0, flags, c.tgid, false);
        if r != LATER {
            return r;
        }
    }
    let now = crate::arch::pit::ticks();
    let old = kept(|k| {
        // this thread's old entry (a call that never reached the kernel half), else a free
        // slot, else the oldest
        let i = k.iter().position(|e| e.tid == c.tid).or_else(|| k.iter().position(|e| e.tid == 0)).unwrap_or_else(|| (0..NKEPT).min_by_key(|&i| k[i].tick).unwrap_or(0));
        let old = k[i].obj.take();
        k[i] = Kept { tid: c.tid, args: [c.args[0], c.args[1], c.args[2]], obj: Some(obj), key, tick: now };
        old
    });
    // (an old entry's object is still in its segment's kept registry entry or mapped, unless
    // the segment went: then its frames go, which needs no kernel lock)
    drop(old);
    super::fileh::LX_TO_KERNEL
}

/// Whether the calling thread has an answer kept: `forward` then leaves the call to the
/// kernel (lx-ipc already answered it).
pub fn forward_kept() -> bool {
    let tid = crate::task::CURRENT_TID.load(Ordering::Relaxed);
    tid != 0 && kept(|k| k.iter().any(|e| e.tid == tid))
}

/// The answer kept for thread `tid`'s call with `args`: the object and its key.
fn take(tid: u64, args: [u64; 3]) -> Option<(Arc<MemObject>, u64)> {
    let e = kept(|k| {
        let i = k.iter().position(|e| e.tid == tid)?;
        Some(core::mem::replace(&mut k[i], KEPT_FREE))
    })?;
    if e.args != args {
        return None;
    }
    Some((e.obj?, e.key))
}

// ----------------------------------------------------------------------
// The calls
// ----------------------------------------------------------------------

/// Tells the IPC service's host that removed segments lost their last attachment.
fn post(notes: &[Note]) {
    if notes.is_empty() {
        return;
    }
    let Some(x) = super::svc::host(super::svc::host_of(LXS_IPC)) else { return };
    let mut any = false;
    for n in notes {
        any |= super::note_quiet_to(x, LX_NOTE_SHM, n.id as u32 as u64, n.pid, 0);
    }
    if any {
        crate::ipc::service::notify(x.endpoint.load(Ordering::Relaxed), NOTIFY_LX_NOTES);
    }
}

/// `shmat(id, addr, flags)` of the calling process: the kernel half (lx-ipc answered on
/// the way here; when it did not, it is asked now).
pub fn shmat(id: i32, addr: u64, flags: u64) -> i64 {
    let (tid, pid) = crate::compat::linux::proc::current_ids();
    let args = [id as u32 as u64, addr, flags];
    let got = match take(tid, args) {
        Some(g) => g,
        None => {
            // (the call did not pass through `forward`: lx-ipc is asked from here)
            let r = ask(args);
            if r != super::fileh::LX_TO_KERNEL {
                // (mapped by `answer` already, or refused)
                return r;
            }
            let Some(g) = take(tid, args) else { return EIDRM };
            g
        }
    };
    let Some(ep) = super::svc::host(super::svc::host_of(LXS_IPC)).map(|x| x.endpoint.load(Ordering::Acquire)) else { return EIDRM };
    map(&got.0, ep, got.1, id, addr, flags, pid, true)
}

/// Sends `shmat` with `args` to lx-ipc from the kernel half (its answer is mapped or kept
/// by [`answer`]).
fn ask(args: [u64; 3]) -> i64 {
    let Some(x) = super::svc::host(super::svc::host_of(LXS_IPC)).filter(|x| super::host_usable(x)) else { return EINVAL };
    let mut c = LxCall::EMPTY;
    c.nr = 30;
    c.args = [args[0], args[1], args[2], 0, 0, 0];
    c.svc = LXS_IPC as u32;
    c.ipc_ns = crate::compat::linux::ns::ipc_ns();
    super::call_ident_raw(x, c, true)
}

/// Maps segment `id`'s object (kept object `key` of the service at `ep`) into the calling
/// process `pid` and counts the attachment. `wait`: the address space's lock may be waited
/// for (else [`LATER`] when it is busy).
#[allow(clippy::too_many_arguments)]
fn map(obj: &Arc<MemObject>, ep: u32, key: u64, id: i32, addr: u64, flags: u64, pid: u64, wait: bool) -> i64 {
    let addr = if flags & SHM_RND != 0 { addr & !0xfff } else { addr };
    if addr & 0xfff != 0 {
        return EINVAL;
    }
    let Some(mm) = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten() else { return EINVAL };
    let len = obj.pages() * 4096;
    let prot = if flags & SHM_RDONLY != 0 { 1 } else { 3 } | if flags & SHM_EXEC != 0 { 4 } else { 0 };
    let fixed = addr != 0;
    let noreplace = fixed && flags & SHM_REMAP == 0;
    // Counted first, while the segment is still lx-ipc's (its object still kept: lx-ipc
    // unkeeps before it tells the kernel the segment went)
    let gen = table(|t| super::mem::kept_of_endpoint(ep, key).filter(|o| Arc::ptr_eq(o, obj)).map(|_| t.pre_attach(id)));
    let Some(gen) = gen else { return EIDRM };
    let mut m = if wait {
        mm.lock()
    } else {
        match mm.try_lock() {
            Some(m) => m,
            None => {
                let n = table(|t| t.undo(id, pid, gen));
                post(n.as_slice());
                return LATER;
            }
        }
    };
    let o: Arc<dyn MappedObject> = obj.clone();
    let at = match m.mmap(addr, len, prot, true, fixed, noreplace, Backing::Object { obj: o, pgoff: 0 }) {
        Ok(a) => {
            // Read permission was all that was checked: mprotect may not add write
            // (Linux: no VM_MAYWRITE, EACCES)
            if flags & SHM_RDONLY != 0 {
                m.deny_write(a, a + len);
            }
            a
        }
        Err(e) => {
            drop(m);
            let n = table(|t| t.undo(id, pid, gen));
            post(n.as_slice());
            return if e == -17 { EINVAL } else { e };
        }
    };
    drop(m);
    let t = now();
    let n = table(|tb| tb.attached(pid, at, id, len, obj_id(obj), gen, t));
    post(n.as_slice());
    // (SHM_REMAP over other attachments of this process: those may be gone now)
    if fixed {
        after_unmap(at, at + len);
    }
    at as i64
}

/// `shmdt(addr)` of the calling process: only a mapping that still is the segment is
/// unmapped (an attachment whose mapping went otherwise is dropped: `EINVAL`).
pub fn shmdt(addr: u64) -> i64 {
    let pid = crate::compat::linux::proc::current_ids().1;
    let Some(a) = table(|tb| tb.find(pid, addr)) else { return EINVAL };
    let ok = match crate::compat::linux::mm::current_mm() {
        Some(mm) => {
            let mut m = mm.lock();
            let ok = maps_obj(&m, a.obj, addr, addr + a.len, true);
            if ok {
                m.unmap(addr, addr + a.len);
            }
            ok
        }
        None => false,
    };
    let t = now();
    let n = table(|tb| tb.detach(pid, addr, t).and_then(|(_, n)| n));
    post(n.as_slice());
    if ok {
        0
    } else {
        EINVAL
    }
}

/// `munmap`, `mremap` or a `MAP_FIXED` mapping changed `[start, end)` of the calling
/// process: its attachments there with nothing of their segment left in their range go
/// (Linux counts mappings: `shm_close`).
pub fn after_unmap(start: u64, end: u64) {
    if !active() {
        return;
    }
    let pid = crate::compat::linux::proc::current_ids().1;
    let cand = table(|tb| if tb.is_empty() { Vec::new() } else { tb.overlapping(pid, start, end) });
    if cand.is_empty() {
        return;
    }
    let Some(mm) = crate::compat::linux::mm::current_mm() else { return };
    let gone: Vec<u64> = {
        let m = mm.lock();
        cand.iter().filter(|(at, a)| !maps_obj(&m, a.obj, *at, *at + a.len, false)).map(|(at, _)| *at).collect()
    };
    if gone.is_empty() {
        return;
    }
    let t = now();
    let notes: Vec<Note> = table(|tb| gone.iter().filter_map(|&at| tb.detach(pid, at, t).and_then(|(_, n)| n)).collect());
    post(&notes);
}

/// A forked child inherits its parent's attachments. (Called under the kernel lock before
/// the child's first system call can run: its `shmdt` and exit take that lock too.)
pub fn on_fork(parent: u64, child: u64) {
    let t = now();
    let alive = crate::compat::linux::proc::PROCS.lock().get(&child).is_some_and(|p| !p.zombie);
    if alive {
        table(|tb| if !tb.is_empty() { tb.fork(parent, child, t) });
    }
}

/// Process `pid` exited or replaced its image: its attachments go.
pub fn forget(pid: u64) {
    let t = now();
    let notes = table(|tb| if tb.is_empty() { Vec::new() } else { tb.forget(pid, t) });
    post(&notes);
}

/// `SYS_LX_OBJ` op [`LX_OBJ_SHM`](crate::ipc::protocol::LX_OBJ_SHM) of host `h` (lx-ipc's
/// host only): `(sub-op, b, c)`.
pub fn ctl(h: crate::ipc::protocol::SvcId, sub: u64, b: u64, c: u64) -> i64 {
    if h != super::svc::host_of(LXS_IPC) {
        return EPERM;
    }
    match sub {
        LX_SHM_NATTCH => table(|t| t.nattch(b as i32)) as i64,
        LX_SHM_STAT => {
            const SZ: usize = core::mem::size_of::<LxShmStat>();
            let n = c.min(4096) as usize;
            let Ok(mut raw) = crate::compat::linux::vfs::copy_in(b, n * SZ) else { return EFAULT };
            table(|t| {
                for e in raw.chunks_exact_mut(SZ) {
                    let id = i64::from_le_bytes(e[..8].try_into().unwrap()) as i32;
                    let i = t.info(id);
                    let s = LxShmStat { id: id as i64, nattch: i.nattch, atime: i.atime, dtime: i.dtime, lpid: i.lpid as u64 };
                    // SAFETY: a plain repr(C) struct of integers, SZ bytes
                    e.copy_from_slice(unsafe { core::slice::from_raw_parts(&s as *const LxShmStat as *const u8, SZ) });
                }
            });
            crate::compat::linux::vfs::copy_out(b, &raw).map_or(EFAULT, |()| n as i64)
        }
        LX_SHM_RMID => table(|t| t.rmid(b as i32)) as i64,
        LX_SHM_FORGET => {
            table(|t| t.forget_id(b as i32));
            0
        }
        LX_SHM_RESET => {
            table(|t| t.reset());
            0
        }
        LX_SHM_IPCNS => match super::proc::ns_ids(b) {
            Some(n) => n.ipc as i64,
            None => ESRCH,
        },
        _ => ENOSYS,
    }
}

/// Attachments in the table, made and dropped since boot (diagnostics).
pub fn stats() -> (usize, u64, u64) {
    table(|t| (t.len(), t.made, t.dropped))
}
