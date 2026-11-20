//! # Calls between services (wave 6, Group 20)
//!
//! The design is `docs/linux-services-design.md`, sections 4.2–4.4. A Linux-facing service
//! (linux-server, vfs-server, lx-sec, the test service, ...) calls another one with
//! **`SYS_SVC_DCALL`** (native call 70) and posts it an event with **`SYS_SVC_POST`** (71).
//! Calls to classic servers (net-server, zfs-server, the drivers) keep using `SYS_SVC_CALL`,
//! whose own direct path is in `ipc::service` ("The direct path").
//!
//! ## The direct call
//!
//! `SYS_SVC_DCALL(target svc, op, in, in_len, out, out_cap)` is a forwarded call that comes
//! from a service instead of a Linux program, and it uses the same machinery: the kernel
//! builds an [`LxCall`] with `nr =` [`LX_DCALL_NR`], copies `in` (up to the copy area's 3 KiB,
//! from the caller's own memory: no page walk of another process) into the target worker's
//! syscall page, and switches straight to an idle worker of the target (the direct switch of
//! a forwarded call). The worker answers with `SYS_LX_REPLY_RECV` as for any call, which
//! switches straight back; up to `out_cap` bytes it leaves in the page for `out` come back to
//! the caller. A callee that must wait answers "pending" and completes later
//! (`SYS_LX_COMPLETE`), writing its output with `SYS_LX_WRITE`; the dcall's caller blocks
//! meanwhile, as a Linux caller would.
//!
//! What the callee sees (until the registry's `LxCall` fields exist, in the arguments too):
//! `args = [op, in, out, in_len, out_cap, from_svc]`; read the input with the copy helpers
//! (`Cx::copy_in(args[1], args[3])`), write the output with `Cx::copy_out(args[2], ..)`, and
//! return the result (by convention the output's length, or a negative errno).
//!
//! ## Delegation (4.3)
//!
//! A dcall made by a worker while it serves request R is made *for R's caller*: the kernel
//! copies that program's identity (thread, process, credentials, groups) into the callee's
//! call and records R as `on_behalf`; the caller cannot choose them. While the dcall lasts the
//! callee may name R in `SYS_LX_READ`/`SYS_LX_WRITE`/`LX_OBJ_*` as if it served R itself
//! ([`delegated`]); the right ends with the answer.
//!
//! ## Who may call whom; no cycles (4.4)
//!
//! Synchronous calls go only *down* this order: the test service (a back end) < vfs <
//! {ipc, net, display, input, sound, tty, sec} < proc < linux ([`rank`]). Those edges are
//! allowed from the start; the supervisor may add or remove edges (`LX_SVC_ALLOW`, kernel
//! only). An undeclared edge fails with `-EPERM`. The null operation
//! [`LX_DCALL_OP_NULL`] is allowed on every edge (it is answered at once: no wait, no cycle).
//! A call to the caller's own process (another worker of the same pool) is made only when a
//! worker of that pool is idle, so a pool can never wait for itself (`-EAGAIN` otherwise).
//!
//! ## Posts
//!
//! `SYS_SVC_POST(target svc, op, data, len)` appends one entry to the target's notification
//! ring, kind [`LX_NOTE_POST`]: `(from_svc | op << 32, word 0, word 1)`, `len` <= 16 bytes,
//! and wakes its main thread. Nobody waits for an answer.
//!
//! ## When the callee dies
//!
//! Its calls in flight fail with `-EIO` as every forwarded call does (`server_gone`), so the
//! caller never hangs.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::protocol::{
    LxCall, SvcId, LXS_DISPLAY, LXS_INPUT, LXS_IPC, LXS_LINUX, LXS_MAX, LXS_NET, LXS_PROC, LXS_SEC, LXS_SOUND, LXS_TEST, LXS_TTY, LXS_VFS, LX_DCALL_NR,
    LX_DCALL_OP_NULL, LX_GROUPS, LX_NOTE_POST,
};

use super::svc;

use super::copy;

const EPERM: i64 = -1;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const E2BIG: i64 = -7;

/// Most bytes one post carries.
pub const POST_MAX: u64 = 16;

// ----------------------------------------------------------------------
// Who may call whom
// ----------------------------------------------------------------------

/// A service's place in the call order (design 4.4): synchronous calls go to a lower rank
/// only. 0: not a Linux service (no calls).
pub fn rank(svc: SvcId) -> u8 {
    match svc {
        LXS_TEST => 1,
        LXS_VFS => 2,
        LXS_IPC | LXS_NET | LXS_DISPLAY | LXS_INPUT | LXS_SOUND | LXS_TTY | LXS_SEC => 3,
        LXS_PROC => 4,
        LXS_LINUX => 5,
        _ => 0,
    }
}

/// Per caller id: bit `t` set = it may call service `t` ([`allow`]); filled from [`rank`] at
/// the first use.
static ALLOW: [AtomicU16; LXS_MAX] = [const { AtomicU16::new(0) }; LXS_MAX];
static ALLOW_SET: AtomicBool = AtomicBool::new(false);

fn allow_init() {
    if ALLOW_SET.load(Ordering::Acquire) {
        return;
    }
    for f in 0..LXS_MAX as u8 {
        let mut bits = 0u16;
        for t in 0..LXS_MAX as u8 {
            if rank(f) != 0 && rank(t) != 0 && rank(t) < rank(f) {
                bits |= 1 << t;
            }
        }
        // (an edge the supervisor set before the first use stays)
        ALLOW[f as usize].fetch_or(bits, Ordering::AcqRel);
    }
    ALLOW_SET.store(true, Ordering::Release);
}

/// `LX_SVC_ALLOW` (the supervisor, in the kernel): lets service `from` call service `to`
/// (`on`), or no longer.
pub fn allow(from: SvcId, to: SvcId, on: bool) {
    if (from as usize) >= LXS_MAX || (to as usize) >= LXS_MAX {
        return;
    }
    allow_init();
    if on {
        ALLOW[from as usize].fetch_or(1 << to, Ordering::AcqRel);
    } else {
        ALLOW[from as usize].fetch_and(!(1 << to), Ordering::AcqRel);
    }
}

/// Whether `from` may make call `op` to `to`.
pub fn allowed(from: SvcId, to: SvcId, op: u64) -> bool {
    if (from as usize) >= LXS_MAX || (to as usize) >= LXS_MAX {
        return false;
    }
    allow_init();
    op == LX_DCALL_OP_NULL || ALLOW[from as usize].load(Ordering::Acquire) & (1 << to) != 0
}

// ----------------------------------------------------------------------
// Delegation
// ----------------------------------------------------------------------

/// Delegations in force: `(thread making a dcall, request it is made for)`; 0: free. A
/// thread makes one dcall at a time, so the dcall request whose caller is that thread is the
/// one the delegation belongs to.
static DELEG: Mutex<[(u64, u64); 64]> = Mutex::new([(0, 0); 64]);

/// Whether request `id` may be used by the server of a dcall whose calling thread is
/// `dcall_caller` (that dcall was made on behalf of `id` and is not answered yet). For the
/// per-service tables: the check that a request belongs to the calling process accepts such
/// an `id` too.
pub fn delegated(dcall_caller: u64, id: u64) -> bool {
    id != 0 && x86_64::instructions::interrupts::without_interrupts(|| DELEG.lock().iter().any(|&(d, r)| d == dcall_caller && r == id))
}

fn deleg_add(d: u64, r: u64) -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut t = DELEG.lock();
        match t.iter_mut().find(|e| e.0 == 0) {
            Some(e) => {
                *e = (d, r);
                true
            }
            None => false,
        }
    })
}

fn deleg_end(d: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        for e in DELEG.lock().iter_mut().filter(|e| e.0 == d) {
            *e = (0, 0);
        }
    })
}

// ----------------------------------------------------------------------
// Counters
// ----------------------------------------------------------------------

/// Direct calls made, refused (`EPERM`), and posts.
pub static DCALLS: AtomicU64 = AtomicU64::new(0);
/// See [`DCALLS`].
pub static DCALLS_REFUSED: AtomicU64 = AtomicU64::new(0);
/// See [`DCALLS`].
pub static POSTS: AtomicU64 = AtomicU64::new(0);

/// One line for `linux prof show`: the calls between services.
pub fn summary() -> alloc::string::String {
    alloc::format!(
        "{} direct calls between services ({} refused), {} posts; {}",
        DCALLS.load(Ordering::Relaxed),
        DCALLS_REFUSED.load(Ordering::Relaxed),
        POSTS.load(Ordering::Relaxed),
        crate::ipc::service::direct_summary()
    )
}

// ----------------------------------------------------------------------
// The calls
// ----------------------------------------------------------------------

/// The host id of the calling process (its first service: the one a call from it is from;
/// 0: not a Linux service's process).
fn my_svc() -> SvcId {
    // A worker (the common caller): its host, without a lock
    let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
    if let Some(h) = svc::worker_host(tid) {
        return h;
    }
    crate::task::current_service().and_then(svc::host_by_endpoint).unwrap_or(0)
}

/// Service `target`'s host when it serves calls now (`None`: in the kernel, or not running).
fn target_host(target: SvcId) -> Option<&'static svc::Host> {
    if svc::mode(target) == svc::SvcMode::Kernel {
        return None;
    }
    svc::host(svc::host_of(target)).filter(|x| x.is_online())
}

/// The identity a dcall made by thread `me` (of host `mine`) carries: the program it serves
/// a request for (`(request, its caller)`), else its own.
fn identity(c: &mut LxCall, me: u64, mine: SvcId) -> u64 {
    // The request the calling worker serves, if any
    let serving = svc::host(mine).and_then(|x| x.lx(|s| {
        let w = s.workers.iter().find(|w| w.task == me)?;
        if w.req == super::NONE {
            return None;
        }
        let r = &s.reqs[w.req];
        matches!(r.state, super::RState::Delivered).then_some((r.id, r.client))
    }));
    let (on_behalf, who) = match serving {
        Some((r, client)) => (r, client),
        None => (0, me),
    };
    // The program's identity as this CPU's forwarding cache holds it (the forwarded call
    // that the worker serves came through this cache, usually on this CPU), still valid
    if let Some(id) = super::ident_of(who) {
        c.tid = id.tid;
        c.tgid = id.tgid;
        [c.uid, c.euid, c.suid, c.gid, c.egid, c.sgid] = id.ids;
        c.caps = id.caps;
        c.ngroups = id.ngroups;
        c.groups = id.groups;
        return on_behalf;
    }
    let found = crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(who), |t| {
        (t.id.0, t.tgid, [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid], if t.caps.in_userns { 0 } else { t.caps.effective })
    });
    if let Some((tid, tgid, ids, caps)) = found {
        c.tid = tid;
        c.tgid = tgid;
        [c.uid, c.euid, c.suid, c.gid, c.egid, c.sgid] = ids;
        c.caps = caps;
        // (never waiting for the process table: this may run without the kernel lock)
        if let Some(procs) = crate::compat::linux::proc::PROCS.try_lock() {
            if let Some(p) = procs.get(&tgid) {
                let n = p.groups.len().min(LX_GROUPS);
                c.groups[..n].copy_from_slice(&p.groups[..n]);
                c.ngroups = n as u64;
            }
        }
    }
    on_behalf
}

/// Where a dcall's arguments are: `[op, in, out, in_len, out_cap, from]`.
static DCALL_DESC: copy::Desc = [copy::Arg::None, copy::Arg::In(copy::len_arg(3)), copy::Arg::Out(copy::len_arg(4)), copy::Arg::None, copy::Arg::None, copy::Arg::None];

/// `SYS_SVC_DCALL(target, op, in, in_len, out, out_cap)` by thread `me` (at `idx`, a hint).
/// `nobkl`: made on the lock-free path.
///
/// # Returns
///
/// The callee's result, or `-EPERM` (no such edge, or not a Linux service), `-EINVAL`
/// (bad target, `in_len`/`out_cap` over the copy area), `-EFAULT` (bad `in`), `-ENOSYS`
/// (target not online), `-EAGAIN` (a call to its own process with no idle worker), `-EIO`
/// (the target went away during the call).
pub fn dcall(me: u64, idx: usize, a: [u64; 6], nobkl: bool) -> i64 {
    let (target, op, inp, in_len, out, out_cap) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    if target as usize >= LXS_MAX || target == 0 {
        return EINVAL;
    }
    let target = target as SvcId;
    let from = my_svc();
    if from == 0 || !allowed(from, target, op) {
        DCALLS_REFUSED.fetch_add(1, Ordering::Relaxed);
        return EPERM;
    }
    let size = crate::ipc::protocol::LX_DATA_SIZE as u64;
    if in_len > size || out_cap > size || in_len + out_cap > size || (in_len > 0 && inp == 0) || (out_cap > 0 && out == 0) {
        return EINVAL;
    }
    let Some(x) = target_host(target) else { return ENOSYS };
    // A pool never waits for itself: a call to its own process needs an idle worker now
    if x.id == from && !x.lx(|s| s.workers.iter().any(|w| w.idle)) {
        return EAGAIN;
    }
    let mut c = LxCall::EMPTY;
    c.nr = LX_DCALL_NR;
    c.args = [op, if in_len > 0 { inp } else { 0 }, if out_cap > 0 { out } else { 0 }, in_len, out_cap, from as u64];
    c.svc = target as u32;
    c.from_svc = from as u32;
    c.dcall_op = op as u32;
    let on_behalf = identity(&mut c, me, from);
    c.on_behalf = on_behalf;
    // The input is copied when the call is placed (Group 22: straight into the worker's
    // page; a bad pointer fails there with EFAULT; it fits by the check above)
    c.note_seq = x.notes_head();
    DCALLS.fetch_add(1, Ordering::Relaxed);
    // The delegation holds while the call lasts (it is in force before the callee runs)
    let deleg = on_behalf != 0 && deleg_add(me, on_behalf);
    let mut redir = (0, 0);
    let r = x86_64::instructions::interrupts::without_interrupts(|| super::call_and_wait(x, me, idx, c, copy::Src::User(DCALL_DESC), nobkl, None, &mut redir));
    // (a redirect answer is not a dcall's: the callee answers itself)
    let r = if r == crate::ipc::protocol::LX_REDIRECTED { EINVAL } else { r };
    if deleg {
        deleg_end(me);
    }
    r
}

/// `SYS_SVC_POST(target, op, data, len)`: one event to service `target`'s notification
/// ring (see the module comment).
pub fn post(a: [u64; 6]) -> i64 {
    let (target, op, data, len) = (a[0], a[1], a[2], a[3]);
    if target as usize >= LXS_MAX || target == 0 || op > u32::MAX as u64 {
        return EINVAL;
    }
    if len > POST_MAX {
        return E2BIG;
    }
    let target = target as SvcId;
    let from = my_svc();
    // Posts go any direction (nobody waits), but only between Linux services
    if from == 0 || rank(target) == 0 {
        return EPERM;
    }
    let mut w = [0u8; 16];
    if len > 0 && copy::read_user(data, &mut w[..len as usize]).is_err() {
        return EFAULT;
    }
    let Some(x) = target_host(target) else { return ENOSYS };
    POSTS.fetch_add(1, Ordering::Relaxed);
    let w0 = u64::from_le_bytes(w[..8].try_into().unwrap());
    let w1 = u64::from_le_bytes(w[8..].try_into().unwrap());
    super::note_to(x.id, LX_NOTE_POST, from as u64 | op << 32 | (target as u64) << 56, w0, w1);
    0
}

/// Whether the calling thread (a worker) serves a dcall made on behalf of request `id`, so
/// it may use `id` as its own (client memory, installing a descriptor; design 4.3).
pub(super) fn may_use(id: u64) -> bool {
    let me = crate::task::CURRENT_TID.load(Ordering::Acquire);
    let Some(x) = svc::worker_host(me).and_then(svc::host) else { return false };
    let dcall_caller = x.lx(|s| {
        let w = s.workers.iter().find(|w| w.task == me)?;
        if w.req == super::NONE {
            return None;
        }
        let r = &s.reqs[w.req];
        matches!(r.state, super::RState::Delivered | super::RState::Pending).then_some(r.client)
    });
    dcall_caller.is_some_and(|d| delegated(d, id))
}

/// Ops 3-7 of `SYS_LX_SVC` (72): 3 `LX_SVC_ALLOW` (kernel only: `-EPERM` from programs),
/// 4 `LX_SVC_DCALL_INFO(buf)`: the counters as four u64 (dcalls, refused, posts, classic
/// direct switches).
pub fn svc_op(op: u64, a: u64, _b: u64, _c: u64) -> i64 {
    match op {
        3 => EPERM,
        4 => {
            let v = [
                DCALLS.load(Ordering::Relaxed),
                DCALLS_REFUSED.load(Ordering::Relaxed),
                POSTS.load(Ordering::Relaxed),
                crate::ipc::service::DIRECT_SWITCHED.load(Ordering::Relaxed),
            ];
            let mut bytes = [0u8; 32];
            for (i, x) in v.iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
            }
            match copy::write_user(a, &bytes) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        _ => EINVAL,
    }
}

// Host tests (test wave, Group 30): tests/host-t30 compiles this file with them
#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_dcall.rs"]
pub(crate) mod tests;
