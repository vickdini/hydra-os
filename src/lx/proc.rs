//! # Process identity: the kernel's primitives (wave 9, Group 7a)
//!
//! Decision 11 (`docs/microkernel-plan.md`) keeps a process's identity in the kernel:
//! credentials, the process tree, process groups and sessions, PID translation, namespace
//! ids and resource limits (`docs/linux-services-design.md` section 2.2). This file is that
//! mechanism's one front: small primitives over the task records and the process table, which
//! the Linux layer's system calls, the services' kernel sides (`console.rs`, `info.rs`, the
//! call header in `mod.rs`) and, from wave 10, the process service `lx-proc` call.
//!
//! - **Credentials** ([`task_creds`], [`task_creds_set`]): a thread's real, effective and
//!   saved user and group ids; a change of user ids applies the capability rules.
//! - **Process groups and sessions** ([`task_pgrp`], [`task_pgrp_set`], [`pgrp_members`],
//!   [`pgrp_in_session`], [`pgrp_used`], [`pgrp_signal`]).
//! - **The tree and PID view** ([`task_tree`], [`pid_ns_init`], [`pid_to_view`],
//!   [`pid_from_view`]).
//! - **Resource limits** ([`task_limits`], [`task_limits_set`]): stored per process in
//!   `compat/linux/limits.rs`, enforced at the kernel's own points.
//! - **Namespace ids** ([`ns_ids`], [`ns_set`], [`ns_apply`], [`ns_new_id`]): the small id of
//!   each kind a process is in; the namespace *objects* belong to the service of that kind.
//!
//! The primitives decide nothing: [`rules`] holds today's policy (who may change what) as
//! pure functions. They stay in the kernel this wave (the system calls call them) and move
//! to lx-proc in wave 10, which then sets the result through these primitives (`SYS_LX_OBJ`
//! op 75, `LX_OBJ_PROCID`, reserved for it).
//!
//! Lock order: as the process table's (the scheduler before [`PROCS`], never the reverse);
//! no primitive holds one table while calling out (signals are posted after the table is
//! released).

use alloc::vec::Vec;

use crate::compat::linux::ns::{Ns, UserNs};
use crate::compat::linux::proc::PROCS;


// ----------------------------------------------------------------------
// Credentials
// ----------------------------------------------------------------------

/// A thread's user and group ids, each `[real, effective, saved]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Creds {
    /// User ids.
    pub uid: [u32; 3],
    /// Group ids.
    pub gid: [u32; 3],
}

/// Runs `f` on thread `tid` (0: the calling thread).
fn with_thread<R>(tid: u64, f: impl FnOnce(&mut crate::task::Task) -> R) -> Option<R> {
    if tid == 0 {
        crate::task::with_current_task_mut(f)
    } else {
        crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(tid), f)
    }
}

/// The credentials of thread `tid` (0: the caller), with whether it holds `CAP_SETUID` and
/// `CAP_SETGID` (what [`rules`] asks).
pub fn task_creds(tid: u64) -> Option<(Creds, bool, bool)> {
    use crate::task::tcb::Caps;
    with_thread(tid, |t| (Creds { uid: [t.uid, t.euid, t.suid], gid: [t.gid, t.egid, t.sgid] }, t.caps.has(Caps::SETUID), t.caps.has(Caps::SETGID)))
}

/// Sets the credentials of thread `tid` (0: the caller) to `new`; a change of user ids
/// applies the capability rules (`Caps::on_uid_change`). `false`: no such thread.
pub fn task_creds_set(tid: u64, new: Creds) -> bool {
    with_thread(tid, |t| {
        let old = (t.uid, t.euid, t.suid);
        [t.uid, t.euid, t.suid] = new.uid;
        [t.gid, t.egid, t.sgid] = new.gid;
        t.caps.on_uid_change(old, (t.uid, t.euid, t.suid));
    })
    .is_some()
}

// ----------------------------------------------------------------------
// Process groups and sessions
// ----------------------------------------------------------------------

/// A process's place in the tree, its group and its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pgrp {
    /// Process id.
    pub pid: u64,
    /// Parent's.
    pub ppid: u64,
    /// Process group.
    pub pgid: u64,
    /// Session.
    pub sid: u64,
    /// Exited, not reaped yet.
    pub zombie: bool,
}

/// Process `pid`'s group and session (zombies too).
pub fn task_pgrp(pid: u64) -> Option<Pgrp> {
    PROCS.lock().get(&pid).map(|p| Pgrp { pid: p.pid, ppid: p.ppid, pgid: p.pgid, sid: p.sid, zombie: p.zombie })
}

/// Puts process `pid` into group `pgid`; with `new_session` it also leads a new session
/// (`sid = pid`). `false`: no such process.
pub fn task_pgrp_set(pid: u64, pgid: u64, new_session: bool) -> bool {
    match PROCS.lock().get_mut(&pid) {
        Some(p) => {
            p.pgid = pgid;
            if new_session {
                p.sid = pid;
            }
            true
        }
        None => false,
    }
}

/// The live processes of group `pgid` (only those in session `sid` when given).
pub fn pgrp_members(pgid: u64, sid: Option<u64>) -> Vec<u64> {
    PROCS.lock().values().filter(|p| p.pgid == pgid && !p.zombie && sid.map_or(true, |s| p.sid == s)).map(|p| p.pid).collect()
}

/// Whether group `pgid` has a live member in session `sid`: `Some(true)`; members only in
/// other sessions: `Some(false)`; no live member: `None`.
pub fn pgrp_in_session(pgid: u64, sid: u64) -> Option<bool> {
    let procs = PROCS.lock();
    let mut any = false;
    for p in procs.values().filter(|p| p.pgid == pgid && !p.zombie) {
        if p.sid == sid {
            return Some(true);
        }
        any = true;
    }
    any.then_some(false)
}

/// Whether a process other than `except` (zombies too) is in group `pgid`.
pub fn pgrp_used(pgid: u64, except: u64) -> bool {
    PROCS.lock().values().any(|p| p.pgid == pgid && p.pid != except)
}

/// Posts `sig` to the live members of group `pgid` (only those in session `sid` when
/// given); the number of members.
pub fn pgrp_signal(pgid: u64, sid: Option<u64>, sig: u32) -> usize {
    let members = pgrp_members(pgid, sid);
    for &pid in &members {
        crate::compat::linux::proc::post_process(pid, sig);
    }
    members.len()
}

// ----------------------------------------------------------------------
// The tree and the PID view
// ----------------------------------------------------------------------

/// A process's facts from the process table (`/proc/<pid>/stat` and the info primitives).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    /// Parent.
    pub ppid: u64,
    /// Process group.
    pub pgid: u64,
    /// Session.
    pub sid: u64,
    /// Live threads (at least 1).
    pub threads: u64,
    /// Start time in clock ticks since boot.
    pub start: u64,
    /// Exited, not reaped yet.
    pub zombie: bool,
    /// System PIDs of the init of each PID namespace it is in, outermost first.
    pub pid_inits: Vec<u64>,
}

/// Process `pid`'s facts from the process table.
pub fn task_tree(pid: u64) -> Option<Tree> {
    PROCS.lock().get(&pid).map(|p| Tree {
        ppid: p.ppid,
        pgid: p.pgid,
        sid: p.sid,
        threads: p.threads_alive().max(1) as u64,
        start: p.start_time,
        zombie: p.zombie,
        pid_inits: p.ns.pid_inits.clone(),
    })
}

/// The system PID of the init of process `pid`'s PID namespace (`None`: the first one, or
/// no such process).
pub fn pid_ns_init(pid: u64) -> Option<u64> {
    PROCS.lock().get(&pid).and_then(|p| p.ns.pid_inits.last().copied())
}

/// A system-wide id as a process whose PID namespace's init is `init` sees it.
pub fn pid_to_view(id: u64, init: Option<u64>) -> u64 {
    match init {
        Some(i) if i == id => 1,
        _ => id,
    }
}

/// An id named by a process whose PID namespace's init is `init`, as a system-wide id.
pub fn pid_from_view(id: u64, init: Option<u64>) -> u64 {
    match init {
        Some(i) if id == 1 => i,
        _ => id,
    }
}

// ----------------------------------------------------------------------
// Resource limits
// ----------------------------------------------------------------------

/// Process `tgid`'s limits, `(soft, hard)` by resource number.
pub fn task_limits(tgid: u64) -> [(u64, u64); crate::compat::linux::limits::NLIMITS] {
    crate::compat::linux::limits::limits_of(tgid)
}

/// Sets process `tgid`'s limit `res` to `(soft, hard)` (`false`: no such resource).
pub fn task_limits_set(tgid: u64, res: usize, new: (u64, u64)) -> bool {
    if res >= crate::compat::linux::limits::NLIMITS {
        return false;
    }
    crate::compat::linux::limits::store_limit(tgid, res, new);
    true
}

// ----------------------------------------------------------------------
// Namespace ids
// ----------------------------------------------------------------------

/// A namespace kind held as a plain id (the user namespace is an object: [`NsChange::User`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsKind {
    /// PID namespace.
    Pid,
    /// The PID namespace children are created in (0: the process's own).
    PidForChildren,
    /// Network.
    Net,
    /// Mount.
    Mnt,
    /// IPC.
    Ipc,
    /// UTS (host and domain names).
    Uts,
    /// Cgroup.
    Cgroup,
}

/// One change of a process's namespaces.
#[derive(Clone)]
pub enum NsChange {
    /// Kind `.0` becomes id `.1`.
    Id(NsKind, u64),
    /// The user namespace (`None`: the initial one).
    User(Option<alloc::sync::Arc<UserNs>>),
}

/// A process's namespace ids (0: the initial namespace of that kind).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NsIds {
    /// User namespace id (0: the initial one).
    pub user: u64,
    /// PID namespace.
    pub pid: u64,
    /// The PID namespace for children (0: the process's own).
    pub pid_for_children: u64,
    /// Network.
    pub net: u64,
    /// Mount.
    pub mnt: u64,
    /// IPC.
    pub ipc: u64,
    /// UTS.
    pub uts: u64,
    /// Cgroup.
    pub cgroup: u64,
}

impl NsIds {
    /// The ids of `ns`.
    pub fn of(ns: &Ns) -> NsIds {
        NsIds {
            user: ns.user.as_ref().map_or(0, |u| u.id),
            pid: ns.pid,
            pid_for_children: ns.pid_for_children.unwrap_or(0),
            net: ns.net,
            mnt: ns.mnt,
            ipc: ns.ipc,
            uts: ns.uts,
            cgroup: ns.cgroup,
        }
    }
}

/// Process `pid`'s namespace ids.
pub fn ns_ids(pid: u64) -> Option<NsIds> {
    PROCS.lock().get(&pid).map(|p| NsIds::of(&p.ns))
}

/// Applies `changes` to `ns`, in order (for a caller that holds the process table).
pub fn ns_apply(ns: &mut Ns, changes: &[NsChange]) {
    for c in changes {
        match c {
            NsChange::User(u) => ns.user = u.clone(),
            &NsChange::Id(k, id) => match k {
                NsKind::Pid => ns.pid = id,
                NsKind::PidForChildren => ns.pid_for_children = (id != 0).then_some(id),
                NsKind::Net => ns.net = id,
                NsKind::Mnt => ns.mnt = id,
                NsKind::Ipc => ns.ipc = id,
                NsKind::Uts => ns.uts = id,
                NsKind::Cgroup => ns.cgroup = id,
            },
        }
    }
}

/// Applies `changes` to process `pid`'s namespaces; its ids afterwards (`None`: no such
/// process).
pub fn ns_set(pid: u64, changes: &[NsChange]) -> Option<NsIds> {
    let mut procs = PROCS.lock();
    let p = procs.get_mut(&pid)?;
    ns_apply(&mut p.ns, changes);
    Some(NsIds::of(&p.ns))
}

/// A fresh namespace id (never 0; the ids `/proc/<pid>/ns/*` shows).
pub fn ns_new_id() -> u64 {
    crate::compat::linux::ns::new_id()
}

// ----------------------------------------------------------------------
// The call header's process context
// ----------------------------------------------------------------------

/// What a forwarded call carries about its caller's process: group, session, namespaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallCtx {
    /// Process group.
    pub pgid: u64,
    /// Session.
    pub sid: u64,
    /// Mount namespace.
    pub mnt: u64,
    /// Network namespace.
    pub net: u64,
    /// PID namespace.
    pub pid: u64,
    /// Whether it is in a user namespace of its own.
    pub user: bool,
}

/// Process `tgid`'s call context: `Err(())` if the table is busy and `wait` is not allowed,
/// `Ok(None)` if there is no such process.
pub fn call_ctx(tgid: u64, wait: bool) -> Result<Option<CallCtx>, ()> {
    let procs = if wait { PROCS.lock() } else { PROCS.try_lock().ok_or(())? };
    Ok(procs.get(&tgid).map(|p| CallCtx { pgid: p.pgid, sid: p.sid, mnt: p.ns.mnt, net: p.ns.net, pid: p.ns.pid, user: p.ns.user.is_some() }))
}

// ----------------------------------------------------------------------
// Policy (moves to lx-proc in wave 10)
// ----------------------------------------------------------------------

/// Today's rules for changing process identity (pure; its own file so host builds that
/// stub the primitives still compile the real rules).
#[path = "proc_rules.rs"]
pub mod rules;
