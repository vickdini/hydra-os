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

/// The check-and-set of a group or session change, under one hold of the process table (a
/// concurrent `setpgid`/`setsid` cannot slip between the rule and the change): `rule` sees
/// process `pid` and whether a group is used (`used(pgid, except)`: a process other than
/// `except`, zombies too, is in `pgid`), and answers `(pgid, new_session)` or an errno; the
/// change is then made. The group joined, or the errno.
pub fn task_pgrp_update(pid: u64, rule: impl FnOnce(Option<Pgrp>, &dyn Fn(u64, u64) -> bool) -> Result<(u64, bool), i64>) -> Result<u64, i64> {
    let mut procs = PROCS.lock();
    let me = procs.get(&pid).map(|p| Pgrp { pid: p.pid, ppid: p.ppid, pgid: p.pgid, sid: p.sid, zombie: p.zombie });
    let (pgid, new_session) = {
        let table = &*procs;
        rule(me, &|g, except| table.values().any(|p| p.pgid == g && p.pid != except))?
    };
    let p = procs.get_mut(&pid).ok_or(-3)?;
    p.pgid = pgid;
    if new_session {
        p.sid = pid;
    }
    Ok(pgid)
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

/// The check-and-set of limit `res` of process `tgid` under one hold of the limits table:
/// `rule` sees the old `(soft, hard)` and allows the change to `new` or answers an errno.
pub fn task_limits_update(tgid: u64, res: usize, new: (u64, u64), rule: impl FnOnce((u64, u64)) -> Result<(), i64>) -> Result<(), i64> {
    if res >= crate::compat::linux::limits::NLIMITS {
        return Err(-22);
    }
    crate::compat::linux::limits::update_limit(tgid, res, new, rule)
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

// wave10 G7b-1 begin: what lx-proc needs beyond 7a's primitives
// ----------------------------------------------------------------------
// Compare-and-set (lx-proc decides outside the table's lock)
// ----------------------------------------------------------------------

/// "Changed meanwhile: decide again" (`EAGAIN`).
pub const CHANGED: i64 = -11;

/// Process `pid`'s group and session, with whether a process other than it (zombies too)
/// is in group `pid` (what `setsid`'s rule asks), under one hold of the table.
pub fn task_pgrp_probe(pid: u64) -> Option<(Pgrp, bool)> {
    let procs = PROCS.lock();
    let p = procs.get(&pid)?;
    let me = Pgrp { pid: p.pid, ppid: p.ppid, pgid: p.pgid, sid: p.sid, zombie: p.zombie };
    let used = procs.values().any(|q| q.pgid == pid && q.pid != pid);
    Some((me, used))
}

/// Sets process `pid`'s group to `pgid` (and a new session with `new_session`) only if its
/// group and session are still `old` (`(pgid, sid)`), and, with `only_unused`, no other
/// process is in group `pid`: 0, `ESRCH`, [`CHANGED`], or `EPERM` (the group is used).
pub fn task_pgrp_cas(pid: u64, old: (u64, u64), pgid: u64, new_session: bool, only_unused: bool) -> i64 {
    let mut procs = PROCS.lock();
    match procs.get(&pid) {
        None => return -3,
        Some(p) if (p.pgid, p.sid) != old => return CHANGED,
        Some(_) => {}
    }
    if only_unused && procs.values().any(|q| q.pgid == pid && q.pid != pid) {
        return -1;
    }
    let Some(p) = procs.get_mut(&pid) else { return -3 };
    p.pgid = pgid;
    if new_session {
        p.sid = pid;
    }
    0
}

/// Sets limit `res` of process `tgid` to `new` only if it is still `old`: 0, `EINVAL` (no
/// such resource) or [`CHANGED`].
pub fn task_limits_cas(tgid: u64, res: usize, old: (u64, u64), new: (u64, u64)) -> i64 {
    match task_limits_update(tgid, res, new, |cur| if cur == old { Ok(()) } else { Err(CHANGED) }) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ----------------------------------------------------------------------
// prctl's attributes (`comm`, dumpable, parent-death signal, subreaper)
// ----------------------------------------------------------------------

/// A thread's attributes set by `prctl` (absent: the defaults).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadAttrs {
    /// Its process.
    pub tgid: u64,
    /// `PR_SET_NAME` (`None`: the executable's name).
    pub comm: Option<[u8; 16]>,
    /// `PR_SET_PDEATHSIG` (0: none).
    pub pdeathsig: u32,
}

/// A process's attributes set by `prctl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcAttrs {
    /// `PR_SET_DUMPABLE` (0, 1, 2; 1 by default).
    pub dumpable: u8,
    /// `PR_SET_CHILD_SUBREAPER`.
    pub subreaper: bool,
}

impl Default for ProcAttrs {
    fn default() -> Self {
        ProcAttrs { dumpable: 1, subreaper: false }
    }
}

/// By thread id.
static TATTRS: spin::Mutex<alloc::collections::BTreeMap<u64, ThreadAttrs>> = spin::Mutex::new(alloc::collections::BTreeMap::new());
/// By process id.
static PATTRS: spin::Mutex<alloc::collections::BTreeMap<u64, ProcAttrs>> = spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Thread `tid`'s attributes.
pub fn thread_attrs(tid: u64) -> ThreadAttrs {
    TATTRS.lock().get(&tid).copied().unwrap_or_default()
}

/// Process `tgid`'s attributes.
pub fn proc_attrs(tgid: u64) -> ProcAttrs {
    PATTRS.lock().get(&tgid).copied().unwrap_or_default()
}

/// The name `PR_SET_NAME` gave thread `tid` (`None`: none; `/proc` shows the executable's).
pub fn comm_of(tid: u64) -> Option<[u8; 16]> {
    TATTRS.lock().get(&tid).and_then(|a| a.comm)
}

/// Thread `tid`'s `comm`: its `PR_SET_NAME` name, else the file name of `exe` (at most 15
/// bytes), NUL-padded.
pub fn comm_or_exe(tid: u64, exe: &str) -> [u8; 16] {
    if let Some(c) = comm_of(tid) {
        return c;
    }
    let mut out = [0u8; 16];
    let name = exe.rsplit('/').next().unwrap_or("").as_bytes();
    let n = name.len().min(15);
    out[..n].copy_from_slice(&name[..n]);
    out
}

/// Changes thread `tid`'s (of process `tgid`) attributes with `f`.
pub fn thread_attrs_set(tid: u64, tgid: u64, f: impl FnOnce(&mut ThreadAttrs)) {
    let mut t = TATTRS.lock();
    let a = t.entry(tid).or_insert(ThreadAttrs { tgid, ..Default::default() });
    a.tgid = tgid;
    f(a);
}

/// Changes process `tgid`'s attributes with `f`.
pub fn proc_attrs_set(tgid: u64, f: impl FnOnce(&mut ProcAttrs)) {
    f(PATTRS.lock().entry(tgid).or_default());
}

/// A new process `child` of thread `parent_tid` in process `parent`: it starts with the
/// parent thread's name and the parent's dumpable flag (no parent-death signal, no
/// subreaper: not inherited).
pub fn attrs_on_fork(parent_tid: u64, parent: u64, child: u64) {
    if let Some(comm) = comm_of(parent_tid) {
        thread_attrs_set(child, child, |a| a.comm = Some(comm));
    }
    let d = proc_attrs(parent).dumpable;
    if d != 1 {
        proc_attrs_set(child, |a| a.dumpable = d);
    }
}

/// Thread `tid` of `tgid` ran `execve`: its name becomes the new executable's (Linux sets
/// `comm` at exec) and the process is dumpable again; the parent-death signal stays.
pub fn attrs_on_exec(tid: u64, tgid: u64) {
    if let Some(a) = TATTRS.lock().get_mut(&tid) {
        a.comm = None;
    }
    if let Some(p) = PATTRS.lock().get_mut(&tgid) {
        p.dumpable = 1;
    }
}

/// Process `tgid` ended: its records go.
pub fn attrs_on_exit(tgid: u64) {
    TATTRS.lock().retain(|_, a| a.tgid != tgid);
    PATTRS.lock().remove(&tgid);
}

// ----------------------------------------------------------------------
// Calls lx-proc allowed, run by the kernel's code without its own check
// ----------------------------------------------------------------------

/// `(thread, call number)` lx-proc approved ([`approve`]); taken by [`take_approval`].
static APPROVED: spin::Mutex<[(u64, u64); 16]> = spin::Mutex::new([(0, 0); 16]);

/// lx-proc allowed thread `tid`'s call `nr` (it answers with a redirect to the kernel).
pub fn approve(tid: u64, nr: u64) {
    let mut a = APPROVED.lock();
    let i = a.iter().position(|e| e.0 == tid).or_else(|| a.iter().position(|e| e.0 == 0)).unwrap_or(0);
    a[i] = (tid, nr);
}

/// Whether lx-proc allowed thread `tid`'s call `nr` (once: the mark goes, as any other of
/// that thread's).
pub fn take_approval(tid: u64, nr: u64) -> bool {
    let mut a = APPROVED.lock();
    let mut ok = false;
    for e in a.iter_mut().filter(|e| e.0 == tid && tid != 0) {
        ok |= e.1 == nr;
        *e = (0, 0);
    }
    ok
}
// wave10 G7b-1 end

// ----------------------------------------------------------------------
// Policy (moves to lx-proc in wave 10)
// ----------------------------------------------------------------------

/// Today's rules for changing process identity (pure; its own file so host builds that
/// stub the primitives still compile the real rules).
#[path = "proc_rules.rs"]
pub mod rules;
