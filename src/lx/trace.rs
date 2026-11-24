//! # The tracing calls' facts and the check at use (wave 10, Group 8-1)
//!
//! lx-proc decides `ptrace`'s attach family, `perf_event_open`, `process_vm_readv`/`writev`,
//! `kcmp` and `pidfd_getfd` (the rule: [`super::ptrace_rules`]); the kernel keeps the
//! mechanism (stopping, registers, memory, single-step, breakpoints, the counters). This is
//! the kernel's half of the decision:
//!
//! - [`gather`]: the facts of a call as the kernel will run it (its targets resolved in the
//!   caller's PID namespace and descriptor table), for lx-proc (op 75 sub-op
//!   `LXP_TRACE_FACTS`, [`facts_op`]) and for the check at use.
//! - [`check`]: called by the kernel's code where it used to check permission: lx-proc's
//!   verdict when its approval mark was given for exactly the facts as they are now,
//!   otherwise the rule run here (`lx.proc=kernel`, or the facts changed in between).
//!
//! Requests on an attached tracee (`PEEK`/`POKE`/`GETREGS`/`CONT`/...) and perf's `read` and
//! `ioctl` never come here: they are mechanism, answered by the kernel alone.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::proc as mech;
use super::ptrace_rules::{self as rules, Facts, Target, Who};
use crate::ipc::protocol::LxProcIo;
use crate::task::TaskId;

const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;

/// Checks that used lx-proc's verdict, and that found no mark or other facts (the kernel's
/// own decision).
static USED: AtomicU64 = AtomicU64::new(0);
static OWN: AtomicU64 = AtomicU64::new(0);
static LOGGED: AtomicBool = AtomicBool::new(false);
static LOGGED_MISMATCH: AtomicBool = AtomicBool::new(false);

/// One line for `linux prof show`: checks with lx-proc's verdict, checks decided by the
/// kernel, and the lock-free redirects marked and taken (`lx::TRACE_MARKS`).
pub fn summary() -> alloc::string::String {
    let m = &super::TRACE_MARKS;
    alloc::format!(
        "tracing calls: {} verdicts from lx-proc, {} decided by the kernel; lock-free redirects {} marked, {} taken",
        USED.load(Ordering::Relaxed),
        OWN.load(Ordering::Relaxed),
        m.0.load(Ordering::Relaxed),
        m.1.load(Ordering::Relaxed)
    )
}

/// Thread `tid` as the caller of a decision, and its process.
fn who_of(tid: u64) -> Option<(Who, u64)> {
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| {
        (Who { uid: [t.uid, t.euid, t.suid], gid: [t.gid, t.egid, t.sgid], caps: t.caps.effective, in_userns: t.caps.in_userns, seccomp: t.seccomp.mode != 0 }, t.tgid)
    })
}

/// A target: thread `id` (`process`: process `id`, its first live thread), as caller
/// process `me` sees it (`None`: no such live task).
fn target(id: u64, process: bool, me: u64) -> Option<Target> {
    let get = |t: &crate::task::Task| (t.state != crate::task::TaskState::Dead).then(|| (t.id.0, t.tgid, [t.uid, t.euid, t.suid], [t.gid, t.egid, t.sgid], t.service.is_some()));
    let got = {
        let mut s = crate::task::SCHEDULER.lock();
        if process {
            s.with_process(id, get).flatten()
        } else {
            s.with_task_mut(TaskId(id), |t| get(t)).flatten()
        }
    };
    let (tid, tgid, uid, gid, service) = got?;
    let same = tgid == me;
    Some(Target { tgid, tid, uid, gid, same, service, within: same || crate::compat::linux::ns::user_within(tgid, me), dumpable: mech::proc_attrs(tgid).dumpable })
}

/// The live task thread `tid` belongs to (`kcmp` names threads).
fn thread_tgid(tid: u64) -> Option<u64> {
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| (t.state != crate::task::TaskState::Dead).then_some(t.tgid)).flatten()
}

/// `process_vm_*`'s process: `pid` as caller process `me` names it (0: itself; a thread
/// id: its process).
fn vm_target(pid: u64, me: u64, init: Option<u64>) -> Result<u64, i64> {
    let pid = pid as i32;
    if pid < 0 {
        return Err(ESRCH);
    }
    if pid == 0 {
        return Ok(me);
    }
    let sys = mech::pid_from_view(pid as u64, init);
    if crate::compat::linux::proc::PROCS.lock().get(&sys).map_or(true, |p| p.zombie) {
        return thread_tgid(sys).ok_or(ESRCH);
    }
    Ok(sys)
}

/// The facts of call `nr` with arguments `a` made by thread `client`, as the kernel's code
/// will run it. `extra`: `perf_event_open`'s `PERF_KERNEL` bit (from the attribute, which
/// whoever asks has read). Errors are those the call itself gives before its permission
/// check (a missing target, a descriptor that is not a pidfd).
pub fn gather(nr: u64, a: &[u64; 6], client: u64, extra: u32) -> Result<Facts, i64> {
    let (who, me) = who_of(client).ok_or(ESRCH)?;
    let init = mech::pid_ns_init(me);
    let mut f = Facts { nr, who, ..Facts::default() };
    match nr {
        rules::NR_PTRACE => {
            f.kind = rules::ptrace_kind(a[0]);
            match f.kind {
                rules::K_ATTACH | rules::K_SEIZE => {
                    let tid = mech::pid_from_view(a[1] as i32 as i64 as u64, init);
                    f.t[0] = Some(target(tid, false, me).ok_or(ESRCH)?);
                    if f.kind == rules::K_SEIZE {
                        f.extra = a[3] as u32;
                    }
                }
                rules::K_TRACEME => f.t[0] = target(crate::compat::linux::proc::parent_of(me), true, me),
                rules::K_SETOPTIONS => f.extra = a[3] as u32,
                _ => return Err(EINVAL),
            }
        }
        rules::NR_PERF_EVENT_OPEN => {
            f.cpu = a[2] as i32;
            let class = match a[1] as i32 {
                0 => rules::PERF_PID_SELF,
                -1 => rules::PERF_PID_CPU,
                p if p > 0 => {
                    let sys = mech::pid_from_view(p as u64, init);
                    f.t[0] = crate::compat::linux::proc::tgid_of(sys).and_then(|g| target(g, true, me));
                    rules::PERF_PID_OTHER
                }
                _ => rules::PERF_PID_BAD,
            };
            f.extra = (extra & rules::PERF_KERNEL) | class << rules::PERF_PID_SHIFT;
        }
        rules::NR_PROCESS_VM_READV | rules::NR_PROCESS_VM_WRITEV => {
            let pid = vm_target(a[0], me, init)?;
            f.t[0] = Some(target(pid, true, me).ok_or(ESRCH)?);
        }
        rules::NR_KCMP => {
            for i in 0..2 {
                let p = a[i] as i32;
                if p <= 0 {
                    return Err(ESRCH);
                }
                let tid = mech::pid_from_view(p as u64, init);
                f.t[i] = Some(target(tid, false, me).ok_or(ESRCH)?);
            }
        }
        rules::NR_PIDFD_GETFD => {
            let fds = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()).ok_or(ESRCH)?;
            let pid = {
                let t = fds.lock();
                match crate::compat::linux::pidfd::pid_in(&t, a[0]) {
                    Some(p) => p,
                    None if t.get(a[0] as usize).is_none() => return Err(EBADF),
                    None => return Err(EINVAL),
                }
            };
            f.t[0] = Some(target(pid, true, me).ok_or(ESRCH)?);
        }
        _ => return Err(rules::ENOSYS),
    }
    Ok(f)
}

/// `LXP_TRACE_FACTS` for thread `client` (the request's caller): in `a[0]` the call number,
/// `a[1..7]` its arguments, `a[7]` the extra bit; out: the facts' words.
pub fn facts_op(client: u64, x: &mut LxProcIo) -> i64 {
    let a = x.a;
    let args: [u64; 6] = a[1..7].try_into().unwrap();
    match gather(a[0], &args, client, a[7] as u32) {
        Ok(f) => {
            x.a = f.encode();
            0
        }
        Err(e) => e,
    }
}

/// The permission check of call `nr` (arguments `a`, `extra` as for [`gather`]) by the
/// calling thread, where the kernel's code checks it: lx-proc's verdict if its mark was
/// given for these very facts, else the rule decided here.
pub fn check(nr: u64, a: &[u64; 6], extra: u32) -> Result<(), i64> {
    let tid = crate::compat::linux::proc::current_ids().0;
    let mark = mech::take_approval_mark(tid, nr);
    let f = gather(nr, a, tid, extra)?;
    if let Some(m) = mark {
        if let Some(v) = rules::verdict_of(m, &f.encode()) {
            USED.fetch_add(1, Ordering::Relaxed);
            if !LOGGED.swap(true, Ordering::Relaxed) {
                crate::kprintln!("[lx] tracing calls: lx-proc's verdicts in use (first: call {}, verdict {})", nr, v);
            }
            return if v == 0 { Ok(()) } else { Err(v) };
        }
        if !LOGGED_MISMATCH.swap(true, Ordering::Relaxed) {
            crate::kprintln!("[lx] tracing calls: an approval for call {} no longer matches the facts; decided by the kernel", nr);
        }
    }
    OWN.fetch_add(1, Ordering::Relaxed);
    rules::decide(&f)
}

/// The ptrace access rule for the calling thread on process `tgid` in `mode`
/// (`ptrace_rules::MODE_*`), decided here (callers that do not go through lx-proc: `/proc`
/// links, `migrate_pages`, `move_pages`, `process_madvise`, `prlimit` of the kernel copy).
pub fn may_access_mode(tgid: u64, mode: u32) -> Result<(), i64> {
    let tid = crate::compat::linux::proc::current_ids().0;
    let (who, me) = who_of(tid).ok_or(ESRCH)?;
    let t = target(tgid, true, me).ok_or(ESRCH)?;
    rules::may_access(mode, &who, &t)
}
