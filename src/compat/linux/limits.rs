//! Resource limits, priorities and memory locking.
//!
//! - **Resource limits** (`getrlimit`, `setrlimit`, `prlimit64`) are kept per process,
//!   inherited by children and kept across `execve`. Raising a hard limit needs
//!   `CAP_SYS_RESOURCE`; `RLIMIT_NOFILE` cannot pass the descriptor table's size (1024).
//!   Enforced: `RLIMIT_NOFILE` (descriptor allocation, `EMFILE`), `RLIMIT_NPROC` (fork,
//!   `EAGAIN`), `RLIMIT_FSIZE` (writes: `EFBIG` and `SIGXFSZ`), `RLIMIT_MEMLOCK` (`mlock`).
//! - **Priorities**: `setpriority`/`getpriority` (nice), `sched_setscheduler`, `setparam`,
//!   `getscheduler`, `getparam` share `sched_setattr`'s per-thread record and steer Hydra's
//!   scheduler: real-time policies and nice below -9 run at high priority, the idle policy
//!   and nice above 9 at low. Lowering nice or real-time policies need `CAP_SYS_NICE`
//!   (or `RLIMIT_NICE`/`RLIMIT_RTPRIO`).
//! - **I/O priorities** (`ioprio_set`/`ioprio_get`) are kept per thread (one I/O queue: no
//!   effect); the real-time class needs `CAP_SYS_ADMIN`.
//! - **mlock** family: ranges must be mapped; locked bytes count against `RLIMIT_MEMLOCK`
//!   (unless `CAP_IPC_LOCK`) and show as `VmLck`. Nothing is ever swapped out, so locking
//!   has no other effect.
//! - **sched_setaffinity**: the mask must include CPU 0, the only one.
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use super::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

const RLIM_INFINITY: u64 = u64::MAX;
const NLIMITS: usize = 16;
const RLIMIT_FSIZE: usize = 1;
const RLIMIT_STACK: usize = 3;
const RLIMIT_CORE: usize = 4;
const RLIMIT_NPROC: usize = 6;
const RLIMIT_NOFILE: usize = 7;
const RLIMIT_MEMLOCK: usize = 8;
const RLIMIT_SIGPENDING: usize = 11;
const RLIMIT_MSGQUEUE: usize = 12;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;

/// Ubuntu's defaults (`RLIMIT_NOFILE` capped by the descriptor table).
fn defaults() -> [(u64, u64); NLIMITS] {
    let mut l = [(RLIM_INFINITY, RLIM_INFINITY); NLIMITS];
    l[RLIMIT_STACK] = (8 << 20, RLIM_INFINITY);
    l[RLIMIT_CORE] = (0, RLIM_INFINITY);
    l[RLIMIT_NPROC] = (15_000, 15_000);
    l[RLIMIT_NOFILE] = (1024, crate::fs::MAX_FDS as u64);
    l[RLIMIT_MEMLOCK] = (8 << 20, 8 << 20);
    l[RLIMIT_SIGPENDING] = (15_000, 15_000);
    l[RLIMIT_MSGQUEUE] = (819_200, 819_200);
    l[RLIMIT_NICE] = (0, 0);
    l[RLIMIT_RTPRIO] = (0, 0);
    l
}

/// Per-process state.
#[derive(Clone)]
struct Proc {
    limits: [(u64, u64); NLIMITS],
    /// Locked ranges (`[start, end)`), and whether future mappings are locked.
    locked: Vec<(u64, u64)>,
    lock_future: bool,
}

static PROCS: Mutex<BTreeMap<u64, Proc>> = Mutex::new(BTreeMap::new());
/// I/O priorities by thread.
static IOPRIO: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

fn get(tgid: u64) -> Proc {
    PROCS.lock().get(&tgid).cloned().unwrap_or(Proc { limits: defaults(), locked: Vec::new(), lock_future: false })
}

fn put(tgid: u64, p: Proc) {
    PROCS.lock().insert(tgid, p);
}

fn cap(bit: u32) -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1u64 << bit) != 0).unwrap_or(false)
}

/// A new thread `child` of process `child_tgid` (a new process unless `thread`): it
/// inherits limits (a new process: a copy, without memory locks), scheduling attributes and
/// I/O priority.
pub fn on_clone(parent_tid: u64, parent_tgid: u64, child_tid: u64, child_tgid: u64, thread: bool) {
    if !thread {
        let mut p = get(parent_tgid);
        p.locked.clear();
        p.lock_future = false;
        put(child_tgid, p);
    }
    let io = IOPRIO.lock().get(&parent_tid).copied();
    if let Some(io) = io {
        IOPRIO.lock().insert(child_tid, io);
    }
    super::extra::sched_inherit(parent_tid, child_tid);
}

/// Process `pid` ended.
pub fn on_exit(pid: u64) {
    PROCS.lock().remove(&pid);
}

/// The calling process exec'd: memory locks go (limits stay).
pub fn on_exec(pid: u64) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        p.locked.clear();
        p.lock_future = false;
    }
}

/// The calling process's ID, without waiting for the scheduler (callers may hold it).
fn current_pid() -> Option<u64> {
    let mut s = crate::task::SCHEDULER.try_lock()?;
    s.current_task_mut(|t| t.tgid)
}

/// The calling process's soft `RLIMIT_NOFILE` (descriptors below it may be allocated).
pub fn nofile() -> usize {
    let Some(pid) = current_pid() else { return crate::fs::MAX_FDS };
    PROCS.lock().get(&pid).map_or(1024, |p| p.limits[RLIMIT_NOFILE].0.min(crate::fs::MAX_FDS as u64) as usize)
}

/// The calling process's soft `RLIMIT_FSIZE` (`u64::MAX`: none).
pub fn fsize() -> u64 {
    let Some(pid) = current_pid() else { return RLIM_INFINITY };
    PROCS.lock().get(&pid).map_or(RLIM_INFINITY, |p| p.limits[RLIMIT_FSIZE].0)
}

/// Whether the calling process may make another process (`RLIMIT_NPROC`).
pub fn may_fork() -> bool {
    if cap(24) || cap(21) {
        return true; // CAP_SYS_RESOURCE, CAP_SYS_ADMIN
    }
    let pid = super::proc::current_ids().1;
    let limit = get(pid).limits[RLIMIT_NPROC].0;
    if limit == RLIM_INFINITY {
        return true;
    }
    let uid = crate::task::with_current_task_mut(|t| t.uid).unwrap_or(0);
    if uid == 0 {
        return true;
    }
    (user_tasks(uid, true).len() as u64) < limit
}

/// The live threads (or, with `procs`, processes) of user `uid`.
fn user_tasks(uid: u32, procs: bool) -> Vec<u64> {
    let mut out = Vec::new();
    crate::task::SCHEDULER.lock().for_each_task_mut(|t| {
        if t.uid == uid && t.state != crate::task::TaskState::Dead && t.tgid != 0 && (!procs || t.id.0 == t.tgid) {
            out.push(t.id.0);
        }
    });
    out
}

// ----------------------------------------------------------------------
// Limits
// ----------------------------------------------------------------------

fn read_pair(ptr: u64) -> Result<(u64, u64), i64> {
    let b = copy_in(ptr, 16)?;
    Ok((u64::from_le_bytes(b[0..8].try_into().unwrap()), u64::from_le_bytes(b[8..16].try_into().unwrap())))
}

fn write_pair(ptr: u64, v: (u64, u64)) -> i64 {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&v.0.to_le_bytes());
    b[8..16].copy_from_slice(&v.1.to_le_bytes());
    copy_out(ptr, &b).map_or(EFAULT, |_| 0)
}

/// Sets limit `res` of process `tgid` to `new` (checked as Linux does).
fn set_limit(tgid: u64, res: usize, new: (u64, u64)) -> i64 {
    if new.0 > new.1 {
        return EINVAL;
    }
    let mut p = get(tgid);
    let old = p.limits[res];
    if new.1 > old.1 && !cap(24) {
        return EPERM;
    }
    if res == RLIMIT_NOFILE && new.1 > crate::fs::MAX_FDS as u64 && new.1 != old.1 {
        return EPERM; // past the descriptor table (Linux: fs.nr_open)
    }
    p.limits[res] = new;
    put(tgid, p);
    0
}

/// `getrlimit(resource, rlim)`, `setrlimit(resource, rlim)`, `prlimit64(pid, resource, new,
/// old)`.
pub fn rlimit(num: u64, a: [u64; 6]) -> i64 {
    let me = super::proc::current_ids().1;
    match num {
        97 => {
            if a[0] as usize >= NLIMITS {
                return EINVAL;
            }
            write_pair(a[1], get(me).limits[a[0] as usize])
        }
        160 => {
            if a[0] as usize >= NLIMITS {
                return EINVAL;
            }
            match read_pair(a[1]) {
                Ok(v) => set_limit(me, a[0] as usize, v),
                Err(e) => e,
            }
        }
        _ => {
            let res = a[1] as usize;
            if res >= NLIMITS {
                return EINVAL;
            }
            let target = match a[0] as i32 {
                0 => me,
                p if p > 0 => {
                    let sys = super::ns::pid_from_caller(p as u64);
                    match super::proc::tgid_of(sys) {
                        Some(t) => t,
                        None => return ESRCH,
                    }
                }
                _ => return ESRCH,
            };
            if target != me {
                // Another process: same credentials, or CAP_SYS_RESOURCE
                let ok = cap(24) || super::extra::may_access(target).is_ok();
                if !ok {
                    return EPERM;
                }
            }
            let new = if a[2] != 0 {
                match read_pair(a[2]) {
                    Ok(v) => Some(v),
                    Err(e) => return e,
                }
            } else {
                None
            };
            let old = get(target).limits[res];
            if let Some(n) = new {
                let r = set_limit(target, res, n);
                if r != 0 {
                    return r;
                }
            }
            if a[3] != 0 {
                return write_pair(a[3], old);
            }
            0
        }
    }
}

// ----------------------------------------------------------------------
// Priorities
// ----------------------------------------------------------------------

/// The threads `setpriority`/`getpriority` (`which`, `who`) name.
fn prio_targets(which: u64, who: u64) -> Result<Vec<u64>, i64> {
    let (tid, pid) = super::proc::current_ids();
    match which {
        // PRIO_PROCESS: a thread (0: the caller)
        0 => {
            if who == 0 {
                Ok(alloc::vec![tid])
            } else {
                let t = super::ns::pid_from_caller(who);
                if super::proc::tgid_of(t).is_some() { Ok(alloc::vec![t]) } else { Err(ESRCH) }
            }
        }
        // PRIO_PGRP: every thread of the group's processes
        1 => {
            let pgid = if who == 0 { super::proc::getpgid(0) as u64 } else { super::ns::pid_from_caller(who) };
            let tids: Vec<u64> = super::proc::group_members(pgid).iter().flat_map(|&p| super::proc::thread_ids_of(p)).collect();
            if tids.is_empty() { Err(ESRCH) } else { Ok(tids) }
        }
        // PRIO_USER: every thread of the user's processes
        2 => {
            let uid = if who == 0 { crate::task::with_current_task_mut(|t| t.uid).unwrap_or(0) } else { who as u32 };
            let tids = user_tasks(uid, false);
            let _ = pid;
            if tids.is_empty() { Err(ESRCH) } else { Ok(tids) }
        }
        _ => Err(EINVAL),
    }
}

/// `getpriority(which, who)`: 20 - the lowest nice of the threads named.
pub fn getpriority(which: u64, who: u64) -> i64 {
    match prio_targets(which, who) {
        Ok(t) => 20 - t.iter().map(|&x| super::extra::sched_of(x).1).min().unwrap_or(0) as i64,
        Err(e) => e,
    }
}

/// `setpriority(which, who, prio)`.
pub fn setpriority(which: u64, who: u64, prio: u64) -> i64 {
    let nice = (prio as i64 as i32).clamp(-20, 19);
    let targets = match prio_targets(which, who) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let me = super::proc::current_ids().1;
    let min_nice = 20 - get(me).limits[RLIMIT_NICE].0.min(40) as i32;
    for t in targets {
        let (policy, cur, rt, reset) = super::extra::sched_of(t);
        if nice < cur && nice < min_nice && !cap(23) {
            return EACCES;
        }
        super::extra::sched_set(t, policy, nice, rt, reset);
    }
    0
}

/// `sched_setscheduler(pid, policy, param)` and `sched_setparam(pid, param)` (`policy`
/// `None`).
pub fn sched_set(pid: u64, policy: Option<u64>, param: u64) -> i64 {
    let tid = match target_tid(pid) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let prio = match copy_in(param, 4) {
        Ok(b) => i32::from_le_bytes(b.try_into().unwrap()),
        Err(e) => return e,
    };
    let (cur_policy, nice, _, cur_reset) = super::extra::sched_of(tid);
    let (pol, reset) = match policy {
        Some(p) => ((p & !0x4000_0000) as u32, p & 0x4000_0000 != 0),
        None => (cur_policy, cur_reset),
    };
    let rt = matches!(pol, 1 | 2);
    match pol {
        0 | 3 | 5 => {
            if prio != 0 {
                return EINVAL;
            }
        }
        1 | 2 => {
            if !(1..=99).contains(&prio) {
                return EINVAL;
            }
        }
        _ => return EINVAL,
    }
    if rt && !cap(23) && prio as u64 > get(super::proc::current_ids().1).limits[RLIMIT_RTPRIO].0 {
        return EPERM;
    }
    super::extra::sched_set(tid, pol, nice, prio as u32, reset);
    0
}

/// `sched_getscheduler(pid)`.
pub fn sched_getscheduler(pid: u64) -> i64 {
    match target_tid(pid) {
        Ok(t) => {
            let (p, _, _, reset) = super::extra::sched_of(t);
            p as i64 | if reset { 0x4000_0000 } else { 0 }
        }
        Err(e) => e,
    }
}

/// `sched_getparam(pid, param)`.
pub fn sched_getparam(pid: u64, param: u64) -> i64 {
    match target_tid(pid) {
        Ok(t) => copy_out(param, &(super::extra::sched_of(t).2 as i32).to_le_bytes()).map_or(EFAULT, |_| 0),
        Err(e) => e,
    }
}

fn target_tid(pid: u64) -> Result<u64, i64> {
    match pid as i32 {
        0 => Ok(super::proc::current_ids().0),
        p if p > 0 => {
            let t = super::ns::pid_from_caller(p as u64);
            if super::proc::tgid_of(t).is_some() { Ok(t) } else { Err(ESRCH) }
        }
        _ => Err(EINVAL),
    }
}

/// `sched_setaffinity(pid, size, mask)`: CPU 0 must be in it.
pub fn sched_setaffinity(pid: u64, size: u64, mask: u64) -> i64 {
    if let Err(e) = target_tid(pid) {
        return e;
    }
    if size == 0 {
        return EINVAL;
    }
    match copy_in(mask, 1) {
        Ok(b) if b[0] & 1 != 0 => 0,
        Ok(_) => EINVAL,
        Err(e) => e,
    }
}

/// `ioprio_set(which, who, ioprio)` / `ioprio_get(which, who)`.
pub fn ioprio(num: u64, which: u64, who: u64, prio: u64) -> i64 {
    const IOPRIO_WHO_PROCESS: u64 = 1;
    const IOPRIO_WHO_PGRP: u64 = 2;
    const IOPRIO_WHO_USER: u64 = 3;
    let targets: Vec<u64> = match which {
        IOPRIO_WHO_PROCESS => match target_tid(who) {
            Ok(t) => alloc::vec![t],
            Err(e) => return e,
        },
        IOPRIO_WHO_PGRP | IOPRIO_WHO_USER => match prio_targets(which - 1, who) {
            Ok(t) => t,
            Err(e) => return e,
        },
        _ => return EINVAL,
    };
    if num == 252 {
        // The best of them; IOPRIO_CLASS_NONE and level 4 when never set
        return targets.iter().map(|t| IOPRIO.lock().get(t).copied().unwrap_or(4)).min().unwrap_or(4) as i64;
    }
    let class = (prio >> 13) & 7;
    let level = prio & 0x1fff;
    match class {
        0 => {}
        1 | 2 => {
            if level > 7 {
                return EINVAL;
            }
            if class == 1 && !cap(21) && !cap(23) {
                return EPERM;
            }
        }
        3 => {}
        _ => return EINVAL,
    }
    for t in targets {
        IOPRIO.lock().insert(t, prio as u32);
    }
    0
}

// ----------------------------------------------------------------------
// Memory locking
// ----------------------------------------------------------------------

fn locked_bytes(p: &Proc) -> u64 {
    p.locked.iter().map(|(s, e)| e - s).sum()
}

/// `VmLck` of process `tgid`, in KiB.
pub fn locked_kib(tgid: u64) -> u64 {
    PROCS.lock().get(&tgid).map_or(0, |p| locked_bytes(p) / 1024)
}

fn merge(v: &mut Vec<(u64, u64)>, s: u64, e: u64) {
    v.push((s, e));
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (a, b) in v.drain(..) {
        match out.last_mut() {
            Some(l) if a <= l.1 => l.1 = l.1.max(b),
            _ => out.push((a, b)),
        }
    }
    *v = out;
}

fn remove(v: &mut Vec<(u64, u64)>, s: u64, e: u64) {
    let mut out = Vec::new();
    for &(a, b) in v.iter() {
        if b <= s || a >= e {
            out.push((a, b));
            continue;
        }
        if a < s {
            out.push((a, s));
        }
        if b > e {
            out.push((e, b));
        }
    }
    *v = out;
}

/// Whether `[start, end)` is all mapped in the calling process.
fn mapped(start: u64, end: u64) -> bool {
    let Some(mm) = super::mm::current_mm() else { return false };
    let m = mm.lock();
    let mut at = start;
    while at < end {
        match m.find_vma(at) {
            Some(v) => at = v.end,
            None => return false,
        }
    }
    true
}

/// `mlock`, `munlock`, `mlockall`, `munlockall`, `mlock2`.
pub fn mlock(num: u64, a: [u64; 6]) -> i64 {
    const MCL_CURRENT: u64 = 1;
    const MCL_FUTURE: u64 = 2;
    const MCL_ONFAULT: u64 = 4;
    let pid = super::proc::current_ids().1;
    let mut p = get(pid);
    let limit = p.limits[RLIMIT_MEMLOCK].0;
    let unlimited = cap(14) || limit == RLIM_INFINITY; // CAP_IPC_LOCK
    match num {
        // mlock, munlock, mlock2
        149 | 150 | 325 => {
            if num == 325 && a[2] & !1 != 0 {
                return EINVAL; // MLOCK_ONFAULT only
            }
            let start = a[0] & !4095;
            let Some(end) = a[0].checked_add(a[1]).map(|e| (e + 4095) & !4095) else { return EINVAL };
            if a[1] == 0 {
                return 0;
            }
            if !mapped(start, end) {
                return ENOMEM;
            }
            if num == 150 {
                remove(&mut p.locked, start, end);
            } else {
                let mut next = p.locked.clone();
                merge(&mut next, start, end);
                let total: u64 = next.iter().map(|(s, e)| e - s).sum();
                if !unlimited && total > limit {
                    return if limit == 0 { EPERM } else { ENOMEM };
                }
                p.locked = next;
            }
        }
        // mlockall
        151 => {
            let f = a[0];
            if f == 0 || f & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 || f == MCL_ONFAULT {
                return EINVAL;
            }
            if f & MCL_CURRENT != 0 {
                let Some(mm) = super::mm::current_mm() else { return ENOMEM };
                let areas: Vec<(u64, u64)> = mm.lock().vmas().map(|v| (v.start, v.end)).collect();
                let mut next = p.locked.clone();
                for (s, e) in areas {
                    merge(&mut next, s, e);
                }
                let total: u64 = next.iter().map(|(s, e)| e - s).sum();
                if !unlimited && total > limit {
                    return if limit == 0 { EPERM } else { ENOMEM };
                }
                p.locked = next;
            }
            p.lock_future = f & MCL_FUTURE != 0;
        }
        // munlockall
        _ => {
            p.locked.clear();
            p.lock_future = false;
        }
    }
    let _ = EAGAIN;
    put(pid, p);
    0
}

/// `/proc/<pid>/limits`.
pub fn limits_text(tgid: u64) -> alloc::string::String {
    const NAMES: [(&str, &str); NLIMITS] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let l = get(tgid).limits;
    let v = |x: u64| if x == RLIM_INFINITY { alloc::string::String::from("unlimited") } else { alloc::format!("{}", x) };
    let mut s = alloc::format!("{:<25} {:<20} {:<20} {:<10}\n", "Limit", "Soft Limit", "Hard Limit", "Units");
    for (i, (name, unit)) in NAMES.iter().enumerate() {
        s.push_str(&alloc::format!("{:<25} {:<20} {:<20} {:<10}\n", name, v(l[i].0), v(l[i].1), unit));
    }
    s
}
