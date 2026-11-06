//! Smaller system calls:
//!
//! - NUMA memory policy (`mbind`, `set_mempolicy`, `migrate_pages`, `move_pages`,
//!   `set_mempolicy_home_node`): Hydra has one memory node, node 0; requests naming
//!   other nodes fail as on a single-node Linux machine.
//! - `readahead`, `cachestat`: file data is served by the pool, so every page counts as
//!   cached.
//! - `mseal`: arguments and the mapping are checked; sealing is not enforced.
//! - `kcmp`: compares the kernel objects behind two processes' resources.
//! - `sched_setattr`, `sched_getattr`: policy and nice value are recorded per thread.
//! - `process_vm_readv`, `process_vm_writev`: copy between address spaces (ptrace access
//!   rules).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::fs::FileDescriptor;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const E2BIG: i64 = -7;
const EOPNOTSUPP: i64 = -95;

const PAGE: u64 = 4096;

const CAP_SYS_PTRACE: u64 = 1 << 19;
const CAP_SYS_NICE: u64 = 1 << 23;

fn has_cap(bit: u64) -> bool {
    crate::task::with_current_task_mut(|t| t.caps.has(bit)).unwrap_or(false)
}

/// Dispatches the calls of this module.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    Some(match num {
        187 => readahead(a[0]),
        237 => mbind(a[0], a[1], a[2], a[3], a[4], a[5]),
        238 => set_mempolicy(a[0], a[1], a[2]),
        256 => migrate_pages(a[0], a[1], a[2], a[3]),
        279 => move_pages(a[0], a[1], a[2], a[3], a[4], a[5]),
        310 => process_vm(a[0], a[1], a[2], a[3], a[4], a[5], false),
        311 => process_vm(a[0], a[1], a[2], a[3], a[4], a[5], true),
        312 => kcmp(a[0], a[1], a[2], a[3], a[4]),
        314 => sched_setattr(a[0], a[1], a[2]),
        315 => sched_getattr(a[0], a[1], a[2], a[3]),
        450 => set_mempolicy_home_node(a[0], a[1], a[2], a[3]),
        451 => cachestat(a[0], a[1], a[2], a[3]),
        462 => mseal(a[0], a[1], a[2]),
        _ => return None,
    })
}

// ----------------------------------------------------------------------
// Processes
// ----------------------------------------------------------------------

/// The system PID of a PID argument (0: the caller); ESRCH if there is none.
fn target_pid(pid: u64) -> Result<u64, i64> {
    let pid = pid as i32;
    if pid < 0 {
        return Err(ESRCH);
    }
    if pid == 0 {
        return Ok(super::proc::current_ids().1);
    }
    let sys = super::ns::pid_from_caller(pid as u64);
    if super::proc::PROCS.lock().get(&sys).map_or(true, |p| p.zombie) {
        // Maybe a thread ID: its process
        return crate::task::SCHEDULER.lock().with_process(sys, |t| t.tgid).ok_or(ESRCH);
    }
    Ok(sys)
}

/// Ptrace-style access check (`PTRACE_MODE_ATTACH_REALCREDS`): same real, effective and
/// saved user IDs, or `CAP_SYS_PTRACE`.
pub(crate) fn may_access(pid: u64) -> Result<(), i64> {
    let target = crate::task::SCHEDULER.lock().with_process(pid, |t| (t.uid, t.euid, t.suid, t.service.is_some()));
    let Some((uid, euid, suid, service)) = target else { return Err(ESRCH) };
    if pid == super::proc::current_ids().1 {
        return Ok(());
    }
    if service {
        return Err(EPERM);
    }
    let me = crate::task::with_current_task_mut(|t| t.uid).unwrap_or(u32::MAX);
    if has_cap(CAP_SYS_PTRACE) || (me == uid && me == euid && me == suid) {
        Ok(())
    } else {
        Err(EPERM)
    }
}

// ----------------------------------------------------------------------
// NUMA policy
// ----------------------------------------------------------------------

const MPOL_MAX: u64 = 6;
const MPOL_MODE_FLAGS: u64 = (1 << 15) | (1 << 14) | (1 << 13);

/// Checks a policy mode and node mask: only node 0 exists.
fn check_policy(mode: u64, nodemask: u64, maxnode: u64) -> Result<(), i64> {
    let base = mode & !MPOL_MODE_FLAGS;
    if base > MPOL_MAX || mode & 0xC000 == 0xC000 {
        return Err(EINVAL);
    }
    let nodes = read_nodemask(nodemask, maxnode)?;
    if nodes & !1 != 0 {
        return Err(EINVAL);
    }
    // MPOL_DEFAULT and MPOL_LOCAL take no nodes; BIND, INTERLEAVE and PREFERRED_MANY need some
    match base {
        0 | 4 if nodes != 0 => Err(EINVAL),
        2 | 3 | 5 | 6 if nodes == 0 => Err(EINVAL),
        _ => Ok(()),
    }
}

/// The first word of a node mask (`maxnode` bits at `ptr`); bits past node 63 must be clear.
fn read_nodemask(ptr: u64, maxnode: u64) -> Result<u64, i64> {
    if ptr == 0 || maxnode <= 1 {
        return Ok(0);
    }
    let bits = maxnode - 1;
    if bits > 1024 * 8 {
        return Err(EINVAL);
    }
    let words = bits.div_ceil(64) as usize;
    let raw = copy_in(ptr, words * 8)?;
    let mut first = 0u64;
    for (i, w) in raw.chunks(8).enumerate() {
        let mut v = u64::from_le_bytes(w.try_into().unwrap());
        let valid = bits.saturating_sub(i as u64 * 64);
        if valid < 64 {
            v &= (1u64 << valid) - 1;
        }
        if i == 0 {
            first = v;
        } else if v != 0 {
            return Err(EINVAL);
        }
    }
    Ok(first)
}

fn mbind(addr: u64, len: u64, mode: u64, nodemask: u64, maxnode: u64, flags: u64) -> i64 {
    // MPOL_MF_STRICT, MPOL_MF_MOVE, MPOL_MF_MOVE_ALL
    if flags & !7 != 0 || addr % PAGE != 0 {
        return EINVAL;
    }
    if flags & 4 != 0 && !has_cap(CAP_SYS_NICE) {
        return EPERM;
    }
    if let Err(e) = check_policy(mode, nodemask, maxnode) {
        return e;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = addr.checked_add(len.div_ceil(PAGE) * PAGE) else { return EINVAL };
    if !range_mapped(addr, end) {
        return EFAULT;
    }
    0
}

fn set_mempolicy(mode: u64, nodemask: u64, maxnode: u64) -> i64 {
    match check_policy(mode, nodemask, maxnode) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn set_mempolicy_home_node(start: u64, len: u64, home: u64, flags: u64) -> i64 {
    if flags != 0 || start % PAGE != 0 || home != 0 {
        return EINVAL;
    }
    let Some(end) = start.checked_add(len.div_ceil(PAGE) * PAGE) else { return EINVAL };
    if len != 0 && !range_mapped(start, end) {
        return EFAULT;
    }
    0
}

/// `migrate_pages`: every page is already on node 0; returns the pages not moved (0).
fn migrate_pages(pid: u64, maxnode: u64, old: u64, new: u64) -> i64 {
    let pid = match target_pid(pid) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if let Err(e) = may_access(pid) {
        return e;
    }
    for mask in [old, new] {
        match read_nodemask(mask, maxnode) {
            Ok(n) if n & !1 != 0 => return EINVAL,
            Err(e) => return e,
            _ => {}
        }
    }
    0
}

/// `move_pages`: pages can only be on (and moved to) node 0.
fn move_pages(pid: u64, count: u64, pages: u64, nodes: u64, status: u64, flags: u64) -> i64 {
    // MPOL_MF_MOVE, MPOL_MF_MOVE_ALL
    if flags & !6 != 0 {
        return EINVAL;
    }
    if flags & 4 != 0 && !has_cap(CAP_SYS_NICE) {
        return EPERM;
    }
    let pid = match target_pid(pid) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if let Err(e) = may_access(pid) {
        return e;
    }
    if count == 0 {
        return 0;
    }
    if count > 1 << 20 {
        return E2BIG;
    }
    let addrs = match copy_in(pages, count as usize * 8) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let wanted = if nodes != 0 {
        match copy_in(nodes, count as usize * 4) {
            Ok(n) => Some(n),
            Err(e) => return e,
        }
    } else {
        None
    };
    let mm = crate::task::SCHEDULER.lock().with_process(pid, |t| t.mm.clone()).flatten();
    let mut out = Vec::with_capacity(count as usize * 4);
    for i in 0..count as usize {
        let addr = u64::from_le_bytes(addrs[i * 8..i * 8 + 8].try_into().unwrap());
        let mapped = mm.as_ref().map_or(true, |m| m.lock().vmas().any(|v| v.start <= addr && addr < v.end));
        let st: i32 = if let Some(n) = &wanted {
            let node = i32::from_le_bytes(n[i * 4..i * 4 + 4].try_into().unwrap());
            if node != 0 {
                // A target node that is not online fails the call
                return ENODEV;
            } else if !mapped {
                EFAULT as i32
            } else {
                0
            }
        } else if mapped {
            0
        } else {
            EFAULT as i32
        };
        out.extend_from_slice(&st.to_le_bytes());
    }
    match copy_out(status, &out) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Whether `[start, end)` of the caller's address space is covered by mappings.
fn range_mapped(start: u64, end: u64) -> bool {
    let Some(mm) = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten() else { return true };
    let mm = mm.lock();
    let mut at = start;
    for v in mm.vmas() {
        if v.end <= at {
            continue;
        }
        if v.start > at {
            return false;
        }
        at = v.end;
        if at >= end {
            return true;
        }
    }
    at >= end
}

// ----------------------------------------------------------------------
// Files
// ----------------------------------------------------------------------

/// The size of a regular file descriptor (`None`: not a regular file).
fn file_size(fd: u64) -> Result<Option<u64>, i64> {
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());
    match desc {
        None => Err(EBADF),
        Some(FileDescriptor::Vnode(f)) => {
            let ino = f.lock().ino;
            let attr = crate::fs::client::ZfsClient::getattr(ino)?;
            Ok(if attr.mode & 0o170000 == 0o100000 { Some(attr.size) } else { None })
        }
        Some(FileDescriptor::MemFd { memfd, .. }) => Ok(Some(memfd.lock().size() as u64)),
        Some(_) => Ok(None),
    }
}

fn readahead(fd: u64) -> i64 {
    match file_size(fd) {
        Ok(Some(_)) => 0,
        Ok(None) => EINVAL,
        Err(e) => e,
    }
}

/// `cachestat`: all of a file's pages count as cached.
fn cachestat(fd: u64, range: u64, cstat: u64, flags: u64) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    let raw = match copy_in(range, 16) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let off = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let size = match file_size(fd) {
        Ok(Some(s)) => s,
        // Pipes and sockets have no page cache
        Ok(None) => return ESPIPE,
        Err(e) => return e,
    };
    let first = off / PAGE;
    let last = if len == 0 { u64::MAX } else { off.saturating_add(len - 1) / PAGE };
    let pages = size.div_ceil(PAGE);
    let cached = if first >= pages { 0 } else { last.min(pages - 1) - first + 1 };
    let mut out = [0u8; 40];
    out[0..8].copy_from_slice(&cached.to_le_bytes());
    match copy_out(cstat, &out) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ----------------------------------------------------------------------
// Memory
// ----------------------------------------------------------------------

/// `mseal`: checks the arguments and that the range is mapped.
fn mseal(addr: u64, len: u64, flags: u64) -> i64 {
    if flags != 0 || addr % PAGE != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = addr.checked_add(len.div_ceil(PAGE) * PAGE) else { return EINVAL };
    if end > 0x0000_8000_0000_0000 {
        return EINVAL;
    }
    if !range_mapped(addr, end) {
        return ENOMEM;
    }
    0
}

/// `process_vm_readv` / `process_vm_writev`.
fn process_vm(pid: u64, liov: u64, lcnt: u64, riov: u64, rcnt: u64, flags: u64, write: bool) -> i64 {
    const IOV_MAX: u64 = 1024;
    if flags != 0 || lcnt > IOV_MAX || rcnt > IOV_MAX {
        return EINVAL;
    }
    let read_iov = |ptr: u64, n: u64| -> Result<Vec<(u64, u64)>, i64> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let raw = copy_in(ptr, n as usize * 16)?;
        Ok(raw
            .chunks(16)
            .map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap())))
            .filter(|&(_, l)| l > 0)
            .collect())
    };
    let local = match read_iov(liov, lcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let remote = match read_iov(riov, rcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let pid = match target_pid(pid) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if let Err(e) = may_access(pid) {
        return e;
    }
    let Some(mm) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.mm.clone()).flatten() else { return ESRCH };
    let mut done: u64 = 0;
    let (mut li, mut loff) = (0usize, 0u64);
    'remote: for &(rbase, rlen) in &remote {
        let mut roff = 0;
        while roff < rlen {
            if li >= local.len() {
                break 'remote;
            }
            let (lbase, llen) = local[li];
            let raddr = rbase.wrapping_add(roff);
            let laddr = lbase.wrapping_add(loff);
            // One step stays within a remote page and the current local segment
            let n = (rlen - roff).min(llen - loff).min(PAGE - raddr % PAGE).min(4096);
            let ok = if write {
                match copy_in(laddr, n as usize) {
                    Ok(data) => remote_copy(&mm, raddr, Some(&data), n).is_some(),
                    Err(e) => return if done == 0 { e } else { done as i64 },
                }
            } else {
                match remote_copy(&mm, raddr, None, n) {
                    Some(data) => {
                        if let Err(e) = copy_out(laddr, &data) {
                            return if done == 0 { e } else { done as i64 };
                        }
                        true
                    }
                    None => false,
                }
            };
            if !ok {
                // A remote fault ends the transfer (after the bytes already copied)
                break 'remote;
            }
            done += n;
            roff += n;
            loff += n;
            if loff == llen {
                li += 1;
                loff = 0;
            }
        }
    }
    if done == 0 && !remote.is_empty() && !local.is_empty() {
        return EFAULT;
    }
    done as i64
}

/// Reads (`data` = None) or writes `n` bytes at `addr` of address space `mm`, within one page.
fn remote_copy(mm: &Arc<Mutex<crate::memory::vm::Mm>>, addr: u64, data: Option<&[u8]>, n: u64) -> Option<Vec<u8>> {
    if addr >= 0x0000_8000_0000_0000 || addr.checked_add(n)? > 0x0000_8000_0000_0000 {
        return None;
    }
    let mut m = mm.lock();
    m.prefault(addr, n, data.is_some()).ok()?;
    let phys = m.translate(addr)?.as_u64();
    // Physical memory is identity-mapped in the kernel
    let ptr = phys as *mut u8;
    unsafe {
        match data {
            Some(d) => {
                core::ptr::copy_nonoverlapping(d.as_ptr(), ptr, n as usize);
                Some(Vec::new())
            }
            None => Some(core::slice::from_raw_parts(ptr, n as usize).to_vec()),
        }
    }
}

// ----------------------------------------------------------------------
// kcmp
// ----------------------------------------------------------------------

/// Identity of the object behind a descriptor (0: none shared).
fn desc_ident(d: &FileDescriptor) -> usize {
    match d {
        FileDescriptor::PipeRead(a) | FileDescriptor::PipeWrite(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Socket(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Epoll(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::EventFd(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::MemFd { memfd, .. } => Arc::as_ptr(memfd) as *const u8 as usize,
        FileDescriptor::Vnode(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Inet(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Pty(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::SignalFd(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Unix(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::TimerFd(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Inotify(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::PidFd(a) => Arc::as_ptr(a) as *const u8 as usize,
        FileDescriptor::Device(a) => Arc::as_ptr(a) as *const u8 as usize,
        _ => 0,
    }
}

/// `kcmp`: 0 if both refer to the same object, otherwise 1 or 2 by an arbitrary but
/// consistent order.
fn kcmp(pid1: u64, pid2: u64, kind: u64, idx1: u64, idx2: u64) -> i64 {
    const KCMP_FILE: u64 = 0;
    const KCMP_VM: u64 = 1;
    const KCMP_FILES: u64 = 2;
    const KCMP_FS: u64 = 3;
    const KCMP_SIGHAND: u64 = 4;
    const KCMP_IO: u64 = 5;
    const KCMP_SYSVSEM: u64 = 6;
    const KCMP_EPOLL_TFD: u64 = 7;
    if kind > KCMP_EPOLL_TFD {
        return EINVAL;
    }
    // Thread IDs are allowed: their tasks are looked up directly
    let resolve = |p: u64| -> Result<u64, i64> {
        let p = p as i32;
        if p <= 0 {
            return Err(ESRCH);
        }
        Ok(super::ns::pid_from_caller(p as u64))
    };
    let (a, b) = match (resolve(pid1), resolve(pid2)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let info = |tid: u64| crate::task::SCHEDULER.lock().with_process(tid, |t| (t.tgid, t.fds.clone(), t.mm.clone()));
    let (Some((ga, fa, ma)), Some((gb, fb, mb))) = (info(a), info(b)) else { return ESRCH };
    for g in [ga, gb] {
        if let Err(e) = may_access(g) {
            return e;
        }
    }
    let order = |x: usize, y: usize| -> i64 {
        if x == y {
            0
        } else if x < y {
            1
        } else {
            2
        }
    };
    let fds_ptr = |f: &crate::fs::SharedFdTable| Arc::as_ptr(f) as *const u8 as usize;
    match kind {
        KCMP_FILE => {
            let da = fa.lock().get(idx1 as usize).cloned();
            let db = fb.lock().get(idx2 as usize).cloned();
            let (Some(da), Some(db)) = (da, db) else { return EBADF };
            let (ia, ib) = (desc_ident(&da), desc_ident(&db));
            if ia == 0 || ib == 0 {
                // Unshared kinds (console, plain files): the same only as the same descriptor
                if ga == gb && idx1 == idx2 && fds_ptr(&fa) == fds_ptr(&fb) {
                    0
                } else {
                    order(ga as usize * 65536 + idx1 as usize, gb as usize * 65536 + idx2 as usize).max(1)
                }
            } else {
                order(ia, ib)
            }
        }
        KCMP_VM => {
            let p = |m: &Option<Arc<Mutex<crate::memory::vm::Mm>>>| m.as_ref().map_or(0, |m| Arc::as_ptr(m) as *const u8 as usize);
            order(p(&ma), p(&mb))
        }
        // Root and working directory live in the descriptor table here
        KCMP_FILES | KCMP_FS => order(fds_ptr(&fa), fds_ptr(&fb)),
        KCMP_SIGHAND | KCMP_IO | KCMP_SYSVSEM => order(ga as usize, gb as usize),
        _ => EOPNOTSUPP,
    }
}

// ----------------------------------------------------------------------
// sched_setattr / sched_getattr
// ----------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct SchedAttr {
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
    util_min: u32,
    util_max: u32,
}

/// Recorded attributes by thread ID (threads without an entry: SCHED_OTHER, nice 0)
static SCHED: Mutex<BTreeMap<u64, SchedAttr>> = Mutex::new(BTreeMap::new());

const SCHED_ATTR_SIZE_VER0: u32 = 48;
const SCHED_ATTR_SIZE_VER1: u32 = 56;

fn sched_target(pid: u64) -> Result<u64, i64> {
    let pid = pid as i32;
    if pid < 0 {
        return Err(EINVAL);
    }
    if pid == 0 {
        return Ok(super::proc::current_ids().0);
    }
    let tid = super::ns::pid_from_caller(pid as u64);
    if crate::task::SCHEDULER.lock().with_process(tid, |_| ()).is_none() {
        return Err(ESRCH);
    }
    Ok(tid)
}

fn sched_setattr(pid: u64, uattr: u64, flags: u64) -> i64 {
    if flags != 0 || uattr == 0 {
        return EINVAL;
    }
    let head = match copy_in(uattr, 4) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let mut size = u32::from_le_bytes(head[..4].try_into().unwrap());
    if size == 0 {
        size = SCHED_ATTR_SIZE_VER0;
    }
    if size < SCHED_ATTR_SIZE_VER0 || size > 4096 {
        let _ = copy_out(uattr, &SCHED_ATTR_SIZE_VER1.to_le_bytes());
        return E2BIG;
    }
    let raw = match copy_in(uattr, size as usize) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // Fields this kernel does not know must be zero
    if raw.len() > SCHED_ATTR_SIZE_VER1 as usize && raw[SCHED_ATTR_SIZE_VER1 as usize..].iter().any(|&b| b != 0) {
        let _ = copy_out(uattr, &SCHED_ATTR_SIZE_VER1.to_le_bytes());
        return E2BIG;
    }
    let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
    let mut attr = SchedAttr {
        policy: u32_at(4),
        flags: u64_at(8),
        nice: u32_at(16) as i32,
        priority: u32_at(20),
        runtime: u64_at(24),
        deadline: u64_at(32),
        period: u64_at(40),
        util_min: 0,
        util_max: 1024,
    };
    if raw.len() >= SCHED_ATTR_SIZE_VER1 as usize {
        attr.util_min = u32_at(48);
        attr.util_max = u32_at(52);
    }
    // RESET_ON_FORK, RECLAIM, DL_OVERRUN, KEEP_POLICY, KEEP_PARAMS, UTIL_CLAMP_MIN/MAX
    if attr.flags & !0x7f != 0 {
        return EINVAL;
    }
    let tid = match sched_target(pid) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let old = SCHED.lock().get(&tid).copied().unwrap_or_default();
    if attr.flags & 0x08 != 0 {
        attr.policy = old.policy;
    }
    if attr.flags & 0x10 != 0 {
        attr.nice = old.nice;
        attr.priority = old.priority;
    }
    if attr.flags & 0x60 != 0 && (attr.util_min > attr.util_max || attr.util_max > 1024) {
        return EINVAL;
    }
    let privileged = has_cap(CAP_SYS_NICE);
    match attr.policy {
        // SCHED_OTHER, SCHED_BATCH, SCHED_IDLE
        0 | 3 | 5 => {
            if attr.priority != 0 || !(-20..=19).contains(&attr.nice) {
                return EINVAL;
            }
            if attr.nice < old.nice && !privileged {
                return EPERM;
            }
        }
        // SCHED_FIFO, SCHED_RR
        1 | 2 => {
            if !(1..=99).contains(&attr.priority) {
                return EINVAL;
            }
            if !privileged {
                return EPERM;
            }
        }
        // SCHED_DEADLINE
        6 => {
            let period = if attr.period == 0 { attr.deadline } else { attr.period };
            if attr.runtime < 1024 || attr.runtime > attr.deadline || attr.deadline > period {
                return EINVAL;
            }
            if !privileged {
                return EPERM;
            }
        }
        _ => return EINVAL,
    }
    // Another user's thread needs CAP_SYS_NICE
    let (me, them) = (
        crate::task::with_current_task_mut(|t| t.euid).unwrap_or(u32::MAX),
        crate::task::SCHEDULER.lock().with_process(tid, |t| t.uid).unwrap_or(u32::MAX),
    );
    if me != them && me != 0 && !privileged {
        return EPERM;
    }
    SCHED.lock().insert(tid, attr);
    0
}

fn sched_getattr(pid: u64, uattr: u64, size: u64, flags: u64) -> i64 {
    if flags != 0 || uattr == 0 || size < SCHED_ATTR_SIZE_VER0 as u64 || size > 4096 {
        return EINVAL;
    }
    let tid = match sched_target(pid) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let mut a = {
        let mut all = SCHED.lock();
        // Drop the records of threads that are gone
        if all.len() > 64 {
            let sched = crate::task::SCHEDULER.lock();
            all.retain(|t, _| sched.with_process(*t, |_| ()).is_some());
        }
        all.get(&tid).copied().unwrap_or_default()
    };
    if a.util_max == 0 && a.policy == 0 && a.flags == 0 {
        a.util_max = 1024;
    }
    let n = (size as u32).min(SCHED_ATTR_SIZE_VER1);
    let mut out = Vec::with_capacity(n as usize);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&a.policy.to_le_bytes());
    out.extend_from_slice(&(a.flags & 0x07).to_le_bytes());
    out.extend_from_slice(&a.nice.to_le_bytes());
    out.extend_from_slice(&a.priority.to_le_bytes());
    out.extend_from_slice(&a.runtime.to_le_bytes());
    out.extend_from_slice(&a.deadline.to_le_bytes());
    out.extend_from_slice(&a.period.to_le_bytes());
    out.extend_from_slice(&a.util_min.to_le_bytes());
    out.extend_from_slice(&a.util_max.to_le_bytes());
    out.truncate(n as usize);
    match copy_out(uattr, &out) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
