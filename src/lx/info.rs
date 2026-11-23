//! # Info primitives for the pseudo file systems (wave 7, Group 7-4)
//!
//! linux-server serves `/proc` and `/sys` (the file service redirects lookups under them
//! there, `docs/vfs-design.md` section 5). Most of what those files show is kept by
//! linux-server or can be computed there; what only the kernel knows comes from these
//! `SYS_LX_OBJ` operations (linux-server's host only):
//!
//! | Operation | Answer |
//! |---|---|
//! | `LX_INFO_TASK (id, pid \| tid << 32, *LxTaskInfo)` | a process and one of its threads: ids, state, times, memory, `comm` |
//! | `LX_INFO_SYS (*LxSysInfo)` | uptime, CPU times, load, task counts, memory, swap, boot time |
//! | `LX_INFO_ARGS (id, pid \| len << 32, buf)` | the `cmdline` bytes |
//! | `LX_INFO_MAPS (id, pid \| len << 32, buf)` | the memory areas ([`LxMapEntry`] records with names) |
//! | `LX_INFO_PIDS (buf, n)` | the process IDs |
//! | `LX_INFO_EFIVAR (name, name_len \| len << 32, buf)` | a UEFI variable (attributes, then data) |
//!
//! Process IDs are named as the request's caller sees them (its PID namespace: only the
//! init of a namespace is renumbered, to 1, as in `compat::linux::ns`); 0 is the caller.
//!
//! The decisions and encodings above the kernel's data (PID translation, the `ptrace` read
//! rule, the map records, `comm`, the `cmdline` rule) are plain functions, host-tested in
//! `tests/host-w7-40`; the gathering from the kernel's tables is in [`glue`] (kernel only).

use alloc::vec::Vec;

use crate::ipc::protocol::{LxMapEntry, LX_MAP_SHARED};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;

/// `CAP_SYS_PTRACE`.
pub const CAP_SYS_PTRACE: u64 = 1 << 19;

/// A process ID as caller names it (`who`; 0: the caller `caller_tgid`), as a system-wide
/// ID. `init`: the init of the caller's PID namespace (`None`: the first namespace).
pub fn resolve_pid(who: u64, caller_tgid: u64, init: Option<u64>) -> u64 {
    match (who, init) {
        (0, _) => caller_tgid,
        (1, Some(i)) => i,
        (w, _) => w,
    }
}

/// A system-wide ID as a caller whose PID namespace's init is `init` sees it.
pub fn to_caller(id: u64, init: Option<u64>) -> u64 {
    match init {
        Some(i) if i == id => 1,
        _ => id,
    }
}

/// Whether a caller may read another process's memory facts (`maps`; `cmdline` is open to
/// all): Linux's `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`: itself; never a service's
/// process; with `CAP_SYS_PTRACE`; or when the caller's file-system user ID (here the
/// effective one) is the target's real, effective and saved user ID **and** its file-system
/// group ID the target's real, effective and saved group ID (a set-group-ID program is not
/// readable by its user).
pub fn may_see(same: bool, target_service: bool, caller: (u32, u32), caller_caps: u64, target_uids: (u32, u32, u32), target_gids: (u32, u32, u32)) -> bool {
    if same {
        return true;
    }
    if target_service {
        return false;
    }
    let (u, g) = caller;
    caller_caps & CAP_SYS_PTRACE != 0
        || (u == target_uids.0 && u == target_uids.1 && u == target_uids.2 && g == target_gids.0 && g == target_gids.1 && g == target_gids.2)
}

/// Whether the info primitives answer for a caller (`init`: its PID namespace's init, `None`
/// in the first; `in_userns`: it is in a user namespace of its own) about a target (a
/// service's process or not): only callers in the first PID and user namespace (linux-server
/// sends the others' `/proc` to the kernel, which translates their IDs), never about a
/// service (`ESRCH`: services are not Linux processes).
pub fn may_query(init: Option<u64>, in_userns: bool, target_service: bool) -> Result<(), i64> {
    if init.is_some() || in_userns {
        return Err(EPERM);
    }
    if target_service {
        return Err(ESRCH);
    }
    Ok(())
}

/// `comm` of an executable path: its file name, at most 15 bytes, NUL-padded.
pub fn comm_of(exe: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let name = exe.rsplit('/').next().unwrap_or("");
    // (whole characters, as the kernel's `chars().take(15)` text, cut to 15 bytes)
    let mut n = 0;
    for ch in name.chars().take(15) {
        let mut b = [0u8; 4];
        let s = ch.encode_utf8(&mut b);
        if n + s.len() > 15 {
            break;
        }
        out[n..n + s.len()].copy_from_slice(s.as_bytes());
        n += s.len();
    }
    out
}

/// The `cmdline` rule (Linux's): `args` is the argument area as it is now; when it ends with
/// its NUL it is the answer; otherwise (`setproctitle` overwrote the final NUL) the text runs
/// on into `env` (the start of the environment) and stops after the first NUL.
pub fn cmdline_rule(mut args: Vec<u8>, env: &[u8]) -> Vec<u8> {
    // (an empty area is empty: the environment is never shown alone)
    if args.is_empty() || args.last() == Some(&0) {
        return args;
    }
    args.extend_from_slice(env);
    if let Some(nul) = args.iter().position(|&b| b == 0) {
        args.truncate(nul + 1);
    }
    args
}

/// One memory area as [`encode_maps`] takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Area<'a> {
    /// First address.
    pub start: u64,
    /// Address after the last.
    pub end: u64,
    /// Offset in the mapped object (bytes).
    pub offset: u64,
    /// `PROT_READ` (1), `PROT_WRITE` (2), `PROT_EXEC` (4).
    pub prot: u32,
    /// `MAP_SHARED`.
    pub shared: bool,
    /// What `maps` shows after the numbers (a path, `[stack]`, ...).
    pub name: Option<&'a str>,
}

/// The size of a record for an area named `name_len` bytes (header, name, padding to 8).
pub fn record_len(name_len: usize) -> usize {
    (core::mem::size_of::<LxMapEntry>() + name_len + 7) & !7
}

/// `LX_INFO_MAPS`'s answer for `areas` in a buffer of `cap` bytes: the records that fit
/// (whole), and the length all of them need.
pub fn encode_maps(areas: &[Area], cap: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut total = 0;
    let mut full = false;
    for a in areas {
        let name = a.name.unwrap_or("").as_bytes();
        // (a name longer than 4095 bytes is cut, as a path is)
        let name = &name[..name.len().min(4095)];
        let len = record_len(name.len());
        total += len;
        if full || out.len() + len > cap {
            full = true;
            continue;
        }
        let e = LxMapEntry {
            start: a.start,
            end: a.end,
            offset: a.offset,
            flags: (a.prot & 7) | if a.shared { LX_MAP_SHARED } else { 0 },
            name_len: name.len() as u32,
        };
        // SAFETY: `LxMapEntry` is plain integers (repr C)
        let raw = unsafe { core::slice::from_raw_parts(&e as *const LxMapEntry as *const u8, core::mem::size_of::<LxMapEntry>()) };
        out.extend_from_slice(raw);
        out.extend_from_slice(name);
        while out.len() % 8 != 0 {
            out.push(0);
        }
    }
    (out, total)
}

/// The `pid | tid << 32` word of `LX_INFO_TASK`: `(pid, tid)`.
pub fn split_who(w: u64) -> (u64, u64) {
    (w & 0xFFFF_FFFF, w >> 32)
}

/// Checks the length arguments of a buffer answer (at most 16 MiB).
pub fn check_len(len: u64) -> Result<usize, i64> {
    if len > 16 << 20 {
        return Err(EINVAL);
    }
    Ok(len as usize)
}

/// Errors the operations answer (for the glue and its tests).
pub mod err {
    /// No such process or thread.
    pub const ESRCH: i64 = super::ESRCH;
    /// A caller the primitives do not answer for (a namespace of its own).
    pub const EPERM: i64 = super::EPERM;
    /// The caller may not see it.
    pub const EACCES: i64 = super::EACCES;
    /// Bad arguments.
    pub const EINVAL: i64 = super::EINVAL;
}

/// The kernel's side: gathering from the scheduler, the process table and memory.
#[cfg(target_os = "uefi")]
pub mod glue {
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    use super::*;
    use crate::compat::linux as lx;
    use crate::ipc::protocol::{
        LxSysInfo, LxTaskInfo, LX_INFO_ARGS, LX_INFO_CPUS, LX_INFO_EFIVAR, LX_INFO_MAPS, LX_INFO_NS, LX_INFO_PIDS, LX_INFO_SYS, LX_INFO_SYS_CPU, LX_INFO_SYS_MEM, LX_INFO_TASK,
        LX_INFO_TASK_NOMEM, LXS_LINUX, LXS_PROC,
    };
    use crate::task::TaskId;

    const EFAULT: i64 = -14;

    /// Whether `op` is one of these operations.
    pub fn is_info(op: u64) -> bool {
        (LX_INFO_TASK..=LX_INFO_EFIVAR).contains(&op)
    }

    /// `SYS_LX_OBJ` operations 56..=61 for host `h` (only the host of linux-server's
    /// services may ask).
    pub fn ctl(h: crate::ipc::protocol::SvcId, op: u64, a: u64, b: u64, c: u64) -> i64 {
        if h != crate::lx::svc::host_of(LXS_LINUX) && h != crate::lx::svc::host_of(LXS_PROC) {
            return EPERM;
        }
        match op {
            LX_INFO_TASK => task(a, b, c),
            LX_INFO_SYS => out(a, &sys(b)),
            LX_INFO_ARGS => args(a, b & 0xFFFF_FFFF, c, b >> 32),
            LX_INFO_MAPS => maps(a, b & 0xFFFF_FFFF, c, b >> 32),
            LX_INFO_PIDS => pids(a, b),
            LX_INFO_EFIVAR => efivar(a, b & 0xFFFF_FFFF, c, b >> 32),
            _ => EINVAL,
        }
    }

    /// Copies plain struct `v` to linux-server's `ptr`.
    fn out<T: Copy>(ptr: u64, v: &T) -> i64 {
        // SAFETY: `T` is a repr(C) struct of plain integers
        let raw = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
        match lx::vfs::copy_out(ptr, raw) {
            Ok(()) => 0,
            Err(_) => EFAULT,
        }
    }

    /// Copies at most `len` bytes of `data` to `buf`; answers `data`'s full length.
    fn out_bytes(buf: u64, len: u64, data: &[u8]) -> i64 {
        let Ok(len) = check_len(len) else { return EINVAL };
        let n = data.len().min(len);
        if n > 0 && lx::vfs::copy_out(buf, &data[..n]).is_err() {
            return EFAULT;
        }
        data.len() as i64
    }

    /// The caller of request `id`: its thread, process, real uid, effective capabilities
    /// and PID namespace's init.
    fn caller(id: u64) -> Result<Caller, i64> {
        let client = crate::lx::client_of(id).ok_or(ESRCH)?;
        let (tgid, euid, egid, caps, in_userns) = crate::task::SCHEDULER
            .lock()
            .with_task_mut(TaskId(client), |t| (t.tgid, t.euid, t.egid, if t.caps.in_userns { 0 } else { t.caps.effective }, t.caps.in_userns))
            .ok_or(ESRCH)?;
        // wave9 G7a: the PID view through the process-identity primitive
        let init = crate::lx::proc::pid_ns_init(tgid);
        // (only callers of the first namespaces: their IDs need no translation)
        may_query(init, in_userns, false)?;
        Ok(Caller { tgid, euid, egid, caps, init })
    }

    /// The caller of a request, as the operations check it.
    struct Caller {
        tgid: u64,
        euid: u32,
        egid: u32,
        caps: u64,
        init: Option<u64>,
    }

    /// Whether process `pid` is a service's (services are not Linux processes).
    fn is_service(pid: u64) -> Option<bool> {
        crate::task::SCHEDULER.lock().with_process(pid, |t| t.service.is_some())
    }

    /// `LX_INFO_TASK`.
    fn task(id: u64, who: u64, ptr: u64) -> i64 {
        let Caller { tgid: ctgid, init, .. } = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let (p, t) = split_who(who & !LX_INFO_TASK_NOMEM);
        let pid = resolve_pid(p, ctgid, init);
        let tid = if t == 0 { pid } else { resolve_pid(t, ctgid, init) };
        if let Err(e) = may_query(init, false, is_service(pid).unwrap_or(false)) {
            return e;
        }
        match fill_task(pid, tid, init, who & LX_INFO_TASK_NOMEM == 0) {
            Some(info) => out(ptr, &info),
            None => ESRCH,
        }
    }

    /// The facts of process `pid`, thread `tid`, for a caller whose namespace's init is
    /// `init` (the kernel's `/proc/<pid>/{stat,status,statm}` sources).
    fn fill_task(pid: u64, tid: u64, init: Option<u64>, mem: bool) -> Option<LxTaskInfo> {
        if tid != pid && !lx::proc::thread_ids_of(pid).contains(&tid) {
            return None;
        }
        let (exe, ids, mm) = crate::task::SCHEDULER
            .lock()
            .with_process(pid, |t| (alloc::string::String::from(t.exe_path()), [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid], t.mm.clone()))?;
        let mut i = LxTaskInfo { pid: to_caller(pid, init), tid: to_caller(tid, init), ids, comm: comm_of(&exe), ..Default::default() };
        // wave9 G7a: the tree through the process-identity primitive
        let crate::lx::proc::Tree { ppid, pgid, sid, threads, start, zombie, pid_inits: inits } =
            crate::lx::proc::task_tree(pid).unwrap_or(crate::lx::proc::Tree { ppid: 0, pgid: pid, sid: pid, threads: 1, start: 0, zombie: false, pid_inits: Vec::new() });
        i.ppid = ppid;
        i.pgid = pgid;
        i.sid = sid;
        i.threads = threads;
        i.start = start;
        i.state = if zombie {
            b'Z' as u64
        } else if crate::task::SCHEDULER.lock().process_runnable(pid) {
            b'R' as u64
        } else {
            b'S' as u64
        };
        let ct = lx::proc::to_clock_ticks;
        let cpu = lx::proc::cpu_times(pid);
        (i.utime, i.stime, i.cutime, i.cstime) = (ct(cpu.0), ct(cpu.1), ct(cpu.2), ct(cpu.3));
        i.nice = lx::extra::sched_of(tid).1 as i64;
        let (vm, anon, file) = mm.filter(|_| mem).map_or((0, 0, 0), |m| m.lock().memory_usage());
        (i.vsize, i.rss_anon, i.rss_file) = (vm, anon, file);
        i.locked_kib = lx::limits::locked_kib(pid);
        let (nnp, mode) = lx::seccomp::status_of(pid);
        i.nnp = nnp as u32;
        i.seccomp = mode as u32;
        i.tracer = match lx::ptrace::tracer_of(pid) {
            0 => 0,
            t => to_caller(t, init),
        };
        i.ns_depth = inits.len().min(LX_INFO_NS) as u64;
        for (k, v) in inits.iter().take(LX_INFO_NS).enumerate() {
            i.ns_inits[k] = *v;
        }
        Some(i)
    }

    /// `LX_INFO_SYS` (the kernel's `/proc/{stat,uptime,loadavg,meminfo}` sources): the
    /// parts `what` names (`LX_INFO_SYS_MEM`, `LX_INFO_SYS_CPU`).
    pub fn sys(what: u64) -> LxSysInfo {
        let mut s = LxSysInfo { now_ns: crate::arch::pit::now_ns(), ..Default::default() };
        let n = crate::arch::smp::online().max(1);
        s.ncpu = n as u64;
        s.boot_time = crate::arch::rtc::now().0.saturating_sub(s.now_ns / 1_000_000_000);
        if what & LX_INFO_SYS_CPU != 0 {
            cpu_part(&mut s, n);
        }
        if what & LX_INFO_SYS_MEM != 0 {
            mem_part(&mut s);
        }
        s
    }

    fn cpu_part(s: &mut LxSysInfo, n: usize) {
        for c in 0..n.min(LX_INFO_CPUS) {
            let t = &crate::task::scheduler::CPU_TIMES[c.min(crate::arch::smp::MAX_CPUS - 1)];
            s.cpu[c] = [0, 1, 2].map(|k| lx::proc::to_clock_ticks(t[k].load(Ordering::Relaxed)));
        }
        for k in 0..3 {
            s.load[k] = crate::task::scheduler::LOAD_AVG[k].load(Ordering::Relaxed);
        }
        let (running, total) = crate::task::SCHEDULER.lock().task_counts();
        s.running = running as u64;
        s.tasks = total as u64;
        {
            let procs = lx::proc::PROCS.lock();
            s.last_pid = procs.keys().next_back().copied().unwrap_or(0);
            s.procs = procs.len() as u64;
        }
    }

    fn mem_part(s: &mut LxSysInfo) {
        {
            let fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
            s.mem_total = fa.total_usable_memory() / 1024;
            s.mem_free = fa.free_memory() / 1024;
        }
        let (cached, reclaimable) = lx::mm::cache_pages();
        s.cached = cached as u64 * 4;
        s.reclaimable = reclaimable as u64 * 4;
        (s.swap_total, s.swap_free) = lx::admin::swap_kib();
    }

    /// `LX_INFO_ARGS`.
    fn args(id: u64, who: u64, buf: u64, len: u64) -> i64 {
        let Caller { tgid: ctgid, init, .. } = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let pid = resolve_pid(who, ctgid, init);
        let Some((fallback, service)) = crate::task::SCHEDULER.lock().with_process(pid, |t| (t.cmdline.clone(), t.service.is_some())) else { return ESRCH };
        if let Err(e) = may_query(init, false, service) {
            return e;
        }
        let text = lx::fs::live_cmdline(pid).unwrap_or_else(|| fallback.map(|c| c.to_vec()).unwrap_or_default());
        out_bytes(buf, len, &text)
    }

    /// `LX_INFO_MAPS`.
    fn maps(id: u64, who: u64, buf: u64, len: u64) -> i64 {
        let Caller { tgid: ctgid, euid, egid, caps, init } = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let Ok(cap) = check_len(len) else { return EINVAL };
        let pid = resolve_pid(who, ctgid, init);
        let Some((uids, gids, service, mm)) =
            crate::task::SCHEDULER.lock().with_process(pid, |t| ((t.uid, t.euid, t.suid), (t.gid, t.egid, t.sgid), t.service.is_some(), t.mm.clone()))
        else {
            return ESRCH;
        };
        if let Err(e) = may_query(init, false, service) {
            return e;
        }
        if !may_see(pid == ctgid, service, (euid, egid), caps, uids, gids) {
            return EACCES;
        }
        let entries = mm.map(|m| m.lock().maps_entries()).unwrap_or_default();
        let areas: Vec<Area> = entries.iter().map(|e| Area { start: e.0, end: e.1, offset: e.2, prot: e.3, shared: e.4, name: e.5.as_deref() }).collect();
        let (data, total) = encode_maps(&areas, cap);
        if !data.is_empty() && lx::vfs::copy_out(buf, &data).is_err() {
            return EFAULT;
        }
        total as i64
    }

    /// `LX_INFO_PIDS`.
    fn pids(buf: u64, n: u64) -> i64 {
        let Ok(n) = check_len(n.saturating_mul(8)) else { return EINVAL };
        let all: Vec<u64> = lx::proc::PROCS.lock().keys().copied().collect();
        let k = all.len().min(n / 8);
        let mut raw = Vec::with_capacity(k * 8);
        for p in &all[..k] {
            raw.extend_from_slice(&p.to_le_bytes());
        }
        if k > 0 && lx::vfs::copy_out(buf, &raw).is_err() {
            return EFAULT;
        }
        all.len() as i64
    }

    /// `LX_INFO_EFIVAR`.
    fn efivar(name: u64, name_len: u64, buf: u64, len: u64) -> i64 {
        if name_len == 0 || name_len > 512 {
            return EINVAL;
        }
        let Ok(raw) = lx::vfs::copy_in(name, name_len as usize) else { return EFAULT };
        let Ok(file) = core::str::from_utf8(&raw) else { return EINVAL };
        let Some((n, guid)) = lx::efivars::parse_name(file) else { return -2 };
        match lx::efivars::get(&n, &guid) {
            Ok((attrs, data)) => {
                let mut v = Vec::with_capacity(4 + data.len());
                v.extend_from_slice(&attrs.to_le_bytes());
                v.extend_from_slice(&data);
                out_bytes(buf, len, &v)
            }
            Err(e) => e,
        }
    }
}

/// Host builds of `src/lx` (`tests/host-t30`): the operations are not there.
#[cfg(not(target_os = "uefi"))]
pub mod glue {
    /// Whether `op` is one of these operations (never, on the host).
    pub fn is_info(_op: u64) -> bool {
        false
    }

    /// The operations (none, on the host).
    pub fn ctl(_h: crate::ipc::protocol::SvcId, _op: u64, _a: u64, _b: u64, _c: u64) -> i64 {
        super::err::EINVAL
    }
}
