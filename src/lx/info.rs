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

// wave11 GP begin: callers in a PID namespace of their own
/// Whether process `pid` (in the PID namespaces whose inits are `inits`) is there for a
/// caller whose PID namespace's init is `init` and who named it `who` (0: itself): in the
/// first namespace every process is; in another one only its init and the processes below
/// it, and the init only by the number 1 (as `/proc/1`), not by its system-wide ID.
pub fn in_view(pid: u64, inits: &[u64], init: Option<u64>, who: u64) -> bool {
    match init {
        None => true,
        Some(i) => (pid == i || inits.contains(&i)) && !(who == i && i != 1),
    }
}

/// A list of IDs as `u32`s (little-endian), the `LX_PX_FDS`/`TASKS`/`PIDS` answers.
pub fn u32_list(ids: &[u64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ids.len() * 4);
    for &i in ids {
        v.extend_from_slice(&(i.min(u32::MAX as u64) as u32).to_le_bytes());
    }
    v
}
// wave11 GP end

/// Whether a caller may read another process's memory facts (`maps`; `cmdline` is open to
/// all): Linux's `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`: itself; never a service's
/// process; with `CAP_SYS_PTRACE`; or when the caller's file-system user ID (here the
/// effective one) is the target's real, effective and saved user ID **and** its file-system
/// group ID the target's real, effective and saved group ID (a set-group-ID program is not
/// readable by its user). wave10 G7b-2: a target that is not dumpable (`PR_SET_DUMPABLE` 0,
/// or a program that gained privileges at exec: set-ID or file capabilities) is readable
/// only with `CAP_SYS_PTRACE`, as Linux's `__ptrace_may_access`. wave10 G8-1: the one ptrace
/// rule (`lx::ptrace_rules::may_access`, shared with lx-proc's tracing decisions and the
/// kernel's copy), for a capability-less target in the caller's user namespace ([`may_read`]
/// takes those inputs too).
pub fn may_see(same: bool, target_service: bool, caller: (u32, u32), caller_caps: u64, target_uids: (u32, u32, u32), target_gids: (u32, u32, u32), target_dumpable: bool) -> bool {
    may_read(same, target_service, caller, caller_caps, target_uids, target_gids, target_dumpable, TargetCaps::PLAIN)
}

// wave10 G8-1 begin
/// What the ptrace read rule's capability part reads of a target: its permitted
/// capabilities and how its user namespace stands to the caller's (as the ptrace facts:
/// `lx::trace`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetCaps {
    /// Permitted capabilities.
    pub perm: u64,
    /// Its user namespace is the caller's or lies below it.
    pub within: bool,
    /// Its user namespace is the caller's own.
    pub same_ns: bool,
    /// Its user namespace lies below the caller's and the caller's user made it.
    pub owned: bool,
}

impl TargetCaps {
    /// A capability-less target in the caller's user namespace.
    pub const PLAIN: TargetCaps = TargetCaps { perm: 0, within: true, same_ns: true, owned: false };
}

/// [`may_see`] with every input of the rule (`PTRACE_MODE_READ_FSCREDS` of
/// `lx::ptrace_rules::may_access`): also the target's dumpable flag and its capabilities and
/// user namespace (Linux's commoncap test: a target in another user namespace, or holding
/// capabilities the caller lacks, is readable only with `CAP_SYS_PTRACE` over it).
#[allow(clippy::too_many_arguments)]
pub fn may_read(same: bool, target_service: bool, caller: (u32, u32), caller_caps: u64, target_uids: (u32, u32, u32), target_gids: (u32, u32, u32), target_dumpable: bool, tc: TargetCaps) -> bool {
    use super::ptrace_rules::{may_access, Target, Who, MODE_FSCREDS, MODE_READ};
    let (u, g) = caller;
    let who = Who { uid: [u; 3], gid: [g; 3], caps: caller_caps, perm: caller_caps, in_userns: false, seccomp: false, suspended: false };
    let t = Target {
        tgid: 0,
        tid: 0,
        uid: [target_uids.0, target_uids.1, target_uids.2],
        gid: [target_gids.0, target_gids.1, target_gids.2],
        same,
        service: target_service,
        within: tc.within,
        same_ns: tc.same_ns,
        owned: tc.owned,
        tracer_cap: false,
        dumpable: target_dumpable as u8,
        perm: tc.perm,
    };
    may_access(MODE_READ | MODE_FSCREDS, &who, &t).is_ok()
}
// wave10 G8-1 end

/// Whether the info primitives answer for a caller (`init`: its PID namespace's init, `None`
/// in the first; `in_userns`: it is in a user namespace of its own) about a target (a
/// service's process or not): never about a service (`ESRCH`: services are not Linux
/// processes). wave11 GP: callers in a PID or user namespace of their own are answered too
/// (lx-proc serves their `/proc`): the IDs are translated ([`to_caller`], the user
/// namespace's map) and processes outside the caller's PID namespace are not there
/// ([`in_view`]).
pub fn may_query(_init: Option<u64>, _in_userns: bool, target_service: bool) -> Result<(), i64> {
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
        (LX_INFO_TASK..=LX_INFO_EFIVAR).contains(&op) || op == crate::ipc::protocol::LX_INFO_PROCX // wave11 GP
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
            // (wave10 G7b-2: the environment with `LX_INFO_ARGS_ENV` in the pid word)
            LX_INFO_ARGS if b & crate::ipc::protocol::LX_INFO_ARGS_ENV != 0 => environ(a, b & 0x7FFF_FFFF, c, b >> 32),
            LX_INFO_ARGS => args(a, b & 0xFFFF_FFFF, c, b >> 32),
            LX_INFO_MAPS => maps(a, b & 0xFFFF_FFFF, c, b >> 32),
            LX_INFO_PIDS => pids(a, b),
            LX_INFO_EFIVAR => efivar(a, b & 0xFFFF_FFFF, c, b >> 32),
            // wave11 GP: the rest of `/proc` (`lx::procx`)
            crate::ipc::protocol::LX_INFO_PROCX if h == crate::lx::svc::host_of(LXS_PROC) => crate::lx::procx::ctl(a, b, c),
            _ => EINVAL,
        }
    }

    /// Copies plain struct `v` to linux-server's `ptr`.
    pub(crate) fn out<T: Copy>(ptr: u64, v: &T) -> i64 {
        // SAFETY: `T` is a repr(C) struct of plain integers
        let raw = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
        match lx::vfs::copy_out(ptr, raw) {
            Ok(()) => 0,
            Err(_) => EFAULT,
        }
    }

    /// Copies at most `len` bytes of `data` to `buf`; answers `data`'s full length.
    pub(crate) fn out_bytes(buf: u64, len: u64, data: &[u8]) -> i64 {
        let Ok(len) = check_len(len) else { return EINVAL };
        let n = data.len().min(len);
        if n > 0 && lx::vfs::copy_out(buf, &data[..n]).is_err() {
            return EFAULT;
        }
        data.len() as i64
    }

    /// The caller of request `id`: its thread, process, real uid, effective capabilities
    /// and PID namespace's init.
    pub(crate) fn caller(id: u64) -> Result<Caller, i64> {
        let client = crate::lx::client_of(id).ok_or(ESRCH)?;
        // wave10 G7b-2: a `/proc` snapshot being made again answers with the rights of the
        // process that opened it (as Linux checks at open), not the reader's
        if let Some(o) = crate::lx::procsnap::glue::opener_of(client) {
            may_query(o.init, o.in_userns, false)?;
            return Ok(Caller { tgid: o.tgid, euid: o.euid, egid: o.egid, caps: o.caps, init: o.init, in_userns: o.in_userns });
        }
        let (tgid, euid, egid, caps, in_userns) = crate::task::SCHEDULER
            .lock()
            .with_task_mut(TaskId(client), |t| (t.tgid, t.euid, t.egid, if t.caps.in_userns { 0 } else { t.caps.effective }, t.caps.in_userns))
            .ok_or(ESRCH)?;
        // wave9 G7a: the PID view through the process-identity primitive
        let init = crate::lx::proc::pid_ns_init(tgid);
        // (only callers of the first namespaces: their IDs need no translation)
        may_query(init, in_userns, false)?;
        Ok(Caller { tgid, euid, egid, caps, init, in_userns })
    }

    // wave10 G8-1 begin
    /// Process `pid`'s capability facts for the read rule of caller process `ctgid`
    /// (effective user `euid`), as `lx::trace` gathers them for the ptrace facts.
    pub(crate) fn target_caps(pid: u64, ctgid: u64, euid: u32, perm: u64) -> TargetCaps {
        if pid == ctgid {
            return TargetCaps { perm, ..TargetCaps::PLAIN };
        }
        let rel = crate::compat::linux::ns::user_rel_in(&crate::compat::linux::proc::PROCS.lock(), pid, ctgid, euid);
        let (within, same_ns, owned) = rel.unwrap_or((false, false, false));
        TargetCaps { perm, within, same_ns, owned }
    }
    // wave10 G8-1 end

    /// The caller of a request, as the operations check it.
    pub(crate) struct Caller {
        pub(crate) tgid: u64,
        pub(crate) euid: u32,
        pub(crate) egid: u32,
        pub(crate) caps: u64,
        pub(crate) init: Option<u64>,
        /// wave11 GP: in a user namespace of its own (IDs shown through its map).
        pub(crate) in_userns: bool,
    }

    /// Whether process `pid` is a service's (services are not Linux processes).
    pub(crate) fn is_service(pid: u64) -> Option<bool> {
        crate::task::SCHEDULER.lock().with_process(pid, |t| t.service.is_some())
    }

    /// `LX_INFO_TASK`.
    fn task(id: u64, who: u64, ptr: u64) -> i64 {
        let c = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let (ctgid, init) = (c.tgid, c.init);
        let (p, t) = split_who(who & !LX_INFO_TASK_NOMEM);
        let pid = resolve_pid(p, ctgid, init);
        let tid = if t == 0 { pid } else { resolve_pid(t, ctgid, init) };
        if let Err(e) = may_query(init, false, is_service(pid).unwrap_or(false)) {
            return e;
        }
        // wave11 GP: a process outside the caller's PID namespace is not there
        if !visible(pid, init, p) {
            return ESRCH;
        }
        match fill_task(pid, tid, init, who & LX_INFO_TASK_NOMEM == 0).map(|i| if t != 0 { thread_view(i, tid) } else { i }) {
            Some(mut info) => {
                // wave11 GP: the tree and the ids as the caller's namespaces show them
                if init.is_some() {
                    for v in [&mut info.ppid, &mut info.pgid, &mut info.sid] {
                        *v = to_caller(*v, init);
                    }
                }
                if c.in_userns {
                    for (k, v) in info.ids.iter_mut().enumerate() {
                        *v = lx::ns::id_seen_by(ctgid, *v, k >= 3);
                    }
                }
                out(ptr, &info)
            }
            None => ESRCH,
        }
    }

    // wave11 GP begin
    /// Whether process `pid`, named `who` by a caller whose PID namespace's init is `init`,
    /// is there for it ([`in_view`]).
    pub(crate) fn visible(pid: u64, init: Option<u64>, who: u64) -> bool {
        if init.is_none() {
            return true;
        }
        let inits = lx::proc::PROCS.lock().get(&pid).map(|p| p.ns.pid_inits.clone()).unwrap_or_default();
        in_view(pid, &inits, init, who)
    }
    // wave11 GP end

    // wave11 GD begin
    /// `/proc/<pid>/task/<tid>/stat`: the thread's own state and CPU time, not its
    /// process's (top -H showed every thread of a process with the process's whole time
    /// and running while any thread ran).
    fn thread_view(mut i: LxTaskInfo, tid: u64) -> LxTaskInfo {
        if let Some((run, sys, runnable)) = crate::task::SCHEDULER.lock().thread_cpu(tid) {
            let ct = lx::proc::to_clock_ticks;
            (i.utime, i.stime, i.cutime, i.cstime) = (ct(run - sys.min(run)), ct(sys), 0, 0);
            if i.state != b'Z' as u64 {
                i.state = if runnable { b'R' as u64 } else { b'S' as u64 };
            }
        }
        i
    }
    // wave11 GD end

    /// The facts of process `pid`, thread `tid`, for a caller whose namespace's init is
    /// `init` (the kernel's `/proc/<pid>/{stat,status,statm}` sources).
    fn fill_task(pid: u64, tid: u64, init: Option<u64>, mem: bool) -> Option<LxTaskInfo> {
        if tid != pid && !lx::proc::thread_ids_of(pid).contains(&tid) {
            return None;
        }
        let (exe, ids, mm) = crate::task::SCHEDULER
            .lock()
            .with_process(pid, |t| (alloc::string::String::from(t.exe_path()), [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid], t.mm.clone()))?;
        // (wave10 G7b-1: the thread's PR_SET_NAME name when it has one)
        let comm = crate::lx::proc::comm_of(tid).unwrap_or_else(|| comm_of(&exe));
        let mut i = LxTaskInfo { pid: to_caller(pid, init), tid: to_caller(tid, init), ids, comm, ..Default::default() };
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
        if !visible(pid, init, who) {
            return ESRCH; // wave11 GP
        }
        let Some((fallback, service)) = crate::task::SCHEDULER.lock().with_process(pid, |t| (t.cmdline.clone(), t.service.is_some())) else { return ESRCH };
        if let Err(e) = may_query(init, false, service) {
            return e;
        }
        let text = lx::fs::live_cmdline(pid).unwrap_or_else(|| fallback.map(|c| c.to_vec()).unwrap_or_default());
        out_bytes(buf, len, &text)
    }

    // wave10 G7b-2 begin
    /// `LX_INFO_ARGS` with `LX_INFO_ARGS_ENV`: the environment (`/proc/<pid>/environ`), under
    /// the `ptrace` read rule as the maps (Linux: `PTRACE_MODE_READ_FSCREDS`).
    fn environ(id: u64, who: u64, buf: u64, len: u64) -> i64 {
        let Caller { tgid: ctgid, euid, egid, caps, init, .. } = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let pid = resolve_pid(who, ctgid, init);
        if !visible(pid, init, who) {
            return ESRCH; // wave11 GP
        }
        // (wave10 G8-1: + the target's permitted capabilities)
        let Some((uids, gids, service, perm)) =
            crate::task::SCHEDULER.lock().with_process(pid, |t| ((t.uid, t.euid, t.suid), (t.gid, t.egid, t.sgid), t.service.is_some(), t.caps.permitted))
        else {
            return ESRCH;
        };
        if let Err(e) = may_query(init, false, service) {
            return e;
        }
        // wave10 G8-1: the whole read rule: dumpable, capabilities, user namespace
        if !may_read(pid == ctgid, service, (euid, egid), caps, uids, gids, crate::lx::proc::proc_attrs(pid).dumpable == 1, target_caps(pid, ctgid, euid, perm)) {
            return EACCES;
        }
        out_bytes(buf, len, &lx::fs::live_environ(pid).unwrap_or_default())
    }
    // wave10 G7b-2 end

    /// `LX_INFO_MAPS`.
    fn maps(id: u64, who: u64, buf: u64, len: u64) -> i64 {
        let Caller { tgid: ctgid, euid, egid, caps, init, .. } = match caller(id) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let Ok(cap) = check_len(len) else { return EINVAL };
        let pid = resolve_pid(who, ctgid, init);
        if !visible(pid, init, who) {
            return ESRCH; // wave11 GP
        }
        // (wave10 G8-1: + the target's permitted capabilities)
        let Some((uids, gids, service, mm, perm)) = crate::task::SCHEDULER
            .lock()
            .with_process(pid, |t| ((t.uid, t.euid, t.suid), (t.gid, t.egid, t.sgid), t.service.is_some(), t.mm.clone(), t.caps.permitted))
        else {
            return ESRCH;
        };
        if let Err(e) = may_query(init, false, service) {
            return e;
        }
        // wave10 G8-1: the whole read rule: dumpable, capabilities, user namespace
        if !may_read(pid == ctgid, service, (euid, egid), caps, uids, gids, crate::lx::proc::proc_attrs(pid).dumpable == 1, target_caps(pid, ctgid, euid, perm)) {
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
