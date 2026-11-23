//! # The rules of process identity, pure (wave 10, Group 7b-1)
//!
//! Two parts, both free of system calls so the host tests run them as they are:
//!
//! - [`rules`]: the kernel's `src/lx/proc_rules.rs` (wave 9, Group 7a), built here with
//!   `#[path]`: one copy of the setuid-family, `setpgid`, `setsid` and limit rules for both
//!   the kernel's copy (`lx.proc=kernel`) and lx-proc.
//! - [`serve`]: every call lx-proc answers, written against two small interfaces: the
//!   kernel's primitives ([`Kernel`], `SYS_LX_OBJ` op 75) and the caller's memory ([`Mem`]).
//!   Each call reads what it needs from the kernel, decides, and changes the kernel's state
//!   through one primitive; the compare-and-set primitives answer `EAGAIN` when the state
//!   changed meanwhile, and the call decides again.
//!
//! The answers match the kernel's own code of wave 9 (the switch back), check for check
//! and in the same order, so a program sees no difference between the two.

use alloc::vec::Vec;

use crate::proto::*;

/// A process's place in the tree (what [`rules`] reads).
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

/// The kernel's rules of wave 9, shared with the kernel.
#[path = "../../../../src/lx/proc_rules.rs"]
pub mod rules;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const EAGAIN: i64 = -11;

/// `CAP_SETGID`.
const CAP_SETGID: u32 = 6;
/// `CAP_SETUID`.
const CAP_SETUID: u32 = 7;
/// `CAP_SYS_PTRACE`.
const CAP_SYS_PTRACE: u32 = 19;
/// `CAP_SYS_PACCT`.
const CAP_SYS_PACCT: u32 = 20;
/// `CAP_SYS_ADMIN`.
const CAP_SYS_ADMIN: u32 = 21;
/// `CAP_SYS_RESOURCE`.
const CAP_SYS_RESOURCE: u32 = 24;
/// `CAP_SYSLOG`.
const CAP_SYSLOG: u32 = 34;
/// Resource limits the kernel keeps.
pub const NLIMITS: u64 = 16;
/// How often a compare-and-set is tried before giving up with `EAGAIN`.
const TRIES: usize = 64;

const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const CLONE_NEW_ALL: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

/// The kernel's process-identity primitives (`SYS_LX_OBJ(LX_OBJ_PROCID, req, sub, io)`):
/// sub-op `sub` with `io`, for the caller of the request being served.
pub trait Kernel {
    /// Runs sub-op `sub` (`LXP_*`); its result (`>= 0`) or a negative errno.
    fn op(&self, sub: u64, io: &mut LxProcIo) -> i64;
}

/// The caller's memory.
pub trait Mem {
    /// `len` bytes at `ptr`.
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64>;
    /// Writes `data` at `ptr`.
    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64>;
    /// The NUL-terminated string at `ptr` (without the NUL).
    fn cstr(&self, ptr: u64) -> Result<Vec<u8>, i64>;
}

/// A call to answer.
#[derive(Clone, Copy, Debug, Default)]
pub struct Call {
    /// System call number.
    pub nr: u64,
    /// Its arguments.
    pub args: [u64; 6],
    /// The caller's process.
    pub tgid: u64,
    /// The caller's effective capabilities as `Caps::has` sees them (0 when they hold only
    /// in a user namespace of its own: `LxCall::caps`).
    pub caps: u64,
}

impl Call {
    /// Whether the caller holds `cap` system-wide.
    fn has(&self, cap: u32) -> bool {
        self.caps & (1 << cap) != 0
    }
}

/// What lx-proc answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    /// This result.
    Ret(i64),
    /// The kernel's own code runs the call (a redirect to service 0): calls whose work is
    /// mechanism in the caller's context, after [`LXP_APPROVE`] when lx-proc decided.
    Kernel,
}

/// A thread as `LXP_TASK_GET` describes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Task {
    /// Thread id.
    pub tid: u64,
    /// Process id.
    pub tgid: u64,
    /// Real, effective, saved user id.
    pub uid: [u32; 3],
    /// Real, effective, saved group id.
    pub gid: [u32; 3],
    /// Effective capabilities (also those holding only in its own user namespace).
    pub eff: u64,
    /// Permitted capabilities.
    pub perm: u64,
    /// `LXP_F_*`.
    pub flags: u64,
    /// Dumpable.
    pub dumpable: u64,
    /// Parent-death signal.
    pub pdeathsig: u64,
    /// Live threads of its process.
    pub threads: u64,
    /// Its `comm`.
    pub comm: [u8; 16],
}

impl Task {
    /// Whether it holds `cap` system-wide (`Caps::has`: not only in its own user namespace).
    pub fn has(&self, cap: u32) -> bool {
        self.flags & LXP_F_USERNS == 0 && self.eff & (1 << cap) != 0
    }

    /// Whether `cap` is in its effective set (namespace-scoped checks).
    pub fn eff_has(&self, cap: u32) -> bool {
        self.eff & (1 << cap) != 0
    }
}

/// `LXP_TASK_GET` of thread `tid` (0: the caller; with `process`, a process).
pub fn task<K: Kernel>(k: &K, tid: u64, process: bool) -> Result<Task, i64> {
    let mut io = LxProcIo::EMPTY;
    io.a[0] = tid;
    io.a[1] = process as u64;
    let r = k.op(LXP_TASK_GET, &mut io);
    if r < 0 {
        return Err(r);
    }
    let a = io.a;
    let mut comm = [0u8; 16];
    comm.copy_from_slice(&io.b[..16]);
    Ok(Task {
        tid: a[0],
        tgid: a[1],
        uid: [a[2] as u32, a[3] as u32, a[4] as u32],
        gid: [a[5] as u32, a[6] as u32, a[7] as u32],
        eff: a[8],
        perm: a[9],
        flags: a[10],
        dumpable: a[11],
        pdeathsig: a[12],
        threads: a[13],
        comm,
    })
}

/// Sub-op `sub` with words `w` (the rest zero); the result and the words back.
fn op<K: Kernel>(k: &K, sub: u64, w: &[u64]) -> (i64, [u64; 16]) {
    let mut io = LxProcIo::EMPTY;
    io.a[..w.len()].copy_from_slice(w);
    let r = k.op(sub, &mut io);
    (r, io.a)
}

/// Answers call `c`.
pub fn serve<K: Kernel, M: Mem>(k: &K, m: &M, c: &Call) -> Out {
    let a = c.args;
    let r = match c.nr {
        105 | 106 | 113 | 114 | 117 | 119 => set_ids(k, c),
        // setfsuid / setfsgid: the file-system ids follow the effective ones (the current
        // one is the answer, as the kernel's code)
        122 | 123 => match task(k, 0, false) {
            Ok(t) => (if c.nr == 122 { t.uid[1] } else { t.gid[1] }) as i64,
            Err(e) => e,
        },
        116 => setgroups(k, m, a[0], a[1]),
        121 | 124 => {
            let (r, w) = op(k, LXP_PGRP_GET, &[a[0] as u32 as u64]);
            if r < 0 {
                ESRCH
            } else if c.nr == 121 {
                w[2] as i64
            } else {
                w[3] as i64
            }
        }
        109 => setpgid(k, c.tgid, a[0] as u32 as u64, a[1] as u32 as u64),
        112 => setsid(k, c.tgid),
        160 => setrlimit(k, m, a[0], a[1]),
        302 => prlimit(k, m, c, a),
        157 => return prctl(k, m, a),
        63 => uname(k, m, a[0]),
        170 | 171 => set_uts(k, m, a[0], a[1], c.nr == 171),
        272 => return unshare(k, a[0]),
        308 => return setns(k, a[0], a[1]),
        // syslog (dmesg_restrict = 1: everything needs CAP_SYSLOG or CAP_SYS_ADMIN) and
        // acct (CAP_SYS_PACCT): decided here; the log ring and the accounting file are the
        // kernel's, which runs the rest in the caller's context
        103 => return approve_if(k, 103, c.has(CAP_SYSLOG) || c.has(CAP_SYS_ADMIN)),
        163 => return approve_if(k, 163, c.has(CAP_SYS_PACCT)),
        _ => ENOSYS,
    };
    Out::Ret(r)
}

/// `allowed`: the kernel runs call `nr` (marked approved); otherwise `EPERM`.
fn approve_if<K: Kernel>(k: &K, nr: u64, allowed: bool) -> Out {
    if !allowed {
        return Out::Ret(EPERM);
    }
    let (r, _) = op(k, LXP_APPROVE, &[nr]);
    if r < 0 {
        Out::Ret(r)
    } else {
        Out::Kernel
    }
}

/// The setuid family: today's rule on the calling thread's ids, then `LXP_CREDS_SET`.
fn set_ids<K: Kernel>(k: &K, c: &Call) -> i64 {
    let t = match task(k, 0, false) {
        Ok(t) => t,
        Err(_) => return EPERM,
    };
    let (cap_uid, cap_gid) = (t.has(CAP_SETUID), t.has(CAP_SETGID));
    let (x, y, z) = (c.args[0] as u32, c.args[1] as u32, c.args[2] as u32);
    let (mut uid, mut gid) = (t.uid, t.gid);
    let r = match c.nr {
        105 => rules::set_id(uid, x, cap_uid).map(|v| uid = v),
        106 => rules::set_id(gid, x, cap_gid).map(|v| gid = v),
        113 => rules::set_re(uid, x, y, cap_uid).map(|v| uid = v),
        114 => rules::set_re(gid, x, y, cap_gid).map(|v| gid = v),
        117 => rules::set_res(uid, [x, y, z], cap_uid).map(|v| uid = v),
        _ => rules::set_res(gid, [x, y, z], cap_gid).map(|v| gid = v),
    };
    if let Err(e) = r {
        return e;
    }
    let w = [0, uid[0] as u64, uid[1] as u64, uid[2] as u64, gid[0] as u64, gid[1] as u64, gid[2] as u64];
    if op(k, LXP_CREDS_SET, &w).0 < 0 {
        EPERM
    } else {
        0
    }
}

/// `setgroups(size, list)`: `CAP_SETGID` (system-wide).
fn setgroups<K: Kernel, M: Mem>(k: &K, m: &M, size: u64, list: u64) -> i64 {
    if size > 65536 {
        return EINVAL;
    }
    match task(k, 0, false) {
        Ok(t) if t.has(CAP_SETGID) => {}
        _ => return EPERM,
    }
    let groups: Vec<u32> = if size == 0 {
        Vec::new()
    } else {
        match m.copy_in(list, size as usize * 4) {
            Ok(b) => b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect(),
            Err(_) => return EFAULT,
        }
    };
    let (r, _) = op(k, LXP_GROUPS_SET, &[0, groups.as_ptr() as u64, groups.len() as u64]);
    r.min(0)
}

/// `LXP_PGRP_GET` of process `pid`: its place, and whether another process is in group
/// `pid`.
fn pgrp<K: Kernel>(k: &K, pid: u64) -> Option<(Pgrp, bool)> {
    let (r, w) = op(k, LXP_PGRP_GET, &[pid]);
    (r >= 0).then(|| (Pgrp { pid: w[0], ppid: w[1], pgid: w[2], sid: w[3], zombie: w[4] != 0 }, w[5] != 0))
}

/// `setpgid(target, pgid)` by process `me`.
fn setpgid<K: Kernel>(k: &K, me: u64, target: u64, pgid: u64) -> i64 {
    let target = if target == 0 { me } else { target };
    for _ in 0..TRIES {
        let t = pgrp(k, target).map(|p| p.0);
        let g = match rules::setpgid(me, t, pgid) {
            Ok(g) => g,
            Err(e) => return e,
        };
        let Some(t) = t else { return ESRCH };
        match op(k, LXP_PGRP_SET, &[target, t.pgid, t.sid, g, 0, 0]).0 {
            EAGAIN => continue,
            r => return r.min(0),
        }
    }
    EAGAIN
}

/// `setsid()` by process `me`: the new session's id.
fn setsid<K: Kernel>(k: &K, me: u64) -> i64 {
    for _ in 0..TRIES {
        let p = pgrp(k, me);
        let sid = match rules::setsid(p.map(|p| p.0), p.is_some_and(|p| p.1)) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let Some((p, _)) = p else { return ESRCH };
        match op(k, LXP_PGRP_SET, &[me, p.pgid, p.sid, sid, 1, 1]).0 {
            EAGAIN => continue,
            r if r < 0 => return r,
            _ => return sid as i64,
        }
    }
    EAGAIN
}

/// Process `tgid`'s limit `res` and the descriptor table's size (`EINVAL`: no such
/// resource).
fn limit<K: Kernel>(k: &K, tgid: u64, res: u64) -> Result<((u64, u64), u64), i64> {
    let (r, w) = op(k, LXP_LIMIT_GET, &[tgid, res]);
    if r < 0 {
        Err(r)
    } else {
        Ok(((w[0], w[1]), w[2]))
    }
}

/// Sets limit `res` of process `tgid` to `new` by today's rule (`cap_resource`:
/// `CAP_SYS_RESOURCE` in the caller's effective set); the old value.
fn set_limit<K: Kernel>(k: &K, tgid: u64, res: u64, new: (u64, u64), cap_resource: bool) -> Result<(u64, u64), i64> {
    for _ in 0..TRIES {
        let (old, max_fds) = limit(k, tgid, res)?;
        rules::set_limit(res as usize, old, new, cap_resource, max_fds)?;
        match op(k, LXP_LIMIT_SET, &[tgid, res, old.0, old.1, new.0, new.1]).0 {
            EAGAIN => continue,
            r if r < 0 => return Err(r),
            _ => return Ok(old),
        }
    }
    Err(EAGAIN)
}

/// A `struct rlimit` at `ptr`.
fn read_pair<M: Mem>(m: &M, ptr: u64) -> Result<(u64, u64), i64> {
    let b = m.copy_in(ptr, 16).map_err(|_| EFAULT)?;
    Ok((u64::from_le_bytes(b[0..8].try_into().unwrap()), u64::from_le_bytes(b[8..16].try_into().unwrap())))
}

/// Writes a `struct rlimit` at `ptr`.
fn write_pair<M: Mem>(m: &M, ptr: u64, v: (u64, u64)) -> i64 {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&v.0.to_le_bytes());
    b[8..16].copy_from_slice(&v.1.to_le_bytes());
    m.copy_out(ptr, &b).map_or(EFAULT, |_| 0)
}

/// `setrlimit(res, rlim)`.
fn setrlimit<K: Kernel, M: Mem>(k: &K, m: &M, res: u64, ptr: u64) -> i64 {
    if res >= NLIMITS {
        return EINVAL;
    }
    let new = match read_pair(m, ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let cap = task(k, 0, false).is_ok_and(|t| t.eff_has(CAP_SYS_RESOURCE));
    match set_limit(k, 0, res, new, cap) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `prlimit64(pid, res, new, old)`.
fn prlimit<K: Kernel, M: Mem>(k: &K, m: &M, c: &Call, a: [u64; 6]) -> i64 {
    let res = a[1];
    if res >= NLIMITS {
        return EINVAL;
    }
    let me = c.tgid;
    let target = match a[0] as i32 {
        0 => me,
        p if p > 0 => match op(k, LXP_PID_GET, &[p as u64]) {
            (r, w) if r >= 0 => w[0],
            _ => return ESRCH,
        },
        _ => return ESRCH,
    };
    let mine = match task(k, 0, false) {
        Ok(t) => t,
        Err(e) => return e,
    };
    if target != me {
        // Another process: CAP_SYS_RESOURCE, or the same credentials (`may_access`)
        if !mine.eff_has(CAP_SYS_RESOURCE) && !may_access(k, &mine, target) {
            return EPERM;
        }
    }
    let new = if a[2] != 0 {
        match read_pair(m, a[2]) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    } else {
        None
    };
    let old = match new {
        Some(n) => match set_limit(k, target, res, n, mine.eff_has(CAP_SYS_RESOURCE)) {
            Ok(old) => old,
            Err(e) => return e,
        },
        None => match limit(k, target, res) {
            Ok((old, _)) => old,
            Err(e) => return e,
        },
    };
    if a[3] != 0 {
        return write_pair(m, a[3], old);
    }
    0
}

/// Whether the caller `me` may act on process `target`: not a service; `CAP_SYS_PTRACE`,
/// or its real id is the target's real, effective and saved id.
fn may_access<K: Kernel>(k: &K, me: &Task, target: u64) -> bool {
    let Ok(t) = task(k, target, true) else { return false };
    if t.flags & LXP_F_SERVICE != 0 {
        return false;
    }
    me.has(CAP_SYS_PTRACE) || (me.uid[0] == t.uid[0] && me.uid[0] == t.uid[1] && me.uid[0] == t.uid[2])
}

/// `prctl(option, ...)`: names, dumpable, parent-death signal, keepcaps, no_new_privs and
/// subreaper here; everything else (seccomp, auxv, Hydra's access attributes, ...) is the
/// kernel's mechanism.
fn prctl<K: Kernel, M: Mem>(k: &K, m: &M, a: [u64; 6]) -> Out {
    let set = |attr: u64, v: u64| Out::Ret(op(k, LXP_ATTR_SET, &[0, attr, v]).0.min(0));
    let int_out = |v: u64| Out::Ret(m.copy_out(a[1], &(v as i32).to_le_bytes()).map_or(EFAULT, |_| 0));
    match a[0] {
        // PR_SET_NAME: up to 15 bytes (a longer name is cut)
        15 => {
            let name = match m.cstr(a[1]) {
                Ok(n) => n,
                Err(_) => match bytewise(m, a[1]) {
                    Ok(n) => n,
                    Err(e) => return Out::Ret(e),
                },
            };
            let mut io = LxProcIo::EMPTY;
            io.a[1] = LXP_ATTR_COMM;
            let n = name.len().min(15);
            io.b[..n].copy_from_slice(&name[..n]);
            Out::Ret(k.op(LXP_ATTR_SET, &mut io).min(0))
        }
        // PR_GET_NAME
        16 => match task(k, 0, false) {
            Ok(t) => Out::Ret(m.copy_out(a[1], &t.comm).map_or(EFAULT, |_| 0)),
            Err(e) => Out::Ret(e),
        },
        // PR_SET_PDEATHSIG, PR_GET_PDEATHSIG
        1 if a[1] > 64 => Out::Ret(EINVAL),
        1 => set(LXP_ATTR_PDEATHSIG, a[1]),
        2 => match task(k, 0, false) {
            Ok(t) => int_out(t.pdeathsig),
            Err(e) => Out::Ret(e),
        },
        // PR_GET_DUMPABLE, PR_SET_DUMPABLE (0 or 1)
        3 => Out::Ret(task(k, 0, false).map_or_else(|e| e, |t| t.dumpable as i64)),
        4 if a[1] > 1 => Out::Ret(EINVAL),
        4 => set(LXP_ATTR_DUMPABLE, a[1]),
        // PR_GET_KEEPCAPS, PR_SET_KEEPCAPS
        7 => Out::Ret(task(k, 0, false).map_or_else(|e| e, |t| (t.flags & LXP_F_KEEPCAPS != 0) as i64)),
        8 if a[1] > 1 => Out::Ret(EINVAL),
        8 => set(LXP_ATTR_KEEPCAPS, a[1]),
        // PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER
        36 => set(LXP_ATTR_SUBREAPER, (a[1] != 0) as u64),
        37 => match task(k, 0, false) {
            Ok(t) => int_out((t.flags & LXP_F_SUBREAPER != 0) as u64),
            Err(e) => Out::Ret(e),
        },
        // PR_SET_NO_NEW_PRIVS (only ever set), PR_GET_NO_NEW_PRIVS
        38 if a[1] != 1 => Out::Ret(EINVAL),
        38 => set(LXP_ATTR_NNP, 1),
        39 => Out::Ret(task(k, 0, false).map_or_else(|e| e, |t| (t.flags & LXP_F_NNP != 0) as i64)),
        _ => Out::Kernel,
    }
}

/// Up to 15 bytes of the string at `ptr`, read one at a time (a short name just before an
/// unmapped page).
fn bytewise<M: Mem>(m: &M, ptr: u64) -> Result<Vec<u8>, i64> {
    let mut v = Vec::new();
    for i in 0..15 {
        let b = m.copy_in(ptr + i, 1).map_err(|_| EFAULT)?;
        if b[0] == 0 {
            break;
        }
        v.push(b[0]);
    }
    Ok(v)
}

/// `struct utsname` for the caller's UTS namespace.
pub fn utsname(host: &[u8], domain: &[u8]) -> [u8; 390] {
    let mut u = [0u8; 390];
    for (i, s) in [b"Linux".as_slice(), host, b"6.8.0-hydra", b"#1 SMP PREEMPT Hydra Microkernel", b"x86_64", domain].iter().enumerate() {
        let n = s.len().min(64);
        u[i * 65..i * 65 + n].copy_from_slice(&s[..n]);
    }
    u
}

/// `uname(buf)`.
fn uname<K: Kernel, M: Mem>(k: &K, m: &M, buf: u64) -> i64 {
    let mut io = LxProcIo::EMPTY;
    let r = k.op(LXP_UTS_GET, &mut io);
    if r < 0 {
        return r;
    }
    let field = |b: &[u8]| -> Vec<u8> { b.iter().copied().take_while(|&c| c != 0).collect() };
    let (host, dom) = (field(&io.b[..65]), field(&io.b[65..130]));
    m.copy_out(buf, &utsname(&host, &dom)).map_or(EFAULT, |_| 0)
}

/// `sethostname` / `setdomainname(name, len)`: `CAP_SYS_ADMIN` (also in the caller's own
/// user namespace).
fn set_uts<K: Kernel, M: Mem>(k: &K, m: &M, name: u64, len: u64, domain: bool) -> i64 {
    if len > 64 {
        return EINVAL;
    }
    let raw = if len == 0 {
        Vec::new()
    } else {
        match m.copy_in(name, len as usize) {
            Ok(r) => r,
            Err(_) => return EFAULT,
        }
    };
    match task(k, 0, false) {
        Ok(t) if t.eff_has(CAP_SYS_ADMIN) => {}
        _ => return EPERM,
    }
    let mut io = LxProcIo::EMPTY;
    io.a[0] = domain as u64;
    io.a[1] = raw.len() as u64;
    io.b[..raw.len()].copy_from_slice(&raw);
    k.op(LXP_UTS_SET, &mut io).min(0)
}

/// `unshare(flags)`: the rules; the kernel then makes the namespaces.
fn unshare<K: Kernel>(k: &K, flags: u64) -> Out {
    const ALLOWED: u64 = CLONE_NEW_ALL | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM | CLONE_THREAD | CLONE_SYSVSEM;
    if flags & !ALLOWED != 0 {
        return Out::Ret(EINVAL);
    }
    let t = match task(k, 0, false) {
        Ok(t) => t,
        Err(e) => return Out::Ret(e),
    };
    // A new user namespace (and unsharing threads, signal handlers or memory) needs a
    // single-threaded process
    if t.threads > 1 && flags & (CLONE_NEWUSER | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 {
        return Out::Ret(EINVAL);
    }
    let ns = flags & CLONE_NEW_ALL;
    if ns == 0 {
        return Out::Ret(0);
    }
    // Other namespace types need CAP_SYS_ADMIN, which a new user namespace provides
    if ns & !CLONE_NEWUSER != 0 && ns & CLONE_NEWUSER == 0 && !t.eff_has(CAP_SYS_ADMIN) {
        return Out::Ret(EPERM);
    }
    approve_if(k, 272, true)
}

/// `setns(fd, nstype)`: the rules; the kernel then joins.
fn setns<K: Kernel>(k: &K, fd: u64, nstype: u64) -> Out {
    let (r, w) = op(k, LXP_NS_FD, &[fd, nstype]);
    if r < 0 {
        return Out::Ret(r);
    }
    let (target, kinds) = (w[0], w[1]);
    let (r, theirs) = op(k, LXP_NS_GET, &[target]);
    if r < 0 {
        return Out::Ret(ESRCH);
    }
    let t = match task(k, 0, false) {
        Ok(t) => t,
        Err(e) => return Out::Ret(e),
    };
    let admin = t.eff_has(CAP_SYS_ADMIN);
    if kinds & CLONE_NEWUSER != 0 {
        let same = theirs[9] & 2 != 0;
        if same {
            // Joining the namespace one is already in is refused (only for user namespaces)
            if kinds == CLONE_NEWUSER {
                return Out::Ret(EINVAL);
            }
        } else {
            if t.threads > 1 {
                return Out::Ret(EINVAL);
            }
            // CAP_SYS_ADMIN in the target: it lies below ours and we own it or are privileged
            let within = theirs[9] & 1 != 0;
            if !within || !(theirs[8] == t.uid[1] as u64 || admin) {
                return Out::Ret(EPERM);
            }
        }
    }
    if kinds & !CLONE_NEWUSER != 0 && !admin && kinds & CLONE_NEWUSER == 0 {
        return Out::Ret(EPERM);
    }
    // A PID namespace is joined for children only, and only one at or below the caller's
    if kinds & CLONE_NEWPID != 0 && theirs[10] == 2 {
        return Out::Ret(EINVAL);
    }
    approve_if(k, 308, true)
}
