//! # The ptrace access rule and the decisions of the tracing calls, pure (wave 10, Group 8-1)
//!
//! One copy of Linux's `__ptrace_may_access` and of the permission decisions of `ptrace`'s
//! attach family, `perf_event_open`, `process_vm_readv`/`writev`, `kcmp` and `pidfd_getfd`.
//! It is built into the kernel (`lx::ptrace_rules`: the kernel's own copy, `lx.proc=kernel`,
//! the `/proc` read rule of `lx::info`) and into lx-proc (`#[path]`), which decides these
//! calls since wave 10.
//!
//! ## How a call is decided
//!
//! The kernel gathers the *facts* a decision reads ([`Facts`]: the caller's ids and
//! capabilities, each target's ids, dumpable flag and user-namespace relation, the call's
//! own bits) for the call as it will run it, and hands them to lx-proc as 16 words
//! ([`Facts::encode`], op 75 sub-op `LXP_TRACE_FACTS`). lx-proc runs [`decide`] and leaves the
//! verdict as an approval mark bound to [`key`] (a hash of every input, the verdict in its
//! low byte), then redirects the call to the kernel. The kernel runs its argument checks,
//! gathers the facts again where it used to check permission and takes the mark
//! ([`verdict_of`]): the same facts give lx-proc's verdict; no mark or other facts (the
//! target exec'd or changed its ids in between) and it runs [`decide`] itself.
//!
//! No Yama scope: Hydra enforces none (Yama's scope 0, "classic ptrace permissions").

/// `-EPERM`.
pub const EPERM: i64 = -1;
/// `-ESRCH`.
pub const ESRCH: i64 = -3;
/// `-EACCES`.
pub const EACCES: i64 = -13;
/// `-EINVAL`.
pub const EINVAL: i64 = -22;
/// `-ENOSYS`.
pub const ENOSYS: i64 = -38;

/// `PTRACE_MODE_READ`: looking (`/proc/<pid>/maps`, `kcmp`, `perf_event_open`).
pub const MODE_READ: u32 = 1;
/// `PTRACE_MODE_ATTACH`: changing (`ptrace` attach, `process_vm_*`, `pidfd_getfd`).
pub const MODE_ATTACH: u32 = 2;
/// `PTRACE_MODE_FSCREDS`: compare the caller's file-system ids (Hydra: the effective ones).
pub const MODE_FSCREDS: u32 = 4;
/// `PTRACE_MODE_REALCREDS`: compare the caller's real ids.
pub const MODE_REALCREDS: u32 = 8;

/// `CAP_SYS_ADMIN`.
pub const CAP_SYS_ADMIN: u32 = 21;
/// `CAP_SYS_PTRACE`.
pub const CAP_SYS_PTRACE: u32 = 19;
/// `CAP_PERFMON`.
pub const CAP_PERFMON: u32 = 38;

/// `ptrace` requests the rule decides (the others are mechanism on an attached tracee).
pub const PTRACE_TRACEME: u64 = 0;
/// `PTRACE_ATTACH`.
pub const PTRACE_ATTACH: u64 = 16;
/// `PTRACE_SETOPTIONS`.
pub const PTRACE_SETOPTIONS: u64 = 0x4200;
/// `PTRACE_SEIZE`.
pub const PTRACE_SEIZE: u64 = 0x4206;
/// `PTRACE_O_SUSPEND_SECCOMP`: needs `CAP_SYS_ADMIN` and a tracer not under seccomp.
pub const O_SUSPEND_SECCOMP: u64 = 1 << 21;

/// The call numbers decided here.
pub const NR_PTRACE: u64 = 101;
/// `perf_event_open`.
pub const NR_PERF_EVENT_OPEN: u64 = 298;
/// `process_vm_readv`.
pub const NR_PROCESS_VM_READV: u64 = 310;
/// `process_vm_writev`.
pub const NR_PROCESS_VM_WRITEV: u64 = 311;
/// `kcmp`.
pub const NR_KCMP: u64 = 312;
/// `pidfd_getfd`.
pub const NR_PIDFD_GETFD: u64 = 438;

/// [`Facts::kind`] of a `ptrace` call.
pub const K_ATTACH: u8 = 1;
/// `PTRACE_SEIZE`.
pub const K_SEIZE: u8 = 2;
/// `PTRACE_TRACEME`.
pub const K_TRACEME: u8 = 3;
/// `PTRACE_SETOPTIONS`.
pub const K_SETOPTIONS: u8 = 4;

/// [`Facts::extra`] of `perf_event_open`: the event counts kernel mode too (`exclude_kernel`
/// clear).
pub const PERF_KERNEL: u32 = 1;
/// Bits 1..2 of [`Facts::extra`] of `perf_event_open`: which task (`pid`).
pub const PERF_PID_SHIFT: u32 = 1;
/// `pid` 0: the caller.
pub const PERF_PID_SELF: u32 = 0;
/// `pid` > 0: another task (target 0; absent: none such).
pub const PERF_PID_OTHER: u32 = 1;
/// `pid` -1: every task on a CPU.
pub const PERF_PID_CPU: u32 = 2;
/// `pid` < -1.
pub const PERF_PID_BAD: u32 = 3;

/// Whether a `ptrace(request, ..., data)` is decided by the rule (and so goes to lx-proc
/// when the calls are forwarded): the attach family, and options asking to suspend seccomp.
/// Every other request is mechanism on a tracee already attached: the kernel answers it.
#[inline]
pub fn ptrace_routed(request: u64, data: u64) -> bool {
    matches!(request, PTRACE_TRACEME | PTRACE_ATTACH | PTRACE_SEIZE) || (request == PTRACE_SETOPTIONS && data & O_SUSPEND_SECCOMP != 0)
}

/// [`Facts::kind`] of a `ptrace` request (0: not one the rule decides).
pub fn ptrace_kind(request: u64) -> u8 {
    match request {
        PTRACE_ATTACH => K_ATTACH,
        PTRACE_SEIZE => K_SEIZE,
        PTRACE_TRACEME => K_TRACEME,
        PTRACE_SETOPTIONS => K_SETOPTIONS,
        _ => 0,
    }
}

/// The caller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Who {
    /// Real, effective, saved user id (the file-system id is the effective one).
    pub uid: [u32; 3],
    /// Real, effective, saved group id.
    pub gid: [u32; 3],
    /// Effective capabilities (also those holding only in its own user namespace).
    pub caps: u64,
    /// It is in a user namespace of its own (its capabilities hold only there and below).
    pub in_userns: bool,
    /// It runs under seccomp (strict or filter).
    pub seccomp: bool,
}

impl Who {
    /// Whether it holds `cap` system-wide (Linux's `capable`: in the first user namespace).
    pub fn capable(&self, cap: u32) -> bool {
        !self.in_userns && self.caps & (1 << cap) != 0
    }
}

/// A target process (one of its threads).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Target {
    /// Process id (system-wide).
    pub tgid: u64,
    /// The thread named (the process's first thread when a process was named).
    pub tid: u64,
    /// Real, effective, saved user id.
    pub uid: [u32; 3],
    /// Real, effective, saved group id.
    pub gid: [u32; 3],
    /// It is the caller's own process.
    pub same: bool,
    /// It is a service's process (not a Linux process: never reachable).
    pub service: bool,
    /// Its user namespace is the caller's or lies below it (the caller's capabilities count
    /// there).
    pub within: bool,
    /// `PR_SET_DUMPABLE` (0, 1, 2); only 1 lets processes of the same ids in.
    pub dumpable: u8,
}

/// Whether the caller holds `cap` over target `t` (Linux's `ns_capable(t's user ns)`): in
/// its effective set, and `t`'s user namespace at or below the caller's.
pub fn cap_over(who: &Who, t: &Target, cap: u32) -> bool {
    who.caps & (1 << cap) != 0 && t.within
}

/// Linux's `__ptrace_may_access(t, mode)`: its own process always; a service's process
/// never; with the ids of `mode` (`MODE_FSCREDS`: effective, else real) equal to the
/// target's real, effective and saved user ids **and** group ids, or `CAP_SYS_PTRACE` over
/// it; and then a target that is not dumpable only with `CAP_SYS_PTRACE` over it.
pub fn may_access(mode: u32, who: &Who, t: &Target) -> Result<(), i64> {
    if t.same {
        return Ok(());
    }
    if t.service {
        return Err(EPERM);
    }
    let (u, g) = if mode & MODE_FSCREDS != 0 { (who.uid[1], who.gid[1]) } else { (who.uid[0], who.gid[0]) };
    let ids_match = t.uid.iter().all(|&x| x == u) && t.gid.iter().all(|&x| x == g);
    let cap = cap_over(who, t, CAP_SYS_PTRACE);
    if !ids_match && !cap {
        return Err(EPERM);
    }
    if t.dumpable != 1 && !cap {
        return Err(EPERM);
    }
    Ok(())
}

/// Linux's `commit_creds` rule for the dumpable flag: a credential change from `old` to `new`
/// (effective user id, effective group id, permitted capabilities; Hydra's file-system ids
/// are the effective ones) leaves the process not dumpable when an effective id changes or
/// capabilities are gained (dropping them does not).
pub fn creds_clear_dumpable(old: (u32, u32, u64), new: (u32, u32, u64)) -> bool {
    old.0 != new.0 || old.1 != new.1 || new.2 & !old.2 != 0
}

/// The inputs of one decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// System call number.
    pub nr: u64,
    /// `ptrace`: `K_*`; 0 otherwise.
    pub kind: u8,
    /// `ptrace` SEIZE/SETOPTIONS: the options; `perf_event_open`: `PERF_*` bits.
    pub extra: u32,
    /// `perf_event_open`: the CPU argument.
    pub cpu: i32,
    /// The caller.
    pub who: Who,
    /// The targets (`kcmp`: two; `perf_event_open` of the caller or a CPU: none).
    pub t: [Option<Target>; 2],
}

const T_PRESENT: u64 = 1;
const T_SAME: u64 = 2;
const T_SERVICE: u64 = 4;
const T_WITHIN: u64 = 8;
const W_USERNS: u64 = 1;
const W_SECCOMP: u64 = 2;

fn pack(lo: u32, hi: u32) -> u64 {
    lo as u64 | (hi as u64) << 32
}

fn lo(w: u64) -> u32 {
    w as u32
}

fn hi(w: u64) -> u32 {
    (w >> 32) as u32
}

impl Facts {
    /// The 16 words of `LXP_TRACE_FACTS`: `[0]` call | kind << 16 | extra << 32; `[1..4]` the
    /// caller's ids (uid, euid | suid, gid | egid, sgid packed by twos); `[4]` its effective
    /// capabilities; `[5]` its flags | cpu << 32; `[6..11]` and `[11..16]` the targets (tgid
    /// | tid << 32, ids by twos, flags | dumpable << 8).
    pub fn encode(&self) -> [u64; 16] {
        let mut w = [0u64; 16];
        w[0] = (self.nr & 0xffff) | (self.kind as u64) << 16 | (self.extra as u64) << 32;
        let (u, g) = (self.who.uid, self.who.gid);
        w[1] = pack(u[0], u[1]);
        w[2] = pack(u[2], g[0]);
        w[3] = pack(g[1], g[2]);
        w[4] = self.who.caps;
        w[5] = (self.who.in_userns as u64 * W_USERNS) | (self.who.seccomp as u64 * W_SECCOMP) | (self.cpu as u32 as u64) << 32;
        for (i, t) in self.t.iter().enumerate() {
            let b = 6 + 5 * i;
            if let Some(t) = t {
                w[b] = pack(t.tgid as u32, t.tid as u32);
                w[b + 1] = pack(t.uid[0], t.uid[1]);
                w[b + 2] = pack(t.uid[2], t.gid[0]);
                w[b + 3] = pack(t.gid[1], t.gid[2]);
                w[b + 4] = T_PRESENT | (t.same as u64 * T_SAME) | (t.service as u64 * T_SERVICE) | (t.within as u64 * T_WITHIN) | (t.dumpable as u64) << 8;
            }
        }
        w
    }

    /// [`Facts::encode`] read back.
    pub fn decode(w: &[u64; 16]) -> Facts {
        let mut t = [None; 2];
        for (i, slot) in t.iter_mut().enumerate() {
            let b = 6 + 5 * i;
            let f = w[b + 4];
            if f & T_PRESENT != 0 {
                *slot = Some(Target {
                    tgid: lo(w[b]) as u64,
                    tid: hi(w[b]) as u64,
                    uid: [lo(w[b + 1]), hi(w[b + 1]), lo(w[b + 2])],
                    gid: [hi(w[b + 2]), lo(w[b + 3]), hi(w[b + 3])],
                    same: f & T_SAME != 0,
                    service: f & T_SERVICE != 0,
                    within: f & T_WITHIN != 0,
                    dumpable: (f >> 8) as u8,
                });
            }
        }
        Facts {
            nr: w[0] & 0xffff,
            kind: (w[0] >> 16) as u8,
            extra: hi(w[0]),
            cpu: hi(w[5]) as i32,
            who: Who {
                uid: [lo(w[1]), hi(w[1]), lo(w[2])],
                gid: [hi(w[2]), lo(w[3]), hi(w[3])],
                caps: w[4],
                in_userns: w[5] & W_USERNS != 0,
                seccomp: w[5] & W_SECCOMP != 0,
            },
            t,
        }
    }
}

/// `PTRACE_O_SUSPEND_SECCOMP` (Linux's `check_ptrace_options`): `CAP_SYS_ADMIN` system-wide,
/// and the tracer itself not under seccomp.
fn suspend_ok(who: &Who, options: u32) -> Result<(), i64> {
    if options as u64 & O_SUSPEND_SECCOMP != 0 && (!who.capable(CAP_SYS_ADMIN) || who.seccomp) {
        return Err(EPERM);
    }
    Ok(())
}

/// The decision of the call the facts describe, in the order the kernel's code reports its
/// errors: `Ok` or the errno.
pub fn decide(f: &Facts) -> Result<(), i64> {
    let who = &f.who;
    match f.nr {
        NR_PTRACE => match f.kind {
            K_ATTACH | K_SEIZE => {
                let t = f.t[0].ok_or(ESRCH)?;
                // (attaching to one's own process is refused, unlike the access rule)
                if t.same {
                    return Err(EPERM);
                }
                may_access(MODE_ATTACH | MODE_REALCREDS, who, &t)?;
                if f.kind == K_SEIZE {
                    suspend_ok(who, f.extra)?;
                }
                Ok(())
            }
            // Linux checks nothing for TRACEME but Yama's scope 3 (Hydra has no Yama)
            K_TRACEME => Ok(()),
            K_SETOPTIONS => suspend_ok(who, f.extra),
            _ => Err(EINVAL),
        },
        NR_PERF_EVENT_OPEN => {
            // perf_event_paranoid = 2: kernel-mode counting and whole-CPU events are for
            // CAP_PERFMON or CAP_SYS_ADMIN; another task by the ptrace read rule
            let privileged = who.capable(CAP_PERFMON) || who.capable(CAP_SYS_ADMIN);
            if f.extra & PERF_KERNEL != 0 && !privileged {
                return Err(EACCES);
            }
            if f.cpu < -1 || f.cpu > 0 {
                return Err(EINVAL); // one CPU
            }
            match (f.extra >> PERF_PID_SHIFT) & 3 {
                PERF_PID_CPU => {
                    if f.cpu < 0 {
                        Err(EINVAL)
                    } else if !privileged {
                        Err(EACCES)
                    } else {
                        Ok(())
                    }
                }
                PERF_PID_SELF => Ok(()),
                PERF_PID_OTHER => {
                    let t = f.t[0].ok_or(ESRCH)?;
                    may_access(MODE_READ | MODE_REALCREDS, who, &t).map_err(|_| EACCES)
                }
                _ => Err(ESRCH),
            }
        }
        NR_PROCESS_VM_READV | NR_PROCESS_VM_WRITEV | NR_PIDFD_GETFD => may_access(MODE_ATTACH | MODE_REALCREDS, who, &f.t[0].ok_or(ESRCH)?),
        NR_KCMP => {
            for t in f.t {
                may_access(MODE_READ | MODE_REALCREDS, who, &t.ok_or(ESRCH)?)?;
            }
            Ok(())
        }
        _ => Err(ENOSYS),
    }
}

/// The hash of facts words (never 0 above the low byte, bit 63 set).
fn hash(w: &[u64; 16]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ 0x8100;
    for v in w {
        h = (h ^ v).wrapping_mul(0x0000_0100_0000_01b3).rotate_left(23);
    }
    (h & !0xff) | 1 << 63
}

/// The approval key of a decision: the hash of every input (`w`, [`Facts::encode`]), the
/// verdict (0 or an errno up to 255) in the low byte.
pub fn key(w: &[u64; 16], verdict: i64) -> u64 {
    hash(w) | (verdict.unsigned_abs() & 0xff)
}

/// The verdict a mark (`key`) gave the facts `w`: `Some(0)` or `Some(errno)` when it was
/// given for exactly these facts, `None` otherwise (the kernel decides itself).
pub fn verdict_of(key: u64, w: &[u64; 16]) -> Option<i64> {
    (key & !0xff == hash(w)).then(|| -((key & 0xff) as i64))
}

/// The answer of a decision as a verdict word (0 or the negative errno).
pub fn verdict(r: Result<(), i64>) -> i64 {
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}
