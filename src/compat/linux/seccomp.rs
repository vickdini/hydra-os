//! Secure computing (`seccomp`) for the Linux personality: strict mode and classic-BPF
//! syscall filters, as Chromium's and Brave's sandbox installs them.
//!
//! - **State**: every task carries a [`State`] — the `no_new_privs` bit, the mode, and the
//!   head of a chain of filters. Children inherit it on `clone`/`fork`, `execve` keeps it,
//!   and a new filter is pushed in front of the existing chain (filters only ever add).
//! - **Evaluation**: [`check`] runs at the top of every Linux system call; it builds a
//!   `struct seccomp_data` from the registers, runs every filter in the chain, and takes the
//!   most restrictive answer.
//! - **Actions**: `ALLOW`/`LOG` run the call; `ERRNO` fails it; `TRAP` skips it and raises
//!   `SIGSYS` with the `si_syscall`/`si_call_addr` fields Chromium's handler reads;
//!   `KILL_*` end the process; `TRACE`/`USER_NOTIF` (no tracer, no listener) fail with
//!   `ENOSYS`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::syscall::SyscallFrame;

/// `AUDIT_ARCH_X86_64`: the `arch` field of `seccomp_data` for 64-bit calls.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `seccomp(2)` operation: strict mode (only `read`, `write`, `exit`, `rt_sigreturn`).
const SECCOMP_SET_MODE_STRICT: u64 = 0;
/// `seccomp(2)` operation: install a BPF filter.
const SECCOMP_SET_MODE_FILTER: u64 = 1;
/// `seccomp(2)` operation: is this filter return action supported?
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
/// `seccomp(2)` operation: sizes of the user-notification structures.
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;

/// Filter flag: apply the filter to every thread of the process.
const FLAG_TSYNC: u64 = 1;
/// Filter flag: log every action except `ALLOW`.
const FLAG_LOG: u64 = 2;
/// Filter flag: do not force speculative-store-bypass mitigation.
const FLAG_SPEC_ALLOW: u64 = 4;
/// Filter flag: return a user-notification listener fd (not supported).
const FLAG_NEW_LISTENER: u64 = 8;
/// Filter flag: with `TSYNC`, report a failing thread as `-ESRCH`.
const FLAG_TSYNC_ESRCH: u64 = 16;

/// Return action: kill the whole process.
const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Return action: kill the thread.
const RET_KILL_THREAD: u32 = 0x0000_0000;
/// Return action: raise `SIGSYS`.
const RET_TRAP: u32 = 0x0003_0000;
/// Return action: fail with the errno in the low 16 bits.
const RET_ERRNO: u32 = 0x0005_0000;
/// Return action: pass to a user-space listener.
const RET_USER_NOTIF: u32 = 0x7FC0_0000;
/// Return action: pass to a `ptrace` tracer.
const RET_TRACE: u32 = 0x7FF0_0000;
/// Return action: allow and log.
const RET_LOG: u32 = 0x7FFC_0000;
/// Return action: allow.
const RET_ALLOW: u32 = 0x7FFF_0000;
/// Mask selecting the action of a filter's return value.
const RET_ACTION_FULL: u32 = 0xFFFF_0000;
/// Mask selecting the data (errno) of a filter's return value.
const RET_DATA: u32 = 0x0000_FFFF;

/// Largest program `seccomp` accepts (`BPF_MAXINSNS`).
const MAX_INSNS: usize = 4096;
/// Largest total instruction count of a task's filter chain (`MAX_INSNS_PER_PATH`).
const MAX_CHAIN_INSNS: usize = (1 << 18) / 8;
/// Size of `struct seccomp_data`.
const DATA_LEN: u32 = 64;
/// Number of scratch memory words (`BPF_MEMWORDS`).
const MEMWORDS: usize = 16;

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const EACCES: i64 = -13;
const ENOMEM: i64 = -12;
const ENOSYS: i64 = -38;
const EOPNOTSUPP: i64 = -95;

/// Set once any task installs a filter, so tasks never filtered skip the lookup.
static ANY_FILTER: AtomicBool = AtomicBool::new(false);

/// One classic-BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// One installed filter, linked to the filters installed before it.
pub struct Filter {
    prog: Vec<Insn>,
    /// Log the actions this filter takes (`SECCOMP_FILTER_FLAG_LOG`).
    log: bool,
    prev: Option<Arc<Filter>>,
    /// Instructions in this filter and every earlier one.
    chain_len: usize,
}

/// A task's seccomp state.
#[derive(Clone, Default)]
pub struct State {
    /// `PR_SET_NO_NEW_PRIVS`: `execve` never grants privileges.
    pub no_new_privs: bool,
    /// 0 disabled, 1 strict, 2 filter (what `PR_GET_SECCOMP` reports).
    pub mode: u8,
    /// Most recently installed filter.
    pub filter: Option<Arc<Filter>>,
    /// Landlock domain (kept here: inherited and kept across `execve` the same way).
    pub landlock: Option<Arc<super::landlock::Domain>>,
}

// BPF opcode fields
const CLASS_LD: u16 = 0x00;
const CLASS_LDX: u16 = 0x01;
const CLASS_ST: u16 = 0x02;
const CLASS_STX: u16 = 0x03;
const CLASS_ALU: u16 = 0x04;
const CLASS_JMP: u16 = 0x05;
const CLASS_RET: u16 = 0x06;
const CLASS_MISC: u16 = 0x07;
const SIZE_W: u16 = 0x00;
const MODE_IMM: u16 = 0x00;
const MODE_ABS: u16 = 0x20;
const MODE_MEM: u16 = 0x60;
const MODE_LEN: u16 = 0x80;
const SRC_X: u16 = 0x08;
const RVAL_A: u16 = 0x10;
const ALU_ADD: u16 = 0x00;
const ALU_SUB: u16 = 0x10;
const ALU_MUL: u16 = 0x20;
const ALU_DIV: u16 = 0x30;
const ALU_OR: u16 = 0x40;
const ALU_AND: u16 = 0x50;
const ALU_LSH: u16 = 0x60;
const ALU_RSH: u16 = 0x70;
const ALU_NEG: u16 = 0x80;
const ALU_MOD: u16 = 0x90;
const ALU_XOR: u16 = 0xa0;
const JMP_JA: u16 = 0x00;
const JMP_JEQ: u16 = 0x10;
const JMP_JGT: u16 = 0x20;
const JMP_JGE: u16 = 0x30;
const JMP_JSET: u16 = 0x40;
const MISC_TAX: u16 = 0x00;
const MISC_TXA: u16 = 0x80;

/// Checks a program the way the kernel's `seccomp_check_filter` does: only the
/// instructions seccomp allows, loads aligned inside `seccomp_data`, scratch slots in
/// range, jumps inside the program, no constant division by zero, and a final `RET`.
fn validate(prog: &[Insn]) -> bool {
    if prog.is_empty() || prog.len() > MAX_INSNS {
        return false;
    }
    for (pc, i) in prog.iter().enumerate() {
        let class = i.code & 0x07;
        let ok = match class {
            CLASS_LD | CLASS_LDX => {
                let mode = i.code & 0xe0;
                let size_ok = i.code & 0x18 == SIZE_W;
                match mode {
                    MODE_ABS => class == CLASS_LD && size_ok && i.k % 4 == 0 && i.k < DATA_LEN,
                    MODE_LEN | MODE_IMM => size_ok,
                    MODE_MEM => size_ok && (i.k as usize) < MEMWORDS,
                    _ => false,
                }
            }
            CLASS_ST | CLASS_STX => i.code & !0x07 == 0 && (i.k as usize) < MEMWORDS,
            CLASS_ALU => {
                let op = i.code & 0xf0;
                let k_src = i.code & SRC_X == 0;
                match op {
                    ALU_DIV | ALU_MOD => !(k_src && i.k == 0),
                    ALU_ADD | ALU_SUB | ALU_MUL | ALU_OR | ALU_AND | ALU_LSH | ALU_RSH | ALU_XOR | ALU_NEG => true,
                    _ => false,
                }
            }
            CLASS_JMP => {
                let rest = prog.len() - pc - 1;
                match i.code & 0xf0 {
                    JMP_JA => i.code & SRC_X == 0 && (i.k as usize) < rest,
                    JMP_JEQ | JMP_JGT | JMP_JGE | JMP_JSET => (i.jt as usize) < rest && (i.jf as usize) < rest,
                    _ => false,
                }
            }
            CLASS_RET => matches!(i.code & 0x18, 0x00 | RVAL_A) && i.code & !0x1f == 0,
            CLASS_MISC => matches!(i.code & 0xf8, MISC_TAX | MISC_TXA),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    prog.last().map_or(false, |i| i.code & 0x07 == CLASS_RET)
}

/// Runs a validated program over `data` (`struct seccomp_data` as 16 words).
fn run(prog: &[Insn], data: &[u32; 16]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; MEMWORDS];
    let mut pc = 0usize;
    while pc < prog.len() {
        let i = prog[pc];
        pc += 1;
        match i.code & 0x07 {
            CLASS_LD => {
                a = match i.code & 0xe0 {
                    MODE_ABS => data[(i.k / 4) as usize],
                    MODE_LEN => DATA_LEN,
                    MODE_MEM => mem[i.k as usize],
                    _ => i.k,
                }
            }
            CLASS_LDX => {
                x = match i.code & 0xe0 {
                    MODE_LEN => DATA_LEN,
                    MODE_MEM => mem[i.k as usize],
                    _ => i.k,
                }
            }
            CLASS_ST => mem[i.k as usize] = a,
            CLASS_STX => mem[i.k as usize] = x,
            CLASS_ALU => {
                let v = if i.code & SRC_X != 0 { x } else { i.k };
                a = match i.code & 0xf0 {
                    ALU_ADD => a.wrapping_add(v),
                    ALU_SUB => a.wrapping_sub(v),
                    ALU_MUL => a.wrapping_mul(v),
                    ALU_DIV => {
                        if v == 0 {
                            return RET_KILL_THREAD;
                        }
                        a / v
                    }
                    ALU_MOD => {
                        if v == 0 {
                            return RET_KILL_THREAD;
                        }
                        a % v
                    }
                    ALU_OR => a | v,
                    ALU_AND => a & v,
                    ALU_LSH => if v >= 32 { 0 } else { a << v },
                    ALU_RSH => if v >= 32 { 0 } else { a >> v },
                    ALU_XOR => a ^ v,
                    _ => a.wrapping_neg(),
                }
            }
            CLASS_JMP => {
                let v = if i.code & SRC_X != 0 { x } else { i.k };
                let taken = match i.code & 0xf0 {
                    JMP_JA => {
                        pc += i.k as usize;
                        continue;
                    }
                    JMP_JEQ => a == v,
                    JMP_JGT => a > v,
                    JMP_JGE => a >= v,
                    _ => a & v != 0,
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            CLASS_RET => return if i.code & RVAL_A != 0 { a } else { i.k },
            _ => {
                if i.code & 0xf8 == MISC_TXA {
                    a = x
                } else {
                    x = a
                }
            }
        }
    }
    RET_KILL_THREAD
}

/// Orders actions from most to least restrictive, as the kernel does (signed compare).
fn precedence(ret: u32) -> i32 {
    (ret & RET_ACTION_FULL) as i32
}

/// What the system call dispatcher should do with a call after filtering.
pub enum Verdict {
    /// Run the call.
    Allow,
    /// Skip the call and return this value.
    Return(i64),
}

/// Runs the calling task's filters on the call in `frame`.
///
/// # Arguments
/// * `frame` - Registers of the call being made.
///
/// # Returns
/// Whether to run the call or what to return instead. A `KILL` action does not return.
pub fn check(frame: &mut SyscallFrame) -> Verdict {
    if !ANY_FILTER.load(Ordering::Relaxed) {
        return Verdict::Allow;
    }
    let state = crate::task::with_current_task_mut(|t| (t.seccomp.mode, t.seccomp.filter.clone()));
    let (mode, filter) = match state {
        Some((m, f)) if m != 0 => (m, f),
        _ => return Verdict::Allow,
    };
    let nr = frame.rax;
    let ret = if mode == 1 {
        // Strict: read, write, exit, rt_sigreturn
        if !matches!(nr, 0 | 1 | 60 | 15) {
            crate::compat::linux::proc::die_by_signal(9);
        }
        RET_ALLOW
    } else {
        let args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
        let mut data = [0u32; 16];
        data[0] = nr as u32;
        data[1] = AUDIT_ARCH_X86_64;
        data[2] = frame.rip as u32;
        data[3] = (frame.rip >> 32) as u32;
        for (i, a) in args.iter().enumerate() {
            data[4 + i * 2] = *a as u32;
            data[5 + i * 2] = (*a >> 32) as u32;
        }
        let mut best = RET_ALLOW;
        let mut log = false;
        let mut f = filter.as_deref();
        while let Some(cur) = f {
            let r = run(&cur.prog, &data);
            if precedence(r) < precedence(best) {
                best = r;
                log = cur.log;
            }
            f = cur.prev.as_deref();
        }
        if log && best & RET_ACTION_FULL != RET_ALLOW {
            crate::kprintln!("[seccomp] syscall {} action {:#x}", nr, best);
        }
        best
    };
    let data = (ret & RET_DATA) as i64;
    match ret & RET_ACTION_FULL {
        RET_ALLOW | RET_LOG => Verdict::Allow,
        RET_ERRNO => Verdict::Return(-data.min(4095)),
        RET_TRAP => {
            crate::compat::linux::proc::force_seccomp_sigsys(nr as i32, frame.rip, data as i32);
            // The handler sees the call number in rax, as after the kernel's rollback
            Verdict::Return(nr as i64)
        }
        RET_TRACE | RET_USER_NOTIF => Verdict::Return(ENOSYS),
        _ => {
            crate::kprintln!("[seccomp] killed on syscall {}", nr);
            crate::compat::linux::proc::die_by_signal(31);
        }
    }
}

/// Copies a `struct sock_fprog` program in from user memory.
fn read_prog(uargs: u64) -> Result<Vec<Insn>, i64> {
    if uargs == 0 || !crate::memory::vm::prefault_current(uargs, 16, false) {
        return Err(EFAULT);
    }
    let hdr = unsafe { core::ptr::read_unaligned(uargs as *const [u64; 2]) };
    let len = (hdr[0] & 0xffff) as usize;
    let ptr = hdr[1];
    if len == 0 || len > MAX_INSNS {
        return Err(EINVAL);
    }
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, (len * 8) as u64, false) {
        return Err(EFAULT);
    }
    let raw = unsafe { core::slice::from_raw_parts(ptr as *const [u8; 8], len) };
    let prog: Vec<Insn> = raw
        .iter()
        .map(|b| Insn {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
        .collect();
    if !validate(&prog) {
        return Err(EINVAL);
    }
    Ok(prog)
}

/// Whether the caller may install a filter: `no_new_privs` set, or `CAP_SYS_ADMIN` (21).
fn may_filter() -> bool {
    crate::task::with_current_task_mut(|t| t.seccomp.no_new_privs || t.caps.effective & (1 << 21) != 0).unwrap_or(false)
}

/// Installs a filter (`SECCOMP_SET_MODE_FILTER`).
fn set_filter(flags: u64, uargs: u64) -> i64 {
    if flags & !(FLAG_TSYNC | FLAG_LOG | FLAG_SPEC_ALLOW | FLAG_TSYNC_ESRCH) != 0 {
        return if flags & FLAG_NEW_LISTENER != 0 { EOPNOTSUPP } else { EINVAL };
    }
    if !may_filter() {
        return EACCES;
    }
    let prog = match read_prog(uargs) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let log = flags & FLAG_LOG != 0;
    let installed = crate::task::with_current_task_mut(|t| {
        if t.seccomp.mode == 1 {
            return Err(EINVAL);
        }
        let prev = t.seccomp.filter.clone();
        let chain_len = prog.len() + prev.as_ref().map_or(0, |p| p.chain_len);
        if chain_len > MAX_CHAIN_INSNS {
            return Err(ENOMEM);
        }
        let f = Arc::new(Filter { prog, log, prev, chain_len });
        t.seccomp.filter = Some(f.clone());
        t.seccomp.mode = 2;
        Ok((f, t.tgid, t.id.0 as u64))
    });
    let (f, tgid, me) = match installed {
        Some(Ok(v)) => v,
        Some(Err(e)) => return e,
        None => return EINVAL,
    };
    ANY_FILTER.store(true, Ordering::Relaxed);
    if flags & FLAG_TSYNC != 0 {
        // Every other thread gets the caller's chain. Their chains are always ancestors of
        // the caller's here (threads that install filters do so before spawning others).
        let mut sched = crate::task::SCHEDULER.lock();
        sched.for_each_task_mut(|t| {
            if t.tgid == tgid && t.id.0 as u64 != me {
                t.seccomp.filter = Some(f.clone());
                t.seccomp.mode = 2;
                t.seccomp.no_new_privs = true;
            }
        });
    }
    0
}

/// `seccomp(2)`.
///
/// # Arguments
/// * `op` - Operation (`SECCOMP_SET_MODE_*`, `SECCOMP_GET_*`).
/// * `flags` - Operation flags.
/// * `uargs` - Operation argument pointer.
///
/// # Returns
/// 0 (or the requested value) on success, or a negative errno.
pub fn sys_seccomp(op: u64, flags: u64, uargs: u64) -> i64 {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 {
                return EINVAL;
            }
            let r = crate::task::with_current_task_mut(|t| {
                if t.seccomp.mode == 2 {
                    EINVAL
                } else {
                    t.seccomp.mode = 1;
                    0
                }
            })
            .unwrap_or(EINVAL);
            ANY_FILTER.store(true, Ordering::Relaxed);
            r
        }
        SECCOMP_SET_MODE_FILTER => set_filter(flags, uargs),
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 || uargs == 0 || !crate::memory::vm::prefault_current(uargs, 4, false) {
                return if flags != 0 { EINVAL } else { EFAULT };
            }
            let action = unsafe { core::ptr::read_unaligned(uargs as *const u32) };
            match action {
                RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP | RET_ERRNO | RET_TRACE | RET_LOG | RET_ALLOW => 0,
                _ => EOPNOTSUPP,
            }
        }
        SECCOMP_GET_NOTIF_SIZES => EOPNOTSUPP,
        _ => EINVAL,
    }
}

/// `prctl` options for seccomp and `no_new_privs`, or `None` for other options.
///
/// # Arguments
/// * `option` - `prctl` option.
/// * `a2` - Second argument.
/// * `a3` - Third argument.
///
/// # Returns
/// The `prctl` result for the options handled here.
pub fn prctl(option: u64, a2: u64, a3: u64) -> Option<i64> {
    Some(match option {
        21 => crate::task::with_current_task_mut(|t| t.seccomp.mode as i64).unwrap_or(0), // PR_GET_SECCOMP
        22 => match a2 {
            // PR_SET_SECCOMP
            1 => sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0),
            2 => sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, a3),
            _ => EINVAL,
        },
        38 => {
            // PR_SET_NO_NEW_PRIVS
            if a2 != 1 {
                return Some(EINVAL);
            }
            crate::task::with_current_task_mut(|t| t.seccomp.no_new_privs = true);
            0
        }
        39 => crate::task::with_current_task_mut(|t| t.seccomp.no_new_privs as i64).unwrap_or(0), // PR_GET_NO_NEW_PRIVS
        _ => return None,
    })
}

/// The calling task's `(no_new_privs, mode)`, for `/proc/<pid>/status`.
pub fn status_of(pid: u64) -> (bool, u8) {
    crate::task::SCHEDULER
        .lock()
        .with_process(pid, |t| (t.seccomp.no_new_privs, t.seccomp.mode))
        .unwrap_or((false, 0))
}
