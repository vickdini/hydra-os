//! # Linux Processes and Signals
//!
//! The process table (parent/child links, process groups, sessions, exit status and
//! zombies), POSIX signals (dispositions, masks, pending sets, delivery, `rt_sigreturn`),
//! and the `wait4`/`waitid`/`kill` family.
//!
//! ## Model
//!
//! A process is a thread group (`tgid`). Signal dispositions and process-directed
//! pending signals belong to the process; each thread has its own mask, pending set and
//! alternate stack. Signals are delivered when a thread returns to user mode, either from
//! a system call ([`deliver_on_syscall_return`]) or from an interrupt or exception
//! ([`deliver_on_trap_return`]). The signal frame on the user stack has exactly the layout
//! of Linux's x86_64 `rt_sigframe`, so the C library's `sa_restorer` trampoline and
//! `ucontext_t` accessors work unchanged.
//!
//! Blocking system calls poll for completion and return [`ERESTARTSYS`] when a signal
//! arrives; delivery turns that into a transparent restart (`SA_RESTART` or an ignored
//! signal) or `-EINTR`.
//!
//! Lock order: the scheduler lock may be held while taking [`PROCS`], never the reverse.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::arch::idt::{ExceptionContext, FpuState};
use crate::arch::syscall::SyscallFrame;
use crate::memory::vm::prefault_current;

pub const NSIG: usize = 64;

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGWINCH: u32 = 28;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

const SA_SIGINFO: u64 = 0x4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;

const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;

/// Internal return value of interrupted blocking system calls (never seen by user code).
pub const ERESTARTSYS: i64 = -512;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const ECHILD: i64 = -10;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

/// Kernel `struct sigaction` for x86_64.
#[derive(Clone, Copy, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

#[derive(Clone, Copy, Default)]
struct ThreadSig {
    mask: u64,
    pending: u64,
    alt_sp: u64,
    alt_size: u64,
    alt_flags: u32,
}

/// One process (thread group).
pub struct Process {
    pub pid: u64,
    pub ppid: u64,
    pub pgid: u64,
    pub sid: u64,
    pub actions: [SigAction; NSIG + 1],
    pub pending: u64,
    threads: BTreeMap<u64, ThreadSig>,
    /// Exit status in `wait` encoding, set by `exit_group` or a fatal signal.
    pub exit_status: Option<i32>,
    /// Set once every thread has exited (zombie until reaped).
    pub zombie: bool,
    /// `vfork` parent waits until this child execs or exits.
    pub vfork_released: bool,
}

/// All Linux processes, including zombies not yet reaped.
pub static PROCS: Mutex<BTreeMap<u64, Process>> = Mutex::new(BTreeMap::new());

fn bit(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

/// The calling thread's (tid, pid).
pub fn current_ids() -> (u64, u64) {
    crate::task::with_current_task_mut(|t| (t.id.0, t.tgid)).unwrap_or((0, 0))
}

// ----------------------------------------------------------------------
// Process table
// ----------------------------------------------------------------------

/// Registers a new process with a single thread. A child inherits its parent's process
/// group, session and signal dispositions (`fork`); otherwise it starts its own session.
pub fn register_process(pid: u64, ppid: u64, tid: u64, inherit_from: Option<u64>) {
    let mut procs = PROCS.lock();
    let (pgid, sid, actions, mask) = match inherit_from.and_then(|p| procs.get(&p)) {
        Some(parent) => {
            let mask = parent.threads.values().next().map(|t| t.mask).unwrap_or(0);
            (parent.pgid, parent.sid, parent.actions, mask)
        }
        None => (pid, pid, [SigAction::default(); NSIG + 1], 0),
    };
    let mut threads = BTreeMap::new();
    threads.insert(tid, ThreadSig { mask, ..ThreadSig::default() });
    procs.insert(
        pid,
        Process {
            pid,
            ppid,
            pgid,
            sid,
            actions,
            pending: 0,
            threads,
            exit_status: None,
            zombie: false,
            vfork_released: false,
        },
    );
}

/// Adds a thread to an existing process (inherits the creating thread's mask).
pub fn register_thread(pid: u64, tid: u64, creator: u64) {
    let mut procs = PROCS.lock();
    if let Some(p) = procs.get_mut(&pid) {
        let mask = p.threads.get(&creator).map(|t| t.mask).unwrap_or(0);
        p.threads.insert(tid, ThreadSig { mask, ..ThreadSig::default() });
    }
}

/// Records the exit status for a whole process (`exit_group`, fatal signal).
pub fn set_exit_status(pid: u64, status: i32) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        if p.exit_status.is_none() {
            p.exit_status = Some(status);
        }
    }
}

/// Called by the scheduler when thread `tid` of process `pid` dies. When the last thread
/// is gone the process becomes a zombie, its children are re-parented, and its parent
/// receives `SIGCHLD` (or the zombie is discarded if no Linux parent will wait for it).
pub fn thread_exited(pid: u64, tid: u64) {
    let mut procs = PROCS.lock();
    let (ppid, now_zombie) = match procs.get_mut(&pid) {
        Some(p) => {
            p.threads.remove(&tid);
            if p.threads.is_empty() && !p.zombie {
                p.zombie = true;
                p.vfork_released = true;
                if p.exit_status.is_none() {
                    p.exit_status = Some(0);
                }
                (p.ppid, true)
            } else {
                (p.ppid, false)
            }
        }
        None => return,
    };
    if !now_zombie {
        return;
    }
    // Orphans are adopted by "init" (pid 1); zombies of init are reaped at once
    let orphans: Vec<u64> = procs.values().filter(|c| c.ppid == pid).map(|c| c.pid).collect();
    for c in orphans {
        let reap = procs.get(&c).map_or(false, |c| c.zombie);
        if reap {
            procs.remove(&c);
        } else if let Some(child) = procs.get_mut(&c) {
            child.ppid = 1;
        }
    }
    match procs.get_mut(&ppid) {
        Some(parent) if !parent.zombie => {
            let ign = parent.actions[SIGCHLD as usize].handler == SIG_IGN;
            if ign {
                procs.remove(&pid);
            } else {
                parent.pending |= bit(SIGCHLD);
            }
        }
        // Parent 0 is the Hydra shell, which reads the status itself (see `take_status`)
        _ if ppid == 0 => {}
        _ => {
            procs.remove(&pid);
        }
    }
}

/// Reaps a zombie started from the Hydra shell, returning its `wait` status.
pub fn take_status(pid: u64) -> Option<i32> {
    let mut procs = PROCS.lock();
    match procs.get(&pid) {
        Some(p) if p.zombie => procs.remove(&pid).and_then(|p| p.exit_status),
        _ => None,
    }
}

impl Process {
    /// Threads of this process still running.
    pub fn threads_alive(&self) -> usize {
        self.threads.len()
    }
}

pub fn getppid() -> i64 {
    let (_, pid) = current_ids();
    PROCS.lock().get(&pid).map_or(1, |p| p.ppid as i64)
}

pub fn getpgid(target: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    PROCS.lock().get(&target).map_or(ESRCH, |p| p.pgid as i64)
}

pub fn getsid(target: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    PROCS.lock().get(&target).map_or(ESRCH, |p| p.sid as i64)
}

pub fn setpgid(target: u64, pgid: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    let pgid = if pgid == 0 { target } else { pgid };
    let mut procs = PROCS.lock();
    let allowed = procs.get(&target).map_or(false, |p| p.pid == pid || p.ppid == pid);
    if !allowed {
        return ESRCH;
    }
    let p = procs.get_mut(&target).unwrap();
    if p.sid == p.pid {
        return EPERM; // a session leader cannot change its group
    }
    p.pgid = pgid;
    0
}

pub fn setsid() -> i64 {
    let (_, pid) = current_ids();
    let mut procs = PROCS.lock();
    if procs.values().any(|p| p.pgid == pid && p.pid != pid) {
        return EPERM;
    }
    match procs.get_mut(&pid) {
        Some(p) if p.pgid != pid => {
            p.pgid = pid;
            p.sid = pid;
            pid as i64
        }
        Some(_) => EPERM,
        None => ESRCH,
    }
}

/// Session and process group of `pid`.
pub fn session_of(pid: u64) -> Option<(u64, u64)> {
    PROCS.lock().get(&pid).map(|p| (p.sid, p.pgid))
}

/// Resets signal dispositions across `execve` (handled signals return to default).
pub fn exec_reset(pid: u64) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        for a in p.actions.iter_mut() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
        p.vfork_released = true;
        for t in p.threads.values_mut() {
            t.alt_flags = SS_DISABLE;
            t.alt_sp = 0;
            t.alt_size = 0;
        }
    }
}

/// Lets a `vfork` parent continue (the child has exec'ed or exited).
pub fn vfork_released(child: u64) -> bool {
    PROCS.lock().get(&child).map_or(true, |p| p.vfork_released)
}

// ----------------------------------------------------------------------
// Sending signals
// ----------------------------------------------------------------------

fn default_ignored(sig: u32) -> bool {
    matches!(sig, SIGCHLD | SIGURG | SIGWINCH | SIGCONT | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

fn wake_process(pid: u64) {
    let mut sched = crate::task::SCHEDULER.lock();
    sched.unblock_group(pid);
}

/// Posts `sig` to process `pid` (process-directed). Returns false if no such process.
pub fn post_process(pid: u64, sig: u32) -> bool {
    {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid) {
            Some(p) if !p.zombie => {
                if sig != 0 {
                    p.pending |= bit(sig);
                }
            }
            _ => return false,
        }
    }
    wake_process(pid);
    true
}

/// Posts `sig` to one thread.
pub fn post_thread(pid: u64, tid: u64, sig: u32) -> bool {
    {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => {
                if sig != 0 {
                    t.pending |= bit(sig);
                }
            }
            None => return false,
        }
    }
    wake_process(pid);
    true
}

/// Posts `sig` to every process in process group `pgid`. Returns the number signalled.
pub fn post_group(pgid: u64, sig: u32) -> usize {
    let members: Vec<u64> = PROCS.lock().values().filter(|p| p.pgid == pgid && !p.zombie).map(|p| p.pid).collect();
    for &pid in &members {
        post_process(pid, sig);
    }
    members.len()
}

pub fn sys_kill(pid: i64, sig: u64) -> i64 {
    if sig as usize > NSIG {
        return EINVAL;
    }
    let sig = sig as u32;
    let (_, me) = current_ids();
    let n = match pid {
        p if p > 0 => post_process(p as u64, sig) as usize,
        0 => {
            let pgid = PROCS.lock().get(&me).map_or(me, |p| p.pgid);
            post_group(pgid, sig)
        }
        -1 => {
            let all: Vec<u64> = PROCS.lock().keys().copied().filter(|&p| p != me).collect();
            all.iter().filter(|&&p| post_process(p, sig)).count()
        }
        p => post_group((-p) as u64, sig),
    };
    if n == 0 {
        ESRCH
    } else {
        0
    }
}

pub fn sys_tgkill(pid: u64, tid: u64, sig: u64) -> i64 {
    if sig as usize > NSIG {
        return EINVAL;
    }
    if post_thread(pid, tid, sig as u32) {
        0
    } else {
        ESRCH
    }
}

pub fn sys_tkill(tid: u64, sig: u64) -> i64 {
    let pid = PROCS.lock().values().find(|p| p.threads.contains_key(&tid)).map(|p| p.pid);
    match pid {
        Some(pid) => sys_tgkill(pid, tid, sig),
        None => ESRCH,
    }
}

// ----------------------------------------------------------------------
// Dispositions and masks
// ----------------------------------------------------------------------

fn read_u64s<const N: usize>(ptr: u64) -> Option<[u64; N]> {
    if !prefault_current(ptr, (N * 8) as u64, false) {
        return None;
    }
    let mut out = [0u64; N];
    for (i, v) in out.iter_mut().enumerate() {
        *v = unsafe { *((ptr + i as u64 * 8) as *const u64) };
    }
    Some(out)
}

fn write_bytes(ptr: u64, data: &[u8]) -> bool {
    if !prefault_current(ptr, data.len() as u64, true) {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    true
}

pub fn sys_rt_sigaction(sig: u64, act: u64, oact: u64, size: u64) -> i64 {
    if size != 8 || sig == 0 || sig as usize > NSIG {
        return EINVAL;
    }
    let sig = sig as u32;
    let new = if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return EINVAL;
        }
        match read_u64s::<4>(act) {
            Some([handler, flags, restorer, mask]) => Some(SigAction { handler, flags, restorer, mask }),
            None => return EFAULT,
        }
    } else {
        None
    };
    let (_, pid) = current_ids();
    let old = {
        let mut procs = PROCS.lock();
        let p = match procs.get_mut(&pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        let old = p.actions[sig as usize];
        if let Some(a) = new {
            p.actions[sig as usize] = a;
            if a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig)) {
                // Setting a signal to ignored discards it if pending
                p.pending &= !bit(sig);
                for t in p.threads.values_mut() {
                    t.pending &= !bit(sig);
                }
            }
        }
        old
    };
    if oact != 0 {
        let mut b = [0u8; 32];
        for (i, v) in [old.handler, old.flags, old.restorer, old.mask].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        if !write_bytes(oact, &b) {
            return EFAULT;
        }
    }
    0
}

pub fn sys_rt_sigprocmask(how: u64, set: u64, oset: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let new = if set != 0 {
        match read_u64s::<1>(set) {
            Some([v]) => Some(v),
            None => return EFAULT,
        }
    } else {
        None
    };
    let (tid, pid) = current_ids();
    let old = {
        let mut procs = PROCS.lock();
        let t = match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => t,
            None => return 0,
        };
        let old = t.mask;
        if let Some(v) = new {
            t.mask = match how {
                0 => t.mask | v,  // SIG_BLOCK
                1 => t.mask & !v, // SIG_UNBLOCK
                2 => v,           // SIG_SETMASK
                _ => return EINVAL,
            } & !UNBLOCKABLE;
        }
        old
    };
    if oset != 0 && !write_bytes(oset, &old.to_le_bytes()) {
        return EFAULT;
    }
    0
}

pub fn sys_sigaltstack(ss: u64, old: u64) -> i64 {
    let (tid, pid) = current_ids();
    let mut procs = PROCS.lock();
    let t = match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
        Some(t) => *t,
        None => return EINVAL,
    };
    drop(procs);
    if old != 0 {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&t.alt_sp.to_le_bytes());
        let flags = if t.alt_size == 0 { SS_DISABLE } else { t.alt_flags };
        b[8..12].copy_from_slice(&flags.to_le_bytes());
        b[16..24].copy_from_slice(&t.alt_size.to_le_bytes());
        if !write_bytes(old, &b) {
            return EFAULT;
        }
    }
    if ss != 0 {
        let [sp, flags, size] = match read_u64s::<3>(ss) {
            Some(v) => v,
            None => return EFAULT,
        };
        let flags = flags as u32;
        let mut procs = PROCS.lock();
        if let Some(t) = procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            if flags & SS_DISABLE != 0 {
                t.alt_sp = 0;
                t.alt_size = 0;
                t.alt_flags = SS_DISABLE;
            } else {
                t.alt_sp = sp;
                t.alt_size = size;
                t.alt_flags = 0;
            }
        }
    }
    0
}

pub fn sys_rt_sigpending(set: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let (tid, pid) = current_ids();
    let pending = PROCS
        .lock()
        .get(&pid)
        .map(|p| p.pending | p.threads.get(&tid).map_or(0, |t| t.pending))
        .unwrap_or(0);
    if write_bytes(set, &pending.to_le_bytes()) {
        0
    } else {
        EFAULT
    }
}

/// `rt_sigsuspend`: waits with a temporary mask until a signal is delivered.
pub fn sys_rt_sigsuspend(mask_ptr: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let mask = match read_u64s::<1>(mask_ptr) {
        Some([m]) => m,
        None => return EFAULT,
    };
    let (tid, pid) = current_ids();
    let saved = {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => {
                let saved = t.mask;
                t.mask = mask & !UNBLOCKABLE;
                saved
            }
            None => return EINTR,
        }
    };
    while !signal_pending() {
        crate::task::sleep_ticks(1);
    }
    // The original mask is restored after the handler runs (stored for delivery)
    SUSPEND_RESTORE.lock().insert(tid, saved);
    EINTR
}

/// Masks to restore after a signal interrupted `rt_sigsuspend`, by thread.
static SUSPEND_RESTORE: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

/// True if the calling thread has an unblocked pending signal (blocking syscalls poll this).
pub fn signal_pending() -> bool {
    let (tid, pid) = current_ids();
    let procs = match PROCS.try_lock() {
        Some(p) => p,
        None => return false,
    };
    match procs.get(&pid) {
        Some(p) => {
            let t = p.threads.get(&tid).copied().unwrap_or_default();
            (p.pending | t.pending) & !(t.mask & !UNBLOCKABLE) != 0
        }
        None => false,
    }
}

// ----------------------------------------------------------------------
// Delivery
// ----------------------------------------------------------------------

/// Complete user register state of an interrupted context.
#[derive(Clone, Copy, Default)]
pub struct UserRegs {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
}

enum Action {
    None,
    Handler(u32, SigAction, u64),
    Terminate(u32),
}

/// Takes the next deliverable signal for the calling thread and decides what to do.
fn dequeue() -> Action {
    let (tid, pid) = current_ids();
    let mut procs = match PROCS.try_lock() {
        Some(p) => p,
        None => return Action::None,
    };
    let p = match procs.get_mut(&pid) {
        Some(p) => p,
        None => return Action::None,
    };
    loop {
        let t = p.threads.entry(tid).or_default();
        let ready = (p.pending | t.pending) & !(t.mask & !UNBLOCKABLE);
        if ready == 0 {
            return Action::None;
        }
        let sig = ready.trailing_zeros() + 1;
        if t.pending & bit(sig) != 0 {
            t.pending &= !bit(sig);
        } else {
            p.pending &= !bit(sig);
        }
        let mask = t.mask;
        let act = p.actions[sig as usize];
        match act.handler {
            SIG_IGN if sig != SIGKILL => continue,
            SIG_DFL => {
                if default_ignored(sig) {
                    continue;
                }
                return Action::Terminate(sig);
            }
            _ if sig == SIGKILL => return Action::Terminate(sig),
            _ => {
                if act.flags & SA_RESETHAND != 0 {
                    p.actions[sig as usize] = SigAction::default();
                }
                let t = p.threads.get_mut(&tid).unwrap();
                let restore = SUSPEND_RESTORE.lock().remove(&tid).unwrap_or(mask);
                t.mask |= act.mask & !UNBLOCKABLE;
                if act.flags & SA_NODEFER == 0 {
                    t.mask |= bit(sig);
                }
                return Action::Handler(sig, act, restore);
            }
        }
    }
}

/// Terminates the calling process because of `sig` (default action).
fn die(sig: u32) -> ! {
    let (_, pid) = current_ids();
    let core = matches!(sig, SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV);
    if sig != SIGPIPE && sig != SIGTERM && sig != SIGINT && sig != SIGKILL {
        crate::println!("[linux] pid {} killed by signal {}{}", pid, sig, if core { " (core dumped)" } else { "" });
    }
    set_exit_status(pid, (sig as i32) | if core { 0x80 } else { 0 });
    crate::task::exit_group();
}

/// Writes an `rt_sigframe` for `sig` onto the user stack and redirects `regs` to the
/// handler. Returns false if the stack is unusable.
fn build_frame(regs: &mut UserRegs, fpu: &FpuState, sig: u32, act: &SigAction, old_mask: u64) -> bool {
    let (tid, pid) = current_ids();
    let alt = PROCS.lock().get(&pid).and_then(|p| p.threads.get(&tid).copied()).unwrap_or_default();
    let on_alt = alt.alt_size != 0 && regs.rsp > alt.alt_sp && regs.rsp <= alt.alt_sp + alt.alt_size;
    let mut sp = if act.flags & SA_ONSTACK != 0 && alt.alt_size != 0 && !on_alt {
        alt.alt_sp + alt.alt_size
    } else {
        regs.rsp - 128 // skip the red zone
    };

    // FXSAVE area, then the frame: pretcode (8) + ucontext (304) + siginfo (128)
    sp = (sp - 512) & !63;
    let fp_addr = sp;
    let frame = ((sp - 440) & !15) - 8;
    let uc = frame + 8;
    let info = uc + 304;

    let mut f = [0u8; 440];
    let put = |f: &mut [u8; 440], off: usize, v: u64| f[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut f, 0, act.restorer);
    // ucontext: uc_flags, uc_link, uc_stack
    put(&mut f, 8 + 16, alt.alt_sp);
    f[8 + 24..8 + 28].copy_from_slice(&(if on_alt { SS_ONSTACK } else if alt.alt_size == 0 { SS_DISABLE } else { 0 }).to_le_bytes());
    put(&mut f, 8 + 32, alt.alt_size);
    // sigcontext (uc + 40)
    let mc = 8 + 40;
    let gprs = [
        regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rdi, regs.rsi, regs.rbp, regs.rbx,
        regs.rdx, regs.rax, regs.rcx, regs.rsp, regs.rip, regs.rflags,
    ];
    for (i, v) in gprs.iter().enumerate() {
        put(&mut f, mc + i * 8, *v);
    }
    f[mc + 144..mc + 146].copy_from_slice(&0x23u16.to_le_bytes()); // cs
    f[mc + 150..mc + 152].copy_from_slice(&0x1bu16.to_le_bytes()); // ss
    put(&mut f, mc + 160, 0); // err
    put(&mut f, mc + 168, 0); // trapno
    put(&mut f, mc + 176, old_mask);
    put(&mut f, mc + 192, fp_addr);
    // uc_sigmask
    put(&mut f, 8 + 296, old_mask);
    // siginfo: si_signo, si_errno, si_code (SI_USER = 0)
    f[312..316].copy_from_slice(&(sig as i32).to_le_bytes());

    if !write_bytes(fp_addr, &fpu.0) || !write_bytes(frame, &f) {
        return false;
    }

    regs.rsp = frame;
    regs.rip = act.handler;
    regs.rdi = sig as u64;
    regs.rsi = info;
    regs.rdx = uc;
    regs.rax = 0;
    regs.rflags &= !0x400; // clear DF
    true
}

/// Delivers pending signals before returning from a system call. `orig_nr` is the system
/// call number (for restarts); the result is already in `frame.rax`.
pub fn deliver_on_syscall_return(frame: &mut SyscallFrame, fpu: *mut FpuState, orig_nr: u64) {
    let result = frame.rax as i64;
    match dequeue() {
        Action::None => {
            if result == ERESTARTSYS {
                // Interrupted by a signal that turned out to be ignored: restart
                frame.rip -= 2;
                frame.rax = orig_nr;
            }
        }
        Action::Terminate(sig) => die(sig),
        Action::Handler(sig, act, old_mask) => {
            if result == ERESTARTSYS {
                if act.flags & SA_RESTART != 0 {
                    frame.rip -= 2;
                    frame.rax = orig_nr;
                } else {
                    frame.rax = EINTR as u64;
                }
            }
            let mut regs = UserRegs {
                r8: frame.r8,
                r9: frame.r9,
                r10: frame.r10,
                r11: frame.rflags,
                r12: frame.r12,
                r13: frame.r13,
                r14: frame.r14,
                r15: frame.r15,
                rdi: frame.rdi,
                rsi: frame.rsi,
                rbp: frame.rbp,
                rbx: frame.rbx,
                rdx: frame.rdx,
                rax: frame.rax,
                rcx: frame.rip,
                rsp: frame.rsp,
                rip: frame.rip,
                rflags: frame.rflags,
            };
            let fpu_ref = unsafe { &*fpu };
            if !build_frame(&mut regs, fpu_ref, sig, &act, old_mask) {
                die(SIGSEGV);
            }
            frame.rip = regs.rip;
            frame.rsp = regs.rsp;
            frame.rdi = regs.rdi;
            frame.rsi = regs.rsi;
            frame.rdx = regs.rdx;
            frame.rax = regs.rax;
            frame.rflags = regs.rflags;
        }
    }
}

/// Delivers pending signals to a thread about to return to user mode from an interrupt
/// or exception.
pub fn deliver_on_trap_return(ctx: &mut ExceptionContext, fpu: *mut FpuState) {
    if (ctx.cs & 3) != 3 || fpu.is_null() || !signal_pending() {
        return;
    }
    match dequeue() {
        Action::None => {}
        Action::Terminate(sig) => die(sig),
        Action::Handler(sig, act, old_mask) => {
            let mut regs = UserRegs {
                r8: ctx.r8,
                r9: ctx.r9,
                r10: ctx.r10,
                r11: ctx.r11,
                r12: ctx.r12,
                r13: ctx.r13,
                r14: ctx.r14,
                r15: ctx.r15,
                rdi: ctx.rdi,
                rsi: ctx.rsi,
                rbp: ctx.rbp,
                rbx: ctx.rbx,
                rdx: ctx.rdx,
                rax: ctx.rax,
                rcx: ctx.rcx,
                rsp: ctx.rsp,
                rip: ctx.rip,
                rflags: ctx.rflags,
            };
            let fpu_ref = unsafe { &*fpu };
            if !build_frame(&mut regs, fpu_ref, sig, &act, old_mask) {
                die(SIGSEGV);
            }
            ctx.rip = regs.rip;
            ctx.rsp = regs.rsp;
            ctx.rdi = regs.rdi;
            ctx.rsi = regs.rsi;
            ctx.rdx = regs.rdx;
            ctx.rax = regs.rax;
            ctx.rflags = regs.rflags;
        }
    }
}

/// Raises a synchronous fault signal (`SIGSEGV`, `SIGILL`, `SIGFPE`, `SIGBUS`) in the
/// current thread. If the signal is blocked or has no handler, the process dies.
pub fn force_fault_signal(ctx: &mut ExceptionContext, fpu: *mut FpuState, sig: u32) {
    let (tid, pid) = current_ids();
    let handled = {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid) {
            Some(p) => {
                let act = p.actions[sig as usize];
                let t = p.threads.entry(tid).or_default();
                let usable = act.handler > SIG_IGN && t.mask & bit(sig) == 0;
                if usable {
                    t.pending |= bit(sig);
                }
                usable
            }
            None => false,
        }
    };
    if !handled {
        die(sig);
    }
    deliver_on_trap_return(ctx, fpu);
}

/// `rt_sigreturn`: restores the context saved in the signal frame and returns to it.
pub fn sys_rt_sigreturn(frame: &SyscallFrame) -> ! {
    let uc = frame.rsp; // the handler's `ret` popped pretcode, so rsp points at the ucontext
    let mut raw = [0u8; 304];
    if !prefault_current(uc, 304, false) {
        die(SIGSEGV);
    }
    unsafe { core::ptr::copy_nonoverlapping(uc as *const u8, raw.as_mut_ptr(), 304) };
    let get = |off: usize| u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
    let mc = 40;
    let g = |i: usize| get(mc + i * 8);
    let regs = UserRegs {
        r8: g(0),
        r9: g(1),
        r10: g(2),
        r11: g(3),
        r12: g(4),
        r13: g(5),
        r14: g(6),
        r15: g(7),
        rdi: g(8),
        rsi: g(9),
        rbp: g(10),
        rbx: g(11),
        rdx: g(12),
        rax: g(13),
        rcx: g(14),
        rsp: g(15),
        rip: g(16),
        // User code may only change the arithmetic flags, DF, TF... keep IF set
        rflags: (g(17) & 0x0000_0000_0025_4DD5) | 0x202,
    };
    let fp_addr = get(mc + 192);
    let mask = get(296);

    let (tid, pid) = current_ids();
    if let Some(t) = PROCS.lock().get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
        t.mask = mask & !UNBLOCKABLE;
    }

    let mut fpu = FpuState::new();
    if fp_addr != 0 && prefault_current(fp_addr, 512, false) {
        unsafe { core::ptr::copy_nonoverlapping(fp_addr as *const u8, fpu.0.as_mut_ptr(), 512) };
        // Keep MXCSR's reserved bits clear or FXRSTOR faults
        let mxcsr = u32::from_le_bytes(fpu.0[24..28].try_into().unwrap()) & 0xFFFF;
        fpu.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    }
    if regs.rip >= crate::memory::vm::USER_SPACE_END || regs.rsp >= crate::memory::vm::USER_SPACE_END {
        die(SIGSEGV);
    }
    unsafe { return_to_user(&regs, &fpu) }
}

/// Returns to user mode with every register (including `rcx`/`r11`) taken from `regs`
/// and the FPU state from `fpu`, via `iretq`. Used where `sysret` cannot restore the
/// full context.
pub unsafe fn return_to_user(regs: &UserRegs, fpu: &FpuState) -> ! {
    let regs = *regs;
    core::arch::asm!(
        "fxrstor64 [{fpu}]",
        "push 0x1b",          // SS
        "push qword ptr [{r} + 15*8]", // RSP
        "push qword ptr [{r} + 17*8]", // RFLAGS
        "push 0x23",          // CS
        "push qword ptr [{r} + 16*8]", // RIP
        "mov r8,  [{r} + 0*8]",
        "mov r9,  [{r} + 1*8]",
        "mov r10, [{r} + 2*8]",
        "mov r11, [{r} + 3*8]",
        "mov r12, [{r} + 4*8]",
        "mov r13, [{r} + 5*8]",
        "mov r14, [{r} + 6*8]",
        "mov r15, [{r} + 7*8]",
        "mov rdi, [{r} + 8*8]",
        "mov rsi, [{r} + 9*8]",
        "mov rbp, [{r} + 10*8]",
        "mov rbx, [{r} + 11*8]",
        "mov rdx, [{r} + 12*8]",
        "mov rcx, [{r} + 14*8]",
        "mov rax, [{r} + 13*8]",
        "iretq",
        r = in(reg) &regs as *const UserRegs,
        fpu = in(reg) fpu as *const FpuState,
        options(noreturn)
    );
}

// ----------------------------------------------------------------------
// wait4 / waitid
// ----------------------------------------------------------------------

const WNOHANG: u64 = 1;
const WNOWAIT: u64 = 0x0100_0000;

fn matches(child: &Process, me: u64, my_pgid: u64, sel: i64) -> bool {
    child.ppid == me
        && match sel {
            -1 => true,
            0 => child.pgid == my_pgid,
            s if s > 0 => child.pid == s as u64,
            s => child.pgid == (-s) as u64,
        }
}

/// Finds (and unless `keep`, reaps) a zombie child matching `sel`.
/// Returns Ok(Some((pid, status))), Ok(None) if children exist but none exited, Err(ECHILD).
fn reap(sel: i64, keep: bool) -> Result<Option<(u64, i32)>, i64> {
    let (_, me) = current_ids();
    let mut procs = PROCS.lock();
    let my_pgid = procs.get(&me).map_or(me, |p| p.pgid);
    let mut any = false;
    let mut found = None;
    for c in procs.values() {
        if matches(c, me, my_pgid, sel) {
            any = true;
            if c.zombie {
                found = Some((c.pid, c.exit_status.unwrap_or(0)));
                break;
            }
        }
    }
    if !any {
        return Err(ECHILD);
    }
    if let Some((pid, _)) = found {
        if !keep {
            procs.remove(&pid);
        }
    }
    Ok(found)
}

/// Encodes an exit status the way `wait` reports it.
pub fn wait_status_exit(code: i32) -> i32 {
    (code & 0xff) << 8
}

fn wait_loop(sel: i64, options: u64) -> Result<Option<(u64, i32)>, i64> {
    loop {
        match reap(sel, options & WNOWAIT != 0)? {
            Some(r) => return Ok(Some(r)),
            None if options & WNOHANG != 0 => return Ok(None),
            None => {}
        }
        if signal_pending() {
            return Err(ERESTARTSYS);
        }
        crate::task::sleep_ticks(1);
    }
}

pub fn sys_wait4(pid: i64, status_ptr: u64, options: u64, _rusage: u64) -> i64 {
    match wait_loop(pid, options) {
        Ok(Some((pid, status))) => {
            if status_ptr != 0 && !write_bytes(status_ptr, &status.to_le_bytes()) {
                return EFAULT;
            }
            pid as i64
        }
        Ok(None) => 0,
        Err(e) => e,
    }
}

pub fn sys_waitid(idtype: u64, id: u64, infop: u64, options: u64) -> i64 {
    let sel = match idtype {
        0 => -1,               // P_ALL
        1 => id as i64,        // P_PID
        2 => -(id as i64),     // P_PGID
        _ => return EINVAL,
    };
    if options & 4 == 0 {
        return EINVAL; // only WEXITED is supported
    }
    match wait_loop(sel, options) {
        Ok(Some((pid, status))) => {
            if infop != 0 {
                let mut info = [0u8; 128];
                info[0..4].copy_from_slice(&(SIGCHLD as i32).to_le_bytes());
                let (code, value) = if status & 0x7f == 0 { (1, (status >> 8) & 0xff) } else { (2, status & 0x7f) };
                info[8..12].copy_from_slice(&(code as i32).to_le_bytes());
                info[16..20].copy_from_slice(&(pid as i32).to_le_bytes());
                info[24..28].copy_from_slice(&value.to_le_bytes());
                if !write_bytes(infop, &info) {
                    return EFAULT;
                }
            }
            0
        }
        Ok(None) => {
            if infop != 0 {
                write_bytes(infop, &[0u8; 128]);
            }
            0
        }
        Err(e) => e,
    }
}
