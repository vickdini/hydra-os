//! ptrace: what debuggers (gdb) and tracers (strace) are built on.
//!
//! - **Tracees** are threads. `PTRACE_TRACEME` makes the parent the tracer; `PTRACE_ATTACH`
//!   (with a `SIGSTOP`) and `PTRACE_SEIZE` (without) attach the caller. Children of a
//!   tracee are traced too when the tracer asked for fork/vfork/clone events.
//! - **Stops**: a traced thread stops for every signal but `SIGKILL` before acting on it
//!   (the tracer chooses which signal, if any, is then delivered), at system call entry and
//!   exit after `PTRACE_SYSCALL`, after a single step, at fork/vfork/clone/exec/exit events
//!   it asked for, and on `PTRACE_INTERRUPT`. A stopping thread copies its registers here
//!   and sleeps; the tracer reads and changes the copy, and the thread takes it back when
//!   resumed. The tracer learns about stops through `wait` and `SIGCHLD`.
//! - **Memory**: peeks and pokes go to the tracee's address space; a poke into read-only
//!   text (a breakpoint) gives the tracee a private copy of the page first.
//! - **Breakpoints and stepping**: `int3` and the trap flag raise `SIGTRAP`.
//! - **Hardware breakpoints and watchpoints**: `u_debugreg` through PEEKUSER/POKEUSER.
//! - **`/proc/<pid>/mem`**: the same memory as a file (`pread`/`pwrite`).
//! - **Seccomp**: a filter's `TRACE` action stops for a tracer asking for seccomp events.
//! - **Not covered**: `PTRACE_SYSEMU`.
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::arch::idt::{ExceptionContext, FpuState};
use crate::arch::syscall::SyscallFrame;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

const SIGKILL: u32 = 9;
const SIGTRAP: u32 = 5;
const SIGSTOP: u32 = 19;
const SIGCHLD: u64 = 17;

const TRACEME: u64 = 0;
const PEEKTEXT: u64 = 1;
const PEEKDATA: u64 = 2;
const PEEKUSR: u64 = 3;
const POKETEXT: u64 = 4;
const POKEDATA: u64 = 5;
const POKEUSR: u64 = 6;
const CONT: u64 = 7;
const KILL: u64 = 8;
const SINGLESTEP: u64 = 9;
const GETREGS: u64 = 12;
const SETREGS: u64 = 13;
const GETFPREGS: u64 = 14;
const SETFPREGS: u64 = 15;
const ATTACH: u64 = 16;
const DETACH: u64 = 17;
const SYSCALL: u64 = 24;
const SETOPTIONS: u64 = 0x4200;
const GETEVENTMSG: u64 = 0x4201;
const GETSIGINFO: u64 = 0x4202;
const SETSIGINFO: u64 = 0x4203;
const GETREGSET: u64 = 0x4204;
const SETREGSET: u64 = 0x4205;
const SEIZE: u64 = 0x4206;
const INTERRUPT: u64 = 0x4207;
const LISTEN: u64 = 0x4208;
const GET_SYSCALL_INFO: u64 = 0x420e;

const O_TRACESYSGOOD: u64 = 1;
const O_TRACEFORK: u64 = 2;
const O_TRACEVFORK: u64 = 4;
const O_TRACECLONE: u64 = 8;
const O_TRACEEXEC: u64 = 0x10;
const O_TRACEVFORKDONE: u64 = 0x20;
const O_TRACEEXIT: u64 = 0x40;
const O_TRACESECCOMP: u64 = 0x80;
const O_EXITKILL: u64 = 1 << 20;
const O_ALL: u64 = 0xff | O_EXITKILL | (1 << 21);

const EV_FORK: u32 = 1;
const EV_VFORK: u32 = 2;
const EV_CLONE: u32 = 3;
const EV_EXEC: u32 = 4;
const EV_VFORK_DONE: u32 = 5;
const EV_EXIT: u32 = 6;
const EV_SECCOMP: u32 = 7;
const EV_STOP: u32 = 128;

/// Registers in `struct user_regs_struct` order.
pub type Regs = [u64; 27];
const R_RAX: usize = 10;
const R_ORIG_RAX: usize = 15;
const R_RIP: usize = 16;
const R_EFLAGS: usize = 18;
const R_RSP: usize = 19;
const R_FS_BASE: usize = 21;
const REGS_SIZE: usize = 27 * 8;
/// `sizeof(struct user)` and where its debug registers sit.
const USER_SIZE: u64 = 912;
const USER_DEBUGREG: u64 = 848;
/// User code and stack selectors of 64-bit programs (debuggers tell 64-bit from 32-bit
/// tracees by `cs`): the same as Linux's (`arch::gdt`).
const USER_CS: u64 = 0x33;
const USER_SS: u64 = 0x2b;
/// Flags a tracer may change: CF PF AF ZF SF TF DF OF NT RF AC.
const FLAGS_USER: u64 = 0x54dd5;
const TF: u64 = 0x100;

/// What a stop is, for `PTRACE_GET_SYSCALL_INFO`.
#[derive(Clone, Copy, PartialEq)]
enum Op {
    Other,
    Entry,
    Exit,
    /// A seccomp `TRACE` stop, with the filter's data.
    Seccomp(u16),
}

/// How the tracer let a stopped thread go.
#[derive(Clone, Copy, Default)]
struct Resume {
    sig: u32,
    step: bool,
    detach: bool,
}

/// A traced thread.
struct Tracee {
    tgid: u64,
    tracer: u64,
    seized: bool,
    options: u64,
    /// In a stop, waiting for the tracer.
    stopped: bool,
    /// Gone; `status` is its exit status, for the tracer's `wait`.
    exited: bool,
    /// `wait` status of the current stop (or the exit).
    status: i32,
    reported: bool,
    resume: Option<Resume>,
    regs: Regs,
    regs_dirty: bool,
    fpu: [u8; 512],
    fpu_dirty: bool,
    siginfo: [u8; 128],
    eventmsg: u64,
    /// Resumed with `PTRACE_SYSCALL`: stop at the next system call entry or exit.
    syscall_stops: bool,
    op: Op,
    /// An event to report at the end of the current system call (exec).
    pending_event: Option<(u32, u64)>,
    /// `PTRACE_INTERRUPT` (or a seized child's first stop): stop with this signal.
    interrupt: Option<u32>,
    /// `PTRACE_LISTEN`: stays in its group stop until the process is continued.
    listening: bool,
}

impl Tracee {
    fn new(tgid: u64, tracer: u64, seized: bool, options: u64) -> Self {
        Tracee {
            tgid,
            tracer,
            seized,
            options,
            stopped: false,
            exited: false,
            status: 0,
            reported: false,
            resume: None,
            regs: [0; 27],
            regs_dirty: false,
            fpu: [0; 512],
            fpu_dirty: false,
            siginfo: [0; 128],
            eventmsg: 0,
            syscall_stops: false,
            op: Op::Other,
            pending_event: None,
            interrupt: None,
            listening: false,
        }
    }
}

/// Traced threads by thread ID. Lock order: `proc::PROCS` before this, never after.
static TRACEES: Mutex<BTreeMap<u64, Tracee>> = Mutex::new(BTreeMap::new());
/// Set once anything was traced: until then every hook returns at once.
static ANY: AtomicBool = AtomicBool::new(false);
/// Stopped tracees wait here for their tracer.
static RESUMED: WaitQueue = WaitQueue::new();

/// Whether anything was ever traced (the hooks' fast path).
#[inline]
pub fn active() -> bool {
    ANY.load(Ordering::Relaxed)
}

/// Whether thread `tid` is traced.
pub fn is_traced(tid: u64) -> bool {
    active() && TRACEES.lock().get(&tid).is_some_and(|t| !t.exited)
}

/// The tracer of process `tgid`'s main thread, or 0 (`TracerPid`).
pub fn tracer_of(tgid: u64) -> u64 {
    if !active() {
        return 0;
    }
    TRACEES.lock().get(&tgid).filter(|t| !t.exited).map_or(0, |t| t.tracer)
}

fn current_tid() -> u64 {
    super::proc::current_ids().0
}

fn wait_status_stop(sig: u32, event: u32) -> i32 {
    0x7f | ((sig as i32) << 8) | ((event as i32) << 16)
}

// ----------------------------------------------------------------------
// Register frames
// ----------------------------------------------------------------------

fn fs_base() -> u64 {
    crate::task::with_current_task_mut(|t| t.fs_base).unwrap_or(0)
}

fn set_fs_base(v: u64) {
    if v < 0x0000_8000_0000_0000 && v != fs_base() {
        crate::task::with_current_task_mut(|t| t.fs_base = v);
        unsafe { crate::arch::syscall::wrmsr(0xC000_0100, v) };
    }
}

fn sane_flags(old: u64, new: u64) -> u64 {
    (old & !FLAGS_USER) | (new & FLAGS_USER) | 0x200
}

fn canonical(addr: u64) -> bool {
    addr < 0x0000_8000_0000_0000
}

/// A saved user register frame: a system call's or a trap's.
pub trait UserFrame {
    /// The registers, with `orig_rax` = `orig`.
    fn regs(&self, orig: u64) -> Regs;
    /// Takes the tracer's registers back (`orig_rax` is the caller's business).
    fn apply(&mut self, r: &Regs);
    /// Sets or clears the trap flag.
    fn set_tf(&mut self, on: bool);
}

impl UserFrame for SyscallFrame {
    fn regs(&self, orig: u64) -> Regs {
        // After `syscall` rcx holds the return address and r11 the flags
        [
            self.r15, self.r14, self.r13, self.r12, self.rbp, self.rbx, self.rflags, self.r10, self.r9, self.r8, self.rax, self.rip,
            self.rdx, self.rsi, self.rdi, orig, self.rip, USER_CS, self.rflags, self.rsp, USER_SS, fs_base(), 0, 0, 0, 0, 0,
        ]
    }
    fn apply(&mut self, r: &Regs) {
        self.r15 = r[0];
        self.r14 = r[1];
        self.r13 = r[2];
        self.r12 = r[3];
        self.rbp = r[4];
        self.rbx = r[5];
        self.r10 = r[7];
        self.r9 = r[8];
        self.r8 = r[9];
        self.rax = r[10];
        self.rdx = r[12];
        self.rsi = r[13];
        self.rdi = r[14];
        if canonical(r[R_RIP]) {
            self.rip = r[R_RIP];
        }
        self.rflags = sane_flags(self.rflags, r[R_EFLAGS]);
        self.rsp = r[R_RSP];
        set_fs_base(r[R_FS_BASE]);
    }
    fn set_tf(&mut self, on: bool) {
        self.rflags = if on { self.rflags | TF } else { self.rflags & !TF };
    }
}

impl UserFrame for super::proc::UserRegs {
    fn regs(&self, orig: u64) -> Regs {
        [
            self.r15, self.r14, self.r13, self.r12, self.rbp, self.rbx, self.r11, self.r10, self.r9, self.r8, self.rax, self.rcx,
            self.rdx, self.rsi, self.rdi, orig, self.rip, USER_CS, self.rflags, self.rsp, USER_SS, fs_base(), 0, 0, 0, 0, 0,
        ]
    }
    fn apply(&mut self, r: &Regs) {
        self.r15 = r[0];
        self.r14 = r[1];
        self.r13 = r[2];
        self.r12 = r[3];
        self.rbp = r[4];
        self.rbx = r[5];
        self.r11 = r[6];
        self.r10 = r[7];
        self.r9 = r[8];
        self.r8 = r[9];
        self.rax = r[10];
        self.rcx = r[11];
        self.rdx = r[12];
        self.rsi = r[13];
        self.rdi = r[14];
        if canonical(r[R_RIP]) {
            self.rip = r[R_RIP];
        }
        self.rflags = sane_flags(self.rflags, r[R_EFLAGS]);
        self.rsp = r[R_RSP];
        set_fs_base(r[R_FS_BASE]);
    }
    fn set_tf(&mut self, on: bool) {
        self.rflags = if on { self.rflags | TF } else { self.rflags & !TF };
    }
}

impl UserFrame for ExceptionContext {
    fn regs(&self, orig: u64) -> Regs {
        [
            self.r15, self.r14, self.r13, self.r12, self.rbp, self.rbx, self.r11, self.r10, self.r9, self.r8, self.rax, self.rcx,
            self.rdx, self.rsi, self.rdi, orig, self.rip, USER_CS, self.rflags, self.rsp, USER_SS, fs_base(), 0, 0, 0, 0, 0,
        ]
    }
    fn apply(&mut self, r: &Regs) {
        self.r15 = r[0];
        self.r14 = r[1];
        self.r13 = r[2];
        self.r12 = r[3];
        self.rbp = r[4];
        self.rbx = r[5];
        self.r11 = r[6];
        self.r10 = r[7];
        self.r9 = r[8];
        self.r8 = r[9];
        self.rax = r[10];
        self.rcx = r[11];
        self.rdx = r[12];
        self.rsi = r[13];
        self.rdi = r[14];
        if canonical(r[R_RIP]) {
            self.rip = r[R_RIP];
        }
        self.rflags = sane_flags(self.rflags, r[R_EFLAGS]);
        self.rsp = r[R_RSP];
        set_fs_base(r[R_FS_BASE]);
    }
    fn set_tf(&mut self, on: bool) {
        self.rflags = if on { self.rflags | TF } else { self.rflags & !TF };
    }
}

// ----------------------------------------------------------------------
// Stopping (the tracee's side)
// ----------------------------------------------------------------------

/// What a stop handed back.
struct Resumed {
    sig: u32,
    regs: Option<Regs>,
    step: bool,
}

/// Stops the calling thread with `wait` status `status` until its tracer resumes it (or it
/// is killed, or the tracer goes). `None` if it is not traced.
fn stop<F: UserFrame>(frame: &mut F, fpu: *mut FpuState, orig: u64, status: i32, op: Op, siginfo: Option<&[u8; 128]>, eventmsg: Option<u64>) -> Option<Resumed> {
    let tid = current_tid();
    let regs = frame.regs(orig);
    let tracer = {
        let mut tr = TRACEES.lock();
        let t = tr.get_mut(&tid).filter(|t| !t.exited)?;
        t.stopped = true;
        t.status = status;
        t.reported = false;
        t.resume = None;
        t.regs = regs;
        t.regs_dirty = false;
        if !fpu.is_null() {
            t.fpu = unsafe { (*fpu).0 };
        }
        t.fpu_dirty = false;
        t.op = op;
        match siginfo {
            Some(s) => t.siginfo = *s,
            None => {
                // A stop for SIGTRAP of the kernel's own making (si_code SI_KERNEL)
                t.siginfo = [0; 128];
                t.siginfo[0..4].copy_from_slice(&((status >> 8) & 0x7f).to_le_bytes());
                t.siginfo[8..12].copy_from_slice(&0x80i32.to_le_bytes());
            }
        }
        if let Some(m) = eventmsg {
            t.eventmsg = m;
        }
        t.tracer
    };
    super::proc::notify_tracer(tracer);
    super::pidfd::EXIT_WQ.wake_all();
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Static(&RESUMED));
    let resumed = loop {
        waits.register();
        {
            let mut tr = TRACEES.lock();
            let Some(t) = tr.get_mut(&tid) else { break Resumed { sig: 0, regs: None, step: false } };
            if let Some(r) = t.resume.take() {
                t.stopped = false;
                t.listening = false;
                let regs = t.regs_dirty.then_some(t.regs);
                if t.fpu_dirty && !fpu.is_null() {
                    unsafe { (*fpu).0 = t.fpu };
                }
                if r.detach {
                    tr.remove(&tid);
                }
                break Resumed { sig: r.sig, regs, step: r.step };
            }
        }
        if super::proc::sigkill_pending() {
            if let Some(t) = TRACEES.lock().get_mut(&tid) {
                t.stopped = false;
            }
            break Resumed { sig: 0, regs: None, step: false };
        }
        waits.wait(None);
    };
    if let Some(r) = &resumed.regs {
        frame.apply(r);
    }
    // After the tracer's registers, whose flags may not have the trap flag
    frame.set_tf(resumed.step);
    Some(resumed)
}

/// Signal-delivery stop for `sig` (`siginfo` as the handler would see it). Returns the
/// signal to deliver instead: the tracer's choice, 0 for none.
pub fn signal_stop<F: UserFrame>(frame: &mut F, fpu: *mut FpuState, orig: u64, sig: u32, siginfo: &[u8; 128]) -> u32 {
    match stop(frame, fpu, orig, wait_status_stop(sig, 0), Op::Other, Some(siginfo), None) {
        Some(r) => r.sig,
        None => sig,
    }
}

/// A traced thread's group stop for stop signal `sig` (after its signal-delivery stop).
pub fn group_stop<F: UserFrame>(frame: &mut F, fpu: *mut FpuState, orig: u64, sig: u32) {
    let seized = TRACEES.lock().get(&current_tid()).is_some_and(|t| t.seized);
    let status = wait_status_stop(sig, if seized { EV_STOP } else { 0 });
    stop(frame, fpu, orig, status, Op::Other, None, None);
}

/// Whether the calling thread has a `PTRACE_INTERRUPT` (or first stop) to take.
pub fn interrupt_pending() -> bool {
    active() && TRACEES.lock().get(&current_tid()).is_some_and(|t| t.interrupt.is_some() && !t.exited)
}

/// Takes a pending `PTRACE_INTERRUPT` stop.
pub fn interrupt_stop<F: UserFrame>(frame: &mut F, fpu: *mut FpuState, orig: u64) {
    let sig = TRACEES.lock().get_mut(&current_tid()).and_then(|t| t.interrupt.take());
    if let Some(sig) = sig {
        stop(frame, fpu, orig, wait_status_stop(sig, EV_STOP), Op::Other, None, None);
    }
}

/// An event stop (`PTRACE_EVENT_*`) with message `msg`, if the tracer asked for it.
fn event_stop<F: UserFrame>(frame: &mut F, fpu: *mut FpuState, orig: u64, ev: u32, msg: u64) {
    stop(frame, fpu, orig, wait_status_stop(SIGTRAP, ev), Op::Other, None, Some(msg));
}

fn options() -> Option<u64> {
    TRACEES.lock().get(&current_tid()).filter(|t| !t.exited).map(|t| t.options)
}

fn syscall_status(opts: u64) -> i32 {
    wait_status_stop(if opts & O_TRACESYSGOOD != 0 { SIGTRAP | 0x80 } else { SIGTRAP }, 0)
}

/// System call entry: stops if the tracer asked to. Returns the call to make (the tracer
/// may change it), or `Err(result)` when the tracer cancelled it (call number -1).
pub fn syscall_entry(frame: &mut SyscallFrame, fpu: *mut FpuState, num: u64) -> Result<u64, i64> {
    let interrupt = match TRACEES.lock().get(&current_tid()).filter(|t| !t.exited) {
        Some(t) => t.interrupt.is_some(),
        None => return Ok(num),
    };
    if interrupt {
        interrupt_stop(frame, fpu, num);
    }
    // Read after the interrupt stop: the tracer may have resumed with PTRACE_SYSCALL
    let Some((opts, stops)) = TRACEES.lock().get(&current_tid()).filter(|t| !t.exited).map(|t| (t.options, t.syscall_stops)) else { return Ok(num) };
    let mut num = num;
    if stops {
        frame.rax = ENOSYS as u64;
        if let Some(r) = stop(frame, fpu, num, syscall_status(opts), Op::Entry, None, None) {
            if let Some(regs) = r.regs {
                num = regs[R_ORIG_RAX];
            }
        }
        if num == u64::MAX {
            // Cancelled: the result is whatever the tracer left in rax
            return Err(frame.rax as i64);
        }
    }
    if matches!(num, 60 | 231) && opts & O_TRACEEXIT != 0 {
        // About to exit: the message is the exit status as wait reports it
        let msg = ((frame.rdi & 0xff) << 8) as u64;
        event_stop(frame, fpu, num, EV_EXIT, msg);
    }
    frame.rax = num;
    Ok(num)
}

/// System call exit: reports a pending exec event, then stops if the tracer asked to.
/// Returns the result (the tracer may change it).
pub fn syscall_exit(frame: &mut SyscallFrame, fpu: *mut FpuState, num: u64, res: i64) -> i64 {
    let (opts, stops, event) = match TRACEES.lock().get_mut(&current_tid()).filter(|t| !t.exited) {
        Some(t) => (t.options, t.syscall_stops, t.pending_event.take()),
        None => return res,
    };
    frame.rax = res as u64;
    if let Some((ev, msg)) = event {
        event_stop(frame, fpu, num, ev, msg);
    }
    if stops {
        stop(frame, fpu, num, syscall_status(opts), Op::Exit, None, None);
    }
    frame.rax as i64
}

/// `rt_sigreturn`'s exit stop, on the context it restored.
pub fn sigreturn_exit<F: UserFrame>(frame: &mut F, fpu: *mut FpuState) {
    let Some((opts, stops)) = TRACEES.lock().get(&current_tid()).filter(|t| !t.exited).map(|t| (t.options, t.syscall_stops)) else { return };
    if stops {
        stop(frame, fpu, 15, syscall_status(opts), Op::Exit, None, None);
    }
}

/// After a successful `execve`: an exec event if asked for, else a `SIGTRAP`.
pub fn on_exec(tgid: u64, tid: u64) {
    if !active() {
        return;
    }
    let legacy = {
        let mut tr = TRACEES.lock();
        let Some(t) = tr.get_mut(&tid).filter(|t| !t.exited) else { return };
        if t.options & O_TRACEEXEC != 0 {
            t.pending_event = Some((EV_EXEC, tid));
            false
        } else {
            true
        }
    };
    if legacy {
        super::proc::post_thread(tgid, tid, SIGTRAP);
    }
}

/// After the calling thread made thread `child` (of process `child_tgid`) with clone
/// `flags`: traces the child when asked to and reports the event. `frame` is the caller's.
pub fn on_clone(frame: &mut SyscallFrame, child_tgid: u64, child: u64, flags: u64) {
    const CLONE_VFORK: u64 = 0x4000;
    const CLONE_PTRACE: u64 = 0x2000;
    const CLONE_UNTRACED: u64 = 0x80_0000;
    const CLONE_THREAD: u64 = 0x1_0000;
    let tid = current_tid();
    let (ev, opt) = if flags & CLONE_VFORK != 0 {
        (EV_VFORK, O_TRACEVFORK)
    } else if flags & CLONE_THREAD != 0 || flags & 0xff != SIGCHLD {
        (EV_CLONE, O_TRACECLONE)
    } else {
        (EV_FORK, O_TRACEFORK)
    };
    let (tracer, seized, options) = match TRACEES.lock().get(&tid).filter(|t| !t.exited) {
        Some(t) => (t.tracer, t.seized, t.options),
        None => return,
    };
    let report = options & opt != 0;
    if flags & CLONE_UNTRACED != 0 || !(report || flags & CLONE_PTRACE != 0) {
        return;
    }
    {
        let mut t = Tracee::new(child_tgid, tracer, seized, options);
        // A seized child's first stop is an event stop (SIGTRAP); an attached one's a SIGSTOP
        if seized {
            t.interrupt = Some(SIGTRAP);
        }
        TRACEES.lock().insert(child, t);
    }
    if !seized {
        super::proc::post_thread(child_tgid, child, SIGSTOP);
    }
    if report {
        let fpu = crate::arch::syscall::SYSCALL_FPU.load(Ordering::Acquire);
        let orig = frame.rax;
        let child_ns = super::ns::pid_to_caller(child);
        event_stop(frame, fpu, orig, ev, child_ns);
        frame.rax = orig;
    }
}

/// Process `tgid` was sent `SIGCONT`: its listening tracees leave their group stop.
pub fn on_sigcont(tgid: u64) {
    if !active() {
        return;
    }
    let mut any = false;
    for t in TRACEES.lock().values_mut().filter(|t| t.tgid == tgid && t.listening && t.stopped) {
        t.resume = Some(Resume::default());
        any = true;
    }
    if any {
        RESUMED.wake_all();
    }
}

/// After a `vfork` child released its parent (the caller): the vfork-done event.
pub fn on_vfork_done(frame: &mut SyscallFrame, child: u64) {
    if !active() || options().map_or(true, |o| o & O_TRACEVFORKDONE == 0) {
        return;
    }
    let fpu = crate::arch::syscall::SYSCALL_FPU.load(Ordering::Acquire);
    let orig = frame.rax;
    event_stop(frame, fpu, orig, EV_VFORK_DONE, super::ns::pid_to_caller(child));
    frame.rax = orig;
}

// ----------------------------------------------------------------------
// Exits
// ----------------------------------------------------------------------

/// Thread `tid` of process `tgid` (whose parent is `parent`) is gone with exit `status`:
/// its tracer hears of it through `wait` (a parent tracing its own child reaps it the usual
/// way). Returns the tracer to notify, if any.
pub fn on_thread_exit(tgid: u64, tid: u64, status: i32, parent: u64) -> Option<u64> {
    if !active() {
        return None;
    }
    let mut tr = TRACEES.lock();
    let t = tr.get_mut(&tid)?;
    if tid == tgid && t.tracer == parent {
        tr.remove(&tid);
        return None;
    }
    t.exited = true;
    t.stopped = false;
    t.status = status;
    t.reported = false;
    Some(t.tracer)
}

/// Process `pid` is gone: its tracees are let go. Returns the `(tgid, tid)` of those to
/// kill (`PTRACE_O_EXITKILL`).
pub fn on_tracer_exit(pid: u64) -> Vec<(u64, u64)> {
    if !active() {
        return Vec::new();
    }
    let mut kill = Vec::new();
    let mut tr = TRACEES.lock();
    tr.retain(|&tid, t| {
        if t.tracer != pid {
            return true;
        }
        if t.options & O_EXITKILL != 0 && !t.exited {
            kill.push((t.tgid, tid));
        }
        if t.stopped {
            // The stopped thread removes itself on the way out
            t.resume = Some(Resume { detach: true, ..Resume::default() });
            return true;
        }
        false
    });
    drop(tr);
    RESUMED.wake_all();
    kill
}

// ----------------------------------------------------------------------
// wait
// ----------------------------------------------------------------------

/// A stop or exit of a tracee of `me` matching `wait` selector `sel` (a thread ID, or -1),
/// as `(tid, status)`; marked reported (an exit forgotten) unless `keep`.
pub fn wait_report(me: u64, sel: i64, keep: bool) -> Option<(u64, i32)> {
    if !active() {
        return None;
    }
    let mut tr = TRACEES.lock();
    let tid = tr
        .iter()
        .find(|(&tid, t)| t.tracer == me && (sel == -1 || sel == tid as i64) && !t.reported && (t.exited || (t.stopped && t.resume.is_none())))
        .map(|(&tid, _)| tid)?;
    let t = tr.get_mut(&tid)?;
    let status = t.status;
    if !keep {
        if t.exited {
            tr.remove(&tid);
        } else {
            t.reported = true;
        }
    }
    Some((tid, status))
}

/// Whether `me` traces a thread matching `wait` selector `sel` (so `wait` does not fail
/// with `ECHILD`).
pub fn has_tracee(me: u64, sel: i64) -> bool {
    active() && TRACEES.lock().iter().any(|(&tid, t)| t.tracer == me && (sel == -1 || sel == tid as i64))
}

// ----------------------------------------------------------------------
// Tracee memory
// ----------------------------------------------------------------------

fn tracee_mm(tgid: u64) -> Result<alloc::sync::Arc<Mutex<crate::memory::vm::Mm>>, i64> {
    crate::task::SCHEDULER.lock().with_process(tgid, |t| t.mm.clone()).flatten().ok_or(ESRCH)
}

fn mem_read(tgid: u64, addr: u64, len: usize) -> Result<Vec<u8>, i64> {
    if !canonical(addr) || !canonical(addr.wrapping_add(len as u64)) {
        return Err(EIO);
    }
    let mm = tracee_mm(tgid)?;
    let mut m = mm.lock();
    let mut out = Vec::with_capacity(len);
    let mut a = addr;
    while out.len() < len {
        let n = ((4096 - (a & 4095)) as usize).min(len - out.len());
        m.prefault(a, n as u64, false).map_err(|_| EIO)?;
        let phys = m.translate(a).ok_or(EIO)?.as_u64();
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(crate::memory::frame_allocator::phys_to_virt(phys) as *const u8, n) });
        a += n as u64;
    }
    Ok(out)
}

fn mem_write(tgid: u64, addr: u64, data: &[u8]) -> Result<(), i64> {
    if !canonical(addr) || !canonical(addr.wrapping_add(data.len() as u64)) {
        return Err(EIO);
    }
    let mm = tracee_mm(tgid)?;
    let r = mm.lock().force_write(addr, data);
    r.map_err(|_| EIO)
}

// ----------------------------------------------------------------------
// The ptrace system call
// ----------------------------------------------------------------------

fn put_u64(ptr: u64, v: u64) -> i64 {
    copy_out(ptr, &v.to_le_bytes()).map_or_else(|e| e, |_| 0)
}

fn regs_bytes(r: &Regs) -> Vec<u8> {
    r.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn regs_from(b: &[u8], into: &mut Regs) {
    for (i, c) in b.chunks_exact(8).enumerate().take(27) {
        into[i] = u64::from_le_bytes(c.try_into().unwrap());
    }
}

// ----------------------------------------------------------------------
// Debug registers
// ----------------------------------------------------------------------

fn debugregs_of(tid: u64) -> Option<[u64; 8]> {
    crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(tid), |t| t.debugregs)
}

/// POKEUSER of debug register `i` of stopped thread `tid` (checked as Linux does).
fn set_debugreg(tid: u64, i: usize, v: u64) -> i64 {
    let Some(mut dr) = debugregs_of(tid) else { return ESRCH };
    match i {
        0..=3 if v >= 0x0000_7fff_ffff_f000 => return EIO,
        0..=3 | 6 => {}
        7 => {
            // Local/global enables, exact-match bits and each breakpoint's type and length
            if v & !(0xffff_0000 | 0x3ff) != 0 {
                return EIO;
            }
            for n in 0..4 {
                if v & (3 << (n * 2)) == 0 {
                    continue;
                }
                let rw = (v >> (16 + n * 4)) & 3;
                let len = (v >> (18 + n * 4)) & 3;
                let bytes = [1u64, 2, 8, 4][len as usize];
                // No I/O breakpoints; an instruction breakpoint is one byte; aligned
                if rw == 2 || (rw == 0 && len != 0) || dr[n] % bytes != 0 {
                    return EINVAL;
                }
            }
        }
        _ => return EIO,
    }
    dr[i] = v;
    crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(tid), |t| t.debugregs = dr);
    0
}

// ----------------------------------------------------------------------
// Seccomp
// ----------------------------------------------------------------------

/// A seccomp filter returned `TRACE` with `data`: a seccomp event stop if the tracer asked
/// for them (`None` if not: the call fails). `Ok` to run the (possibly changed) call,
/// `Err(result)` if the tracer skipped it (call number -1).
pub fn seccomp_stop(frame: &mut SyscallFrame, data: u16) -> Option<Result<(), i64>> {
    if !active() || options()? & O_TRACESECCOMP == 0 {
        return None;
    }
    let fpu = crate::arch::syscall::SYSCALL_FPU.load(Ordering::Acquire);
    let num = frame.rax;
    frame.rax = ENOSYS as u64;
    let r = stop(frame, fpu, num, wait_status_stop(SIGTRAP, EV_SECCOMP), Op::Seccomp(data), None, Some(data as u64))?;
    let num = r.regs.map_or(num, |g| g[R_ORIG_RAX]);
    if num == u64::MAX {
        return Some(Err(frame.rax as i64));
    }
    frame.rax = num;
    Some(Ok(()))
}

// ----------------------------------------------------------------------
// /proc/<pid>/mem
// ----------------------------------------------------------------------

/// An open `/proc/<pid>/mem`: the process's memory at file offsets equal to addresses.
/// After the process execs it follows the new address space, if the opener may still
/// trace the process (so a set-user-ID program's memory stays out of reach).
pub struct ProcMem {
    pid: u64,
    mm: Mutex<alloc::sync::Arc<Mutex<crate::memory::vm::Mm>>>,
    pos: Mutex<u64>,
    read: bool,
    write: bool,
}

/// Opens process `pid`'s memory (the caller must be allowed to trace it).
pub fn open_proc_mem(pid: u64, read: bool, write: bool) -> Result<alloc::sync::Arc<dyn super::chardev::CharDevice>, i64> {
    super::extra::may_access(pid)?;
    let mm = tracee_mm(pid)?;
    Ok(alloc::sync::Arc::new(ProcMem { pid, mm: Mutex::new(mm), pos: Mutex::new(0), read, write }))
}

impl ProcMem {
    /// Copies between `addr` and `buf` page by page up to the first page that cannot be
    /// reached: the bytes done, or `EIO` if none.
    fn access(&self, addr: u64, buf: &mut [u8], write: bool) -> i64 {
        // The process's address space now (it may have exec'd since the open)
        let Ok(now) = tracee_mm(self.pid) else { return 0 };
        let mm = {
            let mut held = self.mm.lock();
            if !alloc::sync::Arc::ptr_eq(&held, &now) {
                if super::extra::may_access(self.pid).is_err() {
                    return 0;
                }
                *held = now;
            }
            held.clone()
        };
        let mut done = 0usize;
        while done < buf.len() {
            let a = addr.wrapping_add(done as u64);
            let n = ((4096 - (a & 4095)) as usize).min(buf.len() - done);
            if !canonical(a) || !canonical(a + n as u64) {
                break;
            }
            let mut m = mm.lock();
            let ok = if write {
                m.force_write(a, &buf[done..done + n]).is_ok()
            } else {
                match m.prefault(a, n as u64, false).ok().and_then(|_| m.translate(a)) {
                    Some(phys) => {
                        buf[done..done + n].copy_from_slice(unsafe { core::slice::from_raw_parts(crate::memory::frame_allocator::phys_to_virt(phys.as_u64()) as *const u8, n) });
                        true
                    }
                    None => false,
                }
            };
            if !ok {
                break;
            }
            done += n;
        }
        if done == 0 && !buf.is_empty() {
            EIO
        } else {
            done as i64
        }
    }
}

impl super::chardev::CharDevice for ProcMem {
    fn read(&self, buf: &mut [u8]) -> i64 {
        let at = *self.pos.lock();
        let r = self.pread(buf, at).unwrap_or(EIO);
        if r > 0 {
            *self.pos.lock() = at + r as u64;
        }
        r
    }
    fn write(&self, data: &[u8]) -> i64 {
        let at = *self.pos.lock();
        let r = self.pwrite(data, at).unwrap_or(EIO);
        if r > 0 {
            *self.pos.lock() = at + r as u64;
        }
        r
    }
    fn pread(&self, buf: &mut [u8], offset: u64) -> Option<i64> {
        Some(if self.read { self.access(offset, buf, false) } else { -9 })
    }
    fn pwrite(&self, data: &[u8], offset: u64) -> Option<i64> {
        if !self.write {
            return Some(-9);
        }
        let mut copy = data.to_vec();
        Some(self.access(offset, &mut copy, true))
    }
    fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
        let mut pos = self.pos.lock();
        let new = match whence {
            0 => offset as u64,
            1 => pos.wrapping_add(offset as u64),
            _ => return Some(EINVAL),
        };
        *pos = new;
        Some(new as i64)
    }
    fn poll_events(&self) -> u32 {
        0x5 // POLLIN | POLLOUT
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> alloc::string::String {
        alloc::format!("/proc/{}/mem", super::ns::pid_to_caller(self.pid))
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn stat(&self) -> super::types::LinuxStat {
        let mut st = super::types::LinuxStat::default();
        st.st_dev = 4; // proc
        st.st_ino = self.pid << 8 | 0x6d;
        st.st_mode = 0o100600;
        st.st_nlink = 1;
        st.st_blksize = 4096;
        st
    }
}

/// `ptrace(request, pid, addr, data)`.
pub fn sys_ptrace(req: u64, pid: u64, addr: u64, data: u64) -> i64 {
    let (my_tid, me) = super::proc::current_ids();
    match req {
        TRACEME => {
            let parent = super::proc::parent_of(me);
            let mut tr = TRACEES.lock();
            if tr.get(&my_tid).is_some_and(|t| !t.exited) {
                return EPERM;
            }
            tr.insert(my_tid, Tracee::new(me, parent, false, 0));
            ANY.store(true, Ordering::Relaxed);
            return 0;
        }
        ATTACH | SEIZE => {
            if req == SEIZE && (addr != 0 || data & !O_ALL != 0) {
                return if addr != 0 { EIO } else { EINVAL };
            }
            let tid = super::ns::pid_from_caller(pid as i32 as i64 as u64);
            let Some(tgid) = super::proc::tgid_of(tid) else { return ESRCH };
            if tgid == me {
                return EPERM;
            }
            if let Err(e) = super::extra::may_access(tgid) {
                return e;
            }
            {
                let mut tr = TRACEES.lock();
                if tr.get(&tid).is_some_and(|t| !t.exited) {
                    return EPERM;
                }
                let opts = if req == SEIZE { data } else { 0 };
                tr.insert(tid, Tracee::new(tgid, me, req == SEIZE, opts));
                ANY.store(true, Ordering::Relaxed);
            }
            if req == ATTACH {
                super::proc::post_thread(tgid, tid, SIGSTOP);
            }
            return 0;
        }
        _ => {}
    }
    let tid = super::ns::pid_from_caller(pid as i32 as i64 as u64);
    let mut tr = TRACEES.lock();
    let Some(t) = tr.get_mut(&tid).filter(|t| t.tracer == me && !t.exited) else { return ESRCH };
    match req {
        KILL => {
            let tgid = t.tgid;
            drop(tr);
            super::proc::post_thread(tgid, tid, SIGKILL);
            return 0;
        }
        INTERRUPT => {
            if !t.seized {
                return EIO;
            }
            if !t.stopped {
                t.interrupt = Some(SIGTRAP);
                let tgid = t.tgid;
                drop(tr);
                crate::task::wait::wake_process_deferred(tgid);
            }
            return 0;
        }
        _ => {}
    }
    // Everything else needs the tracee stopped
    if !t.stopped || t.resume.is_some() {
        return ESRCH;
    }
    let tgid = t.tgid;
    match req {
        PEEKTEXT | PEEKDATA => {
            drop(tr);
            match mem_read(tgid, addr, 8) {
                Ok(b) => put_u64(data, u64::from_le_bytes(b[..8].try_into().unwrap())),
                Err(e) => e,
            }
        }
        POKETEXT | POKEDATA => {
            drop(tr);
            mem_write(tgid, addr, &data.to_le_bytes()).map_or_else(|e| e, |_| 0)
        }
        PEEKUSR => {
            if addr & 7 != 0 || addr >= USER_SIZE {
                return EIO;
            }
            let v = if (addr as usize) < REGS_SIZE {
                t.regs[addr as usize / 8]
            } else if addr >= USER_DEBUGREG {
                drop(tr);
                let i = ((addr - USER_DEBUGREG) / 8) as usize;
                return put_u64(data, debugregs_of(tid).map_or(0, |d| d[i]));
            } else {
                0
            };
            drop(tr);
            put_u64(data, v)
        }
        POKEUSR => {
            if addr & 7 != 0 || addr >= USER_SIZE {
                return EIO;
            }
            if (addr as usize) < REGS_SIZE {
                t.regs[addr as usize / 8] = data;
                t.regs_dirty = true;
                0
            } else if addr >= USER_DEBUGREG {
                drop(tr);
                set_debugreg(tid, ((addr - USER_DEBUGREG) / 8) as usize, data)
            } else {
                0 // the rest of struct user (fpvalid, sizes): nothing to change
            }
        }
        GETREGS => {
            let b = regs_bytes(&t.regs);
            drop(tr);
            copy_out(data, &b).map_or_else(|e| e, |_| 0)
        }
        SETREGS => {
            drop(tr);
            let Ok(b) = copy_in(data, REGS_SIZE) else { return -14 };
            let mut tr = TRACEES.lock();
            let Some(t) = tr.get_mut(&tid) else { return ESRCH };
            regs_from(&b, &mut t.regs);
            t.regs_dirty = true;
            0
        }
        GETFPREGS => {
            let b = t.fpu;
            drop(tr);
            copy_out(data, &b).map_or_else(|e| e, |_| 0)
        }
        SETFPREGS => {
            drop(tr);
            let Ok(b) = copy_in(data, 512) else { return -14 };
            let mut tr = TRACEES.lock();
            let Some(t) = tr.get_mut(&tid) else { return ESRCH };
            t.fpu.copy_from_slice(&b);
            t.fpu_dirty = true;
            0
        }
        GETREGSET | SETREGSET => {
            // addr: NT_PRSTATUS (1) or NT_PRFPREG (2); data: struct iovec
            let size = match addr {
                1 => REGS_SIZE,
                2 => 512,
                _ => return EINVAL,
            };
            let current = if addr == 1 { regs_bytes(&t.regs) } else { t.fpu.to_vec() };
            drop(tr);
            let Ok(iov) = copy_in(data, 16) else { return -14 };
            let base = u64::from_le_bytes(iov[0..8].try_into().unwrap());
            let len = (u64::from_le_bytes(iov[8..16].try_into().unwrap()) as usize).min(size);
            if req == GETREGSET {
                if let Err(e) = copy_out(base, &current[..len]) {
                    return e;
                }
            } else {
                let Ok(b) = copy_in(base, len) else { return -14 };
                let mut merged = current;
                merged[..len].copy_from_slice(&b);
                let mut tr = TRACEES.lock();
                let Some(t) = tr.get_mut(&tid) else { return ESRCH };
                if addr == 1 {
                    regs_from(&merged, &mut t.regs);
                    t.regs_dirty = true;
                } else {
                    t.fpu.copy_from_slice(&merged);
                    t.fpu_dirty = true;
                }
            }
            put_u64(data + 8, len as u64)
        }
        GETSIGINFO => {
            let b = t.siginfo;
            drop(tr);
            copy_out(data, &b).map_or_else(|e| e, |_| 0)
        }
        SETSIGINFO => {
            drop(tr);
            let Ok(b) = copy_in(data, 128) else { return -14 };
            let mut tr = TRACEES.lock();
            if let Some(t) = tr.get_mut(&tid) {
                t.siginfo.copy_from_slice(&b);
            }
            0
        }
        GETEVENTMSG => {
            let m = t.eventmsg;
            drop(tr);
            put_u64(data, m)
        }
        SETOPTIONS => {
            if data & !O_ALL != 0 {
                return EINVAL;
            }
            t.options = data;
            0
        }
        GET_SYSCALL_INFO => {
            let mut info = [0u8; 84];
            let r = t.regs;
            let op = t.op;
            drop(tr);
            info[4..8].copy_from_slice(&super::seccomp::AUDIT_ARCH_X86_64.to_le_bytes());
            info[8..16].copy_from_slice(&r[R_RIP].to_le_bytes());
            info[16..24].copy_from_slice(&r[R_RSP].to_le_bytes());
            let size = match op {
                Op::Entry => {
                    info[0] = 1;
                    info[24..32].copy_from_slice(&r[R_ORIG_RAX].to_le_bytes());
                    for (i, reg) in [14usize, 13, 12, 7, 9, 8].iter().enumerate() {
                        info[32 + i * 8..40 + i * 8].copy_from_slice(&r[*reg].to_le_bytes());
                    }
                    80
                }
                Op::Exit => {
                    info[0] = 2;
                    let rval = r[R_RAX] as i64;
                    info[24..32].copy_from_slice(&rval.to_le_bytes());
                    info[32] = (-4095..0).contains(&rval) as u8;
                    33
                }
                Op::Seccomp(d) => {
                    info[0] = 3;
                    info[24..32].copy_from_slice(&r[R_ORIG_RAX].to_le_bytes());
                    for (i, reg) in [14usize, 13, 12, 7, 9, 8].iter().enumerate() {
                        info[32 + i * 8..40 + i * 8].copy_from_slice(&r[*reg].to_le_bytes());
                    }
                    info[80..84].copy_from_slice(&(d as u32).to_le_bytes());
                    84
                }
                Op::Other => 24,
            };
            let n = (addr as usize).min(size);
            if let Err(e) = copy_out(data, &info[..n]) {
                return e;
            }
            size as i64
        }
        LISTEN => {
            // Only from a seized tracee's group stop
            if !t.seized || (t.status >> 16) as u32 != EV_STOP || !matches!((t.status >> 8) & 0xff, 19 | 20 | 21 | 22) {
                return EIO;
            }
            t.listening = true;
            0
        }
        CONT | SYSCALL | SINGLESTEP | DETACH => {
            if data > 64 {
                return EIO;
            }
            t.syscall_stops = req == SYSCALL;
            t.resume = Some(Resume { sig: data as u32, step: req == SINGLESTEP, detach: req == DETACH });
            drop(tr);
            RESUMED.wake_all();
            0
        }
        _ => EIO,
    }
}
