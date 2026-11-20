//! `src/compat/linux/ptrace.rs`: attaching (TRACEME, ATTACH, SEIZE), the stops a traced
//! thread makes (signal, group, syscall, event, interrupt, seccomp), every request a tracer
//! sends while it is stopped, wait reporting, exits, tracee memory and `/proc/<pid>/mem`.
//!
//! A stopped tracee sleeps until its tracer resumes it; on the host the tracer's side runs
//! inside the fake wait (`fake::ON_WAIT`): [`as_tracer`] switches to the tracer, runs the
//! test's requests once, and switches back.

use super::common::*;
use crate::arch::idt::{ExceptionContext, FpuState};
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::chardev::CharDevice;
use crate::compat::linux::proc::UserRegs;
use crate::compat::linux::ptrace::*;
use crate::memory::vm::{Mm, USER_SPACE_START};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

const TRACEME: u64 = 0;
const PEEKDATA: u64 = 2;
const PEEKUSR: u64 = 3;
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

const SIGTRAP: u32 = 5;
const SIGUSR1: u32 = 10;
const SIGSTOP: u32 = 19;
const SIGKILL: u32 = 9;

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

/// Thread `tid`'s pending signal among `mask`, taken.
fn take(pid: u64, tid: u64, sig: u32) -> bool {
    linux::proc::take_signal_info_of(tid, pid, bit(sig)).is_some()
}

/// While the current (tracee) thread is stopped, runs `f` once as `tracer`, then makes
/// further waits fail (a test that forgets to resume would otherwise spin forever).
fn as_tracer(tracer: u64, f: impl FnOnce() + 'static) {
    let mut f = Some(f);
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(move || {
            let me = fake::CURRENT.get();
            let Some(g) = f.take() else { panic!("tracee not resumed") };
            fake::switch_to(tracer);
            g();
            fake::switch_to(me);
        }))
    });
}

fn no_tracer() {
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
}

/// Process `tracer` (root) with child `tracee`.
fn pair(tracer: u64, tracee: u64) {
    spawn(tracer, 1);
    spawn(tracee, tracer);
}

fn frame() -> SyscallFrame {
    SyscallFrame { rax: 39, rdi: 1, rsi: 2, rdx: 3, r10: 4, r8: 5, r9: 6, rip: 0x40_1000, rsp: 0x7fff_0000, rflags: 0x202, ..Default::default() }
}

#[test]
fn traceme_attach_and_seize() {
    let _g = setup();
    pair(2000, 2001);
    run(2001);
    assert!(!is_traced(2001));
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    assert!(is_traced(2001) && active());
    assert_eq!(tracer_of(2001), 2000);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), EPERM, "already traced");
    // ATTACH from another process: already traced
    spawn(2002, 1);
    run(2002);
    assert_eq!(sys_ptrace(ATTACH, 2001, 0, 0), EPERM);
    assert_eq!(sys_ptrace(ATTACH, 9999, 0, 0), ESRCH);
    assert_eq!(sys_ptrace(ATTACH, 2002, 0, 0), EPERM, "itself");
    // ATTACH posts SIGSTOP to the thread
    spawn(2003, 1);
    run(2002);
    assert_eq!(sys_ptrace(ATTACH, 2003, 0, 0), 0);
    assert!(take(2003, 2003, SIGSTOP));
    assert_eq!(tracer_of(2003), 2002);
    // SEIZE: no SIGSTOP; argument checks
    spawn(2004, 1);
    assert_eq!(sys_ptrace(SEIZE, 2004, 1, 0), EIO, "addr must be 0");
    assert_eq!(sys_ptrace(SEIZE, 2004, 0, 1 << 30), EINVAL, "unknown option");
    assert_eq!(sys_ptrace(SEIZE, 2004, 0, O_TRACESYSGOOD | O_EXITKILL), 0);
    assert!(!take(2004, 2004, SIGSTOP));
    // Another user's process
    spawn_as(2005, 1, 1000, 1000);
    spawn_as(2006, 1, 2000, 2000);
    run(2005);
    assert_eq!(sys_ptrace(ATTACH, 2006, 0, 0), EPERM);
    // Requests to a thread we do not trace / that is running
    assert_eq!(sys_ptrace(CONT, 2004, 0, 0), ESRCH, "not our tracee");
    run(2002);
    assert_eq!(sys_ptrace(CONT, 2004, 0, 0), ESRCH, "running");
    assert_eq!(sys_ptrace(GETREGS, 2004, 0, 0), ESRCH);
    // has_tracee / wait_report with nothing to report
    assert!(has_tracee(2002, -1) && has_tracee(2002, 2003) && !has_tracee(2002, 2001));
    assert_eq!(wait_report(2002, -1, false), None);
}

#[test]
fn signal_stop_and_register_requests() {
    let _g = setup();
    pair(2010, 2011);
    run(2011);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    fake::task(2011, |t| t.fs_base = 0x1000);
    let mut fpu = FpuState::new();
    fpu.0[100] = 0xab;
    let mut f = frame();
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&SIGUSR1.to_le_bytes());
    let seen = Rc::new(Cell::new(false));
    let s2 = seen.clone();
    as_tracer(2010, move || {
        // wait sees the stop once
        assert_eq!(wait_report(2010, 2011, true), Some((2011, 0x7f | (10 << 8))), "keep: still reportable");
        assert_eq!(wait_report(2010, -1, false), Some((2011, 0x7f | (10 << 8))));
        assert_eq!(wait_report(2010, -1, false), None, "reported once");
        // GETREGS: user_regs_struct order
        let mut regs = [0u64; 27];
        assert_eq!(sys_ptrace(GETREGS, 2011, 0, mptr(&mut regs)), 0);
        assert_eq!((regs[10], regs[14], regs[13], regs[12], regs[7], regs[9], regs[8]), (39, 1, 2, 3, 4, 5, 6));
        assert_eq!((regs[15], regs[16], regs[17], regs[19], regs[20], regs[21]), (39, 0x40_1000, 0x33, 0x7fff_0000, 0x2b, 0x1000));
        // PEEKUSR: a register, the padding, a debug register; bad offsets
        let mut v = 0u64;
        assert_eq!(sys_ptrace(PEEKUSR, 2011, 16 * 8, mptr(&mut v)), 0);
        assert_eq!(v, 0x40_1000);
        assert_eq!(sys_ptrace(PEEKUSR, 2011, 304, mptr(&mut v)), 0);
        assert_eq!(v, 0);
        assert_eq!(sys_ptrace(PEEKUSR, 2011, 848 + 7 * 8, mptr(&mut v)), 0);
        assert_eq!(sys_ptrace(PEEKUSR, 2011, 3, mptr(&mut v)), EIO);
        assert_eq!(sys_ptrace(PEEKUSR, 2011, 912, mptr(&mut v)), EIO);
        // POKEUSR into rax and rflags (only user flags may change), and the padding
        assert_eq!(sys_ptrace(POKEUSR, 2011, 10 * 8, 77), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2011, 18 * 8, 0xffff_ffff), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2011, 400, 1), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2011, 5, 1), EIO);
        assert_eq!(sys_ptrace(POKEUSR, 2011, 912, 1), EIO);
        // FP registers
        let mut fp = [0u8; 512];
        assert_eq!(sys_ptrace(GETFPREGS, 2011, 0, mptr(&mut fp)), 0);
        assert_eq!(fp[100], 0xab);
        fp[200] = 0xcd;
        assert_eq!(sys_ptrace(SETFPREGS, 2011, 0, ptr(&fp)), 0);
        // siginfo
        let mut si = [0u8; 128];
        assert_eq!(sys_ptrace(GETSIGINFO, 2011, 0, mptr(&mut si)), 0);
        assert_eq!(si[0], 10);
        si[0] = 12;
        assert_eq!(sys_ptrace(SETSIGINFO, 2011, 0, ptr(&si)), 0);
        assert_eq!(sys_ptrace(GETSIGINFO, 2011, 0, mptr(&mut si)), 0);
        assert_eq!(si[0], 12);
        // options and the event message
        assert_eq!(sys_ptrace(SETOPTIONS, 2011, 0, 1 << 30), EINVAL);
        assert_eq!(sys_ptrace(SETOPTIONS, 2011, 0, O_TRACESYSGOOD), 0);
        assert_eq!(sys_ptrace(GETEVENTMSG, 2011, 0, mptr(&mut v)), 0);
        // syscall info of a signal stop: just the common part
        let mut sinfo = [0u8; 84];
        assert_eq!(sys_ptrace(GET_SYSCALL_INFO, 2011, 84, mptr(&mut sinfo)), 24);
        assert_eq!(sinfo[0], 0);
        assert_eq!(u32::from_le_bytes(sinfo[4..8].try_into().unwrap()), 0xc000_003e);
        // LISTEN only for a seized tracee in a group stop
        assert_eq!(sys_ptrace(LISTEN, 2011, 0, 0), EIO);
        // INTERRUPT only for seized tracees
        assert_eq!(sys_ptrace(INTERRUPT, 2011, 0, 0), EIO);
        // An unknown request, a signal number out of range
        assert_eq!(sys_ptrace(0x9999, 2011, 0, 0), EIO);
        assert_eq!(sys_ptrace(CONT, 2011, 0, 65), EIO);
        // Resume, delivering SIGUSR2 instead
        assert_eq!(sys_ptrace(CONT, 2011, 0, 12), 0);
        assert_eq!(sys_ptrace(CONT, 2011, 0, 0), ESRCH, "already resumed");
        s2.set(true);
    });
    let sig = signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &info);
    no_tracer();
    assert!(seen.get());
    assert_eq!(sig, 12, "the tracer's choice");
    assert_eq!(f.rax, 77, "the tracer's rax");
    assert_eq!(f.rflags & 0x54dd5, 0x54dd5 & 0xffff_ffff & !0x100, "user flags taken, TF off (no step)");
    assert_eq!(f.rflags & 0x200, 0x200, "IF stays set");
    assert_eq!(fpu.0[200], 0xcd, "the tracer's FP state");
    // An untraced thread's signal stop is a no-op
    run(2010);
    assert_eq!(signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &info), SIGUSR1);
}

#[test]
fn setregs_regsets_and_singlestep() {
    let _g = setup();
    pair(2020, 2021);
    run(2021);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let mut fpu = FpuState::new();
    let mut f = frame();
    as_tracer(2020, || {
        let mut regs = [0u64; 27];
        assert_eq!(sys_ptrace(GETREGS, 2021, 0, mptr(&mut regs)), 0);
        regs[14] = 111; // rdi
        regs[16] = 0x0000_9000_0000_0000; // a non-canonical rip is ignored
        regs[21] = 0x2000; // fs_base
        assert_eq!(sys_ptrace(SETREGS, 2021, 0, ptr(&regs)), 0);
        assert_eq!(sys_ptrace(SETREGS, 2021, 0, 0), -14);
        // GETREGSET / SETREGSET with an iovec
        let mut buf = [0u64; 27];
        let mut iov = [mptr(&mut buf), 27 * 8 + 100];
        assert_eq!(sys_ptrace(GETREGSET, 2021, 1, mptr(&mut iov)), 0);
        assert_eq!(iov[1], 27 * 8, "clamped to the set's size");
        assert_eq!(buf[14], 111);
        buf[13] = 222; // rsi, through a short write of the first 14 registers
        let mut iov = [ptr(&buf), 14 * 8];
        assert_eq!(sys_ptrace(SETREGSET, 2021, 1, mptr(&mut iov)), 0);
        let mut fp = [0u8; 512];
        let mut iov = [mptr(&mut fp), 512];
        assert_eq!(sys_ptrace(GETREGSET, 2021, 2, mptr(&mut iov)), 0);
        fp[0] = 0x7f;
        let mut iov = [ptr(&fp), 512];
        assert_eq!(sys_ptrace(SETREGSET, 2021, 2, mptr(&mut iov)), 0);
        assert_eq!(sys_ptrace(GETREGSET, 2021, 3, mptr(&mut iov)), EINVAL);
        assert_eq!(sys_ptrace(GETREGSET, 2021, 1, 0), -14);
        assert_eq!(sys_ptrace(SINGLESTEP, 2021, 0, 0), 0);
    });
    let sig = signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    no_tracer();
    assert_eq!(sig, 0);
    assert_eq!((f.rdi, f.rsi, f.rip), (111, 222, 0x40_1000));
    assert_eq!(f.rflags & 0x100, 0x100, "single step: TF set");
    assert_eq!(fake::task(2021, |t| t.fs_base), Some(0x2000));
    assert!(fake::called("wrmsr(0xc0000100,0x2000)"));
    assert_eq!(fpu.0[0], 0x7f);
}

#[test]
fn syscall_stops_entry_exit_and_cancel() {
    let _g = setup();
    pair(2030, 2031);
    run(2031);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let mut fpu = FpuState::new();
    let mut f = frame();
    // Not resumed with PTRACE_SYSCALL yet: entry and exit pass through
    assert_eq!(syscall_entry(&mut f, &mut fpu, 39), Ok(39));
    assert_eq!(syscall_exit(&mut f, &mut fpu, 39, 5), 5);
    // A signal stop; the tracer resumes with PTRACE_SYSCALL and TRACESYSGOOD
    as_tracer(2030, || {
        assert_eq!(sys_ptrace(SETOPTIONS, 2031, 0, O_TRACESYSGOOD), 0);
        assert_eq!(sys_ptrace(SYSCALL, 2031, 0, 0), 0);
    });
    signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    // Entry stop: status SIGTRAP|0x80; the tracer reads the call, changes it to getppid
    as_tracer(2030, || {
        assert_eq!(wait_report(2030, -1, false), Some((2031, 0x7f | (0x85 << 8))));
        let mut info = [0u8; 84];
        assert_eq!(sys_ptrace(GET_SYSCALL_INFO, 2031, 84, mptr(&mut info)), 80);
        assert_eq!(info[0], 1, "entry");
        assert_eq!(u64::from_le_bytes(info[24..32].try_into().unwrap()), 39);
        assert_eq!(u64::from_le_bytes(info[32..40].try_into().unwrap()), 1, "args[0]");
        let mut rax = 0u64;
        assert_eq!(sys_ptrace(PEEKUSR, 2031, 80, mptr(&mut rax)), 0);
        assert_eq!(rax as i64, ENOSYS, "rax is -ENOSYS at entry");
        assert_eq!(sys_ptrace(POKEUSR, 2031, 15 * 8, 110), 0);
        assert_eq!(sys_ptrace(SYSCALL, 2031, 0, 0), 0);
    });
    assert_eq!(syscall_entry(&mut f, &mut fpu, 39), Ok(110));
    assert_eq!(f.rax, 110);
    // Exit stop: the tracer changes the result
    as_tracer(2030, || {
        let mut info = [0u8; 84];
        assert_eq!(sys_ptrace(GET_SYSCALL_INFO, 2031, 40, mptr(&mut info)), 33);
        assert_eq!((info[0], i64::from_le_bytes(info[24..32].try_into().unwrap()), info[32]), (2, -2, 1), "an error result");
        assert_eq!(sys_ptrace(POKEUSR, 2031, 80, 7), 0);
        assert_eq!(sys_ptrace(SYSCALL, 2031, 0, 0), 0);
    });
    assert_eq!(syscall_exit(&mut f, &mut fpu, 110, -2), 7);
    // Cancelled at entry: orig_rax -1, the result is the tracer's rax
    as_tracer(2030, || {
        assert_eq!(sys_ptrace(POKEUSR, 2031, 15 * 8, u64::MAX), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2031, 80, (-1i64) as u64), 0);
        assert_eq!(sys_ptrace(SYSCALL, 2031, 0, 0), 0);
    });
    assert_eq!(syscall_entry(&mut f, &mut fpu, 39), Err(-1));
    // rt_sigreturn's exit stop
    as_tracer(2030, || {
        assert_eq!(sys_ptrace(CONT, 2031, 0, 0), 0);
    });
    let mut regs = UserRegs::default();
    sigreturn_exit(&mut regs, &mut fpu);
    no_tracer();
    // Resumed with CONT: no more syscall stops
    assert_eq!(syscall_entry(&mut f, &mut fpu, 39), Ok(39));
    sigreturn_exit(&mut regs, &mut fpu);
}

#[test]
fn exit_exec_and_seccomp_events() {
    let _g = setup();
    pair(2040, 2041);
    run(2041);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let mut fpu = FpuState::new();
    let mut f = frame();
    // exec without TRACEEXEC: a plain SIGTRAP
    on_exec(2041, 2041);
    assert!(take(2041, 2041, SIGTRAP));
    // Options: exit, exec, seccomp
    as_tracer(2040, || {
        assert_eq!(sys_ptrace(SETOPTIONS, 2041, 0, O_TRACEEXIT | O_TRACEEXEC | O_TRACESECCOMP), 0);
        assert_eq!(sys_ptrace(CONT, 2041, 0, 0), 0);
    });
    signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    // exit_group(3): an exit event with the status as wait would show it
    f.rdi = 3;
    as_tracer(2040, || {
        assert_eq!(wait_report(2040, -1, false), Some((2041, 0x7f | (5 << 8) | (6 << 16))));
        let mut m = 0u64;
        assert_eq!(sys_ptrace(GETEVENTMSG, 2041, 0, mptr(&mut m)), 0);
        assert_eq!(m, 3 << 8);
        assert_eq!(sys_ptrace(CONT, 2041, 0, 0), 0);
    });
    assert_eq!(syscall_entry(&mut f, &mut fpu, 231), Ok(231));
    // exec with TRACEEXEC: reported when execve returns
    on_exec(2041, 2041);
    assert!(!take(2041, 2041, SIGTRAP));
    as_tracer(2040, || {
        assert_eq!(wait_report(2040, -1, false), Some((2041, 0x7f | (5 << 8) | (4 << 16))));
        assert_eq!(sys_ptrace(CONT, 2041, 0, 0), 0);
    });
    assert_eq!(syscall_exit(&mut f, &mut fpu, 59, 0), 0);
    // A seccomp TRACE stop: the tracer may skip the call
    fake::task(2041, |_| ());
    as_tracer(2040, || {
        let mut info = [0u8; 84];
        assert_eq!(sys_ptrace(GET_SYSCALL_INFO, 2041, 84, mptr(&mut info)), 84);
        assert_eq!((info[0], u32::from_le_bytes(info[80..84].try_into().unwrap())), (3, 0x42));
        assert_eq!(sys_ptrace(POKEUSR, 2041, 15 * 8, u64::MAX), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2041, 80, 5), 0);
        assert_eq!(sys_ptrace(CONT, 2041, 0, 0), 0);
    });
    f.rax = 39;
    assert_eq!(seccomp_stop(&mut f, 0x42), Some(Err(5)));
    // ... or let it run (possibly changed)
    as_tracer(2040, || {
        assert_eq!(sys_ptrace(CONT, 2041, 0, 0), 0);
    });
    f.rax = 39;
    assert_eq!(seccomp_stop(&mut f, 1), Some(Ok(())));
    assert_eq!(f.rax, 39);
    no_tracer();
    // Without TRACESECCOMP or a tracer: no stop
    run(2040);
    assert_eq!(seccomp_stop(&mut f, 1), None);
}

#[test]
fn clone_events_and_traced_children() {
    let _g = setup();
    pair(2050, 2051);
    run(2051);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let mut fpu = FpuState::new();
    let mut f = frame();
    // No options: a child stays untraced
    spawn(2052, 2051);
    on_clone(&mut f, 2052, 2052, 17);
    assert!(!is_traced(2052));
    // CLONE_PTRACE traces it without an event (attached: SIGSTOP)
    spawn(2053, 2051);
    on_clone(&mut f, 2053, 2053, 17 | 0x2000);
    assert!(is_traced(2053) && take(2053, 2053, SIGSTOP));
    // TRACEFORK: a fork event with the child's pid
    as_tracer(2050, || {
        assert_eq!(sys_ptrace(SETOPTIONS, 2051, 0, O_TRACEFORK | O_TRACEVFORK | O_TRACECLONE | O_TRACEVFORKDONE), 0);
        assert_eq!(sys_ptrace(CONT, 2051, 0, 0), 0);
    });
    signal_stop(&mut f, &mut fpu, 57, SIGUSR1, &[0; 128]);
    spawn(2054, 2051);
    f.rax = 2054;
    as_tracer(2050, || {
        assert_eq!(wait_report(2050, 2051, false), Some((2051, 0x7f | (5 << 8) | (1 << 16))));
        let mut m = 0u64;
        assert_eq!(sys_ptrace(GETEVENTMSG, 2051, 0, mptr(&mut m)), 0);
        assert_eq!(m, 2054);
        assert_eq!(sys_ptrace(CONT, 2051, 0, 0), 0);
    });
    on_clone(&mut f, 2054, 2054, 17);
    assert_eq!(f.rax, 2054, "the fork's result is kept");
    assert!(is_traced(2054));
    // vfork event, then vfork-done
    spawn(2055, 2051);
    as_tracer(2050, || {
        assert_eq!(wait_report(2050, 2051, false), Some((2051, 0x7f | (5 << 8) | (2 << 16))));
        assert_eq!(sys_ptrace(CONT, 2051, 0, 0), 0);
    });
    on_clone(&mut f, 2055, 2055, 0x4000 | 0x100 | 17);
    as_tracer(2050, || {
        assert_eq!(wait_report(2050, 2051, false), Some((2051, 0x7f | (5 << 8) | (5 << 16))));
        assert_eq!(sys_ptrace(CONT, 2051, 0, 0), 0);
    });
    on_vfork_done(&mut f, 2055);
    // A thread: a clone event
    add_thread(2051, 2056);
    as_tracer(2050, || {
        assert_eq!(wait_report(2050, 2051, false), Some((2051, 0x7f | (5 << 8) | (3 << 16))));
        assert_eq!(sys_ptrace(CONT, 2051, 0, 0), 0);
    });
    on_clone(&mut f, 2051, 2056, 0x10000 | 0x100);
    no_tracer();
    // CLONE_UNTRACED: never traced
    spawn(2057, 2051);
    on_clone(&mut f, 2057, 2057, 17 | 0x80_0000);
    assert!(!is_traced(2057));
    // An untraced caller: nothing
    run(2050);
    on_clone(&mut f, 2058, 2058, 17);
    on_vfork_done(&mut f, 2058);
    assert!(!is_traced(2058));
}

#[test]
fn seized_tracees_interrupt_and_listen() {
    let _g = setup();
    spawn(2060, 1);
    spawn(2061, 1);
    run(2060);
    assert_eq!(sys_ptrace(SEIZE, 2061, 0, O_TRACECLONE), 0);
    // INTERRUPT a running tracee: it stops at its next chance
    assert_eq!(sys_ptrace(INTERRUPT, 2061, 0, 0), 0);
    assert!(fake::called("wake_process_deferred(2061)"));
    run(2061);
    assert!(interrupt_pending());
    let mut fpu = FpuState::new();
    let mut f = frame();
    as_tracer(2060, || {
        assert_eq!(wait_report(2060, -1, false), Some((2061, 0x7f | (5 << 8) | (128 << 16))));
        // INTERRUPT of a stopped tracee: nothing more to do
        assert_eq!(sys_ptrace(INTERRUPT, 2061, 0, 0), 0);
        assert_eq!(sys_ptrace(LISTEN, 2061, 0, 0), EIO, "not a group stop");
        assert_eq!(sys_ptrace(CONT, 2061, 0, 0), 0);
    });
    interrupt_stop(&mut f, &mut fpu, 39);
    assert!(!interrupt_pending());
    interrupt_stop(&mut f, &mut fpu, 39); // nothing pending: returns at once
    // An interrupt taken at system call entry
    run(2060);
    assert_eq!(sys_ptrace(INTERRUPT, 2061, 0, 0), 0);
    run(2061);
    as_tracer(2060, || {
        assert_eq!(sys_ptrace(CONT, 2061, 0, 0), 0);
    });
    assert_eq!(syscall_entry(&mut f, &mut fpu, 39), Ok(39));
    // A seized tracee's group stop (SIGSTOP) is an EV_STOP stop; LISTEN keeps it there
    // until SIGCONT
    as_tracer(2060, || {
        assert_eq!(wait_report(2060, -1, false), Some((2061, 0x7f | (19 << 8) | (128 << 16))));
        assert_eq!(sys_ptrace(LISTEN, 2061, 0, 0), 0);
        on_sigcont(2061);
    });
    group_stop(&mut f, &mut fpu, 39, SIGSTOP);
    no_tracer();
    // A seized tracee's clone child gets an interrupt (SIGTRAP) instead of SIGSTOP
    as_tracer(2060, || {
        assert_eq!(sys_ptrace(CONT, 2061, 0, 0), 0);
    });
    spawn(2062, 2061);
    on_clone(&mut f, 2062, 2062, 0x100 | 0x200);
    no_tracer();
    assert!(is_traced(2062) && !take(2062, 2062, SIGSTOP));
    run(2062);
    assert!(interrupt_pending());
    on_sigcont(4242); // nobody listening there
}

#[test]
fn kill_detach_exits_and_tracer_exit() {
    let _g = setup();
    pair(2070, 2071);
    run(2071);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let mut fpu = FpuState::new();
    let mut f = frame();
    // KILL: works on a running tracee, posts SIGKILL
    run(2070);
    assert_eq!(sys_ptrace(KILL, 2071, 0, 0), 0);
    assert!(take(2071, 2071, SIGKILL));
    // A stopped tracee with SIGKILL pending leaves its stop by itself
    run(2071);
    linux::proc::post_thread(2071, 2071, SIGKILL);
    fake::SPIN_WAITS.set(true);
    assert_eq!(signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]), 0);
    fake::SPIN_WAITS.set(false);
    take(2071, 2071, SIGKILL);
    // DETACH: the tracee is no longer traced after its stop
    as_tracer(2070, || {
        assert_eq!(sys_ptrace(DETACH, 2071, 0, 0), 0);
    });
    signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    no_tracer();
    assert!(!is_traced(2071));
    // A main thread traced by its parent: the parent reaps it the usual way
    run(2071);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    assert_eq!(on_thread_exit(2071, 2071, 0, 2070), None);
    assert!(!is_traced(2071));
    // Another tracer: it hears of the exit through wait, once
    spawn(2072, 1);
    spawn(2073, 1);
    add_thread(2073, 2074);
    run(2072);
    assert_eq!(sys_ptrace(SEIZE, 2073, 0, O_EXITKILL), 0);
    assert_eq!(sys_ptrace(SEIZE, 2074, 0, 0), 0);
    assert_eq!(on_thread_exit(2073, 2074, 9, 1), Some(2072));
    assert_eq!(wait_report(2072, -1, false), Some((2074, 9)));
    assert_eq!(wait_report(2072, -1, false), None, "an exit is forgotten once reported");
    assert_eq!(on_thread_exit(2073, 9999, 0, 1), None, "not traced");
    // The tracer exits: EXITKILL tracees are to be killed, the rest let go
    assert_eq!(sys_ptrace(SEIZE, 2074, 0, 0), 0);
    assert_eq!(on_tracer_exit(2072), vec![(2073, 2073)]);
    assert!(!is_traced(2073) && !is_traced(2074));
    // A stopped tracee of an exiting tracer detaches on its way out
    spawn(2075, 1);
    spawn(2076, 1);
    run(2075);
    assert_eq!(sys_ptrace(SEIZE, 2076, 0, 0), 0);
    run(2076);
    as_tracer(2075, || {
        assert!(on_tracer_exit(2075).is_empty());
    });
    signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    no_tracer();
    assert!(!is_traced(2076));
}

/// Gives process `pid` an address space with `n` pages at `base` filled with `fill`.
fn give_mm(pid: u64, base: u64, n: u64) -> Arc<spin::Mutex<Mm>> {
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    assert_eq!(linux::mm::sys_mmap(&mm, base, n * 4096, 3, 0x32, -1, 0) as u64, base);
    fake::task(pid, |t| t.mm = Some(mm.clone()));
    mm
}

#[test]
fn peek_and_poke_memory_and_debug_registers() {
    let _g = setup();
    pair(2080, 2081);
    run(2081);
    assert_eq!(sys_ptrace(TRACEME, 0, 0, 0), 0);
    let base = USER_SPACE_START + 0x500_0000;
    let _mm = give_mm(2081, base, 2);
    let mut fpu = FpuState::new();
    let mut f = frame();
    as_tracer(2080, move || {
        assert_eq!(sys_ptrace(POKEDATA, 2081, base + 4092, 0x1122_3344_5566_7788), 0, "across a page boundary");
        let mut v = 0u64;
        assert_eq!(sys_ptrace(PEEKDATA, 2081, base + 4092, mptr(&mut v)), 0);
        assert_eq!(v, 0x1122_3344_5566_7788);
        assert_eq!(sys_ptrace(PEEKDATA, 2081, base + 3 * 4096, mptr(&mut v)), EIO, "unmapped");
        assert_eq!(sys_ptrace(PEEKDATA, 2081, 0xffff_8000_0000_0000, mptr(&mut v)), EIO, "kernel address");
        assert_eq!(sys_ptrace(POKEDATA, 2081, 0xffff_8000_0000_0000, 1), EIO);
        assert_eq!(sys_ptrace(POKEDATA, 2081, base + 3 * 4096, 1), EIO);
        // Debug registers: addresses, DR7 checks
        let dr = |i: u64| 848 + i * 8;
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(0), 0x40_1000), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(1), 0x0000_7fff_ffff_f000), EIO, "a kernel-side address");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(6), 0), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(4), 0), EIO, "DR4 does not exist");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(7), 1 << 12), EIO, "reserved DR7 bits");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(7), 1 | (2 << 16)), EINVAL, "an I/O breakpoint");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(7), 1 | (3 << 18)), EINVAL, "an instruction breakpoint is 1 byte");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(1), 0x40_1001), 0);
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(7), (1 << 2) | (1 << 20) | (1 << 22)), EINVAL, "a 2-byte watch at an odd address");
        assert_eq!(sys_ptrace(POKEUSR, 2081, dr(7), 1 | (1 << 16) | (3 << 18)), 0, "a 4-byte write watch at DR0");
        let mut v7 = 0u64;
        assert_eq!(sys_ptrace(PEEKUSR, 2081, dr(7), mptr(&mut v7)), 0);
        assert_eq!(v7, 1 | (1 << 16) | (3 << 18));
        assert_eq!(sys_ptrace(CONT, 2081, 0, 0), 0);
    });
    signal_stop(&mut f, &mut fpu, 39, SIGUSR1, &[0; 128]);
    no_tracer();
    assert_eq!(fake::task(2081, |t| t.debugregs[0]), Some(0x40_1000));
}

#[test]
fn proc_pid_mem() {
    let _g = setup();
    spawn_as(2090, 1, 1000, 1000);
    spawn_as(2091, 1, 1000, 1000);
    spawn_as(2092, 1, 2000, 2000);
    run(2090);
    let base = USER_SPACE_START + 0x600_0000;
    let _mm = give_mm(2091, base, 2);
    assert_eq!(open_proc_mem(2092, true, true).err(), Some(EPERM), "another user");
    assert_eq!(open_proc_mem(2090, true, true).err(), Some(ESRCH), "no address space");
    let m = open_proc_mem(2091, true, true).unwrap();
    assert_eq!(m.pwrite(b"hello", base + 4094), Some(5), "across pages");
    let mut buf = [0u8; 5];
    assert_eq!(m.pread(&mut buf, base + 4094), Some(5));
    assert_eq!(&buf, b"hello");
    // read/write follow the position; seek moves it
    assert_eq!(m.seek(base as i64, 0), Some(base as i64));
    assert_eq!(m.write(b"ab"), 2);
    assert_eq!(m.seek(-2, 1), Some(base as i64));
    let mut two = [0u8; 2];
    assert_eq!(m.read(&mut two), 2);
    assert_eq!(&two, b"ab");
    assert_eq!(m.seek(0, 2), Some(EINVAL));
    // A short copy at the end of the mapping, EIO when nothing can be copied
    let mut big = [0u8; 16];
    assert_eq!(m.pread(&mut big, base + 2 * 4096 - 4), Some(4));
    assert_eq!(m.pread(&mut big, base + 3 * 4096), Some(EIO));
    assert_eq!(m.pread(&mut big, 0xffff_8000_0000_0000), Some(EIO));
    assert_eq!(m.pwrite(&big, base + 3 * 4096), Some(EIO));
    assert_eq!(m.pread(&mut [], base), Some(0));
    // Read-only and write-only opens
    let ro = open_proc_mem(2091, true, false).unwrap();
    assert_eq!(ro.pwrite(b"x", base), Some(EBADF));
    assert_eq!(ro.write(b"x"), EBADF);
    let wo = open_proc_mem(2091, false, true).unwrap();
    assert_eq!(wo.pread(&mut two, base), Some(EBADF));
    assert_eq!(wo.read(&mut two), EBADF);
    // File properties
    assert_eq!(m.path(), "/proc/2091/mem");
    assert_eq!(m.poll_events(), 5);
    assert_eq!(m.rdev(), 0);
    assert!(!m.nonblock());
    m.set_nonblock(true);
    let st = m.stat();
    assert_eq!((st.st_mode, st.st_ino, st.st_nlink), (0o100600, 2091 << 8 | 0x6d, 1));
    let mut ws = crate::task::wait::WaitSet::new();
    m.add_wait_queues(&mut ws);
    // After an exec (a new address space) it follows, if still allowed
    let mm2 = give_mm(2091, base, 1);
    assert_eq!(m.pread(&mut two, base), Some(2));
    assert_eq!(two, [0, 0], "the new, empty memory");
    // ... but not once the process belongs to someone else (a set-user-ID exec)
    fake::task(2091, |t| {
        t.uid = 0;
        t.euid = 0;
        t.suid = 0;
    });
    let _mm3 = give_mm(2091, base, 1);
    assert_eq!(m.pread(&mut two, base), Some(0));
    drop(mm2);
    // The process is gone: nothing to read
    fake::task(2091, |t| t.state = TaskState::Dead);
    assert_eq!(m.pread(&mut two, base), Some(0));
}

#[test]
fn register_frames_of_traps_and_signals() {
    let _g = setup();
    spawn(2095, 1);
    run(2095);
    fake::task(2095, |t| t.fs_base = 0x3000);
    let mut u = UserRegs { rax: 1, rcx: 2, r11: 3, rip: 0x1000, rsp: 0x2000, rflags: 0x202, ..Default::default() };
    let r = UserFrame::regs(&u, 9);
    assert_eq!((r[10], r[11], r[6], r[15], r[16], r[19], r[21]), (1, 2, 3, 9, 0x1000, 0x2000, 0x3000));
    let mut n = r;
    n[0] = 15;
    n[6] = 33;
    n[11] = 22;
    n[16] = 0x5000;
    n[21] = 0x3000; // unchanged fs_base: no MSR write
    UserFrame::apply(&mut u, &n);
    assert_eq!((u.r15, u.r11, u.rcx, u.rip), (15, 33, 22, 0x5000));
    UserFrame::set_tf(&mut u, true);
    assert_eq!(u.rflags & 0x100, 0x100);
    UserFrame::set_tf(&mut u, false);
    assert_eq!(u.rflags & 0x100, 0);
    let mut e = ExceptionContext { rax: 4, rcx: 5, r11: 6, rip: 0x1100, rsp: 0x2100, rflags: 0x202, ..Default::default() };
    let r = UserFrame::regs(&e, 10);
    assert_eq!((r[10], r[11], r[6], r[15], r[16], r[19]), (4, 5, 6, 10, 0x1100, 0x2100));
    let mut n = r;
    n[16] = 0xffff_8000_0000_0000; // non-canonical: kept
    n[21] = 0xffff_8000_0000_0000; // kernel fs_base: refused
    n[5] = 55;
    UserFrame::apply(&mut e, &n);
    assert_eq!((e.rip, e.rbx), (0x1100, 55));
    assert_eq!(fake::task(2095, |t| t.fs_base), Some(0x3000));
    UserFrame::set_tf(&mut e, true);
    assert_eq!(e.rflags & 0x100, 0x100);
    UserFrame::set_tf(&mut e, false);
    let mut s = frame();
    UserFrame::set_tf(&mut s, true);
    assert_eq!(s.rflags & 0x100, 0x100);
}
