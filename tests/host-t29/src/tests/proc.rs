//! `src/compat/linux/proc.rs`: the process table (registration, exit, zombies, reparenting,
//! groups and sessions), signal sending and permission rules, dispositions and masks,
//! delivery (signal frames, restarts, stops, traps), `rt_sigreturn`, and `wait4`/`waitid`.

use super::common::*;
use crate::arch::idt::{ExceptionContext, FpuState};
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::proc::*;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const ECHILD: i64 = -10;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;
const SIGRT: u32 = 34;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const SA_NOCLDSTOP: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

fn with_proc<R>(pid: u64, f: impl FnOnce(&mut Process) -> R) -> R {
    f(PROCS.lock().get_mut(&pid).expect("process"))
}

fn action(handler: u64, flags: u64, mask: u64) -> SigAction {
    SigAction { handler, flags, restorer: 0xdead_0000, mask }
}

fn set(sig: u32, a: SigAction) {
    set_action(sig, Some(a)).unwrap();
}

/// A user stack in host memory: (buffer, top).
fn stack() -> (Vec<u8>, u64) {
    let v = vec![0u8; 16 * 1024];
    let top = (v.as_ptr() as u64 + v.len() as u64 - 256) & !15;
    (v, top)
}

fn rd(addr: u64) -> u64 {
    unsafe { core::ptr::read_unaligned(addr as *const u64) }
}

// ------------------------------------------------------------- table

#[test]
fn registration_inherits_from_the_parent() {
    let _g = setup();
    spawn(3000, 0);
    with_proc(3000, |p| {
        assert_eq!((p.pid, p.ppid, p.pgid, p.sid), (3000, 0, 3000, 3000), "no parent: its own session");
        p.groups = vec![4, 5];
        p.oom_score_adj = 100;
        p.personality = 8;
        p.abac = 3;
        p.cgroup = Some("/user.slice".into());
        p.actions[SIGUSR1 as usize] = action(0x1000, 0, 0);
    });
    spawn(3001, 3000);
    with_proc(3001, |p| {
        assert_eq!((p.ppid, p.pgid, p.sid), (3000, 3000, 3000));
        assert_eq!((p.groups.clone(), p.oom_score_adj, p.personality, p.abac), (vec![4, 5], 100, 8, 3));
        assert_eq!(p.cgroup.as_deref(), Some("/user.slice"));
        assert_eq!(p.actions[SIGUSR1 as usize].handler, 0x1000);
        assert_eq!(p.threads_alive(), 1);
        assert_eq!(p.thread_ids(), vec![3001]);
    });
    add_thread(3001, 3002);
    assert_eq!(thread_ids_of(3001), vec![3001, 3002]);
    assert_eq!(thread_ids_of(4242), vec![4242], "unknown: the pid itself");
    set_fs_peer(3001, 3000);
    assert_eq!(with_proc(3001, |p| p.fs_peer), 3000);
    set_fs_peer(4242, 1); // nothing to update
    register_thread(4242, 1, 1);
    assert!(process_exists(3001) && !process_exists(4242));
    assert_eq!(process_count(), 2);
    assert_eq!(session_of(3001), Some((3000, 3000)));
    assert_eq!(session_of(4242), None);
    assert_eq!(tgid_of(3002), Some(3001));
    assert_eq!(tgid_of(4242), None);
    assert_eq!(parent_of(3001), 3000);
    // Access-control subject
    assert_eq!(abac_subject(3001), 3);
    assert!(set_abac_subject(3001, 9));
    assert_eq!(abac_subject(3001), 9);
    assert!(!set_abac_subject(4242, 1));
    // Groups
    run(3001);
    assert_eq!(supplementary_groups(), vec![4, 5]);
    assert!(in_supplementary_groups(5) && !in_supplementary_groups(6));
    assert!(!is_pid_ns_init(3001));
    assert!(!vfork_released(3001));
    assert!(vfork_released(4242));
}



#[test]
fn getppid_and_visible_pids_respect_pid_namespaces() {
    let _g = setup();
    spawn(3030, 0);
    spawn(3031, 3030);
    run(3031);
    assert_eq!(getppid(), 3030);
    assert_eq!(visible_pids(), vec![3030, 3031]);
    // 3032 is the init of a new PID namespace (a child of 3031): its parent is invisible
    run(3031);
    assert_eq!(linux::ns::sys_unshare(linux::ns::CLONE_NEWPID), 0);
    spawn(3032, 3031);
    spawn(3033, 3032);
    run(3032);
    assert_eq!(getppid(), 0);
    assert!(is_pid_ns_init(3032));
    assert_eq!(visible_pids(), vec![1, 3033]);
    run(3033);
    assert_eq!(getppid(), 1, "its parent, the init, is 1 in the namespace");
    fake::switch_to(0);
    assert_eq!(getppid(), 1, "no process: 1");
}

#[test]
fn cpu_times_include_exited_threads_and_children() {
    let _g = setup();
    spawn(3040, 0);
    fake::task(3040, |t| {
        t.ticks_run = 300;
        t.ticks_sys = 100;
    });
    with_proc(3040, |p| {
        p.dead_ticks = (50, 20);
        p.child_ticks = (40, 10);
    });
    assert_eq!(cpu_times(3040), (230, 120, 30, 10));
    assert_eq!(to_clock_ticks(1000), 100);
}

#[test]
fn thread_exit_makes_a_zombie_and_tells_the_parent() {
    let _g = setup();
    spawn(3050, 0);
    spawn(3051, 3050);
    add_thread(3051, 3052);
    // One of two threads: still alive
    thread_exited(3051, 3052, 10, 4, (1000, 1000));
    assert!(!with_proc(3051, |p| p.zombie));
    assert_eq!(with_proc(3051, |p| p.dead_ticks), (10, 4));
    set_exit_status(3051, wait_status_exit(3));
    set_exit_status(3051, wait_status_exit(9)); // the first status stays
    thread_exited(3051, 3051, 5, 1, (1000, 1000));
    with_proc(3051, |p| {
        assert!(p.zombie && p.vfork_released);
        assert_eq!(p.exit_status, Some(3 << 8));
        assert_eq!(p.exit_cred, (1000, 1000));
    });
    assert!(has_exited(3051) && has_exited_locked(3051) && has_exited(4242));
    assert!(!has_exited(3050));
    // The parent got SIGCHLD with the details (CLD_EXITED, pid, status 3)
    assert_eq!(with_proc(3050, |p| p.pending & bit(SIGCHLD)), bit(SIGCHLD));
    assert_eq!(sigchld_details(3050), (1, 3051, 3));
    run(3050);
    let t = take_signal_info(bit(SIGCHLD)).unwrap();
    assert_eq!((t.signo, t.code, t.pid, t.value), (SIGCHLD, 1, 3051, 3));
    for c in ["lx::note(", "locks::process_exited(3051", "misc::forget_process(3051", "ptimer::forget_process(3051", "aio::forget_process(3051", "sysv::forget_process(3051,true"] {
        assert!(fake::called(c), "{c}");
    }
    // Unknown processes are ignored
    thread_exited(4242, 4242, 0, 0, (0, 0));
}

#[test]
fn exit_status_kinds_reach_the_parent() {
    let _g = setup();
    spawn(3055, 0);
    for (pid, status, code, value) in [(3056u64, 9, 2, 9), (3057, 11 | 0x80, 3, 11)] {
        spawn(pid, 3055);
        set_exit_status(pid, status);
        thread_exited(pid, pid, 0, 0, (0, 0));
        let t = {
            run(3055);
            take_signal_info(bit(SIGCHLD)).unwrap()
        };
        assert_eq!((t.code, t.pid, t.value as i32), (code, pid as u32, value));
        assert_eq!(sigchld_details(3055).0, code);
        assert_eq!(take_status(pid), Some(status), "a zombie is reaped by its pid");
        assert!(!process_exists(pid));
    }
    assert_eq!(sigchld_details(3055), (0, 0, 0));
}

#[test]
fn orphans_autoreap_and_the_shell() {
    let _g = setup();
    // A parent ignoring SIGCHLD: no zombie
    spawn(3060, 0);
    run(3060);
    set(SIGCHLD, action(1, 0, 0));
    spawn(3061, 3060);
    thread_exited(3061, 3061, 0, 0, (0, 0));
    assert!(!process_exists(3061));
    // SA_NOCLDWAIT: SIGCHLD but no zombie
    set(SIGCHLD, action(0x5000, SA_NOCLDWAIT, 0));
    spawn(3062, 3060);
    thread_exited(3062, 3062, 0, 0, (0, 0));
    assert!(!process_exists(3062));
    assert_ne!(with_proc(3060, |p| p.pending) & bit(SIGCHLD), 0);
    // The shell's child (ppid 0) stays for take_status
    spawn(3063, 0);
    set_exit_status(3063, 7 << 8);
    assert_eq!(take_status(3063), None, "not exited yet");
    thread_exited(3063, 3063, 0, 0, (0, 0));
    assert_eq!(take_status(3063), Some(7 << 8));
    assert!(!process_exists(3063));
    // A parent that is gone (not a Linux process): the zombie is dropped
    spawn(3064, 4242);
    thread_exited(3064, 3064, 0, 0, (0, 0));
    assert!(!process_exists(3064));
    // Orphans go to init; zombie orphans are reaped
    set(SIGCHLD, action(0, 0, 0));
    spawn(3065, 3060);
    spawn(3066, 3060);
    with_proc(3066, |p| p.zombie = true);
    let epoch = linux::ident_epoch();
    thread_exited(3060, 3060, 0, 0, (0, 0));
    assert_eq!(with_proc(3065, |p| p.ppid), 1);
    assert!(!process_exists(3066));
    assert!(linux::ident_epoch() > epoch, "getppid's cached answers are stale");
}

#[test]
fn a_pid_namespace_dies_with_its_init() {
    let _g = setup();
    spawn(3070, 0);
    run(3070);
    assert_eq!(linux::ns::sys_unshare(linux::ns::CLONE_NEWPID), 0);
    spawn(3071, 3070); // init
    spawn(3072, 3071);
    thread_exited(3071, 3071, 0, 0, (0, 0));
    assert_ne!(with_proc(3072, |p| p.pending) & bit(SIGKILL), 0);
    assert!(fake::called("wake_process_deferred(3072)"));
}

#[test]
fn a_tracer_hears_of_a_tracee_exit() {
    let _g = setup();
    spawn(3075, 0);
    spawn(3076, 0);
    add_thread(3076, 3077);
    run(3075);
    assert_eq!(linux::ptrace::sys_ptrace(0x4206, 3077, 0, 1 << 20), 0); // SEIZE, EXITKILL
    thread_exited(3076, 3077, 0, 0, (0, 0));
    assert_ne!(with_proc(3075, |p| p.pending) & bit(SIGCHLD), 0);
    // The tracer exits: its EXITKILL tracee... (3077 is gone; seize the main thread)
    assert_eq!(linux::ptrace::sys_ptrace(0x4206, 3076, 0, 1 << 20), 0);
    thread_exited(3075, 3075, 0, 0, (0, 0));
    assert!(take_signal_info_of(3076, 3076, bit(SIGKILL)).is_some(), "EXITKILL");
}

// ------------------------------------------------------------- sending

#[test]
fn kill_permissions() {
    let _g = setup();
    spawn_as(3100, 0, 1000, 1000);
    spawn_as(3101, 0, 1000, 1000);
    spawn_as(3102, 0, 2000, 2000);
    run(3100);
    assert_eq!(sys_kill(3101, SIGUSR1 as u64), 0);
    assert_ne!(with_proc(3101, |p| p.pending) & bit(SIGUSR1), 0);
    assert_eq!(sys_kill(3102, SIGUSR1 as u64), EPERM);
    assert_eq!(sys_kill(3102, 0), EPERM, "signal 0 is checked too");
    assert_eq!(sys_kill(4242, 0), ESRCH);
    assert_eq!(sys_kill(3101, 65), EINVAL);
    assert_eq!(sys_kill(3100, 0), 0, "itself");
    // The target's saved uid counts
    fake::task(3102, |t| t.suid = 1000);
    assert!(may_signal(3102, SIGUSR1));
    fake::task(3102, |t| t.suid = 2000);
    // CAP_KILL
    fake::task(3100, |t| t.caps.effective = 1 << 5);
    assert!(may_signal(3102, SIGUSR1));
    fake::task(3100, |t| t.caps.effective = 0);
    // SIGCONT within the session
    with_proc(3102, |p| p.sid = 3100);
    with_proc(3100, |p| p.sid = 3100);
    assert!(may_signal(3102, SIGCONT) && !may_signal(3102, SIGUSR1));
    // A zombie keeps its credentials
    with_proc(3102, |p| {
        p.zombie = true;
        p.exit_cred = (1000, 1000);
    });
    fake::task(3102, |t| t.state = TaskState::Dead);
    assert!(may_signal(3102, SIGUSR1));
    assert_eq!(sys_kill(3102, SIGUSR1 as u64), 0, "a zombie: success, nothing happens");
    assert!(may_signal(4242, SIGUSR1), "gone: allowed (ESRCH comes from the caller)");
    // A system service is never signalled
    fake::task(3101, |t| t.service = Some(5));
    assert_eq!(sys_kill(3101, SIGUSR1 as u64), EPERM);
    // No task: the kernel may signal anyone
    fake::switch_to(0);
    assert!(may_signal(3102, SIGKILL));
}

#[test]
fn kill_groups_and_everyone() {
    let _g = setup();
    spawn_as(3110, 0, 1000, 1000);
    spawn_as(3111, 3110, 1000, 1000);
    spawn_as(3112, 3110, 2000, 2000);
    spawn_as(3113, 0, 1000, 1000);
    run(3110);
    // kill(0): our group
    assert_eq!(sys_kill(0, SIGUSR2 as u64), 0, "one member got it");
    assert_ne!(with_proc(3111, |p| p.pending) & bit(SIGUSR2), 0);
    assert_eq!(with_proc(3112, |p| p.pending) & bit(SIGUSR2), 0, "no permission");
    // kill(-pgid)
    assert_eq!(sys_kill(-3113, SIGUSR1 as u64), 0);
    assert_eq!(sys_kill(-4242, SIGUSR1 as u64), ESRCH, "an empty group");
    run(3113);
    with_proc(3113, |p| p.pgid = 3112);
    with_proc(3112, |p| p.pgid = 3112);
    assert_eq!(sys_kill(-3112, SIGUSR1 as u64), 0);
    with_proc(3113, |p| p.pgid = 3113);
    assert_eq!(sys_kill(-3112, SIGUSR1 as u64), EPERM, "the only member refused");
    // kill(-1): everyone but init and the caller, success even if all refused
    assert_eq!(sys_kill(-1, 0), 0);
    // post_group
    assert_eq!(post_group(3110, SIGUSR1), 2, "3112 moved to its own group above");
    assert_eq!(post_group(4242, SIGUSR1), 0);
    // kill(-1) with nobody else around
    PROCS.lock().retain(|&p, _| p == 3113);
    assert_eq!(sys_kill(-1, 0), ESRCH);
}

#[test]
fn tgkill_and_tkill() {
    let _g = setup();
    spawn(3120, 0);
    add_thread(3120, 3121);
    run(3120);
    assert_eq!(sys_tgkill(3120, 3121, SIGUSR1 as u64), 0);
    let t = take_signal_info_of(3121, 3120, bit(SIGUSR1)).unwrap();
    assert_eq!((t.code, t.pid), (-6, 3120), "SI_TKILL from our process");
    assert_eq!(sys_tgkill(3120, 3122, 0), ESRCH);
    assert_eq!(sys_tgkill(0, 3121, 0), EINVAL);
    assert_eq!(sys_tgkill(3120, 0, 0), EINVAL);
    assert_eq!(sys_tgkill(3120, 3121, 99), EINVAL);
    assert_eq!(sys_tkill(3121, SIGUSR2 as u64), 0);
    assert!(take_signal_info_of(3121, 3120, bit(SIGUSR2)).is_some());
    assert_eq!(sys_tkill(4242, 0), ESRCH);
    assert_eq!(sys_tkill(0, 0), EINVAL);
    spawn_as(3123, 0, 1000, 1000);
    run(3123);
    assert_eq!(sys_tgkill(3120, 3121, 0), EPERM);
    fake::task(3120, |t| t.service = Some(1));
    assert_eq!(sys_tgkill(3120, 3121, 0), EPERM);
}

#[test]
fn sigqueueinfo_and_realtime_queues() {
    let _g = setup();
    spawn(3130, 0);
    spawn(3131, 0);
    add_thread(3130, 3132);
    run(3130);
    // siginfo: signo, errno, code (-1: SI_QUEUE), pid|uid, value
    let info = |code: i32, value: u64| [0u64 | 0, code as u32 as u64, 77 | (88 << 32), value];
    assert_eq!(sys_rt_sigqueueinfo(3131, None, 99, 0), EINVAL);
    with_current_mm(|| assert_eq!(sys_rt_sigqueueinfo(3131, None, SIGRT as u64, 0), EFAULT));
    assert_eq!(sys_rt_sigqueueinfo(3131, None, SIGRT as u64, ptr(&info(0, 1))), EPERM, "SI_USER claimed for another process");
    assert_eq!(sys_rt_sigqueueinfo(3131, None, SIGRT as u64, ptr(&info(-6, 1))), EPERM, "SI_TKILL too");
    assert_eq!(sys_rt_sigqueueinfo(4242, None, SIGRT as u64, ptr(&info(-1, 1))), ESRCH);
    assert_eq!(sys_rt_sigqueueinfo(3131, None, 0, ptr(&info(-1, 1))), 0, "signal 0: a check");
    // Three instances of a real-time signal queue up, each with its value
    for v in [10, 20, 30] {
        assert_eq!(sys_rt_sigqueueinfo(3131, None, SIGRT as u64, ptr(&info(-1, v))), 0);
    }
    assert!(signal_queued(3131, None, SIGRT));
    assert!(pending_for(3131, bit(SIGRT)) && !pending_for(3131, bit(SIGUSR1)) && !pending_for(4242, 1));
    for v in [10, 20, 30] {
        let t = take_signal_info_of(3131, 3131, bit(SIGRT)).unwrap();
        assert_eq!((t.code, t.pid, t.uid, t.value), (-1, 77, 88, v));
    }
    assert!(take_signal_info_of(3131, 3131, bit(SIGRT)).is_none());
    assert!(!signal_queued(3131, None, SIGRT));
    // A thread-directed one (rt_tgsigqueueinfo) to ourselves may claim SI_TKILL
    assert_eq!(sys_rt_sigqueueinfo(3130, Some(3132), SIGRT as u64, ptr(&info(-6, 5))), 0);
    assert_eq!(sys_rt_sigqueueinfo(3130, Some(3132), SIGRT as u64, ptr(&info(-6, 6))), 0);
    assert!(signal_queued(3130, Some(3132), SIGRT));
    assert_eq!(take_signal_info_of(3132, 3130, bit(SIGRT)).unwrap().value, 5);
    assert_eq!(take_signal_info_of(3132, 3130, bit(SIGRT)).unwrap().value, 6);
    assert!(!signal_queued(4242, None, SIGRT));
    assert_eq!(sys_rt_sigqueueinfo(3130, Some(4242), SIGRT as u64, ptr(&info(-1, 1))), ESRCH, "no such thread");
    // The queue's limit: EAGAIN
    for _ in 0..4097 {
        let _ = sys_rt_sigqueueinfo(3131, None, SIGRT as u64, ptr(&info(-1, 1)));
    }
    assert_eq!(sys_rt_sigqueueinfo(3131, None, SIGRT as u64, ptr(&info(-1, 1))), EAGAIN);
    // Ignoring the signal drops every queued instance
    run(3131);
    set(SIGRT, action(1, 0, 0));
    assert!(!signal_queued(3131, None, SIGRT));
    assert!(take_signal_info_of(3131, 3131, bit(SIGRT)).is_none());
}


#[test]
fn sigcont_continues_a_stopped_process() {
    let _g = setup();
    spawn(3150, 0);
    spawn(3151, 3150);
    with_proc(3151, |p| {
        p.stopped = true;
        p.stop_sig = SIGSTOP;
    });
    assert!(is_stopped(3151));
    assert!(post_process(3151, SIGSTOP));
    assert!(post_process(3151, SIGCONT));
    with_proc(3151, |p| {
        assert!(!p.stopped);
        assert_eq!(p.pending & bit(SIGSTOP), 0, "SIGCONT discards pending stops");
    });
    // The parent learns (CLD_CONTINUED), and waitpid(WCONTINUED) reports it once
    run(3150);
    assert_eq!(take_signal_info(bit(SIGCHLD)).map(|t| t.code), Some(6));
    let mut st = 0i32;
    assert_eq!(sys_wait4(3151, mptr(&mut st), 8 | 1, 0), 3151);
    assert_eq!(st, 0xffff);
    assert_eq!(sys_wait4(3151, mptr(&mut st), 8 | 1, 0), 0);
    // A stop signal discards a pending SIGCONT
    assert!(post_process(3151, SIGCONT));
    assert!(post_process(3151, SIGTSTP));
    assert_eq!(with_proc(3151, |p| p.pending) & bit(SIGCONT), 0);
    // A parent with SA_NOCLDSTOP hears nothing
    set(SIGCHLD, action(0x6000, SA_NOCLDSTOP, 0));
    with_proc(3151, |p| p.stopped = true);
    post_process(3151, SIGCONT);
    assert!(take_signal_info(bit(SIGCHLD)).is_none());
    assert!(!post_process(4242, SIGUSR1));
}

// ------------------------------------------------------------- dispositions

#[test]
fn sigaction_and_procmask() {
    let _g = setup();
    spawn(3200, 0);
    run(3200);
    let act = [0x4000u64, SA_RESTART, 0xdead, bit(SIGUSR2)];
    let mut old = [9u64; 4];
    assert_eq!(sys_rt_sigaction(SIGUSR1 as u64, ptr(&act), mptr(&mut old), 8), 0);
    assert_eq!(old, [0; 4], "SIG_DFL before");
    assert_eq!(sys_rt_sigaction(SIGUSR1 as u64, 0, mptr(&mut old), 8), 0);
    assert_eq!(old, act);
    assert_eq!(sys_rt_sigaction(SIGUSR1 as u64, ptr(&act), 0, 4), EINVAL, "size");
    assert_eq!(sys_rt_sigaction(0, 0, 0, 8), EINVAL);
    assert_eq!(sys_rt_sigaction(65, 0, 0, 8), EINVAL);
    assert_eq!(sys_rt_sigaction(SIGKILL as u64, ptr(&act), 0, 8), EINVAL);
    assert_eq!(sys_rt_sigaction(SIGSTOP as u64, ptr(&act), 0, 8), EINVAL);
    assert_eq!(sys_rt_sigaction(SIGKILL as u64, 0, mptr(&mut old), 8), 0, "reading SIGKILL's is fine");
    with_current_mm(|| {
        assert_eq!(sys_rt_sigaction(SIGUSR1 as u64, 8, 0, 8), EFAULT);
        assert_eq!(sys_rt_sigaction(SIGUSR1 as u64, 0, 8, 8), EFAULT);
    });
    // Ignoring a signal discards it if pending (also SIG_DFL of a default-ignored one)
    post_process(3200, SIGUSR2);
    post_thread(3200, 3200, SIGUSR2);
    set(SIGUSR2, action(1, 0, 0));
    assert!(!pending_for(3200, bit(SIGUSR2)));
    post_process(3200, SIGWINCH);
    set(SIGWINCH, action(0, 0, 0));
    assert!(!pending_for(3200, bit(SIGWINCH)));
    assert!(ignores_or_blocks(SIGUSR2) && !ignores_or_blocks(SIGUSR1));
    fake::switch_to(0);
    assert_eq!(set_action(SIGUSR1, None).err(), Some(ESRCH));
    assert!(ignores_or_blocks(SIGUSR1), "no process");
    run(3200);
    // Masks: block, unblock, set; SIGKILL and SIGSTOP never blocked
    let m = bit(SIGUSR1) | bit(SIGKILL);
    let mut oset = 0u64;
    assert_eq!(sys_rt_sigprocmask(0, ptr(&m), mptr(&mut oset), 8), 0);
    assert_eq!(oset, 0);
    assert!(ignores_or_blocks(SIGUSR1));
    assert_eq!(sys_rt_sigprocmask(2, 0, mptr(&mut oset), 8), 0);
    assert_eq!(oset, bit(SIGUSR1));
    let u = bit(SIGUSR1);
    assert_eq!(sys_rt_sigprocmask(1, ptr(&u), 0, 8), 0);
    assert_eq!(sys_rt_sigprocmask(2, ptr(&!0u64), 0, 8), 0);
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut oset), 8), 0);
    assert_eq!(oset, !0 & !(bit(SIGKILL) | bit(SIGSTOP)));
    assert_eq!(sys_rt_sigprocmask(5, ptr(&u), 0, 8), EINVAL);
    assert_eq!(sys_rt_sigprocmask(0, 0, 0, 4), EINVAL);
    with_current_mm(|| {
        assert_eq!(sys_rt_sigprocmask(0, 8, 0, 8), EFAULT);
        assert_eq!(sys_rt_sigprocmask(0, 0, 8, 8), EFAULT);
    });
    // Personalities' mask helpers
    set_current_mask(!0);
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut oset), 8), 0);
    assert_eq!(oset & bit(SIGKILL), 0);
    let old = temp_mask(0).unwrap();
    assert_eq!(old, oset);
    end_temp_mask(old);
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut oset), 8), 0);
    assert_eq!(oset, old, "nothing to deliver: the old mask comes back at once");
    fake::switch_to(0);
    assert_eq!(temp_mask(0), None);
    end_temp_mask(0);
    assert_eq!(sys_rt_sigprocmask(0, 0, 0, 8), 0, "no thread: nothing to do");
}

#[test]
fn alternate_signal_stacks() {
    let _g = setup();
    spawn(3210, 0);
    run(3210);
    let mut old = [7u64; 3];
    assert_eq!(sys_sigaltstack(0, mptr(&mut old), 0), 0);
    assert_eq!((old[0], old[1] as u32, old[2]), (0, 2, 0), "SS_DISABLE");
    let ss = [0x10_0000u64, 0, 0x8000];
    assert_eq!(sys_sigaltstack(ptr(&ss), 0, 0), 0);
    assert_eq!(alt_stack(), (0x10_0000, 0x8000, true));
    assert_eq!(sys_sigaltstack(0, mptr(&mut old), 0x10_4000), 0);
    assert_eq!(old[1] as u32, 1, "SS_ONSTACK while running on it");
    assert_eq!(sys_sigaltstack(ptr(&ss), 0, 0x10_4000), EPERM, "the stack in use");
    assert_eq!(sys_sigaltstack(ptr(&[0u64, 0, 100]), 0, 0), ENOMEM, "below MINSIGSTKSZ");
    assert_eq!(sys_sigaltstack(ptr(&[0u64, 4, 0x8000]), 0, 0), EINVAL, "unknown flag");
    assert_eq!(sys_sigaltstack(ptr(&[0u64, (1u64 << 31) | 2, 0]), 0, 0), 0, "SS_DISABLE | SS_AUTODISARM");
    assert_eq!(alt_stack(), (0, 0, false));
    with_current_mm(|| {
        assert_eq!(sys_sigaltstack(8, 0, 0), EFAULT);
        assert_eq!(sys_sigaltstack(0, 8, 0), EFAULT);
    });
    fake::switch_to(0);
    assert_eq!(sys_sigaltstack(0, 0, 0), EINVAL);
    assert_eq!(alt_stack(), (0, 0, false));
}

#[test]
fn pending_suspend_and_timedwait() {
    let _g = setup();
    spawn(3220, 0);
    run(3220);
    let mask = bit(SIGUSR1);
    assert_eq!(sys_rt_sigprocmask(0, ptr(&mask), 0, 8), 0);
    post_process(3220, SIGUSR1);
    let mut p = 0u64;
    assert_eq!(sys_rt_sigpending(mptr(&mut p), 8), 0);
    assert_eq!(p, bit(SIGUSR1));
    assert_eq!(sys_rt_sigpending(mptr(&mut p), 4), EINVAL);
    with_current_mm(|| assert_eq!(sys_rt_sigpending(8, 8), EFAULT));
    // sigtimedwait takes the blocked SIGUSR1 with its siginfo
    let set_ = bit(SIGUSR1);
    let mut info = [0u8; 128];
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), mptr(&mut info), 0, 8), SIGUSR1 as i64);
    assert_eq!(info[0], SIGUSR1 as u8);
    // Nothing pending: the timeout (EAGAIN)
    let ts = [0u64, 5_000_000];
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), 0, ptr(&ts), 8), EAGAIN);
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), 0, ptr(&[0u64, 1_000_000_000]), 8), EINVAL);
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), 0, ptr(&[u64::MAX, 0]), 8), EINVAL);
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), 0, 0, 4), EINVAL);
    with_current_mm(|| {
        assert_eq!(sys_rt_sigtimedwait(8, 0, 0, 8), EFAULT);
    });
    let mut info_ok = [0u8; 128];
    with_current_mm(|| assert_eq!(sys_rt_sigtimedwait(8, mptr(&mut info_ok), 8, 8), EFAULT));
    // Another (unblocked) signal arrives while waiting: EINTR
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        post_process(3220, SIGUSR2);
    })));
    assert_eq!(sys_rt_sigtimedwait(ptr(&set_), 0, 0, 8), EINTR);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    with_proc(3220, |p| p.pending = 0);
    // sigsuspend: the temporary mask, until a signal arrives; the old mask is restored
    // after the handler (kept for delivery)
    set(SIGUSR2, action(0x7000, 0, 0));
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        post_process(3220, SIGUSR2);
    })));
    let tmp = 0u64;
    assert_eq!(sys_rt_sigsuspend(ptr(&tmp), 8), EINTR);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    assert_eq!(sys_rt_sigsuspend(ptr(&tmp), 4), EINVAL);
    with_current_mm(|| assert_eq!(sys_rt_sigsuspend(8, 8), EFAULT));
    // Delivery of SIGUSR2 puts the pre-suspend mask (SIGUSR1 blocked) back after the handler
    let (_buf, top) = stack();
    let mut f = SyscallFrame { rax: EINTR as u64, rsp: top, rip: 0x40_0000, ..Default::default() };
    let mut fpu = FpuState::new();
    deliver_on_syscall_return(&mut f, &mut fpu, 130);
    assert_eq!(f.rip, 0x7000);
    let uc = f.rdx;
    assert_eq!(rd(uc + 296), bit(SIGUSR1), "uc_sigmask: the mask from before sigsuspend");
    fake::switch_to(0);
    assert_eq!(sys_rt_sigsuspend(ptr(&tmp), 8), EINTR, "no thread");
}

#[test]
fn oom_score_files() {
    let _g = setup();
    spawn_as(3230, 0, 1000, 1000);
    spawn_as(3231, 0, 2000, 2000);
    run(3230);
    assert_eq!(oom_file_text(3230, "oom_score_adj").as_deref(), Some("0\n"));
    assert_eq!(write_oom_score_adj(3230, b"500\n"), 4);
    assert_eq!(oom_file_text(3230, "oom_score").as_deref(), Some("500\n"));
    assert_eq!(write_oom_score_adj(3230, b"-5"), EACCES, "below 0 needs CAP_SYS_RESOURCE");
    assert_eq!(write_oom_score_adj(3230, b"2000"), EINVAL);
    assert_eq!(write_oom_score_adj(3230, b"x"), EINVAL);
    assert_eq!(write_oom_score_adj(3231, b"1"), EPERM, "someone else's");
    assert_eq!(write_oom_score_adj(4242, b"1"), ESRCH);
    fake::task(3230, |t| t.caps.effective = 1 << 24);
    assert_eq!(write_oom_score_adj(3230, b"-100"), 4);
    assert_eq!(oom_file_text(3230, "oom_score").as_deref(), Some("0\n"));
    assert_eq!(oom_file_text(3230, "oom_score_adj").as_deref(), Some("-100\n"));
    with_proc(3230, |p| p.zombie = true);
    assert_eq!(oom_file_text(3230, "oom_score_adj"), None);
    // The task is there but the process table entry is gone
    PROCS.lock().remove(&3231);
    fake::task(3230, |t| t.euid = 0);
    assert_eq!(write_oom_score_adj(3231, b"1"), ESRCH);
}

// ------------------------------------------------------------- delivery

#[test]
fn handlers_get_a_signal_frame() {
    let _g = setup();
    spawn(3300, 0);
    run(3300);
    set(SIGUSR1, action(0x40_1000, SA_RESTART, bit(SIGUSR2)));
    let (_buf, top) = stack();
    // sent by kill: si_pid / si_uid in the frame
    assert_eq!(sys_kill(3300, SIGUSR1 as u64), 0);
    let mut f = SyscallFrame { rax: ERESTARTSYS as u64, rsp: top, rip: 0x40_2002, rflags: 0x646, rdi: 1, ..Default::default() };
    let mut fpu = FpuState::new();
    fpu.0[100] = 0x5a;
    deliver_on_syscall_return(&mut f, &mut fpu, 35);
    // The handler runs with sig, &siginfo, &ucontext; SA_RESTART restarted the call
    assert_eq!((f.rip, f.rdi), (0x40_1000, SIGUSR1 as u64));
    let (frame, info, uc) = (f.rsp, f.rsi, f.rdx);
    assert_eq!(rd(frame), 0xdead_0000, "pretcode: the restorer");
    assert_eq!((info, uc), (uc + 304, frame + 8));
    assert_eq!(rd(info) as u32, SIGUSR1);
    assert_eq!(unsafe { *((info + 16) as *const u32) }, 3300, "si_pid");
    let mc = uc + 40;
    assert_eq!(rd(mc + 16 * 8), 0x40_2000, "saved rip: back over the syscall (restart)");
    assert_eq!(rd(mc + 13 * 8), 35, "saved rax: the call number");
    assert_eq!(rd(mc + 8 * 8), 1, "saved rdi");
    assert_eq!(f.rflags & 0x400, 0, "DF cleared");
    assert!(take_restart_flag(), "a sleep's restart is marked");
    let fpstate = rd(mc + 184);
    assert_eq!(unsafe { *((fpstate + 100) as *const u8) }, 0x5a, "the FPU area");
    // While the handler runs: SIGUSR1 itself and SIGUSR2 (sa_mask) are blocked
    let mut m = 0u64;
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut m), 8), 0);
    assert_eq!(m, bit(SIGUSR1) | bit(SIGUSR2));
    // rt_sigreturn restores everything (rsp at the ucontext after the handler's ret)
    let ret = SyscallFrame { rsp: uc, ..Default::default() };
    let (regs, fpu2, cs) = restore_sigframe(&ret);
    assert_eq!((regs.rip, regs.rax, regs.rdi, cs), (0x40_2000, 35, 1, 0x2b));
    assert_eq!(regs.rflags & 0x202, 0x202);
    assert_eq!(fpu2.0[100], 0x5a);
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut m), 8), 0);
    assert_eq!(m, 0, "the mask from before the handler");
}

#[test]
fn delivery_variants() {
    let _g = setup();
    spawn(3310, 0);
    run(3310);
    let (_buf, top) = stack();
    let mut fpu = FpuState::new();
    // Without SA_RESTART an interrupted call fails with EINTR; SA_NODEFER and
    // SA_RESETHAND; an alternate stack with SA_ONSTACK
    let alt = vec![0u8; 8192];
    let alt_sp = alt.as_ptr() as u64;
    let ss = [alt_sp, 0, 8192];
    assert_eq!(sys_sigaltstack(ptr(&ss), 0, 0), 0);
    set(SIGUSR1, action(0x40_1000, SA_NODEFER | SA_RESETHAND | SA_ONSTACK, 0));
    post_process(3310, SIGUSR1);
    let mut f = SyscallFrame { rax: ERESTARTSYS as u64, rsp: top, rip: 0x40_2002, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 7);
    assert!(f.rsp > alt_sp && f.rsp < alt_sp + 8192, "on the alternate stack");
    let mc = f.rdx + 40;
    assert_eq!(rd(mc + 13 * 8) as i64, EINTR);
    assert_eq!(rd(mc + 16 * 8), 0x40_2002);
    let mut m = 0u64;
    assert_eq!(sys_rt_sigprocmask(0, 0, mptr(&mut m), 8), 0);
    assert_eq!(m, 0, "SA_NODEFER: not blocked");
    assert_eq!(set_action(SIGUSR1, None).unwrap().handler, 0, "SA_RESETHAND");
    // An interrupted call with nothing to deliver restarts transparently
    let mut f = SyscallFrame { rax: ERESTART_RESTARTBLOCK as u64, rsp: top, rip: 0x40_2002, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 35);
    assert_eq!((f.rip, f.rax), (0x40_2000, 35));
    assert!(take_restart_flag());
    // ERESTART_RESTARTBLOCK with a handler: EINTR
    set(SIGUSR2, action(0x40_1000, SA_RESTART, 0));
    post_process(3310, SIGUSR2);
    let mut f = SyscallFrame { rax: ERESTART_RESTARTBLOCK as u64, rsp: top, rip: 0x40_2002, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 35);
    assert_eq!(rd(f.rdx + 40 + 13 * 8) as i64, EINTR);
    // Ignored and default-ignored signals are skipped
    set(SIGUSR2, action(1, 0, 0));
    post_thread(3310, 3310, SIGUSR2);
    post_process(3310, SIGCHLD);
    let mut f = SyscallFrame { rax: 0, rsp: top, rip: 0x40_2002, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    assert_eq!(f.rip, 0x40_2002, "nothing delivered");
    // A frame that cannot be written: SIGSEGV kills the process
    set(SIGUSR1, action(0x40_1000, 0, 0));
    post_process(3310, SIGUSR1);
    let mut f = SyscallFrame { rsp: 0x1000, rip: 0x40_2002, ..Default::default() };
    with_current_mm(|| {
        panics_with("task::exit_group", || deliver_on_syscall_return(&mut f, &mut fpu, 39));
    });
    assert_eq!(with_proc(3310, |p| p.exit_status), Some(11 | 0x80));
}

#[test]
fn default_actions_terminate_or_stop() {
    let _g = setup();
    spawn(3320, 0);
    spawn(3321, 3320);
    run(3321);
    let mut fpu = FpuState::new();
    // SIGTERM: killed, no core
    post_process(3321, SIGTERM);
    let mut f = SyscallFrame::default();
    panics_with("task::exit_group", || deliver_on_syscall_return(&mut f, &mut fpu, 39));
    assert_eq!(with_proc(3321, |p| p.exit_status), Some(SIGTERM as i32));
    // SIGQUIT: core dumped, logged
    with_proc(3321, |p| p.exit_status = None);
    post_process(3321, SIGQUIT);
    panics_with("task::exit_group", || deliver_on_syscall_return(&mut f, &mut fpu, 39));
    assert_eq!(with_proc(3321, |p| p.exit_status), Some(SIGQUIT as i32 | 0x80));
    // (wave11 GD: with the thread's name and executable)
    assert!(fake::called("log:[linux] pid 3321 ("));
    assert!(fake::CALLS.with_borrow(|v| v.iter().any(|c| c.starts_with("log:[linux] pid 3321 (") && c.trim_end().ends_with("killed by signal 3 (core dumped)"))));
    // A handler for SIGKILL never runs (it cannot be set; forced here): still killed
    with_proc(3321, |p| {
        p.exit_status = None;
        p.actions[SIGKILL as usize] = action(0x40_1000, 0, 0);
    });
    post_process(3321, SIGKILL);
    panics_with("task::exit_group", || deliver_on_syscall_return(&mut f, &mut fpu, 39));
    // SIGTSTP: stopped until SIGCONT; the parent hears CLD_STOPPED
    with_proc(3321, |p| p.actions[SIGKILL as usize] = SigAction::default());
    post_process(3321, SIGTSTP);
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        assert!(is_stopped(3321));
        post_process(3321, SIGCONT);
    })));
    TRACE.store(true);
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    TRACE.store(false);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    assert!(!is_stopped(3321));
    assert!(fake::called("log:[signal] pid 3321 stopped by signal 20"));
    run(3320);
    let mut st = 0i32;
    // (the continue was reported after the stop; WUNTRACED found nothing left)
    assert_eq!(sys_wait4(3321, mptr(&mut st), 2 | 1, 0), 0);
    // A handled SIGSTOP still stops (forced handler)
    run(3321);
    with_proc(3321, |p| p.actions[SIGSTOP as usize] = action(0x40_1000, 0, 0));
    post_process(3321, SIGSTOP);
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        post_process(3321, SIGKILL);
    })));
    panics_with("task::exit_group", || deliver_on_syscall_return(&mut f, &mut fpu, 39));
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
}

/// The system call tracing switch (mod.rs) as an atomic the tests flip.
struct Trace;
static TRACE: Trace = Trace;
impl Trace {
    fn store(&self, on: bool) {
        linux::TRACE_SYSCALLS.store(on, core::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn stopped_process_waits_and_wait4_reports_the_stop() {
    let _g = setup();
    spawn(3330, 0);
    spawn(3331, 3330);
    run(3331);
    post_process(3331, SIGSTOP);
    let mut fpu = FpuState::new();
    let mut f = SyscallFrame::default();
    // While stopped, the parent's wait sees it (WUNTRACED), once
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(|| {
            fake::switch_to(3330);
            let mut st = 0i32;
            let r = sys_wait4(-1, mptr(&mut st), 2 | 1, 0);
            if r == 3331 {
                assert_eq!(st, 0x7f | (SIGSTOP as i32) << 8);
                post_process(3331, SIGCONT);
            }
            fake::switch_to(3331);
        }))
    });
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    assert!(!is_stopped(3331));
}

#[test]
fn traps_faults_and_seccomp_sigsys() {
    let _g = setup();
    spawn(3340, 0);
    run(3340);
    let (_buf, top) = stack();
    let mut fpu = FpuState::new();
    // Not from user mode, or nothing pending: nothing happens
    let mut ctx = ExceptionContext { cs: 0x8, rsp: top, rip: 0x40_1000, ..Default::default() };
    deliver_on_trap_return(&mut ctx, &mut fpu);
    ctx.cs = 0x2b;
    deliver_on_trap_return(&mut ctx, &mut fpu);
    deliver_on_trap_return(&mut ctx, std::ptr::null_mut());
    assert_eq!(ctx.rip, 0x40_1000);
    // A handled SIGSEGV from a page fault: si_code, si_addr (CR2), trapno and err in the frame
    set(SIGSEGV, action(0x40_5000, 0, 0));
    x86_64::CR2.store(0xbad0, core::sync::atomic::Ordering::Relaxed);
    let mut ctx = ExceptionContext { cs: 0x23, ss: 0x2b, rsp: top, rip: 0x40_1000, vector: 14, error_code: 5, rflags: 0x202, ..Default::default() };
    force_fault_signal(&mut ctx, &mut fpu, SIGSEGV);
    assert_eq!((ctx.rip, ctx.cs, ctx.ss, ctx.rdi), (0x40_5000, 0x2b, 0x1b, SIGSEGV as u64));
    let (info, uc) = (ctx.rsi, ctx.rdx);
    assert_eq!(unsafe { *((info + 8) as *const i32) }, 2, "SEGV_ACCERR");
    assert_eq!(rd(info + 16), 0xbad0, "si_addr");
    let mc = uc + 40;
    assert_eq!((rd(mc + 152), rd(mc + 160), rd(mc + 176)), (5, 14, 0xbad0), "err, trapno, cr2");
    assert_eq!(unsafe { *((mc + 144) as *const u16) }, 0x23, "the interrupted cs (32-bit code)");
    // Returning from it with the 32-bit cs: the pointers are cut to 32 bits
    unsafe { *((mc + 16 * 8) as *mut u64) = 0x1_2345_6789 };
    let (regs, _, cs) = restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    assert_eq!((cs, regs.rip), (0x23, 0x2345_6789));
    // The other fault kinds' codes
    let cases: [(u32, u64, u64, i32); 6] = [
        (SIGSEGV, 14, 4, 1),    // SEGV_MAPERR
        (SIGBUS, 14, 0, 2),     // BUS_ADRERR
        (SIGILL, 6, 0, 2),      // ILL_ILLOPN
        (SIGFPE, 0, 0, 1),      // FPE_INTDIV
        (SIGTRAP, 3, 0, 0x80),  // int3: SI_KERNEL
        (SIGTRAP, 1, 0, 2),     // single step: TRAP_TRACE
    ];
    for (sig, vector, err, code) in cases {
        set(sig, action(0x40_6000, SA_NODEFER, 0));
        let mut ctx = ExceptionContext { cs: 0x2b, rsp: top, rip: 0x40_1000, vector, error_code: err, ..Default::default() };
        force_fault_signal(&mut ctx, &mut fpu, sig);
        assert_eq!(ctx.rip, 0x40_6000, "signal {sig}");
        assert_eq!(unsafe { *((ctx.rsi + 8) as *const i32) }, code, "signal {sig} vector {vector}");
        let mut m = 0u64;
        sys_rt_sigprocmask(2, ptr(&m), mptr(&mut m), 8);
    }
    // A hardware breakpoint (#DB with DR6 bit 1): TRAP_HWBKPT at DR1's address
    fake::task(3340, |t| t.debugregs[1] = 0x40_7777);
    let mut ctx = ExceptionContext { cs: 0x2b, rsp: top, rip: 0x40_1000, vector: 1, error_code: 2, ..Default::default() };
    force_fault_signal(&mut ctx, &mut fpu, SIGTRAP);
    assert_eq!(unsafe { *((ctx.rsi + 8) as *const i32) }, 4);
    assert_eq!(rd(ctx.rsi + 16), 0x40_7777);
    // seccomp's SIGSYS: forced (unblocked, an ignored disposition reset), its siginfo names
    // the call
    let all = !0u64;
    sys_rt_sigprocmask(2, ptr(&all), 0, 8);
    set(SIGSYS, action(1, 0, 0));
    force_seccomp_sigsys(59, 0x40_1234, 7);
    assert_eq!(set_action(SIGSYS, None).unwrap().handler, 0, "reset to the default");
    set(SIGSYS, action(0x40_8000, 0, 0));
    let mut f = SyscallFrame { rsp: top, rip: 0x40_1236, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 59);
    let info = f.rsi;
    assert_eq!(unsafe { (*((info + 4) as *const i32), *((info + 8) as *const i32), *((info + 24) as *const i32)) }, (7, 1, 59));
    assert_eq!(rd(info + 16), 0x40_1234, "si_call_addr");
    assert_eq!(unsafe { *((info + 28) as *const u32) }, 0xc000_003e, "si_arch");
}

#[test]
fn unhandled_faults_kill_with_a_report() {
    let _g = setup();
    spawn(3345, 0);
    run(3345);
    let (buf, top) = stack();
    let code = [0x0fu8, 0x0b, 0, 0, 0, 0, 0, 0];
    let mut fpu = FpuState::new();
    let mut ctx = ExceptionContext { cs: 0x2b, rsp: top, rip: code.as_ptr() as u64, vector: 6, rax: 0x11, ..Default::default() };
    panics_with("task::exit_group", || force_fault_signal(&mut ctx, &mut fpu, SIGILL));
    assert_eq!(with_proc(3345, |p| p.exit_status), Some(SIGILL as i32 | 0x80));
    assert!(fake::called("log:[linux] pid 3345 () cpu 0 signal 4 at 0x0"));
    assert!(fake::called("log:[linux]   rax 0x11"));
    assert!(fake::called("log:[linux]   stack "));
    drop(buf);
    // Blocked: also fatal (with an address space: no code or stack dump)
    spawn(3346, 0);
    run(3346);
    let m = bit(SIGSEGV);
    sys_rt_sigprocmask(0, ptr(&m), 0, 8);
    set(SIGSEGV, action(0x40_1000, 0, 0));
    global_frames();
    let mm = std::sync::Arc::new(spin::Mutex::new(crate::memory::vm::Mm::new().unwrap()));
    fake::task(3346, |t| t.mm = Some(mm.clone()));
    let mut ctx = ExceptionContext { cs: 0x2b, rsp: 0x1000, rip: 0x2000, vector: 14, ..Default::default() };
    with_current_mm(|| panics_with("task::exit_group", || force_fault_signal(&mut ctx, &mut fpu, SIGSEGV)));
    fake::switch_to(0);
    let mut ctx = ExceptionContext { cs: 0x2b, rip: code.as_ptr() as u64, rsp: top, ..Default::default() };
    let (_b2, top2) = stack();
    ctx.rsp = top2;
    panics_with("task::exit_group", || force_fault_signal(&mut ctx, &mut fpu, SIGFPE));
}

#[test]
fn sigreturn_checks_and_pending_signals() {
    let _g = setup();
    spawn(3350, 0);
    run(3350);
    let (_buf, top) = stack();
    let mut fpu = FpuState::new();
    set(SIGUSR1, action(0x40_1000, 0, 0));
    post_process(3350, SIGUSR1);
    let mut f = SyscallFrame { rsp: top, rip: 0x40_2000, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    let uc = f.rdx;
    // Another signal sent while the handler ran: delivered on the way back
    set(SIGUSR2, action(0x40_3000, 0, 0));
    post_process(3350, SIGUSR2);
    let (regs, _, cs) = restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    assert_eq!((regs.rip, cs), (0x40_3000, 0x2b), "straight into the next handler");
    // A frame with a kernel rip: SIGSEGV
    unsafe { *((uc + 40 + 16 * 8) as *mut u64) = 0xffff_8000_0000_0000 };
    panics_with("task::exit_group", || {
        restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    });
    // An unreadable frame
    with_current_mm(|| panics_with("task::exit_group", || {
        restore_sigframe(&SyscallFrame { rsp: 8, ..Default::default() });
    }));
    // A pending fatal signal on the way back
    unsafe { *((uc + 40 + 16 * 8) as *mut u64) = 0x40_2000 };
    post_process(3350, SIGTERM);
    panics_with("task::exit_group", || {
        restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    });
}

#[test]
fn xsave_frames_round_trip() {
    let _g = setup();
    spawn(3360, 0);
    run(3360);
    fake::XSAVE.set(true);
    let (_buf, top) = stack();
    let mut fpu = FpuState::new();
    fpu.0[600] = 0x77; // AVX state
    set(SIGUSR1, action(0x40_1000, 0, 0));
    post_process(3360, SIGUSR1);
    let mut f = SyscallFrame { rsp: top, rip: 0x40_2000, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    let uc = f.rdx;
    assert_eq!(rd(uc), 1, "uc_flags: UC_FP_XSTATE");
    let fp = rd(uc + 40 + 184);
    assert_eq!(unsafe { *((fp + 464) as *const u32) }, 0x4650_5853, "FP_XSTATE_MAGIC1");
    assert_eq!(unsafe { *((fp + 832) as *const u32) }, 0x4650_5845, "FP_XSTATE_MAGIC2");
    // The handler changes the AVX state; sigreturn takes it back (header sanitised)
    unsafe {
        *((fp + 600) as *mut u8) = 0x99;
        *((fp + 520) as *mut u64) = 0xffff; // a bogus compaction field
    }
    let (_, fpu2, _) = restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    assert_eq!(fpu2.0[600], 0x99);
    assert_eq!(&fpu2.0[520..576], &[0u8; 56]);
    // A wrong magic: only the legacy area comes back
    unsafe { *((fp + 832) as *mut u32) = 0 };
    let (_, fpu3, _) = restore_sigframe(&SyscallFrame { rsp: uc, ..Default::default() });
    assert_eq!(fpu3.0[600], 0);
    fake::XSAVE.set(false);
}

#[test]
fn a_traced_thread_stops_for_its_signals() {
    let _g = setup();
    spawn(3370, 0);
    spawn(3371, 3370);
    run(3371);
    assert_eq!(linux::ptrace::sys_ptrace(0, 0, 0, 0), 0); // TRACEME
    let (_buf, top) = stack();
    let mut fpu = FpuState::new();
    set(SIGUSR2, action(0x40_9000, 0, 0));
    assert_eq!(sys_kill(3371, SIGUSR1 as u64), 0);
    // The tracer sees SIGUSR1 (siginfo from kill) and delivers SIGUSR2 instead
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(|| {
            fake::switch_to(3370);
            let mut si = [0u8; 128];
            assert_eq!(linux::ptrace::sys_ptrace(0x4202, 3371, 0, mptr(&mut si)), 0);
            assert_eq!((si[0], i32::from_le_bytes(si[8..12].try_into().unwrap())), (SIGUSR1 as u8, 0));
            assert_eq!(linux::ptrace::sys_ptrace(7, 3371, 0, SIGUSR2 as u64), 0);
            fake::switch_to(3371);
        }))
    });
    let mut f = SyscallFrame { rsp: top, rip: 0x40_2000, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    assert_eq!(f.rip, 0x40_9000, "the injected SIGUSR2 ran without another stop");
    // A stop signal for a traced thread: a group stop the tracer resumes
    post_process(3371, SIGSTOP);
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(|| {
            fake::switch_to(3370);
            let _ = linux::ptrace::sys_ptrace(7, 3371, 0, 0);
            fake::switch_to(3371);
        }))
    });
    let mut f = SyscallFrame { rsp: top, rip: 0x40_2000, ..Default::default() };
    deliver_on_syscall_return(&mut f, &mut fpu, 39);
    // The same from a trap: signal stop, then the group stop
    post_process(3371, SIGSTOP);
    let mut ctx = ExceptionContext { cs: 0x2b, rsp: top, rip: 0x40_1000, ..Default::default() };
    deliver_on_trap_return(&mut ctx, &mut fpu);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    // An interrupt pending at a trap
    run(3370);
    assert_eq!(linux::ptrace::sys_ptrace(17, 3371, 0, 0), ESRCH, "running");
    assert!(!signal_pending_for(3371, 3371), "everything was delivered");
    assert!(!delivery_maybe(3371, 3371) && !delivery_maybe(4242, 4242));
    post_thread(3371, 3371, SIGUSR1);
    assert!(signal_pending_for(3371, 3371) && delivery_maybe(3371, 3371));
    notify_tracer(3370);
    run(3371);
    assert!(!sigkill_pending());
}

// ------------------------------------------------------------- wait

#[test]
fn wait4_reaps_children() {
    let _g = setup();
    spawn(3400, 0);
    spawn(3401, 3400);
    spawn(3402, 3400);
    run(3400);
    let mut st = 0i32;
    assert_eq!(sys_wait4(-1, mptr(&mut st), 1, 0), 0, "WNOHANG: nobody exited");
    assert_eq!(sys_wait4(4242, 0, 1, 0), ECHILD);
    with_proc(3401, |p| p.dead_ticks = (30, 10));
    set_exit_status(3401, wait_status_exit(4));
    thread_exited(3401, 3401, 0, 0, (0, 0));
    assert_eq!(sys_wait4(-1, mptr(&mut st), 0, 0), 3401);
    assert_eq!(st, 4 << 8);
    assert!(!process_exists(3401), "reaped");
    assert_eq!(with_proc(3400, |p| p.child_ticks), (30, 10));
    // By process group (0: ours; -pgid)
    thread_exited(3402, 3402, 0, 0, (0, 0));
    assert_eq!(sys_wait4(0, 0, 0, 0), 3402);
    spawn(3403, 3400);
    with_proc(3403, |p| p.pgid = 77);
    thread_exited(3403, 3403, 0, 0, (0, 0));
    assert_eq!(sys_wait4(-78, 0, 1, 0), ECHILD);
    assert_eq!(sys_wait4(-77, 0, 1, 0), 3403);
    // A blocking wait interrupted by a signal: ERESTARTSYS
    spawn(3404, 3400);
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        post_process(3400, SIGUSR1);
    })));
    assert_eq!(sys_wait4(-1, 0, 0, 0), ERESTARTSYS);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    // A bad status pointer
    thread_exited(3404, 3404, 0, 0, (0, 0));
    with_current_mm(|| assert_eq!(sys_wait4(-1, 8, 0, 0), EFAULT));
}

#[test]
fn waitid_variants() {
    let _g = setup();
    spawn(3410, 0);
    spawn(3411, 3410);
    run(3410);
    let mut info = [0u8; 128];
    assert_eq!(sys_waitid(9, 0, 0, 4), EINVAL, "idtype");
    assert_eq!(sys_waitid(0, 0, 0, 1), EINVAL, "no WEXITED/WSTOPPED/WCONTINUED");
    // WNOHANG with nothing to report: zeroed siginfo
    info[0] = 9;
    assert_eq!(sys_waitid(0, 0, mptr(&mut info), 4 | 1), 0);
    assert_eq!(info[0], 0);
    // Stopped child (WSTOPPED): CLD_STOPPED
    with_proc(3411, |p| {
        p.stopped = true;
        p.stop_sig = SIGTSTP;
    });
    assert_eq!(sys_waitid(1, 3411, mptr(&mut info), 2), 0);
    assert_eq!((i32::from_le_bytes(info[8..12].try_into().unwrap()), info[24]), (5, SIGTSTP as u8));
    // Continued (WCONTINUED): CLD_CONTINUED
    post_process(3411, SIGCONT);
    assert_eq!(sys_waitid(1, 3411, mptr(&mut info), 8), 0);
    assert_eq!(i32::from_le_bytes(info[8..12].try_into().unwrap()), 6);
    // Exited, kept with WNOWAIT, then reaped; the pidfd form
    set_exit_status(3411, wait_status_exit(2));
    thread_exited(3411, 3411, 0, 0, (0, 0));
    assert_eq!(sys_waitid(0, 0, mptr(&mut info), 4 | 0x0100_0000), 0);
    assert_eq!((i32::from_le_bytes(info[8..12].try_into().unwrap()), u32::from_le_bytes(info[16..20].try_into().unwrap()), info[24]), (1, 3411, 2));
    assert!(process_exists(3411), "WNOWAIT keeps it");
    let fd = linux::pidfd::install(3411, false) as u64;
    assert_eq!(sys_waitid(3, fd, mptr(&mut info), 4), 0);
    assert!(!process_exists(3411));
    assert_eq!(sys_waitid(3, 99, 0, 4), -9, "not a pidfd");
    // Killed and by group
    spawn(3412, 3410);
    set_exit_status(3412, 9);
    thread_exited(3412, 3412, 0, 0, (0, 0));
    assert_eq!(sys_waitid(2, 3410, mptr(&mut info), 4), 0);
    assert_eq!((i32::from_le_bytes(info[8..12].try_into().unwrap()), info[24]), (2, 9));
    with_current_mm(|| {
        spawn(3413, 3410);
        thread_exited(3413, 3413, 0, 0, (0, 0));
        assert_eq!(sys_waitid(0, 0, 8, 4), EFAULT);
    });
    assert_eq!(sys_waitid(0, 0, 0, 4 | 1), ECHILD, "no children left");
}

#[test]
fn waitid_without_wexited_leaves_exited_children() {
    let _g = setup();
    spawn(3420, 0);
    spawn(3421, 3420);
    run(3420);
    thread_exited(3421, 3421, 0, 0, (0, 0));
    // Only stops asked for: the exited child is neither reported nor reaped
    let mut info = [7u8; 128];
    assert_eq!(sys_waitid(0, 0, mptr(&mut info), 2 | 1), 0);
    assert_eq!(&info[..4], &[0; 4], "nothing reported");
    assert!(process_exists(3421), "not reaped");
    assert_eq!(sys_waitid(0, 0, mptr(&mut info), 4 | 1), 0);
    assert!(!process_exists(3421));
}

#[test]
fn wait_reports_ptrace_stops() {
    let _g = setup();
    spawn(3430, 0);
    spawn(3431, 0);
    run(3430);
    assert_eq!(linux::ptrace::sys_ptrace(0x4206, 3431, 0, 0), 0);
    assert_eq!(sys_wait4(-1, 0, 1, 0), 0, "a tracee: no ECHILD");
    assert_eq!(linux::ptrace::on_thread_exit(3431, 3431, 5, 0), Some(3430));
    let mut st = 0;
    assert_eq!(sys_wait4(-1, mptr(&mut st), 1, 0), 3431);
    assert_eq!(st, 5);
}
