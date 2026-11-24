//! `src/compat/linux/process.rs`: the process-attribute dispatcher (robust lists, sleeps,
//! getrusage, clock_getres, time, capget/capset, prctl, reboot, sysinfo, affinity, and the
//! calls it forwards to other modules).

use super::common::*;
use crate::compat::linux::process::{current_auxv, dispatch};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ERESTART_RESTARTBLOCK: i64 = -516;

fn call(nr: u64, a: [u64; 6]) -> i64 {
    dispatch(nr, a).expect("process.rs serves this call")
}

fn proc_(pid: u64, uid: u32) {
    spawn_as(pid, 1, uid, uid);
    run(pid);
}

#[test]
fn unknown_calls_are_not_ours() {
    let _g = setup();
    assert_eq!(dispatch(0, [0; 6]), None);
    assert_eq!(dispatch(9999, [0; 6]), None);
}

#[test]
fn robust_lists() {
    let _g = setup();
    proc_(900, 1000);
    assert_eq!(call(273, [0x1234, 23, 0, 0, 0, 0]), EINVAL, "wrong head size");
    assert_eq!(call(273, [0x1234, 24, 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(900, |t| t.robust_list), Some(0x1234));
    let (mut head, mut len) = (0u64, 0u64);
    assert_eq!(call(274, [0, mptr(&mut head), mptr(&mut len), 0, 0, 0]), 0);
    assert_eq!((head, len), (0x1234, 24));
    // Another thread of the process; same user's process; another user's
    add_thread(900, 901);
    fake::task(901, |t| t.robust_list = 0x5678);
    assert_eq!(call(274, [901, mptr(&mut head), mptr(&mut len), 0, 0, 0]), 0);
    assert_eq!(head, 0x5678);
    proc_(902, 1000);
    fake::task(902, |t| t.robust_list = 0x9abc);
    run(900);
    assert_eq!(call(274, [902, mptr(&mut head), mptr(&mut len), 0, 0, 0]), 0, "same ids");
    assert_eq!(head, 0x9abc);
    proc_(903, 2000);
    run(900);
    assert_eq!(call(274, [903, mptr(&mut head), mptr(&mut len), 0, 0, 0]), EPERM);
    fake::task(900, |t| t.caps.effective = 1 << 19);
    assert_eq!(call(274, [903, mptr(&mut head), mptr(&mut len), 0, 0, 0]), 0, "CAP_SYS_PTRACE");
    assert_eq!(call(274, [9999, mptr(&mut head), mptr(&mut len), 0, 0, 0]), ESRCH);
    assert_eq!(call(274, [-1i64 as u64, mptr(&mut head), mptr(&mut len), 0, 0, 0]), ESRCH);
    assert_eq!(call(274, [0, mptr(&mut head), 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(274, [0, 0, mptr(&mut len), 0, 0, 0]), EFAULT);
    fake::switch_to(0);
    assert_eq!(call(274, [0, mptr(&mut head), mptr(&mut len), 0, 0, 0]), ESRCH, "no task");
}

#[test]
fn kill_calls_translate_namespace_pids() {
    let _g = setup();
    proc_(930, 0);
    spawn(931, 930);
    // kill(931, 0): exists
    assert_eq!(call(62, [931, 0, 0, 0, 0, 0]), 0);
    assert_eq!(call(62, [9999, 0, 0, 0, 0, 0]), ESRCH);
    // pid_t is 32 bits: 0xffff_ffff_0000_0000 | 931 is still 931
    assert_eq!(call(62, [0xffff_ffff_0000_0000 | 931, 0, 0, 0, 0, 0]), 0);
    assert_eq!(call(200, [931, 0, 0, 0, 0, 0]), 0, "tkill");
    assert_eq!(call(234, [931, 931, 0, 0, 0, 0]), 0, "tgkill");
    assert_eq!(call(234, [930, 931, 0, 0, 0, 0]), ESRCH, "thread of another process");
}

#[test]
fn nanosleep_runs_to_the_deadline() {
    let _g = setup();
    proc_(940, 0);
    let t0 = fake::TICKS.get();
    let ts = [0i64, 5_000_000]; // 5 ms
    assert_eq!(call(35, [ptr(&ts), 0, 0, 0, 0, 0]), 0);
    assert!(fake::TICKS.get() >= t0 + 5);
    // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, until t0 + 20 ms)
    let at = (t0 + 20) * 1_000_000;
    let until = [(at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64];
    assert_eq!(call(230, [1, 1, ptr(&until), 0, 0, 0]), 0);
    assert!(fake::TICKS.get() >= t0 + 20);
    // A deadline already passed returns at once
    let before = fake::TICKS.get();
    assert_eq!(call(230, [1, 1, ptr(&[0i64, 0]), 0, 0, 0]), 0);
    assert_eq!(fake::TICKS.get(), before);
    // CLOCK_REALTIME absolute: converted from the wall clock (2026-01-01 + 2 ms)
    let wall = [1_767_225_600i64, 2_000_000];
    let before = fake::TICKS.get();
    assert_eq!(call(230, [0, 1, ptr(&wall), 0, 0, 0]), 0);
    assert!(fake::TICKS.get() >= before + 2 && fake::TICKS.get() <= before + 3);
    // Invalid times
    assert_eq!(call(35, [ptr(&[-1i64, 0]), 0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(35, [ptr(&[0i64, 1_000_000_000]), 0, 0, 0, 0, 0]), EINVAL);
}

#[test]
fn nanosleep_interrupted_and_restarted() {
    let _g = setup();
    proc_(941, 0);
    // A signal arrives while asleep: ERESTART_RESTARTBLOCK and the time left in rem
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(|| {
            fake::TICKS.set(fake::TICKS.get() + 3);
            linux::proc::post_process(941, 10);
        }))
    });
    let t0 = fake::TICKS.get();
    let ts = [1i64, 0];
    let mut rem = [0i64; 2];
    assert_eq!(call(35, [ptr(&ts), mptr(&mut rem), 0, 0, 0, 0]), ERESTART_RESTARTBLOCK);
    assert_eq!(rem, [0, 997_000_000]);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    // Without rem: nothing is written
    assert_eq!(call(35, [ptr(&ts), 0, 0, 0, 0, 0]), ERESTART_RESTARTBLOCK, "the signal is still pending");
    // Clear the signal, then the transparent restart continues to the original deadline
    linux::proc::PROCS.lock().get_mut(&941).unwrap().pending = 0;
    // Returning from the call with nothing to deliver restarts it (rip back over the
    // syscall instruction) and marks the restart
    let mut frame = crate::arch::syscall::SyscallFrame { rax: ERESTART_RESTARTBLOCK as u64, rip: 0x1002, ..Default::default() };
    let mut fpu = crate::arch::idt::FpuState::new();
    linux::proc::deliver_on_syscall_return(&mut frame, &mut fpu, 35);
    assert_eq!((frame.rip, frame.rax), (0x1000, 35));
    assert_eq!(call(35, [ptr(&[50i64, 0]), 0, 0, 0, 0, 0]), 0);
    assert!(fake::TICKS.get() >= t0 + 1000 && fake::TICKS.get() < t0 + 2000, "the original 1 s, not 50 s");
}

#[test]
fn pause_returns_eintr_on_a_signal() {
    let _g = setup();
    proc_(942, 0);
    fake::ON_WAIT.with_borrow_mut(|h| *h = Some(Box::new(|| {
        linux::proc::post_process(942, 10);
    })));
    assert_eq!(call(34, [0; 6]), EINTR);
}

#[test]
fn getrusage_reports_cpu_time() {
    let _g = setup();
    proc_(950, 0);
    fake::task(950, |t| {
        t.ticks_run = 2500;
        t.ticks_sys = 500;
    });
    let mut ru = [0i64; 18];
    assert_eq!(call(98, [0, mptr(&mut ru), 0, 0, 0, 0]), 0, "RUSAGE_SELF");
    assert_eq!(&ru[..4], &[2, 0, 0, 500_000], "2 s user, 0.5 s system");
    assert_eq!(call(98, [1, mptr(&mut ru), 0, 0, 0, 0]), 0, "RUSAGE_THREAD");
    assert_eq!(&ru[..4], &[2, 0, 0, 500_000]);
    assert_eq!(call(98, [-1i64 as u64, mptr(&mut ru), 0, 0, 0, 0]), 0, "RUSAGE_CHILDREN");
    assert_eq!(&ru[..4], &[0, 0, 0, 0]);
    assert_eq!(call(98, [2, mptr(&mut ru), 0, 0, 0, 0]), EINVAL);
}

#[test]
fn clock_getres_and_time() {
    let _g = setup();
    proc_(951, 0);
    let mut ts = [7i64; 2];
    for c in [0u64, 1, 4, 7, 8, 9, 11] {
        assert_eq!(call(229, [c, mptr(&mut ts), 0, 0, 0, 0]), 0);
        assert_eq!(ts, [0, 1], "clock {c}");
    }
    for c in [2u64, 3, 5, 6, -2i64 as u64] {
        assert_eq!(call(229, [c, mptr(&mut ts), 0, 0, 0, 0]), 0);
        assert_eq!(ts, [0, 10_000_000], "clock {c}");
    }
    assert_eq!(call(229, [10, mptr(&mut ts), 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(229, [0, 0, 0, 0, 0, 0]), 0, "no buffer");
    let mut t = 0i64;
    assert_eq!(call(201, [mptr(&mut t), 0, 0, 0, 0, 0]), 1_767_225_600);
    assert_eq!(t, 1_767_225_600);
    assert_eq!(call(201, [0; 6]), 1_767_225_600);
}

#[test]
fn faults_through_an_address_space() {
    // With an address space loaded, kernel and null pointers are refused (EFAULT) before
    // anything is touched
    let _g = setup();
    proc_(952, 0);
    with_current_mm(|| {
        assert_eq!(call(229, [0, 8, 0, 0, 0, 0]), EFAULT);
        assert_eq!(call(201, [8, 0, 0, 0, 0, 0]), EFAULT);
        assert_eq!(call(98, [0, 8, 0, 0, 0, 0]), EFAULT);
        assert_eq!(call(35, [8, 0, 0, 0, 0, 0]), EINVAL, "nanosleep: an unreadable request is EINVAL here");
        assert_eq!(call(204, [0, 8, 8, 0, 0, 0]), EFAULT);
        assert_eq!(call(239, [8, 0, 0, 0, 0, 0]), EFAULT);
        assert_eq!(call(99, [8, 0, 0, 0, 0, 0]), EFAULT);
        assert_eq!(call(274, [0, 8, 8, 0, 0, 0]), EFAULT);
        assert_eq!(call(157, [16, 8, 0, 0, 0, 0]), EFAULT, "PR_GET_NAME");
    });
}

#[test]
fn affinity_sysinfo_and_mempolicy() {
    let _g = setup();
    proc_(960, 0);
    let mut mask = [0u8; 16];
    assert_eq!(call(204, [0, 4, mptr(&mut mask), 0, 0, 0]), EINVAL, "smaller than the cpumask");
    assert_eq!(call(204, [0, 16, mptr(&mut mask), 0, 0, 0]), 8);
    assert_eq!(mask[0], 1);
    fake::ONLINE_CPUS.set(4);
    assert_eq!(call(204, [0, 16, mptr(&mut mask), 0, 0, 0]), 8);
    assert_eq!(mask[0], 0xf);
    fake::ONLINE_CPUS.set(64);
    assert_eq!(call(204, [0, 8, mptr(&mut mask), 0, 0, 0]), 8);
    assert_eq!(&mask[..8], &[0xff; 8]);
    let one = 1u64;
    assert_eq!(call(203, [0, 8, ptr(&one), 0, 0, 0]), 0, "sched_setaffinity via limits.rs");
    // sysinfo: uptime, memory, process count
    global_frames();
    fake::TICKS.set(12_345);
    let mut si = [0u8; 112];
    assert_eq!(call(99, [mptr(&mut si), 0, 0, 0, 0, 0]), 0);
    assert_eq!(u64::from_le_bytes(si[0..8].try_into().unwrap()), 123);
    assert!(u64::from_le_bytes(si[32..40].try_into().unwrap()) > 0, "total memory");
    assert_eq!(u16::from_le_bytes(si[80..82].try_into().unwrap()), 1, "one process");
    assert_eq!(u32::from_le_bytes(si[104..108].try_into().unwrap()), 1);
    // get_mempolicy: MPOL_DEFAULT
    let mut mode = 7i32;
    assert_eq!(call(239, [mptr(&mut mode), 0, 0, 0, 0, 0]), 0);
    assert_eq!(mode, 0);
    assert_eq!(call(239, [0; 6]), 0);
}

#[test]
fn scheduling_calls_go_to_limits() {
    let _g = setup();
    proc_(961, 0);
    assert_eq!(call(140, [0, 0, 0, 0, 0, 0]), 20, "getpriority");
    assert_eq!(call(141, [0, 0, 3, 0, 0, 0]), 0, "setpriority");
    assert_eq!(call(140, [0, 0, 0, 0, 0, 0]), 17);
    let prio = 0i32;
    assert_eq!(call(144, [0, 0, ptr(&prio), 0, 0, 0]), 0, "sched_setscheduler");
    assert_eq!(call(142, [0, ptr(&prio), 0, 0, 0, 0]), 0, "sched_setparam");
    let mut out = 9i32;
    assert_eq!(call(143, [0, mptr(&mut out), 0, 0, 0, 0]), 0);
    assert_eq!(out, 0);
    assert_eq!(call(145, [0; 6]), 0);
    // sched_get_priority_max / min
    assert_eq!((call(146, [1, 0, 0, 0, 0, 0]), call(146, [0, 0, 0, 0, 0, 0]), call(146, [9, 0, 0, 0, 0, 0])), (99, 0, EINVAL));
    assert_eq!((call(147, [2, 0, 0, 0, 0, 0]), call(147, [5, 0, 0, 0, 0, 0]), call(147, [4, 0, 0, 0, 0, 0])), (1, 0, EINVAL));
    // rlimits, mlock, ioprio
    let mut lim = [0u64; 2];
    assert_eq!(call(97, [7, mptr(&mut lim), 0, 0, 0, 0]), 0);
    assert_eq!(lim, [1024, 1024]);
    assert_eq!(call(152, [0; 6]), 0, "munlockall");
    assert_eq!(call(252, [1, 0, 0, 0, 0, 0]), 4, "ioprio_get");
}

#[test]
fn capget_and_capset() {
    let _g = setup();
    proc_(970, 1000);
    fake::task(970, |t| {
        t.caps.permitted = 0x3_0000_00ff;
        t.caps.effective = 0x1_0000_000f;
    });
    // Version query: an unknown version gets the preferred one back
    let mut head = [0u32, 0];
    assert_eq!(call(125, [mptr(&mut head), 0, 0, 0, 0, 0]), 0);
    assert_eq!(head[0], 0x2008_0522);
    let mut bad = [1u32, 0];
    let mut data = [0u32; 6];
    assert_eq!(call(125, [mptr(&mut bad), mptr(&mut data), 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(125, [0, 0, 0, 0, 0, 0]), EFAULT);
    // v3: two words of (effective, permitted, inheritable)
    let v3 = [0x2008_0522u32, 0];
    assert_eq!(call(125, [ptr(&v3), 0, 0, 0, 0, 0]), 0, "no data pointer: just the version check");
    assert_eq!(call(125, [ptr(&v3), mptr(&mut data), 0, 0, 0, 0]), 0);
    assert_eq!(data, [0xf, 0xff, 0, 1, 3, 0]);
    // v1: one word
    let v1 = [0x1998_0330u32, 0];
    let mut d1 = [0u32; 3];
    assert_eq!(call(125, [ptr(&v1), mptr(&mut d1), 0, 0, 0, 0]), 0);
    assert_eq!(d1, [0xf, 0xff, 0]);
    // capset: permitted may only shrink; effective within permitted
    let grow = [0xfu32, 0x1ff, 0, 1, 3, 0];
    assert_eq!(call(126, [ptr(&v3), ptr(&grow), 0, 0, 0, 0]), EPERM);
    let wide = [0x1ffu32, 0xff, 0, 1, 3, 0];
    assert_eq!(call(126, [ptr(&v3), ptr(&wide), 0, 0, 0, 0]), EPERM);
    let shrink = [0x3u32, 0x7, 0, 0, 1, 0];
    assert_eq!(call(126, [ptr(&v3), ptr(&shrink), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(970, |t| (t.caps.effective, t.caps.permitted)), Some((0x3, 0x1_0000_0007)));
    // A v1 caller leaves the upper capabilities alone
    let v1set = [0x1u32, 0x7, 0];
    assert_eq!(call(126, [ptr(&v1), ptr(&v1set), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(970, |t| (t.caps.effective, t.caps.permitted)), Some((0x1, 0x1_0000_0007)));
    // Another process, a bad version, bad pointers
    let other = [0x2008_0522u32, 4242];
    assert_eq!(call(126, [ptr(&other), ptr(&shrink), 0, 0, 0, 0]), EPERM);
    let mine = [0x2008_0522u32, 970];
    assert_eq!(call(126, [ptr(&mine), ptr(&shrink), 0, 0, 0, 0]), 0);
    assert_eq!(call(126, [ptr(&[5u32, 0]), ptr(&shrink), 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(126, [0, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(126, [ptr(&v3), 0, 0, 0, 0, 0]), EFAULT);
    fake::switch_to(0);
    assert_eq!(call(126, [ptr(&v3), ptr(&shrink), 0, 0, 0, 0]), EPERM, "no task");
    assert_eq!(call(125, [ptr(&v3), mptr(&mut data), 0, 0, 0, 0]), 0, "no task: root's set");
    assert_eq!(data[0], u32::MAX);
}

#[test]
fn prctl_options() {
    let _g = setup();
    proc_(980, 0);
    // (wave10 G7b-1: PR_SET_NAME reads its name: a null one is EFAULT)
    assert_eq!(call(157, [15, 0, 0, 0, 0, 0]), EFAULT, "PR_SET_NAME of nothing");
    for opt in [1u64, 4, 36, 47, 24] {
        assert_eq!(call(157, [opt, 0, 0, 0, 0, 0]), 0, "option {opt}");
    }
    assert_eq!(call(157, [3, 0, 0, 0, 0, 0]), 0, "PR_GET_DUMPABLE after PR_SET_DUMPABLE 0");
    assert_eq!(call(157, [4, 2, 0, 0, 0, 0]), EINVAL, "PR_SET_DUMPABLE 2");
    assert_eq!(call(157, [4, 1, 0, 0, 0, 0]), 0);
    assert_eq!(call(157, [3, 0, 0, 0, 0, 0]), 1, "PR_GET_DUMPABLE");
    assert_eq!(call(157, [1, 65, 0, 0, 0, 0]), EINVAL, "PR_SET_PDEATHSIG 65");
    assert_eq!(call(157, [1, 9, 0, 0, 0, 0]), 0);
    let mut sig = [0u8; 4];
    assert_eq!(call(157, [2, mptr(&mut sig), 0, 0, 0, 0]), 0, "PR_GET_PDEATHSIG");
    assert_eq!(i32::from_le_bytes(sig), 9);
    assert_eq!(call(157, [36, 1, 0, 0, 0, 0]), 0);
    assert_eq!(call(157, [37, mptr(&mut sig), 0, 0, 0, 0]), 0, "PR_GET_CHILD_SUBREAPER");
    assert_eq!(i32::from_le_bytes(sig), 1);
    assert_eq!(call(157, [23, 0, 0, 0, 0, 0]), 1, "PR_CAPBSET_READ");
    assert_eq!(call(157, [8, 2, 0, 0, 0, 0]), EINVAL, "PR_SET_KEEPCAPS 2");
    assert_eq!(call(157, [8, 1, 0, 0, 0, 0]), 0);
    assert_eq!(call(157, [7, 0, 0, 0, 0, 0]), 1, "PR_GET_KEEPCAPS");
    let mut name = [0u8; 16];
    assert_eq!(call(157, [16, mptr(&mut name), 0, 0, 0, 0]), 0);
    let exe = fake::task(980, |t| t.exe_path().to_string()).unwrap();
    assert_eq!(name, crate::lx::proc::comm_or_exe(980, &exe), "the executable's name");
    let new = *b"a-much-longer-name\0";
    assert_eq!(call(157, [15, ptr(&new), 0, 0, 0, 0]), 0, "PR_SET_NAME");
    assert_eq!(call(157, [16, mptr(&mut name), 0, 0, 0, 0]), 0);
    assert_eq!(&name, b"a-much-longer-n\0", "cut to 15");
    crate::lx::proc::attrs_on_exit(980);
    assert_eq!(call(157, [999, 0, 0, 0, 0, 0]), EINVAL);
    // no_new_privs goes to seccomp.rs
    assert_eq!(call(157, [39, 0, 0, 0, 0, 0]), 0);
    assert_eq!(call(157, [38, 1, 0, 0, 0, 0]), 0);
    assert_eq!(call(157, [39, 0, 0, 0, 0, 0]), 1);
    assert_eq!(call(157, [21, 0, 0, 0, 0, 0]), 0, "PR_GET_SECCOMP");
    // Hydra's access-control option goes to abac.rs
    fake::set_ret("abac::prctl", 42);
    assert_eq!(call(157, [0x4859_4401, 0, 0, 0, 0, 0]), 42);
    // PR_GET_AUXV: the auxiliary vector of the address space
    assert_eq!(call(157, [0x4155_5856, 0, 0, 0, 0, 0]), 0, "no address space: empty");
    assert!(current_auxv().is_empty());
    global_frames();
    let mm = std::sync::Arc::new(spin::Mutex::new(crate::memory::vm::Mm::new().unwrap()));
    mm.lock().auxv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    fake::task(980, |t| t.mm = Some(mm.clone()));
    let mut buf = [0u8; 4];
    assert_eq!(call(157, [0x4155_5856, mptr(&mut buf), 4, 0, 0, 0]), 10, "the full size");
    assert_eq!(buf, [1, 2, 3, 4], "as much as fits");
    assert_eq!(call(157, [0x4155_5856, 0, 0, 0, 0, 0]), 10, "size query");
}

#[test]
fn reboot_needs_privilege_and_magic() {
    let _g = setup();
    proc_(990, 1000);
    const M1: u64 = 0xfee1_dead;
    const M2: u64 = 672274793;
    assert_eq!(call(169, [M1, M2, 0x4321_fedc, 0, 0, 0]), EPERM, "needs CAP_SYS_BOOT first");
    fake::task(990, |t| t.caps.effective = 1 << 22);
    assert_eq!(call(169, [1, M2, 0, 0, 0, 0]), EINVAL, "bad magic");
    assert_eq!(call(169, [M1, 7, 0, 0, 0, 0]), EINVAL, "bad magic2");
    assert_eq!(call(169, [M1, 85072278, 0x89ab_cdef, 0, 0, 0]), 0, "CAD on");
    assert_eq!(call(169, [M1, M2, 0, 0, 0, 0]), 0, "CAD off");
    assert_eq!(call(169, [M1, M2, 5, 0, 0, 0]), EINVAL, "unknown command");
    panics_with("power_off", || {
        call(169, [M1, 369367448, 0x4321_fedc, 0, 0, 0]);
    });
    panics_with("power_off", || {
        call(169, [M1, M2, 0xcdef_0123, 0, 0, 0]);
    });
    panics_with("reboot", || {
        call(169, [M1, 537993216, 0x0123_4567, 0, 0, 0]);
    });
}
