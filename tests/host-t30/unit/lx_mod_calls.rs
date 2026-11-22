//! `src/lx/mod.rs`: the request table's paths through real workers: pending answers and
//! `SYS_LX_COMPLETE` (also early), signals at each state, the crash policy, redirects, net
//! waits, the copy-in/copy-out table.

use super::*;

/// A thread `tid` of service process `tgid` (endpoint `ep`), with an address space.
pub(crate) fn server_task(tid: u64, tgid: u64, ep: u32) -> Task {
    let mut t = Task::server(tid, tgid, ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    t
}

/// Waits (yielding) until `v` is non-zero; its value.
pub(crate) fn wait_set(v: &StdAtomicU64) -> u64 {
    for _ in 0..10_000 {
        let x = v.load(Ordering::Acquire);
        if x != 0 {
            return x;
        }
        crate::task::yield_now();
    }
    panic!("never set");
}

// ----------------------------------------------------------------------
// Pending answers
// ----------------------------------------------------------------------

#[test]
fn a_pending_call_is_completed_later_by_another_server_thread() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    let i3 = id.clone();
    sim.spawn(server_task(350, 300, s.ep), move || {
        let id = wait_set(&i3);
        // While pending: the server reaches its caller (client_of)
        assert_eq!(client_of(id), Some(100));
        // Another host's request id is not this service's
        assert_eq!(complete(id & !(0xFF << 56) | (LXS_SEC as u64) << 56, 1), EINVAL);
        assert_eq!(complete(id, LX_TEST_PENDING_RESULT), 0);
        // Answered: no longer pending
        assert_eq!(complete(id, 1), EINVAL);
    });
    assert_eq!(test_call(LX_TEST_PENDING, 0, 0), LX_TEST_PENDING_RESULT);
    s.x.lx(|t| assert!(t.reqs.iter().all(|r| r.state == RState::Free)));
}

#[test]
fn a_completion_before_the_pending_answer_is_kept() {
    let sim = world();
    // The service finishes the call (another of its threads) before the worker's "pending"
    // answer reaches the kernel: the pending answer turns into that result
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        assert_eq!(complete(s.call.id, 77), 0);
        // A second early completion is refused (already completed early)
        assert_eq!(complete(s.call.id, 78), EINVAL);
        (0, LX_REPLY_PENDING)
    }));
    assert_eq!(test_call(LX_TEST_PENDING, 0, 0), 77);
}

#[test]
fn an_early_completion_wins_over_the_ordinary_answer_too() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, false, handler(|s| {
        assert_eq!(complete(s.call.id, 55), 0);
        (999, 0)
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), 55);
}

#[test]
fn a_completion_for_a_dead_caller_frees_the_request() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    sim.spawn(Task::linux(101, 100), || {
        crate::world::bkl_enter();
        let _ = forward(&frame(LX_TEST_NR, [LX_TEST_PENDING, 0, 0, 0, 0, 0]));
        unreachable!("the caller died in its call");
    });
    sim.run_others();
    let id = id.load(Ordering::Acquire);
    assert_ne!(id, 0);
    // The caller dies while its call is pending
    sim.with_task(101, |t| t.state = crate::task::TaskState::Dead);
    assert_eq!(complete_as_kernel(id, 5), 0);
    s.x.lx(|t| assert!(t.reqs.iter().all(|r| r.state == RState::Free), "the request is freed"));
    // An unknown host or request
    assert_eq!(complete_as_kernel((15u64) << 56 | 1, 0), EINVAL);
    assert_eq!(complete_as_kernel(id, 0), EINVAL);
}

#[test]
fn complete_needs_a_service_thread() {
    let _sim = world();
    // The running task is a Linux program
    assert_eq!(complete((LXS_TEST as u64) << 56 | 1, 0), EPERM);
}

// ----------------------------------------------------------------------
// Signals
// ----------------------------------------------------------------------

#[test]
fn a_signal_withdraws_a_call_still_queued() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        if s.call.args[1] == 1 {
            // Thread 101 queues its call meanwhile ...
            crate::task::yield_now();
            // ... and gets a signal (its poster wakes it)
            crate::fake::set_signal(101, true);
            crate::task::SCHEDULER.lock().unblock_task(crate::task::TaskId(101));
            crate::task::yield_now();
        }
        (1, 0)
    }));
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 100), move || {
        crate::world::bkl_enter();
        let r = forward(&frame(LX_TEST_NR, [0, 2, 0, 0, 0, 0])).unwrap();
        g2.store(r as u64, Ordering::Release);
    });
    assert_eq!(test_call(LX_TEST_NULL, 1, 0), 1);
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire) as i64, EINTR);
    // The withdrawn call never reached the worker; nothing is left in the table
    assert_eq!(calls.lock().unwrap().len(), 1);
    s.x.lx(|t| assert!(t.reqs.iter().all(|r| r.state == RState::Free)));
}

#[test]
fn a_signal_marks_a_call_being_served() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        assert_eq!(s.flags() & LX_CALL_INTERRUPTED, 0);
        crate::fake::set_signal(100, true);
        crate::task::SCHEDULER.lock().unblock_task(crate::task::TaskId(100));
        crate::task::yield_now();
        // The caller marked its call in the page; the server answers EINTR
        if s.flags() & LX_CALL_INTERRUPTED != 0 {
            (EINTR, 0)
        } else {
            (0, 0)
        }
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), EINTR);
}

#[test]
fn a_signal_for_a_pending_call_is_told_through_the_ring() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    let x = s.x;
    let i3 = id.clone();
    sim.spawn(server_task(350, 300, s.ep), move || {
        let id = wait_set(&i3);
        crate::fake::set_signal(100, true);
        crate::task::SCHEDULER.lock().unblock_task(crate::task::TaskId(100));
        crate::task::yield_now();
        // The caller told the service (once), and waits for the answer
        let n = notes(x);
        assert_eq!(n.iter().filter(|e| e[0] == LX_NOTE_INTERRUPT && e[1] == id).count(), 1, "{n:?}");
        assert_eq!(complete(id, EINTR), 0);
    });
    assert_eq!(test_call(LX_TEST_PENDING, 0, 0), EINTR);
}

#[test]
fn a_signal_while_served_then_pending_is_told_by_the_pending_answer() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        crate::fake::set_signal(100, true);
        crate::task::SCHEDULER.lock().unblock_task(crate::task::TaskId(100));
        crate::task::yield_now();
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    let x = s.x;
    let i3 = id.clone();
    sim.spawn(server_task(350, 300, s.ep), move || {
        let id = wait_set(&i3);
        // (the worker's pending answer posted it: the caller had marked the call already)
        assert!(notes(x).iter().any(|e| e[0] == LX_NOTE_INTERRUPT && e[1] == id));
        assert_eq!(complete(id, 3), 0);
    });
    assert_eq!(test_call(LX_TEST_PENDING, 0, 0), 3);
}

// ----------------------------------------------------------------------
// The crash policy
// ----------------------------------------------------------------------

#[test]
fn calls_in_flight_fail_with_eio_when_the_service_dies() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|_s| {
        // The service's process goes away while it serves the call
        server_gone(LXS_TEST);
        (0, 0)
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), EIO);
    assert_eq!(FAILED_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(s.x.failed.load(Ordering::Relaxed), 1);
    assert!(!s.x.is_online());
    assert!(crate::fake::logged("test (process 300) went away: 1 calls in flight failed with EIO"));
    // The worker is gone from every list
    assert_eq!(svc::worker_host(s.workers[0]), None);
    s.x.lx(|t| assert!(t.workers.is_empty()));
    // FailObjects (the default): new calls wait for the new instance, at most 30 s
    assert!(restart::restarting(LXS_TEST));
    let t0 = crate::arch::pit::now_ns();
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), EIO);
    assert!(crate::arch::pit::now_ns() - t0 >= 30_000_000_000);
    assert!(crate::fake::logged("did not come back within 30 s"));
}

#[test]
fn linux_server_dying_ends_every_linux_program() {
    let sim = world();
    restart::configure(LXS_LINUX, restart::RestartClass::EndLinux);
    let s = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    // (from the supervisor's context: the hook of its endpoint)
    on_signal_for::<{ ENDPOINT_LINUX_SERVER }>(crate::ipc::service::SIGNAL_GONE);
    assert!(!s.x.is_online());
    assert!(sim.spawned().contains(&"lx-recover"));
    assert!(s.x.recovering.load(Ordering::Relaxed));
    // A second report while recovering starts nothing new
    server_gone(LXS_LINUX);
    assert_eq!(sim.spawned().iter().filter(|n| **n == "lx-recover").count(), 1);
    // Its whole process was ended
    assert_eq!(sim.state(s.workers[0]), crate::task::TaskState::Dead);
    // EndLinux: callers do not wait for the new instance
    assert!(!restart::restarting(LXS_LINUX));
    assert_eq!(forward(&frame(LX_NULL_NR, [0; 6])), Some(ENOSYS));
}

#[test]
fn a_transparent_restart_sends_queued_calls_again() {
    let sim = world();
    restart::configure(LXS_TEST, restart::RestartClass::Transparent);
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        if s.call.args[1] == 1 {
            // Thread 101's call queues meanwhile; then the service dies
            crate::task::yield_now();
            server_gone(LXS_TEST);
        }
        (s.call.args[1] as i64, 0)
    }));
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 100), move || {
        crate::world::bkl_enter();
        // LX_TEST_PENDING (op 2) is idempotent; the call never reached the old instance
        let r = forward(&frame(LX_TEST_NR, [LX_TEST_PENDING, 2, 0, 0, 0, 0])).unwrap();
        g2.store(r as u64, Ordering::Release);
    });
    // The call being served (op 3, not idempotent) fails with EIO
    assert_eq!(test_call(3, 1, 0), EIO);
    assert!(restart::restarting(LXS_TEST));
    assert!(crate::fake::logged("calls in flight wait to be sent again"));
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 0, "101 waits for the new instance");
    // The new instance comes up (another process): 101's call is sent again and answered
    let s2 = start(&sim, LXS_TEST, 400, 1, true, handler(|s| (s.call.args[1] as i64 * 100, 0)));
    assert!(core::ptr::eq(s.x, s2.x));
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 200);
    assert_eq!(restart::RESENT.load(Ordering::Relaxed), 1);
    assert!(!restart::restarting(LXS_TEST));
}

#[test]
fn watch_ends_a_service_whose_worker_died() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 2, true, handler(|_| (0, 0)));
    watch();
    assert!(sim.log().iter().all(|e| !matches!(e, Ev::Kill(_))));
    sim.with_task(s.workers[1], |t| t.state = crate::task::TaskState::Dead);
    watch();
    assert!(sim.log().contains(&Ev::Kill(300)));
    assert!(crate::fake::logged("test worker 302 died: ending the service (process 300)"));
}

// ----------------------------------------------------------------------
// Redirects
// ----------------------------------------------------------------------

/// linux-server's answer to a redirected call, as the real test pair has it.
fn linux_redirect_answer() -> Handler {
    handler(|s| (0x5000 + s.call.redir_obj as i64 + 0x100 * s.call.redirs as i64 + s.call.redir_tail as i64, 0))
}

#[test]
fn a_redirect_sends_the_call_to_the_service_named() {
    let sim = world();
    start(&sim, LXS_LINUX, 200, 1, true, linux_redirect_answer());
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        s.set_redir_obj(s.call.args[1]);
        (LXS_LINUX as i64 | (s.call.args[2] as i64) << 32, LX_REPLY_REDIRECT)
    }));
    assert_eq!(test_call(LX_TEST_REDIRECT, 0x20, 3), 0x5000 + 0x20 + 0x100 + 3);
    assert_eq!(REDIRECTS.load(Ordering::Relaxed), 1);
}

#[test]
fn a_redirect_loop_ends_with_eloop() {
    let sim = world();
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        n2.fetch_add(1, Ordering::AcqRel);
        // The same object slot is kept for a redirect to the same host
        (LXS_TEST as i64, LX_REPLY_REDIRECT)
    }));
    assert_eq!(test_call(LX_TEST_REDIR_LOOP, 9, 0), ELOOP);
    assert_eq!(n.load(Ordering::Acquire), LX_REDIR_MAX as u64 + 1);
}

#[test]
fn a_redirect_to_a_service_in_the_kernel_or_not_running_fails() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| (s.call.args[1] as i64, LX_REPLY_REDIRECT)));
    // linux-server is not running
    assert_eq!(test_call(LX_TEST_REDIRECT, LXS_LINUX as u64, 0), ENOSYS);
    // wave7 G7-4: a service switched back to the kernel (or every service): the kernel's own
    // code answers the call (nothing happened in the redirecting service)
    let kernel_answers = || {
        crate::world::bkl_enter();
        forward(&frame(LX_TEST_NR, [LX_TEST_REDIRECT, LXS_LINUX as u64, 0, 0, 0, 0]))
    };
    svc::tests::set_mode(LXS_LINUX, svc::SvcMode::Kernel);
    assert_eq!(kernel_answers(), None);
    svc::tests::set_mode(LXS_LINUX, svc::SvcMode::Forward);
    ALL_KERNEL.store(true, Ordering::Release);
    assert_eq!(kernel_answers(), None);
    ALL_KERNEL.store(false, Ordering::Release);
}

// ----------------------------------------------------------------------
// Net waits
// ----------------------------------------------------------------------

#[test]
fn a_net_wait_makes_the_call_again_when_its_handle_is_listed() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.flags & LX_CALL_RETRIED != 0 {
            return (5, 0);
        }
        // A word that changed: try again at once; the same word: registered
        crate::fake::rec(|r| r.net_words.insert(7, 3));
        assert_eq!(netwait(s.call.id, 7, 2), 1);
        assert_eq!(netwait(s.call.id, 7, 3), 0);
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    let i3 = id.clone();
    sim.spawn(server_task(350, 300, s.ep), move || {
        let id = wait_set(&i3);
        // Another handle: nothing happens
        net_event(Some(&[8]));
        assert_eq!(netwaits(|w| w.len()), 1);
        net_event(Some(&[7]));
        assert_eq!(netwaits(|w| w.len()), 0);
        let _ = id;
    });
    assert_eq!(test_call(LX_TEST_PENDING, 0, 0), 5);
    assert_eq!(NET_RETRIES.load(Ordering::Relaxed), 1);
}

#[test]
fn netwait_registration_rules() {
    let _sim = world();
    // A request nobody is serving
    assert_eq!(netwait((LXS_TEST as u64) << 56 | 9, 1, 0), ESRCH);
    // Cancel: 1 if it was registered
    netwaits(|w| w.push((4, 77)));
    assert_eq!(netcancel(77), 1);
    assert_eq!(netcancel(77), 0);
    // An empty list, and "anything changed" (None) taking every wait
    net_event(None);
    netwaits(|w| {
        w.push((1, 1 << 56 | 5));
        w.push((2, 1 << 56 | 6));
    });
    net_event(None);
    assert_eq!(netwaits(|w| w.len()), 0);
}

#[test]
fn netwait_drops_stale_waits_when_the_list_is_long() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        netwaits(|w| {
            for i in 0..256 {
                w.push((1, i));
            }
        });
        assert_eq!(netwait(s.call.id, 9, 0), 0);
        // The 256 waits of requests that ended went; this one stays
        assert_eq!(netwaits(|w| w.clone()), vec![(9, s.call.id)]);
        assert_eq!(netcancel(s.call.id), 1);
        (0, 0)
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), 0);
}

#[test]
fn the_relay_follows_watched_sockets_and_the_main_thread() {
    let _sim = world();
    assert!(!relay_wanted());
    assert_eq!(set_relay(true), 0);
    assert!(relay_wanted());
    // The network service's main thread was told to catch up
    let ep = svc::endpoint_of(LXS_NET);
    assert_ne!(crate::ipc::service::tests::pending_bits(ep) & NOTIFY_LX_NET, 0);
    assert_eq!(set_relay(false), 0);
    assert!(!relay_wanted());
    WATCHED_NET.store(1, Ordering::Release);
    assert!(relay_wanted());
}

// ----------------------------------------------------------------------
// The copy-in/copy-out table, end to end
// ----------------------------------------------------------------------

/// Routes call `nr` to the test service (as if it had moved there).
fn route_to_test(nr: u64) {
    TABLE[nr as usize].store(T_SERVER | (LXS_TEST as u32) << T_SVC_SHIFT, Ordering::Release);
}

#[test]
fn pointer_arguments_are_copied_in_and_out() {
    let sim = world();
    crate::fake::user_space_on();
    route_to_test(248);
    route_to_test(250);
    let inputs = StdArc::new(StdMutex::new(Vec::new()));
    let i2 = inputs.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.nr == 248 {
            i2.lock().unwrap().push((s.input(0), s.input(1), s.input(2)));
            (11, 0)
        } else {
            // keyctl READ: its buffer comes back
            s.output(2, b"secret");
            (6, 0)
        }
    }));
    let ty = b"user\0".to_vec();
    let desc = b"hello\0".to_vec();
    let payload = b"abc".to_vec();
    crate::world::bkl_enter();
    let a = [ty.as_ptr() as u64, desc.as_ptr() as u64, payload.as_ptr() as u64, 3, 0, 0];
    assert_eq!(forward(&frame(248, a)), Some(11));
    let (t, d, p) = inputs.lock().unwrap()[0].clone();
    assert_eq!(t.as_deref(), Some(&b"user"[..]));
    assert_eq!(d.as_deref(), Some(&b"hello"[..]));
    assert_eq!(p.as_deref(), Some(&b"abc"[..]));
    let mut out = vec![0u8; 16];
    assert_eq!(forward(&frame(250, [11, 5, out.as_mut_ptr() as u64, 16, 0, 0])), Some(6));
    assert_eq!(&out[..6], b"secret");
    assert_eq!(&out[6..], &[0; 10]);
}

#[test]
fn a_page_not_there_yet_is_faulted_in_and_a_bad_pointer_fails() {
    let sim = world();
    crate::fake::user_space_on();
    route_to_test(248);
    route_to_test(250);
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        n2.fetch_add(1, Ordering::AcqRel);
        if s.call.nr == 250 {
            s.output(2, b"xy");
        }
        (0, 0)
    }));
    // A string that starts 100 bytes before a page boundary and ends 100 bytes after it
    let base = crate::fake::alloc_pages(3);
    let p = base + 4096 - 100;
    // SAFETY: our pages
    unsafe {
        core::ptr::write_bytes(p as *mut u8, b'k', 200);
        *((p + 200) as *mut u8) = 0;
    }
    crate::world::bkl_enter();
    // The string's second page is missing: faulted in, then the call is placed again
    crate::fake::make_missing(base + 4096, 1);
    let before = copy::FAULT_INS.load(Ordering::Relaxed);
    assert_eq!(forward(&frame(248, [0, p, 0, 0, 0, 0])), Some(0));
    assert_eq!(copy::FAULT_INS.load(Ordering::Relaxed), before + 1);
    assert_eq!(n.load(Ordering::Acquire), 1);
    // A page that cannot be had: EFAULT without the server
    crate::fake::make_bad(p);
    assert_eq!(forward(&frame(248, [0, p, 0, 0, 0, 0])), Some(EFAULT));
    assert_eq!(n.load(Ordering::Acquire), 1);
    // An output that faults turns the answer into EFAULT (after the server answered)
    let out = crate::fake::alloc_pages(1);
    crate::fake::make_bad(out);
    assert_eq!(forward(&frame(250, [11, 5, out, 8, 0, 0])), Some(EFAULT));
    assert_eq!(n.load(Ordering::Acquire), 2);
}

#[test]
fn without_an_address_space_a_pointer_is_bad() {
    let sim = world();
    crate::fake::user_space_on();
    route_to_test(248);
    start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    crate::world::bkl_enter();
    // Without an address space nothing is copied: the call goes on without copies
    crate::memory::vm::CURRENT_MM.store(core::ptr::null_mut(), Ordering::Release);
    let s = b"abc\0".to_vec();
    assert_eq!(forward(&frame(248, [s.as_ptr() as u64, 0, 0, 0, 0, 0])), Some(EFAULT));
}

#[test]
fn queued_calls_keep_their_copies_in_the_slot() {
    let sim = world();
    crate::fake::user_space_on();
    route_to_test(248);
    let inputs = StdArc::new(StdMutex::new(Vec::new()));
    let i2 = inputs.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        i2.lock().unwrap().push(s.input(1));
        if s.call.args[3] == 1 {
            crate::task::yield_now();
        }
        (0, 0)
    }));
    let d2 = b"second\0".to_vec();
    let d2p = d2.as_ptr() as u64;
    sim.spawn(Task::linux(101, 100), move || {
        crate::world::bkl_enter();
        assert_eq!(forward(&frame(248, [0, d2p, 0, 2, 0, 0])), Some(0));
        drop(d2);
    });
    let d1 = b"first\0".to_vec();
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(248, [0, d1.as_ptr() as u64, 0, 1, 0, 0])), Some(0));
    sim.run_others();
    let got = inputs.lock().unwrap().clone();
    assert_eq!(got, vec![Some(b"first".to_vec()), Some(b"second".to_vec())]);
    assert_eq!(QUEUED_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn a_full_request_table_refuses_the_call() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    // Every slot taken (by calls nobody serves)
    s.x.lx(|t| {
        for (i, r) in t.reqs.iter_mut().enumerate() {
            r.state = RState::Pending;
            r.id = 1000 + i as u64;
        }
    });
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), EAGAIN);
    assert!(crate::fake::logged("[lx] too many calls in flight (test)"));
    s.x.lx(|t| {
        for r in t.reqs.iter_mut() {
            *r = svc::Req::FREE;
        }
    });
}

// ----------------------------------------------------------------------
// Requests whose caller died before taking their end
// ----------------------------------------------------------------------

#[test]
fn slots_of_callers_killed_after_a_crash_are_reclaimed_when_the_table_is_full() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, LX_REPLY_PENDING)));
    // Three programs wait in pending calls
    for t in 101..104 {
        sim.spawn(Task::linux(t, t), || {
            crate::world::bkl_enter();
            let _ = forward(&frame(LX_TEST_NR, [LX_TEST_PENDING, 0, 0, 0, 0, 0]));
            unreachable!("killed in its call");
        });
    }
    sim.run_others();
    assert_eq!(s.x.lx(|t| t.reqs.iter().filter(|r| r.state == RState::Pending).count()), 3);
    // The service dies (its calls fail), and the programs are killed before they run
    // again (EndLinux's recovery ends every Linux program: a blocked thread dies at once)
    server_gone(LXS_TEST);
    for t in 101..104 {
        sim.with_task(t, |t| t.state = crate::task::TaskState::Dead);
    }
    // Nobody will take those three ends: their slots stay Failed
    assert_eq!(s.x.lx(|t| t.reqs.iter().filter(|r| r.state == RState::Failed).count()), 3);
    // The new instance; every other slot taken by live calls
    let s2 = start(&sim, LXS_TEST, 400, 1, true, handler(|_| (9, 0)));
    s2.x.lx(|t| {
        for (i, r) in t.reqs.iter_mut().enumerate() {
            if r.state == RState::Free {
                *r = svc::Req { state: RState::Pending, id: 5000 + i as u64, client: 100, ..svc::Req::FREE };
            }
        }
    });
    // A full table frees the dead callers' slots instead of refusing the call
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), 9);
    assert_eq!(s2.x.lx(|t| t.reqs.iter().filter(|r| r.state == RState::Failed).count()), 0);
    s2.x.lx(|t| {
        for r in t.reqs.iter_mut() {
            *r = svc::Req::FREE;
        }
    });
}

// wave8 GX2 begin
/// A call being served that its worker marked safe to send again (`LX_CALL_RESEND_OFF` holds
/// its id: lx-net's receive before it takes the data) is sent again after a Transparent
/// restart instead of failing with EIO; a stale mark (another call's id) does not count.
#[test]
fn a_call_marked_safe_is_sent_again_after_a_transparent_restart() {
    let sim = world();
    restart::configure(LXS_TEST, restart::RestartClass::Transparent);
    let _s = start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        // op 3 is not idempotent: only the mark can save it
        let mark = match s.call.args[1] {
            1 => s.call.id,
            _ => s.call.id + 1,
        };
        // SAFETY: the worker's syscall page
        unsafe { core::ptr::write_volatile(s.page.add(LX_CALL_RESEND_OFF) as *mut u64, mark) };
        server_gone(LXS_TEST);
        (0, 0)
    }));
    let got = StdArc::new(StdAtomicU64::new(u64::MAX));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 100), move || {
        crate::world::bkl_enter();
        let r = forward(&frame(LX_TEST_NR, [3, 1, 0, 0, 0, 0])).unwrap();
        g2.store(r as u64, Ordering::Release);
    });
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), u64::MAX, "101 waits for the new instance");
    let _s2 = start(&sim, LXS_TEST, 400, 1, true, handler(|s| (s.call.args[1] as i64 * 100, 0)));
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 100);
}

#[test]
fn a_stale_resend_mark_does_not_count() {
    let sim = world();
    restart::configure(LXS_TEST, restart::RestartClass::Transparent);
    let _s3 = start(&sim, LXS_TEST, 500, 1, true, handler(|s| {
        // SAFETY: as above
        unsafe { core::ptr::write_volatile(s.page.add(LX_CALL_RESEND_OFF) as *mut u64, s.call.id + 1) };
        server_gone(LXS_TEST);
        (0, 0)
    }));
    assert_eq!(test_call(3, 2, 0), EIO);
}
// wave8 GX2 end
