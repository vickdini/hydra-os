//! `src/lx/mod.rs`, the server side: `SYS_LX_CTL`, `SYS_LX_REPLY_RECV` refusals, the
//! notification ring, the doorbell hook, the task dump and statistics, the kernel's
//! requests to a service's main thread (`/proc` texts), the recovery task.

use super::*;
use calls::server_task;

/// A thread of service process `tgid` (endpoint `ep`) answering the kernel's requests to
/// its main thread with `f` (which may write the window), forever.
pub(crate) fn serve_main(sim: &Sim, tid: u64, tgid: u64, ep: u32, f: impl Fn(crate::ipc::Message, &mut [u8]) -> crate::ipc::Message + Send + 'static) {
    sim.spawn(server_task(tid, tgid, ep), move || loop {
        let (id, m) = crate::ipc::service::recv(ep).expect("recv");
        let win = crate::ipc::service::window(ep).expect("a window");
        let a = f(m, win);
        crate::ipc::service::reply(ep, id, a).expect("reply");
    });
}

#[test]
fn ctl_refuses_programs_and_unknown_operations() {
    let sim = world();
    assert_eq!(ctl(LX_CTL_ATTACH), EPERM);
    assert_eq!(reply_recv(0, 0), EPERM);
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(server_task(350, 300, s.ep), move || {
        // Not a worker: no answer to give, no call to wait for
        r2.lock().unwrap().push(reply_recv(0, 0));
        r2.lock().unwrap().push(ctl(99));
        r2.lock().unwrap().push(ctl(LX_CTL_WAKE));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![EPERM, EINVAL, 0]);
    assert_ne!(crate::ipc::service::tests::pending_bits(s.ep) & NOTIFY_LX_NOTES, 0);
}

#[test]
fn attach_limits_and_a_new_process() {
    let sim = world();
    let x = svc::host_or_make(LXS_TEST, ENDPOINT_SVC_TEST);
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(server_task(301, 300, ENDPOINT_SVC_TEST), move || {
        for _ in 0..MAX_WORKERS {
            assert!(ctl(LX_CTL_ATTACH) > 0);
        }
        r2.lock().unwrap().push(ctl(LX_CTL_ATTACH));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![EBUSY]);
    assert_eq!(x.lx(|s| (s.workers.len(), s.server_tgid)), (MAX_WORKERS, 300));
    // Another process while the first one lives: refused
    sim.spawn(server_task(302, 300, ENDPOINT_SVC_TEST), || loop {
        crate::task::SCHEDULER.lock().block_current();
        crate::task::yield_now();
    });
    sim.run_others();
    let r3 = r.clone();
    sim.spawn(server_task(401, 400, ENDPOINT_SVC_TEST), move || r3.lock().unwrap().push(ctl(LX_CTL_ATTACH)));
    sim.run_others();
    assert_eq!(r.lock().unwrap()[1], EBUSY);
    // Once it is gone, the new process's first worker clears the old ones
    sim.with_task(302, |t| t.state = crate::task::TaskState::Dead);
    let r4 = r.clone();
    sim.spawn(server_task(402, 400, ENDPOINT_SVC_TEST), move || r4.lock().unwrap().push(ctl(LX_CTL_ATTACH)));
    sim.run_others();
    assert!(r.lock().unwrap()[2] > 0);
    assert_eq!(x.lx(|s| (s.workers.len(), s.server_tgid)), (1, 400));
    assert_eq!(svc::worker_host(301), None);
    assert_eq!(svc::worker_host(402), Some(LXS_TEST));
}

#[test]
fn attach_and_objarea_fail_without_memory() {
    let sim = world();
    // (the object area is made once per host and kept: start without one)
    obj::tests::drop_area(svc::host_or_make(LXS_TEST, ENDPOINT_SVC_TEST));
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(server_task(301, 300, ENDPOINT_SVC_TEST), move || {
        crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
        r2.lock().unwrap().push(ctl(LX_CTL_ATTACH));
        crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
        r2.lock().unwrap().push(ctl(LX_CTL_OBJAREA));
        // Mapped (the area is made once and kept)
        let a = ctl(LX_CTL_OBJAREA);
        r2.lock().unwrap().push((a > 0) as i64);
    });
    // No address space: the page cannot be mapped
    sim.spawn(Task::server(303, 300, ENDPOINT_SVC_TEST), {
        let r = r.clone();
        move || r.lock().unwrap().push(ctl(LX_CTL_ATTACH))
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![ENOMEM, -12, 1, EFAULT]);
}

#[test]
fn online_needs_the_host_its_window_and_workers() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(server_task(300, 300, ENDPOINT_SVC_TEST), move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        // No host yet (no worker attached)
        if svc::host(LXS_TEST).is_none() {
            push(ctl(LX_CTL_ONLINE));
        } else {
            push(EINVAL);
        }
        svc::host_or_make(LXS_TEST, ENDPOINT_SVC_TEST);
        // No window: the endpoint is not registered
        push(ctl(LX_CTL_ONLINE));
        crate::ipc::service::register(ENDPOINT_SVC_TEST).unwrap();
        // No workers
        push(ctl(LX_CTL_ONLINE));
        assert!(ctl(LX_CTL_ATTACH) > 0);
        // The object area cannot be made
        crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
        let x = svc::host(LXS_TEST).unwrap();
        obj::tests::drop_area(x);
        push(ctl(LX_CTL_ONLINE));
        push(ctl(LX_CTL_ONLINE));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![EINVAL, EINVAL, EINVAL, ENOMEM, 0]);
    assert!(svc::host(LXS_TEST).unwrap().is_online());
    assert!(crate::fake::logged("[lx] test online (process 300, endpoint 0x32, 1 workers)"));
}

#[test]
fn a_worker_woken_after_its_service_went_away_ends() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    server_gone(LXS_TEST);
    // (killed with its process; a stray wake-up finds it in no table)
    sim.with_task(s.workers[0], |t| t.state = crate::task::TaskState::Ready);
    sim.run_others();
    assert_eq!(sim.state(s.workers[0]), crate::task::TaskState::Dead);
}

// ----------------------------------------------------------------------
// The notification ring
// ----------------------------------------------------------------------

#[test]
fn process_events_go_to_subscribed_hosts() {
    let sim = world();
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    let t = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    note(LX_NOTE_FORK, 100, 101, 0);
    note(LX_NOTE_EXIT, 101, 0, 9);
    note(70, 1, 2, 3);
    assert_eq!(notes(l.x), vec![[LX_NOTE_FORK, 100, 101, 0], [LX_NOTE_EXIT, 101, 0, 9]]);
    assert!(notes(t.x).is_empty());
    assert_eq!(l.x.notes_head(), 2);
    assert_ne!(crate::ipc::service::tests::pending_bits(l.ep) & NOTIFY_LX_NOTES, 0);
    // A call made now carries the ring position
    note_to(LXS_TEST, LX_NOTE_CLOSE, 5, 1, 0);
    assert_eq!(notes(t.x), vec![[LX_NOTE_CLOSE, 5, 1, 0]]);
    // An offline host gets nothing
    note_to(LXS_SEC, LX_NOTE_CLOSE, 1, 1, 0);
    assert!(!note_quiet_to(svc::host_or_make(LXS_SEC, ENDPOINT_LX_SEC), 1, 0, 0, 0));
}

#[test]
fn a_full_ring_counts_what_it_drops() {
    let sim = world();
    let t = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    let w = t.x.notes.load(Ordering::Acquire) as *mut u64;
    // SAFETY: the ring's header in the window
    unsafe {
        *w = LX_NOTES;
        *w.add(1) = 0;
    }
    note_to(LXS_TEST, LX_NOTE_CLOSE, 1, 0, 0);
    note_to(LXS_TEST, LX_NOTE_CLOSE, 2, 0, 0);
    // SAFETY: as above
    unsafe {
        assert_eq!(*w, LX_NOTES, "nothing was added");
        assert_eq!(*w.add(2), 2, "two dropped");
    }
}

#[test]
fn the_doorbell_hook_and_unknown_endpoints() {
    let sim = world();
    let t = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    // Readiness changed: handled by the objects' doorbell (nothing marked: nothing to do)
    on_signal_for::<{ ENDPOINT_SVC_TEST }>(LX_SIGNAL_OBJS);
    on_signal_for::<{ ENDPOINT_SVC_TEST }>(0);
    assert!(t.x.is_online());
    // An endpoint no service has
    on_signal_for::<0x7777>(crate::ipc::service::SIGNAL_GONE);
    // linux-server's own hook (not running: its host is offline anyway)
    on_signal(0);
    on_signal(crate::ipc::service::SIGNAL_GONE);
    assert!(t.x.is_online());
}

// ----------------------------------------------------------------------
// Diagnostics
// ----------------------------------------------------------------------

#[test]
fn dump_and_stats_describe_the_hosts() {
    let sim = world();
    assert_eq!(stats(), (false, 0, 0, 0, 0, 0, 0));
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    let l = start(&sim, LXS_LINUX, 200, 2, true, handler(move |s| {
        i2.store(s.call.id, Ordering::Release);
        (0, LX_REPLY_PENDING)
    }));
    sim.spawn(Task::linux(101, 100), || {
        crate::world::bkl_enter();
        let _ = forward(&frame(LX_NULL_NR, [1, 0, 0, 0, 0, 0]));
    });
    sim.run_others();
    let (online, workers, idle, inflight, direct, queued, failed) = stats();
    assert!(online);
    assert_eq!((workers, idle, inflight, direct, queued, failed), (2, 2, 1, 1, 0, 0));
    dump();
    let out = crate::fake::rec(|r| r.serial.clone());
    assert!(out.contains("[lx] online true"), "{out}");
    assert!(out.contains("[lx] linux worker 0 task 201 idle true"), "{out}");
    assert!(out.contains(&format!("[lx] linux req slot 0 id {:#x} Pending client 101", id.load(Ordering::Relaxed))), "{out}");
    // A table someone holds is not waited for
    let g = l.x.table.lock();
    crate::fake::rec(|r| r.serial.clear());
    dump();
    drop(g);
    assert!(crate::fake::rec(|r| r.serial.contains("[lx] linux: request table locked")));
}

#[test]
fn delivery_maybe_follows_the_identity_cache() {
    let _sim = world();
    // No identity cached for this thread: deliver the ordinary way
    assert!(delivery_maybe());
    x86_64::instructions::interrupts::without_interrupts(|| assert!(ident().is_some()));
    assert!(!delivery_maybe());
    crate::fake::set_signal(100, true);
    assert!(delivery_maybe());
}

#[test]
fn the_lock_free_path_serves_only_plain_linux_threads() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| (s.call.ngroups as i64 + 100, 0)));
    // The test call's groups are not sent
    match fast_entry(&frame(LX_TEST_NR, [0; 6])) {
        Some(Fast::Call(r)) => assert_eq!(r, 100),
        _ => panic!("not forwarded"),
    }
    // ... the cached identity is used the second time
    assert!(matches!(fast_entry(&frame(LX_TEST_NR, [0; 6])), Some(Fast::Call(100))));
    // Not forwarded: a kernel call, tracing on, a hand-off in progress
    assert!(fast_entry(&frame(39, [0; 6])).is_none());
    crate::compat::linux::TRACE_SYSCALLS.store(true, Ordering::Release);
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    crate::compat::linux::TRACE_SYSCALLS.store(false, Ordering::Release);
    crate::task::scheduler::HANDOFF_ACTIVE.store(true, Ordering::Release);
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    crate::task::scheduler::HANDOFF_ACTIVE.store(false, Ordering::Release);
    // A traced thread, a seccomp filter (the identity is filled again after a change)
    crate::fake::TRACED.lock().unwrap().insert(100);
    crate::fake::EPOCH.fetch_add(1, Ordering::AcqRel);
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    crate::fake::TRACED.lock().unwrap().clear();
    sim.with_task(100, |t| t.seccomp.mode = 2);
    crate::fake::EPOCH.fetch_add(1, Ordering::AcqRel);
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    sim.with_task(100, |t| t.seccomp.mode = 0);
    crate::fake::EPOCH.fetch_add(1, Ordering::AcqRel);
    // The process table busy while the identity is filled: not this path
    let g = crate::compat::linux::proc::PROCS.lock();
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    drop(g);
    // The service offline
    svc::host(LXS_TEST).unwrap().online.store(false, Ordering::Release);
    assert!(fast_entry(&frame(LX_TEST_NR, [0; 6])).is_none());
    // A SYS_LX_REPLY_RECV of a thread that is no worker: the ordinary path
    assert!(fast_entry(&frame(crate::arch::syscall::SYS_LX_REPLY_RECV, [0; 6])).is_none());
}

// ----------------------------------------------------------------------
// The kernel's requests to a service's main thread
// ----------------------------------------------------------------------

/// Writes `text` where the `/proc` texts go and answers its length.
fn answer_text(text: &'static str) -> impl Fn(crate::ipc::Message, &mut [u8]) -> crate::ipc::Message + Send {
    move |_m, win| {
        win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + text.len()].copy_from_slice(text.as_bytes());
        crate::ipc::Message::with_args(MSG_LX_REPLY, [text.len() as u64, 0, 0, 0])
    }
}

#[test]
fn proc_net_text_comes_from_the_network_service() {
    let sim = world();
    assert_eq!(proc_net_text("tcp"), None);
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    let asked = StdArc::new(StdMutex::new(Vec::new()));
    let a2 = asked.clone();
    let text = answer_text("  sl  local_address\n");
    serve_main(&sim, 250, 200, l.ep, move |m, w| {
        a2.lock().unwrap().push((m.label, m.args[0], m.args[1]));
        text(m, w)
    });
    sim.run_others();
    assert_eq!(proc_net_text("tcp6").as_deref(), Some("  sl  local_address\n"));
    assert_eq!(proc_net_text("udp").as_deref(), Some("  sl  local_address\n"));
    assert_eq!(proc_net_text("raw"), None);
    assert_eq!(*asked.lock().unwrap(), vec![(MSG_LX_PROC_NET, 1, 0), (MSG_LX_PROC_NET, 2, 0)]);
    // Unix sockets: from the IPC service once step 4 moved them
    assert_eq!(proc_net_unix_text().as_deref(), Some("  sl  local_address\n"));
    STEP4.store(false, Ordering::Release);
    assert_eq!(proc_net_unix_text(), None);
    // Internet sockets still the kernel's
    set_forwarding(false);
    assert_eq!(proc_net_text("tcp"), None);
}

#[test]
fn proc_keys_text_comes_from_the_key_service() {
    let sim = world();
    // lx-sec not running: an empty file
    assert_eq!(proc_keys_text().as_deref(), Some(""));
    let s = start(&sim, LXS_SEC, 500, 1, true, handler(|_| (0, 0)));
    let groups = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = groups.clone();
    let text = answer_text("0001 key\n");
    serve_main(&sim, 550, 500, s.ep, move |m, w| {
        assert_eq!(m.label, MSG_LX_PROC_KEYS);
        assert_eq!((m.args[0], m.args[1]), (100, 100));
        let n = u32::from_le_bytes(w[LX_PROC_KEYS_GROUPS_OFF..LX_PROC_KEYS_GROUPS_OFF + 4].try_into().unwrap()) as usize;
        for i in 0..n {
            let o = LX_PROC_KEYS_GROUPS_OFF + 4 + 4 * i;
            g2.lock().unwrap().push(u32::from_le_bytes(w[o..o + 4].try_into().unwrap()));
        }
        text(m, w)
    });
    sim.run_others();
    assert_eq!(proc_keys_text().as_deref(), Some("0001 key\n"));
    assert_eq!(*groups.lock().unwrap(), vec![1000, 27]);
    // A failing answer: empty
    // The key calls in the kernel: the in-kernel table answers
    set_forwarding(false);
    assert_eq!(proc_keys_text(), None);
}

#[test]
fn window_text_fails_without_a_window_or_on_an_error_answer() {
    let sim = world();
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    serve_main(&sim, 250, 200, l.ep, |_m, _w| crate::ipc::Message::with_args(MSG_LX_REPLY, [(-5i64) as u64, 0, 0, 0]));
    sim.run_others();
    assert_eq!(proc_net_text("tcp"), None);
    // linux-server's endpoint without a window (never registered here: the VFS endpoint)
    assert_eq!(window_text(LXS_VFS, crate::ipc::Message::new(0), |_| {}), None);
}

// ----------------------------------------------------------------------
// The crash policy's recovery task
// ----------------------------------------------------------------------

#[test]
fn recovery_waits_for_linux_server_and_restarts_the_login_screen() {
    let sim = world();
    let x = svc::host_or_make(LXS_LINUX, ENDPOINT_LINUX_SERVER);
    x.recovering.store(true, Ordering::Release);
    // linux-server does not come back within a minute
    let r = std::panic::catch_unwind(recover_task);
    assert!(r.is_err(), "the task exits");
    assert!(crate::fake::logged("linux-server did not come back"));
    assert!(!x.recovering.load(Ordering::Relaxed));
    // It is back, and the display manager ran: the login screen starts again
    x.online.store(true, Ordering::Release);
    crate::fake::rec(|r| r.display_manager = true);
    let _ = std::panic::catch_unwind(recover_task);
    assert_eq!(crate::fake::rec(|r| r.plasma), 1);
    assert!(crate::fake::logged("starting the login screen again"));
    crate::fake::rec(|r| r.display_manager = false);
    let _ = std::panic::catch_unwind(recover_task);
    assert!(crate::fake::logged("[lx] linux-server is back"));
    let _ = sim;
}

#[test]
fn summary_includes_restarts_and_copies() {
    let _sim = world();
    let s = summary();
    assert!(s.contains("restarts: 0 calls waited"), "{s}");
    assert!(s.contains("; copies: "), "{s}");
}
