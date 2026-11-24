//! `src/lx/dcall.rs`: the call order, direct calls between services (delegation, copies,
//! own pool), posts, ops 3-7.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::{frame, handler, notes, start, test_call, world, Seen};
use std::sync::{Arc as StdArc, Mutex as StdMutex};

#[test]
fn the_call_order_goes_down_only() {
    let _sim = world();
    assert_eq!(rank(LXS_LINUX), 5);
    assert_eq!(rank(LXS_TEST), 1);
    assert_eq!(rank(0), 0);
    assert!(allowed(LXS_LINUX, LXS_TEST, 5));
    assert!(!allowed(LXS_TEST, LXS_LINUX, 5));
    // The null operation is allowed on every edge
    assert!(allowed(LXS_TEST, LXS_LINUX, LX_DCALL_OP_NULL));
    assert!(!allowed(LXS_MAX as u8, 1, 0));
    // The supervisor adds and removes edges
    allow(LXS_TEST, LXS_LINUX, true);
    assert!(allowed(LXS_TEST, LXS_LINUX, 5));
    allow(LXS_TEST, LXS_LINUX, false);
    assert!(!allowed(LXS_TEST, LXS_LINUX, 5));
    allow(LXS_MAX as u8, 1, true);
    // Programs may not set edges
    assert_eq!(svc_op(3, 0, 0, 0), EPERM);
    assert_eq!(svc_op(9, 0, 0, 0), EINVAL);
    assert!(summary().contains("direct calls between services"));
}

#[test]
fn a_direct_call_made_for_a_program_carries_its_identity() {
    let sim = world();
    crate::fake::user_space_on();
    sim.with_task(100, |t| t.mm = Some(crate::memory::vm::Mm::shared()));
    let seen: Seen = StdArc::new(StdMutex::new(Vec::new()));
    let s2 = seen.clone();
    let mine = StdArc::new(StdMutex::new(vec![1u8, 2, 3]));
    let mp = mine.lock().unwrap().as_ptr() as u64;
    // The callee: echoes its input doubled, and reads the program's memory by delegation
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        s2.lock().unwrap().push(s.call);
        let inp = s.input(1).unwrap_or_default();
        let out: Vec<u8> = inp.iter().map(|b| b * 2).collect();
        s.output(2, &out);
        let mut b = [0u8; 3];
        let r = crate::lx::client_mem(crate::lx::MemOp::Read, s.call.on_behalf, mp, 3, b.as_mut_ptr() as u64);
        assert_eq!((r, b), (3, [1, 2, 3]));
        assert!(may_use(s.call.on_behalf));
        (out.len() as i64, 0)
    }));
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    // The caller: linux-server's worker, serving a program's call
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| {
        let inp = [5u8, 6, 7];
        let mut out = [0u8; 8];
        let r = dcall(s.tid, 0, [LXS_TEST as u64, 9, inp.as_ptr() as u64, 3, out.as_mut_ptr() as u64, 8], true);
        g2.lock().unwrap().push((r, out, s.call.id));
        // The lock-free entry, too
        let r2 = match crate::lx::fast_entry(&frame(crate::arch::syscall::SYS_SVC_DCALL, [LXS_TEST as u64, 9, inp.as_ptr() as u64, 1, out.as_mut_ptr() as u64, 8])) {
            Some(crate::lx::Fast::Reply(v)) => v,
            _ => -1000,
        };
        (r2, 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(crate::lx::forward(&frame(LX_NULL_NR, [0; 6])), Some(1));
    let g = got.lock().unwrap().clone();
    assert_eq!((g[0].0, &g[0].1[..3]), (3, &[10u8, 12, 14][..]));
    let c = seen.lock().unwrap()[0];
    assert_eq!((c.nr, c.tid, c.tgid, c.uid, c.from_svc, c.dcall_op, c.on_behalf), (LX_DCALL_NR, 100, 100, 1000, LXS_LINUX as u32, 9, g[0].2));
    assert_eq!(c.args[5], LXS_LINUX as u64);
    assert_eq!(DCALLS.load(Ordering::Relaxed), 2);
    // The delegation ended with the answer
    assert!(!delegated(201, g[0].2));
    let mut buf = [0u64; 4];
    assert_eq!(svc_op(4, buf.as_mut_ptr() as u64, 0, 0), 0);
    assert_eq!(buf[0], 2);
    assert_eq!(svc_op(4, 0, 0, 0), -14);
}

#[test]
fn direct_calls_that_are_refused() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        let me = s.tid;
        let push = |v: i64| r2.lock().unwrap().push(v);
        let b = [0u8; 4];
        let p = b.as_ptr() as u64;
        let size = LX_DATA_SIZE as u64;
        // Bad targets, an edge up the order, sizes, NULL buffers
        push(dcall(me, 0, [0, 1, 0, 0, 0, 0], false));
        push(dcall(me, 0, [LXS_MAX as u64, 1, 0, 0, 0, 0], false));
        push(dcall(me, 0, [LXS_LINUX as u64, 1, 0, 0, 0, 0], false));
        push(dcall(me, 0, [LXS_TEST as u64, 0, p, size + 1, 0, 0], false));
        push(dcall(me, 0, [LXS_TEST as u64, 0, p, 0, p, size + 1], false));
        push(dcall(me, 0, [LXS_TEST as u64, 0, p, size, p, 1], false));
        push(dcall(me, 0, [LXS_TEST as u64, 0, 0, 4, 0, 0], false));
        push(dcall(me, 0, [LXS_TEST as u64, 0, 0, 0, 0, 4], false));
        // Its own pool, whose only worker is this one (busy): EAGAIN
        push(dcall(me, 0, [LXS_TEST as u64, LX_DCALL_OP_NULL, 0, 0, 0, 0], false));
        // Targets not running
        push(dcall(me, 0, [LXS_SEC as u64, LX_DCALL_OP_NULL, 0, 0, 0, 0], false));
        push(dcall(me, 0, [LXS_VFS as u64, LX_DCALL_OP_NULL, 0, 0, 0, 0], false));
        (0, 0)
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), 0);
    assert_eq!(*r.lock().unwrap(), vec![EINVAL, EINVAL, EPERM, EINVAL, EINVAL, EINVAL, EINVAL, EINVAL, EAGAIN, ENOSYS, ENOSYS]);
    assert_eq!(DCALLS_REFUSED.load(Ordering::Relaxed), 1);
    // A program is no service
    assert_eq!(dcall(100, 0, [LXS_TEST as u64, 0, 0, 0, 0, 0], false), EPERM);
}

#[test]
fn a_redirect_answer_to_a_direct_call_is_refused_and_bad_input_faults() {
    let sim = world();
    crate::fake::user_space_on();
    start(&sim, LXS_TEST, 300, 1, true, handler(|_| (LXS_LINUX as i64, LX_REPLY_REDIRECT)));
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| {
        r2.lock().unwrap().push(dcall(s.tid, 0, [LXS_TEST as u64, 1, 0, 0, 0, 0], true));
        let bad = crate::fake::alloc_pages(1);
        crate::fake::make_bad(bad);
        r2.lock().unwrap().push(dcall(s.tid, 0, [LXS_TEST as u64, 1, bad, 4, 0, 0], true));
        (0, 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(crate::lx::forward(&frame(LX_NULL_NR, [0; 6])), Some(0));
    assert_eq!(*r.lock().unwrap(), vec![EINVAL, EFAULT]);
}

#[test]
fn a_service_thread_that_is_no_worker_calls_with_its_own_identity() {
    let sim = world();
    let seen: Seen = StdArc::new(StdMutex::new(Vec::new()));
    let s2 = seen.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        s2.lock().unwrap().push(s.call);
        (0, 0)
    }));
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    let r = StdArc::new(StdMutex::new(None));
    let r2 = r.clone();
    let mut t = crate::world::Task::server(250, 200, l.ep);
    t.uid = 7;
    sim.spawn(t, move || {
        crate::world::bkl_enter();
        *r2.lock().unwrap() = Some(dcall(250, 0, [LXS_TEST as u64, 1, 0, 0, 0, 0], false));
    });
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(0));
    let c = seen.lock().unwrap()[0];
    assert_eq!((c.tid, c.uid, c.on_behalf), (250, 7, 0));
}

#[test]
fn posts_go_to_the_targets_ring() {
    let sim = world();
    crate::fake::user_space_on();
    let t = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |_| {
        let push = |v: i64| r2.lock().unwrap().push(v);
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        push(post([LXS_TEST as u64, 3, data.as_ptr() as u64, 16, 0, 0]));
        push(post([0, 3, 0, 0, 0, 0]));
        push(post([LXS_TEST as u64, 1 << 33, 0, 0, 0, 0]));
        push(post([LXS_TEST as u64, 3, 0, 17, 0, 0]));
        push(post([12, 3, 0, 0, 0, 0]));
        push(post([LXS_TEST as u64, 3, 0, 4, 0, 0]));
        push(post([LXS_SEC as u64, 3, 0, 0, 0, 0]));
        (0, 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(crate::lx::forward(&frame(LX_NULL_NR, [0; 6])), Some(0));
    assert_eq!(*r.lock().unwrap(), vec![0, EINVAL, EINVAL, E2BIG, EPERM, EFAULT, ENOSYS]);
    let n: Vec<_> = notes(t.x).into_iter().filter(|e| e[0] == LX_NOTE_POST).collect();
    assert_eq!(n, vec![[LX_NOTE_POST, LXS_LINUX as u64 | 3 << 32 | (LXS_TEST as u64) << 56, 1, 2]]);
    assert_eq!(POSTS.load(Ordering::Relaxed), 1);
    // A program may not post
    assert_eq!(post([LXS_TEST as u64, 3, 0, 0, 0, 0]), EPERM);
}

#[test]
fn delegations_table() {
    let _sim = world();
    assert!(!delegated(1, 0));
    assert!(deleg_add(1, 5));
    assert!(delegated(1, 5));
    deleg_end(1);
    assert!(!delegated(1, 5));
    for i in 0..64 {
        assert!(deleg_add(i + 10, 1));
    }
    assert!(!deleg_add(99, 1));
    // may_use: not a worker
    assert!(!may_use(1));
}

// wave7 GB begin: a dcall to a restarting service waits for it (it failed with ENOSYS)
/// A linux-server thread (no worker) making dcall `op` to the test service from its own
/// task; the result lands in the returned cell.
fn dcall_from_linux_thread(sim: &crate::world::Sim, ep: u32, op: u64) -> StdArc<StdMutex<Option<i64>>> {
    let r = StdArc::new(StdMutex::new(None));
    let r2 = r.clone();
    sim.spawn(crate::world::Task::server(250, 200, ep), move || {
        crate::world::bkl_enter();
        *r2.lock().unwrap() = Some(dcall(250, 0, [LXS_TEST as u64, op, 0, 0, 0, 0], false));
    });
    r
}

#[test]
fn a_direct_call_to_a_restarting_service_waits_for_its_new_instance() {
    let sim = world();
    crate::lx::restart::configure(LXS_TEST, crate::lx::restart::RestartClass::Transparent);
    let old = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (1, 0)));
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    // The test service goes away: it is restarting
    crate::lx::server_gone(LXS_TEST);
    assert!(crate::lx::restart::restarting(LXS_TEST));
    let r = dcall_from_linux_thread(&sim, l.ep, 9);
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), None, "the dcall waits (it was ENOSYS at once)");
    // The new instance comes up: the call is made to it
    let new = start(&sim, LXS_TEST, 400, 1, true, handler(|s| (s.call.dcall_op as i64 * 10, 0)));
    assert!(core::ptr::eq(old.x, new.x));
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(90));
}

#[test]
fn a_direct_call_to_a_service_that_does_not_come_back_fails_with_eio() {
    let sim = world();
    // FailObjects (the default): callers wait at most 30 s after the crash
    start(&sim, LXS_TEST, 300, 1, true, handler(|_| (1, 0)));
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    crate::lx::server_gone(LXS_TEST);
    let t0 = crate::arch::pit::now_ns();
    let r = dcall_from_linux_thread(&sim, l.ep, 9);
    sim.settle();
    assert_eq!(*r.lock().unwrap(), None, "it waits");
    sim.sleep(31 * crate::arch::pit::frequency_hz());
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(EIO));
    assert!(crate::arch::pit::now_ns() - t0 >= 30_000_000_000);
    // Given up by the ladder: EIO at once; never started at all: ENOSYS
    crate::lx::restart::tests::set_restarting(LXS_TEST, false);
    crate::lx::restart::tests::set_down(LXS_TEST, true);
    let r = dcall_from_linux_thread(&sim, l.ep, 9);
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(EIO));
    crate::lx::restart::tests::set_down(LXS_TEST, false);
    let r = dcall_from_linux_thread(&sim, l.ep, 9);
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(ENOSYS));
}

#[test]
fn a_direct_call_being_served_when_its_target_dies_fails_with_eio_and_a_queued_one_is_sent_again() {
    let sim = world();
    crate::lx::restart::configure(LXS_TEST, crate::lx::restart::RestartClass::Transparent);
    // The first call (op 1) dies with the instance after the second one (op 2) queued
    start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        if s.call.dcall_op == 1 {
            crate::task::yield_now();
            crate::lx::server_gone(LXS_TEST);
        }
        (s.call.dcall_op as i64, 0)
    }));
    let l = start(&sim, LXS_LINUX, 200, 1, true, handler(|_| (0, 0)));
    let first = dcall_from_linux_thread(&sim, l.ep, 1);
    let r2 = StdArc::new(StdMutex::new(None));
    let r3 = r2.clone();
    sim.spawn(crate::world::Task::server(251, 200, l.ep), move || {
        crate::world::bkl_enter();
        *r3.lock().unwrap() = Some(dcall(251, 0, [LXS_TEST as u64, 2, 0, 0, 0, 0], false));
    });
    sim.settle();
    assert_eq!(*first.lock().unwrap(), Some(EIO), "a dcall is not known to be idempotent");
    assert_eq!(*r2.lock().unwrap(), None, "the queued one waits");
    start(&sim, LXS_TEST, 400, 1, true, handler(|s| (s.call.dcall_op as i64 * 100, 0)));
    sim.settle();
    assert_eq!(*r2.lock().unwrap(), Some(200));
}
// wave7 GB end
