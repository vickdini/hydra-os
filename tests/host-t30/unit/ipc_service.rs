//! Tests of `src/ipc/service.rs`: requests by id, hand-off and queued calls, the direct
//! path, grants, notifications and doorbells, windows, device access, interrupts.

use super::*;
use crate::ipc::protocol::*;
use crate::world::{Ev, Sim, Task};
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::Arc as StdArc;
use std::sync::Mutex as StdMutex;

/// Every request, grant, window holder, interrupt line and service back to boot state
/// (windows, once allocated, are kept: as in the kernel).
pub(crate) fn reset() {
    *REQUESTS.lock() = [Request::FREE; MAX_REQUESTS];
    for i in 0..MAX_REQUESTS {
        QUEUED_CALLER[i].store(0, Ordering::Release);
        QUEUED_OWNER[i].store(0, Ordering::Release);
        REQ_ANSWERED[i].store(false, Ordering::Release);
    }
    for s in SERVICES.iter() {
        s.server.store(0, Ordering::Release);
        s.grants.lock().clear();
        s.irq_notify.store(core::ptr::null_mut(), Ordering::Release);
        s.clients.lock().clear();
        s.notify.store(0, Ordering::Release);
        s.irq_forward.store(0, Ordering::Release);
        s.signal_hook.store(0, Ordering::Release);
        s.parked.store(0, Ordering::Release);
        s.parked_idx.store(0, Ordering::Release);
    }
    WINDOW_HOLDERS.lock().clear();
    WINDOWS_HELD.store(0, Ordering::Release);
    *GRANTS.lock() = [Grant::FREE; MAX_GRANTS];
    GRANTS_MADE.store(0, Ordering::Release);
    for i in 0..IRQ_LINES {
        IRQ_OWNER[i].store(0, Ordering::Release);
        IRQ_PENDING[i].store(0, Ordering::Release);
        IRQ_COUNT[i].store(0, Ordering::Release);
        IRQ_NOTIFIED[i].store(0, Ordering::Release);
        IRQ_SERVICE[i].store(0, Ordering::Release);
    }
    for d in MSI_DEVICE.iter() {
        d.store(0, Ordering::Release);
    }
    DIRECT_ON.store(true, Ordering::Release);
    for c in [&DIRECT_SWITCHED, &DIRECT_WOKEN, &DIRECT_BACK, &DIRECT_SPUN] {
        c.store(0, Ordering::Release);
    }
}

/// Notification bits raised for `endpoint`'s server and not taken yet.
pub(crate) fn pending_bits(endpoint: u32) -> u64 {
    service(endpoint).map_or(0, |s| slot_owner(s).notify.load(Ordering::Acquire))
}

// ----------------------------------------------------------------------
// Harness
// ----------------------------------------------------------------------

const EP: u32 = ENDPOINT_SVC_TEST;

/// A world whose running task is kernel-side caller 100 (no service of its own).
fn world() -> Sim {
    let sim = Sim::new(Task::linux(100, 100));
    crate::lx::tests::reset_all();
    sim
}

/// A driver thread `tid` (process `tid`) of endpoint `ep`, with an address space.
fn driver(tid: u64, ep: u32) -> Task {
    let mut t = Task::server(tid, tid, ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    t
}

/// A server for `ep` (thread `tid`): registers, then answers every request with `f`
/// (`reply_recv`: the direct path's half when `rr`).
fn server(sim: &Sim, tid: u64, ep: u32, rr: bool, f: impl Fn(u64, Message) -> Message + Send + 'static) {
    sim.spawn(driver(tid, ep), move || {
        crate::world::bkl_enter();
        register(ep).expect("register");
        let (mut id, mut m) = recv(ep).expect("recv");
        loop {
            let a = f(id, m);
            if rr {
                (id, m) = reply_recv(ep, id, a, 0).expect("reply_recv");
            } else {
                reply(ep, id, a).expect("reply");
                (id, m) = recv(ep).expect("recv");
            }
        }
    });
    sim.run_others();
    assert_eq!(server_of(ep), tid);
}

fn echo(_id: u64, m: Message) -> Message {
    Message::with_args(m.label + 1, [m.args[0] + 1, 0, 0, 0])
}

fn ask(n: u64) -> Message {
    Message::with_args(0x77, [n, 0, 0, 0])
}

// ----------------------------------------------------------------------
// Calls
// ----------------------------------------------------------------------

#[test]
fn wire_messages_convert_both_ways() {
    let m = Message::with_args(5, [1, 2, 3, 4]);
    let w: WireMessage = m.into();
    assert_eq!((w.label, w.args), (5, [1, 2, 3, 4]));
    let back: Message = w.into();
    assert_eq!((back.label, back.args), (5, [1, 2, 3, 4]));
}

#[test]
fn a_handoff_call_runs_the_server_and_comes_back() {
    let sim = world();
    server(&sim, 200, EP, false, echo);
    assert!(is_online(EP));
    assert!(!is_online(ENDPOINT_LX_IPC));
    sim.clear_log();
    let r = call(EP, ask(41), CALL_TIMEOUT_TICKS).unwrap();
    assert_eq!((r.label, r.args[0]), (0x78, 42));
    let log = sim.log();
    assert!(log.contains(&Ev::Handoff(100, 200)), "{log:?}");
    assert!(log.contains(&Ev::HandoffEnd(100)), "{log:?}");
    assert!(request_list().is_empty());
    // call_once and call_once_mode: the same without a revival
    assert_eq!(call_once(EP, ask(1), 100).unwrap().args[0], 2);
    assert_eq!(call_once_mode(EP, ask(2), 100, CallMode::Queued).unwrap().args[0], 3);
}

#[test]
fn a_queued_call_sleeps_until_the_reply() {
    let sim = world();
    server(&sim, 200, EP, false, echo);
    sim.clear_log();
    assert_eq!(call_queued(EP, ask(9), 100).unwrap().args[0], 10);
    // No hand-off: the caller waited on its request's queue
    assert!(sim.log().iter().all(|e| !matches!(e, Ev::Handoff(..))));
}

#[test]
fn calls_without_a_server() {
    let sim = world();
    // Unknown endpoint; a service nobody serves (the supervisor cannot revive it)
    assert_eq!(call(0x7777, ask(0), 10).err(), Some(ENODEV));
    assert_eq!(call(EP, ask(0), 10).err(), Some(ENODEV));
    assert_eq!(crate::fake::rec(|r| r.revived.clone()), vec![EP]);
    assert_eq!(call_once(EP, ask(0), 10).err(), Some(ENODEV));
    assert_eq!(call_once(0x7777, ask(0), 10).err(), Some(ENODEV));
    let _ = sim;
}

#[test]
fn a_server_calling_itself_would_deadlock() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(None));
    let r2 = r.clone();
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        *r2.lock().unwrap() = Some(call_once(EP, ask(0), 10).err());
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), Some(Some(EDEADLK)));
}

#[test]
fn a_full_request_table_refuses_calls() {
    let sim = world();
    server(&sim, 200, EP, false, echo);
    REQUESTS.lock().iter_mut().for_each(|r| r.state = ReqState::Failed);
    assert_eq!(call_once(EP, ask(0), 10).err(), Some(EBUSY));
    assert!(crate::fake::logged("too many requests in flight"));
    reset();
}

#[test]
fn a_queued_call_times_out_and_its_request_is_abandoned() {
    let sim = world();
    let id = StdArc::new(StdAtomicU64::new(0));
    let i2 = id.clone();
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        let (rid, _) = recv(EP).unwrap();
        i2.store(rid, Ordering::Release);
        // Answers only much later (after the caller gave up)
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + 1000));
        reply(EP, rid, ask(0)).unwrap();
        // A request that is gone cannot be answered again
        assert_eq!(reply(EP, rid, ask(0)), Err(EINVAL));
        loop {
            let _ = recv(EP);
        }
    });
    sim.run_others();
    assert_eq!(call_once_mode(EP, ask(0), 50, CallMode::Queued).err(), Some(ETIMEDOUT));
    assert!(crate::fake::logged("no reply"));
    // Taken by the server: kept (abandoned) until it answers
    let l = request_list();
    assert_eq!(l.len(), 1);
    assert_eq!((l[0].0, l[0].3), (id.load(Ordering::Acquire), "abandoned"));
    sim.run_others();
    for _ in 0..3 {
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + 1000));
    }
    assert!(request_list().is_empty());
}

#[test]
fn a_queued_call_never_taken_is_withdrawn_at_its_deadline() {
    let sim = world();
    // A server that registered and never receives
    sim.spawn(driver(200, EP), || {
        register(EP).unwrap();
        loop {
            crate::task::SCHEDULER.lock().block_current();
            crate::task::yield_now();
        }
    });
    sim.run_others();
    assert_eq!(call_once_mode(EP, ask(0), 20, CallMode::Queued).err(), Some(ETIMEDOUT));
    assert!(request_list().is_empty());
}

#[test]
fn a_signal_ends_a_queued_wait() {
    let sim = world();
    sim.spawn(driver(200, EP), || {
        register(EP).unwrap();
        let _ = recv(EP).unwrap();
        crate::fake::set_signal(100, true);
        crate::world::defer_wakes([100]);
        loop {
            crate::task::SCHEDULER.lock().block_current();
            crate::task::yield_now();
        }
    });
    sim.run_others();
    assert_eq!(call_once_mode(EP, ask(0), 500, CallMode::Queued).err(), Some(EINTR));
}

#[test]
fn a_server_going_away_fails_its_requests() {
    let sim = world();
    let gone = StdArc::new(StdAtomicU64::new(0));
    let g2 = gone.clone();
    set_signal_hook(EP, |bits| {
        if bits == SIGNAL_GONE {
            HOOK.store(1, Ordering::Release);
        }
    });
    static HOOK: StdAtomicU64 = StdAtomicU64::new(0);
    HOOK.store(0, Ordering::Release);
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        let _ = recv(EP).unwrap();
        // The supervisor unregisters it (it died)
        unregister(EP);
        g2.store(1, Ordering::Release);
    });
    sim.run_others();
    // The queued caller wakes with an error at once; no successor: EIO
    assert_eq!(call_queued(EP, ask(0), 500).err(), Some(EIO));
    assert_eq!(gone.load(Ordering::Acquire), 1);
    assert_eq!(HOOK.load(Ordering::Acquire), 1);
    assert!(!is_online(EP));
}

#[test]
fn a_handoff_caller_is_resumed_when_its_server_goes() {
    let sim = world();
    sim.spawn(driver(200, EP), || {
        register(EP).unwrap();
        let _ = recv(EP).unwrap();
        unregister(EP);
    });
    sim.run_others();
    crate::fake::rec(|r| r.revive.insert(EP, false));
    assert_eq!(call(EP, ask(0), 500).err(), Some(EIO));
    assert!(sim.log().contains(&Ev::HandoffEnd(100)));
}

#[test]
fn a_dead_server_is_revived_and_the_call_made_again() {
    let sim = world();
    // The first server dies with the request taken
    sim.spawn(driver(200, EP), || {
        register(EP).unwrap();
        let _ = recv(EP).unwrap();
        unregister(EP);
    });
    // ... the supervisor's revival starts a successor, which registers
    sim.spawn(driver(300, EP), || {
        while crate::fake::rec(|r| r.revived.is_empty()) {
            crate::task::yield_now();
        }
        register(EP).unwrap();
        loop {
            let (id, m) = recv(EP).unwrap();
            reply(EP, id, echo(id, m)).unwrap();
        }
    });
    sim.run_others();
    crate::fake::rec(|r| r.revive.insert(EP, true));
    assert_eq!(call(EP, ask(5), 500).unwrap().args[0], 6);
    assert_eq!(server_of(EP), 300);
}

#[test]
fn disk_calls_are_profiled() {
    let sim = world();
    server(&sim, 200, ENDPOINT_BLOCK_DEV, false, |_, m| Message::with_args(MSG_BLOCK_REPLY, [0, if m.label == MSG_BLOCK_READV { 7 } else { 0 }, 0, 0]));
    call(ENDPOINT_BLOCK_DEV, Message::with_args(MSG_BLOCK_READ, [0, 8, 0, 0]), 100).unwrap();
    call(ENDPOINT_BLOCK_DEV, Message::with_args(MSG_BLOCK_READV, [0, 3, 0, 0]), 100).unwrap();
    call(ENDPOINT_BLOCK_DEV, Message::with_args(MSG_BLOCK_WRITE, [0, 2, 0, 0]), 100).unwrap();
    use crate::compat::linux::prof::{DISK_OTHER, DISK_READ, DISK_READV};
    assert_eq!(crate::fake::rec(|r| r.disk_calls.clone()), vec![(DISK_READ, 8), (DISK_READV, 7), (DISK_OTHER, 2)]);
}

#[test]
fn driver_call_mode_follows_the_handoff() {
    let sim = world();
    assert_eq!(driver_call_mode(), CallMode::Queued);
    let seen = StdArc::new(StdMutex::new(None));
    let s2 = seen.clone();
    server(&sim, 200, EP, false, move |_, m| {
        // Serving a hand-off: its own calls are hand-offs too
        *s2.lock().unwrap() = Some(driver_call_mode());
        m
    });
    call(EP, ask(0), 100).unwrap();
    assert_eq!(*seen.lock().unwrap(), Some(CallMode::Handoff));
}

#[test]
fn queued_callers_are_mirrored_for_the_scheduler() {
    let sim = world();
    let seen = StdArc::new(StdMutex::new(Vec::new()));
    let s2 = seen.clone();
    server(&sim, 200, EP, false, move |_, m| {
        s2.lock().unwrap().push((serves_queued_for(EP, |c| c == 100), serves_queued_for(ENDPOINT_NET_DEV, |_| true), request_list()[0].3));
        m
    });
    call_queued(EP, ask(0), 100).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![(true, false, "delivered")]);
    assert!(!serves_queued_for(EP, |_| true));
}

// ----------------------------------------------------------------------
// The direct path
// ----------------------------------------------------------------------

/// A ring-3 caller (thread 150 of net-server) making a queued call: the direct path.
fn ring3_caller(sim: &Sim, f: impl FnOnce() + Send + 'static) {
    sim.spawn(driver(150, ENDPOINT_NET_SERVER), move || {
        crate::world::bkl_enter();
        f();
    });
}

#[test]
fn a_ring3_queued_call_switches_to_the_parked_server_and_back() {
    let sim = world();
    server(&sim, 200, EP, true, echo);
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    ring3_caller(&sim, move || {
        g2.store(call_queued(EP, ask(1), 100).unwrap().args[0], Ordering::Release);
        g2.fetch_add(call_queued(EP, ask(10), 100).unwrap().args[0] * 100, Ordering::AcqRel);
    });
    sim.clear_log();
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 2 + 1100);
    let log = sim.log();
    assert!(log.contains(&Ev::Direct(150, 200)), "{log:?}");
    assert!(log.contains(&Ev::Direct(200, 150)), "{log:?}");
    assert_eq!(DIRECT_SWITCHED.load(Ordering::Relaxed), 2);
    assert!(DIRECT_BACK.load(Ordering::Relaxed) >= 1);
    assert!(direct_summary().starts_with("direct path on: 2 calls switched straight to the server"));
}

#[test]
fn with_the_direct_path_off_the_server_is_woken() {
    let sim = world();
    server(&sim, 200, EP, false, echo);
    DIRECT_ON.store(false, Ordering::Release);
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    ring3_caller(&sim, move || g2.store(call_queued(EP, ask(1), 100).unwrap().args[0], Ordering::Release));
    sim.settle();
    assert_eq!(got.load(Ordering::Acquire), 2);
    assert_eq!(DIRECT_SWITCHED.load(Ordering::Relaxed), 0);
    assert!(direct_summary().starts_with("direct path off"));
}

#[test]
fn a_server_not_parked_is_woken_the_ordinary_way() {
    let sim = world();
    // The server is busy with a kernel caller's request (it yields while serving it) when
    // the ring-3 call comes: not parked, so it is woken through its queue
    server(&sim, 200, EP, false, |_, m| {
        if m.args[0] == 1 {
            crate::task::yield_now();
        }
        echo(0, m)
    });
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    ring3_caller(&sim, move || g2.store(call_queued(EP, ask(3), 100).unwrap().args[0], Ordering::Release));
    assert_eq!(call_queued(EP, ask(1), 100).unwrap().args[0], 2);
    sim.settle();
    assert_eq!(got.load(Ordering::Acquire), 4);
    assert!(DIRECT_WOKEN.load(Ordering::Relaxed) >= 1);
}

#[test]
fn recv_yield_hands_the_cpu_back_and_stays_ready() {
    let sim = world();
    let order = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = order.clone();
    sim.spawn(driver(200, EP), move || {
        crate::world::bkl_enter();
        register(EP).unwrap();
        let (id, m) = recv(EP).unwrap();
        // Answer, give the caller the CPU, go on without receiving
        let r = reply_recv(EP, id, echo(id, m), RECV_YIELD).unwrap();
        o2.lock().unwrap().push(format!("server back {:#x}", r.1.label));
        loop {
            let _ = recv(EP);
        }
    });
    sim.run_others();
    let o3 = order.clone();
    ring3_caller(&sim, move || {
        let r = call_queued(EP, ask(1), 100).unwrap();
        o3.lock().unwrap().push(format!("caller {}", r.args[0]));
    });
    sim.run_others();
    sim.run_others();
    assert_eq!(*order.lock().unwrap(), vec!["caller 2".to_string(), format!("server back {:#x}", MSG_SVC_NOTIFY)]);
}

#[test]
fn recv_yield_with_a_handoff_or_plain_queued_caller() {
    let sim = world();
    sim.spawn(driver(200, EP), || {
        crate::world::bkl_enter();
        register(EP).unwrap();
        loop {
            let (id, m) = recv(EP).unwrap();
            let _ = reply_recv(EP, id, echo(id, m), RECV_YIELD).unwrap();
        }
    });
    sim.run_others();
    // A hand-off caller, and a queued one without the direct path (a kernel task)
    assert_eq!(call(EP, ask(1), 100).unwrap().args[0], 2);
    assert_eq!(call_queued(EP, ask(2), 100).unwrap().args[0], 3);
}

#[test]
fn reply_recv_answers_handoff_and_plain_queued_callers() {
    let sim = world();
    server(&sim, 200, EP, true, echo);
    assert_eq!(call(EP, ask(1), 100).unwrap().args[0], 2);
    assert_eq!(call_queued(EP, ask(2), 100).unwrap().args[0], 3);
}

#[test]
fn a_direct_caller_spins_for_an_answer_from_another_cpu() {
    let sim = world();
    // Two CPUs: the server (on the other one) answers while the caller spins
    crate::fake::ONLINE_CPUS.store(2, Ordering::Release);
    crate::world::CLOCK_STEP_NS.store(1_000, Ordering::Release);
    server(&sim, 200, EP, false, echo);
    service(EP).unwrap().parked.store(0, Ordering::Release);
    sim.with_task(200, |t| t.state = crate::task::TaskState::Ready);
    // (the answer is marked by the time the caller looks)
    assert!(!spin_for_answer(5));
    REQ_ANSWERED[5].store(true, Ordering::Release);
    crate::world::bkl_enter();
    assert!(spin_for_answer(5));
    assert!(crate::world::bkl_held());
    assert_eq!(DIRECT_SPUN.load(Ordering::Relaxed), 1);
    REQ_ANSWERED[5].store(false, Ordering::Release);
    crate::fake::ONLINE_CPUS.store(1, Ordering::Release);
    assert!(!spin_for_answer(5));
}

#[test]
fn hand_back_and_wake_back_details() {
    let sim = world();
    // hand_back to a caller that is neither blocked nor ready: nothing happens
    hand_back(999, 0);
    // wake_back of nobody
    wake_back(None);
    // During a hand-off the switch is not made (the caller is only made ready)
    sim.spawn(Task::linux(101, 101), || loop {
        crate::task::SCHEDULER.lock().block_current();
        crate::task::yield_now();
    });
    sim.run_others();
    crate::task::scheduler::HANDOFF_ACTIVE.store(true, Ordering::Release);
    hand_back(101, 1);
    assert_eq!(sim.state(101), crate::task::TaskState::Ready);
    crate::task::scheduler::HANDOFF_ACTIVE.store(false, Ordering::Release);
    // switch_to_parked: nothing parked, or a hand-off
    let svc = service(EP).unwrap();
    assert!(!switch_to_parked(svc, 0));
    svc.parked.store(102, Ordering::Release);
    crate::task::scheduler::HANDOFF_ACTIVE.store(true, Ordering::Release);
    assert!(!switch_to_parked(svc, 0));
    crate::task::scheduler::HANDOFF_ACTIVE.store(false, Ordering::Release);
    // A parked mark naming a task that cannot be switched to
    assert!(!switch_to_parked(svc, 0));
    assert_eq!(DIRECT_WOKEN.load(Ordering::Relaxed), 3);
    // wait_clobbered with a deadline already passed returns at once
    wait_clobbered(Some(0));
}

// ----------------------------------------------------------------------
// Server side
// ----------------------------------------------------------------------

#[test]
fn notifications_and_the_receive_timeout() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        // Raised before: taken at once
        let (id, m) = recv_with(EP, RECV_NOTIFY).unwrap();
        g2.lock().unwrap().push((id, m.label, m.args[0]));
        // Nothing raised: back after the timeout with no bits
        let (id, m) = recv_with(EP, RECV_NOTIFY | 5).unwrap();
        g2.lock().unwrap().push((id, m.label, m.args[0]));
        // Raised while it waits
        let (id, m) = recv_with(EP, RECV_NOTIFY).unwrap();
        g2.lock().unwrap().push((id, m.label, m.args[0]));
    });
    notify(EP, 0b101);
    sim.run_others();
    // Time passes: the second receive times out
    sim.sleep(10);
    notify(EP, 0b10);
    sim.settle();
    assert_eq!(*got.lock().unwrap(), vec![(0, MSG_SVC_NOTIFY, 0b101), (0, MSG_SVC_NOTIFY, 0), (0, MSG_SVC_NOTIFY, 0b10)]);
    // Unknown endpoints are ignored
    notify(0x7777, 1);
}

#[test]
fn a_signal_ends_recv() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(None));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        *g2.lock().unwrap() = Some(recv(EP).err());
    });
    sim.run_others();
    crate::fake::set_signal(200, true);
    crate::world::defer_wakes([200]);
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), Some(Some(EINTR)));
}

#[test]
fn the_doorbell_runs_the_clients_hook() {
    let sim = world();
    static BITS: StdAtomicU64 = StdAtomicU64::new(0);
    BITS.store(0, Ordering::Release);
    set_signal_hook(EP, |b| {
        BITS.store(b, Ordering::Release);
    });
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        g2.lock().unwrap().push(signal(EP, 0x55));
        g2.lock().unwrap().push(signal(ENDPOINT_NET_DEV, 1));
    });
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), vec![Ok(()), Err(EPERM)]);
    assert_eq!(BITS.load(Ordering::Acquire), 0x55);
    // Unknown endpoints: nothing to set
    set_signal_hook(0x7777, |_| {});
    forward_irq(0x7777, 1);
    set_grants(0x7777, vec![]);
    allow_client(0x7777, 1);
}

#[test]
fn reply_by_id_zero_answers_the_oldest_and_unknown_ids_fail() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        register(EP).unwrap();
        let (a, _) = recv(EP).unwrap();
        let (b, _) = recv(EP).unwrap();
        g2.lock().unwrap().push(reply(EP, 12345, ask(0)));
        // id 0: the oldest taken
        g2.lock().unwrap().push(reply(EP, 0, ask(100)));
        g2.lock().unwrap().push(reply(EP, b, ask(200)));
        let _ = a;
        // Not its endpoint
        g2.lock().unwrap().push(reply(ENDPOINT_NET_DEV, 1, ask(0)));
        loop {
            let _ = recv(EP);
        }
    });
    sim.run_others();
    let r1 = StdArc::new(StdAtomicU64::new(0));
    let r2 = r1.clone();
    sim.spawn(Task::linux(101, 101), move || r2.store(call_queued(EP, ask(1), 100).unwrap().args[0], Ordering::Release));
    let mine = call_queued(EP, ask(2), 100).unwrap().args[0];
    sim.run_others();
    sim.settle();
    // This task's call came first (its id is older), so id 0 answered it
    assert_eq!((r1.load(Ordering::Acquire), mine), (200, 100));
    assert_eq!(*got.lock().unwrap(), vec![Err(EINVAL), Ok(()), Ok(()), Err(EPERM)]);
}

#[test]
fn register_needs_the_endpoint_memory_and_an_address_space() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    // A program may not register
    assert_eq!(register(EP).err(), Some(EPERM));
    // The sound driver's window is made the first time (never before in this run)
    let g3 = g2.clone();
    sim.spawn(driver(200, ENDPOINT_SOUND_DEV), move || {
        if window(ENDPOINT_SOUND_DEV).is_none() {
            crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
            g3.lock().unwrap().push(register(ENDPOINT_SOUND_DEV).err());
        } else {
            g3.lock().unwrap().push(Some(ENOMEM));
        }
    });
    // Without an address space the window cannot be mapped
    sim.spawn(Task::server(201, 201, EP), move || g2.lock().unwrap().push(register(EP).err()));
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), vec![Some(ENOMEM), Some(EFAULT)]);
}

#[test]
fn attach_maps_a_service_window_for_its_clients() {
    let sim = world();
    server(&sim, 200, ENDPOINT_BLOCK_DEV, false, echo);
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(300, ENDPOINT_ZFS_SERVER), move || {
        g2.lock().unwrap().push(attach(ENDPOINT_BLOCK_DEV).err());
        allow_client(ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER);
        allow_client(ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER);
        let a = attach(ENDPOINT_BLOCK_DEV);
        g2.lock().unwrap().push(a.err());
        assert!(a.unwrap() > 0);
        g2.lock().unwrap().push(attach(0x7777).err());
    });
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), vec![Some(EPERM), None, Some(ENODEV)]);
    assert_eq!(service(ENDPOINT_BLOCK_DEV).unwrap().clients.lock().len(), 1);
    // A program is no client; a service whose server went is not attached to
    assert_eq!(attach(ENDPOINT_BLOCK_DEV).err(), Some(EPERM));
    service(ENDPOINT_BLOCK_DEV).unwrap().server.store(0, Ordering::Release);
    let g4 = got.clone();
    sim.spawn(driver(301, ENDPOINT_ZFS_SERVER), move || g4.lock().unwrap().push(attach(ENDPOINT_BLOCK_DEV).err()));
    sim.run_others();
    assert_eq!(got.lock().unwrap()[3], Some(ENODEV));
}

#[test]
fn the_usb_disks_are_served_by_the_usb_drivers_process() {
    let sim = world();
    assert_eq!(primary_of(ENDPOINT_USB_DISK), ENDPOINT_INPUT_DEV);
    assert_eq!(primary_of(EP), EP);
    assert_eq!(primary_of(0x7777), 0x7777);
    // The input driver takes the disk requests too
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, ENDPOINT_INPUT_DEV), move || {
        register(ENDPOINT_INPUT_DEV).unwrap();
        register(ENDPOINT_USB_DISK).unwrap();
        let (id, m) = recv(ENDPOINT_INPUT_DEV).unwrap();
        g2.lock().unwrap().push(m.args[0]);
        reply(ENDPOINT_USB_DISK, id, echo(id, m)).unwrap();
        loop {
            let _ = recv(ENDPOINT_INPUT_DEV);
        }
    });
    sim.run_others();
    assert_eq!(call(ENDPOINT_USB_DISK, ask(4), 100).unwrap().args[0], 5);
    assert_eq!(*got.lock().unwrap(), vec![4]);
    notify(ENDPOINT_USB_DISK, 8);
    assert_eq!(pending_bits(ENDPOINT_INPUT_DEV), 8);
    // Its process goes: the aliases go with it
    unregister(ENDPOINT_INPUT_DEV);
    assert!(!is_online(ENDPOINT_USB_DISK));
}

// ----------------------------------------------------------------------
// Windows
// ----------------------------------------------------------------------

#[test]
fn window_holders_nest_and_are_released() {
    let sim = world();
    {
        let _a = hold_window(EP);
        let _b = hold_window(EP);
        assert_eq!(window_holders(), vec![(EP, 100)]);
        assert!(holds_window(100));
        assert!(!window_held_by_other(100));
        assert!(window_held_by_other(5));
        drop(_b);
        assert!(holds_window(100));
    }
    assert!(!holds_window(100));
    assert!(!window_held_by_other(5));
    // A quiet holder (queued calls only) does not hold other kernel code back
    {
        let _q = hold_window_queued(EP);
        assert!(holds_window(100));
        assert!(!window_held_by_other(5));
    }
    // A task that ended in the middle of a call: its windows go
    let g = hold_window(EP);
    let g2 = hold_window(ENDPOINT_NET_DEV);
    core::mem::forget(g);
    core::mem::forget(g2);
    release_windows(100);
    assert!(window_holders().is_empty());
    assert_eq!(WINDOWS_HELD.load(Ordering::Relaxed), 0);
    let _ = sim;
}

#[test]
fn a_window_another_task_holds_is_waited_for() {
    let sim = world();
    let order = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = order.clone();
    sim.spawn(Task::linux(101, 101), move || {
        let g = hold_window(EP);
        o2.lock().unwrap().push("101 holds");
        crate::task::yield_now();
        o2.lock().unwrap().push("101 lets go");
        drop(g);
    });
    sim.run_others();
    // This task waits (a timer tick in its waiting loop lets 101 finish)
    crate::world::PREEMPT_IN_BKL_EXIT.store(4, Ordering::Release);
    let g = hold_window(EP);
    order.lock().unwrap().push("100 holds");
    drop(g);
    assert_eq!(*order.lock().unwrap(), vec!["101 holds", "101 lets go", "100 holds"]);
}

// ----------------------------------------------------------------------
// Grants
// ----------------------------------------------------------------------

#[test]
fn a_grant_lends_the_callers_pages_for_one_request() {
    let sim = world();
    let segs = StdArc::new(StdMutex::new(Vec::new()));
    let s2 = segs.clone();
    server(&sim, 200, EP, false, move |id, m| {
        *s2.lock().unwrap() = vec![grant_segments(EP, id), grant_segments(EP, id + 1000), grant_segments(ENDPOINT_NET_DEV, id)];
        m
    });
    let buf = crate::fake::alloc_pages(3);
    let mut spec = GrantSpec { ranges: [(0, 0); GRANT_RANGES], n: 2, server_writes: true };
    spec.ranges[0] = (buf + 100, 5000);
    spec.ranges[1] = (buf + 8192, 0);
    let got = StdArc::new(StdMutex::new(None));
    let g2 = got.clone();
    sim.spawn(driver(150, ENDPOINT_ZFS_SERVER), move || {
        *g2.lock().unwrap() = Some(call_with(EP, ask(1), 100, CallMode::Queued, Some(&spec)).map(|m| m.args[0]));
    });
    sim.run_others();
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), Some(Ok(1)));
    let s = segs.lock().unwrap().clone();
    // Host memory is physically contiguous here: one merged segment
    assert_eq!(s[0], Ok((vec![(buf + 100, 5000)], true)));
    assert_eq!(s[1], Err(EINVAL));
    assert_eq!(s[2], Err(EPERM));
    // Pinned while the server could use them, unpinned with the answer
    assert_eq!(crate::fake::frame_refs(buf), 0);
    assert_eq!(crate::fake::frame_refs(buf + 4096), 0);
    assert_eq!(GRANTS_MADE.load(Ordering::Relaxed), 1);
    // The IOMMU domain held the segment meanwhile
    let dma = crate::fake::rec(|r| r.dma.clone());
    assert_eq!(dma, vec![(true, EP, buf + 100, 5000), (false, EP, buf + 100, 5000)]);
}

#[test]
fn grants_that_cannot_be_made() {
    let sim = world();
    let buf = crate::fake::alloc_pages(2);
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(driver(150, ENDPOINT_ZFS_SERVER), move || {
        let mut spec = GrantSpec { ranges: [(buf, 10); GRANT_RANGES], n: 0, server_writes: false };
        let push = |v: Result<u8, i64>| r2.lock().unwrap().push(v);
        push(make_grant(&spec, EP));
        spec.n = GRANT_RANGES + 1;
        push(make_grant(&spec, EP));
        // A range that wraps
        spec.n = 1;
        spec.ranges[0] = (u64::MAX - 10, 100);
        push(make_grant(&spec, EP));
        // Too many pages
        spec.ranges[0] = (buf, 300 * 4096);
        push(make_grant(&spec, EP));
        // A page that is not there
        spec.ranges[0] = (buf, 10);
        crate::fake::make_bad(buf);
        push(make_grant(&spec, EP));
        crate::fake::BAD.lock().unwrap().clear();
        // The IOMMU refuses: EINVAL (the caller falls back to the window)
        crate::fake::rec(|r| r.dma_fail = 1);
        push(make_grant(&spec, EP));
        // Sixteen alive: the 17th waits for one
        for _ in 0..MAX_GRANTS {
            assert!(make_grant(&spec, EP).is_ok());
        }
        push(make_grant(&spec, EP));
        for g in 1..=MAX_GRANTS as u8 {
            release_grant(g);
        }
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![Err(EINVAL), Err(EINVAL), Err(EINVAL), Err(EINVAL), Err(EFAULT), Err(EINVAL), Err(EBUSY)]);
    // Every pin was undone
    assert_eq!(crate::fake::frame_refs(buf), 0);
    // A caller without an address space
    let spec = GrantSpec { ranges: [(buf, 10); GRANT_RANGES], n: 1, server_writes: false };
    assert_eq!(make_grant(&spec, EP), Err(EINVAL));
    release_grant(0);
}

#[test]
fn an_unregistered_server_releases_lent_pages() {
    let sim = world();
    let buf = crate::fake::alloc_pages(1);
    sim.spawn(driver(200, EP), || {
        register(EP).unwrap();
        let _ = recv(EP).unwrap();
        unregister(EP);
    });
    sim.run_others();
    let spec = GrantSpec { ranges: [(buf, 64); GRANT_RANGES], n: 1, server_writes: false };
    let got = StdArc::new(StdMutex::new(None));
    let g2 = got.clone();
    sim.spawn(driver(150, ENDPOINT_ZFS_SERVER), move || *g2.lock().unwrap() = Some(call_once_with(EP, ask(0), 100, CallMode::Queued, Some(&spec)).err()));
    sim.run_others();
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), Some(Some(ESRCH)));
    assert_eq!(crate::fake::frame_refs(buf), 0);
}

// ----------------------------------------------------------------------
// Device access
// ----------------------------------------------------------------------

#[test]
fn contiguous_frames_and_device_ranges() {
    let _g = crate::world::serial();
    crate::fake::reset();
    let f = ContiguousFrames::allocate(3).unwrap();
    assert_eq!(f.pages, 3);
    assert_eq!(crate::fake::frame_refs(f.base + 8192), 1);
    // SAFETY: nobody else uses these frames
    let b = unsafe { f.bytes() };
    assert_eq!(b.len(), 3 * 4096);
    assert!(b.iter().all(|&x| x == 0));
    assert_eq!(f.get_page(2).unwrap().start_address().as_u64(), f.base + 8192);
    assert!(f.get_page(3).is_none());
    let base = f.base;
    drop(f);
    assert_eq!(crate::fake::frame_refs(base), 0);
    // DMA memory leaves its driver's IOMMU domain when freed
    let d = ContiguousFrames::allocate_for(2, EP).unwrap();
    let db = d.base;
    drop(d);
    assert_eq!(crate::fake::rec(|r| r.dma.clone()), vec![(false, EP, db, 8192)]);
    let r = DeviceRange { base: 0xFEB0_0000, pages: 2 };
    assert_eq!(r.get_page(1).unwrap().start_address().as_u64(), 0xFEB0_1000);
    assert!(r.get_page(2).is_none());
    crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
    assert!(ContiguousFrames::allocate(1).is_none());
}

#[test]
fn physmap_dma_alloc_and_iopl() {
    let sim = world();
    set_grants(EP, vec![(0xFEB0_0000, 0x2000)]);
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        let push = |v: Result<u64, i64>| g2.lock().unwrap().push(v.map(|a| a != 0));
        push(physmap(0xFEB0_0000, 0x2000));
        push(physmap(0xFEB0_0001, 0x1000));
        push(physmap(0xFEB0_0000, 0));
        push(physmap(0xFEB0_0000, 0x3000));
        push(physmap(u64::MAX & !0xFFF, 0x2000));
        push(dma_alloc(0).map(|_| 1));
        push(dma_alloc(17 << 20).map(|_| 1));
        let (a, p) = dma_alloc(5000).unwrap();
        push(Ok((a != 0 && p != 0) as u64));
        crate::fake::rec(|r| r.dma_fail = 1);
        push(dma_alloc(4096).map(|_| 1));
        push(iopl_allowed().map(|_| 1));
    });
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), vec![Ok(true), Err(EINVAL), Err(EINVAL), Err(EPERM), Err(EINVAL), Err(EINVAL), Err(EINVAL), Ok(true), Err(ENOMEM), Ok(true)]);
    // Programs get none of it
    assert_eq!(physmap(0xFEB0_0000, 0x1000), Err(EPERM));
    assert_eq!(dma_alloc(4096), Err(EPERM));
    assert_eq!(iopl_allowed(), Err(EPERM));
    // The DMA buffer entered the driver's IOMMU domain
    assert!(crate::fake::rec(|r| r.dma.iter().any(|d| d.0 && d.1 == EP && d.3 == 8192)));
}

// ----------------------------------------------------------------------
// Interrupts
// ----------------------------------------------------------------------

#[test]
fn interrupt_lines_of_a_driver() {
    let sim = world();
    static NOTE: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
    notify_on_irq(EP, &NOTE);
    forward_irq(EP, ENDPOINT_NET_SERVER);
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        let push = |v: Result<u32, i64>| g2.lock().unwrap().push(v);
        // Reserved and invalid lines
        for l in [0u64, 1, 2, 12, 32, 16] {
            push(irq_register(l).map(|_| 0));
        }
        push(irq_register(11).map(|_| 0));
        push(irq_register(5).map(|_| 0));
        // Raised twice while it works: counted
        assert!(irq_raised(11));
        assert!(irq_raised(11));
        push(irq_ack(11));
        push(irq_ack(11));
        // Waits: one pending already; then a timeout
        assert!(irq_raised(5));
        push(irq_wait(5, 0));
        push(irq_wait(5, 3));
        // Not its lines
        push(irq_ack(9));
        push(irq_wait(40, 0));
        // Raised while it waits
        push(irq_wait(11, 0));
    });
    sim.run_others();
    // Time passes (the wait on line 5 times out), then line 11 fires
    sim.sleep(10);
    assert!(!irq_raised(3));
    assert!(irq_raised(11));
    sim.settle();
    let g = got.lock().unwrap().clone();
    assert_eq!(g, vec![Err(EINVAL), Err(EINVAL), Err(EINVAL), Err(EINVAL), Err(EINVAL), Err(EINVAL), Ok(0), Ok(0), Ok(2), Ok(0), Ok(1), Ok(0), Err(EPERM), Err(EPERM), Ok(1)]);
    // Line 11 is on the second controller: the cascade was unmasked too
    let pic = crate::fake::rec(|r| r.pic.clone());
    assert!(pic.contains(&(false, 11)) && pic.contains(&(false, 2)) && pic.contains(&(true, 11)));
    // Clients were woken and net-server notified
    assert!(NOTE.wakes() >= 4);
    assert_ne!(pending_bits(ENDPOINT_NET_SERVER) & NOTIFY_IRQ, 0);
    // Statistics read the PIC's mask registers
    x86_64::PORTS.lock().unwrap().insert(0xA1, 1 << 3);
    let st = irq_stats();
    let l11 = st.iter().find(|s| s.0 == 11).unwrap();
    assert_eq!((l11.1, l11.2), (200, 3));
    assert!(l11.5, "masked");
    // A program owns no line; the driver's end releases them
    assert_eq!(irq_register(9), Err(EPERM));
    assert_eq!(irq_ack(11), Err(EPERM));
    release_irqs(200);
    assert!(irq_stats().is_empty());
    assert!(!irq_raised(11));
}

#[test]
fn a_signal_ends_an_interrupt_wait() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(None));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        irq_register(10).unwrap();
        *g2.lock().unwrap() = Some(irq_wait(10, 0));
    });
    sim.run_others();
    crate::fake::set_signal(200, true);
    crate::world::defer_wakes([200]);
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), Some(Err(EINTR)));
}

#[test]
fn msi_lines_follow_their_device() {
    let _sim = world();
    let a = crate::arch::pci::PciDevice { bus: 0, device: 3, function: 0 };
    let b = crate::arch::pci::PciDevice { bus: 1, device: 0, function: 0 };
    let la = msi_line(&a).unwrap();
    assert_eq!(la, MSI_FIRST_LINE);
    assert_eq!(msi_line(&a), Some(la));
    assert_eq!(msi_line(&b), Some(la + 1));
    // A device without MSI: its line is freed
    crate::fake::rec(|r| r.msi_ok = false);
    let c = crate::arch::pci::PciDevice { bus: 2, device: 0, function: 0 };
    assert_eq!(msi_line(&c), None);
    // MSI-X: the table, the message address and data
    assert_eq!(msix_line(&c), None);
    crate::fake::rec(|r| r.msix_table = Some(0xFEBF_0000));
    let (l, t, addr, data) = msix_line(&c).unwrap();
    assert_eq!((l, t, addr, data), (la + 2, 0xFEBF_0000, 0xFEE0_0000 | 3 << 12, 0x50 + 2));
    // An MSI line a device was given can be registered by its driver
    let mut d = driver(200, EP);
    d.state = crate::task::TaskState::Ready;
    let _ = d;
    // Lines all used up
    for i in 3..16u8 {
        let dev = crate::arch::pci::PciDevice { bus: 10 + i, device: 0, function: 0 };
        msix_line(&dev);
    }
    assert_eq!(msix_line(&crate::arch::pci::PciDevice { bus: 200, device: 0, function: 0 }), None);
}

#[test]
fn an_msi_line_is_registered_once_given() {
    let sim = world();
    let dev = crate::arch::pci::PciDevice { bus: 0, device: 4, function: 0 };
    let line = msi_line(&dev).unwrap() as u64;
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    sim.spawn(driver(200, EP), move || {
        g2.lock().unwrap().push(irq_register(line));
        g2.lock().unwrap().push(irq_register(line + 1));
        // MSI lines are not masked at a controller
        assert!(irq_raised(line as u8));
        g2.lock().unwrap().push(irq_ack(line).map(|_| ()));
    });
    sim.run_others();
    assert_eq!(*got.lock().unwrap(), vec![Ok(()), Err(EINVAL), Ok(())]);
    assert!(crate::fake::rec(|r| r.pic.is_empty()));
}

// wave7 GB begin: registration and teardown exclude each other; retired threads
#[test]
fn a_registration_waits_for_a_teardown_in_progress() {
    let sim = world();
    crate::task::RETIRED_TID.store(0, Ordering::Release);
    // A teardown (unregister / unregister_if) holds the registration lock
    let held = REGISTRATION.lock();
    let r = StdArc::new(StdMutex::new(None));
    let r2 = r.clone();
    sim.spawn(driver(200, EP), move || {
        crate::world::bkl_enter();
        *r2.lock().unwrap() = Some(register(EP).map(|_| 0));
    });
    sim.run_others();
    assert_eq!(server_of(EP), 0, "the new server waits: the teardown cannot clear it afterwards");
    assert_eq!(*r.lock().unwrap(), None);
    drop(held);
    sim.settle();
    assert_eq!(*r.lock().unwrap(), Some(Ok(0)));
    assert_eq!(server_of(EP), 200);
    // unregister_if: only the server looked at, never an empty registration
    assert!(!unregister_if(EP, 0));
    assert!(!unregister_if(EP, 999));
    assert_eq!(server_of(EP), 200);
    assert!(unregister_if(EP, 200));
    assert_eq!(server_of(EP), 0);
}

#[test]
fn a_retired_thread_neither_registers_nor_claims_a_line() {
    let sim = world();
    crate::task::RETIRED_TID.store(200, Ordering::Release);
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(driver(200, EP), move || {
        crate::world::bkl_enter();
        r2.lock().unwrap().push(register(EP).map(|_| 0));
        r2.lock().unwrap().push(irq_register(11).map(|_| 0));
    });
    sim.settle();
    crate::task::RETIRED_TID.store(0, Ordering::Release);
    assert_eq!(*r.lock().unwrap(), vec![Err(ESRCH), Err(ESRCH)]);
    assert_eq!(server_of(EP), 0);
    assert_eq!(IRQ_OWNER[11].load(Ordering::Acquire), 0);
}

#[test]
fn a_process_end_releases_the_lines_of_all_its_threads_and_of_gone_ones() {
    let sim = world();
    // Threads 301 and 302 of process 300, thread 401 of process 400 (all alive), and
    // thread 999 (reaped: not in the table)
    for (tid, tgid) in [(301u64, 300u64), (302, 300), (401, 400)] {
        sim.spawn(Task::server(tid, tgid, EP), || loop {
            crate::task::block_current();
        });
    }
    sim.run_others();
    for (line, owner) in [(5usize, 301u64), (9, 302), (10, 401), (11, 999)] {
        IRQ_OWNER[line].store(owner, Ordering::Release);
        IRQ_SERVICE[line].store(EP, Ordering::Release);
    }
    release_irqs_of_process(300);
    let owners: Vec<u64> = [5usize, 9, 10, 11].iter().map(|&l| IRQ_OWNER[l].load(Ordering::Acquire)).collect();
    assert_eq!(owners, vec![0, 0, 401, 0]);
    assert_eq!(IRQ_SERVICE[10].load(Ordering::Acquire), EP);
}
// wave7 GB end
