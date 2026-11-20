//! Tests of `src/ipc/endpoint.rs`: the bounded message ring, shared endpoints, blocking
//! send and receive in the simulated world, the system endpoints.

use super::*;
use crate::world::{Sim, Task};
use std::sync::atomic::{AtomicU64 as StdAtomicU64, Ordering};
use std::sync::Arc;

fn msg(n: u64) -> Message {
    Message::with_args(n as u32, [n, n + 1, 0, 0])
}

#[test]
fn the_ring_holds_sixteen_messages_in_order() {
    let mut e = Endpoint::new(7);
    assert_eq!(e.id(), 7);
    assert!(e.receive().is_none());
    for i in 0..QUEUE_CAPACITY as u64 {
        assert!(e.send(msg(i)).is_ok());
    }
    assert_eq!(e.send(msg(99)), Err("Endpoint message queue is full"));
    assert_eq!(e.pending_count(), QUEUE_CAPACITY);
    // FIFO, and the ring wraps
    for i in 0..10 {
        assert_eq!(e.receive().unwrap().label, i);
    }
    for i in 100..110 {
        assert!(e.send(msg(i)).is_ok());
    }
    let order: Vec<u32> = core::iter::from_fn(|| e.receive().map(|m| m.label)).collect();
    let want: Vec<u32> = (10..16).chain(100..110).collect();
    assert_eq!(order, want);
    assert_eq!(e.pending_count(), 0);
    assert_eq!((e.waiting_receivers(), e.waiting_senders()), (0, 0));
}

#[test]
fn reset_empties_the_ring() {
    let mut e = Endpoint::new(1);
    e.send(msg(1)).unwrap();
    e.send(msg(2)).unwrap();
    e.reset();
    assert_eq!(e.pending_count(), 0);
    assert!(e.receive().is_none());
    // Usable again from the start
    e.send(msg(3)).unwrap();
    assert_eq!(e.receive().unwrap().label, 3);
}

#[test]
fn shared_endpoints_and_the_system_table() {
    let s = SharedEndpoint::new(9);
    assert_eq!(s.id(), 9);
    assert!(s.receive().is_none());
    s.send(msg(5)).unwrap();
    assert_eq!(s.pending_count(), 1);
    assert_eq!(s.receive().unwrap().args, [5, 6, 0, 0]);
    s.send(msg(6)).unwrap();
    s.reset();
    assert_eq!(s.pending_count(), 0);
    assert_eq!((s.waiting_receivers(), s.waiting_senders()), (0, 0));
    for i in 0..64 {
        assert_eq!(get_system_endpoint(i).unwrap().id(), i);
    }
    assert!(get_system_endpoint(64).is_none());
    assert_eq!(SYSTEM_ENDPOINTS.len(), 64);
}

#[test]
fn a_blocking_receive_waits_for_the_message() {
    let sim = Sim::new(Task::linux(100, 100));
    static EP: SharedEndpoint = SharedEndpoint::new(40);
    EP.reset();
    let got = Arc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 101), move || {
        g2.store(EP.receive_blocking().args[0] + 1, Ordering::Release);
    });
    sim.run_others();
    // The receiver waits on the endpoint
    assert_eq!(EP.waiting_receivers(), 1);
    assert_eq!(sim.state(101), crate::task::TaskState::Blocked);
    EP.send(msg(41)).unwrap();
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 42);
    // A message already there: no wait
    EP.send(msg(7)).unwrap();
    assert_eq!(EP.receive_blocking().label, 7);
}

#[test]
fn a_blocking_send_waits_for_room() {
    let sim = Sim::new(Task::linux(100, 100));
    static EP: SharedEndpoint = SharedEndpoint::new(41);
    EP.reset();
    for i in 0..QUEUE_CAPACITY as u64 {
        EP.send(msg(i)).unwrap();
    }
    let done = Arc::new(StdAtomicU64::new(0));
    let d2 = done.clone();
    sim.spawn(Task::linux(101, 101), move || {
        EP.send_blocking(msg(77));
        d2.store(1, Ordering::Release);
    });
    sim.run_others();
    assert_eq!(done.load(Ordering::Acquire), 0);
    assert_eq!(EP.waiting_senders(), 1);
    assert_eq!(EP.receive().unwrap().label, 0);
    sim.run_others();
    assert_eq!(done.load(Ordering::Acquire), 1);
    assert_eq!(EP.pending_count(), QUEUE_CAPACITY);
    // Room already: no wait
    EP.receive().unwrap();
    EP.send_blocking(msg(78));
    assert_eq!(EP.pending_count(), QUEUE_CAPACITY);
}

/// Group 31's find (NOTES 2026-11-20): the waiter enqueued itself, let the endpoint's lock
/// go, and only then blocked. A message sent in between (here: a timer tick lets the sender
/// run there) found the receiver still running, dropped it from the queue, and the
/// receiver then slept forever: the world reports the deadlock.
#[test]
fn a_message_sent_between_enqueue_and_block_is_not_lost() {
    let sim = Sim::new(Task::linux(100, 100));
    static EP: SharedEndpoint = SharedEndpoint::new(42);
    EP.reset();
    let got = Arc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 101), move || {
        crate::world::PREEMPT_BEFORE_BLOCK.store(1, Ordering::Release);
        g2.store(EP.receive_blocking().label as u64, Ordering::Release);
    });
    // The receiver runs first, enqueues itself and is preempted before it blocks; this
    // task sends meanwhile
    sim.run_others();
    EP.send(msg(9)).unwrap();
    for _ in 0..3 {
        sim.run_others();
    }
    assert_eq!(got.load(Ordering::Acquire), 9);
}

#[test]
fn room_made_between_enqueue_and_block_is_not_lost() {
    let sim = Sim::new(Task::linux(100, 100));
    static EP: SharedEndpoint = SharedEndpoint::new(43);
    EP.reset();
    for i in 0..QUEUE_CAPACITY as u64 {
        EP.send(msg(i)).unwrap();
    }
    let done = Arc::new(StdAtomicU64::new(0));
    let d2 = done.clone();
    sim.spawn(Task::linux(101, 101), move || {
        crate::world::PREEMPT_BEFORE_BLOCK.store(1, Ordering::Release);
        EP.send_blocking(msg(77));
        d2.store(1, Ordering::Release);
    });
    sim.run_others();
    EP.receive().unwrap();
    for _ in 0..3 {
        sim.run_others();
    }
    assert_eq!(done.load(Ordering::Acquire), 1);
}
