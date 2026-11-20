//! Event wait queues (`src/task/wait.rs`): registering, deferred wakeups applied by the
//! scheduler, wait sets with deadlines, and the timed waits.

mod common;
use common::*;

use hydra_hosttests_t31::task::wait::{self, Deadline, QueueRef, WaitQueue, WaitSet};
use hydra_hosttests_t31::task::{self, TaskId, TaskState};
use std::sync::atomic::Ordering;
use std::sync::Arc;

static STATIC_Q: WaitQueue = WaitQueue::new();

fn spawn(name: &'static str) -> u64 {
    task::spawn(name, noop, task::TaskPriority::Normal).0
}

#[test]
fn wake_all_wakes_registered_waiters_once_and_counts() {
    let _w = booted();
    let q = WaitQueue::new_shared();
    assert_eq!(q.wakes(), 0);
    q.register();
    q.register(); // once
    assert!(task::SCHEDULER.lock().event_wait_current(None));
    q.wake_all();
    assert_eq!(q.wakes(), 1);
    assert_eq!(with(0, |t| (t.state, t.woken)), (TaskState::Ready, true));
    assert!(fake::PROF.lock().unwrap().contains(&("wake_requested", 0)));
    assert_eq!(fake::KICK_IDLE.load(Ordering::SeqCst) >= 1, true);
    // Woken waiters are removed: a second wake_all wakes nobody
    with(0, |t| {
        t.state = TaskState::Blocked;
        t.event_wait = true;
    });
    q.wake_all();
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert_eq!(q.wakes(), 2);
    // Unregistering
    q.register();
    q.unregister();
    q.wake_all();
    assert_eq!(state(0), Some(TaskState::Blocked));
}

#[test]
fn a_wake_while_the_scheduler_is_busy_is_applied_later() {
    let _w = booted();
    let a = spawn("a");
    with(a, |t| {
        t.state = TaskState::Blocked;
        t.event_wait = true;
    });
    let q = WaitQueue::new();
    // registering on a's behalf: through a wait set while a is current
    assert_eq!(yield_on(0), 0); // shell stays (a blocked)
    task::SCHEDULER.lock().with_task_mut(TaskId(0), |t| t.state = TaskState::Running);
    let g = task::SCHEDULER.lock();
    drop(g);
    // simulate: a registered earlier
    {
        let mut s = WaitSet::new();
        s.add(QueueRef::Static(&STATIC_Q));
        // make a current to register it
        with(0, |t| t.state = TaskState::Blocked);
        with(a, |t| t.state = TaskState::Ready);
        assert_eq!(yield_on(0), a);
        s.register();
        std::mem::forget(s); // stays registered
    }
    with(a, |t| {
        t.state = TaskState::Blocked;
        t.event_wait = true;
    });
    let held = task::SCHEDULER.lock();
    STATIC_Q.wake_all(); // the scheduler lock is busy: deferred
    assert!(wait::wakes_pending());
    drop(held);
    assert_eq!(state(a), Some(TaskState::Blocked));
    yield_on(0); // the next pass applies it
    assert!(!wait::wakes_pending());
    assert_ne!(state(a), Some(TaskState::Blocked));
    let _ = q;
}

#[test]
fn wait_sleeps_in_an_event_wait_until_the_deadline_or_returns_at_once() {
    let _w = booted();
    let now = fake::ticks();
    wait::wait(Some(now)); // already passed
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 0);
    wait::wait(Some(now + 5));
    assert_eq!(with(0, |t| (t.state, t.event_wait)), (TaskState::Sleeping { wake_tick: now + 5 }, true));
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 1);
    // A pending wakeup: no sleep
    with(0, |t| {
        t.state = TaskState::Running;
        t.wake_pending = true;
    });
    wait::wait(None);
    assert_eq!(state(0), Some(TaskState::Running));
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 1);
    wait::wait(None);
    assert_eq!(state(0), Some(TaskState::Blocked));
    // Precise
    with(0, |t| t.state = TaskState::Running);
    let ns = fake::now_ns();
    wait::wait_ns(Some(ns));
    assert_eq!(state(0), Some(TaskState::Running));
    wait::wait_ns(Some(ns + 3_000_000));
    assert_eq!(with(0, |t| t.wake_ns), ns + 3_000_000);
    with(0, |t| {
        t.state = TaskState::Running;
        t.wake_pending = true;
    });
    wait::wait_ns(None);
    assert_eq!(state(0), Some(TaskState::Running));
    // Without the scheduler or the timer: one tick of the clock
    fake::PIT_ACTIVE.store(false, Ordering::SeqCst);
    wait::wait(None);
    wait::wait_ns(None);
    assert_eq!(fake::PIT_SLEPT.load(Ordering::SeqCst), 2);
}

struct TickDeadline(u64);
impl Deadline for TickDeadline {
    fn next_tick(&self) -> Option<u64> {
        Some(self.0)
    }
}
struct NsDeadline(u64);
impl Deadline for NsDeadline {
    fn next_tick(&self) -> Option<u64> {
        None
    }
    fn next_ns(&self) -> Option<u64> {
        Some(self.0)
    }
}

#[test]
fn a_wait_set_registers_its_queues_and_takes_the_earliest_deadline() {
    let _w = booted();
    let q1 = WaitQueue::new_shared();
    let mut set = WaitSet::new();
    set.register(); // no queues: nothing
    set.add(QueueRef::Shared(q1.clone()));
    set.add(QueueRef::Static(&STATIC_Q));
    let r: &WaitQueue = &QueueRef::Shared(q1.clone());
    assert_eq!(r.wakes(), 0);
    set.register();
    let now = fake::ticks();
    set.add_deadline(Arc::new(TickDeadline(now + 7)));
    set.wait(Some(now + 20));
    assert_eq!(state(0), Some(TaskState::Sleeping { wake_tick: now + 7 }));
    q1.wake_all();
    assert_eq!(state(0), Some(TaskState::Ready));
    // A polled set waits at most until the next tick
    with(0, |t| t.state = TaskState::Running);
    set.polled = true;
    set.wait(None);
    assert_eq!(state(0), Some(TaskState::Sleeping { wake_tick: now + 1 }));
    // A deadline that knows its exact time: a precise wait
    with(0, |t| t.state = TaskState::Running);
    set.polled = false;
    let ns = fake::now_ns() + 2_500_000;
    set.add_deadline(Arc::new(NsDeadline(ns)));
    set.wait(Some(now + 20));
    assert_eq!(with(0, |t| t.wake_ns), ns);
    with(0, |t| t.state = TaskState::Running);
    set.polled = true;
    set.wait_ns(None);
    assert_eq!(with(0, |t| t.wake_ns), ns, "the earlier of the deadline and the next tick");
    // Dropping the set unregisters from every queue
    drop(set);
    with(0, |t| {
        t.state = TaskState::Blocked;
        t.event_wait = true;
    });
    q1.wake_all();
    assert_eq!(state(0), Some(TaskState::Blocked));
}

#[test]
fn a_process_wake_unblocks_every_thread() {
    let _w = booted();
    let p = spawn("p");
    let t1 = spawn("t1");
    with(t1, |t| {
        t.tgid = p;
        t.state = TaskState::Blocked;
    });
    wait::wake_process_deferred(p);
    assert_eq!(state(t1), Some(TaskState::Ready));
}
