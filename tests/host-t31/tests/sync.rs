//! The blocking primitives of `src/sync`: wait queue, mutex, semaphore, condition
//! variable and channel.
//!
//! Single-thread tests check the bookkeeping. The cross-thread tests run two fake CPUs
//! (threads) on the real scheduler: a CPU whose task blocks waits (`YieldMode::WaitRunnable`)
//! until something makes the task runnable again, and panics with "lost wakeup" if
//! nothing ever does, which is how a wakeup that arrives between a waiter's enqueue and
//! its block shows up.

mod common;
use common::*;

use hydra_hosttests_t31::sync::{Channel, CondVar, Mutex, Semaphore, WaitQueue};
use hydra_hosttests_t31::task::{self, TaskId, TaskState};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn set_state(id: u64, s: TaskState) {
    task::SCHEDULER.lock().with_task_mut(TaskId(id), |t| t.state = s);
}

/// Two fake CPUs: CPU 0 runs the shell (task 0), CPU 1 its idle task (task 2); blocked
/// tasks wait to be woken.
fn two_cpus() -> World {
    let w = booted();
    add_cpus(2);
    *fake::YIELD_MODE.lock().unwrap() = fake::YieldMode::WaitRunnable;
    w
}

/// Runs `f` on a thread playing CPU 1.
fn on_cpu1<F: FnOnce() + Send + 'static>(f: F) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        fake::set_cpu(1);
        f();
    })
}

// ------------------------------------------------------------------ wait queue

#[test]
fn wait_queue_keeps_each_task_once_and_wakes_only_blocked_ones() {
    let _w = booted();
    let a = task::spawn("a", noop, task::TaskPriority::Normal).0;
    let b = task::spawn("b", noop, task::TaskPriority::Normal).0;
    let mut q = WaitQueue::new();
    assert!(q.is_empty());
    q.enqueue(TaskId(a));
    q.enqueue(TaskId(a));
    q.enqueue(TaskId(b));
    assert_eq!(q.len(), 2);
    // a is not blocked: dropped; b is woken
    set_state(b, TaskState::Blocked);
    assert_eq!(q.wake_one(), Some(TaskId(b)));
    assert!(q.is_empty());
    assert_eq!(state(b), Some(TaskState::Ready));
    assert_eq!(q.wake_one(), None);
    for id in [a, b] {
        set_state(id, TaskState::Blocked);
        q.enqueue(TaskId(id));
    }
    q.enqueue(TaskId(77)); // no such task
    assert_eq!(q.wake_all(), 2);
    assert_eq!(q.len(), 0);
    let d = WaitQueue::default();
    assert!(d.clone().is_empty());
}

#[test]
fn wait_queue_wait_blocks_the_current_task_and_yields() {
    let _w = booted();
    let mut q = WaitQueue::new();
    assert_eq!(q.wait(), TaskId(0));
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert_eq!(q.len(), 1);
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 1);
    assert_eq!(q.wake_one(), Some(TaskId(0)));
}

// ------------------------------------------------------------------ mutex

#[test]
fn mutex_records_its_owner_and_try_lock_fails_while_held() {
    let _w = booted();
    let m = Mutex::new(5u32);
    assert!(!m.is_locked());
    {
        let mut g = m.lock();
        *g += 1;
        assert!(m.is_locked());
        assert_eq!(m.owner_pid(), 0);
        assert!(m.try_lock().is_none());
        assert_eq!(m.waiting_count(), 0);
    }
    assert!(!m.is_locked());
    let g = m.try_lock().unwrap();
    assert_eq!(*g, 6);
}

#[test]
fn mutex_contended_across_cpus_hands_over_without_losing_a_wakeup() {
    let _w = two_cpus();
    let m = Arc::new(Mutex::new(0u64));
    let m2 = m.clone();
    const N: u64 = 3000;
    let h = on_cpu1(move || {
        for _ in 0..N {
            *m2.lock() += 1;
        }
    });
    for _ in 0..N {
        *m.lock() += 1;
    }
    h.join().unwrap();
    assert_eq!(*m.lock(), 2 * N);
    assert_eq!(m.waiting_count(), 0);
}

#[test]
fn mutex_waiter_blocks_and_is_woken_by_the_unlock() {
    let _w = two_cpus();
    let m = Arc::new(Mutex::new(()));
    let g = m.lock();
    let m2 = m.clone();
    let done = Arc::new(AtomicUsize::new(0));
    let d2 = done.clone();
    let h = on_cpu1(move || {
        let _g = m2.lock();
        assert_eq!(m2.owner_pid(), 2, "CPU 1's task owns it");
        d2.store(1, Ordering::SeqCst);
    });
    while state(2) != Some(TaskState::Blocked) {
        std::thread::yield_now();
    }
    assert_eq!(m.waiting_count(), 1);
    assert_eq!(done.load(Ordering::SeqCst), 0);
    drop(g);
    h.join().unwrap();
    assert_eq!(done.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------------------ semaphore

#[test]
fn semaphore_counts_permits() {
    let _w = booted();
    let s = Semaphore::new(2);
    assert!(s.try_acquire());
    s.acquire();
    assert_eq!(s.available_permits(), 0);
    assert!(!s.try_acquire());
    s.release();
    assert_eq!(s.available_permits(), 1);
    assert_eq!(s.waiting_count(), 0);
    assert!(s.try_acquire());
}

#[test]
fn semaphore_ping_pong_across_cpus_loses_no_wakeup() {
    let _w = two_cpus();
    let ping = Arc::new(Semaphore::new(0));
    let pong = Arc::new(Semaphore::new(0));
    let (p2, q2) = (ping.clone(), pong.clone());
    const N: usize = 3000;
    let h = on_cpu1(move || {
        for _ in 0..N {
            p2.acquire();
            q2.release();
        }
    });
    for _ in 0..N {
        ping.release();
        pong.acquire();
    }
    h.join().unwrap();
    assert_eq!(ping.available_permits(), 0);
    assert_eq!(pong.available_permits(), 0);
}

// ------------------------------------------------------------------ condition variable

#[test]
fn condvar_notify_counts_the_tasks_woken() {
    let _w = booted();
    let cv = CondVar::new();
    assert_eq!(cv.notify_all(), 0);
    cv.notify_one();
    assert_eq!(cv.waiting_count(), 0);
}

#[test]
fn condvar_wait_releases_the_mutex_and_returns_with_it() {
    let _w = two_cpus();
    let pair = Arc::new((Mutex::new(0u32), CondVar::new()));
    let p2 = pair.clone();
    let h = on_cpu1(move || {
        let (m, cv) = &*p2;
        let mut g = m.lock();
        while *g == 0 {
            g = cv.wait(g);
        }
        assert!(m.is_locked());
        *g = 2;
    });
    // Wait until CPU 1 sleeps on the condition (it released the mutex)
    while pair.1.waiting_count() == 0 || state(2) != Some(TaskState::Blocked) {
        std::thread::yield_now();
    }
    assert!(!pair.0.is_locked());
    *pair.0.lock() = 1;
    pair.1.notify_one();
    h.join().unwrap();
    assert_eq!(*pair.0.lock(), 2);
}

#[test]
fn condvar_producer_consumer_across_cpus_loses_no_wakeup() {
    let _w = two_cpus();
    let pair = Arc::new((Mutex::new((0u64, false)), CondVar::new()));
    let p2 = pair.clone();
    const N: u64 = 2000;
    let h = on_cpu1(move || {
        let (m, cv) = &*p2;
        for i in 1..=N {
            let mut g = m.lock();
            while g.1 {
                g = cv.wait(g);
            }
            *g = (i, true);
            drop(g);
            cv.notify_all();
        }
    });
    let (m, cv) = &*pair;
    let mut sum = 0;
    for _ in 0..N {
        let mut g = m.lock();
        while !g.1 {
            g = cv.wait(g);
        }
        sum += g.0;
        g.1 = false;
        drop(g);
        cv.notify_all();
    }
    h.join().unwrap();
    assert_eq!(sum, N * (N + 1) / 2);
}

// ------------------------------------------------------------------ channel

#[test]
fn channel_bounds_and_non_blocking_calls() {
    let _w = booted();
    let c = Channel::new(0);
    assert_eq!(c.capacity(), 1, "at least one slot");
    assert!(c.is_empty());
    assert_eq!(c.try_recv(), None::<u8>);
    assert!(c.try_send(1u8).is_ok());
    assert_eq!(c.try_send(2), Err(2));
    assert_eq!(c.len(), 1);
    assert_eq!(c.recv(), 1);
    c.send(3);
    assert_eq!(c.try_recv(), Some(3));
    assert_eq!((c.waiting_receivers(), c.waiting_senders()), (0, 0));
}

#[test]
fn channel_blocks_full_senders_and_empty_receivers_across_cpus() {
    let _w = two_cpus();
    let c = Arc::new(Channel::new(2));
    let c2 = c.clone();
    const N: u64 = 3000;
    let h = on_cpu1(move || {
        for i in 0..N {
            c2.send(i);
        }
    });
    let mut expect = 0;
    for _ in 0..N {
        assert_eq!(c.recv(), expect, "in order");
        expect += 1;
    }
    h.join().unwrap();
    assert!(c.is_empty());
}

#[test]
fn a_receiver_blocked_on_an_empty_channel_is_woken_by_send() {
    let _w = two_cpus();
    let c = Arc::new(Channel::new(1));
    let c2 = c.clone();
    let h = on_cpu1(move || {
        assert_eq!(c2.recv(), 9u8);
    });
    while c.waiting_receivers() == 0 || state(2) != Some(TaskState::Blocked) {
        std::thread::yield_now();
    }
    c.send(9);
    h.join().unwrap();
}

#[test]
fn enqueue_blocked_blocks_the_caller_in_the_same_step() {
    let _w = booted();
    let mut q = WaitQueue::new();
    q.enqueue_blocked(TaskId(0));
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert_eq!(q.len(), 1);
    // A wake that comes before the caller yields still finds it blocked
    assert_eq!(q.wake_one(), Some(TaskId(0)));
    assert_eq!(state(0), Some(TaskState::Ready));
}
