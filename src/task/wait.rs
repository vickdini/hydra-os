//! # Task Subsystem: Event Wait Queues
//!
//! Lets a task sleep until an event source (a pipe, socket, terminal or device interrupt)
//! wakes it, instead of re-checking every timer tick.
//!
//! ## Architectural Role & Design Rationale
//!
//! The waiting protocol avoids lost wakeups without holding locks across the sleep:
//!
//! 1. register the current task on every queue it depends on (`WaitQueue::register`);
//! 2. check the condition (and pending signals) and return if satisfied;
//! 3. sleep with [`wait`], optionally until a deadline;
//! 4. repeat (waking removes the task from the queue).
//!
//! A wakeup that lands between steps 1 and 3 marks the task, so step 3 returns at once.
//!
//! Wakeups may come from interrupt handlers, which must not take the scheduler lock (the
//! interrupted code may hold it). `WaitQueue::wake_all` therefore records woken tasks in
//! a fixed lock-free ring that the scheduler drains on its next pass (or right away when its
//! lock is free).
//!
//! ## Key Types & Interfaces
//!
//! - `WaitQueue`: Interrupt-safe queue of task IDs waiting on a single event source.
//! - `QueueRef`: Either a `'static` or `Arc`-shared reference to a `WaitQueue`.
//! - `WaitSet` & `Deadline`: Multi-queue and timer-deadline aggregator for `poll`/`select`/`epoll`.
//! - [`wait`], `wake_process_deferred`, `wakes_pending`: Core event-sleep and deferred-wakeup entry points.
//!
//! ## Hardware & Dependency Context
//!
//! - **Interrupt Safety**: Disables CPU interrupts briefly (`without_interrupts`) when mutating
//!   a queue's waiter vector and posts wakeups to the lock-free `PENDING` atomic ring.
//! - **Timers**: Consults [`crate::arch::pit::ticks`] for deadline expiration.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::SCHEDULER;

/// Woken task ids (+1; 0 = empty slot) not yet applied by the scheduler.
static PENDING: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// The ring overflowed: wake every task in an event wait (each re-checks its condition).
static OVERFLOW: AtomicBool = AtomicBool::new(false);

/// Enqueues `id` into the lock-free `PENDING` wakeup ring, setting `OVERFLOW` if all slots are full.
fn defer_wake(id: u64) {
    for slot in PENDING.iter() {
        if slot.compare_exchange(0, id + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return;
        }
    }
    OVERFLOW.store(true, Ordering::Release);
}

/// Marks a whole-process wakeup (a signal arrived) in the ring.
const PROCESS_WAKE: u64 = 1 << 62;

/// Wakes every thread of process `tgid` (as for a newly pending signal) without taking
/// the scheduler lock, for code that may run under it (task exit paths).
pub fn wake_process_deferred(tgid: u64) {
    defer_wake(tgid | PROCESS_WAKE);
    flush();
}

/// True if wakeups are waiting for the scheduler (the idle loop then reschedules).
pub fn wakes_pending() -> bool {
    OVERFLOW.load(Ordering::Acquire) || PENDING.iter().any(|s| s.load(Ordering::Acquire) != 0)
}

/// Takes the recorded wakeups: calls `wake(id, whole_process)` for each, and returns
/// whether the ring overflowed (every waiting task must then be woken).
pub(super) fn drain(mut wake: impl FnMut(u64, bool)) -> bool {
    for slot in PENDING.iter() {
        let v = slot.swap(0, Ordering::AcqRel);
        if v != 0 {
            let v = v - 1;
            wake(v & !PROCESS_WAKE, v & PROCESS_WAKE != 0);
        }
    }
    OVERFLOW.swap(false, Ordering::AcqRel)
}

/// Applies recorded wakeups now if the scheduler lock is free (it is otherwise applied by
/// the lock holder's next scheduling pass).
fn flush() {
    if let Some(mut sched) = SCHEDULER.try_lock() {
        sched.apply_wakes();
    }
}

/// Tasks waiting for one event source. Usable from interrupt handlers.
pub struct WaitQueue {
    /// Interrupt-safe spinlock-protected list of waiting task IDs.
    waiters: Mutex<Vec<u64>>,
}

impl WaitQueue {
    /// Creates an empty `WaitQueue`.
    pub const fn new() -> Self {
        Self { waiters: Mutex::new(Vec::new()) }
    }

    /// Creates a new `WaitQueue` wrapped in an [`Arc`].
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Adds the current task (once). Call before checking the condition being waited for.
    pub fn register(&self) {
        self.register_id(SCHEDULER.lock().current_task_id().0);
    }

    /// Registers task `id` in the waiter list with interrupts disabled if not already present.
    fn register_id(&self, id: u64) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut w = self.waiters.lock();
            if !w.contains(&id) {
                w.push(id);
            }
        });
    }

    /// Removes the current task (when it stops waiting without being woken).
    pub fn unregister(&self) {
        let id = SCHEDULER.lock().current_task_id().0;
        x86_64::instructions::interrupts::without_interrupts(|| self.waiters.lock().retain(|&w| w != id));
    }

    /// Wakes every registered task. Never allocates or blocks; safe in interrupt handlers.
    pub fn wake_all(&self) {
        let any = x86_64::instructions::interrupts::without_interrupts(|| {
            let mut w = self.waiters.lock();
            let any = !w.is_empty();
            for id in w.drain(..) {
                defer_wake(id);
            }
            any
        });
        if any {
            flush();
        }
    }
}

/// A queue a waiter depends on: a static one (the terminal) or one owned by an object.
#[derive(Clone)]
pub enum QueueRef {
    /// Reference to a global static `WaitQueue`.
    Static(&'static WaitQueue),
    /// Reference-counted handle to a dynamically allocated `WaitQueue`.
    Shared(Arc<WaitQueue>),
}

impl core::ops::Deref for QueueRef {
    type Target = WaitQueue;
    fn deref(&self) -> &WaitQueue {
        match self {
            QueueRef::Static(q) => q,
            QueueRef::Shared(q) => q,
        }
    }
}

/// The queues one blocking call (`poll`, `select`, a socket read...) waits on.
///
/// `polled` is set when some object has no queue: its readiness can change unannounced,
/// so the waiter re-checks every tick, as before event-driven waiting existed.
pub struct WaitSet {
    /// Event wait queues registered in this set.
    queues: Vec<QueueRef>,
    /// True if at least one monitored resource lacks an event queue and requires per-tick polling.
    pub polled: bool,
    /// Objects that become ready at a time (timers): the wait ends at the earliest.
    deadlines: Vec<Arc<dyn Deadline>>,
}

/// Something that becomes ready at a known timer tick (a `timerfd`).
pub trait Deadline: Send + Sync {
    /// The tick at which it next becomes ready, if armed.
    fn next_tick(&self) -> Option<u64>;
}

impl WaitSet {
    /// Creates an empty `WaitSet` with no queues or deadlines.
    pub fn new() -> Self {
        Self { queues: Vec::new(), polled: false, deadlines: Vec::new() }
    }

    /// Adds a `QueueRef` to the set of queues this wait depends on.
    pub fn add(&mut self, q: QueueRef) {
        self.queues.push(q);
    }

    /// Also ends waits when `d` becomes ready (checked each time the set sleeps).
    pub fn add_deadline(&mut self, d: Arc<dyn Deadline>) {
        self.deadlines.push(d);
    }

    /// Registers the current task on every queue (repeat before each condition check).
    pub fn register(&self) {
        if self.queues.is_empty() {
            return;
        }
        let id = SCHEDULER.lock().current_task_id().0;
        for q in &self.queues {
            q.register_id(id);
        }
    }

    /// Sleeps until a queue is woken, a signal arrives, or tick `deadline` passes.
    pub fn wait(&self, deadline: Option<u64>) {
        let deadline = self.deadlines.iter().filter_map(|d| d.next_tick()).fold(deadline, |acc, t| Some(acc.map_or(t, |a| a.min(t))));
        let deadline = if self.polled {
            let next = crate::arch::pit::ticks() + 1;
            Some(deadline.map_or(next, |d| d.min(next)))
        } else {
            deadline
        };
        wait(deadline);
    }
}

impl Drop for WaitSet {
    fn drop(&mut self) {
        for q in &self.queues {
            q.unregister();
        }
    }
}

/// Sleeps the current task until a wait queue it registered on wakes it, a signal is
/// posted to its process, or tick `deadline` passes. Returns at once if a wakeup arrived
/// since the previous wait. Callers re-check their condition afterwards.
pub fn wait(deadline: Option<u64>) {
    if !super::is_active() || !crate::arch::pit::is_active() {
        crate::arch::pit::sleep_ticks(1);
        return;
    }
    if deadline.map_or(false, |d| crate::arch::pit::ticks() >= d) {
        return;
    }
    let sleeping = SCHEDULER.lock().event_wait_current(deadline);
    if sleeping {
        super::yield_now();
    }
}
