//! # Linux Compatibility: Fast Userspace Mutex (`futex`) Subsystem
//!
//! Provides the kernel-assisted sleeping and waking mechanism (`sys_futex`) backing
//! `glibc`, `musl`, and Qt6 mutexes, condition variables, semaphores, and thread joins.
//!
//! ## Architectural Role & Design Rationale
//! In uncontended cases, userspace locks acquire and release atomically without entering the
//! kernel. When contention occurs, threads invoke `sys_futex` to atomically verify that the
//! 32-bit lock word at `uaddr` still holds the expected value `val` before enqueuing on its
//! bucket of [`FUTEX_QUEUES`] and sleeping via [`crate::task::wait::wait`].
//!
//! A private futex (`FUTEX_PRIVATE_FLAG`, or any futex in private memory) is keyed by its
//! virtual address within an address space, so unrelated processes using the same virtual
//! address do not wake each other. A shared futex in a shared mapping (`MAP_SHARED` file,
//! `memfd`, or anonymous memory inherited across `fork`) is keyed by the underlying physical
//! address of its 32-bit word, enabling cross-process synchronization.
//!
//! ## Key Types & Interfaces
//! - [`FutexKey`]: Composite `(space, uaddr)` identifier distinguishing private and shared futexes.
//! - [`FutexWaiter`]: Wait queue entry associating a sleeping `TaskId` with a [`FutexKey`] and bitset.
//! - [`FutexQueue`] / [`FUTEX_QUEUES`]: Wait lists for blocked threads, one spinlock per hash
//!   bucket of futex keys (threads using different futexes rarely contend).
//! - [`dispatch_futex()`]: Top-level `sys_futex` system call multiplexer.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reads PIT tick counter and CMOS RTC for relative/absolute timeouts;
//!   queries page tables via [`crate::memory::vm`] to resolve shared physical addresses.
//! - Concurrency: Atomicity between the 32-bit word check and sleep enqueueing is guaranteed by
//!   holding the futex's bucket lock (both buckets, lower index first, for the operations on
//!   two futexes; all of them for `futex_waitv`).

use alloc::vec::Vec;
use spin::Mutex;
use crate::task::TaskId;

/// `futex` operation: verify `*uaddr == val` and sleep until woken or timed out (relative timeout).
pub const FUTEX_WAIT: i32 = 0;
/// `futex` operation: wake up to `val` waiters blocked on `uaddr`.
pub const FUTEX_WAKE: i32 = 1;
/// Legacy `futex` operation: create a file descriptor associated with a futex (unsupported; returns `-ENOSYS`).
pub const FUTEX_FD: i32 = 2;
/// `futex` operation: wake up to `val` waiters on `uaddr` and move up to `timeout` waiters to `uaddr2`.
pub const FUTEX_REQUEUE: i32 = 3;
/// `futex` operation: like [`FUTEX_REQUEUE`], but first verifies `*uaddr == val3`.
pub const FUTEX_CMP_REQUEUE: i32 = 4;
/// `futex` operation: atomically modify `*uaddr2`, wake waiters on `uaddr`, and conditionally wake `uaddr2`.
pub const FUTEX_WAKE_OP: i32 = 5;
/// Priority-inheritance futex lock (returns `-ENOSYS` so `glibc` falls back to normal futexes).
pub const FUTEX_LOCK_PI: i32 = 6;
/// Priority-inheritance futex unlock (returns `-ENOSYS`).
pub const FUTEX_UNLOCK_PI: i32 = 7;
/// Priority-inheritance futex trylock (returns `-ENOSYS`).
pub const FUTEX_TRYLOCK_PI: i32 = 8;
/// `futex` operation: like [`FUTEX_WAIT`], but matches a 32-bit `val3` bitmask and uses an absolute timeout.
pub const FUTEX_WAIT_BITSET: i32 = 9;
/// `futex` operation: wake up to `val` waiters on `uaddr` whose bitset intersects `val3`.
pub const FUTEX_WAKE_BITSET: i32 = 10;
/// Flag bit in `op`: futex is process-private and never shared across address spaces.
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
/// Flag bit in `op`: evaluate absolute timeouts against `CLOCK_REALTIME` instead of `CLOCK_MONOTONIC`.
pub const FUTEX_CLOCK_REALTIME: i32 = 256;
/// Mask extracting the base `FUTEX_*` command from `op` by stripping modifier flags.
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
/// Wildcard bitset (`0xffff_ffff`) matching any waiter bitmask in `FUTEX_WAIT` / `FUTEX_WAKE`.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

/// Negative errno for wait interrupted by a pending signal.
const EINTR: i64 = -4;
/// Negative errno for `*uaddr != val` mismatch during wait or compare-requeue.
const EAGAIN: i64 = -11;
/// Negative errno for invalid or unmapped userland pointer.
const EFAULT: i64 = -14;
/// Negative errno for unaligned `uaddr`, zero bitset, or invalid timespec.
const EINVAL: i64 = -22;
/// Negative errno for unimplemented futex operation (e.g., PI futexes).
const ENOSYS: i64 = -38;
/// Negative errno for wait timeout expiration.
const ETIMEDOUT: i64 = -110;
const EPERM: i64 = -1;
const EDEADLK: i64 = -35;

/// `FUTEX_LOCK_PI2`: `FUTEX_LOCK_PI` with a `CLOCK_MONOTONIC` timeout by default.
const FUTEX_LOCK_PI2: i32 = 13;
/// `FUTEX_WAIT_REQUEUE_PI` (not implemented: ENOSYS), named for the clock-flag check.
const FUTEX_WAIT_REQUEUE_PI: i32 = 11;
/// PI futex word: other threads wait in the kernel (the owner must unlock through it).
const FUTEX_WAITERS: u32 = 0x8000_0000;
/// PI futex word: the previous owner died holding the lock.
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// PI futex word: thread id of the owner.
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

/// Unique kernel identifier for a futex word: `(address_space_id, address)`.
///
/// # Concurrency & Thread Safety
/// Value type compared under its bucket lock to match wakers with sleeping threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexKey {
    /// Address-space token (pointer to `Mm`, thread-group ID, or [`PHYSICAL`] for shared pages).
    pub space: u64,
    /// Virtual address (for private futexes) or physical byte address (for shared futexes).
    pub uaddr: u64,
}

/// Represents a single thread blocked in the kernel waiting on a futex word.
///
/// # Lifecycle
/// Pushed onto [`FutexQueue`] before sleeping in [`wait`], and removed either by a waker
/// (`wake_task_ids`) or by the waiter itself upon timeout or signal interruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    /// Target futex key being waited upon.
    pub key: FutexKey,
    /// Scheduler identifier of the sleeping thread.
    pub task_id: TaskId,
    /// 32-bit bitmask used by `FUTEX_WAIT_BITSET` / `FUTEX_WAKE_BITSET`.
    pub bitset: u32,
}

/// Global futex wait queue managing all threads currently blocked on `sys_futex`.
///
/// # Concurrency & Thread Safety
/// Guarded by its bucket's spinlock in [`FUTEX_QUEUES`]. To prevent lost wakeups, [`wait`] reads the
/// userland futex word while holding this lock before inserting the [`FutexWaiter`].
pub struct FutexQueue {
    /// Ordered list of active futex waiters (FIFO wake order).
    waiters: Vec<FutexWaiter>,
}

impl FutexQueue {
    /// Creates an empty [`FutexQueue`] at compile time.
    pub const fn new() -> Self {
        Self { waiters: Vec::new() }
    }

    /// Removes up to `max_wake` waiters blocked on `key` whose bitset intersects `bitset`,
    /// returning their `TaskId`s so the caller can wake them in the scheduler.
    ///
    /// # Arguments
    /// * `key` - Target [`FutexKey`] to match.
    /// * `max_wake` - Maximum number of waiting tasks to dequeue.
    /// * `bitset` - Bitmask filter (`(waiter.bitset & bitset) != 0`).
    ///
    /// # Returns
    /// Vector of dequeued `TaskId`s to wake.
    pub fn wake_task_ids(&mut self, key: FutexKey, max_wake: usize, bitset: u32) -> Vec<TaskId> {
        let mut ids = Vec::new();
        let mut i = 0;
        while i < self.waiters.len() && ids.len() < max_wake {
            if self.waiters[i].key == key && (self.waiters[i].bitset & bitset) != 0 {
                ids.push(self.waiters.remove(i).task_id);
            } else {
                i += 1;
            }
        }
        ids
    }

    /// Takes out up to `max` waiters on `from` (requeued: they go to another key's bucket).
    fn take(&mut self, from: FutexKey, max: usize) -> Vec<FutexWaiter> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.waiters.len() && out.len() < max {
            if self.waiters[i].key == from {
                out.push(self.waiters.remove(i));
            } else {
                i += 1;
            }
        }
        out
    }

    /// Whether `task` waits on `key`.
    fn is_waiting(&self, task: TaskId, key: FutexKey) -> bool {
        self.waiters.iter().any(|w| w.task_id == task && w.key == key)
    }

    /// Removes `task`'s wait on `key`.
    fn remove(&mut self, task: TaskId, key: FutexKey) {
        self.waiters.retain(|w| !(w.task_id == task && w.key == key));
    }
}

/// Number of futex queue buckets.
const BUCKETS: usize = 64;

/// The futex wait queues: a bucket per hash of the key, each with its own lock, so threads
/// waiting on and waking different futexes do not contend.
pub static FUTEX_QUEUES: [Mutex<FutexQueue>; BUCKETS] = [const { Mutex::new(FutexQueue::new()) }; BUCKETS];

/// The bucket index of `key`.
fn bucket_index(key: &FutexKey) -> usize {
    let h = key.space.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (key.uaddr >> 2).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    (h >> 58) as usize % BUCKETS
}

/// The bucket of `key`.
fn bucket(key: &FutexKey) -> &'static Mutex<FutexQueue> {
    &FUTEX_QUEUES[bucket_index(key)]
}

/// Locks the buckets of two keys, the lower index first (one lock when they share it).
fn lock_two(a: &FutexKey, b: &FutexKey) -> (spin::MutexGuard<'static, FutexQueue>, Option<spin::MutexGuard<'static, FutexQueue>>) {
    let (i, j) = (bucket_index(a), bucket_index(b));
    if i == j {
        (FUTEX_QUEUES[i].lock(), None)
    } else if i < j {
        let first = FUTEX_QUEUES[i].lock();
        (first, Some(FUTEX_QUEUES[j].lock()))
    } else {
        let second = FUTEX_QUEUES[j].lock();
        (FUTEX_QUEUES[i].lock(), Some(second))
    }
}

/// Wakes up to `max` waiters on `key` whose bitset matches (for wakes from outside a futex
/// call, such as a thread's exit clearing its `clear_child_tid` word).
///
/// # Returns
/// The woken tasks, for the caller to make runnable.
pub fn wake_key(key: FutexKey, max: usize, bitset: u32) -> Vec<TaskId> {
    bucket(&key).lock().wake_task_ids(key, max, bitset)
}

/// Waiters moved to another futex by a requeue: (task, the key it waited on, the key it
/// waits on now). A waiter looks its entry up after waking; without requeues (glibc's
/// condition variables do not use them) the table stays empty and unlocked.
static REQUEUED: Mutex<Vec<(TaskId, FutexKey, FutexKey)>> = Mutex::new(Vec::new());
/// Entries in [`REQUEUED`].
static REQUEUED_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The key `task` waits on now, having started on `orig`.
fn current_key(task: TaskId, orig: FutexKey) -> FutexKey {
    if REQUEUED_COUNT.load(core::sync::atomic::Ordering::Acquire) == 0 {
        return orig;
    }
    REQUEUED.lock().iter().find(|e| e.0 == task && e.1 == orig).map_or(orig, |e| e.2)
}

/// Notes that `task`, waiting on `from`, now waits on `to`.
fn note_requeue(task: TaskId, from: FutexKey, to: FutexKey) {
    let mut r = REQUEUED.lock();
    match r.iter_mut().find(|e| e.0 == task && e.2 == from) {
        Some(e) => e.2 = to,
        None => r.push((task, from, to)),
    }
    REQUEUED_COUNT.store(r.len(), core::sync::atomic::Ordering::Release);
}

/// Forgets `task`'s requeue from `orig` (its wait ended).
fn forget_requeue(task: TaskId, orig: FutexKey) {
    if REQUEUED_COUNT.load(core::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    let mut r = REQUEUED.lock();
    r.retain(|e| !(e.0 == task && e.1 == orig));
    REQUEUED_COUNT.store(r.len(), core::sync::atomic::Ordering::Release);
}

/// Returns the identity of the calling task's address space (shared by threads of a process
/// and by a `vfork` child).
///
/// # Returns
///
/// Unique address space identifier (pointer or TGID).
fn current_space() -> u64 {
    crate::task::with_current_task_mut(|t| t.mm.as_ref().map_or(t.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64)).unwrap_or(0)
}

/// Sentinel `FutexKey::space` value for futexes keyed by physical address in shared mappings.
const PHYSICAL: u64 = u64::MAX;

/// Constructs a private [`FutexKey`] for virtual address `uaddr` in the calling task's address space.
///
/// # Arguments
/// * `uaddr` - User virtual address of the 32-bit futex word.
///
/// # Returns
/// A [`FutexKey`] scoped to the current address space.
pub fn key_of(uaddr: u64) -> FutexKey {
    FutexKey { space: current_space(), uaddr }
}

/// Computes the [`FutexKey`] for a futex operation: shared futexes in shared mappings are
/// keyed by the physical address of the word (faulting the page in first), while private
/// futexes are keyed by virtual address and address space.
///
/// # Arguments
///
/// * `uaddr` - User virtual address of the futex word.
/// * `private` - `true` if operation is private to address space; `false` if shared.
///
/// # Returns
///
/// Computed `FutexKey`.
fn key_for(uaddr: u64, private: bool) -> FutexKey {
    if !private && crate::memory::vm::prefault_current(uaddr & !3, 4, false) {
        if let Some(phys) = crate::memory::vm::shared_phys_current(uaddr) {
            return FutexKey { space: PHYSICAL, uaddr: phys };
        }
    }
    key_of(uaddr)
}

/// Constructs the [`FutexKey`] of `uaddr` in the address space of `task` (used when the
/// scheduler wakes `clear_child_tid` on thread exit while holding the scheduler lock).
///
/// # Arguments
/// * `task` - Reference to the exiting [`Task`](crate::task::Task).
/// * `uaddr` - User virtual address of the `clear_child_tid` futex word.
///
/// # Returns
/// The [`FutexKey`] corresponding to `uaddr` in `task`'s address space.
pub fn key_for_task(task: &crate::task::Task, uaddr: u64) -> FutexKey {
    FutexKey { space: task.mm.as_ref().map_or(task.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64), uaddr }
}

/// Reads a 4-byte aligned `u32` word from user memory at `uaddr`, prefaulting the page if necessary.
///
/// # Arguments
///
/// * `uaddr` - User virtual address.
///
/// # Returns
///
/// `Ok(val)` on success, or a negative Linux errno on error.
fn read_word(uaddr: u64) -> Result<u32, i64> {
    if uaddr & 3 != 0 || !crate::memory::vm::prefault_current(uaddr, 4, false) {
        return Err(if uaddr & 3 != 0 { EINVAL } else { EFAULT });
    }
    Ok(unsafe { core::ptr::read_volatile(uaddr as *const u32) })
}

/// Wakes each task in `ids` via the global task scheduler.
///
/// # Arguments
///
/// * `ids` - Slice of task IDs to wake.
fn wake_ids(ids: &[TaskId]) {
    if ids.is_empty() {
        return;
    }
    let mut sched = crate::task::SCHEDULER.lock();
    for id in ids {
        sched.wake_task(id.0);
    }
}

/// Computes the PIT deadline tick for a futex wait from a user `struct timespec` pointer.
///
/// Relative timespecs count from the current tick; absolute timespecs are evaluated against
/// `CLOCK_MONOTONIC` or (when `realtime` is `true`) the CMOS wall clock (`CLOCK_REALTIME`).
///
/// # Arguments
///
/// * `ts_ptr` - User virtual pointer to `struct timespec` (or `0`).
/// * `relative` - `true` if timespec is relative duration; `false` if absolute.
/// * `realtime` - `true` if clock is `CLOCK_REALTIME`.
///
/// # Returns
///
/// `Ok(Some(tick))` with absolute deadline tick, `Ok(None)` if no timeout, or `Err(errno)` on fault.
pub(crate) fn deadline_tick(ts_ptr: u64, relative: bool, realtime: bool) -> Result<Option<u64>, i64> {
    let tick = crate::arch::pit::tick_ns();
    Ok(deadline_ns(ts_ptr, relative, realtime)?.map(|d| d.div_ceil(tick)))
}

/// Absolute deadline (nanoseconds on the boot clock, [`crate::arch::pit::now_ns`]) of a
/// futex wait's `struct timespec` timeout: relative, or absolute on `CLOCK_REALTIME` or
/// `CLOCK_MONOTONIC`.
pub(crate) fn deadline_ns(ts_ptr: u64, relative: bool, realtime: bool) -> Result<Option<u64>, i64> {
    if ts_ptr == 0 {
        return Ok(None);
    }
    if !crate::memory::vm::prefault_current(ts_ptr, 16, false) {
        return Err(EFAULT);
    }
    let s = unsafe { core::ptr::read_unaligned(ts_ptr as *const i64) };
    let ns = unsafe { core::ptr::read_unaligned((ts_ptr + 8) as *const i64) };
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    let total_ns = s as i128 * 1_000_000_000 + ns as i128;
    let now = crate::arch::pit::now_ns() as i128;
    let target_ns = if relative {
        now + total_ns
    } else if realtime {
        let (rs, rns) = crate::arch::rtc::now();
        let offset = rs as i128 * 1_000_000_000 + rns as i128 - now;
        total_ns - offset
    } else {
        total_ns
    };
    Ok(Some(target_ns.max(0) as u64))
}

/// Implements `FUTEX_WAIT` and `FUTEX_WAIT_BITSET`: verifies `*uaddr == val` under the queue
/// lock and sleeps until woken by a waker, interrupted by a signal, or `deadline` expires.
///
/// # Arguments
///
/// * `uaddr` - User virtual address of the futex word.
/// * `val` - Expected current value of the futex word.
/// * `bitset` - Waiter bitset mask.
/// * `deadline` - Optional PIT tick deadline.
/// * `private` - `true` if private to process.
///
/// # Returns
///
/// `0` on successful wake, or a negative Linux errno on timeout/interruption.
fn wait(uaddr: u64, val: u32, bitset: u32, deadline: Option<u64>, private: bool) -> i64 {
    if bitset == 0 {
        return EINVAL;
    }
    if uaddr & 3 != 0 {
        return EINVAL;
    }
    let key = key_for(uaddr, private);
    let me = crate::task::SCHEDULER.lock().current_task_id();
    {
        let mut fq = bucket(&key).lock();
        // Checking the value and queueing happen under the bucket lock, so a waker that
        // changes the value first and then wakes cannot be missed
        match read_word(uaddr) {
            Ok(v) if v == val => {}
            Ok(_) => return EAGAIN,
            Err(e) => return e,
        }
        fq.waiters.push(FutexWaiter { key, task_id: me, bitset });
    }
    loop {
        crate::task::wait::wait_ns(deadline);
        // (a requeue may have moved the wait to another futex, and bucket)
        let now = current_key(me, key);
        let mut fq = bucket(&now).lock();
        if !fq.is_waiting(me, now) {
            drop(fq);
            forget_requeue(me, key);
            return 0; // woken
        }
        let end = if deadline.map_or(false, |d| crate::arch::pit::now_ns() >= d) {
            Some(ETIMEDOUT)
        } else if super::proc::signal_pending() {
            Some(if deadline.is_some() { EINTR } else { super::proc::ERESTARTSYS })
        } else {
            None
        };
        if let Some(e) = end {
            fq.remove(me, now);
            drop(fq);
            forget_requeue(me, key);
            return e;
        }
        // Spurious wakeup: keep waiting
    }
}

/// Compare-and-exchange on a user futex word; returns the value found.
///
/// # Arguments
///
/// * `uaddr` - User virtual address.
/// * `old` - Expected old value.
/// * `new` - Replacement new value.
///
/// # Returns
///
/// `Ok(found_value)` or `Err(errno)`.
fn user_cmpxchg(uaddr: u64, old: u32, new: u32) -> Result<u32, i64> {
    if uaddr & 3 != 0 || !crate::memory::vm::prefault_current(uaddr, 4, true) {
        return Err(if uaddr & 3 != 0 { EINVAL } else { EFAULT });
    }
    let word = unsafe { &*(uaddr as *const core::sync::atomic::AtomicU32) };
    Ok(match word.compare_exchange(old, new, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst) {
        Ok(v) | Err(v) => v,
    })
}

/// `FUTEX_LOCK_PI` / `FUTEX_TRYLOCK_PI`: takes a priority-inheritance lock whose word
/// holds the owner's thread id. Waiters set `FUTEX_WAITERS` so the owner unlocks through
/// the kernel, which wakes one of them. (One CPU and no real-time scheduling here, so
/// there is no priority to inherit; the protocol is what programs depend on.)
///
/// # Arguments
///
/// * `uaddr` - User virtual address.
/// * `deadline` - Optional tick deadline.
/// * `private` - Private futex flag.
/// * `try_only` - Non-blocking trylock flag.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
fn lock_pi(uaddr: u64, deadline: Option<u64>, private: bool, try_only: bool) -> i64 {
    let key = key_for(uaddr, private);
    let (tid, _) = super::proc::current_ids();
    let tid = tid as u32 & FUTEX_TID_MASK;
    let me = crate::task::SCHEDULER.lock().current_task_id();
    loop {
        {
            let mut fq = bucket(&key).lock();
            let v = match read_word(uaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let owner = v & FUTEX_TID_MASK;
            // Taking a free lock, or one whose owner died: keep the waiters bit for the others
            let dead_owner = owner != 0 && !crate::task::is_task_alive(TaskId(owner as u64));
            if owner == 0 || dead_owner {
                let others = fq.waiters.iter().any(|w| w.key == key && w.task_id != me);
                let died = if dead_owner { FUTEX_OWNER_DIED } else { v & FUTEX_OWNER_DIED };
                let new = tid | died | if others { FUTEX_WAITERS } else { 0 };
                match user_cmpxchg(uaddr, v, new) {
                    Ok(found) if found == v => {
                        fq.remove(me, key);
                        return 0;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        fq.remove(me, key);
                        return e;
                    }
                }
            }
            if owner == tid {
                fq.remove(me, key);
                return EDEADLK;
            }
            if try_only {
                return EAGAIN;
            }
            if v & FUTEX_WAITERS == 0 {
                match user_cmpxchg(uaddr, v, v | FUTEX_WAITERS) {
                    Ok(found) if found == v => {}
                    Ok(_) => continue,
                    Err(e) => return e,
                }
            }
            if !fq.is_waiting(me, key) {
                fq.waiters.push(FutexWaiter { key, task_id: me, bitset: FUTEX_BITSET_MATCH_ANY });
            }
        }
        crate::task::wait::wait_ns(deadline);
        if deadline.map_or(false, |d| crate::arch::pit::now_ns() >= d) {
            bucket(&key).lock().remove(me, key);
            return ETIMEDOUT;
        }
        if super::proc::signal_pending() {
            bucket(&key).lock().remove(me, key);
            return super::proc::ERESTARTSYS;
        }
    }
}

/// `FUTEX_UNLOCK_PI`: releases a lock the caller owns and wakes one waiter (which takes
/// the lock in [`lock_pi`], setting the waiters bit again for any others).
///
/// # Arguments
///
/// * `uaddr` - User virtual address.
/// * `private` - Private futex flag.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
fn unlock_pi(uaddr: u64, private: bool) -> i64 {
    let key = key_for(uaddr, private);
    let (tid, _) = super::proc::current_ids();
    let tid = tid as u32 & FUTEX_TID_MASK;
    let ids = {
        let mut fq = bucket(&key).lock();
        loop {
            let v = match read_word(uaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if v & FUTEX_TID_MASK != tid {
                return EPERM;
            }
            match user_cmpxchg(uaddr, v, 0) {
                Ok(found) if found == v => break,
                Ok(_) => continue,
                Err(e) => return e,
            }
        }
        fq.wake_task_ids(key, 1, FUTEX_BITSET_MATCH_ANY)
    };
    wake_ids(&ids);
    0
}

/// Applies an encoded `FUTEX_WAKE_OP` read-modify-write operation to `*uaddr2` and evaluates
/// whether its comparison against the old value holds.
///
/// # Arguments
///
/// * `uaddr2` - Second user futex address.
/// * `encoded` - Encoded `FUTEX_OP_*` value.
///
/// # Returns
///
/// * `Ok(true)` if comparison condition evaluated to true.
/// * `Ok(false)` if condition evaluated to false.
/// * `Err(-EFAULT)` if memory cannot be written.
fn wake_op_apply(uaddr2: u64, encoded: u32) -> Result<bool, i64> {
    if uaddr2 & 3 != 0 || !crate::memory::vm::prefault_current(uaddr2, 4, true) {
        return Err(EFAULT);
    }
    let op = (encoded >> 28) & 0xf;
    let cmp = (encoded >> 24) & 0xf;
    // Linux: oparg and cmparg are signed 12-bit values, and a shift count outside 0..=31
    // is taken modulo 32 (FUTEX_OP_OPARG_SHIFT)
    let sign12 = |v: u32| ((v as i32) << 20) >> 20;
    let mut oparg = sign12((encoded >> 12) & 0xfff) as u32;
    let cmparg = sign12(encoded & 0xfff);
    if op & 8 != 0 {
        oparg = 1u32 << (oparg & 31);
    }
    let p = uaddr2 as *mut u32;
    let old = unsafe { core::ptr::read_volatile(p) };
    let new = match op & 7 {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        4 => old ^ oparg,
        _ => return Err(ENOSYS),
    };
    unsafe { core::ptr::write_volatile(p, new) };
    let (o, c) = (old as i32, cmparg);
    Ok(match cmp {
        0 => o == c,
        1 => o != c,
        2 => o < c,
        3 => o <= c,
        4 => o > c,
        5 => o >= c,
        _ => return Err(ENOSYS),
    })
}

/// Whether futex operation `op` (with `val3`) is a private wake the system call fast path
/// serves (`FUTEX_WAKE`, or `FUTEX_WAKE_BITSET` with a nonzero mask, private).
pub fn fast_wake_op(op: i32, val3: u32) -> bool {
    let cmd = op & FUTEX_CMD_MASK;
    // (with FUTEX_CLOCK_REALTIME the slow path answers ENOSYS)
    op & FUTEX_PRIVATE_FLAG != 0 && op & FUTEX_CLOCK_REALTIME == 0 && (cmd == FUTEX_WAKE || (cmd == FUTEX_WAKE_BITSET && val3 != 0))
}

/// A private futex wake without the kernel lock (see [`fast_wake_op`]): it touches no user
/// memory, only the futex queue and, for the waiters it wakes, the scheduler.
///
/// # Arguments
/// * `space` - The caller's address space (as [`key_of`] computes it).
/// * `uaddr`, `val`, `op`, `val3` - The `futex` arguments.
///
/// # Returns
/// The number of waiters woken.
pub fn fast_wake(space: u64, uaddr: u64, val: u32, op: i32, val3: u32) -> i64 {
    if uaddr & 3 != 0 {
        return EINVAL; // as dispatch_futex
    }
    let bitset = if op & FUTEX_CMD_MASK == FUTEX_WAKE { FUTEX_BITSET_MATCH_ANY } else { val3 };
    let ids = wake_key(FutexKey { space, uaddr }, val as usize, bitset);
    wake_ids(&ids);
    ids.len() as i64
}

/// Top-level system call dispatcher for `sys_futex` (`SYSCALL 202`).
///
/// # Arguments
/// * `uaddr` - User virtual address of the primary 32-bit futex word (must be 4-byte aligned).
/// * `op` - Futex command (`FUTEX_WAIT`, `FUTEX_WAKE`, etc.) combined with [`FUTEX_PRIVATE_FLAG`]
///   and [`FUTEX_CLOCK_REALTIME`].
/// * `val` - Expected value for `WAIT` or maximum number of waiters to wake for `WAKE`/`REQUEUE`.
/// * `timeout` - Pointer to `struct timespec` for `WAIT*`, or `val2` (requeue/wake limit) for
///   `REQUEUE`/`WAKE_OP`.
/// * `uaddr2` - Secondary futex word address for `REQUEUE` and `WAKE_OP`.
/// * `val3` - Bitmask for `*_BITSET`, expected value for `CMP_REQUEUE`, or encoded op for `WAKE_OP`.
///
/// # Returns
/// * `0` on a successful `FUTEX_WAIT*` wakeup.
/// * Number of woken (and for `CMP_REQUEUE`, requeued) waiters for `WAKE`/`REQUEUE`/`WAKE_OP`.
/// * Negative errno (`-EAGAIN`, `-EINTR`, `-ETIMEDOUT`, `-EINVAL`, `-EFAULT`, `-ENOSYS`) on error.
pub fn dispatch_futex(uaddr: u64, op: i32, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
    let cmd = op & FUTEX_CMD_MASK;
    let realtime = op & FUTEX_CLOCK_REALTIME != 0;
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    let key_of = |addr: u64| key_for(addr, private);
    // Linux: FUTEX_CLOCK_REALTIME only on the commands with an absolute timeout on a
    // chosen clock; futex words are 32-bit aligned (EINVAL), the second one too
    if realtime && !matches!(cmd, FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI | FUTEX_LOCK_PI2) {
        return ENOSYS;
    }
    let known = matches!(
        cmd,
        FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAKE | FUTEX_WAKE_BITSET | FUTEX_REQUEUE | FUTEX_CMP_REQUEUE | FUTEX_WAKE_OP
            | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI | FUTEX_UNLOCK_PI
    );
    let two_words = matches!(cmd, FUTEX_REQUEUE | FUTEX_CMP_REQUEUE | FUTEX_WAKE_OP);
    if known && (uaddr & 3 != 0 || (two_words && uaddr2 & 3 != 0)) {
        return EINVAL;
    }
    match cmd {
        FUTEX_WAIT => match deadline_ns(timeout, true, false) {
            Ok(d) => wait(uaddr, val, FUTEX_BITSET_MATCH_ANY, d, private),
            Err(e) => e,
        },
        FUTEX_WAIT_BITSET => match deadline_ns(timeout, false, realtime) {
            Ok(d) => wait(uaddr, val, val3, d, private),
            Err(e) => e,
        },
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let bitset = if cmd == FUTEX_WAKE { FUTEX_BITSET_MATCH_ANY } else { val3 };
            if bitset == 0 {
                return EINVAL;
            }
            let ids = wake_key(key_of(uaddr), val as usize, bitset);
            wake_ids(&ids);
            ids.len() as i64
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            // `timeout` carries the maximum number of waiters to requeue; both counts are
            // ints on Linux and must not be negative
            if (val as i32) < 0 || (timeout as u32 as i32) < 0 {
                return EINVAL;
            }
            let (from, to) = (key_of(uaddr), key_of(uaddr2));
            let (mut a, mut b) = lock_two(&from, &to);
            if cmd == FUTEX_CMP_REQUEUE {
                match read_word(uaddr) {
                    Ok(v) if v == val3 => {}
                    Ok(_) => return EAGAIN,
                    Err(e) => return e,
                }
            }
            // Both buckets are held: `a` is `from`'s, `b` is `to`'s (none when they share one)
            let ids = a.wake_task_ids(from, val as usize, FUTEX_BITSET_MATCH_ANY);
            let moving = if from == to { Vec::new() } else { a.take(from, timeout as u32 as usize) };
            let moved = moving.len();
            let to_q = match b.as_mut() {
                Some(q) => q,
                None => &mut a,
            };
            for w in moving {
                note_requeue(w.task_id, from, to);
                to_q.waiters.push(FutexWaiter { key: to, ..w });
            }
            drop(b);
            drop(a);
            wake_ids(&ids);
            // Linux returns the waiters woken plus those requeued, for both commands
            (ids.len() + moved) as i64
        }
        FUTEX_WAKE_OP => {
            let (k1, k2) = (key_of(uaddr), key_of(uaddr2));
            let (mut a, mut b) = lock_two(&k1, &k2);
            let fire = match wake_op_apply(uaddr2, val3) {
                Ok(f) => f,
                Err(e) => return e,
            };
            // `a` is k1's bucket, `b` k2's (none when they share one)
            let mut ids = a.wake_task_ids(k1, val as usize, FUTEX_BITSET_MATCH_ANY);
            if fire {
                // `timeout` carries the number of waiters to wake on uaddr2
                let q2 = match b.as_mut() {
                    Some(q) => q,
                    None => &mut a,
                };
                ids.extend(q2.wake_task_ids(k2, timeout as u32 as usize, FUTEX_BITSET_MATCH_ANY));
            }
            drop(b);
            drop(a);
            wake_ids(&ids);
            ids.len() as i64
        }
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => {
            // LOCK_PI's absolute timeout is CLOCK_REALTIME; LOCK_PI2 follows the flag
            let rt = cmd == FUTEX_LOCK_PI || realtime;
            match deadline_ns(timeout, false, rt) {
                Ok(d) => lock_pi(uaddr, d, private, false),
                Err(e) => e,
            }
        }
        FUTEX_TRYLOCK_PI => lock_pi(uaddr, None, private, true),
        FUTEX_UNLOCK_PI => unlock_pi(uaddr, private),
        // PI requeueing and futex descriptors
        _ => ENOSYS,
    }
}

/// `FUTEX2_SIZE_U32`: the futex word is 32 bits (the only size Linux supports).
const FUTEX2_SIZE_U32: u32 = 2;
/// `FUTEX2_SIZE_MASK`: the size bits of a futex2 flags word.
const FUTEX2_SIZE_MASK: u32 = 3;
/// `FUTEX2_PRIVATE`: private to the process (same bit as `FUTEX_PRIVATE_FLAG`).
const FUTEX2_PRIVATE: u32 = 128;
/// Most futexes one `futex_waitv` may wait on.
const FUTEX_WAITV_MAX: u64 = 128;

/// Checks futex2 flags (32-bit size required) and returns whether the futex is private.
fn futex2_private(flags: u32) -> Result<bool, i64> {
    if flags & !(FUTEX2_SIZE_MASK | FUTEX2_PRIVATE) != 0 || flags & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32 {
        return Err(EINVAL);
    }
    Ok(flags & FUTEX2_PRIVATE != 0)
}

/// Absolute deadline of a futex2 timeout on `clockid` (`CLOCK_MONOTONIC` or `CLOCK_REALTIME`).
fn futex2_deadline(timeout: u64, clockid: u64) -> Result<Option<u64>, i64> {
    match clockid {
        0 => deadline_ns(timeout, false, true),
        1 => deadline_ns(timeout, false, false),
        _ if timeout == 0 => Ok(None),
        _ => Err(EINVAL),
    }
}

/// `futex_waitv(2)`: waits on up to 128 futexes at once; returns the index of one that
/// was woken.
///
/// # Arguments
/// * `waiters` - User pointer to `struct futex_waitv[nr]` (value, address, flags).
/// * `nr` - Number of futexes.
/// * `flags` - Must be 0.
/// * `timeout` - Absolute timeout on `clockid`, or 0.
/// * `clockid` - `CLOCK_MONOTONIC` or `CLOCK_REALTIME`.
///
/// # Returns
/// The index of a woken futex, `-EAGAIN` if a value differed, `-ETIMEDOUT`, or `-ERESTARTSYS`.
pub fn sys_futex_waitv(waiters: u64, nr: u64, flags: u64, timeout: u64, clockid: u64) -> i64 {
    if flags != 0 || nr == 0 || nr > FUTEX_WAITV_MAX {
        return EINVAL;
    }
    let deadline = match futex2_deadline(timeout, clockid) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if !crate::memory::vm::prefault_current(waiters, nr * 24, false) {
        return EFAULT;
    }
    let mut entries = Vec::with_capacity(nr as usize);
    for i in 0..nr {
        let raw = unsafe { core::ptr::read_unaligned((waiters + i * 24) as *const [u64; 3]) };
        let (val, uaddr, wflags) = (raw[0], raw[1], (raw[2] & 0xffff_ffff) as u32);
        if raw[2] >> 32 != 0 || uaddr & 3 != 0 || val > u32::MAX as u64 {
            return EINVAL;
        }
        let private = match futex2_private(wflags) {
            Ok(p) => p,
            Err(e) => return e,
        };
        entries.push((key_for(uaddr, private), uaddr, val as u32));
    }
    let me = crate::task::SCHEDULER.lock().current_task_id();
    {
        // All values are checked and all waiters queued with every involved bucket locked
        // (in index order)
        let mut idx: Vec<usize> = entries.iter().map(|(k, _, _)| bucket_index(k)).collect();
        idx.sort_unstable();
        idx.dedup();
        let mut held: Vec<(usize, spin::MutexGuard<'static, FutexQueue>)> = idx.iter().map(|&i| (i, FUTEX_QUEUES[i].lock())).collect();
        for (_, uaddr, val) in &entries {
            match read_word(*uaddr) {
                Ok(v) if v == *val => {}
                Ok(_) => return EAGAIN,
                Err(e) => return e,
            }
        }
        for (key, _, _) in &entries {
            let i = bucket_index(key);
            if let Some((_, q)) = held.iter_mut().find(|(j, _)| *j == i) {
                q.waiters.push(FutexWaiter { key: *key, task_id: me, bitset: FUTEX_BITSET_MATCH_ANY });
            }
        }
    }
    // Ends the wait: every entry still queued goes, and the requeue notes with it
    let finish = |result: i64| -> i64 {
        for (key, _, _) in &entries {
            let now = current_key(me, *key);
            bucket(&now).lock().remove(me, now);
            forget_requeue(me, *key);
        }
        result
    };
    loop {
        crate::task::wait::wait_ns(deadline);
        // A waker removes the entry it wakes: the first missing one is the answer
        let woken = entries.iter().position(|(key, _, _)| {
            let now = current_key(me, *key);
            !bucket(&now).lock().is_waiting(me, now)
        });
        if let Some(i) = woken {
            return finish(i as i64);
        }
        if deadline.map_or(false, |d| crate::arch::pit::now_ns() >= d) {
            return finish(ETIMEDOUT);
        }
        if super::proc::signal_pending() {
            return finish(super::proc::ERESTARTSYS);
        }
    }
}

/// `futex_wake(2)` (futex2): wakes up to `nr` waiters on `uaddr` matching `mask`.
pub fn sys_futex_wake(uaddr: u64, mask: u64, nr: u64, flags: u64) -> i64 {
    let private = match futex2_private(flags as u32) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if flags >> 32 != 0 || mask as u32 == 0 {
        return EINVAL;
    }
    let op = FUTEX_WAKE_BITSET | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    dispatch_futex(uaddr, op, nr.min(i32::MAX as u64) as u32, 0, 0, mask as u32)
}

/// `futex_wait(2)` (futex2): waits on `uaddr` while it holds `val`, until woken through
/// `mask` or the absolute `timeout` on `clockid`.
pub fn sys_futex_wait(uaddr: u64, val: u64, mask: u64, flags: u64, timeout: u64, clockid: u64) -> i64 {
    let private = match futex2_private(flags as u32) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if val > u32::MAX as u64 || mask as u32 == 0 {
        return EINVAL;
    }
    match futex2_deadline(timeout, clockid) {
        Ok(d) => wait(uaddr, val as u32, mask as u32, d, private),
        Err(e) => e,
    }
}

/// `futex_requeue(2)` (futex2): `waiters[0]` must still hold its value; wakes `nr_wake`
/// of its waiters and moves up to `nr_requeue` to `waiters[1]`.
pub fn sys_futex_requeue(waiters: u64, flags: u64, nr_wake: u64, nr_requeue: u64) -> i64 {
    if flags != 0 || !crate::memory::vm::prefault_current(waiters, 48, false) {
        return if flags != 0 { EINVAL } else { EFAULT };
    }
    let w = unsafe { core::ptr::read_unaligned(waiters as *const [u64; 6]) };
    let (p0, p1) = match (futex2_private(w[2] as u32), futex2_private(w[5] as u32)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return EINVAL,
    };
    if p0 != p1 {
        return EINVAL;
    }
    let op = FUTEX_CMP_REQUEUE | if p0 { FUTEX_PRIVATE_FLAG } else { 0 };
    dispatch_futex(w[1], op, nr_wake.min(i32::MAX as u64) as u32, nr_requeue.min(i32::MAX as u64), w[4], w[0] as u32)
}
