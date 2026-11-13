//! Tests for futexes (`src/compat/linux/futex.rs`) through `futex::dispatch_futex`: the
//! word checks, timeouts, wake/requeue counting, FUTEX_WAKE_OP's encoded operation and
//! priority-inheritance locks. Every expected value was checked on Linux 5.15
//! (tests/linux/futex_test.c, which also runs under QEMU).
//!
//! Waiting threads are real host threads with their own task id: the fake `wait_ns`
//! spins when `fake::SPIN_WAITS` is set, so a waker on another thread ends the wait.
//! With a deadline the fake clock jumps to it, so timeouts are immediate.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use hydra_hosttests::compat::linux::futex::{
    dispatch_futex, FUTEX_CLOCK_REALTIME, FUTEX_CMP_REQUEUE, FUTEX_LOCK_PI, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE, FUTEX_TRYLOCK_PI,
    FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP,
};
use hydra_hosttests::fake;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const EDEADLK: i64 = -35;
const ENOSYS: i64 = -38;
const ETIMEDOUT: i64 = -110;

const P: i32 = FUTEX_PRIVATE_FLAG;
const OWNER_DIED: u32 = 0x4000_0000;

// FUTEX_OP_* encodings
const OP_SET: u32 = 0;
const OP_ADD: u32 = 1;
const OP_OPARG_SHIFT: u32 = 8;
const CMP_EQ: u32 = 0;
const CMP_GT: u32 = 4;

fn wake_op(op: u32, oparg: u32, cmp: u32, cmparg: u32) -> u32 {
    (op << 28) | (cmp << 24) | ((oparg & 0xfff) << 12) | (cmparg & 0xfff)
}

/// A futex word with its own address.
fn word(v: u32) -> Arc<AtomicU32> {
    Arc::new(AtomicU32::new(v))
}

fn addr(w: &AtomicU32) -> u64 {
    w as *const AtomicU32 as u64
}

/// Runs `FUTEX_WAIT` on `w` (expecting its current value) on a new thread with task id
/// `tid` in process 1, and returns a receiver for its result.
fn waiter(w: &Arc<AtomicU32>, tid: u64) -> mpsc::Receiver<i64> {
    let (tx, rx) = mpsc::channel();
    let w = w.clone();
    std::thread::spawn(move || {
        fake::IDS.set((tid, 1));
        fake::SPIN_WAITS.set(true);
        let v = w.load(Ordering::SeqCst);
        let _ = tx.send(dispatch_futex(addr(&w), FUTEX_WAIT | P, v, 0, 0, 0));
    });
    rx
}

/// Gives waiter threads time to queue.
fn settle() {
    std::thread::sleep(Duration::from_millis(150));
}

fn woken(rx: &mpsc::Receiver<i64>) -> bool {
    rx.recv_timeout(Duration::from_secs(5)) == Ok(0)
}

#[test]
fn wait_checks_the_word_and_times_out() {
    let w = word(5);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 6, 0, 0, 0), EAGAIN, "value differs");
    let ts: [i64; 2] = [0, 10_000_000];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, ts.as_ptr() as u64, 0, 0), ETIMEDOUT);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE | P, 1, 0, 0, 0), 0, "the timed-out waiter left the queue");
    let bad: [i64; 2] = [0, 1_000_000_000];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, bad.as_ptr() as u64, 0, 0), EINVAL, "tv_nsec 1e9");
    let neg: [i64; 2] = [-1, 0];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, neg.as_ptr() as u64, 0, 0), EINVAL, "negative tv_sec");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT_BITSET | P, 5, 0, 0, 0), EINVAL, "bitset 0");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE_BITSET | P, 1, 0, 0, 0), EINVAL, "bitset 0");
    assert_eq!(dispatch_futex(addr(&w), 99, 0, 0, 0, 0), ENOSYS, "unknown command");
}

#[test]
fn clock_realtime_is_only_for_commands_with_an_absolute_timeout() {
    let w = word(0);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE | P | FUTEX_CLOCK_REALTIME, 1, 0, 0, 0), ENOSYS);
}

#[test]
fn misaligned_words_are_einval() {
    let w = word(0);
    let odd = addr(&w) + 1;
    assert_eq!(dispatch_futex(odd, FUTEX_WAKE | P, 1, 0, 0, 0), EINVAL, "WAKE");
    assert_eq!(dispatch_futex(odd, FUTEX_WAIT | P, 0, 0, 0, 0), EINVAL, "WAIT");
    let w2 = word(0);
    let odd2 = addr(&w2) + 2;
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE_OP | P, 1, 1, odd2, wake_op(OP_SET, 0, CMP_EQ, 0)), EINVAL, "WAKE_OP uaddr2");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_REQUEUE | P, 1, 1, odd2, 0), EINVAL, "REQUEUE uaddr2");
    assert_eq!(w2.load(Ordering::SeqCst), 0, "nothing was written");
}

#[test]
fn wake_op_arguments_are_signed_12_bit_values() {
    let (a, b) = (word(0), word(10));
    dispatch_futex(addr(&a), FUTEX_WAKE_OP | P, 0, 0, addr(&b), wake_op(OP_ADD, 0xfff, CMP_EQ, 0));
    assert_eq!(b.load(Ordering::SeqCst), 9, "ADD 0xfff adds -1");
    b.store(0, Ordering::SeqCst);
    dispatch_futex(addr(&a), FUTEX_WAKE_OP | P, 0, 0, addr(&b), wake_op(OP_SET | OP_OPARG_SHIFT, 33, CMP_EQ, 0));
    assert_eq!(b.load(Ordering::SeqCst), 2, "a shift of 33 is a shift of 1");
}

#[test]
fn wake_op_compares_against_a_signed_cmparg() {
    let (a, b) = (word(0), word(0));
    let rx = waiter(&b, 0x7101);
    settle();
    // old value 0 > cmparg 0xfff (-1): the waiter on uaddr2 is woken
    let r = dispatch_futex(addr(&a), FUTEX_WAKE_OP | P, 0, 1, addr(&b), wake_op(OP_SET, 0, CMP_GT, 0xfff));
    if r == 0 {
        dispatch_futex(addr(&b), FUTEX_WAKE | P, 1, 0, 0, 0); // let the thread go
    }
    assert_eq!(r, 1);
    assert!(woken(&rx));
}

#[test]
fn requeue_counts_must_not_be_negative() {
    let (a, b) = (word(0), word(0));
    assert_eq!(dispatch_futex(addr(&a), FUTEX_REQUEUE | P, u32::MAX, 1, addr(&b), 0), EINVAL, "nr_wake -1");
    assert_eq!(dispatch_futex(addr(&a), FUTEX_REQUEUE | P, 1, u64::MAX, addr(&b), 0), EINVAL, "nr_requeue -1");
    a.store(5, Ordering::SeqCst);
    assert_eq!(dispatch_futex(addr(&a), FUTEX_CMP_REQUEUE | P, 1, 1, addr(&b), 6), EAGAIN, "word changed");
}

/// Both requeue commands return the waiters woken plus those moved (Linux's task_count).
#[test]
fn requeue_returns_woken_plus_requeued() {
    for cmd in [FUTEX_REQUEUE, FUTEX_CMP_REQUEUE] {
        let (a, b) = (word(0), word(0));
        let base = if cmd == FUTEX_REQUEUE { 0x7200 } else { 0x7300 };
        let rx: Vec<_> = (0..4).map(|i| waiter(&a, base + i)).collect();
        settle();
        let r = dispatch_futex(addr(&a), cmd | P, 1, i32::MAX as u64, addr(&b), 0);
        let moved = dispatch_futex(addr(&b), FUTEX_WAKE | P, i32::MAX as u32, 0, 0, 0);
        dispatch_futex(addr(&a), FUTEX_WAKE | P, i32::MAX as u32, 0, 0, 0);
        assert!(rx.iter().all(woken), "every waiter ends");
        assert_eq!((r, moved), (4, 3), "command {cmd}: 1 woken + 3 requeued, and the 3 wait on uaddr2");
    }
}

#[test]
fn pi_lock_protocol() {
    let w = word(0);
    let (tid, _) = fake::IDS.get();
    assert_eq!(dispatch_futex(addr(&w), FUTEX_LOCK_PI | P, 0, 0, 0, 0), 0, "free lock");
    assert_eq!(w.load(Ordering::SeqCst), tid as u32, "the word holds the owner");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_LOCK_PI | P, 0, 0, 0, 0), EDEADLK, "the owner again");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), 0);
}

#[test]
fn a_pi_lock_held_by_a_live_task_is_not_taken() {
    let w = word(0x7400);
    fake::SIBLINGS.with_borrow_mut(|v| v.push(fake::Task::sibling(0x7400)));
    assert_eq!(dispatch_futex(addr(&w), FUTEX_TRYLOCK_PI | P, 0, 0, 0, 0), EAGAIN);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), EPERM, "not ours to unlock");
    assert_eq!(w.load(Ordering::SeqCst), 0x7400, "still the other task's");
}

/// Linux refuses a lock whose owner never existed or exited without the robust-list
/// cleanup (ESRCH); only a word the robust list released (owner 0, OWNER_DIED) is free.
#[test]
#[ignore = "BUG 42: robust lists are not walked at thread exit, so a dead owner's PI lock is taken over (OWNER_DIED) instead of ESRCH"]
fn a_pi_lock_whose_owner_does_not_exist_is_esrch() {
    let w = word(0x3fff_fff0);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_LOCK_PI | P, 0, 0, 0, 0), ESRCH);
    assert_eq!(w.load(Ordering::SeqCst), 0x3fff_fff0, "left alone");
}

#[test]
fn a_pi_lock_released_by_a_dead_owner_keeps_owner_died() {
    let w = word(OWNER_DIED);
    let (tid, _) = fake::IDS.get();
    assert_eq!(dispatch_futex(addr(&w), FUTEX_LOCK_PI | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), tid as u32 | OWNER_DIED, "OWNER_DIED stays for the new owner");
}

/// The system call fast path (private FUTEX_WAKE without the kernel lock) follows the
/// same rules: a realtime flag is not for it, and a misaligned word is EINVAL.
#[test]
fn the_fast_wake_path_checks_like_the_slow_one() {
    use hydra_hosttests::compat::linux::futex::{fast_wake, fast_wake_op};
    assert!(!fast_wake_op(FUTEX_WAKE | P | FUTEX_CLOCK_REALTIME, 0), "realtime: the slow path answers ENOSYS");
    assert!(fast_wake_op(FUTEX_WAKE | P, 0));
    let w = word(0);
    assert_eq!(fast_wake(1, addr(&w) + 1, 1, FUTEX_WAKE | P, 0), EINVAL);
    assert_eq!(fast_wake(1, addr(&w), 1, FUTEX_WAKE | P, 0), 0);
}
