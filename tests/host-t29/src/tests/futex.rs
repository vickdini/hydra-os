//! `src/compat/linux/futex.rs`: wait/wake (plain and bitset), timeouts and signals,
//! requeue, wake-op, priority-inheritance locks, robust lists, the lock-free fast wake and
//! the futex2 calls (`futex_waitv`, `futex_wake`, `futex_wait`, `futex_requeue`).
//!
//! Several threads are blocked at once with scripted steps (`fake::step`): each wait runs
//! the next step, which switches to another thread and may wait or wake in turn.

use super::common::*;
use crate::compat::linux::futex::*;
use std::sync::atomic::{AtomicU32, Ordering};

const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const EDEADLK: i64 = -35;
const ENOSYS: i64 = -38;
const EPERM: i64 = -1;
const ETIMEDOUT: i64 = -110;
const ERESTARTSYS: i64 = -512;

const P: i32 = FUTEX_PRIVATE_FLAG;
const WAITERS: u32 = 0x8000_0000;
const OWNER_DIED: u32 = 0x4000_0000;

/// A futex word in host memory (user pointers are host pointers here).
fn word(v: u32) -> Box<AtomicU32> {
    Box::new(AtomicU32::new(v))
}

fn addr(w: &AtomicU32) -> u64 {
    w as *const AtomicU32 as u64
}

/// Process 4000 with threads 4001..=4003; runs as 4000.
fn threads() {
    spawn(4000, 0);
    for t in 4001..=4003 {
        add_thread(4000, t);
    }
    run(4000);
}

fn wake(w: &AtomicU32, n: u32) -> i64 {
    dispatch_futex(addr(w), FUTEX_WAKE | P, n, 0, 0, 0)
}

#[test]
fn argument_checks() {
    let _g = setup();
    threads();
    let w = word(0);
    assert_eq!(wake(&w, 1), 0, "nobody waits");
    assert_eq!(dispatch_futex(addr(&w) + 1, FUTEX_WAKE, 1, 0, 0, 0), EINVAL, "misaligned");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_REQUEUE, 1, 0, addr(&w) + 2, 0), EINVAL, "misaligned second word");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE | FUTEX_CLOCK_REALTIME, 1, 0, 0, 0), ENOSYS);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_FD, 0, 0, 0, 0), ENOSYS);
    assert_eq!(dispatch_futex(addr(&w), 11, 0, 0, 0, 0), ENOSYS, "FUTEX_WAIT_REQUEUE_PI");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAKE_BITSET, 1, 0, 0, 0), EINVAL, "an empty bitset");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT_BITSET, 0, 0, 0, 0), EINVAL);
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT, 1, 0, 0, 0), EAGAIN, "the value changed");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_REQUEUE, u32::MAX, 0, addr(&w), 0), EINVAL, "a negative count");
    assert_eq!(dispatch_futex(addr(&w), FUTEX_REQUEUE, 1, u32::MAX as u64, addr(&w), 0), EINVAL);
    let bad = [-1i64, 0];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT, 0, ptr(&bad), 0, 0), EINVAL, "a negative timeout");
    let bad = [0i64, 1_000_000_000];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT, 0, ptr(&bad), 0, 0), EINVAL);
    with_current_mm(|| {
        assert_eq!(dispatch_futex(8, FUTEX_WAIT, 0, 0, 0, 0), -14, "unreadable word");
        assert_eq!(dispatch_futex(8, FUTEX_WAIT, 0, 16, 0, 0), -14, "unreadable timeout");
    });
}

#[test]
fn wait_timeouts_and_signals() {
    let _g = setup();
    threads();
    let w = word(5);
    // A relative timeout: ETIMEDOUT once the clock passes it
    let t0 = fake::TICKS.get();
    let ts = [0i64, 3_000_000];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, ptr(&ts), 0, 0), ETIMEDOUT);
    assert!(fake::TICKS.get() >= t0 + 3);
    // An absolute monotonic deadline (WAIT_BITSET), and one on CLOCK_REALTIME
    let at = (fake::TICKS.get() + 2) * 1_000_000;
    let abs = [(at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64];
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT_BITSET | P, 5, ptr(&abs), 0, 1), ETIMEDOUT);
    let wall = [1_767_225_600i64 + 1, 0];
    let before = fake::TICKS.get();
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT_BITSET | P | FUTEX_CLOCK_REALTIME, 5, ptr(&wall), 0, !0), ETIMEDOUT);
    assert!(fake::TICKS.get() >= before + 1000 - 5, "about one second (the RTC is 1 s ahead of the deadline's base)");
    // A signal: ERESTARTSYS without a timeout, EINTR with one
    fake::step(|| {
        linux::proc::post_process(4000, 10);
    });
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, 0, 0, 0), ERESTARTSYS);
    let long = [100i64, 0];
    fake::step(|| {});
    assert_eq!(dispatch_futex(addr(&w), FUTEX_WAIT | P, 5, ptr(&long), 0, 0), EINTR);
    linux::proc::PROCS.lock().get_mut(&4000).unwrap().pending = 0;
    // deadline helpers
    assert_eq!(deadline_tick(0, true, false), Ok(None));
    let ts = [0i64, 2_500_000];
    let now = fake::TICKS.get();
    assert_eq!(deadline_tick(ptr(&ts), true, false), Ok(Some(now + 3)), "rounded up to a tick");
    let past = [0i64, 0];
    assert_eq!(deadline_ns(ptr(&past), false, true), Ok(Some(0)), "a realtime deadline long gone");
}

#[test]
fn wait_and_wake_between_threads() {
    let _g = setup();
    threads();
    let w = word(1);
    let a = addr(&w);
    // 4000 waits; 4001 wakes it (after a spurious wakeup that changes nothing)
    fake::step(|| {});
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(dispatch_futex(a, FUTEX_WAKE | P, 10, 0, 0, 0), 1);
    });
    assert_eq!(dispatch_futex(a, FUTEX_WAIT | P, 1, 0, 0, 0), 0);
    assert!(fake::WOKEN.with_borrow(|v| v.contains(&4000)));
    // Bitsets: a wake with a disjoint bitset leaves the waiter
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(dispatch_futex(a, FUTEX_WAKE_BITSET | P, 1, 0, 0, 0b10), 0);
        assert_eq!(dispatch_futex(a, FUTEX_WAKE_BITSET | P, 1, 0, 0, 0b01), 1);
    });
    assert_eq!(dispatch_futex(a, FUTEX_WAIT_BITSET | P, 1, 0, 0, 0b01), 0);
    // A shared (non-private) futex in private memory is keyed like a private one
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a, FUTEX_WAKE, 1, 0, 0, 0), 1);
    });
    assert_eq!(dispatch_futex(a, FUTEX_WAIT, 1, 0, 0, 0), 0);
    // The futex fast path
    assert!(fast_wake_op(FUTEX_WAKE | P, 0));
    assert!(fast_wake_op(FUTEX_WAKE_BITSET | P, 1));
    assert!(!fast_wake_op(FUTEX_WAKE_BITSET | P, 0));
    assert!(!fast_wake_op(FUTEX_WAKE, 0), "shared");
    assert!(!fast_wake_op(FUTEX_WAKE | P | FUTEX_CLOCK_REALTIME, 0));
    assert!(!fast_wake_op(FUTEX_WAIT | P, 0));
    let space = key_of(a).space;
    assert_eq!(space, 4000, "no address space: keyed by the process");
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(fast_wake(space, a, 1, FUTEX_WAKE | P, 0), 1);
    });
    assert_eq!(dispatch_futex(a, FUTEX_WAIT | P, 1, 0, 0, 0), 0);
    assert_eq!(fast_wake(space, a + 1, 1, FUTEX_WAKE | P, 0), EINVAL);
    assert_eq!(fast_wake(space, a, 1, FUTEX_WAKE_BITSET | P, 4), 0);
    // key_for_task: the exiting thread's clear_child_tid wake
    let k = fake::task(4001, |t| key_for_task(t, a)).unwrap();
    assert_eq!(k, FutexKey { space: 4000, uaddr: a });
    assert!(wake_key(k, 1, !0).is_empty());
}

#[test]
fn requeue_moves_waiters() {
    let _g = setup();
    threads();
    let f1 = word(7);
    let f2 = word(0);
    let (a1, a2) = (addr(&f1), addr(&f2));
    // 4000 and 4001 wait on f1; 4002 requeues both to f2 (CMP_REQUEUE checks f1 still 7),
    // then wakes them one at a time on f2
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, 0, 0, 0), 0, "4001 woken on f2");
    });
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a1, FUTEX_CMP_REQUEUE | P, 0, 10, a2, 8), EAGAIN, "f1 is not 8");
        assert_eq!(dispatch_futex(a1, FUTEX_CMP_REQUEUE | P, 0, 10, a2, 7), 2, "two requeued");
        assert_eq!(dispatch_futex(a1, FUTEX_WAKE | P, 10, 0, 0, 0), 0, "nobody left on f1");
        assert_eq!(dispatch_futex(a2, FUTEX_WAKE | P, 1, 0, 0, 0), 1, "the first waiter (4000)");
    });
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a2, FUTEX_WAKE | P, 1, 0, 0, 0), 1, "then 4001");
    });
    assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, 0, 0, 0), 0);
    // Plain REQUEUE: wake one, move the other; requeue onto the same futex only wakes
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, 0, 0, 0), 0);
    });
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a1, FUTEX_REQUEUE | P, 0, 0, a1, 0), 0, "same futex, nothing woken");
        assert_eq!(dispatch_futex(a1, FUTEX_REQUEUE | P, 1, 5, a2, 0), 2, "one woken (4000), one moved");
    });
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a2, FUTEX_WAKE | P, 1, 0, 0, 0), 1);
    });
    assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, 0, 0, 0), 0);
    // A requeued waiter that times out leaves the new futex's queue
    fake::step(move || {
        fake::switch_to(4001);
        let ts = [0i64, 5_000_000];
        assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, ptr(&ts), 0, 0), ETIMEDOUT);
    });
    fake::step(move || {
        fake::switch_to(4002);
        assert_eq!(dispatch_futex(a1, FUTEX_REQUEUE | P, 1, 5, a2, 0), 2);
    });
    let ts = [0i64, 1_000_000];
    // 4000's own wait: woken by the requeue's wake (first in line)
    assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 7, ptr(&ts), 0, 0), 0);
    assert_eq!(dispatch_futex(a2, FUTEX_WAKE | P, 10, 0, 0, 0), 0, "4001 left f2 when it timed out");
}

#[test]
fn wake_op_operations() {
    let _g = setup();
    threads();
    let w1 = word(0);
    let w2 = word(10);
    let (a1, a2) = (addr(&w1), addr(&w2));
    // encoded: op << 28 | cmp << 24 | oparg << 12 | cmparg
    let enc = |op: u32, cmp: u32, oparg: u32, cmparg: u32| op << 28 | cmp << 24 | (oparg & 0xfff) << 12 | (cmparg & 0xfff);
    let cases = [
        (0, 3, 0, 10),       // SET 3; old 10 == 10
        (1, 5, 1, 3),        // ADD 5 -> 8; old 3 != 3? no
        (2, 0x10, 2, 100),   // OR 0x10 -> 0x18; old 8 < 100
        (3, 0x8, 3, 0x18),   // ANDN 8 -> 0x10; old 0x18 <= 0x18
        (4, 0x1, 4, 0),      // XOR 1 -> 0x11; old 0x10 > 0
        (8 | 0, 4, 5, 0x11), // SET 1<<4 (OPARG_SHIFT) -> 16; old 0x11 >= 0x11
    ];
    for (op, oparg, cmp, cmparg) in cases {
        assert!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(op, cmp, oparg, cmparg)) >= 0);
    }
    assert_eq!(w2.load(Ordering::SeqCst), 16);
    // A negative oparg (sign-extended 12 bits): ADD -1
    assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(1, 0, 0xfff, 0)), 0);
    assert_eq!(w2.load(Ordering::SeqCst), 15);
    // Unknown op or comparison
    assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(5, 0, 0, 0)), ENOSYS);
    assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(0, 6, 0, 0)), ENOSYS);
    with_current_mm(|| assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, 8, 0), -14));
    // (an unknown comparison fails after the operation, as on Linux: SET 0 happened)
    assert_eq!(w2.load(Ordering::SeqCst), 0);
    w2.store(15, Ordering::SeqCst);
    // Waiters: one on each word; the comparison decides whether w2's is woken
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(dispatch_futex(a2, FUTEX_WAIT | P, 15, 0, 0, 0), 0);
    });
    fake::step(move || {
        fake::switch_to(4002);
        // SET 15 (unchanged), old 15 == 99? no: only w1's waiter
        assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(0, 0, 15, 99)), 1);
    });
    fake::step(move || {
        fake::switch_to(4002);
        // old 15 == 15: w2's waiter too
        assert_eq!(dispatch_futex(a1, FUTEX_WAKE_OP | P, 1, 1, a2, enc(0, 0, 15, 15)), 1);
    });
    assert_eq!(dispatch_futex(a1, FUTEX_WAIT | P, 0, 0, 0, 0), 0);
}

#[test]
fn priority_inheritance_locks() {
    let _g = setup();
    threads();
    let w = word(0);
    let a = addr(&w);
    // Free: taken with our tid
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), 4000);
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, 0, 0, 0), EDEADLK, "already ours");
    run(4001);
    assert_eq!(dispatch_futex(a, FUTEX_TRYLOCK_PI | P, 0, 0, 0, 0), EAGAIN);
    assert_eq!(dispatch_futex(a, FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), EPERM, "not the owner");
    // Contended: 4001 waits (setting FUTEX_WAITERS); 4000 unlocks; 4001 takes it
    fake::step(move || {
        assert_eq!(unsafe { &*(a as *const AtomicU32) }.load(Ordering::SeqCst), 4000 | WAITERS);
        fake::switch_to(4000);
        assert_eq!(dispatch_futex(a, FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), 0);
    });
    assert_eq!(dispatch_futex(a, 13 | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), 4001);
    // A timeout (absolute, realtime for LOCK_PI) and a signal
    run(4002);
    let soon = [1_767_225_600i64, 5_000_000];
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, ptr(&soon), 0, 0), ETIMEDOUT);
    fake::step(|| {
        linux::proc::post_thread(4000, 4002, 10);
    });
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, 0, 0, 0), ERESTARTSYS);
    linux::proc::take_signal_info_of(4002, 4000, 1 << 9);
    // The owner died without releasing: ESRCH; OWNER_DIED is kept by the next owner
    w.store(9999, Ordering::SeqCst);
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, 0, 0, 0), ESRCH);
    w.store(OWNER_DIED, Ordering::SeqCst);
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), OWNER_DIED | 4002);
    assert_eq!(dispatch_futex(a, FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), 0);
    assert_eq!(w.load(Ordering::SeqCst), 0);
    let bad = [0i64, -1];
    assert_eq!(dispatch_futex(a, FUTEX_LOCK_PI | P, 0, ptr(&bad), 0, 0), EINVAL);
    with_current_mm(|| {
        assert_eq!(dispatch_futex(8, FUTEX_LOCK_PI | P, 0, 0, 0, 0), -14);
        assert_eq!(dispatch_futex(8, FUTEX_UNLOCK_PI | P, 0, 0, 0, 0), -14);
    });
}

/// A robust list in host memory: head { next, offset, pending } and mutexes whose futex
/// word sits `offset` bytes after their list node.
struct Robust {
    head: Box<[u64; 3]>,
    nodes: Vec<Box<[u64; 2]>>, // [next, word (low 32 bits)]
}

impl Robust {
    fn new(words: &[u32], pi: &[bool]) -> Robust {
        let mut head = Box::new([0u64; 3]);
        let mut nodes: Vec<Box<[u64; 2]>> = words.iter().map(|&w| Box::new([0, w as u64])).collect();
        let h = &*head as *const [u64; 3] as u64;
        for i in 0..nodes.len() {
            let next = if i + 1 < nodes.len() { &*nodes[i + 1] as *const [u64; 2] as u64 | pi[i + 1] as u64 } else { h };
            nodes[i][0] = next;
        }
        head[0] = nodes.first().map_or(h, |n| &**n as *const [u64; 2] as u64 | pi[0] as u64);
        head[1] = 8; // offset of the word in a node
        Robust { head, nodes }
    }
    fn head(&self) -> u64 {
        &*self.head as *const [u64; 3] as u64
    }
    fn node(&self, i: usize) -> u64 {
        &*self.nodes[i] as *const [u64; 2] as u64
    }
    fn word(&self, i: usize) -> u32 {
        self.nodes[i][1] as u32
    }
}

#[test]
fn robust_lists_mark_dead_owners() {
    let _g = setup();
    threads();
    // Three mutexes: held by 4000 (with waiters), held by someone else, held by 4000 (PI)
    let r = Robust::new(&[4000 | WAITERS, 1234, 4000], &[false, false, true]);
    let woken = exit_robust_list(r.head(), 4000, 4000);
    assert!(woken.is_empty(), "nobody actually waits");
    assert_eq!(r.word(0), WAITERS | OWNER_DIED);
    assert_eq!(r.word(1), 1234, "not ours: untouched");
    assert_eq!(r.word(2), OWNER_DIED);
    // A waiter on the first mutex is woken
    let r = Robust::new(&[4000 | WAITERS], &[false]);
    let a = r.node(0) + 8;
    fake::step(move || {
        fake::switch_to(4000);
        let w = exit_robust_list(r.head(), 4000, 4000);
        assert_eq!(w.len(), 1);
        assert_eq!(r.word(0), WAITERS | OWNER_DIED);
        drop(r);
    });
    run(4001);
    assert_eq!(dispatch_futex(a, FUTEX_WAIT | P, 4000 | WAITERS, 0, 0, 0), 0);
    // The pending entry: a non-PI mutex already released only gets a wake; one still held
    // is marked
    let mut r = Robust::new(&[0, 4000], &[false, false]);
    r.head[0] = r.head(); // empty list
    r.head[2] = r.node(0);
    assert!(exit_robust_list(r.head(), 4000, 4000).is_empty());
    assert_eq!(r.word(0), 0);
    r.head[2] = r.node(1);
    exit_robust_list(r.head(), 4000, 4000);
    assert_eq!(r.word(1), OWNER_DIED);
    // A pending entry that is also on the list is handled once, at the end
    let mut r = Robust::new(&[4000], &[false]);
    r.head[2] = r.node(0);
    exit_robust_list(r.head(), 4000, 4000);
    assert_eq!(r.word(0), OWNER_DIED);
    // A circular list stops after ROBUST_LIST_LIMIT entries
    let mut r = Robust::new(&[4000], &[false]);
    let n0 = r.node(0);
    r.nodes[0][0] = n0; // points at itself
    exit_robust_list(r.head(), 4000, 4000);
    assert_eq!(r.word(0), OWNER_DIED);
    // A misaligned word stops the walk; no head: nothing
    let mut r = Robust::new(&[4000, 4000], &[false, false]);
    r.head[1] = 9;
    exit_robust_list(r.head(), 4000, 4000);
    assert_eq!(r.word(1), 4000);
    assert!(exit_robust_list(0, 4000, 4000).is_empty());
    with_current_mm(|| assert!(exit_robust_list(8, 4000, 4000).is_empty()));
    // The calling thread's own list (execve)
    let r = Robust::new(&[4002], &[false]);
    run(4002);
    fake::task(4002, |t| t.robust_list = r.head());
    exit_robust_list_current();
    assert_eq!(r.word(0), OWNER_DIED);
    fake::task(4002, |t| t.robust_list = 0);
    exit_robust_list_current();
    fake::switch_to(0);
    exit_robust_list_current();
}

#[test]
fn futex2_calls() {
    let _g = setup();
    threads();
    let w1 = word(1);
    let w2 = word(2);
    let (a1, a2) = (addr(&w1), addr(&w2));
    const U32P: u64 = 2 | 128;
    // futex_waitv: [val, uaddr, flags] each
    let v = [1u64, a1, U32P, 2, a2, U32P];
    assert_eq!(sys_futex_waitv(ptr(&v), 2, 1, 0, 1), EINVAL, "flags");
    assert_eq!(sys_futex_waitv(ptr(&v), 0, 0, 0, 1), EINVAL, "none");
    assert_eq!(sys_futex_waitv(ptr(&v), 129, 0, 0, 1), EINVAL, "too many");
    assert_eq!(sys_futex_waitv(ptr(&v), 2, 0, 1, 5), EINVAL, "a timeout on an unknown clock");
    let bad = [1u64, a1 + 1, U32P];
    assert_eq!(sys_futex_waitv(ptr(&bad), 1, 0, 0, 1), EINVAL, "misaligned");
    let bad = [1u64, a1, 1 << 32 | U32P];
    assert_eq!(sys_futex_waitv(ptr(&bad), 1, 0, 0, 1), EINVAL);
    let bad = [1u64 << 33, a1, U32P];
    assert_eq!(sys_futex_waitv(ptr(&bad), 1, 0, 0, 1), EINVAL, "value wider than 32 bits");
    let bad = [1u64, a1, 3];
    assert_eq!(sys_futex_waitv(ptr(&bad), 1, 0, 0, 1), EINVAL, "64-bit size");
    let stale = [1u64, a1, U32P, 9, a2, U32P];
    assert_eq!(sys_futex_waitv(ptr(&stale), 2, 0, 0, 1), EAGAIN);
    with_current_mm(|| assert_eq!(sys_futex_waitv(8, 1, 0, 0, 1), -14));
    // Timeout
    let at = (fake::TICKS.get() + 2) * 1_000_000;
    let ts = [(at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64];
    assert_eq!(sys_futex_waitv(ptr(&v), 2, 0, ptr(&ts), 1), ETIMEDOUT);
    // Woken through the second futex: index 1
    fake::step(move || {
        fake::switch_to(4001);
        assert_eq!(sys_futex_wake(a2, !0, 1, U32P), 1);
    });
    assert_eq!(sys_futex_waitv(ptr(&v), 2, 0, 0, 1), 1);
    // A signal
    fake::step(|| {
        linux::proc::post_process(4000, 10);
    });
    assert_eq!(sys_futex_waitv(ptr(&v), 2, 0, 0, 0), ERESTARTSYS);
    linux::proc::PROCS.lock().get_mut(&4000).unwrap().pending = 0;
    // futex_wake / futex_wait checks
    assert_eq!(sys_futex_wake(a1, 1, 1, 0), EINVAL, "size bits");
    assert_eq!(sys_futex_wake(a1, 0, 1, U32P), EINVAL, "empty mask");
    assert_eq!(sys_futex_wake(a1, 1, 1, U32P | 1 << 40), EINVAL);
    assert_eq!(sys_futex_wake(a1, !0, u64::MAX, U32P), 0);
    assert_eq!(sys_futex_wait(a1, 1 << 33, !0, U32P, 0, 1), EINVAL);
    assert_eq!(sys_futex_wait(a1, 1, 0, U32P, 0, 1), EINVAL);
    assert_eq!(sys_futex_wait(a1, 1, !0, 0, 0, 1), EINVAL);
    assert_eq!(sys_futex_wait(a1, 1, !0, U32P, 1, 9), EINVAL);
    assert_eq!(sys_futex_wait(a1, 0, !0, U32P, 0, 1), EAGAIN);
    let at = (fake::TICKS.get() + 1) * 1_000_000;
    let ts = [(at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64];
    assert_eq!(sys_futex_wait(a1, 1, !0, U32P, ptr(&ts), 1), ETIMEDOUT);
    let wall = [1_767_225_600i64, 0];
    assert_eq!(sys_futex_wait(a1, 1, !0, U32P, ptr(&wall), 0), ETIMEDOUT, "CLOCK_REALTIME, already past");
    // futex_requeue: [val, uaddr, flags] x 2
    let rq = [1u64, a1, U32P, 0, a2, U32P];
    assert_eq!(sys_futex_requeue(ptr(&rq), 1, 1, 1), EINVAL, "flags");
    with_current_mm(|| assert_eq!(sys_futex_requeue(8, 0, 1, 1), -14));
    let mixed = [1u64, a1, U32P, 0, a2, 2];
    assert_eq!(sys_futex_requeue(ptr(&mixed), 0, 1, 1), EINVAL, "private and shared");
    let badsz = [1u64, a1, 3, 0, a2, U32P];
    assert_eq!(sys_futex_requeue(ptr(&badsz), 0, 1, 1), EINVAL);
    assert_eq!(sys_futex_requeue(ptr(&rq), 0, 1, 1), 0, "nobody waiting");
    let stale = [5u64, a1, U32P, 0, a2, U32P];
    assert_eq!(sys_futex_requeue(ptr(&stale), 0, 1, 1), EAGAIN);
}
