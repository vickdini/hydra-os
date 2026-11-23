//! wave9 G6b-4: tests of `src/lx/uring.rs`: io_uring and aio requests routed like the
//! program's own calls, and the `lx.uring=kernel` switch back.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::{frame, handler, start, world};
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::Arc as StdArc;

/// Requests counted by this test's calls (the counters are global and other tests run in
/// parallel threads: compare differences, at least).
fn delta(before: (u64, u64)) -> (u64, u64) {
    let (f, k) = counts();
    (f - before.0, k - before.1)
}

/// The world with requests routed (the switch-back word off).
fn routed_world() -> crate::world::Sim {
    let sim = world();
    KERNEL.store(false, Ordering::Relaxed);
    sim
}

#[test]
fn boot_word_is_only_uring_kernel() {
    let _sim = routed_world();
    assert!(!boot_word(b"uring=linux"));
    assert!(!boot_word(b"uring"));
    assert!(!boot_word(b"net=kernel"));
    assert!(!in_kernel());
    assert!(boot_word(b"uring=kernel"));
    assert!(in_kernel());
    KERNEL.store(false, Ordering::Relaxed);
}

#[test]
fn svc_init_takes_the_word_with_or_without_the_prefix() {
    let _sim = routed_world();
    crate::lx::svc::init(b"lx.uring=kernel");
    assert!(in_kernel());
    KERNEL.store(false, Ordering::Relaxed);
    crate::lx::svc::init(b"net=linux+uring=kernel");
    assert!(in_kernel());
    KERNEL.store(false, Ordering::Relaxed);
    // Not "everything back": the word only keeps the requests in the kernel
    assert!(!crate::lx::svc::init(b"uring=kernel"));
    KERNEL.store(false, Ordering::Relaxed);
}

#[test]
fn a_request_on_a_moved_call_goes_to_its_service() {
    let sim = routed_world();
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        n2.store(s.call.args[0] + 1, Ordering::Release);
        (42, 0)
    }));
    crate::world::bkl_enter();
    let b = counts();
    assert_eq!(route(&frame(LX_TEST_NR, [0, 0, 0, 0, 0, 0])), Some(42));
    assert_eq!(n.load(Ordering::Acquire), 1, "the service saw the request's call");
    assert!(delta(b).0 >= 1);
}

#[test]
fn a_request_nobody_claims_stays_in_the_kernel() {
    let _sim = routed_world();
    crate::world::bkl_enter();
    // getpid: not a moved call
    assert_eq!(route(&frame(39, [0; 6])), None);
    let b = counts();
    assert_eq!(route(&frame(39, [0; 6])), None);
    assert!(delta(b).1 >= 1);
}

#[test]
fn uring_kernel_keeps_even_moved_calls_in_the_kernel() {
    let sim = routed_world();
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |_| {
        n2.fetch_add(1, Ordering::AcqRel);
        (42, 0)
    }));
    crate::world::bkl_enter();
    KERNEL.store(true, Ordering::Relaxed);
    assert_eq!(route(&frame(LX_TEST_NR, [0; 6])), None);
    KERNEL.store(false, Ordering::Relaxed);
    assert_eq!(n.load(Ordering::Acquire), 0, "the service never saw it");
    // ... and the program's own call is still forwarded
    assert_eq!(crate::lx::forward(&frame(LX_TEST_NR, [0; 6])), Some(42));
}

#[test]
fn with_forwarding_off_nothing_is_routed() {
    let _sim = routed_world();
    crate::lx::set_forwarding(false);
    crate::world::bkl_enter();
    assert_eq!(route(&frame(LX_TEST_NR, [0; 6])), None);
    crate::lx::set_forwarding(true);
}
