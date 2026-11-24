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
    sim
}

#[test]
fn the_old_uring_word_is_ignored() {
    let _sim = routed_world();
    // wave10 G10-C (decision 34): `lx.uring=kernel` no longer keeps requests in the kernel
    crate::lx::svc::init(b"lx.uring=kernel");
    crate::lx::set_forwarding();
    crate::world::bkl_enter();
    assert!(crate::fake::logged("[lx] lx.uring=kernel: ignored"));
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
fn with_forwarding_off_nothing_is_routed() {
    let _sim = routed_world();
    crate::lx::tests::clear_forwarding();
    crate::world::bkl_enter();
    assert_eq!(route(&frame(LX_TEST_NR, [0; 6])), None);
    crate::lx::set_forwarding();
}
