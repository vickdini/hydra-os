//! The pre-merge review's fixes (wave 8, Group S): the stream set-ups the kernel accepts,
//! signals for calls not waiting yet, kept streams with impossible sizes.

use hydra_hosttests_w8_s::intr;
use hydra_hosttests_w8_s::ipc::sound_page::setup_ok;
use hydra_hosttests_w8_s::params::put_u64;
use hydra_hosttests_w8_s::pcm::{Stream, KEPT_STREAM};
use std::collections::VecDeque;

const RING: u64 = 128 * 4096;

#[test]
fn only_setups_inside_the_kernels_ring() {
    // PipeWire's: 16384 frames x 4 bytes, periods of 512 frames
    assert!(setup_ok(0, 65536, 2048, 0x11, RING));
    assert!(setup_ok(1, RING, RING / 2, 0x4011, RING));
    assert!(!setup_ok(2, 65536, 2048, 0x11, RING), "direction");
    assert!(!setup_ok(0, RING + 128, 128 * 1024, 0x11, RING), "beyond the ring");
    assert!(!setup_ok(0, 0, 128, 0x11, RING), "empty");
    assert!(!setup_ok(0, 65536, 100, 0x11, RING), "period not a multiple of 128");
    assert!(!setup_ok(0, 65536 + 128, 2048, 0x11, RING), "not whole periods");
    assert!(!setup_ok(0, 2048, 2048, 0x11, RING), "one period");
    assert!(!setup_ok(0, 512 * 128, 128, 0x11, RING), "more than 256 periods");
    assert!(!setup_ok(0, 65536, 2048, 0x1_0000, RING), "format word");
    assert!(!setup_ok(0, u64::MAX - 127, 128, 0x11, RING), "huge");
}

#[test]
fn a_signal_before_the_call_parks_is_kept() {
    let mut r = VecDeque::new();
    intr::note(&mut r, 7);
    assert!(!intr::take(&mut r, 8));
    assert!(intr::take(&mut r, 7));
    assert!(!intr::take(&mut r, 7), "taken once");
    for i in 0..(intr::KEEP as u64 + 10) {
        intr::note(&mut r, i);
    }
    assert_eq!(r.len(), intr::KEEP);
    assert!(!intr::take(&mut r, 0), "the oldest went");
    assert!(intr::take(&mut r, intr::KEEP as u64 + 9));
}

#[test]
fn kept_streams_with_impossible_sizes_are_refused() {
    let mut s = Stream::new();
    s.open = true;
    let good = {
        let mut b = s.encode();
        put_u64(&mut b, 3 * 8, 1); // has hw
        put_u64(&mut b, 5 * 8, 48000);
        put_u64(&mut b, 6 * 8, 512);
        put_u64(&mut b, 7 * 8, 32);
        put_u64(&mut b, 8 * 8, 16384);
        put_u64(&mut b, 9 * 8, 4);
        put_u64(&mut b, 15 * 8, 1 << 40);
        b
    };
    assert!(Stream::decode(&good, 0).is_some());
    let mut wrap = good;
    put_u64(&mut wrap, 8 * 8, 1 << 62); // buffer * frame bytes wraps
    put_u64(&mut wrap, 9 * 8, 8);
    assert!(Stream::decode(&wrap, 0).is_none());
    let mut periods = good;
    put_u64(&mut periods, 7 * 8, 31); // period x periods != buffer
    assert!(Stream::decode(&periods, 0).is_none());
    let mut slot = good;
    put_u64(&mut slot, 19 * 8, 512);
    assert!(Stream::decode(&slot, 0).is_none());
    assert_eq!(good.len(), KEPT_STREAM);
}
