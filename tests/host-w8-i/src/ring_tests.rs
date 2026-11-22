//! The raw input ring: format, push and take in order, wrap-around, a full ring counting
//! drops, a torn tail, and the shared layout constants.

use crate::input_ring::*;
use crate::protocol::*;

/// Ring memory, 8-byte aligned.
struct Mem(Vec<u64>);

impl Mem {
    fn new() -> Mem {
        Mem(vec![0u64; INPUT_RING_BYTES / 8])
    }
    fn view(&mut self) -> RingView {
        // SAFETY: the vector is INPUT_RING_BYTES long, aligned, and outlives the view's use
        unsafe { RingView::new(self.0.as_mut_ptr() as *mut u8) }
    }
    fn word(&self, off: usize) -> u64 {
        self.0[off / 8]
    }
    fn set_word(&mut self, off: usize, v: u64) {
        self.0[off / 8] = v;
    }
}

fn key(code: u8, t: u64) -> InputRec {
    InputRec { time: t, kind: INPUT_REC_KEY, code, ..InputRec::default() }
}

#[test]
fn layout_constants_fit() {
    assert_eq!(core::mem::size_of::<InputRec>(), INPUT_REC_SIZE);
    assert!(INPUT_RING_REC_OFF + INPUT_RING_RECS * INPUT_REC_SIZE <= INPUT_RING_BYTES);
    assert!(INPUT_RING_MAGIC_OFF + 4 <= INPUT_RING_REC_OFF);
    for off in [INPUT_RING_HEAD, INPUT_RING_TAIL, INPUT_RING_DROPS] {
        assert_eq!(off % 8, 0);
        assert!(off + 8 <= INPUT_RING_MAGIC_OFF);
    }
    assert_eq!(INPUT_RING_BYTES % 4096, 0);
}

#[test]
fn format_marks_valid() {
    let mut m = Mem::new();
    let r = m.view();
    assert!(!r.valid());
    r.format();
    assert!(r.valid());
    assert!(!r.pending());
    assert_eq!(r.counters(), (0, 0, 0));
}

#[test]
fn push_take_in_order() {
    let mut m = Mem::new();
    let r = m.view();
    r.format();
    for i in 0..10u8 {
        assert!(r.push(key(i, i as u64 * 100)));
    }
    assert!(r.pending());
    let mut got = Vec::new();
    assert_eq!(r.take(|x| got.push(x)), 10);
    assert_eq!(got.iter().map(|x| x.code).collect::<Vec<_>>(), (0..10).collect::<Vec<u8>>());
    assert_eq!(got[3].time, 300);
    assert!(!r.pending());
    assert_eq!(r.counters(), (10, 10, 0));
    assert_eq!(r.take(|_| panic!("nothing waits")), 0);
}

#[test]
fn full_ring_drops_and_recovers() {
    let mut m = Mem::new();
    let r = m.view();
    r.format();
    for i in 0..INPUT_RING_RECS {
        assert!(r.push(key(i as u8, 0)));
    }
    assert!(!r.push(key(1, 0)));
    assert!(!r.push(key(2, 0)));
    assert_eq!(r.counters(), (INPUT_RING_RECS as u64, 0, 2));
    let mut n = 0;
    r.take(|_| n += 1);
    assert_eq!(n, INPUT_RING_RECS);
    assert!(r.push(key(7, 0)));
}

#[test]
fn wraps_around_many_times() {
    let mut m = Mem::new();
    let r = m.view();
    r.format();
    let mut next = 0u64;
    let mut expect = 0u64;
    for round in 0..50 {
        for _ in 0..(round % 7 + 100) {
            assert!(r.push(InputRec { time: next, kind: INPUT_REC_REL, ..InputRec::default() }));
            next += 1;
        }
        r.take(|x| {
            assert_eq!(x.time, expect);
            expect += 1;
        });
    }
    assert_eq!(expect, next);
    assert!(next > 4 * INPUT_RING_RECS as u64);
}

#[test]
fn records_land_where_rec_off_says() {
    let mut m = Mem::new();
    let r = m.view();
    r.format();
    r.push(InputRec { time: 0xAABB, kind: INPUT_REC_ABS, code: 0, wheel: -1, buttons: 5, x: 0x1234, y: 0x5678 });
    let off = rec_off(0);
    assert_eq!(off, INPUT_RING_REC_OFF);
    assert_eq!(m.word(off), 0xAABB);
    assert_eq!(rec_off(INPUT_RING_RECS as u64 + 3), INPUT_RING_REC_OFF + 3 * INPUT_REC_SIZE);
    assert!(has_room(5, 5));
    assert!(!has_room(INPUT_RING_RECS as u64 + 9, 9));
    // (a head that wrapped the u64 still counts right)
    assert!(has_room(2, u64::MAX - 3));
}

#[test]
fn torn_tail_restarts_at_head() {
    let mut m = Mem::new();
    {
        let r = m.view();
        r.format();
        for i in 0..5 {
            r.push(key(i, 0));
        }
    }
    // A tail far behind (a consumer that wrote garbage): nothing stale is replayed
    m.set_word(INPUT_RING_TAIL, 0);
    m.set_word(INPUT_RING_HEAD, 10_000);
    let r = m.view();
    assert_eq!(r.take(|_| panic!("stale records")), 0);
    assert_eq!(m.word(INPUT_RING_TAIL), 10_000);
}

#[test]
fn restarted_consumer_continues_at_tail() {
    // The service takes 3 records and dies; 3 more arrive meanwhile; the new instance (a new
    // view of the same memory) takes exactly the 3 it has not seen
    let mut m = Mem::new();
    let r = m.view();
    r.format();
    for i in 0..3 {
        r.push(key(i, 0));
    }
    let mut first = Vec::new();
    r.take(|x| first.push(x.code));
    assert_eq!(first, vec![0, 1, 2]);
    for i in 3..6 {
        r.push(key(i, 0));
    }
    let r2 = m.view();
    assert!(r2.valid());
    let mut second = Vec::new();
    r2.take(|x| second.push(x.code));
    assert_eq!(second, vec![3, 4, 5]);
    assert_eq!(r2.counters(), (6, 6, 0));
}
