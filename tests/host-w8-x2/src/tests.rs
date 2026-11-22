//! lx-net's kept records: the store (alloc, put, get, clear, keep_only), its survival across
//! a "restart" (the same memory opened again), the record encodings, and socket options in
//! a record.

use crate::sockkept::{self as sk, InetRec, NlRec, K_RAW, K_STREAM, K_UDP_USED, K_V6};
use crate::sockopt::Options;

/// The store is one static (as in the service): tests take turns.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A zeroed area of the service's size (the kernel's first kept object), 8-byte aligned.
fn area() -> Vec<u64> {
    vec![0u64; sk::SIZE / 8]
}

fn open(a: &mut [u64]) -> hydra_rt::kept::Adopted {
    // SAFETY: the area outlives the test's use of the store (each test opens its own)
    unsafe { sk::open(a.as_mut_ptr() as *mut u8, a.len() * 8) }
}

#[test]
fn sizes_fit_the_kernels_limit() {
    // Kept objects are at most 2 MiB; the store asks for whole pages
    assert!(sk::SIZE <= 2 << 20);
    assert_eq!(sk::SIZE % 4096, 0);
    assert!(hydra_rt::kept::Kept::capacity(sk::SIZE, sk::REC) >= sk::COUNT);
}

#[test]
fn a_fresh_store_hands_out_records_and_takes_them_back() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    let ad = open(&mut a);
    assert!(ad.fresh);
    let r1 = sk::alloc();
    let r2 = sk::alloc();
    assert_eq!((r1, r2), (1, 2));
    // Record 0 means "not kept": nothing happens
    assert!(!sk::put(0, b"x"));
    assert_eq!(sk::get(0), None);
    sk::clear(0);
    assert!(sk::put(r1, b"one"));
    assert!(sk::put(r2, b"two"));
    assert_eq!(sk::get(r1).as_deref(), Some(&b"one"[..]));
    // Too big for a record: refused, the old value stays
    assert!(!sk::put(r1, &[7u8; sk::REC + 1]));
    assert_eq!(sk::get(r1).as_deref(), Some(&b"one"[..]));
    // A cleared record is free again, and the lowest free one is handed out first
    sk::clear(r1);
    assert_eq!(sk::get(r1), None);
    assert_eq!(sk::alloc(), r1);
}

#[test]
fn an_allocated_record_is_taken_before_its_first_write() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    open(&mut a);
    let r1 = sk::alloc();
    // Not written yet, but not handed out twice
    assert_eq!(sk::get(r1), None);
    assert_ne!(sk::alloc(), r1);
}

#[test]
fn the_store_runs_out_gracefully() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    open(&mut a);
    // (the page-rounded area holds a few more than COUNT)
    let cap = hydra_rt::kept::Kept::capacity(sk::SIZE, sk::REC);
    assert!(cap >= sk::COUNT);
    for i in 0..cap {
        assert_eq!(sk::alloc(), i as u32 + 1);
    }
    // Full: a new socket is simply not kept
    assert_eq!(sk::alloc(), 0);
    sk::clear(77);
    assert_eq!(sk::alloc(), 77);
    assert_eq!(sk::alloc(), 0);
}

#[test]
fn records_survive_a_restart_and_keep_only_drops_the_rest() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    open(&mut a);
    let recs: Vec<u32> = (0..5).map(|_| sk::alloc()).collect();
    for &r in &recs {
        assert!(sk::put(r, &[r as u8; 20]));
    }
    // The new instance opens the same memory
    let ad = open(&mut a);
    assert!(!ad.fresh);
    assert_eq!(ad.records, 5);
    assert_eq!(ad.bad_records, 0);
    for &r in &recs {
        assert_eq!(sk::get(r), Some(vec![r as u8; 20]));
    }
    // Records in use are not handed out again
    assert_eq!(sk::alloc(), 6);
    // Only the adopted sockets' records stay
    sk::keep_only(&[recs[1], recs[3]]);
    let left: Vec<u32> = (1..=6).filter(|&r| sk::get(r).is_some()).collect();
    assert_eq!(left, vec![recs[1], recs[3]]);
    assert_eq!(sk::alloc(), 1);
    // keep_only(&[]) is a clean start
    sk::keep_only(&[]);
    assert!((1..=6).all(|r| sk::get(r).is_none()));
}

#[test]
fn a_damaged_record_is_dropped_on_restart() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    open(&mut a);
    let r = sk::alloc();
    assert!(sk::put(r, b"good"));
    let r2 = sk::alloc();
    assert!(sk::put(r2, b"also good"));
    // Garbage over both copies of the first record (after the 64-byte header)
    let bytes = unsafe { core::slice::from_raw_parts_mut(a.as_mut_ptr() as *mut u8, 64 + 2 * (16 + sk::REC)) };
    for b in &mut bytes[64..] {
        *b ^= 0x5A;
    }
    let ad = open(&mut a);
    assert_eq!(ad.bad_records, 1);
    assert_eq!(sk::get(r), None);
    assert_eq!(sk::get(r2).as_deref(), Some(&b"also good"[..]));
    // ... and its number is free again
    assert_eq!(sk::alloc(), r);
}

#[test]
fn another_layout_starts_fresh() {
    let _t = TURN.lock().unwrap();
    let mut a = area();
    // A kept object some other program version laid out
    let (mut k, _) = unsafe { hydra_rt::kept::Kept::open(a.as_mut_ptr() as *mut u8, a.len() * 8, sk::LAYOUT + 1, sk::REC) };
    assert!(k.put(0, b"old"));
    let ad = open(&mut a);
    assert!(ad.fresh);
    assert_eq!(sk::get(1), None);
}

fn inet(peer: Option<([u8; 4], u16)>) -> InetRec {
    InetRec { flags: K_STREAM | K_V6, handles: [0, 0, 3, 41, 0], bound_port: 40000, bound_ip: [127, 0, 0, 1], peer, uid: 1000, inode: 0x8123 }
}

#[test]
fn an_internet_record_round_trips() {
    for peer in [None, Some(([10, 0, 2, 2], 22)), Some(([0, 0, 0, 0], 0))] {
        let r = inet(peer);
        let mut b = Vec::new();
        r.encode(&mut b);
        assert_eq!(b.len(), InetRec::LEN);
        assert_eq!(b[0], sk::KIND_INET);
        b.extend_from_slice(b"tail");
        let (d, rest) = InetRec::decode(&b).unwrap();
        assert_eq!(d, r);
        assert_eq!(rest, b"tail");
    }
    // Every flag survives
    let mut r = inet(None);
    r.flags = K_STREAM | K_V6 | K_RAW | K_UDP_USED | sk::K_SHUT_RD;
    let mut b = Vec::new();
    r.encode(&mut b);
    assert_eq!(InetRec::decode(&b).unwrap().0.flags, r.flags);
}

#[test]
fn a_wrong_or_short_record_is_refused() {
    let mut b = Vec::new();
    inet(None).encode(&mut b);
    for n in 0..b.len() {
        assert!(InetRec::decode(&b[..n]).is_none(), "cut at {}", n);
    }
    // A netlink record is not an Internet one, and the other way round
    let nl = NlRec { route: true, port: 7, groups: 1 }.encode();
    assert!(InetRec::decode(&nl).is_none());
    assert!(NlRec::decode(&b).is_none());
    assert!(NlRec::decode(&[]).is_none());
}

#[test]
fn a_netlink_record_round_trips() {
    for r in [NlRec { route: true, port: 4242, groups: 0 }, NlRec { route: false, port: 0, groups: 0x8000_0001 }] {
        let b = r.encode();
        assert_eq!(b[0], sk::KIND_NETLINK);
        assert_eq!(NlRec::decode(&b), Some(r));
        assert!(NlRec::decode(&b[..b.len() - 1]).is_none());
    }
}

#[test]
fn options_round_trip() {
    let mut o = Options::default();
    // SO_REUSEADDR, TCP_NODELAY, SO_RCVTIMEO 1.5 s
    assert_eq!(o.set(1, 2, &1i32.to_le_bytes(), true, false, 0), 0);
    assert_eq!(o.set(6, 1, &1i32.to_le_bytes(), true, false, 0), 0);
    let mut tv = Vec::new();
    tv.extend_from_slice(&1i64.to_le_bytes());
    tv.extend_from_slice(&500_000i64.to_le_bytes());
    assert_eq!(o.set(1, 20, &tv, true, false, 0), 0);
    let mut b = vec![0xEE]; // something before (the record)
    o.save(&mut b, 200);
    let (l, n) = Options::load(&b[1..]).unwrap();
    assert_eq!(n, b.len() - 1);
    assert_eq!(l.rcv_timeout(), Some(1_500_000_000));
    assert_eq!(l.snd_timeout(), o.snd_timeout());
    assert!(l.flag(1, 2));
    assert!(l.flag(6, 1));
    assert_eq!(l.value(6, 1), o.value(6, 1));
    // Cut short: refused
    for k in 0..n {
        assert!(Options::load(&b[1..1 + k]).is_none(), "cut at {}", k);
    }
}

#[test]
fn options_that_do_not_fit_are_left_out() {
    let mut o = Options::default();
    for name in 1..=40u32 {
        o.put(1000, name, &[name as u8; 8]);
    }
    o.put(1001, 1, &[1u8; 300]); // more than a record could hold
    let mut b = Vec::new();
    o.save(&mut b, 100);
    assert!(b.len() <= 100);
    let (l, _) = Options::load(&b).unwrap();
    // The first ones fit, in order; the long value never does
    assert_eq!(l.value(1000, 1), Some(&[1u8; 8][..]));
    assert!(l.value(1000, 40).is_none());
    assert!(l.value(1001, 1).is_none());
    // Too little room even for the timeouts: they are written anyway (the record's own
    // reservation), with no entries
    let mut b = Vec::new();
    o.save(&mut b, 0);
    assert_eq!(b.len(), 17);
    assert_eq!(Options::load(&b).unwrap().1, 17);
}

#[test]
fn a_whole_socket_image_fits_a_record() {
    // What inet.rs writes: the record, then the options in the room left
    let mut o = Options::default();
    for name in 1..=30u32 {
        o.put(6, name, &[0u8; 4]);
    }
    let mut b = Vec::new();
    inet(Some(([93, 184, 216, 34], 443))).encode(&mut b);
    let room = sk::REC - b.len();
    o.save(&mut b, room);
    assert!(b.len() <= sk::REC);
    let _t = TURN.lock().unwrap();
    let mut a = area();
    open(&mut a);
    let r = sk::alloc();
    assert!(sk::put(r, &b));
    let back = sk::get(r).unwrap();
    let (rec, rest) = InetRec::decode(&back).unwrap();
    assert_eq!(rec.peer, Some(([93, 184, 216, 34], 443)));
    assert!(Options::load(rest).is_some());
}
