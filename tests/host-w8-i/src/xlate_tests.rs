//! input-server's translation (scancodes, E0 prefixes, repeats, pointer reports, release of
//! held keys), the per-file queue, the device table and every `EVIOC*` answer.

use crate::protocol::*;
use crate::xlate::*;

fn sc(code: u8) -> InputRec {
    InputRec { time: 1_500_000_000, kind: INPUT_REC_KEY, code, ..InputRec::default() }
}

fn rel(dx: i16, dy: i16, wheel: i8, buttons: u8) -> InputRec {
    InputRec { time: 7, kind: INPUT_REC_REL, x: dx as u16, y: dy as u16, wheel, buttons, ..InputRec::default() }
}

fn abs(x: u16, y: u16, wheel: i8, buttons: u8) -> InputRec {
    InputRec { time: 9, kind: INPUT_REC_ABS, x, y, wheel, buttons, ..InputRec::default() }
}

/// (type, code, value) of each event.
fn tcv(evs: &[Event]) -> Vec<(u16, u16, i32)> {
    evs.iter().map(|e| (u16::from_le_bytes([e[16], e[17]]), u16::from_le_bytes([e[18], e[19]]), i32::from_le_bytes([e[20], e[21], e[22], e[23]]))).collect()
}

fn feed(t: &mut Translator, recs: &[InputRec]) -> PerDev {
    let mut out = per_dev();
    for r in recs {
        t.feed(r, &mut out);
    }
    out
}

#[test]
fn event_layout_and_time() {
    let e = event(3_250_000_123, EV_KEY, 30, 1);
    assert_eq!(u64::from_le_bytes(e[0..8].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(e[8..16].try_into().unwrap()), 250_000);
    assert_eq!(ev_type(&e), EV_KEY);
    assert_eq!(tcv(&[e]), vec![(EV_KEY, 30, 1)]);
}

#[test]
fn key_press_repeat_release() {
    let mut t = Translator::new();
    let out = feed(&mut t, &[sc(0x1E), sc(0x1E), sc(0x9E)]);
    assert_eq!(
        tcv(&out[0]),
        vec![
            (EV_MSC, MSC_SCAN, 0x1E),
            (EV_KEY, 30, 1),
            (EV_SYN, SYN_REPORT, 0),
            (EV_MSC, MSC_SCAN, 0x1E),
            (EV_KEY, 30, 2),
            (EV_SYN, SYN_REPORT, 0),
            (EV_MSC, MSC_SCAN, 0x1E),
            (EV_KEY, 30, 0),
            (EV_SYN, SYN_REPORT, 0)
        ]
    );
    assert!(out[1].is_empty() && out[2].is_empty());
    // A release of a key not held is dropped
    assert!(feed(&mut t, &[sc(0x9E)])[0].is_empty());
}

#[test]
fn e0_prefixed_keys() {
    let mut t = Translator::new();
    let out = feed(&mut t, &[sc(0xE0), sc(0x48), sc(0xE0), sc(0xC8)]);
    assert_eq!(tcv(&out[0])[0], (EV_MSC, MSC_SCAN, 0xE048));
    assert_eq!(tcv(&out[0])[1], (EV_KEY, 103, 1));
    assert_eq!(tcv(&out[0])[4], (EV_KEY, 103, 0));
    // An E0 code without a Linux key is skipped, and the prefix does not stick
    let out = feed(&mut t, &[sc(0xE0), sc(0x2A), sc(0x1C)]);
    assert_eq!(tcv(&out[0])[1], (EV_KEY, 28, 1));
    for (m, k) in [(0x1C, 96), (0x1D, 97), (0x35, 98), (0x38, 100), (0x47, 102), (0x49, 104), (0x4B, 105), (0x4D, 106), (0x4F, 107), (0x50, 108), (0x51, 109), (0x52, 110), (0x53, 111), (0x5B, 125), (0x5C, 126), (0x5D, 127)] {
        assert_eq!(e0_keycode(m), k);
    }
    assert_eq!(e0_keycode(0x10), 0);
    // Scancode 0 has no key
    assert!(feed(&mut t, &[sc(0x00)])[0].is_empty());
}

#[test]
fn relative_pointer() {
    let mut t = Translator::new();
    let out = feed(&mut t, &[rel(5, -3, 1, 1)]);
    assert_eq!(tcv(&out[1]), vec![(EV_KEY, BTN_LEFT, 1), (EV_REL, REL_X, 5), (EV_REL, REL_Y, -3), (EV_REL, REL_WHEEL, 1), (EV_REL, REL_WHEEL_HI_RES, 120), (EV_SYN, SYN_REPORT, 0)]);
    // Nothing changed: nothing reported
    assert!(feed(&mut t, &[rel(0, 0, 0, 1)])[1].is_empty());
    let out = feed(&mut t, &[rel(0, 0, 0, 0b110)]);
    assert_eq!(tcv(&out[1]), vec![(EV_KEY, BTN_LEFT, 0), (EV_KEY, BTN_RIGHT, 1), (EV_KEY, BTN_MIDDLE, 1), (EV_SYN, SYN_REPORT, 0)]);
}

#[test]
fn absolute_pointer() {
    let mut t = Translator::new();
    let out = feed(&mut t, &[abs(100, 200, -1, 2)]);
    assert_eq!(tcv(&out[2]), vec![(EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200), (EV_KEY, BTN_RIGHT, 1), (EV_REL, REL_WHEEL, -1), (EV_REL, REL_WHEEL_HI_RES, -120), (EV_SYN, SYN_REPORT, 0)]);
    assert_eq!(t.abs_pos, (100, 200));
    assert!(feed(&mut t, &[abs(100, 200, 0, 2)])[2].is_empty());
}

#[test]
fn release_record_lets_everything_go() {
    let mut t = Translator::new();
    feed(&mut t, &[sc(0x1D), sc(0x38), rel(0, 0, 0, 1), abs(1, 1, 0, 4), sc(0xE0)]);
    let out = feed(&mut t, &[InputRec { time: 5, kind: INPUT_REC_RELEASE, ..InputRec::default() }]);
    assert_eq!(tcv(&out[0]), vec![(EV_KEY, 29, 0), (EV_KEY, 56, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert_eq!(tcv(&out[1]), vec![(EV_KEY, BTN_LEFT, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert_eq!(tcv(&out[2]), vec![(EV_KEY, BTN_MIDDLE, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert!(!t.e0);
    // Nothing held now: a second release says nothing
    let out = feed(&mut t, &[InputRec { kind: INPUT_REC_RELEASE, ..InputRec::default() }]);
    assert!(out.iter().all(|q| q.is_empty()));
    // Unknown record kinds are ignored
    let out = feed(&mut t, &[InputRec { kind: 99, ..InputRec::default() }]);
    assert!(out.iter().all(|q| q.is_empty()));
}

#[test]
fn held_keys_and_buttons() {
    let mut t = Translator::default();
    feed(&mut t, &[sc(0x1E), rel(0, 0, 0, 2), abs(0, 0, 0, 1)]);
    assert_eq!(t.held(0)[30 / 8] & (1 << (30 % 8)), 1 << (30 % 8));
    let m = t.held(1);
    assert_ne!(m[BTN_RIGHT as usize / 8] & (1 << (BTN_RIGHT % 8)), 0);
    assert_eq!(m[BTN_LEFT as usize / 8] & (1 << (BTN_LEFT % 8)), 0);
    let a = t.held(2);
    assert_ne!(a[BTN_LEFT as usize / 8] & (1 << (BTN_LEFT % 8)), 0);
}

#[test]
fn queue_takes_whole_events_and_drops_on_overflow() {
    let mut q = Queue::default();
    assert!(q.is_empty());
    q.extend(&[], 0);
    assert!(q.is_empty());
    let evs: Vec<Event> = (0..5).map(|i| event(0, EV_KEY, i, 1)).collect();
    q.extend(&evs, 0);
    assert_eq!(q.len(), 5);
    let mut buf = [0u8; 24 * 2 + 10];
    assert_eq!(q.take(&mut buf), 48);
    assert_eq!(q.len(), 3);
    q.clear();
    assert!(q.is_empty());
    let many: Vec<Event> = (0..QUEUE_LIMIT).map(|_| event(0, EV_REL, 0, 1)).collect();
    q.extend(&many, 0);
    q.extend(&evs, 42_000);
    assert_eq!(q.len(), 1 + evs.len());
    let mut one = [0u8; 24];
    q.take(&mut one);
    assert_eq!(tcv(&[one]), vec![(EV_SYN, SYN_DROPPED, 0)]);
}

#[test]
fn device_table() {
    assert_eq!(dev_of_minor(64), Some(0));
    assert_eq!(dev_of_minor(66), Some(2));
    assert_eq!(dev_of_minor(63), None);
    assert_eq!(dev_of_minor(67), None);
    assert_eq!(INFO[0].name, "AT Translated Set 2 keyboard");
    assert_eq!(INFO[2].id, [0x11, 0x2, 0x13, 0]);
}

fn bit(m: &[u8], b: u16) -> bool {
    m[b as usize / 8] & (1 << (b % 8)) != 0
}

#[test]
fn capability_bits() {
    let k = capabilities(0, 0);
    assert!(bit(&k, EV_KEY) && bit(&k, EV_REP) && bit(&k, EV_LED) && !bit(&k, EV_REL));
    let kk = capabilities(0, EV_KEY);
    assert_eq!(kk.len(), 96);
    assert!(bit(&kk, 1) && bit(&kk, 88) && bit(&kk, 103) && bit(&kk, 125) && !bit(&kk, 90));
    assert!(bit(&capabilities(0, EV_MSC), MSC_SCAN));
    assert!(bit(&capabilities(0, EV_LED), 2));
    let m = capabilities(1, 0);
    assert!(bit(&m, EV_REL) && !bit(&m, EV_ABS));
    assert!(bit(&capabilities(1, EV_KEY), BTN_MIDDLE));
    assert!(bit(&capabilities(1, EV_REL), REL_WHEEL_HI_RES));
    assert!(bit(&capabilities(2, 0), EV_ABS));
    assert!(bit(&capabilities(2, EV_ABS), ABS_Y));
    assert!(!bit(&capabilities(2, EV_REL), REL_X));
    assert_eq!(capabilities(0, 0x15).len(), 16);
    assert!(capabilities(1, EV_ABS).iter().all(|&b| b == 0));
}

/// An `EVIOC*` number: dir (2 = read), size, nr.
fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    dir << 30 | size << 16 | 0x45 << 8 | nr
}

#[test]
fn ioctl_answers() {
    let t = Translator::new();
    assert_eq!(ioctl(0, 0x5401, &t), Answer::Val(-25)); // TCGETS: not ours
    assert_eq!(ioctl(3, ioc(2, 1, 4), &t), Answer::Val(-25));
    assert_eq!(ioctl(0, ioc(2, 1, 4), &t), Answer::Out { data: 0x10001u32.to_le_bytes().to_vec(), cap: 4, len: false });
    match ioctl(1, ioc(2, 2, 8), &t) {
        Answer::Out { data, cap: 8, len: false } => assert_eq!(data, vec![0x11, 0, 2, 0, 1, 0, 0, 0]),
        a => panic!("{:?}", a),
    }
    match ioctl(0, ioc(2, 3, 8), &t) {
        Answer::Out { data, .. } => assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 250),
        a => panic!("{:?}", a),
    }
    assert_eq!(ioctl(1, ioc(2, 3, 8), &t), Answer::Val(-38));
    assert_eq!(ioctl(0, ioc(1, 3, 8), &t), Answer::Val(0)); // EVIOCSREP
    match ioctl(2, ioc(2, 6, 256), &t) {
        Answer::Out { data, cap: 256, len: true } => assert_eq!(&data[..], b"VirtualPS/2 VMware VMMouse\0"),
        a => panic!("{:?}", a),
    }
    match ioctl(0, ioc(2, 7, 64), &t) {
        Answer::Out { data, .. } => assert_eq!(&data[..], b"isa0060/serio0/input0\0"),
        a => panic!("{:?}", a),
    }
    assert_eq!(ioctl(0, ioc(2, 8, 64), &t), Answer::Out { data: vec![0], cap: 64, len: true });
    assert_eq!(ioctl(0, ioc(2, 9, 8), &t), Answer::Out { data: vec![0; 8], cap: 8, len: true });
    assert_eq!(ioctl(0, ioc(2, 0x0a, 8), &t), Answer::Val(-22));
    match ioctl(0, ioc(2, 0x18, 96), &t) {
        Answer::Out { data, cap: 96, len: true } => assert_eq!(data.len(), 96),
        a => panic!("{:?}", a),
    }
    assert_eq!(ioctl(0, ioc(2, 0x19, 8), &t), Answer::Out { data: vec![0; 8], cap: 8, len: true });
    match ioctl(0, ioc(2, 0x21, 96), &t) {
        Answer::Out { data, .. } => assert!(bit(&data, 30)),
        a => panic!("{:?}", a),
    }
    match ioctl(2, ioc(2, 0x41, 24), &t) {
        Answer::Out { data, len: false, .. } => {
            assert_eq!(i32::from_le_bytes(data[0..4].try_into().unwrap()), 0x8000);
            assert_eq!(i32::from_le_bytes(data[8..12].try_into().unwrap()), ABS_MAX);
        }
        a => panic!("{:?}", a),
    }
    assert_eq!(ioctl(1, ioc(2, 0x40, 24), &t), Answer::Val(-22));
    assert_eq!(ioctl(0, ioc(1, 0x80, 48), &t), Answer::Val(-22));
    assert_eq!(ioctl(0, ioc(2, 0x84, 4), &t), Answer::Out { data: vec![0; 4], cap: 4, len: false });
    assert_eq!(ioctl(0, ioc(1, 0x90, 4), &t), Answer::Grab);
    assert_eq!(ioctl(0, ioc(1, 0x91, 4), &t), Answer::Revoke);
    assert_eq!(ioctl(0, ioc(1, 0x93, 16), &t), Answer::Val(0));
    assert_eq!(ioctl(0, ioc(1, 0xa0, 4), &t), Answer::Val(0));
    assert_eq!(ioctl(0, ioc(1, 0xff, 4), &t), Answer::Val(-22));
}

#[test]
fn held_state_survives_save_and_restore() {
    let mut t = Translator::new();
    feed(&mut t, &[sc(0x1D), sc(0xE0), sc(0x38), rel(0, 0, 0, 2), abs(10, 20, 0, 1)]);
    assert!(t.any_held());
    let b = t.save();
    assert_eq!(b.len(), SAVED_LEN);
    let mut r = Translator::restore(&b).expect("a saved state");
    assert_eq!(r.keys, t.keys);
    assert_eq!((r.buttons, r.abs_buttons, r.abs_pos), (2, 1, (10, 20)));
    assert!(!r.e0);
    // The restarted instance lets go of what was held
    let mut out = per_dev();
    r.release_all(&mut out, 5);
    assert_eq!(tcv(&out[0]), vec![(EV_KEY, 29, 0), (EV_KEY, 100, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert_eq!(tcv(&out[1]), vec![(EV_KEY, BTN_RIGHT, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert_eq!(tcv(&out[2]), vec![(EV_KEY, BTN_LEFT, 0), (EV_SYN, SYN_REPORT, 0)]);
    assert!(!r.any_held());
    // Not a saved state
    assert!(Translator::restore(&[0u8; SAVED_LEN]).is_none());
    assert!(Translator::restore(&b[..10]).is_none());
    assert!(!Translator::new().any_held());
}

#[test]
fn dropped_records_mark_every_device() {
    let mut out = per_dev();
    out[1].push(event(1, EV_REL, REL_X, 1));
    mark_dropped(&mut out, 9);
    for q in out.iter() {
        assert_eq!(tcv(&q[..1]), vec![(EV_SYN, SYN_DROPPED, 0)]);
    }
    assert_eq!(tcv(&out[1])[1], (EV_REL, REL_X, 1));
}

#[test]
fn grabs_as_linux() {
    assert_eq!(grab(None, 3, true), Ok(Some(3)));
    assert_eq!(grab(Some(3), 3, true), Ok(Some(3)));
    assert_eq!(grab(Some(4), 3, true), Err(-16));
    assert_eq!(grab(Some(3), 3, false), Ok(None));
    assert_eq!(grab(Some(4), 3, false), Err(-22));
    assert_eq!(grab(None, 3, false), Err(-22));
    assert!(receives(None, 1) && receives(Some(1), 1) && !receives(Some(2), 1));
}
