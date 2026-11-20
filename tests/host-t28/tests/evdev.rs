//! `evdev.rs`: the keyboard, mouse and absolute pointer as Linux event devices: raw
//! input routed or dropped, scancodes to key events (E0 prefixes, repeats, releases),
//! mouse packets to relative events, the absolute pointer, per-file queues with
//! `SYN_DROPPED`, the EVIOC* ioctls, revoke, and releasing held keys.
//!
//! The ring, translation state and client lists are globals: every test holds
//! `common::serial()`.

mod common;

use std::sync::Arc;

use hydra_hosttests_t28::compat::linux::chardev::{makedev, CharDevice};
use hydra_hosttests_t28::compat::linux::evdev::{self, push_abs, push_mouse, push_scancode};
use hydra_hosttests_t28::fake;

const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENODEV: i64 = -19;
const ENXIO: i64 = -6;
const ENOSYS: i64 = -38;
const EFAULT: i64 = -14;
const ERESTARTSYS: i64 = -512;

#[derive(Debug, PartialEq, Clone, Copy)]
struct Ev {
    ty: u16,
    code: u16,
    value: i32,
}

fn ev(ty: u16, code: u16, value: i32) -> Ev {
    Ev { ty, code, value }
}

/// Everything queued for `f` (non-blocking reads).
fn drain(f: &Arc<dyn CharDevice>) -> Vec<Ev> {
    let mut out = Vec::new();
    loop {
        let mut b = vec![0u8; 24 * 64];
        let n = f.read(&mut b);
        if n == EAGAIN {
            return out;
        }
        assert!(n > 0 && n % 24 == 0, "read {n}");
        for e in b[..n as usize].chunks(24) {
            out.push(Ev {
                ty: u16::from_le_bytes([e[16], e[17]]),
                code: u16::from_le_bytes([e[18], e[19]]),
                value: i32::from_le_bytes(e[20..24].try_into().unwrap()),
            });
        }
    }
}

/// Routing on, a clean translation state, nothing queued.
fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = common::serial();
    evdev::set_routing(true);
    // Release whatever an earlier test left held, then empty the ring into a throwaway file
    evdev::release_held_keys();
    let f = evdev::open(64, true).unwrap();
    drain(&f);
    fake::SIGNAL_PENDING.set(false);
    fake::clear_on_wait();
    g
}

fn kbd() -> Arc<dyn CharDevice> {
    evdev::open(64, true).unwrap()
}
fn mouse() -> Arc<dyn CharDevice> {
    evdev::open(65, true).unwrap()
}
fn abs() -> Arc<dyn CharDevice> {
    evdev::open(66, true).unwrap()
}

#[test]
fn opening_devices() {
    let _g = setup();
    assert_eq!(evdev::open(67, false).err(), Some(ENXIO));
    let k = kbd();
    assert_eq!(k.rdev(), makedev(13, 64));
    assert_eq!(k.path(), "/dev/input/event0");
    assert_eq!(mouse().path(), "/dev/input/event1");
    assert_eq!(abs().rdev(), makedev(13, 66));
    assert!(k.nonblock());
    k.set_nonblock(false);
    assert!(!k.nonblock());
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    k.add_wait_queues(&mut ws);
    assert_eq!(ws.queues.len(), 1);
    // Writes are accepted in whole events and ignored
    assert_eq!(k.write(&[0u8; 50]), 48);
}

#[test]
fn input_before_open_is_not_delivered() {
    let _g = setup();
    push_scancode(0x1E);
    let k = kbd(); // the open pumps the ring first
    assert!(drain(&k).is_empty());
    push_scancode(0x9E); // release of the key the old file saw
}

#[test]
fn keys_press_repeat_release() {
    let _g = setup();
    let k = kbd();
    assert_eq!(k.poll_events(), 0);
    push_scancode(0x1E); // A down
    assert_eq!(k.poll_events(), 0x1);
    push_scancode(0x1E); // typematic repeat
    push_scancode(0x9E); // A up
    push_scancode(0x9E); // a second release: ignored
    let a = 30;
    assert_eq!(
        drain(&k),
        vec![
            ev(4, 4, 0x1E), ev(1, a, 1), ev(0, 0, 0),
            ev(4, 4, 0x1E), ev(1, a, 2), ev(0, 0, 0),
            ev(4, 4, 0x1E), ev(1, a, 0), ev(0, 0, 0),
        ]
    );
}

#[test]
fn e0_prefixed_keys() {
    let _g = setup();
    let k = kbd();
    for (make, code) in [(0x1C, 96), (0x1D, 97), (0x35, 98), (0x38, 100), (0x47, 102), (0x48, 103), (0x49, 104), (0x4B, 105), (0x4D, 106), (0x4F, 107), (0x50, 108), (0x51, 109), (0x52, 110), (0x53, 111), (0x5B, 125), (0x5C, 126), (0x5D, 127)] {

        push_scancode(0xE0);
        push_scancode(make);
        push_scancode(0xE0);
        push_scancode(make | 0x80);
        let evs = drain(&k);
        assert_eq!(evs[0], ev(4, 4, 0xE000 | make as i32));
        assert_eq!(evs[1], ev(1, code as u16, 1));
        assert_eq!(evs[4], ev(1, code as u16, 0));
    }
    // An E0 code without a key (fake shift 0x2A) and scancode 0 are dropped

    push_scancode(0xE0);
    push_scancode(0x2A);
    push_scancode(0x00);
    assert!(drain(&k).is_empty());
}

#[test]
fn mouse_packets() {
    let _g = setup();
    let m = mouse();
    push_mouse(5, -3, 0, 0b001); // left down, move
    push_mouse(0, 0, 1, 0b001); // wheel
    push_mouse(0, 0, 0, 0b110); // left up, right and middle down
    push_mouse(0, 0, 0, 0b110); // nothing changed: no events at all
    assert_eq!(
        drain(&m),
        vec![
            ev(1, 0x110, 1), ev(2, 0, 5), ev(2, 1, -3), ev(0, 0, 0),
            ev(2, 8, 1), ev(2, 11, 120), ev(0, 0, 0),
            ev(1, 0x110, 0), ev(1, 0x111, 1), ev(1, 0x112, 1), ev(0, 0, 0),
        ]
    );
    // EVIOCGKEY shows the held buttons
    let mut keys = [0u8; 96];
    assert_eq!(m.ioctl(0x8060_4518, keys.as_mut_ptr() as u64), 96);
    assert_eq!(keys[0x111 / 8], (1 << (0x111 % 8)) | (1 << (0x112 % 8)));
    push_mouse(0, 0, 0, 0);
    drain(&m);
}

#[test]
fn absolute_pointer() {
    let _g = setup();
    let a = abs();
    push_abs(100, 200, 0, 0b001);
    push_abs(100, 200, -1, 0b001); // same place: only the wheel
    push_abs(100, 200, 0, 0);
    assert_eq!(
        drain(&a),
        vec![
            ev(3, 0, 100), ev(3, 1, 200), ev(1, 0x110, 1), ev(0, 0, 0),
            ev(2, 8, -1), ev(2, 11, -120), ev(0, 0, 0),
            ev(1, 0x110, 0), ev(0, 0, 0),
        ]
    );
    // EVIOCGABS(ABS_X/ABS_Y): value and the 0..0xFFFF range
    let mut info = [0i32; 6];
    assert_eq!(a.ioctl(0x8018_4540, info.as_mut_ptr() as u64), 0);
    assert_eq!((info[0], info[1], info[2]), (100, 0, 0xFFFF));
    assert_eq!(a.ioctl(0x8018_4541, info.as_mut_ptr() as u64), 0);
    assert_eq!(info[0], 200);
    // Other axes, and EVIOCGABS on the keyboard: EINVAL
    assert_eq!(a.ioctl(0x8018_4542, info.as_mut_ptr() as u64), EINVAL);
    assert_eq!(kbd().ioctl(0x8018_4540, info.as_mut_ptr() as u64), EINVAL);
    // EVIOCGKEY of the pointer
    push_abs(1, 1, 0, 0b100);
    drain(&a);
    let mut keys = [0u8; 96];
    a.ioctl(0x8060_4518, keys.as_mut_ptr() as u64);
    assert_eq!(keys[0x112 / 8], 1 << (0x112 % 8));
    push_abs(1, 1, 0, 0);
    drain(&a);
}

#[test]
fn input_is_dropped_when_not_routed() {
    let _g = setup();
    let k = kbd();
    evdev::set_routing(false);
    assert!(!evdev::routing());
    push_scancode(0x1E);
    assert_eq!(k.poll_events(), 0);
    assert!(drain(&k).is_empty());
    evdev::set_routing(true);
    assert!(evdev::routing());
}

#[test]
fn full_ring_drops_new_input() {
    let _g = setup();
    let k = kbd();
    // 512 raw entries fit; the rest is dropped while nobody reads
    for _ in 0..300 {
        push_scancode(0x1E);
        push_scancode(0x9E);
    }
    let evs = drain(&k);
    assert_eq!(evs.len(), 512 * 3);
}

#[test]
fn a_slow_reader_gets_syn_dropped() {
    let _g = setup();
    let k = kbd();
    let other = kbd();
    // 683 key events = 2049 records: more than a queue holds, delivered in two pumps
    for i in 0..700 {
        push_scancode(if i % 2 == 0 { 0x1E } else { 0x9E });
        if i == 400 {
            assert_eq!(other.poll_events(), 0x1); // pumps the first part
            drain(&other);
        }
    }
    let evs = drain(&k);
    assert_eq!(evs[0], ev(0, 3, 0), "SYN_DROPPED first");
    assert_eq!(evs.len(), 1 + (700 - 401) * 3);
}

#[test]
fn reads_need_room_for_one_event() {
    let _g = setup();
    let k = kbd();
    let mut small = [0u8; 23];
    assert_eq!(k.read(&mut small), EINVAL);
    // A buffer for one event takes one at a time
    push_scancode(0x1E);
    push_scancode(0x9E);
    let mut one = [0u8; 30];
    assert_eq!(k.read(&mut one), 24);
    assert_eq!(drain(&k).len(), 5);
}

#[test]
fn blocking_reads_wait_for_input() {
    let _g = setup();
    let k = evdev::open(64, false).unwrap();
    let mut b = [0u8; 24 * 3];
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(k.read(&mut b), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    let mut sent = false;
    fake::on_wait(move || {
        if !sent {
            push_scancode(0x10);
            sent = true;
        }
    });
    assert_eq!(k.read(&mut b), 72);
    fake::clear_on_wait();
    push_scancode(0x90);
    drain(&kbd());
}

#[test]
fn timestamps_come_from_the_tick_counter() {
    let _g = setup();
    let k = kbd();
    fake::TICKS.set(123_456); // 10 ms per tick in the event clock
    push_scancode(0x1E);
    let mut b = [0u8; 24];
    assert_eq!(k.read(&mut b), 24);
    let us = 123_456u64 * 10_000;
    assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), us / 1_000_000);
    assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), us % 1_000_000);
    push_scancode(0x9E);
    drain(&k);
}

#[test]
fn revoke_ends_the_file() {
    let _g = setup();
    let k = kbd();
    push_scancode(0x1E);
    assert_eq!(k.ioctl(0x4004_4591, 1), 0); // EVIOCREVOKE
    assert_eq!(k.poll_events(), 0x0008 | 0x0010);
    let mut b = [0u8; 24];
    assert_eq!(k.read(&mut b), ENODEV);
    // Other files still get input
    let k2 = kbd();
    push_scancode(0x9E);
    assert_eq!(drain(&k2).len(), 3);
}

#[test]
fn release_held_keys_reports_releases() {
    let _g = setup();
    let k = kbd();
    let m = mouse();
    let a = abs();
    push_scancode(0x1D); // Ctrl down
    push_scancode(0x38); // Alt down
    push_mouse(0, 0, 0, 0b011);
    push_abs(5, 5, 0, 0b100);
    drain(&k);
    drain(&m);
    drain(&a);
    evdev::release_held_keys();
    assert_eq!(drain(&k), vec![ev(1, 29, 0), ev(1, 56, 0), ev(0, 0, 0)]);
    assert_eq!(drain(&m), vec![ev(1, 0x110, 0), ev(1, 0x111, 0), ev(0, 0, 0)]);
    assert_eq!(drain(&a), vec![ev(1, 0x112, 0), ev(0, 0, 0)]);
    // Nothing held: nothing reported
    evdev::release_held_keys();
    assert!(drain(&k).is_empty());
    // A key that was down is new again after the release
    push_scancode(0x1D);
    assert_eq!(drain(&k)[1], ev(1, 29, 1));
    push_scancode(0x9D);
}

#[test]
fn identity_ioctls() {
    let _g = setup();
    let k = kbd();
    let mut v = [0u32];
    assert_eq!(k.ioctl(0x8004_4501, v.as_mut_ptr() as u64), 0);
    assert_eq!(v[0], 0x0001_0001);
    let mut id = [0u16; 4];
    assert_eq!(k.ioctl(0x8008_4502, id.as_mut_ptr() as u64), 0);
    assert_eq!(id, [0x11, 1, 1, 0xab41]);
    let mut rep = [0u32; 2];
    assert_eq!(k.ioctl(0x8008_4503, rep.as_mut_ptr() as u64), 0);
    assert_eq!(rep, [250, 33]);
    assert_eq!(mouse().ioctl(0x8008_4503, rep.as_mut_ptr() as u64), ENOSYS);
    assert_eq!(k.ioctl(0x4008_4503, rep.as_mut_ptr() as u64), 0); // EVIOCSREP
    // Names: cut to the caller's size, NUL included when it fits
    let mut name = [0xFFu8; 64];
    let n = k.ioctl(0x8040_4506, name.as_mut_ptr() as u64);
    assert_eq!(n as usize, "AT Translated Set 2 keyboard".len() + 1);
    assert_eq!(&name[..n as usize - 1], b"AT Translated Set 2 keyboard");
    let mut short = [0u8; 4];
    assert_eq!(k.ioctl(0x8004_4506, short.as_mut_ptr() as u64), 4);
    assert_eq!(&short, b"AT T");
    let mut phys = [0u8; 64];
    let n = mouse().ioctl(0x8040_4507, phys.as_mut_ptr() as u64);
    assert_eq!(&phys[..n as usize - 1], b"isa0060/serio1/input0");
    assert_eq!(k.ioctl(0x8040_4508, phys.as_mut_ptr() as u64), 1);
    assert_eq!(k.ioctl(0x8008_4509, phys.as_mut_ptr() as u64), 8);
    assert_eq!(k.ioctl(0x8000_450a, 0), EINVAL);
    for nr in [0x19u64, 0x1a, 0x1b] {
        assert_eq!(k.ioctl(0x8008_4500 | nr, phys.as_mut_ptr() as u64), 8);
    }
    // A size of 0 copies nothing (and does not fault)
    assert_eq!(k.ioctl(0x8000_4506, 0), 0);
    assert_eq!(k.ioctl(0x8040_4506, fake::BAD_PTR), EFAULT);
    assert_eq!(k.ioctl(0x8004_4501, 0), EFAULT);
    // Force feedback, grab, masks, clock; others
    assert_eq!(k.ioctl(0x4030_4580, 0), EINVAL);
    assert_eq!(k.ioctl(0x4004_4581, 0), EINVAL);
    assert_eq!(k.ioctl(0x8004_4584, v.as_mut_ptr() as u64), 0);
    assert_eq!(v[0], 0);
    for cmd in [0x4004_4590u64, 0x8010_4592, 0x4010_4593, 0x4004_45a0] {
        assert_eq!(k.ioctl(cmd, 0), 0, "{cmd:#x}");
    }
    assert_eq!(k.ioctl(0x4004_45ff, 0), EINVAL);
    // Not an evdev request
    assert_eq!(k.ioctl(0x5401, 0), ENOTTY);
}

#[test]
fn capability_bitmaps() {
    let _g = setup();
    let has = |m: &[u8], bit: usize| m[bit / 8] & (1 << (bit % 8)) != 0;
    // Keyboard: SYN KEY MSC LED REP; keys 1..=88, 96..=111, 125..=127
    let ev0 = evdev::capabilities(0, 0);
    assert_eq!(ev0.len(), 8);
    assert_eq!(ev0[0], 0b10011, "{:b}", ev0[0]);
    assert!(has(&ev0, 0x11) && has(&ev0, 0x14));
    let keys = evdev::capabilities(0, 1);
    assert_eq!(keys.len(), 96);
    assert!(has(&keys, 1) && has(&keys, 88) && !has(&keys, 89) && has(&keys, 96) && has(&keys, 111) && !has(&keys, 112) && has(&keys, 127) && !has(&keys, 128));
    assert!(has(&evdev::capabilities(0, 4), 4));
    assert_eq!(evdev::capabilities(0, 0x11)[0], 0b111);
    // Mouse: SYN KEY REL; buttons; X Y wheel and hi-res wheel
    assert_eq!(evdev::capabilities(1, 0)[0], 0b111);
    let rel = evdev::capabilities(1, 2);
    assert!(has(&rel, 0) && has(&rel, 1) && has(&rel, 8) && has(&rel, 11));
    assert!(has(&evdev::capabilities(1, 1), 0x110));
    // Pointer: SYN KEY REL ABS; X Y; wheels only
    assert_eq!(evdev::capabilities(2, 0)[0], 0b1111);
    assert_eq!(evdev::capabilities(2, 3)[0], 0b11);
    let rel = evdev::capabilities(2, 2);
    assert!(!has(&rel, 0) && has(&rel, 8));
    assert!(has(&evdev::capabilities(2, 1), 0x112));
    // Sizes of the other types, all empty
    assert_eq!(evdev::capabilities(0, 0x15).len(), 16);
    assert!(evdev::capabilities(1, 5).iter().all(|&b| b == 0));
    assert_eq!(evdev::capabilities(1, 0x1f).len(), 8);
    // EVIOCGBIT(EV_KEY) returns the same bytes
    let k = kbd();
    let mut b = [0u8; 96];
    assert_eq!(k.ioctl(0x8060_4521, b.as_mut_ptr() as u64), 96);
    assert_eq!(&b[..], &keys[..]);
}

#[test]
fn device_list_and_identities() {
    let _g = setup();
    fake::VMMOUSE.set(false);
    assert_eq!(evdev::device_count(), 2);
    fake::VMMOUSE.set(true);
    assert_eq!(evdev::device_count(), 3);
    let (name, phys, id) = evdev::device_info(2);
    assert_eq!(name, "VirtualPS/2 VMware VMMouse");
    assert_eq!(phys, "isa0060/serio1/input1");
    assert_eq!(id, [0x11, 2, 0x13, 0]);
    assert_eq!(evdev::device_info(1).0, "ImPS/2 Generic Wheel Mouse");
}
