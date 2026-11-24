//! Legacy PC devices behind I/O ports: `arch/pic.rs`, `arch/raw_serial.rs`, `arch/fwcfg.rs`,
//! `arch/power.rs`, `arch/keyboard.rs`, `arch/mouse.rs` and `arch/vmmouse.rs`.
//!
//! Port I/O goes to the shim's per-thread scripted bus; the keyboard and mouse state is
//! global (as in the kernel), so those tests hold [`serial`].

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::{fwcfg, keyboard, mouse, pic, power, raw_serial, vmmouse};
use hydra_hosttests_t32::{host, stubs};

mod common;
use common::ps2::ps2;
use uefi::proto::console::text::{Key, ScanCode};
use x86_64::hw;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

// ------------------------------------------------------------------------------- PIC

#[test]
fn pic_init_remaps_and_masks() {
    host::reset();
    pic::init();
    let w: Vec<_> = hw::port_writes().into_iter().filter(|w| w.0 != 0x80).collect();
    assert_eq!(
        w,
        vec![(0x20, 0x11), (0xA0, 0x11), (0x21, 0x20), (0xA1, 0x28), (0x21, 4), (0xA1, 2), (0x21, 1), (0xA1, 1), (0x21, 0xF8), (0xA1, 0xFF)]
    );
    // An I/O delay after each write
    assert_eq!(hw::port_writes().iter().filter(|w| w.0 == 0x80).count(), 10);
}

#[test]
fn pic_eoi_and_masks() {
    host::reset();
    pic::send_eoi(3);
    assert_eq!(hw::port_writes(), vec![(0x20, 0x20)]);
    hw::clear_ports();
    pic::send_eoi(12);
    assert_eq!(hw::port_writes(), vec![(0xA0, 0x20), (0x20, 0x20)], "slave first");

    // Masks: read-modify-write of the right chip
    let masks = Rc::new(RefCell::new([0xF8u8, 0xFF]));
    let m = masks.clone();
    hw::set_port_handler(move |op| {
        let i = match op.port {
            0x21 => 0,
            0xA1 => 1,
            _ => return 0,
        };
        match op.write {
            Some(v) => {
                m.borrow_mut()[i] = v as u8;
                0
            }
            None => m.borrow()[i] as u32,
        }
    });
    pic::unmask_irq(12);
    pic::unmask_irq(2);
    assert_eq!(*masks.borrow(), [0xF8, 0xEF]);
    pic::mask_irq(1);
    pic::mask_irq(14);
    assert_eq!(*masks.borrow(), [0xFA, 0xEF | 0x40]);
    pic::unmask_irq(4);
    assert_eq!(masks.borrow()[0], 0xEA);
}

// ------------------------------------------------------------------------- serial

#[test]
fn raw_serial_writes_crlf_and_polls() {
    host::reset();
    let mut polls = 0;
    hw::set_port_handler(move |op| {
        if op.port == 0x3FD {
            polls += 1;
            // Busy for the first two polls of each byte
            return if polls % 3 == 0 { 0x20 } else { 0 };
        }
        0
    });
    use core::fmt::Write;
    write!(raw_serial::RawSerial, "a\nb").unwrap();
    let data: Vec<u8> = hw::port_writes().iter().filter(|w| w.0 == 0x3F8).map(|w| w.1 as u8).collect();
    assert_eq!(data, b"a\r\nb");
    // A port that never gets ready: written anyway after the bounded wait
    hw::clear_ports();
    hw::set_port_handler(|_| 0);
    write!(raw_serial::RawSerial, "x").unwrap();
    assert_eq!(hw::port_writes(), vec![(0x3F8, b'x' as u32)]);
}

// ------------------------------------------------------------------------- fw_cfg

/// QEMU's fw_cfg with these files (selector 0x510, data 0x511).
fn fw_cfg(files: &[(&str, &[u8])], signature: &'static [u8; 4]) {
    let mut items: Vec<Vec<u8>> = vec![signature.to_vec()];
    let mut dir = (files.len() as u32).to_be_bytes().to_vec();
    for (i, (name, data)) in files.iter().enumerate() {
        let sel = 0x20 + i as u16;
        let mut e = [0u8; 64];
        e[0..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
        e[4..6].copy_from_slice(&sel.to_be_bytes());
        e[8..8 + name.len()].copy_from_slice(name.as_bytes());
        dir.extend_from_slice(&e);
    }
    let mut map = std::collections::BTreeMap::new();
    map.insert(0u16, items.remove(0));
    map.insert(0x19u16, dir);
    for (i, (_, data)) in files.iter().enumerate() {
        map.insert(0x20 + i as u16, data.to_vec());
    }
    let mut cur = (0u16, 0usize);
    hw::set_port_handler(move |op| match (op.port, op.write) {
        (0x510, Some(v)) => {
            cur = (v as u16, 0);
            0
        }
        (0x511, None) => {
            let b = map.get(&cur.0).and_then(|d| d.get(cur.1)).copied().unwrap_or(0);
            cur.1 += 1;
            b as u32
        }
        _ => 0,
    });
}

#[test]
fn fwcfg_reads_named_files() {
    host::reset();
    fw_cfg(&[("etc/boot-menu", b"x"), ("opt/hydra/boot", b"shell")], b"QEMU");
    assert_eq!(fwcfg::read_file("opt/hydra/boot").as_deref(), Some(&b"shell"[..]));
    assert_eq!(fwcfg::read_file("etc/boot-menu").as_deref(), Some(&b"x"[..]));
    assert_eq!(fwcfg::read_file("opt/hydra/pcid"), None);
    let mut buf = [0u8; 3];
    assert_eq!(fwcfg::read_file_into("opt/hydra/boot", &mut buf), Some(3));
    assert_eq!(&buf, b"she");
    let mut big = [0u8; 16];
    assert_eq!(fwcfg::read_file_into("opt/hydra/boot", &mut big), Some(5));
    assert_eq!(fwcfg::read_file_into("nope", &mut big), None);
}

#[test]
fn fwcfg_without_the_device() {
    host::reset();
    // No device: the data port reads all ones
    assert_eq!(fwcfg::read_file("opt/hydra/boot"), None);
    fw_cfg(&[("opt/hydra/boot", b"shell")], b"BOCH");
    assert_eq!(fwcfg::read_file("opt/hydra/boot"), None);
    let mut b = [0u8; 4];
    assert_eq!(fwcfg::read_file_into("opt/hydra/boot", &mut b), None);
}

// -------------------------------------------------------------------------- power

#[test]
fn power_off_tries_every_method_then_firmware() {
    host::reset();
    stubs::reset();
    let r = std::panic::catch_unwind(|| power::power_off());
    assert!(r.is_err(), "the firmware call is not available on the host");
    assert!(stubs::take_calls().contains(&"zfs::sync".to_string()));
    let w = hw::port_writes();
    assert_eq!(
        w,
        vec![(0x4004, 0x3400), (0x4004, 0x2000), (0x604, 0x2000), (0x604, 0x3400), (0xb004, 0x2000), (0xb004, 0x3400), (0x501, 0)]
    );
    assert!(stubs::take_log().iter().any(|l| l.contains("Powering off")));
}

#[test]
fn reboot_pulses_reset_lines() {
    host::reset();
    stubs::reset();
    stubs::answer("zfs::sync_fails", 1);
    let r = std::panic::catch_unwind(|| power::reboot());
    assert!(r.is_err());
    assert_eq!(hw::port_writes(), vec![(0x64, 0xFE), (0xCF9, 0x06)]);
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("pool commit failed: pool gone")), "{log:?}");
    assert!(log.iter().any(|l| l.contains("Restarting")));
}

// wave7 GB begin
#[test]
fn a_restart_does_not_wait_for_ever_for_a_pool_commit() {
    host::reset();
    stubs::reset();
    // With the scheduler running the commit runs in a task of its own; here it never
    // finishes (the pool's disk is gone): the restart goes on after 30 s
    stubs::task::ACTIVE.set(true);
    stubs::task::SPAWNED.with_borrow_mut(|s| s.clear());
    let r = std::panic::catch_unwind(|| power::reboot());
    stubs::task::ACTIVE.set(false);
    assert!(r.is_err());
    assert_eq!(hw::port_writes(), vec![(0x64, 0xFE), (0xCF9, 0x06)]);
    let calls = stubs::take_calls();
    assert!(calls.contains(&"task::spawn pool-commit".to_string()), "{calls:?}");
    assert_eq!(calls.iter().filter(|c| *c == "task::sleep_ms 100").count(), 300);
    assert!(!calls.contains(&"zfs::sync".to_string()), "not made by the caller");
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("did not finish within 30 s")), "{log:?}");
    assert!(log.iter().any(|l| l.contains("Restarting")));
    // The task itself: commits, then ends
    let entry = stubs::task::SPAWNED.with_borrow(|s| s[0]);
    let r = std::panic::catch_unwind(entry);
    assert!(r.is_err(), "task::exit");
    let calls = stubs::take_calls();
    assert_eq!((calls.contains(&"zfs::sync".to_string()), calls.contains(&"task::exit".to_string())), (true, true));
}
// wave7 GB end

// ----------------------------------------------------------------------- keyboard

fn ch(c: char) -> Option<Key> {
    Some(Key::Printable(uefi::Char16::try_from(c).unwrap()))
}

fn release_modifiers() {
    for b in [0xAA, 0xB6, 0x9D] {
        keyboard::process_scancode(b);
    }
}

#[test]
fn scancodes_decode_with_modifiers() {
    let _g = serial();
    release_modifiers();
    assert_eq!(keyboard::process_scancode(0x1E), ch('a'));
    assert_eq!(keyboard::process_scancode(0x9E), None, "release");
    assert_eq!(keyboard::process_scancode(0x02), ch('1'));
    assert_eq!(keyboard::process_scancode(0x39), ch(' '));
    assert_eq!(keyboard::process_scancode(0x1C), ch('\r'));
    assert_eq!(keyboard::process_scancode(0x0E), ch('\x08'));
    assert_eq!(keyboard::process_scancode(0x01), ch('\x1B'));
    // Shift (left, then right)
    assert_eq!(keyboard::process_scancode(0x2A), None);
    assert_eq!(keyboard::process_scancode(0x1E), ch('A'));
    assert_eq!(keyboard::process_scancode(0x02), ch('!'));
    assert_eq!(keyboard::process_scancode(0x28), ch('"'));
    assert_eq!(keyboard::process_scancode(0xAA), None);
    assert_eq!(keyboard::process_scancode(0x36), None);
    assert_eq!(keyboard::process_scancode(0x35), ch('?'));
    assert_eq!(keyboard::process_scancode(0xB6), None);
    assert_eq!(keyboard::process_scancode(0x35), ch('/'));
    // Ctrl: letters become control codes, others stay
    assert_eq!(keyboard::process_scancode(0x1D), None);
    assert_eq!(keyboard::process_scancode(0x2E), ch('\x03'), "Ctrl+C");
    assert_eq!(keyboard::process_scancode(0x02), ch('1'));
    assert_eq!(keyboard::process_scancode(0x9D), None);
    assert_eq!(keyboard::process_scancode(0x2E), ch('c'));
    // Unknown keys
    assert_eq!(keyboard::process_scancode(0x3B), None, "F1");
    // Every printable of the table, unshifted and shifted
    let table = "1234567890-=\tqwertyuiop[]\rasdfghjkl;'`\\zxcvbnm,./";
    let codes: Vec<u8> = (0x02..=0x0D).chain([0x0F]).chain(0x10..=0x1B).chain([0x1C]).chain(0x1E..=0x29).chain([0x2B]).chain(0x2C..=0x35).collect();
    assert_eq!(codes.len(), table.chars().count());
    let shifted = "!@#$%^&*()_+\tQWERTYUIOP{}\rASDFGHJKL:\"~|ZXCVBNM<>?";
    for ((c, lo), hi) in codes.iter().zip(table.chars()).zip(shifted.chars()) {
        assert_eq!(keyboard::process_scancode(*c), ch(lo), "{c:#x}");
        keyboard::process_scancode(0x2A);
        assert_eq!(keyboard::process_scancode(*c), ch(hi), "shift {c:#x}");
        keyboard::process_scancode(0xAA);
    }
}

#[test]
fn extended_keys() {
    let _g = serial();
    release_modifiers();
    let ext = |c| {
        assert_eq!(keyboard::process_scancode(0xE0), None);
        keyboard::process_scancode(c)
    };
    for (code, sc) in [(0x48, 1), (0x50, 2), (0x4D, 3), (0x4B, 4), (0x47, 5), (0x4F, 6), (0x53, 8), (0x49, 9), (0x51, 10)] {
        assert_eq!(ext(code), Some(Key::Special(ScanCode(sc))), "{code:#x}");
    }
    assert_eq!(ext(0x1C), None, "keypad Enter is not mapped");
    assert_eq!(ext(0xC8), None, "extended release");
    // The prefix applies to one code only
    assert_eq!(keyboard::process_scancode(0x48), None, "keypad 8 without E0: unmapped");
    // Right Ctrl (E0 1D) holds Ctrl like the left one
    ext(0x1D);
    assert_eq!(keyboard::process_scancode(0x1E), ch('\x01'));
    ext(0x9D);
    assert_eq!(keyboard::process_scancode(0x1E), ch('a'));
}

#[test]
fn console_keys_reach_the_buffer_and_wake_readers() {
    let _g = serial();
    release_modifiers();
    while keyboard::read_key().is_some() {}
    let wakes = hydra_hosttests_t32::compat::linux::tty::INPUT_WQ.wakes();
    for c in [0x23, 0x17] {
        keyboard::handle_scancode(c);
        keyboard::handle_scancode(c | 0x80);
    }
    assert_eq!(hydra_hosttests_t32::compat::linux::tty::INPUT_WQ.wakes(), wakes + 2);
    assert_eq!(keyboard::read_key(), ch('h'));
    assert_eq!(keyboard::get_key(), ch('i').unwrap());
    assert_eq!(keyboard::read_key(), None);
    // The ring holds 1024 keys; more are dropped
    for _ in 0..1100 {
        keyboard::handle_scancode(0x1E);
    }
    let mut n = 0;
    while keyboard::read_key().is_some() {
        n += 1;
    }
    assert_eq!(n, 1024);
}

#[test]
fn special_console_keys() {
    let _g = serial();
    use std::sync::atomic::Ordering::Relaxed;
    keyboard::TASK_DUMP_REQUESTED.store(false, Relaxed);
    keyboard::handle_scancode(0x58);
    assert!(keyboard::TASK_DUMP_REQUESTED.load(Relaxed), "F12 asks for a task dump");
    let trace = &hydra_hosttests_t32::compat::linux::TRACE_SYSCALLS;
    let was = trace.load(Relaxed);
    keyboard::handle_scancode(0x46);
    keyboard::handle_scancode(0xC6);
    assert_eq!(trace.load(Relaxed), !was, "Scroll Lock toggles tracing (release ignored)");
    keyboard::handle_scancode(0x46);
    assert_eq!(trace.load(Relaxed), was);
    // Ctrl+Alt+F2 with a hidden session: back to it
    stubs::answer("drm::session_hidden", 1);
    for c in [0x1D, 0x38, 0x3C] {
        keyboard::handle_scancode(c);
    }
    assert_eq!(stubs::take_calls(), vec!["drm::request_vt_switch true"]);
    for c in [0xBC, 0xB8, 0x9D] {
        keyboard::handle_scancode(c);
    }
    // ...not without Alt
    keyboard::handle_scancode(0x1D);
    keyboard::handle_scancode(0x3C);
    keyboard::handle_scancode(0x9D);
    assert!(stubs::take_calls().is_empty());
}

#[test]
fn session_keyboard_goes_to_evdev() {
    let _g = serial();
    stubs::answer("evdev::routing", 1);
    keyboard::handle_scancode(0x1E);
    keyboard::handle_scancode(0x9E);
    // Ctrl+Alt+F1: to the console, the F1 press and release swallowed
    for c in [0x1D, 0x38, 0x3B, 0xBB, 0xB8, 0x9D] {
        keyboard::handle_scancode(c);
    }
    // F1 alone goes through
    keyboard::handle_scancode(0x3B);
    keyboard::handle_scancode(0xBB);
    assert_eq!(
        stubs::take_calls(),
        vec![
            "evdev::scancode 0x1e",
            "evdev::scancode 0x9e",
            "evdev::scancode 0x1d",
            "evdev::scancode 0x38",
            "drm::request_vt_switch false",
            "evdev::scancode 0xb8",
            "evdev::scancode 0x9d",
            "evdev::scancode 0x3b",
            "evdev::scancode 0xbb",
        ]
    );
}

#[test]
fn keyboard_irq_reads_the_data_port() {
    let _g = serial();
    release_modifiers();
    while keyboard::read_key().is_some() {}
    hw::set_port_handler(|op| if op.port == 0x60 { 0x30 } else { 0 });
    keyboard::on_keyboard_irq();
    assert_eq!(keyboard::read_key(), ch('b'));
}

#[test]
fn early_polling_before_interrupts() {
    let _g = serial();
    release_modifiers();
    while keyboard::read_key().is_some() {}
    // Interrupts off and no timer yet (this binary never starts the PIT): poll the 8042
    hw::set_if(false);
    let mut status = 0;
    hw::set_port_handler(move |op| match op.port {
        0x64 => {
            status += 1;
            if status >= 3 { 1 } else { 0 }
        }
        0x60 => 0x2C,
        _ => 0,
    });
    assert_eq!(keyboard::read_key(), None, "nothing in the output buffer");
    assert_eq!(keyboard::get_key(), ch('z').unwrap());
    hw::set_if(true);
}

#[test]
fn get_key_halts_until_a_key_comes() {
    let _g = serial();
    release_modifiers();
    while keyboard::read_key().is_some() {}
    hw::set_if(true);
    hw::set_hlt_hook(Some(Box::new(|| keyboard::handle_scancode(0x13))));
    assert_eq!(keyboard::get_key(), ch('r').unwrap());
    hw::set_hlt_hook(None);
    assert_eq!(hw::hlts(), 1);
}

#[test]
fn keyboard_init_enables_irq1_and_scanning() {
    let _g = serial();
    let s = ps2(0x10 | 0x40, false, true);
    s.borrow_mut().out.extend([0xAA, 0x55]); // stale bytes to drain
    keyboard::init();
    let s = s.borrow();
    assert_eq!(s.log, vec!["cmd 0xae", "cmd 0x20", "cmd 0x60", "config 0x41", "kbd 0xf4"]);
    assert!(s.out.is_empty(), "drained, and the ACK read");
}

#[test]
fn mouse_without_wheel_or_absent() {
    let _g = serial();
    // A plain mouse: 3-byte packets (this test runs after or before the wheel one: the
    // driver's state is global, so only what `enable_irq` sets is checked)
    let s = ps2(0, false, true);
    mouse::init();
    host::HYPERVISOR.set(false);
    mouse::enable_irq();
    let _ = s;
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l == "[mouse] 3 packets"), "{log:?}");
    let bytes = Rc::new(RefCell::new(VecDeque::from(vec![0x08 | 0x20, 0x05, 0xFE])));
    let b = bytes.clone();
    hw::set_port_handler(move |op| match op.port {
        0x60 => b.borrow_mut().pop_front().unwrap_or(0) as u32,
        _ => 0,
    });
    stubs::take_calls();
    for _ in 0..3 {
        mouse::on_mouse_irq();
    }
    // dy = 0xFE sign-extended (-2), inverted: +2 (down)
    assert_eq!(stubs::take_calls(), vec!["evdev::mouse 5 2 0 0"]);
}

#[test]
fn mouse_inject_scales_absolute() {
    let _g = serial();
    mouse::inject_relative(1, -1, 0, 4);
    mouse::inject_absolute(512, 2000, 1024, -1, 1);
    mouse::inject_absolute(0, 0, 0, 0, 0);
    assert_eq!(stubs::take_calls(), vec!["evdev::mouse 1 -1 0 4", "evdev::abs 32767 65535 -1 1", "evdev::abs 0 0 0 0"]);
}

// ------------------------------------------------------------------------- vmmouse

/// A VMware backdoor with absolute reports queued.
fn backdoor(reports: Vec<(u32, u32, u32, u32)>, version: u32) -> Rc<RefCell<Vec<String>>> {
    let log = Rc::new(RefCell::new(Vec::new()));
    let l = log.clone();
    let mut q: VecDeque<_> = reports.into();
    host::VMWARE.with_borrow_mut(|v| {
        *v = Some(Box::new(move |cmd, arg| {
            l.borrow_mut().push(format!("{cmd} {arg:#x}"));
            match (cmd, arg) {
                (10, _) => (6, 0x564D_5868, 0, 0),
                (40, _) => match q.front() {
                    Some(&(f, ..)) if f == 0xFFFF_0000 => {
                        q.pop_front();
                        (0xFFFF_0000, 0, 0, 0)
                    }
                    _ => ((q.len() * 4) as u32 | 0x10000 * 0, 0, 0, 0),
                },
                (39, 1) => (version, 0, 0, 0),
                (39, 4) => q.pop_front().unwrap_or((0, 0, 0, 0)),
                _ => (0, 0, 0, 0),
            }
        }))
    });
    log
}

#[test]
fn vmmouse_needs_a_hypervisor_and_the_backdoor() {
    let _g = serial();
    host::HYPERVISOR.set(false);
    assert!(!vmmouse::enable());
    host::HYPERVISOR.set(true);
    host::VMWARE.with_borrow_mut(|v| *v = Some(Box::new(|_, _| (0, 0, 0, 0))));
    assert!(!vmmouse::enable(), "no magic in ebx");
    // Present, but the status says nothing is there (count 0)
    let log = backdoor(vec![], 0x3442_554a);
    assert!(!vmmouse::enable());
    assert!(vmmouse::present());
    assert!(!vmmouse::active());
    assert_eq!(log.borrow()[1], format!("41 {:#x}", 0x4541_4552), "ENABLE");
}

#[test]
fn vmmouse_absolute_reports() {
    let _g = serial();
    host::HYPERVISOR.set(true);
    let reports = vec![(0x20 | 0x08, 70000, 100, 0xFF), (0x0001_0000, 5, 5, 0), (0x10, 1, 2, 1)];
    let log = backdoor(reports, 0x3442_554a);
    assert!(vmmouse::enable());
    assert!(vmmouse::active());
    assert!(log.borrow().contains(&format!("41 {:#x}", 0x5342_4152)), "REQUEST_ABSOLUTE");
    let mut got = Vec::new();
    vmmouse::drain(|r| got.push((r.x, r.y, r.buttons, r.wheel)));
    // Left+middle, x clamped to 0xFFFF, wheel byte 0xFF = -1 inverted; a stale relative
    // packet skipped; right button, wheel 1 inverted
    assert_eq!(got, vec![(0xFFFF, 100, 0b101, 1), (1, 2, 0b010, -1)]);
}

#[test]
fn vmmouse_status_error_reenables() {
    let _g = serial();
    host::HYPERVISOR.set(true);
    let _ = backdoor(vec![], 0x3442_554a);
    host::VMWARE.with_borrow_mut(|_| ());
    let _ = backdoor(vec![(0, 0, 0, 0)], 0x3442_554a);
    assert!(vmmouse::enable());
    // The device reset itself: an error status, and the re-enable fails (wrong version)
    let _ = backdoor(vec![(0xFFFF_0000, 0, 0, 0)], 0x1234);
    let mut n = 0;
    vmmouse::drain(|_| n += 1);
    assert_eq!(n, 0);
    assert!(!vmmouse::active());
}

#[test]
fn mouse_irq_with_vmmouse_reads_absolute_reports() {
    let _g = serial();
    // A plain PS/2 mouse, then the backdoor on
    let _s = ps2(0, false, true);
    mouse::init();
    host::HYPERVISOR.set(true);
    let reports = vec![(0x20, 10, 20, 0), (0x20, 30, 40, 0)];
    let _ = backdoor(reports, 0x3442_554a);
    mouse::enable_irq();
    assert!(vmmouse::active());
    assert!(stubs::take_log().iter().any(|l| l.contains("absolute (vmmouse)")));
    // A PS/2 packet only says reports are queued
    let bytes = Rc::new(RefCell::new(VecDeque::from(vec![0x08, 0, 0])));
    let b = bytes.clone();
    hw::set_port_handler(move |op| match op.port {
        0x60 => b.borrow_mut().pop_front().unwrap_or(0) as u32,
        _ => 0,
    });
    stubs::take_calls();
    for _ in 0..3 {
        mouse::on_mouse_irq();
    }
    let calls: Vec<_> = stubs::take_calls().into_iter().filter(|c| c.starts_with("evdev")).collect();
    assert_eq!(calls, vec!["evdev::abs 10 20 0 1", "evdev::abs 30 40 0 1"]);
    // Leave the backdoor off for the other tests
    host::HYPERVISOR.set(true);
    let _ = backdoor(vec![(0xFFFF_0000, 0, 0, 0)], 0);
    vmmouse::drain(|_| ());
    assert!(!vmmouse::active());
}

