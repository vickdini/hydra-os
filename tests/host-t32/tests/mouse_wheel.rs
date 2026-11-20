//! `arch/mouse.rs` from a fresh driver: a wheel mouse (own binary: the driver initializes once).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use hydra_hosttests_t32::arch::mouse;
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

mod common;
use common::ps2::ps2;

fn serial() {
    host::reset();
    stubs::reset();
}

#[test]
fn mouse_init_with_wheel_then_packets() {
    serial();
    let s = ps2(0x20, true, true);
    mouse::init();
    {
        let s = s.borrow();
        assert_eq!(&s.log[..5], &["cmd 0xa8", "cmd 0x20", "cmd 0x60", "config 0x2", "cmd 0xd4"]);
        assert!(s.log.contains(&"mouse 0xf6".to_string()));
        assert!(s.log.contains(&"mouse 0xf4".to_string()));
        assert_eq!(&s.rates[..4], &[200, 100, 80, 100], "wheel knock, then back to 100/s");
    }
    assert!(stubs::take_log().iter().any(|l| l.contains("[+] PS/2 Mouse")));
    // Again: already done
    mouse::init();
    assert!(stubs::take_log().is_empty());

    // The IRQ mode: the handshake again, stale replies dropped, IRQs 2 and 12 unmasked
    s.borrow_mut().after_f4.extend([0xFA, 0xFE]); // late replies after the handshake
    host::HYPERVISOR.set(false);
    mouse::enable_irq();
    assert!(s.borrow().out.is_empty());
    assert!(stubs::take_log().iter().any(|l| l.contains("4 packets (wheel enabled)")));

    // 4-byte packets: left button, dx -3, dy +2 (up), wheel 1 toward the user
    drop(s);
    let bytes = Rc::new(RefCell::new(VecDeque::from(vec![
        0xFA, // a stray ACK: skipped
        0x07, // no bit 3: out of sync, skipped
        0x09 | 0x10, 0xFD, 0x02, 0xFF,
        0x08, 0x00, 0x00, 0x00,
    ])));
    let b = bytes.clone();
    hw::set_port_handler(move |op| match op.port {
        0x60 => b.borrow_mut().pop_front().unwrap_or(0) as u32,
        _ => 0xFF,
    });
    stubs::take_calls();
    for _ in 0..10 {
        mouse::on_mouse_irq();
    }
    let calls: Vec<_> = stubs::take_calls().into_iter().filter(|c| c.starts_with("evdev")).collect();
    assert_eq!(calls, vec!["evdev::mouse -3 -2 1 1", "evdev::mouse 0 0 0 0"]);
}
