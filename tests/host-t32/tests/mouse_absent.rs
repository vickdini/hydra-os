//! `arch/mouse.rs` from a fresh driver: no mouse answers (own binary: the driver initializes once).

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
fn mouse_init_reports_an_absent_device() {
    serial();
    // The mouse never answers its commands (NAK): init fails at "enable reporting"
    let _s = ps2(0, false, false);
    mouse::init();
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("not present: Mouse did not return 0xFA ACK")), "{log:?}");
    // No wheel knock got through: set defaults failed (ignored), the rate command failed
    let s = _s.borrow();
    assert!(s.rates.is_empty());
    assert_eq!(s.log.iter().filter(|l| l.starts_with("mouse")).count(), 3, "F6, F3, F4: {:?}", s.log);
    drop(s);
    // Not initialized: the IRQ mode is not entered, IRQ 12 stays masked
    hw::clear_ports();
    mouse::enable_irq();
    assert!(hw::port_writes().is_empty());
}

#[test]
fn controller_timeouts() {
    serial();
    // A controller whose input buffer never empties: every wait times out
    hw::set_port_handler(|op| if op.port == 0x64 { 0x02 } else { 0 });
    mouse::init();
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("timeout waiting for input buffer ready")), "{log:?}");
    // ...and one whose output buffer never fills
    hw::set_port_handler(|op| if op.port == 0x64 { 0x00 } else { 0 });
    mouse::init();
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("timeout waiting for output data")), "{log:?}");
}
