//! `arch/pcid.rs` turned off at run time (own binary: the off switch stays).

use hydra_hosttests_t32::arch::pcid;
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

#[test]
fn disabled_pcid() {
    host::reset();
    stubs::reset();
    host::set_cpu(1);
    hw::set_cr(3, 0x5000);
    pcid::init_with(true, true);
    assert!(pcid::enabled());
    pcid::load_cr3(0x9000);
    assert!(hw::cr(3) & 0xFFF != 0, "an ID in use");
    pcid::disable("a test");
    assert!(!pcid::enabled());
    assert_eq!(hw::cr(3), 0x9000, "CR3's ID bits cleared");
    assert_eq!(hw::cr(4) & (1 << 17), 0);
    assert!(stubs::take_log().iter().any(|l| l.contains("PCID turned off: a test")));
    assert!(pcid::summary().starts_with("PCID off (a test)"));
    // init after that: stays off, saying why
    pcid::init_with(true, true);
    assert!(!pcid::enabled());
    assert!(stubs::take_log()[0].contains("turned off by a test"));
    without_pcid_cr3_loads_flush();
}

fn without_pcid_cr3_loads_flush() {
    host::reset();
    pcid::disable("off for this test");
    host::set_cpu(4);
    pcid::load_cr3(0x60_0000);
    assert_eq!(hw::cr(3), 0x60_0000);
    pcid::load_cr3(0x70_0000);
    pcid::load_cr3(0x60_0000);
    assert_eq!(hw::cr(3), 0x60_0000, "plain loads");
    pcid::forget(0x60_0000); // nothing to forget
    pcid::flush_current(None);
    assert_eq!(hw::cr(3), 0x60_0000);
}

