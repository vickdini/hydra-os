//! # evdev input devices: the kernel's part
//!
//! The event devices (`/dev/input/event0`..`2`) are the input service's
//! (`userland/drivers/input-server`, wave 8 I; wave 10 10-C deleted the in-kernel copy that
//! `lx=kernel`/`lx.input=kernel` used). What stays here: the routing switch (to the input
//! ring, [`crate::ipc::input`]) and the devices' static descriptions the kernel writes into
//! `/sys` ([`super::devices`]).

use alloc::vec::Vec;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const EV_MSC: u16 = 0x04;
const EV_LED: u16 = 0x11;
const EV_REP: u16 = 0x14;
const MSC_SCAN: u16 = 4;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_WHEEL: u16 = 8;
const REL_WHEEL_HI_RES: u16 = 11;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const DEVICES: usize = 3;

/// Sends the keyboard and mouse to the event devices (`true`) or back to Hydra (`false`)
/// (the input ring's routing, [`crate::ipc::input::set_routing`]).
///
/// # Arguments
///
/// * `on` - `true` to route input to evdev; `false` to route back to Hydra.
pub fn set_routing(on: bool) {
    crate::ipc::input::set_routing(on);
}

/// Static description of a device.
struct Info {
    name: &'static str,
    phys: &'static str,
    id: [u16; 4],
}

const INFO: [Info; DEVICES] = [
    Info { name: "AT Translated Set 2 keyboard", phys: "isa0060/serio0/input0", id: [0x11, 0x1, 0x1, 0xab41] },
    Info { name: "ImPS/2 Generic Wheel Mouse", phys: "isa0060/serio1/input0", id: [0x11, 0x2, 0x1, 0] },
    // As Linux's vmmouse driver names it (BUS_I8042, vendor 2, product PSMOUSE_VMMOUSE)
    Info { name: "VirtualPS/2 VMware VMMouse", phys: "isa0060/serio1/input1", id: [0x11, 0x2, 0x13, 0] },
];

/// Number of event devices to list: the absolute pointer only where the hypervisor offers it.
pub fn device_count() -> usize {
    if crate::arch::vmmouse::present() { DEVICES } else { DEVICES - 1 }
}

/// Device names and identities for sysfs ([`super::devices`]).
///
/// # Arguments
///
/// * `dev` - Device index (`0` for keyboard, `1` for mouse).
///
/// # Returns
///
/// `(name, phys_path, id_quad)` tuple.
pub fn device_info(dev: usize) -> (&'static str, &'static str, [u16; 4]) {
    let i = &INFO[dev];
    (i.name, i.phys, i.id)
}

/// Sets a single bit in a capability byte array.
///
/// # Arguments
///
/// * `map` - Mutable byte slice representing bitmask.
/// * `bit` - Index of the bit to set.
fn set_bit(map: &mut [u8], bit: usize) {
    if bit / 8 < map.len() {
        map[bit / 8] |= 1 << (bit % 8);
    }
}

/// Capability bitmap of event type `ty` (0 = the event types themselves), in bytes.
///
/// # Arguments
///
/// * `dev` - Device index (`0` for keyboard, `1` for mouse).
/// * `ty` - Event type code.
///
/// # Returns
///
/// Byte vector containing capability bitmask.
pub fn capabilities(dev: usize, ty: u16) -> Vec<u8> {
    let bytes = match ty {
        0 => 8,
        EV_KEY => 96,
        EV_REL | EV_MSC | EV_LED | EV_REP => 8,
        0x03 | 0x05 | 0x12 => 8, // ABS, SW, SND
        0x15 => 16,              // FF
        _ => 8,
    };
    let mut m = alloc::vec![0u8; bytes];
    match (dev, ty) {
        (0, 0) => [EV_SYN, EV_KEY, EV_MSC, EV_LED, EV_REP].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (1, 0) => [EV_SYN, EV_KEY, EV_REL].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (2, 0) => [EV_SYN, EV_KEY, EV_REL, EV_ABS].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (2, EV_KEY) => [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().for_each(|&k| set_bit(&mut m, k as usize)),
        (2, EV_REL) => [REL_WHEEL, REL_WHEEL_HI_RES].iter().for_each(|&c| set_bit(&mut m, c as usize)),
        (2, EV_ABS) => [ABS_X, ABS_Y].iter().for_each(|&c| set_bit(&mut m, c as usize)),
        (0, EV_KEY) => {
            (1..=88).chain(96..=111).chain(125..=127).for_each(|k| set_bit(&mut m, k));
        }
        (1, EV_KEY) => [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().for_each(|&k| set_bit(&mut m, k as usize)),
        (1, EV_REL) => {
            for code in [REL_X, REL_Y, REL_WHEEL, REL_WHEEL_HI_RES] {
                set_bit(&mut m, code as usize);
            }
        }
        (0, EV_MSC) => set_bit(&mut m, MSC_SCAN as usize),
        (0, EV_LED) => (0..3).for_each(|l| set_bit(&mut m, l)),
        _ => {}
    }
    m
}
