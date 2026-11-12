//! # QEMU firmware configuration (fw_cfg)
//!
//! QEMU's `-fw_cfg name=opt/...,string=...` hands named values to the guest through two I/O
//! ports: a selector (0x510) and a data port (0x511). Hydra reads `opt/hydra/boot` to choose
//! how to boot (`shell`: stay in the Hydra shell instead of starting the desktop), which lets
//! test harnesses pick the shell without racing a countdown. Without the device (real
//! hardware, other hypervisors) every read finds nothing.

use alloc::vec::Vec;
use x86_64::instructions::port::Port;

const SELECTOR: u16 = 0x510;
const DATA: u16 = 0x511;
/// Item of the signature ("QEMU").
const SIGNATURE: u16 = 0x0000;
/// Item of the file directory.
const FILE_DIR: u16 = 0x0019;

fn select(item: u16) {
    unsafe { Port::<u16>::new(SELECTOR).write(item) };
}

fn read_bytes(buf: &mut [u8]) {
    let mut data = Port::<u8>::new(DATA);
    for b in buf.iter_mut() {
        *b = unsafe { data.read() };
    }
}

/// The contents of the fw_cfg file `name` (e.g. `opt/hydra/boot`).
///
/// # Returns
/// `None` without the device or the file.
pub fn read_file(name: &str) -> Option<Vec<u8>> {
    select(SIGNATURE);
    let mut sig = [0u8; 4];
    read_bytes(&mut sig);
    if &sig != b"QEMU" {
        return None;
    }
    select(FILE_DIR);
    let mut count = [0u8; 4];
    read_bytes(&mut count);
    // Entries: size (u32), selector (u16), reserved (u16), name (56 bytes); big-endian
    for _ in 0..u32::from_be_bytes(count).min(4096) {
        let mut e = [0u8; 64];
        read_bytes(&mut e);
        let len = e[8..].iter().position(|&b| b == 0).unwrap_or(56);
        if &e[8..8 + len] == name.as_bytes() {
            let size = u32::from_be_bytes([e[0], e[1], e[2], e[3]]).min(4096) as usize;
            let item = u16::from_be_bytes([e[4], e[5]]);
            let mut v = alloc::vec![0u8; size];
            select(item);
            read_bytes(&mut v);
            return Some(v);
        }
    }
    None
}
