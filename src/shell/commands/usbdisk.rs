//! # Shell Command: USB disks (`usbdisk`)
//!
//! Lists the USB disks the USB driver serves ([`ENDPOINT_USB_DISK`], `MSG_BLOCK_LIST`) and
//! tests them through the block protocol, as the file server and the Linux block layer
//! use them:
//! - `usbdisk` / `usbdisk list`: number, size, sector size, where it is plugged in (root
//!   port and hub ports), USB IDs, model and serial;
//! - `usbdisk test <n> [blocks]`: writes patterns over `blocks` 4 KiB blocks (default
//!   2048, 8 MiB) at the start, the middle and the end of disk `n`, reads them back and
//!   compares, then puts the original data back;
//! - `usbdisk speed <n|ahci> [MiB] [write]`: sequential read speed (and, with `write`,
//!   write speed: the data read is written back unchanged) over the first `MiB` (64).
//!
//! The disk holding the running pool is refused for `test` and `speed ... write`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ipc::protocol::{
    BLOCK_LIST_RECORD, ENDPOINT_BLOCK_DEV, ENDPOINT_USB_DISK, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_LIST, MSG_BLOCK_READ, MSG_BLOCK_REPLY,
    MSG_BLOCK_WRITE,
};
use crate::ipc::service;
use crate::ipc::Message;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Set when the file server was told to find the pool on a USB disk.
pub static POOL_ON_USB: AtomicBool = AtomicBool::new(false);

/// Blocks per request (the window holds 64).
const CHUNK: u64 = 64;

/// Shell command for USB disks.
pub struct UsbDiskCommand;

/// One block request to disk `disk` of `endpoint`; returns the reply's status and value.
fn request(endpoint: u32, disk: u64, label: u32, a0: u64, a1: u64, data: Option<&mut [u8]>, write: bool) -> Result<u64, i64> {
    let _w = service::hold_window(endpoint);
    let window = service::window(endpoint).ok_or(-19i64)?;
    if write {
        if let Some(d) = data.as_deref() {
            window[..d.len()].copy_from_slice(d);
        }
    }
    let r = service::call(endpoint, Message::with_args(label, [a0, a1, 0, disk]), 6000)?;
    if r.label != MSG_BLOCK_REPLY || (r.args[0] as i64) < 0 {
        return Err(r.args[0] as i64);
    }
    if !write {
        if let Some(d) = data {
            let n = d.len();
            d.copy_from_slice(&window[..n]);
        }
    }
    Ok(r.args[1])
}

/// Reads or writes `count` blocks at `block` of disk `disk` in chunks of [`CHUNK`].
fn blocks(endpoint: u32, disk: u64, block: u64, count: u64, buf: &mut [u8], write: bool) -> Result<(), i64> {
    let mut done = 0;
    while done < count {
        let n = (count - done).min(CHUNK);
        let part = &mut buf[(done * 4096) as usize..((done + n) * 4096) as usize];
        request(endpoint, disk, if write { MSG_BLOCK_WRITE } else { MSG_BLOCK_READ }, block + done, n, Some(part), write)?;
        done += n;
    }
    Ok(())
}

/// The ASCII field `b`, trimmed.
fn text(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?").trim_end_matches([' ', '\0'])
}

fn list() {
    if !service::is_online(ENDPOINT_USB_DISK) {
        crate::println!("usbdisk: the USB driver is not running (no xHCI controller?)");
        return;
    }
    let mut records = Vec::new();
    let n = {
        let _w = service::hold_window(ENDPOINT_USB_DISK);
        match service::call(ENDPOINT_USB_DISK, Message::with_args(MSG_BLOCK_LIST, [0; 4]), 6000) {
            Ok(r) if r.label == MSG_BLOCK_REPLY && r.args[0] == 0 => {
                let n = r.args[1] as usize;
                if let Some(w) = service::window(ENDPOINT_USB_DISK) {
                    records.extend_from_slice(&w[..n * BLOCK_LIST_RECORD]);
                }
                n
            }
            r => {
                crate::println!("usbdisk: no answer from the USB driver ({:?})", r.map(|m| m.args[0] as i64));
                return;
            }
        }
    };
    if n == 0 {
        crate::println!("No USB disks.");
        return;
    }
    for r in records.chunks_exact(BLOCK_LIST_RECORD) {
        let u32_at = |o: usize| u32::from_le_bytes(r[o..o + 4].try_into().unwrap());
        let blocks = u64::from_le_bytes(r[8..16].try_into().unwrap());
        let (port, depth, speed, flags, route) = (r[20], r[21] as u32, r[22], r[23], u32_at(24));
        let mut place = alloc::format!("port {}", port);
        for t in 0..depth {
            place.push_str(&alloc::format!(".{}", (route >> (4 * t)) & 0xF));
        }
        crate::println!(
            "usb disk {}: {} MiB, {}-byte sectors, {}, {} speed {}, {:04x}:{:04x} '{}' serial '{}'{}{}{}",
            u32_at(0),
            blocks * 4096 / (1024 * 1024),
            u32_at(16),
            place,
            match speed {
                1 => "full",
                2 => "low",
                3 => "high",
                4 => "super",
                _ => "super+",
            },
            speed,
            u16::from_le_bytes([r[28], r[29]]),
            u16::from_le_bytes([r[30], r[31]]),
            text(&r[32..72]),
            text(&r[72..104]),
            if flags & 1 != 0 { ", removable" } else { "" },
            if flags & 2 != 0 { ", write-protected" } else { "" },
            if flags & 4 == 0 { ", no medium" } else { "" },
        );
    }
}

/// Size of disk `disk` of `endpoint` in blocks.
fn size(endpoint: u32, disk: u64) -> Result<u64, i64> {
    request(endpoint, disk, MSG_BLOCK_GET_SIZE, 0, 0, None, false)
}

/// Pattern byte `i` of block `b` for round `round`.
fn pattern(b: u64, i: usize, round: u64) -> u8 {
    ((b.wrapping_mul(2654435761) ^ (i as u64).wrapping_mul(40503) ^ round.wrapping_mul(0x9E37)) >> 3) as u8
}

fn test(disk: u64, count: u64) {
    let ep = ENDPOINT_USB_DISK;
    let total = match size(ep, disk) {
        Ok(t) => t,
        Err(e) => return crate::println!("usbdisk: disk {}: error {}", disk, e),
    };
    let count = count.clamp(1, total / 3);
    let mut saved = alloc::vec![0u8; (count * 4096) as usize];
    let mut buf = alloc::vec![0u8; (count * 4096) as usize];
    let mut bad = 0u64;
    let t0 = crate::arch::pit::ticks();
    for (k, start) in [0, total / 2, total - count].into_iter().enumerate() {
        if let Err(e) = blocks(ep, disk, start, count, &mut saved, false) {
            return crate::println!("usbdisk: read of {} blocks at {} failed: error {}", count, start, e);
        }
        for round in 0..2u64 {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = pattern(start + (i / 4096) as u64, i, round + k as u64 * 2);
            }
            if let Err(e) = blocks(ep, disk, start, count, &mut buf, true) {
                return crate::println!("usbdisk: write of {} blocks at {} failed: error {}", count, start, e);
            }
            let _ = request(ep, disk, MSG_BLOCK_FLUSH, 0, 0, None, false);
            buf.fill(0);
            if let Err(e) = blocks(ep, disk, start, count, &mut buf, false) {
                return crate::println!("usbdisk: read back of {} blocks at {} failed: error {}", count, start, e);
            }
            for (i, b) in buf.iter().enumerate() {
                if *b != pattern(start + (i / 4096) as u64, i, round + k as u64 * 2) {
                    bad += 1;
                }
            }
        }
        if let Err(e) = blocks(ep, disk, start, count, &mut saved, true) {
            return crate::println!("usbdisk: restoring {} blocks at {} failed: error {}", count, start, e);
        }
        buf.fill(0);
        let _ = blocks(ep, disk, start, count, &mut buf, false);
        if buf != saved {
            bad += 1;
            crate::println!("usbdisk: the original data at {} did not come back", start);
        }
    }
    let _ = request(ep, disk, MSG_BLOCK_FLUSH, 0, 0, None, false);
    let secs = (crate::arch::pit::ticks() - t0) as f64 / 100.0;
    crate::println!(
        "usbdisk test disk {}: {} blocks x 3 places x 2 patterns written, read back and restored in {:.1} s: {}",
        disk,
        count,
        secs,
        if bad == 0 { alloc::string::String::from("OK, all data matched") } else { alloc::format!("FAILED, {} bytes differ", bad) }
    );
}

fn speed(ep: u32, disk: u64, mib: u64, write: bool) {
    let total = match size(ep, disk) {
        Ok(t) => t,
        Err(e) => return crate::println!("usbdisk: error {}", e),
    };
    let count = (mib * 256).min(total);
    let mut buf = alloc::vec![0u8; (CHUNK * 4096) as usize];
    let t0 = crate::arch::pit::ticks();
    let mut done = 0;
    while done < count {
        let n = (count - done).min(CHUNK);
        if let Err(e) = request(ep, disk, MSG_BLOCK_READ, done, n, Some(&mut buf[..(n * 4096) as usize]), false) {
            return crate::println!("usbdisk: read failed at block {}: error {}", done, e);
        }
        done += n;
    }
    let t = (crate::arch::pit::ticks() - t0).max(1);
    crate::println!("usbdisk speed: read {} MiB in {:.2} s: {} MiB/s", count / 256, t as f64 / 100.0, count * 4096 * 100 / t / (1024 * 1024));
    if !write {
        return;
    }
    let t0 = crate::arch::pit::ticks();
    let mut done = 0;
    while done < count {
        let n = (count - done).min(CHUNK);
        let part = &mut buf[..(n * 4096) as usize];
        if let Err(e) = request(ep, disk, MSG_BLOCK_READ, done, n, Some(part), false) {
            return crate::println!("usbdisk: read failed at block {}: error {}", done, e);
        }
        if let Err(e) = request(ep, disk, MSG_BLOCK_WRITE, done, n, Some(part), true) {
            return crate::println!("usbdisk: write failed at block {}: error {}", done, e);
        }
        done += n;
    }
    let _ = request(ep, disk, MSG_BLOCK_FLUSH, 0, 0, None, false);
    let t = (crate::arch::pit::ticks() - t0).max(1);
    crate::println!(
        "usbdisk speed: read and wrote back {} MiB in {:.2} s: {} MiB/s moved (reads + writes)",
        count / 256,
        t as f64 / 100.0,
        count * 4096 * 2 * 100 / t / (1024 * 1024)
    );
}

impl Command for UsbDiskCommand {
    fn name(&self) -> &'static str {
        "usbdisk"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn description(&self) -> &'static str {
        "List and test USB disks (USB mass storage)"
    }

    fn usage(&self) -> &'static str {
        "usbdisk [list | test <n> [blocks] | speed <n|ahci> [MiB] [write]]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let num = |i: usize, default: u64| args.get(i).and_then(|a| a.parse::<u64>().ok()).unwrap_or(default);
        match args.first().copied().unwrap_or("list") {
            "list" => list(),
            "test" => {
                if POOL_ON_USB.load(Ordering::Acquire) {
                    return crate::println!("usbdisk: the running pool is on a USB disk; not writing to USB disks");
                }
                test(num(1, 0), num(2, 2048))
            }
            "speed" => {
                let write = args.contains(&"write");
                let (ep, disk) = if args.get(1) == Some(&"ahci") { (ENDPOINT_BLOCK_DEV, 0) } else { (ENDPOINT_USB_DISK, num(1, 0)) };
                if write && (ep == ENDPOINT_BLOCK_DEV || POOL_ON_USB.load(Ordering::Acquire)) {
                    return crate::println!("usbdisk: not writing to the disk of the running pool");
                }
                speed(ep, disk, num(2, 64), write)
            }
            _ => crate::println!("usage: {}", self.usage()),
        }
    }
}
