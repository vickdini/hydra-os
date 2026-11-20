//! # Admin operations on the pool and the disks (op group `0x5_`)
//!
//! Thin wrappers over the ZFS file server (a ring-3 server already): directory listings,
//! lookups, the changes the file commands make (`mkdir`, `cp`, `mv`, `rm`, writes), the
//! datasets, the file server's checks, and the disks. File contents are read with the
//! native `open`/`read` calls, not through here. When the shell talks to the file server
//! over IPC itself, most of this goes away.
//!
//! The USB disk tool (`usbdisk`) is a report operation: it drives the USB driver's block
//! protocol through the kernel's service windows, which a ring-3 client cannot reach.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::proto::*;
use super::{Failure, Failure::*};
use crate::fs::ZfsClient;
use crate::ipc::protocol::{
    BLOCK_LIST_RECORD, ENDPOINT_BLOCK_DEV, ENDPOINT_USB_DISK, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_LIST, MSG_BLOCK_READ, MSG_BLOCK_REPLY,
    MSG_BLOCK_WRITE,
};
use crate::ipc::service;
use crate::ipc::Message;

/// `ADMIN_POOL_STATUS`.
pub fn pool_status() -> PoolStatus {
    let mut st = PoolStatus { on_disk: crate::fs::zfs::disk_info().is_some() as u64, ..Default::default() };
    if let Ok((total_mib, alloc_kib, free_kib, txg)) = ZfsClient::pool_status() {
        st.metrics_valid = 1;
        st.total_mib = total_mib;
        st.alloc_kib = alloc_kib;
        st.free_kib = free_kib;
        st.txg = txg;
    }
    st
}

/// The record kind of a dnode type.
fn kind_of(t: crate::fs::zfs::types::DnodeType) -> u8 {
    use crate::fs::zfs::types::DnodeType;
    match t {
        DnodeType::Directory => KIND_DIR,
        DnodeType::PlainFile => KIND_FILE,
        _ => KIND_OTHER,
    }
}

/// `ADMIN_DIR_LIST`.
pub fn dir_list(path: &str, out: &mut Vec<u8>) -> Result<(), Failure> {
    let (entries, count, dataset) = ZfsClient::list_dir(path).map_err(|e| Message(ENOENT, e))?;
    let header = DirHeader { count: count as u64, dataset: name_field(dataset) };
    out.extend_from_slice(as_bytes(&header));
    for e in entries.iter() {
        let rec = DirRecord {
            obj: e.object_id,
            kind: if !e.is_valid { KIND_INVALID } else { kind_of(e.obj_type) },
            _pad: [0; 7],
            name: name_field(&e.name),
        };
        out.extend_from_slice(as_bytes(&rec));
    }
    Ok(())
}

/// `ADMIN_LOOKUP`.
pub fn lookup(path: &str) -> Result<LookupRecord, Failure> {
    let st = ZfsClient::file_stat(path).map_err(|e| Message(ENOENT, e))?;
    Ok(LookupRecord { obj: st.obj_id, kind: kind_of(st.obj_type) as u64, size: st.size })
}

/// `ADMIN_FILE_STAT`.
pub fn stat(path: &str) -> Result<StatRecord, Failure> {
    let st = ZfsClient::file_stat(path).map_err(|e| Message(ENOENT, e))?;
    Ok(StatRecord { obj: st.obj_id, kind: kind_of(st.obj_type) as u64, size: st.size, birth_txg: st.birth_txg, checksum: st.checksum })
}

/// `ADMIN_FS_OP`.
///
/// # Arguments
/// * `code` - `FS_*`.
/// * `input` - `path`, or `path`, a NUL and the second part.
///
/// # Returns
/// The transaction group of the change (0 when the file server does not say).
pub fn fs_op(code: u64, input: &[u8]) -> Result<u64, Failure> {
    let (path, second) = match input.iter().position(|&b| b == 0) {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => (input, &[][..]),
    };
    let path = core::str::from_utf8(path).map_err(|_| Errno(EINVAL))?;
    let text = || core::str::from_utf8(second).map_err(|_| Errno(EINVAL));
    let fail = |e: &'static str| Message(EIO, e);
    match code {
        FS_MKDIR => ZfsClient::create_dir(path).map_err(fail),
        FS_MKDIR_ALL => ZfsClient::create_dir_all(path).map_err(fail),
        FS_RMDIR => ZfsClient::remove_dir(path).map(|_| 0).map_err(fail),
        FS_UNLINK => ZfsClient::remove_file(path).map(|_| 0).map_err(fail),
        FS_COPY => ZfsClient::copy_file(path, text()?).map_err(fail),
        FS_RENAME => ZfsClient::move_entry(path, text()?).map(|_| 0).map_err(fail),
        FS_TOUCH => ZfsClient::touch_file(path).map_err(fail),
        FS_WRITE => ZfsClient::write_file_by_path(path, second).map_err(fail),
        FS_APPEND => {
            let size = ZfsClient::file_stat(path).map(|s| s.size as usize).unwrap_or(0);
            let mut all = alloc::vec![0u8; size];
            let n = if size > 0 { ZfsClient::read_file_by_path(path, &mut all).unwrap_or(0) } else { 0 };
            all.truncate(n);
            all.extend_from_slice(second);
            ZfsClient::write_file_by_path(path, &all).map_err(fail)
        }
        FS_SYNC => ZfsClient::sync().map(|_| 0).map_err(fail),
        FS_SNAPSHOT => ZfsClient::snapshot(0).map_err(fail),
        _ => Err(Errno(EINVAL)),
    }
}

/// `ADMIN_DATASET_LIST`.
pub fn datasets(out: &mut Vec<u8>) -> Result<(), Failure> {
    let pool = crate::fs::zfs::with_server(|s| Ok((s.pool_status()?, s.datasets()?)));
    let ((_, allocated, free, _, _), sets) = pool.map_err(|_| Message(EIO, "the file server did not answer"))?;
    out.extend_from_slice(as_bytes(&DatasetHeader { count: sets.len() as u64, allocated, free }));
    for (name, mount, txg, snapshot) in sets.iter() {
        let rec = DatasetRecord { txg: *txg, snapshot: *snapshot as u64, name: name_field(name), mount: name_field(mount) };
        out.extend_from_slice(as_bytes(&rec));
    }
    Ok(())
}

/// `ADMIN_ZFS_DIAG` (report: the file server prints on the console).
pub fn zfs_diag(code: u64, repair: bool, dir: &str) -> Result<(), Failure> {
    use crate::fs::zfs::fsproto::{FS_FSCK, FS_SELFTEST, FS_VERIFY};
    let (op, dir) = match code {
        ZFSDIAG_SELFTEST => (FS_SELFTEST, ""),
        ZFSDIAG_VERIFY => (FS_VERIFY, ""),
        ZFSDIAG_FSCK => (FS_FSCK, if dir.is_empty() { "/" } else { dir }),
        _ => return Err(Errno(EINVAL)),
    };
    let _ = crate::fs::zfs::with_server(|s| s.diagnostic(op, dir, repair));
    Ok(())
}

/// `ADMIN_DISK_INFO`.
pub fn disk_info() -> DiskInfo {
    match crate::fs::zfs::disk_info() {
        Some(d) => DiskInfo { present: 1, sectors: d.sectors, lba48: d.lba48 as u64, dma: d.dma as u64, model: name_field(&d.model) },
        None => DiskInfo::default(),
    }
}

/// `ADMIN_USBDISK` (report).
pub fn usbdisk(args: &[u64; 4]) -> Result<(), Failure> {
    use crate::fs::zfs::POOL_ON_USB;
    match args[0] {
        USBDISK_LIST => list(),
        USBDISK_TEST => {
            if POOL_ON_USB.load(Ordering::Acquire) {
                crate::println!("usbdisk: the running pool is on a USB disk; not writing to USB disks");
                return Ok(());
            }
            test(args[1], args[2])
        }
        USBDISK_SPEED => {
            let write = args[3] != 0;
            let (ep, disk) = if args[1] == u64::MAX { (ENDPOINT_BLOCK_DEV, 0) } else { (ENDPOINT_USB_DISK, args[1]) };
            if write && (ep == ENDPOINT_BLOCK_DEV || POOL_ON_USB.load(Ordering::Acquire)) {
                crate::println!("usbdisk: not writing to the disk of the running pool");
                return Ok(());
            }
            speed(ep, disk, args[2], write)
        }
        _ => return Err(Errno(EINVAL)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The USB disk tool (moved from the kernel shell's usbdisk command)
// ---------------------------------------------------------------------------

/// Blocks per request (the window holds 64).
const CHUNK: u64 = 64;


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
    // Three places of at least one block each (a smaller disk made `clamp` panic)
    if total < 3 {
        return crate::println!("usbdisk: disk {}: too small for the test ({} blocks)", disk, total);
    }
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

