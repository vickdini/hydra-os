//! # Disks as the kernel sees them, below the pool
//!
//! Every disk the block drivers found, the pool's included: what the Linux block devices
//! (`/dev/sdX`, [`crate::compat::linux::blockdev`]) read and write. A block driver serves
//! several disks on its endpoint, addressed by unit (`args[3]`, see `hydra_rt::blockunits`
//! and `ipc/protocol.rs`): unit 0 is the pool view the ZFS file server uses, unit `1 + i`
//! the driver's disk `i` whole. This module uses only the whole-disk units.
//!
//! The ZFS file server calls the same driver through the same window without taking the
//! kernel's window lock, but only while it serves a request, and every request comes
//! from a kernel task that holds the file server's window. So a call here first takes the
//! file server's window, then the driver's: the two never overlap.
//!
//! Disk I/O is in bytes; the drivers move 4 KiB blocks, so partial blocks are read,
//! changed and written back. Nothing is cached: a write is on its way to the disk when
//! the call returns ([`flush`] empties the disk's own write cache).

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use super::gpt;
use crate::ipc::protocol::{ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_READ, MSG_BLOCK_REPLY, MSG_BLOCK_WRITE};
use crate::ipc::service;
use crate::ipc::Message;

/// Block size of the driver protocol.
pub const BLOCK: u64 = 4096;

const EIO: i64 = -5;
const EBUSY: i64 = -16;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;

/// The block driver endpoints, in the order their disks are named (`sda`, `sdb`, ...).
/// A new block driver (USB storage) adds its endpoint here.
pub const ENDPOINTS: &[u32] = &[ENDPOINT_BLOCK_DEV, crate::ipc::protocol::ENDPOINT_USB_DISK];

/// Longest a disk request may take (60 s, as the ZFS file server allows).
const DISK_TIMEOUT_TICKS: u64 = 6000;

/// One partition, as the kernel currently knows it (read from the table, or changed by
/// `BLKPG`).
#[derive(Clone, Debug)]
pub struct Partition {
    /// Partition number (1-based).
    pub number: u32,
    /// First byte on the disk.
    pub start: u64,
    /// Length in bytes.
    pub len: u64,
    /// What the partition table says about it (`None` for one added by `BLKPG` that the
    /// table does not have).
    pub entry: Option<gpt::Part>,
}

/// A disk.
#[derive(Clone, Debug)]
pub struct Disk {
    /// Linux name (`sda`).
    pub name: String,
    /// Driver endpoint.
    pub endpoint: u32,
    /// Whole-disk unit on that endpoint (`1 + i`).
    pub unit: u64,
    /// Size in bytes.
    pub bytes: u64,
    /// Logical sector size.
    pub sector_size: u32,
    /// Drive model.
    pub model: String,
    /// Removable media (USB sticks).
    pub removable: bool,
    /// The pool's bytes on this disk (`start..end`), if the pool is on it.
    pub pool: Option<(u64, u64)>,
    /// The partition table kind and disk GUID, if the disk has a table.
    pub table: Option<(gpt::Kind, gpt::Guid)>,
    /// The partitions.
    pub parts: Vec<Partition>,
    /// Changes of the partition list (Linux `diskseq`-like; device files compare it).
    pub generation: u64,
}

impl Disk {
    /// Whether the byte range `start..end` overlaps the pool.
    pub fn touches_pool(&self, start: u64, end: u64) -> bool {
        self.pool.map_or(false, |(a, b)| start < b && end > a)
    }

    /// The partition numbered `n`.
    pub fn part(&self, n: u32) -> Option<&Partition> {
        self.parts.iter().find(|p| p.number == n)
    }
}

/// The disks, in name order.
static DISKS: Mutex<Vec<Disk>> = Mutex::new(Vec::new());

/// A copy of the disk list.
pub fn disks() -> Vec<Disk> {
    DISKS.lock().clone()
}

/// A copy of disk `idx`.
pub fn disk(idx: usize) -> Option<Disk> {
    DISKS.lock().get(idx).cloned()
}

/// Linux name of the `n`th disk: `sda`..`sdz`, `sdaa`...
fn disk_name(n: usize) -> String {
    let mut s = String::from("sd");
    if n >= 26 {
        s.push((b'a' + (n / 26 - 1) as u8) as char);
    }
    s.push((b'a' + (n % 26) as u8) as char);
    s
}

/// Calls block driver `endpoint` with the file server's window and its own held; `with`
/// fills the window before the call, `after` reads it afterwards.
fn call<R>(endpoint: u32, label: u32, args: [u64; 4], with: impl FnOnce(&mut [u8]), after: impl FnOnce(&Message, &[u8]) -> R) -> Result<R, i64> {
    if !service::is_online(endpoint) {
        return Err(ENODEV);
    }
    let _zfs = service::hold_window(ENDPOINT_ZFS_SERVER);
    let _own = service::hold_window(endpoint);
    let window = service::window(endpoint).ok_or(ENODEV)?;
    with(window);
    let r = service::call(endpoint, Message::with_args(label, args), DISK_TIMEOUT_TICKS)?;
    if r.label != MSG_BLOCK_REPLY {
        return Err(EIO);
    }
    if (r.args[0] as i64) < 0 {
        return Err(r.args[0] as i64);
    }
    let window = service::window(endpoint).ok_or(ENODEV)?;
    Ok(after(&r, window))
}

/// Reads whole blocks of a disk from `block` into `buf` (a multiple of [`BLOCK`] long).
fn read_blocks(endpoint: u32, unit: u64, block: u64, buf: &mut [u8]) -> Result<(), i64> {
    let max = service::WINDOW_SIZE;
    for (i, chunk) in buf.chunks_mut(max).enumerate() {
        let at = block + (i * max) as u64 / BLOCK;
        let n = chunk.len() as u64 / BLOCK;
        call(endpoint, MSG_BLOCK_READ, [at, n, 0, unit], |_| {}, |_, w| chunk.copy_from_slice(&w[..chunk.len()]))?;
    }
    Ok(())
}

/// Writes whole blocks of a disk from `data` at `block`.
fn write_blocks(endpoint: u32, unit: u64, block: u64, data: &[u8]) -> Result<(), i64> {
    let max = service::WINDOW_SIZE;
    for (i, chunk) in data.chunks(max).enumerate() {
        let at = block + (i * max) as u64 / BLOCK;
        let n = chunk.len() as u64 / BLOCK;
        call(endpoint, MSG_BLOCK_WRITE, [at, n, 0, unit], |w| w[..chunk.len()].copy_from_slice(chunk), |_, _| ())?;
    }
    Ok(())
}

/// Endpoint, unit and size of disk `idx`.
fn target(idx: usize) -> Result<(u32, u64, u64), i64> {
    let d = DISKS.lock();
    let d = d.get(idx).ok_or(ENODEV)?;
    Ok((d.endpoint, d.unit, d.bytes))
}

/// Reads `buf.len()` bytes of disk `idx` at byte `offset` (any alignment); returns the
/// bytes read (fewer at the end of the disk).
pub fn read_at(idx: usize, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let (ep, unit, bytes) = target(idx)?;
    if offset >= bytes {
        return Ok(0);
    }
    let len = (buf.len() as u64).min(bytes - offset) as usize;
    let mut done = 0usize;
    while done < len {
        let pos = offset + done as u64;
        let first = pos / BLOCK;
        let skip = (pos % BLOCK) as usize;
        // Aligned middle part straight into the caller's buffer, a window at a time
        if skip == 0 && len - done >= BLOCK as usize {
            let n = ((len - done) / BLOCK as usize * BLOCK as usize).min(service::WINDOW_SIZE);
            read_blocks(ep, unit, first, &mut buf[done..done + n])?;
            done += n;
            continue;
        }
        let mut tmp = [0u8; BLOCK as usize];
        read_blocks(ep, unit, first, &mut tmp)?;
        let n = (BLOCK as usize - skip).min(len - done);
        buf[done..done + n].copy_from_slice(&tmp[skip..skip + n]);
        done += n;
    }
    Ok(done)
}

/// Writes `data` to disk `idx` at byte `offset` (any alignment; partial blocks are read
/// first). Writes touching the pool are refused (`EBUSY`).
pub fn write_at(idx: usize, offset: u64, data: &[u8]) -> Result<usize, i64> {
    let (ep, unit, bytes) = target(idx)?;
    if offset >= bytes {
        return if data.is_empty() { Ok(0) } else { Err(ENOSPC) };
    }
    let len = (data.len() as u64).min(bytes - offset) as usize;
    if disk(idx).map_or(false, |d| d.touches_pool(offset, offset + len as u64)) {
        return Err(EBUSY);
    }
    let mut done = 0usize;
    while done < len {
        let pos = offset + done as u64;
        let first = pos / BLOCK;
        let skip = (pos % BLOCK) as usize;
        if skip == 0 && len - done >= BLOCK as usize {
            let n = ((len - done) / BLOCK as usize * BLOCK as usize).min(service::WINDOW_SIZE);
            write_blocks(ep, unit, first, &data[done..done + n])?;
            done += n;
            continue;
        }
        let mut tmp = [0u8; BLOCK as usize];
        read_blocks(ep, unit, first, &mut tmp)?;
        let n = (BLOCK as usize - skip).min(len - done);
        tmp[skip..skip + n].copy_from_slice(&data[done..done + n]);
        write_blocks(ep, unit, first, &tmp)?;
        done += n;
    }
    Ok(done)
}

/// Writes zeros over `len` bytes at `offset` (`BLKZEROOUT`, `BLKDISCARD`).
pub fn zero_range(idx: usize, offset: u64, len: u64) -> Result<(), i64> {
    let chunk = alloc::vec![0u8; service::WINDOW_SIZE];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        write_at(idx, offset + done, &chunk[..n])?;
        done += n as u64;
    }
    Ok(())
}

/// Empties the write cache of disk `idx`.
pub fn flush(idx: usize) -> Result<(), i64> {
    let (ep, unit, _) = target(idx)?;
    call(ep, MSG_BLOCK_FLUSH, [0, 0, 0, unit], |_| {}, |_, _| ())
}

/// Empties the write cache of every disk but the pool's (the file server flushes that
/// one at its commits).
pub fn flush_all() {
    let n = DISKS.lock().len();
    for i in 0..n {
        if disk(i).map_or(false, |d| d.pool.is_none()) {
            let _ = flush(i);
        }
    }
}

/// Reads the partition table of disk `idx`.
fn read_table(idx: usize, bytes: u64) -> Option<gpt::Table> {
    let mut read = |off: u64, buf: &mut [u8]| read_at(idx, off, buf).map_or(false, |n| n == buf.len());
    gpt::read_table(&mut read, bytes)
}

/// The partitions of a table.
fn partitions(t: &Option<gpt::Table>) -> Vec<Partition> {
    t.as_ref().map_or_else(Vec::new, |t| {
        t.parts.iter().filter(|p| p.number <= 15).map(|p| Partition { number: p.number, start: p.start, len: p.len, entry: Some(p.clone()) }).collect()
    })
}

/// Finds the disks of every block driver (at boot, once the file server runs).
pub fn scan() {
    let mut found: Vec<Disk> = Vec::new();
    for &ep in ENDPOINTS {
        for unit in 1..=32u64 {
            let info = call(ep, MSG_BLOCK_GET_SIZE, [0, 0, 0, unit], |_| {}, |r, w| {
                let model = core::str::from_utf8(&w[..40]).unwrap_or("").trim_end_matches(|c: char| c == ' ' || c == '\0');
                let sector = u32::from_le_bytes(w[40..44].try_into().unwrap());
                let flags = u32::from_le_bytes(w[44..48].try_into().unwrap());
                let pool_base = u64::from_le_bytes(w[48..56].try_into().unwrap());
                let pool_blocks = u64::from_le_bytes(w[56..64].try_into().unwrap());
                (r.args[1], String::from(model.trim()), sector, flags, pool_base, pool_blocks)
            });
            // USB disk numbers can have gaps (a stick unplugged): look at all of them
            let Ok((blocks, model, sector, flags, pool_base, pool_blocks)) = info else {
                if ep == crate::ipc::protocol::ENDPOINT_USB_DISK && unit < 8 {
                    continue;
                }
                break;
            };
            let pool = (flags & 2 != 0).then_some((pool_base * BLOCK, (pool_base + pool_blocks) * BLOCK));
            found.push(Disk {
                name: disk_name(found.len()),
                endpoint: ep,
                unit,
                bytes: blocks * BLOCK,
                sector_size: if sector == 0 { 512 } else { sector },
                model,
                removable: flags & 1 != 0,
                pool,
                table: None,
                parts: Vec::new(),
                generation: 1,
            });
        }
    }
    *DISKS.lock() = found.clone();
    for (i, d) in found.iter().enumerate() {
        let t = read_table(i, d.bytes);
        let mut all = DISKS.lock();
        all[i].table = t.as_ref().map(|t| (t.kind, t.disk_guid));
        all[i].parts = partitions(&t);
        crate::kprintln!(
            "[disks] {}: '{}' {} MiB on endpoint {:#x} unit {}, {} partitions{}",
            d.name,
            d.model,
            d.bytes >> 20,
            d.endpoint,
            d.unit,
            all[i].parts.len(),
            match d.pool {
                Some((a, b)) => alloc::format!(", the pool at {}..{} MiB", a >> 20, b >> 20),
                None => String::new(),
            }
        );
    }
}

/// Reads disk `idx`'s partition table again (`BLKRRPART`). A disk holding the pool is
/// busy (as Linux answers for a disk with a partition in use).
pub fn reread(idx: usize) -> Result<(), i64> {
    let d = disk(idx).ok_or(ENODEV)?;
    if d.pool.is_some() {
        return Err(EBUSY);
    }
    let t = read_table(idx, d.bytes);
    let mut all = DISKS.lock();
    let d = all.get_mut(idx).ok_or(ENODEV)?;
    d.table = t.as_ref().map(|t| (t.kind, t.disk_guid));
    d.parts = partitions(&t);
    d.generation += 1;
    Ok(())
}

/// `BLKPG` add (`op` 1), delete (2) or resize (3) of partition `number` of disk `idx`
/// (bytes `start`, `len`).
pub fn blkpg(idx: usize, op: u32, number: u32, start: u64, len: u64) -> Result<(), i64> {
    let mut all = DISKS.lock();
    let d = all.get_mut(idx).ok_or(ENODEV)?;
    if number == 0 || number > 15 {
        return Err(EINVAL);
    }
    let pos = d.parts.iter().position(|p| p.number == number);
    if let Some(p) = pos {
        if d.pool.map_or(false, |(a, b)| d.parts[p].start < b && d.parts[p].start + d.parts[p].len > a) {
            return Err(EBUSY);
        }
    }
    match op {
        1 => {
            if pos.is_some() {
                return Err(-16);
            }
            if start % 512 != 0 || len == 0 || start + len > d.bytes || d.parts.iter().any(|p| start < p.start + p.len && start + len > p.start) {
                return Err(EINVAL);
            }
            d.parts.push(Partition { number, start, len, entry: None });
            d.parts.sort_by_key(|p| p.number);
        }
        2 => {
            let p = pos.ok_or(-6)?; // ENXIO
            d.parts.remove(p);
        }
        3 => {
            let p = pos.ok_or(-6)?;
            if d.parts[p].start != start || start + len > d.bytes {
                return Err(EINVAL);
            }
            d.parts[p].len = len;
        }
        _ => return Err(EINVAL),
    }
    d.generation += 1;
    Ok(())
}
