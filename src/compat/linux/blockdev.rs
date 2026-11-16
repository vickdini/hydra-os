//! # Linux block devices: `/dev/sdX` and `/dev/sdXN`
//!
//! The disks of [`crate::fs::blockdev`] as SCSI disk devices (major 8, minor `16 * disk +
//! partition`), so partitioning and formatting tools work on them: `sfdisk`, `sgdisk`,
//! `parted`, `mkfs.vfat`, `dd`, `blkid`, `lsblk`, `wipefs`, `efibootmgr`.
//!
//! An open device file reads and writes the disk directly (no page cache: every write is
//! on its way to the disk when it returns, so `O_DIRECT` and `fsync` need nothing more
//! than the disk's cache flush). A partition's place is fixed when it is opened, as on
//! Linux.
//!
//! The ioctls these programs use: sizes and sector sizes (`BLKGETSIZE64`, `BLKGETSIZE`,
//! `BLKSSZGET`, `BLKPBSZGET`, `BLKBSZGET`, `BLKIOMIN`, `BLKIOOPT`, `BLKALIGNOFF`),
//! `BLKROGET`, `HDIO_GETGEO`, `BLKFLSBUF`, `BLKDISCARD`/`BLKZEROOUT` (zeros written),
//! `BLKRRPART` (read the partition table again) and `BLKPG` (add, delete or resize one
//! partition). After either of the last two the device files, sysfs and udev records are
//! rewritten ([`super::devices::refresh_block_tree`]).
//!
//! The disk holding the running pool is visible and readable; writes that would touch
//! the pool are refused (`EBUSY`), as is re-reading its partition table. Its other
//! partitions (the EFI system partition of an installed system) can be written.

use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

use super::chardev::{makedev, CharDevice};
use super::types::LinuxStat;
use super::vfs::{copy_in, copy_out};
use crate::fs::blockdev;
use crate::task::wait::WaitSet;

const EBADF: i64 = -9;
const ENXIO: i64 = -6;
const EINVAL: i64 = -22;
const EACCES: i64 = -13;
const ENOTTY: i64 = -25;
const EIO: i64 = -5;

/// Major number of SCSI disks.
pub const SD_MAJOR: u64 = 8;

/// Device number of partition `part` (0: the whole disk) of disk `disk`.
pub fn rdev(disk: usize, part: u32) -> u64 {
    makedev(SD_MAJOR, disk as u64 * 16 + part as u64)
}

/// An open disk or partition.
pub struct BlockFile {
    disk: usize,
    part: u32,
    /// The partition's first byte on the disk and its length (the whole disk: 0, size).
    start: u64,
    len: u64,
    pos: Mutex<u64>,
    read: bool,
    write: bool,
    nonblock: core::sync::atomic::AtomicBool,
}

/// Opens block device `rdev`; `None` if it is not one of ours.
pub fn open(rdev: u64, flags: u32) -> Option<Result<Arc<dyn CharDevice>, i64>> {
    let (major, minor) = ((rdev >> 8) & 0xFFF, (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00));
    if major != SD_MAJOR {
        return None;
    }
    let (disk, part) = ((minor / 16) as usize, (minor % 16) as u32);
    let Some(d) = blockdev::disk(disk) else { return Some(Err(ENXIO)) };
    let (start, len) = if part == 0 {
        (0, d.bytes)
    } else {
        match d.part(part) {
            Some(p) => (p.start, p.len),
            None => return Some(Err(ENXIO)),
        }
    };
    let acc = flags & 3;
    Some(Ok(Arc::new(BlockFile {
        disk,
        part,
        start,
        len,
        pos: Mutex::new(0),
        read: acc != 1,
        write: acc != 0,
        nonblock: core::sync::atomic::AtomicBool::new(flags & 0o4000 != 0),
    })))
}

/// Whether the caller has `CAP_SYS_ADMIN`.
fn admin() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1u64 << 21) != 0).unwrap_or(false)
}

impl BlockFile {
    fn put_u64(arg: u64, v: u64) -> i64 {
        copy_out(arg, &v.to_le_bytes()).map_or_else(|e| e, |_| 0)
    }

    fn put_u32(arg: u64, v: u32) -> i64 {
        copy_out(arg, &v.to_le_bytes()).map_or_else(|e| e, |_| 0)
    }

    /// Rewrites the device files after the partition list changed.
    fn changed(&self) {
        super::devices::refresh_block_tree();
    }

    /// The `[start, len]` pair of `BLKDISCARD`/`BLKZEROOUT`, as bytes of this device,
    /// written as zeros.
    fn zero(&self, arg: u64) -> i64 {
        if !self.write {
            return EBADF;
        }
        let Ok(raw) = copy_in(arg, 16) else { return -14 };
        let off = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        if off % 512 != 0 || len % 512 != 0 || off.checked_add(len).map_or(true, |e| e > self.len) {
            return EINVAL;
        }
        match blockdev::zero_range(self.disk, self.start + off, len) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    /// `BLKPG`: `struct blkpg_ioctl_arg { int op, flags, datalen; void *data; }` with
    /// `struct blkpg_partition { long long start, length; int pno; char devname[64],
    /// volname[64]; }`.
    fn blkpg(&self, arg: u64) -> i64 {
        if !admin() {
            return EACCES;
        }
        if self.part != 0 {
            return EINVAL;
        }
        let Ok(a) = copy_in(arg, 24) else { return -14 };
        let op = u32::from_le_bytes(a[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(a[16..24].try_into().unwrap());
        let Ok(p) = copy_in(data, 20) else { return -14 };
        let start = i64::from_le_bytes(p[0..8].try_into().unwrap());
        let len = i64::from_le_bytes(p[8..16].try_into().unwrap());
        let pno = i32::from_le_bytes(p[16..20].try_into().unwrap());
        if start < 0 || len < 0 || pno <= 0 {
            return EINVAL;
        }
        match blockdev::blkpg(self.disk, op, pno as u32, start as u64, len as u64) {
            Ok(()) => {
                self.changed();
                0
            }
            Err(e) => e,
        }
    }
}

impl CharDevice for BlockFile {
    fn read(&self, buf: &mut [u8]) -> i64 {
        let at = *self.pos.lock();
        let r = self.pread(buf, at).unwrap_or(EIO);
        if r > 0 {
            *self.pos.lock() = at + r as u64;
        }
        r
    }

    fn write(&self, data: &[u8]) -> i64 {
        let at = *self.pos.lock();
        let r = self.pwrite(data, at).unwrap_or(EIO);
        if r > 0 {
            *self.pos.lock() = at + r as u64;
        }
        r
    }

    fn pread(&self, buf: &mut [u8], offset: u64) -> Option<i64> {
        if !self.read {
            return Some(EBADF);
        }
        if offset >= self.len || buf.is_empty() {
            return Some(0);
        }
        let n = (buf.len() as u64).min(self.len - offset) as usize;
        Some(match blockdev::read_at(self.disk, self.start + offset, &mut buf[..n]) {
            Ok(n) => n as i64,
            Err(e) => e,
        })
    }

    fn pwrite(&self, data: &[u8], offset: u64) -> Option<i64> {
        if !self.write {
            return Some(EBADF);
        }
        if data.is_empty() {
            return Some(0);
        }
        if offset >= self.len {
            return Some(-28); // ENOSPC
        }
        let n = (data.len() as u64).min(self.len - offset) as usize;
        Some(match blockdev::write_at(self.disk, self.start + offset, &data[..n]) {
            Ok(n) => n as i64,
            Err(e) => e,
        })
    }

    fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
        let mut pos = self.pos.lock();
        let base = match whence {
            0 => 0i64,
            1 => *pos as i64,
            2 => self.len as i64,
            // SEEK_DATA / SEEK_HOLE: all data
            3 => {
                return Some(if offset < 0 || offset as u64 >= self.len { ENXIO } else {
                    *pos = offset as u64;
                    offset
                });
            }
            4 => {
                return Some(if offset < 0 || offset as u64 >= self.len { ENXIO } else {
                    *pos = self.len;
                    self.len as i64
                });
            }
            _ => return Some(EINVAL),
        };
        let new = base + offset;
        if new < 0 {
            return Some(EINVAL);
        }
        *pos = new as u64;
        Some(new)
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        let ssz = blockdev::disk(self.disk).map_or(512, |d| d.sector_size);
        match cmd {
            // BLKGETSIZE64
            0x8008_1272 => Self::put_u64(arg, self.len),
            // BLKGETSIZE: 512-byte sectors (unsigned long)
            0x1260 => Self::put_u64(arg, self.len / 512),
            // BLKSSZGET (int), BLKPBSZGET, BLKIOMIN (unsigned int)
            0x1268 => Self::put_u32(arg, ssz),
            0x127B | 0x1278 => Self::put_u32(arg, ssz.max(4096)),
            // BLKBSZGET (int; the size_t-numbered request)
            0x8008_1270 => Self::put_u32(arg, 4096),
            // BLKIOOPT, BLKALIGNOFF
            0x1279 | 0x127A => Self::put_u32(arg, 0),
            // BLKROGET
            0x125E => Self::put_u32(arg, 0),
            // BLKROSET: accepted, nothing changes
            0x125D => 0,
            // BLKDISCARDZEROES (unsigned int), BLKROTATIONAL (unsigned short)
            0x127C => Self::put_u32(arg, 0),
            0x127E => copy_out(arg, &0u16.to_le_bytes()).map_or_else(|e| e, |_| 0),
            // BLKGETDISKSEQ (u64)
            0x8008_1280 => Self::put_u64(arg, self.disk as u64 + 1),
            // BLKRASET/BLKFRASET: accepted; BLKRAGET/BLKFRAGET: 256 sectors
            0x1262 | 0x1264 => 0,
            0x1263 | 0x1265 => Self::put_u64(arg, 256),
            // BLKFLSBUF: no buffers of our own; the disk's cache is flushed
            0x1261 => blockdev::flush(self.disk).map_or_else(|e| e, |_| 0),
            // BLKRRPART
            0x125F => {
                if self.part != 0 {
                    return EINVAL;
                }
                if !admin() {
                    return EACCES;
                }
                match blockdev::reread(self.disk) {
                    Ok(()) => {
                        self.changed();
                        0
                    }
                    Err(e) => e,
                }
            }
            // BLKPG
            0x1269 => self.blkpg(arg),
            // BLKDISCARD, BLKSECDISCARD, BLKZEROOUT
            0x1277 | 0x127D | 0x127F => self.zero(arg),
            // HDIO_GETGEO: struct hd_geometry { u8 heads, sectors; u16 cylinders; unsigned long start; }
            0x0301 => {
                let sectors = self.len / 512;
                let cyl = (sectors / (255 * 63)).min(0xFFFF) as u16;
                let mut g = [0u8; 16];
                g[0] = 255;
                g[1] = 63;
                g[2..4].copy_from_slice(&cyl.to_le_bytes());
                g[8..16].copy_from_slice(&(self.start / 512).to_le_bytes());
                copy_out(arg, &g).map_or_else(|e| e, |_| 0)
            }
            // BLKGETZONESZ, BLKGETNRZONES: not zoned
            0x8004_1284 | 0x8004_1285 => Self::put_u32(arg, 0),
            _ => ENOTTY,
        }
    }

    fn poll_events(&self) -> u32 {
        0x5
    }

    fn add_wait_queues(&self, _waits: &mut WaitSet) {}

    fn rdev(&self) -> u64 {
        rdev(self.disk, self.part)
    }

    fn path(&self) -> String {
        let name = blockdev::disk(self.disk).map_or_else(|| String::from("sd?"), |d| d.name);
        if self.part == 0 {
            alloc::format!("/dev/{}", name)
        } else {
            alloc::format!("/dev/{}{}", name, self.part)
        }
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, core::sync::atomic::Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn fsync(&self) -> Option<i64> {
        Some(blockdev::flush(self.disk).map_or_else(|e| e, |_| 0))
    }

    fn stat(&self) -> LinuxStat {
        let mut st = LinuxStat::default();
        st.st_dev = 6; // devtmpfs
        st.st_ino = self.rdev() | 0x2_0000_0000;
        st.st_mode = 0o060660;
        st.st_nlink = 1;
        st.st_gid = 6; // disk
        st.st_rdev = self.rdev();
        st.st_blksize = 4096;
        st
    }
}
