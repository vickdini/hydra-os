//! # The disks behind one block driver
//!
//! A block driver (`ahci-driver`, `ata-driver`, a USB storage driver) may find several
//! disks. The block protocol (the kernel's `ipc/protocol.rs`, `MSG_BLOCK_*`) addresses
//! them with a unit number in `args[3]`:
//!
//! - unit 0, the **pool view**: the blocks of the Hydra pool, numbered from 0 (a whole
//!   disk, or the Hydra pool partition of a GPT disk). The ZFS file server uses only it.
//! - unit `1 + i`: disk `i` whole, for the kernel's Linux block devices (`/dev/sdX`).
//!   Writes that would touch the pool view's blocks are refused (`EBUSY`).
//!
//! Which disk holds the pool ([`Units::choose`]): with `boot_part=<GUID>` (the unique GUID
//! of the GPT partition the kernel was loaded from, which the kernel passes when it booted
//! from a disk) the Hydra pool partition of the disk that has that partition, or no pool
//! view at all when none of this driver's disks has it (another driver's disk does).
//! Without it: the first disk; its Hydra pool partition if it has a GPT with one,
//! otherwise all of it (the pool written straight to the disk, as the ISO-booted setups
//! have it).

use alloc::vec::Vec;

#[path = "../../../../src/fs/gpt.rs"]
pub mod gpt;

const BLOCK: usize = 4096;
const EBUSY: i64 = -16;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;

/// What a driver offers about its disks.
pub trait DiskSet {
    /// Number of disks.
    fn count(&self) -> usize;
    /// Size of disk `disk` in 4 KiB blocks.
    fn blocks(&self, disk: usize) -> u64;
    /// Reads whole 4 KiB blocks of disk `disk` from `block` into `buf`.
    fn read(&mut self, disk: usize, block: u64, buf: &mut [u8]) -> Result<(), &'static str>;
}

/// Where the pool's blocks are.
#[derive(Clone, Copy, Debug)]
pub struct PoolView {
    /// Disk index.
    pub disk: usize,
    /// First block on that disk.
    pub base: u64,
    /// Length in blocks.
    pub blocks: u64,
}

/// The units of one driver.
pub struct Units {
    /// The pool view, if this driver's disks hold the pool.
    pub pool: Option<PoolView>,
}

/// Value of a `key=<text>` argument.
fn text_arg<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))
}

/// Reads the partition table of disk `d`.
pub fn table(set: &mut dyn DiskSet, d: usize) -> Option<gpt::Table> {
    let bytes = set.blocks(d) * BLOCK as u64;
    let mut read = |off: u64, buf: &mut [u8]| -> bool {
        let first = off / BLOCK as u64;
        let last = (off + buf.len() as u64).div_ceil(BLOCK as u64);
        let mut tmp: Vec<u8> = alloc::vec![0u8; ((last - first) as usize) * BLOCK];
        if set.read(d, first, &mut tmp).is_err() {
            return false;
        }
        let at = (off - first * BLOCK as u64) as usize;
        buf.copy_from_slice(&tmp[at..at + buf.len()]);
        true
    };
    gpt::read_table(&mut read, bytes)
}

/// The pool view a Hydra pool partition gives (whole blocks inside it).
fn view_of(d: usize, p: &gpt::Part) -> PoolView {
    let base = p.start.div_ceil(BLOCK as u64);
    let end = (p.start + p.len) / BLOCK as u64;
    PoolView { disk: d, base, blocks: end.saturating_sub(base) }
}

impl Units {
    /// Decides where the pool is (see the module documentation). `name` prefixes the
    /// messages.
    pub fn choose(args: &[&str], set: &mut dyn DiskSet, name: &str) -> Self {
        if set.count() == 0 {
            return Self { pool: None };
        }
        if let Some(text) = text_arg(args, "boot_part") {
            let Some(want) = gpt::parse_guid(text) else {
                crate::println!("[{}] boot_part={}: not a GUID", name, text);
                return Self { pool: None };
            };
            for d in 0..set.count() {
                let Some(t) = table(set, d) else { continue };
                if t.by_guid(&want).is_none() {
                    continue;
                }
                return match t.by_type(&gpt::HYDRA_POOL_TYPE) {
                    Some(p) => {
                        let v = view_of(d, p);
                        crate::println!("[{}] the pool: partition {} of disk {} (blocks {}..{}), the boot disk", name, p.number, d, v.base, v.base + v.blocks);
                        Self { pool: Some(v) }
                    }
                    None => {
                        crate::println!("[{}] the boot disk (disk {}) has no Hydra pool partition", name, d);
                        Self { pool: None }
                    }
                };
            }
            crate::println!("[{}] the boot disk is not one of this driver's disks", name);
            return Self { pool: None };
        }
        if let Some(t) = table(set, 0) {
            if let Some(p) = t.by_type(&gpt::HYDRA_POOL_TYPE) {
                let v = view_of(0, p);
                crate::println!("[{}] the pool: partition {} of disk 0 (blocks {}..{})", name, p.number, v.base, v.base + v.blocks);
                return Self { pool: Some(v) };
            }
        }
        Self { pool: Some(PoolView { disk: 0, base: 0, blocks: set.blocks(0) }) }
    }

    /// Disk and absolute block of a request on `unit` for `count` blocks at `block`, or
    /// the error to answer.
    pub fn map(&self, unit: u64, block: u64, count: u64, write: bool, set: &dyn DiskSet) -> Result<(usize, u64), i64> {
        if unit == 0 {
            let v = self.pool.ok_or(ENODEV)?;
            if count == 0 || block.checked_add(count).map_or(true, |e| e > v.blocks) {
                return Err(EINVAL);
            }
            return Ok((v.disk, v.base + block));
        }
        let d = (unit - 1) as usize;
        if d >= set.count() {
            return Err(ENODEV);
        }
        if count == 0 || block.checked_add(count).map_or(true, |e| e > set.blocks(d)) {
            return Err(EINVAL);
        }
        if write {
            if let Some(v) = self.pool {
                if v.disk == d && block < v.base + v.blocks && block + count > v.base {
                    return Err(EBUSY);
                }
            }
        }
        Ok((d, block))
    }

    /// The disk behind `unit` (for `MSG_BLOCK_GET_SIZE`, `MSG_BLOCK_FLUSH`).
    pub fn disk_of(&self, unit: u64, set: &dyn DiskSet) -> Result<usize, i64> {
        if unit == 0 {
            return self.pool.map(|v| v.disk).ok_or(ENODEV);
        }
        let d = (unit - 1) as usize;
        if d < set.count() { Ok(d) } else { Err(ENODEV) }
    }

    /// Size in blocks of `unit`.
    pub fn blocks_of(&self, unit: u64, set: &dyn DiskSet) -> u64 {
        match (unit, self.pool) {
            (0, Some(v)) => v.blocks,
            (0, None) => 0,
            (u, _) => set.blocks((u - 1) as usize),
        }
    }

    /// Fills the window's description of `unit` after its model (bytes 0..40, written
    /// by the driver): logical sector size at 40, flags at 44 (bit 0 removable, bit 1 the
    /// disk holds the pool view), the pool view's first block and length at 48 and 56.
    pub fn describe(&self, unit: u64, window: &mut [u8], sector_size: u32, removable: bool) {
        let d = if unit == 0 { self.pool.map(|v| v.disk) } else { Some((unit - 1) as usize) };
        let holds = matches!((self.pool, d), (Some(v), Some(d)) if v.disk == d);
        window[40..44].copy_from_slice(&sector_size.to_le_bytes());
        let flags = removable as u32 | (holds as u32) << 1;
        window[44..48].copy_from_slice(&flags.to_le_bytes());
        let (b, n) = self.pool.filter(|_| holds).map_or((0, 0), |v| (v.base, v.blocks));
        window[48..56].copy_from_slice(&b.to_le_bytes());
        window[56..64].copy_from_slice(&n.to_le_bytes());
    }
}
