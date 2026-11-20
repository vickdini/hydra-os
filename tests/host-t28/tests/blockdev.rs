//! `blockdev.rs`: `/dev/sdX` and `/dev/sdXN` as device files over the fake disks
//! (`fake::DISKS`): open, read/write/seek at the partition's place, the block ioctls,
//! permissions, and the device tree rewritten after partition changes.

mod common;

use hydra_hosttests_t28::compat::linux::blockdev::{self, rdev, SD_MAJOR};
use hydra_hosttests_t28::compat::linux::chardev::{makedev, CharDevice};
use hydra_hosttests_t28::fake::{self, Partition};
use std::sync::Arc;

const EBADF: i64 = -9;
const ENXIO: i64 = -6;
const EINVAL: i64 = -22;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const ENOTTY: i64 = -25;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const MIB: u64 = 1 << 20;

/// A 4 MiB disk `sda` whose partition 1 is at 1 MiB, 2 MiB long.
fn disk() -> usize {
    let i = fake::add_disk("sda", 4 * MIB);
    fake::with_disk(i, |d| {
        d.disk.parts.push(Partition { number: 1, start: MIB, len: 2 * MIB, entry: None });
        d.disk.model = "QEMU HARDDISK".into();
    });
    i
}

fn open(disk: usize, part: u32, flags: u32) -> Arc<dyn CharDevice> {
    blockdev::open(rdev(disk, part), flags).expect("ours").expect("opens")
}

fn p<T>(v: &mut [T]) -> u64 {
    v.as_mut_ptr() as u64
}

#[test]
fn device_numbers() {
    assert_eq!(rdev(0, 0), makedev(SD_MAJOR, 0));
    assert_eq!(rdev(1, 2), makedev(8, 18));
    assert_eq!(rdev(16, 1), makedev(8, 257));
}

#[test]
fn open_finds_disks_and_partitions() {
    let d = disk();
    // Another major: not ours
    assert!(blockdev::open(makedev(9, 0), 0).is_none());
    // No such disk or partition
    assert_eq!(blockdev::open(rdev(5, 0), 0).unwrap().err(), Some(ENXIO));
    assert_eq!(blockdev::open(rdev(d, 2), 0).unwrap().err(), Some(ENXIO));
    let whole = open(d, 0, 0o4000);
    assert!(whole.nonblock());
    whole.set_nonblock(false);
    assert!(!whole.nonblock());
    assert_eq!(whole.path(), "/dev/sda");
    assert_eq!(open(d, 1, 0).path(), "/dev/sda1");
    assert_eq!(whole.rdev(), makedev(8, 0));
    assert_eq!(whole.poll_events(), 0x5);
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    whole.add_wait_queues(&mut ws);
    assert!(ws.queues.is_empty());
    let st = open(d, 1, 0).stat();
    assert_eq!(st.st_mode, 0o060660);
    assert_eq!(st.st_rdev, makedev(8, 1));
    assert_eq!(st.st_ino, makedev(8, 1) | 0x2_0000_0000);
    assert_eq!((st.st_dev, st.st_gid, st.st_nlink, st.st_blksize), (6, 6, 1, 4096));
}

#[test]
fn partition_reads_and_writes_are_offset() {
    let d = disk();
    fake::with_disk(d, |fd| {
        fd.data[MIB as usize..MIB as usize + 4].copy_from_slice(b"PART");
        fd.data[0..4].copy_from_slice(b"DISK");
    });
    let part = open(d, 1, 2); // O_RDWR
    let mut b = [0u8; 4];
    assert_eq!(part.read(&mut b), 4);
    assert_eq!(&b, b"PART");
    // The position moved: the next read continues
    assert_eq!(part.read(&mut b), 4);
    assert_eq!(b, [0; 4]);
    assert_eq!(part.seek(0, 0), Some(0));
    assert_eq!(part.write(b"new!"), 4);
    assert_eq!(fake::with_disk(d, |fd| fd.data[MIB as usize..MIB as usize + 4].to_vec()), b"new!");
    // pread past the end: 0; empty buffers: 0
    assert_eq!(part.pread(&mut b, 2 * MIB), Some(0));
    assert_eq!(part.pread(&mut [], 0), Some(0));
    // A read at the end is cut short
    let mut big = vec![0u8; 8192];
    assert_eq!(part.pread(&mut big, 2 * MIB - 100), Some(100));
    // Writes past the end: ENOSPC; at the end cut short; empty: 0
    assert_eq!(part.pwrite(b"x", 2 * MIB), Some(-28));
    assert_eq!(part.pwrite(&big, 2 * MIB - 10), Some(10));
    assert_eq!(part.pwrite(&[], 0), Some(0));
    // The whole disk sees the start
    let whole = open(d, 0, 0);
    assert_eq!(whole.pread(&mut b, 0), Some(4));
    assert_eq!(&b, b"DISK");
}

#[test]
fn access_modes_are_enforced() {
    let d = disk();
    let ro = open(d, 0, 0); // O_RDONLY
    assert_eq!(ro.write(b"x"), EBADF);
    assert_eq!(ro.pwrite(b"x", 0), Some(EBADF));
    let wo = open(d, 0, 1); // O_WRONLY
    let mut b = [0u8; 1];
    assert_eq!(wo.read(&mut b), EBADF);
    assert_eq!(wo.pread(&mut b, 0), Some(EBADF));
    // BLKDISCARD needs write access
    let mut range = [0u64, 512];
    assert_eq!(ro.ioctl(0x1277, p(&mut range)), EBADF);
}

#[test]
fn disk_errors_pass_through() {
    let d = disk();
    let f = open(d, 0, 2);
    fake::with_disk(d, |fd| fd.fail = Some(-5));
    let mut b = [0u8; 4];
    assert_eq!(f.read(&mut b), -5);
    assert_eq!(f.write(b"abcd"), -5);
    assert_eq!(f.fsync(), Some(-5));
    assert_eq!(f.ioctl(0x1261, 0), -5);
    let mut range = [0u64, 512];
    assert_eq!(f.ioctl(0x127F, p(&mut range)), -5);
    // Position unchanged by failures
    assert_eq!(f.seek(0, 1), Some(0));
}

#[test]
fn seek_whences() {
    let d = disk();
    let f = open(d, 1, 0);
    assert_eq!(f.seek(100, 0), Some(100));
    assert_eq!(f.seek(50, 1), Some(150));
    assert_eq!(f.seek(-10, 2), Some((2 * MIB - 10) as i64));
    assert_eq!(f.seek(-1, 0), Some(EINVAL));
    assert_eq!(f.seek(0, 9), Some(EINVAL));
    // SEEK_DATA: all data; SEEK_HOLE: the end
    assert_eq!(f.seek(4096, 3), Some(4096));
    assert_eq!(f.seek(-1, 3), Some(ENXIO));
    assert_eq!(f.seek(2 * MIB as i64, 3), Some(ENXIO));
    assert_eq!(f.seek(4096, 4), Some(2 * MIB as i64));
    assert_eq!(f.seek(0, 1), Some(2 * MIB as i64));
    assert_eq!(f.seek(-5, 4), Some(ENXIO));
    assert_eq!(f.seek(2 * MIB as i64, 4), Some(ENXIO));
}

#[test]
fn size_and_geometry_ioctls() {
    let d = disk();
    fake::with_disk(d, |fd| fd.disk.sector_size = 4096);
    let f = open(d, 1, 0);
    let mut v = [0u64; 2];
    assert_eq!(f.ioctl(0x8008_1272, p(&mut v)), 0);
    assert_eq!(v[0], 2 * MIB);
    assert_eq!(f.ioctl(0x1260, p(&mut v)), 0);
    assert_eq!(v[0], 2 * MIB / 512);
    let mut u = [0u32; 2];
    for (cmd, want) in [(0x1268, 4096), (0x127B, 4096), (0x1278, 4096), (0x8008_1270, 4096), (0x1279, 0), (0x127A, 0), (0x125E, 0), (0x127C, 0), (0x8004_1284, 0), (0x8004_1285, 0)] {
        u[0] = 0xdead;
        assert_eq!(f.ioctl(cmd, p(&mut u)), 0, "cmd {cmd:#x}");
        assert_eq!(u[0], want, "cmd {cmd:#x}");
    }
    let mut s = [0xFFFFu16];
    assert_eq!(f.ioctl(0x127E, p(&mut s)), 0);
    assert_eq!(s[0], 0);
    assert_eq!(f.ioctl(0x8008_1280, p(&mut v)), 0);
    assert_eq!(v[0], d as u64 + 1);
    assert_eq!(f.ioctl(0x1263, p(&mut v)), 0);
    assert_eq!(v[0], 256);
    assert_eq!(f.ioctl(0x1262, 0), 0);
    assert_eq!(f.ioctl(0x125D, 0), 0);
    // HDIO_GETGEO: 255 heads, 63 sectors, start in sectors
    let mut g = [0u8; 16];
    assert_eq!(f.ioctl(0x0301, p(&mut g)), 0);
    assert_eq!((g[0], g[1]), (255, 63));
    assert_eq!(u16::from_le_bytes([g[2], g[3]]), (2 * MIB / 512 / (255 * 63)) as u16);
    assert_eq!(u64::from_le_bytes(g[8..16].try_into().unwrap()), MIB / 512);
    // Small sector size: physical size at least 4096
    fake::with_disk(d, |fd| fd.disk.sector_size = 512);
    assert_eq!(f.ioctl(0x1268, p(&mut u)), 0);
    assert_eq!(u[0], 512);
    assert_eq!(f.ioctl(0x127B, p(&mut u)), 0);
    assert_eq!(u[0], 4096);
    // Faults and unknown requests
    assert_eq!(f.ioctl(0x8008_1272, fake::BAD_PTR), EFAULT);
    assert_eq!(f.ioctl(0x1268, 0), EFAULT);
    assert_eq!(f.ioctl(0x127E, 0), EFAULT);
    assert_eq!(f.ioctl(0x0301, 0), EFAULT);
    assert_eq!(f.ioctl(0x4242, 0), ENOTTY);
}

#[test]
fn flush_and_fsync() {
    let d = disk();
    let f = open(d, 0, 0);
    fake::DISK_OPS.with_borrow_mut(|v| v.clear());
    assert_eq!(f.ioctl(0x1261, 0), 0);
    assert_eq!(f.fsync(), Some(0));
    assert_eq!(fake::DISK_OPS.with_borrow(|v| v.clone()), vec![format!("flush {d}"), format!("flush {d}")]);
}

#[test]
fn discard_and_zeroout_write_zeros() {
    let d = disk();
    fake::with_disk(d, |fd| fd.data[MIB as usize..MIB as usize + 2048].fill(0xEE));
    let f = open(d, 1, 2);
    let mut range = [512u64, 1024];
    assert_eq!(f.ioctl(0x127F, p(&mut range)), 0);
    let data = fake::with_disk(d, |fd| fd.data[MIB as usize..MIB as usize + 2048].to_vec());
    assert!(data[..512].iter().all(|&b| b == 0xEE));
    assert!(data[512..1536].iter().all(|&b| b == 0));
    assert!(data[1536..].iter().all(|&b| b == 0xEE));
    // Unaligned, past the end, overflowing, faulting
    for r in [[1u64, 512], [0, 100], [2 * MIB, 512], [u64::MAX - 511, 1024]] {
        let mut r = r;
        assert_eq!(f.ioctl(0x1277, p(&mut r)), EINVAL, "{r:?}");
    }
    assert_eq!(f.ioctl(0x127D, fake::BAD_PTR), EFAULT);
}

#[test]
fn rereading_the_partition_table() {
    let d = disk();
    let f = open(d, 0, 0);
    // Needs CAP_SYS_ADMIN, and the whole disk
    fake::CAPS.set(Some(0));
    assert_eq!(f.ioctl(0x125F, 0), EACCES);
    fake::CAPS.set(None);
    assert_eq!(f.ioctl(0x125F, 0), EACCES);
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(open(d, 1, 0).ioctl(0x125F, 0), EINVAL);
    fake::DISK_OPS.with_borrow_mut(|v| v.clear());
    assert_eq!(f.ioctl(0x125F, 0), 0);
    assert_eq!(fake::DISK_OPS.with_borrow(|v| v.clone()), vec![format!("reread {d}")]);
    fake::with_disk(d, |fd| fd.fail = Some(-16));
    assert_eq!(f.ioctl(0x125F, 0), -16);
    fake::CAPS.set(Some(0));
}

#[test]
fn blkpg_adds_and_removes_partitions() {
    let d = disk();
    let f = open(d, 0, 2);
    // struct blkpg_partition { start, length, pno, devname[64], volname[64] }
    let mut part = vec![0u8; 20 + 128];
    part[0..8].copy_from_slice(&(3 * MIB as i64).to_le_bytes());
    part[8..16].copy_from_slice(&(MIB as i64).to_le_bytes());
    part[16..20].copy_from_slice(&2i32.to_le_bytes());
    let mut arg = [0u8; 24];
    arg[0..4].copy_from_slice(&1u32.to_le_bytes()); // BLKPG_ADD_PARTITION
    arg[16..24].copy_from_slice(&(part.as_mut_ptr() as u64).to_le_bytes());

    fake::CAPS.set(Some(0));
    assert_eq!(f.ioctl(0x1269, p(&mut arg)), EACCES);
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(open(d, 1, 0).ioctl(0x1269, p(&mut arg)), EINVAL);
    fake::DISK_OPS.with_borrow_mut(|v| v.clear());
    assert_eq!(f.ioctl(0x1269, p(&mut arg)), 0);
    assert_eq!(fake::DISK_OPS.with_borrow(|v| v.clone()), vec![format!("blkpg {d} 1 2 {} {}", 3 * MIB, MIB)]);
    // Bad arguments: negative start, negative length, partition 0
    for (off, bytes) in [(0usize, (-1i64).to_le_bytes().to_vec()), (8, (-1i64).to_le_bytes().to_vec()), (16, 0i32.to_le_bytes().to_vec())] {
        let mut bad = part.clone();
        bad[off..off + bytes.len()].copy_from_slice(&bytes);
        let mut a = arg;
        a[16..24].copy_from_slice(&(bad.as_mut_ptr() as u64).to_le_bytes());
        assert_eq!(f.ioctl(0x1269, p(&mut a)), EINVAL);
    }
    // Faults on the argument and on the partition record
    assert_eq!(f.ioctl(0x1269, fake::BAD_PTR), EFAULT);
    let mut a = arg;
    a[16..24].copy_from_slice(&fake::BAD_PTR.to_le_bytes());
    assert_eq!(f.ioctl(0x1269, p(&mut a)), EFAULT);
    // The disk refuses
    fake::with_disk(d, |fd| fd.fail = Some(-16));
    assert_eq!(f.ioctl(0x1269, p(&mut arg)), -16);
    fake::CAPS.set(Some(0));
}

/// After a write, closing the last descriptor rewrites the block device records in the
/// Linux root (`devices::refresh_block_tree`), as udev's watch rule does on Linux.
#[test]
fn closing_a_written_device_rewrites_the_udev_records() {
    let _g = common::serial(); // devices' LINUX_ROOT is global
    let root = fake::fs_mkdir_p("/linux");
    assert!(root > 0);
    let d = disk();
    hydra_hosttests_t28::compat::linux::devices::populate("/linux").expect("populate");
    // A FAT32 file system appears on partition 1
    let f = open(d, 1, 2);
    let mut boot = vec![0u8; 512];
    boot[82..87].copy_from_slice(b"FAT32");
    boot[0x43..0x47].copy_from_slice(&0x1234_ABCDu32.to_le_bytes());
    boot[0x47..0x52].copy_from_slice(b"MYSTICK    ");
    boot[510] = 0x55;
    boot[511] = 0xAA;
    assert_eq!(f.write(&boot), 512);
    let before = fake::fs_text("/linux/run/udev/data/b8:1");
    assert!(!before.contains("ID_FS_TYPE"), "{before}");
    drop(f);
    let after = fake::fs_text("/linux/run/udev/data/b8:1");
    assert!(after.contains("E:ID_FS_TYPE=vfat\n"), "{after}");
    assert!(after.contains("E:ID_FS_UUID=1234-ABCD\n"), "{after}");
    assert!(after.contains("E:ID_FS_LABEL=MYSTICK\n"), "{after}");
    // A read-only open that wrote nothing does not rewrite
    let n = fake::with_fs(|fs| fs.ops.get("write").copied().unwrap_or(0));
    drop(open(d, 1, 0));
    assert_eq!(fake::with_fs(|fs| fs.ops.get("write").copied().unwrap_or(0)), n);
}
