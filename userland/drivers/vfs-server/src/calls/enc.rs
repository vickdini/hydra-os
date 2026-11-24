//! The byte layouts of the file calls' results (x86-64 Linux), as the kernel's `vfs.rs`
//! writes them: `struct stat`, `struct statx`, `struct linux_dirent64`, `struct statfs`.
//! Plain functions of their inputs (unit-tested on the host, `tests/host-w7-37`).

use alloc::vec::Vec;

use crate::fs::fsproto::{Attr, ReaddirEntry};

/// `st_dev` of pool objects (the kernel's `ZFS_DEV`).
pub const ZFS_DEV: u64 = 0x0801;
/// `f_type` of the pool (`ZFS_SUPER_MAGIC`).
pub const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;
/// Size of `struct stat`.
pub const STAT_SIZE: usize = 144;
/// Size of `struct statx`.
pub const STATX_SIZE: usize = 256;
/// Size of `struct statfs`.
pub const STATFS_SIZE: usize = 120;

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `struct stat` of pool object `a`.
pub fn stat(a: &Attr) -> [u8; STAT_SIZE] {
    let mut b = [0u8; STAT_SIZE];
    put64(&mut b, 0, ZFS_DEV);
    put64(&mut b, 8, a.ino);
    put64(&mut b, 16, a.nlink as u64);
    put32(&mut b, 24, a.mode);
    put32(&mut b, 28, a.uid);
    put32(&mut b, 32, a.gid);
    put64(&mut b, 40, a.rdev);
    put64(&mut b, 48, a.size);
    put64(&mut b, 56, 4096);
    put64(&mut b, 64, a.blocks);
    for (off, (s, ns)) in [(72, a.atime), (88, a.mtime), (104, a.ctime)] {
        put64(&mut b, off, s as u64);
        put64(&mut b, off + 8, ns as u64);
    }
    b
}

/// `struct statx` of pool object `a` (the kernel's fields: basic stats and the mount id;
/// the birth time is the change time, as the kernel reports it).
pub fn statx(a: &Attr) -> [u8; STATX_SIZE] {
    let mut b = [0u8; STATX_SIZE];
    put32(&mut b, 0, 0x17FF); // STATX_BASIC_STATS | STATX_MNT_ID
    put32(&mut b, 4, 4096);
    put32(&mut b, 16, a.nlink);
    put32(&mut b, 20, a.uid);
    put32(&mut b, 24, a.gid);
    b[28..30].copy_from_slice(&(a.mode as u16).to_le_bytes());
    put64(&mut b, 32, a.ino);
    put64(&mut b, 40, a.size);
    put64(&mut b, 48, a.blocks);
    for (off, (s, ns)) in [(64, a.atime), (80, a.ctime), (96, a.ctime), (112, a.mtime)] {
        put64(&mut b, off, s as u64);
        put32(&mut b, off + 8, ns);
    }
    put32(&mut b, 128, ((a.rdev >> 8) & 0xFFF) as u32);
    put32(&mut b, 132, (a.rdev & 0xFF) as u32);
    put32(&mut b, 136, ((ZFS_DEV >> 8) & 0xFFF) as u32);
    put32(&mut b, 140, (ZFS_DEV & 0xFF) as u32);
    // One mount id per device number, as the kernel says
    put64(&mut b, 144, 20 + (ZFS_DEV & 0xFFFF));
    b
}

/// The `linux_dirent64` records of `entries` that fit in `count` bytes, and the cookie after
/// the last one taken (`cookie` if none was).
pub fn dirents(entries: &[ReaddirEntry], count: usize, cookie: u64) -> (Vec<u8>, u64) {
    let mut out: Vec<u8> = Vec::with_capacity(count.min(1 << 16));
    let mut next = cookie;
    for e in entries {
        let reclen = (19 + e.name.len() + 1 + 7) & !7;
        if out.len() + reclen > count {
            break;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(e.next_cookie as i64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(e.dtype);
        out.extend_from_slice(&e.name);
        out.resize(start + reclen, 0);
        next = e.next_cookie;
    }
    (out, next)
}

/// The `struct linux_dirent` (old `getdents`) records of `entries` that fit in `count`.
pub fn dirents_old(entries: &[ReaddirEntry], count: usize, cookie: u64) -> (Vec<u8>, u64) {
    let mut out: Vec<u8> = Vec::with_capacity(count.min(1 << 16));
    let mut next = cookie;
    for e in entries {
        // d_ino, d_off, d_reclen, name, NUL, then d_type in the last byte
        let reclen = (18 + e.name.len() + 2 + 7) & !7;
        if out.len() + reclen > count {
            break;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(e.next_cookie as i64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.extend_from_slice(&e.name);
        out.resize(start + reclen, 0);
        out[start + reclen - 1] = e.dtype;
        next = e.next_cookie;
    }
    (out, next)
}

/// `struct statfs` of the pool: `(total, free, objects)` blocks and objects as zfs-server
/// reports them; `fsid` the pool's.
pub fn statfs(total: u64, free: u64, objs: u64, fsid: [u32; 2]) -> [u8; STATFS_SIZE] {
    let mut b = [0u8; STATFS_SIZE];
    let vals: [i64; 7] = [ZFS_SUPER_MAGIC, 4096, total as i64, free as i64, free as i64, (objs + 1_000_000) as i64, 1_000_000];
    for (i, v) in vals.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    put32(&mut b, 56, fsid[0]);
    put32(&mut b, 60, fsid[1]);
    put64(&mut b, 64, 255);
    put64(&mut b, 72, 4096);
    b
}

// wave10 GV1 begin
/// `f_type` of a tmpfs (`TMPFS_MAGIC`).
pub const TMPFS_MAGIC: i64 = 0x0102_1994;

/// `struct statfs` of a tmpfs mount (the kernel's): with `usage` = `(limit, used, files)` of
/// a tmpfs whose files keep data in memory, blocks = its `size=`; without, the type only.
pub fn statfs_tmpfs(usage: Option<(u64, u64, u64)>) -> [u8; STATFS_SIZE] {
    let mut b = [0u8; STATFS_SIZE];
    let vals: [i64; 7] = match usage {
        Some((limit, used, files)) => {
            let (total, free) = (limit / 4096, limit.saturating_sub(used) / 4096);
            [TMPFS_MAGIC, 4096, total as i64, free as i64, free as i64, (files + 1_000_000) as i64, 1_000_000]
        }
        None => [TMPFS_MAGIC, 4096, 0, 0, 0, 0, 0],
    };
    for (i, v) in vals.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    put64(&mut b, 64, 255);
    put64(&mut b, 72, 4096);
    b
}
// wave10 GV1 end
