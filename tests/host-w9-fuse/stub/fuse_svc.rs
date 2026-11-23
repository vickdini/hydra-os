//! *stub* `src/compat/linux/fuse_svc.rs` for host crates that build the kernel's `fuse.rs`
//! (wave 9, Group 6b-2): the inode test is the real one; every forwarded operation answers
//! `ENOTCONN` (no vfs-server on the host). The real module is tested in QEMU.
#![allow(dead_code, missing_docs, clippy::all)]

use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use crate::fs::zfs::fsproto::{Attr, ReaddirEntry};

const ENOTCONN: i64 = -107;

pub static KERNEL_ONLY: AtomicBool = AtomicBool::new(false);

pub fn forwarded() -> bool {
    false
}
pub fn is_remote(ino: u64) -> bool {
    ino >> 62 == 1 && (ino >> 40) & 0x8000 != 0
}
pub fn remote_conn(conn: u16) -> bool {
    conn & 0x8000 != 0
}
pub fn root_of(conn: u16) -> u64 {
    1 << 62 | (conn as u64) << 40 | 1
}
pub fn lookup_attr(_dir: u64, _name: &[u8]) -> Result<(u64, Attr), i64> {
    Err(ENOTCONN)
}
pub fn getattr(_ino: u64) -> Result<Attr, i64> {
    Err(ENOTCONN)
}
pub fn setattr(_ino: u64, _set_in: &[u8]) -> Result<Attr, i64> {
    Err(ENOTCONN)
}
pub fn readlink(_ino: u64) -> Result<Vec<u8>, i64> {
    Err(ENOTCONN)
}
pub fn read(_ino: u64, _offset: u64, _buf: &mut [u8]) -> Result<usize, i64> {
    Err(ENOTCONN)
}
pub fn write(_ino: u64, _offset: u64, _data: &[u8]) -> Result<usize, i64> {
    Err(ENOTCONN)
}
pub fn readdir(_dir: u64, _cookie: u64, _max: usize) -> Result<Vec<ReaddirEntry>, i64> {
    Err(ENOTCONN)
}
pub fn create(_dir: u64, _name: &[u8], _perm: u32) -> Result<u64, i64> {
    Err(ENOTCONN)
}
pub fn mknod(_dir: u64, _name: &[u8], _mode: u32, _rdev: u64) -> Result<u64, i64> {
    Err(ENOTCONN)
}
pub fn mkdir(_dir: u64, _name: &[u8], _perm: u32) -> Result<u64, i64> {
    Err(ENOTCONN)
}
pub fn symlink(_dir: u64, _name: &[u8], _to: &[u8]) -> Result<u64, i64> {
    Err(ENOTCONN)
}
pub fn link(_ino: u64, _dir: u64, _name: &[u8]) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn unlink(_dir: u64, _name: &[u8]) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn rmdir(_dir: u64, _name: &[u8]) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn rename(_sdir: u64, _sname: &[u8], _ddir: u64, _dname: &[u8]) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn getxattr(_ino: u64, _name: &[u8]) -> Result<Vec<u8>, i64> {
    Err(ENOTCONN)
}
pub fn listxattr(_ino: u64) -> Result<Vec<u8>, i64> {
    Err(ENOTCONN)
}
pub fn setxattr(_ino: u64, _name: &[u8], _value: &[u8], _flags: u32) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn removexattr(_ino: u64, _name: &[u8]) -> Result<(), i64> {
    Err(ENOTCONN)
}
pub fn statfs(_ino: u64) -> Result<[u8; 120], i64> {
    Err(ENOTCONN)
}
pub fn open_ref(_ino: u64) {}
pub fn release(_ino: u64) {}
pub fn name_of(_ino: u64) -> Option<(u64, Vec<u8>)> {
    None
}
pub fn parent(ino: u64) -> Result<u64, i64> {
    Ok(ino)
}
pub fn user_ino(ino: u64) -> u64 {
    ino & 0xFF_FFFF_FFFF
}
pub fn mount(_slot: u64, _uid: u32, _gid: u32, _allow_other: bool) -> Result<u16, i64> {
    Err(ENOTCONN)
}
pub fn abort(_conn: u16) {}
