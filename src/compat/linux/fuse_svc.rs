//! # FUSE served by vfs-server (wave 9, Group 6b-2)
//!
//! While the file service is forwarded, `/dev/fuse` is vfs-server's (`chardev.rs` sends
//! 10:229 there) and vfs-server is the FUSE client: it speaks the protocol with the daemon,
//! keeps the node table and the daemon's handles, and walks into the mounts itself. Its
//! files have FUSE inode numbers whose connection is [`FUSE_SVC_CONN`] or above, so the
//! kernel's file code (handles, the calls vfs-server leaves to the kernel, `lx.vfs` code
//! paths) still treats them as FUSE inodes: [`super::fuse`]'s functions send each operation
//! on such an inode here, and this module forwards it to vfs-server
//! ([`LX_KCALL_FUSE`](crate::ipc::protocol::LX_KCALL_FUSE)), lending the kernel's buffers
//! for the data ([`crate::lx::call_vfs_fuse`]).
//!
//! `lx.fuse=kernel` (or `lx.vfs=kernel`, `lx=kernel`) at boot: the kernel's own client
//! serves `/dev/fuse` as before.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

use super::fuse::{attr_of, dirents, is_fuse, statfs_of, u64_at};
use crate::fs::zfs::fsproto::{Attr, ReaddirEntry};
use crate::ipc::protocol::*;

/// `lx.fuse=kernel` at boot: `/dev/fuse` stays the kernel's client.
pub static KERNEL_ONLY: AtomicBool = AtomicBool::new(false);
/// Operations forwarded to vfs-server since boot.
pub static CALLS: AtomicU64 = AtomicU64::new(0);

const EIO: i64 = -5;

/// Whether new `/dev/fuse` opens go to vfs-server.
pub fn forwarded() -> bool {
    !KERNEL_ONLY.load(Ordering::Relaxed) && crate::lx::svc::mode(LXS_VFS) == crate::lx::svc::SvcMode::Forward && !crate::lx::all_kernel()
}

/// Whether `ino` is a file of one of vfs-server's FUSE connections.
pub fn is_remote(ino: u64) -> bool {
    is_fuse(ino) && remote_conn(((ino >> 40) & 0xFFFF) as u16)
}

/// Whether connection number `conn` is vfs-server's.
pub fn remote_conn(conn: u16) -> bool {
    conn & FUSE_SVC_CONN != 0
}

/// The root inode of vfs-server's connection `conn`.
pub fn root_of(conn: u16) -> u64 {
    super::fuse::FUSE_BIT | (conn as u64) << 40 | 1
}

/// The daemon's inode numbers of vfs-server's files, as the replies brought them (what
/// `stat` shows); bounded.
static USER_INO: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());
const USER_INO_MAX: usize = 8192;

fn remember(ino: u64, user: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut m = USER_INO.lock();
        if m.len() >= USER_INO_MAX && !m.contains_key(&ino) {
            m.clear();
        }
        m.insert(ino, user);
    });
}

/// One operation (`FUSE_OP_*`) with arguments `a`, input `kin`, output into `kout`.
fn op(op: u64, a: [u64; 5], kin: &[u8], kout: &mut [u8]) -> Result<i64, i64> {
    CALLS.fetch_add(1, Ordering::Relaxed);
    let r = crate::lx::call_vfs_fuse([op, a[0], a[1], a[2], a[3], a[4]], kin, kout);
    if r == EIO {
        static SHOWN: AtomicU64 = AtomicU64::new(0);
        if SHOWN.fetch_add(1, Ordering::Relaxed) < 5 {
            crate::kprintln!("[fuse] vfs-server answered EIO to operation {} on {:#x}", op, a[0]);
        }
    }
    if r < 0 { Err(r) } else { Ok(r) }
}

/// `fuse_attr` at `b` (as vfs-server answers) as the attributes of `ino`.
fn attr(ino: u64, b: &[u8]) -> Attr {
    remember(ino, u64_at(b, 0));
    attr_of(ino, b)
}

/// Two names as one input: `a\0b`.
fn pair(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len() + 1);
    v.extend_from_slice(a);
    v.push(0);
    v.extend_from_slice(b);
    v
}

/// [`super::fuse::lookup_attr`] for an inode of vfs-server's.
pub fn lookup_attr(dir: u64, name: &[u8]) -> Result<(u64, Attr), i64> {
    let mut out = [0u8; 96];
    op(FUSE_OP_LOOKUP, [dir, 0, 0, 0, name.len() as u64], name, &mut out)?;
    let ino = u64_at(&out, 0);
    if !is_remote(ino) {
        return Err(EIO);
    }
    Ok((ino, attr(ino, &out[8..])))
}

/// [`super::fuse::getattr`] for an inode of vfs-server's.
pub fn getattr(ino: u64) -> Result<Attr, i64> {
    let mut out = [0u8; 88];
    op(FUSE_OP_GETATTR, [ino, 0, 0, 0, 0], &[], &mut out)?;
    Ok(attr(ino, &out))
}

/// [`super::fuse::setattr`] for an inode of vfs-server's (`set_in`: `fuse_setattr_in`).
pub fn setattr(ino: u64, set_in: &[u8]) -> Result<Attr, i64> {
    let mut out = [0u8; 88];
    op(FUSE_OP_SETATTR, [ino, 0, 0, 0, set_in.len() as u64], set_in, &mut out)?;
    Ok(attr(ino, &out))
}

/// [`super::fuse::readlink`] for an inode of vfs-server's.
pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; 4096];
    let n = op(FUSE_OP_READLINK, [ino, 0, 0, 0, 0], &[], &mut out)? as usize;
    out.truncate(n.min(4096));
    Ok(out)
}

/// Largest part of one read or write.
const CHUNK: usize = 128 * 1024;

/// [`super::fuse::read`] for an inode of vfs-server's.
pub fn read(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let mut done = 0;
    while done < buf.len() {
        let want = (buf.len() - done).min(CHUNK);
        let got = op(FUSE_OP_READ, [ino, offset + done as u64, want as u64, 0, 0], &[], &mut buf[done..done + want])? as usize;
        let got = got.min(want);
        done += got;
        if got < want {
            break;
        }
    }
    Ok(done)
}

/// [`super::fuse::write`] for an inode of vfs-server's.
pub fn write(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
    let mut done = 0;
    while done < data.len() {
        let part = &data[done..(done + CHUNK).min(data.len())];
        let w = (op(FUSE_OP_WRITE, [ino, offset + done as u64, 0, 0, part.len() as u64], part, &mut [])? as usize).min(part.len());
        done += w;
        if w < part.len() {
            break;
        }
    }
    Ok(done)
}

/// [`super::fuse::readdir`] for an inode of vfs-server's.
pub fn readdir(dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
    let mut out = alloc::vec![0u8; 16384];
    let n = op(FUSE_OP_READDIR, [dir, cookie, 0, 0, 0], &[], &mut out)? as usize;
    Ok(dirents(&out[..n.min(out.len())], max))
}

/// An operation that makes a node and answers its inode.
fn made(o: u64, a: [u64; 5], kin: &[u8]) -> Result<u64, i64> {
    let mut out = [0u8; 8];
    op(o, a, kin, &mut out)?;
    let ino = u64_at(&out, 0);
    if is_remote(ino) { Ok(ino) } else { Err(EIO) }
}

/// [`super::fuse::create`] for an inode of vfs-server's.
pub fn create(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    made(FUSE_OP_CREATE, [dir, perm as u64, 0, 0, name.len() as u64], name)
}

/// [`super::fuse::mknod`] for an inode of vfs-server's.
pub fn mknod(dir: u64, name: &[u8], mode: u32, rdev: u64) -> Result<u64, i64> {
    made(FUSE_OP_MKNOD, [dir, mode as u64, rdev, 0, name.len() as u64], name)
}

/// [`super::fuse::mkdir`] for an inode of vfs-server's.
pub fn mkdir(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    made(FUSE_OP_MKDIR, [dir, perm as u64, 0, 0, name.len() as u64], name)
}

/// [`super::fuse::symlink`] for an inode of vfs-server's.
pub fn symlink(dir: u64, name: &[u8], to: &[u8]) -> Result<u64, i64> {
    let kin = pair(name, to);
    made(FUSE_OP_SYMLINK, [dir, 0, 0, 0, kin.len() as u64], &kin)
}

/// [`super::fuse::link`] for inodes of vfs-server's.
pub fn link(ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
    op(FUSE_OP_LINK, [ino, dir, 0, 0, name.len() as u64], name, &mut []).map(|_| ())
}

/// [`super::fuse::unlink`] for an inode of vfs-server's.
pub fn unlink(dir: u64, name: &[u8]) -> Result<(), i64> {
    op(FUSE_OP_UNLINK, [dir, 0, 0, 0, name.len() as u64], name, &mut []).map(|_| ())
}

/// [`super::fuse::rmdir`] for an inode of vfs-server's.
pub fn rmdir(dir: u64, name: &[u8]) -> Result<(), i64> {
    op(FUSE_OP_RMDIR, [dir, 0, 0, 0, name.len() as u64], name, &mut []).map(|_| ())
}

/// [`super::fuse::rename`] for inodes of vfs-server's.
pub fn rename(sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
    let kin = pair(sname, dname);
    op(FUSE_OP_RENAME, [sdir, ddir, 0, 0, kin.len() as u64], &kin, &mut []).map(|_| ())
}

/// [`super::fuse::getxattr`] for an inode of vfs-server's.
pub fn getxattr(ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; 65536];
    let n = op(FUSE_OP_GETXATTR, [ino, 0, 0, 0, name.len() as u64], name, &mut out)? as usize;
    out.truncate(n.min(65536));
    Ok(out)
}

/// [`super::fuse::listxattr`] for an inode of vfs-server's.
pub fn listxattr(ino: u64) -> Result<Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; 65536];
    let n = op(FUSE_OP_LISTXATTR, [ino, 0, 0, 0, 0], &[], &mut out)? as usize;
    out.truncate(n.min(65536));
    Ok(out)
}

/// [`super::fuse::setxattr`] for an inode of vfs-server's.
pub fn setxattr(ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
    let mut kin = Vec::with_capacity(name.len() + value.len());
    kin.extend_from_slice(name);
    kin.extend_from_slice(value);
    op(FUSE_OP_SETXATTR, [ino, flags as u64, name.len() as u64, 0, kin.len() as u64], &kin, &mut []).map(|_| ())
}

/// [`super::fuse::removexattr`] for an inode of vfs-server's.
pub fn removexattr(ino: u64, name: &[u8]) -> Result<(), i64> {
    op(FUSE_OP_REMOVEXATTR, [ino, 0, 0, 0, name.len() as u64], name, &mut []).map(|_| ())
}

/// [`super::fuse::statfs`] for an inode of vfs-server's.
pub fn statfs(ino: u64) -> Result<[u8; 120], i64> {
    let mut out = [0u8; 80];
    let n = op(FUSE_OP_STATFS, [ino, 0, 0, 0, 0], &[], &mut out)? as usize;
    Ok(statfs_of(ino, &out[..n.min(80)]))
}

/// [`super::fuse::open_ref`] for an inode of vfs-server's. Not for a handle vfs-server
/// installs itself (`LX_FH_INSTALL`, on its own thread): it counted that open already.
pub fn open_ref(ino: u64) {
    if crate::task::with_current_task_mut(|t| t.service.is_some()).unwrap_or(false) {
        return;
    }
    let _ = op(FUSE_OP_OPEN_REF, [ino, 0, 0, 0, 0], &[], &mut []);
}

/// [`super::fuse::release`] for an inode of vfs-server's.
pub fn release(ino: u64) {
    let _ = op(FUSE_OP_RELEASE, [ino, 0, 0, 0, 0], &[], &mut []);
}

/// The directory `ino` was found in and its name there (`None` for a root).
pub fn name_of(ino: u64) -> Option<(u64, Vec<u8>)> {
    let mut out = alloc::vec![0u8; 8 + 256];
    let n = op(FUSE_OP_NAME_OF, [ino, 0, 0, 0, 0], &[], &mut out).ok()? as usize;
    if n < 8 {
        return None;
    }
    Some((u64_at(&out, 0), out[8..n.min(out.len())].to_vec()))
}

/// The directory `ino` was found in (a root: itself).
pub fn parent(ino: u64) -> Result<u64, i64> {
    let mut out = alloc::vec![0u8; 8 + 256];
    let n = op(FUSE_OP_NAME_OF, [ino, 0, 0, 0, 0], &[], &mut out)? as usize;
    if n < 8 { Ok(ino) } else { Ok(u64_at(&out, 0)) }
}

/// The inode number the daemon gave `ino`.
pub fn user_ino(ino: u64) -> u64 {
    if let Some(u) = x86_64::instructions::interrupts::without_interrupts(|| USER_INO.lock().get(&ino).copied()) {
        return u;
    }
    match getattr(ino) {
        Ok(_) => x86_64::instructions::interrupts::without_interrupts(|| USER_INO.lock().get(&ino).copied()).unwrap_or(ino & 0xFF_FFFF_FFFF),
        Err(_) => ino & 0xFF_FFFF_FFFF,
    }
}

/// Mounts the vfs-server connection of the caller's `/dev/fuse` object `slot`: its number.
pub fn mount(slot: u64, uid: u32, gid: u32, allow_other: bool) -> Result<u16, i64> {
    let c = op(FUSE_OP_MOUNT, [slot, uid as u64 | (gid as u64) << 32, allow_other as u64, 0, 0], &[], &mut []);
    crate::kprintln!("[fuse] mount of vfs-server's /dev/fuse (slot {}): {:?}", slot, c);
    let c = c? as u16;
    if remote_conn(c) { Ok(c) } else { Err(EIO) }
}

/// Connection `conn` was unmounted: the daemon's reads end with `ENODEV`.
pub fn abort(conn: u16) {
    let _ = op(FUSE_OP_ABORT, [conn as u64, 0, 0, 0, 0], &[], &mut []);
}
