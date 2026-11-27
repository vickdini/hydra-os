//! # Linux Compatibility: fanotify (what the kernel keeps)
//!
//! Since wave 9 (Group 6b-1) fanotify groups are vfs-server's objects: `fanotify_init` and
//! `fanotify_mark` go there (`lx::fileh`), and the kernel hands vfs-server the events and
//! permission questions of its own opens, reads, writes and closes (`lx::notifyfwd`).
//! Wave 9's closing (Group 9-C) deleted the kernel's own groups (the switch back
//! `lx.vfs=kernel`). Left here: the event bits other kernel code names, the pool's file
//! system ID, `name_to_handle_at` / `open_by_handle_at` (the handles fanotify reports), and
//! the answers for the calls that still reach the kernel: `fanotify_init` with vfs-server
//! not running (`ENOSYS`) and `fanotify_mark` on a descriptor that is not vfs-server's group
//! (`EBADF` / `EINVAL`).

use alloc::string::String;
use alloc::vec::Vec;

use super::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOSYS: i64 = -38;

/// `FAN_ACCESS`: a file was read.
pub const FAN_ACCESS: u64 = 0x1;
/// `FAN_MODIFY`: a file was written.
pub const FAN_MODIFY: u64 = 0x2;
/// `FAN_CLOSE_WRITE`: a file opened for writing was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x8;
/// `FAN_CLOSE_NOWRITE`: a file opened read-only was closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;

/// The file system ID Hydra's pool reports (`statfs` `f_fsid`, fanotify handle records).
pub const POOL_FSID: [i32; 2] = [0x4859_4452, 0x5a46_5301];

/// System calls 300 (`fanotify_init`) and 301 (`fanotify_mark`) reaching the kernel.
pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
    match num {
        // (vfs-server never claimed it: wave11 GK)
        300 => ENOSYS,
        _ => {
            if crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).is_some()) {
                EINVAL
            } else {
                EBADF
            }
        }
    }
}

// ----------------------------------------------------------------------
// ----------------------------------------------------------------------
// name_to_handle_at / open_by_handle_at (the handles fanotify reports)
// ----------------------------------------------------------------------

/// `name_to_handle_at(dirfd, path, handle, mount_id, flags)`: the 8-byte inode handle.
pub fn name_to_handle_at(dirfd: u64, path: u64, handle: u64, mount_id: u64, flags: u64) -> i64 {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_HANDLE_FID: u64 = 0x200;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID) != 0 {
        return EINVAL;
    }
    let p = match super::vfs::user_cstr(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if p.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return ENOENT;
    }
    let (base, _) = match super::vfs::base_dir(dirfd as i32 as i64, if p.is_empty() { b"x" } else { &p }) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let ino = if p.is_empty() {
        base
    } else {
        match super::vfs::resolve(base, &p, flags & AT_SYMLINK_FOLLOW != 0) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    let Ok(hdr) = copy_in(handle, 8) else { return EFAULT };
    let room = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if room > 128 {
        return EINVAL; // MAX_HANDLE_SZ
    }
    if room < 8 {
        let _ = copy_out(handle, &8u32.to_le_bytes());
        return -75; // EOVERFLOW
    }
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    if copy_out(handle, &out).is_err() {
        return EFAULT;
    }
    // The mount ID /proc/self/fdinfo reports
    if copy_out(mount_id, &2069i32.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

/// `open_by_handle_at(mount_fd, handle, flags)` (`CAP_DAC_READ_SEARCH`).
pub fn open_by_handle_at(_mount_fd: u64, handle: u64, flags: u64) -> i64 {
    if !crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 2) != 0 && !t.caps.in_userns).unwrap_or(false) {
        return EPERM;
    }
    let Ok(raw) = copy_in(handle, 16) else { return EFAULT };
    let bytes = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let kind = i32::from_le_bytes(raw[4..8].try_into().unwrap());
    if bytes != 8 || kind != 1 {
        return -116; // ESTALE
    }
    let ino = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if crate::fs::ZfsClient::getattr(ino).is_err() {
        return -116;
    }
    let file = crate::fs::fd::OpenFile::new(ino, flags as u32 & (3 | 0o2000 | 0o4000 | 0o200000 | 0o10000000), String::new());
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Vnode(file)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & 0o2000000 != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}
