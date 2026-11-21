//! The file calls' decisions that depend only on their inputs (unit-tested on the host,
//! `tests/host-w7-37`): which opens are served here, the type checks of `open`, the
//! kernel's permission rule, the handle descriptor an open installs, path checks.

use crate::proto::{LxCall, LxFhDesc, LX_AT_CWD, LX_FHP_ABS, LX_FHP_AT, LX_FHP_CWD, LX_FH_PATH_MAX};

/// The error that means "the kernel answers this call" (never a Linux errno).
pub const KERNEL: i64 = i64::MIN;

pub const ENOENT: i64 = -2;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const ENAMETOOLONG: i64 = -36;
pub const ELOOP: i64 = -40;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;

pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_PATH: u32 = 0o10000000;
/// `O_TMPFILE` without `O_DIRECTORY`.
pub const O_TMPFILE_MASK: u32 = 0o20000000;

/// Access bits (`MAY_*` of `crate::perm`).
pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;

/// Whether an open with `flags` can be served here at all: it changes nothing (no
/// truncation; creation is decided after the walk) and needs nothing only the kernel has.
pub fn servable(flags: u32) -> bool {
    let acc = flags & O_ACCMODE;
    flags & (O_PATH | O_TMPFILE_MASK) == 0 && !(flags & O_TRUNC != 0 && acc != O_RDONLY)
}

/// What an open of an object of mode `mode` with `flags` does: `Ok(want)` the access to
/// check (`MAY_*`), `Err(e)` its error ([`KERNEL`] for devices, FIFOs, sockets). In the
/// kernel's order, before the permission check.
pub fn decide(mode: u32, flags: u32) -> Result<u32, i64> {
    let acc = flags & O_ACCMODE;
    let kind = mode & S_IFMT;
    if kind == S_IFLNK {
        return Err(ELOOP);
    }
    if flags & O_DIRECTORY != 0 && kind != S_IFDIR {
        return Err(ENOTDIR);
    }
    match kind {
        S_IFDIR if acc != O_RDONLY => return Err(EISDIR),
        S_IFDIR | S_IFREG => {}
        _ => return Err(KERNEL),
    }
    let want = match acc {
        O_RDONLY => MAY_READ,
        O_WRONLY => MAY_WRITE,
        _ => MAY_READ | MAY_WRITE,
    };
    // (the kernel asks for write permission for O_TRUNC even on a read-only open)
    Ok(if flags & O_TRUNC != 0 { want | MAY_WRITE } else { want })
}

/// The kernel's permission rule (`vfs::may_access`) for user `uid`, group `gid` on an
/// object with `mode`, owner `ouid`, group `ogid`: user 0 may read and write anything and
/// execute what has an `x` bit (or a directory); others by `acl` (the ACL's answer, when the
/// object has one) or the mode bits; `in_group(g)`: whether `g` is `gid` or a supplementary
/// group.
pub fn may_access(mode: u32, ouid: u32, ogid: u32, uid: u32, want: u32, acl: Option<bool>, in_group: impl Fn(u32) -> bool) -> bool {
    if uid == 0 {
        return want & MAY_EXEC == 0 || mode & 0o111 != 0 || mode & S_IFMT == S_IFDIR;
    }
    if let Some(r) = acl {
        return r;
    }
    let bits = if ouid == uid {
        (mode >> 6) & 7
    } else if in_group(ogid) {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want == want
}

/// A path as the kernel takes one for a path call: `ENOENT` when empty (unless `empty_ok`),
/// `ENAMETOOLONG` for a component over 255 bytes.
pub fn check_path(p: &[u8], empty_ok: bool) -> Result<(), i64> {
    if p.is_empty() && !empty_ok {
        return Err(ENOENT);
    }
    if p.split(|&b| b == b'/').any(|c| c.len() > 255) {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

/// The descriptor of the handle an open of `path` (by call `c`, directory descriptor
/// `dirfd`) installs for object `ino` of mount `mnt`.
pub fn handle_desc(c: &LxCall, ino: u64, mnt: u16, is_dir: bool, flags: u32, path: &[u8], dirfd: i32) -> Result<LxFhDesc, i64> {
    if path.len() > LX_FH_PATH_MAX {
        return Err(KERNEL);
    }
    let mut d = LxFhDesc::EMPTY;
    d.ino = ino;
    d.mnt = mnt as u32;
    d.is_dir = is_dir as u32;
    d.flags = flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_PATH | O_CLOEXEC);
    d.path_kind = if path.first() == Some(&b'/') {
        LX_FHP_ABS
    } else if c.at_kind == LX_AT_CWD {
        LX_FHP_CWD
    } else {
        d.at_fd = dirfd;
        LX_FHP_AT
    };
    d.path[..path.len()].copy_from_slice(path);
    d.path_len = path.len() as u32;
    Ok(d)
}

/// `(path pointer, AT_* flags, output pointer, statx?)` of a `stat`-family call.
pub fn stat_args(nr: u64, a: &[u64; 6]) -> (u64, u64, u64, bool) {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    match nr {
        4 => (a[0], 0, a[1], false),
        6 => (a[0], AT_SYMLINK_NOFOLLOW, a[1], false),
        262 => (a[1], a[3], a[2], false),
        _ => (a[1], a[2], a[4], true),
    }
}

/// `(path pointer, mode, flags)` of an `access`-family call.
pub fn access_args(nr: u64, a: &[u64; 6]) -> (u64, u32, u64) {
    match nr {
        21 => (a[0], a[1] as u32, 0),
        269 => (a[1], a[2] as u32, 0),
        _ => (a[1], a[2] as u32, a[3]),
    }
}
