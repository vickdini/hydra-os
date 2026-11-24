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

/// Whether an open with `flags` can be served here at all (wave10 GV1: creating,
/// truncating, `O_PATH` and `O_TMPFILE` opens are; `O_CREAT` with `O_DIRECTORY` and no
/// `O_TMPFILE` — Linux's `EINVAL` on new kernels, a file made then `ENOTDIR` on the kernel's
/// — stays the kernel's, as do the flag mixes `open` rejects).
pub fn servable(flags: u32) -> bool {
    if flags & O_TMPFILE_MASK != 0 {
        // O_TMPFILE needs O_DIRECTORY with it, no O_CREAT, no O_PATH
        return flags & O_DIRECTORY != 0 && flags & (O_CREAT | O_PATH) == 0;
    }
    !(flags & O_CREAT != 0 && flags & O_DIRECTORY != 0)
}

// wave10 GV1 begin
/// `EINVAL`.
pub const EINVAL: i64 = -22;
/// `UTIME_NOW`.
pub const UTIME_NOW: i64 = (1 << 30) - 1;
/// `UTIME_OMIT`.
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// The new `(atime, mtime)` of a times call `nr` (`utime` 132: `struct utimbuf` of two
/// seconds; `utimes` 235 / `futimesat` 261: two `timeval`s; `utimensat` 280: two
/// `timespec`s with `UTIME_NOW`/`UTIME_OMIT`) from its argument's bytes (`None`: a NULL
/// pointer, both "now"); `now` the wall clock. `EINVAL` for microseconds or nanoseconds out
/// of range.
pub fn utimes(nr: u64, raw: Option<&[u8]>, now: (i64, u32)) -> Result<(Option<(i64, u32)>, Option<(i64, u32)>), i64> {
    let Some(b) = raw else { return Ok((Some(now), Some(now))) };
    let w = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    match nr {
        132 => Ok((Some((w(0), 0)), Some((w(8), 0)))),
        235 | 261 => {
            let tv = |o: usize| {
                let us = w(o + 8);
                if !(0..1_000_000).contains(&us) {
                    return Err(EINVAL);
                }
                Ok(Some((w(o), (us * 1000) as u32)))
            };
            Ok((tv(0)?, tv(16)?))
        }
        _ => {
            let ts = |o: usize| match w(o + 8) {
                UTIME_NOW => Ok(Some(now)),
                UTIME_OMIT => Ok(None),
                ns if (0..1_000_000_000).contains(&ns) => Ok(Some((w(o), ns as u32))),
                _ => Err(EINVAL),
            };
            Ok((ts(0)?, ts(16)?))
        }
    }
}

/// Whether a times call sets an explicit time (only the owner may), not just "now" (anyone
/// who may write the file may).
pub fn times_explicit(nr: u64, raw: Option<&[u8]>) -> bool {
    let Some(b) = raw else { return false };
    if nr != 280 {
        return true;
    }
    let ns = |o: usize| i64::from_le_bytes(b[o + 8..o + 16].try_into().unwrap());
    [ns(0), ns(16)].iter().any(|&n| n != UTIME_NOW && n != UTIME_OMIT)
}

/// The namespace of an extended attribute name (the kernel's `xattr_op` rules).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum XattrNs {
    /// `user.*`: regular files and directories, by read or write permission.
    User,
    /// `trusted.*`: `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.*`: anyone reads; `security.capability` needs `CAP_SETFCAP` to change,
    /// others `CAP_SYS_ADMIN`.
    Security,
    /// `system.posix_acl_access` (`false`) or `system.posix_acl_default` (`true`).
    Acl(bool),
    /// Another `system.*` name: not supported.
    System,
}

/// `ERANGE`.
pub const ERANGE: i64 = -34;
/// `EOPNOTSUPP`.
pub const EOPNOTSUPP: i64 = -95;

/// The namespace of xattr `name`: `ERANGE` for an empty or too long name, `EOPNOTSUPP`
/// without a known prefix, `EINVAL` for the prefix alone.
pub fn xattr_ns(name: &[u8]) -> Result<XattrNs, i64> {
    if name.is_empty() || name.len() > 255 {
        return Err(ERANGE);
    }
    let (ns, len) = if name.starts_with(b"user.") {
        (XattrNs::User, 5)
    } else if name.starts_with(b"trusted.") {
        (XattrNs::Trusted, 8)
    } else if name.starts_with(b"security.") {
        (XattrNs::Security, 9)
    } else if name.starts_with(b"system.") {
        let k = match name {
            b"system.posix_acl_access" => XattrNs::Acl(false),
            b"system.posix_acl_default" => XattrNs::Acl(true),
            _ => XattrNs::System,
        };
        (k, 7)
    } else {
        return Err(EOPNOTSUPP);
    };
    if name.len() == len {
        return Err(EINVAL);
    }
    Ok(ns)
}

/// Whether a `security.capability` value is a valid `struct vfs_cap_data` (revision 2, 20
/// bytes, or 3, 24 bytes with a root id; no flag bits but the effective one).
pub fn fcaps_valid(data: &[u8]) -> bool {
    let magic = data.get(..4).map_or(0, |m| u32::from_le_bytes(m.try_into().unwrap()));
    let ok = (data.len() == 20 && magic & 0xff00_0000 == 0x0200_0000) || (data.len() == 24 && magic & 0xff00_0000 == 0x0300_0000);
    ok && magic & 0x00ff_fffe == 0
}

/// A listed xattr name list (NUL-terminated names) as a caller sees it: `trusted.*` only
/// with `CAP_SYS_ADMIN`.
pub fn xattr_list_shown(names: &[u8], admin: bool) -> alloc::vec::Vec<u8> {
    let mut shown = alloc::vec::Vec::new();
    for n in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        // (wave10 GV1: vfs-server's own mark of an unnamed O_TMPFILE object is never shown)
        if (admin || !n.starts_with(b"trusted.")) && n != b"trusted.hydra.tmpfile" {
            shown.extend_from_slice(n);
            shown.push(0);
        }
    }
    shown
}

/// What an xattr read of `len` bytes answers for a buffer of `size`: the length to report
/// with `size` 0, `ERANGE` when it does not fit, else the length copied.
pub fn xattr_fits(len: usize, size: u64) -> Result<usize, i64> {
    if size != 0 && (size as usize) < len {
        return Err(ERANGE);
    }
    Ok(len)
}
// wave10 GV1 end

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

/// wave9 GP2: the open flags a handle keeps (the kernel takes the same from the call's own
/// arguments when it makes the handle from the answer, `LX_REDIR_FH`).
pub const FH_PLAIN: u32 = O_ACCMODE | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_PATH | O_CLOEXEC;

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
    d.flags = flags & FH_PLAIN;
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

/// How many directory entries one `getdents` of `count` bytes asks zfs-server for (each
/// record takes 24 bytes at least; at most 4096 per request).
pub fn readdir_max(count: usize) -> usize {
    (count / 24).clamp(1, 4096)
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

/// `chown`'s rule (the kernel's `chown_ok`) for caller `euid` (`in_group(g)`: its effective or
/// a supplementary group) on an object owned by `ouid`/`ogid`; `u32::MAX` keeps a value.
pub fn chown_ok(euid: u32, ouid: u32, ogid: u32, uid: u32, gid: u32, in_group: impl Fn(u32) -> bool) -> bool {
    if euid == 0 {
        return true;
    }
    let uid_ok = uid == u32::MAX || uid == ouid;
    let gid_ok = gid == u32::MAX || gid == ogid || in_group(gid);
    euid == ouid && uid_ok && gid_ok
}

/// The kernel's sticky-directory rule: may `euid` not remove an entry owned by `entry_uid`
/// from a directory of mode `dmode` owned by `duid`?
pub fn sticky_denied(dmode: u32, duid: u32, entry_uid: u32, euid: u32) -> bool {
    euid != 0 && dmode & 0o1000 != 0 && duid != euid && entry_uid != euid
}
