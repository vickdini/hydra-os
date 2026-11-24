//! # Pseudo-terminals: the kernel's part
//!
//! The terminals (`/dev/ptmx`, `/dev/pts/N`, the console's line discipline) are
//! tty-server's (wave 8 T; wave 10 10-C deleted the in-kernel copy `lx.tty=kernel` used).
//! What stays: the devpts numbers, `stat`/`chmod`/`chown` of `/dev/pts` names answered with
//! tty-server's node table (`lx::console`), and `vhangup`'s hand-off.

/// Device numbers: `/dev/ptmx` is 5:2, slaves are major 136 and up.
pub const PTMX_MAJOR: u64 = 5;

/// Minor device number for `/dev/ptmx`.
pub const PTMX_MINOR: u64 = 2;

/// Major device number for pseudo-terminal slave endpoints (`/dev/pts/*`).
pub const PTS_MAJOR: u64 = 136;

/// `st_dev` of the devpts file system.
pub const PTS_DEV: u64 = 0x18;

/// Linux `makedev` encoding of a device number.
///
/// # Arguments
///
/// * `major` - Device major number.
/// * `minor` - Device minor number.
///
/// # Returns
///
/// Encoded 64-bit device number.
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
}

/// Hangs up the controlling terminal of session `sid` (`vhangup`): the session loses it and
/// earlier descriptors are dead. Returns `(session leader, foreground group)` to signal.
pub fn hangup(sid: u64) -> Option<(u64, u64)> {
    // wave8 GT: tty-server's terminals
    crate::lx::console::hangup(sid)
}

/// `stat` of `/dev/ptmx`, `/dev/pts` or `/dev/pts/N`; `None` for other paths.
///
/// # Arguments
///
/// * `abs` - Absolute path string to inspect.
///
/// # Returns
///
/// * `Some(Ok(stat))` if path is a recognized PTY virtual path.
/// * `Some(Err(errno))` on failure (e.g. slave not found).
/// * `None` if path does not belong to PTY subsystem.
pub fn stat_path(abs: &str) -> Option<Result<super::types::LinuxStat, i64>> {
    let mut st = super::types::LinuxStat::default();
    st.st_blksize = 1024;
    st.st_nlink = 1;
    if abs == "/dev/ptmx" {
        st.st_dev = PTS_DEV;
        st.st_ino = 2;
        st.st_mode = 0o020666;
        st.st_rdev = makedev(PTMX_MAJOR, PTMX_MINOR);
        return Some(Ok(st));
    }
    if abs == "/dev/pts" || abs == "/dev/pts/" {
        st.st_dev = PTS_DEV;
        st.st_ino = 1;
        st.st_mode = 0o040755;
        st.st_nlink = 2;
        return Some(Ok(st));
    }
    let index = slave_index(abs)?;
    // wave8 GT: tty-server's terminals (the same numbers as `fill_stat`, and as tty-server's
    // objects report to `fstat`, so `ttyname` matches them)
    Some(crate::lx::console::pty_stat(index as u64).map(|(mode, uid, gid)| {
        st.st_dev = PTS_DEV;
        st.st_ino = index as u64 + 3;
        st.st_mode = 0o020000 | mode;
        st.st_uid = uid;
        st.st_gid = gid;
        st.st_rdev = makedev(PTS_MAJOR + (index as u64 >> 8), index as u64 & 0xFF);
        st
    }))
}

/// `chmod`/`chown` of `/dev/pts/N` by `euid` (the owner may change the mode and group;
/// only root may give the node away). `None` for other paths.
///
/// # Arguments
///
/// * `abs` - Absolute path.
/// * `euid` - Effective UID of caller.
/// * `mode` - Optional new mode bits.
/// * `uid` - Optional new UID.
/// * `gid` - Optional new GID.
///
/// # Returns
///
/// `Some(0)` on success, `Some(-EPERM)` or `Some(-ENOENT)` on error, or `None` if not `/dev/pts/*`.
pub fn setattr_path(abs: &str, euid: u32, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> Option<i64> {
    let index = slave_index(abs)?;
    // wave8 GT: tty-server's terminals
    let _ = euid; // (tty-server checks the caller's identity from the call)
    Some(crate::lx::console::pty_setattr(index as u64, mode, uid, gid))
}

/// The slave index named by `/dev/pts/<N>`.
///
/// # Arguments
///
/// * `abs` - Absolute path string.
///
/// # Returns
///
/// `Some(index)` if path matches `/dev/pts/<N>`, or `None`.
pub fn slave_index(abs: &str) -> Option<u32> {
    abs.strip_prefix("/dev/pts/")?.parse().ok()
}
