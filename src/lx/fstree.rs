//! # Which tree a path is in (wave 10, Group V2)
//!
//! `/sys` and `/dev` are pool trees vfs-server walks (written at boot by
//! `compat/linux/devices.rs`), but `statfs` reports them as the file systems Linux has there:
//! sysfs, cgroup2 at `/sys/fs/cgroup`, efivarfs at `/sys/firmware/efi/efivars`, devpts at
//! `/dev/pts`. Only the kernel knows the path of a handle (`OpenFile::path`) and of a working
//! directory, so it sends the tree of each with a file call ([`at_bits`], [`cwd_bits`]);
//! vfs-server classifies the paths it walks with the same rules ([`class_of`]).
//!
//! Plain functions of their inputs: the kernel builds this file, vfs-server includes it with
//! `#[path]`, and `tests/host-w10-v2` tests it.

/// The pool (or anything else).
pub const TREE_POOL: u32 = 0;
/// `/sys` (sysfs).
pub const TREE_SYS: u32 = 1;
/// `/sys/fs/cgroup` (cgroup2).
pub const TREE_CGROUP: u32 = 2;
/// `/sys/firmware/efi/efivars` (efivarfs).
pub const TREE_EFIVARS: u32 = 3;
/// `/dev` (a pool tree here; `statfs` shows the pool, as the kernel's copy did).
pub const TREE_DEV: u32 = 4;
/// `/dev/pts` (devpts).
pub const TREE_DEVPTS: u32 = 5;

/// Where a handle's tree is in [`crate::ipc::protocol::LxCall::fh_flags`] (3 bits; open
/// flags stop below bit 23, `LX_FH_NOTRUNC`/`LX_FH_NONOTIFY` are bits 30/31).
pub const AT_SHIFT: u32 = 23;
/// Where the working directory's tree is in `LxCall::fs_flags` (3 bits; the `LX_FS_*` bits
/// stop at bit 7).
pub const CWD_SHIFT: u32 = 24;
/// The 3 bits.
pub const MASK: u32 = 7;

/// Whether `path` is `dir` or below it.
fn under(path: &[u8], dir: &[u8]) -> bool {
    path.starts_with(dir) && (path.len() == dir.len() || path[dir.len()] == b'/')
}

/// The tree of absolute path `path` (as the caller sees it: from its root).
pub fn class_of(path: &[u8]) -> u32 {
    // (most paths: one byte compare)
    if path.len() < 4 || path[0] != b'/' || !(path[1] == b's' || path[1] == b'd') {
        return TREE_POOL;
    }
    if under(path, b"/sys") {
        if under(path, b"/sys/fs/cgroup") {
            TREE_CGROUP
        } else if under(path, b"/sys/firmware/efi/efivars") {
            TREE_EFIVARS
        } else {
            TREE_SYS
        }
    } else if under(path, b"/dev") {
        if under(path, b"/dev/pts") { TREE_DEVPTS } else { TREE_DEV }
    } else {
        TREE_POOL
    }
}

/// [`class_of`] for names from the caller's root (a walk's path, `names[0]` the first).
pub fn class_of_names(names: &[&[u8]]) -> u32 {
    match names {
        [b"sys", b"fs", b"cgroup", ..] => TREE_CGROUP,
        [b"sys", b"firmware", b"efi", b"efivars", ..] => TREE_EFIVARS,
        [b"sys", ..] => TREE_SYS,
        [b"dev", b"pts", ..] => TREE_DEVPTS,
        [b"dev", ..] => TREE_DEV,
        _ => TREE_POOL,
    }
}

/// The tree a walk ended in that started in tree `start` and went down by `names` (no `..`
/// above the start): the deeper trees `/sys` and `/dev` hold, when their names follow.
/// (A start inside `/sys` other than its top cannot be told apart from `/sys` itself:
/// `/sys/fs` + `cgroup` stays sysfs. Such relative `statfs` calls are rare.)
pub fn class_below(start: u32, names: &[&[u8]]) -> u32 {
    match (start, names) {
        (TREE_DEV, [b"pts", ..]) => TREE_DEVPTS,
        (s, _) => s,
    }
}

/// `f_type` of tree `t` (`statfs`): 0 for the pool (its own numbers are used).
pub fn magic_of(t: u32) -> i64 {
    match t {
        TREE_SYS => 0x6265_6572,         // SYSFS_MAGIC
        TREE_CGROUP => 0x6367_7270,      // CGROUP2_SUPER_MAGIC
        TREE_EFIVARS => 0xde5e_81e4,     // EFIVARFS_MAGIC
        TREE_DEVPTS => 0x1cd1,           // DEVPTS_SUPER_MAGIC
        _ => 0,
    }
}

/// The `fh_flags` bits of a handle opened at `path`.
pub fn at_bits(path: &str) -> u32 {
    class_of(path.as_bytes()) << AT_SHIFT
}

/// The `fs_flags` bits of a working directory at `path`.
pub fn cwd_bits(path: &str) -> u32 {
    class_of(path.as_bytes()) << CWD_SHIFT
}

/// The tree in `fh_flags`.
pub fn at_of(fh_flags: u32) -> u32 {
    (fh_flags >> AT_SHIFT) & MASK
}

/// The tree in `fs_flags`.
pub fn cwd_of(fs_flags: u32) -> u32 {
    (fs_flags >> CWD_SHIFT) & MASK
}
