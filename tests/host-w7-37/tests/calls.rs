//! vfs-server's file calls: the result layouts (`calls/enc.rs`) against the kernel's
//! `struct stat`/`statx`/`linux_dirent64`/`statfs` writers, and the calls' decisions
//! (`calls/rules.rs`) against the kernel's `open_path`, `may_access` and path checks.

use hydra_hosttests_w7_37::calls::enc::*;
use hydra_hosttests_w7_37::calls::rules::*;
use hydra_hosttests_w7_37::fs::fsproto::{Attr, ReaddirEntry};
use hydra_hosttests_w7_37::proto::*;

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn attr() -> Attr {
    Attr {
        ino: 1234,
        mode: 0o100644,
        nlink: 2,
        uid: 1000,
        gid: 100,
        rdev: 0x0103,
        size: 5000,
        blocks: 16,
        atime: (111, 1),
        mtime: (222, 2),
        ctime: (333, 3),
        generation: 9,
        birth_txg: 4,
        has_xattr: false,
    }
}

// ----------------------------------------------------------------------
// Layouts
// ----------------------------------------------------------------------

#[test]
fn stat_has_the_kernels_layout() {
    let b = stat(&attr());
    assert_eq!(b.len(), 144);
    assert_eq!(u64_at(&b, 0), ZFS_DEV);
    assert_eq!(u64_at(&b, 8), 1234);
    assert_eq!(u64_at(&b, 16), 2);
    assert_eq!(u32_at(&b, 24), 0o100644);
    assert_eq!((u32_at(&b, 28), u32_at(&b, 32)), (1000, 100));
    assert_eq!(u64_at(&b, 40), 0x0103);
    assert_eq!(u64_at(&b, 48), 5000);
    assert_eq!(u64_at(&b, 56), 4096);
    assert_eq!(u64_at(&b, 64), 16);
    assert_eq!((u64_at(&b, 72), u64_at(&b, 80)), (111, 1));
    assert_eq!((u64_at(&b, 88), u64_at(&b, 96)), (222, 2));
    assert_eq!((u64_at(&b, 104), u64_at(&b, 112)), (333, 3));
    assert!(b[120..].iter().all(|&x| x == 0));
}

#[test]
fn statx_has_the_kernels_layout() {
    let b = statx(&attr());
    assert_eq!(b.len(), 256);
    assert_eq!(u32_at(&b, 0), 0x17FF);
    assert_eq!(u32_at(&b, 4), 4096);
    assert_eq!(u32_at(&b, 16), 2);
    assert_eq!((u32_at(&b, 20), u32_at(&b, 24)), (1000, 100));
    assert_eq!(u16::from_le_bytes([b[28], b[29]]), 0o100644 as u16);
    assert_eq!(u64_at(&b, 32), 1234);
    assert_eq!(u64_at(&b, 40), 5000);
    assert_eq!(u64_at(&b, 48), 16);
    // atime, btime (= ctime), ctime, mtime
    assert_eq!((u64_at(&b, 64), u32_at(&b, 72)), (111, 1));
    assert_eq!((u64_at(&b, 80), u32_at(&b, 88)), (333, 3));
    assert_eq!((u64_at(&b, 96), u32_at(&b, 104)), (333, 3));
    assert_eq!((u64_at(&b, 112), u32_at(&b, 120)), (222, 2));
    // rdev 1:3, dev 8:1, mount id
    assert_eq!((u32_at(&b, 128), u32_at(&b, 132)), (1, 3));
    assert_eq!((u32_at(&b, 136), u32_at(&b, 140)), (8, 1));
    assert_eq!(u64_at(&b, 144), 20 + 0x0801);
}

fn entry(name: &[u8], ino: u64, next: u64) -> ReaddirEntry {
    ReaddirEntry { name: name.to_vec(), ino, dtype: 8, next_cookie: next }
}

#[test]
fn dirents_pack_what_fits() {
    let e = [entry(b".", 1, 1), entry(b"hello.txt", 7, 2), entry(b"x", 8, 3)];
    let (out, next) = dirents(&e, 4096, 0);
    assert_eq!(next, 3);
    // reclen: (19 + name + 1 + 7) & !7
    assert_eq!(out.len(), 24 + 32 + 24);
    assert_eq!(u64_at(&out, 0), 1);
    assert_eq!(u64_at(&out, 8), 1);
    assert_eq!(u16::from_le_bytes([out[16], out[17]]), 24);
    assert_eq!(out[18], 8);
    assert_eq!(&out[19..21], b".\0");
    assert_eq!(&out[24 + 19..24 + 19 + 10], b"hello.txt\0");
    // Only the first two fit in 56 bytes
    let (out, next) = dirents(&e, 56, 0);
    assert_eq!((out.len(), next), (56, 2));
    // Nothing fits: the cookie stays
    let (out, next) = dirents(&e, 10, 5);
    assert_eq!((out.len(), next), (0, 5));
}

#[test]
fn old_dirents_keep_the_type_in_the_last_byte() {
    let e = [entry(b"abc", 7, 2)];
    let (out, next) = dirents_old(&e, 4096, 0);
    assert_eq!(next, 2);
    assert_eq!(out.len(), 24);
    assert_eq!(u16::from_le_bytes([out[16], out[17]]), 24);
    assert_eq!(&out[18..22], b"abc\0");
    assert_eq!(out[23], 8);
    // the same record length as getdents64's (the kernel converts in place)
    assert_eq!(dirents(&e, 4096, 0).0.len(), out.len());
    assert_eq!(dirents_old(&e, 23, 0).0.len(), 0);
}

#[test]
fn statfs_of_the_pool() {
    let b = statfs(1000, 400, 50, [0x4859_4452, 0x5a46_5301]);
    assert_eq!(u64_at(&b, 0) as i64, ZFS_SUPER_MAGIC);
    assert_eq!(u64_at(&b, 8), 4096);
    assert_eq!((u64_at(&b, 16), u64_at(&b, 24), u64_at(&b, 32)), (1000, 400, 400));
    assert_eq!((u64_at(&b, 40), u64_at(&b, 48)), (1_000_050, 1_000_000));
    assert_eq!((u32_at(&b, 56), u32_at(&b, 60)), (0x4859_4452, 0x5a46_5301));
    assert_eq!((u64_at(&b, 64), u64_at(&b, 72)), (255, 4096));
}

// ----------------------------------------------------------------------
// Decisions
// ----------------------------------------------------------------------

#[test]
fn which_opens_are_served_here() {
    assert!(servable(O_RDONLY));
    assert!(servable(O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
    assert!(servable(O_WRONLY | O_APPEND));
    assert!(servable(O_CREAT | O_RDONLY));
    // reading with O_TRUNC truncates nothing (Linux leaves it to the file system)
    assert!(servable(O_RDONLY | O_TRUNC));
    // wave10 GV1: truncating, O_PATH and O_TMPFILE opens are served too
    assert!(servable(O_WRONLY | O_TRUNC));
    assert!(servable(O_PATH));
    assert!(servable(O_TMPFILE_MASK | O_DIRECTORY | O_RDWR_FLAG));
    // (O_TMPFILE needs O_DIRECTORY, takes no O_CREAT or O_PATH; O_CREAT | O_DIRECTORY is
    // the kernel's)
    assert!(!servable(O_TMPFILE_MASK | O_RDWR_FLAG));
    assert!(!servable(O_TMPFILE_MASK | O_DIRECTORY | O_CREAT | O_RDWR_FLAG));
    assert!(!servable(O_CREAT | O_DIRECTORY));
}

const O_RDWR_FLAG: u32 = 2;

#[test]
fn open_checks_types_in_the_kernels_order() {
    assert_eq!(decide(0o100644, O_RDONLY), Ok(MAY_READ));
    assert_eq!(decide(0o100644, O_WRONLY), Ok(MAY_WRITE));
    assert_eq!(decide(0o100644, O_RDWR_FLAG), Ok(MAY_READ | MAY_WRITE));
    assert_eq!(decide(0o040755, O_RDONLY | O_DIRECTORY), Ok(MAY_READ));
    assert_eq!(decide(0o100644, O_RDONLY | O_TRUNC), Ok(MAY_READ | MAY_WRITE));
    assert_eq!(decide(0o040755, O_WRONLY), Err(EISDIR));
    assert_eq!(decide(0o100644, O_DIRECTORY), Err(ENOTDIR));
    // A link (O_NOFOLLOW met one): ELOOP before anything else
    assert_eq!(decide(0o120777, O_DIRECTORY | O_WRONLY), Err(ELOOP));
    // Devices, FIFOs, sockets go to the kernel; with O_DIRECTORY they are ENOTDIR first
    for m in [0o020666, 0o060660, 0o010644, 0o140755] {
        assert_eq!(decide(m, O_RDONLY), Err(KERNEL), "{m:o}");
        assert_eq!(decide(m, O_DIRECTORY), Err(ENOTDIR), "{m:o}");
    }
}

#[test]
fn the_kernels_permission_rule() {
    let none = |_g: u32| false;
    let in100 = |g: u32| g == 100;
    // root: anything but executing a file without x bits
    assert!(may_access(0o000, 5, 5, 0, MAY_READ | MAY_WRITE, None, none));
    assert!(!may_access(0o100600, 5, 5, 0, MAY_EXEC, None, none));
    assert!(may_access(0o100700, 5, 5, 0, MAY_EXEC, None, none));
    assert!(may_access(0o040000, 5, 5, 0, MAY_EXEC, None, none));
    // owner, group, other
    assert!(may_access(0o100640, 1000, 100, 1000, MAY_READ | MAY_WRITE, None, none));
    assert!(!may_access(0o100640, 1000, 100, 1001, MAY_WRITE, None, in100));
    assert!(may_access(0o100640, 1000, 100, 1001, MAY_READ, None, in100));
    assert!(!may_access(0o100640, 1000, 100, 1001, MAY_READ, None, none));
    assert!(may_access(0o100604, 1000, 100, 1001, MAY_READ, None, none));
    // the owner class decides even when others may more
    assert!(!may_access(0o100047, 1000, 100, 1000, MAY_READ, None, in100));
    // an ACL's answer wins
    assert!(may_access(0o100000, 1000, 100, 1001, MAY_READ, Some(true), none));
    assert!(!may_access(0o100777, 1000, 100, 1001, MAY_READ, Some(false), none));
}

#[test]
fn paths_as_the_kernel_takes_them() {
    assert_eq!(check_path(b"", false), Err(ENOENT));
    assert_eq!(check_path(b"", true), Ok(()));
    assert_eq!(check_path(b"/usr/bin", false), Ok(()));
    let long = [b'a'; 256];
    let mut p = b"/x/".to_vec();
    p.extend_from_slice(&long);
    assert_eq!(check_path(&p, false), Err(ENAMETOOLONG));
    assert_eq!(check_path(&long[..255], false), Ok(()));
}

#[test]
fn an_open_installs_a_handle_named_as_the_kernel_names_it() {
    let mut c = LxCall::EMPTY;
    c.at_kind = LX_AT_CWD;
    let d = handle_desc(&c, 77, 0, false, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT, b"a/b", -100).unwrap();
    assert_eq!((d.ino, d.mnt, d.is_dir, d.path_kind), (77, 0, 0, LX_FHP_CWD));
    // kept: access mode, O_APPEND, O_NONBLOCK, O_DIRECTORY, O_PATH; and O_CLOEXEC for the descriptor
    assert_eq!(d.flags, O_CLOEXEC);
    assert_eq!(&d.path[..d.path_len as usize], b"a/b");
    let d = handle_desc(&c, 78, 0, true, O_DIRECTORY, b"/etc", -100).unwrap();
    assert_eq!((d.is_dir, d.path_kind, d.flags), (1, LX_FHP_ABS, O_DIRECTORY));
    c.at_kind = LX_AT_DIR;
    let d = handle_desc(&c, 79, 0, false, O_WRONLY | O_APPEND | O_NONBLOCK, b"f", 5).unwrap();
    assert_eq!((d.path_kind, d.at_fd, d.flags), (LX_FHP_AT, 5, O_WRONLY | O_APPEND | O_NONBLOCK));
    let long = vec![b'a'; LX_FH_PATH_MAX + 1];
    assert_eq!(handle_desc(&c, 79, 0, false, 0, &long, 5).map(|_| ()), Err(KERNEL));
}

#[test]
fn call_arguments() {
    let a = [10, 11, 12, 13, 14, 15];
    assert_eq!(stat_args(4, &a), (10, 0, 11, false));
    assert_eq!(stat_args(6, &a), (10, 0x100, 11, false));
    assert_eq!(stat_args(262, &a), (11, 13, 12, false));
    assert_eq!(stat_args(332, &a), (11, 12, 14, true));
    assert_eq!(access_args(21, &a), (10, 11, 0));
    assert_eq!(access_args(269, &a), (11, 12, 0));
    assert_eq!(access_args(439, &a), (11, 12, 13));
}

#[test]
fn the_kernels_chown_and_sticky_rules() {
    let none = |_g: u32| false;
    let in27 = |g: u32| g == 27;
    assert!(chown_ok(0, 5, 5, 7, 7, none));
    // the owner may change the group to one of its own, not the owner
    assert!(chown_ok(1000, 1000, 100, u32::MAX, 27, in27));
    assert!(!chown_ok(1000, 1000, 100, u32::MAX, 28, in27));
    assert!(!chown_ok(1000, 1000, 100, 1001, u32::MAX, in27));
    assert!(chown_ok(1000, 1000, 100, 1000, 100, none));
    assert!(!chown_ok(1001, 1000, 100, u32::MAX, u32::MAX, none));
    // sticky: only root, the directory's owner or the entry's owner
    assert!(!sticky_denied(0o41777, 0, 5, 0));
    assert!(!sticky_denied(0o40777, 0, 5, 6));
    assert!(sticky_denied(0o41777, 0, 5, 6));
    assert!(!sticky_denied(0o41777, 6, 5, 6));
    assert!(!sticky_denied(0o41777, 0, 6, 6));
}


#[test]
fn readdir_requests_are_bounded() {
    assert_eq!(readdir_max(0), 1);
    assert_eq!(readdir_max(23), 1);
    assert_eq!(readdir_max(32768), 1365);
    assert_eq!(readdir_max(u32::MAX as usize), 4096);
}
