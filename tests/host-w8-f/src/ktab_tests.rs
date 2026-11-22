//! The kernel's mount rules on the shared table format, as vfs-server applies them.

use crate::ktab::*;
use crate::mntrec::{MntRec, MntTable, MK_NAMED, MK_TREE};
use alloc::string::String;
use alloc::vec::Vec;

/// A new namespace's table as the kernel's `initial_table` makes it (root object 10).
fn initial() -> MntTable {
    let mut t = MntTable { gen: 1, hash: 0, root: 1, system_root: 10, slots: Vec::new() };
    let m = |parent: u32, kind: u32, root: u64, mp: u64, fs: &str, path: &str, serves: Option<&str>| MntRec {
        id: 100 + parent,
        parent,
        kind,
        tmpfs: 0,
        mountpoint: mp,
        root,
        flags: MS_RELATIME,
        propagation: MS_SHARED,
        fstype: String::from(fs),
        source: String::from(fs),
        path: String::from(path),
        serves: serves.map(String::from),
    };
    t.push(m(0, MK_TREE, 10, 0, "zfs", "/", None));
    t.push(m(1, MK_NAMED, 0, 11, "proc", "/proc", Some("/proc")));
    t.push(m(1, MK_NAMED, 0, 12, "sysfs", "/sys", None));
    t.push(m(3, MK_NAMED, 0, 13, "cgroup2", "/sys/fs/cgroup", Some("/sys/fs/cgroup")));
    t.push(m(1, MK_NAMED, 0, 14, "devtmpfs", "/dev", None));
    t.push(m(5, MK_NAMED, 0, 15, "devpts", "/dev/pts", Some("/dev/pts")));
    t.push(m(1, MK_NAMED, 0, 16, "tmpfs", "/run", None));
    t
}

/// A directory of mount `mnt`.
fn dir(path: &str, ino: u64, mnt: u32) -> Loc {
    Loc { path: String::from(path), ino, mnt, is_dir: true }
}

/// A path that does not resolve.
fn unresolved(path: &str) -> Loc {
    Loc { path: String::from(path), ..Loc::default() }
}

struct FakeEnv {
    next: u32,
    made: Vec<(u32, u32, u32)>,
    fail: Option<i64>,
}

impl Env for FakeEnv {
    fn make_tmpfs(&mut self, mode: u32, uid: u32, gid: u32) -> Result<(u32, u64), i64> {
        if let Some(e) = self.fail {
            return Err(e);
        }
        self.next += 1;
        self.made.push((mode, uid, gid));
        Ok((self.next, 1000 + self.next as u64))
    }
}

fn env() -> FakeEnv {
    FakeEnv { next: 0, made: Vec::new(), fail: None }
}

/// Mounts a tmpfs at `/<name>` (object `ino` of the root mount); its index.
fn tmpfs_at(t: &mut MntTable, e: &mut FakeEnv, name: &str, ino: u64) -> u32 {
    let at = dir(&alloc::format!("/{}", name), ino, 1);
    mount(t, Err(EFAULT), &at, Some("tmpfs"), Some("none"), MS_NOSUID, Some("mode=755,uid=5"), (1000, 1000), e).unwrap();
    t.slots.len() as u32
}

/// Mounts a tmpfs on `at`; its index.
fn tmpfs_on(t: &mut MntTable, e: &mut FakeEnv, at: &Loc) -> u32 {
    mount(t, Err(EFAULT), at, Some("tmpfs"), None, 0, None, (0, 0), e).unwrap();
    t.slots.len() as u32
}

#[test]
fn paths_normalize_and_rebase_as_the_kernel() {
    assert_eq!(normalize("/a/./b//c/../d"), "/a/b/d");
    assert_eq!(normalize("/../.."), "/");
    assert_eq!(normalize(""), "/");
    assert_eq!(rebase("/a/b/c", "/a", "/x").as_deref(), Some("/x/b/c"));
    assert_eq!(rebase("/a", "/a", "/").as_deref(), Some("/"));
    assert_eq!(rebase("/ab", "/a", "/x"), None);
    assert_eq!(rebase("/q", "/", "/old").as_deref(), Some("/old/q"));
}

#[test]
fn small_rules() {
    assert!(is_fuse_type("fuse"));
    assert!(is_fuse_type("fuse.sshfs"));
    assert!(!is_fuse_type("fuseblk"));
    assert_eq!(serves_of("proc"), Some("/proc"));
    assert_eq!(serves_of("cgroup"), Some("/sys/fs/cgroup"));
    assert_eq!(serves_of("mqueue"), None);
    assert!(lenient(MS_REMOUNT));
    assert!(lenient(MS_PRIVATE | MS_REC));
    assert!(!lenient(MS_PRIVATE | MS_BIND));
    assert!(lenient(MS_REMOUNT | MS_BIND));
    assert!(!lenient(0));
    assert_eq!(tmpfs_options(None, 3, 4), (0o1777, 3, 4));
    assert_eq!(tmpfs_options(Some("size=1m,mode=0700,gid=9"), 3, 4), (0o700, 3, 9));
    assert_eq!(tmpfs_options(Some("mode=zz,uid=x"), 3, 4), (0o1777, 3, 4));
    assert_eq!(tmpfs_options(Some("mode=17777"), 0, 0), (0o7777, 0, 0));
}

#[test]
fn tmpfs_mount_is_a_tree_with_its_id() {
    let mut t = initial();
    let mut e = env();
    let i = tmpfs_at(&mut t, &mut e, "mnt", 20);
    let m = t.get(i).unwrap();
    assert_eq!((m.id, m.parent, m.kind, m.tmpfs, m.mountpoint, m.root), (0, 1, MK_TREE, 1, 20, 1001));
    assert_eq!((m.fstype.as_str(), m.source.as_str(), m.path.as_str()), ("tmpfs", "none", "/mnt"));
    assert_eq!(m.flags, MS_NOSUID);
    assert_eq!(e.made, [(0o755, 5, 1000)]);
    // the source name defaults to the type
    let at = dir("/m2", 21, 1);
    mount(&mut t, Err(EFAULT), &at, Some("ramfs"), None, 0, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.get(t.slots.len() as u32).unwrap().source, "ramfs");
    assert!(t.check().is_ok());
}

#[test]
fn new_mount_errors() {
    let mut t = initial();
    let mut e = env();
    let at = dir("/mnt", 20, 1);
    assert_eq!(mount(&mut t, Err(EFAULT), &at, None, None, 0, None, (0, 0), &mut e), Err(EFAULT));
    assert_eq!(mount(&mut t, Err(EFAULT), &at, Some("ext4"), None, 0, None, (0, 0), &mut e), Err(ENODEV));
    assert_eq!(mount(&mut t, Err(EFAULT), &at, Some("sysfs"), None, 0, None, (0, 0), &mut e), Err(KERNEL));
    assert_eq!(mount(&mut t, Err(EFAULT), &at, Some("devtmpfs"), None, 0, None, (0, 0), &mut e), Err(KERNEL));
    let file = Loc { is_dir: false, ..at.clone() };
    assert_eq!(mount(&mut t, Err(EFAULT), &file, Some("tmpfs"), None, 0, None, (0, 0), &mut e), Err(ENOTDIR));
    e.fail = Some(-28);
    assert_eq!(mount(&mut t, Err(EFAULT), &at, Some("tmpfs"), None, 0, None, (0, 0), &mut e), Err(-28));
    assert_eq!(t, initial(), "nothing changed by a failed call");
}

#[test]
fn named_mounts_are_listed_with_their_served_path() {
    let mut t = initial();
    let mut e = env();
    let at = dir("/newproc", 30, 1);
    mount(&mut t, Err(EFAULT), &at, Some("proc"), Some("proc"), MS_NOSUID | MS_NOEXEC | (1 << 40), None, (0, 0), &mut e).unwrap();
    let m = t.get(t.slots.len() as u32).unwrap();
    assert_eq!((m.kind, m.root, m.serves.as_deref(), m.flags), (MK_NAMED, 0, Some("/proc"), MS_NOSUID | MS_NOEXEC));
    let at = dir("/mq", 31, 1);
    mount(&mut t, Err(EFAULT), &at, Some("mqueue"), None, 0, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.get(t.slots.len() as u32).unwrap().serves, None);
    assert!(e.made.is_empty());
}

#[test]
fn bind_takes_the_source_mounts_kind() {
    let mut t = initial();
    let mut e = env();
    let tm = tmpfs_at(&mut t, &mut e, "mnt", 20);
    // a directory inside the tmpfs, bound elsewhere: a tree of the same tmpfs
    let src = dir("/mnt/sub", 1500, tm);
    let at = dir("/b", 40, 1);
    mount(&mut t, Ok(&src), &at, None, Some("/mnt/sub"), MS_BIND | MS_RDONLY, None, (0, 0), &mut e).unwrap();
    let m = t.get(t.slots.len() as u32).unwrap();
    assert_eq!((m.kind, m.tmpfs, m.root, m.mountpoint, m.parent, m.flags), (MK_TREE, 1, 1500, 40, 1, MS_RDONLY));
    assert_eq!((m.fstype.as_str(), m.path.as_str()), ("tmpfs", "/b"));
    // a pool directory: not a tmpfs
    let src = dir("/usr", 50, 1);
    let at = dir("/c", 41, 1);
    mount(&mut t, Ok(&src), &at, None, None, MS_BIND, None, (0, 0), &mut e).unwrap();
    let m = t.get(t.slots.len() as u32).unwrap();
    assert_eq!((m.tmpfs, m.fstype.as_str(), m.root), (0, "zfs", 50));
}

#[test]
fn bind_errors() {
    let mut t = initial();
    let mut e = env();
    let at = dir("/b", 40, 1);
    assert_eq!(mount(&mut t, Err(EFAULT), &at, None, None, MS_BIND, None, (0, 0), &mut e), Err(EFAULT));
    assert_eq!(mount(&mut t, Err(-2), &at, None, None, MS_BIND, None, (0, 0), &mut e), Err(-2));
    let file = Loc { path: String::from("/etc/passwd"), ino: 60, mnt: 1, is_dir: false };
    assert_eq!(mount(&mut t, Ok(&file), &at, None, None, MS_BIND, None, (0, 0), &mut e), Err(ENOTDIR));
    // a file onto a file is fine
    let fat = Loc { path: String::from("/f"), ino: 61, mnt: 1, is_dir: false };
    assert!(mount(&mut t, Ok(&file), &fat, None, None, MS_BIND, None, (0, 0), &mut e).is_ok());
    // a source in a mount the table does not have
    let ghost = dir("/x", 70, 99);
    assert_eq!(mount(&mut t, Ok(&ghost), &at, None, None, MS_BIND, None, (0, 0), &mut e), Err(EINVAL));
}

#[test]
fn recursive_bind_copies_the_submounts() {
    let mut t = initial();
    let mut e = env();
    // /data (tmpfs) with /data/inner (tmpfs) below it
    let d = tmpfs_at(&mut t, &mut e, "data", 20);
    let inner_idx = tmpfs_on(&mut t, &mut e, &dir("/data/inner", 1101, d));
    let src = dir("/data", 1001, d);
    let at = dir("/copy", 80, 1);
    mount(&mut t, Ok(&src), &at, None, None, MS_BIND | MS_REC, None, (0, 0), &mut e).unwrap();
    let n = t.slots.len() as u32;
    let top = t.get(n - 1).unwrap().clone();
    let sub = t.get(n).unwrap().clone();
    assert_eq!((top.path.as_str(), top.root, top.parent), ("/copy", 1001, 1));
    assert_eq!((sub.path.as_str(), sub.parent, sub.root, sub.id, sub.propagation), ("/copy/inner", n - 1, t.get(inner_idx).unwrap().root, 0, 0));
    // without MS_REC: only the top
    let at2 = dir("/copy2", 81, 1);
    mount(&mut t, Ok(&src), &at2, None, None, MS_BIND, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.slots.len() as u32, n + 1);
    assert!(t.check().is_ok());
}

#[test]
fn move_carries_the_subtree() {
    let mut t = initial();
    let mut e = env();
    let a = tmpfs_at(&mut t, &mut e, "a", 20);
    let s = tmpfs_on(&mut t, &mut e, &dir("/a/s", 1008, a));
    let src = dir("/a", 1001, a);
    let to = dir("/z", 90, 1);
    mount(&mut t, Ok(&src), &to, None, None, MS_MOVE, None, (0, 0), &mut e).unwrap();
    let am = t.get(a).unwrap();
    assert_eq!((am.path.as_str(), am.mountpoint, am.parent), ("/z", 90, 1));
    assert_eq!(t.get(s).unwrap().path, "/z/s");
    // into itself
    let inside = dir("/z/s/x", 5, s);
    assert_eq!(mount(&mut t, Ok(&dir("/z", 1001, a)), &inside, None, None, MS_MOVE, None, (0, 0), &mut e), Err(EINVAL));
    // not a mount's root
    assert_eq!(mount(&mut t, Ok(&dir("/z/q", 1234, a)), &to, None, None, MS_MOVE, None, (0, 0), &mut e), Err(EINVAL));
    // the root
    assert_eq!(mount(&mut t, Ok(&dir("/", 10, 1)), &to, None, None, MS_MOVE, None, (0, 0), &mut e), Err(EINVAL));
    // no source
    assert_eq!(mount(&mut t, Err(EFAULT), &to, None, None, MS_MOVE, None, (0, 0), &mut e), Err(EFAULT));
}

#[test]
fn remount_and_propagation() {
    let mut t = initial();
    let mut e = env();
    let a = tmpfs_at(&mut t, &mut e, "a", 20);
    let root = dir("/a", 1001, a);
    mount(&mut t, Err(EFAULT), &root, None, None, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOEXEC, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.get(a).unwrap().flags, MS_RDONLY | MS_NOEXEC);
    // a named mount by its path (it does not resolve: 0, 0)
    mount(&mut t, Err(EFAULT), &unresolved("/proc"), None, None, MS_REMOUNT | MS_RDONLY, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.get(2).unwrap().flags, MS_RDONLY);
    // not a mount point
    assert_eq!(mount(&mut t, Err(EFAULT), &dir("/etc", 33, 1), None, None, MS_REMOUNT, None, (0, 0), &mut e), Err(EINVAL));
    // propagation: alone, recursive from the root
    mount(&mut t, Err(EFAULT), &dir("/", 10, 1), None, None, MS_PRIVATE | MS_REC, None, (0, 0), &mut e).unwrap();
    assert!(t.live().all(|(_, m)| m.propagation == MS_PRIVATE));
    mount(&mut t, Err(EFAULT), &root, None, None, MS_SLAVE, None, (0, 0), &mut e).unwrap();
    assert_eq!(t.get(a).unwrap().propagation, MS_SLAVE);
    assert_eq!(t.get(1).unwrap().propagation, MS_PRIVATE);
    // on a path that does not resolve: nothing (the kernel's mount 0)
    let before = t.clone();
    mount(&mut t, Err(EFAULT), &unresolved("/nope"), None, None, MS_SHARED, None, (0, 0), &mut e).unwrap();
    assert_eq!(t, before);
}

#[test]
fn umount_rules() {
    let mut t = initial();
    let mut e = env();
    let a = tmpfs_at(&mut t, &mut e, "a", 20);
    let s = tmpfs_on(&mut t, &mut e, &dir("/a/s", 1008, a));
    let root = dir("/a", 1001, a);
    assert_eq!(umount(&mut t, &root, 0), Err(EBUSY));
    assert_eq!(umount(&mut t, &dir("/etc", 33, 1), 0), Err(EINVAL));
    assert_eq!(umount(&mut t, &dir("/", 10, 1), MNT_DETACH), Err(EINVAL));
    // the leaf, then the rest
    let sroot = t.get(s).unwrap().root;
    umount(&mut t, &dir("/a/s", sroot, s), 0).unwrap();
    assert!(t.get(s).is_none());
    assert_eq!(t.slots.len() as u32, s, "slots are never reused");
    umount(&mut t, &root, 0).unwrap();
    assert!(t.get(a).is_none());
    // lazily, with children
    let b = tmpfs_at(&mut t, &mut e, "b", 21);
    let broot = dir("/b", t.get(b).unwrap().root, b);
    let bs = tmpfs_on(&mut t, &mut e, &dir("/b/s", 5555, b));
    umount(&mut t, &broot, MNT_DETACH).unwrap();
    assert!(t.get(b).is_none() && t.get(bs).is_none());
    // a named mount by path
    umount(&mut t, &unresolved("/dev/pts"), 0).unwrap();
    assert!(t.get(6).is_none());
    assert!(t.check().is_ok());
}

#[test]
fn pivot_root_swaps_the_root() {
    let mut t = initial();
    let mut e = env();
    let n = tmpfs_at(&mut t, &mut e, "newroot", 20);
    let nroot = t.get(n).unwrap().root;
    let new_root = dir("/newroot", nroot, n);
    let put_old = dir("/newroot/old", 777, n);
    let d = pivot_root(&mut t, &new_root, &put_old).unwrap();
    assert_eq!(d.pivot, Some((10, nroot, n)));
    assert_eq!(t.root, n);
    let nm = t.get(n).unwrap();
    assert_eq!((nm.parent, nm.mountpoint, nm.path.as_str()), (0, 0, "/"));
    let old = t.get(1).unwrap();
    assert_eq!((old.parent, old.mountpoint, old.path.as_str()), (n, 777, "/old"));
    assert_eq!(t.get(2).unwrap().path, "/old/proc");
    assert_eq!(t.get(4).unwrap().path, "/old/sys/fs/cgroup");
    assert!(t.check().is_ok());
    // then the old root can go
    umount(&mut t, &dir("/old", 10, 1), MNT_DETACH).unwrap();
    assert!(t.live().all(|(i, _)| i == n));
}

#[test]
fn pivot_root_errors() {
    let mut t = initial();
    let mut e = env();
    let n = tmpfs_at(&mut t, &mut e, "newroot", 20);
    let nroot = t.get(n).unwrap().root;
    let before = t.clone();
    // not a mount's root
    assert_eq!(pivot_root(&mut t, &dir("/etc", 33, 1), &dir("/etc/o", 34, 1)), Err(EINVAL));
    // the current root
    assert_eq!(pivot_root(&mut t, &dir("/", 10, 1), &dir("/o", 34, 1)), Err(EINVAL));
    // put_old outside new_root
    assert_eq!(pivot_root(&mut t, &dir("/newroot", nroot, n), &dir("/tmp", 35, 1)), Err(EINVAL));
    assert_eq!(t, before, "nothing changed by a failed call");
}

#[test]
fn mount_at_prefers_the_tree_root_then_the_latest_named() {
    let mut t = initial();
    let mut e = env();
    // a second proc on /proc: the latest one is the mount there
    mount(&mut t, Err(EFAULT), &dir("/proc", 11, 1), Some("proc"), None, 0, None, (0, 0), &mut e).unwrap();
    assert_eq!(mount_at(&t, &unresolved("/proc")), Some(t.slots.len() as u32));
    let a = tmpfs_at(&mut t, &mut e, "a", 20);
    assert_eq!(mount_at(&t, &dir("/a", 1001, a)), Some(a));
    assert_eq!(mount_at(&t, &dir("/a/x", 1002, a)), None);
}
