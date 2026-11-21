//! Mount tables: namespaces, mount/bind/move/umount, pivot_root, the walk's questions,
//! listings, the new mount API's rules, kept state.

use crate::mount::*;

const LINUX: SvcId = 1;
const PROC: SvcId = 5;

/// tmpfs instances numbered from 1, every known pseudo type served by linux-server.
#[derive(Default)]
struct Factory {
    made: Vec<(String, u32, u32)>,
}

impl FsFactory for Factory {
    fn new_tmpfs(&mut self, data: &str, euid: u32, egid: u32) -> Result<(u32, u64), i64> {
        if data.contains("bad") {
            return Err(EINVAL);
        }
        self.made.push((data.to_string(), euid, egid));
        Ok((self.made.len() as u32, 1))
    }
    fn served(&self, fstype: &str) -> Option<(SvcId, u64, String)> {
        match fstype {
            "devpts" => Some((LINUX, 0, "/pts".to_string())),
            "proc" => Some((PROC, 3, "/".to_string())),
            "debugfs" => None,
            _ => Some((LINUX, 0, "/".to_string())),
        }
    }
}

/// The pool: `/`=1, /proc=10, /sys=11, /sys/fs/cgroup=12, /dev=13, /dev/pts=14,
/// /tmp=20, /usr=30, /usr/share=31, /mnt=40, /mnt2=41, /run=50, /newroot=60.
fn pool(p: &str) -> u64 {
    match p {
        "/" => 1,
        "/proc" => 10,
        "/sys" => 11,
        "/sys/fs/cgroup" => 12,
        "/dev" => 13,
        "/dev/pts" => 14,
        "/tmp" => 20,
        "/usr" => 30,
        "/usr/share" => 31,
        "/mnt" => 40,
        "/mnt2" => 41,
        "/run" => 50,
        "/newroot" => 60,
        _ => 0,
    }
}

fn root_caller(ns: NsId) -> Caller {
    Caller { ns, caps: CAP_SYS_ADMIN | CAP_SYS_CHROOT, euid: 0, egid: 0 }
}

fn dir(path: &str, mnt: MntIdx) -> Loc {
    Loc::new(path, pool(path), mnt, true)
}

/// ns 0 (by name) and ns 7 (a copy).
fn tables() -> MountTables {
    let mut t = MountTables::new();
    let fx = t.install(0, 1, &standard_layout(PROC, LINUX, true, &pool));
    assert_eq!(fx.hold, vec![1, 50]);
    t.copy_ns(0, 7, &pool).unwrap();
    t
}

fn paths(t: &MountTables, ns: NsId) -> Vec<String> {
    t.ns(ns).unwrap().live().map(|(_, m)| m.path.clone()).collect()
}

#[test]
fn helpers() {
    assert_eq!(normalize("//a/./b/../c/"), "/a/c");
    assert_eq!(normalize("/.."), "/");
    assert_eq!(normalize(""), "/");
    assert_eq!(rebase("/a/b/c", "/a", "/x").as_deref(), Some("/x/b/c"));
    assert_eq!(rebase("/a", "/a", "/").as_deref(), Some("/"));
    assert_eq!(rebase("/ab", "/a", "/"), None);
    assert_eq!(rebase("/b", "/", "/old").as_deref(), Some("/old/b"));
    assert!(known_fs("tmpfs") && known_fs("mqueue") && !known_fs("ext4"));
    assert_eq!(fs_magic("tmpfs"), 0x0102_1994);
    assert_eq!(fs_magic("zfs"), 0x2fc1_2fc1);
    assert_eq!(fs_magic("proc"), 0x9fa0);
    assert_eq!(fs_magic("sysfs"), 0x6265_6572);
    assert_eq!(fs_magic("devpts"), 0x1cd1);
    assert_eq!(fs_magic("cgroup2"), 0x6367_7270);
    assert_eq!(fs_magic("mqueue"), 0x1980_2202);
    assert_eq!(fs_magic("x"), 0);
    assert_eq!(mount_opts(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME | MS_NOSYMFOLLOW), "ro,nosuid,nodev,noexec,noatime,nodiratime,nosymfollow");
    assert_eq!(mount_opts(MS_RELATIME), "rw,relatime");
}

#[test]
fn admin_and_chroot_rules() {
    let c = Caller { ns: 7, caps: 0, euid: 1000, egid: 1000 };
    assert_eq!(may_admin(&c, true), Err(EPERM));
    assert_eq!(may_admin(&root_caller(0), true), Err(EPERM));
    assert_eq!(may_admin(&root_caller(0), false), Ok(()));
    assert_eq!(may_admin(&root_caller(7), true), Ok(()));
    let d = dir("/usr", 1);
    assert_eq!(chroot_check(0, &d), Err(EPERM));
    assert_eq!(chroot_check(CAP_SYS_CHROOT, &d), Ok(()));
    assert_eq!(chroot_check(CAP_SYS_CHROOT, &Loc::new("/f", 5, 1, false)), Err(ENOTDIR));
}

#[test]
fn initial_namespace_by_name() {
    let t = tables();
    let ns = t.ns(0).unwrap();
    assert_eq!(paths(&t, 0), ["/", "/proc", "/sys", "/sys/fs/cgroup", "/dev", "/dev/pts", "/run"]);
    assert_eq!(ns.root, 1);
    let m = |i| ns.get(i).unwrap();
    assert!(m(2).by_name && m(6).by_name && !m(7).by_name);
    assert_eq!((m(4).parent, m(6).parent), (3, 5), "parents found by path");
    assert_eq!(ns.by_name("/proc/self/stat"), Some((2, "/self/stat".to_string())));
    assert_eq!(ns.by_name("/proc"), Some((2, "/".to_string())));
    assert_eq!(ns.by_name("/sys/fs/cgroup/x"), Some((4, "/x".to_string())), "the deepest");
    assert_eq!(ns.by_name("/dev/pts/0").map(|v| v.0), Some(6));
    assert_eq!(ns.by_name("/usr/bin"), None);
    assert_eq!(ns.by_name("/procfoo"), None);
    let r = ns.redirect(6, "/0").unwrap();
    assert_eq!(r, Redirect { svc: LINUX, obj: 0, mnt: 6, path: "/pts/0".to_string() });
    assert_eq!(ns.redirect(2, "/self").unwrap().svc, PROC);
    // Group 7-1's question for names under the caller's root
    assert_eq!(ns.pseudo_at_root(b"proc"), Some((PROC, 0)));
    assert_eq!(ns.pseudo_at_root(b"dev"), Some((LINUX, 0)));
    assert_eq!(ns.pseudo_at_root(b"pts"), None);
    assert_eq!(ns.pseudo_at_root(b"run"), None, "not served elsewhere");
    assert_eq!(ns.pseudo_at_root(b"usr"), None);
    assert_eq!(ns.redirect(4, "x").unwrap().path, "/fs/cgroup/x");
    assert_eq!(ns.redirect(1, "/x"), None, "the pool is not redirected");
    assert_eq!(ns.redirect(99, "/x"), None);
    // /run lists the pool's directory as a tmpfs
    assert_eq!(ns.child_at(1, 50), Some(7));
    assert_eq!(m(7).root, 50);
    assert_eq!(ns.child_at(1, 10), None, "by-name mounts are not found by object");
    assert_eq!(ns.up(1), None);
    assert_eq!(ns.up(2), None, "a by-name mount has no mount point to climb to");
    assert_eq!(ns.up(7), Some((1, 50)));
    assert_eq!(ns.len(), 7);
    // Mounting there is refused while the layout is fixed
    let mut t = t;
    let mut f = Factory::default();
    assert_eq!(t.mount(&root_caller(0), None, &dir("/tmp", 1), Some("tmpfs"), None, 0, None, &mut f), Err(EPERM));
}

#[test]
fn standard_layout_on_objects() {
    let l = standard_layout(PROC, LINUX, false, &|p| if p == "/run" { 0 } else { pool(p) });
    assert_eq!(l.len(), 5, "no /run when the pool has none");
    assert_eq!(l[0].mountpoint, 10);
    let mut t = MountTables::new();
    t.install(3, 1, &l);
    assert_eq!(t.ns(3).unwrap().child_at(1, 10), Some(2));
    assert_eq!(t.ns(3).unwrap().child_at(1, 13), Some(5));
    // Installing again replaces the table and lets the old roots go
    let fx = t.install(3, 1, &[]);
    assert_eq!(fx.release, vec![1]);
    assert_eq!(fx.hold, vec![1]);
}

#[test]
fn copy_keeps_indices_and_resolves_by_name_mounts() {
    let mut t = tables();
    let (a, b) = (t.ns(0).unwrap().clone(), t.ns(7).unwrap().clone());
    assert_eq!(a.mounts.len(), b.mounts.len());
    for ((i, x), (j, y)) in a.live().zip(b.live()) {
        assert_eq!((i, &x.path, x.backend), (j, &y.path, y.backend));
        assert_ne!(x.id, y.id, "new mount IDs");
        // Below a served mount (cgroup2 under /sys, devpts under /dev) they stay by name
        assert_eq!(y.by_name, i == 4 || i == 6, "{}", y.path);
    }
    assert_eq!(b.child_at(1, 10), Some(2));
    assert_eq!(b.child_at(5, 14), None, "/dev's objects are linux-server's");
    assert_eq!(b.by_name("/dev/pts/3"), Some((6, "/3".to_string())));
    assert_eq!(b.up(2), Some((1, 10)));
    assert_eq!(t.copy_ns(0, 7, &pool), Err(EBUSY));
    assert_eq!(t.copy_ns(99, 8, &pool), Err(EINVAL));
    // A by-name mount whose path has no object stays by name
    let fx = t.copy_ns(0, 8, &|p| if p == "/proc" { 0 } else { pool(p) }).unwrap();
    assert!(t.ns(8).unwrap().get(2).unwrap().by_name);
    assert_eq!(fx.hold, vec![1, 50]);
}

#[test]
fn tmpfs_mount_stack_and_umount() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = Caller { ns: 7, caps: CAP_SYS_ADMIN, euid: 5, egid: 6 };
    let fx = t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), Some("none"), MS_NOSUID, Some("size=1m"), &mut f).unwrap();
    assert_eq!(fx, Effects::default());
    assert_eq!(f.made, vec![("size=1m".to_string(), 5, 6)]);
    let ns = t.ns(7).unwrap();
    let i = ns.child_at(1, 20).unwrap();
    let m = ns.get(i).unwrap();
    assert_eq!((m.backend, m.root, m.parent, m.flags, m.source.as_str()), (Backend::Tmpfs(1), 1, 1, MS_NOSUID, "none"));
    assert!(ns.is_tmpfs(i) && !ns.is_tmpfs(1));
    assert_eq!(ns.up(i), Some((1, 20)));
    let info = t.mountinfo(7).unwrap();
    let line = info.lines().last().unwrap();
    assert!(line.ends_with("/tmp rw,nosuid - tmpfs none rw,size=1m"), "{line}");
    assert!(t.mounts(7).unwrap().ends_with("none /tmp tmpfs rw,size=1m 0 0\n"));
    // Stacked: a second tmpfs on the first's root
    let top = Loc::new("/tmp", 1, i, true);
    let (j, _) = t.mount_new(&c, &top, "tmpfs", "tmpfs", 0, "", &mut f).unwrap();
    assert_eq!(t.ns(7).unwrap().child_at(i, 1), Some(j));
    assert_eq!(t.ns(7).unwrap().covering(1, 20), Some(j), "the top of the stack");
    assert_eq!(t.ns(7).unwrap().covering(j, 1), None);
    assert_eq!(t.ns(7).unwrap().covering(1, 30), None);
    assert_eq!(t.ns(7).unwrap().mount_at(&top), Some(i));
    // Busy: /tmp has a mount below it
    assert_eq!(t.umount(&c, &top, 0), Err(EBUSY));
    let fx = t.umount(&c, &Loc::new("/tmp", 1, j, true), 0).unwrap();
    assert_eq!(fx.tmpfs_gone, vec![2]);
    let fx = t.umount(&c, &top, MNT_FORCE).unwrap();
    assert_eq!(fx.tmpfs_gone, vec![1]);
    assert_eq!(t.ns(7).unwrap().child_at(1, 20), None);
    // Errors
    assert_eq!(t.mount(&c, None, &Loc::new("/f", 5, 1, false), Some("tmpfs"), None, 0, None, &mut f), Err(ENOTDIR));
    assert_eq!(t.mount(&c, None, &dir("/tmp", 1), Some("ext4"), None, 0, None, &mut f), Err(ENODEV));
    assert_eq!(t.mount(&c, None, &dir("/tmp", 1), Some("debugfs"), None, 0, None, &mut f), Err(ENODEV));
    assert_eq!(t.mount(&c, None, &dir("/tmp", 1), None, None, 0, None, &mut f), Err(EFAULT));
    assert_eq!(t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), None, 0, Some("bad"), &mut f), Err(EINVAL));
    assert_eq!(t.mount_new(&root_caller(99), &dir("/tmp", 1), "tmpfs", "x", 0, "", &mut f), Err(EINVAL));
    assert_eq!(t.umount(&c, &dir("/usr", 1), 0), Err(EINVAL), "not a mount point");
    assert_eq!(t.umount(&c, &Loc::new("/", 1, 1, true), MNT_DETACH), Err(EINVAL), "the root");
    assert_eq!(t.umount(&c, &top, 0x100), Err(EINVAL));
}

#[test]
fn tmpfs_shared_by_two_namespaces() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    t.copy_ns(7, 8, &pool).unwrap();
    let i = t.ns(7).unwrap().child_at(1, 20).unwrap();
    assert!(t.tmpfs_in_use(1));
    let fx = t.umount(&c, &Loc::new("/tmp", 1, i, true), 0).unwrap();
    assert!(fx.tmpfs_gone.is_empty(), "ns 8 still mounts it");
    let fx = t.collect(&[7]);
    assert_eq!(fx.tmpfs_gone, vec![1]);
    assert_eq!(fx.release, vec![1, 50]);
    assert!(t.ns(8).is_none());
    assert!(t.ns(0).is_some(), "the initial namespace stays");
    assert_eq!(t.collect(&[7]), Effects::default());
}

#[test]
fn pseudo_mounts_are_served_elsewhere() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    // mount -t proc proc /mnt, and devpts on a path with no object
    t.mount(&c, None, &dir("/mnt", 1), Some("proc"), Some("proc"), MS_NOSUID | MS_NODEV | MS_NOEXEC, None, &mut f).unwrap();
    let ns = t.ns(7).unwrap();
    let i = ns.child_at(1, 40).unwrap();
    assert_eq!(ns.redirect(i, "/self/stat").unwrap(), Redirect { svc: PROC, obj: 3, mnt: i, path: "/self/stat".to_string() });
    assert_eq!(ns.get(i).unwrap().root, 0);
    let ghost = Loc::new("/dev/ptmx-dir", 0, 0, true);
    let (j, _) = t.mount_new(&c, &ghost, "devpts", "devpts", 0, "newinstance", &mut f).unwrap();
    let ns = t.ns(7).unwrap();
    assert!(ns.get(j).unwrap().by_name);
    assert_eq!(ns.get(j).unwrap().parent, 5, "under /dev");
    assert_eq!(ns.redirect(j, "0").unwrap().path, "/pts/0");
    assert_eq!(ns.by_name("/dev/ptmx-dir/0"), Some((j, "/0".to_string())));
    // A served mount is found by its path (the walk does not enter it by object)
    assert_eq!(ns.mount_at(&Loc::new("/mnt", 0, i, true)), Some(i));
    assert_eq!(ns.mount_at(&Loc::new("/proc", 0, 0, true)), Some(2));
    assert_eq!(ns.mount_at(&ghost), Some(j));
    let fx = t.umount(&c, &Loc::new("/proc", 0, 0, true), 0).unwrap();
    assert_eq!(fx, Effects::default());
    assert_eq!(t.ns(7).unwrap().child_at(1, 10), None);
}

#[test]
fn bind_mounts() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    // /usr/share gets a tmpfs; then bind /usr to /mnt (plain) and /mnt2 (recursive)
    t.mount(&c, None, &dir("/usr/share", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    let src = dir("/usr", 1);
    let fx = t.mount(&c, Some(&src), &dir("/mnt", 1), None, None, MS_BIND | MS_RDONLY, None, &mut f).unwrap();
    assert_eq!(fx.hold, vec![30]);
    let fx = t.mount(&c, Some(&src), &dir("/mnt2", 1), None, None, MS_BIND | MS_REC, None, &mut f).unwrap();
    assert_eq!(fx.hold, vec![30]);
    let ns = t.ns(7).unwrap();
    let b = ns.child_at(1, 40).unwrap();
    let m = ns.get(b).unwrap();
    assert_eq!((m.root, m.backend, m.fs_root.as_str(), m.dev, m.flags), (30, Backend::Pool, "/usr", ns.get(1).unwrap().dev, MS_RDONLY));
    assert_eq!(ns.check_write(b), EROFS);
    assert_eq!(ns.check_write(1), 0);
    assert_eq!(ns.child_at(b, 31), None, "not recursive: no /mnt/share");
    let r = ns.child_at(1, 41).unwrap();
    let share = ns.child_at(r, 31).unwrap();
    let s = ns.get(share).unwrap();
    assert_eq!((s.path.as_str(), s.backend), ("/mnt2/share", Backend::Tmpfs(1)));
    assert_eq!(ns.up(share), Some((r, 31)));
    // A bind of a directory below a tmpfs root keeps its place in mountinfo
    let tm = ns.child_at(1, 31).unwrap();
    let sub = Loc::new("/usr/share/sub", 5, tm, true);
    t.bind(7, &sub, &dir("/tmp", 1), 0).unwrap();
    let ns = t.ns(7).unwrap();
    let bt = ns.child_at(1, 20).unwrap();
    assert_eq!((ns.get(bt).unwrap().fs_root.as_str(), ns.get(bt).unwrap().root), ("/sub", 5));
    assert!(t.mountinfo(7).unwrap().contains(" /sub /tmp rw - tmpfs tmpfs rw"));
    // Kinds must agree; a source is needed
    assert_eq!(t.bind(7, &Loc::new("/f", 5, 1, false), &dir("/mnt", 1), 0), Err(ENOTDIR));
    assert_eq!(t.mount(&c, None, &dir("/mnt", 1), None, None, MS_BIND, None, &mut f), Err(EFAULT));
    assert_eq!(t.bind(7, &Loc::new("/x", 5, 99, true), &dir("/mnt", 1), 0), Err(EINVAL));
    // The tmpfs stays while a bind of it is mounted
    let fx = t.umount(&c, &Loc::new("/usr/share", 1, tm, true), 0).unwrap();
    assert!(fx.tmpfs_gone.is_empty());
    // Unbindable sources
    t.set_propagation(7, &dir("/usr", 1), MS_UNBINDABLE, false).ok();
    let b2 = t.ns(7).unwrap().child_at(1, 40).unwrap();
    t.set_propagation(7, &Loc::new("/mnt", 30, b2, true), MS_UNBINDABLE, false).unwrap();
    assert_eq!(t.bind(7, &Loc::new("/mnt", 30, b2, true), &dir("/run", 1), 0), Err(EINVAL));
}

#[test]
fn recursive_bind_skips_unbindable_and_outside() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    t.mount(&c, None, &dir("/usr/share", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    let tm = t.ns(7).unwrap().child_at(1, 31).unwrap();
    t.set_propagation(7, &Loc::new("/usr/share", 1, tm, true), MS_UNBINDABLE, false).unwrap();
    t.bind(7, &dir("/usr", 1), &dir("/mnt", 1), MS_REC).unwrap();
    let ns = t.ns(7).unwrap();
    let b = ns.child_at(1, 40).unwrap();
    assert_eq!(ns.child_at(b, 31), None);
    // An rbind of / copies everything under it; mounts of other trees keep their places
    let before = ns.len();
    t.bind(7, &Loc::new("/", 1, 1, true), &dir("/newroot", 1), MS_REC).unwrap();
    let ns = t.ns(7).unwrap();
    assert!(ns.len() > before + 5);
    assert!(paths(&t, 7).contains(&"/newroot/proc".to_string()));
    assert!(paths(&t, 7).contains(&"/newroot/dev/pts".to_string()));
}

#[test]
fn bind_of_a_served_file() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    // bwrap: --dev-bind /dev/null /tmp/null (the source in /dev, served by linux-server)
    let src = Loc::new("/dev/null", 0, 5, false);
    let dst = Loc::new("/tmp/null", 77, 1, false);
    let fx = t.mount(&c, Some(&src), &dst, None, None, MS_BIND, None, &mut f).unwrap();
    assert!(fx.hold.is_empty(), "nothing to hold in the pool");
    let ns = t.ns(7).unwrap();
    let i = ns.child_at(1, 77).unwrap();
    assert_eq!(ns.redirect(i, "").unwrap().path, "/null");
    assert_eq!(ns.get(i).unwrap().fstype, "devtmpfs");
    assert_eq!(ns.mount_at(&Loc::new("/tmp/null", 0, i, false)), Some(i));
}

#[test]
fn move_mount_rules() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    let i = t.ns(7).unwrap().child_at(1, 20).unwrap();
    let tmp = Loc::new("/tmp", 1, i, true);
    t.mount_new(&c, &Loc::new("/tmp/inner", 9, i, true), "tmpfs", "tmpfs", 0, "", &mut f).unwrap();
    t.mount(&c, Some(&tmp), &dir("/mnt", 1), None, None, MS_MOVE, None, &mut f).unwrap();
    let ns = t.ns(7).unwrap();
    assert_eq!(ns.child_at(1, 20), None);
    assert_eq!(ns.child_at(1, 40), Some(i));
    assert!(paths(&t, 7).contains(&"/mnt/inner".to_string()));
    let moved = Loc::new("/mnt", 1, i, true);
    assert_eq!(t.move_mount(7, &moved, &Loc::new("/mnt/inner/x", 3, i + 1, true)), Err(EINVAL), "into itself");
    assert_eq!(t.move_mount(7, &Loc::new("/", 1, 1, true), &dir("/mnt2", 1)), Err(EINVAL), "the root");
    assert_eq!(t.move_mount(7, &dir("/usr", 1), &dir("/mnt2", 1)), Err(EINVAL), "not a mount");
    assert_eq!(t.mount(&c, None, &dir("/mnt2", 1), None, None, MS_MOVE, None, &mut f), Err(EFAULT));
    assert_eq!(t.move_mount(99, &moved, &dir("/mnt2", 1)), Err(EINVAL));
}

#[test]
fn remount_and_flags() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), None, 0, Some("size=1m"), &mut f).unwrap();
    let i = t.ns(7).unwrap().child_at(1, 20).unwrap();
    let tmp = Loc::new("/tmp", 1, i, true);
    t.mount(&c, None, &tmp, None, None, MS_REMOUNT | MS_RDONLY | MS_NOEXEC | MS_NOSUID, Some("size=2m"), &mut f).unwrap();
    let ns = t.ns(7).unwrap();
    assert_eq!(ns.check_write(i), EROFS);
    assert_eq!(ns.exec_flags(i), (true, true));
    assert_eq!(ns.get(i).unwrap().sb_opts, "size=2m");
    // MS_BIND | MS_REMOUNT: only the per-mount flags
    t.mount(&c, None, &tmp, None, None, MS_REMOUNT | MS_BIND, Some("size=9m"), &mut f).unwrap();
    let ns = t.ns(7).unwrap();
    assert_eq!((ns.flags_of(i), ns.get(i).unwrap().sb_opts.as_str()), (0, "size=2m"));
    assert_eq!(ns.exec_flags(i), (false, false));
    assert_eq!(ns.flags_of(99), 0);
    assert_eq!(t.mount(&c, None, &dir("/usr", 1), None, None, MS_REMOUNT, None, &mut f), Err(EINVAL));
    // set_attrs (mount_setattr) recursive
    t.mount_new(&c, &Loc::new("/tmp/in", 4, i, true), "tmpfs", "tmpfs", 0, "", &mut f).unwrap();
    t.set_attrs(7, &tmp, MS_RDONLY | MS_NODEV, 0, true, MS_PRIVATE).unwrap();
    let ns = t.ns(7).unwrap();
    assert_eq!(ns.flags_of(i + 1), MS_RDONLY | MS_NODEV);
    assert_eq!(ns.get(i + 1).unwrap().propagation, MS_PRIVATE);
    t.set_attrs(7, &tmp, 0, MS_RDONLY, false, 0).unwrap();
    let ns = t.ns(7).unwrap();
    assert_eq!((ns.flags_of(i), ns.flags_of(i + 1)), (MS_NODEV, MS_RDONLY | MS_NODEV));
    assert_eq!(ns.get(i).unwrap().propagation, MS_PRIVATE, "prop 0 leaves it");
    assert_eq!(t.set_attrs(7, &dir("/usr", 1), 0, 0, false, 0), Err(EINVAL));
}

#[test]
fn propagation_flags_are_listed() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    assert!(t.mountinfo(7).unwrap().lines().next().unwrap().contains(" shared:"));
    t.mount(&c, None, &Loc::new("/", 1, 1, true), None, None, MS_PRIVATE | MS_REC, None, &mut f).unwrap();
    assert!(!t.mountinfo(7).unwrap().contains("shared:"));
    t.mount(&c, None, &Loc::new("/", 1, 1, true), None, None, MS_SHARED, None, &mut f).unwrap();
    let info = t.mountinfo(7).unwrap();
    assert_eq!(info.matches("shared:").count(), 1, "not recursive");
    // A location that is not a mount point: its mount
    t.set_propagation(7, &dir("/usr", 1), MS_SLAVE, false).unwrap();
    assert_eq!(t.ns(7).unwrap().get(1).unwrap().propagation, MS_SLAVE);
    assert_eq!(t.set_propagation(99, &dir("/usr", 1), MS_SLAVE, false), Err(EINVAL));
}

#[test]
fn pivot_root_like_bubblewrap() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    // mount -t tmpfs tmpfs /newroot; mkdir /newroot/oldroot (object 2 in the tmpfs)
    t.mount(&c, None, &dir("/newroot", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    let n = t.ns(7).unwrap().child_at(1, 60).unwrap();
    let new_root = Loc::new("/newroot", 1, n, true);
    let put_old = Loc::new("/newroot/oldroot", 2, n, true);
    // Errors first
    assert_eq!(t.pivot_root(&c, &dir("/usr", 1), &put_old), Err(EINVAL), "not a mount");
    assert_eq!(t.pivot_root(&c, &Loc::new("/", 1, 1, true), &put_old), Err(EINVAL), "the root");
    assert_eq!(t.pivot_root(&c, &new_root, &dir("/tmp", 1)), Err(EINVAL), "put_old outside");
    assert_eq!(t.pivot_root(&c, &new_root, &Loc::new("/newroot/f", 3, n, false)), Err(ENOTDIR));
    assert_eq!(t.pivot_root(&root_caller(0), &new_root, &put_old), Err(EPERM));
    let p = t.pivot_root(&c, &new_root, &put_old).unwrap();
    assert_eq!(p, Pivot { old_root: (1, 1), new_root: (n, 1) });
    let ns = t.ns(7).unwrap();
    assert_eq!(ns.root, n);
    let nm = ns.get(n).unwrap();
    assert_eq!((nm.path.as_str(), nm.parent, nm.mountpoint), ("/", 0, 0));
    let old = ns.get(1).unwrap();
    assert_eq!((old.path.as_str(), old.parent, old.mountpoint), ("/oldroot", n, 2));
    assert_eq!(ns.get(2).unwrap().path, "/oldroot/proc");
    assert_eq!(ns.child_at(n, 2), Some(1));
    assert_eq!(ns.up(1), Some((n, 2)));
    assert_eq!(ns.up(n), None);
    // umount -l /oldroot takes the whole old tree
    let fx = t.umount(&c, &Loc::new("/oldroot", 1, 1, true), MNT_DETACH).unwrap();
    assert_eq!(fx.release, vec![1, 50]);
    assert_eq!(paths(&t, 7), ["/"]);
}

#[test]
fn listmount_and_statmount() {
    let t = tables();
    let ns = t.ns(7).unwrap();
    let ids: Vec<u64> = ns.live().map(|(_, m)| UNIQUE_BASE + m.id as u64).collect();
    assert_eq!(t.listmount(7, LSMT_ROOT, 0, false, 100).unwrap(), ids);
    let root = ids[0];
    let kids = t.listmount(7, root, 0, false, 100).unwrap();
    assert_eq!(kids, vec![ids[1], ids[2], ids[4], ids[6]], "/proc /sys /dev /run");
    assert_eq!(t.listmount(7, root, ids[2], false, 100).unwrap(), vec![ids[4], ids[6]]);
    assert_eq!(t.listmount(7, root, 0, true, 2).unwrap(), vec![ids[6], ids[4]]);
    assert_eq!(t.listmount(7, root, ids[4], true, 100).unwrap(), vec![ids[2], ids[1]]);
    assert_eq!(t.listmount(7, 5, 0, false, 10), Err(ENOENT));
    assert_eq!(t.listmount(99, LSMT_ROOT, 0, false, 10), Err(EINVAL));
    // statmount of /proc: everything
    let all = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_PROPAGATE_FROM | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE | STATMOUNT_MNT_NS_ID | STATMOUNT_MNT_OPTS | STATMOUNT_SB_SOURCE;
    let b = t.statmount(7, ids[1], all, 4096).unwrap();
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let s_at = |o: usize| {
        let at = 512 + u32_at(o) as usize;
        let end = b[at..].iter().position(|&c| c == 0).unwrap();
        String::from_utf8(b[at..at + end].to_vec()).unwrap()
    };
    assert_eq!(u32_at(0) as usize, b.len());
    assert_eq!(u64_at(8), all);
    assert_eq!(u64_at(24), 0x9fa0);
    assert_eq!(u64_at(40), ids[1]);
    assert_eq!(u64_at(48), root);
    assert_eq!(u64_at(64), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC);
    assert_eq!(u64_at(72), MS_SHARED);
    assert_eq!(u64_at(112), 7);
    assert_eq!((s_at(36), s_at(108), s_at(104), s_at(124)), ("proc".into(), "/proc".into(), "/".into(), "proc".into()));
    assert_eq!(t.statmount(7, ids[1], all, 100), Err(EOVERFLOW));
    assert_eq!(t.statmount(7, 1, all, 4096), Err(ENOENT));
    assert_eq!(t.statmount(99, ids[1], all, 4096), Err(EINVAL));
    let b = t.statmount(7, root, STATMOUNT_SB_BASIC, 4096).unwrap();
    assert_eq!(b.len(), 512);
    // Private mounts and a read-only one
    let mut t = t;
    let mut f = Factory::default();
    t.mount(&root_caller(7), None, &dir("/tmp", 1), Some("tmpfs"), None, MS_RDONLY | MS_NOATIME, None, &mut f).unwrap();
    let id = UNIQUE_BASE + t.ns(7).unwrap().get(8).unwrap().id as u64;
    let b = t.statmount(7, id, STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC, 4096).unwrap();
    assert_eq!(u32::from_le_bytes(b[32..36].try_into().unwrap()), 1, "SB_RDONLY");
    assert_eq!(u64::from_le_bytes(b[72..80].try_into().unwrap()), MS_PRIVATE);
    assert_eq!(u64::from_le_bytes(b[64..72].try_into().unwrap()), MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOATIME);
}

#[test]
fn attr_conversions() {
    assert_eq!(attr_to_ms(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW), MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NODIRATIME | MS_NOSYMFOLLOW | MS_RELATIME);
    assert_eq!(attr_to_ms(MOUNT_ATTR_NOATIME), MS_NOATIME);
    assert_eq!(attr_to_ms(MOUNT_ATTR_STRICTATIME), 0);
    assert_eq!(ms_to_attr(0), MOUNT_ATTR_STRICTATIME);
    assert_eq!(ms_to_attr(MS_RELATIME | MS_NODEV), MOUNT_ATTR_NODEV);
    assert_eq!(ms_to_attr(MS_NOSYMFOLLOW | MS_NODIRATIME | MS_RELATIME), MOUNT_ATTR_NOSYMFOLLOW | MOUNT_ATTR_NODIRATIME);
}

fn attr_bytes(set: u64, clr: u64, prop: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[0..8].copy_from_slice(&set.to_le_bytes());
    v[8..16].copy_from_slice(&clr.to_le_bytes());
    v[16..24].copy_from_slice(&prop.to_le_bytes());
    v
}

#[test]
fn mount_setattr_arguments() {
    assert_eq!(parse_mount_attr(&attr_bytes(MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, 0, 32), 0), Ok((MS_RDONLY, MS_NOSUID, 0)));
    assert_eq!(parse_mount_attr(&attr_bytes(MOUNT_ATTR_NOATIME, 0, MS_PRIVATE, 32), AT_RECURSIVE), Ok((MS_NOATIME, MS_NOATIME | MS_RELATIME, MS_PRIVATE)));
    assert_eq!(parse_mount_attr(&attr_bytes(MOUNT_ATTR_STRICTATIME, 0, 0, 32), 0), Ok((0, MS_NOATIME | MS_RELATIME, 0)));
    assert_eq!(parse_mount_attr(&attr_bytes(0, 0, 0, 24), 0), Err(EINVAL));
    assert_eq!(parse_mount_attr(&attr_bytes(0, 0, 0, 5000), 0), Err(E2BIG));
    let mut tail = attr_bytes(0, 0, 0, 40);
    tail[39] = 1;
    assert_eq!(parse_mount_attr(&tail, 0), Err(E2BIG));
    assert_eq!(parse_mount_attr(&attr_bytes(0, 0, 0, 40), 0), Ok((0, 0, 0)));
    assert_eq!(parse_mount_attr(&attr_bytes(MOUNT_ATTR_IDMAP, 0, 0, 32), 0), Err(EINVAL));
    assert_eq!(parse_mount_attr(&attr_bytes(0x8000_0000, 0, 0, 32), 0), Err(EINVAL));
    assert_eq!(parse_mount_attr(&attr_bytes(0, 0, MS_SHARED | MS_PRIVATE, 32), 0), Err(EINVAL));
    assert_eq!(parse_mount_attr(&attr_bytes(0, 0, 0, 32), 0x1), Err(EINVAL));
    let mut d = open_tree_clone(&dir("/usr", 1), AT_RECURSIVE);
    setattr_detached(&mut d, MS_RDONLY, 0, MS_SLAVE);
    setattr_detached(&mut d, MS_NODEV, MS_RDONLY, 0);
    assert_eq!((d.flags, d.propagation), (MS_NODEV, MS_SLAVE));
}

#[test]
fn new_mount_api_flow() {
    assert_eq!(fsopen("tmpfs", 2).unwrap_err(), EINVAL);
    assert_eq!(fsopen("ext4", 0).unwrap_err(), ENODEV);
    let mut c = fsopen("tmpfs", FSOPEN_CLOEXEC).unwrap();
    assert_eq!(MountObj::Ctx(c.clone()).path(), "anon_inode:[fscontext]");
    assert_eq!(fsmount(&mut c, 0, 0), Err(EINVAL), "not created yet");
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_STRING, Some("source"), Some("mytmp"), 0), Ok(ConfigOut::Done));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_STRING, Some("source"), Some("again"), 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_STRING, Some("size"), Some("1m"), 0), Ok(ConfigOut::Done));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_STRING, Some("size"), Some("1m"), 1), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_STRING, None, Some("x"), 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_PATH, Some("p"), None, 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_FLAG, Some("ro"), None, 0), Ok(ConfigOut::Done));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_FLAG, Some("noswap"), None, 0), Ok(ConfigOut::Done));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_FLAG, Some("x"), Some("v"), 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_FLAG, None, None, 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_BINARY, Some("k"), Some("v"), 1), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_SET_FD, Some("k"), None, 3), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_CMD_RECONFIGURE, None, None, 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, FSCONFIG_CMD_CREATE, Some("k"), None, 0), Err(EINVAL));
    assert_eq!(fsconfig(&mut c, 99, None, None, 0), Err(EOPNOTSUPP));
    assert_eq!(fsconfig(&mut c, FSCONFIG_CMD_CREATE, None, None, 0), Ok(ConfigOut::Done));
    assert_eq!(fsconfig(&mut c, FSCONFIG_CMD_CREATE_EXCL, None, None, 0), Err(EBUSY));
    assert_eq!(fsmount(&mut c, 2, 0), Err(EINVAL));
    assert_eq!(fsmount(&mut c, 0, MOUNT_ATTR_IDMAP), Err(EINVAL));
    let mut d = fsmount(&mut c, 0, MOUNT_ATTR_NOEXEC).unwrap();
    assert_eq!(fsmount(&mut c, 0, 0), Err(EBUSY));
    assert_eq!(MountObj::Mnt(d.clone()).path(), "/");
    let a = d.attach();
    assert_eq!(a, Attach::New { fs: "tmpfs".into(), source: Some("mytmp".into()), data: "size=1m,noswap".into(), flags: MS_NOEXEC | MS_RELATIME | MS_RDONLY });
    // The caller carries it out
    let mut t = tables();
    let mut f = Factory::default();
    let Attach::New { fs, source, data, flags } = a else { unreachable!() };
    t.mount_new(&root_caller(7), &dir("/mnt", 1), &fs, source.as_deref().unwrap(), flags, &data, &mut f).unwrap();
    d.attached = Some("/mnt".into());
    assert_eq!(d.attach(), Attach::Move { from: "/mnt".into() });
    assert_eq!(MountObj::Mnt(d).path(), "/mnt");
    // fspick and reconfigure
    let i = t.ns(7).unwrap().child_at(1, 40).unwrap();
    let mut p = fspick(t.ns(7).unwrap(), &Loc::new("/mnt", 1, i, true)).unwrap();
    assert!(p.ro && p.created);
    assert_eq!(p.source.as_deref(), Some("mytmp"));
    assert_eq!(fsconfig(&mut p, FSCONFIG_CMD_CREATE, None, None, 0), Err(EBUSY));
    assert_eq!(fsmount(&mut p, 0, 0), Err(EINVAL));
    fsconfig(&mut p, FSCONFIG_SET_FLAG, Some("rw"), None, 0).unwrap();
    assert_eq!(fsconfig(&mut p, FSCONFIG_CMD_RECONFIGURE, None, None, 0), Ok(ConfigOut::Reconfigure { path: "/mnt".into(), ro: false }));
    assert_eq!(fspick(t.ns(7).unwrap(), &dir("/usr", 1)), Err(EINVAL));
    // open_tree and move_mount rules
    assert_eq!(open_tree_flags(0), Ok(false));
    assert_eq!(open_tree_flags(OPEN_TREE_CLONE | AT_RECURSIVE | O_CLOEXEC), Ok(true));
    assert_eq!(open_tree_flags(AT_RECURSIVE), Err(EINVAL));
    assert_eq!(open_tree_flags(0x2), Err(EINVAL));
    let clone = open_tree_clone(&dir("/usr", 1), 0);
    assert_eq!(clone.attach(), Attach::Bind { source: "/usr".into(), recursive: false, flags: 0 });
    assert_eq!(move_mount_flags(MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_SYMLINKS), Ok(()));
    assert_eq!(move_mount_flags(0x100), Err(EINVAL));
}

#[test]
fn kept_state_round_trip() {
    let mut t = tables();
    let mut f = Factory::default();
    let c = root_caller(7);
    t.mount(&c, None, &dir("/tmp", 1), Some("tmpfs"), None, MS_NOSUID, Some("size=1m"), &mut f).unwrap();
    let i = t.ns(7).unwrap().child_at(1, 20).unwrap();
    t.umount(&c, &Loc::new("/tmp", 1, i, true), 0).unwrap(); // a hole in the table
    t.mount(&c, None, &dir("/mnt", 1), Some("proc"), None, 0, None, &mut f).unwrap();
    t.ns0_fixed = false;
    let bytes = t.encode();
    let back = MountTables::decode(&bytes).unwrap();
    assert_eq!(back, t);
    // Counters continue: the next mount gets a new ID
    let mut back = back;
    back.mount(&c, None, &dir("/mnt2", 1), Some("tmpfs"), None, 0, None, &mut f).unwrap();
    let ids: Vec<u32> = back.ns(7).unwrap().live().map(|(_, m)| m.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len());
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0; 100]);
    assert_eq!(MountTables::decode(&padded).unwrap(), t);
    for at in [0, 4, 9, 17, 30, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 0x10;
        assert_eq!(MountTables::decode(&bad), Err(EINVAL), "byte {at}");
    }
    assert_eq!(MountTables::decode(&bytes[..23]), Err(EINVAL));
    assert_eq!(MountTables::decode(&bytes[..bytes.len() - 1]), Err(EINVAL));
}

/// Changes the body of a sealed table and seals it again (only the reader can object).
fn reseal(bytes: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = unseal(0x4d4e_5433, 1, bytes).unwrap().to_vec();
    f(&mut body);
    seal(0x4d4e_5433, 1, &body)
}

#[test]
fn kept_state_reader_checks_structure() {
    let mut t = MountTables::new();
    t.install(0, 1, &[]);
    let bytes = t.encode();
    assert_eq!(MountTables::decode(&reseal(&bytes, |_| {})).unwrap(), t);
    // Body: next_id 4, next_dev 4, fixed 1, count 4, then ns id 8, root 8, slots 4, tag 1
    assert_eq!(MountTables::decode(&reseal(&bytes, |b| b.push(1))), Err(EINVAL), "trailing bytes");
    assert_eq!(MountTables::decode(&reseal(&bytes, |b| b[21] = 5)), Err(EINVAL), "root slot missing");
    assert_eq!(MountTables::decode(&reseal(&bytes, |b| b[29..33].copy_from_slice(&u32::MAX.to_le_bytes()))), Err(EINVAL), "absurd count");
    assert_eq!(MountTables::decode(&reseal(&bytes, |b| b[33] = 7)), Err(EINVAL), "slot tag");
    // The backend tag of the root mount: id 4, parent 8, mountpoint 8, by_name 1
    assert_eq!(MountTables::decode(&reseal(&bytes, |b| b[34 + 21] = 9)), Err(EINVAL), "backend tag");
    let mut v = seal(1, 1, b"x");
    assert_eq!(unseal(1, 1, &v), Ok(&b"x"[..]));
    assert_eq!(unseal(1, 2, &v), Err(EINVAL));
    assert_eq!(unseal(2, 1, &v), Err(EINVAL));
    v[8] = 200;
    assert_eq!(unseal(1, 1, &v), Err(EINVAL), "length beyond the buffer");
    assert_eq!(checksum(b""), 0xcbf2_9ce4_8422_2325);
    // Strings must be UTF-8
    let mut e = Enc::default();
    e.bytes(&[0xff, 0xfe]);
    assert_eq!(Dec::new(&e.buf).str(), Err(EINVAL));
    let mut e = Enc::default();
    e.i64(-5);
    assert_eq!(Dec::new(&e.buf).i64(), Ok(-5));
}
