//! vfs-server's copy of the kernel's mount tables (`kmounts`) and the walk across it; the
//! walk's leftovers from 7-1 (wave 7, Group 7-7).

use alloc::vec::Vec;

use crate::ctx::{Ctx, Node};
use crate::fake::{Fake, ROOT};
use crate::fs::fsproto::Attr;
use crate::kmounts::{self, View, MS_NOEXEC, MS_RDONLY};
use crate::proto::{LxMntHead, LxMntRec, LXS_PROC, LX_MNT_HOLE, LX_MNT_KERNEL, LX_MNT_TMPFS, LX_MNT_TREE};
use crate::walk::{self, Backend, MountInfo, MountKind, Mounts, ParentWalked, Start, Walked, NOFOLLOW};

const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;
const ESTALE: i64 = -116;

/// The fake file system walked with a [`View`] as its mounts.
struct WithView<'a> {
    fs: &'a Fake,
    view: &'a View,
}

impl Backend for WithView<'_> {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        self.fs.lookup(dir, name)
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        self.fs.getattr(n)
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        self.fs.readlink(n)
    }
    fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64> {
        self.fs.acl(n)
    }
    fn mounts(&self) -> &dyn Mounts {
        self.view
    }
}

fn rec(kind: u32, flags: u32, parent: u32, mountpoint: u64, root: u64) -> LxMntRec {
    LxMntRec { kind, flags, parent, pad: 0, mountpoint, root }
}

fn found(r: Result<Walked, i64>) -> Result<Node, i64> {
    r.map(|w| match w {
        Walked::Found { node, .. } => node,
        Walked::Redirect(r) => panic!("unexpected redirect {:?}", r),
    })
}

fn is_kernel(r: Result<Walked, i64>) -> bool {
    matches!(r, Ok(Walked::Redirect(ref x)) if x.svc == 0)
}

/// /data/f, /ro, /tmp, /run/user/doc, /newroot/proc, /etc/passwd, /link -> /data
struct Tree {
    fs: Fake,
    data: u64,
    f: u64,
    ro: u64,
    tmp: u64,
    tmproot: u64,
    doc: u64,
    nrproc: u64,
    etc: u64,
}

fn tree() -> Tree {
    let fs = Fake::new();
    let data = fs.mkdir(ROOT, "data", 0o755);
    let f = fs.file(data, "f", 0o644);
    let ro = fs.mkdir(ROOT, "ro", 0o755);
    let tmp = fs.mkdir(ROOT, "tmp", 0o1777);
    let hidden = fs.mkdir(ROOT, ".hydra-tmpfs", 0o700);
    let tmproot = fs.mkdir(hidden, "1", 0o1777);
    fs.file(tmproot, "scratch", 0o600);
    let run = fs.mkdir(ROOT, "run", 0o755);
    let user = fs.mkdir(run, "user", 0o755);
    let doc = fs.mkdir(user, "doc", 0o755);
    let nr = fs.mkdir(ROOT, "newroot", 0o755);
    let nrproc = fs.mkdir(nr, "proc", 0o555);
    let etc = fs.mkdir(ROOT, "etc", 0o755);
    fs.file(etc, "passwd", 0o644);
    fs.symlink(ROOT, "link", "/data");
    Tree { fs, data, f, ro, tmp, tmproot, doc, nrproc, etc }
}

/// A namespace table as the kernel gives it: 1 the root, 2..7 the standard named mounts
/// (holes), 8 /data bound read-only at /ro, 9 a tmpfs at /tmp, 10 proc at /newroot/proc.
fn ns_view(t: &Tree) -> View {
    let mut recs = alloc::vec![rec(LX_MNT_TREE, 0, 0, 0, ROOT)];
    for _ in 0..6 {
        recs.push(rec(LX_MNT_HOLE, 0, 1, 77, 0));
    }
    recs.push(rec(LX_MNT_TREE, MS_RDONLY | MS_NOEXEC, 1, t.ro, t.data));
    recs.push(rec(LX_MNT_TMPFS, 0, 1, t.tmp, t.tmproot));
    recs.push(rec(LX_MNT_KERNEL, 0, 1, t.nrproc, 0));
    let n = recs.len() as u32;
    kmounts::parse(5, &LxMntHead { gen: 3, root: 1, n }, &recs).unwrap()
}

fn ns_cx() -> Ctx {
    let mut c = Ctx::new(0, 0, 0, Node::new(1, ROOT));
    c.ns = 5;
    c
}

#[test]
fn walks_cross_the_kernels_mounts_with_its_numbers() {
    let t = tree();
    let v = ns_view(&t);
    let be = WithView { fs: &t.fs, view: &v };
    let cx = ns_cx();
    // The root mount's objects are in mount 1
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/etc/passwd", 0)).unwrap().mnt, 1);
    // /ro is /data in mount 8 (read-only, noexec)
    let n = found(walk::walk(&be, &cx, Start::Root, b"/ro/f", 0)).unwrap();
    assert_eq!(n, Node::new(8, t.f));
    assert_eq!(v.flags(n.mnt), MS_RDONLY | MS_NOEXEC);
    assert_eq!(v.flags(1), 0);
    // The same file through its own path: mount 1
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/data/f", 0)).unwrap(), Node::new(1, t.f));
    // `..` climbs out of the bind to the directory it covers
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/ro/../etc", 0)).unwrap(), Node::new(1, t.etc));
    // The tmpfs tree
    let s = found(walk::walk(&be, &cx, Start::Root, b"/tmp/scratch", 0)).unwrap();
    assert_eq!(s.mnt, 9);
    assert!(v.is_tmpfs(s.mnt));
    // proc elsewhere: the kernel's
    assert!(is_kernel(walk::walk(&be, &cx, Start::Root, b"/newroot/proc/self", 0)));
    assert!(is_kernel(walk::walk(&be, &cx, Start::Root, b"/newroot/proc", NOFOLLOW)));
    // ... but `proc/..` backs out here
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/newroot/proc/../proc/..", 0)).unwrap().mnt, 1);
    // /proc under the root is the process service's, by name
    match walk::walk(&be, &cx, Start::Root, b"/proc/self", 0).unwrap() {
        Walked::Redirect(r) => assert_eq!(r.svc, LXS_PROC),
        w => panic!("{:?}", w),
    }
    // A link into the bind's source stays in the root mount
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/link/f", 0)).unwrap(), Node::new(1, t.f));
    // A walk from a directory of mount 8
    assert_eq!(found(walk::walk(&be, &cx, Start::At(Node::new(8, t.data)), b"f", 0)).unwrap(), Node::new(8, t.f));
    // The parent walk of a name on a mount point
    match walk::walk_parent(&be, &cx, Start::Root, b"/ro").unwrap() {
        ParentWalked::Found(p) => {
            assert_eq!(p.child, Some(Node::new(1, t.ro)));
            assert!(v.is_mountpoint(Node::new(1, t.ro)));
            // (busy through any mount that shows the same directory — 7-7 review)
            assert!(v.is_mountpoint(Node::new(8, t.ro)));
            assert!(!v.is_mountpoint(Node::new(1, t.etc)));
        }
        w => panic!("{:?}", w),
    }
    // A named mount the kernel serves where it is (a hole) is not a mount for the walk, but
    // its directory is still a mount point
    assert_eq!(v.covering(5, Node::new(1, 77)), None);
    assert!(v.is_mountpoint(Node::new(1, 77)));
}

#[test]
fn the_namespace_root_has_nothing_below_it() {
    let t = tree();
    let v = ns_view(&t);
    let be = WithView { fs: &t.fs, view: &v };
    // A caller chrooted in /data: `..` from its root stays; from a directory outside its
    // root (a descriptor) up to the namespace's root, and no further
    let mut cx = ns_cx();
    cx.root = Node::new(1, t.data);
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/../..", 0)).unwrap(), Node::new(1, t.data));
    assert_eq!(found(walk::walk(&be, &cx, Start::At(Node::new(1, t.etc)), b"../../..", 0)).unwrap(), Node::new(1, ROOT));
    // A node of a mount the table does not have
    assert_eq!(found(walk::walk(&be, &ns_cx(), Start::At(Node::new(3, t.etc)), b"..", 0)), Err(ESTALE));
}

#[test]
fn after_a_pivot_root_the_old_root_is_below_the_new() {
    let t = tree();
    // pivot_root(/data, /data/old): the old root (mount 1) is on /data's `old` in mount 2,
    // and mount 2 (/data) is the root
    let old = t.fs.mkdir(t.data, "old", 0o755);
    let recs = alloc::vec![rec(LX_MNT_TREE, 0, 2, old, ROOT), rec(LX_MNT_TREE, 0, 0, 0, t.data)];
    let v = kmounts::parse(6, &LxMntHead { gen: 1, root: 2, n: 2 }, &recs).unwrap();
    let be = WithView { fs: &t.fs, view: &v };
    let mut cx = Ctx::new(0, 0, 0, Node::new(2, t.data));
    cx.ns = 6;
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/f", 0)).unwrap(), Node::new(2, t.f));
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/old/etc/passwd", 0)).unwrap().mnt, 1);
    // `..` from the old root's top goes back to the new root's `old`'s directory
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/old/..", 0)).unwrap(), Node::new(2, t.data));
    assert_eq!(v.root_ino(), Some(t.data));
}

#[test]
fn the_initial_namespaces_fuse_mounts_are_the_kernels() {
    let t = tree();
    let recs = alloc::vec![rec(LX_MNT_KERNEL, 0, 0, t.doc, 1 << 62)];
    let v = kmounts::parse(0, &LxMntHead { gen: 9, root: 0, n: 1 }, &recs).unwrap();
    let be = WithView { fs: &t.fs, view: &v };
    let cx = Ctx::new(1000, 1000, 0, Node::new(0, ROOT));
    assert!(is_kernel(walk::walk(&be, &cx, Start::Root, b"/run/user/doc", 0)));
    assert!(is_kernel(walk::walk(&be, &cx, Start::Root, b"/run/user/doc/x/y", 0)));
    // Everything else is the pool's own tree, mount 0
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/run/user", 0)).unwrap(), Node::new(0, t.doc - 1));
    assert!(v.walkable(Node::new(0, ROOT)));
    assert!(!v.walkable(Node::new(1, ROOT)));
    // The empty view (no FUSE mount): as the boot table
    let e = View::empty();
    let be = WithView { fs: &t.fs, view: &e };
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/run/user/doc", 0)).unwrap(), Node::new(0, t.doc));
}

#[test]
fn a_table_that_does_not_fit_is_refused() {
    let r = rec(LX_MNT_TREE, 0, 0, 0, ROOT);
    // Count mismatch, root out of range, a hole as the root, an unknown kind, a parent
    // outside the table
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 2 }, &[r]).is_none());
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 2, n: 1 }, &[r]).is_none());
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 0, n: 1 }, &[r]).is_none());
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 1 }, &[rec(LX_MNT_HOLE, 0, 0, 0, 0)]).is_none());
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 1 }, &[rec(9, 0, 0, 0, ROOT)]).is_none());
    assert!(kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 2 }, &[r, rec(LX_MNT_TREE, 0, 7, 3, 4)]).is_none());
    // The initial namespace has no root mount
    assert!(kmounts::parse(0, &LxMntHead { gen: 1, root: 0, n: 0 }, &[]).is_some());
}

#[test]
fn copies_are_taken_by_generation() {
    // Generation 0 of the initial namespace: the empty table, without asking the kernel
    let v = kmounts::view(0, 0).unwrap();
    assert!(v.recs.is_empty());
    // Anything else needs the kernel (the host stand-in refuses: the kernel answers)
    assert_eq!(kmounts::view(0, 5).unwrap_err(), crate::calls::KERNEL);
    assert_eq!(kmounts::view(12, 1).unwrap_err(), crate::calls::KERNEL);
    kmounts::forget(12);
    kmounts::forget_all();
    assert_eq!(kmounts::stats().0, 0);
}

#[test]
fn mount_info_of_the_view() {
    let t = tree();
    let v = ns_view(&t);
    assert_eq!(v.mount(5, 8), Some(MountInfo { parent: 1, mountpoint: Node::new(1, t.ro), root: Node::new(8, t.data), kind: MountKind::Zfs }));
    assert_eq!(v.mount(5, 10).unwrap().kind, MountKind::Redirect { svc: 0, obj: 0 });
    // The root: its own mount point; holes and mount 0 are none
    assert_eq!(v.mount(5, 1).unwrap().mountpoint, Node::new(1, ROOT));
    assert_eq!(v.mount(5, 2), None);
    assert_eq!(v.mount(5, 0), None);
    assert_eq!(v.covering(5, Node::new(1, t.ro)), Some(8));
    assert_eq!(v.covering(5, Node::new(8, t.ro)), None);
}

// ----------------------------------------------------------------------
// The walk's leftovers from 7-1 (7-3's review)
// ----------------------------------------------------------------------

#[test]
fn dotdot_at_the_root_does_not_enter_a_mount_on_the_root() {
    let t = tree();
    // A mount on top of the root directory itself
    let recs = alloc::vec![rec(LX_MNT_TREE, 0, 0, 0, ROOT), rec(LX_MNT_TREE, 0, 1, ROOT, t.data)];
    let v = kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 2 }, &recs).unwrap();
    let be = WithView { fs: &t.fs, view: &v };
    let cx = ns_cx();
    // `/` and `/..` are the same: the root, not the mount on it
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/", 0)).unwrap(), Node::new(1, ROOT));
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/..", 0)).unwrap(), Node::new(1, ROOT));
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/../etc", 0)).unwrap(), Node::new(1, t.etc));
    // ... and `sub/..` back at the root is the root too (7-7 review: it entered the mount)
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/etc/..", 0)).unwrap(), Node::new(1, ROOT));
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/etc/../etc", 0)).unwrap(), Node::new(1, t.etc));
}

#[test]
fn a_redirected_parent_walk_keeps_the_trailing_slash() {
    let t = tree();
    t.fs.symlink(ROOT, "pl", "/newroot/proc/sys");
    let v = ns_view(&t);
    let be = WithView { fs: &t.fs, view: &v };
    let cx = ns_cx();
    match walk::walk_parent(&be, &cx, Start::Root, b"/pl/kernel/").unwrap() {
        ParentWalked::Redirect(r) => {
            assert_eq!(r.tail, None);
            assert_eq!(r.text, b"sys/kernel/".to_vec());
        }
        w => panic!("{:?}", w),
    }
    match walk::walk_parent(&be, &cx, Start::Root, b"/pl/kernel").unwrap() {
        ParentWalked::Redirect(r) => assert_eq!(r.text, b"sys/kernel".to_vec()),
        w => panic!("{:?}", w),
    }
}

#[test]
fn up_asks_for_mount_zero_too() {
    // A table that puts mount 0 under another (7-3's after a pivot_root)
    struct M0(Node, Node);
    impl Mounts for M0 {
        fn covering(&self, _ns: u32, _at: Node) -> Option<u16> {
            None
        }
        fn mount(&self, _ns: u32, m: u16) -> Option<MountInfo> {
            match m {
                0 => Some(MountInfo { parent: 1, mountpoint: self.1, root: self.0, kind: MountKind::Zfs }),
                // (mount 1: a root with nothing below it)
                1 => Some(MountInfo { parent: 0, mountpoint: Node::new(1, ROOT), root: Node::new(1, ROOT), kind: MountKind::Zfs }),
                _ => None,
            }
        }
        fn pseudo_at_root(&self, _ns: u32, _name: &[u8]) -> Option<(crate::proto::SvcId, u64)> {
            None
        }
    }
    struct B<'a>(&'a Fake, M0);
    impl Backend for B<'_> {
        fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
            self.0.lookup(dir, name)
        }
        fn getattr(&self, n: Node) -> Result<Attr, i64> {
            self.0.getattr(n)
        }
        fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
            self.0.readlink(n)
        }
        fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64> {
            self.0.acl(n)
        }
        fn mounts(&self) -> &dyn Mounts {
            &self.1
        }
    }
    let t = tree();
    let be = B(&t.fs, M0(Node::new(0, ROOT), Node::new(1, t.tmp)));
    let cx = Ctx::new(0, 0, 0, Node::new(1, t.data));
    // `..` from mount 0's root climbs to where it is mounted (mount 1's /tmp), then up
    assert_eq!(found(walk::walk(&be, &cx, Start::At(Node::new(0, ROOT)), b"..", 0)).unwrap(), Node::new(1, ROOT));
    let _ = (ENOENT, ENOTDIR);
}

// wave7 G7-7: counted records stop where the bytes end
#[test]
fn a_reader_says_how_much_is_left() {
    use crate::fs::fsproto::{Reader, Writer};
    let mut buf = [0u8; 64];
    let n = {
        let mut w = Writer::new(&mut buf);
        w.u64(7);
        w.bytes(b"abc");
        w.len()
    };
    let mut r = Reader::new(&buf[..n]);
    assert_eq!(r.remaining(), 15);
    assert_eq!(r.u64(), 7);
    assert_eq!(r.bytes(), b"abc");
    assert_eq!(r.remaining(), 0);
    // Past the end: 0, never an underflow
    r.u64();
    assert_eq!(r.remaining(), 0);
}

// 7-7 review: a pool tree mounted on something the kernel serves is not walked from
#[test]
fn a_tree_on_a_kernel_mount_is_the_kernels() {
    let t = tree();
    let recs = alloc::vec![rec(LX_MNT_TREE, 0, 0, 0, ROOT), rec(LX_MNT_KERNEL, 0, 1, t.doc, 1 << 62), rec(LX_MNT_TREE, 0, 2, (1 << 62) + 5, t.data)];
    let v = kmounts::parse(5, &LxMntHead { gen: 1, root: 1, n: 3 }, &recs).unwrap();
    assert!(v.walkable(Node::new(1, t.etc)));
    assert!(!v.walkable(Node::new(2, t.etc)));
    assert!(!v.walkable(Node::new(3, t.data)));
}

// 7-7 review: a record cut short is seen as such
#[test]
fn a_cut_record_is_an_overrun() {
    use crate::fs::fsproto::{Reader, Writer};
    let mut buf = [0u8; 64];
    let n = {
        let mut w = Writer::new(&mut buf);
        w.u64(1);
        w.u64(2);
        w.bytes(b"name");
        w.len()
    };
    // Whole: no overrun
    let mut r = Reader::new(&buf[..n]);
    r.u64();
    r.u64();
    assert_eq!(r.bytes(), b"name");
    assert!(!r.overrun());
    // Cut inside the name: overrun, empty name
    let mut r = Reader::new(&buf[..n - 2]);
    r.u64();
    r.u64();
    assert_eq!(r.bytes(), b"");
    assert!(r.overrun());
    // Cut right after the length field
    let mut r = Reader::new(&buf[..20]);
    r.u64();
    r.u64();
    r.bytes();
    assert!(r.overrun());
}
