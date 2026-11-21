//! Group 7-1's walk over Group 7-3's tables (`mount.rs`): the boot answers, a namespace
//! with a tmpfs, a bind mount inside the tmpfs, `..` across mounts, served mounts. The
//! tables are the program's statics, so everything runs in one test.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::{Attr, ENOENT};
use crate::fs::types::{S_IFDIR, S_IFLNK, S_IFREG};
use crate::mount::{self, MTAB, TMPFS};
use crate::mtab::{Caller, FsFactory, Loc, SvcId, CAP_SYS_ADMIN, MS_BIND};
use crate::proto::{LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_PROC};
use crate::walk::{self, Backend, Mounts, Start, Walked};

/// The pool: `/` = 2, `/proc` 10, `/tmp` 20, `/usr` 30, `/usr/bin` 31 (a file), `/lnk` 40
/// -> `tmp`.
struct Pool {
    ns: u32,
    objs: BTreeMap<u64, (u32, Vec<(&'static [u8], u64)>, &'static [u8])>,
}

impl Pool {
    fn new(ns: u32) -> Pool {
        let mut objs = BTreeMap::new();
        objs.insert(2, (S_IFDIR | 0o755, vec![(&b"proc"[..], 10), (b"tmp", 20), (b"usr", 30), (b"lnk", 40)], &b""[..]));
        objs.insert(10, (S_IFDIR | 0o555, vec![], &b""[..]));
        objs.insert(20, (S_IFDIR | 0o1777, vec![], &b""[..]));
        objs.insert(30, (S_IFDIR | 0o755, vec![(&b"bin"[..], 31)], &b""[..]));
        objs.insert(31, (S_IFREG | 0o755, vec![], &b""[..]));
        objs.insert(40, (S_IFLNK | 0o777, vec![], &b"tmp"[..]));
        Pool { ns, objs }
    }
    fn parent(&self, ino: u64) -> u64 {
        self.objs.iter().find(|(_, o)| o.1.iter().any(|e| e.1 == ino)).map_or(2, |(i, _)| *i)
    }
}

/// Routes like the program's `be.rs`: tmpfs mounts to the tmpfs, the rest to the pool.
impl Backend for Pool {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        if let Some(t) = mount::tmpfs_of(self.ns, dir.mnt) {
            return mount::tmpfs_lookup(t, dir, name);
        }
        if name == b".." {
            return Ok(Node::new(dir.mnt, self.parent(dir.ino)));
        }
        let o = self.objs.get(&dir.ino).ok_or(ENOENT)?;
        o.1.iter().find(|e| e.0 == name).map(|e| Node::new(dir.mnt, e.1)).ok_or(ENOENT)
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        if let Some(t) = mount::tmpfs_of(self.ns, n.mnt) {
            return mount::tmpfs_getattr(t, n);
        }
        let o = self.objs.get(&n.ino).ok_or(ENOENT)?;
        Ok(Attr { ino: n.ino, mode: o.0, nlink: 1, ..Attr::default() })
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        if let Some(t) = mount::tmpfs_of(self.ns, n.mnt) {
            return mount::tmpfs_readlink(t, n);
        }
        Ok(self.objs.get(&n.ino).ok_or(ENOENT)?.2.to_vec())
    }
    fn acl(&self, n: Node) -> Option<Vec<u8>> {
        mount::tmpfs_of(self.ns, n.mnt).and_then(|t| mount::tmpfs_acl(t, n))
    }
    fn mounts(&self) -> &dyn Mounts {
        &mount::TABLES
    }
}

/// tmpfs instances in the program's set; nothing served.
struct Factory;

impl FsFactory for Factory {
    fn new_tmpfs(&mut self, data: &str, euid: u32, egid: u32) -> Result<(u32, u64), i64> {
        TMPFS.lock().as_mut().unwrap().create(data, euid, egid, 1 << 30, (0, 0))
    }
    fn served(&self, _fstype: &str) -> Option<(SvcId, u64, String)> {
        None
    }
}

fn cx(ns: u32) -> Ctx {
    let mut c = Ctx::new(0, 0, 0, Node::new(0, 2));
    c.ns = ns;
    c
}

fn found(ns: u32, path: &str) -> Result<(Node, Attr), i64> {
    match walk::walk(&Pool::new(ns), &cx(ns), Start::Root, path.as_bytes(), 0)? {
        Walked::Found { node, attr } => Ok((node, attr)),
        Walked::Redirect(r) => panic!("{path}: redirected to {}", r.svc),
    }
}

fn redirected(ns: u32, path: &str) -> (SvcId, u64) {
    match walk::walk(&Pool::new(ns), &cx(ns), Start::Root, path.as_bytes(), 0).unwrap() {
        Walked::Redirect(r) => (r.svc, r.obj),
        Walked::Found { node, .. } => panic!("{path}: found {node:?}"),
    }
}

#[test]
fn the_walk_over_the_tables() {
    mount::install_boot(2);
    // The boot answers (as 7-1's BootMounts)
    assert_eq!(redirected(0, "/proc/self/stat"), (LXS_PROC, LX_VFS_PSEUDO_PROC));
    assert_eq!(redirected(0, "/dev/null").0, LXS_LINUX);
    assert_eq!(found(0, "/usr/bin").unwrap().0, Node::new(0, 31));
    assert_eq!(mount::TABLES.covering(0, Node::new(0, 20)), None);
    assert_eq!(mount::TABLES.mount(0, 1), None);
    assert_eq!(mount::tmpfs_of(0, 3), None);

    // Namespace 7: a copy (proc, sys, dev turn into mounts where the pool has the
    // directory: only /proc here) and a tmpfs on /tmp
    let caller = Caller { ns: 7, caps: CAP_SYS_ADMIN, euid: 0, egid: 0 };
    let pool_of = |p: &str| match p {
        "/proc" => 10,
        _ => 0,
    };
    {
        let mut g = MTAB.lock();
        let t = g.as_mut().unwrap();
        t.copy_ns(0, 7, &pool_of).unwrap();
        t.mount(&caller, None, &Loc::new("/tmp", 20, 1, true), Some("tmpfs"), None, 0, Some("size=1m"), &mut Factory).unwrap();
    }
    mount::changed();
    let tm = MTAB.lock().as_ref().unwrap().ns(7).unwrap().child_at(1, 20).unwrap();
    let n = mount::tmpfs_of(7, tm as u16).expect("a tmpfs mount");
    let (x, d) = {
        let mut g = TMPFS.lock();
        let t = g.as_mut().unwrap().get_mut(n).unwrap();
        let x = t.mknod(1, b"x", 0o644, 0, 0, 0, (1, 0)).unwrap();
        let d = t.mkdir(1, b"d", 0o755, 0, 0, (1, 0)).unwrap();
        t.symlink(1, b"up", b"../usr", 0, 0, (1, 0)).unwrap();
        (x, d)
    };
    // Into the tmpfs, out again with `..`, through symbolic links on both sides
    let (node, attr) = found(7, "/tmp/x").unwrap();
    assert_eq!((node, attr.mode & 0o170000), (Node::new(tm as u16, x), S_IFREG));
    assert_eq!(found(7, "/tmp").unwrap().0, Node::new(tm as u16, 1));
    assert_eq!(found(7, "/tmp/..").unwrap().0, Node::new(0, 2));
    assert_eq!(found(7, "/tmp/d/../x").unwrap().0, Node::new(tm as u16, x));
    assert_eq!(found(7, "/lnk/x").unwrap().0, Node::new(tm as u16, x));
    assert_eq!(found(7, "/tmp/up/bin").unwrap().0, Node::new(0, 31));
    assert_eq!(found(7, "/tmp/nope").map(|f| f.0), Err(ENOENT));
    // The initial namespace (and one the server never heard of) does not see it
    assert_eq!(found(0, "/tmp/x").map(|f| f.0), Err(ENOENT));
    assert_eq!(found(99, "/tmp/x").map(|f| f.0), Err(ENOENT));
    assert_eq!(found(0, "/tmp").unwrap().0, Node::new(0, 20));
    // /proc in the copy: a mount on the pool's directory, served by the process service
    assert_eq!(redirected(7, "/proc/self/stat"), (LXS_PROC, LX_VFS_PSEUDO_PROC));
    // /dev had no directory in this pool: it stays by name
    assert_eq!(redirected(7, "/dev/null").0, LXS_LINUX);

    // A bind of /usr inside the tmpfs: the walk crosses pool -> tmpfs -> pool
    {
        let mut g = MTAB.lock();
        let t = g.as_mut().unwrap();
        t.mount(&caller, Some(&Loc::new("/usr", 30, 1, true)), &Loc::new("/tmp/d", d, tm, true), None, None, MS_BIND, None, &mut Factory).unwrap();
    }
    let (bin, _) = found(7, "/tmp/d/bin").unwrap();
    assert_eq!(bin.ino, 31);
    assert_ne!(bin.mnt, 0);
    assert_eq!(found(7, "/tmp/d/..").unwrap().0, Node::new(tm as u16, 1), "out of the bind into the tmpfs");
    let info = mount::TABLES.mount(7, bin.mnt).unwrap();
    assert_eq!((info.parent, info.mountpoint, info.root), (tm as u16, Node::new(tm as u16, d), Node::new(bin.mnt, 30)));
    assert_eq!(mount::TABLES.covering(7, Node::new(tm as u16, d)), Some(bin.mnt));
    assert_eq!(mount::TABLES.pseudo_at_root(7, b"dev"), Some((LXS_LINUX, crate::proto::LX_VFS_PSEUDO_DEV)));
    assert_eq!(mount::TABLES.pseudo_at_root(7, b"proc"), None, "a mount on the object now");

    // tmpfs ACLs reach the permission checks
    {
        let mut g = TMPFS.lock();
        let t = g.as_mut().unwrap().get_mut(n).unwrap();
        t.setxattr(x, crate::perm::ACL_ACCESS, b"acl", 0, (2, 0)).unwrap();
    }
    assert_eq!(Pool::new(7).acl(Node::new(tm as u16, x)).as_deref(), Some(&b"acl"[..]));
    assert_eq!(Pool::new(7).readlink(Node::new(tm as u16, 4)).unwrap(), b"../usr");
}
