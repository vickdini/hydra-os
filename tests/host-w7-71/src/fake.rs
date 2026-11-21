//! An in-memory file system for the walk's [`Backend`]: directories, files, symbolic links,
//! owners and modes, ACLs, and a mount table; it counts the requests it answers (what the
//! zfs-server requests would be). [`Cached`] puts vfs-server's caches in front of it the way
//! the program's `be.rs` does with zfs-server.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::cache::Cache;
use crate::ctx::Node;
use crate::fs::fsproto::{Attr, ENODATA, ENOENT, ENOTDIR, EINVAL};
use crate::fs::types::{S_IFDIR, S_IFLNK, S_IFREG};
use crate::walk::{MountInfo, Mounts};
use crate::proto::SvcId;
use crate::walk::Backend;

/// The fake pool root's object number.
pub const ROOT: u64 = 2;

enum Kind {
    Dir(BTreeMap<Vec<u8>, u64>, u64),
    File,
    Link(Vec<u8>),
}

struct Obj {
    attr: Attr,
    kind: Kind,
    acl: Option<Vec<u8>>,
}

/// A mount table: mounts 1.. in order; `pseudo` names under the caller's root.
#[derive(Default)]
pub struct FakeMounts {
    pub list: Vec<MountInfo>,
    pub pseudo: Vec<(Vec<u8>, SvcId, u64)>,
}

impl Mounts for FakeMounts {
    fn covering(&self, _ns: u32, at: Node) -> Option<u16> {
        self.list.iter().rposition(|m| m.mountpoint == at).map(|i| i as u16 + 1)
    }
    fn mount(&self, _ns: u32, m: u16) -> Option<MountInfo> {
        (m as usize).checked_sub(1).and_then(|i| self.list.get(i)).copied()
    }
    fn pseudo_at_root(&self, _ns: u32, name: &[u8]) -> Option<(SvcId, u64)> {
        self.pseudo.iter().find(|p| p.0 == name).map(|p| (p.1, p.2))
    }
}

/// The fake file system.
pub struct Fake {
    objs: RefCell<BTreeMap<u64, Obj>>,
    next: Cell<u64>,
    /// Requests answered (lookup, getattr, readlink, acl).
    pub requests: Cell<u64>,
    pub mounts: FakeMounts,
}

fn attr(ino: u64, mode: u32, uid: u32, gid: u32) -> Attr {
    Attr { ino, mode, nlink: 1, uid, gid, size: 0, ..Default::default() }
}

impl Fake {
    /// A file system with just the root (mode 0755, root's).
    pub fn new() -> Self {
        let f = Fake { objs: RefCell::new(BTreeMap::new()), next: Cell::new(ROOT + 1), requests: Cell::new(0), mounts: FakeMounts::default() };
        f.objs.borrow_mut().insert(ROOT, Obj { attr: attr(ROOT, S_IFDIR | 0o755, 0, 0), kind: Kind::Dir(BTreeMap::new(), ROOT), acl: None });
        f
    }

    fn add(&self, parent: u64, name: &str, mode: u32, kind: Kind) -> u64 {
        let ino = self.next.get();
        self.next.set(ino + 1);
        let mut o = self.objs.borrow_mut();
        match &mut o.get_mut(&parent).expect("parent").kind {
            Kind::Dir(m, _) => {
                m.insert(name.as_bytes().to_vec(), ino);
            }
            _ => panic!("parent not a directory"),
        }
        o.insert(ino, Obj { attr: attr(ino, mode, 0, 0), kind, acl: None });
        ino
    }

    /// A directory `name` in `parent` with permission bits `perm`.
    pub fn mkdir(&self, parent: u64, name: &str, perm: u32) -> u64 {
        self.add(parent, name, S_IFDIR | perm, Kind::Dir(BTreeMap::new(), parent))
    }

    /// A regular file.
    pub fn file(&self, parent: u64, name: &str, perm: u32) -> u64 {
        self.add(parent, name, S_IFREG | perm, Kind::File)
    }

    /// A symbolic link to `target`.
    pub fn symlink(&self, parent: u64, name: &str, target: &str) -> u64 {
        self.add(parent, name, S_IFLNK | 0o777, Kind::Link(target.as_bytes().to_vec()))
    }

    /// Sets an object's owner and group.
    pub fn chown(&self, ino: u64, uid: u32, gid: u32) {
        let mut o = self.objs.borrow_mut();
        let a = &mut o.get_mut(&ino).unwrap().attr;
        a.uid = uid;
        a.gid = gid;
    }

    /// Sets an object's permission bits.
    pub fn chmod(&self, ino: u64, perm: u32) {
        let mut o = self.objs.borrow_mut();
        let a = &mut o.get_mut(&ino).unwrap().attr;
        a.mode = (a.mode & !0o7777) | perm;
    }

    /// Gives an object an access ACL (and so `has_xattr`).
    pub fn set_acl(&self, ino: u64, acl: Vec<u8>) {
        let mut o = self.objs.borrow_mut();
        let x = o.get_mut(&ino).unwrap();
        x.attr.has_xattr = true;
        x.acl = Some(acl);
    }

    /// Removes `name` from `dir`.
    pub fn unlink(&self, dir: u64, name: &str) {
        if let Kind::Dir(m, _) = &mut self.objs.borrow_mut().get_mut(&dir).unwrap().kind {
            m.remove(name.as_bytes());
        }
    }

    fn count(&self) {
        self.requests.set(self.requests.get() + 1);
    }
}

impl Backend for Fake {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        self.count();
        let o = self.objs.borrow();
        match &o.get(&dir.ino).ok_or(ENOENT)?.kind {
            Kind::Dir(m, parent) => {
                if name == b".." {
                    return Ok(Node::new(dir.mnt, *parent));
                }
                m.get(name).map(|&i| Node::new(dir.mnt, i)).ok_or(ENOENT)
            }
            _ => Err(ENOTDIR),
        }
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        self.count();
        self.objs.borrow().get(&n.ino).map(|o| o.attr).ok_or(ENOENT)
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        self.count();
        match &self.objs.borrow().get(&n.ino).ok_or(ENOENT)?.kind {
            Kind::Link(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }
    fn acl(&self, n: Node) -> Option<Vec<u8>> {
        self.count();
        self.objs.borrow().get(&n.ino).and_then(|o| o.acl.clone())
    }
    fn mounts(&self) -> &dyn Mounts {
        &self.mounts
    }
}

/// The fake behind vfs-server's caches (the program's `be.rs` with zfs-server).
pub struct Cached<'a> {
    pub fs: &'a Fake,
    pub cache: &'a Cache,
}

impl Backend for Cached<'_> {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        if name != b".." {
            if let Some(r) = self.cache.name(dir, name) {
                return r.ok_or(ENOENT);
            }
        }
        let t = self.cache.begin();
        match self.fs.lookup(dir, name) {
            Ok(n) => {
                if name != b".." {
                    self.cache.put_name(t, dir, name, Some(n));
                }
                Ok(n)
            }
            Err(ENOENT) => {
                self.cache.put_name(t, dir, name, None);
                Err(ENOENT)
            }
            Err(e) => Err(e),
        }
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        if let Some(a) = self.cache.attr(n) {
            return Ok(a);
        }
        let t = self.cache.begin();
        let a = self.fs.getattr(n)?;
        self.cache.put_attr(t, n, a);
        Ok(a)
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        if let Some(l) = self.cache.link(n) {
            return Ok(l);
        }
        let t = self.cache.begin();
        let l = self.fs.readlink(n)?;
        self.cache.put_link(t, n, &l);
        Ok(l)
    }
    fn acl(&self, n: Node) -> Option<Vec<u8>> {
        if let Some(a) = self.cache.acl(n) {
            return a;
        }
        let t = self.cache.begin();
        let a = self.fs.acl(n);
        self.cache.put_acl(t, n, a.as_deref());
        let _ = ENODATA;
        a
    }
    fn mounts(&self) -> &dyn Mounts {
        self.fs.mounts()
    }
}
