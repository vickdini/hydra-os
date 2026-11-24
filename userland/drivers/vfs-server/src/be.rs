//! The walk's back end in the program: zfs-server through the caches (7-3 adds `tmpfs`
//! mounts here: a node's mount says which back end serves it).

use alloc::vec::Vec;

use crate::cache::CACHE;
use crate::ctx::Node;
use crate::fs::fsproto::{Attr, ENODATA, ENOENT};
use crate::mount;
use crate::walk::Mounts;
use crate::perm::ACL_ACCESS;
use crate::walk::Backend;
use crate::zfs;

/// zfs-server through the caches (`nocache`: every step asks zfs-server).
pub struct ZfsBackend {
    /// Bypass the caches (neither read nor filled).
    pub nocache: bool,
    /// The caller's mount namespace: a node in one of its tmpfs mounts goes to that tmpfs
    /// (7-3).
    pub ns: u32,
}

impl Backend for ZfsBackend {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        crate::fuse::not_fuse(dir)?; // wave9 G6b-2
        if let Some(t) = mount::tmpfs_of(self.ns, dir.mnt) {
            return mount::tmpfs_lookup(t, dir, name);
        }
        // (wave10 GV2: `..` is cached too — /sys's links are full of `../..`; a rename of the
        // directory forgets the names in it, `..` among them: `change::rename` and the
        // kernel's change notes both name the moved object, `Cache::forget_object`)
        let cached = !self.nocache;
        if cached {
            if let Some(r) = CACHE.name(dir, name) {
                return r.ok_or(ENOENT);
            }
        }
        let t = CACHE.begin();
        match zfs::lookup(dir.ino, name) {
            Ok(i) => {
                let n = Node::new(dir.mnt, i);
                if cached {
                    CACHE.put_name(t, dir, name, Some(n));
                }
                Ok(n)
            }
            Err(ENOENT) => {
                if cached {
                    CACHE.put_name(t, dir, name, None);
                }
                Err(ENOENT)
            }
            Err(e) => Err(e),
        }
    }

    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        crate::fuse::not_fuse(n)?; // wave9 G6b-2
        if let Some(t) = mount::tmpfs_of(self.ns, n.mnt) {
            return mount::tmpfs_getattr(t, n);
        }
        if !self.nocache {
            if let Some(a) = CACHE.attr(n) {
                return Ok(a);
            }
        }
        let t = CACHE.begin();
        let a = zfs::getattr(n.ino)?;
        if !self.nocache {
            CACHE.put_attr(t, n, a);
        }
        Ok(a)
    }

    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        crate::fuse::not_fuse(n)?; // wave9 G6b-2
        if let Some(t) = mount::tmpfs_of(self.ns, n.mnt) {
            return mount::tmpfs_readlink(t, n);
        }
        if !self.nocache {
            if let Some(l) = CACHE.link(n) {
                return Ok(l);
            }
        }
        let t = CACHE.begin();
        let l = zfs::readlink(n.ino)?;
        if !self.nocache {
            CACHE.put_link(t, n, &l);
        }
        Ok(l)
    }

    fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64> {
        crate::fuse::not_fuse(n)?; // wave9 G6b-2
        if let Some(t) = mount::tmpfs_of(self.ns, n.mnt) {
            return mount::tmpfs_acl(t, n);
        }
        if !self.nocache {
            if let Some(a) = CACHE.acl(n) {
                return Ok(a);
            }
        }
        let t = CACHE.begin();
        let a = match zfs::getxattr(n.ino, ACL_ACCESS) {
            Ok(v) => Some(v),
            Err(ENODATA) => None,
            // (another error: fail, uncached; the mode bits alone could allow what the ACL
            // denies)
            Err(e) => return Err(e),
        };
        if !self.nocache {
            CACHE.put_acl(t, n, a.as_deref());
        }
        Ok(a)
    }

    fn mounts(&self) -> &dyn Mounts {
        &mount::TABLES
    }
    // wave10 GV2: the names other services serve in /sys and /dev (as the calls' walker)
    fn may_serve(&self, name: &[u8]) -> bool {
        crate::calls::served::may_serve(name)
    }
    fn served(&self, cx: &crate::ctx::Ctx, dir: Node, name: &[u8], rest: &[&[u8]]) -> Option<(crate::proto::SvcId, u64)> {
        crate::calls::served::check(self, cx, dir, name, rest, false)
    }
}
