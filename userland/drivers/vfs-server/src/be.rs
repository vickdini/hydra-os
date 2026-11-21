//! The walk's back end in the program: zfs-server through the caches (7-3 adds `tmpfs`
//! mounts here: a node's mount says which back end serves it).

use alloc::vec::Vec;

use crate::cache::CACHE;
use crate::ctx::Node;
use crate::fs::fsproto::{Attr, ENODATA, ENOENT};
use crate::walk::{BootMounts, Mounts};
use crate::perm::ACL_ACCESS;
use crate::walk::Backend;
use crate::zfs;

/// The mount tables (the boot table until 7-3).
pub static MOUNTS: BootMounts = BootMounts { pseudo: true };

/// zfs-server through the caches (`nocache`: every step asks zfs-server).
pub struct ZfsBackend {
    /// Bypass the caches (neither read nor filled).
    pub nocache: bool,
}

impl Backend for ZfsBackend {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        // (`..` is not cached: a rename of the directory would have to forget it)
        let cached = !self.nocache && name != b"..";
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
        &MOUNTS
    }
}
