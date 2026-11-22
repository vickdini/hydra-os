//! One request of the kernel or vfs-server, decoded and served ([`serve`]); the main loop
//! and the intent log's replay both call it.

use alloc::vec::Vec;

use crate::zfs;
use crate::fs;
use zfs::fsproto::*;
use zfs::server::with_server;

/// Serves one request: returns `(status, value, reply bytes)`, the reply data written to
/// `out`.
///
/// # Arguments
/// * `op` - Filesystem operation code.
/// * `req` - Request parameter byte slice.
/// * `out` - Destination reply byte buffer.
///
/// # Returns
/// Tuple of `(status_code, return_value, reply_byte_length)`.
pub fn serve(op: u32, req: &[u8], out: &mut [u8]) -> (i64, u64, usize) {
    let mut r = Reader::new(req);
    let mut w = Writer::new(out);
    let res: Result<(u64, usize), i64> = match op {
        FS_ROOT => with_server(|s| Ok((s.root_obj(), 0))),
        FS_LOOKUP => {
            let dir = r.u64();
            let name = r.bytes();
            with_server(|s| s.lookup(dir, name).map(|i| (i, 0)))
        }
        FS_RESOLVE => {
            let (root, base, follow) = (r.u64(), r.u64(), r.u64() != 0);
            let path = r.bytes();
            // Reply: the directories walked through that not everyone may search
            let mut dirs = Vec::new();
            with_server(|s| fs::client::resolve_in_dirs(s, root, base, path, follow, &mut dirs)).map(|i| {
                w.u64(dirs.len() as u64);
                for d in &dirs {
                    w.u64(*d);
                }
                (i, w.len())
            })
        }
        FS_RESOLVE_MNT => {
            let (root, root_mnt, base, base_mnt, follow) = (r.u64(), r.u64() as usize, r.u64(), r.u64() as usize, r.u64() != 0);
            let path = r.bytes().to_vec();
            let n = (r.u64() as usize).min(1024);
            let mounts: Vec<(u64, u64, usize)> = (0..n).map(|_| (r.u64(), r.u64(), r.u64() as usize)).collect();
            with_server(|s| {
                fs::client::resolve_mnt(s, root, root_mnt, base, base_mnt, &path, follow, &mounts).map(|(ino, mnt, rest)| match rest {
                    // Stopped at FUSE mount `mnt`: its index and the rest of the path
                    Some(rest) => {
                        w.u64(mnt as u64);
                        w.bytes(&rest);
                        ((mnt as u64) << MNT_SHIFT, w.len())
                    }
                    None => (ino | ((mnt as u64) << MNT_SHIFT), 0),
                })
            })
        }
        FS_GETATTR => {
            let ino = r.u64();
            with_server(|s| s.getattr(ino)).map(|a| {
                w.attr(&a);
                (0, w.len())
            })
        }
        FS_SETATTR => {
            let ino = r.u64();
            let set = r.setattr();
            with_server(|s| s.setattr(ino, set)).map(|a| {
                w.attr(&a);
                (0, w.len())
            })
        }
        FS_READ => {
            let (ino, off, len) = (r.u64(), r.u64(), (r.u64() as usize).min(MAX_IO).min(out.len()));
            with_server(|s| s.read(ino, off, &mut out[..len])).map(|n| (n as u64, n))
        }
        FS_WRITE => {
            let (ino, off) = (r.u64(), r.u64());
            let data = r.bytes();
            // A writer without CAP_FSETID: its groups (set-ID bits go)
            let kill: Option<Vec<u32>> = if r.u64() & 1 != 0 {
                let n = r.u64().min(64);
                Some((0..n).map(|_| r.u64() as u32).collect())
            } else {
                None
            };
            with_server(|s| s.write(ino, off, data, kill.as_deref())).map(|n| (n as u64, 0))
        }
        FS_CREATE | FS_MKDIR => {
            let dir = r.u64();
            let name = r.bytes();
            let (perm, uid, gid) = (r.u64() as u32, r.u64() as u32, r.u64() as u32);
            with_server(|s| if op == FS_CREATE { s.create(dir, name, perm, uid, gid) } else { s.mkdir(dir, name, perm, uid, gid) }).map(|i| (i, 0))
        }
        FS_MKNOD => {
            let dir = r.u64();
            let name = r.bytes();
            let (mode, rdev, uid, gid) = (r.u64() as u32, r.u64(), r.u64() as u32, r.u64() as u32);
            with_server(|s| s.mknod(dir, name, mode, rdev, uid, gid)).map(|i| (i, 0))
        }
        FS_SYMLINK => {
            let dir = r.u64();
            let name = r.bytes();
            let target = r.bytes();
            let (uid, gid) = (r.u64() as u32, r.u64() as u32);
            with_server(|s| s.symlink(dir, name, target, uid, gid)).map(|i| (i, 0))
        }
        FS_GETXATTR | FS_LISTXATTR => {
            let ino = r.u64();
            let v = if op == FS_GETXATTR {
                let name = r.bytes();
                with_server(|s| s.getxattr(ino, name))
            } else {
                with_server(|s| s.listxattr(ino))
            };
            v.map(|v| {
                let n = v.len().min(out.len());
                out[..n].copy_from_slice(&v[..n]);
                (v.len() as u64, n)
            })
        }
        FS_SETXATTR => {
            let ino = r.u64();
            let name = r.bytes();
            let value = r.bytes();
            let flags = r.u64() as u32;
            with_server(|s| s.setxattr(ino, name, value, flags)).map(|()| (0, 0))
        }
        FS_REMOVEXATTR => {
            let ino = r.u64();
            let name = r.bytes();
            with_server(|s| s.removexattr(ino, name)).map(|()| (0, 0))
        }
        FS_READLINK => {
            let ino = r.u64();
            with_server(|s| s.readlink(ino)).map(|t| {
                let n = t.len().min(out.len());
                out[..n].copy_from_slice(&t[..n]);
                (n as u64, n)
            })
        }
        FS_LINK => {
            let (ino, dir) = (r.u64(), r.u64());
            let name = r.bytes();
            with_server(|s| s.link(ino, dir, name)).map(|()| (0, 0))
        }
        FS_UNLINK | FS_RMDIR => {
            let dir = r.u64();
            let name = r.bytes();
            with_server(|s| if op == FS_UNLINK { s.unlink(dir, name) } else { s.rmdir(dir, name) }).map(|()| (0, 0))
        }
        FS_RENAME => {
            let sdir = r.u64();
            let sname = r.bytes();
            let ddir = r.u64();
            let dname = r.bytes();
            with_server(|s| s.rename(sdir, sname, ddir, dname)).map(|()| (0, 0))
        }
        FS_READDIR => {
            let (dir, cookie, max) = (r.u64(), r.u64(), r.u64() as usize);
            with_server(|s| s.readdir(dir, cookie, max)).map(|entries| {
                let mut n = 0;
                for e in &entries {
                    if !w.entry(e) {
                        break;
                    }
                    n += 1;
                }
                (n, w.len())
            })
        }
        FS_STATFS => with_server(|s| Ok(s.statfs())).map(|(a, b, c)| {
            w.u64(a);
            w.u64(b);
            w.u64(c);
            (0, w.len())
        }),
        FS_OPEN_REF => {
            let ino = r.u64();
            with_server(|s| {
                s.open_ref(ino);
                Ok((0, 0))
            })
        }
        FS_RELEASE => {
            let ino = r.u64();
            with_server(|s| {
                s.release(ino);
                Ok((0, 0))
            })
        }
        FS_NOTIFY => {
            let (ino, mask) = (r.u64(), r.u64() as u32);
            with_server(|s| {
                s.notify_file(ino, mask);
                Ok((0, 0))
            })
        }
        FS_SYNC => with_server(|s| s.sync()).map(|t| (t, 0)),
        FS_SYNC_IF_DIRTY => with_server(|s| {
            if s.dmu.has_pending_changes() {
                s.sync().map(|_| (1, 0))
            } else {
                Ok((0, 0))
            }
        }),
        FS_SNAPSHOT => {
            let idx = r.u64() as usize;
            let name = core::str::from_utf8(r.bytes()).unwrap_or("snap");
            with_server(|s| s.snapshot(idx, name)).map(|t| (t, 0))
        }
        FS_POOL_STATUS => with_server(|s| {
            w.u64(s.dmu.spa.total_capacity_bytes());
            w.u64(s.dmu.spa.allocated_bytes());
            w.u64(s.dmu.spa.free_bytes());
            w.u64(s.dmu.ub.txg);
            w.u64(s.dmu.open_txg);
            Ok((0, w.len()))
        }),
        FS_OBJECT_INFO => {
            let ino = r.u64();
            with_server(|s| {
                let dn = s.dmu.get_dnode(ino).map_err(|_| EIO)?;
                let bp = dn.blkptr[0];
                w.u64(dn.birth_txg);
                w.u64(!bp.is_hole() as u64);
                for c in [bp.checksum.a, bp.checksum.b, bp.checksum.c, bp.checksum.d] {
                    w.u64(c);
                }
                Ok((0, w.len()))
            })
        }
        FS_DATASETS => with_server(|s| {
            let mut n = 0;
            for d in &s.datasets {
                if !(w.bytes(d.name_str().as_bytes()) && w.bytes(d.mountpoint_str().as_bytes()) && w.u64(d.txg) && w.u64(d.is_snapshot as u64)) {
                    break;
                }
                n += 1;
            }
            Ok((n, w.len()))
        }),
        FS_SELFTEST => {
            zfs::selftest::run_selftest();
            Ok((0, 0))
        }
        FS_VERIFY => {
            zfs::selftest::run_verify();
            Ok((0, 0))
        }
        FS_FSCK => {
            let path = alloc::string::String::from(core::str::from_utf8(r.bytes()).unwrap_or("/"));
            let repair = r.u64() != 0;
            zfs::selftest::run_fsck(&path, repair);
            Ok((0, 0))
        }
        _ => Err(-38),
    };
    match res {
        Ok((value, len)) => (0, value, len),
        Err(e) => (e, 0, 0),
    }
}
