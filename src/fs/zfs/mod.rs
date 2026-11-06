//! # OpenZFS: the Kernel's Side of the ZFS File Server
//!
//! Hydra's OpenZFS implementation (Storage Pool Allocator, DMU, ZAP directories, POSIX
//! layer) is the ZFS file server, a Ring 3 program (`userland/drivers/zfs-server`) that the
//! supervisor starts after the disk driver; it owns the pool. The kernel's file layer
//! ([`crate::fs::client`], the Linux VFS) talks to it through [`ZfsServer`], which has the
//! server's ZPL operations as methods: each is a request over
//! [`crate::ipc::protocol::ENDPOINT_ZFS_SERVER`] ([`fsproto`] describes them).
//!
//! ## Key Types & Interfaces
//! - [`ZfsServer`] & [`with_server`]: the file server, as the kernel calls it.
//! - [`init_server`]: checks the server is up and learns the pool's root directory.
//! - [`types`]: on-disk structures and mode bits (shared with the server).
//! - [`fsproto`]: the requests, their types (`Attr`, `SetAttr`, ...) and encoding.
//!
//! ## Concurrency
//! A request runs the server in the caller's place ([`crate::ipc::service::call`]); nothing
//! else runs until it answers, so requests are serialized and the window is the caller's
//! for the duration.

pub mod fsproto;
pub mod types;

/// The ZPL's types and error numbers, under the path the kernel always used.
pub mod zpl {
    pub use super::fsproto::{
        Attr, ReaddirEntry, SetAttr, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ELOOP, EMLINK, ENAMETOOLONG, ENOENT, ENOSPC,
        ENOTDIR, ENOTEMPTY, EPERM, EXDEV,
    };

    /// Result of a ZPL operation (negative Linux errno on failure).
    pub type ZplResult<T> = Result<T, i64>;
}

/// Directory entries as listed by the shell.
pub mod zap {
    pub use super::fsproto::ZapEntry;
}

pub use crate::ipc::protocol::ENDPOINT_ZFS_SERVER;
pub use types::{DnodeType, ZFS_BLOCK_SIZE};

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ipc::service;
use crate::ipc::Message;
use fsproto::*;

/// What the disk driver reports about the pool's disk (`disks`, `zpool status`).
#[derive(Clone)]
pub struct DiskInfo {
    /// Drive model.
    pub model: alloc::string::String,
    /// Size in 512-byte sectors.
    pub sectors: u64,
    /// Whether the driver uses 48-bit addressing.
    pub lba48: bool,
    /// Whether the driver uses bus-master DMA.
    pub dma: bool,
}

/// Asks the disk driver about its disk; `None` if there is no disk driver (the pool is
/// then on a RAM disk).
///
/// # Returns
///
/// An [`Option<DiskInfo>`] containing information about the disk driver, or `None` if unavailable.
pub fn disk_info() -> Option<DiskInfo> {
    use crate::ipc::protocol::{ENDPOINT_BLOCK_DEV, MSG_BLOCK_GET_SIZE, MSG_BLOCK_REPLY};
    if !service::is_online(ENDPOINT_BLOCK_DEV) {
        return None;
    }
    let r = service::call(ENDPOINT_BLOCK_DEV, Message::new(MSG_BLOCK_GET_SIZE), service::CALL_TIMEOUT_TICKS).ok()?;
    if r.label != MSG_BLOCK_REPLY || (r.args[0] as i64) < 0 {
        return None;
    }
    let window = service::window(ENDPOINT_BLOCK_DEV)?;
    let model = core::str::from_utf8(&window[..40]).unwrap_or("").trim_end_matches(|c: char| c == ' ' || c == '\0');
    Some(DiskInfo { model: alloc::string::String::from(model), sectors: r.args[1] * 8, lba48: r.args[2] != 0, dma: r.args[3] != 0 })
}

/// How long a request may take: a commit of a large transaction group takes a while.
const TIMEOUT_TICKS: u64 = 12_000;

/// Root directory of the pool (0 until [`init_server`]).
static ROOT: AtomicU64 = AtomicU64::new(0);

/// The file server, as the kernel calls it: its ZPL operations, one request each.
pub struct ZfsServer {
    root: u64,
}

/// Checks the file server is running and learns the pool's root directory.
pub fn init_server() {
    let mut s = ZfsServer { root: 0 };
    match s.request(FS_ROOT, |_| {}) {
        Ok((root, _)) => ROOT.store(root, Ordering::Release),
        Err(e) => crate::println!("[!] OpenZFS: the file server is not available (error {})", e),
    }
}

/// Runs `f` with the file server, or fails with `-EIO` if it is not running.
///
/// # Arguments
/// * `f` - A closure invoked with a mutable reference to [`ZfsServer`].
///
/// # Returns
///
/// The result returned by `f`, or `-EIO` if the file server is not running.
pub fn with_server<R>(f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return Err(EIO);
    }
    f(&mut ZfsServer { root })
}

impl ZfsServer {
    /// Sends request `op` with the parameters `params` writes; returns `(value, reply
    /// bytes)` and hands the operation's inotify events to the kernel's watchers.
    ///
    /// # Arguments
    /// * `op` - The operation identifier.
    /// * `params` - A closure that encodes parameters into the shared window.
    ///
    /// # Returns
    ///
    /// A tuple `(value, reply_len)` on success, or a negative errno error code on failure.
    fn request(&mut self, op: u32, params: impl FnOnce(&mut Writer)) -> Result<(u64, usize), i64> {
        let window = match service::window(ENDPOINT_ZFS_SERVER) {
            Some(w) => w,
            None => {
                crate::task::supervisor::revive(ENDPOINT_ZFS_SERVER);
                service::window(ENDPOINT_ZFS_SERVER).ok_or(EIO)?
            }
        };
        params(&mut Writer::new(&mut window[..EVENT_OFFSET]));
        let reply = service::call(ENDPOINT_ZFS_SERVER, Message::with_args(op, [0; 4]), TIMEOUT_TICKS).map_err(|_| EIO)?;
        if reply.label != FS_REPLY {
            return Err(EIO);
        }
        let events = reply.args[3] as usize;
        if events > 0 && crate::compat::linux::inotify::active() {
            let mut r = Reader::new(&window[EVENT_OFFSET..EVENT_OFFSET + EVENT_SPACE]);
            for _ in 0..events {
                let e = r.event();
                crate::compat::linux::inotify::event(e.ino, e.mask, e.cookie, &e.name);
            }
        }
        match reply.args[0] as i64 {
            e if e < 0 => Err(e),
            _ => Ok((reply.args[1], reply.args[2] as usize)),
        }
    }

    /// The reply data of the last request.
    ///
    /// # Arguments
    /// * `len` - Length in bytes of the reply to retrieve.
    ///
    /// # Returns
    ///
    /// A static byte slice referencing the reply window data.
    fn reply(&self, len: usize) -> &'static [u8] {
        service::window(ENDPOINT_ZFS_SERVER).map_or(&[][..], |w| &w[..len.min(EVENT_OFFSET)])
    }

    /// Root directory object ID of the pool.
    ///
    /// # Returns
    ///
    /// The object ID of the root directory.
    pub fn root_obj(&self) -> u64 {
        self.root
    }

    /// Looks up `name` in directory `dir`.
    ///
    /// # Arguments
    /// * `dir` - Object ID of the directory to search in.
    /// * `name` - The byte slice file/directory name to look up.
    ///
    /// # Returns
    ///
    /// The target object ID on success, or a negative errno error code on failure.
    pub fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<u64, i64> {
        self.request(FS_LOOKUP, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|r| r.0)
    }

    /// Resolves `path` inside `root` relative to `base` (symbolic links expanded), in one
    /// request.
    ///
    /// # Arguments
    /// * `root` - Root object ID boundary.
    /// * `base` - Starting directory object ID.
    /// * `path` - Path byte slice to resolve.
    /// * `follow_last` - Whether to resolve symbolic links on the final path component.
    ///
    /// # Returns
    ///
    /// The resolved object ID on success, or a negative errno error code on failure.
    pub fn resolve_in(&mut self, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        if path.len() > 4096 {
            return Err(ENAMETOOLONG);
        }
        self.request(FS_RESOLVE, |w| {
            w.u64(root);
            w.u64(base);
            w.u64(follow_last as u64);
            w.bytes(path);
        })
        .map(|r| r.0)
    }

    /// Resolves `path` through a mount table (see [`FS_RESOLVE_MNT`]).
    ///
    /// # Arguments
    /// * `root`, `root_mnt` - Root directory and the mount (1-based, 0 = none) it lies in.
    /// * `base`, `base_mnt` - Starting directory and its mount.
    /// * `path` - Path byte slice.
    /// * `follow_last` - Whether to follow a symbolic link in the last component.
    /// * `mounts` - `(mountpoint, mounted root, parent mount)` per mount.
    ///
    /// # Returns
    ///
    /// The object ID and the mount it lies in, or a negative errno.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_mnt(
        &mut self,
        root: u64,
        root_mnt: usize,
        base: u64,
        base_mnt: usize,
        path: &[u8],
        follow_last: bool,
        mounts: &[(u64, u64, usize)],
    ) -> Result<(u64, usize), i64> {
        if path.len() > 4096 {
            return Err(ENAMETOOLONG);
        }
        self.request(FS_RESOLVE_MNT, |w| {
            w.u64(root);
            w.u64(root_mnt as u64);
            w.u64(base);
            w.u64(base_mnt as u64);
            w.u64(follow_last as u64);
            w.bytes(path);
            w.u64(mounts.len() as u64);
            for m in mounts {
                w.u64(m.0);
                w.u64(m.1);
                w.u64(m.2 as u64);
            }
        })
        .map(|r| (r.0 & ((1u64 << MNT_SHIFT) - 1), (r.0 >> MNT_SHIFT) as usize))
    }

    /// Attributes of `ino`.
    ///
    /// # Arguments
    /// * `ino` - Object ID / inode number.
    ///
    /// # Returns
    ///
    /// The object's [`Attr`] record on success, or a negative errno error code on failure.
    pub fn getattr(&mut self, ino: u64) -> Result<Attr, i64> {
        let (_, len) = self.request(FS_GETATTR, |w| {
            w.u64(ino);
        })?;
        Ok(Reader::new(self.reply(len)).attr())
    }

    /// Changes attributes of `ino`; returns the new ones.
    ///
    /// # Arguments
    /// * `ino` - Object ID / inode number.
    /// * `set` - Attributes to update.
    ///
    /// # Returns
    ///
    /// The updated [`Attr`] record on success, or a negative errno error code on failure.
    pub fn setattr(&mut self, ino: u64, set: SetAttr) -> Result<Attr, i64> {
        let (_, len) = self.request(FS_SETATTR, |w| {
            w.u64(ino);
            w.setattr(&set);
        })?;
        Ok(Reader::new(self.reply(len)).attr())
    }

    /// Reads from `ino` at `offset` into `buf`; returns the bytes read.
    ///
    /// # Arguments
    /// * `ino` - Object ID to read from.
    /// * `offset` - Byte offset within the object.
    /// * `buf` - Destination buffer for read bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes actually read on success, or a negative errno error code on failure.
    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(MAX_IO);
            let (n, _) = self.request(FS_READ, |w| {
                w.u64(ino);
                w.u64(offset + done as u64);
                w.u64(want as u64);
            })?;
            let n = n as usize;
            buf[done..done + n].copy_from_slice(self.reply(n));
            done += n;
            if n < want {
                break;
            }
        }
        Ok(done)
    }

    /// Writes `data` to `ino` at `offset`; returns the bytes written.
    ///
    /// # Arguments
    /// * `ino` - Object ID to write to.
    /// * `offset` - Byte offset within the object.
    /// * `data` - Byte slice to write.
    ///
    /// # Returns
    ///
    /// The number of bytes actually written on success, or a negative errno error code on failure.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        let mut done = 0;
        while done < data.len() || data.is_empty() {
            let chunk = &data[done..(done + MAX_IO).min(data.len())];
            let (n, _) = self.request(FS_WRITE, |w| {
                w.u64(ino);
                w.u64(offset + done as u64);
                w.bytes(chunk);
            })?;
            done += n as usize;
            if (n as usize) < chunk.len() || data.is_empty() {
                break;
            }
        }
        Ok(done)
    }

    /// Creates regular file `name` in `dir`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the new file.
    /// * `perm` - File permissions and mode bits.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    ///
    /// The newly created object ID on success, or a negative errno error code on failure.
    pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        self.request(FS_CREATE, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(perm as u64);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| r.0)
    }

    /// Creates a device node, FIFO or socket `name` in `dir`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the special file.
    /// * `mode` - File type and permission bits.
    /// * `rdev` - Device major/minor ID if device node.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    ///
    /// The newly created object ID on success, or a negative errno error code on failure.
    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> Result<u64, i64> {
        self.request(FS_MKNOD, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(mode as u64);
            w.u64(rdev);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| r.0)
    }

    /// Creates directory `name` in `dir`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the new directory.
    /// * `perm` - Directory permission bits.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    ///
    /// The newly created directory object ID on success, or a negative errno error code on failure.
    pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        self.request(FS_MKDIR, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(perm as u64);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| r.0)
    }

    /// Creates symbolic link `name` in `dir` pointing at `target`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the symbolic link.
    /// * `target` - Target path the symlink points to.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    ///
    /// The newly created symlink object ID on success, or a negative errno error code on failure.
    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64, i64> {
        self.request(FS_SYMLINK, |w| {
            w.u64(dir);
            w.bytes(name);
            w.bytes(target);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| r.0)
    }

    /// Target of symbolic link `ino`.
    ///
    /// # Arguments
    /// * `ino` - Object ID of the symbolic link.
    ///
    /// # Returns
    ///
    /// A byte vector of the target path on success, or a negative errno error code on failure.
    pub fn readlink(&mut self, ino: u64) -> Result<Vec<u8>, i64> {
        let (n, _) = self.request(FS_READLINK, |w| {
            w.u64(ino);
        })?;
        Ok(self.reply(n as usize).to_vec())
    }

    /// Adds hard link `name` in `dir` to `ino`.
    ///
    /// # Arguments
    /// * `ino` - Target object ID to link to.
    /// * `dir` - Directory object ID where the new link will reside.
    /// * `name` - Name of the new link.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative errno error code on failure.
    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
        self.request(FS_LINK, |w| {
            w.u64(ino);
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ())
    }

    /// Removes `name` (not a directory) from `dir`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the entry to unlink.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative errno error code on failure.
    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        self.request(FS_UNLINK, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ())
    }

    /// Removes empty directory `name` from `dir`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory object ID.
    /// * `name` - Name of the empty directory to remove.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative errno error code on failure.
    pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        self.request(FS_RMDIR, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ())
    }

    /// Renames `sdir/sname` to `ddir/dname`.
    ///
    /// # Arguments
    /// * `sdir` - Source parent directory object ID.
    /// * `sname` - Source entry name.
    /// * `ddir` - Destination parent directory object ID.
    /// * `dname` - Destination entry name.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative errno error code on failure.
    pub fn rename(&mut self, sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
        self.request(FS_RENAME, |w| {
            w.u64(sdir);
            w.bytes(sname);
            w.u64(ddir);
            w.bytes(dname);
        })
        .map(|_| ())
    }

    /// Up to `max` entries of `dir` from `cookie` on.
    ///
    /// # Arguments
    /// * `dir` - Directory object ID.
    /// * `cookie` - Pagination cookie to continue listing from.
    /// * `max` - Maximum number of entries to read.
    ///
    /// # Returns
    ///
    /// A vector of [`ReaddirEntry`] items on success, or a negative errno error code on failure.
    pub fn readdir(&mut self, dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
        let (count, len) = self.request(FS_READDIR, |w| {
            w.u64(dir);
            w.u64(cookie);
            w.u64(max as u64);
        })?;
        let mut r = Reader::new(self.reply(len));
        Ok((0..count).map(|_| r.entry()).collect())
    }

    /// `(total blocks, free blocks, inodes in use)` (zeros if the server is unavailable).
    ///
    /// # Returns
    ///
    /// A `(total_blocks, free_blocks, inodes_in_use)` tuple.
    pub fn statfs(&mut self) -> (u64, u64, u64) {
        match self.request(FS_STATFS, |_| {}) {
            Ok((_, len)) => {
                let mut r = Reader::new(self.reply(len));
                (r.u64(), r.u64(), r.u64())
            }
            Err(_) => (0, 0, 0),
        }
    }

    /// A descriptor opened `ino` (an unlinked inode lives until its last close).
    ///
    /// # Arguments
    /// * `ino` - Inode object ID being opened.
    pub fn open_ref(&mut self, ino: u64) {
        let _ = self.request(FS_OPEN_REF, |w| {
            w.u64(ino);
        });
    }

    /// A descriptor on `ino` was closed.
    ///
    /// # Arguments
    /// * `ino` - Inode object ID being released.
    pub fn release(&mut self, ino: u64) {
        let _ = self.request(FS_RELEASE, |w| {
            w.u64(ino);
        });
    }

    /// Reports inotify event `mask` for `ino` (and its directory).
    ///
    /// # Arguments
    /// * `ino` - Inode object ID.
    /// * `mask` - Inotify event bitmask.
    pub fn notify_file(&mut self, ino: u64, mask: u32) {
        let _ = self.request(FS_NOTIFY, |w| {
            w.u64(ino);
            w.u64(mask as u64);
        });
    }

    /// Commits the open transaction group; returns its number.
    ///
    /// # Returns
    ///
    /// The transaction group number committed on success, or a negative errno error code on failure.
    pub fn sync(&mut self) -> Result<u64, i64> {
        self.request(FS_SYNC, |_| {}).map(|r| r.0)
    }

    /// Commits if there are uncommitted changes; returns whether it did.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if changes were synced, `Ok(false)` if not dirty, or a negative errno error code on failure.
    pub fn sync_if_dirty(&mut self) -> Result<bool, i64> {
        self.request(FS_SYNC_IF_DIRTY, |_| {}).map(|r| r.0 != 0)
    }

    /// Snapshots dataset `dataset_index` as `snap_name`; returns its transaction group.
    ///
    /// # Arguments
    /// * `dataset_index` - Index of the dataset to snapshot.
    /// * `snap_name` - Name for the created snapshot.
    ///
    /// # Returns
    ///
    /// The transaction group number of the snapshot on success, or a negative errno error code on failure.
    pub fn snapshot(&mut self, dataset_index: usize, snap_name: &str) -> Result<u64, i64> {
        self.request(FS_SNAPSHOT, |w| {
            w.u64(dataset_index as u64);
            w.bytes(snap_name.as_bytes());
        })
        .map(|r| r.0)
    }

    /// `(total bytes, allocated bytes, free bytes, committed txg, open txg)`.
    ///
    /// # Returns
    ///
    /// A tuple `(total_bytes, allocated_bytes, free_bytes, committed_txg, open_txg)` on success, or an errno code on failure.
    pub fn pool_status(&mut self) -> Result<(u64, u64, u64, u64, u64), i64> {
        let (_, len) = self.request(FS_POOL_STATUS, |_| {})?;
        let mut r = Reader::new(self.reply(len));
        Ok((r.u64(), r.u64(), r.u64(), r.u64(), r.u64()))
    }

    /// `(birth txg, has blocks, checksum of its first block pointer)` of object `ino`.
    ///
    /// # Arguments
    /// * `ino` - Inode object ID.
    ///
    /// # Returns
    ///
    /// A tuple `(birth_txg, has_blocks, checksum_words)` on success, or an errno code on failure.
    pub fn object_info(&mut self, ino: u64) -> Result<(u64, bool, [u64; 4]), i64> {
        let (_, len) = self.request(FS_OBJECT_INFO, |w| {
            w.u64(ino);
        })?;
        let mut r = Reader::new(self.reply(len));
        Ok((r.u64(), r.u64() != 0, [r.u64(), r.u64(), r.u64(), r.u64()]))
    }

    /// Datasets and snapshots: `(name, mount point, txg, is snapshot)`.
    ///
    /// # Returns
    ///
    /// A vector of dataset/snapshot tuples `(name, mount_point, txg, is_snapshot)` on success, or an errno code on failure.
    pub fn datasets(&mut self) -> Result<Vec<(alloc::string::String, alloc::string::String, u64, bool)>, i64> {
        let (count, len) = self.request(FS_DATASETS, |_| {})?;
        let mut r = Reader::new(self.reply(len));
        Ok((0..count)
            .map(|_| {
                let name = alloc::string::String::from_utf8_lossy(r.bytes()).into_owned();
                let mount = alloc::string::String::from_utf8_lossy(r.bytes()).into_owned();
                (name, mount, r.u64(), r.u64() != 0)
            })
            .collect())
    }

    /// Runs the server's self test, block verification, or tree check (`zfs` command);
    /// output appears on the console.
    ///
    /// # Arguments
    /// * `op` - Diagnostic operation opcode.
    /// * `path` - Target dataset or object path string.
    /// * `repair` - Whether to attempt repair during check.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative errno error code on failure.
    pub fn diagnostic(&mut self, op: u32, path: &str, repair: bool) -> Result<(), i64> {
        self.request(op, |w| {
            w.bytes(path.as_bytes());
            w.u64(repair as u64);
        })
        .map(|_| ())
    }
}
