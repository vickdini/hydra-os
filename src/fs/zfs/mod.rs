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
    let _window = service::hold_window(ENDPOINT_BLOCK_DEV);
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
    /// The server's window while this client uses it (taken by the first request; let go
    /// before waiting for a FUSE daemon, which may need the file server to answer)
    window: Option<service::WindowGuard>,
}

/// Checks the file server is running and learns the pool's root directory.
pub fn init_server() {
    let mut s = ZfsServer { root: 0, window: None };
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
    f(&mut ZfsServer { root, window: None })
}

/// For a write or truncation by the calling task: its groups (effective, then
/// supplementary) if it lacks `CAP_FSETID`, so set-ID bits go (`None`: they stay).
fn kill_suid() -> Option<alloc::vec::Vec<u32>> {
    let (fsetid, egid) = crate::task::with_current_task_mut(|t| (t.caps.has(1 << 4), t.egid)).unwrap_or((true, 0));
    if fsetid {
        return None;
    }
    let mut g = alloc::vec![egid];
    g.extend(crate::compat::linux::proc::supplementary_groups());
    Some(g)
}

use crate::compat::linux::fuse;

/// Attributes of pool objects, so `stat` and permission checks need no request to the file
/// server. Every change to an object goes through this client, which forgets what it
/// changes: the cache never differs from the pool.
static ATTRS: spin::Mutex<alloc::collections::BTreeMap<u64, Attr>> = spin::Mutex::new(alloc::collections::BTreeMap::new());
/// Most objects kept (the cache starts over when full).
const ATTRS_MAX: usize = 16384;

/// Counts forgettings: a reply asked for before one is not kept (it may be older than the
/// change that caused it).
static ATTR_GEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn attr_gen() -> u64 {
    ATTR_GEN.load(core::sync::atomic::Ordering::Acquire)
}

/// The cached attributes of `ino`.
fn cached_attr(ino: u64) -> Option<Attr> {
    x86_64::instructions::interrupts::without_interrupts(|| ATTRS.lock().get(&ino).copied())
}

/// Keeps the attributes of `ino` read by a request made at generation `gen` (unless
/// something was forgotten since).
fn cache_attr(ino: u64, a: Attr, gen: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut c = ATTRS.lock();
        if attr_gen() != gen {
            return;
        }
        if c.len() >= ATTRS_MAX {
            c.clear();
        }
        c.insert(ino, a);
    })
}

/// Forgets the attributes of `ino` (it changed).
fn forget_attr(ino: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut c = ATTRS.lock();
        ATTR_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        c.remove(&ino);
    });
}

/// Forgets every object's attributes (a change whose objects are not all known here: a
/// name removed or moved changes the link count of the object it named).
pub fn forget_all_attrs() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut c = ATTRS.lock();
        ATTR_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        c.clear();
    });
}

/// What a name lookup or path walk found: the object (and mount), the rest of the path at a
/// FUSE mount, or ENOENT/ENOTDIR.
type Found = Result<(u64, usize, Option<Vec<u8>>), i64>;

/// Results of lookups and path walks, keyed by the whole request (kind, directories,
/// mounts, path): a `stat` or `open` of a known path needs no request to the file server.
/// Any change to a name (creating, removing, linking, renaming) forgets them all.
static NAMES: spin::Mutex<alloc::collections::BTreeMap<Vec<u8>, Found>> = spin::Mutex::new(alloc::collections::BTreeMap::new());
/// Most results kept (the cache starts over when full).
const NAMES_MAX: usize = 8192;
static NAMES_GEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// For each cached path walk (same key as [`NAMES`]), the directories it went through that
/// not everyone may search: the caller's search permission is checked on those each time
/// (the result itself does not depend on who asked).
static SEARCH_DIRS: spin::Mutex<alloc::collections::BTreeMap<Vec<u8>, Vec<u64>>> = spin::Mutex::new(alloc::collections::BTreeMap::new());

fn names_gen() -> u64 {
    NAMES_GEN.load(core::sync::atomic::Ordering::Acquire)
}

fn cached_name(key: &[u8]) -> Option<Found> {
    x86_64::instructions::interrupts::without_interrupts(|| NAMES.lock().get(key).cloned())
}

/// Keeps a result asked for at generation `gen` (unless a name changed since; errors other
/// than ENOENT/ENOTDIR are not kept).
fn cache_name(key: Vec<u8>, found: &Found, gen: u64) {
    if matches!(found, Err(e) if *e != ENOENT && *e != ENOTDIR) {
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut c = NAMES.lock();
        if names_gen() != gen {
            return;
        }
        if c.len() >= NAMES_MAX {
            c.clear();
            SEARCH_DIRS.lock().clear();
        }
        c.insert(key, found.clone());
    })
}

/// Keeps the directories a cached walk went through (see [`SEARCH_DIRS`]).
fn cache_search_dirs(key: Vec<u8>, dirs: Vec<u64>, gen: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if names_gen() != gen {
            return;
        }
        let mut c = SEARCH_DIRS.lock();
        if c.len() >= NAMES_MAX {
            c.clear();
        }
        c.insert(key, dirs);
    })
}

fn cached_search_dirs(key: &[u8]) -> Vec<u64> {
    x86_64::instructions::interrupts::without_interrupts(|| SEARCH_DIRS.lock().get(key).cloned().unwrap_or_default())
}

/// Forgets every lookup's result (a name changed).
pub fn forget_names() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut c = NAMES.lock();
        NAMES_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        c.clear();
        SEARCH_DIRS.lock().clear();
    });
}

/// The key of a lookup: its kind, numbers and bytes.
fn name_key(kind: u8, nums: &[u64], bytes: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + nums.len() * 8 + bytes.len());
    k.push(kind);
    for n in nums {
        k.extend_from_slice(&n.to_le_bytes());
    }
    k.extend_from_slice(bytes);
    k
}

/// Forgets the attributes of an object when dropped: at the end of a change to it, after
/// the request (a lookup racing with the change may have kept the old ones).
struct Changed(u64);

impl Drop for Changed {
    fn drop(&mut self) {
        forget_attr(self.0);
    }
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
        // The request and its reply pass through the server's window: this task's until
        // the client is done (or turns to a FUSE file system)
        if self.window.is_none() {
            self.window = Some(service::hold_window(ENDPOINT_ZFS_SERVER));
        }
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
        if events > 0 && (crate::compat::linux::inotify::active() || crate::compat::linux::fanotify::active()) {
            let mut r = Reader::new(&window[EVENT_OFFSET..EVENT_OFFSET + EVENT_SPACE]);
            for _ in 0..events {
                let e = r.event();
                crate::compat::linux::inotify::event(e.ino, e.mask, e.cookie, &e.name);
                crate::compat::linux::fanotify::fs_event(e.ino, e.mask, &e.name);
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::lookup(dir, name);
        }
        let key = name_key(0, &[dir], name);
        if let Some(f) = cached_name(&key) {
            return f.map(|f| f.0);
        }
        let gen = names_gen();
        let r = self.request(FS_LOOKUP, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|r| (r.0, 0, None));
        cache_name(key, &r, gen);
        r.map(|f| f.0)
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
        self.resolve_in_dirs(root, base, path, follow_last).map(|r| r.0)
    }

    /// [`Self::resolve_in`], with the directories the walk went through that not everyone
    /// may search (all three `x` bits set): a Linux system call checks the caller's search
    /// permission on them.
    pub fn resolve_in_dirs(&mut self, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<(u64, Vec<u64>), i64> {
        if path.len() > 4096 {
            return Err(ENAMETOOLONG);
        }
        // Through the initial namespace's FUSE mounts (not checked: see resolve_mnt)
        if fuse::ns0_any() || fuse::is_fuse(base) || fuse::is_fuse(root) {
            let list = fuse::ns0_list();
            return self.resolve_mnt(root, fuse::ns0_mnt_of(root), base, fuse::ns0_mnt_of(base), path, follow_last, &list).map(|r| (r.0, Vec::new()));
        }
        let key = name_key(1, &[root, base, follow_last as u64], path);
        if let Some(f) = cached_name(&key) {
            return f.map(|f| (f.0, cached_search_dirs(&key)));
        }
        let gen = names_gen();
        let r = self.request(FS_RESOLVE, |w| {
            w.u64(root);
            w.u64(base);
            w.u64(follow_last as u64);
            w.bytes(path);
        });
        let r = r.map(|(ino, len)| {
            let mut dirs = Vec::new();
            if len > 0 {
                let mut rd = Reader::new(self.reply(len));
                let n = rd.u64().min(256);
                dirs = (0..n).map(|_| rd.u64()).collect();
            }
            (ino, dirs)
        });
        let found: Found = r.as_ref().map(|(ino, _)| (*ino, 0, None)).map_err(|e| *e);
        cache_name(key.clone(), &found, gen);
        if let Ok((_, dirs)) = &r {
            cache_search_dirs(key, dirs.clone(), gen);
        }
        r
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
        if path.is_empty() {
            return Err(ENOENT);
        }
        // The file server walks the pool; a FUSE file system's part is walked here, and
        // the walk goes back and forth at mount points
        let follow = follow_last || path.ends_with(b"/");
        let (mut cur, mut mnt) = if path[0] == b'/' { (root, root_mnt) } else { (base, base_mnt) };
        let mut rest = path.to_vec();
        let mut links = 0u32;
        for _ in 0..64 {
            let stopped = if fuse::is_fuse(cur) {
                self.window = None;
                match fuse::walk(cur, mnt, &rest, follow, mounts, root, root_mnt, &mut links)? {
                    fuse::Walk::Done(i, m) => return self.trailing_dir(path, (i, m)),
                    fuse::Walk::Out(i, m, r) => (i, m, r),
                }
            } else {
                match self.resolve_mnt_raw(root, root_mnt, cur, mnt, &rest, follow, mounts)? {
                    (i, m, None) => return Ok((i, m)),
                    (i, m, Some(r)) => (i, m, r),
                }
            };
            (cur, mnt, rest) = stopped;
            if rest.is_empty() {
                return self.trailing_dir(path, (cur, mnt));
            }
        }
        Err(ELOOP)
    }

    /// `found`, or `ENOTDIR` if `path` ends with a slash and it is not a directory.
    fn trailing_dir(&mut self, path: &[u8], found: (u64, usize)) -> Result<(u64, usize), i64> {
        if path.ends_with(b"/") && !self.getattr(found.0)?.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(found)
    }

    /// One [`FS_RESOLVE_MNT`] request: `(object, mount, None)`, or a FUSE mount's root, the
    /// mount and the rest of the path when the walk entered one.
    #[allow(clippy::too_many_arguments)]
    fn resolve_mnt_raw(
        &mut self,
        root: u64,
        root_mnt: usize,
        base: u64,
        base_mnt: usize,
        path: &[u8],
        follow_last: bool,
        mounts: &[(u64, u64, usize)],
    ) -> Result<(u64, usize, Option<Vec<u8>>), i64> {
        let mut nums = alloc::vec![root, root_mnt as u64, base, base_mnt as u64, follow_last as u64, mounts.len() as u64];
        for m in mounts {
            nums.extend_from_slice(&[m.0, m.1, m.2 as u64]);
        }
        let key = name_key(2, &nums, path);
        if let Some(f) = cached_name(&key) {
            return f;
        }
        let gen = names_gen();
        let r = self.resolve_mnt_request(root, root_mnt, base, base_mnt, path, follow_last, mounts);
        cache_name(key, &r, gen);
        r
    }

    /// The request of [`Self::resolve_mnt_raw`].
    #[allow(clippy::too_many_arguments)]
    fn resolve_mnt_request(
        &mut self,
        root: u64,
        root_mnt: usize,
        base: u64,
        base_mnt: usize,
        path: &[u8],
        follow_last: bool,
        mounts: &[(u64, u64, usize)],
    ) -> Result<(u64, usize, Option<Vec<u8>>), i64> {
        let (v, len) = self.request(FS_RESOLVE_MNT, |w| {
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
        })?;
        let mnt = (v >> MNT_SHIFT) as usize;
        if len > 0 {
            let mut r = Reader::new(self.reply(len));
            let _ = r.u64();
            let rest = r.bytes().to_vec();
            let root = mounts.get(mnt.wrapping_sub(1)).map(|m| m.1).ok_or(EIO)?;
            return Ok((root, mnt, Some(rest)));
        }
        Ok((v & ((1u64 << MNT_SHIFT) - 1), mnt, None))
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::getattr(ino);
        }
        if let Some(a) = cached_attr(ino) {
            return Ok(a);
        }
        let gen = attr_gen();
        let (_, len) = self.request(FS_GETATTR, |w| {
            w.u64(ino);
        })?;
        let a = Reader::new(self.reply(len)).attr();
        cache_attr(ino, a, gen);
        Ok(a)
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
    pub fn setattr(&mut self, ino: u64, mut set: SetAttr) -> Result<Attr, i64> {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::setattr(ino, set);
        }
        // A truncation by a caller without CAP_FSETID drops the set-ID bits, as a write does
        if let (Some(_), None, Some(groups)) = (set.size, set.mode, if set.size.is_some() { kill_suid() } else { None }) {
            let a = self.getattr(ino)?;
            let m = super::zfs::fsproto::suid_killed(a.mode & 0o7777, a.gid, &groups);
            if m != a.mode & 0o7777 && a.mode & 0o170000 != 0o040000 {
                set.mode = Some(m);
            }
        }
        let changed = Changed(ino);
        let (_, len) = self.request(FS_SETATTR, |w| {
            w.u64(ino);
            w.setattr(&set);
        })?;
        let a = Reader::new(self.reply(len)).attr();
        drop(changed);
        cache_attr(ino, a, attr_gen());
        Ok(a)
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::read(ino, offset, buf);
        }
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::write(ino, offset, data);
        }
        let _changed = Changed(ino);
        let mut done = 0;
        while done < data.len() || data.is_empty() {
            let chunk = &data[done..(done + MAX_IO).min(data.len())];
            let kill = kill_suid();
            let (n, _) = self.request(FS_WRITE, |w| {
                w.u64(ino);
                w.u64(offset + done as u64);
                w.bytes(chunk);
                // Set-ID bits go for a writer without CAP_FSETID: its groups decide set-group-ID
                w.u64(kill.is_some() as u64);
                if let Some(g) = &kill {
                    w.u64(g.len().min(64) as u64);
                    for &x in g.iter().take(64) {
                        w.u64(x as u64);
                    }
                }
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::create(dir, name, perm);
        }
        let r = self.request(FS_CREATE, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(perm as u64);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| {
            forget_attr(r.0);
            r.0
        });
        forget_attr(dir);
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::mknod(dir, name, mode, rdev);
        }
        let r = self.request(FS_MKNOD, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(mode as u64);
            w.u64(rdev);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| {
            forget_attr(r.0);
            r.0
        });
        forget_attr(dir);
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::mkdir(dir, name, perm);
        }
        let r = self.request(FS_MKDIR, |w| {
            w.u64(dir);
            w.bytes(name);
            w.u64(perm as u64);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| {
            forget_attr(r.0);
            r.0
        });
        forget_attr(dir);
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::symlink(dir, name, target);
        }
        let r = self.request(FS_SYMLINK, |w| {
            w.u64(dir);
            w.bytes(name);
            w.bytes(target);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })
        .map(|r| {
            forget_attr(r.0);
            r.0
        });
        forget_attr(dir);
        forget_names();
        r
    }

    /// Extended attribute `name` of `ino`.
    pub fn getxattr(&mut self, ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::getxattr(ino, name);
        }
        let (_, got) = self.request(FS_GETXATTR, |w| {
            w.u64(ino);
            w.bytes(name);
        })?;
        Ok(self.reply(got).to_vec())
    }

    /// Sets extended attribute `name` of `ino` (`flags`: `XATTR_CREATE`, `XATTR_REPLACE`).
    pub fn setxattr(&mut self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::setxattr(ino, name, value, flags);
        }
        let _changed = Changed(ino);
        self.request(FS_SETXATTR, |w| {
            w.u64(ino);
            w.bytes(name);
            w.bytes(value);
            w.u64(flags as u64);
        })
        .map(|_| ())
    }

    /// `ino`'s extended attribute names, each NUL-terminated.
    pub fn listxattr(&mut self, ino: u64) -> Result<Vec<u8>, i64> {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::listxattr(ino);
        }
        let (_, got) = self.request(FS_LISTXATTR, |w| {
            w.u64(ino);
        })?;
        Ok(self.reply(got).to_vec())
    }

    /// Removes extended attribute `name` of `ino`.
    pub fn removexattr(&mut self, ino: u64, name: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::removexattr(ino, name);
        }
        let _changed = Changed(ino);
        self.request(FS_REMOVEXATTR, |w| {
            w.u64(ino);
            w.bytes(name);
        })
        .map(|_| ())
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::readlink(ino);
        }
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
        if fuse::is_fuse(ino) || fuse::is_fuse(dir) {
            self.window = None;
            return fuse::link(ino, dir, name);
        }
        let r = self.request(FS_LINK, |w| {
            w.u64(ino);
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ());
        forget_all_attrs();
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::unlink(dir, name);
        }
        let r = self.request(FS_UNLINK, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ());
        forget_all_attrs();
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::rmdir(dir, name);
        }
        let r = self.request(FS_RMDIR, |w| {
            w.u64(dir);
            w.bytes(name);
        })
        .map(|_| ());
        forget_all_attrs();
        forget_names();
        r
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
        if fuse::is_fuse(sdir) || fuse::is_fuse(ddir) {
            self.window = None;
            return fuse::rename(sdir, sname, ddir, dname);
        }
        let r = self.request(FS_RENAME, |w| {
            w.u64(sdir);
            w.bytes(sname);
            w.u64(ddir);
            w.bytes(dname);
        })
        .map(|_| ());
        forget_all_attrs();
        forget_names();
        r
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
        if fuse::is_fuse(dir) {
            self.window = None;
            return fuse::readdir(dir, cookie, max);
        }
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::open_ref(ino);
        }
        let _ = self.request(FS_OPEN_REF, |w| {
            w.u64(ino);
        });
    }

    /// A descriptor on `ino` was closed.
    ///
    /// # Arguments
    /// * `ino` - Inode object ID being released.
    pub fn release(&mut self, ino: u64) {
        if fuse::is_fuse(ino) {
            self.window = None;
            return fuse::release(ino);
        }
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
        if fuse::is_fuse(ino) {
            self.window = None;
            return;
        }
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
        let r = self.request(FS_SNAPSHOT, |w| {
            w.u64(dataset_index as u64);
            w.bytes(snap_name.as_bytes());
        })
        .map(|r| r.0);
        forget_names();
        r
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
        let r = self.request(op, |w| {
            w.bytes(path.as_bytes());
            w.u64(repair as u64);
        })
        .map(|_| ());
        forget_all_attrs();
        forget_names();
        r
    }
}
