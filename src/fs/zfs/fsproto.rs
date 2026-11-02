//! # File System Protocol: the kernel's requests to the ZFS file server
//!
//! The OpenZFS implementation runs as a Ring 3 program (`userland/drivers/zfs-server`); the
//! kernel's file layer asks it for ZPL operations (POSIX-style, by inode) over
//! `ENDPOINT_ZFS_SERVER`. This module is shared by both sides
//! (the server includes it with `#[path]`): the operation codes, the types they carry, and
//! their encoding in the service window.
//!
//! ## Wire format
//!
//! A request is a message whose label is the operation; its parameters are encoded in the
//! window from offset 0 (`Writer`: little-endian `u64`s and length-prefixed byte strings).
//! The reply carries `args = [status (value or -errno), value, reply bytes, events]`: reply
//! data is in the window from offset 0, and the inotify events the operation caused are at
//! `EVENT_OFFSET` (the kernel delivers them to its watchers).

use alloc::string::String;
use alloc::vec::Vec;

use super::types::{DnodeType, S_IFDIR, S_IFMT};

/// Largest data transfer of one read or write request.
pub const MAX_IO: usize = 128 * 1024;
/// Where inotify events start in the window of a reply.
pub const EVENT_OFFSET: usize = 192 * 1024;
/// Space for inotify events in the window.
pub const EVENT_SPACE: usize = 64 * 1024;

/// Reply label.
pub const FS_REPLY: u32 = 0x31FF;
/// `() -> root directory inode`.
pub const FS_ROOT: u32 = 0x3101;
/// `(dir, name) -> inode`.
pub const FS_LOOKUP: u32 = 0x3102;
/// `(root, base, follow, path) -> inode`: path resolution inside `root` (symlinks expanded).
pub const FS_RESOLVE: u32 = 0x3103;
/// `(ino) -> Attr`.
pub const FS_GETATTR: u32 = 0x3104;
/// `(ino, SetAttr) -> Attr`.
pub const FS_SETATTR: u32 = 0x3105;
/// `(ino, offset, len) -> bytes`.
pub const FS_READ: u32 = 0x3106;
/// `(ino, offset, bytes) -> count`.
pub const FS_WRITE: u32 = 0x3107;
/// `(dir, name, perm, uid, gid) -> inode`.
pub const FS_CREATE: u32 = 0x3108;
/// `(dir, name, mode, rdev, uid, gid) -> inode`.
pub const FS_MKNOD: u32 = 0x3109;
/// `(dir, name, perm, uid, gid) -> inode`.
pub const FS_MKDIR: u32 = 0x310A;
/// `(dir, name, target, uid, gid) -> inode`.
pub const FS_SYMLINK: u32 = 0x310B;
/// `(ino) -> bytes`.
pub const FS_READLINK: u32 = 0x310C;
/// `(ino, dir, name)`.
pub const FS_LINK: u32 = 0x310D;
/// `(dir, name)`.
pub const FS_UNLINK: u32 = 0x310E;
/// `(dir, name)`.
pub const FS_RMDIR: u32 = 0x310F;
/// `(sdir, sname, ddir, dname)`.
pub const FS_RENAME: u32 = 0x3110;
/// `(dir, cookie, max) -> entries`.
pub const FS_READDIR: u32 = 0x3111;
/// `() -> (total, free, files)` as three `u64`s.
pub const FS_STATFS: u32 = 0x3112;
/// `(ino)`: a descriptor opened it.
pub const FS_OPEN_REF: u32 = 0x3113;
/// `(ino)`: a descriptor on it was closed.
pub const FS_RELEASE: u32 = 0x3114;
/// `(ino, mask)`: report an inotify event for it.
pub const FS_NOTIFY: u32 = 0x3115;
/// `() -> txg`: commit the open transaction group.
pub const FS_SYNC: u32 = 0x3116;
/// `() -> committed`: commit if there are changes (the kernel's `txgd` sends it every 5 s).
pub const FS_SYNC_IF_DIRTY: u32 = 0x3117;
/// `(dataset index, name) -> txg`.
pub const FS_SNAPSHOT: u32 = 0x3118;
/// `() -> (total bytes, allocated, free, txg, open txg)` as five `u64`s.
pub const FS_POOL_STATUS: u32 = 0x3119;
/// `(ino) -> (birth txg, allocated, checksum[4])` as six `u64`s.
pub const FS_OBJECT_INFO: u32 = 0x311A;
/// `() -> count`, then per dataset or snapshot: name, mount point, txg, is snapshot.
pub const FS_DATASETS: u32 = 0x311B;
/// `()`: runs the self test (output on the console).
pub const FS_SELFTEST: u32 = 0x311C;
/// `()`: verifies every block of the pool (output on the console).
pub const FS_VERIFY: u32 = 0x311D;
/// `(path, repair)`: checks (and repairs) a directory tree (output on the console).
pub const FS_FSCK: u32 = 0x311E;

/// Operation not permitted.
pub const EPERM: i64 = -1;
/// No such file or directory.
pub const ENOENT: i64 = -2;
/// Input/output error.
pub const EIO: i64 = -5;
/// File exists.
pub const EEXIST: i64 = -17;
/// Cross-device link.
pub const EXDEV: i64 = -18;
/// Not a directory.
pub const ENOTDIR: i64 = -20;
/// Is a directory.
pub const EISDIR: i64 = -21;
/// Invalid argument.
pub const EINVAL: i64 = -22;
/// File too large.
pub const EFBIG: i64 = -27;
/// No space left on device.
pub const ENOSPC: i64 = -28;
/// Too many links.
pub const EMLINK: i64 = -31;
/// File name too long.
pub const ENAMETOOLONG: i64 = -36;
/// Directory not empty.
pub const ENOTEMPTY: i64 = -39;
/// Too many levels of symbolic links.
pub const ELOOP: i64 = -40;

/// Attributes of an inode (the fields of Linux `struct stat`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Attr {
    /// Inode / object identifier.
    pub ino: u64,
    /// File mode and permission bits (e.g. `S_IFREG | 0o644`).
    pub mode: u32,
    /// Number of hard links pointing to this inode.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID for character / block special files.
    pub rdev: u64,
    /// Logical size of the file in bytes.
    pub size: u64,
    /// Allocated size in 512-byte units.
    pub blocks: u64,
    /// Last access timestamp as (seconds, nanoseconds).
    pub atime: (i64, u32),
    /// Last modification timestamp as (seconds, nanoseconds).
    pub mtime: (i64, u32),
    /// Status change timestamp as (seconds, nanoseconds).
    pub ctime: (i64, u32),
    /// Inode generation counter for NFS / stale handle detection.
    pub generation: u64,
    /// Transaction group in which this inode was created.
    pub birth_txg: u64,
}

impl Attr {
    /// Determines the dnode type from the mode bits.
    ///
    /// # Returns
    ///
    /// The mapped [`DnodeType`].
    pub fn kind(&self) -> DnodeType {
        DnodeType::from_mode(self.mode)
    }

    /// Returns true if this inode represents a directory.
    ///
    /// # Returns
    ///
    /// `true` if this inode is a directory, `false` otherwise.
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// Attribute changes for `setattr`; `None` leaves a field unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetAttr {
    /// Optional updated file mode and permissions.
    pub mode: Option<u32>,
    /// Optional updated owner user ID.
    pub uid: Option<u32>,
    /// Optional updated owner group ID.
    pub gid: Option<u32>,
    /// Optional updated file size (truncates or extends).
    pub size: Option<u64>,
    /// Optional updated access time (seconds, nanoseconds).
    pub atime: Option<(i64, u32)>,
    /// Optional updated modification time (seconds, nanoseconds).
    pub mtime: Option<(i64, u32)>,
}

/// One entry returned by `readdir`.
pub struct ReaddirEntry {
    /// Name of the directory entry as a byte vector.
    pub name: Vec<u8>,
    /// Inode number of the target object.
    pub ino: u64,
    /// Directory entry type identifier (`DT_REG`, `DT_DIR`, etc.).
    pub dtype: u8,
    /// Cookie to pass to `readdir` to continue after this entry.
    pub next_cookie: u64,
}

/// A directory entry as the shell lists it.
#[derive(Debug, Clone)]
pub struct ZapEntry {
    /// Name of the directory entry.
    pub name: String,
    /// Inode / target object ID.
    pub object_id: u64,
    /// Dnode type representation (e.g. file, directory, symlink).
    pub obj_type: DnodeType,
    /// Whether this directory entry represents a valid record.
    pub is_valid: bool,
}

impl ZapEntry {
    /// Creates a new directory entry record.
    ///
    /// # Arguments
    /// * `name` - Raw byte slice of the file name.
    /// * `object_id` - Target object identifier.
    /// * `obj_type` - Dnode type of the target.
    ///
    /// # Returns
    ///
    /// A new [`ZapEntry`] instance.
    pub fn new(name: &[u8], object_id: u64, obj_type: DnodeType) -> Self {
        Self { name: String::from_utf8_lossy(name).into_owned(), object_id, obj_type, is_valid: true }
    }

    /// Returns a string slice of the entry name.
    ///
    /// # Returns
    ///
    /// The entry name as a `&str`.
    pub fn name_str(&self) -> &str {
        &self.name
    }
}

/// An inotify event caused by an operation.
pub struct Event {
    /// Inode the event is about.
    pub ino: u64,
    /// `IN_*` mask.
    pub mask: u32,
    /// Pairs `IN_MOVED_FROM` with `IN_MOVED_TO`.
    pub cookie: u32,
    /// Entry name, for events on a directory about one of its entries.
    pub name: Vec<u8>,
}

/// Encodes parameters or results into the window.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Writes from the start of `buf`.
    ///
    /// # Arguments
    /// * `buf` - The destination buffer to write encoded data into.
    ///
    /// # Returns
    ///
    /// A new [`Writer`] instance.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer.
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Appends a `u64`; returns false if it does not fit.
    ///
    /// # Arguments
    /// * `v` - The 64-bit integer to append.
    ///
    /// # Returns
    ///
    /// `true` if written successfully, `false` if the buffer is full.
    pub fn u64(&mut self, v: u64) -> bool {
        self.raw(&v.to_le_bytes())
    }

    /// Appends a length-prefixed byte string; returns false if it does not fit.
    ///
    /// # Arguments
    /// * `b` - The byte slice to append.
    ///
    /// # Returns
    ///
    /// `true` if written successfully, `false` if insufficient capacity.
    pub fn bytes(&mut self, b: &[u8]) -> bool {
        self.pos + 4 + b.len() <= self.buf.len() && self.raw(&(b.len() as u32).to_le_bytes()) && self.raw(b)
    }

    /// Appends raw bytes without length prefix.
    ///
    /// # Arguments
    /// * `b` - Raw bytes to append.
    ///
    /// # Returns
    ///
    /// `true` on success, `false` if insufficient space.
    fn raw(&mut self, b: &[u8]) -> bool {
        if self.pos + b.len() > self.buf.len() {
            return false;
        }
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        true
    }

    /// Appends an attribute record.
    ///
    /// # Arguments
    /// * `a` - File attributes to encode.
    ///
    /// # Returns
    ///
    /// `true` if all attributes were written successfully, `false` otherwise.
    pub fn attr(&mut self, a: &Attr) -> bool {
        self.u64(a.ino)
            && self.u64(a.mode as u64 | (a.nlink as u64) << 32)
            && self.u64(a.uid as u64 | (a.gid as u64) << 32)
            && self.u64(a.rdev)
            && self.u64(a.size)
            && self.u64(a.blocks)
            && self.time(a.atime)
            && self.time(a.mtime)
            && self.time(a.ctime)
            && self.u64(a.generation)
            && self.u64(a.birth_txg)
    }

    /// Appends a timestamp tuple (seconds, nanoseconds).
    ///
    /// # Arguments
    /// * `t` - Timestamp tuple to encode.
    ///
    /// # Returns
    ///
    /// `true` on success, `false` if insufficient space.
    fn time(&mut self, t: (i64, u32)) -> bool {
        self.u64(t.0 as u64) && self.u64(t.1 as u64)
    }

    /// Appends an attribute change record (a presence mask, then the values).
    ///
    /// # Arguments
    /// * `s` - Attribute changes to encode.
    ///
    /// # Returns
    ///
    /// `true` on success, `false` if insufficient space.
    pub fn setattr(&mut self, s: &SetAttr) -> bool {
        let mask = s.mode.is_some() as u64
            | (s.uid.is_some() as u64) << 1
            | (s.gid.is_some() as u64) << 2
            | (s.size.is_some() as u64) << 3
            | (s.atime.is_some() as u64) << 4
            | (s.mtime.is_some() as u64) << 5;
        self.u64(mask)
            && self.u64(s.mode.unwrap_or(0) as u64)
            && self.u64(s.uid.unwrap_or(0) as u64)
            && self.u64(s.gid.unwrap_or(0) as u64)
            && self.u64(s.size.unwrap_or(0))
            && self.time(s.atime.unwrap_or((0, 0)))
            && self.time(s.mtime.unwrap_or((0, 0)))
    }

    /// Appends a directory entry.
    ///
    /// # Arguments
    /// * `e` - Directory entry to encode.
    ///
    /// # Returns
    ///
    /// `true` on success, `false` if insufficient space.
    pub fn entry(&mut self, e: &ReaddirEntry) -> bool {
        self.u64(e.ino) && self.u64(e.dtype as u64) && self.u64(e.next_cookie) && self.bytes(&e.name)
    }

    /// Appends an inotify event.
    ///
    /// # Arguments
    /// * `e` - Event record to encode.
    ///
    /// # Returns
    ///
    /// `true` on success, `false` if insufficient space.
    pub fn event(&mut self, e: &Event) -> bool {
        self.u64(e.ino) && self.u64(e.mask as u64 | (e.cookie as u64) << 32) && self.bytes(&e.name)
    }
}

/// Decodes what a [`Writer`] encoded.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Reads from the start of `buf`.
    ///
    /// # Arguments
    /// * `buf` - The buffer to read encoded protocol data from.
    ///
    /// # Returns
    ///
    /// A new [`Reader`] instance.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Next `u64` (0 past the end).
    ///
    /// # Returns
    ///
    /// The decoded `u64` value.
    pub fn u64(&mut self) -> u64 {
        let v = self.buf.get(self.pos..self.pos + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
        self.pos += 8;
        v
    }

    /// Next byte string (empty past the end).
    ///
    /// # Returns
    ///
    /// The decoded byte slice.
    pub fn bytes(&mut self) -> &'a [u8] {
        let len = self.buf.get(self.pos..self.pos + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
        self.pos += 4;
        let b = self.buf.get(self.pos..self.pos + len).unwrap_or(&[]);
        self.pos += len;
        b
    }

    /// Decodes a timestamp tuple.
    ///
    /// # Returns
    ///
    /// A `(seconds, nanoseconds)` tuple.
    fn time(&mut self) -> (i64, u32) {
        (self.u64() as i64, self.u64() as u32)
    }

    /// Next attribute record.
    ///
    /// # Returns
    ///
    /// The decoded [`Attr`] record.
    pub fn attr(&mut self) -> Attr {
        let ino = self.u64();
        let mode_nlink = self.u64();
        let ids = self.u64();
        Attr {
            ino,
            mode: mode_nlink as u32,
            nlink: (mode_nlink >> 32) as u32,
            uid: ids as u32,
            gid: (ids >> 32) as u32,
            rdev: self.u64(),
            size: self.u64(),
            blocks: self.u64(),
            atime: self.time(),
            mtime: self.time(),
            ctime: self.time(),
            generation: self.u64(),
            birth_txg: self.u64(),
        }
    }

    /// Next attribute change record.
    ///
    /// # Returns
    ///
    /// The decoded [`SetAttr`] record.
    pub fn setattr(&mut self) -> SetAttr {
        let mask = self.u64();
        let (mode, uid, gid, size) = (self.u64() as u32, self.u64() as u32, self.u64() as u32, self.u64());
        let (atime, mtime) = (self.time(), self.time());
        SetAttr {
            mode: (mask & 1 != 0).then_some(mode),
            uid: (mask & 2 != 0).then_some(uid),
            gid: (mask & 4 != 0).then_some(gid),
            size: (mask & 8 != 0).then_some(size),
            atime: (mask & 16 != 0).then_some(atime),
            mtime: (mask & 32 != 0).then_some(mtime),
        }
    }

    /// Next directory entry.
    ///
    /// # Returns
    ///
    /// The decoded [`ReaddirEntry`] record.
    pub fn entry(&mut self) -> ReaddirEntry {
        let ino = self.u64();
        let dtype = self.u64() as u8;
        let next_cookie = self.u64();
        ReaddirEntry { name: self.bytes().to_vec(), ino, dtype, next_cookie }
    }

    /// Next inotify event.
    ///
    /// # Returns
    ///
    /// The decoded [`Event`] record.
    pub fn event(&mut self) -> Event {
        let ino = self.u64();
        let mc = self.u64();
        Event { ino, mask: mc as u32, cookie: (mc >> 32) as u32, name: self.bytes().to_vec() }
    }
}
