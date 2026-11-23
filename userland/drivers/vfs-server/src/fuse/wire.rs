//! # The FUSE wire format and a connection's tables (wave 9, Group 6b-2)
//!
//! Pure code (no system calls), so the host unit tests (`tests/host-w9-fuse`) cover it: the
//! request header, argument encoding, reply parsing, the node table (the daemon's node IDs
//! behind vfs-server's local node numbers) and the daemon's handles per open node. Protocol
//! 7.14, as the kernel's own client (`src/compat/linux/fuse.rs`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const LOOKUP: u32 = 1;
pub const GETATTR: u32 = 3;
pub const SETATTR: u32 = 4;
pub const READLINK: u32 = 5;
pub const SYMLINK: u32 = 6;
pub const MKNOD: u32 = 8;
pub const MKDIR: u32 = 9;
pub const UNLINK: u32 = 10;
pub const RMDIR: u32 = 11;
pub const RENAME: u32 = 12;
pub const LINK: u32 = 13;
pub const OPEN: u32 = 14;
pub const READ: u32 = 15;
pub const WRITE: u32 = 16;
pub const STATFS: u32 = 17;
pub const RELEASE: u32 = 18;
pub const SETXATTR: u32 = 21;
pub const GETXATTR: u32 = 22;
pub const LISTXATTR: u32 = 23;
pub const REMOVEXATTR: u32 = 24;
pub const FLUSH: u32 = 25;
pub const INIT: u32 = 26;
pub const OPENDIR: u32 = 27;
pub const READDIR: u32 = 28;
pub const RELEASEDIR: u32 = 29;
pub const CREATE: u32 = 35;
pub const INTERRUPT: u32 = 36;

/// Protocol minor version offered.
pub const MINOR: u32 = 14;
const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
const FUSE_BIG_WRITES: u32 = 1 << 5;

pub const IN_HEADER: usize = 40;
pub const OUT_HEADER: usize = 16;
/// `struct fuse_attr`.
pub const ATTR: usize = 88;
/// `struct fuse_entry_out` without its attributes.
pub const ENTRY: usize = 40;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;

pub fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// `name` with its NUL.
pub fn cstr(name: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(name.len() + 1);
    v.extend_from_slice(name);
    v.push(0);
    v
}

/// Little-endian values of the given widths (4 or 8 bytes).
pub fn le(vals: &[u64], widths: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (v, w) in vals.iter().zip(widths) {
        if *w == 4 {
            out.extend_from_slice(&(*v as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    out
}

/// Who a request is made for (the in-header's uid, gid, pid).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Who {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

/// A whole request: the header (`len, opcode, unique, nodeid, uid, gid, pid, padding`) and
/// the arguments.
pub fn request(opcode: u32, unique: u64, nodeid: u64, who: Who, args: &[&[u8]]) -> Vec<u8> {
    let len = IN_HEADER + args.iter().map(|a| a.len()).sum::<usize>();
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_le_bytes());
    m.extend_from_slice(&opcode.to_le_bytes());
    m.extend_from_slice(&unique.to_le_bytes());
    m.extend_from_slice(&nodeid.to_le_bytes());
    m.extend_from_slice(&who.uid.to_le_bytes());
    m.extend_from_slice(&who.gid.to_le_bytes());
    m.extend_from_slice(&who.pid.to_le_bytes());
    m.extend_from_slice(&[0u8; 4]);
    for a in args {
        m.extend_from_slice(a);
    }
    m
}

/// The unique ID of request `m`.
pub fn unique_of(m: &[u8]) -> u64 {
    u64_at(m, 8)
}

/// `INIT`'s arguments: version, readahead, flags.
pub fn init_args() -> Vec<u8> {
    le(&[7, MINOR as u64, 128 * 1024, (FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES) as u64], &[4, 4, 4, 4])
}

/// The daemon's `INIT` reply: `Some(max_write)` when it speaks protocol 7.
pub fn init_reply(err: i32, body: &[u8]) -> Option<u32> {
    if err != 0 || body.len() < 8 || u32_at(body, 0) != 7 {
        return None;
    }
    Some(if body.len() >= 24 { u32_at(body, 20).clamp(4096, 128 * 1024) } else { 4096 })
}

/// A reply's header: `(error, unique)`, or `None` when it is malformed (shorter than a
/// header, a length that is not the write's, an error that is not `-errno`).
pub fn reply_header(data: &[u8]) -> Option<(i32, u64)> {
    if data.len() < OUT_HEADER || u32_at(data, 0) as usize != data.len() {
        return None;
    }
    let err = u32_at(data, 4) as i32;
    let unique = u64_at(data, 8);
    if unique != 0 && (err > 0 || err < -4095) {
        return None;
    }
    Some((err, unique))
}

/// A valid-for time (`secs`, `nsecs`) in milliseconds, at most an hour.
pub fn valid_ms(secs: u64, nsecs: u32) -> u64 {
    secs.min(3600) * 1000 + (nsecs / 1_000_000) as u64
}

/// `fuse_setattr_in` changes the size (FATTR_SIZE).
pub fn setattr_size(set_in: &[u8]) -> bool {
    u32_at(set_in, 0) & 8 != 0
}

/// The daemon's handle of one open node, per kind of use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handles {
    pub read: Option<u64>,
    pub write: Option<u64>,
    pub dir: Option<u64>,
    pub refs: u32,
}

/// A handle kind an operation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Read,
    Write,
    Dir,
}

impl Want {
    /// The open request: opcode and the flags to try, in order.
    pub fn open(self) -> (u32, &'static [u32]) {
        match self {
            Want::Read => (OPEN, &[0]),
            // O_RDWR, else O_WRONLY
            Want::Write => (OPEN, &[2, 1]),
            Want::Dir => (OPENDIR, &[0o200000]),
        }
    }
}

impl Handles {
    pub fn get(&self, w: Want) -> Option<u64> {
        match w {
            Want::Read => self.read,
            Want::Write => self.write,
            Want::Dir => self.dir,
        }
    }

    pub fn set(&mut self, w: Want, fh: u64) {
        match w {
            Want::Read => self.read = Some(fh),
            Want::Write => self.write = Some(fh),
            Want::Dir => self.dir = Some(fh),
        }
    }

    /// The release requests for these handles: `(opcode, args)` (a written one is flushed
    /// first).
    pub fn releases(&self) -> Vec<(u32, Vec<u8>)> {
        let mut v = Vec::new();
        if let Some(fh) = self.write {
            v.push((FLUSH, le(&[fh, 0, 0, 0], &[8, 4, 4, 8])));
            v.push((RELEASE, le(&[fh, 1, 0, 0], &[8, 4, 4, 8])));
        }
        if let Some(fh) = self.read {
            v.push((RELEASE, le(&[fh, 0, 0, 0], &[8, 4, 4, 8])));
        }
        if let Some(fh) = self.dir {
            v.push((RELEASEDIR, le(&[fh, 0, 0, 0], &[8, 4, 4, 8])));
        }
        v
    }
}

/// A node vfs-server knows.
#[derive(Clone, Debug)]
pub struct Node {
    pub nodeid: u64,
    pub parent: u64,
    pub name: Vec<u8>,
    /// Its `fuse_attr` while the daemon says it stays valid (until the time, in ms).
    pub cached: Option<([u8; ATTR], u64)>,
}

/// The node table of one connection: local numbers (1 = the root) for the daemon's node IDs.
#[derive(Clone, Debug)]
pub struct Nodes {
    pub nodes: Vec<Node>,
    pub by_nodeid: BTreeMap<u64, u64>,
}

impl Default for Nodes {
    fn default() -> Self {
        Self::new()
    }
}

impl Nodes {
    pub fn new() -> Self {
        let n = |id| Node { nodeid: id, parent: 1, name: Vec::new(), cached: None };
        Nodes { nodes: alloc::vec![n(0), n(1)], by_nodeid: BTreeMap::from([(1, 1)]) }
    }

    /// The daemon's node ID of local node `l`.
    pub fn nodeid(&self, l: u64) -> Option<u64> {
        self.nodes.get(l as usize).map(|n| n.nodeid).filter(|&n| n != 0)
    }

    /// The local node of the daemon's `nodeid` (new if unknown), found as `name` in `parent`.
    pub fn intern(&mut self, nodeid: u64, parent: u64, name: &[u8]) -> u64 {
        if let Some(&l) = self.by_nodeid.get(&nodeid) {
            if l != 1 {
                let n = &mut self.nodes[l as usize];
                n.parent = parent;
                n.name = name.to_vec();
            }
            return l;
        }
        let l = self.nodes.len() as u64;
        self.nodes.push(Node { nodeid, parent, name: name.to_vec(), cached: None });
        self.by_nodeid.insert(nodeid, l);
        l
    }

    /// Keeps `attr` of `l` for `ms` (0: not at all), from `now`.
    pub fn cache(&mut self, l: u64, attr: &[u8], ms: u64, now: u64) {
        let Some(n) = self.nodes.get_mut(l as usize) else { return };
        if ms == 0 || attr.len() < ATTR {
            n.cached = None;
            return;
        }
        let mut a = [0u8; ATTR];
        a.copy_from_slice(&attr[..ATTR]);
        n.cached = Some((a, now + ms));
    }

    /// `l`'s kept attributes if still valid at `now`.
    pub fn cached(&self, l: u64, now: u64) -> Option<[u8; ATTR]> {
        let (a, until) = self.nodes.get(l as usize)?.cached?;
        (now < until).then_some(a)
    }

    /// Forgets the kept attributes of `l`, or of every node.
    pub fn uncache(&mut self, l: Option<u64>) {
        match l {
            Some(l) => {
                if let Some(n) = self.nodes.get_mut(l as usize) {
                    n.cached = None;
                }
            }
            None => self.nodes.iter_mut().for_each(|n| n.cached = None),
        }
    }

    /// `l`'s directory and name (`None` for the root or an unknown node).
    pub fn name_of(&self, l: u64) -> Option<(u64, &[u8])> {
        if l == 1 {
            return None;
        }
        let n = self.nodes.get(l as usize).filter(|n| n.nodeid != 0)?;
        Some((n.parent, &n.name))
    }
}

/// A `fuse_entry_out` reply: `(nodeid, entry valid ms, attr valid ms, attributes)`.
pub fn entry(r: &[u8]) -> Option<(u64, u64, u64, &[u8])> {
    let nodeid = u64_at(r, 0);
    if nodeid == 0 || r.len() < ENTRY + ATTR {
        return None;
    }
    Some((nodeid, valid_ms(u64_at(r, 16), u32_at(r, 32)), valid_ms(u64_at(r, 24), u32_at(r, 36)), &r[ENTRY..ENTRY + ATTR]))
}

/// A `fuse_attr_out` reply: `(attr valid ms, attributes)`.
pub fn attr_out(r: &[u8]) -> Option<(u64, &[u8])> {
    if r.len() < 16 + ATTR {
        return None;
    }
    Some((valid_ms(u64_at(r, 0), u32_at(r, 8)), &r[16..16 + ATTR]))
}

/// The mode in a `fuse_attr`.
pub fn attr_mode(a: &[u8]) -> u32 {
    u32_at(a, 60)
}

/// Read/write arguments (`fuse_read_in` / `fuse_write_in` have the same layout).
pub fn rw_args(fh: u64, offset: u64, size: usize) -> Vec<u8> {
    le(&[fh, offset, size as u64, 0, 0, 0, 0], &[8, 8, 4, 4, 8, 4, 4])
}

/// Connection numbers: `FUSE_SVC_CONN | n` for `n` in 1..0x4000, skipping live ones.
pub fn next_conn(next: &mut u16, live: impl Fn(u16) -> bool) -> u16 {
    loop {
        *next = (*next % 0x3FFF) + 1;
        let c = 0x8000 | *next;
        if !live(c) {
            return c;
        }
    }
}

/// A local inode number: `FUSE_BIT | conn << 40 | local`.
pub fn ino(conn: u16, local: u64) -> u64 {
    1 << 62 | (conn as u64) << 40 | (local & ((1 << 40) - 1))
}

/// `(conn, local)` of a FUSE inode number of vfs-server's (`None`: not one).
pub fn split(ino: u64) -> Option<(u16, u64)> {
    if ino >> 62 != 1 {
        return None;
    }
    let conn = ((ino >> 40) & 0xFFFF) as u16;
    (conn & 0x8000 != 0).then_some((conn, ino & ((1 << 40) - 1)))
}
