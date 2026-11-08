//! # FUSE
//!
//! File systems served by user-space daemons through `/dev/fuse` (char 10:229), with the
//! Linux FUSE protocol (7.14): the daemon reads requests from its descriptor and writes the
//! replies back. `fusermount3` mounts a connection (`mount(2)` with `fd=N`); the files below
//! the mount point are then the daemon's.
//!
//! A daemon's files have inode numbers of their own: [`FUSE_BIT`], the connection and an
//! index into the connection's node table (`1` is the root). The file server client
//! ([`crate::fs::zfs::ZfsServer`]) sends every operation on such an inode here, and path
//! lookups cross between the pool and FUSE mounts at mount points ([`walk`]).
//!
//! Open files: the daemon's file handles are kept per inode (one for reading, one for
//! writing, one for listing) while the inode is open, and released with its last close.
//! Attributes are not cached: every `stat` asks the daemon.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use spin::Mutex;

use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const ENOENT: i64 = -2;
const EIO: i64 = -5;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EXDEV: i64 = -18;
const ENODEV: i64 = -19;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ELOOP: i64 = -40;
const EOPNOTSUPP: i64 = -95;
const ENOTCONN: i64 = -107;

/// Marks a FUSE inode (bit 63 clear: `u64::MAX` and its neighbours are Hydra's own).
pub const FUSE_BIT: u64 = 1 << 62;
const CONN_SHIFT: u32 = 40;
const LOCAL_MASK: u64 = (1 << CONN_SHIFT) - 1;

/// `/dev/fuse`.
pub const RDEV: u64 = super::chardev::makedev(10, 229);

// Opcodes
const LOOKUP: u32 = 1;
const GETATTR: u32 = 3;
const SETATTR: u32 = 4;
const READLINK: u32 = 5;
const SYMLINK: u32 = 6;
const MKNOD: u32 = 8;
const MKDIR: u32 = 9;
const UNLINK: u32 = 10;
const RMDIR: u32 = 11;
const RENAME: u32 = 12;
const LINK: u32 = 13;
const OPEN: u32 = 14;
const READ: u32 = 15;
const WRITE: u32 = 16;
const STATFS: u32 = 17;
const RELEASE: u32 = 18;
const SETXATTR: u32 = 21;
const GETXATTR: u32 = 22;
const LISTXATTR: u32 = 23;
const REMOVEXATTR: u32 = 24;
const FLUSH: u32 = 25;
const INIT: u32 = 26;
const OPENDIR: u32 = 27;
const READDIR: u32 = 28;
const RELEASEDIR: u32 = 29;
const CREATE: u32 = 35;

/// Protocol version offered: 7.14 (libfuse offers splice from it; it splices only what fits
/// its pipe, and `splice` copies through `read`/`write`).
const MINOR: u32 = 14;
const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
const FUSE_BIG_WRITES: u32 = 1 << 5;

// setattr `valid` bits
const FATTR_MODE: u32 = 1;
const FATTR_UID: u32 = 2;
const FATTR_GID: u32 = 4;
const FATTR_SIZE: u32 = 8;
const FATTR_ATIME: u32 = 16;
const FATTR_MTIME: u32 = 32;

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;

/// Whether `ino` is a file of a FUSE daemon.
pub fn is_fuse(ino: u64) -> bool {
    ino >> 62 == 1
}

fn split(ino: u64) -> (u16, u64) {
    (((ino & !FUSE_BIT) >> CONN_SHIFT) as u16, ino & LOCAL_MASK)
}

fn make(conn: u16, local: u64) -> u64 {
    FUSE_BIT | ((conn as u64) << CONN_SHIFT) | local
}

/// A node the kernel knows: the daemon's node ID, its parent (local index) and the inode
/// number the daemon reports.
struct Node {
    nodeid: u64,
    parent: u64,
    user_ino: u64,
    /// The name it was last looked up by.
    name: Vec<u8>,
}

/// The daemon's file handles of one open inode.
#[derive(Default)]
struct Handles {
    read: Option<u64>,
    write: Option<u64>,
    dir: Option<u64>,
    refs: u32,
}

enum Slot {
    Waiting,
    Done(i32, Vec<u8>),
    /// Nobody waits (release): the reply is dropped.
    Discard,
}

struct State {
    queue: VecDeque<Vec<u8>>,
    slots: BTreeMap<u64, Slot>,
    next_unique: u64,
    init_unique: u64,
    initialized: bool,
    aborted: bool,
    max_write: u32,
    nodes: Vec<Node>,
    by_nodeid: BTreeMap<u64, u64>,
    handles: BTreeMap<u64, Handles>,
}

/// One connection: a daemon and the file system it serves.
pub struct Conn {
    /// Connection number (in the inode numbers of its files).
    pub id: u16,
    st: Mutex<State>,
    /// The daemon's readers wait here.
    daemon_wq: Arc<WaitQueue>,
    /// Callers waiting for replies (and for INIT) wait here.
    reply_wq: Arc<WaitQueue>,
    mounted: AtomicBool,
    owner: Mutex<(u32, u32, bool)>,
}

static NEXT_CONN: AtomicU16 = AtomicU16::new(1);
static CONNS: Mutex<BTreeMap<u16, Arc<Conn>>> = Mutex::new(BTreeMap::new());

fn conn_of(ino: u64) -> Result<Arc<Conn>, i64> {
    CONNS.lock().get(&split(ino).0).cloned().ok_or(ENOTCONN)
}

impl Conn {
    fn new() -> Arc<Self> {
        let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed) & 0x3FFF;
        let c = Arc::new(Conn {
            id,
            st: Mutex::new(State {
                queue: VecDeque::new(),
                slots: BTreeMap::new(),
                next_unique: 2,
                init_unique: 0,
                initialized: false,
                aborted: false,
                max_write: 4096,
                // Index 0 unused, 1 the root (node ID 1)
                nodes: alloc::vec![Node { nodeid: 0, parent: 0, user_ino: 0, name: Vec::new() }, Node { nodeid: 1, parent: 1, user_ino: 1, name: Vec::new() }],
                by_nodeid: BTreeMap::from([(1, 1)]),
                handles: BTreeMap::new(),
            }),
            daemon_wq: WaitQueue::new_shared(),
            reply_wq: WaitQueue::new_shared(),
            mounted: AtomicBool::new(false),
            owner: Mutex::new((0, 0, false)),
        });
        CONNS.lock().insert(id, c.clone());
        c
    }

    /// The connection's root directory.
    pub fn root(&self) -> u64 {
        make(self.id, 1)
    }

    /// Queues a request; returns its unique ID.
    fn push(&self, st: &mut State, opcode: u32, nodeid: u64, args: &[&[u8]], slot: Slot) -> u64 {
        let unique = st.next_unique;
        st.next_unique += 2;
        let len = IN_HEADER + args.iter().map(|a| a.len()).sum::<usize>();
        let (uid, gid) = crate::task::with_current_task_mut(|t| (t.euid, t.egid)).unwrap_or((0, 0));
        let pid = super::proc::current_ids().1 as u32;
        let mut m = Vec::with_capacity(len);
        m.extend_from_slice(&(len as u32).to_le_bytes());
        m.extend_from_slice(&opcode.to_le_bytes());
        m.extend_from_slice(&unique.to_le_bytes());
        m.extend_from_slice(&nodeid.to_le_bytes());
        m.extend_from_slice(&uid.to_le_bytes());
        m.extend_from_slice(&gid.to_le_bytes());
        m.extend_from_slice(&pid.to_le_bytes());
        m.extend_from_slice(&[0u8; 4]);
        for a in args {
            m.extend_from_slice(a);
        }
        st.queue.push_back(m);
        st.slots.insert(unique, slot);
        self.daemon_wq.wake_all();
        unique
    }

    /// Sends a request and waits for the reply: its data, or the daemon's errno.
    fn call(&self, opcode: u32, nodeid: u64, args: &[&[u8]]) -> Result<Vec<u8>, i64> {
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.reply_wq.clone()));
        // Requests wait for the daemon's INIT reply
        let unique = loop {
            waits.register();
            {
                let mut st = self.st.lock();
                if st.aborted {
                    return Err(ENOTCONN);
                }
                if st.initialized {
                    break self.push(&mut st, opcode, nodeid, args, Slot::Waiting);
                }
            }
            waits.wait(None);
        };
        loop {
            waits.register();
            {
                let mut st = self.st.lock();
                if matches!(st.slots.get(&unique), Some(Slot::Done(..))) {
                    let Some(Slot::Done(err, data)) = st.slots.remove(&unique) else { unreachable!() };
                    return if err < 0 { Err(err as i64) } else { Ok(data) };
                }
                if st.aborted {
                    st.slots.remove(&unique);
                    return Err(ENOTCONN);
                }
            }
            waits.wait(None);
        }
    }

    /// Sends a request without waiting for its reply.
    fn send(&self, opcode: u32, nodeid: u64, args: &[&[u8]]) {
        let mut st = self.st.lock();
        if !st.aborted && st.initialized {
            self.push(&mut st, opcode, nodeid, args, Slot::Discard);
        }
    }

    /// Ends the connection: requests fail with `ENOTCONN`, the daemon reads `ENODEV`.
    pub fn abort(&self) {
        self.st.lock().aborted = true;
        self.daemon_wq.wake_all();
        self.reply_wq.wake_all();
    }

    /// Mounted: the daemon gets INIT.
    pub fn start(&self, uid: u32, gid: u32, allow_other: bool) {
        *self.owner.lock() = (uid, gid, allow_other);
        self.mounted.store(true, Ordering::Release);
        let mut init = Vec::new();
        for v in [7u32, MINOR, 128 * 1024, FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES] {
            init.extend_from_slice(&v.to_le_bytes());
        }
        let mut st = self.st.lock();
        let u = self.push(&mut st, INIT, 0, &[&init], Slot::Discard);
        st.init_unique = u;
    }

    /// The daemon's node ID of local node `local`.
    fn nodeid(&self, local: u64) -> Result<u64, i64> {
        self.st.lock().nodes.get(local as usize).map(|n| n.nodeid).filter(|&n| n != 0).ok_or(ENOENT)
    }

    /// The local node of the daemon's `nodeid` (a new one if unknown), under `parent`.
    fn intern(&self, nodeid: u64, parent: u64, user_ino: u64, name: &[u8]) -> u64 {
        let mut st = self.st.lock();
        if let Some(&l) = st.by_nodeid.get(&nodeid) {
            let n = &mut st.nodes[l as usize];
            if l != 1 {
                n.parent = parent;
                n.name = name.to_vec();
            }
            n.user_ino = user_ino;
            return l;
        }
        let l = st.nodes.len() as u64;
        st.nodes.push(Node { nodeid, parent, user_ino, name: name.to_vec() });
        st.by_nodeid.insert(nodeid, l);
        l
    }

    /// Whether the caller may use the file system: its owner, or anyone with `allow_other`.
    fn permitted(&self) -> Result<(), i64> {
        let (uid, _, other) = *self.owner.lock();
        let euid = crate::task::with_current_task_mut(|t| t.euid).unwrap_or(0);
        if other || euid == uid { Ok(()) } else { Err(EACCES) }
    }
}

// ----------------------------------------------------------------------
// The device
// ----------------------------------------------------------------------

/// An open `/dev/fuse`: the daemon's end of a connection.
pub struct FuseDev {
    /// The connection.
    pub conn: Arc<Conn>,
    nonblock: AtomicBool,
}

impl Drop for FuseDev {
    fn drop(&mut self) {
        // The daemon is gone: its file system answers ENOTCONN
        self.conn.abort();
    }
}

/// `open("/dev/fuse")`.
pub fn open(flags: u32) -> Result<Arc<dyn super::chardev::CharDevice>, i64> {
    Ok(Arc::new(FuseDev { conn: Conn::new(), nonblock: AtomicBool::new(flags & 0o4000 != 0) }))
}

impl FuseDev {
    fn read_request(&self, buf: &mut [u8]) -> i64 {
        let c = &self.conn;
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(c.daemon_wq.clone()));
        loop {
            waits.register();
            {
                let mut st = c.st.lock();
                if st.aborted {
                    return ENODEV;
                }
                if let Some(m) = st.queue.front() {
                    if m.len() > buf.len() {
                        return EINVAL;
                    }
                    let m = st.queue.pop_front().unwrap();
                    buf[..m.len()].copy_from_slice(&m);
                    return m.len() as i64;
                }
            }
            if self.nonblock.load(Ordering::Relaxed) {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    fn write_reply(&self, data: &[u8]) -> i64 {
        if data.len() < OUT_HEADER {
            return EINVAL;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let err = i32::from_le_bytes(data[4..8].try_into().unwrap());
        let unique = u64::from_le_bytes(data[8..16].try_into().unwrap());
        if len != data.len() {
            return EINVAL;
        }
        // A notification (its code in the error field; cache invalidation...): nothing is
        // cached
        if unique == 0 {
            return len as i64;
        }
        if err > 0 || err < -4095 {
            return EINVAL;
        }
        let c = &self.conn;
        let mut st = c.st.lock();
        if st.aborted {
            return ENODEV;
        }
        let body = data[OUT_HEADER..].to_vec();
        if unique == st.init_unique && !st.initialized {
            st.slots.remove(&unique);
            if err != 0 || body.len() < 8 {
                drop(st);
                c.abort();
                return len as i64;
            }
            let major = u32::from_le_bytes(body[0..4].try_into().unwrap());
            if major != 7 {
                drop(st);
                c.abort();
                return len as i64;
            }
            if body.len() >= 24 {
                let mw = u32::from_le_bytes(body[20..24].try_into().unwrap());
                st.max_write = mw.clamp(4096, 128 * 1024);
            }
            st.initialized = true;
            drop(st);
            c.reply_wq.wake_all();
            return len as i64;
        }
        match st.slots.get(&unique) {
            Some(Slot::Waiting) => {
                st.slots.insert(unique, Slot::Done(err, body));
                drop(st);
                c.reply_wq.wake_all();
            }
            Some(Slot::Discard) => {
                st.slots.remove(&unique);
            }
            _ => return ENOENT,
        }
        len as i64
    }
}

impl super::chardev::CharDevice for FuseDev {
    fn read(&self, buf: &mut [u8]) -> i64 {
        self.read_request(buf)
    }
    fn read_unlocked(&self, buf: &mut [u8]) -> Option<i64> {
        Some(self.read_request(buf))
    }
    fn write(&self, data: &[u8]) -> i64 {
        self.write_reply(data)
    }
    fn poll_events(&self) -> u32 {
        let st = self.conn.st.lock();
        if st.aborted {
            return 0x4 | 0x8; // POLLOUT | POLLERR
        }
        if st.queue.is_empty() { 0x4 } else { 0x1 | 0x4 }
    }
    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.conn.daemon_wq.clone()));
    }
    fn rdev(&self) -> u64 {
        RDEV
    }
    fn path(&self) -> String {
        String::from("/dev/fuse")
    }
    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }
    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
    fn as_fuse(&self) -> Option<Arc<Conn>> {
        Some(self.conn.clone())
    }
}

// ----------------------------------------------------------------------
// Mounts in the initial namespace (other namespaces keep theirs in their tables)
// ----------------------------------------------------------------------

/// A FUSE mount of the initial mount namespace.
#[derive(Clone)]
pub struct Ns0Mount {
    /// The directory mounted on.
    pub mountpoint: u64,
    /// The connection.
    pub conn: Arc<Conn>,
    /// Mount point path.
    pub path: String,
    /// File system type (`fuse.<name>`).
    pub fstype: String,
    /// Source (the daemon's name).
    pub source: String,
    /// Options as `/proc/mounts` shows them.
    pub opts: String,
}

static NS0: Mutex<Vec<Ns0Mount>> = Mutex::new(Vec::new());

/// The initial namespace's FUSE mounts as a mount list for the file server:
/// `(mountpoint, root, parent mount 0)`.
pub fn ns0_list() -> Vec<(u64, u64, usize)> {
    NS0.lock().iter().map(|m| (m.mountpoint, m.conn.root(), 0)).collect()
}

/// Whether the initial namespace has FUSE mounts.
pub fn ns0_any() -> bool {
    !NS0.lock().is_empty()
}

/// The mount (1-based index in [`ns0_list`]) a FUSE inode of the initial namespace lies in.
pub fn ns0_mnt_of(ino: u64) -> usize {
    if !is_fuse(ino) {
        return 0;
    }
    let c = split(ino).0;
    NS0.lock().iter().position(|m| m.conn.id == c).map_or(0, |i| i + 1)
}

/// The initial namespace's FUSE mounts.
pub fn ns0_snapshot() -> Vec<Ns0Mount> {
    NS0.lock().clone()
}

/// Records a FUSE mount of the initial namespace.
pub fn ns0_add(m: Ns0Mount) {
    NS0.lock().push(m);
}

/// Unmounts the initial namespace's FUSE mount whose root is `root`; the daemon's reads
/// end with `ENODEV`.
pub fn ns0_remove(root: u64) -> bool {
    let mut l = NS0.lock();
    let Some(i) = l.iter().position(|m| m.conn.root() == root) else { return false };
    let m = l.remove(i);
    drop(l);
    m.conn.abort();
    true
}

/// `/proc/mounts` lines of the initial namespace's FUSE mounts.
pub fn ns0_mounts_text() -> String {
    let mut out = String::new();
    for m in NS0.lock().iter() {
        out.push_str(&alloc::format!("{} {} {} {} 0 0\n", m.source, m.path, m.fstype, m.opts));
    }
    out
}

/// `/proc/self/mountinfo` lines of the initial namespace's FUSE mounts.
pub fn ns0_mountinfo_text() -> String {
    let mut out = String::new();
    for (i, m) in NS0.lock().iter().enumerate() {
        let id = 4000 + i;
        out.push_str(&alloc::format!("{} 2069 0:{} / {} {} - {} {} {}\n", id, 60 + m.conn.id as u32, m.path, m.opts.split(',').take(4).collect::<Vec<_>>().join(","), m.fstype, m.source, m.opts));
    }
    out
}

/// The directory a FUSE inode was found in and its name there (`None` for a root).
pub fn name_of(ino: u64) -> Option<(u64, Vec<u8>)> {
    let (c, l) = split(ino);
    if l == 1 {
        return None;
    }
    let conn = CONNS.lock().get(&c).cloned()?;
    let st = conn.st.lock();
    let n = st.nodes.get(l as usize)?;
    Some((make(c, n.parent), n.name.clone()))
}

/// The mount point of the initial namespace's FUSE mount whose root is `ino`.
pub fn ns0_mountpoint(ino: u64) -> Option<u64> {
    NS0.lock().iter().find(|m| m.conn.root() == ino).map(|m| m.mountpoint)
}

/// Device number `stat` reports for a FUSE file.
pub fn dev(ino: u64) -> u64 {
    super::chardev::makedev(0, 60 + split(ino).0 as u64)
}

/// The inode number the daemon gave `ino`.
pub fn user_ino(ino: u64) -> u64 {
    let (c, l) = split(ino);
    CONNS.lock().get(&c).and_then(|c| c.st.lock().nodes.get(l as usize).map(|n| n.user_ino)).unwrap_or(l)
}

// ----------------------------------------------------------------------
// Path lookup across FUSE mounts
// ----------------------------------------------------------------------

/// How a walk in a FUSE file system ended.
pub enum Walk {
    /// At `(ino, mount)`.
    Done(u64, usize),
    /// It left the file system: go on from `(ino, mount)` (a pool directory) with `rest`.
    Out(u64, usize, Vec<u8>),
}

fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
}

fn join(stack: &[Vec<u8>]) -> Vec<u8> {
    // `stack` is reversed (the next component last)
    let mut out = Vec::new();
    for c in stack.iter().rev() {
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

/// Walks `rest` from FUSE directory `(cur, mnt)` within mount list `mounts`
/// (`(mountpoint, root, parent)`, 1-based). `..` at a mount's root leaves the mount; a
/// symbolic link to an absolute path goes on from `(root, root_mnt)`.
#[allow(clippy::too_many_arguments)]
pub fn walk(cur: u64, mnt: usize, rest: &[u8], follow: bool, mounts: &[(u64, u64, usize)], root: u64, root_mnt: usize, links: &mut u32) -> Result<Walk, i64> {
    let (mut cur, mut mnt) = (cur, mnt);
    let mut stack = components(rest);
    stack.reverse();
    while let Some(c) = stack.pop() {
        if c == b".." {
            if (cur, mnt) == (root, root_mnt) {
                continue;
            }
            if mnt != 0 && mounts.get(mnt - 1).is_some_and(|m| m.1 == cur) {
                let m = mounts[mnt - 1];
                stack.push(c);
                if !is_fuse(m.0) {
                    return Ok(Walk::Out(m.0, m.2, join(&stack)));
                }
                cur = m.0;
                mnt = m.2;
                continue;
            }
            cur = parent(cur)?;
            continue;
        }
        let (next, attr) = lookup_attr(cur, &c)?;
        let last = stack.is_empty();
        if attr.mode & S_IFMT == S_IFLNK && (!last || follow) {
            *links += 1;
            if *links > 40 {
                return Err(ELOOP);
            }
            let target = readlink(next)?;
            let mut more = components(&target);
            more.reverse();
            if target.first() == Some(&b'/') {
                stack.extend(more);
                return Ok(Walk::Out(root, root_mnt, join(&stack)));
            }
            stack.extend(more);
            continue;
        }
        if !last && attr.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        let (mut n, mut m) = (next, mnt);
        for _ in 0..=mounts.len() {
            match mounts.iter().rposition(|x| x.0 == n && x.2 == m) {
                Some(i) => {
                    n = mounts[i].1;
                    m = i + 1;
                }
                None => break,
            }
        }
        if !is_fuse(n) {
            return Ok(Walk::Out(n, m, join(&stack)));
        }
        cur = n;
        mnt = m;
    }
    Ok(Walk::Done(cur, mnt))
}

fn parent(ino: u64) -> Result<u64, i64> {
    let (c, l) = split(ino);
    let conn = conn_of(ino)?;
    let p = conn.st.lock().nodes.get(l as usize).map(|n| n.parent).ok_or(ENOENT)?;
    Ok(make(c, p))
}

// ----------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------

fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// `struct fuse_attr` at `b` as Hydra's attributes of inode `ino`.
fn attr_of(ino: u64, b: &[u8]) -> Attr {
    Attr {
        ino,
        size: u64_at(b, 8),
        blocks: u64_at(b, 16),
        atime: (u64_at(b, 24) as i64, u32_at(b, 48)),
        mtime: (u64_at(b, 32) as i64, u32_at(b, 52)),
        ctime: (u64_at(b, 40) as i64, u32_at(b, 56)),
        mode: u32_at(b, 60),
        nlink: u32_at(b, 64),
        uid: u32_at(b, 68),
        gid: u32_at(b, 72),
        rdev: u32_at(b, 76) as u64,
        ..Attr::default()
    }
}

fn cstr(name: &[u8]) -> Vec<u8> {
    let mut v = name.to_vec();
    v.push(0);
    v
}

fn le(vals: &[u64], widths: &[u8]) -> Vec<u8> {
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

/// A connection, the caller allowed on it, and the node ID of `ino`.
fn target(ino: u64) -> Result<(Arc<Conn>, u64), i64> {
    let c = conn_of(ino)?;
    c.permitted()?;
    let n = c.nodeid(split(ino).1)?;
    Ok((c, n))
}

/// A `fuse_entry_out` reply under directory `dir`: the new inode and its attributes.
fn entry(c: &Conn, dir: u64, name: &[u8], r: &[u8]) -> Result<(u64, Attr), i64> {
    let nodeid = u64_at(r, 0);
    if nodeid == 0 || r.len() < 40 + 88 {
        return Err(ENOENT);
    }
    let a = &r[40..];
    let l = c.intern(nodeid, split(dir).1, u64_at(a, 0), name);
    let ino = make(c.id, l);
    Ok((ino, attr_of(ino, a)))
}

/// Looks `name` up in FUSE directory `dir`: the inode and its attributes.
pub fn lookup_attr(dir: u64, name: &[u8]) -> Result<(u64, Attr), i64> {
    if name == b".." {
        let p = parent(dir)?;
        return Ok((p, getattr(p)?));
    }
    if name == b"." || name.is_empty() {
        return Ok((dir, getattr(dir)?));
    }
    let (c, n) = target(dir)?;
    let r = c.call(LOOKUP, n, &[&cstr(name)])?;
    entry(&c, dir, name, &r)
}

/// Looks `name` up in FUSE directory `dir`.
pub fn lookup(dir: u64, name: &[u8]) -> Result<u64, i64> {
    lookup_attr(dir, name).map(|r| r.0)
}

/// Attributes of FUSE inode `ino`.
pub fn getattr(ino: u64) -> Result<Attr, i64> {
    let (c, n) = target(ino)?;
    let r = c.call(GETATTR, n, &[&[0u8; 16]])?;
    if r.len() < 16 + 88 {
        return Err(EIO);
    }
    if let Some(node) = c.st.lock().nodes.get_mut(split(ino).1 as usize) {
        node.user_ino = u64_at(&r, 16);
    }
    Ok(attr_of(ino, &r[16..]))
}

/// Changes attributes of FUSE inode `ino`; returns the new ones.
pub fn setattr(ino: u64, set: SetAttr) -> Result<Attr, i64> {
    let (c, n) = target(ino)?;
    let mut valid = 0;
    let mode = set.mode.map(|m| {
        valid |= FATTR_MODE;
        m
    });
    let uid = set.uid.map(|u| {
        valid |= FATTR_UID;
        u
    });
    let gid = set.gid.map(|g| {
        valid |= FATTR_GID;
        g
    });
    let size = set.size.map(|s| {
        valid |= FATTR_SIZE;
        s
    });
    let atime = set.atime.map(|t| {
        valid |= FATTR_ATIME;
        t
    });
    let mtime = set.mtime.map(|t| {
        valid |= FATTR_MTIME;
        t
    });
    let mut a = Vec::with_capacity(88);
    a.extend_from_slice(&valid.to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // fh
    a.extend_from_slice(&size.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // lock_owner
    a.extend_from_slice(&(atime.map_or(0, |t| t.0) as u64).to_le_bytes());
    a.extend_from_slice(&(mtime.map_or(0, |t| t.0) as u64).to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // ctime
    a.extend_from_slice(&atime.map_or(0, |t| t.1).to_le_bytes());
    a.extend_from_slice(&mtime.map_or(0, |t| t.1).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes()); // ctimensec
    a.extend_from_slice(&mode.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    a.extend_from_slice(&uid.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&gid.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    let r = c.call(SETATTR, n, &[&a])?;
    if r.len() < 16 + 88 {
        return getattr(ino);
    }
    Ok(attr_of(ino, &r[16..]))
}

/// Target of FUSE symbolic link `ino`.
pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
    // Not a link: EINVAL without asking the daemon (realpath asks of every component)
    if getattr(ino)?.mode & S_IFMT != S_IFLNK {
        return Err(EINVAL);
    }
    let (c, n) = target(ino)?;
    c.call(READLINK, n, &[])
}

/// Kind of handle an operation needs.
#[derive(Clone, Copy, PartialEq)]
enum Want {
    Read,
    Write,
    Dir,
}

/// The daemon's handle of `ino` for `want`, opening one if there is none.
fn handle(c: &Conn, ino: u64, n: u64, want: Want) -> Result<u64, i64> {
    let l = split(ino).1;
    {
        let st = c.st.lock();
        if let Some(h) = st.handles.get(&l) {
            let got = match want {
                Want::Read => h.read,
                Want::Write => h.write,
                Want::Dir => h.dir,
            };
            if let Some(fh) = got {
                return Ok(fh);
            }
        }
    }
    let (op, flags): (u32, &[u32]) = match want {
        Want::Read => (OPEN, &[0]),
        // O_RDWR, else O_WRONLY
        Want::Write => (OPEN, &[2, 1]),
        Want::Dir => (OPENDIR, &[0o200000]),
    };
    let mut last = EACCES;
    for &f in flags {
        match c.call(op, n, &[&le(&[f as u64, 0], &[4, 4])]) {
            Ok(r) => {
                let fh = u64_at(&r, 0);
                let mut st = c.st.lock();
                let h = st.handles.entry(l).or_default();
                match want {
                    Want::Read => h.read = Some(fh),
                    Want::Write => h.write = Some(fh),
                    Want::Dir => h.dir = Some(fh),
                }
                return Ok(fh);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Reads `ino` at `offset` into `buf`.
pub fn read(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let (c, n) = target(ino)?;
    let fh = handle(&c, ino, n, Want::Read)?;
    let chunk = 128 * 1024;
    let mut done = 0;
    while done < buf.len() {
        let want = (buf.len() - done).min(chunk);
        let a = le(&[fh, offset + done as u64, want as u64, 0, 0, 0, 0], &[8, 8, 4, 4, 8, 4, 4]);
        let r = c.call(READ, n, &[&a])?;
        let got = r.len().min(want);
        buf[done..done + got].copy_from_slice(&r[..got]);
        done += got;
        if got < want {
            break;
        }
    }
    Ok(done)
}

/// Writes `data` to `ino` at `offset`.
pub fn write(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
    let (c, n) = target(ino)?;
    let fh = handle(&c, ino, n, Want::Write)?;
    let max = c.st.lock().max_write as usize;
    let mut done = 0;
    while done < data.len() {
        let part = &data[done..(done + max).min(data.len())];
        let a = le(&[fh, offset + done as u64, part.len() as u64, 0, 0, 0, 0], &[8, 8, 4, 4, 8, 4, 4]);
        let r = c.call(WRITE, n, &[&a, part])?;
        let w = (u32_at(&r, 0) as usize).min(part.len());
        done += w;
        if w < part.len() {
            break;
        }
    }
    Ok(done)
}

/// Up to `max` entries of directory `dir` from `cookie` (the daemon's offset) on.
pub fn readdir(dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
    let (c, n) = target(dir)?;
    let fh = handle(&c, dir, n, Want::Dir)?;
    let a = le(&[fh, cookie, 16384, 0, 0, 0, 0], &[8, 8, 4, 4, 8, 4, 4]);
    let r = c.call(READDIR, n, &[&a])?;
    let mut out = Vec::new();
    let mut o = 0;
    while o + 24 <= r.len() && out.len() < max {
        let ino = u64_at(&r, o);
        let off = u64_at(&r, o + 8);
        let namelen = u32_at(&r, o + 16) as usize;
        let dtype = u32_at(&r, o + 20) as u8;
        if o + 24 + namelen > r.len() {
            break;
        }
        out.push(ReaddirEntry { name: r[o + 24..o + 24 + namelen].to_vec(), ino, dtype, next_cookie: off });
        o += (24 + namelen + 7) & !7;
    }
    Ok(out)
}

/// A file created in `dir`: the daemon's `create` (keeping the handle for writing), or
/// `mknod` when it has none.
pub fn create(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    let (c, n) = target(dir)?;
    // O_CREAT | O_EXCL | O_RDWR
    let a = le(&[0o302, (S_IFREG | (perm & 0o7777)) as u64, 0, 0], &[4, 4, 4, 4]);
    match c.call(CREATE, n, &[&a, &cstr(name)]) {
        Ok(r) => {
            let (ino, _) = entry(&c, dir, name, &r)?;
            if r.len() >= 128 + 16 {
                let fh = u64_at(&r, 128);
                c.st.lock().handles.entry(split(ino).1).or_default().write = Some(fh);
            }
            Ok(ino)
        }
        Err(ENOSYS) => mknod(dir, name, S_IFREG | (perm & 0o7777), 0),
        Err(e) => Err(e),
    }
}

/// A node made in `dir`.
pub fn mknod(dir: u64, name: &[u8], mode: u32, rdev: u64) -> Result<u64, i64> {
    let (c, n) = target(dir)?;
    let a = le(&[mode as u64, rdev & 0xFFFF_FFFF, 0, 0], &[4, 4, 4, 4]);
    let r = c.call(MKNOD, n, &[&a, &cstr(name)])?;
    entry(&c, dir, name, &r).map(|e| e.0)
}

/// A directory made in `dir`.
pub fn mkdir(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    let (c, n) = target(dir)?;
    let a = le(&[(perm & 0o7777) as u64, 0], &[4, 4]);
    let r = c.call(MKDIR, n, &[&a, &cstr(name)])?;
    entry(&c, dir, name, &r).map(|e| e.0)
}

/// A symbolic link made in `dir`.
pub fn symlink(dir: u64, name: &[u8], to: &[u8]) -> Result<u64, i64> {
    let (c, n) = target(dir)?;
    let r = c.call(SYMLINK, n, &[&cstr(name), &cstr(to)])?;
    entry(&c, dir, name, &r).map(|e| e.0)
}

/// A hard link to `ino` made in `dir` (same file system only).
pub fn link(ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
    if !is_fuse(ino) || !is_fuse(dir) || split(ino).0 != split(dir).0 {
        return Err(EXDEV);
    }
    let (c, n) = target(dir)?;
    let old = c.nodeid(split(ino).1)?;
    let r = c.call(LINK, n, &[&old.to_le_bytes(), &cstr(name)])?;
    entry(&c, dir, name, &r).map(|_| ())
}

/// Removes `name` from `dir`.
pub fn unlink(dir: u64, name: &[u8]) -> Result<(), i64> {
    let (c, n) = target(dir)?;
    c.call(UNLINK, n, &[&cstr(name)]).map(|_| ())
}

/// Removes directory `name` from `dir`.
pub fn rmdir(dir: u64, name: &[u8]) -> Result<(), i64> {
    let (c, n) = target(dir)?;
    c.call(RMDIR, n, &[&cstr(name)]).map(|_| ())
}

/// Renames within one FUSE file system.
pub fn rename(sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
    if !is_fuse(sdir) || !is_fuse(ddir) || split(sdir).0 != split(ddir).0 {
        return Err(EXDEV);
    }
    let (c, n) = target(sdir)?;
    let nd = c.nodeid(split(ddir).1)?;
    c.call(RENAME, n, &[&nd.to_le_bytes(), &cstr(sname), &cstr(dname)]).map(|_| ())
}

fn xattr_err(e: i64) -> i64 {
    if e == ENOSYS { EOPNOTSUPP } else { e }
}

/// Extended attribute `name` of `ino`.
pub fn getxattr(ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
    let (c, n) = target(ino)?;
    c.call(GETXATTR, n, &[&le(&[65536, 0], &[4, 4]), &cstr(name)]).map_err(xattr_err)
}

/// Names of `ino`'s extended attributes.
pub fn listxattr(ino: u64) -> Result<Vec<u8>, i64> {
    let (c, n) = target(ino)?;
    c.call(LISTXATTR, n, &[&le(&[65536, 0], &[4, 4])]).map_err(xattr_err)
}

/// Sets extended attribute `name` of `ino`.
pub fn setxattr(ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
    let (c, n) = target(ino)?;
    c.call(SETXATTR, n, &[&le(&[value.len() as u64, flags as u64], &[4, 4]), &cstr(name), value]).map(|_| ()).map_err(xattr_err)
}

/// Removes extended attribute `name` of `ino`.
pub fn removexattr(ino: u64, name: &[u8]) -> Result<(), i64> {
    let (c, n) = target(ino)?;
    c.call(REMOVEXATTR, n, &[&cstr(name)]).map(|_| ()).map_err(xattr_err)
}

/// `(blocks, free blocks, files)` of the file system `ino` is in.
pub fn statfs(ino: u64) -> Result<(u64, u64, u64, u32), i64> {
    let (c, n) = target(ino)?;
    let r = c.call(STATFS, n, &[])?;
    Ok((u64_at(&r, 0), u64_at(&r, 8), u64_at(&r, 24), u32_at(&r, 40)))
}

/// A descriptor opened `ino`.
pub fn open_ref(ino: u64) {
    if let Ok(c) = conn_of(ino) {
        c.st.lock().handles.entry(split(ino).1).or_default().refs += 1;
    }
}

/// A descriptor of `ino` closed: with the last, the daemon's handles are released (without
/// waiting for the daemon).
pub fn release(ino: u64) {
    let Ok(c) = conn_of(ino) else { return };
    let l = split(ino).1;
    let gone = {
        let mut st = c.st.lock();
        let Some(h) = st.handles.get_mut(&l) else { return };
        h.refs = h.refs.saturating_sub(1);
        if h.refs > 0 {
            return;
        }
        st.handles.remove(&l)
    };
    let Some(h) = gone else { return };
    let Ok(n) = c.nodeid(l) else { return };
    if let Some(fh) = h.write {
        c.send(FLUSH, n, &[&le(&[fh, 0, 0, 0], &[8, 4, 4, 8])]);
        c.send(RELEASE, n, &[&le(&[fh, 1, 0, 0], &[8, 4, 4, 8])]);
    }
    if let Some(fh) = h.read {
        c.send(RELEASE, n, &[&le(&[fh, 0, 0, 0], &[8, 4, 4, 8])]);
    }
    if let Some(fh) = h.dir {
        c.send(RELEASEDIR, n, &[&le(&[fh, 0, 0, 0], &[8, 4, 4, 8])]);
    }
}

// ----------------------------------------------------------------------
// mount
// ----------------------------------------------------------------------

/// Options of a FUSE mount: `(fd, rootmode, user_id, group_id, allow_other)`.
fn options(data: &str) -> Result<(i32, u32, u32, u32, bool), i64> {
    let (mut fd, mut rootmode, mut uid, mut gid, mut other) = (None, None, None, None, false);
    for o in data.split(',') {
        let (k, v) = o.split_once('=').unwrap_or((o, ""));
        match k {
            "fd" => fd = v.parse::<i32>().ok(),
            "rootmode" => rootmode = u32::from_str_radix(v, 8).ok(),
            "user_id" => uid = v.parse::<u32>().ok(),
            "group_id" => gid = v.parse::<u32>().ok(),
            "allow_other" => other = true,
            _ => {}
        }
    }
    match (fd, rootmode, uid, gid) {
        (Some(f), Some(r), Some(u), Some(g)) => Ok((f, r, u, g, other)),
        _ => Err(EINVAL),
    }
}

/// The connection behind descriptor `fd` (an open `/dev/fuse`).
fn conn_of_fd(fd: i32) -> Result<Arc<Conn>, i64> {
    let d = crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
        _ => None,
    })
    .ok_or(EBADF)?;
    d.as_fuse().ok_or(EINVAL)
}

/// Mounts the connection named by `data`'s `fd=` on `(path, mountpoint)`.
///
/// # Returns
/// The connection's root directory, to enter in the caller's mount table (initial
/// namespace: `ns0` records the mount here).
pub fn mount(path: &str, mountpoint: u64, fstype: &str, source: &str, flags: u64, data: &str, ns0: bool) -> Result<u64, i64> {
    let (fd, _rootmode, uid, gid, other) = options(data)?;
    let c = conn_of_fd(fd)?;
    if c.mounted.load(Ordering::Acquire) {
        return Err(EINVAL);
    }
    c.start(uid, gid, other);
    if ns0 {
        let mut opts = String::from(if flags & 1 != 0 { "ro" } else { "rw" });
        for (bit, name) in [(2u64, "nosuid"), (4, "nodev"), (8, "noexec")] {
            if flags & bit != 0 {
                opts.push(',');
                opts.push_str(name);
            }
        }
        opts.push_str(&alloc::format!(",relatime,user_id={},group_id={}", uid, gid));
        if other {
            opts.push_str(",allow_other");
        }
        ns0_add(Ns0Mount { mountpoint, conn: c.clone(), path: String::from(path), fstype: String::from(fstype), source: String::from(source), opts });
    }
    Ok(c.root())
}

/// Whether `fstype` is a FUSE file system type (`fuse`, `fuse.<name>`).
pub fn is_fuse_type(fstype: &str) -> bool {
    fstype == "fuse" || fstype.starts_with("fuse.")
}
