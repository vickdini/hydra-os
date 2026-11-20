//! A FUSE daemon for the tests: an in-memory file system served over `/dev/fuse` with the
//! FUSE protocol (7.14), as libfuse would. Install it as the wait hook ([`Daemon::install`])
//! and every request the kernel queues is answered while the caller waits.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::compat::linux::chardev::CharDevice;

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

#[derive(Clone)]
pub struct FNode {
    pub name: Vec<u8>,
    pub parent: u64,
    pub mode: u32,
    pub data: Vec<u8>,
    pub target: Vec<u8>,
    pub uid: u32,
    pub nlink: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The inode number the daemon reports.
    pub ino: u64,
}

/// One request as the daemon read it.
#[derive(Clone, Debug)]
pub struct Req {
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub pid: u32,
    pub body: Vec<u8>,
}

pub struct Daemon {
    pub dev: Arc<dyn CharDevice>,
    pub fd: i64,
    pub nodes: BTreeMap<u64, FNode>,
    next: u64,
    /// Every request read, in order.
    pub seen: Vec<Req>,
    /// Errors to answer per opcode (negative errno).
    pub errors: BTreeMap<u32, i32>,
    /// Requests left unanswered (to test interrupts).
    pub hold: Vec<u32>,
    pub held: Vec<Req>,
    /// `attr_valid` seconds in entry and attribute replies.
    pub attr_valid: u64,
    /// The INIT reply's major version and max_write.
    pub init_major: u32,
    pub max_write: u32,
    /// The body of the next INIT reply is cut to this many bytes.
    pub init_short: Option<usize>,
    /// Reads answer at most this many bytes.
    pub read_cap: Option<usize>,
    /// Writes accept at most this many bytes.
    pub write_cap: Option<usize>,
    /// GETATTR replies are cut short (`EIO` for the kernel).
    pub short_attr: bool,
    /// STATFS answers zeros for the sizes (the kernel then uses defaults).
    pub statfs_zero: bool,
}

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn cstr_at(b: &[u8], o: usize) -> (Vec<u8>, usize) {
    let end = b[o..].iter().position(|&c| c == 0).map_or(b.len(), |p| o + p);
    (b[o..end].to_vec(), end + 1)
}

impl Daemon {
    /// A daemon on `/dev/fuse` descriptor `fd` (opened by the test), with an empty root.
    pub fn new(fd: i64) -> Daemon {
        let dev = match crate::testkit::desc(fd) {
            Some(crate::fs::FileDescriptor::Device(d)) => d,
            _ => panic!("fd {} is not /dev/fuse", fd),
        };
        dev.set_nonblock(true);
        let mut nodes = BTreeMap::new();
        nodes.insert(1, FNode { name: Vec::new(), parent: 1, mode: S_IFDIR | 0o755, data: Vec::new(), target: Vec::new(), uid: 0, nlink: 2, xattrs: BTreeMap::new(), ino: 1 });
        Daemon {
            dev,
            fd,
            nodes,
            next: 2,
            seen: Vec::new(),
            errors: BTreeMap::new(),
            hold: Vec::new(),
            held: Vec::new(),
            attr_valid: 0,
            init_major: 7,
            max_write: 4096,
            init_short: None,
            read_cap: None,
            write_cap: None,
            short_attr: false,
            statfs_zero: false,
        }
    }

    /// Makes `name` in directory `parent`; returns its node ID.
    pub fn add(&mut self, parent: u64, name: &str, mode: u32, data: &[u8], target: &str) -> u64 {
        let id = self.next;
        self.next += 1;
        self.nodes.insert(
            id,
            FNode { name: name.as_bytes().to_vec(), parent, mode, data: data.to_vec(), target: target.as_bytes().to_vec(), uid: 0, nlink: 1, xattrs: BTreeMap::new(), ino: 1000 + id },
        );
        id
    }

    pub fn find(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.nodes.iter().find(|(_, n)| n.parent == parent && n.name == name).map(|(&i, _)| i).filter(|&i| i != 1)
    }

    /// Opcodes of the requests seen.
    pub fn ops(&self) -> Vec<u32> {
        self.seen.iter().map(|r| r.opcode).collect()
    }

    fn attr(&self, id: u64) -> Vec<u8> {
        let n = &self.nodes[&id];
        let mut a = Vec::with_capacity(88);
        let size = if n.mode & 0o170000 == S_IFLNK { n.target.len() } else { n.data.len() } as u64;
        for v in [n.ino, size, size.div_ceil(512), 11, 22, 33] {
            a.extend_from_slice(&v.to_le_bytes());
        }
        for v in [1u32, 2, 3, n.mode, n.nlink, n.uid, n.uid, 0, 4096, 0] {
            a.extend_from_slice(&v.to_le_bytes());
        }
        a
    }

    fn entry(&self, id: u64) -> Vec<u8> {
        let mut e = Vec::with_capacity(128);
        e.extend_from_slice(&id.to_le_bytes());
        e.extend_from_slice(&1u64.to_le_bytes()); // generation
        e.extend_from_slice(&1u64.to_le_bytes()); // entry_valid
        e.extend_from_slice(&self.attr_valid.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend(self.attr(id));
        e
    }

    fn reply(&self, unique: u64, err: i32, body: &[u8]) {
        let mut m = Vec::with_capacity(16 + body.len());
        m.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
        m.extend_from_slice(&err.to_le_bytes());
        m.extend_from_slice(&unique.to_le_bytes());
        m.extend_from_slice(body);
        let r = self.dev.write(&m);
        assert!(r == m.len() as i64 || r == -2, "reply refused: {}", r);
    }

    /// Writes raw bytes to the device (a notification, a malformed reply).
    pub fn write_raw(&self, m: &[u8]) -> i64 {
        self.dev.write(m)
    }

    /// Answers a held request now.
    pub fn release_held(&mut self) {
        let held = core::mem::take(&mut self.held);
        for r in held {
            self.answer(r);
        }
    }

    /// Reads and answers every queued request.
    pub fn serve(&mut self) {
        loop {
            let mut b = alloc::vec![0u8; 256 * 1024];
            let n = self.dev.read(&mut b);
            if n <= 0 {
                return;
            }
            b.truncate(n as usize);
            let r = Req { opcode: le32(&b, 4), unique: le64(&b, 8), nodeid: le64(&b, 16), uid: le32(&b, 24), pid: le32(&b, 32), body: b[40..].to_vec() };
            self.seen.push(r.clone());
            if self.hold.contains(&r.opcode) {
                self.held.push(r);
                continue;
            }
            self.answer(r);
        }
    }

    fn answer(&mut self, r: Req) {
        let u = r.unique;
        if let Some(&e) = self.errors.get(&r.opcode) {
            if r.opcode != INIT {
                return self.reply(u, e, &[]);
            }
        }
        let b = &r.body;
        match r.opcode {
            INIT => {
                let mut body = Vec::new();
                for v in [self.init_major, 14, 65536, 0] {
                    body.extend_from_slice(&v.to_le_bytes());
                }
                body.extend_from_slice(&[0u8; 4]);
                body.extend_from_slice(&self.max_write.to_le_bytes());
                if let Some(n) = self.init_short {
                    body.truncate(n);
                }
                let err = self.errors.get(&INIT).copied().unwrap_or(0);
                self.reply(u, err, &body);
            }
            LOOKUP => {
                let (name, _) = cstr_at(b, 0);
                match self.find(r.nodeid, &name) {
                    Some(id) => self.reply(u, 0, &self.entry(id)),
                    None => self.reply(u, -2, &[]),
                }
            }
            GETATTR => {
                if !self.nodes.contains_key(&r.nodeid) {
                    return self.reply(u, -2, &[]);
                }
                let mut body = Vec::new();
                body.extend_from_slice(&self.attr_valid.to_le_bytes());
                body.extend_from_slice(&[0u8; 8]);
                body.extend(self.attr(r.nodeid));
                if self.short_attr {
                    body.truncate(20);
                }
                self.reply(u, 0, &body);
            }
            SETATTR => {
                let valid = le32(b, 0);
                let n = self.nodes.get_mut(&r.nodeid).unwrap();
                if valid & 1 != 0 {
                    n.mode = (n.mode & 0o170000) | (le32(b, 68) & 0o7777);
                }
                if valid & 2 != 0 {
                    n.uid = le32(b, 76);
                }
                if valid & 8 != 0 {
                    n.data.resize(le64(b, 16) as usize, 0);
                }
                let mut body = Vec::new();
                body.extend_from_slice(&self.attr_valid.to_le_bytes());
                body.extend_from_slice(&[0u8; 8]);
                body.extend(self.attr(r.nodeid));
                self.reply(u, 0, &body);
            }
            READLINK => {
                let t = self.nodes[&r.nodeid].target.clone();
                self.reply(u, 0, &t);
            }
            SYMLINK => {
                let (name, o) = cstr_at(b, 0);
                let (target, _) = cstr_at(b, o);
                let id = self.add(r.nodeid, &String::from_utf8_lossy(&name), S_IFLNK | 0o777, &[], &String::from_utf8_lossy(&target));
                self.reply(u, 0, &self.entry(id));
            }
            MKNOD | MKDIR | CREATE => {
                let (mode, name_at) = match r.opcode {
                    MKNOD => (le32(b, 0), 16),
                    MKDIR => (S_IFDIR | le32(b, 0), 8),
                    _ => (le32(b, 4), 16),
                };
                let (name, _) = cstr_at(b, name_at);
                if self.find(r.nodeid, &name).is_some() {
                    return self.reply(u, -17, &[]);
                }
                let id = self.add(r.nodeid, &String::from_utf8_lossy(&name), mode, &[], "");
                let mut body = self.entry(id);
                if r.opcode == CREATE {
                    body.extend_from_slice(&(500 + id).to_le_bytes());
                    body.extend_from_slice(&[0u8; 8]);
                }
                self.reply(u, 0, &body);
            }
            UNLINK | RMDIR => {
                let (name, _) = cstr_at(b, 0);
                match self.find(r.nodeid, &name) {
                    Some(id) => {
                        self.nodes.remove(&id);
                        self.reply(u, 0, &[]);
                    }
                    None => self.reply(u, -2, &[]),
                }
            }
            RENAME => {
                let newdir = le64(b, 0);
                let (old, o) = cstr_at(b, 8);
                let (new, _) = cstr_at(b, o);
                match self.find(r.nodeid, &old) {
                    Some(id) => {
                        if let Some(victim) = self.find(newdir, &new) {
                            self.nodes.remove(&victim);
                        }
                        let n = self.nodes.get_mut(&id).unwrap();
                        n.parent = newdir;
                        n.name = new;
                        self.reply(u, 0, &[]);
                    }
                    None => self.reply(u, -2, &[]),
                }
            }
            LINK => {
                let old = le64(b, 0);
                let (name, _) = cstr_at(b, 8);
                let mut n = self.nodes[&old].clone();
                n.name = name;
                n.parent = r.nodeid;
                // Same node: the entry reply names the old node ID
                self.nodes.get_mut(&old).unwrap().nlink += 1;
                let _ = n;
                self.reply(u, 0, &self.entry(old));
            }
            OPEN | OPENDIR => {
                let mut body = (700 + r.nodeid).to_le_bytes().to_vec();
                body.extend_from_slice(&[0u8; 8]);
                self.reply(u, 0, &body);
            }
            READ => {
                let (off, size) = (le64(b, 8) as usize, le32(b, 16) as usize);
                let d = &self.nodes[&r.nodeid].data;
                let start = off.min(d.len());
                let mut end = (off + size).min(d.len());
                if let Some(c) = self.read_cap {
                    end = end.min(start + c);
                }
                let out = d[start..end].to_vec();
                self.reply(u, 0, &out);
            }
            WRITE => {
                let (off, size) = (le64(b, 8) as usize, le32(b, 16) as usize);
                let mut take = size;
                if let Some(c) = self.write_cap {
                    take = take.min(c);
                }
                let data = b[40..40 + take].to_vec();
                let n = self.nodes.get_mut(&r.nodeid).unwrap();
                if n.data.len() < off + take {
                    n.data.resize(off + take, 0);
                }
                n.data[off..off + take].copy_from_slice(&data);
                let mut body = (take as u32).to_le_bytes().to_vec();
                body.extend_from_slice(&[0u8; 4]);
                self.reply(u, 0, &body);
            }
            STATFS => {
                let mut body = Vec::new();
                if self.statfs_zero {
                    body = alloc::vec![0u8; 80];
                } else {
                    for v in [1000u64, 500, 400, 100, 50] {
                        body.extend_from_slice(&v.to_le_bytes());
                    }
                    for v in [4096u32, 200, 1024, 0] {
                        body.extend_from_slice(&v.to_le_bytes());
                    }
                }
                self.reply(u, 0, &body);
            }
            READDIR => {
                let off = le64(b, 8);
                let kids: Vec<(u64, FNode)> = self.nodes.iter().filter(|(&i, n)| n.parent == r.nodeid && i != 1).map(|(&i, n)| (i, n.clone())).collect();
                let mut body = Vec::new();
                for (k, (id, n)) in kids.iter().enumerate().skip(off as usize) {
                    let start = body.len();
                    body.extend_from_slice(&n.ino.to_le_bytes());
                    body.extend_from_slice(&((k + 1) as u64).to_le_bytes());
                    body.extend_from_slice(&(n.name.len() as u32).to_le_bytes());
                    body.extend_from_slice(&((n.mode >> 12) & 0xF).to_le_bytes());
                    body.extend_from_slice(&n.name);
                    let pad = (24 + n.name.len() + 7) & !7;
                    body.resize(start + pad, 0);
                    let _ = id;
                }
                self.reply(u, 0, &body);
            }
            SETXATTR => {
                let size = le32(b, 0) as usize;
                let (name, o) = cstr_at(b, 8);
                let value = b[o..o + size].to_vec();
                self.nodes.get_mut(&r.nodeid).unwrap().xattrs.insert(name, value);
                self.reply(u, 0, &[]);
            }
            GETXATTR => {
                let (name, _) = cstr_at(b, 8);
                match self.nodes[&r.nodeid].xattrs.get(&name).cloned() {
                    Some(v) => self.reply(u, 0, &v),
                    None => self.reply(u, -61, &[]),
                }
            }
            LISTXATTR => {
                let mut out = Vec::new();
                for k in self.nodes[&r.nodeid].xattrs.keys() {
                    out.extend_from_slice(k);
                    out.push(0);
                }
                self.reply(u, 0, &out);
            }
            REMOVEXATTR => {
                let (name, _) = cstr_at(b, 0);
                match self.nodes.get_mut(&r.nodeid).unwrap().xattrs.remove(&name) {
                    Some(_) => self.reply(u, 0, &[]),
                    None => self.reply(u, -61, &[]),
                }
            }
            RELEASE | RELEASEDIR | FLUSH => self.reply(u, 0, &[]),
            INTERRUPT => {
                // Answer the interrupted request with EINTR
                let target = le64(b, 0);
                if let Some(i) = self.held.iter().position(|h| h.unique == target) {
                    let h = self.held.remove(i);
                    self.reply(h.unique, -4, &[]);
                }
            }
            _ => self.reply(u, -38, &[]),
        }
    }

    /// Makes this daemon answer whenever the code under test waits; returns the shared
    /// handle the test keeps.
    pub fn install(self) -> Rc<RefCell<Daemon>> {
        let d = Rc::new(RefCell::new(self));
        let h = d.clone();
        crate::task::wait::on_wait(move || {
            if let Ok(mut d) = h.try_borrow_mut() {
                d.serve();
            }
        });
        d
    }
}

/// Opens `/dev/fuse` (a node of the pool) for the current task; returns the descriptor.
pub fn open_dev_fuse() -> i64 {
    if crate::fake::memfs::lookup("/dev/fuse").is_none() {
        crate::fake::memfs::mknode("/dev/fuse", 0o020666, crate::compat::linux::chardev::makedev(10, 229));
    }
    crate::testkit::open("/dev/fuse", crate::testkit::O_RDWR)
}

/// Mounts the FUSE connection on descriptor `fd` at `target` (made if missing) with
/// `mount(2)` in the caller's namespace; returns the result.
pub fn mount(fd: i64, target: &str, extra: &str) -> i64 {
    crate::fake::memfs::mkdir_p(target);
    let data = alloc::format!("fd={},rootmode=40000,user_id=0,group_id=0{}", fd, extra);
    let a = [crate::fake::cstr("testfs"), crate::fake::cstr(target), crate::fake::cstr("fuse.testfs"), 0, crate::fake::cstr(&data), 0];
    crate::compat::linux::mount::dispatch(165, a).unwrap()
}
