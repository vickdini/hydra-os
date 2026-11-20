//! A fake ring-3 service layer and a fake ZFS file server.
//!
//! The kernel's [`crate::fs::zfs`] client talks to the file server through
//! `crate::ipc::service` (a shared window and a call). Here `service` is a stand-in
//! ([`service`]) whose windows are leaked per-thread buffers and whose calls run a
//! handler in the caller's thread, as the kernel's hand-off runs the server in the
//! caller's place. The ZFS endpoint's handler is [`FakeFs`]: an in-memory file system
//! that decodes the real request encoding (`fsproto::Reader`) and answers with the real
//! reply encoding (`fsproto::Writer`), so the client's encoding, caching and error
//! paths run unchanged.
//!
//! One pool for the whole test binary (the kernel client keeps its root and caches in
//! statics): tests that use it call [`pool`] and work in a directory of their own.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::fs::zfs::fsproto::*;
use crate::fs::zfs::types::{S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use crate::ipc::protocol::ENDPOINT_ZFS_SERVER;
use crate::ipc::Message;

// ------------------------------------------------------------------ service

/// A request handler: `(request, window) -> reply`.
pub type Handler = Box<dyn FnMut(&Message, &mut [u8]) -> Result<Message, i64>>;

thread_local! {
    /// Per-thread endpoint handlers (block drivers in tests); the ZFS endpoint falls back
    /// to the shared [`FakeFs`] when none is set here.
    static HANDLERS: RefCell<BTreeMap<u32, Handler>> = RefCell::new(BTreeMap::new());
    /// Per-thread windows (leaked: `window()` hands out `'static` slices).
    static WINDOWS: RefCell<BTreeMap<u32, usize>> = RefCell::new(BTreeMap::new());
    /// Endpoints that are offline on this thread (default: online when a handler exists).
    static OFFLINE: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Endpoints whose window is missing until revived (`supervisor::revive`).
    static NO_WINDOW: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Endpoints revived (`supervisor::revive` calls), in order.
    pub static REVIVED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Windows held (`hold_window`), count per endpoint, currently.
    pub static HELD: RefCell<BTreeMap<u32, i32>> = RefCell::new(BTreeMap::new());
    /// Calls made, per thread: (endpoint, label, args).
    pub static CALLS: RefCell<Vec<(u32, u32, [u64; 4])>> = const { RefCell::new(Vec::new()) };
}

/// Installs `h` as this thread's handler of `endpoint` (online).
pub fn set_handler(endpoint: u32, h: Handler) {
    HANDLERS.with_borrow_mut(|m| m.insert(endpoint, h));
    OFFLINE.with_borrow_mut(|v| v.retain(|&e| e != endpoint));
}

/// Removes this thread's handler of `endpoint`.
pub fn clear_handler(endpoint: u32) {
    HANDLERS.with_borrow_mut(|m| m.remove(&endpoint));
}

/// Marks `endpoint` offline (or online again) on this thread.
pub fn set_offline(endpoint: u32, off: bool) {
    OFFLINE.with_borrow_mut(|v| {
        v.retain(|&e| e != endpoint);
        if off {
            v.push(endpoint);
        }
    });
}

/// Makes `window(endpoint)` fail until the endpoint is revived.
pub fn drop_window(endpoint: u32) {
    NO_WINDOW.with_borrow_mut(|v| v.push(endpoint));
}

/// The fake `crate::ipc::service`.
pub mod service {
    use super::*;

    pub const WINDOW_PAGES: u64 = 64;
    pub const WINDOW_SIZE: usize = (WINDOW_PAGES * 4096) as usize;
    pub const CALL_TIMEOUT_TICKS: u64 = 500;

    fn has_handler(endpoint: u32) -> bool {
        HANDLERS.with_borrow(|m| m.contains_key(&endpoint)) || (endpoint == ENDPOINT_ZFS_SERVER && ZFS_ONLINE.lock().map_or(false, |g| *g))
    }

    pub fn is_online(endpoint: u32) -> bool {
        has_handler(endpoint) && !OFFLINE.with_borrow(|v| v.contains(&endpoint))
    }

    pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
        if NO_WINDOW.with_borrow(|v| v.contains(&endpoint)) || !has_handler(endpoint) {
            return None;
        }
        let p = WINDOWS.with_borrow_mut(|m| *m.entry(endpoint).or_insert_with(|| Box::leak(vec![0u8; WINDOW_SIZE].into_boxed_slice()).as_mut_ptr() as usize));
        // SAFETY: a leaked buffer of WINDOW_SIZE bytes (aliased as the kernel's window is)
        Some(unsafe { core::slice::from_raw_parts_mut(p as *mut u8, WINDOW_SIZE) })
    }

    /// Held while a client uses an endpoint's window.
    pub struct WindowGuard(u32);

    impl Drop for WindowGuard {
        fn drop(&mut self) {
            let _ = HELD.try_with(|h| *h.borrow_mut().entry(self.0).or_insert(0) -= 1);
        }
    }

    pub fn hold_window(endpoint: u32) -> WindowGuard {
        HELD.with_borrow_mut(|h| *h.entry(endpoint).or_insert(0) += 1);
        WindowGuard(endpoint)
    }

    pub fn call(endpoint: u32, request: Message, _timeout_ticks: u64) -> Result<Message, i64> {
        CALLS.with_borrow_mut(|v| v.push((endpoint, request.label, [request.args[0], request.args[1], request.args[2], request.args[3]])));
        if !is_online(endpoint) {
            return Err(-19); // ENODEV
        }
        let w = window(endpoint).ok_or(-19i64)?;
        let mut h = HANDLERS.with_borrow_mut(|m| m.remove(&endpoint));
        let r = match h.as_mut() {
            Some(h) => h(&request, w),
            None => zfs_handle(&request, w),
        };
        if let Some(h) = h {
            HANDLERS.with_borrow_mut(|m| { m.entry(endpoint).or_insert(h); });
        }
        r
    }
}

/// `task::supervisor::revive`: the endpoint's window comes back.
pub fn revive(endpoint: u32) -> bool {
    REVIVED.with_borrow_mut(|v| v.push(endpoint));
    NO_WINDOW.with_borrow_mut(|v| v.retain(|&e| e != endpoint));
    true
}

// ------------------------------------------------------------------ the pool

/// Whether the shared file server answers (set by [`pool`]).
static ZFS_ONLINE: Mutex<bool> = Mutex::new(false);
/// The shared file server.
pub static FS: Mutex<Option<FakeFs>> = Mutex::new(None);

/// Starts the shared fake pool (once) and runs the kernel's `init_server` against it;
/// returns the pool's root directory.
pub fn pool() -> u64 {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        *FS.lock().unwrap() = Some(FakeFs::new());
        *ZFS_ONLINE.lock().unwrap() = true;
        crate::fs::zfs::init_server();
    });
    ROOT_INO
}

/// Runs `f` on the shared file system (for setting up and checking state).
pub fn with_fs<R>(f: impl FnOnce(&mut FakeFs) -> R) -> R {
    pool();
    let mut g = FS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.as_mut().unwrap())
}

/// A fresh directory `/<name>` for one test (removed first if a previous run left it).
pub fn test_dir(name: &str) -> u64 {
    pool();
    with_fs(|fs| {
        let n = name.trim_start_matches('/');
        if let Some(old) = fs.child(ROOT_INO, n.as_bytes()) {
            fs.detach(ROOT_INO, n.as_bytes());
            let _ = old;
        }
        fs.mknode(ROOT_INO, n.as_bytes(), S_IFDIR | 0o755, Kind::Dir(BTreeMap::new())).unwrap()
    })
}

thread_local! {
    /// Fails the next request with this operation (or any, with 0) on this thread:
    /// `(op, errno, how many times)`.
    pub static FAIL: RefCell<Vec<(u32, i64, u32)>> = const { RefCell::new(Vec::new()) };
    /// inotify events to report with the next reply on this thread.
    pub static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    /// Requests this thread made, by operation.
    pub static OPS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Answer replies with a wrong label (a broken server).
    pub static BAD_LABEL: Cell<bool> = const { Cell::new(false) };
    /// Short writes: at most this many bytes per write request (0: no limit).
    pub static WRITE_LIMIT: Cell<usize> = const { Cell::new(0) };
}

/// Fails the next `times` requests of `op` (0: any) with `errno`.
pub fn fail(op: u32, errno: i64, times: u32) {
    FAIL.with_borrow_mut(|v| v.push((op, errno, times)));
}

/// How many requests of `op` this thread made.
pub fn ops(op: u32) -> usize {
    OPS.with_borrow(|v| v.iter().filter(|&&o| o == op).count())
}

/// Forgets this thread's request log.
pub fn clear_ops() {
    OPS.with_borrow_mut(|v| v.clear());
}

pub const ROOT_INO: u64 = 1000;

/// What a node is.
#[derive(Clone)]
pub enum Kind {
    Dir(BTreeMap<Vec<u8>, u64>),
    File(Vec<u8>),
    Symlink(Vec<u8>),
    Special,
}

#[derive(Clone)]
pub struct Node {
    pub attr: Attr,
    pub kind: Kind,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// The in-memory file system.
pub struct FakeFs {
    pub nodes: BTreeMap<u64, Node>,
    next: u64,
    pub txg: u64,
    pub open_txg: u64,
    pub dirty: bool,
    /// Server-side open references (first open / last release only).
    pub refs: BTreeMap<u64, i64>,
    /// `FS_NOTIFY` requests: (ino, mask).
    pub notified: Vec<(u64, u32)>,
    /// Snapshots taken: (dataset, name).
    pub snapshots: Vec<(u64, String)>,
    /// Diagnostics run: (op, path, repair).
    pub diagnostics: Vec<(u32, String, bool)>,
    /// Writer group lists received with writes (`None`: set-ID bits kept).
    pub write_kills: Vec<Option<Vec<u32>>>,
}

impl FakeFs {
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            ROOT_INO,
            Node { attr: Attr { ino: ROOT_INO, mode: S_IFDIR | 0o755, nlink: 2, ..Default::default() }, kind: Kind::Dir(BTreeMap::new()), xattrs: BTreeMap::new() },
        );
        Self {
            nodes,
            next: ROOT_INO + 1,
            txg: 10,
            open_txg: 11,
            dirty: false,
            refs: BTreeMap::new(),
            notified: Vec::new(),
            snapshots: Vec::new(),
            diagnostics: Vec::new(),
            write_kills: Vec::new(),
        }
    }

    pub fn child(&self, dir: u64, name: &[u8]) -> Option<u64> {
        match &self.nodes.get(&dir)?.kind {
            Kind::Dir(m) => m.get(name).copied(),
            _ => None,
        }
    }

    /// Removes entry `name` from `dir` (no checks).
    pub fn detach(&mut self, dir: u64, name: &[u8]) -> Option<u64> {
        match &mut self.nodes.get_mut(&dir)?.kind {
            Kind::Dir(m) => m.remove(name),
            _ => None,
        }
    }

    /// Makes a node `name` in `dir`.
    pub fn mknode(&mut self, dir: u64, name: &[u8], mode: u32, kind: Kind) -> Result<u64, i64> {
        if name.is_empty() || name.contains(&b'/') {
            return Err(EINVAL);
        }
        if name.len() > 255 {
            return Err(ENAMETOOLONG);
        }
        let d = self.nodes.get(&dir).ok_or(ENOENT)?;
        let Kind::Dir(m) = &d.kind else { return Err(ENOTDIR) };
        if m.contains_key(name) {
            return Err(EEXIST);
        }
        let ino = self.next;
        self.next += 1;
        let size = match &kind {
            Kind::File(d) => d.len() as u64,
            Kind::Symlink(t) => t.len() as u64,
            _ => 0,
        };
        let is_dir = matches!(kind, Kind::Dir(_));
        self.nodes.insert(
            ino,
            Node {
                attr: Attr { ino, mode, nlink: if is_dir { 2 } else { 1 }, size, generation: 1, birth_txg: self.open_txg, mtime: (1_700_000_000, 0), ..Default::default() },
                kind,
                xattrs: BTreeMap::new(),
            },
        );
        if let Some(Node { kind: Kind::Dir(m), .. }) = self.nodes.get_mut(&dir) {
            m.insert(name.to_vec(), ino);
        }
        self.dirty = true;
        Ok(ino)
    }

    /// Test helper: makes `path` (relative to `base`) a directory, parents included.
    pub fn mkdir_p(&mut self, base: u64, path: &str) -> u64 {
        let mut cur = base;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            cur = match self.child(cur, c.as_bytes()) {
                Some(i) => i,
                None => self.mknode(cur, c.as_bytes(), S_IFDIR | 0o755, Kind::Dir(BTreeMap::new())).unwrap(),
            };
        }
        cur
    }

    /// Test helper: a file at `path` below `base` with `data`.
    pub fn put(&mut self, base: u64, path: &str, data: &[u8]) -> u64 {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (self.mkdir_p(base, d), n),
            None => (base, path),
        };
        if let Some(old) = self.child(dir, name.as_bytes()) {
            self.detach(dir, name.as_bytes());
            let _ = old;
        }
        self.mknode(dir, name.as_bytes(), S_IFREG | 0o644, Kind::File(data.to_vec())).unwrap()
    }

    /// Test helper: a symbolic link at `path` below `base`.
    pub fn link_to(&mut self, base: u64, path: &str, target: &str) -> u64 {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (self.mkdir_p(base, d), n),
            None => (base, path),
        };
        self.mknode(dir, name.as_bytes(), S_IFLNK | 0o777, Kind::Symlink(target.as_bytes().to_vec())).unwrap()
    }

    /// Contents of file `ino`.
    pub fn data(&self, ino: u64) -> Option<Vec<u8>> {
        match &self.nodes.get(&ino)?.kind {
            Kind::File(d) => Some(d.clone()),
            _ => None,
        }
    }

    pub fn attr(&self, ino: u64) -> Result<Attr, i64> {
        let n = self.nodes.get(&ino).ok_or(ENOENT)?;
        let mut a = n.attr;
        a.has_xattr = !n.xattrs.is_empty();
        if let Kind::File(d) = &n.kind {
            a.size = d.len() as u64;
            a.blocks = (a.size + 511) / 512;
        }
        Ok(a)
    }

    fn is_dir(&self, ino: u64) -> bool {
        matches!(self.nodes.get(&ino).map(|n| &n.kind), Some(Kind::Dir(_)))
    }

    fn parent_of(&self, ino: u64) -> u64 {
        for (&p, n) in &self.nodes {
            if let Kind::Dir(m) = &n.kind {
                if m.values().any(|&c| c == ino) && p != ino {
                    return p;
                }
            }
        }
        ino
    }

    /// Walks `path` from `base` (or `root` for an absolute path) inside `root`, as the
    /// server's `resolve_in_dirs`; `dirs` gets the directories passed that not everyone may
    /// search.
    pub fn resolve(&self, root: u64, base: u64, path: &[u8], follow: bool, dirs: &mut Vec<u64>) -> Result<u64, i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut cur = if path[0] == b'/' { root } else { base };
        let mut todo: std::collections::VecDeque<Vec<u8>> = path.split(|&b| b == b'/').filter(|c| !c.is_empty()).map(|c| c.to_vec()).collect();
        let trailing = path.ends_with(b"/");
        let mut links = 0;
        while let Some(c) = todo.pop_front() {
            if !self.is_dir(cur) {
                return Err(ENOTDIR);
            }
            let m = self.nodes[&cur].attr.mode;
            if m & 0o111 != 0o111 && !dirs.contains(&cur) {
                dirs.push(cur);
            }
            if c == b"." {
                continue;
            }
            if c == b".." {
                if cur != root {
                    cur = self.parent_of(cur);
                }
                continue;
            }
            let next = self.child(cur, &c).ok_or(ENOENT)?;
            if let Kind::Symlink(t) = &self.nodes[&next].kind {
                if !todo.is_empty() || follow || trailing {
                    links += 1;
                    if links > 40 {
                        return Err(ELOOP);
                    }
                    if t.first() == Some(&b'/') {
                        cur = root;
                    }
                    for p in t.split(|&b| b == b'/').filter(|c| !c.is_empty()).rev() {
                        todo.push_front(p.to_vec());
                    }
                    continue;
                }
            }
            cur = next;
        }
        if trailing && !self.is_dir(cur) {
            return Err(ENOTDIR);
        }
        Ok(cur)
    }

    fn take_fail(op: u32) -> Option<i64> {
        FAIL.with_borrow_mut(|v| {
            let i = v.iter().position(|f| f.0 == op || f.0 == 0)?;
            let e = v[i].1;
            v[i].2 -= 1;
            if v[i].2 == 0 {
                v.remove(i);
            }
            Some(e)
        })
    }

    /// Handles one request: `(errno, value, reply length)`; the reply is written to `out`.
    fn handle(&mut self, op: u32, params: &[u8], out: &mut [u8]) -> Result<(u64, usize), i64> {
        if let Some(e) = Self::take_fail(op) {
            return Err(e);
        }
        let mut r = Reader::new(params);
        let mut w = Writer::new(out);
        match op {
            FS_ROOT => Ok((ROOT_INO, 0)),
            FS_LOOKUP => {
                let dir = r.u64();
                let name = r.bytes();
                if !self.is_dir(dir) {
                    return Err(ENOTDIR);
                }
                self.child(dir, name).map(|i| (i, 0)).ok_or(ENOENT)
            }
            FS_RESOLVE => {
                let (root, base, follow) = (r.u64(), r.u64(), r.u64() != 0);
                let path = r.bytes();
                let mut dirs = Vec::new();
                let ino = self.resolve(root, base, path, follow, &mut dirs)?;
                w.u64(dirs.len() as u64);
                for d in &dirs {
                    w.u64(*d);
                }
                Ok((ino, w.len()))
            }
            FS_RESOLVE_MNT => {
                let (root, _root_mnt, base, base_mnt, follow) = (r.u64(), r.u64() as usize, r.u64(), r.u64() as usize, r.u64() != 0);
                let path = r.bytes().to_vec();
                let n = r.u64() as usize;
                let mounts: Vec<(u64, u64, usize)> = (0..n).map(|_| (r.u64(), r.u64(), r.u64() as usize)).collect();
                // A simple walk: a component that names a mount point continues in the mount
                // (a FUSE root, bit 62, stops the walk with the rest of the path)
                let comps: Vec<&[u8]> = path.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
                let (mut cur, mut mnt) = if path.first() == Some(&b'/') { (root, 0usize) } else { (base, base_mnt) };
                for (i, c) in comps.iter().enumerate() {
                    let mut dirs = Vec::new();
                    let next = self.resolve(root, cur, c, follow || i + 1 < comps.len(), &mut dirs)?;
                    cur = next;
                    if let Some(k) = mounts.iter().position(|m| m.0 == cur) {
                        mnt = k + 1;
                        let mroot = mounts[k].1;
                        if mroot & (1 << 62) != 0 {
                            let rest: Vec<u8> = comps[i + 1..].join(&b'/');
                            w.u64(mnt as u64);
                            w.bytes(&rest);
                            return Ok(((mnt as u64) << MNT_SHIFT, w.len()));
                        }
                        cur = mroot;
                    }
                }
                Ok((cur | (mnt as u64) << MNT_SHIFT, 0))
            }
            FS_GETATTR => {
                let a = self.attr(r.u64())?;
                w.attr(&a);
                Ok((0, w.len()))
            }
            FS_SETATTR => {
                let ino = r.u64();
                let s = r.setattr();
                let n = self.nodes.get_mut(&ino).ok_or(ENOENT)?;
                if let Some(m) = s.mode {
                    n.attr.mode = (n.attr.mode & S_IFMT) | (m & 0o7777);
                }
                if let Some(u) = s.uid {
                    n.attr.uid = u;
                }
                if let Some(g) = s.gid {
                    n.attr.gid = g;
                }
                if let Some(t) = s.atime {
                    n.attr.atime = t;
                }
                if let Some(t) = s.mtime {
                    n.attr.mtime = t;
                }
                if let Some(size) = s.size {
                    match &mut n.kind {
                        Kind::File(d) => d.resize(size as usize, 0),
                        Kind::Dir(_) => return Err(EISDIR),
                        _ => return Err(EINVAL),
                    }
                }
                self.dirty = true;
                let a = self.attr(ino)?;
                w.attr(&a);
                Ok((0, w.len()))
            }
            FS_READ => {
                let (ino, off, len) = (r.u64(), r.u64() as usize, (r.u64() as usize).min(MAX_IO));
                let n = self.nodes.get(&ino).ok_or(ENOENT)?;
                let Kind::File(d) = &n.kind else { return Err(EISDIR) };
                let start = off.min(d.len());
                let k = len.min(d.len() - start);
                let bytes = d[start..start + k].to_vec();
                out[..k].copy_from_slice(&bytes);
                Ok((k as u64, k))
            }
            FS_WRITE => {
                let (ino, off) = (r.u64(), r.u64() as usize);
                let mut data = r.bytes().to_vec();
                let kill = if r.u64() & 1 != 0 {
                    let n = r.u64();
                    Some((0..n).map(|_| r.u64() as u32).collect())
                } else {
                    None
                };
                self.write_kills.push(kill);
                let lim = WRITE_LIMIT.get();
                if lim != 0 && data.len() > lim {
                    data.truncate(lim);
                }
                let n = self.nodes.get_mut(&ino).ok_or(ENOENT)?;
                let Kind::File(d) = &mut n.kind else { return Err(EISDIR) };
                if d.len() < off + data.len() {
                    d.resize(off + data.len(), 0);
                }
                d[off..off + data.len()].copy_from_slice(&data);
                self.dirty = true;
                Ok((data.len() as u64, 0))
            }
            FS_CREATE | FS_MKDIR => {
                let dir = r.u64();
                let name = r.bytes().to_vec();
                let (perm, uid, gid) = (r.u64() as u32, r.u64() as u32, r.u64() as u32);
                let (mode, kind) = if op == FS_CREATE { (S_IFREG | perm, Kind::File(Vec::new())) } else { (S_IFDIR | perm, Kind::Dir(BTreeMap::new())) };
                let ino = self.mknode(dir, &name, mode, kind)?;
                let n = self.nodes.get_mut(&ino).unwrap();
                n.attr.uid = uid;
                n.attr.gid = gid;
                Ok((ino, 0))
            }
            FS_MKNOD => {
                let dir = r.u64();
                let name = r.bytes().to_vec();
                let (mode, rdev, uid, gid) = (r.u64() as u32, r.u64(), r.u64() as u32, r.u64() as u32);
                let ino = self.mknode(dir, &name, mode, Kind::Special)?;
                let n = self.nodes.get_mut(&ino).unwrap();
                n.attr.rdev = rdev;
                n.attr.uid = uid;
                n.attr.gid = gid;
                Ok((ino, 0))
            }
            FS_SYMLINK => {
                let dir = r.u64();
                let name = r.bytes().to_vec();
                let target = r.bytes().to_vec();
                let (uid, gid) = (r.u64() as u32, r.u64() as u32);
                let ino = self.mknode(dir, &name, S_IFLNK | 0o777, Kind::Symlink(target))?;
                let n = self.nodes.get_mut(&ino).unwrap();
                n.attr.uid = uid;
                n.attr.gid = gid;
                Ok((ino, 0))
            }
            FS_READLINK => {
                let n = self.nodes.get(&r.u64()).ok_or(ENOENT)?;
                let Kind::Symlink(t) = &n.kind else { return Err(EINVAL) };
                let t = t.clone();
                out[..t.len()].copy_from_slice(&t);
                Ok((t.len() as u64, t.len()))
            }
            FS_LINK => {
                let (ino, dir) = (r.u64(), r.u64());
                let name = r.bytes().to_vec();
                if self.is_dir(ino) {
                    return Err(EPERM);
                }
                let d = self.nodes.get_mut(&dir).ok_or(ENOENT)?;
                let Kind::Dir(m) = &mut d.kind else { return Err(ENOTDIR) };
                if m.contains_key(&name) {
                    return Err(EEXIST);
                }
                m.insert(name, ino);
                self.nodes.get_mut(&ino).ok_or(ENOENT)?.attr.nlink += 1;
                Ok((0, 0))
            }
            FS_UNLINK | FS_RMDIR => {
                let dir = r.u64();
                let name = r.bytes().to_vec();
                let ino = self.child(dir, &name).ok_or(ENOENT)?;
                let is_dir = self.is_dir(ino);
                if op == FS_UNLINK && is_dir {
                    return Err(EISDIR);
                }
                if op == FS_RMDIR {
                    if !is_dir {
                        return Err(ENOTDIR);
                    }
                    if matches!(&self.nodes[&ino].kind, Kind::Dir(m) if !m.is_empty()) {
                        return Err(ENOTEMPTY);
                    }
                }
                self.detach(dir, &name);
                if let Some(n) = self.nodes.get_mut(&ino) {
                    n.attr.nlink = n.attr.nlink.saturating_sub(1);
                }
                Ok((0, 0))
            }
            FS_RENAME => {
                let sdir = r.u64();
                let sname = r.bytes().to_vec();
                let ddir = r.u64();
                let dname = r.bytes().to_vec();
                let ino = self.child(sdir, &sname).ok_or(ENOENT)?;
                if !self.is_dir(ddir) {
                    return Err(ENOTDIR);
                }
                self.detach(sdir, &sname);
                self.detach(ddir, &dname);
                if let Some(Node { kind: Kind::Dir(m), .. }) = self.nodes.get_mut(&ddir) {
                    m.insert(dname, ino);
                }
                Ok((0, 0))
            }
            FS_READDIR => {
                let (dir, cookie, max) = (r.u64(), r.u64(), r.u64() as usize);
                let n = self.nodes.get(&dir).ok_or(ENOENT)?;
                let Kind::Dir(m) = &n.kind else { return Err(ENOTDIR) };
                // Cookies: 0 ".", 1 "..", 2 + i the i-th entry
                let mut all: Vec<ReaddirEntry> = Vec::new();
                all.push(ReaddirEntry { name: b".".to_vec(), ino: dir, dtype: 4, next_cookie: 1 });
                all.push(ReaddirEntry { name: b"..".to_vec(), ino: self.parent_of(dir), dtype: 4, next_cookie: 2 });
                for (i, (name, &ino)) in m.iter().enumerate() {
                    all.push(ReaddirEntry { name: name.clone(), ino, dtype: 8, next_cookie: 3 + i as u64 });
                }
                let mut count = 0;
                for e in all.iter().skip(cookie as usize).take(max) {
                    if !w.entry(e) {
                        break;
                    }
                    count += 1;
                }
                Ok((count, w.len()))
            }
            FS_STATFS => {
                w.u64(1 << 20);
                w.u64(1 << 19);
                w.u64(self.nodes.len() as u64);
                Ok((0, w.len()))
            }
            FS_OPEN_REF => {
                *self.refs.entry(r.u64()).or_insert(0) += 1;
                Ok((0, 0))
            }
            FS_RELEASE => {
                *self.refs.entry(r.u64()).or_insert(0) -= 1;
                Ok((0, 0))
            }
            FS_NOTIFY => {
                let (ino, mask) = (r.u64(), r.u64() as u32);
                self.notified.push((ino, mask));
                Ok((0, 0))
            }
            FS_SYNC => {
                self.txg = self.open_txg;
                self.open_txg += 1;
                self.dirty = false;
                Ok((self.txg, 0))
            }
            FS_SYNC_IF_DIRTY => {
                if self.dirty {
                    self.txg = self.open_txg;
                    self.open_txg += 1;
                    self.dirty = false;
                    Ok((1, 0))
                } else {
                    Ok((0, 0))
                }
            }
            FS_SNAPSHOT => {
                let idx = r.u64();
                let name = String::from_utf8_lossy(r.bytes()).into_owned();
                if idx > 1 {
                    return Err(EINVAL);
                }
                self.snapshots.push((idx, name));
                Ok((self.txg, 0))
            }
            FS_POOL_STATUS => {
                w.u64(64 << 20);
                w.u64(8 << 20);
                w.u64(56 << 20);
                w.u64(self.txg);
                w.u64(self.open_txg);
                Ok((0, w.len()))
            }
            FS_OBJECT_INFO => {
                let a = self.attr(r.u64())?;
                w.u64(a.birth_txg);
                w.u64((a.size > 0) as u64);
                for c in [a.ino, a.size, 3, 4] {
                    w.u64(c);
                }
                Ok((0, w.len()))
            }
            FS_DATASETS => {
                let mut n = 0;
                let mut list: Vec<(String, String, u64, bool)> = vec![("hydrapool".into(), "/".into(), self.txg, false)];
                for (_, s) in &self.snapshots {
                    list.push((format!("hydrapool@{s}"), String::new(), self.txg, true));
                }
                for (name, mount, txg, snap) in &list {
                    w.bytes(name.as_bytes());
                    w.bytes(mount.as_bytes());
                    w.u64(*txg);
                    w.u64(*snap as u64);
                    n += 1;
                }
                Ok((n, w.len()))
            }
            FS_SELFTEST | FS_VERIFY | FS_FSCK => {
                let path = String::from_utf8_lossy(r.bytes()).into_owned();
                let repair = r.u64() != 0;
                self.diagnostics.push((op, path, repair));
                Ok((0, 0))
            }
            FS_GETXATTR | FS_LISTXATTR => {
                let ino = r.u64();
                let n = self.nodes.get(&ino).ok_or(ENOENT)?;
                let v = if op == FS_GETXATTR {
                    let name = r.bytes();
                    n.xattrs.get(name).cloned().ok_or(ENODATA)?
                } else {
                    let mut v = Vec::new();
                    for k in n.xattrs.keys() {
                        v.extend_from_slice(k);
                        v.push(0);
                    }
                    v
                };
                out[..v.len()].copy_from_slice(&v);
                Ok((v.len() as u64, v.len()))
            }
            FS_SETXATTR => {
                let ino = r.u64();
                let name = r.bytes().to_vec();
                let value = r.bytes().to_vec();
                let _flags = r.u64();
                self.nodes.get_mut(&ino).ok_or(ENOENT)?.xattrs.insert(name, value);
                Ok((0, 0))
            }
            FS_REMOVEXATTR => {
                let ino = r.u64();
                let name = r.bytes().to_vec();
                self.nodes.get_mut(&ino).ok_or(ENOENT)?.xattrs.remove(&name).map(|_| (0, 0)).ok_or(ENODATA)
            }
            _ => Err(-38),
        }
    }
}

/// The ZFS endpoint's handler: decodes the request in `w`, answers in `w` (and its events
/// after `EVENT_OFFSET`).
fn zfs_handle(req: &Message, w: &mut [u8]) -> Result<Message, i64> {
    let op = req.label;
    OPS.with_borrow_mut(|v| v.push(op));
    let len = req.args[0] as usize;
    let params = w[..len].to_vec();
    let mut out = vec![0u8; EVENT_OFFSET];
    let res = {
        let mut g = FS.lock().unwrap_or_else(|e| e.into_inner());
        g.as_mut().ok_or(-5i64)?.handle(op, &params, &mut out)
    };
    let events: Vec<Event> = EVENTS.with_borrow_mut(std::mem::take);
    {
        let mut ew = Writer::new(&mut w[EVENT_OFFSET..EVENT_OFFSET + EVENT_SPACE]);
        for e in &events {
            ew.event(e);
        }
    }
    let (errno, value, rlen) = match res {
        Ok((v, l)) => {
            w[..l].copy_from_slice(&out[..l]);
            (0i64, v, l)
        }
        Err(e) => (e, 0, 0),
    };
    let label = if BAD_LABEL.get() { 0x1234 } else { FS_REPLY };
    Ok(Message::with_args(label, [errno as u64, value, rlen as u64, events.len() as u64]))
}
