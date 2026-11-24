//! # FUSE: vfs-server as the FUSE client (wave 9, Group 6b-2)
//!
//! While the file service is forwarded, `/dev/fuse` (char 10:229) opens here
//! (`LX_KCALL_DEVOPEN`; the kernel routes the one device by number, major 10 is shared): each
//! open is a server object of kind [`LX_OBJ_KIND_FUSE`] and a new connection. The daemon
//! reads requests from it (`read`/`readv`, PENDING until one is queued) and writes replies
//! (`write`/`writev`); its readiness word drives poll/epoll; its close ends the connection
//! (callers get `ENOTCONN`, other readers `ENODEV`).
//!
//! The files of a connection have FUSE inode numbers with connection numbers from
//! `FUSE_SVC_CONN` on ([`wire::ino`]): the kernel's file code keeps treating them as FUSE
//! inodes and sends every operation on them here (`LX_KCALL_FUSE`, from
//! `src/compat/linux/fuse_svc.rs`), lending its buffers for the data
//! (`FUSE_KBUF_IN`/`FUSE_KBUF_OUT`).
//!
//! **Nothing here waits for a daemon.** An operation is a short chain of requests
//! ([`Op`], [`begin`], [`on_reply`]); a call whose operation has to ask the daemon answers
//! PENDING, and the worker that takes the daemon's reply runs the next step or completes the
//! call. So a daemon that itself uses files (xdg-document-portal serves real files) never
//! finds every worker blocked.

pub mod wire;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::svcrt::{objs, Answer, Cx};
use hydra_rt::sys;

use crate::ctx::Node;
use crate::fs::fsproto::Attr;
use crate::lock::YLock;
use crate::proto::*;
use wire::*;

const EINTR: i64 = -4;
const EIO: i64 = -5;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EXDEV: i64 = -18;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;
const EOPNOTSUPP: i64 = -95;
const ENOTCONN: i64 = -107;
const ESTALE: i64 = -116;
const ERESTARTSYS: i64 = -512;

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const POLLERR: u32 = 0x8;
/// `makedev(10, 229)`.
const RDEV: u64 = (10 << 8) | 229;
/// Largest reply a daemon may write (a READ reply of 128 KiB and its header, with room).
const MSG_MAX: usize = 256 * 1024;

/// Operations started, and calls that waited for a daemon (PENDING), since start.
pub static OPS: AtomicU64 = AtomicU64::new(0);
pub static WAITED: AtomicU64 = AtomicU64::new(0);

/// A daemon's read waiting for a request.
struct Reader {
    id: u64,
    /// `(address, length)` parts (one for `read`, the iovec for `readv`).
    parts: Vec<(u64, u64)>,
}

impl Reader {
    fn len(&self) -> u64 {
        self.parts.iter().fold(0u64, |t, p| t.saturating_add(p.1))
    }
}

/// What a request's reply goes to.
enum Wait {
    Op(Op),
    Discard,
    Init,
    /// A lookup the walk of a program's call needed: the call runs again with the answer.
    Rerun(Box<Rerun>),
}

/// One connection: a daemon and the file system it serves.
struct Conn {
    id: u16,
    /// The daemon's descriptors (server-object slots).
    devs: Vec<u32>,
    mounted: bool,
    initialized: bool,
    aborted: bool,
    /// `(uid, gid, allow_other)` of the mount.
    owner: (u32, u32, bool),
    max_write: u32,
    queue: VecDeque<Vec<u8>>,
    readers: VecDeque<Reader>,
    waits: BTreeMap<u64, Wait>,
    next_unique: u64,
    nodes: Nodes,
    handles: BTreeMap<u64, Handles>,
    /// Operations that came before the daemon answered INIT.
    before_init: Vec<Op>,
    /// Names whose entries the daemon said stay valid: `(dir, name)` -> `(node, until ms)`.
    names: BTreeMap<(u64, Vec<u8>), (u64, u64)>,
    /// Answers fetched for a call that runs again (lookups, attributes, link targets), good
    /// for [`SHOT_MS`] whatever the daemon's valid times (a walk may ask the same twice, and
    /// the run must find both).
    shots: BTreeMap<(u64, Vec<u8>), (Result<u64, i64>, u64)>,
    attr_shots: BTreeMap<u64, (Result<[u8; ATTR], i64>, u64)>,
    link_shots: BTreeMap<u64, (Result<Vec<u8>, i64>, u64)>,
    /// wave10 GV2: the daemon's `statfs` answer fetched for a call that runs again.
    statfs_shot: Option<(Result<Vec<u8>, i64>, u64)>,
    /// wave11 GF: program calls whose walk reached the mount before the daemon answered INIT
    /// (they run again after it).
    init_waits: Vec<LxCall>,
}

impl Conn {
    fn new(id: u16) -> Self {
        Conn {
            id,
            devs: Vec::new(),
            mounted: false,
            initialized: false,
            aborted: false,
            owner: (0, 0, false),
            max_write: 4096,
            queue: VecDeque::new(),
            readers: VecDeque::new(),
            waits: BTreeMap::new(),
            next_unique: 2,
            nodes: Nodes::with_base(EPOCH.load(Ordering::Relaxed) << 32),
            handles: BTreeMap::new(),
            before_init: Vec::new(),
            names: BTreeMap::new(),
            shots: BTreeMap::new(),
            attr_shots: BTreeMap::new(),
            link_shots: BTreeMap::new(),
            statfs_shot: None,
            init_waits: Vec::new(),
        }
    }

    /// Names were made, removed or moved: no kept attributes or names stay.
    fn forget_all(&mut self) {
        self.nodes.uncache(None);
        self.names.clear();
        self.shots.clear();
        self.attr_shots.clear();
        self.link_shots.clear();
    }

    /// Node `l`'s attributes changed (a write, a setattr).
    fn forget_attr(&mut self, l: u64) {
        self.nodes.uncache(Some(l));
        self.attr_shots.remove(&l);
    }

    fn ready(&self) -> u32 {
        if self.aborted {
            POLLOUT | POLLERR
        } else if self.queue.is_empty() {
            POLLOUT
        } else {
            POLLIN | POLLOUT
        }
    }

    fn set_ready(&self) {
        let r = self.ready();
        for &s in &self.devs {
            objs::set(s, r, 0);
        }
    }
}

/// A call to complete from another worker: request, where its output goes, the output,
/// the result.
struct Finish {
    id: u64,
    parts: Vec<(u64, u64)>,
    out: Vec<u8>,
    r: i64,
    /// A program's call to run again instead.
    rerun: Option<Box<LxCall>>,
    /// A request handed to a daemon's read: the connection it goes back to if the read's
    /// buffer cannot take it.
    requeue: Option<u16>,
    /// wave11 GF: a program's call answered from its operation's reply ([`Then`]).
    then: Option<Box<Then>>,
}

impl Finish {
    fn err(id: u64, r: i64) -> Self {
        Finish { id, parts: Vec::new(), out: Vec::new(), r, rerun: None, requeue: None, then: None }
    }

    fn kout(id: u64, r: i64, out: Vec<u8>) -> Self {
        let n = out.len() as u64;
        Finish { id, parts: alloc::vec![(FUSE_KBUF_OUT, n)], out, r, rerun: None, requeue: None, then: None }
    }

    fn run(self) {
        if let Some(c) = self.rerun {
            crate::rerun(&c);
            return;
        }
        // wave11 GF: a program's call (a change decided by vfs-server)
        if let Some(t) = self.then {
            if let Some(r) = then_result(self.id, self.r, &self.out, *t) {
                let _ = sys::lx_complete(self.id, r);
            }
            return;
        }
        let mut r = self.r;
        let mut o = 0usize;
        for (addr, len) in self.parts {
            if o >= self.out.len() {
                break;
            }
            let n = (len as usize).min(self.out.len() - o);
            if let Err(e) = sys::lx_write(self.id, addr, &self.out[o..o + n]) {
                r = e;
                break;
            }
            o += n;
        }
        let failed = r < 0;
        let _ = sys::lx_complete(self.id, r);
        if failed {
            if let Some(conn) = self.requeue {
                requeue(conn, self.out);
            }
        }
    }
}

/// Request `m`, taken by a daemon's read whose buffer could not take it, goes back to the
/// front of connection `conn`'s queue (the next read gets it).
fn requeue(conn: u16, m: Vec<u8>) {
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        let Some(c) = st.conns.get_mut(&conn) else { return };
        if c.aborted {
            return;
        }
        c.queue.push_front(m);
        feed(c, &mut fin);
    }
    finish_all(fin);
}

struct State {
    conns: BTreeMap<u16, Conn>,
    devs: BTreeMap<u32, u16>,
    next: u16,
}

static ST: YLock<State> = YLock::new(State { conns: BTreeMap::new(), devs: BTreeMap::new(), next: 0 });

// ----------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------

/// What an operation does (and how far it got).
enum Kind {
    /// `name` in directory `local`.
    Lookup { name: Vec<u8> },
    /// `with_ino`: the answer is `[ino][attr]` (a lookup of `.` or `..`).
    Getattr { with_ino: bool },
    Setattr { set_in: Vec<u8> },
    /// `checked`: the node is known to be a link.
    Readlink { checked: bool },
    Read { off: u64, len: usize, open: Option<usize> },
    Write { off: u64, total: usize, done: usize, part: usize, open: Option<usize> },
    Readdir { cookie: u64, open: Option<usize> },
    Create { name: Vec<u8>, perm: u32, mknod: bool },
    /// A request whose reply is a new entry named `name` (mknod, mkdir, symlink, link).
    Make { name: Vec<u8>, opcode: u32, args: Vec<u8> },
    /// A request with an empty answer (unlink, rmdir, rename, setxattr, removexattr).
    Plain { opcode: u32, args: Vec<u8>, xattr: bool },
    /// A request whose reply's bytes are the answer (getxattr, listxattr).
    Data { opcode: u32, args: Vec<u8> },
    Statfs,
}

/// One operation for call `id`, on local node `local` of connection `conn`.
struct Op {
    id: u64,
    who: Who,
    local: u64,
    kind: Kind,
    /// wave11 GF: `None`: the kernel's operation (`LX_KCALL_FUSE`); else a program's call
    /// answered from the reply.
    to: Option<Then>,
}

/// The next step of an operation.
enum Step {
    Send { opcode: u32, nodeid: u64, args: Vec<Vec<u8>>, op: Op },
    Done { id: u64, r: i64, out: Vec<u8>, to: Option<Then> },
}

fn done(op: &Op, r: i64, out: Vec<u8>) -> Step {
    Step::Done { id: op.id, r, out, to: op.to.clone() }
}

fn want_of(k: &Kind) -> Want {
    match k {
        Kind::Read { .. } => Want::Read,
        Kind::Write { .. } => Want::Write,
        _ => Want::Dir,
    }
}

/// The handle an operation needs: `Ok(fh)`, or the open request to send first.
fn handle(c: &Conn, op: Op, nodeid: u64) -> Result<(u64, Op), Step> {
    let want = want_of(&op.kind);
    if let Some(fh) = c.handles.get(&op.local).and_then(|h| h.get(want)) {
        return Ok((fh, op));
    }
    let mut op = op;
    let (opcode, flags) = want.open();
    match &mut op.kind {
        Kind::Read { open, .. } | Kind::Write { open, .. } | Kind::Readdir { open, .. } => *open = Some(0),
        _ => {}
    }
    Err(Step::Send { opcode, nodeid, args: alloc::vec![le(&[flags[0] as u64, 0], &[4, 4])], op })
}

/// The first step of `op`.
fn begin(c: &mut Conn, op: Op) -> Step {
    let Some(nodeid) = c.nodes.nodeid(op.local) else { return done(&op, ESTALE, Vec::new()) };
    let now = hydra_rt::svcrt::now_ms();
    match &op.kind {
        Kind::Lookup { name } => {
            Step::Send { opcode: LOOKUP, nodeid, args: alloc::vec![cstr(name)], op }
        }
        Kind::Getattr { with_ino } => match c.nodes.cached(op.local, now) {
            Some(a) => {
                let mut out = Vec::with_capacity(8 + ATTR);
                if *with_ino {
                    out.extend_from_slice(&ino(c.id, op.local).to_le_bytes());
                }
                out.extend_from_slice(&a);
                done(&op, 0, out)
            }
            None => Step::Send { opcode: GETATTR, nodeid, args: alloc::vec![alloc::vec![0u8; 16]], op },
        },
        Kind::Setattr { set_in } => {
            let a = set_in.clone();
            c.forget_attr(op.local);
            Step::Send { opcode: SETATTR, nodeid, args: alloc::vec![a], op }
        }
        Kind::Readlink { checked } => {
            if !*checked {
                match c.nodes.cached(op.local, now) {
                    Some(a) if attr_mode(&a) & S_IFMT != S_IFLNK => return done(&op, EINVAL, Vec::new()),
                    Some(_) => {}
                    None => return Step::Send { opcode: GETATTR, nodeid, args: alloc::vec![alloc::vec![0u8; 16]], op },
                }
            }
            Step::Send { opcode: READLINK, nodeid, args: Vec::new(), op }
        }
        Kind::Read { off, len, .. } => {
            let (off, len) = (*off, *len);
            match handle(c, op, nodeid) {
                Ok((fh, op)) => Step::Send { opcode: READ, nodeid, args: alloc::vec![rw_args(fh, off, len)], op },
                Err(s) => s,
            }
        }
        Kind::Write { .. } => match handle(c, op, nodeid) {
            Ok((fh, op)) => write_next(c, op, nodeid, fh),
            Err(s) => s,
        },
        Kind::Readdir { cookie, .. } => {
            let cookie = *cookie;
            match handle(c, op, nodeid) {
                Ok((fh, op)) => Step::Send { opcode: READDIR, nodeid, args: alloc::vec![rw_args(fh, cookie, 16384)], op },
                Err(s) => s,
            }
        }
        Kind::Create { name, perm, mknod } => {
            c.forget_all();
            let mode = (S_IFREG | (perm & 0o7777)) as u64;
            if *mknod {
                Step::Send { opcode: MKNOD, nodeid, args: alloc::vec![le(&[mode, 0, 0, 0], &[4, 4, 4, 4]), cstr(name)], op }
            } else {
                // O_CREAT | O_EXCL | O_RDWR
                Step::Send { opcode: CREATE, nodeid, args: alloc::vec![le(&[0o302, mode, 0, 0], &[4, 4, 4, 4]), cstr(name)], op }
            }
        }
        Kind::Make { opcode, args, .. } | Kind::Plain { opcode, args, .. } | Kind::Data { opcode, args } => {
            let (opcode, args) = (*opcode, args.clone());
            if !matches!(op.kind, Kind::Data { .. }) {
                c.forget_all();
            }
            Step::Send { opcode, nodeid, args: alloc::vec![args], op }
        }
        Kind::Statfs => Step::Send { opcode: STATFS, nodeid, args: Vec::new(), op },
    }
}

/// The next part of a write: its data from the kernel's buffer.
fn write_next(c: &Conn, mut op: Op, nodeid: u64, fh: u64) -> Step {
    let Kind::Write { off, total, done: d, part, .. } = &mut op.kind else { unreachable!() };
    let n = (*total - *d).min(c.max_write as usize);
    let mut data = alloc::vec![0u8; n];
    if n > 0 {
        if let Err(e) = sys::lx_read(op.id, FUSE_KBUF_IN + *d as u64, &mut data) {
            return done(&op, e, Vec::new());
        }
    }
    *part = n;
    let a = rw_args(fh, *off + *d as u64, n);
    Step::Send { opcode: WRITE, nodeid, args: alloc::vec![a, data], op }
}

/// The step after the daemon's reply (`err`, `body`) to `op`'s last request.
fn on_reply(c: &mut Conn, mut op: Op, err: i32, body: Vec<u8>) -> Step {
    let now = hydra_rt::svcrt::now_ms();
    let err = err as i64;
    // An open on the way to a read, write or listing
    let opening = match &op.kind {
        Kind::Read { open, .. } | Kind::Write { open, .. } | Kind::Readdir { open, .. } => *open,
        _ => None,
    };
    if let Some(i) = opening {
        let want = want_of(&op.kind);
        let (opcode, flags) = want.open();
        if err != 0 {
            if i + 1 < flags.len() {
                if let Kind::Read { open, .. } | Kind::Write { open, .. } | Kind::Readdir { open, .. } = &mut op.kind {
                    *open = Some(i + 1);
                }
                let Some(nodeid) = c.nodes.nodeid(op.local) else { return done(&op, ESTALE, Vec::new()) };
                return Step::Send { opcode, nodeid, args: alloc::vec![le(&[flags[i + 1] as u64, 0], &[4, 4])], op };
            }
            return done(&op, err, Vec::new());
        }
        c.handles.entry(op.local).or_default().set(want, u64_at(&body, 0));
        if let Kind::Read { open, .. } | Kind::Write { open, .. } | Kind::Readdir { open, .. } = &mut op.kind {
            *open = None;
        }
        return begin(c, op);
    }
    match &mut op.kind {
        Kind::Create { mknod, .. } if err == ENOSYS && !*mknod => {
            *mknod = true;
            return begin(c, op);
        }
        Kind::Statfs if err == ENOSYS => return done(&op, 0, Vec::new()),
        Kind::Plain { xattr: true, .. } | Kind::Data { .. } if err == ENOSYS => return done(&op, EOPNOTSUPP, Vec::new()),
        _ if err != 0 => {
            if matches!(op.kind, Kind::Write { .. } | Kind::Setattr { .. }) {
                c.forget_attr(op.local);
            }
            return done(&op, err, Vec::new());
        }
        _ => {}
    }
    match &mut op.kind {
        Kind::Lookup { name } => {
            let Some((nodeid, entry_ms, attr_ms, a)) = entry(&body) else { return done(&op, ENOENT, Vec::new()) };
            let l = c.nodes.intern(nodeid, op.local, name);
            c.nodes.cache(l, a, attr_ms, now);
            if entry_ms > 0 {
                c.names.insert((op.local, name.clone()), (l, now + entry_ms));
            }
            let mut out = Vec::with_capacity(8 + ATTR);
            out.extend_from_slice(&ino(c.id, l).to_le_bytes());
            out.extend_from_slice(a);
            done(&op, 0, out)
        }
        Kind::Getattr { .. } | Kind::Setattr { .. } => {
            let Some((ms, a)) = attr_out(&body) else {
                // (a SETATTR reply without attributes: ask for them)
                if matches!(op.kind, Kind::Setattr { .. }) {
                    op.kind = Kind::Getattr { with_ino: false };
                    return begin(c, op);
                }
                return done(&op, EIO, Vec::new());
            };
            c.nodes.cache(op.local, a, ms, now);
            let mut out = Vec::with_capacity(8 + ATTR);
            if let Kind::Getattr { with_ino: true } = op.kind {
                out.extend_from_slice(&ino(c.id, op.local).to_le_bytes());
            }
            out.extend_from_slice(a);
            done(&op, 0, out)
        }
        Kind::Readlink { checked } => {
            if !*checked {
                let Some((ms, a)) = attr_out(&body) else { return done(&op, EIO, Vec::new()) };
                c.nodes.cache(op.local, a, ms, now);
                if attr_mode(a) & S_IFMT != S_IFLNK {
                    return done(&op, EINVAL, Vec::new());
                }
                *checked = true;
                return begin(c, op);
            }
            let mut body = body;
            body.truncate(4096); // (the kernel's buffer)
            let n = body.len() as i64;
            done(&op, n, body)
        }
        Kind::Read { len, .. } => {
            let mut body = body;
            body.truncate(*len);
            let n = body.len() as i64;
            done(&op, n, body)
        }
        Kind::Write { total, done: d, part, .. } => {
            let w = (u32_at(&body, 0) as usize).min(*part);
            *d += w;
            if w < *part || *d >= *total {
                let n = *d as i64;
                c.forget_attr(op.local);
                return done(&op, n, Vec::new());
            }
            let Some(nodeid) = c.nodes.nodeid(op.local) else { return done(&op, ESTALE, Vec::new()) };
            let Some(fh) = c.handles.get(&op.local).and_then(|h| h.write) else { return done(&op, EBADF, Vec::new()) };
            write_next(c, op, nodeid, fh)
        }
        Kind::Readdir { .. } | Kind::Data { .. } => {
            // (never more than the kernel's buffer: 16 KiB of entries, 64 KiB of xattrs)
            let mut body = body;
            body.truncate(if matches!(op.kind, Kind::Readdir { .. }) { 16384 } else { 65536 });
            let n = body.len() as i64;
            done(&op, n, body)
        }
        Kind::Statfs => {
            let n = body.len().min(80);
            let mut body = body;
            body.truncate(n);
            done(&op, n as i64, body)
        }
        Kind::Create { name, mknod, .. } => {
            let Some((nodeid, _, attr_ms, a)) = entry(&body) else { return done(&op, ENOENT, Vec::new()) };
            let l = c.nodes.intern(nodeid, op.local, name);
            c.nodes.cache(l, a, attr_ms, now);
            if !*mknod && body.len() >= ENTRY + ATTR + 16 {
                c.handles.entry(l).or_default().write = Some(u64_at(&body, ENTRY + ATTR));
            }
            c.forget_all();
            done(&op, 0, ino(c.id, l).to_le_bytes().to_vec())
        }
        Kind::Make { name, .. } => {
            let Some((nodeid, _, attr_ms, a)) = entry(&body) else { return done(&op, ENOENT, Vec::new()) };
            let l = c.nodes.intern(nodeid, op.local, name);
            c.forget_all();
            c.nodes.cache(l, a, attr_ms, now);
            done(&op, 0, ino(c.id, l).to_le_bytes().to_vec())
        }
        Kind::Plain { .. } => {
            c.forget_all();
            done(&op, 0, Vec::new())
        }
    }
}

// ----------------------------------------------------------------------
// Requests and readers
// ----------------------------------------------------------------------

/// Queues a request and hands it to a waiting reader if there is one.
fn send(c: &mut Conn, opcode: u32, nodeid: u64, who: Who, args: &[&[u8]], wait: Wait, fin: &mut Vec<Finish>) -> u64 {
    let unique = c.next_unique;
    c.next_unique += 2;
    c.queue.push_back(request(opcode, unique, nodeid, who, args));
    // (INTERRUPT has no reply of its own: nothing waits for one)
    if opcode != INTERRUPT {
        c.waits.insert(unique, wait);
    }
    feed(c, fin);
    unique
}

/// Gives queued requests to waiting readers.
fn feed(c: &mut Conn, fin: &mut Vec<Finish>) {
    while !c.queue.is_empty() && !c.readers.is_empty() {
        let r = c.readers.pop_front().unwrap();
        if (c.queue[0].len() as u64) > r.len() {
            fin.push(Finish::err(r.id, EINVAL));
            continue;
        }
        let m = c.queue.pop_front().unwrap();
        let n = m.len() as i64;
        fin.push(Finish { id: r.id, parts: r.parts, out: m, r: n, rerun: None, requeue: Some(c.id), then: None });
    }
    c.set_ready();
}

/// Runs `step`: a request is sent (`None`: the call waits), or the answer.
fn drive(c: &mut Conn, step: Step, fin: &mut Vec<Finish>) -> Option<(u64, i64, Vec<u8>, Option<Then>)> {
    match step {
        Step::Send { opcode, nodeid, args, op } => {
            let who = op.who;
            let refs: Vec<&[u8]> = args.iter().map(|a| a.as_slice()).collect();
            send(c, opcode, nodeid, who, &refs, Wait::Op(op), fin);
            None
        }
        Step::Done { id, r, out, to } => Some((id, r, out, to)),
    }
}

/// Ends connection `c`: every waiting call fails.
fn abort(c: &mut Conn, fin: &mut Vec<Finish>) {
    c.aborted = true;
    for (_, w) in core::mem::take(&mut c.waits) {
        match w {
            Wait::Op(op) => fin.push(Finish::err(op.id, ENOTCONN)),
            Wait::Rerun(r) => fin.push(Finish::err(r.call.id, ENOTCONN)),
            _ => {}
        }
    }
    for op in core::mem::take(&mut c.before_init) {
        fin.push(Finish::err(op.id, ENOTCONN));
    }
    for call in core::mem::take(&mut c.init_waits) {
        fin.push(Finish::err(call.id, ENOTCONN)); // wave11 GF
    }
    for r in core::mem::take(&mut c.readers) {
        fin.push(Finish::err(r.id, ENODEV));
    }
    c.queue.clear();
    c.set_ready();
}

fn finish_all(fin: Vec<Finish>) {
    for f in fin {
        f.run();
    }
    objs::flush();
}

// ----------------------------------------------------------------------
// Kernel calls (`LX_KCALL_FUSE`)
// ----------------------------------------------------------------------

/// The kernel's input bytes of call `cx` (`args[5]` bytes at `FUSE_KBUF_IN`).
fn input(cx: &Cx) -> Result<Vec<u8>, i64> {
    let n = cx.args[5] as usize;
    if n > FUSE_KBUF_MAX {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; n];
    if n > 0 {
        sys::lx_read(cx.id, FUSE_KBUF_IN, &mut b)?;
    }
    Ok(b)
}

/// Splits `a\0b`.
fn pair(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&x| x == 0)?;
    Some((&b[..i], &b[i + 1..]))
}

/// The answer to the caller's own call: output to the kernel's buffer, then the result.
fn answer_now(cx: &Cx, r: i64, out: &[u8]) -> Answer {
    if !out.is_empty() && r >= 0 {
        if let Err(e) = sys::lx_write(cx.id, FUSE_KBUF_OUT, out) {
            return (e, 0);
        }
    }
    (r, 0)
}

// wave10 GV2 begin: mount(2)/umount2 of the initial namespace decided here (`mountcalls`)
/// Mounts the connection of `/dev/fuse` object `slot` for owner `(uid, gid, allow_other)`:
/// its number (INIT goes to the daemon).
fn mount_locked(st: &mut State, slot: u32, owner: (u32, u32, bool), who: Who, fin: &mut Vec<Finish>) -> Result<u16, i64> {
    let &conn = st.devs.get(&slot).ok_or(EBADF)?;
    let c = st.conns.get_mut(&conn).ok_or(EBADF)?;
    if c.mounted || c.aborted {
        return Err(EINVAL);
    }
    c.owner = owner;
    c.mounted = true;
    let init = init_args();
    send(c, INIT, 0, who, &[&init], Wait::Init, fin);
    save_conn(c);
    Ok(conn)
}

/// Ends connection `conn` (unmounted: callers `ENOTCONN`, the daemon's reads `ENODEV`).
fn abort_locked(st: &mut State, conn: u16, fin: &mut Vec<Finish>) {
    if let Some(c) = st.conns.get_mut(&conn) {
        c.mounted = false;
        abort(c, fin);
    }
}

/// [`mount_locked`] for a `mount(2)` decided here.
pub fn mount_conn(slot: u32, owner: (u32, u32, bool), who: Who) -> Result<u16, i64> {
    let mut fin = Vec::new();
    let r = mount_locked(&mut ST.lock(), slot, owner, who, &mut fin);
    finish_all(fin);
    r
}

/// [`abort_locked`] for a `umount2` decided here.
pub fn abort_conn(conn: u16) {
    let mut fin = Vec::new();
    abort_locked(&mut ST.lock(), conn, &mut fin);
    finish_all(fin);
}
// wave10 GV2 end

/// `LX_KCALL_FUSE`.
pub fn kcall(cx: &Cx) -> Answer {
    let mut fin = Vec::new();
    let r = kcall_locked(cx, &mut fin);
    finish_all(fin);
    r
}

fn kcall_locked(cx: &Cx, fin: &mut Vec<Finish>) -> Answer {
    let a = cx.args;
    let who = Who { uid: cx.c.euid, gid: cx.c.egid, pid: cx.c.tgid as u32 };
    let mut st = ST.lock();
    match a[0] {
        FUSE_OP_MOUNT => return (mount_locked(&mut st, a[1] as u32, (a[2] as u32, (a[2] >> 32) as u32, a[3] != 0), who, fin).map_or_else(|e| e, |c| c as i64), 0),
        FUSE_OP_ABORT => {
            abort_locked(&mut st, a[1] as u16, fin);
            return (0, 0);
        }
        _ => {}
    }
    let Some((conn, local)) = split(a[1]) else { return (EINVAL, 0) };
    let Some(c) = st.conns.get_mut(&conn) else { return (ENOTCONN, 0) };
    // (a release after the end: nothing to tell)
    if a[0] == FUSE_OP_RELEASE || a[0] == FUSE_OP_OPEN_REF {
        let l = local;
        if a[0] == FUSE_OP_OPEN_REF {
            c.handles.entry(l).or_default().refs += 1;
            return (0, 0);
        }
        release_node(c, l, who, fin);
        return (0, 0);
    }
    if a[0] == FUSE_OP_NAME_OF {
        let out = match c.nodes.name_of(local) {
            Some((p, name)) => {
                let mut v = ino(conn, p).to_le_bytes().to_vec();
                v.extend_from_slice(name);
                v
            }
            None if c.nodes.nodeid(local).is_some() => Vec::new(),
            None => return (ESTALE, 0),
        };
        let n = out.len() as i64;
        return answer_now(cx, n, &out);
    }
    if c.aborted {
        return (ENOTCONN, 0);
    }
    let (uid, _, other) = c.owner;
    if !other && cx.c.euid != uid {
        return (EACCES, 0);
    }
    if c.nodes.nodeid(local).is_none() {
        return (ESTALE, 0);
    }
    let data = match input(cx) {
        Ok(d) => d,
        Err(e) => return (e, 0),
    };
    let mut local = local;
    let kind = match a[0] {
        FUSE_OP_LOOKUP => {
            if data.is_empty() || data == b"." {
                Kind::Getattr { with_ino: true }
            } else if data == b".." {
                local = c.nodes.name_of(local).map_or(local, |p| p.0);
                Kind::Getattr { with_ino: true }
            } else {
                Kind::Lookup { name: data }
            }
        }
        FUSE_OP_GETATTR => Kind::Getattr { with_ino: false },
        FUSE_OP_SETATTR => Kind::Setattr { set_in: data },
        FUSE_OP_READLINK => Kind::Readlink { checked: false },
        FUSE_OP_READ => Kind::Read { off: a[2], len: (a[3] as usize).min(128 * 1024), open: None },
        FUSE_OP_WRITE => Kind::Write { off: a[2], total: data.len(), done: 0, part: 0, open: None },
        FUSE_OP_READDIR => Kind::Readdir { cookie: a[2], open: None },
        FUSE_OP_CREATE => Kind::Create { name: data, perm: a[2] as u32, mknod: false },
        FUSE_OP_MKNOD => {
            let args = le(&[a[2], a[3] & 0xFFFF_FFFF, 0, 0], &[4, 4, 4, 4]);
            let mut v = args;
            v.extend_from_slice(&cstr(&data));
            Kind::Make { name: data, opcode: MKNOD, args: v }
        }
        FUSE_OP_MKDIR => {
            let mut v = le(&[a[2] & 0o7777, 0], &[4, 4]);
            v.extend_from_slice(&cstr(&data));
            Kind::Make { name: data, opcode: MKDIR, args: v }
        }
        FUSE_OP_SYMLINK => {
            let Some((name, to)) = pair(&data) else { return (EINVAL, 0) };
            let mut v = cstr(name);
            v.extend_from_slice(&cstr(to));
            Kind::Make { name: name.to_vec(), opcode: SYMLINK, args: v }
        }
        FUSE_OP_LINK => {
            // (`a[1]` the file, `a[2]` the directory: same connection only)
            let Some((dconn, dlocal)) = split(a[2]) else { return (EXDEV, 0) };
            if dconn != conn {
                return (EXDEV, 0);
            }
            let Some(old) = c.nodes.nodeid(local) else { return (ESTALE, 0) };
            let mut v = old.to_le_bytes().to_vec();
            v.extend_from_slice(&cstr(&data));
            local = dlocal;
            Kind::Make { name: data, opcode: LINK, args: v }
        }
        FUSE_OP_UNLINK | FUSE_OP_RMDIR => Kind::Plain { opcode: if a[0] == FUSE_OP_UNLINK { UNLINK } else { RMDIR }, args: cstr(&data), xattr: false },
        FUSE_OP_RENAME => {
            let Some((dconn, dlocal)) = split(a[2]) else { return (EXDEV, 0) };
            if dconn != conn {
                return (EXDEV, 0);
            }
            let Some(nd) = c.nodes.nodeid(dlocal) else { return (ESTALE, 0) };
            let Some((sname, dname)) = pair(&data) else { return (EINVAL, 0) };
            let mut v = nd.to_le_bytes().to_vec();
            v.extend_from_slice(&cstr(sname));
            v.extend_from_slice(&cstr(dname));
            Kind::Plain { opcode: RENAME, args: v, xattr: false }
        }
        FUSE_OP_GETXATTR => {
            let mut v = le(&[65536, 0], &[4, 4]);
            v.extend_from_slice(&cstr(&data));
            Kind::Data { opcode: GETXATTR, args: v }
        }
        FUSE_OP_LISTXATTR => Kind::Data { opcode: LISTXATTR, args: le(&[65536, 0], &[4, 4]) },
        FUSE_OP_SETXATTR => {
            let nl = (a[3] as usize).min(data.len());
            let (name, value) = data.split_at(nl);
            let mut v = le(&[value.len() as u64, a[2]], &[4, 4]);
            v.extend_from_slice(&cstr(name));
            v.extend_from_slice(value);
            Kind::Plain { opcode: SETXATTR, args: v, xattr: true }
        }
        FUSE_OP_REMOVEXATTR => Kind::Plain { opcode: REMOVEXATTR, args: cstr(&data), xattr: true },
        FUSE_OP_STATFS => Kind::Statfs,
        _ => return (ENOSYS, 0),
    };
    OPS.fetch_add(1, Ordering::Relaxed);
    let op = Op { id: cx.id, who, local, kind, to: None };
    if !c.initialized {
        c.before_init.push(op);
        WAITED.fetch_add(1, Ordering::Relaxed);
        return (0, LX_REPLY_PENDING);
    }
    let step = begin(c, op);
    match drive(c, step, fin) {
        Some((_, r, out, _)) => answer_now(cx, r, &out),
        None => {
            WAITED.fetch_add(1, Ordering::Relaxed);
            (0, LX_REPLY_PENDING)
        }
    }
}

// ----------------------------------------------------------------------
// The daemon's device
// ----------------------------------------------------------------------

/// `open("/dev/fuse")` (`LX_KCALL_DEVOPEN`, `rdev` 10:229): a new connection.
pub fn dev_open(cx: &Cx, flags: u64) -> Answer {
    let slot = match objs::alloc() {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let conn = {
        let mut st = ST.lock();
        let st = &mut *st;
        let conns = &st.conns;
        let Some(id) = next_conn(&mut st.next, |c| conns.contains_key(&c)) else {
            objs::free(slot);
            return (-23, 0); // ENFILE: every connection number is live
        };
        let mut c = Conn::new(id);
        c.devs.push(slot);
        save_conn(&c);
        st.conns.insert(id, c);
        st.devs.insert(slot, id);
        id
    };
    objs::set(slot, POLLOUT, 0);
    match objs::install_keyed(cx, slot, LX_OBJ_KIND_FUSE, flags as u32 & 0o2004000, 0o020666, b"/dev/fuse", conn as u64, RDEV) {
        Ok(fd) => {
            objs::flush();
            (fd, 0)
        }
        Err(e) => {
            let mut st = ST.lock();
            st.devs.remove(&slot);
            st.conns.remove(&conn);
            drop(st);
            objs::set(slot, 0, 0);
            objs::free(slot);
            (e, 0)
        }
    }
}

/// A call on a daemon's descriptor: `read`, `readv`, `write`, `writev`, `ioctl`.
pub fn dev_call(cx: &Cx) -> Answer {
    let mut fin = Vec::new();
    let r = dev_call_locked(cx, &mut fin);
    finish_all(fin);
    r
}

/// The `(address, length)` parts of `readv`/`writev`'s iovec, or of `read`/`write`.
fn parts(cx: &Cx) -> Result<Vec<(u64, u64)>, i64> {
    let a = cx.args;
    if cx.nr == 0 || cx.nr == 1 {
        return Ok(alloc::vec![(a[1], a[2])]);
    }
    let n = a[2] as usize;
    if n > 1024 {
        return Err(EINVAL);
    }
    let raw = cx.copy_in_any(a[1], n * 16)?;
    Ok(raw.chunks_exact(16).map(|c| (u64_at(c, 0), u64_at(c, 8))).filter(|p| p.1 > 0).collect())
}

fn dev_call_locked(cx: &Cx, fin: &mut Vec<Finish>) -> Answer {
    let slot = cx.c.obj as u32;
    match cx.nr {
        0 | 19 => {
            let parts = match parts(cx) {
                Ok(p) => p,
                Err(e) => return (e, 0),
            };
            let room: u64 = parts.iter().fold(0u64, |t, p| t.saturating_add(p.1));
            let mut st = ST.lock();
            let Some(&conn) = st.devs.get(&slot) else { return (EBADF, 0) };
            let Some(c) = st.conns.get_mut(&conn) else { return (ENODEV, 0) };
            if c.aborted {
                return (ENODEV, 0);
            }
            if let Some(m) = c.queue.front() {
                if m.len() as u64 > room {
                    return (EINVAL, 0);
                }
                let m = c.queue.pop_front().unwrap();
                c.set_ready();
                drop(st);
                let n = m.len() as i64;
                let mut o = 0;
                for (addr, len) in parts {
                    if o >= m.len() {
                        break;
                    }
                    let k = (len as usize).min(m.len() - o);
                    if let Err(e) = cx.copy_out_direct(addr, &m[o..o + k]) {
                        // (the request is not lost: the next read gets it)
                        requeue(conn, m);
                        return (e, 0);
                    }
                    o += k;
                }
                return (n, 0);
            }
            if cx.nonblock() {
                return (EAGAIN, 0);
            }
            c.readers.push_back(Reader { id: cx.id, parts });
            (0, LX_REPLY_PENDING)
        }
        1 | 20 => {
            let parts = match parts(cx) {
                Ok(p) => p,
                Err(e) => return (e, 0),
            };
            let Some(total) = iov_total(&parts, MSG_MAX as u64) else { return (EINVAL, 0) };
            let mut data = Vec::with_capacity(total as usize);
            for (addr, len) in parts {
                match cx.copy_in_any(addr, len as usize) {
                    Ok(b) => data.extend_from_slice(&b),
                    Err(e) => return (e, 0),
                }
            }
            let mut st = ST.lock();
            let Some(&conn) = st.devs.get(&slot) else { return (EBADF, 0) };
            let Some(c) = st.conns.get_mut(&conn) else { return (ENODEV, 0) };
            (write_reply(c, &data, fin), 0)
        }
        // FUSE_DEV_IOC_CLONE and the rest: not supported (libfuse goes on without)
        16 => (ENOTTY, 0),
        _ => (ENOSYS, 0),
    }
}

/// A reply (or notification) the daemon wrote: its length, or `-errno`.
fn write_reply(c: &mut Conn, data: &[u8], fin: &mut Vec<Finish>) -> i64 {
    let Some((err, unique)) = reply_header(data) else { return EINVAL };
    let len = data.len() as i64;
    let body = &data[OUT_HEADER..];
    if unique == 0 {
        // A notification: FUSE_NOTIFY_INVAL_INODE drops that node's attributes, the others
        // every node's (conservative)
        let node = (err == 2).then(|| u64_at(body, 0));
        match node.map(|n| c.nodes.by_nodeid.get(&n).copied()) {
            Some(Some(l)) => c.nodes.uncache(Some(l)),
            Some(None) => {}
            None => c.nodes.uncache(None),
        }
        return len;
    }
    if c.aborted {
        return ENODEV;
    }
    match c.waits.remove(&unique) {
        None => ENOENT,
        Some(Wait::Discard) => len,
        Some(Wait::Init) => {
            match init_reply(err, body) {
                Some(mw) => {
                    c.max_write = mw;
                    c.initialized = true;
                    save_conn(c);
                    // wave11 GF: the walks that waited for INIT run again
                    for call in core::mem::take(&mut c.init_waits) {
                        fin.push(Finish { id: call.id, parts: Vec::new(), out: Vec::new(), r: 0, rerun: Some(Box::new(call)), requeue: None, then: None });
                    }
                    for op in core::mem::take(&mut c.before_init) {
                        let step = begin(c, op);
                        if let Some((id, r, out, to)) = drive(c, step, fin) {
                            let f = fin_of(c, id, r, out, to);
                            fin.push(f);
                        }
                    }
                }
                None => abort(c, fin),
            }
            len
        }
        Some(Wait::Rerun(rr)) => {
            took_rerun(c, &rr, err, body);
            fin.push(Finish { id: rr.call.id, parts: Vec::new(), out: Vec::new(), r: 0, rerun: Some(Box::new(rr.call)), requeue: None, then: None });
            len
        }
        Some(Wait::Op(op)) => {
            let step = on_reply(c, op, err, body.to_vec());
            if let Some((id, r, out, to)) = drive(c, step, fin) {
                let out = if r < 0 { Vec::new() } else { out };
                let f = fin_of(c, id, r, out, to);
                fin.push(f);
            }
            len
        }
    }
}

// ----------------------------------------------------------------------
// Notes
// ----------------------------------------------------------------------

/// `LX_NOTE_CLOSE` of daemon descriptor `slot`: with its connection's last, the connection
/// ends.
pub fn on_close(slot: u32) {
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        let Some(conn) = st.devs.remove(&slot) else { return };
        let gone = match st.conns.get_mut(&conn) {
            Some(c) => {
                c.devs.retain(|&s| s != slot);
                if c.devs.is_empty() {
                    abort(c, &mut fin);
                    true
                } else {
                    false
                }
            }
            None => false,
        };
        if gone {
            st.conns.remove(&conn);
            clear_conn(conn);
        }
    }
    objs::set(slot, 0, 0);
    objs::free(slot);
    finish_all(fin);
}

/// `LX_NOTE_INTERRUPT` of request `id`: a waiting read ends (`ERESTARTSYS`); a request not
/// yet read is taken back (`EINTR`); one the daemon has gets an INTERRUPT.
pub fn on_interrupt(id: u64) {
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        for c in st.conns.values_mut() {
            if let Some(i) = c.readers.iter().position(|r| r.id == id) {
                c.readers.remove(i);
                fin.push(Finish::err(id, ERESTARTSYS));
                break;
            }
            if let Some(i) = c.before_init.iter().position(|o| o.id == id) {
                c.before_init.remove(i);
                fin.push(Finish::err(id, EINTR));
                break;
            }
            let Some(unique) = c.waits.iter().find(|(_, w)| matches!(w, Wait::Op(o) if o.id == id) || matches!(w, Wait::Rerun(r) if r.call.id == id)).map(|(u, _)| *u) else { continue };
            let before = c.queue.len();
            c.queue.retain(|m| unique_of(m) != unique);
            if c.queue.len() != before {
                c.waits.remove(&unique);
                c.set_ready();
                fin.push(Finish::err(id, EINTR));
            } else {
                let who = Who::default();
                send(c, INTERRUPT, 0, who, &[&unique.to_le_bytes()], Wait::Discard, &mut fin);
            }
            break;
        }
    }
    finish_all(fin);
}

/// Connections and their state, for the log: `(connections, mounted, calls waiting)`.
pub fn counts() -> (usize, usize, usize) {
    let st = ST.lock();
    (st.conns.len(), st.conns.values().filter(|c| c.mounted).count(), st.conns.values().map(|c| c.waits.len() + c.before_init.len()).sum())
}


// ----------------------------------------------------------------------
// The walk into FUSE mounts (program calls served here)
// ----------------------------------------------------------------------

/// What a walk needed from a daemon.
enum MissKind {
    Lookup(Vec<u8>),
    Getattr,
    Readlink,
    /// wave10 GV2: the file system's figures (`statfs` of a path in the mount).
    Statfs,
    /// wave11 GF: the daemon's answer to INIT (the call runs again after it).
    Init,
}

/// A walk's question, until its call waits for the answer (`wait_miss`).
struct Miss {
    conn: u16,
    local: u64,
    kind: MissKind,
}

/// A program's call waiting for a daemon's answer to its walk.
struct Rerun {
    call: LxCall,
    local: u64,
    kind: MissKind,
}

/// How long an answer fetched for a call that runs again is good (ms).
const SHOT_MS: u64 = 100;

/// The tag of a miss error (bits 60..64 = 0b1010; the pseudo redirect has 0b1001).
const MISS_TAG: u64 = 0xA << 60;
static MISSES: YLock<(u64, BTreeMap<u64, Miss>)> = YLock::new((0, BTreeMap::new()));
/// Calls run again after a daemon's answer, since start.
pub static RERUNS: AtomicU64 = AtomicU64::new(0);

/// Whether `e` is a walk's question to a daemon ([`wait_miss`] makes the call wait).
pub fn is_miss(e: i64) -> bool {
    (e as u64) >> 60 == MISS_TAG >> 60 && e != i64::MIN
}

fn miss(conn: u16, local: u64, kind: MissKind) -> i64 {
    let mut m = MISSES.lock();
    if m.1.len() >= 1024 {
        m.1.clear();
    }
    m.0 = (m.0 + 1) & 0xFFFF_FFFF;
    let k = m.0;
    m.1.insert(k, Miss { conn, local, kind });
    (MISS_TAG | k) as i64
}

/// The calls whose walk may wait for a FUSE daemon (and run again from the reply): the
/// stat family, access, readlink, and opens (the creating and truncating ones went to the
/// kernel before their walk). Nothing in them changes anything before the walk ends.
pub fn rerunnable(nr: u64) -> bool {
    // (wave10 GV2: and statfs, which asks the daemon for its figures)
    // (wave11 GF: and the changes, which are this engine's operations after their walk and
    // checks (`start`); fstatfs; creat; chdir/fchdir)
    matches!(nr, 4 | 6 | 262 | 332 | 21 | 269 | 439 | 89 | 267 | 2 | 257 | 137)
        || matches!(nr, 138 | 85 | 80 | 81 | 90 | 268 | 452 | 91 | 92 | 94 | 260 | 93 | 76 | 77 | 280 | 132 | 235 | 261 | 83 | 258 | 133 | 259 | 88 | 266 | 87 | 84 | 263 | 82 | 264 | 316 | 86 | 265 | 188..=199)
        // (and the mount calls: bind mounts of FUSE directories, flatpak's documents)
        || matches!(nr, 155 | 161 | 165 | 166)
}

/// For the pool's back end: a FUSE node is never its (the kernel answers).
pub fn not_fuse(n: Node) -> Result<(), i64> {
    if split(n.ino).is_some() { Err(crate::calls::KERNEL) } else { Ok(()) }
}

/// Hydra's attributes of FUSE inode `ino` from a `fuse_attr` (`generation` carries the
/// daemon's inode number, for `stat`).
fn attr_from(ino: u64, a: &[u8]) -> Attr {
    Attr {
        ino,
        size: u64_at(a, 8),
        blocks: u64_at(a, 16),
        atime: (u64_at(a, 24) as i64, u32_at(a, 48)),
        mtime: (u64_at(a, 32) as i64, u32_at(a, 52)),
        ctime: (u64_at(a, 40) as i64, u32_at(a, 56)),
        mode: u32_at(a, 60),
        nlink: u32_at(a, 64),
        uid: u32_at(a, 68),
        gid: u32_at(a, 72),
        rdev: u32_at(a, 76) as u64,
        generation: u64_at(a, 0),
        ..Attr::default()
    }
}

/// `stat`/`statx` bytes `b` of `attr`: a FUSE file shows its connection's device and the
/// daemon's inode number, as the kernel's client does.
pub fn fix_stat(attr: &Attr, b: &mut [u8], statx: bool) {
    let Some((conn, _)) = split(attr.ino) else { return };
    let minor = 60 + conn as u64;
    let dev = (minor & 0xFF) | ((minor & !0xFF) << 12);
    if statx {
        b[32..40].copy_from_slice(&attr.generation.to_le_bytes());
        b[136..140].copy_from_slice(&0u32.to_le_bytes());
        b[140..144].copy_from_slice(&(minor as u32).to_le_bytes());
    } else {
        b[0..8].copy_from_slice(&dev.to_le_bytes());
        b[8..16].copy_from_slice(&attr.generation.to_le_bytes());
    }
}

/// The connection of FUSE node `n` for a walk by `euid`.
fn walk_conn(st: &mut State, conn: u16, euid: u64) -> Result<&mut Conn, i64> {
    let c = st.conns.get_mut(&conn).ok_or(ENOTCONN)?;
    if c.aborted {
        return Err(ENOTCONN);
    }
    // (wave11 GF: before the daemon answered INIT the call waits for it: `wait_miss`)
    if !c.initialized {
        return Err(miss(conn, 0, MissKind::Init));
    }
    // (review 8: all the caller's ids the mount owner's, as Linux's
    // `fuse_allow_current_process`: `caller_ids`)
    let (uid, gid, other) = c.owner;
    if !other && euid != (uid as u64 | (gid as u64) << 32) {
        return Err(EACCES);
    }
    Ok(c)
}

/// The caller as a FUSE mount without `allow_other` lets it in (review 8): `uid | gid << 32`
/// when its real, effective and saved user ids are one and its group ids are one; else a
/// value no owner has.
pub fn caller_ids(c: &LxCall) -> u64 {
    if c.uid == c.euid && c.euid == c.suid && c.gid == c.egid && c.egid == c.sgid {
        c.euid as u64 | (c.egid as u64) << 32
    } else {
        u64::MAX
    }
}

/// `name` in FUSE directory `dir`, as the walk asks: known, or a miss.
pub fn be_lookup(dir: Node, name: &[u8], euid: u64) -> Result<Node, i64> {
    let (conn, local) = split(dir.ino).ok_or(EINVAL)?;
    let mut st = ST.lock();
    let c = walk_conn(&mut st, conn, euid)?;
    let node = |l: u64| Node::new(dir.mnt, ino(conn, l));
    if name.is_empty() || name == b"." {
        return Ok(dir);
    }
    if name == b".." {
        return Ok(node(c.nodes.name_of(local).map_or(local, |p| p.0)));
    }
    let key = (local, name.to_vec());
    let now = hydra_rt::svcrt::now_ms();
    if let Some((r, until)) = c.shots.get(&key) {
        if now < *until {
            return r.clone().map(node);
        }
    }
    if let Some(&(l, until)) = c.names.get(&key) {
        if now < until {
            return Ok(node(l));
        }
    }
    Err(miss(conn, local, MissKind::Lookup(name.to_vec())))
}

/// The attributes of FUSE node `n`, as the walk asks: known, or a miss.
pub fn be_getattr(n: Node, euid: u64) -> Result<Attr, i64> {
    let (conn, local) = split(n.ino).ok_or(EINVAL)?;
    let mut st = ST.lock();
    let c = walk_conn(&mut st, conn, euid)?;
    if c.nodes.nodeid(local).is_none() {
        return Err(ESTALE);
    }
    let now = hydra_rt::svcrt::now_ms();
    if let Some((r, until)) = c.attr_shots.get(&local) {
        if now < *until {
            return r.map(|a| attr_from(n.ino, &a));
        }
    }
    if let Some(a) = c.nodes.cached(local, now) {
        return Ok(attr_from(n.ino, &a));
    }
    Err(miss(conn, local, MissKind::Getattr))
}

/// The target of FUSE link `n`, as the walk asks: fetched for this call, or a miss.
pub fn be_readlink(n: Node, euid: u64) -> Result<Vec<u8>, i64> {
    let (conn, local) = split(n.ino).ok_or(EINVAL)?;
    let mut st = ST.lock();
    let c = walk_conn(&mut st, conn, euid)?;
    if let Some((r, until)) = c.link_shots.get(&local) {
        if hydra_rt::svcrt::now_ms() < *until {
            return r.clone();
        }
    }
    Err(miss(conn, local, MissKind::Readlink))
}

// wave10 GV2 begin: statfs of a FUSE file system
/// The figures of the file system FUSE node `n` is in, as `statfs` asks: the daemon's
/// `fuse_kstatfs` fetched for this call, or a miss.
pub fn be_statfs(n: Node, euid: u64) -> Result<Vec<u8>, i64> {
    let (conn, local) = split(n.ino).ok_or(EINVAL)?;
    let mut st = ST.lock();
    let c = walk_conn(&mut st, conn, euid)?;
    if let Some((r, until)) = &c.statfs_shot {
        if hydra_rt::svcrt::now_ms() < *until {
            return r.clone();
        }
    }
    Err(miss(conn, local, MissKind::Statfs))
}

/// `struct statfs` of FUSE inode `ino` from the daemon's `fuse_kstatfs` `r` (empty: a
/// daemon without STATFS), as the kernel's client made it (`fuse::statfs_of`).
pub fn statfs_bytes(ino: u64, r: &[u8]) -> [u8; 120] {
    let bsize = match u32_at(r, 40) {
        0 => 512,
        b => b,
    };
    let namelen = match u32_at(r, 44) {
        0 => 255,
        n => n,
    };
    let frsize = match u32_at(r, 48) {
        0 => bsize,
        f => f,
    };
    let vals: [u64; 7] = [0x6573_5546, bsize as u64, u64_at(r, 0), u64_at(r, 8), u64_at(r, 16), u64_at(r, 24), u64_at(r, 32)];
    let mut b = [0u8; 120];
    for (i, v) in vals.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    let minor = 60 + split(ino).map_or(0, |s| s.0 as u64);
    let dev = (minor & 0xFF) | ((minor & !0xFF) << 12);
    b[56..60].copy_from_slice(&(dev as u32).to_le_bytes());
    b[64..72].copy_from_slice(&(namelen as u64).to_le_bytes());
    b[72..80].copy_from_slice(&(frsize as u64).to_le_bytes());
    b
}
// wave10 GV2 end

/// Call `call`'s walk asked `e` of a daemon: the question goes to the daemon and the call
/// waits (`true`), or it cannot (`false`: the kernel answers the call).
pub fn wait_miss(e: i64, call: &LxCall) -> bool {
    let Some(m) = MISSES.lock().1.remove(&(e as u64 & 0xFFFF_FFFF)) else { return false };
    if !rerunnable(call.nr) {
        return false;
    }
    let who = Who { uid: call.euid, gid: call.egid, pid: call.tgid as u32 };
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        let Some(c) = st.conns.get_mut(&m.conn) else { return false };
        // wave11 GF: a walk that reached the mount before INIT waits for it
        if let (MissKind::Init, false) = (&m.kind, c.aborted) {
            if c.initialized {
                fin.push(Finish { id: call.id, parts: Vec::new(), out: Vec::new(), r: 0, rerun: Some(Box::new(*call)), requeue: None, then: None });
            } else {
                c.init_waits.push(*call);
            }
            WAITED.fetch_add(1, Ordering::Relaxed);
            drop(st);
            finish_all(fin);
            return true;
        }
        if c.aborted || !c.initialized {
            return false;
        }
        let Some(nodeid) = c.nodes.nodeid(m.local) else { return false };
        let (opcode, args) = match &m.kind {
            MissKind::Lookup(name) => (LOOKUP, cstr(name)),
            MissKind::Getattr => (GETATTR, alloc::vec![0u8; 16]),
            MissKind::Readlink => (READLINK, Vec::new()),
            MissKind::Statfs => (STATFS, Vec::new()), // wave10 GV2
            MissKind::Init => return false, // (wave11 GF: above)
        };
        WAITED.fetch_add(1, Ordering::Relaxed);
        send(c, opcode, nodeid, who, &[&args], Wait::Rerun(Box::new(Rerun { call: *call, local: m.local, kind: m.kind })), &mut fin);
    }
    finish_all(fin);
    true
}

/// Keeps the daemon's answer to a walk's question for the call's next run.
fn took_rerun(c: &mut Conn, rr: &Rerun, err: i32, body: &[u8]) {
    let n = RERUNS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || (n >= 64 && n.is_power_of_two()) {
        hydra_rt::println!("[vfs-server] FUSE: {} calls ran again after a daemon's answer ({} operations for the kernel)", n, OPS.load(Ordering::Relaxed));
    }
    let now = hydra_rt::svcrt::now_ms();
    if c.shots.len() + c.attr_shots.len() + c.link_shots.len() >= 512 {
        c.shots.clear();
        c.attr_shots.clear();
        c.link_shots.clear();
    }
    let err = err as i64;
    match &rr.kind {
        MissKind::Lookup(name) => {
            let r = if err != 0 {
                Err(err)
            } else {
                match entry(body) {
                    Some((nodeid, entry_ms, attr_ms, a)) => {
                        let l = c.nodes.intern(nodeid, rr.local, name);
                        c.nodes.cache(l, a, attr_ms, now);
                        let mut k = [0u8; ATTR];
                        k.copy_from_slice(a);
                        c.attr_shots.insert(l, (Ok(k), now + SHOT_MS));
                        if entry_ms > 0 {
                            c.names.insert((rr.local, name.clone()), (l, now + entry_ms));
                        }
                        Ok(l)
                    }
                    None => Err(ENOENT),
                }
            };
            c.shots.insert((rr.local, name.clone()), (r, now + SHOT_MS));
        }
        MissKind::Getattr => {
            let r = if err != 0 {
                Err(err)
            } else {
                match attr_out(body) {
                    Some((ms, a)) => {
                        c.nodes.cache(rr.local, a, ms, now);
                        let mut k = [0u8; ATTR];
                        k.copy_from_slice(a);
                        Ok(k)
                    }
                    None => Err(EIO),
                }
            };
            c.attr_shots.insert(rr.local, (r, now + SHOT_MS));
        }
        MissKind::Readlink => {
            c.link_shots.insert(rr.local, (if err != 0 { Err(err) } else { Ok(body.to_vec()) }, now + SHOT_MS));
        }
        // wave10 GV2: (a daemon without STATFS: zero figures, as the kernel's client)
        MissKind::Statfs => {
            let r = if err == ENOSYS { Ok(Vec::new()) } else if err != 0 { Err(err) } else { Ok(body[..body.len().min(80)].to_vec()) };
            c.statfs_shot = Some((r, now + SHOT_MS));
        }
        MissKind::Init => {}
    }
}

/// An open of FUSE file `ino` that vfs-server installs: counted here (`true`), as the
/// kernel's `FUSE_OP_OPEN_REF` does for its own.
pub fn local_open_ref(ino: u64) -> bool {
    let Some((conn, local)) = split(ino) else { return false };
    let mut st = ST.lock();
    let Some(c) = st.conns.get_mut(&conn) else { return false };
    c.handles.entry(local).or_default().refs += 1;
    true
}

/// [`local_open_ref`] undone (the install failed).
pub fn local_release(ino: u64) {
    let Some((conn, local)) = split(ino) else { return };
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        let Some(c) = st.conns.get_mut(&conn) else { return };
        release_node(c, local, Who::default(), &mut fin);
    }
    finish_all(fin);
}

/// One open of local node `l` closed: with the last, the daemon's handles are released.
fn release_node(c: &mut Conn, l: u64, who: Who, fin: &mut Vec<Finish>) {
    let gone = match c.handles.get_mut(&l) {
        Some(h) => {
            h.refs = h.refs.saturating_sub(1);
            if h.refs == 0 { c.handles.remove(&l) } else { None }
        }
        None => None,
    };
    if let (Some(h), Some(n)) = (gone, c.nodes.nodeid(l)) {
        if !c.aborted && c.initialized {
            for (op, args) in h.releases() {
                send(c, op, n, who, &[&args], Wait::Discard, fin);
            }
        }
    }
}

// ----------------------------------------------------------------------
// Restart: the connections survive a crash of vfs-server
// ----------------------------------------------------------------------

/// The instance number (1 = the first since boot): the base of its local node numbers.
static EPOCH: AtomicU64 = AtomicU64::new(0);
/// The kept-state area (`LX_SVC_KEPT`): record 0 holds the instance number, records
/// 1.. a [`ConnRec`] each.
static KEPT: YLock<Option<hydra_rt::kept::Kept>> = YLock::new(None);
const KEPT_LAYOUT: u32 = 0x6B02_0001;
const KEPT_RECS: usize = 65;

/// Writes connection `c`'s record (a free one, or its own).
fn save_conn(c: &Conn) {
    let Some(&slot) = c.devs.first() else { return };
    let r = ConnRec { conn: c.id, slot, mounted: c.mounted, initialized: c.initialized, owner: c.owner, max_write: c.max_write, next_unique: c.next_unique };
    let mut g = KEPT.lock();
    let Some(k) = g.as_mut() else { return };
    let mut free = None;
    for i in 1..KEPT_RECS {
        match k.get(i).and_then(ConnRec::decode) {
            Some(o) if o.conn == c.id => {
                k.put(i, &r.encode());
                return;
            }
            None if free.is_none() => free = Some(i),
            _ => {}
        }
    }
    // (more live connections than records: the newest are not kept)
    if let Some(i) = free {
        k.put(i, &r.encode());
    }
}

/// Forgets connection `conn`'s record.
fn clear_conn(conn: u16) {
    let mut g = KEPT.lock();
    let Some(k) = g.as_mut() else { return };
    for i in 1..KEPT_RECS {
        if k.get(i).and_then(ConnRec::decode).is_some_and(|o| o.conn == conn) {
            k.clear(i);
        }
    }
}

/// Before going online: the kept connection records of the previous instance and its
/// `/dev/fuse` objects are taken back (a Transparent restart), so the daemons' descriptors
/// and the mounts go on; the node tables are not kept (files the old instance had looked up
/// answer `ESTALE`). Returns `(connections taken back, objects dropped)`.
pub fn restart_init() -> (usize, usize) {
    use hydra_rt::kept::Kept;
    let size = Kept::size_for(KEPT_RECS, CONN_REC);
    let p = match sys::lx_svc_kept(size) {
        Ok(p) => p,
        Err(e) => {
            hydra_rt::println!("[vfs-server] FUSE: no kept state ({}): mounts end with a restart", e);
            EPOCH.store(1, Ordering::Relaxed);
            return (0, 0);
        }
    };
    // SAFETY: the kernel mapped `size` bytes at `p` for this process alone
    let (mut k, _) = unsafe { Kept::open(p, size, KEPT_LAYOUT, CONN_REC) };
    let epoch = (k.get(0).map_or(0, |b| u64_at(b, 0)) + 1) & 0xFF;
    let epoch = epoch.max(1);
    k.put(0, &epoch.to_le_bytes());
    EPOCH.store(epoch, Ordering::Relaxed);
    let recs: Vec<ConnRec> = (1..KEPT_RECS).filter_map(|i| k.get(i).and_then(ConnRec::decode)).collect();
    let mut found: Vec<LxSvcObj> = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut start = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, start) {
        if n == 0 {
            break;
        }
        found.extend_from_slice(&buf[..n]);
        start = buf[n - 1].slot + 1;
    }
    let mut dropped = 0;
    let mut keep: Vec<ConnRec> = Vec::new();
    for o in &found {
        // (merge of wave 9 6b-1: only /dev/fuse objects are FUSE's to keep or drop; the
        // notify objects, kinds 73/74, are taken back by `notify`)
        if o.kind != LX_OBJ_KIND_FUSE {
            continue;
        }
        match recs.iter().find(|r| r.slot == o.slot) {
            Some(r) => keep.push(*r),
            None => {
                let _ = sys::lx_svc_dead(o.slot);
                dropped += 1;
            }
        }
    }
    let adopted = !found.is_empty() && sys::lx_svc_adopt().is_ok();
    for i in 1..KEPT_RECS {
        k.clear(i);
    }
    *KEPT.lock() = Some(k);
    if !adopted {
        return (0, dropped);
    }
    let mut st = ST.lock();
    let mut n = 0;
    for r in keep {
        if !objs::reserve(r.slot) {
            let _ = sys::lx_svc_dead(r.slot);
            continue;
        }
        let mut c = Conn::new(r.conn);
        c.devs.push(r.slot);
        c.mounted = r.mounted;
        c.initialized = r.initialized;
        c.owner = r.owner;
        c.max_write = r.max_write;
        // (replies to the old instance's requests find nothing)
        c.next_unique = (r.next_unique + (1 << 33)) & !1;
        c.set_ready();
        save_conn(&c);
        st.devs.insert(r.slot, r.conn);
        st.conns.insert(r.conn, c);
        st.next = st.next.max(r.conn & 0x3FFF);
        n += 1;
    }
    drop(st);
    objs::flush();
    (n, dropped)
}

// ----------------------------------------------------------------------
// wave11 GF begin: changes inside FUSE mounts decided here
// ----------------------------------------------------------------------
//
// Until wave 11 every change inside a FUSE mount (create, mkdir, mknod, symlink, link,
// unlink, rmdir, rename, setattr, xattrs) went back to the kernel, which walked again and
// sent the operation here as `LX_KCALL_FUSE`. Now the program's call walks here (its walk
// may wait for the daemon and run again, as the stat family's: nothing changes before the
// walk and the checks end), and the change is one operation of this engine whose reply
// answers the program's call directly ([`Then`]): no worker waits for the daemon.

/// What a change asks of the daemon (on the node [`start`] names).
pub enum Req {
    /// A regular file `name` (CREATE, MKNOD if the daemon has none), `perm` after the umask.
    Create { name: Vec<u8>, perm: u32 },
    /// MKNOD of `name` with `mode` (type and permissions) and device `rdev`.
    Mknod { name: Vec<u8>, mode: u32, rdev: u64 },
    /// MKDIR of `name` with `perm`.
    Mkdir { name: Vec<u8>, perm: u32 },
    /// SYMLINK `name` -> `to`.
    Symlink { name: Vec<u8>, to: Vec<u8> },
    /// LINK of FUSE inode `file` as `name` (same connection).
    Link { file: u64, name: Vec<u8> },
    /// UNLINK of `name`.
    Unlink { name: Vec<u8> },
    /// RMDIR of `name`.
    Rmdir { name: Vec<u8> },
    /// RENAME of `sname` to `dname` in FUSE directory `ddir` (same connection).
    Rename { sname: Vec<u8>, ddir: u64, dname: Vec<u8> },
    /// SETATTR.
    Setattr(crate::fs::fsproto::SetAttr),
    /// GETXATTR.
    Getxattr { name: Vec<u8> },
    /// LISTXATTR.
    Listxattr,
    /// SETXATTR.
    Setxattr { name: Vec<u8>, value: Vec<u8>, flags: u32 },
    /// REMOVEXATTR.
    Removexattr { name: Vec<u8> },
}

/// How a program's call is answered from its operation's reply.
#[derive(Clone)]
pub enum How {
    /// 0.
    Zero,
    /// This value (an open's descriptor installed before its truncation).
    Value(i64),
    /// A creating open: the new file's handle (`desc` with the new inode); `dir`/`name` to
    /// remove it again if the handle cannot be installed; `again`: the call runs again if the
    /// daemon says the name exists (another caller made it first; not `O_EXCL`).
    Fd { desc: LxFhDesc, dir: u64, name: Vec<u8>, again: Option<Box<LxCall>> },
    /// review 5: an existing file's handle `desc`, installed only once the operation (an
    /// `O_TRUNC` open's truncation) succeeded: a failed truncation leaves no descriptor.
    Install { desc: LxFhDesc },
    /// The reply's bytes to the caller's buffer `ptr` of `size` bytes, as the xattr calls
    /// answer (`size` 0: the length; too small: `ERANGE`); `list`: names shown to a caller
    /// with (`Some(true)`) or without `CAP_SYS_ADMIN`.
    Bytes { ptr: u64, size: u64, list: Option<bool> },
}

/// [`How`], and what the kernel's caches are told after a success: `(ino, LX_FHC_*, size)`.
#[derive(Clone)]
pub struct Then {
    /// The answer.
    pub how: How,
    /// The kernel's caches.
    pub tell: Option<(u64, u64, u64)>,
}

/// The error a call answers when its change went to the daemon: the call waits
/// (`calls::answer` makes it PENDING; the reply completes it).
pub const STARTED: i64 = (0xBu64 << 60) as i64;
/// Changes started here, since start.
pub static CHANGES: AtomicU64 = AtomicU64::new(0);

/// `struct fuse_setattr_in` for `set` (as the kernel's `fuse::setattr_in`).
pub fn setattr_in(set: &crate::fs::fsproto::SetAttr) -> Vec<u8> {
    wire::setattr_in(set.mode, set.uid, set.gid, set.size, set.atime, set.mtime)
}

/// The engine's operation for `req` on a node of connection `c` (number `conn`; `Err`: the
/// call's answer: `EXDEV` for a second node on another connection).
fn kind_of(c: &Conn, conn: u16, req: Req) -> Result<Kind, i64> {
    let other = |ino: u64| -> Result<u64, i64> {
        match split(ino) {
            Some((k, l)) if k == conn => c.nodes.nodeid(l).ok_or(ESTALE),
            _ => Err(EXDEV),
        }
    };
    Ok(match req {
        Req::Create { name, perm } => Kind::Create { name, perm, mknod: false },
        Req::Mknod { name, mode, rdev } => {
            let mut v = le(&[mode as u64, rdev & 0xFFFF_FFFF, 0, 0], &[4, 4, 4, 4]);
            v.extend_from_slice(&cstr(&name));
            Kind::Make { name, opcode: MKNOD, args: v }
        }
        Req::Mkdir { name, perm } => {
            let mut v = le(&[(perm & 0o7777) as u64, 0], &[4, 4]);
            v.extend_from_slice(&cstr(&name));
            Kind::Make { name, opcode: MKDIR, args: v }
        }
        Req::Symlink { name, to } => {
            let mut v = cstr(&name);
            v.extend_from_slice(&cstr(&to));
            Kind::Make { name, opcode: SYMLINK, args: v }
        }
        Req::Link { file, name } => {
            let mut v = other(file)?.to_le_bytes().to_vec();
            v.extend_from_slice(&cstr(&name));
            Kind::Make { name, opcode: LINK, args: v }
        }
        Req::Unlink { name } => Kind::Plain { opcode: UNLINK, args: cstr(&name), xattr: false },
        Req::Rmdir { name } => Kind::Plain { opcode: RMDIR, args: cstr(&name), xattr: false },
        Req::Rename { sname, ddir, dname } => {
            let mut v = other(ddir)?.to_le_bytes().to_vec();
            v.extend_from_slice(&cstr(&sname));
            v.extend_from_slice(&cstr(&dname));
            Kind::Plain { opcode: RENAME, args: v, xattr: false }
        }
        Req::Setattr(set) => Kind::Setattr { set_in: setattr_in(&set) },
        Req::Getxattr { name } => {
            let mut v = le(&[65536, 0], &[4, 4]);
            v.extend_from_slice(&cstr(&name));
            Kind::Data { opcode: GETXATTR, args: v }
        }
        Req::Listxattr => Kind::Data { opcode: LISTXATTR, args: le(&[65536, 0], &[4, 4]) },
        Req::Setxattr { name, value, flags } => {
            let mut v = le(&[value.len() as u64, flags as u64], &[4, 4]);
            v.extend_from_slice(&cstr(&name));
            v.extend_from_slice(&value);
            Kind::Plain { opcode: SETXATTR, args: v, xattr: true }
        }
        Req::Removexattr { name } => Kind::Plain { opcode: REMOVEXATTR, args: cstr(&name), xattr: true },
    })
}

/// Starts change `req` of program call `call` on FUSE node `node`: `Err(STARTED)` (the call
/// waits; the daemon's reply answers it as `then` says), or the call's answer now (an
/// error: no connection, not the mount's owner, a stale node...).
pub fn start(call: &LxCall, node: u64, req: Req, then: Then) -> Result<i64, i64> {
    let (conn, local) = split(node).ok_or(crate::calls::KERNEL)?;
    // (review 3: a change the daemon may have made is not resent after a crash of this
    // service: its caller gets EIO; reads and plain attribute sets may be resent)
    let resendable = match &req {
        Req::Getxattr { .. } | Req::Listxattr => true,
        Req::Setattr(s) => s.size.is_none(),
        _ => false,
    };
    if !resendable {
        let _ = sys::lx_obj(LX_OBJ_PARTIAL, call.id, EIO as u64, 0);
    }
    let who = Who { uid: call.euid, gid: call.egid, pid: call.tgid as u32 };
    let mut fin = Vec::new();
    let now = (|| -> Result<Option<(i64, Vec<u8>, Option<Then>)>, i64> {
        let mut st = ST.lock();
        let c = st.conns.get_mut(&conn).ok_or(ENOTCONN)?;
        if c.aborted {
            return Err(ENOTCONN);
        }
        let (uid, gid, other) = c.owner;
        if !other && caller_ids(call) != (uid as u64 | (gid as u64) << 32) {
            return Err(EACCES);
        }
        c.nodes.nodeid(local).ok_or(ESTALE)?;
        let kind = kind_of(c, conn, req)?;
        OPS.fetch_add(1, Ordering::Relaxed);
        CHANGES.fetch_add(1, Ordering::Relaxed);
        let op = Op { id: call.id, who, local, kind, to: Some(then) };
        if !c.initialized {
            c.before_init.push(op);
            return Ok(None);
        }
        let step = begin(c, op);
        Ok(drive(c, step, &mut fin).map(|(_, r, out, to)| {
            // (answered without the daemon: counted as `fin_of` would)
            if let (Some(t), true) = (&to, r >= 0) {
                count_open(c, &t.how, &out);
            }
            (r, out, to)
        }))
    })();
    finish_all(fin);
    match now? {
        None => {
            WAITED.fetch_add(1, Ordering::Relaxed);
            Err(STARTED)
        }
        Some((r, out, Some(t))) => match then_result(call.id, r, &out, t) {
            Some(r) if r < 0 => Err(r),
            Some(r) => Ok(r),
            // (the call runs again: the name exists after all)
            None => Err(STARTED),
        },
        Some((r, _, None)) => Err(r.min(0)),
    }
}

/// The [`Finish`] of operation `id`'s answer `r`, `out`: to the kernel's buffer, or (`to`)
/// the program's call (a created file's open is counted here, as `local_open_ref`).
fn fin_of(c: &mut Conn, id: u64, r: i64, out: Vec<u8>, to: Option<Then>) -> Finish {
    match to {
        None => Finish::kout(id, r, out),
        Some(t) => {
            if r >= 0 {
                count_open(c, &t.how, &out);
            }
            Finish { id, parts: Vec::new(), out, r, rerun: None, requeue: None, then: Some(Box::new(t)) }
        }
    }
}

/// The open a handle answer makes, counted (as `local_open_ref`): a created file's (`out`
/// holds its inode) or an existing one's.
fn count_open(c: &mut Conn, how: &How, out: &[u8]) {
    let ino = match how {
        How::Fd { .. } => u64_at(out, 0),
        How::Install { desc } => desc.ino,
        _ => return,
    };
    if let Some((_, l)) = split(ino) {
        c.handles.entry(l).or_default().refs += 1;
    }
}

/// The program's answer to change `id` from the reply (`r`, `out`), with what follows it
/// (the handle, the caches); `None`: the call was run again instead.
fn then_result(id: u64, r: i64, out: &[u8], t: Then) -> Option<i64> {
    if r < 0 {
        if let (How::Fd { again: Some(call), .. }, -17) = (&t.how, r) {
            // (review 12: a daemon that says EEXIST to CREATE and ENOENT to LOOKUP: EIO after
            // a few runs)
            let n = {
                let mut a = AGAIN.lock();
                if a.len() > 256 {
                    a.clear();
                }
                let n = a.entry(call.id).or_insert(0);
                *n += 1;
                *n
            };
            if n <= 4 {
                crate::rerun(call);
                return None;
            }
            AGAIN.lock().remove(&call.id);
            return Some(EIO);
        }
        return Some(r);
    }
    if let Some((ino, what, size)) = t.tell {
        crate::calls::tell_kernel(ino, what, size);
    }
    Some(match t.how {
        How::Zero => 0,
        How::Value(v) => v,
        How::Fd { mut desc, dir, name, again } => {
            if let Some(c) = again {
                AGAIN.lock().remove(&c.id);
            }
            let ino = u64_at(out, 0);
            desc.ino = ino;
            match sys::lx_obj(LX_FH_INSTALL, id, &desc as *const LxFhDesc as u64, 0) {
                Ok(fd) => fd as i64,
                Err(e) => {
                    local_release(ino);
                    undo_create(dir, &name, Who::default());
                    e
                }
            }
        }
        How::Install { desc } => match sys::lx_obj(LX_FH_INSTALL, id, &desc as *const LxFhDesc as u64, 0) {
            Ok(fd) => fd as i64,
            Err(e) => {
                local_release(desc.ino);
                e
            }
        },
        How::Bytes { ptr, size, list } => {
            let shown;
            let data = match list {
                Some(admin) => {
                    shown = crate::calls::rules::xattr_list_shown(out, admin);
                    &shown[..]
                }
                None => out,
            };
            match crate::calls::rules::xattr_fits(data.len(), size) {
                Ok(n) => {
                    if size != 0 && n > 0 {
                        if let Err(e) = sys::lx_write(id, ptr, data) {
                            return Some(e);
                        }
                    }
                    n as i64
                }
                Err(e) => e,
            }
        }
    })
}

/// Whether FUSE directory `dir` is `anc` or lies below it, as the node table knows the
/// names (a rename of directory `anc` into `dir`: `EINVAL`).
pub fn descends(dir: u64, anc: u64) -> bool {
    let (Some((c1, mut l)), Some((c2, a))) = (split(dir), split(anc)) else { return false };
    if c1 != c2 {
        return false;
    }
    let st = ST.lock();
    let Some(c) = st.conns.get(&c1) else { return false };
    for _ in 0..4096 {
        if l == a {
            return true;
        }
        match c.nodes.name_of(l) {
            Some((p, _)) => l = p,
            None => return false,
        }
    }
    false
}

/// Creating opens run again after the daemon said EEXIST, by call (review 12).
static AGAIN: YLock<BTreeMap<u64, u32>> = YLock::new(BTreeMap::new());

/// Removes `name` from FUSE directory `dir` again (a created file whose handle could not be
/// installed); nothing waits for the reply.
fn undo_create(dir: u64, name: &[u8], who: Who) {
    let Some((conn, local)) = split(dir) else { return };
    let mut fin = Vec::new();
    {
        let mut st = ST.lock();
        let Some(c) = st.conns.get_mut(&conn) else { return };
        let Some(n) = c.nodes.nodeid(local) else { return };
        if !c.aborted && c.initialized {
            c.forget_all();
            send(c, UNLINK, n, who, &[&cstr(name)], Wait::Discard, &mut fin);
        }
    }
    finish_all(fin);
}
// wave11 GF end
