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

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::svcrt::{objs, Answer, Cx};
use hydra_rt::sys;

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
        self.parts.iter().map(|p| p.1).sum()
    }
}

/// What a request's reply goes to.
enum Wait {
    Op(Op),
    Discard,
    Init,
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
            nodes: Nodes::new(),
            handles: BTreeMap::new(),
            before_init: Vec::new(),
        }
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
}

impl Finish {
    fn err(id: u64, r: i64) -> Self {
        Finish { id, parts: Vec::new(), out: Vec::new(), r }
    }

    fn kout(id: u64, r: i64, out: Vec<u8>) -> Self {
        let n = out.len() as u64;
        Finish { id, parts: alloc::vec![(FUSE_KBUF_OUT, n)], out, r }
    }

    fn run(self) {
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
        let _ = sys::lx_complete(self.id, r);
    }
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
}

/// The next step of an operation.
enum Step {
    Send { opcode: u32, nodeid: u64, args: Vec<Vec<u8>>, op: Op },
    Done { id: u64, r: i64, out: Vec<u8> },
}

fn done(op: &Op, r: i64, out: Vec<u8>) -> Step {
    Step::Done { id: op.id, r, out }
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
            c.nodes.uncache(Some(op.local));
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
            c.nodes.uncache(None);
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
                c.nodes.uncache(None);
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
                c.nodes.uncache(Some(op.local));
            }
            return done(&op, err, Vec::new());
        }
        _ => {}
    }
    match &mut op.kind {
        Kind::Lookup { name } => {
            let Some((nodeid, _, attr_ms, a)) = entry(&body) else { return done(&op, ENOENT, Vec::new()) };
            let l = c.nodes.intern(nodeid, op.local, name);
            c.nodes.cache(l, a, attr_ms, now);
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
                c.nodes.uncache(Some(op.local));
                return done(&op, n, Vec::new());
            }
            let Some(nodeid) = c.nodes.nodeid(op.local) else { return done(&op, ESTALE, Vec::new()) };
            let Some(fh) = c.handles.get(&op.local).and_then(|h| h.write) else { return done(&op, EBADF, Vec::new()) };
            write_next(c, op, nodeid, fh)
        }
        Kind::Readdir { .. } | Kind::Data { .. } => {
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
            c.nodes.uncache(None);
            done(&op, 0, ino(c.id, l).to_le_bytes().to_vec())
        }
        Kind::Make { name, .. } => {
            let Some((nodeid, _, attr_ms, a)) = entry(&body) else { return done(&op, ENOENT, Vec::new()) };
            let l = c.nodes.intern(nodeid, op.local, name);
            c.nodes.uncache(None);
            c.nodes.cache(l, a, attr_ms, now);
            done(&op, 0, ino(c.id, l).to_le_bytes().to_vec())
        }
        Kind::Plain { .. } => {
            c.nodes.uncache(None);
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
    c.waits.insert(unique, wait);
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
        fin.push(Finish { id: r.id, parts: r.parts, out: m, r: n });
    }
    c.set_ready();
}

/// Runs `step`: a request is sent (`None`: the call waits), or the answer.
fn drive(c: &mut Conn, step: Step, fin: &mut Vec<Finish>) -> Option<(u64, i64, Vec<u8>)> {
    match step {
        Step::Send { opcode, nodeid, args, op } => {
            let who = op.who;
            let refs: Vec<&[u8]> = args.iter().map(|a| a.as_slice()).collect();
            send(c, opcode, nodeid, who, &refs, Wait::Op(op), fin);
            None
        }
        Step::Done { id, r, out } => Some((id, r, out)),
    }
}

/// Ends connection `c`: every waiting call fails.
fn abort(c: &mut Conn, fin: &mut Vec<Finish>) {
    c.aborted = true;
    for (_, w) in core::mem::take(&mut c.waits) {
        if let Wait::Op(op) = w {
            fin.push(Finish::err(op.id, ENOTCONN));
        }
    }
    for op in core::mem::take(&mut c.before_init) {
        fin.push(Finish::err(op.id, ENOTCONN));
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
        FUSE_OP_MOUNT => {
            let Some(&conn) = st.devs.get(&(a[1] as u32)) else { return (EBADF, 0) };
            let Some(c) = st.conns.get_mut(&conn) else { return (EBADF, 0) };
            if c.mounted || c.aborted {
                return (EINVAL, 0);
            }
            c.owner = (a[2] as u32, (a[2] >> 32) as u32, a[3] != 0);
            c.mounted = true;
            let init = init_args();
            send(c, INIT, 0, who, &[&init], Wait::Init, fin);
            return (conn as i64, 0);
        }
        FUSE_OP_ABORT => {
            if let Some(c) = st.conns.get_mut(&(a[1] as u16)) {
                c.mounted = false;
                abort(c, fin);
            }
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
    let op = Op { id: cx.id, who, local, kind };
    if !c.initialized {
        c.before_init.push(op);
        WAITED.fetch_add(1, Ordering::Relaxed);
        return (0, LX_REPLY_PENDING);
    }
    let step = begin(c, op);
    match drive(c, step, fin) {
        Some((_, r, out)) => answer_now(cx, r, &out),
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
        let id = next_conn(&mut st.next, |c| conns.contains_key(&c));
        let mut c = Conn::new(id);
        c.devs.push(slot);
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
            let room: u64 = parts.iter().map(|p| p.1).sum();
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
            let total: u64 = parts.iter().map(|p| p.1).sum();
            if total as usize > MSG_MAX {
                return (EINVAL, 0);
            }
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
                    for op in core::mem::take(&mut c.before_init) {
                        let step = begin(c, op);
                        if let Some((id, r, out)) = drive(c, step, fin) {
                            fin.push(Finish::kout(id, r, out));
                        }
                    }
                }
                None => abort(c, fin),
            }
            len
        }
        Some(Wait::Op(op)) => {
            let step = on_reply(c, op, err, body.to_vec());
            if let Some((id, r, out)) = drive(c, step, fin) {
                let out = if r < 0 { Vec::new() } else { out };
                fin.push(Finish::kout(id, r, out));
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
            let Some(unique) = c.waits.iter().find(|(_, w)| matches!(w, Wait::Op(o) if o.id == id)).map(|(u, _)| *u) else { continue };
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

