//! Unix sockets (`AF_UNIX`), moved here from the kernel's `src/compat/linux/unix.rs`
//! (wave 5, step 4). D-Bus and Wayland run on them.
//!
//! - **Sockets** are server objects (one slot per open socket; a connection waiting in a
//!   listener's queue has no slot until `accept`). Stream, datagram and seqpacket types;
//!   `socketpair`, `bind`, `listen`, `connect`, `accept`, the send and receive calls,
//!   `shutdown`, `getsockname`/`getpeername`, the socket options the kernel had, `FIONREAD`,
//!   `SIOCOUTQ` and `/proc/net/unix`. As before, unconnected datagram sends and autobind are
//!   not offered.
//! - **Names:** a path name is the socket node in the file system; the kernel makes it
//!   (`bind`) or checks it (`connect`: a socket, writable by the caller) in the caller's
//!   context and gives us its inode (`LxCall::ino`): a socket is found by its node, under
//!   any name the node gets. Abstract names are ours alone.
//! - **Descriptors in messages** (`SCM_RIGHTS`): the kernel keeps them while they are in
//!   flight (`LX_OBJ_TAKE`); a message holds the tokens, the receiver gets them installed
//!   (`LX_OBJ_GIVE`, with `MSG_CMSG_CLOEXEC`), and what is not received (a socket closed with
//!   its queue full, a `read`, a control buffer too small: `MSG_CTRUNC`) is let go
//!   (`LX_OBJ_DROP`). Any descriptor can travel: files, DRM, memfd, pipes, other sockets.
//!   A socket whose own receive queue holds a Unix socket cannot be sent (`ETOOMANYREFS`):
//!   such cycles would keep each other alive forever (the kernel's rule, kept).
//! - **Credentials:** `SO_PEERCRED` (the peer's process and effective IDs at `connect` or
//!   `socketpair`), `SCM_CREDENTIALS` with `SO_PASSCRED` (the sender's, attached to every
//!   message).
//! - **Blocking without tying up a worker:** a receive with nothing to read, a send with no
//!   room, an `accept` with nobody connecting answer "pending"; the call that unblocks them
//!   completes them, working on the waiter's memory and descriptor table by its request.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::fdio::{kbuf, sigpipe, Iov};
use crate::lock::YLock;

const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const EMSGSIZE: i64 = -90;
const EPROTOTYPE: i64 = -91;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;
const EOPNOTSUPP: i64 = -95;
const EADDRINUSE: i64 = -98;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const ETOOMANYREFS: i64 = -109;
const ECONNREFUSED: i64 = -111;
const ENOTSOCK: i64 = -88;
const ERESTARTSYS: i64 = -512;

const AF_UNIX: u16 = 1;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_SEQPACKET: u32 = 5;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x80000;
const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

/// Bytes a direction buffers before writers wait (Linux's default `wmem`).
const BUFFER_LIMIT: usize = 212_992;
/// Most descriptors one message may carry (`SCM_MAX_FD`).
const MAX_FDS: usize = 253;

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const POLLHUP: u32 = 0x10;
const POLLRDHUP: u32 = 0x2000;

/// `struct ucred`.
#[derive(Clone, Copy)]
struct Ucred {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl Ucred {
    fn of(c: &LxCall) -> Self {
        Self { pid: c.tgid as u32, uid: c.euid, gid: c.egid }
    }

    fn bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..12].copy_from_slice(&self.gid.to_le_bytes());
        b
    }
}

/// A socket name: a path (as given, and its node) or an abstract name.
#[derive(Clone)]
enum Addr {
    Path { shown: Vec<u8>, ino: u64 },
    Abstract(Vec<u8>),
}

impl Addr {
    fn key(&self) -> Vec<u8> {
        match self {
            Addr::Path { ino, .. } => {
                let mut k = alloc::vec![1u8];
                k.extend_from_slice(&ino.to_le_bytes());
                k
            }
            Addr::Abstract(name) => {
                let mut k = alloc::vec![0u8];
                k.extend_from_slice(name);
                k
            }
        }
    }

    fn sockaddr(addr: Option<&Addr>) -> Vec<u8> {
        let mut b = AF_UNIX.to_le_bytes().to_vec();
        match addr {
            Some(Addr::Path { shown, .. }) => {
                b.extend_from_slice(shown);
                b.push(0);
            }
            Some(Addr::Abstract(name)) => {
                b.push(0);
                b.extend_from_slice(name);
            }
            None => {}
        }
        b
    }
}

/// One send: its bytes, the descriptors (kernel tokens) and credentials with them.
struct Segment {
    data: Vec<u8>,
    pos: usize,
    fds: Vec<u64>,
    /// The slots of the Unix sockets among `fds` (for the cycle rule).
    unix_in: Vec<u32>,
    cred: Ucred,
}

/// One direction of a connection.
#[derive(Default)]
struct Queue {
    segs: VecDeque<Segment>,
    bytes: usize,
    /// The writing side shut down or closed: readers see end-of-file once drained.
    write_closed: bool,
    /// The reading side closed: writers get `EPIPE`.
    read_closed: bool,
}

/// A connection: side `s` (socket `socks[s]`) reads `q[s]` and writes `q[1 - s]`.
struct Pair {
    q: [Queue; 2],
    socks: [u64; 2],
}

enum State {
    Unconnected,
    Listening { pending: VecDeque<u64>, cred: Ucred },
    Connected { pair: u64, side: usize, peer_cred: Ucred, peer_addr: Option<Addr> },
}

/// What a waiting receiver does with what it gets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecvKind {
    /// `read`/`readv`: descriptors that arrive are closed.
    Read,
    /// `recvfrom(.., src, addrlen)`.
    From(u64),
    /// `recvmsg(msg)`; `mmsg`: one of `recvmmsg`'s (its length goes after it).
    Msg { msg: u64, mmsg: bool },
}

/// A call waiting on a socket (its call is pending; `c` is the call as the kernel gave it).
enum Wait {
    Recv { c: LxCall, iov: Iov, kind: RecvKind, flags: u64 },
    Send { c: LxCall, iov: Iov, total: usize, done: usize, flags: u64, fds: Vec<u64>, unix_in: Vec<u32>, mmsg: Option<u64> },
    Accept { c: LxCall, addr: u64, len: u64, flags: u64 },
}

impl Wait {
    fn call(&self) -> &LxCall {
        match self {
            Wait::Recv { c, .. } | Wait::Send { c, .. } | Wait::Accept { c, .. } => c,
        }
    }
}

struct Sock {
    ty: u32,
    state: State,
    local: Option<Addr>,
    passcred: bool,
    shut_rd: bool,
    /// Its slot (none while it waits in a listener's queue).
    slot: Option<u32>,
    ino: u64,
    waits: VecDeque<Wait>,
}

struct Unix {
    socks: BTreeMap<u64, Sock>,
    by_slot: BTreeMap<u32, u64>,
    pairs: BTreeMap<u64, Pair>,
    names: BTreeMap<Vec<u8>, u64>,
    next: u64,
}

static U: YLock<Unix> = YLock::new(Unix { socks: BTreeMap::new(), by_slot: BTreeMap::new(), pairs: BTreeMap::new(), names: BTreeMap::new(), next: 1 });

/// Work for after the lock: answers, tokens to let go, `SIGPIPE`s.
#[derive(Default)]
struct After {
    done: Vec<(u64, i64)>,
    drop: Vec<u64>,
    pipe: Vec<u64>,
}

impl After {
    fn run(self) {
        if !self.drop.is_empty() {
            drop_tokens(&self.drop);
        }
        for tgid in self.pipe {
            sigpipe(tgid, 0);
        }
        for (id, r) in self.done {
            let _ = sys::lx_complete(id, r);
        }
    }
}

fn drop_tokens(t: &[u64]) {
    for chunk in t.chunks(512) {
        let _ = sys::lx_obj(LX_OBJ_DROP, chunk.as_ptr() as u64, chunk.len() as u64, 0);
    }
}

impl Unix {
    fn new_sock(&mut self, ty: u32) -> u64 {
        let sid = self.next;
        self.next += 1;
        self.socks.insert(sid, Sock { ty, state: State::Unconnected, local: None, passcred: false, shut_rd: false, slot: None, ino: 0x5000_0000 + sid, waits: VecDeque::new() });
        sid
    }

    fn pair_of(&self, sid: u64) -> Option<(u64, usize)> {
        match self.socks.get(&sid)?.state {
            State::Connected { pair, side, .. } => Some((pair, side)),
            _ => None,
        }
    }

    /// The socket's poll bits (as the kernel's `UnixSocket::poll_events`).
    fn events(&self, sid: u64) -> u32 {
        let Some(s) = self.socks.get(&sid) else { return POLLHUP };
        match &s.state {
            State::Listening { pending, .. } => {
                if pending.is_empty() {
                    0
                } else {
                    POLLIN
                }
            }
            State::Connected { pair, side, .. } => {
                let p = &self.pairs[pair];
                let (readable, eof) = (!p.q[*side].segs.is_empty(), p.q[*side].write_closed);
                let (room, peer_gone) = (p.q[1 - side].bytes < BUFFER_LIMIT, p.q[1 - side].read_closed);
                let mut ev = 0;
                if readable || eof || s.shut_rd {
                    ev |= POLLIN;
                }
                if eof {
                    ev |= POLLRDHUP;
                }
                if room && !peer_gone {
                    ev |= POLLOUT;
                }
                if eof && peer_gone {
                    ev |= POLLHUP;
                }
                ev
            }
            State::Unconnected => POLLOUT | POLLHUP,
        }
    }

    fn publish(&self, sid: u64, event: bool) {
        if let Some(slot) = self.socks.get(&sid).and_then(|s| s.slot) {
            let size = self.pair_of(sid).map_or(0, |(p, side)| self.pairs[&p].q[side].bytes);
            crate::obj::set_ready_ev(slot, self.events(sid), size as u64, event);
        }
    }

    /// Whether Unix sockets wait in `sid`'s receive queue (or, listening, in a pending
    /// connection's).
    fn holds_unix_in_flight(&self, sid: u64) -> bool {
        let in_queue = |pair: u64, side: usize| self.pairs.get(&pair).is_some_and(|p| p.q[side].segs.iter().any(|s| !s.unix_in.is_empty()));
        match &self.socks.get(&sid).map(|s| &s.state) {
            Some(State::Connected { pair, side, .. }) => in_queue(*pair, *side),
            Some(State::Listening { pending, .. }) => pending.iter().any(|&p| self.pair_of(p).is_some_and(|(pair, side)| in_queue(pair, side))),
            _ => false,
        }
    }
}

// ----------------------------------------------------------------------
// Receiving and sending
// ----------------------------------------------------------------------

/// What one receive took.
struct Got {
    data: Vec<u8>,
    fds: Vec<u64>,
    cred: Option<Ucred>,
    truncated: bool,
}

/// Stream read: as many bytes as fit, never past a segment carrying descriptors once data
/// has been taken, and never beyond the first segment that carries some.
fn take_stream(q: &mut Queue, max: usize, peek: bool) -> Got {
    let mut data = Vec::new();
    let mut fds = Vec::new();
    let cred = q.segs.front().map(|s| s.cred);
    let mut i = 0;
    while data.len() < max && i < q.segs.len() {
        let seg = &mut q.segs[i];
        if !data.is_empty() && !seg.fds.is_empty() {
            break;
        }
        let take = (seg.data.len() - seg.pos).min(max - data.len());
        data.extend_from_slice(&seg.data[seg.pos..seg.pos + take]);
        let had_fds = !seg.fds.is_empty();
        if !peek {
            fds.append(&mut seg.fds);
            seg.unix_in.clear();
            seg.pos += take;
        }
        i += 1;
        if had_fds {
            break;
        }
    }
    if !peek {
        q.bytes -= data.len();
        while q.segs.front().is_some_and(|s| s.pos >= s.data.len()) {
            q.segs.pop_front();
        }
    }
    Got { data, fds, cred, truncated: false }
}

/// Record read: one whole message (the rest of it is discarded if the buffer is short).
fn take_record(q: &mut Queue, max: usize, peek: bool) -> Got {
    let seg = q.segs.front().unwrap();
    let n = seg.data.len().min(max);
    let data = seg.data[..n].to_vec();
    let truncated = seg.data.len() > n;
    let cred = Some(seg.cred);
    if peek {
        return Got { data, fds: Vec::new(), cred, truncated };
    }
    let seg = q.segs.pop_front().unwrap();
    q.bytes -= seg.data.len();
    Got { data, fds: seg.fds, cred, truncated }
}

/// Takes from socket `sid`'s receive queue: `Ok(None)` if it would wait.
fn try_take(u: &mut Unix, sid: u64, max: usize, peek: bool) -> Result<Option<Got>, i64> {
    let (ty, shut_rd) = match u.socks.get(&sid) {
        Some(s) => (s.ty, s.shut_rd),
        None => return Err(EBADF),
    };
    let Some((pair, side)) = u.pair_of(sid) else { return Err(ENOTCONN) };
    let q = &mut u.pairs.get_mut(&pair).unwrap().q[side];
    if !q.segs.is_empty() && !shut_rd {
        let g = if ty == SOCK_STREAM { take_stream(q, max, peek) } else { take_record(q, max, peek) };
        return Ok(Some(g));
    }
    if q.write_closed || shut_rd {
        return Ok(Some(Got { data: Vec::new(), fds: Vec::new(), cred: None, truncated: false }));
    }
    Ok(None)
}

/// Hands what a receive took to its caller (`cx`: the call, served now or completed later):
/// the bytes, the descriptors and credentials (`recvmsg`), the message header's fields.
fn deliver(cx: &Cx, iov: &Iov, kind: RecvKind, flags: u64, passcred: bool, g: Got, after: &mut After) -> i64 {
    if let Err(e) = iov.scatter(cx, &g.data) {
        after.drop.extend(g.fds);
        return e;
    }
    let n = g.data.len() as i64;
    match kind {
        RecvKind::Read => {
            after.drop.extend(g.fds);
            n
        }
        RecvKind::From(len_ptr) => {
            after.drop.extend(g.fds);
            if len_ptr != 0 {
                let _ = cx.copy_out(len_ptr, &0u32.to_le_bytes());
            }
            n
        }
        RecvKind::Msg { msg, mmsg } => {
            let r = (|| -> Result<i64, i64> {
                let mut hdr = cx.copy_in(msg, 56)?;
                let (control, cap) = (Cx::u64_at(&hdr, 32), Cx::u64_at(&hdr, 40) as usize);
                let cred = if passcred { g.cred } else { None };
                let (used, mut mflags) = build_control(cx, control, cap, g.fds, cred, flags & MSG_CMSG_CLOEXEC != 0, after)?;
                if g.truncated {
                    mflags |= MSG_TRUNC;
                }
                // msg_namelen = 0 (connected sockets), msg_controllen, msg_flags: the header
                // goes back whole (one copy, through the page when the kernel gave room)
                hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
                hdr[40..48].copy_from_slice(&(used as u64).to_le_bytes());
                hdr[48..52].copy_from_slice(&mflags.to_le_bytes());
                cx.copy_out(msg, &hdr)?;
                if mmsg {
                    cx.copy_out(msg + 56, &(n as u32).to_le_bytes())?;
                    return Ok(1);
                }
                Ok(n)
            })();
            r.unwrap_or_else(|e| e)
        }
    }
}

/// Builds the received control messages into the caller's buffer: installs descriptors
/// (letting go of those that do not fit: `MSG_CTRUNC`) and adds credentials.
fn build_control(cx: &Cx, ptr: u64, cap: usize, fds: Vec<u64>, cred: Option<Ucred>, cloexec: bool, after: &mut After) -> Result<(usize, u32), i64> {
    let mut out = Vec::new();
    let mut flags = 0;
    if !fds.is_empty() {
        let room = if cap >= 16 { (cap - 16) / 4 } else { 0 };
        if room < fds.len() {
            flags |= MSG_CTRUNC;
        }
        let mut fds = fds;
        let extra = fds.split_off(room.min(fds.len()));
        after.drop.extend(extra);
        let mut nums = Vec::new();
        if !fds.is_empty() {
            let mut ents: Vec<u64> = Vec::with_capacity(fds.len() * 2);
            for &t in &fds {
                ents.push(t);
                ents.push(u64::MAX);
            }
            let r = sys::lx_obj(LX_OBJ_GIVE, cx.id, ents.as_mut_ptr() as u64, fds.len() as u64 | if cloexec { (0o2000000u64) << 32 } else { 0 });
            for i in 0..fds.len() {
                let fd = ents[i * 2 + 1];
                if fd == u64::MAX {
                    after.drop.push(ents[i * 2]);
                } else {
                    nums.push(fd as i32);
                }
            }
            if let Err(e) = r {
                if nums.is_empty() {
                    return Err(e);
                }
                flags |= MSG_CTRUNC;
            }
        }
        if !nums.is_empty() {
            let clen = 16 + 4 * nums.len();
            out.extend_from_slice(&(clen as u64).to_le_bytes());
            out.extend_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
            out.extend_from_slice(&SCM_RIGHTS.to_le_bytes());
            for n in nums {
                out.extend_from_slice(&n.to_le_bytes());
            }
            out.resize(align8(out.len()), 0);
        }
    }
    if let Some(c) = cred {
        if out.len() + 28 <= cap {
            out.extend_from_slice(&28u64.to_le_bytes());
            out.extend_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
            out.extend_from_slice(&SCM_CREDENTIALS.to_le_bytes());
            out.extend_from_slice(&c.bytes());
            out.resize(align8(out.len()), 0);
        } else {
            flags |= MSG_CTRUNC;
        }
    }
    let used = out.len().min(cap);
    if used > 0 {
        cx.copy_out(ptr, &out[..used])?;
    }
    Ok((used, flags))
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// The descriptors the `SCM_RIGHTS` messages of a control buffer name, kept by the kernel
/// from now on: `(tokens, slots of the Unix sockets among them)`.
fn parse_control(cx: &Cx, ptr: u64, len: u64) -> Result<(Vec<u64>, Vec<(u32, u32)>), i64> {
    if ptr == 0 || len < 16 {
        return Ok((Vec::new(), Vec::new()));
    }
    if len > 65536 {
        return Err(EINVAL);
    }
    let buf = cx.copy_in(ptr, len as usize)?;
    let mut fds: Vec<u64> = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let clen = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let ty = i32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap());
        if clen < 16 || off + clen > buf.len() {
            return Err(EINVAL);
        }
        if level == SOL_SOCKET as i32 && ty == SCM_RIGHTS {
            for c in buf[off + 16..off + clen].chunks_exact(4) {
                let fd = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                if fd < 0 {
                    return Err(EBADF);
                }
                fds.push(fd as u64);
                if fds.len() > MAX_FDS {
                    return Err(EINVAL);
                }
            }
        }
        // SCM_CREDENTIALS: the sender's real credentials are attached anyway
        off += align8(clen);
    }
    if fds.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    // [fd, token, what] each; the kernel keeps them all or none
    let mut ents: Vec<u64> = Vec::with_capacity(fds.len() * 3);
    for &fd in &fds {
        ents.extend_from_slice(&[fd, 0, 0]);
    }
    sys::lx_obj(LX_OBJ_TAKE, cx.id, ents.as_mut_ptr() as u64, fds.len() as u64)?;
    let mut tokens = Vec::with_capacity(fds.len());
    let mut socks = Vec::new();
    for i in 0..fds.len() {
        tokens.push(ents[i * 3 + 1]);
        let what = ents[i * 3 + 2];
        if what >> 63 == 1 && (what >> 32) as u32 & 0xFFFF == LX_OBJ_KIND_UNIX {
            socks.push((what as u32, i as u32));
        }
    }
    Ok((tokens, socks))
}

/// Puts what a send carries into socket `sid`'s peer's queue: `Ok(bytes queued)` (maybe
/// fewer than `data`, for a stream with little room; 0 with nothing queued when there is no
/// room at all), `Err(EPIPE)` when the peer is gone. The descriptors go with the first
/// segment queued.
fn put(u: &mut Unix, sid: u64, data: &[u8], fds: &mut Vec<u64>, unix_in: &mut Vec<u32>, cred: Ucred) -> Result<usize, i64> {
    let ty = u.socks[&sid].ty;
    let Some((pair, side)) = u.pair_of(sid) else { return Err(ENOTCONN) };
    let q = &mut u.pairs.get_mut(&pair).unwrap().q[1 - side];
    if q.read_closed || q.write_closed {
        return Err(EPIPE);
    }
    let record = ty != SOCK_STREAM;
    let room = BUFFER_LIMIT.saturating_sub(q.bytes);
    let fits = if record { room >= data.len() || q.segs.is_empty() } else { room > 0 || data.is_empty() };
    if !fits {
        return Ok(0);
    }
    let n = if record { data.len() } else { room.min(data.len()) };
    if n == 0 && fds.is_empty() && !record {
        return Ok(0);
    }
    q.segs.push_back(Segment { data: data[..n].to_vec(), pos: 0, fds: core::mem::take(fds), unix_in: core::mem::take(unix_in), cred });
    q.bytes += n;
    Ok(n)
}

/// After socket `sid`'s receive queue changed: waiting receivers on it get what is there,
/// waiting senders on its peer put what fits, until nothing moves.
fn settle(u: &mut Unix, sid: u64, after: &mut After) {
    let Some((pair, side)) = u.pair_of(sid) else { return };
    let socks = u.pairs[&pair].socks;
    for _ in 0..64 {
        let mut moved = false;
        // Receivers of this side
        let rsid = socks[side];
        let n = u.socks.get(&rsid).map_or(0, |s| s.waits.iter().filter(|w| matches!(w, Wait::Recv { .. })).count());
        for _ in 0..n {
            let Some(pos) = u.socks.get(&rsid).and_then(|s| s.waits.iter().position(|w| matches!(w, Wait::Recv { .. }))) else { break };
            let (max, peek) = match &u.socks[&rsid].waits[pos] {
                Wait::Recv { iov, flags, .. } => (iov.total(), flags & MSG_PEEK != 0),
                _ => unreachable!(),
            };
            match try_take(u, rsid, max, peek) {
                Ok(None) => break,
                r => {
                    let Some(Wait::Recv { c, iov, kind, flags }) = u.socks.get_mut(&rsid).unwrap().waits.remove(pos) else { unreachable!() };
                    let passcred = u.socks[&rsid].passcred;
                    let res = match r {
                        Ok(Some(g)) => {
                            let cx = Cx::from_call(&c, core::ptr::null_mut());
                            deliver(&cx, &iov, kind, flags, passcred, g, after)
                        }
                        Err(e) => e,
                        Ok(None) => unreachable!(),
                    };
                    after.done.push((c.id, res));
                    moved = true;
                    if peek {
                        continue;
                    }
                }
            }
        }
        // Senders of the other side, into this side's queue
        let wsid = socks[1 - side];
        loop {
            let Some(pos) = u.socks.get(&wsid).and_then(|s| s.waits.iter().position(|w| matches!(w, Wait::Send { .. }))) else { break };
            let Some(Wait::Send { c, iov, total, mut done, flags, mut fds, mut unix_in, mmsg }) = u.socks.get_mut(&wsid).unwrap().waits.remove(pos) else { unreachable!() };
            let ty = u.socks[&wsid].ty;
            let want = if ty == SOCK_STREAM { (total - done).min(BUFFER_LIMIT) } else { total };
            let data = match iov.gather_later(c.id, done, want) {
                Ok(d) => d,
                Err(e) => {
                    after.drop.append(&mut fds);
                    after.done.push((c.id, if done > 0 { done as i64 } else { e }));
                    continue;
                }
            };
            match put(u, wsid, &data, &mut fds, &mut unix_in, Ucred::of(&c)) {
                Ok(0) if !(data.is_empty() && total == 0) => {
                    // Still no room: back in its place
                    u.socks.get_mut(&wsid).unwrap().waits.insert(pos, Wait::Send { c, iov, total, done, flags, fds, unix_in, mmsg });
                    break;
                }
                Ok(n) => {
                    done += n;
                    moved = true;
                    if done >= total || ty != SOCK_STREAM {
                        let r = finish_send(&c, done as i64, mmsg);
                        after.done.push((c.id, r));
                    } else {
                        u.socks.get_mut(&wsid).unwrap().waits.insert(pos, Wait::Send { c, iov, total, done, flags, fds, unix_in, mmsg });
                    }
                }
                Err(e) => {
                    after.drop.append(&mut fds);
                    if e == EPIPE && done == 0 && flags & MSG_NOSIGNAL == 0 {
                        after.pipe.push(c.tgid);
                    }
                    after.done.push((c.id, if done > 0 { done as i64 } else { e }));
                }
            }
        }
        if !moved {
            break;
        }
    }
    u.publish(socks[0], true);
    u.publish(socks[1], true);
}

/// The result of a send that finished (for `sendmmsg`, its length goes after the header).
fn finish_send(c: &LxCall, n: i64, mmsg: Option<u64>) -> i64 {
    if let Some(m) = mmsg {
        let _ = sys::lx_write(c.id, m + 56, &(n as u32).to_le_bytes());
        return 1;
    }
    n
}

/// A receive on socket `sid` (`max` bytes into `iov`): at once, or pending.
fn recv(cx: &Cx, sid: u64, iov: Iov, kind: RecvKind, flags: u64) -> (i64, u64) {
    let mut after = After::default();
    let r = {
        let mut u = U.lock();
        let peek = flags & MSG_PEEK != 0;
        match try_take(&mut u, sid, iov.total(), peek) {
            Err(e) => (e, 0),
            Ok(Some(g)) => {
                let passcred = u.socks[&sid].passcred;
                let r = deliver(cx, &iov, kind, flags, passcred, g, &mut after);
                if !peek {
                    settle(&mut u, sid, &mut after);
                }
                (r, 0)
            }
            Ok(None) if cx.nonblock() || flags & MSG_DONTWAIT != 0 || kbuf(cx) => (EAGAIN, 0),
            Ok(None) => {
                u.socks.get_mut(&sid).unwrap().waits.push_back(Wait::Recv { c: cx.c, iov, kind, flags });
                (0, LX_REPLY_PENDING)
            }
        }
    };
    after.run();
    r
}

/// A send on socket `sid`: the bytes of `iov` with the descriptors of `control`.
fn send(cx: &Cx, sid: u64, iov: Iov, control: (u64, u64), flags: u64, mmsg: Option<u64>) -> (i64, u64) {
    let total = iov.total();
    let ty = match U.lock().socks.get(&sid) {
        Some(s) => s.ty,
        None => return (EBADF, 0),
    };
    if ty != SOCK_STREAM && total > BUFFER_LIMIT {
        return (EMSGSIZE, 0);
    }
    let (mut fds, socks) = match parse_control(cx, control.0, control.1) {
        Ok(f) => f,
        Err(e) => return (e, 0),
    };
    let mut after = After::default();
    let r = 'r: {
        let mut u = U.lock();
        // The cycle rule: a socket whose own queue holds a Unix socket does not travel
        let mut unix_in = Vec::new();
        for &(slot, _) in &socks {
            if let Some(&s) = u.by_slot.get(&slot) {
                if u.holds_unix_in_flight(s) {
                    after.drop.append(&mut fds);
                    break 'r (ETOOMANYREFS, 0);
                }
            }
            unix_in.push(slot);
        }
        if !unix_in.is_empty() && INFLIGHT_SENT.fetch_add(unix_in.len() as u64, core::sync::atomic::Ordering::Relaxed) > 256 {
            // Many sockets sent since the last collection: collect before slots run out
            drop(u);
            gc();
            u = U.lock();
        }
        let nonblock = cx.nonblock() || flags & MSG_DONTWAIT != 0 || kbuf(cx);
        let cred = Ucred::of(&cx.c);
        let first = if ty == SOCK_STREAM { total.min(BUFFER_LIMIT) } else { total };
        let data = match iov.gather(cx, 0, first) {
            Ok(d) => d,
            Err(e) => {
                after.drop.append(&mut fds);
                break 'r (e, 0);
            }
        };
        match put(&mut u, sid, &data, &mut fds, &mut unix_in, cred) {
            Err(e) => {
                after.drop.append(&mut fds);
                if e == EPIPE && flags & MSG_NOSIGNAL == 0 && !kbuf(cx) {
                    after.pipe.push(cx.c.tgid);
                }
                (e, 0)
            }
            Ok(n) => {
                if n > 0 || (total == 0 && ty != SOCK_STREAM) {
                    let (pair, side) = u.pair_of(sid).unwrap();
                    let peer = u.pairs[&pair].socks[1 - side];
                    settle(&mut u, peer, &mut after);
                }
                if n >= total && (n > 0 || fds.is_empty()) {
                    (finish_now(cx, n as i64, mmsg), 0)
                } else if nonblock {
                    after.drop.append(&mut fds);
                    (if n > 0 { finish_now(cx, n as i64, mmsg) } else { EAGAIN }, 0)
                } else {
                    u.socks.get_mut(&sid).unwrap().waits.push_back(Wait::Send { c: cx.c, iov, total, done: n, flags, fds, unix_in, mmsg });
                    (0, LX_REPLY_PENDING)
                }
            }
        }
    };
    after.run();
    r
}

fn finish_now(cx: &Cx, n: i64, mmsg: Option<u64>) -> i64 {
    if let Some(m) = mmsg {
        return match cx.copy_out(m + 56, &(n as u32).to_le_bytes()) {
            Ok(()) => 1,
            Err(e) => e,
        };
    }
    n
}

// ----------------------------------------------------------------------
// The calls
// ----------------------------------------------------------------------

/// The socket of the call's descriptor.
fn sid_of(cx: &Cx) -> Result<u64, i64> {
    U.lock().by_slot.get(&(cx.c.obj as u32)).copied().ok_or(ENOTSOCK)
}

/// Gives socket `sid` a slot and a descriptor in the caller's table.
fn install(u: &mut Unix, cx: &Cx, sid: u64, flags: u64) -> Result<i64, i64> {
    let slot = crate::obj::alloc(LX_OBJ_KIND_UNIX)?;
    let ino = u.socks[&sid].ino;
    u.socks.get_mut(&sid).unwrap().slot = Some(slot);
    u.by_slot.insert(slot, sid);
    u.publish(sid, false);
    let name = alloc::format!("socket:[{}]", ino);
    let f = (flags & (SOCK_NONBLOCK | SOCK_CLOEXEC)) as u32;
    match crate::obj::install_tag(cx, slot, LX_OBJ_KIND_UNIX, f, 0o140777, cx.c.euid, cx.c.egid, name.as_bytes(), ino) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            u.by_slot.remove(&slot);
            u.socks.get_mut(&sid).unwrap().slot = None;
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            Err(e)
        }
    }
}

fn sock_type(ty: u64) -> Result<u32, i64> {
    match ty as u32 & 0xf {
        t @ (SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) => Ok(t),
        _ => Err(EPROTONOSUPPORT),
    }
}

/// `socket(AF_UNIX, type, protocol)` (41) and `socketpair(AF_UNIX, type, protocol, sv)` (53).
pub fn create(cx: &Cx) -> (i64, u64) {
    let a = cx.args;
    if a[0] != AF_UNIX as u64 {
        return (-97, 0); // EAFNOSUPPORT
    }
    if cx.nr == 41 && a[2] != 0 && a[2] != 1 {
        return (EPROTONOSUPPORT, 0);
    }
    let ty = match sock_type(a[1]) {
        Ok(t) => t,
        Err(e) => return (e, 0),
    };
    let mut u = U.lock();
    if cx.nr == 41 {
        let sid = u.new_sock(ty);
        return match install(&mut u, cx, sid, a[1]) {
            Ok(fd) => (fd, 0),
            Err(e) => {
                u.socks.remove(&sid);
                (e, 0)
            }
        };
    }
    let me = Ucred::of(&cx.c);
    let (x, y) = (u.new_sock(ty), u.new_sock(ty));
    let pid = u.next;
    u.next += 1;
    u.pairs.insert(pid, Pair { q: [Queue::default(), Queue::default()], socks: [x, y] });
    u.socks.get_mut(&x).unwrap().state = State::Connected { pair: pid, side: 0, peer_cred: me, peer_addr: None };
    u.socks.get_mut(&y).unwrap().state = State::Connected { pair: pid, side: 1, peer_cred: me, peer_addr: None };
    let fx = match install(&mut u, cx, x, a[1]) {
        Ok(fd) => fd,
        Err(e) => {
            u.socks.remove(&x);
            u.socks.remove(&y);
            u.pairs.remove(&pid);
            return (e, 0);
        }
    };
    let fy = match install(&mut u, cx, y, a[1]) {
        Ok(fd) => fd,
        Err(e) => {
            // x's descriptor stays until the program closes it (the kernel tells us);
            // y was never seen: as if closed
            close_sock(&mut u, y, &mut After::default());
            return (e, 0);
        }
    };
    drop(u);
    let mut sv = [0u8; 8];
    sv[0..4].copy_from_slice(&(fx as i32).to_le_bytes());
    sv[4..8].copy_from_slice(&(fy as i32).to_le_bytes());
    match cx.copy_out(a[3], &sv) {
        Ok(()) => (0, 0),
        Err(e) => (if e == 0 { EFAULT } else { e }, 0),
    }
}

/// Reads a `sockaddr_un` (`ino`: the node the kernel resolved for a path name).
fn read_addr(cx: &Cx, ptr: u64, len: u64) -> Result<Addr, i64> {
    if !(2..=110).contains(&len) {
        return Err(EINVAL);
    }
    let b = cx.copy_in(ptr, len as usize)?;
    if u16::from_le_bytes([b[0], b[1]]) != AF_UNIX {
        return Err(EINVAL);
    }
    let name = &b[2..];
    if name.is_empty() {
        return Err(EINVAL); // autobind is not supported
    }
    if name[0] == 0 {
        return Ok(Addr::Abstract(name[1..].to_vec()));
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    if cx.c.ino == 0 || (cx.c.ino as i64) < 0 {
        return Err(ENOENT);
    }
    Ok(Addr::Path { shown: name[..end].to_vec(), ino: cx.c.ino })
}

/// Writes a socket address to (`addr`, `*len_ptr`), truncated to the caller's buffer, with
/// the full length stored, as Linux does.
fn put_sockaddr(cx: &Cx, addr: u64, len_ptr: u64, sa: &[u8]) -> Result<(), i64> {
    if addr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let cap = u32::from_le_bytes(cx.copy_in(len_ptr, 4)?[..4].try_into().unwrap()) as usize;
    cx.copy_out_any(addr, &sa[..sa.len().min(cap)])?;
    cx.copy_out(len_ptr, &(sa.len() as u32).to_le_bytes())
}

fn bind(cx: &Cx, sid: u64) -> i64 {
    let addr = match read_addr(cx, cx.args[1], cx.args[2]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let mut u = U.lock();
    if u.socks[&sid].local.is_some() {
        return EINVAL;
    }
    let key = addr.key();
    // A path name was just made as a fresh node: an entry under it belongs to a socket
    // whose node was unlinked (and whose number the pool reused): replaced
    if matches!(addr, Addr::Abstract(_)) && u.names.get(&key).is_some_and(|s| u.socks.contains_key(s)) {
        return EADDRINUSE;
    }
    u.names.insert(key, sid);
    u.socks.get_mut(&sid).unwrap().local = Some(addr);
    0
}

fn listen(cx: &Cx, sid: u64) -> i64 {
    let mut u = U.lock();
    let s = u.socks.get_mut(&sid).unwrap();
    if s.ty == SOCK_DGRAM {
        return EOPNOTSUPP;
    }
    match s.state {
        State::Listening { .. } => 0,
        State::Unconnected => {
            if s.local.is_none() {
                return EINVAL; // autobind is not supported
            }
            s.state = State::Listening { pending: VecDeque::new(), cred: Ucred::of(&cx.c) };
            u.publish(sid, false);
            0
        }
        State::Connected { .. } => EINVAL,
    }
}

fn connect(cx: &Cx, sid: u64) -> i64 {
    let addr = match read_addr(cx, cx.args[1], cx.args[2]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let mut after = After::default();
    let r = 'r: {
        let mut u = U.lock();
        let ty = u.socks[&sid].ty;
        if !matches!(u.socks[&sid].state, State::Unconnected) {
            break 'r EISCONN;
        }
        let Some(&lsid) = u.names.get(&addr.key()) else { break 'r ECONNREFUSED };
        let Some(l) = u.socks.get(&lsid) else { break 'r ECONNREFUSED };
        if l.ty != ty {
            break 'r EPROTOTYPE;
        }
        if ty == SOCK_DGRAM {
            break 'r ECONNREFUSED; // unconnected datagram sockets are not supported
        }
        let listen_cred = match &l.state {
            State::Listening { cred, .. } => *cred,
            _ => break 'r ECONNREFUSED,
        };
        let l_local = l.local.clone();
        let me = Ucred::of(&cx.c);
        let server = u.new_sock(ty);
        let pid = u.next;
        u.next += 1;
        u.pairs.insert(pid, Pair { q: [Queue::default(), Queue::default()], socks: [sid, server] });
        let my_local = u.socks[&sid].local.clone();
        {
            let s = u.socks.get_mut(&server).unwrap();
            s.local = l_local.clone();
            s.state = State::Connected { pair: pid, side: 1, peer_cred: me, peer_addr: my_local };
        }
        u.socks.get_mut(&sid).unwrap().state = State::Connected { pair: pid, side: 0, peer_cred: listen_cred, peer_addr: l_local };
        if let State::Listening { pending, .. } = &mut u.socks.get_mut(&lsid).unwrap().state {
            pending.push_back(server);
        }
        u.publish(sid, false);
        u.publish(lsid, true);
        accept_waiting(&mut u, lsid, &mut after);
        0
    };
    after.run();
    r
}

/// Takes the next connection of listener `lsid` for the accept call `cx`: its descriptor.
fn take_conn(u: &mut Unix, cx: &Cx, lsid: u64, addr: u64, len: u64, flags: u64) -> Option<i64> {
    let conn = match &mut u.socks.get_mut(&lsid)?.state {
        State::Listening { pending, .. } => pending.pop_front()?,
        _ => return Some(EINVAL),
    };
    let peer = match &u.socks[&conn].state {
        State::Connected { peer_addr, .. } => peer_addr.clone(),
        _ => None,
    };
    let r = match install(u, cx, conn, flags) {
        Ok(fd) => {
            let _ = put_sockaddr(cx, addr, len, &Addr::sockaddr(peer.as_ref()));
            fd
        }
        Err(e) => {
            // Back at the head of the queue
            if let State::Listening { pending, .. } = &mut u.socks.get_mut(&lsid).unwrap().state {
                pending.push_front(conn);
            }
            e
        }
    };
    u.publish(lsid, false);
    Some(r)
}

/// Completes the accept calls waiting on listener `lsid` while connections wait.
fn accept_waiting(u: &mut Unix, lsid: u64, after: &mut After) {
    loop {
        let has = matches!(&u.socks[&lsid].state, State::Listening { pending, .. } if !pending.is_empty());
        if !has {
            break;
        }
        let Some(pos) = u.socks[&lsid].waits.iter().position(|w| matches!(w, Wait::Accept { .. })) else { break };
        let Some(Wait::Accept { c, addr, len, flags }) = u.socks.get_mut(&lsid).unwrap().waits.remove(pos) else { unreachable!() };
        let cx = Cx::from_call(&c, core::ptr::null_mut());
        let r = take_conn(u, &cx, lsid, addr, len, flags).unwrap_or(EINVAL);
        after.done.push((c.id, r));
    }
}

fn accept(cx: &Cx, sid: u64, flags: u64) -> (i64, u64) {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return (EINVAL, 0);
    }
    let mut u = U.lock();
    if !matches!(u.socks[&sid].state, State::Listening { .. }) {
        return (EINVAL, 0);
    }
    if let Some(r) = take_conn(&mut u, cx, sid, cx.args[1], cx.args[2], flags) {
        return (r, 0);
    }
    if cx.nonblock() {
        return (EAGAIN, 0);
    }
    u.socks.get_mut(&sid).unwrap().waits.push_back(Wait::Accept { c: cx.c, addr: cx.args[1], len: cx.args[2], flags });
    (0, LX_REPLY_PENDING)
}

fn sockopt_get(cx: &Cx, sid: u64) -> i64 {
    let (level, opt, val, len_ptr) = (cx.args[1], cx.args[2], cx.args[3], cx.args[4]);
    if level as u32 != SOL_SOCKET {
        return ENOPROTOOPT;
    }
    let int = |v: u32| v.to_le_bytes().to_vec();
    let bytes = {
        let u = U.lock();
        let s = &u.socks[&sid];
        match opt {
            3 => int(s.ty),                                   // SO_TYPE
            4 => int(0),                                      // SO_ERROR
            7 | 8 => int(BUFFER_LIMIT as u32),                // SO_SNDBUF, SO_RCVBUF
            16 => int(s.passcred as u32),                     // SO_PASSCRED
            17 => match &s.state {
                // SO_PEERCRED
                State::Connected { peer_cred, .. } => peer_cred.bytes().to_vec(),
                State::Listening { cred, .. } => cred.bytes().to_vec(),
                State::Unconnected => Ucred { pid: 0, uid: u32::MAX, gid: u32::MAX }.bytes().to_vec(),
            },
            77 => {
                // SO_PEERPIDFD: a pidfd for the peer process
                let pid = match &s.state {
                    State::Connected { peer_cred, .. } => peer_cred.pid as u64,
                    _ => 0,
                };
                drop(u);
                if pid == 0 {
                    return -61; // ENODATA
                }
                let fd = crate::pidfd::open_for(cx, pid, 0);
                if fd < 0 {
                    return fd;
                }
                int(fd as u32)
            }
            30 => int(matches!(s.state, State::Listening { .. }) as u32), // SO_ACCEPTCONN
            38 => int(0),                                                 // SO_PROTOCOL
            39 => int(AF_UNIX as u32),                                    // SO_DOMAIN
            20 | 21 => alloc::vec![0u8; 16],                              // SO_RCVTIMEO, SO_SNDTIMEO
            _ => return ENOPROTOOPT,
        }
    };
    let r: Result<i64, i64> = (|| {
        let cap = u32::from_le_bytes(cx.copy_in(len_ptr, 4)?[..4].try_into().unwrap()) as usize;
        cx.copy_out_any(val, &bytes[..bytes.len().min(cap)])?;
        cx.copy_out(len_ptr, &(bytes.len().min(cap) as u32).to_le_bytes())?;
        Ok(0)
    })();
    r.unwrap_or_else(|e| e)
}

fn sockopt_set(cx: &Cx, sid: u64) -> i64 {
    let (level, opt, val, len) = (cx.args[1], cx.args[2], cx.args[3], cx.args[4]);
    if level as u32 != SOL_SOCKET {
        return ENOPROTOOPT;
    }
    if opt == 16 {
        // SO_PASSCRED
        if len < 4 {
            return EINVAL;
        }
        match cx.copy_in(val, 4) {
            Ok(v) => U.lock().socks.get_mut(&sid).unwrap().passcred = u32::from_le_bytes(v[..4].try_into().unwrap()) != 0,
            Err(e) => return e,
        }
    }
    0 // buffer sizes, timeouts and the like are accepted and ignored
}

fn shutdown(sid: u64, how: u64) -> i64 {
    if how > 2 {
        return EINVAL;
    }
    let mut after = After::default();
    let r = {
        let mut u = U.lock();
        let Some((pair, side)) = u.pair_of(sid) else { return ENOTCONN };
        if how != 1 {
            u.socks.get_mut(&sid).unwrap().shut_rd = true;
        }
        if how != 0 {
            u.pairs.get_mut(&pair).unwrap().q[1 - side].write_closed = true;
        }
        let socks = u.pairs[&pair].socks;
        settle(&mut u, socks[0], &mut after);
        settle(&mut u, socks[1], &mut after);
        0
    };
    after.run();
    r
}

/// The calls on a Unix socket (slot `cx.c.obj`): the socket calls, and `read`, `write`,
/// `readv`, `writev`, `ioctl`.
pub fn call(cx: &Cx) -> (i64, u64) {
    let sid = match sid_of(cx) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let a = cx.args;
    match cx.nr {
        0 | 19 => match Iov::of_call(cx) {
            Ok(iov) => recv(cx, sid, iov, RecvKind::Read, 0),
            Err(e) => (e, 0),
        },
        1 | 20 => match Iov::of_call(cx) {
            Ok(iov) => send(cx, sid, iov, (0, 0), 0, None),
            Err(e) => (e, 0),
        },
        16 => (ioctl(cx, sid), 0),
        49 => (bind(cx, sid), 0),
        50 => (listen(cx, sid), 0),
        42 => (connect(cx, sid), 0),
        43 => accept(cx, sid, 0),
        288 => accept(cx, sid, a[3]),
        44 => {
            // sendto(fd, buf, len, flags, dest, addrlen): the destination must be the peer
            let ty = U.lock().socks[&sid].ty;
            if a[4] != 0 && U.lock().pair_of(sid).is_none() {
                return (if ty == SOCK_DGRAM { EOPNOTSUPP } else { ENOTCONN }, 0);
            }
            send(cx, sid, Iov::one(a[1], a[2]), (0, 0), a[3], None)
        }
        45 => recv(cx, sid, Iov::one(a[1], a[2]), RecvKind::From(a[5]), a[3]),
        46 => sendmsg(cx, sid, a[1], a[2], None),
        47 => recvmsg(cx, sid, a[1], a[2], false),
        307 | 299 => mmsg(cx, sid),
        48 => (shutdown(sid, a[1]), 0),
        51 => {
            let sa = Addr::sockaddr(U.lock().socks[&sid].local.as_ref());
            (put_sockaddr(cx, a[1], a[2], &sa).map_or_else(|e| e, |()| 0), 0)
        }
        52 => {
            let peer = match &U.lock().socks[&sid].state {
                State::Connected { peer_addr, .. } => Some(Addr::sockaddr(peer_addr.as_ref())),
                _ => None,
            };
            match peer {
                Some(sa) => (put_sockaddr(cx, a[1], a[2], &sa).map_or_else(|e| e, |()| 0), 0),
                None => (ENOTCONN, 0),
            }
        }
        54 => (sockopt_set(cx, sid), 0),
        55 => (sockopt_get(cx, sid), 0),
        _ => (EINVAL, 0),
    }
}

fn sendmsg(cx: &Cx, sid: u64, msg: u64, flags: u64, mmsg: Option<u64>) -> (i64, u64) {
    let hdr = match cx.copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return (e, 0),
    };
    let f = |o: usize| Cx::u64_at(&hdr, o);
    let (name, iov, iovlen, control, controllen) = (f(0), f(16), f(24), f(32), f(40));
    {
        let u = U.lock();
        if name != 0 && u.pair_of(sid).is_none() {
            return (if u.socks[&sid].ty == SOCK_DGRAM { EOPNOTSUPP } else { EISCONN }, 0);
        }
    }
    match Iov::array(cx, iov, iovlen) {
        Ok(v) => send(cx, sid, v, (control, controllen), flags, mmsg),
        Err(e) => (e, 0),
    }
}

fn recvmsg(cx: &Cx, sid: u64, msg: u64, flags: u64, mmsg: bool) -> (i64, u64) {
    let hdr = match cx.copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return (e, 0),
    };
    match Iov::array(cx, Cx::u64_at(&hdr, 16), Cx::u64_at(&hdr, 24)) {
        Ok(v) => recv(cx, sid, v, RecvKind::Msg { msg, mmsg }, flags),
        Err(e) => (e, 0),
    }
}

/// `sendmmsg`/`recvmmsg`: one message at a time (`struct mmsghdr` is 64 bytes). Only the
/// first may wait; later ones stop the call when they would.
fn mmsg(cx: &Cx, sid: u64) -> (i64, u64) {
    let a = cx.args;
    let send = cx.nr == 307;
    let mut done = 0u64;
    while done < a[2] {
        let m = a[1] + done * 64;
        let flags = if done == 0 { a[3] } else { a[3] | MSG_DONTWAIT };
        let (r, f) = if send { sendmsg(cx, sid, m, flags, Some(m)) } else { recvmsg(cx, sid, m, flags, true) };
        if f & LX_REPLY_PENDING != 0 {
            return (r, f);
        }
        if r < 0 {
            if done == 0 {
                return (r, 0);
            }
            break;
        }
        done += 1;
        if !send {
            break; // return what is there rather than waiting for more
        }
    }
    (done as i64, 0)
}

fn ioctl(cx: &Cx, sid: u64) -> i64 {
    let n = {
        let u = U.lock();
        let s = &u.socks[&sid];
        match cx.args[1] {
            // FIONREAD / SIOCINQ
            0x541B => u.pair_of(sid).map_or(0, |(p, side)| {
                let q = &u.pairs[&p].q[side];
                if s.ty == SOCK_STREAM {
                    q.bytes
                } else {
                    q.segs.front().map_or(0, |s| s.data.len())
                }
            }),
            // SIOCOUTQ: bytes the peer has not read yet
            0x5411 => u.pair_of(sid).map_or(0, |(p, side)| u.pairs[&p].q[1 - side].bytes),
            r if r & 0xFF00 == 0x5400 => return ENOTTY,
            _ => return EINVAL,
        }
    };
    match cx.copy_out(cx.args[2], &(n as i32).to_le_bytes()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ----------------------------------------------------------------------
// Ends
// ----------------------------------------------------------------------

/// Socket `sid` goes away (its last descriptor closed, or it was never received).
fn close_sock(u: &mut Unix, sid: u64, after: &mut After) {
    let Some(s) = u.socks.remove(&sid) else { return };
    if let Some(slot) = s.slot {
        u.by_slot.remove(&slot);
    }
    for w in s.waits {
        // (a descriptor's last close while its call waits cannot happen: the kernel holds
        // the descriptor during the call; these are calls of a process that ended)
        if let Wait::Send { mut fds, .. } = w {
            after.drop.append(&mut fds);
        }
    }
    match s.state {
        State::Connected { pair, side, .. } => {
            let gone = {
                let p = u.pairs.get_mut(&pair).unwrap();
                let mine = &mut p.q[side];
                mine.read_closed = true;
                mine.bytes = 0;
                let segs = core::mem::take(&mut mine.segs);
                p.q[1 - side].write_closed = true;
                segs
            };
            for mut seg in gone {
                after.drop.append(&mut seg.fds);
            }
            let other = u.pairs[&pair].socks[1 - side];
            if u.socks.contains_key(&other) {
                // The peer's waiting receivers see end of file, its senders EPIPE
                settle(u, other, after);
                fail_senders(u, other, after);
                u.publish(other, true);
            } else {
                u.pairs.remove(&pair);
            }
        }
        State::Listening { pending, .. } => {
            // Connections nobody accepted are refused
            for c in pending {
                close_sock(u, c, after);
            }
        }
        State::Unconnected => {}
    }
    if let Some(addr) = s.local {
        let key = addr.key();
        if u.names.get(&key) == Some(&sid) {
            u.names.remove(&key);
        }
    }
}

/// Fails the senders waiting on socket `sid` whose peer is gone (`EPIPE`, or what they sent).
fn fail_senders(u: &mut Unix, sid: u64, after: &mut After) {
    let Some(s) = u.socks.get_mut(&sid) else { return };
    let mut keep = VecDeque::new();
    for w in s.waits.drain(..) {
        match w {
            Wait::Send { c, done, flags, mut fds, mmsg, .. } => {
                after.drop.append(&mut fds);
                if done > 0 {
                    after.done.push((c.id, finish_send(&c, done as i64, mmsg)));
                } else {
                    if flags & MSG_NOSIGNAL == 0 {
                        after.pipe.push(c.tgid);
                    }
                    after.done.push((c.id, EPIPE));
                }
            }
            w => keep.push_back(w),
        }
    }
    s.waits = keep;
}

/// The last descriptor of socket slot `slot` went away.
pub fn closed(slot: u32) {
    let mut after = After::default();
    {
        let mut u = U.lock();
        if let Some(sid) = u.by_slot.get(&slot).copied() {
            close_sock(&mut u, sid, &mut after);
        }
    }
    after.run();
}

/// A signal for the caller of pending call `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    let mut after = After::default();
    let found = {
        let mut u = U.lock();
        let mut found = None;
        for s in u.socks.values_mut() {
            if let Some(pos) = s.waits.iter().position(|w| w.call().id == id) {
                found = Some(match s.waits.remove(pos).unwrap() {
                    Wait::Send { done, mut fds, c, mmsg, .. } => {
                        after.drop.append(&mut fds);
                        if done > 0 {
                            finish_send(&c, done as i64, mmsg)
                        } else {
                            ERESTARTSYS
                        }
                    }
                    _ => ERESTARTSYS,
                });
                break;
            }
        }
        found
    };
    after.run();
    match found {
        Some(r) => {
            let _ = sys::lx_complete(id, r);
            true
        }
        None => false,
    }
}

/// Process `tgid` ended: its waiting calls are gone.
pub fn on_exit(tgid: u64) {
    let mut after = After::default();
    {
        let mut u = U.lock();
        for s in u.socks.values_mut() {
            let mut keep = VecDeque::new();
            for w in s.waits.drain(..) {
                if w.call().tgid == tgid {
                    if let Wait::Send { mut fds, .. } = w {
                        after.drop.append(&mut fds);
                    }
                } else {
                    keep.push_back(w);
                }
            }
            s.waits = keep;
        }
    }
    after.run();
}

/// `/proc/net/unix`: each socket's flags (`__SO_ACCEPTCON` when listening), type, state (1
/// unconnected or listening, 3 connected), inode and name (abstract names with `@`).
pub fn proc_net_unix() -> alloc::string::String {
    let u = U.lock();
    let mut out = alloc::string::String::from("Num       RefCount Protocol Flags    Type St Inode Path\n");
    for s in u.socks.values() {
        let (flags, st) = match &s.state {
            State::Listening { .. } => (0x10000u32, 1u8),
            State::Connected { .. } => (0, 3),
            State::Unconnected => (0, 1),
        };
        let name = match &s.local {
            Some(Addr::Path { shown, .. }) => alloc::format!(" {}", alloc::string::String::from_utf8_lossy(shown)),
            Some(Addr::Abstract(n)) => alloc::format!(" @{}", alloc::string::String::from_utf8_lossy(n)),
            None => alloc::string::String::new(),
        };
        out.push_str(&alloc::format!("0000000000000000: {:08X} {:08X} {:08X} {:04X} {:02X} {:5}{}\n", 2, 0, flags, s.ty, st, s.ino, name));
    }
    out
}

// ----------------------------------------------------------------------
// Garbage collection of sockets in flight
// ----------------------------------------------------------------------

/// Unix sockets in flight (tokens in queues) since the last collection, roughly: a send
/// carrying many starts a collection early.
static INFLIGHT_SENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Collects sockets alive only through queues nobody can read any more (Linux's `unix_gc`):
/// a socket sent through itself, or sockets in each other's queues, all closed by their
/// programs. A socket is a candidate when every kernel reference to it is a token in our
/// queues (`LX_OBJ_REFS` equals its count in flight); candidates reachable from the queue
/// of a socket that is not a candidate live on; the queues of the others are emptied, which
/// lets the kernel drop them (their ends come back as ordinary closes).
pub fn gc() {
    use alloc::collections::BTreeSet;
    INFLIGHT_SENT.store(0, core::sync::atomic::Ordering::Relaxed);
    let mut after = After::default();
    {
        let mut u = U.lock();
        // Each socket's receive queues: its own, and (listening) its pending connections'
        let queues_of = |u: &Unix, sid: u64| -> Vec<(u64, usize)> {
            let mut v = Vec::new();
            if let Some(ps) = u.pair_of(sid) {
                v.push(ps);
            }
            if let Some(State::Listening { pending, .. }) = u.socks.get(&sid).map(|s| &s.state) {
                for &c in pending {
                    if let Some(ps) = u.pair_of(c) {
                        v.push(ps);
                    }
                }
            }
            v
        };
        let mut inflight: BTreeMap<u32, u64> = BTreeMap::new();
        for p in u.pairs.values() {
            for q in &p.q {
                for seg in &q.segs {
                    for &s in &seg.unix_in {
                        *inflight.entry(s).or_insert(0) += 1;
                    }
                }
            }
        }
        if inflight.is_empty() {
            return;
        }
        let cand: BTreeSet<u32> = inflight.iter().filter(|(&s, &n)| sys::lx_obj(LX_OBJ_REFS, s as u64, 0, 0) == Ok(n)).map(|(&s, _)| s).collect();
        if cand.is_empty() {
            return;
        }
        // What the sockets that are not candidates hold is reachable
        let mut stack: Vec<u32> = Vec::new();
        for (&sid, s) in &u.socks {
            if s.slot.is_some_and(|sl| cand.contains(&sl)) || s.slot.is_none() {
                continue;
            }
            for (pair, side) in queues_of(&u, sid) {
                for seg in &u.pairs[&pair].q[side].segs {
                    stack.extend_from_slice(&seg.unix_in);
                }
            }
        }
        let mut alive: BTreeSet<u32> = BTreeSet::new();
        while let Some(s) = stack.pop() {
            if !cand.contains(&s) || !alive.insert(s) {
                continue;
            }
            if let Some(&sid) = u.by_slot.get(&s) {
                for (pair, side) in queues_of(&u, sid) {
                    for seg in &u.pairs[&pair].q[side].segs {
                        stack.extend_from_slice(&seg.unix_in);
                    }
                }
            }
        }
        for s in cand.difference(&alive) {
            let Some(&sid) = u.by_slot.get(s) else { continue };
            for (pair, side) in queues_of(&u, sid) {
                let q = &mut u.pairs.get_mut(&pair).unwrap().q[side];
                q.bytes = 0;
                for mut seg in core::mem::take(&mut q.segs) {
                    after.drop.append(&mut seg.fds);
                }
            }
        }
    }
    after.run();
}

/// The main thread, about once a second: collects when sockets are in flight.
pub fn gc_tick() {
    let any = U.lock().pairs.values().any(|p| p.q.iter().any(|q| q.segs.iter().any(|s| !s.unix_in.is_empty())));
    if any {
        gc();
    }
}
