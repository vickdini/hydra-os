//! # Unix Domain Sockets (`AF_UNIX`)
//!
//! Local sockets as D-Bus, X11/Wayland clients and most desktop services use them:
//!
//! - stream (`SOCK_STREAM`) and record (`SOCK_SEQPACKET`) sockets with `bind` / `listen`
//!   / `connect` / `accept`, and connected pairs (`socketpair`, also `SOCK_DGRAM`);
//! - filesystem names (`bind` creates a socket node; the name is looked up through the
//!   process root) and abstract names (a leading NUL byte);
//! - descriptor passing (`SCM_RIGHTS`), kept with the bytes it was sent with: a read never
//!   merges data across a message that carries descriptors;
//! - credentials: `SO_PEERCRED` (the peer at connect time) and, with `SO_PASSCRED`,
//!   `SCM_CREDENTIALS` on every received message;
//! - blocking and non-blocking I/O on wait queues, `MSG_PEEK`, `MSG_DONTWAIT`,
//!   `MSG_NOSIGNAL`, `MSG_CMSG_CLOEXEC`, `shutdown`.
//!
//! Each direction of a connection is a queue of segments (one per send, so descriptors and
//! credentials stay attached) bounded at Linux's default buffer size.
//!
//! Not supported: unconnected datagram sockets (`sendto` to a named `SOCK_DGRAM` socket),
//! autobind, `SO_PEERSEC`, `SO_PEERGROUPS`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::fs::FileDescriptor;
use crate::memory::vm::prefault_current;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const AF_UNIX: u32 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_SEQPACKET: u32 = 5;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2000000;

const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_PEEK: u64 = 0x2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const EPIPE: i64 = -32;
const EMSGSIZE: i64 = -90;
const EPROTOTYPE: i64 = -91;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;
const EOPNOTSUPP: i64 = -95;
const EADDRINUSE: i64 = -98;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const ECONNREFUSED: i64 = -111;

/// Bytes a direction buffers before writers wait (Linux's default `wmem`).
const BUFFER_LIMIT: usize = 212_992;
/// Most descriptors one message may carry (`SCM_MAX_FD`).
const MAX_FDS: usize = 253;

/// `struct ucred`.
#[derive(Clone, Copy)]
pub struct Ucred {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl Ucred {
    fn current() -> Self {
        let (_, pid) = super::proc::current_ids();
        let c = super::vfs::creds();
        Self { pid: pid as u32, uid: c.euid, gid: c.egid }
    }

    fn bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..12].copy_from_slice(&self.gid.to_le_bytes());
        b
    }
}

/// A socket name: a path (as given, plus its lookup key) or an abstract name.
#[derive(Clone)]
enum Addr {
    Path { shown: Vec<u8>, key: Vec<u8> },
    Abstract(Vec<u8>),
}

impl Addr {
    fn key(&self) -> Vec<u8> {
        match self {
            Addr::Path { key, .. } => key.clone(),
            Addr::Abstract(name) => {
                let mut k = alloc::vec![0u8];
                k.extend_from_slice(name);
                k
            }
        }
    }

    /// `struct sockaddr_un` image and its length.
    fn sockaddr(addr: Option<&Addr>) -> Vec<u8> {
        let mut b = (AF_UNIX as u16).to_le_bytes().to_vec();
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

/// One send: its bytes, and the descriptors and credentials that came with them.
struct Segment {
    data: Vec<u8>,
    pos: usize,
    fds: Vec<FileDescriptor>,
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

/// A connection: side `s` reads `q[s]` and writes `q[1 - s]`.
struct Pair {
    q: [Mutex<Queue>; 2],
    wq: Arc<WaitQueue>,
}

enum State {
    Unconnected,
    Listening { backlog: usize, pending: VecDeque<Arc<UnixSocket>>, cred: Ucred },
    Connected { pair: Arc<Pair>, side: usize, peer_cred: Ucred, peer_addr: Option<Addr> },
}

pub struct UnixSocket {
    ty: u32,
    state: Mutex<State>,
    local: Mutex<Option<Addr>>,
    nonblock: AtomicBool,
    passcred: AtomicBool,
    shut_rd: AtomicBool,
    /// Accept and connect waiters.
    wq: Arc<WaitQueue>,
    /// Inode number reported by `fstat`.
    ino: u64,
}

static NEXT_INO: AtomicU64 = AtomicU64::new(0x5000_0000);
/// Bound names (filesystem keys and abstract names) to their sockets.
static NAMES: Mutex<BTreeMap<Vec<u8>, Weak<UnixSocket>>> = Mutex::new(BTreeMap::new());

impl Drop for UnixSocket {
    fn drop(&mut self) {
        let state = core::mem::replace(&mut *self.state.lock(), State::Unconnected);
        match state {
            State::Connected { pair, side, .. } => {
                {
                    let mut mine = pair.q[side].lock();
                    mine.read_closed = true;
                    mine.segs.clear(); // undelivered descriptors are closed
                    mine.bytes = 0;
                }
                pair.q[1 - side].lock().write_closed = true;
                pair.wq.wake_all();
            }
            State::Listening { pending, .. } => drop(pending), // refuses the queued connections
            State::Unconnected => {}
        }
        if let Some(addr) = self.local.lock().take() {
            let mut names = NAMES.lock();
            let key = addr.key();
            if names.get(&key).map_or(false, |w| w.strong_count() == 0) {
                names.remove(&key);
            }
        }
    }
}

impl UnixSocket {
    fn new(ty: u32, nonblock: bool) -> Arc<Self> {
        Arc::new(Self {
            ty,
            state: Mutex::new(State::Unconnected),
            local: Mutex::new(None),
            nonblock: AtomicBool::new(nonblock),
            passcred: AtomicBool::new(false),
            shut_rd: AtomicBool::new(false),
            wq: WaitQueue::new_shared(),
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    fn pair(&self) -> Option<(Arc<Pair>, usize)> {
        match &*self.state.lock() {
            State::Connected { pair, side, .. } => Some((pair.clone(), *side)),
            _ => None,
        }
    }

    /// Wait queues announcing readiness changes.
    pub fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.wq.clone()));
        if let Some((pair, _)) = self.pair() {
            waits.add(QueueRef::Shared(pair.wq.clone()));
        }
    }

    pub fn poll_events(&self) -> u32 {
        const POLLIN: u32 = 0x1;
        const POLLOUT: u32 = 0x4;
        const POLLHUP: u32 = 0x10;
        const POLLRDHUP: u32 = 0x2000;
        match &*self.state.lock() {
            State::Listening { pending, .. } => {
                if pending.is_empty() {
                    0
                } else {
                    POLLIN
                }
            }
            State::Connected { pair, side, .. } => {
                let mut ev = 0;
                let (readable, eof) = {
                    let q = pair.q[*side].lock();
                    (!q.segs.is_empty(), q.write_closed)
                };
                let (room, peer_gone) = {
                    let q = pair.q[1 - side].lock();
                    (q.bytes < BUFFER_LIMIT, q.read_closed)
                };
                if readable || eof || self.shut_rd.load(Ordering::Relaxed) {
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

    /// Bytes ready to read (`FIONREAD`).
    pub fn pending_bytes(&self) -> usize {
        match self.pair() {
            Some((pair, side)) => {
                let q = pair.q[side].lock();
                if self.ty == SOCK_STREAM {
                    q.bytes
                } else {
                    q.segs.front().map_or(0, |s| s.data.len())
                }
            }
            None => 0,
        }
    }

    /// Sends `data` with `fds`. Returns the bytes sent or an error.
    fn send(&self, data: &[u8], mut fds: Vec<FileDescriptor>, flags: u64) -> i64 {
        let (pair, side) = match self.pair() {
            Some(p) => p,
            None => return ENOTCONN,
        };
        let nonblock = self.get_nonblock() || flags & MSG_DONTWAIT != 0;
        let record = self.ty != SOCK_STREAM;
        if record && data.len() > BUFFER_LIMIT {
            return EMSGSIZE;
        }
        let cred = Ucred::current();
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(pair.wq.clone()));
        let mut sent = 0;
        loop {
            waits.register();
            {
                let mut q = pair.q[1 - side].lock();
                if q.read_closed || q.write_closed {
                    drop(q);
                    if sent > 0 {
                        return sent as i64;
                    }
                    if flags & MSG_NOSIGNAL == 0 {
                        let (tid, pid) = super::proc::current_ids();
                        super::proc::post_thread(pid, tid, super::proc::SIGPIPE);
                    }
                    return EPIPE;
                }
                let room = BUFFER_LIMIT.saturating_sub(q.bytes);
                let fits = if record { room >= data.len() || q.segs.is_empty() } else { room > 0 || data.is_empty() };
                if fits {
                    let n = if record { data.len() } else { room.min(data.len() - sent) };
                    q.segs.push_back(Segment {
                        data: data[sent..sent + n].to_vec(),
                        pos: 0,
                        fds: core::mem::take(&mut fds),
                        cred,
                    });
                    q.bytes += n;
                    sent += n;
                    drop(q);
                    pair.wq.wake_all();
                    if sent == data.len() {
                        return sent as i64;
                    }
                    continue;
                }
            }
            if nonblock {
                return if sent > 0 { sent as i64 } else { EAGAIN };
            }
            if super::proc::signal_pending() {
                return if sent > 0 { sent as i64 } else { super::proc::ERESTARTSYS };
            }
            waits.wait(None);
        }
    }

    /// Receives into `buf`. Returns (bytes, descriptors, sender credentials, truncated).
    fn recv(&self, buf: &mut [u8], flags: u64) -> Result<(usize, Vec<FileDescriptor>, Option<Ucred>, bool), i64> {
        let (pair, side) = match self.pair() {
            Some(p) => p,
            None => return Err(ENOTCONN),
        };
        let nonblock = self.get_nonblock() || flags & MSG_DONTWAIT != 0;
        let peek = flags & MSG_PEEK != 0;
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(pair.wq.clone()));
        loop {
            waits.register();
            {
                let mut q = pair.q[side].lock();
                if !q.segs.is_empty() && !self.shut_rd.load(Ordering::Relaxed) {
                    let r = if self.ty == SOCK_STREAM { take_stream(&mut q, buf, peek) } else { take_record(&mut q, buf, peek) };
                    drop(q);
                    if !peek {
                        pair.wq.wake_all(); // room for writers
                    }
                    return Ok(r);
                }
                if q.write_closed || self.shut_rd.load(Ordering::Relaxed) {
                    return Ok((0, Vec::new(), None, false));
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if super::proc::signal_pending() {
                return Err(super::proc::ERESTARTSYS);
            }
            waits.wait(None);
        }
    }

    /// `read` on the socket (descriptors that arrive are closed).
    pub fn read(&self, buf: &mut [u8]) -> i64 {
        match self.recv(buf, 0) {
            Ok((n, _, _, _)) => n as i64,
            Err(e) => e,
        }
    }

    pub fn write(&self, data: &[u8]) -> i64 {
        self.send(data, Vec::new(), 0)
    }
}

/// Stream read: as many bytes as fit, but never past a segment carrying descriptors once
/// data has been taken, and never beyond the first segment that carries some.
fn take_stream(q: &mut Queue, buf: &mut [u8], peek: bool) -> (usize, Vec<FileDescriptor>, Option<Ucred>, bool) {
    let mut n = 0;
    let mut fds = Vec::new();
    let cred = q.segs.front().map(|s| s.cred);
    let mut i = 0;
    while n < buf.len() && i < q.segs.len() {
        let seg = &mut q.segs[i];
        if n > 0 && !seg.fds.is_empty() {
            break;
        }
        let take = (seg.data.len() - seg.pos).min(buf.len() - n);
        buf[n..n + take].copy_from_slice(&seg.data[seg.pos..seg.pos + take]);
        n += take;
        let had_fds = !seg.fds.is_empty();
        if !peek {
            fds.append(&mut seg.fds);
            seg.pos += take;
        }
        i += 1;
        if had_fds {
            break;
        }
    }
    if !peek {
        q.bytes -= n;
        while q.segs.front().map_or(false, |s| s.pos >= s.data.len()) {
            q.segs.pop_front();
        }
    }
    (n, fds, cred, false)
}

/// Record read: one whole message (the rest of it is discarded if `buf` is short).
fn take_record(q: &mut Queue, buf: &mut [u8], peek: bool) -> (usize, Vec<FileDescriptor>, Option<Ucred>, bool) {
    let seg = q.segs.front_mut().unwrap();
    let n = seg.data.len().min(buf.len());
    buf[..n].copy_from_slice(&seg.data[..n]);
    let truncated = seg.data.len() > n;
    let cred = Some(seg.cred);
    if peek {
        return (n, Vec::new(), cred, truncated);
    }
    let seg = q.segs.pop_front().unwrap();
    q.bytes -= seg.data.len();
    (n, seg.fds, cred, truncated)
}

// ----------------------------------------------------------------------
// User memory helpers
// ----------------------------------------------------------------------

fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr == 0 || !prefault_current(ptr, len as u64, false) {
        return Err(EFAULT);
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Ok(v)
}

fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Ok(());
    }
    if ptr == 0 || !prefault_current(ptr, data.len() as u64, true) {
        return Err(EFAULT);
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    Ok(())
}

fn read_u32(ptr: u64) -> Result<u32, i64> {
    let b = copy_in(ptr, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Writes a socket address to (`addr`, `*len_ptr`), truncating to the caller's buffer
/// and storing the full length, as Linux does.
fn put_sockaddr(addr_ptr: u64, len_ptr: u64, sa: &[u8]) -> Result<(), i64> {
    if addr_ptr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let cap = read_u32(len_ptr)? as usize;
    copy_out(addr_ptr, &sa[..sa.len().min(cap)])?;
    copy_out(len_ptr, &(sa.len() as u32).to_le_bytes())
}

/// Parses a `struct sockaddr_un`.
fn read_addr(ptr: u64, len: u64) -> Result<Addr, i64> {
    if len < 2 || len > 110 {
        return Err(EINVAL);
    }
    let b = copy_in(ptr, len as usize)?;
    if u16::from_le_bytes([b[0], b[1]]) as u32 != AF_UNIX {
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
    let shown = name[..end].to_vec();
    if shown.is_empty() {
        return Err(EINVAL);
    }
    let key = super::vfs::socket_key(&shown)?;
    Ok(Addr::Path { shown, key })
}

// ----------------------------------------------------------------------
// Control messages
// ----------------------------------------------------------------------

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Descriptors named by the `SCM_RIGHTS` messages in a control buffer.
fn parse_control(ptr: u64, len: u64) -> Result<Vec<FileDescriptor>, i64> {
    let mut fds = Vec::new();
    if ptr == 0 || len < 16 {
        return Ok(fds);
    }
    let buf = copy_in(ptr, len as usize)?;
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
                let desc = crate::task::with_current_fds_mut(|t| if fd < 0 { None } else { t.get(fd as usize).cloned() });
                fds.push(desc.ok_or(EBADF)?);
                if fds.len() > MAX_FDS {
                    return Err(EINVAL);
                }
            }
        }
        // SCM_CREDENTIALS: the kernel attaches the sender's real credentials anyway
        off += align8(clen);
    }
    Ok(fds)
}

/// Builds the received control messages into the caller's buffer: installs descriptors
/// (closing those that do not fit) and adds credentials. Returns (bytes used, flags).
fn build_control(ptr: u64, cap: usize, fds: Vec<FileDescriptor>, cred: Option<Ucred>, cloexec: bool) -> Result<(usize, u32), i64> {
    let mut out = Vec::new();
    let mut flags = 0;
    if !fds.is_empty() {
        let room = if cap >= 16 { (cap - 16) / 4 } else { 0 };
        if room < fds.len() {
            flags |= MSG_CTRUNC;
        }
        let mut nums = Vec::new();
        for desc in fds.into_iter().take(room) {
            let fd = crate::task::with_current_fds_mut(|t| match t.alloc_fd(desc) {
                Ok(n) => {
                    t.set_cloexec(n, cloexec);
                    Ok(n as i32)
                }
                Err(_) => Err(EMFILE),
            })?;
            nums.push(fd);
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
    copy_out(ptr, &out[..used])?;
    Ok((used, flags))
}

/// (base, len) pairs of an iovec array.
fn read_iov(ptr: u64, count: u64) -> Result<Vec<(u64, u64)>, i64> {
    if count > 1024 {
        return Err(EINVAL);
    }
    let raw = copy_in(ptr, count as usize * 16)?;
    Ok(raw
        .chunks_exact(16)
        .map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap())))
        .collect())
}

fn gather(iov: &[(u64, u64)]) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    for &(base, len) in iov {
        data.extend_from_slice(&copy_in(base, len as usize)?);
    }
    Ok(data)
}

fn scatter(iov: &[(u64, u64)], data: &[u8]) -> Result<(), i64> {
    let mut off = 0;
    for &(base, len) in iov {
        if off >= data.len() {
            break;
        }
        let n = (len as usize).min(data.len() - off);
        copy_out(base, &data[off..off + n])?;
        off += n;
    }
    Ok(())
}

// ----------------------------------------------------------------------
// System calls
// ----------------------------------------------------------------------

fn install(sock: Arc<UnixSocket>, cloexec: bool) -> i64 {
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(FileDescriptor::Unix(sock)) {
        Ok(fd) => {
            fds.set_cloexec(fd, cloexec);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

fn socket_of(fd: u64) -> Option<Arc<UnixSocket>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(FileDescriptor::Unix(s)) => Some(s.clone()),
        _ => None,
    })
}

fn sock_type(ty: u64) -> Result<u32, i64> {
    match ty as u32 & 0xf {
        t @ (SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) => Ok(t),
        _ => Err(EPROTONOSUPPORT),
    }
}

fn bind(sock: &Arc<UnixSocket>, addr_ptr: u64, len: u64) -> i64 {
    let addr = match read_addr(addr_ptr, len) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if sock.local.lock().is_some() {
        return EINVAL;
    }
    let key = addr.key();
    let mut names = NAMES.lock();
    if names.get(&key).map_or(false, |w| w.strong_count() > 0) {
        return EADDRINUSE;
    }
    if let Addr::Path { shown, .. } = &addr {
        // The name is a socket node in the file system (EADDRINUSE if the path exists)
        if let Err(e) = super::vfs::make_socket_node(shown) {
            return if e == -17 { EADDRINUSE } else { e };
        }
    }
    names.insert(key, Arc::downgrade(sock));
    *sock.local.lock() = Some(addr);
    0
}

fn listen(sock: &Arc<UnixSocket>, backlog: u64) -> i64 {
    if sock.ty == SOCK_DGRAM {
        return EOPNOTSUPP;
    }
    let mut st = sock.state.lock();
    match &mut *st {
        State::Listening { backlog: b, .. } => {
            *b = backlog as usize;
            0
        }
        State::Unconnected => {
            if sock.local.lock().is_none() {
                return EINVAL; // autobind is not supported
            }
            *st = State::Listening { backlog: backlog as usize, pending: VecDeque::new(), cred: Ucred::current() };
            0
        }
        State::Connected { .. } => EINVAL,
    }
}

fn connect(sock: &Arc<UnixSocket>, addr_ptr: u64, len: u64) -> i64 {
    let addr = match read_addr(addr_ptr, len) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if !matches!(*sock.state.lock(), State::Unconnected) {
        return EISCONN;
    }
    let target = NAMES.lock().get(&addr.key()).and_then(|w| w.upgrade());
    let listener = match target {
        Some(l) => l,
        None => {
            return match &addr {
                Addr::Path { shown, .. } if super::vfs::path_exists(shown) => ECONNREFUSED,
                Addr::Path { .. } => ENOENT,
                Addr::Abstract(_) => ECONNREFUSED,
            };
        }
    };
    if listener.ty != sock.ty {
        return EPROTOTYPE;
    }
    if sock.ty == SOCK_DGRAM {
        return ECONNREFUSED; // unconnected datagram sockets are not supported
    }
    let me = Ucred::current();
    let mut lst = listener.state.lock();
    let listen_cred = match &*lst {
        State::Listening { cred, .. } => *cred,
        _ => return ECONNREFUSED,
    };
    let pair = Arc::new(Pair { q: [Mutex::new(Queue::default()), Mutex::new(Queue::default())], wq: WaitQueue::new_shared() });
    let server = UnixSocket::new(sock.ty, false);
    *server.local.lock() = listener.local.lock().clone();
    *server.state.lock() = State::Connected {
        pair: pair.clone(),
        side: 1,
        peer_cred: me,
        peer_addr: sock.local.lock().clone(),
    };
    *sock.state.lock() = State::Connected { pair, side: 0, peer_cred: listen_cred, peer_addr: listener.local.lock().clone() };
    if let State::Listening { pending, .. } = &mut *lst {
        pending.push_back(server);
    }
    drop(lst);
    listener.wq.wake_all();
    0
}

fn accept(sock: &Arc<UnixSocket>, addr_ptr: u64, len_ptr: u64, flags: u64) -> i64 {
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Shared(sock.wq.clone()));
    loop {
        waits.register();
        let conn = match &mut *sock.state.lock() {
            State::Listening { pending, .. } => pending.pop_front(),
            _ => return EINVAL,
        };
        if let Some(c) = conn {
            c.set_nonblock(flags as u32 & SOCK_NONBLOCK != 0);
            let peer = match &*c.state.lock() {
                State::Connected { peer_addr, .. } => peer_addr.clone(),
                _ => None,
            };
            if let Err(e) = put_sockaddr(addr_ptr, len_ptr, &Addr::sockaddr(peer.as_ref())) {
                return e;
            }
            return install(c, flags as u32 & SOCK_CLOEXEC != 0);
        }
        if sock.get_nonblock() {
            return EAGAIN;
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        waits.wait(None);
    }
}

fn sendmsg(sock: &Arc<UnixSocket>, msg: u64, flags: u64) -> i64 {
    let hdr = match copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let f = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
    let (name, iov, iovlen, control, controllen) = (f(0), f(16), f(24), f(32), f(40));
    if name != 0 && !matches!(*sock.state.lock(), State::Connected { .. }) {
        return if sock.ty == SOCK_DGRAM { EOPNOTSUPP } else { EISCONN };
    }
    let r: Result<i64, i64> = (|| {
        let iov = read_iov(iov, iovlen)?;
        let data = gather(&iov)?;
        let fds = parse_control(control, controllen)?;
        Ok(sock.send(&data, fds, flags))
    })();
    r.unwrap_or_else(|e| e)
}

fn recvmsg(sock: &Arc<UnixSocket>, msg: u64, flags: u64) -> i64 {
    let hdr = match copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let f = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
    let (iov, iovlen, control, controllen) = (f(16), f(24), f(32), f(40));
    let r: Result<i64, i64> = (|| {
        let iov = read_iov(iov, iovlen)?;
        let total: usize = iov.iter().map(|&(_, l)| l as usize).sum();
        let mut buf = alloc::vec![0u8; total];
        let (n, fds, cred, truncated) = sock.recv(&mut buf, flags)?;
        scatter(&iov, &buf[..n])?;
        let cred = if sock.passcred.load(Ordering::Relaxed) { cred } else { None };
        let (used, mut mflags) = build_control(control, controllen as usize, fds, cred, flags & MSG_CMSG_CLOEXEC != 0)?;
        if truncated {
            mflags |= MSG_TRUNC;
        }
        // msg_namelen = 0 (connected sockets), msg_controllen, msg_flags
        copy_out(msg + 8, &0u32.to_le_bytes())?;
        copy_out(msg + 40, &(used as u64).to_le_bytes())?;
        copy_out(msg + 48, &mflags.to_le_bytes())?;
        Ok(n as i64)
    })();
    r.unwrap_or_else(|e| e)
}

fn getsockopt(sock: &Arc<UnixSocket>, level: u64, opt: u64, val: u64, len_ptr: u64) -> i64 {
    if level as u32 != SOL_SOCKET {
        return ENOPROTOOPT;
    }
    let int = |v: u32| v.to_le_bytes().to_vec();
    let bytes = match opt {
        3 => int(sock.ty),                                                    // SO_TYPE
        4 => int(0),                                                          // SO_ERROR
        7 | 8 => int(BUFFER_LIMIT as u32),                                    // SO_SNDBUF, SO_RCVBUF
        16 => int(sock.passcred.load(Ordering::Relaxed) as u32),              // SO_PASSCRED
        17 => match &*sock.state.lock() {
            // SO_PEERCRED
            State::Connected { peer_cred, .. } => peer_cred.bytes().to_vec(),
            State::Listening { cred, .. } => cred.bytes().to_vec(),
            State::Unconnected => Ucred { pid: 0, uid: u32::MAX, gid: u32::MAX }.bytes().to_vec(),
        },
        30 => int(matches!(*sock.state.lock(), State::Listening { .. }) as u32), // SO_ACCEPTCONN
        38 => int(0),                                                         // SO_PROTOCOL
        39 => int(AF_UNIX),                                                   // SO_DOMAIN
        20 | 21 => alloc::vec![0u8; 16],                                      // SO_RCVTIMEO, SO_SNDTIMEO
        _ => return ENOPROTOOPT,
    };
    let r: Result<i64, i64> = (|| {
        let cap = read_u32(len_ptr)? as usize;
        copy_out(val, &bytes[..bytes.len().min(cap)])?;
        copy_out(len_ptr, &(bytes.len().min(cap) as u32).to_le_bytes())?;
        Ok(0)
    })();
    r.unwrap_or_else(|e| e)
}

fn setsockopt(sock: &Arc<UnixSocket>, level: u64, opt: u64, val: u64, len: u64) -> i64 {
    if level as u32 != SOL_SOCKET {
        return ENOPROTOOPT;
    }
    if opt == 16 {
        // SO_PASSCRED
        if len < 4 {
            return EINVAL;
        }
        match read_u32(val) {
            Ok(v) => sock.passcred.store(v != 0, Ordering::Relaxed),
            Err(e) => return e,
        }
    }
    0 // buffer sizes, timeouts and the like are accepted and ignored
}

fn shutdown(sock: &Arc<UnixSocket>, how: u64) -> i64 {
    let (pair, side) = match sock.pair() {
        Some(p) => p,
        None => return ENOTCONN,
    };
    if how > 2 {
        return EINVAL;
    }
    if how != 1 {
        sock.shut_rd.store(true, Ordering::Relaxed);
    }
    if how != 0 {
        pair.q[1 - side].lock().write_closed = true;
    }
    pair.wq.wake_all();
    0
}

/// Handles `AF_UNIX` socket calls. `None` for other families and descriptors.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    match num {
        41 => {
            // socket(domain, type, protocol)
            if a[0] as u32 != AF_UNIX {
                return None;
            }
            if a[2] != 0 && a[2] != 1 {
                return Some(EPROTONOSUPPORT);
            }
            return Some(match sock_type(a[1]) {
                Ok(t) => install(UnixSocket::new(t, a[1] as u32 & SOCK_NONBLOCK != 0), a[1] as u32 & SOCK_CLOEXEC != 0),
                Err(e) => e,
            });
        }
        53 => {
            // socketpair(domain, type, protocol, sv[2])
            if a[0] as u32 != AF_UNIX {
                return None;
            }
            let ty = match sock_type(a[1]) {
                Ok(t) => t,
                Err(e) => return Some(e),
            };
            let nonblock = a[1] as u32 & SOCK_NONBLOCK != 0;
            let cloexec = a[1] as u32 & SOCK_CLOEXEC != 0;
            let me = Ucred::current();
            let pair = Arc::new(Pair { q: [Mutex::new(Queue::default()), Mutex::new(Queue::default())], wq: WaitQueue::new_shared() });
            let x = UnixSocket::new(ty, nonblock);
            let y = UnixSocket::new(ty, nonblock);
            *x.state.lock() = State::Connected { pair: pair.clone(), side: 0, peer_cred: me, peer_addr: None };
            *y.state.lock() = State::Connected { pair, side: 1, peer_cred: me, peer_addr: None };
            let fx = install(x, cloexec);
            if fx < 0 {
                return Some(fx);
            }
            let fy = install(y, cloexec);
            if fy < 0 {
                crate::task::with_current_fds_mut(|fds| fds.close(fx as usize).ok());
                return Some(fy);
            }
            let mut sv = [0u8; 8];
            sv[0..4].copy_from_slice(&(fx as i32).to_le_bytes());
            sv[4..8].copy_from_slice(&(fy as i32).to_le_bytes());
            return Some(match copy_out(a[3], &sv) {
                Ok(()) => 0,
                Err(e) => e,
            });
        }
        42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 | 54 | 55 | 288 | 299 | 307 => {}
        _ => return None,
    }
    let sock = socket_of(a[0])?;
    Some(match num {
        49 => bind(&sock, a[1], a[2]),
        50 => listen(&sock, a[1]),
        42 => connect(&sock, a[1], a[2]),
        43 => accept(&sock, a[1], a[2], 0),
        288 => accept(&sock, a[1], a[2], a[3]),
        44 => {
            // sendto(fd, buf, len, flags, dest, addrlen): the destination must be the peer
            if a[4] != 0 && !matches!(*sock.state.lock(), State::Connected { .. }) {
                return Some(if sock.ty == SOCK_DGRAM { EOPNOTSUPP } else { ENOTCONN });
            }
            match copy_in(a[1], a[2] as usize) {
                Ok(d) => sock.send(&d, Vec::new(), a[3]),
                Err(e) => e,
            }
        }
        45 => {
            // recvfrom(fd, buf, len, flags, src, addrlen)
            let mut buf = alloc::vec![0u8; a[2] as usize];
            match sock.recv(&mut buf, a[3]) {
                Ok((n, _, _, _)) => match copy_out(a[1], &buf[..n]) {
                    Ok(()) => {
                        if a[5] != 0 {
                            let _ = copy_out(a[5], &0u32.to_le_bytes());
                        }
                        n as i64
                    }
                    Err(e) => e,
                },
                Err(e) => e,
            }
        }
        46 => sendmsg(&sock, a[1], a[2]),
        47 => recvmsg(&sock, a[1], a[2]),
        307 | 299 => {
            // sendmmsg / recvmmsg: one message at a time (struct mmsghdr is 64 bytes)
            let mut done = 0u64;
            while done < a[2] {
                let m = a[1] + done * 64;
                let r = if num == 307 { sendmsg(&sock, m, a[3]) } else { recvmsg(&sock, m, a[3]) };
                if r < 0 {
                    if done == 0 {
                        return Some(r);
                    }
                    break;
                }
                if copy_out(m + 56, &(r as u32).to_le_bytes()).is_err() {
                    break;
                }
                done += 1;
                if num == 299 {
                    break; // return what is there rather than waiting for more
                }
            }
            done as i64
        }
        48 => shutdown(&sock, a[1]),
        51 => match put_sockaddr(a[1], a[2], &Addr::sockaddr(sock.local.lock().as_ref())) {
            Ok(()) => 0,
            Err(e) => e,
        },
        52 => {
            let peer = match &*sock.state.lock() {
                State::Connected { peer_addr, .. } => Some(peer_addr.clone()),
                _ => None,
            };
            match peer {
                Some(p) => match put_sockaddr(a[1], a[2], &Addr::sockaddr(p.as_ref())) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                None => ENOTCONN,
            }
        }
        54 => setsockopt(&sock, a[1], a[2], a[3], a[4]),
        55 => getsockopt(&sock, a[1], a[2], a[3], a[4]),
        _ => EINVAL,
    })
}

/// `ioctl` on a Unix socket.
pub fn ioctl(sock: &Arc<UnixSocket>, request: u64, arg: u64) -> i64 {
    match request {
        0x5421 => match read_u32(arg) {
            // FIONBIO
            Ok(v) => {
                sock.set_nonblock(v != 0);
                0
            }
            Err(e) => e,
        },
        0x541B => match copy_out(arg, &(sock.pending_bytes() as i32).to_le_bytes()) {
            // FIONREAD / SIOCINQ
            Ok(()) => 0,
            Err(e) => e,
        },
        0x5411 => {
            // SIOCOUTQ: bytes the peer has not read yet
            let n = sock.pair().map_or(0, |(p, side)| p.q[1 - side].lock().bytes);
            match copy_out(arg, &(n as i32).to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        r if r & 0xFF00 == 0x5400 => -25, // ENOTTY
        _ => EINVAL,
    }
}
