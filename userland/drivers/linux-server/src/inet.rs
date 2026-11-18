//! `AF_INET` and `AF_INET6` sockets (wave 5, step 3): the kernel's
//! `src/compat/linux/inet.rs` (which stays for `lx=kernel`), moved here. TCP, UDP and ICMP
//! (ping and raw) sockets over net-server ([`crate::netc`]); each socket is a server object
//! of kind [`LX_OBJ_KIND_INET`].
//!
//! What changed from the kernel's copy:
//! - a call never waits here: where the kernel slept on the socket's wait queue, the call
//!   answers [`Out::Block`] and [`crate::socket`] keeps it pending and tries it again when
//!   the socket's readiness changes (a stream send remembers how much it sent: [`Prog`]);
//! - the caller's memory through [`Cx`] (the copy-in table's page, or the client memory
//!   primitives), its identity from the call (capabilities, effective user), its network
//!   namespace from the call's flags ([`LX_OBJ_FLAGS_NETNS`]); Landlock's port rules and
//!   `SIGPIPE` through the kernel (`LX_OBJ_NETCHECK`, `LX_OBJ_SIGTHREAD`);
//! - readiness goes to the object's readiness word ([`refresh`]); `/proc/net/{tcp,udp}[6]`
//!   are made here ([`proc_net`]) since only we know which socket owns a connection.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;
use crate::netc as stack;
use crate::socket::{Out, Prog};
use crate::sockopt::{Options, SockInfo};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2000000;

const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;

const EPERM: i64 = -1;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const ENOTSOCK: i64 = -88;
const EDESTADDRREQ: i64 = -89;
const EPROTONOSUPPORT: i64 = -93;
const ESOCKTNOSUPPORT: i64 = -94;
const EOPNOTSUPP: i64 = -95;
const EAFNOSUPPORT: i64 = -97;
const EADDRNOTAVAIL: i64 = -99;
const ENETUNREACH: i64 = -101;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const EALREADY: i64 = -114;
const EINPROGRESS: i64 = -115;

/// `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`.
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_RAW: u32 = 13;
/// Landlock accesses (`LX_OBJ_NETCHECK`).
const BIND_TCP: u64 = 1;
const CONNECT_TCP: u64 = 2;

/// One socket.
pub struct Sock {
    /// net-server's instance it was made under ([`stack::gen`]): an older one is dead.
    gen: u64,
    stream: bool,
    tcp: Option<u32>,
    udp: Option<u32>,
    bound_port: u16,
    peer: Option<([u8; 4], u16)>,
    shut_rd: bool,
    opts: Options,
    bound_ip: [u8; 4],
    bind_id: Option<u32>,
    listener: Option<u32>,
    /// Owner (the creator's effective user ID), for `/proc/net`.
    uid: u32,
    udp_used: bool,
    v6: bool,
    icmp: Option<u32>,
    raw: bool,
    rx_stamp: Option<u64>,
    /// The number `/proc/<pid>/fd` and `/proc/net` show (`socket:[inode]`).
    inode: u64,
}

impl Sock {
    fn dead(&self) -> bool {
        self.gen != stack::gen()
    }

    /// Poll bits (`POLLIN 1`, `POLLOUT 4`, `POLLERR 8`, `POLLHUP 0x10`).
    fn poll_events(&self) -> u32 {
        if self.dead() {
            return 0x19;
        }
        if let Some(id) = self.icmp {
            return 0x4 | stack::icmp_readable(id) as u32;
        }
        if let Some(id) = self.listener {
            return stack::tcp_acceptable(id) as u32;
        }
        if let Some(id) = self.tcp {
            let (r, w, hup, err) = stack::tcp_poll(id);
            return (r as u32) | (w as u32) << 2 | (err as u32) << 3 | (hup as u32) << 4;
        }
        if self.stream {
            return 0x4;
        }
        0x4 | self.udp.is_some_and(stack::udp_readable) as u32
    }

    /// The UDP handle, opened on first use.
    fn udp_id(&mut self, slot: u32) -> Result<u32, i64> {
        if let Some(id) = self.udp {
            return Ok(id);
        }
        let id = stack::udp_open(self.bound_port)?;
        self.udp = Some(id);
        track(id, slot);
        Ok(id)
    }

    /// Every net-server handle it holds.
    fn handles(&self) -> [Option<u32>; 5] {
        [self.icmp, self.listener, self.bind_id, self.tcp, self.udp]
    }

    /// Closes its handles in net-server (its last descriptor went).
    fn close(&mut self) {
        if self.dead() {
            return;
        }
        if let Some(id) = self.icmp.take() {
            stack::icmp_close(id);
        }
        if let Some(id) = self.listener.take() {
            stack::tcp_unlisten(id);
        }
        if let Some(id) = self.bind_id.take() {
            stack::tcp_unbind(id);
        }
        if let Some(id) = self.tcp.take() {
            stack::tcp_close(id);
        }
        if let Some(id) = self.udp.take() {
            stack::udp_close(id);
        }
    }
}

/// The sockets, by slot.
static SOCKS: YLock<BTreeMap<u32, Arc<YLock<Sock>>>> = YLock::new(BTreeMap::new());
/// net-server handles to the slots holding them (to relay readiness).
static HMAP: YLock<BTreeMap<u32, u32>> = YLock::new(BTreeMap::new());
/// Next inode number.
static INODE: AtomicU64 = AtomicU64::new(0x8000);

/// Handles net-server reported events for before we knew them (a connection's handshake
/// can finish between net-server's answer to `TCP_CONNECT` and our recording the handle):
/// the most recent ones, checked when a handle is recorded. Kept under [`HMAP`]'s lock.
static ORPHANS: YLock<[u32; 64]> = YLock::new([0; 64]);
static ORPHAN_NEXT: AtomicU64 = AtomicU64::new(0);

/// Records that handle `h` is slot `slot`'s; an event that came for it before counts now.
fn track(h: u32, slot: u32) {
    let early = {
        let mut m = HMAP.lock();
        m.insert(h, slot);
        let mut o = ORPHANS.lock();
        match o.iter().position(|&x| x == h) {
            Some(i) => {
                o[i] = 0;
                true
            }
            None => false,
        }
    };
    if early {
        crate::socket::poke(slot);
    }
}

fn sock_of(slot: u32) -> Option<Arc<YLock<Sock>>> {
    SOCKS.lock().get(&slot).cloned()
}

/// The slots holding any of `handles`.
pub fn slots_of(handles: &[u32]) -> Vec<u32> {
    let m = HMAP.lock();
    let mut v: Vec<u32> = Vec::new();
    for &h in handles {
        match m.get(&h) {
            Some(&s) => v.push(s),
            None if h != 0 => {
                // Not ours, or not recorded yet (see ORPHANS)
                let mut o = ORPHANS.lock();
                let i = ORPHAN_NEXT.fetch_add(1, Ordering::Relaxed) as usize % 64;
                o[i] = h;
            }
            None => {}
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// Every socket's slot.
pub fn all_slots() -> Vec<u32> {
    SOCKS.lock().keys().copied().collect()
}

/// Writes slot `slot`'s readiness word (`event`: something new happened on it).
pub fn refresh(slot: u32, event: bool) {
    if let Some(s) = sock_of(slot) {
        let bits = s.lock().poll_events();
        crate::obj::set_ready_ev(slot, bits, 0, event);
    }
}

/// The last descriptor of slot `slot` went away.
pub fn closed(slot: u32) {
    let Some(s) = SOCKS.lock().remove(&slot) else { return };
    let mut s = s.lock();
    {
        let mut m = HMAP.lock();
        for h in s.handles().into_iter().flatten() {
            if m.get(&h) == Some(&slot) {
                m.remove(&h);
            }
        }
    }
    s.close();
}

// ----------------------------------------------------------------------
// Helpers on the caller's memory
// ----------------------------------------------------------------------

fn isolated(cx: &Cx) -> bool {
    cx.c.obj_flags & LX_OBJ_FLAGS_NETNS != 0
}

/// Parses a `struct sockaddr_in`/`sockaddr_in6` at `(ptr, len)`; `Ok(None)` for `AF_UNSPEC`.
fn read_sockaddr(cx: &Cx, ptr: u64, len: u64, v6: bool) -> Result<Option<([u8; 4], u16)>, i64> {
    if len < 2 {
        return Err(EINVAL);
    }
    let raw = cx.copy_in(ptr, (len as usize).min(28))?;
    let family = u16::from_le_bytes([raw[0], raw[1]]) as u32;
    if family == 0 {
        return Ok(None);
    }
    if isolated(cx) {
        return Err(ENETUNREACH);
    }
    if v6 {
        if raw.len() < 24 {
            return Err(EINVAL);
        }
        if family != AF_INET6 {
            return Err(EAFNOSUPPORT);
        }
        let port = u16::from_be_bytes([raw[2], raw[3]]);
        let a = &raw[8..24];
        let ip = if a.iter().all(|&b| b == 0) {
            [0; 4]
        } else if a[..15].iter().all(|&b| b == 0) && a[15] == 1 {
            stack::V6_LOOPBACK
        } else if stack::link_local6().is_some_and(|ll| ll[..] == a[..]) {
            stack::V6_LINKLOCAL
        } else if a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff {
            [a[12], a[13], a[14], a[15]]
        } else {
            return Err(ENETUNREACH);
        };
        return Ok(Some((ip, port)));
    }
    if family == AF_INET6 {
        return Err(EAFNOSUPPORT);
    }
    if family != AF_INET || raw.len() < 8 {
        return Err(EINVAL);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let ip = [raw[4], raw[5], raw[6], raw[7]];
    if ip[0] == 0 && ip != [0; 4] {
        return Err(ENETUNREACH);
    }
    Ok(Some((ip, port)))
}

/// The bytes of a `sockaddr_in`/`sockaddr_in6` for `ip:port`.
fn sockaddr_bytes(ip: [u8; 4], port: u16, v6: bool) -> Vec<u8> {
    if v6 {
        let mut sa = alloc::vec![0u8; 28];
        sa[0..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        if ip == stack::V6_LOOPBACK {
            sa[23] = 1;
        } else if ip == stack::V6_LINKLOCAL {
            sa[8..24].copy_from_slice(&stack::link_local6().unwrap_or([0; 16]));
            sa[24..28].copy_from_slice(&2u32.to_le_bytes());
        } else if ip != [0; 4] {
            sa[18] = 0xff;
            sa[19] = 0xff;
            sa[20..24].copy_from_slice(&ip);
        }
        return sa;
    }
    let mut sa = alloc::vec![0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    sa
}

/// Writes a socket address and its length (`len_ptr` in/out) to the caller.
fn write_sockaddr(cx: &Cx, ptr: u64, len_ptr: u64, ip: [u8; 4], port: u16, v6: bool) -> Result<(), i64> {
    if ptr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let cap = u32::from_le_bytes(cx.copy_in(len_ptr, 4)?.try_into().unwrap()) as usize;
    let sa = sockaddr_bytes(ip, port, v6);
    cx.copy_out_any(ptr, &sa[..cap.min(sa.len())])?;
    cx.copy_out(len_ptr, &(sa.len() as u32).to_le_bytes())
}

/// `(base, length)` pairs of a `struct iovec` array.
fn read_iovecs(cx: &Cx, iov: u64, count: u64) -> Result<Vec<(u64, u64)>, i64> {
    if count > 1024 {
        return Err(EINVAL);
    }
    let raw = cx.copy_in_any(iov, count as usize * 16)?;
    Ok(raw.chunks_exact(16).map(|c| (Cx::u64_at(c, 0), Cx::u64_at(c, 8))).collect())
}

/// The bytes at `segs` from offset `off`, at most `max` of them.
fn gather(cx: &Cx, segs: &[(u64, u64)], mut off: usize, max: usize) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    for &(base, len) in segs {
        let len = len as usize;
        if off >= len {
            off -= len;
            continue;
        }
        let n = (len - off).min(max - out.len());
        if n > 0 {
            out.extend_from_slice(&cx.copy_in(base + off as u64, n)?);
        }
        off = 0;
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

/// Scatters `data` over `segs`.
fn scatter(cx: &Cx, segs: &[(u64, u64)], data: &[u8]) -> Result<(), i64> {
    let mut off = 0;
    for &(base, len) in segs {
        if off >= data.len() {
            break;
        }
        let k = (len as usize).min(data.len() - off);
        if k > 0 {
            cx.copy_out(base, &data[off..off + k])?;
        }
        off += k;
    }
    Ok(())
}

fn connect_target(s: &Sock, ip: [u8; 4]) -> [u8; 4] {
    match (ip, s.v6) {
        ([0, 0, 0, 0], true) => stack::V6_LOOPBACK,
        ([0, 0, 0, 0], false) => [127, 0, 0, 1],
        _ => ip,
    }
}

fn families(s: &Sock, ip: [u8; 4]) -> (bool, bool) {
    if !s.v6 {
        (true, false)
    } else if stack::is_v6(ip) {
        (false, true)
    } else if ip == [0; 4] {
        (!s.opts.flag(41, 26), true)
    } else {
        (true, false)
    }
}

/// Landlock's TCP port rules for the caller.
fn landlock(cx: &Cx, port: u16, want: u64) -> Result<(), i64> {
    sys::lx_obj(LX_OBJ_NETCHECK, cx.id, port as u64, want).map(|_| ()).map_err(|_| EACCES)
}

fn icmp_filter(s: &Sock) -> Option<alloc::boxed::Box<dyn Fn(&[u8]) -> bool>> {
    if !s.raw {
        return None;
    }
    if s.v6 {
        let f = s.opts.value(58, 1)?.to_vec();
        Some(alloc::boxed::Box::new(move |d: &[u8]| {
            let ty = d.first().copied().unwrap_or(0) as usize;
            f.get(ty / 8).is_some_and(|b| b & (1 << (ty % 8)) != 0)
        }))
    } else {
        let f = s.opts.value(255, 1)?;
        let mask = u32::from_le_bytes(f.get(..4)?.try_into().ok()?);
        Some(alloc::boxed::Box::new(move |d: &[u8]| {
            let ty = d.get(20).copied().unwrap_or(0) as u32;
            ty < 32 && mask & (1 << ty) != 0
        }))
    }
}

// ----------------------------------------------------------------------
// socket()
// ----------------------------------------------------------------------

/// `socket(AF_INET or AF_INET6, type, protocol)`: the new descriptor.
pub fn socket(cx: &Cx) -> i64 {
    let domain = cx.args[0] as u32;
    let ty = cx.args[1] as u32 & 0xf;
    let proto = cx.args[2] as u32;
    let icmp_proto = if domain == AF_INET6 { 58 } else { 1 };
    let (stream, icmp) = match ty {
        SOCK_STREAM if matches!(proto, 0 | 6) => (true, None),
        SOCK_DGRAM if matches!(proto, 0 | 17) => (false, None),
        SOCK_DGRAM if proto == icmp_proto => (false, Some(false)),
        SOCK_RAW if proto == icmp_proto => {
            if !cx.has_cap(CAP_NET_RAW) {
                return EPERM;
            }
            (false, Some(true))
        }
        SOCK_STREAM | SOCK_DGRAM | SOCK_RAW => return EPROTONOSUPPORT,
        _ => return ESOCKTNOSUPPORT,
    };
    let slot = match crate::obj::alloc(LX_OBJ_KIND_INET) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let inode = INODE.fetch_add(1, Ordering::Relaxed);
    let mut sock = Sock {
        gen: stack::gen(),
        stream,
        tcp: None,
        udp: None,
        bound_port: 0,
        peer: None,
        shut_rd: false,
        opts: Default::default(),
        bound_ip: [0; 4],
        bind_id: None,
        listener: None,
        uid: cx.c.euid,
        udp_used: false,
        v6: domain == AF_INET6,
        icmp: icmp.map(|raw| stack::icmp_open(raw, domain == AF_INET6)),
        raw: icmp == Some(true),
        rx_stamp: None,
        inode,
    };
    if let Some(h) = sock.icmp {
        track(h, slot);
    }
    if !stream && icmp.is_none() {
        let _ = sock.udp_id(slot);
    }
    let flags = cx.args[1] as u32 & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let bits = sock.poll_events();
    let arc = Arc::new(YLock::new(sock));
    SOCKS.lock().insert(slot, arc);
    crate::obj::set_ready(slot, bits, 0);
    let name = alloc::format!("socket:[{}]", inode);
    match crate::obj::install(cx, slot, LX_OBJ_KIND_INET, flags, 0o140777, cx.c.euid, cx.c.egid, name.as_bytes()) {
        Ok(fd) => fd,
        Err(e) => {
            closed(slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            e
        }
    }
}

// ----------------------------------------------------------------------
// The calls on a socket
// ----------------------------------------------------------------------

/// One attempt at call `cx` on its socket.
pub fn call(cx: &Cx, prog: &mut Prog) -> Out {
    let slot = cx.c.obj as u32;
    let Some(sock) = sock_of(slot) else { return Out::Done(EBADF) };
    let a = cx.args;
    let r = match cx.nr {
        42 => return connect(cx, &sock, slot, a[1], a[2], prog),
        49 => bind(cx, &sock, slot),
        50 => listen(&sock, slot, a[1]),
        43 | 288 => return accept(cx, &sock, prog),
        44 => {
            let dest = if a[4] != 0 {
                let v6 = sock.lock().v6;
                match read_sockaddr(cx, a[4], a[5], v6) {
                    Ok(d) => d.map(|(ip, port)| (connect_target(&sock.lock(), ip), port)),
                    Err(e) => return Out::Done(e),
                }
            } else {
                None
            };
            return send(cx, &sock, slot, &[(a[1], a[2])], a[3], dest, prog);
        }
        45 => {
            let peek_len = a[2] as usize;
            return match recv(cx, &sock, slot, peek_len, a[3], prog) {
                Ok(Some((data, src, _))) => {
                    if let Err(e) = cx.copy_out_any(a[1], &data) {
                        return Out::Done(e);
                    }
                    if let Some((ip, port)) = src {
                        let v6 = sock.lock().v6;
                        let _ = write_sockaddr(cx, a[4], a[5], ip, port, v6);
                    }
                    Out::Done(data.len() as i64)
                }
                Ok(None) => prog.wait(sock.lock().opts.rcv_timeout()),
                Err(e) => Out::Done(e),
            };
        }
        46 => return sendmsg(cx, &sock, slot, a[1], a[2], prog),
        47 => return recvmsg(cx, &sock, slot, a[1], a[2], prog),
        307 => {
            // sendmmsg: the first message may wait, the others go only if they can
            let mut sent = 0i64;
            for i in 0..a[2].min(1024) {
                let m = a[1] + i * 64;
                let r = if i == 0 {
                    match sendmsg(cx, &sock, slot, m, a[3], prog) {
                        Out::Done(r) => r,
                        Out::Block => return Out::Block,
                    }
                } else {
                    let mut p = Prog::new();
                    match sendmsg(cx, &sock, slot, m, a[3] | MSG_DONTWAIT, &mut p) {
                        Out::Done(r) => r,
                        Out::Block => EAGAIN,
                    }
                };
                if r < 0 {
                    return Out::Done(if sent > 0 { sent } else { r });
                }
                let _ = cx.copy_out(m + 56, &(r as u32).to_le_bytes());
                sent += 1;
            }
            sent
        }
        299 => {
            // recvmmsg: the first message may wait, then what is there
            let mut got = 0i64;
            for i in 0..a[2].min(1024) {
                let m = a[1] + i * 64;
                let flags = if got > 0 { a[3] | MSG_DONTWAIT } else { a[3] };
                let r = match recvmsg(cx, &sock, slot, m, flags, prog) {
                    Out::Done(r) => r,
                    Out::Block if got == 0 => return Out::Block,
                    Out::Block => EAGAIN,
                };
                if r < 0 {
                    return Out::Done(if got > 0 { got } else { r });
                }
                let _ = cx.copy_out(m + 56, &(r as u32).to_le_bytes());
                got += 1;
            }
            got
        }
        48 => {
            let mut s = sock.lock();
            if a[1] != 1 {
                s.shut_rd = true;
            }
            let r = match (a[1], s.tcp) {
                (1 | 2, Some(id)) => {
                    if !s.dead() {
                        stack::tcp_shutdown_write(id);
                    }
                    0
                }
                (_, None) if s.stream => ENOTCONN,
                _ => 0,
            };
            drop(s);
            // A receive blocked in another thread sees the end now
            crate::socket::poke(slot);
            r
        }
        51 | 52 => names(cx, &sock, cx.nr),
        54 => setsockopt(cx, &sock),
        55 => getsockopt(cx, &sock),
        // read, write, readv, writev, ioctl on the socket
        0 => {
            return match recv(cx, &sock, slot, a[2] as usize, 0, prog) {
                Ok(Some((data, _, _))) => match cx.copy_out_any(a[1], &data) {
                    Ok(()) => Out::Done(data.len() as i64),
                    Err(e) => Out::Done(e),
                },
                Ok(None) => prog.wait(sock.lock().opts.rcv_timeout()),
                Err(e) => Out::Done(e),
            };
        }
        1 => return send(cx, &sock, slot, &[(a[1], a[2])], 0, None, prog),
        19 => {
            let segs = match read_iovecs(cx, a[1], a[2]) {
                Ok(v) => v,
                Err(e) => return Out::Done(e),
            };
            let total: u64 = segs.iter().map(|s| s.1).sum();
            return match recv(cx, &sock, slot, total as usize, 0, prog) {
                Ok(Some((data, _, _))) => match scatter(cx, &segs, &data) {
                    Ok(()) => Out::Done(data.len() as i64),
                    Err(e) => Out::Done(e),
                },
                Ok(None) => prog.wait(sock.lock().opts.rcv_timeout()),
                Err(e) => Out::Done(e),
            };
        }
        20 => {
            let segs = match read_iovecs(cx, a[1], a[2]) {
                Ok(v) => v,
                Err(e) => return Out::Done(e),
            };
            return send(cx, &sock, slot, &segs, 0, None, prog);
        }
        16 => ioctl(cx, &sock),
        _ => ENOTSOCK,
    };
    Out::Done(r)
}

/// `connect(addr, len)`.
fn connect(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32, addr: u64, len: u64, prog: &mut Prog) -> Out {
    // A connect in progress, tried again (or made again after its net wait): wait for the
    // handshake
    if prog.deadline.is_some() || cx.c.flags & LX_CALL_RETRIED != 0 {
        let (id, dead) = {
            let s = sock.lock();
            (s.tcp, s.dead())
        };
        let Some(id) = id else { return Out::Done(ENOTCONN) };
        if dead {
            return Out::Done(stack::ECONNRESET);
        }
        let snap = stack::word_raw(id);
        return match stack::tcp_state(id) {
            stack::SYN_SENT => {
                prog.wait_on = Some((id, snap));
                if prog.deadline.is_none() {
                    // (made again after a net wait: no deadline of its own)
                    prog.on_signal = EINTR;
                    return prog.wait(None);
                }
                Out::Block
            }
            stack::CLOSED => Out::Done(stack::tcp_take_error(id).unwrap_or(stack::ECONNREFUSED)),
            _ => Out::Done(0),
        };
    }
    let v6 = sock.lock().v6;
    let dest = match read_sockaddr(cx, addr, len, v6) {
        Ok(d) => d.map(|(ip, port)| (connect_target(&sock.lock(), ip), port)),
        Err(e) => return Out::Done(e),
    };
    if let Some((ip, _)) = dest {
        let s = sock.lock();
        if s.v6 && s.opts.flag(41, 26) && !stack::is_v6(ip) {
            return Out::Done(ENETUNREACH);
        }
    }
    let timeout = {
        let mut s = sock.lock();
        if s.dead() {
            return Out::Done(if s.stream { stack::ECONNRESET } else { stack::ENETDOWN });
        }
        if s.icmp.is_some() {
            s.peer = dest;
            return Out::Done(0);
        }
        if !s.stream {
            if let Err(e) = s.udp_id(slot) {
                return Out::Done(e);
            }
            s.udp_used = true;
            s.peer = dest;
            return Out::Done(0);
        }
        if s.listener.is_some() {
            return Out::Done(EISCONN);
        }
        s.opts.snd_timeout()
    };
    let nonblock = cx.nonblock();
    let Some((ip, port)) = dest else { return Out::Done(EAFNOSUPPORT) };
    if landlock(cx, port, CONNECT_TCP).is_err() {
        return Out::Done(EACCES);
    }
    let existing = sock.lock().tcp;
    let id = match existing {
        Some(id) => match stack::tcp_state(id) {
            stack::SYN_SENT => {
                if nonblock {
                    return Out::Done(EALREADY);
                }
                id
            }
            stack::CLOSED => return Out::Done(stack::tcp_take_error(id).unwrap_or(EISCONN)),
            _ => return Out::Done(EISCONN),
        },
        None => {
            let bound = sock.lock().bound_port;
            match stack::tcp_connect(ip, port, if bound != 0 { Some(bound) } else { None }) {
                Ok(id) => {
                    sock.lock().tcp = Some(id);
                    track(id, slot);
                    if nonblock {
                        return Out::Done(EINPROGRESS);
                    }
                    id
                }
                Err(e) => return Out::Done(e),
            }
        }
    };
    let snap = stack::word_raw(id);
    match stack::tcp_state(id) {
        stack::SYN_SENT => {
            prog.wait_on = Some((id, snap));
            // An interrupted or timed-out connect keeps going in the background (Linux)
            prog.on_timeout = EINPROGRESS;
            let o = prog.wait(timeout);
            prog.on_signal = EINTR;
            o
        }
        stack::CLOSED => Out::Done(stack::tcp_take_error(id).unwrap_or(stack::ECONNREFUSED)),
        _ => Out::Done(0),
    }
}

/// `bind(addr, len)`.
fn bind(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32) -> i64 {
    let a = cx.args;
    let v6 = sock.lock().v6;
    if v6 && a[2] >= 4 {
        if let Ok(h) = cx.copy_in(a[1], 4) {
            let port = u16::from_be_bytes([h[2], h[3]]);
            if port != 0 && port < 1024 && !cx.has_cap(CAP_NET_BIND_SERVICE) {
                return EACCES;
            }
        }
    }
    match read_sockaddr(cx, a[1], a[2], v6).map_err(|e| if e == ENETUNREACH { EADDRNOTAVAIL } else { e }) {
        Ok(Some((ip, port))) => {
            let mut s = sock.lock();
            if s.dead() {
                return stack::ENETDOWN;
            }
            if let Some(id) = s.icmp {
                if ip != [0; 4] && !stack::is_local(ip) {
                    return EADDRNOTAVAIL;
                }
                if !s.raw && port != 0 {
                    if let Err(e) = stack::icmp_set_ident(id, port) {
                        return e;
                    }
                }
                s.bound_ip = ip;
                return 0;
            }
            if s.v6 && s.opts.flag(41, 26) && ip != [0; 4] && !stack::is_v6(ip) {
                return EINVAL;
            }
            if s.stream && landlock(cx, port, BIND_TCP).is_err() {
                return EACCES;
            }
            if ip != [0; 4] && !stack::is_local(ip) {
                return EADDRNOTAVAIL;
            }
            if port != 0 && port < 1024 && !cx.has_cap(CAP_NET_BIND_SERVICE) {
                return EACCES;
            }
            if s.stream {
                if s.bind_id.is_some() || s.tcp.is_some() || s.listener.is_some() {
                    return EINVAL;
                }
                let ra = s.opts.flag(1, 2);
                let rp = s.opts.flag(1, 15);
                let (v4, v6) = families(&s, ip);
                match stack::tcp_bind(ip, port, ra, rp, v4, v6) {
                    Ok((id, p)) => {
                        s.bind_id = Some(id);
                        track(id, slot);
                        s.bound_port = p;
                        s.bound_ip = ip;
                        0
                    }
                    Err(e) => e,
                }
            } else if let (Some(id), false) = (s.udp, s.udp_used) {
                match stack::udp_rebind(id, port) {
                    Ok(()) => {
                        s.udp_used = true;
                        s.bound_ip = ip;
                        0
                    }
                    Err(e) => e,
                }
            } else if s.udp.is_some() {
                EINVAL
            } else {
                match stack::udp_open(port) {
                    Ok(id) => {
                        s.udp = Some(id);
                        track(id, slot);
                        s.bound_ip = ip;
                        0
                    }
                    Err(e) => e,
                }
            }
        }
        Ok(None) => 0,
        Err(e) => e,
    }
}

/// `listen(backlog)`.
fn listen(sock: &Arc<YLock<Sock>>, slot: u32, backlog: u64) -> i64 {
    let mut s = sock.lock();
    if !s.stream {
        return EOPNOTSUPP;
    }
    if s.tcp.is_some() {
        return EINVAL;
    }
    if s.dead() {
        return stack::ENETDOWN;
    }
    let b = backlog as i32;
    let backlog = if !(0..=4096).contains(&b) { 4096 } else { b as usize };
    if let Some(id) = s.listener {
        stack::tcp_set_backlog(id, backlog);
        return 0;
    }
    let bind = match s.bind_id {
        Some(b) => b,
        None => {
            let (v4, v6) = families(&s, [0; 4]);
            match stack::tcp_bind([0; 4], 0, false, false, v4, v6) {
                Ok((id, port)) => {
                    s.bind_id = Some(id);
                    track(id, slot);
                    s.bound_port = port;
                    id
                }
                Err(e) => return e,
            }
        }
    };
    match stack::tcp_listen(bind, backlog) {
        Ok(id) => {
            s.listener = Some(id);
            track(id, slot);
            0
        }
        Err(e) => e,
    }
}

/// `accept(addr, addrlen)` / `accept4(.., flags)`.
fn accept(cx: &Cx, sock: &Arc<YLock<Sock>>, prog: &mut Prog) -> Out {
    let a = cx.args;
    let flags = if cx.nr == 288 { a[3] } else { 0 };
    if flags & !((SOCK_NONBLOCK | SOCK_CLOEXEC) as u64) != 0 {
        return Out::Done(EINVAL);
    }
    let (lid, timeout, opts, v6, dead) = {
        let s = sock.lock();
        match s.listener {
            Some(l) => (l, s.opts.rcv_timeout(), s.opts.clone(), s.v6, s.dead()),
            None => return Out::Done(EINVAL),
        }
    };
    if dead {
        return Out::Done(stack::ENETDOWN);
    }
    let snap = stack::word_raw(lid);
    let Some(cid) = stack::tcp_accept(lid) else {
        prog.wait_on = Some((lid, snap));
        return if cx.nonblock() { Out::Done(EAGAIN) } else { prog.wait(timeout) };
    };
    let (lport, rip, rport, lip) = stack::tcp_info(cid).unwrap_or((0, [0; 4], 0, [0; 4]));
    let slot = match crate::obj::alloc(LX_OBJ_KIND_INET) {
        Ok(s) => s,
        Err(e) => {
            stack::tcp_close(cid);
            return Out::Done(e);
        }
    };
    let inode = INODE.fetch_add(1, Ordering::Relaxed);
    let conn = Sock {
        gen: stack::gen(),
        stream: true,
        tcp: Some(cid),
        udp: None,
        bound_port: lport,
        peer: None,
        shut_rd: false,
        opts,
        bound_ip: lip,
        bind_id: None,
        listener: None,
        uid: cx.c.euid,
        udp_used: false,
        v6,
        icmp: None,
        raw: false,
        rx_stamp: None,
        inode,
    };
    track(cid, slot);
    let bits = conn.poll_events();
    SOCKS.lock().insert(slot, Arc::new(YLock::new(conn)));
    crate::obj::set_ready(slot, bits, 0);
    let name = alloc::format!("socket:[{}]", inode);
    let fd = match crate::obj::install(cx, slot, LX_OBJ_KIND_INET, flags as u32 & (SOCK_NONBLOCK | SOCK_CLOEXEC), 0o140777, cx.c.euid, cx.c.egid, name.as_bytes()) {
        Ok(fd) => fd,
        Err(e) => {
            closed(slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            return Out::Done(e);
        }
    };
    if a[1] != 0 {
        if let Err(e) = write_sockaddr(cx, a[1], a[2], rip, rport, v6) {
            return Out::Done(e);
        }
    }
    Out::Done(fd)
}

/// Sends the bytes at `segs` (TCP: as much as fits, waiting for room unless non-blocking;
/// UDP and ICMP: one datagram).
fn send(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32, segs: &[(u64, u64)], flags: u64, dest: Option<([u8; 4], u16)>, prog: &mut Prog) -> Out {
    let total: usize = segs.iter().map(|s| s.1 as usize).sum();
    let icmp = {
        let s = sock.lock();
        s.icmp.map(|id| (id, dest.or(s.peer), s.dead()))
    };
    if let Some((id, to, dead)) = icmp {
        let Some((ip, _)) = to else { return Out::Done(EDESTADDRREQ) };
        if dead {
            return Out::Done(stack::ENETDOWN);
        }
        let data = match gather(cx, segs, 0, total.min(65536)) {
            Ok(d) => d,
            Err(e) => return Out::Done(e),
        };
        return Out::Done(match stack::icmp_send(id, ip, &data) {
            Ok(n) => n as i64,
            Err(e) => e,
        });
    }
    let (stream, tcp, timeout, dead) = {
        let s = sock.lock();
        (s.stream, s.tcp, s.opts.snd_timeout(), s.dead())
    };
    let nonblock = cx.nonblock() || flags & MSG_DONTWAIT != 0;
    if stream {
        let Some(id) = tcp else { return Out::Done(ENOTCONN) };
        let fail = |e: i64| {
            if e == EPIPE || e == stack::ECONNRESET {
                if flags & MSG_NOSIGNAL == 0 {
                    let _ = sys::lx_obj(LX_OBJ_SIGTHREAD, cx.id, 13, 0); // SIGPIPE
                }
                EPIPE
            } else {
                e
            }
        };
        if dead {
            return Out::Done(if prog.sent > 0 { prog.sent as i64 } else { fail(stack::ECONNRESET) });
        }
        while prog.sent < total {
            let chunk = match gather(cx, segs, prog.sent, (total - prog.sent).min(stack::REGION)) {
                Ok(d) => d,
                Err(e) => return Out::Done(if prog.sent > 0 { prog.sent as i64 } else { e }),
            };
            let snap = stack::word_raw(id);
            match stack::tcp_send(id, &chunk) {
                Ok(0) => {
                    prog.wait_on = Some((id, snap));
                    if nonblock {
                        return Out::Done(if prog.sent > 0 { prog.sent as i64 } else { EAGAIN });
                    }
                    return prog.wait(timeout);
                }
                Ok(n) => {
                    prog.sent += n;
                    if nonblock {
                        break;
                    }
                }
                Err(e) if prog.sent > 0 => {
                    let _ = e;
                    break;
                }
                Err(e) => return Out::Done(fail(e)),
            }
        }
        return Out::Done(prog.sent as i64);
    }
    let (ip, port) = match dest.or(sock.lock().peer) {
        Some(d) => d,
        None => return Out::Done(EDESTADDRREQ),
    };
    if dead {
        return Out::Done(stack::ENETDOWN);
    }
    let id = {
        let mut s = sock.lock();
        s.udp_used = true;
        match s.udp_id(slot) {
            Ok(id) => id,
            Err(e) => return Out::Done(e),
        }
    };
    let data = match gather(cx, segs, 0, total.min(65536)) {
        Ok(d) => d,
        Err(e) => return Out::Done(e),
    };
    Out::Done(match stack::udp_send(id, ip, port, &data) {
        Ok(n) => n as i64,
        Err(e) => e,
    })
}

/// One receive of at most `cap` bytes: `Some((data, source, truncated))`, or `None` when
/// a blocking call must wait (a non-blocking one gets `EAGAIN`).
#[allow(clippy::type_complexity)]
fn recv(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32, cap: usize, flags: u64, prog: &mut Prog) -> Result<Option<(Vec<u8>, Option<([u8; 4], u16)>, bool)>, i64> {
    let (stream, tcp, shut_rd, dead) = {
        let s = sock.lock();
        (s.stream, s.tcp, s.shut_rd, s.dead())
    };
    let nonblock = cx.nonblock() || flags & MSG_DONTWAIT != 0;
    let peek = flags & MSG_PEEK != 0;
    let wait = || if nonblock { Err(EAGAIN) } else { Ok(None) };
    let icmp = {
        let s = sock.lock();
        s.icmp.map(|id| (id, icmp_filter(&s)))
    };
    if let Some((id, filter)) = icmp {
        if dead {
            return Err(stack::ENETDOWN);
        }
        loop {
            let snap = stack::word_raw(id);
            match stack::icmp_recv(id, peek) {
                None => {
                    prog.wait_on = Some((id, snap));
                    return wait();
                }
                Some((_, d, _)) if !peek && filter.as_ref().is_some_and(|f| f(&d)) => continue,
                Some((src, mut data, arrived)) => {
                    sock.lock().rx_stamp = Some(arrived);
                    let trunc = data.len() > cap;
                    data.truncate(cap);
                    return Ok(Some((data, Some((src, 0)), trunc)));
                }
            }
        }
    }
    if stream {
        let Some(id) = tcp else { return Err(ENOTCONN) };
        if shut_rd {
            return Ok(Some((Vec::new(), None, false)));
        }
        if dead {
            return Err(stack::ECONNRESET);
        }
        if cap == 0 {
            return Ok(Some((Vec::new(), None, false)));
        }
        let snap = stack::word_raw(id);
        return match stack::tcp_recv(id, cap, peek) {
            Ok((d, false)) if d.is_empty() => {
                if stack::tcp_state(id) == stack::CLOSED {
                    Ok(Some((d, None, false)))
                } else {
                    prog.wait_on = Some((id, snap));
                    wait()
                }
            }
            Ok((d, _)) => Ok(Some((d, None, false))),
            Err(e) => Err(e),
        };
    }
    if dead {
        return Err(stack::ENETDOWN);
    }
    let id = sock.lock().udp_id(slot)?;
    let snap = stack::word_raw(id);
    prog.wait_on = Some((id, snap));
    match stack::udp_recv(id, peek) {
        Some((ip, port, mut data, whole, arrived)) => {
            sock.lock().rx_stamp = Some(arrived);
            let trunc = whole > cap;
            data.truncate(cap);
            Ok(Some((data, Some((ip, port)), trunc)))
        }
        None => wait(),
    }
}

/// `sendmsg(msg, flags)`.
fn sendmsg(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32, msg: u64, flags: u64, prog: &mut Prog) -> Out {
    let hdr = match cx.copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return Out::Done(e),
    };
    let (name, namelen, iov, iovlen) = (Cx::u64_at(&hdr, 0), u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64, Cx::u64_at(&hdr, 16), Cx::u64_at(&hdr, 24));
    let v6 = sock.lock().v6;
    let dest = if name != 0 {
        match read_sockaddr(cx, name, namelen, v6) {
            Ok(d) => d.map(|(ip, port)| (connect_target(&sock.lock(), ip), port)),
            Err(e) => return Out::Done(e),
        }
    } else {
        None
    };
    let segs = match read_iovecs(cx, iov, iovlen) {
        Ok(v) => v,
        Err(e) => return Out::Done(e),
    };
    send(cx, sock, slot, &segs, flags, dest, prog)
}

/// `recvmsg(msg, flags)`.
fn recvmsg(cx: &Cx, sock: &Arc<YLock<Sock>>, slot: u32, msg: u64, flags: u64, prog: &mut Prog) -> Out {
    let mut hdr = match cx.copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return Out::Done(e),
    };
    let (name, namelen, iov, iovlen, control, controllen) = (
        Cx::u64_at(&hdr, 0),
        u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize,
        Cx::u64_at(&hdr, 16),
        Cx::u64_at(&hdr, 24),
        Cx::u64_at(&hdr, 32),
        Cx::u64_at(&hdr, 40),
    );
    let iovs = match read_iovecs(cx, iov, iovlen) {
        Ok(v) => v,
        Err(e) => return Out::Done(e),
    };
    let total: u64 = iovs.iter().map(|&(_, l)| l).sum();
    let (data, src, trunc) = match recv(cx, sock, slot, total as usize, flags, prog) {
        Ok(Some(r)) => r,
        Ok(None) => return prog.wait(sock.lock().opts.rcv_timeout()),
        Err(e) => return Out::Done(e),
    };
    if let Err(e) = scatter(cx, &iovs, &data) {
        return Out::Done(e);
    }
    let (v6, stream) = {
        let s = sock.lock();
        (s.v6, s.stream)
    };
    // msg_namelen
    let mut nlen = 0u32;
    if let (Some((ip, port)), true) = (src, name != 0) {
        let sa = sockaddr_bytes(ip, port, v6);
        let _ = cx.copy_out_any(name, &sa[..namelen.min(sa.len())]);
        nlen = sa.len() as u32;
    }
    hdr[8..12].copy_from_slice(&nlen.to_le_bytes());
    // Control messages: SO_TIMESTAMP(NS) first, then IP_TTL / IPV6_HOPLIMIT when asked
    let want = {
        let s = sock.lock();
        if stream {
            None
        } else if s.v6 && s.opts.flag(41, 51) {
            Some((41u32, 52u32))
        } else if !s.v6 && s.opts.flag(0, 12) {
            Some((0, 2))
        } else {
            None
        }
    };
    let stamp = {
        let s = sock.lock();
        let ns = s.opts.flag(1, 35);
        if (s.opts.flag(1, 29) || ns) && !stream {
            s.rx_stamp.map(|t| (t, ns))
        } else {
            None
        }
    };
    let mut cmsgs: Vec<u8> = Vec::new();
    if let (Some((t, ns)), true) = (stamp, control != 0 && controllen >= 32) {
        let mut c = [0u8; 32];
        c[0..8].copy_from_slice(&32u64.to_le_bytes());
        c[8..12].copy_from_slice(&1u32.to_le_bytes());
        c[12..16].copy_from_slice(&(if ns { 35u32 } else { 29u32 }).to_le_bytes());
        c[16..24].copy_from_slice(&(t / 1_000_000_000).to_le_bytes());
        let sub = if ns { t % 1_000_000_000 } else { (t % 1_000_000_000) / 1000 };
        c[24..32].copy_from_slice(&sub.to_le_bytes());
        cmsgs.extend_from_slice(&c);
    }
    if let (Some((level, ty)), true) = (want, control != 0 && controllen >= cmsgs.len() as u64 + 24) {
        let mut c = [0u8; 24];
        c[0..8].copy_from_slice(&20u64.to_le_bytes());
        c[8..12].copy_from_slice(&level.to_le_bytes());
        c[12..16].copy_from_slice(&ty.to_le_bytes());
        c[16..20].copy_from_slice(&64i32.to_le_bytes());
        cmsgs.extend_from_slice(&c);
    }
    let used = if !cmsgs.is_empty() && cx.copy_out(control, &cmsgs).is_ok() { cmsgs.len() as u64 } else { 0 };
    hdr[40..48].copy_from_slice(&used.to_le_bytes());
    let mflags: i32 = if trunc { MSG_TRUNC as i32 } else { 0 };
    hdr[48..52].copy_from_slice(&mflags.to_le_bytes());
    // The header back in one write (msg_namelen, msg_controllen, msg_flags)
    if let Err(e) = cx.copy_out(msg, &hdr) {
        return Out::Done(e);
    }
    Out::Done(data.len() as i64)
}

/// `getsockname` (51) / `getpeername` (52).
fn names(cx: &Cx, sock: &Arc<YLock<Sock>>, nr: u64) -> i64 {
    let s = sock.lock();
    if s.dead() {
        return if nr == 52 { ENOTCONN } else { write_sockaddr(cx, cx.args[1], cx.args[2], s.bound_ip, s.bound_port, s.v6).map_or_else(|e| e, |()| 0) };
    }
    let me = stack::iface().ip;
    let (ip, port) = if nr == 51 && s.icmp.is_some() {
        let id = s.icmp.unwrap();
        (s.bound_ip, if s.raw { if s.v6 { 58 } else { 1 } } else { stack::icmp_ident(id) })
    } else if nr == 51 {
        match (s.tcp.and_then(stack::tcp_info), s.udp) {
            (Some((lp, _, _, lip)), _) => (lip, lp),
            (None, Some(id)) => (if s.bound_ip != [0; 4] { s.bound_ip } else { me }, stack::udp_port(id)),
            _ => (s.bound_ip, s.bound_port),
        }
    } else {
        match (s.tcp.and_then(stack::tcp_info), s.peer) {
            (Some((_, rip, rp, _)), _) => (rip, rp),
            (None, Some(p)) => p,
            _ => return ENOTCONN,
        }
    };
    let v6 = s.v6;
    drop(s);
    match write_sockaddr(cx, cx.args[1], cx.args[2], ip, port, v6) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `setsockopt(level, optname, optval, optlen)`.
fn setsockopt(cx: &Cx, sock: &Arc<YLock<Sock>>) -> i64 {
    let a = cx.args;
    if (a[4] as i32) < 0 {
        return EINVAL;
    }
    let val = match cx.copy_in_any(a[3], (a[4] as usize).min(4096)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut s = sock.lock();
    let (stream, v6) = (s.stream, s.v6);
    if v6 && a[1] == 41 && a[2] == 26 && (s.bind_id.is_some() || s.tcp.is_some() || s.listener.is_some() || s.udp_used) {
        return EINVAL;
    }
    if s.icmp.is_some() && a[2] == 1 && ((!v6 && a[1] == 255) || (v6 && a[1] == 58)) {
        if !s.raw || val.len() < if v6 { 32 } else { 4 } {
            return if s.raw { EINVAL } else { -92 };
        }
        s.opts.put(a[1] as u32, 1, &val[..if v6 { 32 } else { 4 }]);
        return 0;
    }
    if val.is_empty() && a[3] == 0 && a[4] != 0 {
        return EFAULT;
    }
    s.opts.set(a[1] as u32, a[2] as u32, &val, stream, v6, cx.c.caps)
}

/// `getsockopt(level, optname, optval, optlen*)`.
fn getsockopt(cx: &Cx, sock: &Arc<YLock<Sock>>) -> i64 {
    let a = cx.args;
    let len = match cx.copy_in(a[4], 4) {
        Ok(b) => i32::from_le_bytes(b[..4].try_into().unwrap()),
        Err(e) => return e,
    };
    if len < 0 {
        return EINVAL;
    }
    let v = {
        let s = sock.lock();
        if s.raw && a[2] == 1 && ((!s.v6 && a[1] == 255) || (s.v6 && a[1] == 58)) {
            let n = if s.v6 { 32 } else { 4 };
            s.opts.value(a[1] as u32, 1).map_or(alloc::vec![0; n], |v| v.to_vec())
        } else {
            let state = if s.dead() { s.tcp.map(|_| stack::CLOSED) } else { s.tcp.map(stack::tcp_state) };
            let error = if a[1] == 1 && a[2] == 4 {
                if s.dead() {
                    s.tcp.map_or(0, |_| stack::ECONNRESET)
                } else {
                    s.tcp.and_then(stack::tcp_take_error).unwrap_or(0)
                }
            } else {
                0
            };
            let info = SockInfo {
                kind: if s.raw { 2 } else if s.icmp.is_some() { 1 } else { 0 },
                v6: s.v6,
                listening: s.listener.is_some(),
                stream: s.stream,
                connected: matches!(state, Some(st) if st != stack::SYN_SENT && st != stack::CLOSED) || s.peer.is_some(),
                error,
                tcp_state: match state {
                    Some(st) => tcp_state_num(st),
                    None => 7,
                },
            };
            match s.opts.get(a[1] as u32, a[2] as u32, &info) {
                Ok(v) => v,
                Err(e) => return e,
            }
        }
    };
    let n = v.len().min(len as usize);
    match cx.copy_out_any(a[3], &v[..n]).and_then(|_| cx.copy_out(a[4], &(n as u32).to_le_bytes())) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `ioctl` on a socket: `SIOCGSTAMP`/`SIOCGSTAMPNS`, `FIONREAD` (`FIONBIO` and close-on-exec
/// are the kernel's; the interface queries `SIOCGIF*` too, for any descriptor).
fn ioctl(cx: &Cx, sock: &Arc<YLock<Sock>>) -> i64 {
    let (cmd, arg) = (cx.args[1], cx.args[2]);
    match cmd {
        0x8906 | 0x8907 => {
            let Some(t) = sock.lock().rx_stamp else { return -2 };
            let sub = if cmd == 0x8906 { (t % 1_000_000_000) / 1000 } else { t % 1_000_000_000 };
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&(t / 1_000_000_000).to_le_bytes());
            b[8..16].copy_from_slice(&sub.to_le_bytes());
            cx.copy_out(arg, &b).map_or_else(|e| e, |()| 0)
        }
        0x541B => {
            let n = {
                let s = sock.lock();
                if s.dead() {
                    0
                } else if let Some(id) = s.tcp {
                    stack::tcp_pending(id)
                } else {
                    s.udp.and_then(|id| stack::udp_recv(id, true)).map_or(0, |(_, _, _, whole, _)| whole)
                }
            };
            cx.copy_out(arg, &(n as i32).to_le_bytes()).map_or_else(|e| e, |()| 0)
        }
        r if r & 0xFF00 == 0x5400 => ENOTTY,
        _ => EINVAL,
    }
}

// ----------------------------------------------------------------------
// /proc/net
// ----------------------------------------------------------------------

/// Linux's TCP state numbers from net-server's.
fn tcp_state_num(s: u64) -> u8 {
    match s {
        NETS_TCP_ESTABLISHED => 1,
        NETS_TCP_SYN_SENT => 2,
        NETS_TCP_SYN_RECEIVED => 3,
        NETS_TCP_FIN_WAIT1 => 4,
        NETS_TCP_FIN_WAIT2 => 5,
        NETS_TCP_TIME_WAIT => 6,
        NETS_TCP_CLOSE_WAIT => 8,
        NETS_TCP_LAST_ACK => 9,
        NETS_TCP_CLOSING => 11,
        _ => 7,
    }
}

struct Owner {
    v6: bool,
    inode: u64,
    uid: u32,
    bound_ip: [u8; 4],
    peer: Option<([u8; 4], u16)>,
}

fn owners() -> BTreeMap<u32, Owner> {
    let socks: Vec<Arc<YLock<Sock>>> = SOCKS.lock().values().cloned().collect();
    let mut map = BTreeMap::new();
    for a in socks {
        let s = a.lock();
        if s.dead() {
            continue;
        }
        for id in [s.tcp, s.udp, s.listener].into_iter().flatten() {
            map.insert(id, Owner { v6: s.v6, inode: s.inode, uid: s.uid, bound_ip: s.bound_ip, peer: s.peer });
        }
    }
    map
}

fn hex_addr((ip, port): ([u8; 4], u16)) -> String {
    alloc::format!("{:08X}:{:04X}", u32::from_le_bytes(ip), port)
}

fn hex_addr6((ip, port): ([u8; 4], u16)) -> String {
    let words: [u32; 4] = if ip == stack::V6_LOOPBACK {
        [0, 0, 0, u32::from_le_bytes([0, 0, 0, 1])]
    } else if ip == stack::V6_LINKLOCAL {
        let a = stack::link_local6().unwrap_or([0; 16]);
        let w = |i: usize| u32::from_le_bytes(a[i..i + 4].try_into().unwrap());
        [w(0), w(4), w(8), w(12)]
    } else if ip == [0; 4] {
        [0; 4]
    } else {
        [0, 0, u32::from_le_bytes([0, 0, 0xff, 0xff]), u32::from_le_bytes(ip)]
    };
    alloc::format!("{:08X}{:08X}{:08X}{:08X}:{:04X}", words[0], words[1], words[2], words[3], port)
}

fn pad(mut l: String, width: usize) -> String {
    while l.len() < width {
        l.push(' ');
    }
    l.push('\n');
    l
}

/// `/proc/net/tcp` (`file` 0), `tcp6` (1), `udp` (2), `udp6` (3), as the kernel's copy
/// makes them, for a reader in a network namespace of its own (`isolated`) or not.
pub fn proc_net(file: u64, isolated: bool) -> String {
    if file <= 1 {
        let mut out = pad(String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"), 149);
        if isolated {
            return out;
        }
        let want6 = file == 1;
        let own = owners();
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(([u8; 4], u16), ([u8; 4], u16), u8, usize, usize, u32, u64)> = Vec::new();
        for (id, ip, port, waiting, backlog) in stack::listener_list() {
            let o = own.get(&id);
            if o.is_some_and(|o| o.v6) != want6 {
                continue;
            }
            rows.push(((ip, port), ([0; 4], 0), 0x0A, backlog, waiting, o.map_or(0, |o| o.uid), o.map_or(0, |o| o.inode)));
        }
        for (id, local, remote, state, tx, rx) in stack::tcp_list() {
            let o = own.get(&id);
            if o.map_or(stack::is_v6(local.0), |o| o.v6) != want6 {
                continue;
            }
            rows.push((local, remote, tcp_state_num(state), tx, rx, o.map_or(0, |o| o.uid), o.map_or(0, |o| o.inode)));
        }
        for (i, (l, rem, st, tx, rx, uid, inode)) in rows.into_iter().enumerate() {
            let line = alloc::format!(
                "{:4}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 1 0000000000000000 100 0 0 10 0",
                i,
                if want6 { hex_addr6(l) } else { hex_addr(l) },
                if want6 { hex_addr6(rem) } else { hex_addr(rem) },
                st,
                tx,
                rx,
                uid,
                0,
                inode
            );
            out.push_str(&pad(line, 149));
        }
        return out;
    }
    let mut out = pad(String::from("   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"), 127);
    if isolated {
        return out;
    }
    let want6 = file == 3;
    let own = owners();
    let socks = stack::udp_list().into_iter().filter(|(id, _, _)| own.get(id).is_some_and(|o| o.v6) == want6);
    for (i, (id, port, rx)) in socks.enumerate() {
        let o = own.get(&id);
        let (bound, peer) = o.map_or(([0; 4], None), |o| (o.bound_ip, o.peer));
        let line = alloc::format!(
            "{:5}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 2 0000000000000000 0",
            i,
            if want6 { hex_addr6((bound, port)) } else { hex_addr((bound, port)) },
            if want6 { hex_addr6(peer.unwrap_or(([0; 4], 0))) } else { hex_addr(peer.unwrap_or(([0; 4], 0))) },
            if peer.is_some() { 1 } else { 7 },
            0,
            rx,
            o.map_or(0, |o| o.uid),
            0,
            o.map_or(0, |o| o.inode)
        );
        out.push_str(&pad(line, 127));
    }
    out
}
