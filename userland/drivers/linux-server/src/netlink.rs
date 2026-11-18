//! `AF_NETLINK` sockets (wave 5, step 3): the kernel's `src/compat/linux/rtnetlink.rs`
//! (routing sockets, `NETLINK_ROUTE`) and `netlink.rs` (kernel uevents,
//! `NETLINK_KOBJECT_UEVENT`), which stay for `lx=kernel`, moved here. Each socket is a
//! server object of kind [`LX_OBJ_KIND_NETLINK`].
//!
//! A routing socket answers dump requests for links, addresses and routes (the loopback
//! interface and, once it has an address, `eth0`; only loopback in a network namespace of
//! its own) by queueing reply datagrams; a receive takes them. A uevent socket never has a
//! message (Hydra's devices are fixed at boot): a blocking receive waits for a signal.
//! glibc's `mq_notify(SIGEV_THREAD)` passes a routing socket for its helper thread: message
//! queue notifications reach it through [`pin`] and [`deliver`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use hydra_rt::protocol::*;

use crate::client::Cx;
use crate::lock::YLock;
use crate::netc;
use crate::socket::{Out, Prog};

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPROTONOSUPPORT: i64 = -93;
const EOPNOTSUPP: i64 = -95;
const EAFNOSUPPORT: i64 = -97;
const ENOTSOCK: i64 = -88;

const AF_NETLINK: u16 = 16;
const AF_INET: u8 = 2;
const NETLINK_ROUTE: u64 = 0;
const NETLINK_KOBJECT_UEVENT: u64 = 15;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2000000;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const MSG_PEEK: u64 = 2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

/// One netlink socket.
struct Nl {
    /// A routing socket (else a uevent one).
    route: bool,
    /// Port ID (`nl_pid`): the process ID unless bound to another.
    port: AtomicU32,
    groups: AtomicU32,
    /// Datagrams not yet received.
    replies: YLock<VecDeque<Vec<u8>>>,
    /// Its slot (for waking receivers of a notification).
    slot: u32,
}

/// The sockets, by slot.
static SOCKS: YLock<BTreeMap<u32, Arc<Nl>>> = YLock::new(BTreeMap::new());
/// Sockets kept for message queue notifications, by token.
static PINS: YLock<BTreeMap<u64, Arc<Nl>>> = YLock::new(BTreeMap::new());
static NEXT_PIN: AtomicU64 = AtomicU64::new(1);
/// Tokens of [`pin`] carry this bit (the kernel's own `LX_OBJ_PIN` tokens never do).
pub const PIN_BIT: u64 = 1 << 62;

fn sock_of(slot: u32) -> Option<Arc<Nl>> {
    SOCKS.lock().get(&slot).cloned()
}

/// `socket(AF_NETLINK, type, protocol)`.
pub fn socket(cx: &Cx) -> i64 {
    let ty = cx.args[1];
    if ty & 0xF != 3 && ty & 0xF != 2 {
        return EPROTONOSUPPORT;
    }
    let route = match cx.args[2] {
        NETLINK_ROUTE => true,
        NETLINK_KOBJECT_UEVENT => false,
        _ => return EAFNOSUPPORT,
    };
    let slot = match crate::obj::alloc(LX_OBJ_KIND_NETLINK) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nl = Arc::new(Nl { route, port: AtomicU32::new(cx.c.tgid as u32), groups: AtomicU32::new(0), replies: YLock::new(VecDeque::new()), slot });
    SOCKS.lock().insert(slot, nl);
    crate::obj::set_ready(slot, 0x4, 0);
    let name = alloc::format!("socket:[{}]", 0x4_0000 + slot);
    match crate::obj::install(cx, slot, LX_OBJ_KIND_NETLINK, ty as u32 & (SOCK_NONBLOCK | SOCK_CLOEXEC), 0o140777, cx.c.euid, cx.c.egid, name.as_bytes()) {
        Ok(fd) => fd,
        Err(e) => {
            SOCKS.lock().remove(&slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            e
        }
    }
}

/// The last descriptor of slot `slot` went away.
pub fn closed(slot: u32) {
    SOCKS.lock().remove(&slot);
}

/// Writes slot `slot`'s readiness word: writable, and readable while a datagram waits.
pub fn refresh(slot: u32) {
    if let Some(s) = sock_of(slot) {
        let bits = 0x4 | if s.replies.lock().is_empty() { 0 } else { 0x1 };
        crate::obj::set_ready_ev(slot, bits, 0, bits & 1 != 0);
    }
}

/// Keeps the netlink socket at descriptor `fd` of the caller for message queue
/// notifications (glibc's `SIGEV_THREAD`): its token, if `fd` is one of ours.
pub fn pin(cx: &Cx, fd: u64) -> Option<u64> {
    let (slot, kind, _) = crate::obj::of_fd(cx, fd).ok()?;
    if kind != LX_OBJ_KIND_NETLINK {
        return None;
    }
    let s = sock_of(slot)?;
    let token = PIN_BIT | NEXT_PIN.fetch_add(1, Ordering::Relaxed);
    PINS.lock().insert(token, s);
    Some(token)
}

/// Queues `data` on the socket kept as `token` and wakes its receivers.
pub fn deliver(token: u64, data: &[u8]) {
    let Some(s) = PINS.lock().get(&token).cloned() else { return };
    s.replies.lock().push_back(data.to_vec());
    if sock_of(s.slot).is_some_and(|x| Arc::ptr_eq(&x, &s)) {
        refresh(s.slot);
        crate::socket::poke(s.slot);
    }
}

/// Lets a kept socket go.
pub fn unpin(token: u64) {
    PINS.lock().remove(&token);
}

// ----------------------------------------------------------------------
// The interfaces, as the kernel's rtnetlink.rs describes them
// ----------------------------------------------------------------------

fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn message(out: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, port: u32, body: &[u8]) {
    out.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// The Ethernet interface's `(mac, ip, netmask, gateway)`, if it has an address and the
/// caller can see it.
fn ethernet(isolated: bool) -> Option<([u8; 6], [u8; 4], [u8; 4], [u8; 4])> {
    let i = netc::iface();
    if isolated || !i.present {
        return None;
    }
    (i.ip != [0; 4]).then_some((i.mac, i.ip, i.mask, i.gateway))
}

fn links(isolated: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let link = |kind: u16, index: i32, flags: u32, name: &[u8], mac: &[u8], broadcast: &[u8], mtu: u32| {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&index.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        attr(&mut b, 3, name);
        attr(&mut b, 4, &mtu.to_le_bytes());
        attr(&mut b, 1, mac);
        attr(&mut b, 2, broadcast);
        attr(&mut b, 16, &[6]);
        b
    };
    out.push(link(772, 1, 0x1 | 0x8 | 0x40 | 0x10000, b"lo\0", &[0; 6], &[0; 6], 65536));
    if let Some((mac, ..)) = ethernet(isolated) {
        out.push(link(1, 2, 0x1 | 0x2 | 0x40 | 0x1000 | 0x10000, b"eth0\0", &mac, &[0xff; 6], 1500));
    }
    out
}

fn addresses(family: u8, isolated: bool) -> Vec<Vec<u8>> {
    let mut out = if family == 10 { Vec::new() } else { addresses4(isolated) };
    if family == 0 || family == 10 {
        let addr6 = |index: u32, ip: [u8; 16], prefix: u8, scope: u8| {
            let mut b = alloc::vec![10u8, prefix, 0x80, scope];
            b.extend_from_slice(&index.to_le_bytes());
            attr(&mut b, 1, &ip);
            attr(&mut b, 8, &0x80u32.to_le_bytes());
            b
        };
        let mut lo = [0u8; 16];
        lo[15] = 1;
        out.push(addr6(1, lo, 128, 254));
        if let Some(ll) = netc::link_local6() {
            if ethernet(isolated).is_some() {
                out.push(addr6(2, ll, 64, 253));
            }
        }
    }
    out
}

fn addresses4(isolated: bool) -> Vec<Vec<u8>> {
    let addr = |index: u32, ip: [u8; 4], prefix: u8, scope: u8, label: &[u8], broadcast: Option<[u8; 4]>| {
        let mut b = alloc::vec![AF_INET, prefix, 0x80, scope];
        b.extend_from_slice(&index.to_le_bytes());
        attr(&mut b, 1, &ip);
        attr(&mut b, 2, &ip);
        if let Some(bc) = broadcast {
            attr(&mut b, 4, &bc);
        }
        attr(&mut b, 3, label);
        attr(&mut b, 8, &0x80u32.to_le_bytes());
        b
    };
    let mut out = alloc::vec![addr(1, [127, 0, 0, 1], 8, 254, b"lo\0", None)];
    if let Some((_, ip, mask, _)) = ethernet(isolated) {
        let prefix = u32::from_be_bytes(mask).count_ones() as u8;
        let bc = (u32::from_be_bytes(ip) | !u32::from_be_bytes(mask)).to_be_bytes();
        out.push(addr(2, ip, prefix, 0, b"eth0\0", Some(bc)));
    }
    out
}

fn routes(isolated: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some((_, ip, mask, gateway)) = ethernet(isolated) {
        let route = |dst_len: u8, protocol: u8, scope: u8| {
            let mut b = alloc::vec![AF_INET, dst_len, 0, 0, 254, protocol, scope, 1];
            b.extend_from_slice(&0u32.to_le_bytes());
            attr(&mut b, 15, &254u32.to_le_bytes());
            b
        };
        let prefix = u32::from_be_bytes(mask).count_ones() as u8;
        if gateway != [0; 4] {
            let mut b = route(0, 16, 0);
            attr(&mut b, 5, &gateway);
            attr(&mut b, 4, &2u32.to_le_bytes());
            out.push(b);
        }
        let mut b = route(prefix, 2, 253);
        attr(&mut b, 1, &(u32::from_be_bytes(ip) & u32::from_be_bytes(mask)).to_be_bytes());
        attr(&mut b, 7, &ip);
        attr(&mut b, 4, &2u32.to_le_bytes());
        out.push(b);
    }
    out
}

impl Nl {
    /// Answers the requests in one sent datagram (a routing socket), queueing a reply
    /// datagram for each.
    fn handle(&self, data: &[u8], isolated: bool) {
        if !self.route {
            return;
        }
        let port = self.port.load(Ordering::Relaxed);
        let mut off = 0;
        while off + 16 <= data.len() {
            let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            if len < 16 || off + len > data.len() {
                break;
            }
            let ty = u16::from_le_bytes([data[off + 4], data[off + 5]]);
            let flags = u16::from_le_bytes([data[off + 6], data[off + 7]]);
            let seq = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
            let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
            let mut reply = Vec::new();
            let parts = match ty {
                RTM_GETLINK if dump => Some((RTM_NEWLINK, links(isolated))),
                RTM_GETADDR if dump => Some((RTM_NEWADDR, addresses(data.get(off + 16).copied().unwrap_or(0), isolated))),
                RTM_GETROUTE if dump => Some((RTM_NEWROUTE, routes(isolated))),
                _ => None,
            };
            match parts {
                Some((kind, bodies)) => {
                    for b in bodies {
                        message(&mut reply, kind, NLM_F_MULTI, seq, port, &b);
                    }
                    message(&mut reply, NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_le_bytes());
                }
                None => {
                    // lo is always up with 127.0.0.1 (bubblewrap's new namespace setup
                    // succeeds); any other change is refused
                    let index = data.get(off + 20..off + 24).map(|b| i32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
                    let error = match ty {
                        RTM_NEWLINK | RTM_NEWADDR if index == 1 => 0,
                        RTM_NEWLINK | RTM_NEWADDR | 17 | 21 | 25 => -1,
                        _ => EOPNOTSUPP as i32,
                    };
                    let mut b = error.to_le_bytes().to_vec();
                    b.extend_from_slice(&data[off..off + 16]);
                    message(&mut reply, NLMSG_ERROR, 0, seq, port, &b);
                }
            }
            self.replies.lock().push_back(reply);
            off += (len + 3) & !3;
        }
    }

    /// The next datagram (a copy with `peek`); `Err(EAGAIN)` when none waits and the call
    /// must not wait, `Ok(None)` when it must.
    fn next(&self, peek: bool, nonblock: bool) -> Result<Option<Vec<u8>>, i64> {
        let mut q = self.replies.lock();
        let d = if peek { q.front().cloned() } else { q.pop_front() };
        match d {
            Some(d) => Ok(Some(d)),
            None if nonblock => Err(EAGAIN),
            None => Ok(None),
        }
    }

    fn sockaddr(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
        b[4..8].copy_from_slice(&self.port.load(Ordering::Relaxed).to_le_bytes());
        b[8..12].copy_from_slice(&self.groups.load(Ordering::Relaxed).to_le_bytes());
        b
    }
}

/// The kernel side's address (`struct sockaddr_nl`, port 0).
fn kernel_addr() -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
    b
}

fn put_addr(cx: &Cx, addr: u64, lenp: u64, data: &[u8]) -> i64 {
    if addr == 0 || lenp == 0 {
        return 0;
    }
    let cap = match cx.copy_in(lenp, 4) {
        Ok(v) => u32::from_le_bytes(v[..4].try_into().unwrap()) as usize,
        Err(e) => return e,
    };
    if cx.copy_out_any(addr, &data[..cap.min(data.len())]).is_err() || cx.copy_out(lenp, &(data.len() as u32).to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

fn iovecs(cx: &Cx, msg: &[u8]) -> Result<Vec<(u64, usize)>, i64> {
    let iov = Cx::u64_at(msg, 16);
    let n = (Cx::u64_at(msg, 24) as usize).min(64);
    let raw = cx.copy_in_any(iov, n * 16)?;
    Ok(raw.chunks(16).map(|c| (Cx::u64_at(c, 0), Cx::u64_at(c, 8) as usize)).collect())
}

/// One attempt at call `cx` on its netlink socket.
pub fn call(cx: &Cx, _prog: &mut Prog) -> Out {
    let Some(s) = sock_of(cx.c.obj as u32) else { return Out::Done(-9) };
    let a = cx.args;
    let isolated = cx.c.obj_flags & LX_OBJ_FLAGS_NETNS != 0;
    let nb = |flags: u64| cx.nonblock() || flags & MSG_DONTWAIT != 0;
    let r = match cx.nr {
        49 => {
            let addr = match cx.copy_in(a[1], 12) {
                Ok(v) => v,
                Err(e) => return Out::Done(e),
            };
            let port = u32::from_le_bytes(addr[4..8].try_into().unwrap());
            if port != 0 {
                s.port.store(port, Ordering::Relaxed);
            } else if !s.route {
                s.port.store(cx.c.tgid as u32, Ordering::Relaxed);
            }
            s.groups.store(u32::from_le_bytes(addr[8..12].try_into().unwrap()), Ordering::Relaxed);
            0
        }
        51 => put_addr(cx, a[1], a[2], &s.sockaddr()),
        52 => put_addr(cx, a[1], a[2], &kernel_addr()),
        42 if s.route => 0,
        54 => 0,
        55 => {
            let v: u32 = match (a[1], a[2]) {
                (1, 3) => 3,
                (1, 7) | (1, 8) => 212_992,
                (1, 38) => if s.route { 0 } else { NETLINK_KOBJECT_UEVENT as u32 },
                (1, 39) => AF_NETLINK as u32,
                _ => 0,
            };
            if cx.copy_out(a[3], &v.to_le_bytes()).is_err() || cx.copy_out(a[4], &4u32.to_le_bytes()).is_err() {
                EFAULT
            } else {
                0
            }
        }
        44 | 1 => match cx.copy_in_any(a[1], (a[2] as usize).min(65536)) {
            Ok(d) => {
                s.handle(&d, isolated);
                a[2] as i64
            }
            Err(e) => e,
        },
        46 => {
            let msg = match cx.copy_in(a[1], 56) {
                Ok(m) => m,
                Err(e) => return Out::Done(e),
            };
            let mut data = Vec::new();
            for (base, len) in match iovecs(cx, &msg) {
                Ok(v) => v,
                Err(e) => return Out::Done(e),
            } {
                match cx.copy_in_any(base, len.min(65536)) {
                    Ok(d) => data.extend_from_slice(&d),
                    Err(e) => return Out::Done(e),
                }
            }
            s.handle(&data, isolated);
            data.len() as i64
        }
        45 | 0 => {
            let flags = if cx.nr == 45 { a[3] } else { 0 };
            match s.next(flags & MSG_PEEK != 0, nb(flags)) {
                Ok(Some(d)) => {
                    let n = d.len().min(a[2] as usize);
                    if cx.copy_out_any(a[1], &d[..n]).is_err() {
                        return Out::Done(EFAULT);
                    }
                    if cx.nr == 45 {
                        let r = put_addr(cx, a[4], a[5], &kernel_addr());
                        if r != 0 {
                            return Out::Done(r);
                        }
                    }
                    if flags & MSG_TRUNC != 0 {
                        d.len() as i64
                    } else {
                        n as i64
                    }
                }
                Ok(None) => return Out::Block,
                Err(e) => e,
            }
        }
        47 | 299 => {
            // recvmsg (recvmmsg: its first message only)
            let msgp = if cx.nr == 299 { a[1] } else { a[1] };
            let flags = if cx.nr == 299 { a[3] } else { a[2] };
            let mut msg = match cx.copy_in(msgp, 56) {
                Ok(m) => m,
                Err(e) => return Out::Done(e),
            };
            let iovs = match iovecs(cx, &msg) {
                Ok(v) => v,
                Err(e) => return Out::Done(e),
            };
            let d = match s.next(flags & MSG_PEEK != 0, nb(flags)) {
                Ok(Some(d)) => d,
                Ok(None) => return Out::Block,
                Err(e) => return Out::Done(e),
            };
            let mut done = 0;
            for (base, len) in iovs {
                let n = len.min(d.len() - done);
                if n > 0 && cx.copy_out(base, &d[done..done + n]).is_err() {
                    return Out::Done(EFAULT);
                }
                done += n;
            }
            let name = Cx::u64_at(&msg, 0);
            if name != 0 && u32::from_le_bytes(msg[8..12].try_into().unwrap()) >= 12 {
                let _ = cx.copy_out(name, &kernel_addr());
                msg[8..12].copy_from_slice(&12u32.to_le_bytes());
            }
            msg[40..48].copy_from_slice(&0u64.to_le_bytes());
            msg[48..52].copy_from_slice(&(if done < d.len() { MSG_TRUNC as u32 } else { 0 }).to_le_bytes());
            let _ = cx.copy_out(msgp, &msg);
            let r = if flags & MSG_TRUNC != 0 { d.len() as i64 } else { done as i64 };
            if cx.nr == 299 {
                let _ = cx.copy_out(msgp + 56, &(r as u32).to_le_bytes());
                1
            } else {
                r
            }
        }
        48 => 0,
        42 | 43 | 50 | 288 => EINVAL,
        16 => ENOTTY,
        19 | 20 | 307 => EINVAL,
        _ => ENOTSOCK,
    };
    Out::Done(r)
}
