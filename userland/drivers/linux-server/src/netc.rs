//! net-server's client (wave 5, step 3): linux-server talks to net-server directly
//! (endpoint [`ENDPOINT_NET_SERVER`]), as the kernel's `src/net/client.rs` does for the
//! in-kernel sockets (`lx=kernel`). The protocol is the same (`MSG_NETS_*`):
//!
//! - **Requests** answer at once (never waiting for the network): blocking is ours
//!   ([`crate::socket`] keeps blocked calls pending and retries them on readiness changes).
//! - **Payloads** go through net-server's window, in our part of its data area
//!   ([`NETS_LX_DATA_OFF`]): two regions, each taken by one thread for one request.
//! - **Readiness** is read from the window's readiness table without a call; net-server's
//!   doorbell reaches us as a notification ([`NOTIFY_LX_NET`]) and we take its event ring
//!   with a tail of our own ([`take_events`]).
//! - **A restarted net-server** ([`NOTIFY_LX_NET_GONE`]): its handles mean nothing any more;
//!   [`gen`] counts the instances, and a socket made under an older one is dead.
//!
//! Handles made here carry our client tag ([`NETS_CLIENT_LX`]), so that a restarted
//! linux-server can close what its predecessor left ([`reset`]).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::{sys, Message};

pub const ENETDOWN: i64 = -100;
pub const ECONNRESET: i64 = -104;
pub const ECONNREFUSED: i64 = -111;
const EMSGSIZE: i64 = -90;

/// IPv6's `::1`, carried as this IPv4-shaped value (as net-server and the kernel do).
pub const V6_LOOPBACK: [u8; 4] = [0, 0, 0, 1];
/// The card's IPv6 link-local address, carried the same way.
pub const V6_LINKLOCAL: [u8; 4] = [0, 0, 0, 2];

/// Whether `ip` is one of the IPv6 addresses above.
pub fn is_v6(ip: [u8; 4]) -> bool {
    ip == V6_LOOPBACK || ip == V6_LINKLOCAL
}

/// Linux's TCP states as net-server numbers them (`NETS_TCP_*`).
pub const SYN_SENT: u64 = NETS_TCP_SYN_SENT;
pub const CLOSED: u64 = NETS_TCP_CLOSED;

/// net-server's window in our address space (0: not attached yet).
static BASE: AtomicU64 = AtomicU64::new(0);
/// net-server instances seen go away (a socket made under an older count is dead).
static GEN: AtomicU64 = AtomicU64::new(0);
/// Events of net-server's ring taken so far.
static TAIL: AtomicU64 = AtomicU64::new(0);

/// The current net-server instance count (see [`GEN`]).
pub fn gen() -> u64 {
    GEN.load(Ordering::Acquire)
}

/// The window, attached on first use (net-server may start after us).
fn base() -> Option<u64> {
    let b = BASE.load(Ordering::Acquire);
    if b != 0 {
        return Some(b);
    }
    let b = sys::svc_attach(ENDPOINT_NET_SERVER).ok()?;
    BASE.store(b, Ordering::Release);
    Some(b)
}

/// Status word `i` (0 without a window).
fn status(i: usize) -> u64 {
    let Some(b) = base() else { return 0 };
    // SAFETY: the status page lies in the mapped window; only net-server writes it
    unsafe { core::ptr::read_volatile((b as usize + NETS_STATUS_OFF + 8 * i) as *const u64) }
}

/// Readiness word of handle `h` (`None` if it is not published).
fn word(h: u32) -> Option<u64> {
    let b = base()?;
    let slot = (h as usize) & (NETS_SLOTS - 1);
    // SAFETY: the readiness table lies in the mapped window
    let v = unsafe { core::ptr::read_volatile((b as usize + NETS_SOCKS_OFF + 8 * slot) as *const u64) };
    (v as u32 == h).then_some(v)
}

/// Readiness bits (`NETS_R_*`) of a word.
fn bits(w: u64) -> u64 {
    (w >> 32) & 0xFF
}

/// net-server went away (the kernel told us): its handles are dead from now on.
pub fn gone() {
    GEN.fetch_add(1, Ordering::AcqRel);
    TAIL.store(0, Ordering::Release);
}

/// The handles whose readiness changed since the last call, from net-server's event ring;
/// `None` when the ring overflowed (everything may have changed).
pub fn take_events() -> Option<Vec<u32>> {
    let b = base()?;
    let head = status(NETS_ST_EVENT_HEAD);
    let tail = TAIL.swap(head, Ordering::AcqRel);
    if head < tail || head - tail > NETS_EVENTS as u64 {
        return None;
    }
    core::sync::atomic::fence(Ordering::Acquire);
    Some(
        (tail..head)
            // SAFETY: the ring lies in the mapped window
            .map(|n| unsafe { core::ptr::read_volatile((b as usize + NETS_EVENTS_OFF + 4 * (n as usize % NETS_EVENTS)) as *const u32) })
            .collect(),
    )
}

// ----------------------------------------------------------------------
// Our part of the data area
// ----------------------------------------------------------------------

/// Regions of our part of the data area (each one request's payload at a time).
const REGIONS: usize = 2;
/// Bytes per region.
pub const REGION: usize = NETS_LX_DATA_LEN / REGIONS;
/// Regions in use (bit per region).
static BUSY: AtomicU32 = AtomicU32::new(0);

/// A region taken for one request (given back when dropped).
struct Region(usize);

impl Region {
    /// Takes a free region, yielding while both are in use.
    fn take() -> Self {
        loop {
            let b = BUSY.load(Ordering::Acquire);
            if let Some(i) = (0..REGIONS).find(|&i| b & (1 << i) == 0) {
                if BUSY.compare_exchange(b, b | 1 << i, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    return Region(i);
                }
                continue;
            }
            sys::yield_now();
        }
    }

    /// Its offset in the window (what requests name).
    fn off(&self) -> u64 {
        (NETS_LX_DATA_OFF + self.0 * REGION) as u64
    }

    /// Its bytes (the window must be attached).
    fn bytes(&self) -> &'static mut [u8] {
        let b = BASE.load(Ordering::Acquire) as usize;
        // SAFETY: inside the mapped window, ours alone while taken
        unsafe { core::slice::from_raw_parts_mut((b + self.off() as usize) as *mut u8, REGION) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        BUSY.fetch_and(!(1 << self.0), Ordering::AcqRel);
    }
}

// ----------------------------------------------------------------------
// Requests
// ----------------------------------------------------------------------

/// One request: the reply's words, or its negative errno (`ENETDOWN` without net-server).
fn request(label: u32, args: [u64; 4]) -> Result<[u64; 4], i64> {
    base().ok_or(ENETDOWN)?;
    match sys::svc_call(ENDPOINT_NET_SERVER, Message::new(label as u64, args), 0) {
        Ok(r) if (r.args[0] as i64) < 0 => Err(r.args[0] as i64),
        Ok(r) => Ok(r.args),
        Err(_) => Err(ENETDOWN),
    }
}

/// A request on handle `h` (in `args[0]`).
fn on(h: u32, label: u32, mut args: [u64; 4]) -> Result<[u64; 4], i64> {
    args[0] = h as u64;
    request(label, args)
}

/// Closes every handle a previous linux-server left in net-server (at start).
pub fn reset() {
    let _ = request(MSG_NETS_CLIENT_RESET, [NETS_CLIENT_LX, 0, 0, 0]);
}

/// An address as the protocol carries it.
fn addr(ip: [u8; 4]) -> u64 {
    u32::from_le_bytes(ip) as u64
}

/// The address in a protocol word.
fn ip_of(w: u64) -> [u8; 4] {
    (w as u32).to_le_bytes()
}

// ----------------------------------------------------------------------
// The interface
// ----------------------------------------------------------------------

/// The interface as net-server publishes it.
#[derive(Clone, Copy, Default)]
pub struct Iface {
    pub present: bool,
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub mask: [u8; 4],
    pub gateway: [u8; 4],
}

/// The interface (all zero without net-server).
pub fn iface() -> Iface {
    if status(NETS_ST_MAGIC) != NETS_MAGIC {
        return Iface::default();
    }
    let m = status(NETS_ST_MAC).to_le_bytes();
    Iface {
        present: status(NETS_ST_FLAGS) & NETS_F_NIC != 0,
        mac: [m[0], m[1], m[2], m[3], m[4], m[5]],
        ip: ip_of(status(NETS_ST_IP)),
        mask: ip_of(status(NETS_ST_MASK)),
        gateway: ip_of(status(NETS_ST_GATEWAY)),
    }
}

/// The card's link-local IPv6 address (`fe80::` + modified EUI-64 of the MAC).
pub fn link_local6() -> Option<[u8; 16]> {
    let i = iface();
    if !i.present {
        return None;
    }
    let m = i.mac;
    Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]])
}

/// Whether `ip` is one of ours.
pub fn is_local(ip: [u8; 4]) -> bool {
    if ip[0] == 127 || ip == V6_LOOPBACK {
        return true;
    }
    let i = iface();
    (ip == V6_LINKLOCAL && i.present) || (ip != [0, 0, 0, 0] && ip == i.ip)
}

/// Table `kind` of `MSG_NETS_LIST`, as records of words.
fn list(kind: u64) -> Vec<[u64; 8]> {
    if base().is_none() {
        return Vec::new();
    }
    let reg = Region::take();
    let cap = (REGION / NETS_LIST_RECORD) as u64;
    let Ok(r) = request(MSG_NETS_LIST, [kind, reg.off(), cap, 0]) else { return Vec::new() };
    let w = reg.bytes();
    (0..(r[0] as usize).min(cap as usize))
        .map(|i| core::array::from_fn(|j| u64::from_le_bytes(w[i * NETS_LIST_RECORD + j * 8..i * NETS_LIST_RECORD + j * 8 + 8].try_into().unwrap())))
        .collect()
}

/// TCP connections: `(handle, local, remote, state, bytes to send, bytes unread)`.
pub fn tcp_list() -> Vec<(u32, ([u8; 4], u16), ([u8; 4], u16), u64, usize, usize)> {
    list(0).into_iter().map(|r| (r[0] as u32, (ip_of(r[1] >> 16), r[1] as u16), (ip_of(r[2] >> 16), r[2] as u16), r[3], r[4] as usize, r[5] as usize)).collect()
}

/// Listeners: `(handle, address, port, waiting, backlog)`.
pub fn listener_list() -> Vec<(u32, [u8; 4], u16, usize, usize)> {
    list(1).into_iter().map(|r| (r[0] as u32, ip_of(r[1] >> 16), r[1] as u16, r[2] as usize, r[3] as usize)).collect()
}

/// UDP sockets: `(handle, port, bytes queued)`.
pub fn udp_list() -> Vec<(u32, u16, usize)> {
    list(2).into_iter().map(|r| (r[0] as u32, r[1] as u16, r[2] as usize)).collect()
}

// ----------------------------------------------------------------------
// TCP
// ----------------------------------------------------------------------

pub fn tcp_connect(ip: [u8; 4], port: u16, local_port: Option<u16>) -> Result<u32, i64> {
    request(MSG_NETS_TCP_CONNECT, [addr(ip), port as u64, local_port.unwrap_or(0) as u64, NETS_CLIENT_LX]).map(|r| r[0] as u32)
}

/// The state of connection `h` (`NETS_TCP_*`; [`CLOSED`] if unknown).
pub fn tcp_state(h: u32) -> u64 {
    word(h).map_or(CLOSED, |w| (w >> 40) & 0xFF)
}

/// Takes the pending error of connection `h` (`SO_ERROR`).
pub fn tcp_take_error(h: u32) -> Option<i64> {
    if word(h).is_some_and(|w| w >> 48 == 0) {
        return None;
    }
    match on(h, MSG_NETS_TCP_TAKE_ERROR, [0; 4]) {
        Ok(r) if r[0] != 0 => Some(-(r[0] as i64)),
        _ => None,
    }
}

/// Queues `data` (at most [`REGION`] bytes are taken) on connection `h`: bytes taken.
pub fn tcp_send(h: u32, data: &[u8]) -> Result<usize, i64> {
    base().ok_or(ENETDOWN)?;
    let reg = Region::take();
    let n = data.len().min(REGION);
    reg.bytes()[..n].copy_from_slice(&data[..n]);
    on(h, MSG_NETS_TCP_SEND, [0, reg.off(), n as u64, 0]).map(|r| r[0] as usize)
}

/// Reads up to `cap` bytes of connection `h` (`peek`: leaves them): `(bytes, end of stream)`.
pub fn tcp_recv(h: u32, cap: usize, peek: bool) -> Result<(Vec<u8>, bool), i64> {
    if word(h).is_some_and(|w| bits(w) & NETS_R_IN == 0) {
        return Ok((Vec::new(), false));
    }
    base().ok_or(ENETDOWN)?;
    let reg = Region::take();
    let cap = cap.min(REGION);
    let r = on(h, MSG_NETS_TCP_RECV, [0, reg.off(), cap as u64, peek as u64])?;
    let n = (r[0] as usize).min(cap);
    Ok((reg.bytes()[..n].to_vec(), r[1] != 0))
}

/// Bytes queued to read on connection `h` (`FIONREAD`): a peek of everything.
pub fn tcp_pending(h: u32) -> usize {
    tcp_recv(h, REGION, true).map_or(0, |(d, _)| d.len())
}

/// `(readable, writable, hang up, error)` of connection `h`.
pub fn tcp_poll(h: u32) -> (bool, bool, bool, bool) {
    match word(h) {
        Some(w) => {
            let b = bits(w);
            (b & NETS_R_IN != 0, b & NETS_R_OUT != 0, b & NETS_R_HUP != 0, b & NETS_R_ERR != 0)
        }
        None => (true, false, true, true),
    }
}

pub fn tcp_shutdown_write(h: u32) {
    let _ = on(h, MSG_NETS_TCP_SHUTDOWN, [0; 4]);
}

pub fn tcp_close(h: u32) {
    let _ = on(h, MSG_NETS_TCP_CLOSE, [0; 4]);
}

/// `(local port, remote address, remote port, local address)` of connection `h`.
pub fn tcp_info(h: u32) -> Option<(u16, [u8; 4], u16, [u8; 4])> {
    let r = on(h, MSG_NETS_TCP_INFO, [0; 4]).ok()?;
    Some((r[1] as u16, ip_of(r[2] >> 16), r[2] as u16, ip_of(r[1] >> 16)))
}

pub fn tcp_bind(ip: [u8; 4], port: u16, reuse_addr: bool, reuse_port: bool, v4: bool, v6: bool) -> Result<(u32, u16), i64> {
    let flags = reuse_addr as u64 | (reuse_port as u64) << 1 | (v4 as u64) << 2 | (v6 as u64) << 3;
    request(MSG_NETS_TCP_BIND, [addr(ip), port as u64, flags, NETS_CLIENT_LX]).map(|r| (r[0] as u32, r[1] as u16))
}

pub fn tcp_unbind(h: u32) {
    let _ = on(h, MSG_NETS_TCP_UNBIND, [0; 4]);
}

pub fn tcp_listen(bind: u32, backlog: usize) -> Result<u32, i64> {
    on(bind, MSG_NETS_TCP_LISTEN, [0, backlog as u64, 0, 0]).map(|r| r[0] as u32)
}

pub fn tcp_set_backlog(h: u32, backlog: usize) {
    let _ = on(h, MSG_NETS_TCP_BACKLOG, [0, backlog as u64, 0, 0]);
}

/// The next established connection of listener `h`.
pub fn tcp_accept(h: u32) -> Option<u32> {
    if word(h).is_some_and(|w| bits(w) & NETS_R_ACCEPT == 0) {
        return None;
    }
    on(h, MSG_NETS_TCP_ACCEPT, [0; 4]).ok().map(|r| r[0] as u32)
}

/// Whether listener `h` has a connection waiting.
pub fn tcp_acceptable(h: u32) -> bool {
    word(h).is_some_and(|w| bits(w) & NETS_R_ACCEPT != 0)
}

pub fn tcp_unlisten(h: u32) {
    let _ = on(h, MSG_NETS_TCP_UNLISTEN, [0; 4]);
}

// ----------------------------------------------------------------------
// UDP
// ----------------------------------------------------------------------

pub fn udp_open(port: u16) -> Result<u32, i64> {
    request(MSG_NETS_UDP_OPEN, [port as u64, 0, 0, NETS_CLIENT_LX]).map(|r| r[0] as u32)
}

pub fn udp_rebind(h: u32, port: u16) -> Result<(), i64> {
    on(h, MSG_NETS_UDP_REBIND, [0, port as u64, 0, 0]).map(|_| ())
}

pub fn udp_port(h: u32) -> u16 {
    on(h, MSG_NETS_UDP_PORT, [0; 4]).map_or(0, |r| r[0] as u16)
}

pub fn udp_send(h: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
    base().ok_or(ENETDOWN)?;
    if data.len() > REGION {
        return Err(EMSGSIZE);
    }
    let reg = Region::take();
    reg.bytes()[..data.len()].copy_from_slice(data);
    on(h, MSG_NETS_UDP_SEND, [0, addr(ip) << 16 | port as u64, reg.off(), data.len() as u64]).map(|r| r[0] as usize)
}

/// The next datagram of UDP socket `h` (at most [`REGION`] bytes of it): `(source, port,
/// payload, its whole length, arrival time)`.
pub fn udp_recv(h: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>, usize, u64)> {
    if word(h).is_some_and(|w| bits(w) & NETS_R_IN == 0) {
        return None;
    }
    base()?;
    let reg = Region::take();
    let r = on(h, MSG_NETS_UDP_RECV, [0, reg.off(), peek as u64, REGION as u64]).ok()?;
    let n = (r[3] as usize).min(REGION);
    Some((ip_of(r[1] >> 16), r[1] as u16, reg.bytes()[..n].to_vec(), r[0] as usize, r[2]))
}

pub fn udp_readable(h: u32) -> bool {
    word(h).is_some_and(|w| bits(w) & NETS_R_IN != 0)
}

pub fn udp_close(h: u32) {
    let _ = on(h, MSG_NETS_UDP_CLOSE, [0; 4]);
}

// ----------------------------------------------------------------------
// ICMP
// ----------------------------------------------------------------------

/// A raw or ping ICMP socket (0: none, without net-server: dead from the start).
pub fn icmp_open(raw: bool, v6: bool) -> u32 {
    request(MSG_NETS_ICMP_OPEN, [raw as u64, v6 as u64, 0, NETS_CLIENT_LX]).map_or(0, |r| r[0] as u32)
}

pub fn icmp_ident(h: u32) -> u16 {
    on(h, MSG_NETS_ICMP_IDENT, [0; 4]).map_or(0, |r| r[0] as u16)
}

pub fn icmp_set_ident(h: u32, ident: u16) -> Result<(), i64> {
    on(h, MSG_NETS_ICMP_SET_IDENT, [0, ident as u64, 0, 0]).map(|_| ())
}

pub fn icmp_send(h: u32, dst: [u8; 4], msg: &[u8]) -> Result<usize, i64> {
    base().ok_or(ENETDOWN)?;
    if msg.len() > REGION {
        return Err(EMSGSIZE);
    }
    let reg = Region::take();
    reg.bytes()[..msg.len()].copy_from_slice(msg);
    on(h, MSG_NETS_ICMP_SEND, [0, addr(dst), reg.off(), msg.len() as u64]).map(|r| r[0] as usize)
}

/// The next message of ICMP socket `h`: `(source, payload, arrival time)`.
pub fn icmp_recv(h: u32, peek: bool) -> Option<([u8; 4], Vec<u8>, u64)> {
    if word(h).is_some_and(|w| bits(w) & NETS_R_IN == 0) {
        return None;
    }
    base()?;
    let reg = Region::take();
    let r = on(h, MSG_NETS_ICMP_RECV, [0, reg.off(), peek as u64, REGION as u64]).ok()?;
    let n = (r[3] as usize).min(REGION);
    Some((ip_of(r[1]), reg.bytes()[..n].to_vec(), r[2]))
}

pub fn icmp_readable(h: u32) -> bool {
    word(h).is_some_and(|w| bits(w) & NETS_R_IN != 0)
}

pub fn icmp_close(h: u32) {
    let _ = on(h, MSG_NETS_ICMP_CLOSE, [0; 4]);
}
