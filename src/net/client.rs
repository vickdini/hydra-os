//! # Network: the kernel's client of net-server (sockets)
//!
//! The TCP/UDP/ICMP sockets of the Linux personality live in net-server, a Ring 3 server
//! (`userland/drivers/net-server`, endpoint [`ENDPOINT_NET_SERVER`]); this module is the
//! kernel's side of its protocol (`MSG_NETS_*` in [`crate::ipc::protocol`]). It keeps the
//! interface the in-kernel stack had (`tcp_connect`, `udp_recv`, `tcp_poll`, ...), so the
//! socket layer (`compat/linux/inet.rs`) is unchanged in shape.
//!
//! ## How it works
//!
//! - **Requests:** each operation is one hand-off call ([`service::call`]): callers may
//!   hold socket locks. None of them waits for the network; payloads go through the
//!   server's window (held with [`service::hold_window`] from writing the request until the
//!   reply is read).
//! - **Readiness without a call:** the server keeps a readiness word per socket in its
//!   window's status area; [`tcp_poll`], [`udp_readable`], [`tcp_state`], ... read it.
//! - **Waking:** blocked callers sleep on the socket's [`WaitQueue`] (made here, per
//!   handle). When readiness changes, the server lists the handles in the event ring and
//!   rings the doorbell; [`on_signal`] wakes their queues.
//! - **Server restarts:** a handle belongs to the server process that made it. When that
//!   process goes away ([`on_signal`] with `SIGNAL_GONE`), every waiter wakes, and the
//!   handles read as reset connections and failed sockets from then on (errors, never a
//!   hang); new sockets go to the restarted server.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::protocol::*;
use crate::ipc::service::{self, CALL_TIMEOUT_TICKS};
use crate::ipc::Message;
use crate::task::wait::WaitQueue;

/// Linux errno for Connection Refused (`-111`).
pub const ECONNREFUSED: i64 = -111;
/// Linux errno for Connection Reset by Peer (`-104`).
pub const ECONNRESET: i64 = -104;
/// Linux errno for Connection Timed Out (`-110`).
pub const ETIMEDOUT: i64 = -110;
/// Linux errno for Transport Endpoint Is Not Connected (`-107`).
pub const ENOTCONN: i64 = -107;
/// Linux errno for Broken Pipe (`-32`).
pub const EPIPE: i64 = -32;
/// Linux errno for Network Is Unreachable (`-101`).
pub const ENETUNREACH: i64 = -101;
/// Linux errno for Network Is Down (`-100`): the network server is gone.
pub const ENETDOWN: i64 = -100;

/// Most bytes moved by one send or receive request.
const CHUNK: usize = 128 * 1024;

/// RFC 793 TCP connection states (as net-server reports them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// `SYN` sent; waiting for a matching `SYN-ACK` from the remote peer.
    SynSent,
    /// `SYN` received on a listening port and `SYN-ACK` sent; waiting for the final `ACK`.
    SynReceived,
    /// Connection established; bidirectional data transfer active.
    Established,
    /// Application closed writing and sent `FIN`; waiting for `ACK` or peer `FIN`.
    FinWait1,
    /// Our `FIN` has been acknowledged; waiting for the peer's `FIN`.
    FinWait2,
    /// Peer sent `FIN`; waiting for the local application to close writing.
    CloseWait,
    /// Peer sent `FIN` and local application closed; waiting for `ACK` of our `FIN`.
    LastAck,
    /// Both sides sent `FIN` simultaneously; waiting for `ACK` of our `FIN`.
    Closing,
    /// Both `FIN`s acknowledged; waiting before final cleanup.
    TimeWait,
    /// Connection is completely closed or reset.
    Closed,
}

impl TcpState {
    /// The state numbered `n` by the protocol (`NETS_TCP_*`).
    fn from_number(n: u64) -> Self {
        match n {
            NETS_TCP_SYN_SENT => Self::SynSent,
            NETS_TCP_SYN_RECEIVED => Self::SynReceived,
            NETS_TCP_ESTABLISHED => Self::Established,
            NETS_TCP_FIN_WAIT1 => Self::FinWait1,
            NETS_TCP_FIN_WAIT2 => Self::FinWait2,
            NETS_TCP_CLOSE_WAIT => Self::CloseWait,
            NETS_TCP_LAST_ACK => Self::LastAck,
            NETS_TCP_CLOSING => Self::Closing,
            NETS_TCP_TIME_WAIT => Self::TimeWait,
            _ => Self::Closed,
        }
    }
}

/// IPv6's loopback address `::1`, carried internally as this IPv4-shaped value (from
/// `0.0.0.0/8`, which IPv4 sockets never reach); only loopback traffic uses it.
pub const V6_LOOPBACK: [u8; 4] = [0, 0, 0, 1];
/// The network card's IPv6 link-local address (`fe80::` from its MAC, as Linux assigns one
/// to every interface), carried the same way: usable on this host only.
pub const V6_LINKLOCAL: [u8; 4] = [0, 0, 0, 2];

/// Whether `ip` is one of the IPv6 addresses above.
pub fn is_v6(ip: [u8; 4]) -> bool {
    ip == V6_LOOPBACK || ip == V6_LINKLOCAL
}

// ----------------------------------------------------------------------
// Handles, the status area and the doorbell
// ----------------------------------------------------------------------

/// A socket the kernel holds. The kernel names it by a handle of its own (what the socket
/// layer stores): a restarted server may hand out the numbers of its predecessor again,
/// and a socket of the old server must never reach a new one's.
struct Handle {
    /// The server process it belongs to.
    server: u64,
    /// The server's handle.
    sid: u32,
    /// Its waiters.
    wq: Arc<WaitQueue>,
}

/// Sockets in use, by kernel handle.
static HANDLES: Mutex<BTreeMap<u32, Handle>> = Mutex::new(BTreeMap::new());
/// The running server's handles to kernel handles (for the doorbell and the tables).
static BY_SID: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());
/// Next kernel handle.
static NEXT_KID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
/// Events of the ring taken so far ([`on_signal`]).
static EVENT_TAIL: AtomicU64 = AtomicU64::new(0);

/// Runs `f` on the handles with interrupts off (the doorbell runs in the server's system
/// call; a holder must not be preempted while it spins).
fn handles<R>(f: impl FnOnce(&mut BTreeMap<u32, Handle>, &mut BTreeMap<u32, u32>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut HANDLES.lock(), &mut BY_SID.lock()))
}

/// The process serving the network (0: none).
fn server() -> u64 {
    service::server_of(ENDPOINT_NET_SERVER)
}

/// Starts tracking server handle `sid`, just made by the current server: the kernel
/// handle for it.
fn track(sid: u32) -> u32 {
    let server = server();
    let mut kid = NEXT_KID.fetch_add(1, Ordering::Relaxed);
    if kid == 0 {
        kid = NEXT_KID.fetch_add(1, Ordering::Relaxed);
    }
    handles(|h, by| {
        h.insert(kid, Handle { server, sid, wq: WaitQueue::new_shared() });
        by.insert(sid, kid);
    });
    kid
}

/// Stops tracking socket `id` (closed), waking anyone still waiting on it.
fn untrack(id: u32) {
    let gone = handles(|h, by| {
        let x = h.remove(&id)?;
        if by.get(&x.sid) == Some(&id) {
            by.remove(&x.sid);
        }
        Some(x)
    });
    if let Some(x) = gone {
        x.wq.wake_all();
    }
}

/// The server's handle for socket `id`, if it belongs to the running server (it is not a
/// leftover of a server that went away).
fn sid(id: u32) -> Option<u32> {
    let s = server();
    if s == 0 {
        return None;
    }
    handles(|h, _| h.get(&id).filter(|x| x.server == s).map(|x| x.sid))
}

/// Whether socket `id` belongs to the running server.
fn alive(id: u32) -> bool {
    sid(id).is_some()
}

/// Whether socket `id` died with its server (its operations fail from now on).
pub fn dead(id: u32) -> bool {
    !alive(id)
}

/// The kernel handle of the running server's handle `sid` (0 if the kernel holds none).
fn kid_of(sid: u32) -> u32 {
    handles(|_, by| by.get(&sid).copied().unwrap_or(0))
}

/// Reads status-area word `i` of the server's window.
fn status_word(w: &[u8], i: usize) -> u64 {
    unsafe { core::ptr::read_volatile((w.as_ptr().add(NETS_STATUS_OFF) as *const u64).add(i)) }
}

/// The readiness word of live socket `id` (`None` if it is not live or not published).
fn word(id: u32) -> Option<u64> {
    let sid = sid(id)?;
    let w = service::window(ENDPOINT_NET_SERVER)?;
    let slot = (sid as usize) & (NETS_SLOTS - 1);
    let v = unsafe { core::ptr::read_volatile((w.as_ptr().add(NETS_SOCKS_OFF) as *const u64).add(slot)) };
    (v as u32 == sid).then_some(v)
}

/// Readiness bits (`NETS_R_*`) of a readiness word.
fn bits(w: u64) -> u64 {
    (w >> 32) & 0xFF
}

/// The doorbell hook (`ipc::service::set_signal_hook`): wakes the waiters of the sockets
/// the server listed in the event ring; all of them when the server went away
/// (`SIGNAL_GONE`) or the ring overflowed.
pub fn on_signal(arg: u64) {
    if arg == service::SIGNAL_GONE {
        // Its handles mean nothing any more; the sockets stay (dead) until closed
        EVENT_TAIL.store(0, Ordering::Release);
        handles(|_, by| by.clear());
        wake_all();
        return;
    }
    let Some(w) = service::window(ENDPOINT_NET_SERVER) else { return };
    let head = status_word(w, NETS_ST_EVENT_HEAD);
    let tail = EVENT_TAIL.swap(head, Ordering::AcqRel);
    if head < tail || head - tail > NETS_EVENTS as u64 {
        wake_all();
        return;
    }
    let ids: Vec<u32> = (tail..head)
        .map(|n| unsafe { core::ptr::read_volatile((w.as_ptr().add(NETS_EVENTS_OFF) as *const u32).add(n as usize % NETS_EVENTS)) })
        .collect();
    let queues: Vec<Arc<WaitQueue>> = handles(|h, by| ids.iter().filter_map(|sid| by.get(sid).and_then(|k| h.get(k)).map(|x| x.wq.clone())).collect());
    for q in queues {
        q.wake_all();
    }
}

/// Wakes every socket's waiters.
fn wake_all() {
    let queues: Vec<Arc<WaitQueue>> = handles(|h, _| h.values().map(|x| x.wq.clone()).collect());
    for q in queues {
        q.wake_all();
    }
}

/// The wait queue of socket `id`: woken when its readiness changes.
pub fn wait_queue(id: u32) -> Option<Arc<WaitQueue>> {
    handles(|h, _| h.get(&id).map(|x| x.wq.clone()))
}

/// Whether the network server runs (socket waits then sleep until woken).
pub fn service_running() -> bool {
    service::is_online(ENDPOINT_NET_SERVER)
}

/// An address as the protocol carries it.
fn addr(ip: [u8; 4]) -> u64 {
    u32::from_le_bytes(ip) as u64
}

/// The address in a protocol word.
fn ip_of(w: u64) -> [u8; 4] {
    (w as u32).to_le_bytes()
}

/// One request; the reply's words, or the negative errno it carries.
fn request(label: u32, args: [u64; 4]) -> Result<[u64; 4], i64> {
    match service::call(ENDPOINT_NET_SERVER, Message::with_args(label, args), CALL_TIMEOUT_TICKS) {
        Ok(r) if (r.args[0] as i64) < 0 => Err(r.args[0] as i64),
        Ok(r) => Ok(r.args),
        Err(_) => Err(ENETDOWN),
    }
}

/// A request on live socket `id`, whose server handle goes in `args[0]` (`dead_err` if it
/// died with its server).
fn on(id: u32, dead_err: i64, label: u32, mut args: [u64; 4]) -> Result<[u64; 4], i64> {
    let Some(sid) = sid(id) else { return Err(dead_err) };
    args[0] = sid as u64;
    request(label, args)
}

/// Runs `f` with the server's window held (for a request with a payload).
fn with_window<R>(f: impl FnOnce(&'static mut [u8]) -> Result<R, i64>) -> Result<R, i64> {
    let _guard = service::hold_window(ENDPOINT_NET_SERVER);
    let w = service::window(ENDPOINT_NET_SERVER).ok_or(ENETDOWN)?;
    f(w)
}

// ----------------------------------------------------------------------
// The interface
// ----------------------------------------------------------------------

/// The network interface as net-server publishes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct IfaceInfo {
    /// net-server runs (and has set up its status area).
    pub running: bool,
    /// A network card and its driver are present.
    pub present: bool,
    /// The card has a carrier link.
    pub link: bool,
    /// A DHCP exchange is in progress.
    pub dhcp_busy: bool,
    /// MAC address.
    pub mac: [u8; 6],
    /// IPv4 address (zeros while unconfigured).
    pub ip: [u8; 4],
    /// Subnet mask.
    pub mask: [u8; 4],
    /// Default gateway.
    pub gateway: [u8; 4],
    /// DNS server.
    pub dns: [u8; 4],
    /// DHCP server of the lease.
    pub dhcp_server: [u8; 4],
    /// Card traffic: packets received, bytes received, packets sent, bytes sent.
    pub eth: [u64; 4],
    /// Loopback traffic: bytes, packets.
    pub lo: [u64; 2],
    /// Receive requests made to the card's driver and frames they returned.
    pub rx_calls: [u64; 2],
}

/// The interface, read from net-server's status area (all zero while it does not run).
pub fn iface() -> IfaceInfo {
    let Some(w) = service::window(ENDPOINT_NET_SERVER) else { return IfaceInfo::default() };
    if status_word(w, NETS_ST_MAGIC) != NETS_MAGIC || !service_running() {
        return IfaceInfo::default();
    }
    let flags = status_word(w, NETS_ST_FLAGS);
    let m = status_word(w, NETS_ST_MAC).to_le_bytes();
    let a = |i| ip_of(status_word(w, i));
    IfaceInfo {
        running: true,
        present: flags & NETS_F_NIC != 0,
        link: flags & NETS_F_LINK != 0,
        dhcp_busy: flags & NETS_F_DHCP_BUSY != 0,
        mac: [m[0], m[1], m[2], m[3], m[4], m[5]],
        ip: a(NETS_ST_IP),
        mask: a(NETS_ST_MASK),
        gateway: a(NETS_ST_GATEWAY),
        dns: a(NETS_ST_DNS),
        dhcp_server: a(NETS_ST_DHCP_SERVER),
        eth: core::array::from_fn(|i| status_word(w, NETS_ST_ETH_COUNTERS + i)),
        lo: core::array::from_fn(|i| status_word(w, NETS_ST_LO_COUNTERS + i)),
        rx_calls: core::array::from_fn(|i| status_word(w, NETS_ST_RX_CALLS + i)),
    }
}

/// The network card's link-local IPv6 address (`fe80::` + modified EUI-64 of the MAC).
pub fn link_local6() -> Option<[u8; 16]> {
    let i = iface();
    if !i.present {
        return None;
    }
    let m = i.mac;
    Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]])
}

/// Whether `ip` is one of ours: `127.0.0.0/8`, `::1`, the link-local address or the
/// interface's address.
pub fn is_local(ip: [u8; 4]) -> bool {
    if ip[0] == 127 || ip == V6_LOOPBACK {
        return true;
    }
    let i = iface();
    (ip == V6_LINKLOCAL && i.present) || (ip != [0, 0, 0, 0] && ip == i.ip)
}

/// `((rx bytes, rx packets), (tx bytes, tx packets))` of `lo` and of the network card.
pub fn counters() -> [((u64, u64), (u64, u64)); 2] {
    let i = iface();
    [((i.lo[0], i.lo[1]), (i.lo[0], i.lo[1])), ((i.eth[1], i.eth[0]), (i.eth[3], i.eth[2]))]
}

/// The ARP cache: `(address, MAC)`.
pub fn arp_entries() -> Vec<([u8; 4], [u8; 6])> {
    list(3).into_iter().map(|r| (ip_of(r[0]), { let m = r[1].to_le_bytes(); [m[0], m[1], m[2], m[3], m[4], m[5]] })).collect()
}

/// Table `kind` of `MSG_NETS_LIST`, as records of words.
fn list(kind: u64) -> Vec<[u64; 8]> {
    let cap = (CHUNK / NETS_LIST_RECORD) as u64;
    with_window(|w| {
        let n = request(MSG_NETS_LIST, [kind, 0, cap, 0])?[0] as usize;
        Ok((0..n)
            .map(|i| core::array::from_fn(|j| u64::from_le_bytes(w[i * NETS_LIST_RECORD + j * 8..i * NETS_LIST_RECORD + j * 8 + 8].try_into().unwrap())))
            .collect())
    })
    .unwrap_or_default()
}

// ----------------------------------------------------------------------
// TCP
// ----------------------------------------------------------------------

/// Initiates an active TCP connection to `ip:port` (from `local_port`, or an ephemeral
/// one): the handle, in [`TcpState::SynSent`].
///
/// # Errors
/// `ENETUNREACH` if the interface is down or unconfigured; `ENETDOWN` without the server.
pub fn tcp_connect(ip: [u8; 4], port: u16, local_port: Option<u16>) -> Result<u32, i64> {
    let r = request(MSG_NETS_TCP_CONNECT, [addr(ip), port as u64, local_port.unwrap_or(0) as u64, 0])?;
    Ok(track(r[0] as u32))
}

/// The state of connection `id` ([`TcpState::Closed`] if it is unknown or died).
pub fn tcp_state(id: u32) -> TcpState {
    word(id).map_or(TcpState::Closed, |w| TcpState::from_number((w >> 40) & 0xFF))
}

/// Takes and clears the pending error of connection `id` (`SO_ERROR`); a connection that
/// died with its server reports `ECONNRESET`.
pub fn tcp_take_error(id: u32) -> Option<i64> {
    if !alive(id) {
        return handles(|h, _| h.contains_key(&id)).then_some(ECONNRESET);
    }
    if word(id).is_some_and(|w| w >> 48 == 0) {
        return None;
    }
    match on(id, ECONNRESET, MSG_NETS_TCP_TAKE_ERROR, [0; 4]) {
        Ok(r) if r[0] != 0 => Some(-(r[0] as i64)),
        _ => None,
    }
}

/// Queues `data` for transmission on connection `id`: the bytes taken (0: no room yet).
///
/// # Errors
/// `EPIPE` when the write side is closed, a pending connection error, `ECONNRESET` if the
/// connection died with its server.
pub fn tcp_send(id: u32, data: &[u8]) -> Result<usize, i64> {
    if !alive(id) {
        return Err(ECONNRESET);
    }
    let n = data.len().min(CHUNK);
    with_window(|w| {
        w[..n].copy_from_slice(&data[..n]);
        Ok(on(id, ENETDOWN, MSG_NETS_TCP_SEND, [0, 0, n as u64, 0])?[0] as usize)
    })
}

/// Reads received bytes of connection `id` into `buf` (`peek`: leaves them queued):
/// `(bytes, end of stream)`.
///
/// # Errors
/// A pending connection error once no bytes remain; `ECONNRESET` if it died with its
/// server.
pub fn tcp_recv(id: u32, buf: &mut [u8], peek: bool) -> Result<(usize, bool), i64> {
    if !alive(id) {
        return Err(ECONNRESET);
    }
    // Nothing to read, no end of stream, no error: no need to ask
    if word(id).is_some_and(|w| bits(w) & NETS_R_IN == 0) {
        return Ok((0, false));
    }
    let cap = buf.len().min(CHUNK);
    with_window(|w| {
        let r = on(id, ENETDOWN, MSG_NETS_TCP_RECV, [0, 0, cap as u64, peek as u64])?;
        let n = (r[0] as usize).min(cap);
        buf[..n].copy_from_slice(&w[..n]);
        Ok((n, r[1] != 0))
    })
}

/// The readiness of connection `id`: `(readable, writable, hang_up, error)`.
pub fn tcp_poll(id: u32) -> (bool, bool, bool, bool) {
    match word(id) {
        Some(w) => {
            let b = bits(w);
            (b & NETS_R_IN != 0, b & NETS_R_OUT != 0, b & NETS_R_HUP != 0, b & NETS_R_ERR != 0)
        }
        None => (true, false, true, !alive(id)),
    }
}

/// Shuts down the write half of connection `id` (`FIN` after the buffered data).
pub fn tcp_shutdown_write(id: u32) {
    let _ = on(id, ECONNRESET, MSG_NETS_TCP_SHUTDOWN, [0, 0, 0, 0]);
}

/// Closes connection `id` (it finishes in the background).
pub fn tcp_close(id: u32) {
    let _ = on(id, ECONNRESET, MSG_NETS_TCP_CLOSE, [0, 0, 0, 0]);
    untrack(id);
}

/// `(local port, remote address, remote port, local address)` of connection `id`.
fn tcp_info(id: u32) -> Option<(u16, [u8; 4], u16, [u8; 4])> {
    let r = on(id, ENOTCONN, MSG_NETS_TCP_INFO, [0, 0, 0, 0]).ok()?;
    Some((r[1] as u16, ip_of(r[2] >> 16), r[2] as u16, ip_of(r[1] >> 16)))
}

/// `(local_port, remote_ip, remote_port)` of connection `id`.
pub fn tcp_endpoints(id: u32) -> Option<(u16, [u8; 4], u16)> {
    tcp_info(id).map(|(lp, rip, rp, _)| (lp, rip, rp))
}

/// Local address of connection `id`.
pub fn tcp_local_ip(id: u32) -> Option<[u8; 4]> {
    tcp_info(id).map(|i| i.3)
}

/// Reserves TCP port `port` (0: a free one) on `ip` for `bind`, with Linux's
/// `SO_REUSEADDR` / `SO_REUSEPORT` rules (net-server applies them): `(handle, port)`.
///
/// # Errors
/// `EADDRINUSE`.
pub fn tcp_bind(ip: [u8; 4], port: u16, reuse_addr: bool, reuse_port: bool, v4: bool, v6: bool) -> Result<(u32, u16), i64> {
    let flags = reuse_addr as u64 | (reuse_port as u64) << 1 | (v4 as u64) << 2 | (v6 as u64) << 3;
    let r = request(MSG_NETS_TCP_BIND, [addr(ip), port as u64, flags, 0])?;
    Ok((track(r[0] as u32), r[1] as u16))
}

/// Releases port reservation `id`.
pub fn tcp_unbind(id: u32) {
    let _ = on(id, ENOTCONN, MSG_NETS_TCP_UNBIND, [0, 0, 0, 0]);
    untrack(id);
}

/// Starts listening on reservation `bind` with `backlog`: the listener's handle.
///
/// # Errors
/// `EADDRINUSE` if another socket listens on the port.
pub fn tcp_listen(bind: u32, backlog: usize) -> Result<u32, i64> {
    let r = on(bind, ENETDOWN, MSG_NETS_TCP_LISTEN, [0, backlog as u64, 0, 0])?;
    Ok(track(r[0] as u32))
}

/// Changes listener `id`'s backlog (a second `listen`).
pub fn tcp_set_backlog(id: u32, backlog: usize) {
    let _ = on(id, ENETDOWN, MSG_NETS_TCP_BACKLOG, [0, backlog as u64, 0, 0]);
}

/// Takes the next established connection of listener `id`.
pub fn tcp_accept(id: u32) -> Option<u32> {
    if word(id).is_some_and(|w| bits(w) & NETS_R_ACCEPT == 0) {
        return None;
    }
    let c = on(id, ENETDOWN, MSG_NETS_TCP_ACCEPT, [0, 0, 0, 0]).ok()?[0] as u32;
    Some(track(c))
}

/// Whether listener `id` has a connection to accept (or died: accept then fails).
pub fn tcp_acceptable(id: u32) -> bool {
    word(id).map_or(dead(id), |w| bits(w) & NETS_R_ACCEPT != 0)
}

/// Stops listener `id`: connections not yet accepted are reset.
pub fn tcp_unlisten(id: u32) {
    let _ = on(id, ENETDOWN, MSG_NETS_TCP_UNLISTEN, [0, 0, 0, 0]);
    untrack(id);
}

/// A TCP connection as `/proc/net/tcp` shows it.
pub struct TcpEntry {
    /// Connection handle (the kernel's; 0 if the kernel holds none, as for one closed and
    /// finishing in the background).
    pub id: u32,
    /// Local address and port.
    pub local: ([u8; 4], u16),
    /// Remote address and port.
    pub remote: ([u8; 4], u16),
    /// State.
    pub state: TcpState,
    /// Bytes queued to send (unsent or unacknowledged).
    pub tx: usize,
    /// Bytes received and not yet read.
    pub rx: usize,
}

/// All TCP connections.
pub fn tcp_list() -> Vec<TcpEntry> {
    list(0)
        .into_iter()
        .map(|r| TcpEntry {
            id: kid_of(r[0] as u32),
            local: (ip_of(r[1] >> 16), r[1] as u16),
            remote: (ip_of(r[2] >> 16), r[2] as u16),
            state: TcpState::from_number(r[3]),
            tx: r[4] as usize,
            rx: r[5] as usize,
        })
        .collect()
}

/// All listeners: `(handle, address, port, connections waiting to be accepted, backlog)`.
pub fn listener_list() -> Vec<(u32, [u8; 4], u16, usize, usize)> {
    list(1).into_iter().map(|r| (kid_of(r[0] as u32), ip_of(r[1] >> 16), r[1] as u16, r[2] as usize, r[3] as usize)).collect()
}

/// All UDP sockets: `(handle, port, bytes queued)`.
pub fn udp_list() -> Vec<(u32, u16, usize)> {
    list(2).into_iter().map(|r| (kid_of(r[0] as u32), r[1] as u16, r[2] as usize)).collect()
}

// ----------------------------------------------------------------------
// UDP
// ----------------------------------------------------------------------

/// Opens a UDP socket bound to `port` (`0` allocates an ephemeral port).
///
/// # Errors
/// `EADDRINUSE` if `port` is taken.
pub fn udp_open(port: u16) -> Result<u32, i64> {
    let r = request(MSG_NETS_UDP_OPEN, [port as u64, 0, 0, 0])?;
    Ok(track(r[0] as u32))
}

/// Moves UDP socket `id` to `port` (0: keep its port), as `bind` after an implicit open.
pub fn udp_rebind(id: u32, port: u16) -> Result<(), i64> {
    on(id, ENETDOWN, MSG_NETS_UDP_REBIND, [0, port as u64, 0, 0]).map(|_| ())
}

/// The local port of UDP socket `id` (0 if unknown).
pub fn udp_port(id: u32) -> u16 {
    on(id, ENETDOWN, MSG_NETS_UDP_PORT, [0, 0, 0, 0]).map_or(0, |r| r[0] as u16)
}

/// Sends a datagram from UDP socket `id` to `ip:port`: its length.
///
/// # Errors
/// `ENETUNREACH` if the interface is down, `EMSGSIZE` if it is too long, `ENETDOWN` if
/// the socket died with its server.
pub fn udp_send(id: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
    if !alive(id) {
        return Err(ENETDOWN);
    }
    if data.len() > CHUNK {
        return Err(-90); // EMSGSIZE
    }
    with_window(|w| {
        w[..data.len()].copy_from_slice(data);
        Ok(on(id, ENETDOWN, MSG_NETS_UDP_SEND, [0, addr(ip) << 16 | port as u64, 0, data.len() as u64])?[0] as usize)
    })
}

/// Takes (or peeks at) the next datagram of UDP socket `id`: `(source, source port,
/// payload, arrival time)`; `None` if none waits (or it died: see [`dead`]).
pub fn udp_recv(id: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>, u64)> {
    if word(id).is_some_and(|w| bits(w) & NETS_R_IN == 0) || !alive(id) {
        return None;
    }
    with_window(|w| {
        let r = on(id, ENETDOWN, MSG_NETS_UDP_RECV, [0, 0, peek as u64, 0])?;
        let n = (r[0] as usize).min(NETS_DATA_LEN);
        Ok((ip_of(r[1] >> 16), r[1] as u16, w[..n].to_vec(), r[2]))
    })
    .ok()
}

/// Whether UDP socket `id` has a datagram waiting.
pub fn udp_readable(id: u32) -> bool {
    word(id).is_some_and(|w| bits(w) & NETS_R_IN != 0)
}

/// Closes UDP socket `id`.
pub fn udp_close(id: u32) {
    let _ = on(id, ENETDOWN, MSG_NETS_UDP_CLOSE, [0, 0, 0, 0]);
    untrack(id);
}

// ----------------------------------------------------------------------
// ICMP sockets
// ----------------------------------------------------------------------

/// Opens an ICMP socket: raw (`raw`) or a ping socket, for ICMPv6 (`v6`) or ICMP. Without
/// the server, a handle that is dead from the start (its operations fail).
pub fn icmp_open(raw: bool, v6: bool) -> u32 {
    match request(MSG_NETS_ICMP_OPEN, [raw as u64, v6 as u64, 0, 0]) {
        Ok(r) => track(r[0] as u32),
        Err(_) => 0,
    }
}

/// Echo identifier of ping socket `id`.
pub fn icmp_ident(id: u32) -> u16 {
    on(id, ENETDOWN, MSG_NETS_ICMP_IDENT, [0, 0, 0, 0]).map_or(0, |r| r[0] as u16)
}

/// Gives ping socket `id` echo identifier `ident` (`bind`); `EADDRINUSE` if taken.
pub fn icmp_set_ident(id: u32, ident: u16) -> Result<(), i64> {
    on(id, ENETDOWN, MSG_NETS_ICMP_SET_IDENT, [0, ident as u64, 0, 0]).map(|_| ())
}

/// Sends ICMP message `msg` from socket `id` to `dst` (a ping socket's must be an echo
/// request; the server fills in its identifier and checksum).
pub fn icmp_send(id: u32, dst: [u8; 4], msg: &[u8]) -> Result<usize, i64> {
    if !alive(id) {
        return Err(ENETDOWN);
    }
    if msg.len() > CHUNK {
        return Err(-90);
    }
    with_window(|w| {
        w[..msg.len()].copy_from_slice(msg);
        Ok(on(id, ENETDOWN, MSG_NETS_ICMP_SEND, [0, addr(dst), 0, msg.len() as u64])?[0] as usize)
    })
}

/// Takes (or with `peek` copies) the next message of ICMP socket `id`.
pub fn icmp_recv(id: u32, peek: bool) -> Option<([u8; 4], Vec<u8>, u64)> {
    if word(id).is_some_and(|w| bits(w) & NETS_R_IN == 0) || !alive(id) {
        return None;
    }
    with_window(|w| {
        let r = on(id, ENETDOWN, MSG_NETS_ICMP_RECV, [0, 0, peek as u64, 0])?;
        let n = (r[0] as usize).min(NETS_DATA_LEN);
        Ok((ip_of(r[1]), w[..n].to_vec(), r[2]))
    })
    .ok()
}

/// Whether ICMP socket `id` has a message.
pub fn icmp_readable(id: u32) -> bool {
    word(id).is_some_and(|w| bits(w) & NETS_R_IN != 0)
}

/// Closes ICMP socket `id`.
pub fn icmp_close(id: u32) {
    let _ = on(id, ENETDOWN, MSG_NETS_ICMP_CLOSE, [0, 0, 0, 0]);
    untrack(id);
}

// ----------------------------------------------------------------------
// Requests that answer later (queued calls: the caller holds no locks)
// ----------------------------------------------------------------------

/// Runs DHCP again; waits (up to 15 s) for the lease: its address.
///
/// # Errors
/// No card, no answer, or no server.
pub fn dhcp_renew() -> Result<[u8; 4], &'static str> {
    match service::call_queued(ENDPOINT_NET_SERVER, Message::with_args(MSG_NETS_DHCP, [0; 4]), 1500) {
        Ok(r) if (r.args[0] as i64) >= 0 => Ok(ip_of(r.args[1])),
        Ok(r) if r.args[0] as i64 == -19 => Err("no network card"),
        Ok(_) => Err("no DHCP answer"),
        Err(_) => Err("the network server is not running"),
    }
}

/// Lookups in progress use the data area's last page for the name (they hold no window).
static LOOKUP_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Looks `name` up (DNS A record, the lease's DNS server); waits up to 8 s.
///
/// # Errors
/// An empty name, no network, no answer, or no such name.
pub fn resolve(name: &str) -> Result<[u8; 4], &'static str> {
    const NAME_OFF: usize = NETS_DATA_LEN - 4096;
    if name.is_empty() || name.len() > 1024 {
        return Err("bad name");
    }
    // One lookup at a time owns the name page
    let start = crate::arch::pit::ticks();
    while LOOKUP_BUSY.swap(true, Ordering::AcqRel) {
        if crate::arch::pit::ticks() > start + 1000 {
            return Err("another lookup is in progress");
        }
        crate::task::sleep_ms(10);
    }
    let r = (|| {
        let w = service::window(ENDPOINT_NET_SERVER).ok_or("the network server is not running")?;
        w[NAME_OFF..NAME_OFF + name.len()].copy_from_slice(name.as_bytes());
        match service::call_queued(ENDPOINT_NET_SERVER, Message::with_args(MSG_NETS_RESOLVE, [NAME_OFF as u64, name.len() as u64, 0, 0]), 800) {
            Ok(r) if (r.args[0] as i64) >= 0 => Ok(ip_of(r.args[1])),
            Ok(r) if r.args[0] as i64 == ENETUNREACH => Err("the network interface has no address"),
            Ok(r) if r.args[0] as i64 == ETIMEDOUT => Err("DNS query timed out: no response from DNS server"),
            Ok(r) if r.args[0] as i64 == -2 => Err("no such name"),
            Ok(_) => Err("bad name"),
            Err(_) => Err("the network server is not running"),
        }
    })();
    LOOKUP_BUSY.store(false, Ordering::Release);
    r
}

