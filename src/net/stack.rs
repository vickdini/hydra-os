//! # Network Subsystem: TCP/UDP Transport & Socket Engine
//!
//! Connection-oriented TCP and datagram UDP transport engine built on top of the packet-level
//! Ethernet/IPv4 layer, powering `AF_INET` sockets in the Linux personality.
//!
//! ## Architectural Role & Design Rationale
//!
//! [`poll`] drains received frames, answers ARP, routes UDP datagrams to their socket's
//! queue and TCP segments to their connection's state machine, and runs retransmission
//! timers. Once the scheduler runs, the `netd` kernel task does this whenever the NIC
//! interrupts (or a timer is due) and wakes the wait queue of every socket whose state
//! changed, so blocked socket calls sleep until their data arrives. Before that (early
//! boot, DHCP) callers poll the NIC themselves.
//!
//! TCP implements the client side used by package managers and similar programs: active
//! open, in-order receive (out-of-order segments are dropped and recovered by the peer's
//! retransmission), a sliding send window bounded by the peer's advertised window,
//! go-back-N retransmission with exponential back-off, and orderly (FIN) and abortive
//! (RST) close. The advertised receive window (64 KiB, the most possible without window
//! scaling) fits in the NIC's receive ring.
//!
//! ## Key Types & Interfaces
//!
//! - [`TcpState`]: RFC 793 connection state machine states (`SynSent`, `Established`, `FinWait1`, etc.).
//! - [`NET_WQ`]: Global wait queue woken by the E1000 IRQ handler to schedule the `netd` background daemon.
//! - [`start_service()`] / [`poll()`] / [`kick()`]: Lifecycle and packet-draining entry points for the transport engine.
//! - [`tcp_connect()`], [`tcp_send()`], [`tcp_recv()`], [`tcp_poll()`], [`tcp_close()`]: Connection-oriented TCP socket operations.
//! - [`udp_open()`], [`udp_send()`], [`udp_recv()`], [`udp_readable()`], [`udp_close()`]: Datagram UDP socket operations.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Interacts with [`super::e1000`], [`super::GLOBAL_INTERFACE`], and `crate::task::wait` for blocking socket wakeup.
//! - Concurrency: Global transport state is synchronized via the `STACK` [`spin::Mutex`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::task::wait::{self, WaitQueue};

use super::arp::{ArpPacket, ARP_TABLE};
use super::ethernet::{EtherType, EthernetFrame};
use super::ipv4::{IpProtocol, Ipv4Packet};
use super::tcp::{TcpFlags, TcpPacket};
use super::{e1000, GLOBAL_INTERFACE};

/// Linux errno for Connection Refused (`-111`).
pub const ECONNREFUSED: i64 = -111;
/// Linux errno for Connection Reset by Peer (`-104`).
pub const ECONNRESET: i64 = -104;
/// Linux errno for Connection Timed Out (`-110`).
pub const ETIMEDOUT: i64 = -110;
/// Linux errno for Address Already in Use (`-98`).
pub const EADDRINUSE: i64 = -98;
/// Linux errno for Transport Endpoint Is Not Connected (`-107`).
pub const ENOTCONN: i64 = -107;
/// Linux errno for Broken Pipe (`-32`).
pub const EPIPE: i64 = -32;
/// Linux errno for Network Is Unreachable (`-101`).
pub const ENETUNREACH: i64 = -101;

/// Maximum TCP segment payload size over standard 1500-byte Ethernet MTU (`1460` bytes).
const MSS: usize = 1460;
/// Advertised receive window: the largest a 16-bit window field holds (no window scaling).
const RECV_WINDOW: usize = 65535;
/// Most unsent + unacknowledged data a connection buffers (`256 KiB`).
const SEND_BUFFER: usize = 256 * 1024;
/// Initial retransmission timeout in 100 Hz PIT ticks (`30` ticks = 300 ms).
const RTO_INITIAL_TICKS: u64 = 30; // 300 ms at 100 Hz
/// Maximum exponential back-off retransmission timeout in PIT ticks (`400` ticks = 4 s).
const RTO_MAX_TICKS: u64 = 400;
/// Maximum number of retransmission attempts before aborting with [`ETIMEDOUT`].
const MAX_RETRIES: u32 = 10;
/// First ephemeral port number in the IANA dynamic port range (`49152`).
const EPHEMERAL_FIRST: u16 = 49152;

/// RFC 793 TCP connection state machine states.
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

/// Internal TCP connection control block (TCB).
struct TcpConn {
    /// Local IPv4 address (our interface's, or a loopback address).
    local_ip: [u8; 4],
    /// Bound local 16-bit TCP port.
    local_port: u16,
    /// Remote peer 4-byte IPv4 address.
    remote_ip: [u8; 4],
    /// Remote peer 16-bit TCP port.
    remote_port: u16,
    /// Current state in the RFC 793 state machine.
    state: TcpState,
    /// Initial Send Sequence number (`ISS`).
    iss: u32,
    /// Oldest unacknowledged sequence number (`SND.UNA`).
    snd_una: u32,
    /// Next sequence number to be transmitted (`SND.NXT`).
    snd_nxt: u32,
    /// Peer's most recently advertised receive window (`SND.WND`).
    snd_wnd: u32,
    /// Bytes from `snd_una` onward: sent-but-unacknowledged followed by unsent.
    send_buf: VecDeque<u8>,
    /// Next sequence number expected from the peer (`RCV.NXT`).
    rcv_nxt: u32,
    /// Ordered unread bytes received from the peer awaiting application consumption.
    recv_buf: VecDeque<u8>,
    /// Whether an in-order `FIN` segment has been received from the peer.
    fin_received: bool,
    /// Sequence number of our `FIN` once sent.
    fin_seq: Option<u32>,
    /// The application closed or shut down writing: send `FIN` after the buffered data.
    write_closed: bool,
    /// The socket was closed: free the connection once the close handshake ends.
    detached: bool,
    /// PIT tick timestamp when the last segment requiring acknowledgment was transmitted.
    last_send: u64,
    /// Current retransmission timeout in PIT ticks.
    rto: u64,
    /// Consecutive retransmission count for the current unacknowledged flight.
    retries: u32,
    /// Pending asynchronous socket error (`ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`).
    error: Option<i64>,
    /// Tasks waiting for this connection to change state (data, space, close, error).
    wq: Arc<WaitQueue>,
    /// The listener this passively opened connection belongs to until it is accepted.
    listener: Option<u32>,
    /// Its port was bound with `SO_REUSEADDR` (inherited from the listener).
    reuse_addr: bool,
}

/// A listening TCP port.
struct Listener {
    /// Address listened on (`0.0.0.0`: any).
    ip: [u8; 4],
    /// Port listened on.
    port: u16,
    /// Most connections waiting (handshaking or to be accepted).
    backlog: usize,
    /// Established connections not yet accepted.
    queue: VecDeque<u32>,
    /// Woken when a connection is ready to accept.
    wq: Arc<WaitQueue>,
    /// Bound with `SO_REUSEADDR` (passed on to its connections).
    reuse_addr: bool,
    /// Takes IPv4 connections (to `ip`) and/or IPv6 ones (`::1`).
    v4: bool,
    v6: bool,
}

/// A TCP port reservation made by `bind`.
struct Bind {
    /// Address (`0.0.0.0`: all of ours).
    ip: [u8; 4],
    /// Port.
    port: u16,
    /// `SO_REUSEADDR` was set.
    reuse_addr: bool,
    /// `SO_REUSEPORT` was set.
    reuse_port: bool,
    /// The socket listens.
    listening: bool,
    /// Covers IPv4 (`ip`) and/or IPv6 (a dual-stack `[::]` socket: both).
    v4: bool,
    v6: bool,
}

/// Internal UDP socket state and receive queue.
struct UdpSock {
    /// Bound local 16-bit UDP port.
    local_port: u16,
    /// Queue of received `(source_ip, source_port, payload)` datagrams.
    queue: VecDeque<([u8; 4], u16, Vec<u8>)>,
    /// Wait queue woken when a new UDP datagram arrives.
    wq: Arc<WaitQueue>,
}

/// Central transport table holding active TCP connections and UDP sockets.
struct Stack {
    /// Map of TCP connection handle ID to [`TcpConn`].
    tcp: BTreeMap<u32, TcpConn>,
    /// Listening ports by handle ID.
    listeners: BTreeMap<u32, Listener>,
    /// TCP port reservations by handle ID.
    binds: BTreeMap<u32, Bind>,
    /// Map of UDP socket handle ID to [`UdpSock`].
    udp: BTreeMap<u32, UdpSock>,
    /// Next monotonically increasing socket handle ID.
    next_id: u32,
    /// Next candidate ephemeral port number.
    next_port: u16,
}

/// Global spinlock-protected TCP/UDP transport state.
static STACK: Mutex<Stack> = Mutex::new(Stack {
    tcp: BTreeMap::new(),
    listeners: BTreeMap::new(),
    binds: BTreeMap::new(),
    udp: BTreeMap::new(),
    next_id: 1,
    next_port: EPHEMERAL_FIRST,
});

/// Returns the current 100 Hz PIT tick counter.
///
/// # Returns
///
/// Current PIT timer tick value.
fn now() -> u64 {
    crate::arch::pit::ticks()
}

/// Returns `true` if `a < b` in 32-bit modular TCP sequence space (RFC 1982).
///
/// # Arguments
/// * `a` - First 32-bit sequence number.
/// * `b` - Second 32-bit sequence number.
///
/// # Returns
///
/// `true` if `a` precedes `b` modulo 2^32, `false` otherwise.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Returns `true` if `a <= b` in 32-bit modular TCP sequence space.
///
/// # Arguments
/// * `a` - First 32-bit sequence number.
/// * `b` - Second 32-bit sequence number.
///
/// # Returns
///
/// `true` if `a` precedes or equals `b` modulo 2^32, `false` otherwise.
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// Returns the currently assigned local IPv4 address from [`GLOBAL_INTERFACE`].
///
/// # Returns
///
/// The 4-byte local IPv4 address.
fn local_ip() -> [u8; 4] {
    let mut ip = GLOBAL_INTERFACE.lock().ip();
    if ip == [0, 0, 0, 0] && e1000::is_present() {
        let _ = crate::net::dhcp_acquire();
        ip = GLOBAL_INTERFACE.lock().ip();
    }
    ip
}

/// Returns `true` once the hardware interface is present and has a non-zero IPv4 address (DHCP finished).
///
/// # Returns
///
/// `true` if interface is initialized and configured with an IP, `false` otherwise.
pub fn is_up() -> bool {
    e1000::is_present() && local_ip() != [0, 0, 0, 0]
}

/// Encapsulates and sends an IPv4 packet via [`GLOBAL_INTERFACE`], ignoring link errors.
///
/// # Arguments
/// * `dst` - Destination 4-byte IPv4 address.
/// * `proto` - Transport protocol discriminator.
/// * `payload` - Packet payload byte slice.
fn send_ip(src: [u8; 4], dst: [u8; 4], proto: IpProtocol, payload: &[u8]) {
    if is_local(dst) {
        // Loopback: delivered by the next poll (the network task, woken here)
        let mut q = LOOPBACK.lock();
        if q.len() < 4096 {
            q.push_back((src, dst, proto, payload.to_vec()));
        }
        drop(q);
        NET_WQ.wake_all();
        return;
    }
    let mut iface = GLOBAL_INTERFACE.lock();
    if iface.ip() == [0, 0, 0, 0] && e1000::is_present() {
        drop(iface);
        let _ = crate::net::dhcp_acquire();
        iface = GLOBAL_INTERFACE.lock();
    }
    let _ = iface.send_ipv4(dst, proto, payload);
}

/// Packets sent to ourselves, waiting to be received: `(src, dst, protocol, payload)`.
static LOOPBACK: Mutex<VecDeque<([u8; 4], [u8; 4], IpProtocol, Vec<u8>)>> = Mutex::new(VecDeque::new());

/// IPv6's loopback address `::1`, carried internally as this IPv4-shaped value (from
/// `0.0.0.0/8`, which IPv4 sockets never reach); only loopback traffic uses it.
pub const V6_LOOPBACK: [u8; 4] = [0, 0, 0, 1];

/// Whether `ip` is one of ours: `127.0.0.0/8`, `::1` or the interface's address.
pub fn is_local(ip: [u8; 4]) -> bool {
    ip[0] == 127 || ip == V6_LOOPBACK || (ip != [0, 0, 0, 0] && ip == GLOBAL_INTERFACE.lock().ip())
}

/// The source address for packets to `dst`: the loopback address for `127.0.0.0/8`, `::1`
/// for `::1`.
fn source_for(dst: [u8; 4]) -> [u8; 4] {
    if dst == V6_LOOPBACK {
        V6_LOOPBACK
    } else if dst[0] == 127 {
        [127, 0, 0, 1]
    } else {
        local_ip()
    }
}

/// Whether a socket covering IPv4 address `ip` (`0.0.0.0`: all) and/or IPv6 (`v4`, `v6`)
/// takes packets addressed to `dst`.
fn covers(ip: [u8; 4], v4: bool, v6: bool, dst: [u8; 4]) -> bool {
    if dst == V6_LOOPBACK { v6 } else { v4 && (ip == [0, 0, 0, 0] || ip == dst) }
}

impl Stack {
    /// Allocates an unused ephemeral port in `49152..=65535`.
    ///
    /// # Returns
    ///
    /// An unallocated ephemeral port number.
    fn alloc_port(&mut self) -> u16 {
        loop {
            let p = self.next_port;
            self.next_port = if self.next_port == u16::MAX { EPHEMERAL_FIRST } else { self.next_port + 1 };
            let used = self.tcp.values().any(|c| c.local_port == p)
                || self.udp.values().any(|u| u.local_port == p)
                || self.binds.values().any(|b| b.port == p);
            if !used {
                return p;
            }
        }
    }

    /// Allocates a unique handle ID for a new TCP connection or UDP socket.
    ///
    /// # Returns
    ///
    /// A unique 32-bit socket identifier.
    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl TcpConn {
    /// Computes the current available receive window size to advertise in outgoing segments.
    ///
    /// # Returns
    ///
    /// Available receive window capacity in bytes.
    fn window(&self) -> u16 {
        RECV_WINDOW.saturating_sub(self.recv_buf.len()).min(u16::MAX as usize) as u16
    }

    /// Serializes and transmits a single TCP segment to `self.remote_ip`.
    ///
    /// # Arguments
    /// * `flags` - TCP control flags (SYN, ACK, FIN, RST, PSH).
    /// * `seq` - Sequence number for the segment header.
    /// * `payload` - Segment payload byte slice.
    fn send_segment(&mut self, flags: u8, seq: u32, payload: &[u8]) {
        let mut buf = [0u8; 20 + MSS];
        let src = self.local_ip;
        if let Ok(n) = TcpPacket::serialize(
            src,
            self.remote_ip,
            self.local_port,
            self.remote_port,
            seq,
            self.rcv_nxt,
            flags,
            self.window(),
            payload,
            &mut buf,
        ) {
            send_ip(src, self.remote_ip, IpProtocol::Tcp, &buf[..n]);
        }
    }

    /// Transmits an empty `ACK` segment advertising the current `rcv_nxt` and window.
    fn send_ack(&mut self) {
        let seq = self.snd_nxt;
        self.send_segment(TcpFlags::ACK, seq, &[]);
    }

    /// Sends as much buffered data as the peer's window allows, then a `FIN` if due.
    fn output(&mut self) {
        if matches!(self.state, TcpState::SynSent | TcpState::SynReceived | TcpState::Closed | TcpState::TimeWait) {
            return;
        }
        let window = (self.snd_wnd as usize).max(1).min(SEND_BUFFER);
        loop {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let data_in_flight = in_flight.min(self.send_buf.len());
            let unsent = self.send_buf.len() - data_in_flight;
            if unsent == 0 || in_flight >= window {
                break;
            }
            let n = unsent.min(MSS).min(window - in_flight);
            let chunk: Vec<u8> = self.send_buf.iter().skip(data_in_flight).take(n).copied().collect();
            let seq = self.snd_nxt;
            self.send_segment(TcpFlags::ACK | TcpFlags::PSH, seq, &chunk);
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
            self.last_send = now();
        }
        let all_sent = self.snd_nxt.wrapping_sub(self.snd_una) as usize >= self.send_buf.len();
        if self.write_closed && self.fin_seq.is_none() && all_sent {
            let seq = self.snd_nxt;
            self.send_segment(TcpFlags::FIN | TcpFlags::ACK, seq, &[]);
            self.fin_seq = Some(seq);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.last_send = now();
            self.state = match self.state {
                TcpState::CloseWait => TcpState::LastAck,
                _ => TcpState::FinWait1,
            };
        }
    }

    /// Processes an incoming TCP segment `seg` against this connection's state machine.
    ///
    /// # Arguments
    /// * `seg` - Parsed incoming TCP segment.
    fn input(&mut self, seg: &TcpPacket) {
        let flags = seg.flags;
        if flags & TcpFlags::RST != 0 {
            self.error = Some(if self.state == TcpState::SynSent { ECONNREFUSED } else { ECONNRESET });
            self.state = TcpState::Closed;
            return;
        }
        if self.state == TcpState::SynSent {
            if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 && seg.ack_num == self.iss.wrapping_add(1) {
                self.rcv_nxt = seg.seq_num.wrapping_add(1);
                self.snd_una = seg.ack_num;
                self.snd_wnd = seg.window_size as u32;
                self.state = TcpState::Established;
                self.rto = RTO_INITIAL_TICKS;
                self.retries = 0;
                self.send_ack();
                self.output();
            }
            return;
        }
        if self.state == TcpState::SynReceived {
            if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
                // The peer did not get our SYN-ACK: send it again
                let iss = self.iss;
                self.send_segment(TcpFlags::SYN | TcpFlags::ACK, iss, &[]);
                return;
            }
            if flags & TcpFlags::ACK == 0 || seg.ack_num != self.iss.wrapping_add(1) {
                return;
            }
            // The handshake is done; the segment may carry data too
            self.state = TcpState::Established;
            self.snd_una = seg.ack_num;
            self.snd_wnd = seg.window_size as u32;
            self.rto = RTO_INITIAL_TICKS;
            self.retries = 0;
        }

        // Acknowledgement of our data (and FIN)
        if flags & TcpFlags::ACK != 0 && seq_lt(self.snd_una, seg.ack_num) && seq_le(seg.ack_num, self.snd_nxt) {
            let acked = seg.ack_num.wrapping_sub(self.snd_una) as usize;
            let data = acked.min(self.send_buf.len());
            self.send_buf.drain(..data);
            self.snd_una = seg.ack_num;
            self.rto = RTO_INITIAL_TICKS;
            self.retries = 0;
            self.last_send = now();
            if let Some(fin) = self.fin_seq {
                if seq_lt(fin, self.snd_una) {
                    self.state = match self.state {
                        TcpState::FinWait1 => TcpState::FinWait2,
                        TcpState::Closing => TcpState::TimeWait,
                        TcpState::LastAck => TcpState::Closed,
                        s => s,
                    };
                }
            }
        }
        if flags & TcpFlags::ACK != 0 {
            self.snd_wnd = seg.window_size as u32;
        }

        // In-order data
        let payload = seg.payload;
        if !payload.is_empty() {
            if seg.seq_num == self.rcv_nxt && !self.fin_received {
                let room = RECV_WINDOW.saturating_sub(self.recv_buf.len());
                let take = payload.len().min(room);
                self.recv_buf.extend(&payload[..take]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
            }
            self.send_ack();
        }

        // FIN in sequence
        if flags & TcpFlags::FIN != 0 && seg.seq_num.wrapping_add(payload.len() as u32) == self.rcv_nxt && !self.fin_received {
            self.fin_received = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.send_ack();
            self.state = match self.state {
                TcpState::Established => TcpState::CloseWait,
                TcpState::FinWait1 => TcpState::Closing,
                TcpState::FinWait2 => TcpState::TimeWait,
                s => s,
            };
        }
        self.output();
    }

    /// Returns `true` while a retransmission timer runs (data or `SYN` awaiting acknowledgment).
    ///
    /// # Returns
    ///
    /// `true` if retransmission timer is active, `false` otherwise.
    fn timer_armed(&self) -> bool {
        self.snd_una != self.snd_nxt || matches!(self.state, TcpState::SynSent | TcpState::SynReceived)
    }

    /// Retransmits unacknowledged data when the RTO timer expires.
    ///
    /// # Returns
    /// `true` if the connection failed (`ETIMEDOUT`), or `false` otherwise.
    fn timers(&mut self) -> bool {
        if !self.timer_armed() || now().saturating_sub(self.last_send) < self.rto {
            return false;
        }
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.error = Some(ETIMEDOUT);
            if self.state == TcpState::SynReceived {
                self.detached = true; // never accepted: nobody holds it
            }
            self.state = TcpState::Closed;
            return true;
        }
        self.rto = (self.rto * 2).min(RTO_MAX_TICKS);
        self.last_send = now();
        if self.state == TcpState::SynSent {
            let iss = self.iss;
            self.send_segment(TcpFlags::SYN, iss, &[]);
            return false;
        }
        if self.state == TcpState::SynReceived {
            let iss = self.iss;
            self.send_segment(TcpFlags::SYN | TcpFlags::ACK, iss, &[]);
            return false;
        }
        // Go back N: resend everything from the oldest unacknowledged byte
        self.snd_nxt = self.snd_una;
        if self.fin_seq.is_some() && self.send_buf.is_empty() {
            let seq = self.snd_una;
            self.send_segment(TcpFlags::FIN | TcpFlags::ACK, seq, &[]);
            self.snd_nxt = self.snd_una.wrapping_add(1);
            return false;
        }
        let fin = self.fin_seq.take();
        let state = self.state;
        if fin.is_some() {
            // Re-send data first; output() re-emits the FIN after it
            self.state = if state == TcpState::LastAck { TcpState::CloseWait } else { TcpState::Established };
        }
        self.output();
        if fin.is_none() {
            self.state = state;
        }
        false
    }
}

/// Woken by the NIC interrupt: `netd` has frames to process.
pub static NET_WQ: WaitQueue = WaitQueue::new();
/// Whether the `netd` background task is running; when `true`, other code no longer polls the NIC itself.
static SERVICE_RUNNING: AtomicBool = AtomicBool::new(false);

/// Processes received frames and protocol timers, then wakes the sockets they affected.
///
/// # Returns
/// `true` if the receive ring may still hold more frames after 256 iterations, or `false` if drained.
pub fn poll() -> bool {
    let mut woken: Vec<Arc<WaitQueue>> = Vec::new();
    let mut more = false;
    // Loopback packets first (answers they cause are queued behind them)
    for i in 0..1024 {
        let Some((src, dst, proto, payload)) = LOOPBACK.lock().pop_front() else { break };
        for q in handle_ip(src, dst, proto, &payload) {
            if !woken.iter().any(|w| Arc::ptr_eq(w, &q)) {
                woken.push(q);
            }
        }
        if i == 1023 {
            more = true;
        }
    }
    let nic = e1000::is_present();
    let mut frame = [0u8; 1518];
    let mut nic_more = nic;
    for _ in 0..if nic { 256 } else { 0 } {
        let len = match e1000::receive_frame(&mut frame) {
            Some(l) => l,
            None => {
                nic_more = false;
                break;
            }
        };
        for q in handle_frame(&frame[..len]) {
            if !woken.iter().any(|w| Arc::ptr_eq(w, &q)) {
                woken.push(q);
            }
        }
    }
    more |= nic_more;
    more |= !LOOPBACK.lock().is_empty();
    {
        let mut stack = STACK.lock();
        for c in stack.tcp.values_mut() {
            if c.timers() {
                woken.push(c.wq.clone());
            }
        }
        // Forget closed connections nobody holds any more
        stack.tcp.retain(|_, c| !(c.detached && matches!(c.state, TcpState::Closed | TcpState::TimeWait)));
    }
    for q in woken {
        q.wake_all();
    }
    more
}

/// Lets a waiting socket operation make progress: polls the NIC directly unless `netd` is running.
pub fn kick() {
    if !SERVICE_RUNNING.load(Ordering::Acquire) {
        poll();
    }
}

/// Returns `true` once the `netd` kernel task processes the NIC (socket waits then sleep until woken).
///
/// # Returns
///
/// `true` if background network daemon is running, `false` otherwise.
pub fn service_running() -> bool {
    SERVICE_RUNNING.load(Ordering::Acquire)
}

/// Returns `true` if at least one active TCP connection has a retransmission timer running.
///
/// # Returns
///
/// `true` if any connection timer is running, `false` otherwise.
fn timers_armed() -> bool {
    STACK.lock().tcp.values().any(|c| c.timer_armed())
}

/// Polls when there is no network task: loopback traffic still needs processing.
fn poll_without_service() {
    if !SERVICE_RUNNING.load(Ordering::Acquire) {
        poll();
    }
}

/// Starts the `netd` kernel task and switches the E1000 NIC to interrupt-driven receive.
pub fn start_service() {
    if !e1000::is_present() || SERVICE_RUNNING.load(Ordering::Acquire) {
        return;
    }
    crate::task::spawn("netd", netd_main, crate::task::TaskPriority::High);
    SERVICE_RUNNING.store(true, Ordering::Release);
    e1000::enable_interrupts();
}

/// Main loop of the `netd` kernel task: processes received frames when the NIC interrupts,
/// and runs TCP timers while any are armed (every 50 ms; shortest RTO is 300 ms).
fn netd_main() {
    loop {
        NET_WQ.register();
        if poll() {
            continue;
        }
        let deadline = if timers_armed() { Some(crate::arch::pit::ticks() + 5) } else { None };
        wait::wait(deadline);
    }
}

/// Returns the [`WaitQueue`] associated with a TCP connection or UDP socket handle `id`.
///
/// # Arguments
/// - `id`: Socket handle identifier.
///
/// # Returns
/// `Some(Arc<WaitQueue>)` if `id` refers to a live TCP or UDP endpoint, or `None` otherwise.
pub fn wait_queue(id: u32) -> Option<Arc<WaitQueue>> {
    let stack = STACK.lock();
    stack
        .tcp
        .get(&id)
        .map(|c| c.wq.clone())
        .or_else(|| stack.udp.get(&id).map(|u| u.wq.clone()))
        .or_else(|| stack.listeners.get(&id).map(|l| l.wq.clone()))
}

/// Parses and dispatches a single Ethernet frame; returns the wait queue of the socket it affected.
///
/// # Arguments
/// * `raw` - Raw Ethernet frame bytes received from the network device.
///
/// # Returns
///
/// An optional wait queue reference to wake if a socket received data.
fn handle_frame(raw: &[u8]) -> Vec<Arc<WaitQueue>> {
    let frame = match EthernetFrame::parse(raw) {
        Some(f) => f,
        None => return Vec::new(),
    };
    let my_ip = local_ip();
    match frame.ethertype {
        EtherType::Arp => {
            if let Some(arp) = ArpPacket::parse(frame.payload) {
                ARP_TABLE.lock().insert(arp.sender_ip, arp.sender_mac);
                if arp.opcode == 1 && arp.target_ip == my_ip && my_ip != [0, 0, 0, 0] {
                    let mut reply = [0u8; 28];
                    let mac = e1000::mac_address();
                    if ArpPacket::new_reply(mac, my_ip, arp.sender_mac, arp.sender_ip).serialize(&mut reply).is_ok() {
                        let mut eth = [0u8; 64];
                        if let Ok(n) = EthernetFrame::serialize(arp.sender_mac, mac, EtherType::Arp, &reply, &mut eth) {
                            let _ = e1000::send_frame(&eth[..n]);
                        }
                    }
                }
            }
        }
        EtherType::Ipv4 => {
            if let Some(ip) = Ipv4Packet::parse(frame.payload) {
                if ip.dst_ip == my_ip {
                    return handle_ip(ip.src_ip, ip.dst_ip, ip.protocol, ip.payload);
                }
            }
        }
        _ => {}
    }
    Vec::new()
}

/// Handles an IPv4 packet addressed to us (from the NIC or loopback); returns the wait
/// queues of the sockets it affected.
///
/// # Arguments
/// * `src`, `dst` - Source and destination addresses.
/// * `proto` - Transport protocol.
/// * `payload` - Transport segment or datagram.
fn handle_ip(src: [u8; 4], dst: [u8; 4], proto: IpProtocol, payload: &[u8]) -> Vec<Arc<WaitQueue>> {
    let mut woken = Vec::new();
    match proto {
        IpProtocol::Tcp => {
            let Some(seg) = TcpPacket::parse(payload) else { return woken };
            let mut stack = STACK.lock();
            let found = stack
                .tcp
                .iter()
                .find(|(_, c)| {
                    c.local_port == seg.dst_port && c.remote_port == seg.src_port && c.remote_ip == src && c.state != TcpState::Closed
                })
                .map(|(&id, _)| id);
            if let Some(id) = found {
                let c = stack.tcp.get_mut(&id).unwrap();
                let was = c.state;
                c.input(&seg);
                woken.push(c.wq.clone());
                // A passively opened connection finished its handshake: ready to accept
                if was == TcpState::SynReceived && c.state != TcpState::SynReceived {
                    if c.state == TcpState::Closed {
                        c.detached = true;
                    } else if let Some(lid) = c.listener {
                        if let Some(l) = stack.listeners.get_mut(&lid) {
                            l.queue.push_back(id);
                            woken.push(l.wq.clone());
                        }
                    }
                }
                return woken;
            }
            // A new connection to a listening port
            if seg.flags & TcpFlags::SYN != 0 && seg.flags & (TcpFlags::ACK | TcpFlags::RST) == 0 {
                let listener = stack
                    .listeners
                    .iter()
                    .find(|(_, l)| l.port == seg.dst_port && covers(l.ip, l.v4, l.v6, dst))
                    .map(|(&id, l)| (id, l.backlog, l.reuse_addr));
                if let Some((lid, backlog, reuse_addr)) = listener {
                    let waiting = stack.tcp.values().filter(|c| c.listener == Some(lid)).count();
                    if waiting >= backlog {
                        return woken; // full: the peer retries its SYN
                    }
                    let id = stack.alloc_id();
                    let iss = (now() as u32).wrapping_mul(2_654_435_761) ^ ((seg.src_port as u32) << 16) ^ id;
                    let mut c = TcpConn {
                        local_ip: dst,
                        local_port: seg.dst_port,
                        remote_ip: src,
                        remote_port: seg.src_port,
                        state: TcpState::SynReceived,
                        iss,
                        snd_una: iss,
                        snd_nxt: iss.wrapping_add(1),
                        snd_wnd: seg.window_size as u32,
                        send_buf: VecDeque::new(),
                        rcv_nxt: seg.seq_num.wrapping_add(1),
                        recv_buf: VecDeque::new(),
                        fin_received: false,
                        fin_seq: None,
                        write_closed: false,
                        detached: false,
                        last_send: now(),
                        rto: RTO_INITIAL_TICKS,
                        retries: 0,
                        error: None,
                        wq: WaitQueue::new_shared(),
                        listener: Some(lid),
                        reuse_addr,
                    };
                    c.send_segment(TcpFlags::SYN | TcpFlags::ACK, iss, &[]);
                    stack.tcp.insert(id, c);
                    return woken;
                }
            }
            // No such connection: reset it (unless it is itself a reset)
            if seg.flags & TcpFlags::RST == 0 {
                drop(stack);
                send_reset(dst, src, &seg);
            }
        }
        IpProtocol::Udp => {
            let p = payload;
            if p.len() < 8 {
                return woken;
            }
            let src_port = u16::from_be_bytes([p[0], p[1]]);
            let dst_port = u16::from_be_bytes([p[2], p[3]]);
            let len = (u16::from_be_bytes([p[4], p[5]]) as usize).clamp(8, p.len());
            let mut stack = STACK.lock();
            if let Some(u) = stack.udp.values_mut().find(|u| u.local_port == dst_port) {
                if u.queue.len() < 64 {
                    u.queue.push_back((src, src_port, p[8..len].to_vec()));
                }
                woken.push(u.wq.clone());
            }
        }
        _ => {}
    }
    woken
}

/// Transmits a stateless TCP `RST` segment in response to an unexpected incoming segment `seg`.
///
/// # Arguments
/// * `dst` - Destination IPv4 address.
/// * `seg` - Unexpected incoming segment triggering the reset.
fn send_reset(src: [u8; 4], dst: [u8; 4], seg: &TcpPacket) {
    let mut buf = [0u8; 20];
    let (seq, ack, flags) = if seg.flags & TcpFlags::ACK != 0 {
        (seg.ack_num, 0, TcpFlags::RST)
    } else {
        let len = seg.payload.len() as u32 + (seg.flags & TcpFlags::SYN != 0) as u32 + (seg.flags & TcpFlags::FIN != 0) as u32;
        (0, seg.seq_num.wrapping_add(len), TcpFlags::RST | TcpFlags::ACK)
    };
    if let Ok(n) = TcpPacket::serialize(src, dst, seg.dst_port, seg.src_port, seq, ack, flags, 0, &[], &mut buf) {
        send_ip(src, dst, IpProtocol::Tcp, &buf[..n]);
    }
}

// ----------------------------------------------------------------------
// TCP API
// ----------------------------------------------------------------------

/// Initiates an active TCP connection to `ip:port` and transmits the initial `SYN` segment.
///
/// # Arguments
/// - `ip`: Remote 4-byte IPv4 address.
/// - `port`: Remote 16-bit TCP port.
/// - `local_port`: Optional pre-bound local port; allocates an ephemeral port if `None`.
///
/// # Returns
/// `Ok(handle_id)` for the newly created connection in [`TcpState::SynSent`].
///
/// # Errors
/// Returns `Err(ENETUNREACH)` if the network interface is down or unconfigured.
pub fn tcp_connect(ip: [u8; 4], port: u16, local_port: Option<u16>) -> Result<u32, i64> {
    if !is_local(ip) && !is_up() {
        return Err(ENETUNREACH);
    }
    let src = source_for(ip);
    let mut stack = STACK.lock();
    let lport = match local_port {
        Some(p) => p,
        None => stack.alloc_port(),
    };
    let id = stack.alloc_id();
    let iss = (now() as u32).wrapping_mul(2_654_435_761) ^ (lport as u32) << 16;
    let mut c = TcpConn {
        local_ip: src,
        local_port: lport,
        remote_ip: ip,
        remote_port: port,
        state: TcpState::SynSent,
        iss,
        snd_una: iss,
        snd_nxt: iss.wrapping_add(1),
        snd_wnd: MSS as u32,
        send_buf: VecDeque::new(),
        rcv_nxt: 0,
        recv_buf: VecDeque::new(),
        fin_received: false,
        fin_seq: None,
        write_closed: false,
        detached: false,
        last_send: now(),
        rto: RTO_INITIAL_TICKS,
        retries: 0,
        error: None,
        wq: WaitQueue::new_shared(),
        listener: None,
        reuse_addr: local_port.is_some_and(|p| stack.binds.values().any(|b| b.port == p && b.reuse_addr)),
    };
    c.send_segment(TcpFlags::SYN, iss, &[]);
    stack.tcp.insert(id, c);
    drop(stack);
    poll_without_service();
    Ok(id)
}

/// Returns the current [`TcpState`] of connection `id` (or [`TcpState::Closed`] if not found).
///
/// # Arguments
/// * `id` - Connection identifier.
///
/// # Returns
///
/// The connection's [`TcpState`].
pub fn tcp_state(id: u32) -> TcpState {
    STACK.lock().tcp.get(&id).map_or(TcpState::Closed, |c| c.state)
}

/// Takes and clears the pending asynchronous error of connection `id` (`SO_ERROR`).
///
/// # Arguments
/// * `id` - Connection identifier.
///
/// # Returns
///
/// The pending errno error code if any, or `None`.
pub fn tcp_take_error(id: u32) -> Option<i64> {
    STACK.lock().tcp.get_mut(&id).and_then(|c| c.error.take())
}

/// Peeks at the pending asynchronous error of connection `id` without clearing it.
///
/// # Arguments
/// * `id` - Connection identifier.
///
/// # Returns
///
/// The pending errno error code if any, or `None`.
pub fn tcp_error(id: u32) -> Option<i64> {
    STACK.lock().tcp.get(&id).and_then(|c| c.error)
}

/// Queues `data` for transmission on TCP connection `id` and flushes segments allowed by the send window.
///
/// # Arguments
/// - `id`: TCP connection handle ID.
/// - `data`: Byte slice to queue for transmission.
///
/// # Returns
/// `Ok(bytes_accepted)` (`0` if the send buffer is full or still in `SynSent`).
///
/// # Errors
/// Returns `Err(ENOTCONN)` if `id` is invalid, `Err(EPIPE)` if the write side is closed, or a pending socket error.
pub fn tcp_send(id: u32, data: &[u8]) -> Result<usize, i64> {
    let mut stack = STACK.lock();
    let c = stack.tcp.get_mut(&id).ok_or(ENOTCONN)?;
    if let Some(e) = c.error {
        return Err(e);
    }
    if c.write_closed {
        return Err(EPIPE);
    }
    if c.state == TcpState::SynSent {
        return Ok(0);
    }
    if !matches!(c.state, TcpState::Established | TcpState::CloseWait) {
        return Err(EPIPE);
    }
    let n = data.len().min(SEND_BUFFER - c.send_buf.len());
    c.send_buf.extend(&data[..n]);
    c.output();
    Ok(n)
}

/// Reads received bytes from TCP connection `id` into `buf`.
///
/// # Arguments
/// - `id`: TCP connection handle ID.
/// - `buf`: Destination byte slice.
/// - `peek`: If `true`, copies bytes without draining them from the receive buffer (`MSG_PEEK`).
///
/// # Returns
/// `Ok((bytes_read, eof))` where `eof` is `true` when the peer has sent `FIN` and the receive buffer is empty.
///
/// # Errors
/// Returns `Err(ENOTCONN)` if `id` is unknown, or any pending connection error when no unread bytes remain.
pub fn tcp_recv(id: u32, buf: &mut [u8], peek: bool) -> Result<(usize, bool), i64> {
    let mut stack = STACK.lock();
    let c = stack.tcp.get_mut(&id).ok_or(ENOTCONN)?;
    let n = buf.len().min(c.recv_buf.len());
    for (i, b) in c.recv_buf.iter().take(n).enumerate() {
        buf[i] = *b;
    }
    if !peek && n > 0 {
        let before = c.window();
        c.recv_buf.drain(..n);
        // Tell the peer when the window reopens substantially
        if (before as usize) < MSS && c.window() as usize >= MSS {
            c.send_ack();
        }
    }
    if n == 0 {
        if let Some(e) = c.error {
            return Err(e);
        }
    }
    Ok((n, c.fin_received && c.recv_buf.is_empty()))
}

/// Queries the I/O readiness of TCP connection `id`: `(readable, writable, hang_up, error)`.
///
/// # Arguments
/// * `id` - Connection identifier.
///
/// # Returns
///
/// A tuple `(readable, writable, hang_up, error)`.
pub fn tcp_poll(id: u32) -> (bool, bool, bool, bool) {
    let stack = STACK.lock();
    match stack.tcp.get(&id) {
        Some(c) => {
            let err = c.error.is_some();
            let readable = !c.recv_buf.is_empty() || c.fin_received || err;
            let writable = matches!(c.state, TcpState::Established | TcpState::CloseWait)
                && c.send_buf.len() < SEND_BUFFER
                && !c.write_closed;
            let hup = c.state == TcpState::Closed || (c.fin_received && c.write_closed);
            (readable, writable || err, hup, err)
        }
        None => (true, false, true, false),
    }
}

/// Shuts down the write half of TCP connection `id` (`shutdown(SHUT_WR)`), queueing a `FIN` after buffered data.
///
/// # Arguments
/// * `id` - Connection identifier.
pub fn tcp_shutdown_write(id: u32) {
    if let Some(c) = STACK.lock().tcp.get_mut(&id) {
        c.write_closed = true;
        c.output();
    }
}

/// Closes TCP socket `id`: detaches the handle, sends `RST` if unread data remains, or initiates a background `FIN` close.
///
/// # Arguments
/// * `id` - Connection identifier.
pub fn tcp_close(id: u32) {
    let mut stack = STACK.lock();
    if let Some(c) = stack.tcp.get_mut(&id) {
        c.detached = true;
        if c.state == TcpState::SynSent {
            c.state = TcpState::Closed;
        } else if !c.recv_buf.is_empty() {
            // Unread data: abort with a reset, as Linux does
            let seq = c.snd_nxt;
            c.send_segment(TcpFlags::RST | TcpFlags::ACK, seq, &[]);
            c.state = TcpState::Closed;
        } else {
            c.write_closed = true;
            c.output();
        }
    }
}

/// Returns the `(local_port, remote_ip, remote_port)` tuple for TCP connection `id`.
///
/// # Arguments
/// * `id` - Connection identifier.
///
/// # Returns
///
/// `Some((local_port, remote_ip, remote_port))` if connection exists, or `None`.
pub fn tcp_endpoints(id: u32) -> Option<(u16, [u8; 4], u16)> {
    STACK.lock().tcp.get(&id).map(|c| (c.local_port, c.remote_ip, c.remote_port))
}

/// Local address of connection `id`.
pub fn tcp_local_ip(id: u32) -> Option<[u8; 4]> {
    STACK.lock().tcp.get(&id).map(|c| c.local_ip)
}

// ----------------------------------------------------------------------
// Passive TCP: bind, listen, accept
// ----------------------------------------------------------------------

/// Reserves TCP port `port` (0: a free one) on `ip` (`0.0.0.0`: all of ours) for `bind`,
/// with Linux's rules: another reservation or connection (`TIME_WAIT` too) on the port
/// with an overlapping address conflicts unless both set `SO_REUSEADDR` (and the other
/// does not listen) or both set `SO_REUSEPORT`.
///
/// # Returns
/// The reservation's handle and the port, or `EADDRINUSE`.
pub fn tcp_bind(ip: [u8; 4], port: u16, reuse_addr: bool, reuse_port: bool, v4: bool, v6: bool) -> Result<(u32, u16), i64> {
    let mut stack = STACK.lock();
    let port = if port == 0 { stack.alloc_port() } else { port };
    let ip4_overlap = |a: [u8; 4]| a == [0, 0, 0, 0] || ip == [0, 0, 0, 0] || a == ip;
    for b in stack.binds.values() {
        let overlap = (v4 && b.v4 && ip4_overlap(b.ip)) || (v6 && b.v6);
        if b.port == port && overlap && !(reuse_port && b.reuse_port) && !(reuse_addr && b.reuse_addr && !b.listening) {
            return Err(EADDRINUSE);
        }
    }
    let conn_overlap = |c: &TcpConn| if c.local_ip == V6_LOOPBACK { v6 } else { v4 && ip4_overlap(c.local_ip) };
    if stack.tcp.values().any(|c| c.local_port == port && c.state != TcpState::Closed && conn_overlap(c) && !(reuse_addr && c.reuse_addr)) {
        return Err(EADDRINUSE);
    }
    let id = stack.alloc_id();
    stack.binds.insert(id, Bind { ip, port, reuse_addr, reuse_port, listening: false, v4, v6 });
    Ok((id, port))
}

/// Releases port reservation `id`.
pub fn tcp_unbind(id: u32) {
    STACK.lock().binds.remove(&id);
}

/// Starts listening on reservation `bind` with `backlog`.
///
/// # Returns
/// The listener's handle, or `EADDRINUSE` if another socket listens on the port.
pub fn tcp_listen(bind: u32, backlog: usize) -> Result<u32, i64> {
    let mut stack = STACK.lock();
    let (ip, port, reuse_port, reuse_addr, v4, v6) = match stack.binds.get(&bind) {
        Some(b) => (b.ip, b.port, b.reuse_port, b.reuse_addr, b.v4, b.v6),
        None => return Err(-22),
    };
    let ip4_overlap = |a: [u8; 4]| a == [0, 0, 0, 0] || ip == [0, 0, 0, 0] || a == ip;
    let overlap = |b: &Bind| (v4 && b.v4 && ip4_overlap(b.ip)) || (v6 && b.v6);
    if stack.binds.iter().any(|(&i, b)| i != bind && b.listening && b.port == port && overlap(b) && !(reuse_port && b.reuse_port)) {
        return Err(EADDRINUSE);
    }
    stack.binds.get_mut(&bind).unwrap().listening = true;
    let id = stack.alloc_id();
    stack.listeners.insert(id, Listener { ip, port, backlog: backlog.max(1), queue: VecDeque::new(), wq: WaitQueue::new_shared(), reuse_addr, v4, v6 });
    Ok(id)
}

/// Changes listener `id`'s backlog (a second `listen`).
pub fn tcp_set_backlog(id: u32, backlog: usize) {
    if let Some(l) = STACK.lock().listeners.get_mut(&id) {
        l.backlog = backlog.max(1);
    }
}

/// Takes the next established connection of listener `id`.
pub fn tcp_accept(id: u32) -> Option<u32> {
    let mut stack = STACK.lock();
    let cid = stack.listeners.get_mut(&id)?.queue.pop_front()?;
    if let Some(c) = stack.tcp.get_mut(&cid) {
        c.listener = None;
    }
    Some(cid)
}

/// Whether listener `id` has a connection to accept.
pub fn tcp_acceptable(id: u32) -> bool {
    STACK.lock().listeners.get(&id).map_or(false, |l| !l.queue.is_empty())
}

/// A TCP connection as `/proc/net/tcp` shows it.
pub struct TcpEntry {
    /// Connection handle.
    pub id: u32,
    /// Local address and port.
    pub local: ([u8; 4], u16),
    /// Remote address and port.
    pub remote: ([u8; 4], u16),
    /// State.
    pub state: TcpState,
    /// Bytes queued to send (unsent or unacknowledged) and received but unread.
    pub tx: usize,
    /// Bytes received and not yet read.
    pub rx: usize,
}

/// All TCP connections.
pub fn tcp_list() -> Vec<TcpEntry> {
    STACK
        .lock()
        .tcp
        .iter()
        .map(|(&id, c)| TcpEntry {
            id,
            local: (c.local_ip, c.local_port),
            remote: (c.remote_ip, c.remote_port),
            state: c.state,
            tx: c.send_buf.len(),
            rx: c.recv_buf.len(),
        })
        .collect()
}

/// All listeners: `(handle, address, port, connections waiting to be accepted, backlog)`.
pub fn listener_list() -> Vec<(u32, [u8; 4], u16, usize, usize)> {
    STACK.lock().listeners.iter().map(|(&id, l)| (id, l.ip, l.port, l.queue.len(), l.backlog)).collect()
}

/// All UDP sockets: `(handle, port, bytes queued)`.
pub fn udp_list() -> Vec<(u32, u16, usize)> {
    STACK.lock().udp.iter().map(|(&id, u)| (id, u.local_port, u.queue.iter().map(|d| d.2.len()).sum())).collect()
}

/// Stops listener `id`: connections not yet accepted are reset.
pub fn tcp_unlisten(id: u32) {
    let mut stack = STACK.lock();
    if let Some(l) = stack.listeners.remove(&id) {
        l.wq.wake_all();
    }
    for c in stack.tcp.values_mut().filter(|c| c.listener == Some(id)) {
        let seq = c.snd_nxt;
        c.send_segment(TcpFlags::RST | TcpFlags::ACK, seq, &[]);
        c.state = TcpState::Closed;
        c.detached = true;
        c.listener = None;
    }
}


// ----------------------------------------------------------------------
// UDP API
// ----------------------------------------------------------------------

/// Opens a UDP socket bound to `port` (`0` allocates an ephemeral port).
///
/// # Arguments
/// - `port`: Desired local 16-bit UDP port, or `0` for dynamic allocation.
///
/// # Returns
/// `Ok(handle_id)` for the newly created UDP socket.
///
/// # Errors
/// Returns `Err(EADDRINUSE)` if `port` is non-zero and already bound by another UDP socket.
pub fn udp_open(port: u16) -> Result<u32, i64> {
    let mut stack = STACK.lock();
    let port = if port == 0 {
        stack.alloc_port()
    } else {
        if stack.udp.values().any(|u| u.local_port == port) {
            return Err(EADDRINUSE);
        }
        port
    };
    let id = stack.alloc_id();
    stack.udp.insert(id, UdpSock { local_port: port, queue: VecDeque::new(), wq: WaitQueue::new_shared() });
    Ok(id)
}

/// Moves UDP socket `id` to `port` (0: keep its port), as `bind` after an implicit open.
pub fn udp_rebind(id: u32, port: u16) -> Result<(), i64> {
    let mut stack = STACK.lock();
    if port != 0 && stack.udp.iter().any(|(&o, u)| o != id && u.local_port == port) {
        return Err(EADDRINUSE);
    }
    if port != 0 {
        if let Some(u) = stack.udp.get_mut(&id) {
            u.local_port = port;
        }
    }
    Ok(())
}

/// Returns the local 16-bit UDP port bound to socket `id` (or `0` if invalid).
///
/// # Arguments
/// * `id` - UDP socket identifier.
///
/// # Returns
///
/// The bound 16-bit local UDP port number.
pub fn udp_port(id: u32) -> u16 {
    STACK.lock().udp.get(&id).map_or(0, |u| u.local_port)
}

/// Transmits a UDP datagram from socket `id` to `ip:port`.
///
/// # Arguments
/// - `id`: UDP socket handle ID.
/// - `ip`: Destination 4-byte IPv4 address.
/// - `port`: Destination 16-bit UDP port.
/// - `data`: Datagram payload slice.
///
/// # Returns
/// `Ok(data.len())` once the datagram is handed to the IPv4 layer.
///
/// # Errors
/// Returns `Err(ENETUNREACH)` if the network interface is down, or `Err(-90)` (`EMSGSIZE`) if serialization fails.
pub fn udp_send(id: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
    if !is_local(ip) && !is_up() {
        return Err(ENETUNREACH);
    }
    let lport = udp_port(id);
    let mut buf = alloc::vec![0u8; 8 + data.len()];
    let n = super::udp::UdpPacket::serialize(lport, port, data, &mut buf).map_err(|_| -90i64)?; // EMSGSIZE
    send_ip(source_for(ip), ip, IpProtocol::Udp, &buf[..n]);
    Ok(data.len())
}

/// Takes (or peeks at) the next queued UDP datagram: `(source_ip, source_port, payload)`.
///
/// # Arguments
/// - `id`: UDP socket handle ID.
/// - `peek`: If `true`, clones the front datagram without removing it from the queue.
///
/// # Returns
/// `Some((src_ip, src_port, payload))` if a datagram is available, or `None` if the queue is empty.
pub fn udp_recv(id: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>)> {
    let mut stack = STACK.lock();
    let u = stack.udp.get_mut(&id)?;
    if peek {
        u.queue.front().cloned()
    } else {
        u.queue.pop_front()
    }
}

/// Returns `true` if UDP socket `id` has at least one received datagram waiting in its queue.
///
/// # Arguments
/// * `id` - UDP socket identifier.
///
/// # Returns
///
/// `true` if datagrams are queued for reading, `false` otherwise.
pub fn udp_readable(id: u32) -> bool {
    STACK.lock().udp.get(&id).map_or(false, |u| !u.queue.is_empty())
}

/// Closes UDP socket `id` and frees its queued datagrams.
///
/// # Arguments
/// * `id` - UDP socket identifier to close.
pub fn udp_close(id: u32) {
    STACK.lock().udp.remove(&id);
}
