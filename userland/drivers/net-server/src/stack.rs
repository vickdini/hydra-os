//! # net-server: TCP/UDP/ICMP transport and sockets
//!
//! Connection-oriented TCP, datagram UDP and ICMP (ping and raw) sockets on top of the
//! packet layer (Ethernet, ARP, IPv4), with loopback (`127.0.0.0/8`, `::1`). This was the
//! kernel's `net/stack.rs`; it runs in net-server now, and its clients reach it through the
//! requests in `main.rs` (`ipc/protocol.rs`, `MSG_NETS_*`).
//!
//! ## Architectural Role & Design Rationale
//!
//! [`poll_nic`] drains received frames, answers ARP, routes UDP datagrams to their socket's
//! queue and TCP segments to their connection's state machine; [`poll_loopback`] does the
//! same for packets sent to ourselves and [`run_timers`] runs the retransmission timers.
//! The main loop calls them when the network driver's interrupt is forwarded here, after
//! requests, and on a timer. Nothing here blocks or wakes anyone: after each round the main
//! loop computes every socket's readiness ([`readiness`]) and publishes what changed to the
//! clients (status area and doorbell).
//!
//! TCP implements active open, passive open (listen/accept), in-order receive
//! (out-of-order segments are dropped and recovered by the peer's retransmission), a
//! sliding send window bounded by the peer's advertised window, go-back-N retransmission
//! with exponential back-off, and orderly (FIN) and abortive (RST) close. The advertised
//! receive window (64 KiB, the most possible without window scaling) fits in the NIC's
//! receive ring.
//!
//! ## Handles
//!
//! Sockets, listeners and port reservations are handles `generation << 12 | slot`: the
//! slot (1..4096) indexes the readiness table clients read, the generation tells a reused
//! slot apart. A new server starts its generations from its start time, so handles of a
//! previous instance (after a restart) are not mistaken for new ones.
//!
//! ## Dependencies
//!
//! Single-threaded: the [`spin::Mutex`]es only give the statics interior mutability.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::iface::GLOBAL_INTERFACE;
use crate::net::arp::{ArpPacket, ARP_TABLE};
use crate::net::ethernet::{EtherType, EthernetFrame};
use crate::net::ipv4::{IpProtocol, Ipv4Packet};
use crate::net::tcp::{TcpFlags, TcpPacket};
use crate::nic;
use hydra_rt::protocol::*;

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
    /// The listener this passively opened connection belongs to until it is accepted.
    listener: Option<u32>,
    /// Its port was bound with `SO_REUSEADDR` (inherited from the listener).
    reuse_addr: bool,
}

/// An ICMP socket: a ping socket (`SOCK_DGRAM`, echo replies for its identifier) or a raw
/// one (`SOCK_RAW`, every ICMP message, IPv4 ones with their IP header).
struct IcmpSock {
    /// Echo identifier (ping sockets).
    ident: u16,
    /// A raw socket.
    raw: bool,
    /// ICMPv6 (`::1` only).
    v6: bool,
    /// Received messages and their senders.
    queue: VecDeque<([u8; 4], Vec<u8>, u64)>,
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
    queue: VecDeque<([u8; 4], u16, Vec<u8>, u64)>,
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
    /// ICMP sockets (ping and raw) by handle ID.
    icmp: BTreeMap<u32, IcmpSock>,
    /// Generation of the next handle (see "Handles" above).
    next_gen: u32,
    /// Next candidate ephemeral port number.
    next_port: u16,
}

/// Global spinlock-protected TCP/UDP transport state.
static STACK: Mutex<Stack> = Mutex::new(Stack {
    tcp: BTreeMap::new(),
    listeners: BTreeMap::new(),
    binds: BTreeMap::new(),
    icmp: BTreeMap::new(),
    udp: BTreeMap::new(),
    next_gen: 1,
    next_port: EPHEMERAL_FIRST,
});

/// Returns the current 100 Hz PIT tick counter.
///
/// # Returns
///
/// Current PIT timer tick value.
fn now() -> u64 {
    hydra_rt::sys::uptime_ticks()
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
    GLOBAL_INTERFACE.lock().ip()
}

/// Returns `true` once the hardware interface is present and has a non-zero IPv4 address (DHCP finished).
///
/// # Returns
///
/// `true` if interface is initialized and configured with an IP, `false` otherwise.
pub fn is_up() -> bool {
    nic::is_present() && local_ip() != [0, 0, 0, 0]
}

/// Encapsulates and sends an IPv4 packet via [`GLOBAL_INTERFACE`] (or loops it back),
/// ignoring link errors.
///
/// # Arguments
/// * `dst` - Destination 4-byte IPv4 address.
/// * `proto` - Transport protocol discriminator.
/// * `payload` - Packet payload byte slice.
fn send_ip(src: [u8; 4], dst: [u8; 4], proto: IpProtocol, payload: &[u8]) {
    if is_local(dst) {
        count(&LO, payload.len() + 20);
        // Loopback: delivered by the next poll_loopback (after the current request)
        let mut q = LOOPBACK.lock();
        if q.len() < 4096 {
            q.push_back((src, dst, proto, payload.to_vec()));
        }
        return;
    }
    let mut iface = GLOBAL_INTERFACE.lock();
    let _ = iface.send_ipv4(dst, proto, payload);
}

/// Loopback traffic `[bytes, packets]` for `/proc/net/dev` (sent and received alike; the
/// network card's counts come from its driver).
static LO: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

fn count(c: &[AtomicU64; 2], bytes: usize) {
    c[0].fetch_add(bytes as u64, Ordering::Relaxed);
    c[1].fetch_add(1, Ordering::Relaxed);
}

/// Loopback traffic `(bytes, packets)` (sent and received alike).
pub fn lo_counters() -> (u64, u64) {
    (LO[0].load(Ordering::Relaxed), LO[1].load(Ordering::Relaxed))
}

/// Wall-clock time (nanoseconds) a datagram arrived, kept with it for `SO_TIMESTAMP` and
/// `SIOCGSTAMP` (the arrival, not when the program reads it, as on Linux).
fn arrival_stamp() -> u64 {
    let (s, ns) = hydra_rt::sys::clock();
    s * 1_000_000_000 + ns as u64
}

/// Packets sent to ourselves, waiting to be received: `(src, dst, protocol, payload)`.
static LOOPBACK: Mutex<VecDeque<([u8; 4], [u8; 4], IpProtocol, Vec<u8>)>> = Mutex::new(VecDeque::new());

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

/// Whether `ip` is one of ours: `127.0.0.0/8`, `::1`, the link-local address or the
/// interface's address.
pub fn is_local(ip: [u8; 4]) -> bool {
    ip[0] == 127
        || ip == V6_LOOPBACK
        || (ip == V6_LINKLOCAL && nic::is_present())
        || (ip != [0, 0, 0, 0] && ip == GLOBAL_INTERFACE.lock().ip())
}

/// The source address for packets to `dst`: the loopback address for `127.0.0.0/8`, `::1`
/// for `::1`.
fn source_for(dst: [u8; 4]) -> [u8; 4] {
    if is_v6(dst) {
        dst
    } else if dst[0] == 127 {
        [127, 0, 0, 1]
    } else {
        local_ip()
    }
}

/// Whether a socket covering IPv4 address `ip` (`0.0.0.0`: all) and/or IPv6 (`v4`, `v6`)
/// takes packets addressed to `dst`.
fn covers(ip: [u8; 4], v4: bool, v6: bool, dst: [u8; 4]) -> bool {
    if is_v6(dst) { v6 && (ip == [0, 0, 0, 0] || ip == dst) } else { v4 && (ip == [0, 0, 0, 0] || ip == dst) }
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

    /// Allocates a handle for a new socket, listener or reservation: the lowest free slot
    /// with the next generation (see "Handles" above). With every slot taken (4095 live
    /// handles), the slot of the oldest is shared (its readiness word is then wrong).
    ///
    /// # Returns
    ///
    /// A handle no live socket has.
    fn alloc_id(&mut self) -> u32 {
        let mut used = alloc::vec![false; NETS_SLOTS];
        for id in self.tcp.keys().chain(self.listeners.keys()).chain(self.binds.keys()).chain(self.udp.keys()).chain(self.icmp.keys()) {
            used[slot_of(*id)] = true;
        }
        let slot = (1..NETS_SLOTS).find(|&i| !used[i]).unwrap_or(1);
        self.next_gen = (self.next_gen + 1) & 0xF_FFFF;
        if self.next_gen == 0 {
            self.next_gen = 1;
        }
        self.next_gen << 12 | slot as u32
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
            // The window reopened while what we sent into a (nearly) closed window was not
            // taken (the receiver had no room: a window probe, or data on a stale window):
            // send again from the oldest unacknowledged byte now, instead of after the
            // retransmission timeout (which cost 300 ms per window on loopback)
            if (self.snd_wnd as usize) < MSS
                && seg.window_size as u32 > self.snd_wnd
                && seg.ack_num == self.snd_una
                && self.snd_una != self.snd_nxt
                && self.fin_seq.is_none()
                && matches!(self.state, TcpState::Established | TcpState::CloseWait)
            {
                self.snd_nxt = self.snd_una;
            }
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

/// Packets looped back and waiting ([`poll_loopback`] processes them).
pub fn loopback_pending() -> bool {
    !LOOPBACK.lock().is_empty()
}

/// Processes up to 1024 packets sent to ourselves (answers they cause are queued behind
/// them).
///
/// # Returns
/// `true` if more are waiting.
pub fn poll_loopback() -> bool {
    for _ in 0..1024 {
        let Some((src, dst, proto, payload)) = LOOPBACK.lock().pop_front() else { return false };
        handle_ip(src, dst, proto, &payload);
    }
    loopback_pending()
}

/// Processes the frames the network driver has received.
///
/// # Returns
/// The number of frames taken (the driver may have more: call again while it is not 0).
pub fn poll_nic() -> usize {
    nic::receive_frames(|frame| handle_frame(frame))
}

/// Runs the TCP retransmission timers and forgets closed connections nobody holds.
pub fn run_timers() {
    let mut stack = STACK.lock();
    for c in stack.tcp.values_mut() {
        c.timers();
    }
    stack.tcp.retain(|_, c| !(c.detached && matches!(c.state, TcpState::Closed | TcpState::TimeWait)));
}

/// wave10 GN: forgets closed connections nobody holds (as [`run_timers`] does).
pub fn forget_closed() {
    let mut stack = STACK.lock();
    if stack.tcp.values().any(|c| c.detached && matches!(c.state, TcpState::Closed | TcpState::TimeWait)) {
        stack.tcp.retain(|_, c| !(c.detached && matches!(c.state, TcpState::Closed | TcpState::TimeWait)));
    }
}

/// Returns `true` if at least one active TCP connection has a retransmission timer running.
pub fn timers_armed() -> bool {
    STACK.lock().tcp.values().any(|c| c.timer_armed())
}

/// The TCP state as the protocol numbers it (`NETS_TCP_*`).
pub fn state_number(s: TcpState) -> u64 {
    match s {
        TcpState::SynSent => NETS_TCP_SYN_SENT,
        TcpState::SynReceived => NETS_TCP_SYN_RECEIVED,
        TcpState::Established => NETS_TCP_ESTABLISHED,
        TcpState::FinWait1 => NETS_TCP_FIN_WAIT1,
        TcpState::FinWait2 => NETS_TCP_FIN_WAIT2,
        TcpState::CloseWait => NETS_TCP_CLOSE_WAIT,
        TcpState::LastAck => NETS_TCP_LAST_ACK,
        TcpState::Closing => NETS_TCP_CLOSING,
        TcpState::TimeWait => NETS_TCP_TIME_WAIT,
        TcpState::Closed => NETS_TCP_CLOSED,
    }
}

/// The readiness-table slot of handle `id`.
pub fn slot_of(id: u32) -> usize {
    (id as usize) & (NETS_SLOTS - 1)
}

/// The readiness word of every handle (see `NETS_SOCKS_OFF`): `(handle, word)`.
pub fn readiness() -> Vec<(u32, u64)> {
    let stack = STACK.lock();
    let word = |id: u32, r: u64, state: u64, err: u64| id as u64 | r << 32 | state << 40 | (err & 0xFFFF) << 48;
    let mut out = Vec::with_capacity(stack.tcp.len() + stack.udp.len() + stack.listeners.len() + stack.icmp.len() + stack.binds.len());
    for (&id, c) in stack.tcp.iter() {
        if c.detached {
            continue; // closed by its client: nobody reads it
        }
        let (r, w, hup, err) = conn_poll(c);
        let bits = r as u64 * NETS_R_IN | w as u64 * NETS_R_OUT | hup as u64 * NETS_R_HUP | err as u64 * NETS_R_ERR;
        out.push((id, word(id, bits, state_number(c.state), c.error.map_or(0, |e| (-e) as u64))));
    }
    for (&id, l) in stack.listeners.iter() {
        out.push((id, word(id, if l.queue.is_empty() { 0 } else { NETS_R_ACCEPT | NETS_R_IN }, 0, 0)));
    }
    for (&id, u) in stack.udp.iter() {
        out.push((id, word(id, NETS_R_OUT | if u.queue.is_empty() { 0 } else { NETS_R_IN }, 0, 0)));
    }
    for (&id, i) in stack.icmp.iter() {
        out.push((id, word(id, NETS_R_OUT | if i.queue.is_empty() { 0 } else { NETS_R_IN }, 0, 0)));
    }
    for &id in stack.binds.keys() {
        out.push((id, word(id, 0, 0, 0)));
    }
    out
}

/// Parses and dispatches a single Ethernet frame.
///
/// # Arguments
/// * `raw` - Raw Ethernet frame bytes received from the network device.
fn handle_frame(raw: &[u8]) {
    let frame = match EthernetFrame::parse(raw) {
        Some(f) => f,
        None => return,
    };
    let my_ip = local_ip();
    match frame.ethertype {
        EtherType::Arp => {
            if let Some(arp) = ArpPacket::parse(frame.payload) {
                ARP_TABLE.lock().insert(arp.sender_ip, arp.sender_mac);
                if arp.opcode == 1 && arp.target_ip == my_ip && my_ip != [0, 0, 0, 0] {
                    let mut reply = [0u8; 28];
                    let mac = nic::mac_address();
                    if ArpPacket::new_reply(mac, my_ip, arp.sender_mac, arp.sender_ip).serialize(&mut reply).is_ok() {
                        let mut eth = [0u8; 64];
                        if let Ok(n) = EthernetFrame::serialize(arp.sender_mac, mac, EtherType::Arp, &reply, &mut eth) {
                            let _ = nic::send_frame(&eth[..n]);
                        }
                    }
                }
            }
        }
        EtherType::Ipv4 => {
            if let Some(ip) = Ipv4Packet::parse(frame.payload) {
                // DHCP replies (to the broadcast or the offered address) go to the client
                if ip.protocol == IpProtocol::Udp {
                    if let Some(udp) = crate::net::udp::UdpPacket::parse(ip.payload) {
                        if udp.dst_port == crate::net::dhcp::DHCP_CLIENT_PORT {
                            crate::dhcp_input(udp.payload);
                            return;
                        }
                    }
                }
                if ip.dst_ip == my_ip {
                    handle_ip(ip.src_ip, ip.dst_ip, ip.protocol, ip.payload);
                }
            }
        }
        _ => {}
    }
}

/// Handles an IPv4 packet addressed to us (from the NIC or loopback).
///
/// # Arguments
/// * `src`, `dst` - Source and destination addresses.
/// * `proto` - Transport protocol.
/// * `payload` - Transport segment or datagram.
fn handle_ip(src: [u8; 4], dst: [u8; 4], proto: IpProtocol, payload: &[u8]) {
    match proto {
        IpProtocol::Tcp => {
            let Some(seg) = TcpPacket::parse(payload) else { return };
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
                // A passively opened connection finished its handshake: ready to accept
                if was == TcpState::SynReceived && c.state != TcpState::SynReceived {
                    if c.state == TcpState::Closed {
                        c.detached = true;
                    } else if let Some(lid) = c.listener {
                        if let Some(l) = stack.listeners.get_mut(&lid) {
                            l.queue.push_back(id);
                        }
                    }
                }
                return;
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
                        return; // full: the peer retries its SYN
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
                        listener: Some(lid),
                        reuse_addr,
                    };
                    c.send_segment(TcpFlags::SYN | TcpFlags::ACK, iss, &[]);
                    stack.tcp.insert(id, c);
                    return;
                }
            }
            // No such connection: reset it (unless it is itself a reset)
            if seg.flags & TcpFlags::RST == 0 {
                drop(stack);
                send_reset(dst, src, &seg);
            }
        }
        IpProtocol::Icmp => {
            if payload.len() < 8 {
                return;
            }
            let ty = payload[0];
            let v6 = is_v6(dst);
            // Echo requests to us are answered by the kernel
            if (!v6 && ty == 8) || (v6 && ty == 128) {
                let mut reply = payload.to_vec();
                reply[0] = if v6 { 129 } else { 0 };
                reply[2] = 0;
                reply[3] = 0;
                let c = crate::net::ipv4::compute_checksum(&reply);
                reply[2..4].copy_from_slice(&c.to_be_bytes());
                send_ip(dst, src, IpProtocol::Icmp, &reply);
            }
            let reply_type = if v6 { 129 } else { 0 };
            let ident = u16::from_be_bytes([payload[4], payload[5]]);
            let mut stack = STACK.lock();
            for sock in stack.icmp.values_mut() {
                if sock.v6 != v6 || sock.queue.len() >= 64 {
                    continue;
                }
                if !sock.raw && (ty != reply_type || ident != sock.ident) {
                    continue;
                }
                let data = if sock.raw && !v6 {
                    // Raw IPv4 sockets read the IP header too
                    let mut h = alloc::vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
                    let total = (20 + payload.len()) as u16;
                    h[2..4].copy_from_slice(&total.to_be_bytes());
                    h.extend_from_slice(&src);
                    h.extend_from_slice(&dst);
                    let c = crate::net::ipv4::compute_checksum(&h);
                    h[10..12].copy_from_slice(&c.to_be_bytes());
                    h.extend_from_slice(payload);
                    h
                } else {
                    payload.to_vec()
                };
                sock.queue.push_back((src, data, arrival_stamp()));
            }
        }
        IpProtocol::Udp => {
            let p = payload;
            if p.len() < 8 {
                return;
            }
            let src_port = u16::from_be_bytes([p[0], p[1]]);
            let dst_port = u16::from_be_bytes([p[2], p[3]]);
            let len = (u16::from_be_bytes([p[4], p[5]]) as usize).clamp(8, p.len());
            let mut stack = STACK.lock();
            if let Some(u) = stack.udp.values_mut().find(|u| u.local_port == dst_port) {
                if u.queue.len() < 64 {
                    u.queue.push_back((src, src_port, p[8..len].to_vec(), arrival_stamp()));
                }
            }
        }
        _ => {}
    }
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
        listener: None,
        reuse_addr: local_port.is_some_and(|p| stack.binds.values().any(|b| b.port == p && b.reuse_addr)),
    };
    c.send_segment(TcpFlags::SYN, iss, &[]);
    stack.tcp.insert(id, c);
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

/// A connection's readiness: `(readable, writable, hang_up, error)`.
fn conn_poll(c: &TcpConn) -> (bool, bool, bool, bool) {
    let err = c.error.is_some();
    let readable = !c.recv_buf.is_empty() || c.fin_received || err;
    let writable = matches!(c.state, TcpState::Established | TcpState::CloseWait) && c.send_buf.len() < SEND_BUFFER && !c.write_closed;
    let hup = c.state == TcpState::Closed || (c.fin_received && c.write_closed);
    (readable, writable || err, hup, err)
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
    let conn_overlap = |c: &TcpConn| if is_v6(c.local_ip) { v6 && ip4_overlap(c.local_ip) } else { v4 && ip4_overlap(c.local_ip) };
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
    stack.listeners.insert(id, Listener { ip, port, backlog: backlog.max(1), queue: VecDeque::new(), reuse_addr, v4, v6 });
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
    stack.listeners.remove(&id);
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
    stack.udp.insert(id, UdpSock { local_port: port, queue: VecDeque::new() });
    Ok(id)
}

// ----------------------------------------------------------------------
// ICMP sockets
// ----------------------------------------------------------------------

/// Opens an ICMP socket: raw (`raw`) or a ping socket, for ICMPv6 (`v6`) or ICMP.
pub fn icmp_open(raw: bool, v6: bool) -> u32 {
    let mut stack = STACK.lock();
    let id = stack.alloc_id();
    // A free echo identifier, as Linux picks an unused "port" for ping sockets
    let mut ident = (id as u16).wrapping_mul(40503) | 1;
    while stack.icmp.values().any(|i| !i.raw && i.ident == ident) {
        ident = ident.wrapping_add(1);
    }
    stack.icmp.insert(id, IcmpSock { ident, raw, v6, queue: VecDeque::new() });
    id
}

/// Echo identifier of ping socket `id`.
pub fn icmp_ident(id: u32) -> u16 {
    STACK.lock().icmp.get(&id).map_or(0, |i| i.ident)
}

/// Gives ping socket `id` echo identifier `ident` (`bind`); `EADDRINUSE` if taken.
pub fn icmp_set_ident(id: u32, ident: u16) -> Result<(), i64> {
    let mut stack = STACK.lock();
    if stack.icmp.iter().any(|(&o, i)| o != id && !i.raw && i.ident == ident) {
        return Err(EADDRINUSE);
    }
    if let Some(i) = stack.icmp.get_mut(&id) {
        i.ident = ident;
    }
    Ok(())
}

/// Sends ICMP message `msg` from socket `id` to `dst`. A ping socket's message must be an
/// echo request; its identifier and checksum are filled in.
pub fn icmp_send(id: u32, dst: [u8; 4], msg: &[u8]) -> Result<usize, i64> {
    let (raw, v6, ident) = match STACK.lock().icmp.get(&id) {
        Some(i) => (i.raw, i.v6, i.ident),
        None => return Err(-9),
    };
    if v6 != is_v6(dst) {
        return Err(ENETUNREACH);
    }
    if !is_local(dst) && !is_up() {
        return Err(ENETUNREACH);
    }
    if msg.len() < if raw { 4 } else { 8 } {
        return Err(-22);
    }
    let mut m = msg.to_vec();
    if !raw {
        if m[0] != if v6 { 128 } else { 8 } || m[1] != 0 {
            return Err(-22);
        }
        m[4..6].copy_from_slice(&ident.to_be_bytes());
    }
    if !raw || v6 {
        m[2] = 0;
        m[3] = 0;
        let c = crate::net::ipv4::compute_checksum(&m);
        m[2..4].copy_from_slice(&c.to_be_bytes());
    }
    send_ip(source_for(dst), dst, IpProtocol::Icmp, &m);
    Ok(msg.len())
}

/// Takes (or with `peek` copies) the next message of ICMP socket `id`.
pub fn icmp_recv(id: u32, peek: bool) -> Option<([u8; 4], Vec<u8>, u64)> {
    let mut stack = STACK.lock();
    let i = stack.icmp.get_mut(&id)?;
    if peek { i.queue.front().cloned() } else { i.queue.pop_front() }
}

/// Closes ICMP socket `id`.
pub fn icmp_close(id: u32) {
    STACK.lock().icmp.remove(&id);
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
    let n = crate::net::udp::UdpPacket::serialize(lport, port, data, &mut buf).map_err(|_| -90i64)?; // EMSGSIZE
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
pub fn udp_recv(id: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>, u64)> {
    let mut stack = STACK.lock();
    let u = stack.udp.get_mut(&id)?;
    if peek {
        u.queue.front().cloned()
    } else {
        u.queue.pop_front()
    }
}

/// Closes UDP socket `id` and frees its queued datagrams.
///
/// # Arguments
/// * `id` - UDP socket identifier to close.
pub fn udp_close(id: u32) {
    STACK.lock().udp.remove(&id);
}

/// Whether `id` names a listener.
pub fn listener_exists(id: u32) -> bool {
    STACK.lock().listeners.contains_key(&id)
}

/// Whether `id` names a UDP socket.
pub fn udp_exists(id: u32) -> bool {
    STACK.lock().udp.contains_key(&id)
}

/// Whether `id` names an ICMP socket.
pub fn icmp_exists(id: u32) -> bool {
    STACK.lock().icmp.contains_key(&id)
}

/// Starts handle generations from `seed` (the server's start time): see "Handles".
pub fn seed_generations(seed: u32) {
    STACK.lock().next_gen = seed & 0xF_FFFF;
}
