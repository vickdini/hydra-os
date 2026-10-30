//! # TCP/UDP Transport Engine
//!
//! Connection-oriented TCP and datagram UDP on top of the packet-level Ethernet/IPv4
//! code, for the socket layer (`AF_INET` in the Linux personality).
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

pub const ECONNREFUSED: i64 = -111;
pub const ECONNRESET: i64 = -104;
pub const ETIMEDOUT: i64 = -110;
pub const EADDRINUSE: i64 = -98;
pub const ENOTCONN: i64 = -107;
pub const EPIPE: i64 = -32;
pub const ENETUNREACH: i64 = -101;

const MSS: usize = 1460;
/// Advertised receive window: the largest a 16-bit window field holds (no window scaling).
const RECV_WINDOW: usize = 65535;
/// Most unsent + unacknowledged data a connection buffers.
const SEND_BUFFER: usize = 256 * 1024;
const RTO_INITIAL_TICKS: u64 = 30; // 300 ms at 100 Hz
const RTO_MAX_TICKS: u64 = 400;
const MAX_RETRIES: u32 = 10;
const EPHEMERAL_FIRST: u16 = 49152;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
    TimeWait,
    Closed,
}

struct TcpConn {
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    state: TcpState,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    /// Bytes from `snd_una` onward: sent-but-unacknowledged followed by unsent.
    send_buf: VecDeque<u8>,
    rcv_nxt: u32,
    recv_buf: VecDeque<u8>,
    fin_received: bool,
    /// Sequence number of our FIN once sent.
    fin_seq: Option<u32>,
    /// The application closed or shut down writing: send FIN after the buffered data.
    write_closed: bool,
    /// The socket was closed: free the connection once the close handshake ends.
    detached: bool,
    last_send: u64,
    rto: u64,
    retries: u32,
    error: Option<i64>,
    /// Tasks waiting for this connection to change state (data, space, close, error).
    wq: Arc<WaitQueue>,
}

struct UdpSock {
    local_port: u16,
    queue: VecDeque<([u8; 4], u16, Vec<u8>)>,
    wq: Arc<WaitQueue>,
}

struct Stack {
    tcp: BTreeMap<u32, TcpConn>,
    udp: BTreeMap<u32, UdpSock>,
    next_id: u32,
    next_port: u16,
}

static STACK: Mutex<Stack> = Mutex::new(Stack {
    tcp: BTreeMap::new(),
    udp: BTreeMap::new(),
    next_id: 1,
    next_port: EPHEMERAL_FIRST,
});

fn now() -> u64 {
    crate::arch::pit::ticks()
}

/// `a < b` in 32-bit sequence space.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

fn local_ip() -> [u8; 4] {
    GLOBAL_INTERFACE.lock().ip()
}

/// True once the interface has an address (DHCP finished).
pub fn is_up() -> bool {
    e1000::is_present() && local_ip() != [0, 0, 0, 0]
}

fn send_ip(dst: [u8; 4], proto: IpProtocol, payload: &[u8]) {
    let _ = GLOBAL_INTERFACE.lock().send_ipv4(dst, proto, payload);
}

impl Stack {
    fn alloc_port(&mut self) -> u16 {
        loop {
            let p = self.next_port;
            self.next_port = if self.next_port == u16::MAX { EPHEMERAL_FIRST } else { self.next_port + 1 };
            let used = self.tcp.values().any(|c| c.local_port == p) || self.udp.values().any(|u| u.local_port == p);
            if !used {
                return p;
            }
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl TcpConn {
    fn window(&self) -> u16 {
        RECV_WINDOW.saturating_sub(self.recv_buf.len()).min(u16::MAX as usize) as u16
    }

    fn send_segment(&mut self, flags: u8, seq: u32, payload: &[u8]) {
        let mut buf = [0u8; 20 + MSS];
        let src = local_ip();
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
            send_ip(self.remote_ip, IpProtocol::Tcp, &buf[..n]);
        }
    }

    fn send_ack(&mut self) {
        let seq = self.snd_nxt;
        self.send_segment(TcpFlags::ACK, seq, &[]);
    }

    /// Sends as much buffered data as the peer's window allows, then a FIN if due.
    fn output(&mut self) {
        if matches!(self.state, TcpState::SynSent | TcpState::Closed | TcpState::TimeWait) {
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

    /// True while a retransmission timer runs (data or SYN awaiting acknowledgement).
    fn timer_armed(&self) -> bool {
        self.snd_una != self.snd_nxt || self.state == TcpState::SynSent
    }

    /// Retransmits when the timer expired. Returns true if the connection failed.
    fn timers(&mut self) -> bool {
        if !self.timer_armed() || now().saturating_sub(self.last_send) < self.rto {
            return false;
        }
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.error = Some(ETIMEDOUT);
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
/// The `netd` task runs; other code no longer polls the NIC itself.
static SERVICE_RUNNING: AtomicBool = AtomicBool::new(false);

/// Processes received frames and protocol timers, then wakes the sockets they affected.
/// Returns true if the receive ring may hold more frames.
pub fn poll() -> bool {
    if !e1000::is_present() {
        return false;
    }
    let mut frame = [0u8; 1518];
    let mut woken: Vec<Arc<WaitQueue>> = Vec::new();
    let mut more = true;
    for _ in 0..256 {
        let len = match e1000::receive_frame(&mut frame) {
            Some(l) => l,
            None => {
                more = false;
                break;
            }
        };
        if let Some(q) = handle_frame(&frame[..len]) {
            if !woken.iter().any(|w| Arc::ptr_eq(w, &q)) {
                woken.push(q);
            }
        }
    }
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

/// Lets a waiting socket operation make progress: polls the NIC unless `netd` does it.
pub fn kick() {
    if !SERVICE_RUNNING.load(Ordering::Acquire) {
        poll();
    }
}

/// True once `netd` processes the NIC (socket waits then sleep until woken).
pub fn service_running() -> bool {
    SERVICE_RUNNING.load(Ordering::Acquire)
}

/// True if some connection has a retransmission timer running.
fn timers_armed() -> bool {
    STACK.lock().tcp.values().any(|c| c.timer_armed())
}

/// Starts `netd` and switches the NIC to interrupt-driven receive.
pub fn start_service() {
    if !e1000::is_present() || SERVICE_RUNNING.load(Ordering::Acquire) {
        return;
    }
    crate::task::spawn("netd", netd_main, crate::task::TaskPriority::High);
    SERVICE_RUNNING.store(true, Ordering::Release);
    e1000::enable_interrupts();
}

/// The network task: processes received frames when the NIC interrupts, and runs TCP
/// timers while any are armed (every 50 ms; the shortest retransmission timeout is 300 ms).
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

/// The wait queue of a TCP connection or UDP socket.
pub fn wait_queue(id: u32) -> Option<Arc<WaitQueue>> {
    let stack = STACK.lock();
    stack.tcp.get(&id).map(|c| c.wq.clone()).or_else(|| stack.udp.get(&id).map(|u| u.wq.clone()))
}

/// Handles one frame; returns the wait queue of the socket it affected.
fn handle_frame(raw: &[u8]) -> Option<Arc<WaitQueue>> {
    let frame = match EthernetFrame::parse(raw) {
        Some(f) => f,
        None => return None,
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
            let ip = match Ipv4Packet::parse(frame.payload) {
                Some(p) => p,
                None => return None,
            };
            if ip.dst_ip != my_ip {
                return None;
            }
            match ip.protocol {
                IpProtocol::Tcp => {
                    if let Some(seg) = TcpPacket::parse(ip.payload) {
                        let mut stack = STACK.lock();
                        let conn = stack.tcp.values_mut().find(|c| {
                            c.local_port == seg.dst_port && c.remote_port == seg.src_port && c.remote_ip == ip.src_ip
                        });
                        match conn {
                            Some(c) => {
                                c.input(&seg);
                                return Some(c.wq.clone());
                            }
                            None => {
                                // No such connection: reset it (unless it is itself a reset)
                                if seg.flags & TcpFlags::RST == 0 {
                                    drop(stack);
                                    send_reset(ip.src_ip, &seg);
                                }
                            }
                        }
                    }
                }
                IpProtocol::Udp => {
                    let p = ip.payload;
                    if p.len() < 8 {
                        return None;
                    }
                    let src_port = u16::from_be_bytes([p[0], p[1]]);
                    let dst_port = u16::from_be_bytes([p[2], p[3]]);
                    let len = (u16::from_be_bytes([p[4], p[5]]) as usize).clamp(8, p.len());
                    let mut stack = STACK.lock();
                    if let Some(u) = stack.udp.values_mut().find(|u| u.local_port == dst_port) {
                        if u.queue.len() < 64 {
                            u.queue.push_back((ip.src_ip, src_port, p[8..len].to_vec()));
                        }
                        return Some(u.wq.clone());
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    None
}

fn send_reset(dst: [u8; 4], seg: &TcpPacket) {
    let mut buf = [0u8; 20];
    let (seq, ack, flags) = if seg.flags & TcpFlags::ACK != 0 {
        (seg.ack_num, 0, TcpFlags::RST)
    } else {
        let len = seg.payload.len() as u32 + (seg.flags & TcpFlags::SYN != 0) as u32 + (seg.flags & TcpFlags::FIN != 0) as u32;
        (0, seg.seq_num.wrapping_add(len), TcpFlags::RST | TcpFlags::ACK)
    };
    if let Ok(n) = TcpPacket::serialize(local_ip(), dst, seg.dst_port, seg.src_port, seq, ack, flags, 0, &[], &mut buf) {
        send_ip(dst, IpProtocol::Tcp, &buf[..n]);
    }
}

// ----------------------------------------------------------------------
// TCP API
// ----------------------------------------------------------------------

/// Starts connecting to `ip:port`; returns a connection handle (state `SynSent`).
pub fn tcp_connect(ip: [u8; 4], port: u16, local_port: Option<u16>) -> Result<u32, i64> {
    if !is_up() {
        return Err(ENETUNREACH);
    }
    let mut stack = STACK.lock();
    let lport = match local_port {
        Some(p) => p,
        None => stack.alloc_port(),
    };
    let id = stack.alloc_id();
    let iss = (now() as u32).wrapping_mul(2_654_435_761) ^ (lport as u32) << 16;
    let mut c = TcpConn {
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
    };
    c.send_segment(TcpFlags::SYN, iss, &[]);
    stack.tcp.insert(id, c);
    Ok(id)
}

pub fn tcp_state(id: u32) -> TcpState {
    STACK.lock().tcp.get(&id).map_or(TcpState::Closed, |c| c.state)
}

/// Takes the pending error of a connection (`SO_ERROR`).
pub fn tcp_take_error(id: u32) -> Option<i64> {
    STACK.lock().tcp.get_mut(&id).and_then(|c| c.error.take())
}

pub fn tcp_error(id: u32) -> Option<i64> {
    STACK.lock().tcp.get(&id).and_then(|c| c.error)
}

/// Queues data for sending; returns how much was accepted (0 if the buffer is full).
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

/// Reads received data. `Ok(0)` with `eof == true` means the peer closed.
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

/// Readiness of a connection: (readable, writable, hang-up, error).
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

/// Stops sending (`shutdown(SHUT_WR)`): a FIN follows the buffered data.
pub fn tcp_shutdown_write(id: u32) {
    if let Some(c) = STACK.lock().tcp.get_mut(&id) {
        c.write_closed = true;
        c.output();
    }
}

/// Closes the socket: finishes sending, then closes the connection in the background.
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

/// (local port, remote ip, remote port).
pub fn tcp_endpoints(id: u32) -> Option<(u16, [u8; 4], u16)> {
    STACK.lock().tcp.get(&id).map(|c| (c.local_port, c.remote_ip, c.remote_port))
}

// ----------------------------------------------------------------------
// UDP API
// ----------------------------------------------------------------------

/// Opens a UDP socket bound to `port` (0 = an ephemeral port).
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

pub fn udp_port(id: u32) -> u16 {
    STACK.lock().udp.get(&id).map_or(0, |u| u.local_port)
}

pub fn udp_send(id: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
    if !is_up() {
        return Err(ENETUNREACH);
    }
    let lport = udp_port(id);
    let mut buf = alloc::vec![0u8; 8 + data.len()];
    let n = super::udp::UdpPacket::serialize(lport, port, data, &mut buf).map_err(|_| -90i64)?; // EMSGSIZE
    send_ip(ip, IpProtocol::Udp, &buf[..n]);
    Ok(data.len())
}

/// Takes (or peeks at) the next datagram: (source ip, source port, payload).
pub fn udp_recv(id: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>)> {
    let mut stack = STACK.lock();
    let u = stack.udp.get_mut(&id)?;
    if peek {
        u.queue.front().cloned()
    } else {
        u.queue.pop_front()
    }
}

pub fn udp_readable(id: u32) -> bool {
    STACK.lock().udp.get(&id).map_or(false, |u| !u.queue.is_empty())
}

pub fn udp_close(id: u32) {
    STACK.lock().udp.remove(&id);
}
