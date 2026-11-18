//! # Hydra network server (net-server)
//!
//! The network protocols in Ring 3: Ethernet, ARP, IPv4, ICMP, UDP, TCP (with loopback),
//! the DHCP client and a DNS resolver. They were the kernel's `src/net`; the kernel's Linux
//! socket layer is now a client of this server (`src/net/client.rs` in the kernel).
//!
//! ## How it runs
//!
//! The supervisor starts it after the network driver (`nic=1` when there is a card) and
//! restarts it when it dies. It serves [`ENDPOINT_NET_SERVER`] (requests `MSG_NETS_*`,
//! documented in the kernel's `ipc/protocol.rs`) and talks to `e1000-driver` directly
//! ([`nic`]). One loop does everything, single-threaded:
//!
//! - **requests**: socket operations answer at once, never waiting for the network (the
//!   client blocks, if it wants to); DHCP renewals and DNS lookups answer later (their
//!   request IDs are kept, see [`State`]);
//! - **notifications**: the kernel forwards the network driver's interrupt here; the loop
//!   then takes the received frames from the driver and runs them through the stack;
//! - **timers**: a timeout on the wait runs TCP retransmissions, DHCP and DNS retries and a
//!   link check;
//! - **publishing**: after each of these, every socket's readiness is compared with what
//!   the status area shows; changes are written there, their handles appended to the
//!   event ring and the client's doorbell rung (`SYS_SVC_SIGNAL`).
//!
//! Frames to send are batched ([`nic::flush`] before every reply and after every round).

#![no_std]
#![no_main]

extern crate alloc;

mod iface;
mod net;
mod nic;
mod stack;

use alloc::vec::Vec;
use spin::Mutex;

use hydra_rt::protocol::*;
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

use crate::iface::GLOBAL_INTERFACE;
use crate::net::dhcp::{DhcpClient, DhcpState};
use crate::net::dns::{Lookup, LookupTimer};

hydra_rt::entry!(main);

const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ENETUNREACH: i64 = -101;
const ENOTCONN: i64 = -107;
const ETIMEDOUT: i64 = -110;

/// Ticks between timer rounds while something is timed (TCP retransmission, DHCP, DNS).
const TIMER_TICKS: u64 = 5;
/// Ticks between link checks and polls of an idle card (also the fallback when its
/// interrupt does not work).
const IDLE_TICKS: u64 = 50;
/// Ticks between DHCP attempts while the interface has no address.
const DHCP_RETRY_TICKS: u64 = 3000;

/// The DHCP client (frames reach it from the stack, [`dhcp_input`]).
static DHCP: Mutex<DhcpClient> = Mutex::new(DhcpClient::new());
/// The DHCP server of the lease.
static DHCP_SERVER: Mutex<[u8; 4]> = Mutex::new([0; 4]);

/// A DNS lookup waiting for its answer.
struct PendingLookup {
    /// Request to answer.
    req: u64,
    /// UDP socket the query went out on.
    sock: u32,
    lookup: Lookup,
}

/// The loop's state.
struct State {
    /// The service window (data area, then the status area).
    window: *mut u8,
    /// Readiness words as published, by slot.
    published: Vec<u64>,
    /// Slots with a published word.
    published_slots: Vec<usize>,
    /// Events written so far.
    event_head: u64,
    /// Requests waiting for DHCP to finish.
    dhcp_waiters: Vec<u64>,
    /// Next automatic DHCP attempt while unconfigured.
    next_dhcp: u64,
    /// DNS lookups in flight.
    lookups: Vec<PendingLookup>,
    /// Next DNS transaction ID.
    next_tx: u16,
    /// Next timer round.
    next_timer: u64,
    /// Next link check.
    next_link: u64,
    /// Carrier link seen at the last check.
    link: bool,
    /// Next poll of the card without an interrupt.
    next_poll: u64,
}

/// Kinds of handle, for [`OWNERS`].
const H_TCP: u8 = 0;
const H_BIND: u8 = 1;
const H_LISTEN: u8 = 2;
const H_UDP: u8 = 3;
const H_ICMP: u8 = 4;

/// Wave 5: who made each handle a client holds (`(client tag, kind)`), so that
/// [`MSG_NETS_CLIENT_RESET`] can close a restarted client's leftovers. The kernel's
/// (tag 0) are recorded too; handles net-server uses itself (DNS) are not.
static OWNERS: Mutex<alloc::collections::BTreeMap<u32, (u8, u8)>> = Mutex::new(alloc::collections::BTreeMap::new());

fn own(h: u32, tag: u64, kind: u8) {
    OWNERS.lock().insert(h, (tag as u8, kind));
}

fn disown(h: u32) {
    OWNERS.lock().remove(&h);
}

fn tag_of(h: u32) -> u64 {
    OWNERS.lock().get(&h).map_or(0, |o| o.0 as u64)
}

/// [`MSG_NETS_CLIENT_RESET`]: closes every handle of client `tag`; how many.
fn client_reset(tag: u64) -> i64 {
    let handles: Vec<(u32, u8)> = OWNERS.lock().iter().filter(|(_, o)| o.0 as u64 == tag).map(|(h, o)| (*h, o.1)).collect();
    for &(h, kind) in &handles {
        match kind {
            H_TCP => stack::tcp_close(h),
            H_BIND => stack::tcp_unbind(h),
            H_LISTEN => stack::tcp_unlisten(h),
            H_UDP => stack::udp_close(h),
            _ => stack::icmp_close(h),
        }
        disown(h);
    }
    handles.len() as i64
}

/// Interface changes (leases), for `NETS_ST_IFACE_SEQ`.
static IFACE_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl State {
    /// The window as bytes.
    fn window(&self) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.window, WINDOW_SIZE) }
    }

    /// `len` bytes of the data area at `off`, if they fit.
    fn data(&self, off: u64, len: u64) -> Option<&'static mut [u8]> {
        let (off, len) = (off as usize, len as usize);
        (off.checked_add(len)? <= NETS_DATA_LEN).then(|| &mut self.window()[off..off + len])
    }

    /// Writes status word `i`.
    fn status(&self, i: usize, v: u64) {
        unsafe { core::ptr::write_volatile((self.window.add(NETS_STATUS_OFF) as *mut u64).add(i), v) };
    }

    /// Writes the readiness word of `slot`.
    fn sock_word(&self, slot: usize, v: u64) {
        unsafe { core::ptr::write_volatile((self.window.add(NETS_SOCKS_OFF) as *mut u64).add(slot), v) };
    }

    /// Appends `id` to the event ring (the head is published by [`publish`]).
    fn event(&mut self, id: u32) {
        let at = (self.event_head as usize) % NETS_EVENTS;
        unsafe { core::ptr::write_volatile((self.window.add(NETS_EVENTS_OFF) as *mut u32).add(at), id) };
        self.event_head += 1;
    }
}

/// An address as the protocol carries it.
fn addr(ip: [u8; 4]) -> u64 {
    u32::from_le_bytes(ip) as u64
}

/// The address in a protocol word.
fn ip_of(w: u64) -> [u8; 4] {
    (w as u32).to_le_bytes()
}

/// A reply.
fn reply(args: [u64; 4]) -> Message {
    Message::new(MSG_NETS_REPLY as u64, args)
}

/// A reply with only a result (a value, or a negative errno).
fn result(r: i64) -> Message {
    reply([r as u64, 0, 0, 0])
}

/// Sends a DHCP message: UDP 68 -> 67, from 0.0.0.0 to the broadcast address.
fn dhcp_send(payload: &[u8]) {
    use crate::net::ethernet::{EtherType, EthernetFrame};
    use crate::net::ipv4::{IpProtocol, Ipv4Packet};
    use crate::net::udp::UdpPacket;
    if payload.is_empty() {
        return;
    }
    let mac = nic::mac_address();
    let mut udp = [0u8; 600];
    let mut ip = [0u8; 650];
    let mut eth = [0u8; 700];
    let Ok(u) = UdpPacket::serialize(net::dhcp::DHCP_CLIENT_PORT, net::dhcp::DHCP_SERVER_PORT, payload, &mut udp) else { return };
    let Ok(i) = Ipv4Packet::serialize([0; 4], [255; 4], IpProtocol::Udp, &udp[..u], &mut ip) else { return };
    let Ok(e) = EthernetFrame::serialize(EthernetFrame::BROADCAST_MAC, mac, EtherType::Ipv4, &ip[..i], &mut eth) else { return };
    let _ = nic::send_frame(&eth[..e]);
}

/// A DHCP message arrived (UDP port 68): the client takes it; a lease configures the
/// interface.
pub fn dhcp_input(payload: &[u8]) {
    let mut dhcp = DHCP.lock();
    let was = dhcp.state;
    let out = dhcp.input(payload, sys::uptime_ticks());
    let now = dhcp.state;
    drop(dhcp);
    if let Some(req) = out {
        dhcp_send(&req);
    }
    if let (false, DhcpState::Bound(lease)) = (matches!(was, DhcpState::Bound(_)), now) {
        let mut iface = GLOBAL_INTERFACE.lock();
        iface.set_ip(lease.ip);
        iface.set_subnet_mask(lease.subnet_mask);
        iface.set_gateway(lease.router);
        iface.set_dns_server(lease.dns_server);
        *DHCP_SERVER.lock() = lease.server_ip;
        IFACE_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        println!(
            "[net-server] DHCP lease {}.{}.{}.{} (gateway {}.{}.{}.{}, DNS {}.{}.{}.{})",
            lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3],
            lease.router[0], lease.router[1], lease.router[2], lease.router[3],
            lease.dns_server[0], lease.dns_server[1], lease.dns_server[2], lease.dns_server[3]
        );
    }
}

/// Starts a DHCP exchange.
fn dhcp_start() {
    let mac = nic::mac_address();
    let xid = (sys::uptime_ticks() as u32).wrapping_mul(2_654_435_761) ^ u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let msg = DHCP.lock().start(mac, xid, sys::uptime_ticks());
    dhcp_send(&msg);
    nic::flush();
}

/// Handles request `id`; `None` when the answer comes later (DHCP, DNS).
fn handle(st: &mut State, id: u64, m: &Message) -> Option<Message> {
    let a = m.args;
    let h = a[0] as u32;
    let r = match m.label as u32 {
        MSG_NETS_TCP_CONNECT => match stack::tcp_connect(ip_of(a[0]), a[1] as u16, (a[2] != 0).then_some(a[2] as u16)) {
            Ok(c) => {
                own(c, a[3], H_TCP);
                result(c as i64)
            }
            Err(e) => result(e),
        },
        MSG_NETS_TCP_SEND => match st.data(a[1], a[2]) {
            Some(d) => result(stack::tcp_send(h, d).map_or_else(|e| e, |n| n as i64)),
            None => result(EINVAL),
        },
        MSG_NETS_TCP_RECV => match st.data(a[1], a[2]) {
            Some(d) => match stack::tcp_recv(h, d, a[3] != 0) {
                Ok((n, eof)) => reply([n as u64, eof as u64, 0, 0]),
                Err(e) => result(e),
            },
            None => result(EINVAL),
        },
        MSG_NETS_TCP_SHUTDOWN => {
            stack::tcp_shutdown_write(h);
            result(0)
        }
        MSG_NETS_TCP_CLOSE => {
            stack::tcp_close(h);
            disown(h);
            result(0)
        }
        MSG_NETS_TCP_TAKE_ERROR => result(stack::tcp_take_error(h).map_or(0, |e| -e)),
        MSG_NETS_TCP_INFO => match stack::tcp_endpoints(h) {
            Some((lport, rip, rport)) => {
                let lip = stack::tcp_local_ip(h).unwrap_or([0; 4]);
                reply([0, addr(lip) << 16 | lport as u64, addr(rip) << 16 | rport as u64, stack::state_number(stack::tcp_state(h))])
            }
            None => result(ENOTCONN),
        },
        MSG_NETS_TCP_BIND => {
            let f = a[2];
            match stack::tcp_bind(ip_of(a[0]), a[1] as u16, f & 1 != 0, f & 2 != 0, f & 4 != 0, f & 8 != 0) {
                Ok((b, port)) => {
                    own(b, a[3], H_BIND);
                    reply([b as u64, port as u64, 0, 0])
                }
                Err(e) => result(e),
            }
        }
        MSG_NETS_TCP_UNBIND => {
            stack::tcp_unbind(h);
            disown(h);
            result(0)
        }
        MSG_NETS_TCP_LISTEN => result(stack::tcp_listen(h, a[1] as usize).map_or_else(
            |e| e,
            |l| {
                own(l, tag_of(h), H_LISTEN);
                l as i64
            },
        )),
        MSG_NETS_TCP_BACKLOG => {
            stack::tcp_set_backlog(h, a[1] as usize);
            result(0)
        }
        MSG_NETS_TCP_ACCEPT => match stack::tcp_accept(h) {
            Some(c) => {
                own(c, tag_of(h), H_TCP);
                result(c as i64)
            }
            None if stack::listener_exists(h) => result(EAGAIN),
            None => result(EBADF),
        },
        MSG_NETS_TCP_UNLISTEN => {
            stack::tcp_unlisten(h);
            disown(h);
            result(0)
        }
        MSG_NETS_UDP_OPEN => result(stack::udp_open(a[0] as u16).map_or_else(
            |e| e,
            |u| {
                own(u, a[3], H_UDP);
                u as i64
            },
        )),
        MSG_NETS_UDP_REBIND => result(stack::udp_rebind(h, a[1] as u16).map_or_else(|e| e, |()| 0)),
        MSG_NETS_UDP_PORT => result(stack::udp_port(h) as i64),
        MSG_NETS_UDP_SEND => match st.data(a[2], a[3]) {
            Some(d) if stack::udp_exists(h) => result(stack::udp_send(h, ip_of(a[1] >> 16), a[1] as u16, d).map_or_else(|e| e, |n| n as i64)),
            Some(_) => result(EBADF),
            None => result(EINVAL),
        },
        MSG_NETS_UDP_RECV => match stack::udp_recv(h, a[2] != 0) {
            Some((ip, port, data, stamp)) => {
                // At most `capacity` bytes (wave 5: a client's part of the data area)
                let n = if a[3] != 0 { data.len().min(a[3] as usize) } else { data.len() };
                match st.data(a[1], n as u64) {
                    Some(d) => {
                        d.copy_from_slice(&data[..n]);
                        reply([data.len() as u64, addr(ip) << 16 | port as u64, stamp, n as u64])
                    }
                    None => result(EINVAL),
                }
            }
            None if stack::udp_exists(h) => result(EAGAIN),
            None => result(EBADF),
        },
        MSG_NETS_UDP_CLOSE => {
            stack::udp_close(h);
            disown(h);
            result(0)
        }
        MSG_NETS_ICMP_OPEN => {
            let i = stack::icmp_open(a[0] != 0, a[1] != 0);
            own(i, a[3], H_ICMP);
            result(i as i64)
        }
        MSG_NETS_ICMP_IDENT => result(stack::icmp_ident(h) as i64),
        MSG_NETS_ICMP_SET_IDENT => result(stack::icmp_set_ident(h, a[1] as u16).map_or_else(|e| e, |()| 0)),
        MSG_NETS_ICMP_SEND => match st.data(a[2], a[3]) {
            Some(d) => result(stack::icmp_send(h, ip_of(a[1]), d).map_or_else(|e| e, |n| n as i64)),
            None => result(EINVAL),
        },
        MSG_NETS_ICMP_RECV => match stack::icmp_recv(h, a[2] != 0) {
            Some((ip, data, stamp)) => {
                let n = if a[3] != 0 { data.len().min(a[3] as usize) } else { data.len() };
                match st.data(a[1], n as u64) {
                    Some(d) => {
                        d.copy_from_slice(&data[..n]);
                        reply([data.len() as u64, addr(ip), stamp, n as u64])
                    }
                    None => result(EINVAL),
                }
            }
            None if stack::icmp_exists(h) => result(EAGAIN),
            None => result(EBADF),
        },
        MSG_NETS_ICMP_CLOSE => {
            stack::icmp_close(h);
            disown(h);
            result(0)
        }
        MSG_NETS_CLIENT_RESET => result(client_reset(a[0])),
        MSG_NETS_LIST => result(list(st, a[0], a[1], a[2])),
        MSG_NETS_DHCP => {
            if !nic::is_present() {
                return Some(result(ENODEV));
            }
            if !DHCP.lock().busy() {
                dhcp_start();
            }
            st.dhcp_waiters.push(id);
            return None;
        }
        MSG_NETS_RESOLVE => {
            let Some(name) = st.data(a[0], a[1]).and_then(|d| core::str::from_utf8(d).ok()) else { return Some(result(EINVAL)) };
            if !stack::is_up() {
                return Some(result(ENETUNREACH));
            }
            let dns = GLOBAL_INTERFACE.lock().dns_server();
            st.next_tx = st.next_tx.wrapping_add(0x3D11);
            let lookup = match Lookup::new(name, st.next_tx, dns, sys::uptime_ticks()) {
                Ok(l) => l,
                Err(_) => return Some(result(EINVAL)),
            };
            let sock = match stack::udp_open(0) {
                Ok(s) => s,
                Err(e) => return Some(result(e)),
            };
            if let Err(e) = stack::udp_send(sock, lookup.server, net::dns::DNS_PORT, &lookup.query) {
                stack::udp_close(sock);
                return Some(result(e));
            }
            st.lookups.push(PendingLookup { req: id, sock, lookup });
            return None;
        }
        _ => result(ENOSYS),
    };
    Some(r)
}

/// `MSG_NETS_LIST`: writes up to `cap` records of table `kind` at `off`; returns how many.
fn list(st: &State, kind: u64, off: u64, cap: u64) -> i64 {
    let mut recs: Vec<[u64; 6]> = Vec::new();
    match kind {
        0 => {
            for c in stack::tcp_list() {
                recs.push([c.id as u64, addr(c.local.0) << 16 | c.local.1 as u64, addr(c.remote.0) << 16 | c.remote.1 as u64, stack::state_number(c.state), c.tx as u64, c.rx as u64]);
            }
        }
        1 => {
            for (id, ip, port, waiting, backlog) in stack::listener_list() {
                recs.push([id as u64, addr(ip) << 16 | port as u64, waiting as u64, backlog as u64, 0, 0]);
            }
        }
        2 => {
            for (id, port, queued) in stack::udp_list() {
                recs.push([id as u64, port as u64, queued as u64, 0, 0, 0]);
            }
        }
        3 => {
            for (ip, mac) in crate::net::arp::ARP_TABLE.lock().entries() {
                let mut m = [0u8; 8];
                m[..6].copy_from_slice(&mac);
                recs.push([addr(ip), u64::from_le_bytes(m), 0, 0, 0, 0]);
            }
        }
        _ => return EINVAL,
    }
    let n = recs.len().min(cap as usize);
    let Some(d) = st.data(off, (n * NETS_LIST_RECORD) as u64) else { return EINVAL };
    d.fill(0);
    for (i, r) in recs.iter().take(n).enumerate() {
        for (j, w) in r.iter().enumerate() {
            let at = i * NETS_LIST_RECORD + j * 8;
            d[at..at + 8].copy_from_slice(&w.to_le_bytes());
        }
    }
    n as i64
}

/// Publishes readiness changes, the interface and counters; rings the doorbell if any
/// socket changed.
fn publish(st: &mut State) {
    let words = stack::readiness();
    let mut live = alloc::vec![false; NETS_SLOTS];
    let before = st.event_head;
    let mut slots = Vec::with_capacity(words.len());
    for (id, w) in words {
        let slot = stack::slot_of(id);
        live[slot] = true;
        slots.push(slot);
        if st.published[slot] != w {
            st.sock_word(slot, w);
            st.published[slot] = w;
            st.event(id);
        }
    }
    for &slot in &core::mem::take(&mut st.published_slots) {
        if !live[slot] && st.published[slot] != 0 {
            let old = st.published[slot] as u32;
            st.sock_word(slot, 0);
            st.published[slot] = 0;
            st.event(old);
        }
    }
    st.published_slots = slots;
    // The interface
    let (ip, mask, gw, dns) = {
        let i = GLOBAL_INTERFACE.lock();
        (i.ip(), i.subnet_mask(), i.gateway(), i.dns_server())
    };
    let busy = DHCP.lock().busy();
    let flags = if nic::is_present() { NETS_F_NIC } else { 0 }
        | if st.link { NETS_F_LINK } else { 0 }
        | if ip != [0; 4] { NETS_F_CONFIGURED } else { 0 }
        | if busy { NETS_F_DHCP_BUSY } else { 0 };
    st.status(NETS_ST_IP, addr(ip));
    st.status(NETS_ST_MASK, addr(mask));
    st.status(NETS_ST_GATEWAY, addr(gw));
    st.status(NETS_ST_DNS, addr(dns));
    st.status(NETS_ST_DHCP_SERVER, addr(*DHCP_SERVER.lock()));
    st.status(NETS_ST_FLAGS, flags);
    use core::sync::atomic::Ordering::Relaxed;
    st.status(NETS_ST_ETH_COUNTERS, nic::PACKETS_RX.load(Relaxed));
    st.status(NETS_ST_ETH_COUNTERS + 1, nic::BYTES_RX.load(Relaxed));
    st.status(NETS_ST_ETH_COUNTERS + 2, nic::PACKETS_TX.load(Relaxed));
    st.status(NETS_ST_ETH_COUNTERS + 3, nic::BYTES_TX.load(Relaxed));
    let (lo_bytes, lo_packets) = stack::lo_counters();
    st.status(NETS_ST_LO_COUNTERS, lo_bytes);
    st.status(NETS_ST_LO_COUNTERS + 1, lo_packets);
    st.status(NETS_ST_RX_CALLS, nic::RECV_CALLS.load(Relaxed));
    st.status(NETS_ST_RX_CALLS + 1, nic::RECV_FRAMES.load(Relaxed));
    st.status(NETS_ST_IFACE_SEQ, IFACE_SEQ.load(Relaxed));
    if st.event_head != before {
        // The ring entries are written; now the head, then the doorbell
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        st.status(NETS_ST_EVENT_HEAD, st.event_head);
        sys::svc_signal(ENDPOINT_NET_SERVER, 0);
    }
}

/// Work besides requests: received frames (after an interrupt or on `poll_nic`), loopback,
/// timers, DHCP and DNS progress.
fn background(st: &mut State, poll_nic: bool) {
    let now = sys::uptime_ticks();
    if poll_nic && nic::is_present() {
        // Until the driver has nothing more (each round is one request to it)
        for _ in 0..32 {
            if stack::poll_nic() == 0 {
                break;
            }
            nic::flush();
        }
    }
    for _ in 0..16 {
        if !stack::poll_loopback() {
            break;
        }
    }
    if now >= st.next_timer {
        st.next_timer = now + TIMER_TICKS;
        stack::run_timers();
        if let Some(msg) = DHCP.lock().timer(now) {
            dhcp_send(&msg);
        }
        let mut i = 0;
        while i < st.lookups.len() {
            let l = &mut st.lookups[i];
            match l.lookup.timer(now) {
                LookupTimer::Wait => i += 1,
                LookupTimer::Resend => {
                    let _ = stack::udp_send(l.sock, l.lookup.server, net::dns::DNS_PORT, &l.lookup.query);
                    i += 1;
                }
                LookupTimer::Failed => {
                    let l = st.lookups.remove(i);
                    stack::udp_close(l.sock);
                    let _ = sys::svc_reply(ENDPOINT_NET_SERVER, l.req, &result(ETIMEDOUT));
                }
            }
        }
    }
    if now >= st.next_link && nic::is_present() {
        st.next_link = now + IDLE_TICKS;
        st.link = nic::is_link_up();
        // No address: try DHCP again now and then
        if GLOBAL_INTERFACE.lock().ip() == [0; 4] && !DHCP.lock().busy() && now >= st.next_dhcp && st.link {
            st.next_dhcp = now + DHCP_RETRY_TICKS;
            dhcp_start();
        }
    }
    // DNS answers
    let mut i = 0;
    while i < st.lookups.len() {
        let mut done = None;
        while let Some((src, _, data, _)) = stack::udp_recv(st.lookups[i].sock, false) {
            if let Some(r) = st.lookups[i].lookup.answer(src, &data) {
                done = Some(r);
                break;
            }
        }
        match done {
            Some(r) => {
                let l = st.lookups.remove(i);
                stack::udp_close(l.sock);
                let msg = match r {
                    Ok(ip) => reply([0, addr(ip), 0, 0]),
                    Err(_) => result(-2), // ENOENT: no such name
                };
                let _ = sys::svc_reply(ENDPOINT_NET_SERVER, l.req, &msg);
            }
            None => i += 1,
        }
    }
    // DHCP finished: its waiters
    let state = DHCP.lock().state;
    if !matches!(state, DhcpState::Selecting | DhcpState::Requesting) {
        for w in core::mem::take(&mut st.dhcp_waiters) {
            let msg = match state {
                DhcpState::Bound(l) => reply([0, addr(l.ip), 0, 0]),
                _ => result(ETIMEDOUT),
            };
            let _ = sys::svc_reply(ENDPOINT_NET_SERVER, w, &msg);
        }
    }
    nic::flush();
}

/// How long the loop may wait for a request or notification (ticks; 0: forever).
fn wait_ticks(st: &State) -> u64 {
    if stack::loopback_pending() {
        return 1;
    }
    if stack::timers_armed() || DHCP.lock().busy() || !st.lookups.is_empty() {
        return TIMER_TICKS;
    }
    if nic::is_present() {
        return IDLE_TICKS;
    }
    0
}

/// Server entry point: brings up the card (if any), registers, then serves forever.
fn main(args: &[&str]) {
    stack::seed_generations(sys::uptime_ticks() as u32);
    if args.iter().any(|a| *a == "nic=1") {
        match nic::init() {
            Ok(()) => GLOBAL_INTERFACE.lock().set_mac(nic::mac_address()),
            Err(e) => println!("[net-server] network card unavailable: {}", e),
        }
    }
    let mut server = match Server::register(ENDPOINT_NET_SERVER) {
        Ok(s) => s,
        Err(e) => {
            println!("[net-server] cannot register on endpoint {:#x}: error {}", ENDPOINT_NET_SERVER, e);
            return;
        }
    };
    let window = server.window().as_mut_ptr();
    let mut st = State {
        window,
        published: alloc::vec![0; NETS_SLOTS],
        published_slots: Vec::new(),
        event_head: 0,
        dhcp_waiters: Vec::new(),
        next_dhcp: 0,
        lookups: Vec::new(),
        next_tx: sys::uptime_ticks() as u16,
        next_timer: 0,
        next_link: 0,
        link: false,
        next_poll: 0,
    };
    // The status area of a previous instance (the window outlives it) is cleared first
    st.window()[NETS_STATUS_OFF..].fill(0);
    let m = nic::mac_address();
    st.status(NETS_ST_MAC, u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], 0, 0]));
    if nic::is_present() {
        st.link = nic::is_link_up();
        st.next_dhcp = sys::uptime_ticks() + DHCP_RETRY_TICKS;
        dhcp_start();
    }
    publish(&mut st);
    // Last: clients trust the area from now on
    st.status(NETS_ST_MAGIC, NETS_MAGIC);
    println!(
        "[net-server] serving endpoint {:#x}: {}",
        ENDPOINT_NET_SERVER,
        if nic::is_present() { "network card and loopback" } else { "loopback only (no network card)" }
    );
    loop {
        let poll_nic = match sys::svc_recv_notify(ENDPOINT_NET_SERVER, wait_ticks(&st)) {
            // The card's interrupt, or the timeout (then the card is polled only now and
            // then: its interrupt may not work)
            Ok((0, m)) => {
                let now = sys::uptime_ticks();
                let due = now >= st.next_poll;
                if m.args[0] & NOTIFY_IRQ != 0 || due {
                    st.next_poll = now + IDLE_TICKS;
                    true
                } else {
                    false
                }
            }
            Ok((id, m)) => {
                if m.label == MSG_SUPERVISOR_PING as u64 {
                    let _ = sys::svc_reply(ENDPOINT_NET_SERVER, id, &Message::new(MSG_SUPERVISOR_PONG as u64, [m.args[0], 1, 0, 0]));
                    continue;
                }
                if let Some(r) = handle(&mut st, id, &m) {
                    // Frames it caused go out, and its readiness is visible, before the answer
                    nic::flush();
                    publish(&mut st);
                    let _ = sys::svc_reply(ENDPOINT_NET_SERVER, id, &r);
                }
                false
            }
            Err(_) => continue,
        };
        background(&mut st, poll_nic);
        publish(&mut st);
    }
}
