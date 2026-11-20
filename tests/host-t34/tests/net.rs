//! `src/net/*`: the kernel's client of net-server (handles, readiness words, the event ring,
//! every request), the boot report, ping and HTTP GET on its sockets, and the e1000 lookup.

mod common;
use common::*;
use k::ipc::protocol::*;
use k::net::client::{self as cl, TcpState};
use std::cell::RefCell;
use std::rc::Rc;

/// Answers net-server requests with `f(label, args, window)`; records them.
fn script(f: impl FnMut(u32, [u64; 4], &mut [u8]) -> Result<[u64; 4], i64> + 'static) -> Rc<RefCell<Vec<(u32, [u64; 4], String)>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let s2 = seen.clone();
    let f = RefCell::new(f);
    fake::with(|s| {
        s.handler = Some(Box::new(move |ep, m, kind| {
            assert_eq!(ep, ENDPOINT_NET_SERVER);
            s2.borrow_mut().push((m.label, m.args, kind.to_string()));
            let w = k::ipc::service::window(ep).expect("window");
            (f.borrow_mut())(m.label, m.args, w).map(|a| k::ipc::Message::with_args(MSG_NETS_REPLY, a))
        }))
    });
    seen
}

/// A connection made with server handle `sid`.
fn connect(sid: u32) -> u32 {
    script(move |_, _, _| Ok([sid as u64, 0, 0, 0]));
    cl::tcp_connect([10, 0, 0, 1], 80, None).unwrap()
}

#[test]
fn ipv6_stand_ins() {
    assert!(cl::is_v6(cl::V6_LOOPBACK));
    assert!(cl::is_v6(cl::V6_LINKLOCAL));
    assert!(!cl::is_v6([0, 0, 0, 3]));
    assert!(!cl::is_v6([127, 0, 0, 1]));
}

#[test]
fn the_interface_from_the_status_area() {
    let _g = setup();
    // No server, a server without its magic, a server that went offline
    assert!(!cl::iface().running);
    fake::with(|s| {
        s.servers.insert(ENDPOINT_NET_SERVER, 5);
    });
    assert!(!cl::iface().running);
    net_server(5);
    fake::with(|s| s.online.clear());
    assert!(!cl::iface().running);
    assert!(!cl::service_running());
    net_server(5);
    assert!(cl::service_running());
    let i = cl::iface();
    assert!(i.running && !i.present && !i.link && !i.dhcp_busy);
    iface_up([10, 0, 2, 15], [8, 8, 8, 8]);
    status(NETS_ST_FLAGS, NETS_F_NIC | NETS_F_LINK | NETS_F_DHCP_BUSY);
    for j in 0..4 {
        status(NETS_ST_ETH_COUNTERS + j, 100 + j as u64);
    }
    status(NETS_ST_LO_COUNTERS, 7);
    status(NETS_ST_LO_COUNTERS + 1, 8);
    status(NETS_ST_RX_CALLS + 1, 9);
    let i = cl::iface();
    assert!(i.present && i.link && i.dhcp_busy);
    assert_eq!(i.mac, [0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    assert_eq!((i.ip, i.mask, i.gateway, i.dns, i.dhcp_server), ([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2], [8, 8, 8, 8], [10, 0, 2, 2]));
    assert_eq!((i.eth, i.lo, i.rx_calls), ([100, 101, 102, 103], [7, 8], [0, 9]));
    // /proc/net/dev's numbers: lo as both directions, then the card's (bytes, packets)
    assert_eq!(cl::counters(), [((7, 8), (7, 8)), ((101, 100), (103, 102))]);
    // fe80:: + modified EUI-64
    assert_eq!(cl::link_local6().unwrap(), [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56]);
    status(NETS_ST_FLAGS, 0);
    assert!(cl::link_local6().is_none());
}

#[test]
fn local_addresses() {
    let _g = setup();
    assert!(cl::is_local([127, 1, 2, 3]));
    assert!(cl::is_local(cl::V6_LOOPBACK));
    assert!(!cl::is_local(cl::V6_LINKLOCAL), "no card: no link-local address");
    assert!(!cl::is_local([0, 0, 0, 0]));
    net_server(5);
    iface_up([10, 0, 2, 15], [0; 4]);
    assert!(cl::is_local(cl::V6_LINKLOCAL));
    assert!(cl::is_local([10, 0, 2, 15]));
    assert!(!cl::is_local([10, 0, 2, 16]));
    // Unconfigured: 0.0.0.0 is not ours
    status(NETS_ST_IP, 0);
    assert!(!cl::is_local([0, 0, 0, 0]));
}

#[test]
fn readiness_words_and_states() {
    let _g = setup();
    net_server(5);
    let id = connect(9);
    // Not published yet: closed, readable/hang-up (a read then reports the state)
    assert_eq!(cl::tcp_state(id), TcpState::Closed);
    assert_eq!(cl::tcp_poll(id), (true, false, true, false));
    for (n, st) in [
        (NETS_TCP_SYN_SENT, TcpState::SynSent),
        (NETS_TCP_SYN_RECEIVED, TcpState::SynReceived),
        (NETS_TCP_ESTABLISHED, TcpState::Established),
        (NETS_TCP_FIN_WAIT1, TcpState::FinWait1),
        (NETS_TCP_FIN_WAIT2, TcpState::FinWait2),
        (NETS_TCP_CLOSE_WAIT, TcpState::CloseWait),
        (NETS_TCP_LAST_ACK, TcpState::LastAck),
        (NETS_TCP_CLOSING, TcpState::Closing),
        (NETS_TCP_TIME_WAIT, TcpState::TimeWait),
        (NETS_TCP_CLOSED, TcpState::Closed),
        (77, TcpState::Closed),
    ] {
        sock_word(9, 0, n, 0);
        assert_eq!(cl::tcp_state(id), st);
    }
    sock_word(9, NETS_R_IN | NETS_R_ERR, NETS_TCP_ESTABLISHED, 0);
    assert_eq!(cl::tcp_poll(id), (true, false, false, true));
    sock_word(9, NETS_R_OUT | NETS_R_HUP, NETS_TCP_ESTABLISHED, 0);
    assert_eq!(cl::tcp_poll(id), (false, true, true, false));
    // The whole word for linux-server; a slot holding another handle's word reads 0
    assert_eq!(cl::raw_word(9) as u32, 9);
    assert_eq!(cl::raw_word(9 + NETS_SLOTS as u32), 0);
    fake::with(|s| s.servers.clear());
    assert_eq!(cl::raw_word(9), 0);
    assert_eq!(cl::tcp_state(id), TcpState::Closed);
}

#[test]
fn sockets_die_with_their_server() {
    let _g = setup();
    net_server(5);
    let id = connect(3);
    assert!(!cl::dead(id));
    assert!(cl::wait_queue(id).is_some());
    // A restarted server (another process): the handle is dead, its errors say so
    net_server(6);
    assert!(cl::dead(id));
    let mut buf = [0u8; 4];
    assert_eq!(cl::tcp_send(id, b"x"), Err(cl::ECONNRESET));
    assert_eq!(cl::tcp_recv(id, &mut buf, false), Err(cl::ECONNRESET));
    assert_eq!(cl::tcp_take_error(id), Some(cl::ECONNRESET));
    assert_eq!(cl::tcp_poll(id), (true, false, true, true));
    assert!(cl::tcp_endpoints(id).is_none());
    // No request reaches the new server for it
    let seen = script(|_, _, _| Ok([0; 4]));
    cl::tcp_shutdown_write(id);
    assert!(seen.borrow().is_empty());
    // Closing forgets it: unknown handles have no pending error
    cl::tcp_close(id);
    assert!(cl::wait_queue(id).is_none());
    assert_eq!(cl::tcp_take_error(id), None);
    // No server at all
    fake::with(|s| s.servers.clear());
    assert!(cl::dead(1));
}

#[test]
fn requests_and_their_errors() {
    let _g = setup();
    net_server(5);
    // No answer at all: the network is down
    fake::with(|s| s.handler = None);
    assert_eq!(cl::tcp_connect([1, 2, 3, 4], 80, Some(5000)), Err(cl::ENETDOWN));
    assert_eq!(cl::udp_open(53), Err(cl::ENETDOWN));
    assert_eq!(cl::icmp_open(false, false), 0);
    // A negative answer is the errno
    let seen = script(|_, _, _| Ok([-98i64 as u64, 0, 0, 0]));
    assert_eq!(cl::tcp_bind([0; 4], 80, true, false, true, false), Err(-98));
    assert_eq!(seen.borrow()[0].1, [0, 80, 0b0101, 0]);
    // Addresses travel as little-endian words
    let seen = script(|_, _, _| Ok([4, 0, 0, 0]));
    cl::tcp_connect([10, 0, 2, 2], 8080, Some(4000)).unwrap();
    assert_eq!(seen.borrow()[0].1, [u32::from_le_bytes([10, 0, 2, 2]) as u64, 8080, 4000, 0]);
    assert_eq!(seen.borrow()[0].2, "call");
}

#[test]
fn tcp_connection_lifecycle() {
    let _g = setup();
    net_server(5);
    let id = connect(12);
    sock_word(12, NETS_R_OUT, NETS_TCP_ESTABLISHED, 0);
    // Send: through the window, at most one chunk, on the socket's own handle
    let sent = Rc::new(RefCell::new(Vec::new()));
    let s2 = sent.clone();
    let seen = script(move |label, a, w| match label {
        MSG_NETS_TCP_SEND => {
            s2.borrow_mut().extend_from_slice(&w[..a[2] as usize]);
            Ok([a[2], 0, 0, 0])
        }
        MSG_NETS_TCP_RECV => {
            w[..5].copy_from_slice(b"hello");
            Ok([5, 1, 0, 0])
        }
        MSG_NETS_TCP_INFO => Ok([0, (u32::from_le_bytes([10, 0, 2, 15]) as u64) << 16 | 40000, (u32::from_le_bytes([10, 0, 0, 1]) as u64) << 16 | 80, 0]),
        MSG_NETS_TCP_TAKE_ERROR => Ok([111, 0, 0, 0]),
        _ => Ok([0; 4]),
    });
    let big = vec![7u8; NETS_KERNEL_DATA_LEN + 10];
    assert_eq!(cl::tcp_send(id, &big), Ok(NETS_KERNEL_DATA_LEN));
    assert_eq!(sent.borrow().len(), NETS_KERNEL_DATA_LEN);
    let req = seen.borrow().last().cloned().unwrap();
    assert_eq!((req.0, req.1[0], req.2.as_str()), (MSG_NETS_TCP_SEND, 12, "once"));
    // The window is held around a payload request
    assert!(fake::logged(&format!("hold_window {}", ENDPOINT_NET_SERVER)));
    // Receive: nothing readable means no request at all
    let mut buf = [0u8; 3];
    let n = seen.borrow().len();
    assert_eq!(cl::tcp_recv(id, &mut buf, false), Ok((0, false)));
    assert_eq!(seen.borrow().len(), n);
    sock_word(12, NETS_R_IN, NETS_TCP_ESTABLISHED, 0);
    // Capped at the caller's buffer
    assert_eq!(cl::tcp_recv(id, &mut buf, true), Ok((3, true)));
    assert_eq!(&buf, b"hel");
    assert_eq!(seen.borrow().last().unwrap().1, [12, 0, 3, 1]);
    // Endpoints
    assert_eq!(cl::tcp_endpoints(id), Some((40000, [10, 0, 0, 1], 80)));
    assert_eq!(cl::tcp_local_ip(id), Some([10, 0, 2, 15]));
    // A pending error: only asked when the word says there is one
    assert_eq!(cl::tcp_take_error(id), None);
    sock_word(12, NETS_R_ERR, NETS_TCP_CLOSED, 1);
    assert_eq!(cl::tcp_take_error(id), Some(-111));
    script(|_, _, _| Ok([0; 4]));
    assert_eq!(cl::tcp_take_error(id), None);
    cl::tcp_shutdown_write(id);
    cl::tcp_close(id);
    assert!(cl::dead(id));
    // A reply error, or the server leaving during the call
    let id = connect(13);
    script(|_, _, _| Ok([-32i64 as u64, 0, 0, 0]));
    assert_eq!(cl::tcp_send(id, b"x"), Err(cl::EPIPE));
    script(|_, _, _| Err(-1));
    assert_eq!(cl::tcp_send(id, b"x"), Err(cl::ENETDOWN));
    assert!(cl::tcp_endpoints(id).is_none());
    // No window
    fake::with(|s| s.windows.clear());
    fake::with(|s| s.servers.insert(ENDPOINT_NET_SERVER, 5));
}

#[test]
fn listening_sockets() {
    let _g = setup();
    net_server(5);
    let seen = script(|label, _, _| match label {
        MSG_NETS_TCP_BIND => Ok([20, 8080, 0, 0]),
        MSG_NETS_TCP_LISTEN => Ok([21, 0, 0, 0]),
        MSG_NETS_TCP_ACCEPT => Ok([22, 0, 0, 0]),
        _ => Ok([0; 4]),
    });
    let (b, port) = cl::tcp_bind([0; 4], 0, false, true, false, true).unwrap();
    assert_eq!(port, 8080);
    assert_eq!(seen.borrow()[0].1[2], 0b1010);
    let l = cl::tcp_listen(b, 16).unwrap();
    assert_eq!(seen.borrow()[1].1, [20, 16, 0, 0]);
    cl::tcp_set_backlog(l, 32);
    assert_eq!(seen.borrow()[2].1, [21, 32, 0, 0]);
    // Nothing to accept
    sock_word(21, 0, 0, 0);
    assert!(!cl::tcp_acceptable(l));
    assert!(cl::tcp_accept(l).is_none());
    sock_word(21, NETS_R_ACCEPT, 0, 0);
    assert!(cl::tcp_acceptable(l));
    let c = cl::tcp_accept(l).unwrap();
    assert!(!cl::dead(c));
    // Unpublished word: asked anyway
    sock_word(21, 0, 0, 0);
    {
        let w = k::ipc::service::window(ENDPOINT_NET_SERVER).unwrap();
        let o = NETS_SOCKS_OFF + 21 * 8;
        w[o..o + 8].fill(0);
    }
    assert!(cl::tcp_accept(l).is_some());
    assert!(!cl::tcp_acceptable(l));
    cl::tcp_unlisten(l);
    cl::tcp_unbind(b);
    assert!(cl::dead(l) && cl::dead(b));
    // A dead listener is "acceptable" (accept then fails)
    assert!(cl::tcp_acceptable(l));
    script(|_, _, _| Ok([-98i64 as u64, 0, 0, 0]));
    assert_eq!(cl::tcp_listen(c, 1), Err(-98));
}

#[test]
fn tables_for_proc_net() {
    let _g = setup();
    net_server(5);
    let id = connect(30);
    let rec = |w: &mut [u8], i: usize, words: [u64; 8]| {
        for (j, v) in words.iter().enumerate() {
            let o = i * NETS_LIST_RECORD + j * 8;
            w[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
    };
    let ip = |a: [u8; 4], port: u64| (u32::from_le_bytes(a) as u64) << 16 | port;
    script(move |label, a, w| {
        assert_eq!(label, MSG_NETS_LIST);
        assert_eq!(a[2], (NETS_KERNEL_DATA_LEN / NETS_LIST_RECORD) as u64);
        match a[0] {
            0 => {
                rec(w, 0, [30, ip([10, 0, 2, 15], 40000), ip([1, 1, 1, 1], 443), NETS_TCP_ESTABLISHED, 5, 6, 0, 0]);
                rec(w, 1, [99, ip([127, 0, 0, 1], 1), ip([127, 0, 0, 1], 2), NETS_TCP_TIME_WAIT, 0, 0, 0, 0]);
                Ok([2, 0, 0, 0])
            }
            1 => {
                rec(w, 0, [30, ip([0, 0, 0, 0], 22), 1, 128, 0, 0, 0, 0]);
                Ok([1, 0, 0, 0])
            }
            2 => {
                rec(w, 0, [31, 53, 100, 0, 0, 0, 0, 0]);
                Ok([1, 0, 0, 0])
            }
            3 => {
                rec(w, 0, [u32::from_le_bytes([10, 0, 2, 2]) as u64, u64::from_le_bytes([0x52, 0x55, 10, 0, 2, 2, 0, 0]), 0, 0, 0, 0, 0, 0]);
                Ok([1, 0, 0, 0])
            }
            _ => Ok([0; 4]),
        }
    });
    let t = cl::tcp_list();
    assert_eq!(t.len(), 2);
    assert_eq!((t[0].id, t[0].local, t[0].remote, t[0].state, t[0].tx, t[0].rx), (id, ([10, 0, 2, 15], 40000), ([1, 1, 1, 1], 443), TcpState::Established, 5, 6));
    // A connection the kernel does not hold (closed, finishing): handle 0
    assert_eq!((t[1].id, t[1].state), (0, TcpState::TimeWait));
    assert_eq!(cl::listener_list(), vec![(id, [0, 0, 0, 0], 22, 1, 128)]);
    assert_eq!(cl::udp_list(), vec![(0, 53, 100)]);
    assert_eq!(cl::arp_entries(), vec![([10, 0, 2, 2], [0x52, 0x55, 10, 0, 2, 2])]);
    // No answer: empty tables
    script(|_, _, _| Err(-1));
    assert!(cl::tcp_list().is_empty());
}

#[test]
fn udp_sockets() {
    let _g = setup();
    net_server(5);
    let got = Rc::new(RefCell::new(Vec::new()));
    let g2 = got.clone();
    let seen = script(move |label, a, w| match label {
        MSG_NETS_UDP_OPEN => Ok([40, 0, 0, 0]),
        MSG_NETS_UDP_PORT => Ok([5353, 0, 0, 0]),
        MSG_NETS_UDP_SEND => {
            g2.borrow_mut().extend_from_slice(&w[..a[3] as usize]);
            Ok([a[3], 0, 0, 0])
        }
        MSG_NETS_UDP_RECV => {
            w[..3].copy_from_slice(b"dns");
            Ok([3, (u32::from_le_bytes([8, 8, 8, 8]) as u64) << 16 | 53, 999, 0])
        }
        _ => Ok([0; 4]),
    });
    let u = cl::udp_open(0).unwrap();
    assert_eq!(cl::udp_port(u), 5353);
    cl::udp_rebind(u, 6000).unwrap();
    assert_eq!(seen.borrow()[2].1, [40, 6000, 0, 0]);
    assert_eq!(cl::udp_send(u, [8, 8, 8, 8], 53, b"query"), Ok(5));
    assert_eq!(&got.borrow()[..], b"query");
    assert_eq!(seen.borrow()[3].1, [40, (u32::from_le_bytes([8, 8, 8, 8]) as u64) << 16 | 53, 0, 5]);
    assert_eq!(cl::udp_send(u, [8, 8, 8, 8], 53, &vec![0u8; NETS_KERNEL_DATA_LEN + 1]), Err(-90));
    // Readable only with the IN bit
    sock_word(40, 0, 0, 0);
    assert!(!cl::udp_readable(u));
    assert!(cl::udp_recv(u, false).is_none());
    sock_word(40, NETS_R_IN, 0, 0);
    assert!(cl::udp_readable(u));
    assert_eq!(cl::udp_recv(u, true), Some(([8, 8, 8, 8], 53, b"dns".to_vec(), 999)));
    script(|_, _, _| Ok([-11i64 as u64, 0, 0, 0]));
    assert!(cl::udp_recv(u, false).is_none());
    assert_eq!(cl::udp_port(u), 0);
    assert_eq!(cl::udp_rebind(u, 1), Err(-11));
    cl::udp_close(u);
    assert_eq!(cl::udp_send(u, [1, 1, 1, 1], 1, b"x"), Err(cl::ENETDOWN));
    assert!(cl::udp_recv(u, false).is_none());
}

#[test]
fn icmp_sockets() {
    let _g = setup();
    net_server(5);
    script(|label, a, w| match label {
        MSG_NETS_ICMP_OPEN => Ok([50 + a[0] + 2 * a[1], 0, 0, 0]),
        MSG_NETS_ICMP_IDENT => Ok([0x1234, 0, 0, 0]),
        MSG_NETS_ICMP_SET_IDENT => Ok(if a[1] == 7 { [-98i64 as u64, 0, 0, 0] } else { [0; 4] }),
        MSG_NETS_ICMP_SEND => Ok([a[3], 0, 0, 0]),
        MSG_NETS_ICMP_RECV => {
            w[..2].copy_from_slice(&[0, 0]);
            Ok([2, u32::from_le_bytes([10, 0, 2, 2]) as u64, 55, 0])
        }
        _ => Ok([0; 4]),
    });
    let raw6 = cl::icmp_open(true, true);
    assert_ne!(raw6, 0);
    let p = cl::icmp_open(false, false);
    assert_eq!(cl::icmp_ident(p), 0x1234);
    assert_eq!(cl::icmp_set_ident(p, 9), Ok(()));
    assert_eq!(cl::icmp_set_ident(p, 7), Err(-98));
    assert_eq!(cl::icmp_send(p, [10, 0, 2, 2], &[8, 0, 0, 0]), Ok(4));
    assert_eq!(cl::icmp_send(p, [10, 0, 2, 2], &vec![0; NETS_KERNEL_DATA_LEN + 1]), Err(-90));
    sock_word(50, NETS_R_IN, 0, 0);
    assert!(cl::icmp_readable(p));
    assert_eq!(cl::icmp_recv(p, false), Some(([10, 0, 2, 2], vec![0, 0], 55)));
    sock_word(50, 0, 0, 0);
    assert!(!cl::icmp_readable(p));
    assert!(cl::icmp_recv(p, false).is_none());
    cl::icmp_close(p);
    assert_eq!(cl::icmp_ident(p), 0);
    assert_eq!(cl::icmp_send(p, [1, 1, 1, 1], b"x"), Err(cl::ENETDOWN));
    assert!(cl::icmp_recv(p, false).is_none());
}

#[test]
fn the_doorbell_wakes_the_listed_sockets() {
    let _g = setup();
    net_server(5);
    let a = connect(60);
    let b = connect(61);
    let wakes = |id: u32| cl::wait_queue(id).unwrap().wakes.load(core::sync::atomic::Ordering::Relaxed);
    // Events 0..2 list handle 61 twice and an unknown one
    let w = k::ipc::service::window(ENDPOINT_NET_SERVER).unwrap();
    for (i, sid) in [61u32, 999, 61].iter().enumerate() {
        let o = NETS_EVENTS_OFF + i * 4;
        w[o..o + 4].copy_from_slice(&sid.to_le_bytes());
    }
    status(NETS_ST_EVENT_HEAD, 3);
    cl::on_signal(0);
    assert_eq!((wakes(a), wakes(b)), (0, 2));
    assert!(fake::logged("net_event Some([61, 999, 61])"));
    // Nothing new: nothing woken
    cl::on_signal(0);
    assert_eq!(wakes(b), 2);
    // The ring overflowed (more than it holds): everyone
    status(NETS_ST_EVENT_HEAD, 3 + NETS_EVENTS as u64 + 1);
    cl::on_signal(0);
    assert_eq!((wakes(a), wakes(b)), (1, 3));
    assert!(fake::logged("net_event None"));
    // The head went backwards (a restarted server): everyone
    status(NETS_ST_EVENT_HEAD, 1);
    cl::on_signal(0);
    assert_eq!((wakes(a), wakes(b)), (2, 4));
    // No window: nothing
    fake::with(|s| s.servers.clear());
    cl::on_signal(0);
    assert_eq!(wakes(a), 2);
}

#[test]
fn the_server_going_away_wakes_everyone() {
    let _g = setup();
    net_server(5);
    let a = connect(70);
    let wakes = || cl::wait_queue(a).unwrap().wakes.load(core::sync::atomic::Ordering::Relaxed);
    fake::take_log();
    cl::on_signal(k::ipc::service::SIGNAL_GONE);
    assert_eq!(wakes(), 1);
    assert_eq!(fake::take_log(), vec!["net_event None"]);
    // The server's handles mean nothing now: the table shows handle 0
    script(|_, _, w| {
        w[..8].copy_from_slice(&70u64.to_le_bytes());
        Ok([1, 0, 0, 0])
    });
    assert_eq!(cl::udp_list()[0].0, 0);
}

#[test]
fn linux_server_is_told_about_the_doorbell() {
    use core::sync::atomic::Ordering::Relaxed;
    let _g = setup();
    net_server(5);
    k::lx::ONLINE.store(true, Relaxed);
    k::lx::NET_MOVED.store(true, Relaxed);
    // The server went away: always told
    cl::on_signal(k::ipc::service::SIGNAL_GONE);
    assert!(fake::logged(&format!("notify {} {}", ENDPOINT_LINUX_SERVER, NOTIFY_LX_NET_GONE)));
    // A doorbell: only when it wants the relay
    fake::take_log();
    cl::on_signal(0);
    assert!(!fake::logged("notify"));
    k::lx::RELAY.store(true, Relaxed);
    cl::on_signal(0);
    assert!(fake::logged(&format!("notify {} {}", ENDPOINT_LINUX_SERVER, NOTIFY_LX_NET)));
    k::lx::RELAY.store(false, Relaxed);
    k::lx::NET_MOVED.store(false, Relaxed);
    k::lx::ONLINE.store(false, Relaxed);
}

#[test]
fn dhcp_renewal() {
    let _g = setup();
    net_server(5);
    let seen = script(|_, _, _| Ok([0, u32::from_le_bytes([10, 0, 2, 15]) as u64, 0, 0]));
    assert_eq!(cl::dhcp_renew(), Ok([10, 0, 2, 15]));
    assert_eq!(seen.borrow()[0].2, "queued");
    script(|_, _, _| Ok([-19i64 as u64, 0, 0, 0]));
    assert_eq!(cl::dhcp_renew(), Err("no network card"));
    script(|_, _, _| Ok([-110i64 as u64, 0, 0, 0]));
    assert_eq!(cl::dhcp_renew(), Err("no DHCP answer"));
    script(|_, _, _| Err(-1));
    assert_eq!(cl::dhcp_renew(), Err("the network server is not running"));
}

#[test]
fn name_lookups() {
    let _g = setup();
    assert_eq!(cl::resolve(""), Err("bad name"));
    assert_eq!(cl::resolve(&"a".repeat(1025)), Err("bad name"));
    assert_eq!(cl::resolve("x.org"), Err("the network server is not running"));
    net_server(5);
    let seen = script(|_, a, w| {
        let name = String::from_utf8_lossy(&w[a[0] as usize..(a[0] + a[1]) as usize]).to_string();
        Ok(match name.as_str() {
            "ok.org" => [0, u32::from_le_bytes([1, 2, 3, 4]) as u64, 0, 0],
            "unreach" => [cl::ENETUNREACH as u64, 0, 0, 0],
            "slow" => [cl::ETIMEDOUT as u64, 0, 0, 0],
            "none" => [-2i64 as u64, 0, 0, 0],
            _ => [-22i64 as u64, 0, 0, 0],
        })
    });
    assert_eq!(cl::resolve("ok.org"), Ok([1, 2, 3, 4]));
    // The name sits in the data area's last page
    assert_eq!(seen.borrow()[0].1[0], (NETS_DATA_LEN - 4096) as u64);
    assert_eq!(seen.borrow()[0].2, "queued");
    assert_eq!(cl::resolve("unreach"), Err("the network interface has no address"));
    assert_eq!(cl::resolve("slow"), Err("DNS query timed out: no response from DNS server"));
    assert_eq!(cl::resolve("none"), Err("no such name"));
    assert_eq!(cl::resolve("weird"), Err("bad name"));
    script(|_, _, _| Err(-1));
    assert_eq!(cl::resolve("ok.org"), Err("the network server is not running"));
}

#[test]
fn one_lookup_at_a_time() {
    let _g = setup();
    net_server(5);
    // While a lookup runs, a second one waits (10 s at most) and gives up
    let inner = Rc::new(RefCell::new(None));
    let i2 = inner.clone();
    script(move |_, _, _| {
        let t0 = fake::ticks();
        *i2.borrow_mut() = Some((cl::resolve("second"), fake::ticks() - t0));
        Ok([0, 0x0100007f, 0, 0])
    });
    assert_eq!(cl::resolve("first"), Ok([127, 0, 0, 1]));
    let (r, waited) = inner.borrow_mut().take().unwrap();
    assert_eq!(r, Err("another lookup is in progress"));
    assert_eq!(waited, 1001);
    // The first one released the name page
    assert_eq!(cl::resolve("again"), Ok([127, 0, 0, 1]));
}

// ------------------------------------------------------------------------ net/mod.rs

#[test]
fn the_boot_report() {
    let _g = setup();
    // No server: reported at once
    k::net::init();
    assert_eq!(fake::take_out(), "[*] Network Subsystem: the network server is not running\n");
    // A server that never publishes its status: 2 s of waiting
    fake::with(|s| {
        s.online.insert(ENDPOINT_NET_SERVER);
    });
    k::net::init();
    assert_eq!(fake::ticks(), 200);
    assert!(fake::take_out().contains("the network server is not running"));
    net_server(5);
    k::net::init();
    assert_eq!(fake::take_out(), "[*] Network Subsystem: No compatible Ethernet adapter detected (loopback only)\n");
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    k::net::init();
    let out = fake::take_out();
    assert!(out.contains("[+] Network Subsystem: Intel E1000 Online (MAC 52:54:00:12:34:56, Link: UP), protocols in net-server"));
    assert!(out.ends_with("    - DHCP Lease: Acquiring dynamic IPv4 configuration... ONLINE (10.0.2.15, GW 10.0.2.2, DNS 10.0.2.3)\n"));
    // No lease within 10 s; no link yet
    status(NETS_ST_IP, 0);
    status(NETS_ST_FLAGS, NETS_F_NIC);
    let t0 = fake::ticks();
    k::net::init();
    assert_eq!(fake::ticks() - t0, 1000);
    let out = fake::take_out();
    assert!(out.contains("Link: NEGOTIATING"));
    assert!(out.ends_with("Deferred (no DHCP answer yet; net-server keeps trying)\n"));
}

#[test]
fn the_lease_arrives_during_boot() {
    let _g = setup();
    net_server(5);
    iface_up([0, 0, 0, 0], [10, 0, 2, 3]);
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 500_000_000 {
                status_in(st, NETS_ST_IP, ipw([10, 0, 2, 15]));
            }
        }))
    });
    k::net::init();
    assert!(fake::take_out().contains("ONLINE (10.0.2.15"));
    assert_eq!(fake::ticks(), 50);
}

#[test]
fn dhcp_and_dns_wrappers() {
    let _g = setup();
    let net = fake_net();
    iface_up([0, 0, 0, 0], [10, 0, 2, 3]);
    net.borrow_mut().dhcp = Some(Ok([10, 0, 2, 20]));
    assert_eq!(k::net::dhcp_renew().unwrap().ip, [10, 0, 2, 20]);
    net.borrow_mut().dhcp = Some(Err(-19));
    assert_eq!(k::net::dhcp_renew().unwrap_err(), "no network card");
    net.borrow_mut().names.push(("host.lan".into(), [10, 0, 2, 9]));
    assert_eq!(k::net::resolve("http://host.lan:8080/x"), Ok([10, 0, 2, 9]));
    assert_eq!(k::net::resolve("http://"), Err("Domain name cannot be empty"));
}

#[test]
fn ping() {
    let _g = setup();
    // Not configured, not local: refused before asking
    net_server(5);
    assert_eq!(k::net::ping([8, 8, 8, 8], 1), Err("Local network interface has no IP address assigned (run 'dhcp' first)"));
    // Loopback needs no address, but needs the server
    fake::with(|s| s.handler = None);
    assert_eq!(k::net::ping([127, 0, 0, 1], 1), Err("the network server is not running"));
    let net = fake_net();
    iface_up([10, 0, 2, 15], [0; 4]);
    net.borrow_mut().pingable.push([10, 0, 2, 2]);
    assert_eq!(k::net::ping([10, 0, 2, 2], 7), Ok(0));
    // The echo request: type 8, sequence, payload
    let send = net.borrow().seen.iter().find(|s| s.0 == MSG_NETS_ICMP_SEND).cloned().unwrap();
    assert_eq!(send.1[3], 8 + 31);
    // The socket was closed
    assert!(net.borrow().seen.iter().any(|s| s.0 == MSG_NETS_ICMP_CLOSE));
    // No reply within 1.5 s
    let t0 = fake::with(|s| s.clock_ns);
    assert_eq!(k::net::ping([10, 0, 2, 3], 1), Err("Request timed out (no ICMP Echo Reply received)"));
    assert_eq!(fake::with(|s| s.clock_ns) - t0, 1_500_000_000);
    // A reply with another sequence number does not count
    net.borrow_mut().pingable.push([10, 0, 2, 4]);
    let inner = RefCell::new(fake::with(|s| s.handler.take()).unwrap());
    fake::with(|s| {
        s.handler = Some(Box::new(move |e, m, kd| {
            let r = (inner.borrow_mut())(e, m, kd);
            if m.label == MSG_NETS_ICMP_RECV && r.is_ok() {
                k::ipc::service::window(e).unwrap()[7] ^= 1;
            }
            r
        }))
    });
    assert_eq!(k::net::ping([10, 0, 2, 4], 1), Err("Request timed out (no ICMP Echo Reply received)"));
    // A reply from another host does not count either
    script(|label, a, w| match label {
        MSG_NETS_ICMP_OPEN => Ok([6, 0, 0, 0]),
        MSG_NETS_ICMP_SEND => {
            sock_word(6, NETS_R_IN, 0, 0);
            Ok([a[3], 0, 0, 0])
        }
        MSG_NETS_ICMP_RECV => {
            w[..8].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
            Ok([8, u32::from_le_bytes([10, 0, 2, 99]) as u64, 0, 0])
        }
        _ => Ok([0; 4]),
    });
    assert!(k::net::ping([10, 0, 2, 4], 1).is_err());
    // Sending fails
    script(|label, _, _| match label {
        MSG_NETS_ICMP_OPEN => Ok([5, 0, 0, 0]),
        MSG_NETS_ICMP_SEND => Ok([-101i64 as u64, 0, 0, 0]),
        _ => Ok([0; 4]),
    });
    assert_eq!(k::net::ping([10, 0, 2, 2], 1), Err("cannot send the echo request"));
}

#[test]
fn http_get() {
    let _g = setup();
    let net = fake_net();
    iface_up([10, 0, 2, 15], [0; 4]);
    let body = "x".repeat(2500);
    net.borrow_mut().http_response = format!("HTTP/1.0 200 OK\r\nServer: t\r\n\r\n{}", body).into_bytes();
    let mut out = vec![0u8; 4096];
    let n = k::net::http_get([10, 0, 2, 2], 80, "/f", &mut out).unwrap();
    assert_eq!(n, 2500);
    assert!(out[..n].iter().all(|&b| b == b'x'));
    // Truncated to the caller's buffer
    let mut small = [0u8; 10];
    assert_eq!(k::net::http_get([10, 0, 2, 2], 80, "/f", &mut small), Ok(10));
    // No header end
    net.borrow_mut().http_response = b"garbage".to_vec();
    assert_eq!(k::net::http_get([10, 0, 2, 2], 80, "/", &mut out), Err("malformed HTTP response (no header end)"));
    // Refused, or no connection at all
    net.borrow_mut().refuse = true;
    assert_eq!(k::net::http_get([10, 0, 2, 2], 80, "/", &mut out), Err("connection refused"));
    net.borrow_mut().fail = Some(-101);
    assert_eq!(k::net::http_get([10, 0, 2, 2], 80, "/", &mut out), Err("cannot connect (no network?)"));
}

#[test]
fn http_get_timeouts_and_resets() {
    let _g = setup();
    net_server(5);
    // The handshake never finishes
    script(|label, _, _| match label {
        MSG_NETS_TCP_CONNECT => {
            sock_word(1, 0, NETS_TCP_SYN_SENT, 0);
            Ok([1, 0, 0, 0])
        }
        _ => Ok([0; 4]),
    });
    let mut out = [0u8; 64];
    let t0 = fake::with(|s| s.clock_ns);
    assert_eq!(k::net::http_get([1, 1, 1, 1], 80, "/", &mut out), Err("TCP handshake timed out (no SYN-ACK received)"));
    assert!(fake::with(|s| s.clock_ns) - t0 > 5_000_000_000);
    // Connected; the send queue is full once, then takes everything; no data comes
    let full_once = Rc::new(RefCell::new(true));
    let f2 = full_once.clone();
    script(move |label, a, _| match label {
        MSG_NETS_TCP_CONNECT => {
            sock_word(2, NETS_R_OUT, NETS_TCP_ESTABLISHED, 0);
            Ok([2, 0, 0, 0])
        }
        MSG_NETS_TCP_SEND => {
            if f2.replace(false) {
                Ok([0, 0, 0, 0])
            } else {
                Ok([a[2], 0, 0, 0])
            }
        }
        _ => Ok([0; 4]),
    });
    assert_eq!(k::net::http_get([1, 1, 1, 1], 80, "/", &mut out), Err("the transfer stalled (no data for 5 s)"));
    // Sending fails
    script(|label, _, _| match label {
        MSG_NETS_TCP_CONNECT => {
            sock_word(3, NETS_R_OUT, NETS_TCP_ESTABLISHED, 0);
            Ok([3, 0, 0, 0])
        }
        MSG_NETS_TCP_SEND => Ok([-32i64 as u64, 0, 0, 0]),
        _ => Ok([0; 4]),
    });
    assert_eq!(k::net::http_get([1, 1, 1, 1], 80, "/", &mut out), Err("sending the request failed"));
    // The connection is reset while receiving
    script(|label, a, _| match label {
        MSG_NETS_TCP_CONNECT => {
            sock_word(4, NETS_R_OUT | NETS_R_IN, NETS_TCP_ESTABLISHED, 0);
            Ok([4, 0, 0, 0])
        }
        MSG_NETS_TCP_SEND => Ok([a[2], 0, 0, 0]),
        MSG_NETS_TCP_RECV => Ok([-104i64 as u64, 0, 0, 0]),
        _ => Ok([0; 4]),
    });
    assert_eq!(k::net::http_get([1, 1, 1, 1], 80, "/", &mut out), Err("the connection was reset"));
}

// -------------------------------------------------------------------------- e1000

#[test]
fn finding_the_network_adapter() {
    use k::net::e1000::*;
    let _g = setup();
    assert!(find_adapter().is_none());
    // An I218-V and an 82574: the table's order decides (82574 first)
    fake::with(|s| s.pci = vec![(0x8086, 0x1559, 0xF000_0000), (0x8086, 0x10D3, 0xE000_0000), (0x10EC, 0x100E, 1)]);
    let a = find_adapter().unwrap();
    assert_eq!((a.model, a.bar0, a.dev.device), ("82574", 0xE000_0000, 0x10D3));
    assert!(fake::logged("bus_master 10d3"));
    // A device without its register window is skipped
    fake::with(|s| s.pci = vec![(0x8086, E1000_DEVICE_ID, 0), (0x8086, 0x15A3, 0xD000_0000)]);
    let a = find_adapter().unwrap();
    assert_eq!((a.model, a.bar0), ("pch", 0xD000_0000));
    assert_eq!((E1000_VENDOR_ID, E1000_DEVICE_ID), (0x8086, 0x100E));
}

#[test]
fn http_get_ends_at_an_empty_end_of_stream() {
    let _g = setup();
    net_server(5);
    let first = Rc::new(RefCell::new(true));
    let f2 = first.clone();
    script(move |label, a, w| match label {
        MSG_NETS_TCP_CONNECT => {
            sock_word(8, NETS_R_OUT | NETS_R_IN, NETS_TCP_ESTABLISHED, 0);
            Ok([8, 0, 0, 0])
        }
        MSG_NETS_TCP_SEND => Ok([a[2], 0, 0, 0]),
        MSG_NETS_TCP_RECV => {
            if f2.replace(false) {
                let r = b"HTTP/1.0 204 No Content\r\n\r\n";
                w[..r.len()].copy_from_slice(r);
                Ok([r.len() as u64, 0, 0, 0])
            } else {
                // The end of the stream, with no more bytes
                Ok([0, 1, 0, 0])
            }
        }
        _ => Ok([0; 4]),
    });
    let mut out = [0u8; 16];
    assert_eq!(k::net::http_get([1, 1, 1, 1], 80, "/", &mut out), Ok(0));
}
