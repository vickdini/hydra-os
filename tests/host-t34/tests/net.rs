//! `src/net/*`: the kernel's client of net-server (handles, readiness words, the event ring,
//! every request), the boot report, ping and HTTP GET on its sockets, and the e1000 lookup.
#![allow(dead_code, unused_imports)] // (wave10 G10-C: helpers of tests deleted with the kernel socket copy)

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

// wave8 GX2 begin
#[test]
fn lx_net_is_told_about_the_doorbell() {
    use core::sync::atomic::Ordering::Relaxed;
    let _g = setup();
    net_server(5);
    k::lx::ONLINE.store(true, Relaxed);
    k::lx::NET_MOVED.store(true, Relaxed);
    k::lx::svc::NET_EP.store(ENDPOINT_LX_NET, Relaxed);
    // The doorbell goes to the network service's own process, not linux-server
    k::lx::RELAY.store(true, Relaxed);
    fake::take_log();
    cl::on_signal(0);
    assert!(fake::logged(&format!("notify {} {}", ENDPOINT_LX_NET, NOTIFY_LX_NET)));
    assert!(!fake::logged(&format!("notify {} ", ENDPOINT_LINUX_SERVER)));
    cl::on_signal(k::ipc::service::SIGNAL_GONE);
    assert!(fake::logged(&format!("notify {} {}", ENDPOINT_LX_NET, NOTIFY_LX_NET_GONE)));
    // Offline (restarting): nobody is told
    k::lx::ONLINE.store(false, Relaxed);
    fake::take_log();
    cl::on_signal(0);
    assert!(!fake::logged("notify"));
    k::lx::svc::NET_EP.store(ENDPOINT_LINUX_SERVER, Relaxed);
    k::lx::RELAY.store(false, Relaxed);
    k::lx::NET_MOVED.store(false, Relaxed);
}
// wave8 GX2 end

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
