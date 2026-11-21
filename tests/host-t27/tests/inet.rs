//! Internet sockets (`src/compat/linux/inet.rs`): the kernel side of `AF_INET`/`AF_INET6`
//! TCP, UDP and ICMP sockets, against a scripted net-server ([`fake::net`]): address
//! parsing and formatting, the connect/bind/listen/accept state machine, blocking and
//! non-blocking I/O, `sendmsg`/`recvmsg` with control messages, options and `/proc/net`.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::inet::{self, dispatch, InetSocket};
use hydra_hosttests_t27::fake::net::{self, Tcp, TcpState};
use hydra_hosttests_t27::fs::FileDescriptor;
use std::sync::Arc;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const EPIPE: i64 = -32;
const EDESTADDRREQ: i64 = -89;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;
const ESOCKTNOSUPPORT: i64 = -94;
const EOPNOTSUPP: i64 = -95;
const EAFNOSUPPORT: i64 = -97;
const EADDRNOTAVAIL: i64 = -99;
const ENETDOWN: i64 = -100;
const ENETUNREACH: i64 = -101;
const ECONNRESET: i64 = -104;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const ECONNREFUSED: i64 = -111;
const EALREADY: i64 = -114;
const EINPROGRESS: i64 = -115;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const RAW: u64 = 3;
const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;
const MSG_PEEK: u64 = 2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;

const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
const CAP_NET_RAW: u64 = 1 << 13;

/// `inet.rs` keeps one global socket list (`SOCKETS`) while the scripted net-server is per
/// thread: tests running in parallel would see each other's sockets, so they run one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn call(num: u64, a: [u64; 6]) -> i64 {
    dispatch(num, a).expect("an AF_INET call")
}

fn socket(domain: u64, ty: u64, proto: u64) -> u64 {
    let fd = call(41, [domain, ty, proto, 0, 0, 0]);
    assert!(fd >= 3, "socket: {fd}");
    fd as u64
}

fn obj(fd: u64) -> Arc<spin::Mutex<InetSocket>> {
    match fake::fd::get(fd as i64) {
        Some(FileDescriptor::Inet(s)) => s,
        _ => panic!("not an inet socket"),
    }
}

fn sin(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&2u16.to_le_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip);
    b
}

fn sin6(addr: [u8; 16], port: u16) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&10u16.to_le_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[8..24].copy_from_slice(&addr);
    b
}

fn v6(last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[15] = last;
    a
}

fn mapped(ip: [u8; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12..].copy_from_slice(&ip);
    a
}

fn connect(fd: u64, sa: &[u8]) -> i64 {
    call(42, [fd, sa.as_ptr() as u64, sa.len() as u64, 0, 0, 0])
}

fn bind(fd: u64, sa: &[u8]) -> i64 {
    call(49, [fd, sa.as_ptr() as u64, sa.len() as u64, 0, 0, 0])
}

/// `getsockname` (51) / `getpeername` (52): the address bytes and length.
fn name(num: u64, fd: u64) -> Result<(Vec<u8>, u32), i64> {
    let mut sa = [0u8; 28];
    let mut len = 28u32;
    let r = call(num, [fd, mptr(&mut sa), mptr(&mut len), 0, 0, 0]);
    if r < 0 {
        Err(r)
    } else {
        Ok((sa[..len as usize].to_vec(), len))
    }
}

/// (ip, port) of a `sockaddr_in`.
fn v4_of(sa: &[u8]) -> ([u8; 4], u16) {
    assert_eq!(u16::from_le_bytes([sa[0], sa[1]]), 2);
    ([sa[4], sa[5], sa[6], sa[7]], u16::from_be_bytes([sa[2], sa[3]]))
}

fn setsockopt(fd: u64, level: u64, opt: u64, val: &[u8]) -> i64 {
    call(54, [fd, level, opt, val.as_ptr() as u64, val.len() as u64, 0])
}

fn getsockopt(fd: u64, level: u64, opt: u64) -> Result<Vec<u8>, i64> {
    let mut v = [0u8; 256];
    let mut len = 256u32;
    let r = call(55, [fd, level, opt, mptr(&mut v), mptr(&mut len), 0]);
    if r < 0 {
        Err(r)
    } else {
        Ok(v[..len as usize].to_vec())
    }
}

fn int(v: i32) -> [u8; 4] {
    v.to_le_bytes()
}

/// The newest TCP connection in the fake server.
fn last_tcp() -> u32 {
    net::with(|n| *n.tcp.keys().last().expect("a connection"))
}

fn last_udp() -> u32 {
    net::with(|n| *n.udp.keys().last().expect("a UDP endpoint"))
}

fn last_icmp() -> u32 {
    net::with(|n| *n.icmp.keys().last().expect("an ICMP endpoint"))
}

fn log_has(s: &str) -> bool {
    net::with(|n| n.log.iter().any(|l| l == s))
}

fn sendto(fd: u64, data: &[u8], flags: u64, dest: Option<&[u8]>) -> i64 {
    let (p, l) = dest.map_or((0, 0), |d| (d.as_ptr() as u64, d.len() as u64));
    call(44, [fd, data.as_ptr() as u64, data.len() as u64, flags, p, l])
}

fn recvfrom(fd: u64, buf: &mut [u8], flags: u64) -> (i64, Vec<u8>) {
    let mut sa = [0u8; 28];
    let mut len = 28u32;
    let r = call(45, [fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags, mptr(&mut sa), mptr(&mut len)]);
    (r, sa[..len as usize].to_vec())
}

/// A connected TCP socket (fd, connection id).
fn connected(nonblock: bool) -> (u64, u32) {
    let fd = socket(AF_INET, STREAM, 0);
    net::with(|n| n.connect_state = TcpState::Established);
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 80)), 0);
    obj(fd).lock().nonblock = nonblock;
    (fd, last_tcp())
}

// ------------------------------------------------------------------ socket()

#[test]
fn socket_types_and_protocols() {
    let _serial = serial();
    fake::reset();
    assert_eq!(dispatch(41, [1, STREAM, 0, 0, 0, 0]), None, "AF_UNIX is not ours");
    assert_eq!(dispatch(42, [3, 0, 0, 0, 0, 0]), None, "not an inet descriptor");
    assert_eq!(dispatch(0, [3, 0, 0, 0, 0, 0]), None, "not a socket call");
    socket(AF_INET, STREAM, 0);
    socket(AF_INET, STREAM, 6);
    socket(AF_INET6, STREAM, 0);
    let u = socket(AF_INET, DGRAM, 17);
    assert!(log_has("udp_open 0"), "a UDP socket opens its endpoint at once");
    assert_eq!(obj(u).lock().poll_events(), 4, "writable");
    let ping = socket(AF_INET, DGRAM, 1);
    assert!(log_has("icmp_open false false"));
    assert_eq!(obj(ping).lock().poll_events(), 4);
    socket(AF_INET6, DGRAM, 58);
    assert!(log_has("icmp_open false true"));
    assert_eq!(call(41, [AF_INET, RAW, 1, 0, 0, 0]), EPERM, "raw sockets need CAP_NET_RAW");
    fake::CAPS.set(Some(CAP_NET_RAW));
    socket(AF_INET, RAW, 1);
    assert!(log_has("icmp_open true false"));
    assert_eq!(call(41, [AF_INET, STREAM, 17, 0, 0, 0]), EPROTONOSUPPORT);
    assert_eq!(call(41, [AF_INET, DGRAM, 6, 0, 0, 0]), EPROTONOSUPPORT);
    assert_eq!(call(41, [AF_INET, RAW, 6, 0, 0, 0]), EPROTONOSUPPORT);
    assert_eq!(call(41, [AF_INET, 5, 0, 0, 0, 0]), ESOCKTNOSUPPORT);
    let fd = socket(AF_INET, STREAM | NONBLOCK | CLOEXEC, 0);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    assert!(obj(fd).lock().nonblock);
    fake::fd::FDS.with_borrow_mut(|f| f.limit = fd as usize + 1);
    assert_eq!(call(41, [AF_INET, STREAM, 0, 0, 0, 0]), EMFILE);
}

#[test]
fn closing_releases_the_server_handles() {
    let _serial = serial();
    fake::reset();
    fake::CAPS.set(Some(CAP_NET_RAW));
    let raw = socket(AF_INET, RAW, 1);
    let icmp = last_icmp();
    let lst = socket(AF_INET, STREAM, 0);
    assert_eq!(call(50, [lst, 5, 0, 0, 0, 0]), 0);
    let (conn, cid) = connected(false);
    let u = socket(AF_INET, DGRAM, 0);
    let uid = last_udp();
    fake::fd::FDS.with_borrow_mut(|f| {
        for fd in [raw, lst, conn, u] {
            f.close(fd as usize).unwrap();
        }
    });
    assert!(log_has(&format!("icmp_close {icmp}")));
    assert!(net::with(|n| n.log.iter().any(|l| l.starts_with("tcp_unlisten "))));
    assert!(net::with(|n| n.log.iter().any(|l| l.starts_with("tcp_unbind "))));
    assert!(log_has(&format!("tcp_close {cid}")));
    assert!(log_has(&format!("udp_close {uid}")));
}

// ------------------------------------------------------------------ addresses

#[test]
fn ipv4_address_parsing() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    assert_eq!(call(42, [u, 0, 1, 0, 0, 0]), EINVAL, "too short");
    assert_eq!(call(42, [u, 0, 16, 0, 0, 0]), EFAULT);
    assert_eq!(connect(u, &sin6(v6(1), 1)), EAFNOSUPPORT, "an IPv6 address on an IPv4 socket");
    let mut unix = sin([1, 2, 3, 4], 5);
    unix[0] = 1;
    assert_eq!(connect(u, &unix), EINVAL, "another family");
    assert_eq!(connect(u, &sin([1, 2, 3, 4], 5)[..6]), EINVAL, "truncated sockaddr_in");
    assert_eq!(connect(u, &sin([0, 1, 2, 3], 5)), ENETUNREACH, "0.0.0.0/8");
    assert_eq!(connect(u, &sin([8, 8, 8, 8], 53)), 0);
    assert_eq!(v4_of(&name(52, u).unwrap().0), ([8, 8, 8, 8], 53));
    // 0.0.0.0 means this host
    assert_eq!(connect(u, &sin([0; 4], 53)), 0);
    assert_eq!(v4_of(&name(52, u).unwrap().0), ([127, 0, 0, 1], 53));
    // AF_UNSPEC disconnects
    assert_eq!(connect(u, &[0u8, 0]), 0);
    assert_eq!(name(52, u), Err(ENOTCONN));
    // A network namespace of its own reaches nothing
    fake::NET_ISOLATED.set(true);
    assert_eq!(connect(u, &sin([8, 8, 8, 8], 53)), ENETUNREACH);
}

#[test]
fn ipv6_address_parsing_and_formatting() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    let u = socket(AF_INET6, DGRAM, 0);
    assert_eq!(connect(u, &sin([1, 2, 3, 4], 5)), EINVAL, "shorter than sockaddr_in6");
    let mut v4fam = sin6(v6(1), 5);
    v4fam[0] = 2;
    assert_eq!(connect(u, &v4fam), EAFNOSUPPORT);
    let mut global = [0u8; 16];
    global[0] = 0x20;
    global[1] = 0x01;
    assert_eq!(connect(u, &sin6(global, 80)), ENETUNREACH, "no IPv6 route");
    let peer = |u: u64| name(52, u).unwrap();
    // ::1
    assert_eq!(connect(u, &sin6(v6(1), 80)), 0);
    let (sa, len) = peer(u);
    assert_eq!(len, 28);
    assert_eq!(u16::from_le_bytes([sa[0], sa[1]]), 10);
    assert_eq!(u16::from_be_bytes([sa[2], sa[3]]), 80);
    assert_eq!(&sa[8..24], &v6(1));
    // :: means this host (::1)
    assert_eq!(connect(u, &sin6([0; 16], 81)), 0);
    assert_eq!(&peer(u).0[8..24], &v6(1));
    // Our link-local address, with eth0's scope
    let ll = net::link_local6().unwrap();
    assert_eq!(connect(u, &sin6(ll, 82)), 0);
    let (sa, _) = peer(u);
    assert_eq!(&sa[8..24], &ll);
    assert_eq!(u32::from_le_bytes(sa[24..28].try_into().unwrap()), 2);
    // IPv4-mapped
    assert_eq!(connect(u, &sin6(mapped([10, 0, 2, 2]), 83)), 0);
    assert_eq!(&peer(u).0[8..24], &mapped([10, 0, 2, 2]));
    // A short buffer gets a prefix and the full length
    let mut sa = [0u8; 8];
    let mut len = 8u32;
    assert_eq!(call(52, [u, mptr(&mut sa), mptr(&mut len), 0, 0, 0]), 0);
    assert_eq!(len, 28);
    assert_eq!(&sa[..4], &[10, 0, 0, 83]);
    // No buffer: nothing written
    assert_eq!(call(52, [u, 0, 0, 0, 0, 0]), 0);
    let mut bad_len = 28u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(52, [u, mptr(&mut sa), mptr(&mut bad_len), 0, 0, 0]), EFAULT);
    // IPV6_V6ONLY: no mapped destinations
    let only = socket(AF_INET6, STREAM, 0);
    assert_eq!(setsockopt(only, 41, 26, &int(1)), 0);
    assert_eq!(connect(only, &sin6(mapped([10, 0, 2, 2]), 80)), ENETUNREACH);
}

// ------------------------------------------------------------------ TCP connect

#[test]
fn blocking_connect_waits_for_the_handshake() {
    let _serial = serial();
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    fake::on_wait(|_| {
        let id = last_tcp();
        net::with(|n| n.tcp.get_mut(&id).unwrap().state = TcpState::Established);
    });
    assert_eq!(connect(fd, &sin([93, 184, 216, 34], 443)), 0);
    assert!(log_has("tcp_connect [93, 184, 216, 34] 443 None"));
    assert_eq!(fake::WAITS.get(), 1);
    assert_eq!(fake::wait::LAST_QUEUES.get(), 1, "slept on the connection's queue");
    assert_eq!(connect(fd, &sin([93, 184, 216, 34], 443)), EISCONN);
    assert_eq!(obj(fd).lock().poll_events() & 4, 4, "writable once established");
}

#[test]
fn refused_and_interrupted_connects() {
    let _serial = serial();
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    fake::on_wait(|_| {
        let id = last_tcp();
        net::with(|n| n.tcp.get_mut(&id).unwrap().state = TcpState::Closed);
    });
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), ECONNREFUSED, "reset without an error: refused");
    // The error of a dead connection, once
    let id = last_tcp();
    net::with(|n| n.tcp.get_mut(&id).unwrap().error = Some(-110));
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), -110);
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), EISCONN);
    // A signal: EINTR, the connection goes on
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), EINTR);
    // With SO_SNDTIMEO: the timeout gives EINPROGRESS
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    let tv = [0i64, 20_000]; // 20 ms
    assert_eq!(setsockopt(fd, 1, 21, &bytes(&tv)), 0);
    let start = fake::now_ns();
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), EINPROGRESS);
    assert!(fake::now_ns() >= start + 20_000_000);
    // A signal with a timeout set: EINTR too
    fake::SIGNAL_PENDING.set(true);
    let fd2 = socket(AF_INET, STREAM, 0);
    assert_eq!(setsockopt(fd2, 1, 21, &bytes(&tv)), 0);
    assert_eq!(connect(fd2, &sin([10, 0, 2, 2], 1)), EINTR);
    // The server refuses outright
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    net::with(|n| n.connect_err = Some(ENETUNREACH));
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 1)), ENETUNREACH);
}

fn bytes(v: &[i64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

#[test]
fn non_blocking_connect() {
    let _serial = serial();
    fake::reset();
    let fd = socket(AF_INET, STREAM | NONBLOCK, 0);
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 80)), EINPROGRESS);
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 80)), EALREADY);
    assert_eq!(getsockopt(fd, 6, 11).unwrap()[0], 2, "TCP_INFO: SYN_SENT");
    // Blocking again: waits for the same connection
    obj(fd).lock().nonblock = false;
    let id = last_tcp();
    fake::on_wait(move |_| net::with(|n| n.tcp.get_mut(&id).unwrap().state = TcpState::Established));
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 80)), 0);
    assert_eq!(getsockopt(fd, 6, 11).unwrap()[0], 1, "ESTABLISHED");
    // A connection that failed reports its error through SO_ERROR, once
    net::with(|n| {
        let t = n.tcp.get_mut(&id).unwrap();
        t.state = TcpState::Closed;
        t.error = Some(ECONNREFUSED);
    });
    assert_eq!(getsockopt(fd, 1, 4).unwrap(), int(111).to_vec());
    assert_eq!(getsockopt(fd, 1, 4).unwrap(), int(0).to_vec());
}

#[test]
fn connect_rules() {
    let _serial = serial();
    fake::reset();
    // AF_UNSPEC on a stream socket
    let fd = socket(AF_INET, STREAM, 0);
    assert_eq!(connect(fd, &[0u8, 0]), EAFNOSUPPORT);
    // Landlock
    fake::LANDLOCK_DENY.with_borrow_mut(|v| v.push((25, 2)));
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 25)), EACCES);
    // From the bound port; 0.0.0.0 is this host
    let fd = socket(AF_INET, STREAM | NONBLOCK, 0);
    assert_eq!(bind(fd, &sin([0; 4], 5000)), 0);
    assert_eq!(connect(fd, &sin([0; 4], 80)), EINPROGRESS);
    assert!(log_has("tcp_connect [127, 0, 0, 1] 80 Some(5000)"));
    // A listener cannot connect
    let l = socket(AF_INET, STREAM, 0);
    assert_eq!(call(50, [l, 1, 0, 0, 0, 0]), 0);
    assert_eq!(connect(l, &sin([10, 0, 2, 2], 80)), EISCONN);
    // An IPv6 socket's :: is ::1
    let fd = socket(AF_INET6, STREAM | NONBLOCK, 0);
    assert_eq!(connect(fd, &sin6([0; 16], 80)), EINPROGRESS);
    assert!(log_has("tcp_connect [0, 0, 0, 1] 80 None"));
}

#[test]
fn waits_poll_without_a_queue() {
    let _serial = serial();
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    net::with(|n| n.running = false);
    let mut first = true;
    fake::on_wait(move |_| {
        if first {
            first = false;
            let id = last_tcp();
            net::with(|n| n.tcp.get_mut(&id).unwrap().state = TcpState::Established);
        }
    });
    assert_eq!(connect(fd, &sin([10, 0, 2, 2], 80)), 0);
    assert!(fake::wait::LAST_POLLED.get(), "no running server: polled every tick");
    assert!(fake::LAST_DEADLINE.get().is_some());
}

// ------------------------------------------------------------------ TCP I/O

#[test]
fn tcp_send_and_receive() {
    let _serial = serial();
    fake::reset();
    let (fd, id) = connected(false);
    let s = obj(fd);
    assert_eq!(inet::write(&s, b"GET / HTTP/1.0\r\n\r\n"), 18);
    assert_eq!(net::with(|n| n.tcp[&id].sent.clone()), b"GET / HTTP/1.0\r\n\r\n");
    net::with(|n| n.tcp.get_mut(&id).unwrap().rx.extend(b"HTTP/1.0 200 OK".iter().copied()));
    assert_eq!(inet::pending_bytes(&s), 15, "FIONREAD");
    assert_eq!(s.lock().poll_events() & 1, 1);
    let mut buf = [0u8; 8];
    let (n, _) = recvfrom(fd, &mut buf, MSG_PEEK);
    assert_eq!((n, &buf[..]), (8, &b"HTTP/1.0"[..]));
    assert_eq!(inet::read(&s, &mut buf), 8);
    assert_eq!(inet::read(&s, &mut buf), 7);
    assert_eq!(&buf[..7], b" 200 OK");
    // Nothing more: would wait
    assert_eq!(recvfrom(fd, &mut buf, MSG_DONTWAIT).0, EAGAIN);
    // The peer finished: end of file
    net::with(|n| n.tcp.get_mut(&id).unwrap().eof = true);
    assert_eq!(inet::read(&s, &mut buf), 0);
    net::with(|n| {
        n.tcp.get_mut(&id).unwrap().eof = false;
        n.tcp.get_mut(&id).unwrap().state = TcpState::Closed;
    });
    assert_eq!(inet::read(&s, &mut buf), 0, "a closed connection: end of file");
    net::with(|n| n.tcp.get_mut(&id).unwrap().recv_err = Some(ECONNRESET));
    assert_eq!(inet::read(&s, &mut buf), ECONNRESET);
}

#[test]
fn tcp_blocking_receive() {
    let _serial = serial();
    fake::reset();
    let (fd, id) = connected(false);
    let s = obj(fd);
    fake::on_wait(move |_| net::with(|n| n.tcp.get_mut(&id).unwrap().rx.extend(b"late".iter().copied())));
    let mut buf = [0u8; 16];
    assert_eq!(inet::read(&s, &mut buf), 4);
    // SO_RCVTIMEO: EAGAIN when it passes
    fake::reset();
    let (fd, _) = connected(false);
    let tv = [1i64, 0];
    assert_eq!(setsockopt(fd, 1, 20, &bytes(&tv)), 0);
    let start = fake::now_ns();
    assert_eq!(inet::read(&obj(fd), &mut buf), EAGAIN);
    assert_eq!(fake::now_ns(), start + 1_000_000_000);
    // A signal: restarted
    fake::reset();
    let (fd, _) = connected(false);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(inet::read(&obj(fd), &mut buf), -512);
    // Non-blocking socket
    fake::reset();
    let (fd, _) = connected(true);
    assert_eq!(inet::read(&obj(fd), &mut buf), EAGAIN);
}

#[test]
fn tcp_send_in_pieces_and_errors() {
    let _serial = serial();
    fake::reset();
    let (fd, id) = connected(false);
    let s = obj(fd);
    // The server takes 3 bytes per call: a blocking send loops until all is taken
    net::with(|n| n.tcp.get_mut(&id).unwrap().send_cap = Some(3));
    assert_eq!(inet::write(&s, b"0123456789"), 10);
    assert_eq!(net::with(|n| n.tcp[&id].sent.clone()), b"0123456789");
    // Non-blocking: what fits
    assert_eq!(sendto(fd, b"abcdef", MSG_DONTWAIT, None), 3);
    // No room: a blocking send waits for some
    net::with(|n| n.tcp.get_mut(&id).unwrap().send_cap = Some(0));
    assert_eq!(sendto(fd, b"x", MSG_DONTWAIT, None), EAGAIN);
    fake::on_wait(move |_| net::with(|n| n.tcp.get_mut(&id).unwrap().send_cap = Some(100)));
    assert_eq!(inet::write(&s, b"xyz"), 3);
    fake::WAIT_HOOK.with_borrow_mut(|h| *h = None);
    // A broken connection: EPIPE and SIGPIPE, unless MSG_NOSIGNAL
    fake::IDS.set((8, 7));
    net::with(|n| n.tcp.get_mut(&id).unwrap().send_err = Some(EPIPE));
    assert_eq!(inet::write(&s, b"x"), EPIPE);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.clone()), vec![(7, 8, 13)]);
    net::with(|n| n.tcp.get_mut(&id).unwrap().send_err = Some(ECONNRESET));
    assert_eq!(sendto(fd, b"x", MSG_NOSIGNAL, None), EPIPE);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.len()), 1, "no signal with MSG_NOSIGNAL");
    net::with(|n| n.tcp.get_mut(&id).unwrap().send_err = Some(-90));
    assert_eq!(inet::write(&s, b"x"), -90, "other errors as they are");
    // An error after part was sent: the part counts
    net::with(|n| {
        let t = n.tcp.get_mut(&id).unwrap();
        t.send_err = None;
        t.send_script.extend([Ok(2), Err(ECONNRESET)]);
    });
    assert_eq!(inet::write(&s, b"abcd"), 2);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.len()), 1, "no SIGPIPE for a partial send");
    // Unconnected stream socket
    let lone = socket(AF_INET, STREAM, 0);
    assert_eq!(inet::write(&obj(lone), b"x"), ENOTCONN);
    let mut b = [0u8; 4];
    assert_eq!(inet::read(&obj(lone), &mut b), ENOTCONN);
    assert_eq!(obj(lone).lock().poll_events(), 4);
}

#[test]
fn shutdown() {
    let _serial = serial();
    fake::reset();
    let (fd, id) = connected(false);
    assert_eq!(call(48, [fd, 1, 0, 0, 0, 0]), 0);
    assert!(net::with(|n| n.tcp[&id].shut_wr));
    let mut b = [0u8; 4];
    net::with(|n| n.tcp.get_mut(&id).unwrap().rx.extend(b"data".iter().copied()));
    assert_eq!(inet::read(&obj(fd), &mut b), 4, "SHUT_WR leaves reading");
    assert_eq!(call(48, [fd, 0, 0, 0, 0, 0]), 0);
    net::with(|n| n.tcp.get_mut(&id).unwrap().rx.extend(b"more".iter().copied()));
    assert_eq!(inet::read(&obj(fd), &mut b), 0, "SHUT_RD: end of file");
    let (fd2, id2) = connected(false);
    assert_eq!(call(48, [fd2, 2, 0, 0, 0, 0]), 0);
    assert!(net::with(|n| n.tcp[&id2].shut_wr));
    let lone = socket(AF_INET, STREAM, 0);
    assert_eq!(call(48, [lone, 2, 0, 0, 0, 0]), ENOTCONN);
    let u = socket(AF_INET, DGRAM, 0);
    assert_eq!(call(48, [u, 2, 0, 0, 0, 0]), 0);
}

// ------------------------------------------------------------------ bind, listen, accept

#[test]
fn tcp_bind() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    let fd = socket(AF_INET, STREAM, 0);
    assert_eq!(bind(fd, &sin([0; 4], 80)), EACCES, "a privileged port");
    assert_eq!(bind(fd, &sin([192, 168, 1, 1], 8080)), EADDRNOTAVAIL, "not our address");
    assert_eq!(bind(fd, &sin([0, 1, 2, 3], 8080)), EADDRNOTAVAIL, "unreachable: not ours");
    assert_eq!(setsockopt(fd, 1, 2, &int(1)), 0); // SO_REUSEADDR
    assert_eq!(bind(fd, &sin([10, 0, 2, 15], 8080)), 0);
    assert!(log_has("tcp_bind [10, 0, 2, 15] 8080 true false true false"));
    assert_eq!(v4_of(&name(51, fd).unwrap().0), ([10, 0, 2, 15], 8080));
    assert_eq!(bind(fd, &sin([0; 4], 8081)), EINVAL, "bound already");
    assert_eq!(bind(fd, &[0u8, 0]), 0, "AF_UNSPEC: nothing to do");
    fake::CAPS.set(Some(CAP_NET_BIND_SERVICE));
    let fd = socket(AF_INET, STREAM, 0);
    assert_eq!(setsockopt(fd, 1, 15, &int(1)), 0); // SO_REUSEPORT
    assert_eq!(bind(fd, &sin([127, 0, 0, 1], 80)), 0);
    assert!(log_has("tcp_bind [127, 0, 0, 1] 80 false true true false"));
    let fd = socket(AF_INET, STREAM, 0);
    net::with(|n| n.bind_err = Some(-98));
    assert_eq!(bind(fd, &sin([0; 4], 9000)), -98);
    fake::LANDLOCK_DENY.with_borrow_mut(|v| v.push((9001, 1)));
    assert_eq!(bind(fd, &sin([0; 4], 9001)), EACCES);
}

#[test]
fn ipv6_bind_families() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    let fd = socket(AF_INET6, STREAM, 0);
    assert_eq!(bind(fd, &sin6([0; 16], 443)), EACCES, "IPv6 checks the port first");
    assert_eq!(bind(fd, &sin6([0; 16], 8443)), 0);
    assert!(log_has("tcp_bind [0, 0, 0, 0] 8443 false false true true"), "[::] takes IPv4 too");
    let fd = socket(AF_INET6, STREAM, 0);
    assert_eq!(setsockopt(fd, 41, 26, &int(1)), 0);
    assert_eq!(bind(fd, &sin6(mapped([127, 0, 0, 1]), 8444)), EINVAL, "V6ONLY: no mapped address");
    assert_eq!(bind(fd, &sin6([0; 16], 8444)), 0);
    assert!(log_has("tcp_bind [0, 0, 0, 0] 8444 false false false true"));
    assert_eq!(setsockopt(fd, 41, 26, &int(0)), EINVAL, "V6ONLY is fixed once bound");
    let fd = socket(AF_INET6, STREAM, 0);
    assert_eq!(bind(fd, &sin6(v6(1), 8445)), 0);
    assert!(log_has("tcp_bind [0, 0, 0, 1] 8445 false false false true"), "::1: IPv6 only");
    let fd = socket(AF_INET6, STREAM, 0);
    assert_eq!(bind(fd, &sin6(mapped([127, 0, 0, 1]), 8446)), 0);
    assert!(log_has("tcp_bind [127, 0, 0, 1] 8446 false false true false"), "mapped: IPv4 only");
    let mut global = [0u8; 16];
    global[0] = 0x20;
    let fd = socket(AF_INET6, STREAM, 0);
    assert_eq!(bind(fd, &sin6(global, 8447)), EADDRNOTAVAIL);
    assert_eq!(bind(fd, &[10u8, 0, 0]), EINVAL, "too short for sockaddr_in6");
}

#[test]
fn udp_bind() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    // The endpoint opened at creation moves to the port
    assert_eq!(bind(u, &sin([0; 4], 5353)), 0);
    assert!(log_has(&format!("udp_rebind {id} 5353")));
    assert_eq!(v4_of(&name(51, u).unwrap().0).1, 5353);
    assert_eq!(bind(u, &sin([0; 4], 5354)), EINVAL, "bound for good");
    // Used to send: bound for good too
    let u2 = socket(AF_INET, DGRAM, 0);
    assert_eq!(sendto(u2, b"x", 0, Some(&sin([10, 0, 2, 3], 53))), 1);
    assert_eq!(bind(u2, &sin([0; 4], 5355)), EINVAL);
    let u3 = socket(AF_INET, DGRAM, 0);
    net::with(|n| n.rebind_err = Some(-98));
    assert_eq!(bind(u3, &sin([0; 4], 5356)), -98);
    // No endpoint yet (its creation failed): opened on the port
    net::with(|n| n.udp_open_err = Some(-12));
    let u4 = socket(AF_INET, DGRAM, 0);
    assert_eq!(bind(u4, &sin([127, 0, 0, 1], 5357)), 0);
    assert!(log_has("udp_open 5357"));
    assert_eq!(v4_of(&name(51, u4).unwrap().0), ([127, 0, 0, 1], 5357));
    net::with(|n| n.udp_open_err = Some(-12));
    let u5 = socket(AF_INET, DGRAM, 0);
    net::with(|n| n.udp_open_err = Some(-98));
    assert_eq!(bind(u5, &sin([0; 4], 5358)), -98);
}

#[test]
fn listen_and_backlogs() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    assert_eq!(call(50, [u, 5, 0, 0, 0, 0]), EOPNOTSUPP);
    let (c, _) = connected(false);
    assert_eq!(call(50, [c, 5, 0, 0, 0, 0]), EINVAL, "connected");
    let l = socket(AF_INET, STREAM, 0);
    assert_eq!(call(50, [l, -1i64 as u64, 0, 0, 0, 0]), 0);
    assert!(net::with(|n| n.log.iter().any(|x| x.starts_with("tcp_bind [0, 0, 0, 0] 0 "))), "bound automatically");
    assert!(net::with(|n| n.log.iter().any(|x| x.starts_with("tcp_listen ") && x.ends_with(" 4096"))), "negative: the cap");
    let lid = net::with(|n| *n.listeners.keys().last().unwrap());
    assert_eq!(call(50, [l, 10_000, 0, 0, 0, 0]), 0);
    assert!(log_has(&format!("tcp_set_backlog {lid} 4096")));
    assert_eq!(call(50, [l, 7, 0, 0, 0, 0]), 0);
    assert!(log_has(&format!("tcp_set_backlog {lid} 7")));
    assert_eq!(getsockopt(l, 1, 30).unwrap(), int(1).to_vec(), "SO_ACCEPTCONN");
    // After an explicit bind, that reservation listens
    let b = socket(AF_INET, STREAM, 0);
    assert_eq!(bind(b, &sin([0; 4], 7070)), 0);
    let bid = net::with(|n| *n.binds.keys().last().unwrap());
    assert_eq!(call(50, [b, 3, 0, 0, 0, 0]), 0);
    assert!(log_has(&format!("tcp_listen {bid} 3")));
    // Failures
    let f = socket(AF_INET, STREAM, 0);
    net::with(|n| n.bind_err = Some(-98));
    assert_eq!(call(50, [f, 1, 0, 0, 0, 0]), -98);
    net::with(|n| n.listen_err = Some(-12));
    assert_eq!(call(50, [f, 1, 0, 0, 0, 0]), -12);
    assert_eq!(bind(l, &sin([0; 4], 7071)), EINVAL, "a listener cannot bind again");
}

#[test]
fn accept_connections() {
    let _serial = serial();
    fake::reset();
    let l = socket(AF_INET, STREAM | NONBLOCK, 0);
    assert_eq!(call(43, [l, 0, 0, 0, 0, 0]), EINVAL, "not listening");
    assert_eq!(call(50, [l, 8, 0, 0, 0, 0]), 0);
    let lid = net::with(|n| *n.listeners.keys().last().unwrap());
    assert_eq!(call(288, [l, 0, 0, 1, 0, 0]), EINVAL, "unknown accept4 flag");
    assert_eq!(call(43, [l, 0, 0, 0, 0, 0]), EAGAIN);
    assert_eq!(obj(l).lock().poll_events(), 0);
    // Options are inherited
    assert_eq!(setsockopt(l, 6, 1, &int(1)), 0); // TCP_NODELAY
    let cid = net::incoming(lid, Tcp { endpoints: Some((8080, [10, 0, 2, 2], 51000)), local_ip: Some([10, 0, 2, 15]), ..Default::default() });
    assert_eq!(obj(l).lock().poll_events(), 1, "readable: a connection waits");
    fake::EUID.set(1000);
    let mut sa = [0u8; 16];
    let mut len = 16u32;
    let c = call(288, [l, mptr(&mut sa), mptr(&mut len), NONBLOCK | CLOEXEC, 0, 0]);
    assert!(c >= 3);
    assert_eq!(v4_of(&sa), ([10, 0, 2, 2], 51000));
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(c as usize)));
    let conn = obj(c as u64);
    assert!(conn.lock().nonblock);
    assert_eq!(getsockopt(c as u64, 6, 1).unwrap(), int(1).to_vec());
    assert_eq!(v4_of(&name(51, c as u64).unwrap().0), ([10, 0, 2, 15], 8080));
    assert_eq!(v4_of(&name(52, c as u64).unwrap().0), ([10, 0, 2, 2], 51000));
    // The connection shows in /proc/net/tcp with its owner
    let tcp = inet::proc_net("tcp").unwrap();
    assert!(tcp.lines().any(|l| l.contains(&format!("{:08X}:{:04X} 01 ", u32::from_le_bytes([10, 0, 2, 2]), 51000)) && l.contains(" 1000 ")), "{tcp}");
    let _ = cid;
    // A blocking accept waits
    obj(l).lock().nonblock = false;
    fake::on_wait(move |_| {
        net::incoming(lid, Tcp::default());
    });
    assert!(call(43, [l, 0, 0, 0, 0, 0]) >= 3);
    // Writing the address can fault
    net::incoming(lid, Tcp::default());
    let mut bad = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad), 16);
    let mut len = 16u32;
    assert_eq!(call(43, [l, mptr(&mut bad), mptr(&mut len), 0, 0, 0]), EFAULT);
    // A full table
    net::incoming(lid, Tcp::default());
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(call(43, [l, 0, 0, 0, 0, 0]), EMFILE);
}

#[test]
fn accept_on_ipv6_reports_mapped_peers() {
    let _serial = serial();
    fake::reset();
    let l = socket(AF_INET6, STREAM, 0);
    assert_eq!(call(50, [l, 8, 0, 0, 0, 0]), 0);
    let lid = net::with(|n| *n.listeners.keys().last().unwrap());
    net::incoming(lid, Tcp { endpoints: Some((80, [10, 0, 2, 2], 4000)), ..Default::default() });
    let mut sa = [0u8; 28];
    let mut len = 28u32;
    assert!(call(43, [l, mptr(&mut sa), mptr(&mut len), 0, 0, 0]) >= 3);
    assert_eq!(len, 28);
    assert_eq!(&sa[8..24], &mapped([10, 0, 2, 2]));
}

// ------------------------------------------------------------------ UDP

#[test]
fn udp_datagrams() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    assert_eq!(sendto(u, b"query", 0, None), EDESTADDRREQ);
    assert_eq!(sendto(u, b"query", 0, Some(&sin([10, 0, 2, 3], 53))), 5);
    assert_eq!(net::with(|n| n.udp[&id].sent.clone()), vec![([10, 0, 2, 3], 53, b"query".to_vec())]);
    // Connected: the default destination
    assert_eq!(connect(u, &sin([10, 0, 2, 3], 53)), 0);
    assert_eq!(inet::write(&obj(u), b"q2"), 2);
    // Errors from the server
    net::with(|n| n.udp.get_mut(&id).unwrap().send_err = Some(-90));
    assert_eq!(inet::write(&obj(u), b"q3"), -90);
    // Receive, with the source address
    assert_eq!(obj(u).lock().poll_events(), 4);
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([10, 0, 2, 3], 53, b"answer".to_vec(), 5_000_000_123)));
    assert_eq!(obj(u).lock().poll_events(), 5);
    assert_eq!(inet::pending_bytes(&obj(u)), 6);
    let mut buf = [0u8; 4];
    let (n, sa) = recvfrom(u, &mut buf, 0);
    assert_eq!(n, 4, "truncated to the buffer");
    assert_eq!(v4_of(&sa), ([10, 0, 2, 3], 53));
    assert_eq!(inet::pending_bytes(&obj(u)), 0, "the rest of the datagram is gone");
    // SIOCGSTAMP / SIOCGSTAMPNS: when it arrived
    let mut ts = [0u64; 2];
    assert_eq!(inet::stamp_ioctl(&obj(u), 0x8906, mptr(&mut ts)), 0);
    assert_eq!(ts, [5, 0]);
    assert_eq!(inet::stamp_ioctl(&obj(u), 0x8907, mptr(&mut ts)), 0);
    assert_eq!(ts, [5, 123]);
    fake::bad_ptr(mptr(&mut ts), 16);
    assert_eq!(inet::stamp_ioctl(&obj(u), 0x8906, mptr(&mut ts)), EFAULT);
    let fresh = socket(AF_INET, DGRAM, 0);
    assert_eq!(inet::stamp_ioctl(&obj(fresh), 0x8906, 0), ENOENT, "nothing received yet");
    // Nothing left: would wait
    assert_eq!(recvfrom(u, &mut buf, MSG_DONTWAIT).0, EAGAIN);
    // The endpoint died with the server
    net::with(|n| n.dead.insert(id));
    assert_eq!(recvfrom(u, &mut buf, 0).0, ENETDOWN);
    // recvfrom faults on the buffer
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([1, 1, 1, 1], 1, b"x".to_vec(), 0)));
    let mut bad = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad), 4);
    assert_eq!(call(45, [u, mptr(&mut bad), 4, 0, 0, 0]), EFAULT);
    assert_eq!(sendto(u, &bad, 0, None), EFAULT);
    assert_eq!(sendto(u, b"x", 0, Some(&[2u8])), EINVAL, "a bad destination");
}

#[test]
fn udp_names_and_queues() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    let port = net::udp_port(id);
    assert_eq!(v4_of(&name(51, u).unwrap().0), ([10, 0, 2, 15], port), "unbound: the interface address");
    assert_eq!(name(52, u), Err(ENOTCONN));
    assert!(obj(u).lock().wait_queue().is_some());
    // An endpoint without a queue yet is opened to be polled
    net::with(|n| n.udp_open_err = Some(-12));
    let v = socket(AF_INET, DGRAM, 0);
    assert!(obj(v).lock().wait_queue().is_some(), "opened now");
    // TCP: none before connecting
    let t = socket(AF_INET, STREAM, 0);
    assert!(obj(t).lock().wait_queue().is_none());
    let lone = name(51, t).unwrap();
    assert_eq!(v4_of(&lone.0), ([0; 4], 0));
    assert_eq!(inet::pending_bytes(&obj(t)), 0);
}

// ------------------------------------------------------------------ ICMP

#[test]
fn ping_sockets() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    let p = socket(AF_INET, DGRAM, 1);
    let id = last_icmp();
    assert_eq!(sendto(p, b"echo", 0, None), EDESTADDRREQ);
    assert_eq!(sendto(p, b"echo", 0, Some(&sin([10, 0, 2, 2], 0))), 4);
    assert_eq!(connect(p, &sin([10, 0, 2, 3], 0)), 0);
    assert_eq!(inet::write(&obj(p), b"e2"), 2);
    assert_eq!(net::with(|n| n.icmp[&id].sent.clone()), vec![([10, 0, 2, 2], b"echo".to_vec()), ([10, 0, 2, 3], b"e2".to_vec())]);
    net::with(|n| n.icmp_send_err = Some(-1));
    assert_eq!(inet::write(&obj(p), b"e3"), -1);
    // bind: our address, the "port" is the echo identifier
    assert_eq!(bind(p, &sin([192, 168, 9, 9], 7)), EADDRNOTAVAIL);
    assert_eq!(bind(p, &sin([10, 0, 2, 15], 777)), 0);
    assert_eq!(v4_of(&name(51, p).unwrap().0), ([10, 0, 2, 15], 777));
    net::with(|n| n.ident_err = Some(-98));
    assert_eq!(bind(p, &sin([0; 4], 778)), -98);
    // Receive: the source, the arrival time
    net::with(|n| n.icmp.get_mut(&id).unwrap().rx.push_back(([10, 0, 2, 2], b"reply!".to_vec(), 7_000_000_000)));
    assert_eq!(obj(p).lock().poll_events(), 5);
    let mut buf = [0u8; 16];
    let (n, sa) = recvfrom(p, &mut buf, 0);
    assert_eq!((n, &buf[..6]), (6, &b"reply!"[..]));
    assert_eq!(v4_of(&sa), ([10, 0, 2, 2], 0));
    let mut ts = [0u64; 2];
    assert_eq!(inet::stamp_ioctl(&obj(p), 0x8906, mptr(&mut ts)), 0);
    assert_eq!(ts[0], 7);
    assert_eq!(recvfrom(p, &mut buf, MSG_DONTWAIT).0, EAGAIN);
    net::with(|n| n.dead.insert(id));
    assert_eq!(recvfrom(p, &mut buf, 0).0, ENETDOWN);
    assert!(obj(p).lock().wait_queue().is_some());
    // ICMP_FILTER is for raw sockets
    assert_eq!(setsockopt(p, 255, 1, &int(0)), ENOPROTOOPT);
    assert_eq!(getsockopt(p, 1, 38).unwrap(), int(1).to_vec(), "SO_PROTOCOL: ICMP");
}

#[test]
fn raw_sockets_and_icmp_filters() {
    let _serial = serial();
    fake::reset();
    fake::CAPS.set(Some(CAP_NET_RAW));
    let r = socket(AF_INET, RAW, 1);
    let id = last_icmp();
    assert_eq!(v4_of(&name(51, r).unwrap().0).1, 1, "a raw socket's port: its protocol");
    assert_eq!(getsockopt(r, 255, 1).unwrap(), vec![0; 4], "no filter yet");
    assert_eq!(setsockopt(r, 255, 1, &[1, 2]), EINVAL, "too short");
    // Block echo requests (type 8)
    assert_eq!(setsockopt(r, 255, 1, &(1u32 << 8).to_le_bytes()), 0);
    assert_eq!(getsockopt(r, 255, 1).unwrap(), (1u32 << 8).to_le_bytes().to_vec());
    let ip_icmp = |ty: u8| {
        let mut d = vec![0x45u8; 20];
        d.extend([ty, 0, 0, 0]);
        d
    };
    net::with(|n| {
        let q = &mut n.icmp.get_mut(&id).unwrap().rx;
        q.push_back(([1, 1, 1, 1], ip_icmp(8), 0));
        q.push_back(([1, 1, 1, 1], ip_icmp(0), 0));
    });
    let mut buf = [0u8; 64];
    // A peek sees the filtered message (as it stands in the queue)
    let (n, _) = recvfrom(r, &mut buf, MSG_PEEK);
    assert_eq!((n, buf[20]), (24, 8));
    let (n, _) = recvfrom(r, &mut buf, 0);
    assert_eq!((n, buf[20]), (24, 0), "the echo request was dropped");
    assert_eq!(bind(r, &sin([127, 0, 0, 1], 99)), 0, "a raw socket's port is ignored");
    // IPv6: ICMP6_FILTER, 256 bits
    let r6 = socket(AF_INET6, RAW, 58);
    let id6 = last_icmp();
    assert_eq!(v4_of(&{ let mut s = name(51, r6).unwrap().0; s[0] = 2; s }).1, 58);
    assert_eq!(getsockopt(r6, 58, 1).unwrap(), vec![0; 32]);
    assert_eq!(setsockopt(r6, 58, 1, &[0u8; 8]), EINVAL);
    let mut f = [0u8; 32];
    f[128 / 8] = 1; // block type 128 (echo request)
    assert_eq!(setsockopt(r6, 58, 1, &f), 0);
    net::with(|n| {
        let q = &mut n.icmp.get_mut(&id6).unwrap().rx;
        q.push_back(([0, 0, 0, 1], vec![128, 0, 0, 0], 0));
        q.push_back(([0, 0, 0, 1], vec![129, 0, 0, 0], 0));
    });
    let (n, sa) = recvfrom(r6, &mut buf, 0);
    assert_eq!((n, buf[0]), (4, 129));
    assert_eq!(&sa[8..24], &v6(1));
}

// ------------------------------------------------------------------ options

#[test]
fn socket_option_calls() {
    let _serial = serial();
    fake::reset();
    let fd = socket(AF_INET, STREAM, 0);
    assert_eq!(call(54, [fd, 1, 2, 0, -1i64 as u64, 0]), EINVAL, "negative length");
    assert_eq!(call(54, [fd, 1, 2, 0, 4, 0]), EFAULT);
    assert_eq!(setsockopt(fd, 1, 7, &int(10_000)), 0);
    assert_eq!(getsockopt(fd, 1, 7).unwrap(), int(20_000).to_vec(), "doubled, as Linux");
    assert_eq!(getsockopt(fd, 1, 3).unwrap(), int(1).to_vec(), "SO_TYPE: stream");
    assert_eq!(getsockopt(fd, 99, 1), Err(ENOPROTOOPT));
    // At most *optlen bytes
    let mut v = [0xffu8; 8];
    let mut len = 2u32;
    assert_eq!(call(55, [fd, 1, 3, mptr(&mut v), mptr(&mut len), 0]), 0);
    assert_eq!((len, &v[..3]), (2, &[1, 0, 0xff][..]));
    let mut neg = -1i32;
    assert_eq!(call(55, [fd, 1, 3, mptr(&mut v), mptr(&mut neg), 0]), EINVAL);
    let mut bad_len = 4u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(55, [fd, 1, 3, mptr(&mut v), mptr(&mut bad_len), 0]), EFAULT);
    let mut bad_v = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad_v), 4);
    let mut len = 4u32;
    assert_eq!(call(55, [fd, 1, 3, mptr(&mut bad_v), mptr(&mut len), 0]), EFAULT);
    // V6ONLY can change until the socket is bound or used
    let u6 = socket(AF_INET6, DGRAM, 0);
    assert_eq!(setsockopt(u6, 41, 26, &int(1)), 0);
    assert_eq!(sendto(u6, b"x", 0, Some(&sin6(v6(1), 9))), 1);
    assert_eq!(setsockopt(u6, 41, 26, &int(0)), EINVAL);
    // TCP_INFO's state of each connection state
    let (c, id) = connected(false);
    for (st, num) in [
        (TcpState::Established, 1u8),
        (TcpState::SynReceived, 3),
        (TcpState::FinWait1, 4),
        (TcpState::FinWait2, 5),
        (TcpState::TimeWait, 6),
        (TcpState::Closed, 7),
        (TcpState::CloseWait, 8),
        (TcpState::LastAck, 9),
        (TcpState::Closing, 11),
    ] {
        net::with(|n| n.tcp.get_mut(&id).unwrap().state = st);
        assert_eq!(getsockopt(c, 6, 11).unwrap()[0], num, "{st:?}");
    }
}

// ------------------------------------------------------------------ sendmsg / recvmsg

#[repr(C)]
#[derive(Default)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _pad: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad2: u32,
}

/// `struct mmsghdr`.
#[repr(C)]
#[derive(Default)]
struct MMsgHdr {
    hdr: MsgHdr,
    len: u32,
    _pad: u32,
}

#[test]
fn sendmsg_gathers_iovecs() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    let dest = sin([0; 4], 9999);
    let (a, b) = (*b"hello ", *b"world");
    let iov = [(ptr(&a), 6u64), (ptr(&b), 5u64)];
    let msg = MsgHdr { name: ptr(&dest), namelen: 16, iov: ptr(&iov), iovlen: 2, ..Default::default() };
    assert_eq!(call(46, [u, ptr(&msg), 0, 0, 0, 0]), 11);
    assert_eq!(net::with(|n| n.udp[&id].sent[0].clone()), ([127, 0, 0, 1], 9999, b"hello world".to_vec()));
    // Errors: header, sockaddr, iovec array, a buffer, too many iovecs
    let mut gone = [0u8; 56];
    fake::bad_ptr(mptr(&mut gone), 56);
    assert_eq!(call(46, [u, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    let bad_name = MsgHdr { name: ptr(&dest), namelen: 1, ..Default::default() };
    assert_eq!(call(46, [u, ptr(&bad_name), 0, 0, 0, 0]), EINVAL);
    let many = MsgHdr { iov: ptr(&iov), iovlen: 1025, ..Default::default() };
    assert_eq!(call(46, [u, ptr(&many), 0, 0, 0, 0]), EINVAL);
    let mut bad_buf = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad_buf), 4);
    let iov2 = [(mptr(&mut bad_buf), 4u64)];
    let m2 = MsgHdr { name: ptr(&dest), namelen: 16, iov: ptr(&iov2), iovlen: 1, ..Default::default() };
    assert_eq!(call(46, [u, ptr(&m2), 0, 0, 0, 0]), EFAULT);
}

#[test]
fn recvmsg_scatters_and_reports() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([10, 0, 2, 3], 53, b"0123456789".to_vec(), 3_000_456_789)));
    let (mut a, mut b) = ([0u8; 4], [0u8; 4]);
    let iov = [(mptr(&mut a), 4u64), (mptr(&mut b), 4u64)];
    let mut sa = [0u8; 16];
    let mut msg = MsgHdr { name: mptr(&mut sa), namelen: 16, iov: ptr(&iov), iovlen: 2, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut msg), 0, 0, 0, 0]), 8);
    assert_eq!((&a, &b), (b"0123", b"4567"));
    assert_eq!(msg.flags, 0x20, "MSG_TRUNC");
    assert_eq!(msg.namelen, 16);
    assert_eq!(v4_of(&sa), ([10, 0, 2, 3], 53));
    assert_eq!(msg.controllen, 0);
    // Without a name buffer: msg_namelen 0
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([10, 0, 2, 3], 53, b"ab".to_vec(), 0)));
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 2, namelen: 77, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut msg), 0, 0, 0, 0]), 2);
    assert_eq!((msg.namelen, msg.flags), (0, 0));
    // Errors
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 2, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut msg), MSG_DONTWAIT, 0, 0, 0]), EAGAIN);
    let mut gone = [0u8; 56];
    fake::bad_ptr(mptr(&mut gone), 56);
    assert_eq!(call(47, [u, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    let mut many = MsgHdr { iov: ptr(&iov), iovlen: 2000, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut many), 0, 0, 0, 0]), EINVAL);
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([10, 0, 2, 3], 53, b"zz".to_vec(), 0)));
    let mut bad = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad), 4);
    let iov3 = [(mptr(&mut bad), 4u64)];
    let mut m3 = MsgHdr { iov: ptr(&iov3), iovlen: 1, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut m3), 0, 0, 0, 0]), EFAULT);
}

#[test]
fn recvmsg_control_messages() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    assert_eq!(setsockopt(u, 1, 29, &int(1)), 0); // SO_TIMESTAMP
    assert_eq!(setsockopt(u, 0, 12, &int(1)), 0); // IP_RECVTTL
    let push = |d: &[u8]| net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([1, 2, 3, 4], 5, d.to_vec(), 3_000_456_789)));
    let mut data = [0u8; 16];
    let iov = [(mptr(&mut data), 16u64)];
    let mut control = [0u8; 64];
    push(b"a");
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 64, ..Default::default() };
    assert_eq!(call(47, [u, mptr(&mut msg), 0, 0, 0, 0]), 1);
    assert_eq!(msg.controllen, 56, "a timeval and a TTL");
    let q = |o: usize| u64::from_le_bytes(control[o..o + 8].try_into().unwrap());
    let d = |o: usize| u32::from_le_bytes(control[o..o + 4].try_into().unwrap());
    assert_eq!((q(0), d(8), d(12), q(16), q(24)), (32, 1, 29, 3, 456_789 / 1000), "SCM_TIMESTAMP");
    assert_eq!((q(32), d(40), d(44), d(48)), (20, 0, 2, 64), "IP_TTL 64");
    // SO_TIMESTAMPNS: a timespec
    assert_eq!(setsockopt(u, 1, 35, &int(1)), 0);
    push(b"b");
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 64, ..Default::default() };
    call(47, [u, mptr(&mut msg), 0, 0, 0, 0]);
    let q = |o: usize| u64::from_le_bytes(control[o..o + 8].try_into().unwrap());
    let d = |o: usize| u32::from_le_bytes(control[o..o + 4].try_into().unwrap());
    assert_eq!((d(12), q(24)), (35, 456_789));
    // Too little room: only what fits
    push(b"c");
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 40, ..Default::default() };
    call(47, [u, mptr(&mut msg), 0, 0, 0, 0]);
    assert_eq!(msg.controllen, 32, "the timestamp only");
    push(b"d");
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 24, ..Default::default() };
    call(47, [u, mptr(&mut msg), 0, 0, 0, 0]);
    assert_eq!(msg.controllen, 24, "no room for the timestamp: the TTL");
    // IPv6: IPV6_HOPLIMIT
    let u6 = socket(AF_INET6, DGRAM, 0);
    let id6 = last_udp();
    assert_eq!(setsockopt(u6, 41, 51, &int(1)), 0); // IPV6_RECVHOPLIMIT
    net::with(|n| n.udp.get_mut(&id6).unwrap().rx.push_back(([0, 0, 0, 1], 5, b"e".to_vec(), 0)));
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 64, ..Default::default() };
    call(47, [u6, mptr(&mut msg), 0, 0, 0, 0]);
    assert_eq!(msg.controllen, 24);
    let d = |o: usize| u32::from_le_bytes(control[o..o + 4].try_into().unwrap());
    assert_eq!((d(8), d(12)), (41, 52));
    // Stream sockets get none
    let (c, cid) = connected(false);
    assert_eq!(setsockopt(c, 1, 29, &int(1)), 0);
    net::with(|n| n.tcp.get_mut(&cid).unwrap().rx.extend(b"tcp".iter().copied()));
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: mptr(&mut control), controllen: 64, ..Default::default() };
    assert_eq!(call(47, [c, mptr(&mut msg), 0, 0, 0, 0]), 3);
    assert_eq!(msg.controllen, 0);
}

#[test]
fn sendmmsg_and_recvmmsg() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    let dest = sin([10, 0, 2, 3], 53);
    let (a, b) = (*b"one", *b"three");
    let iova = [(ptr(&a), 3u64)];
    let iovb = [(ptr(&b), 5u64)];
    let mut v = [
        MMsgHdr { hdr: MsgHdr { name: ptr(&dest), namelen: 16, iov: ptr(&iova), iovlen: 1, ..Default::default() }, ..Default::default() },
        MMsgHdr { hdr: MsgHdr { name: ptr(&dest), namelen: 16, iov: ptr(&iovb), iovlen: 1, ..Default::default() }, ..Default::default() },
        MMsgHdr { hdr: MsgHdr { name: 0, iov: ptr(&iovb), iovlen: 1, ..Default::default() }, ..Default::default() },
    ];
    assert_eq!(call(307, [u, mptr(&mut v[0]), 3, 0, 0, 0]), 2, "the third has no destination");
    assert_eq!((v[0].len, v[1].len), (3, 5));
    assert_eq!(call(307, [u, mptr(&mut v[2]), 1, 0, 0, 0]), EDESTADDRREQ, "the first fails: its error");
    // recvmmsg: what is there, without waiting after the first
    net::with(|n| {
        let q = &mut n.udp.get_mut(&id).unwrap().rx;
        q.push_back(([1, 1, 1, 1], 1, b"r1".to_vec(), 0));
        q.push_back(([1, 1, 1, 1], 1, b"r22".to_vec(), 0));
    });
    let mut bufs = [[0u8; 8]; 3];
    let iovs: Vec<[(u64, u64); 1]> = bufs.iter_mut().map(|b| [(b.as_mut_ptr() as u64, 8u64)]).collect();
    let mut r: Vec<MMsgHdr> = iovs.iter().map(|i| MMsgHdr { hdr: MsgHdr { iov: ptr(&i[0]), iovlen: 1, ..Default::default() }, ..Default::default() }).collect();
    assert_eq!(call(299, [u, mptr(&mut r[0]), 3, 0, 0, 0]), 2);
    assert_eq!((r[0].len, r[1].len), (2, 3));
    assert_eq!(&bufs[1][..3], b"r22");
    assert_eq!(call(299, [u, mptr(&mut r[0]), 3, MSG_DONTWAIT, 0, 0]), EAGAIN);
}

// ------------------------------------------------------------------ /proc/net

#[test]
fn proc_net_tables() {
    let _serial = serial();
    fake::reset();
    net::eth_up();
    assert_eq!(inet::proc_net("raw"), None);
    let header = inet::proc_net("tcp").unwrap();
    assert_eq!(header.lines().next().unwrap().len(), 149, "fixed-width rows");
    fake::EUID.set(33);
    let l = socket(AF_INET, STREAM, 0);
    assert_eq!(bind(l, &sin([0; 4], 8080)), 0);
    assert_eq!(call(50, [l, 16, 0, 0, 0, 0]), 0);
    let l6 = socket(AF_INET6, STREAM, 0);
    assert_eq!(bind(l6, &sin6(v6(1), 8081)), 0);
    assert_eq!(call(50, [l6, 16, 0, 0, 0, 0]), 0);
    let (_c, id) = connected(false);
    net::with(|n| n.tcp.get_mut(&id).unwrap().state = TcpState::TimeWait);
    let tcp = inet::proc_net("tcp").unwrap();
    let rows: Vec<&str> = tcp.lines().skip(1).collect();
    assert!(rows.iter().any(|r| r.contains("00000000:1F90 00000000:0000 0A ") && r.contains("   33 ")), "the listener: {tcp}");
    assert!(rows.iter().any(|r| r.contains(" 06 ")), "TIME_WAIT");
    assert!(!rows.iter().any(|r| r.contains(":1F91")), "IPv6 sockets are in tcp6");
    let tcp6 = inet::proc_net("tcp6").unwrap();
    assert!(tcp6.contains("00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A"), "{tcp6}");
    // UDP: bound address and peer
    let u = socket(AF_INET, DGRAM, 0);
    assert_eq!(bind(u, &sin([127, 0, 0, 1], 5353)), 0);
    let u2 = socket(AF_INET, DGRAM, 0);
    assert_eq!(connect(u2, &sin([10, 0, 2, 3], 53)), 0);
    let udp = inet::proc_net("udp").unwrap();
    assert_eq!(udp.lines().next().unwrap().len(), 127);
    assert!(udp.contains("0100007F:14E9 00000000:0000 07 "), "{udp}");
    assert!(udp.contains(&format!("{:08X}:0035 01 ", u32::from_le_bytes([10, 0, 2, 3]))), "connected: state 1");
    let u6 = socket(AF_INET6, DGRAM, 0);
    assert_eq!(connect(u6, &sin6(mapped([10, 0, 2, 3]), 53)), 0);
    let ll6 = socket(AF_INET6, DGRAM, 0);
    assert_eq!(connect(ll6, &sin6(net::link_local6().unwrap(), 53)), 0);
    let udp6 = inet::proc_net("udp6").unwrap();
    assert!(udp6.contains("0000000000000000FFFF0000"), "a mapped peer: {udp6}");
    assert!(udp6.contains("000080FE00000000"), "the link-local peer");
    // A network namespace of its own: headers only
    fake::NET_ISOLATED.set(true);
    assert_eq!(inet::proc_net("tcp").unwrap().lines().count(), 1);
    assert_eq!(inet::proc_net("udp").unwrap().lines().count(), 1);
    let dev = inet::proc_net("dev").unwrap();
    assert_eq!(dev.lines().count(), 3, "lo only");
    assert!(dev.lines().nth(2).unwrap().trim_start().starts_with("lo:       0"));
}

#[test]
fn proc_net_tcp_states() {
    let _serial = serial();
    fake::reset();
    let (_c, id) = connected(false);
    for (st, num) in [
        (TcpState::Established, "01"),
        (TcpState::SynSent, "02"),
        (TcpState::SynReceived, "03"),
        (TcpState::FinWait1, "04"),
        (TcpState::FinWait2, "05"),
        (TcpState::TimeWait, "06"),
        (TcpState::Closed, "07"),
        (TcpState::CloseWait, "08"),
        (TcpState::LastAck, "09"),
        (TcpState::Closing, "0B"),
    ] {
        net::with(|n| n.tcp.get_mut(&id).unwrap().state = st);
        let tcp = inet::proc_net("tcp").unwrap();
        let row = tcp.lines().nth(1).unwrap();
        assert_eq!(row.split_whitespace().nth(3), Some(num), "{st:?}: {row}");
    }
}

#[test]
fn mmsg_all_succeed_and_unopenable_endpoints() {
    let _serial = serial();
    fake::reset();
    let u = socket(AF_INET, DGRAM, 0);
    let id = last_udp();
    let dest = sin([10, 0, 2, 3], 53);
    let a = *b"one";
    let iova = [(ptr(&a), 3u64)];
    let mut v = [MMsgHdr { hdr: MsgHdr { name: ptr(&dest), namelen: 16, iov: ptr(&iova), iovlen: 1, ..Default::default() }, ..Default::default() }];
    assert_eq!(call(307, [u, mptr(&mut v[0]), 1, 0, 0, 0]), 1);
    net::with(|n| n.udp.get_mut(&id).unwrap().rx.push_back(([1, 1, 1, 1], 1, b"r".to_vec(), 0)));
    let mut b = [0u8; 4];
    let iovb = [(mptr(&mut b), 4u64)];
    let mut r = [MMsgHdr { hdr: MsgHdr { iov: ptr(&iovb), iovlen: 1, ..Default::default() }, ..Default::default() }];
    assert_eq!(call(299, [u, mptr(&mut r[0]), 1, 0, 0, 0]), 1);
    assert_eq!(r[0].len, 1);
    // A UDP socket whose endpoint cannot be opened: sending and receiving fail
    net::with(|n| n.udp_open_err = Some(-12));
    let w = socket(AF_INET, DGRAM, 0);
    net::with(|n| n.udp_open_err = Some(-12));
    assert_eq!(sendto(w, b"x", 0, Some(&dest)), -12);
    net::with(|n| n.udp_open_err = Some(-12));
    assert_eq!(recvfrom(w, &mut b, 0).0, -12);
    // An IPv6 bind whose address cannot be read
    let s6 = socket(AF_INET6, STREAM, 0);
    let mut bad = [0u8; 28];
    fake::bad_ptr(mptr(&mut bad), 28);
    assert_eq!(call(49, [s6, mptr(&mut bad), 28, 0, 0, 0]), EFAULT);
}

#[test]
fn proc_net_dev() {
    let _serial = serial();
    fake::reset();
    net::with(|n| n.counters = [((100, 2), (100, 2)), ((5000, 40), (600, 7))]);
    let dev = inet::proc_net("dev").unwrap();
    assert_eq!(dev.lines().count(), 3, "no card: lo only");
    net::eth_up();
    net::with(|n| n.counters = [((100, 2), (100, 2)), ((5000, 40), (600, 7))]);
    let dev = inet::proc_net("dev").unwrap();
    let eth = dev.lines().nth(3).unwrap();
    let f: Vec<&str> = eth.split_whitespace().collect();
    assert_eq!((f[0], f[1], f[2], f[9], f[10]), ("eth0:", "5000", "40", "600", "7"));
}
