//! Routing netlink sockets (`src/compat/linux/rtnetlink.rs`): link, address and route dumps
//! built from the interface net-server reports, the refusals of configuration changes, the
//! socket calls glibc and Chromium make, the `/proc/net` tables and the `SIOCGIF*` ioctls.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::rtnetlink::{interface_ioctl, proc_net_text, socket};
use hydra_hosttests_t27::fake::net;
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::Arc;

const EPERM: i32 = -1;
const ENODEV: i64 = -19;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i32 = -95;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
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

fn open(flags: u64) -> Arc<dyn CharDevice> {
    let fd = socket(3 | flags);
    assert!(fd >= 3);
    match fake::fd::get(fd) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("not a device"),
    }
}

/// A request: header and body.
fn request(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    m.extend_from_slice(&ty.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(body);
    while m.len() % 4 != 0 {
        m.push(0);
    }
    m
}

struct Msg {
    ty: u16,
    flags: u16,
    seq: u32,
    port: u32,
    body: Vec<u8>,
}

fn parse(d: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= d.len() {
        let len = u32::from_le_bytes(d[off..off + 4].try_into().unwrap()) as usize;
        assert!(len >= 16 && off + len <= d.len(), "well-formed");
        out.push(Msg {
            ty: u16::from_le_bytes([d[off + 4], d[off + 5]]),
            flags: u16::from_le_bytes([d[off + 6], d[off + 7]]),
            seq: u32::from_le_bytes(d[off + 8..off + 12].try_into().unwrap()),
            port: u32::from_le_bytes(d[off + 12..off + 16].try_into().unwrap()),
            body: d[off + 16..off + len].to_vec(),
        });
        off += (len + 3) & !3;
    }
    assert_eq!(off, d.len(), "padded to 4 bytes");
    out
}

/// Route attributes from `off` in `body`.
fn attrs(body: &[u8], mut off: usize) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while off + 4 <= body.len() {
        let len = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
        let ty = u16::from_le_bytes([body[off + 2], body[off + 3]]);
        out.push((ty, body[off + 4..off + len].to_vec()));
        off += (len + 3) & !3;
    }
    out
}

fn attr(a: &[(u16, Vec<u8>)], ty: u16) -> Vec<u8> {
    a.iter().find(|(t, _)| *t == ty).map(|(_, d)| d.clone()).unwrap_or_else(|| panic!("attribute {ty} missing"))
}

fn reply(d: &Arc<dyn CharDevice>) -> Vec<Msg> {
    let mut buf = vec![0u8; 8192];
    let n = d.read(&mut buf);
    assert!(n > 0, "a reply: {n}");
    parse(&buf[..n as usize])
}

fn dump(d: &Arc<dyn CharDevice>, ty: u16, family: u8) -> Vec<Msg> {
    let body = [family, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(d.write(&request(ty, NLM_F_REQUEST | NLM_F_DUMP, 9, &body)), 32);
    let m = reply(d);
    let last = m.last().unwrap();
    assert_eq!((last.ty, last.flags, last.seq), (NLMSG_DONE, NLM_F_MULTI, 9));
    m
}

fn error_of(m: &Msg) -> i32 {
    assert_eq!(m.ty, NLMSG_ERROR);
    i32::from_le_bytes(m.body[0..4].try_into().unwrap())
}

#[test]
fn socket_takes_the_process_id_as_its_port() {
    fake::reset();
    fake::IDS.set((61, 60));
    let fd = socket(3 | 0o4000 | 0o2000000);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    let d = open(0);
    assert!(!d.nonblock());
    let m = dump(&d, RTM_GETLINK, 0);
    assert!(m.iter().all(|m| m.port == 60));
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(socket(3), -24);
}

#[test]
fn link_dump() {
    fake::reset();
    let d = open(0);
    let m = dump(&d, RTM_GETLINK, 0);
    assert_eq!(m.len(), 2, "lo only while eth0 has no address");
    let lo = &m[0];
    assert_eq!((lo.ty, lo.flags), (RTM_NEWLINK, NLM_F_MULTI));
    assert_eq!(u16::from_le_bytes([lo.body[2], lo.body[3]]), 772, "ARPHRD_LOOPBACK");
    assert_eq!(i32::from_le_bytes(lo.body[4..8].try_into().unwrap()), 1);
    let a = attrs(&lo.body, 16);
    assert_eq!(attr(&a, 3), b"lo\0");
    assert_eq!(attr(&a, 4), 65536u32.to_le_bytes());
    assert_eq!(attr(&a, 16), vec![6], "IF_OPER_UP");
    net::eth_up();
    let m = dump(&d, RTM_GETLINK, 0);
    assert_eq!(m.len(), 3);
    let eth = attrs(&m[1].body, 16);
    assert_eq!(attr(&eth, 3), b"eth0\0");
    assert_eq!(attr(&eth, 1), vec![0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    assert_eq!(attr(&eth, 2), vec![0xff; 6]);
    assert_eq!(attr(&eth, 4), 1500u32.to_le_bytes());
    // A network namespace of its own sees lo only
    fake::NET_ISOLATED.set(true);
    assert_eq!(dump(&d, RTM_GETLINK, 0).len(), 2);
    fake::NET_ISOLATED.set(false);
    // A card without an address, or no card
    net::with(|n| n.iface.ip = [0; 4]);
    assert_eq!(dump(&d, RTM_GETLINK, 0).len(), 2);
    net::with(|n| n.iface.present = false);
    assert_eq!(dump(&d, RTM_GETLINK, 0).len(), 2);
}

#[test]
fn address_dump_by_family() {
    fake::reset();
    net::eth_up();
    let d = open(0);
    let all = dump(&d, RTM_GETADDR, 0);
    assert_eq!(all.len(), 5, "127.0.0.1, 10.0.2.15, ::1, fe80::, done");
    assert!(all[..4].iter().all(|m| m.ty == RTM_NEWADDR));
    let lo = attrs(&all[0].body, 8);
    assert_eq!(&all[0].body[0..4], &[2, 8, 0x80, 254]);
    assert_eq!(attr(&lo, 1), vec![127, 0, 0, 1]);
    assert_eq!(attr(&lo, 3), b"lo\0");
    let eth = attrs(&all[1].body, 8);
    assert_eq!(&all[1].body[0..4], &[2, 24, 0x80, 0]);
    assert_eq!(attr(&eth, 2), vec![10, 0, 2, 15]);
    assert_eq!(attr(&eth, 4), vec![10, 0, 2, 255], "broadcast");
    assert_eq!(&all[2].body[0..4], &[10, 128, 0x80, 254]);
    let mut one = [0u8; 16];
    one[15] = 1;
    assert_eq!(attr(&attrs(&all[2].body, 8), 1), one.to_vec());
    assert_eq!(&all[3].body[0..4], &[10, 64, 0x80, 253]);
    assert_eq!(attr(&attrs(&all[3].body, 8), 1), net::link_local6().unwrap().to_vec());
    assert_eq!(dump(&d, RTM_GETADDR, 2).len(), 3, "IPv4 only");
    assert_eq!(dump(&d, RTM_GETADDR, 10).len(), 3, "IPv6 only");
    // No address on eth0: no link-local address shown either
    net::with(|n| n.iface.ip = [0; 4]);
    assert_eq!(dump(&d, RTM_GETADDR, 10).len(), 2);
}

#[test]
fn route_dump() {
    fake::reset();
    let d = open(0);
    assert_eq!(dump(&d, RTM_GETROUTE, 0).len(), 1, "no routes without an address");
    net::eth_up();
    let m = dump(&d, RTM_GETROUTE, 0);
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].ty, RTM_NEWROUTE);
    assert_eq!(&m[0].body[0..8], &[2, 0, 0, 0, 254, 16, 0, 1], "default route, from DHCP");
    let def = attrs(&m[0].body, 12);
    assert_eq!(attr(&def, 5), vec![10, 0, 2, 2]);
    assert_eq!(attr(&def, 4), 2u32.to_le_bytes());
    assert_eq!(attr(&def, 15), 254u32.to_le_bytes());
    assert_eq!(&m[1].body[0..8], &[2, 24, 0, 0, 254, 2, 253, 1], "the subnet");
    let net_route = attrs(&m[1].body, 12);
    assert_eq!(attr(&net_route, 1), vec![10, 0, 2, 0]);
    assert_eq!(attr(&net_route, 7), vec![10, 0, 2, 15]);
    net::with(|n| n.iface.gateway = [0; 4]);
    assert_eq!(dump(&d, RTM_GETROUTE, 0).len(), 2, "no gateway: the subnet only");
}

#[test]
fn changes_are_refused_except_bringing_up_lo() {
    fake::reset();
    let d = open(0);
    let ifinfo = |index: i32| {
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&index.to_le_bytes());
        b
    };
    // Several requests in one datagram: one reply each
    let mut dgram = request(RTM_NEWLINK, NLM_F_REQUEST, 1, &ifinfo(1));
    dgram.extend(request(RTM_NEWADDR, NLM_F_REQUEST, 2, &ifinfo(1)));
    dgram.extend(request(RTM_NEWLINK, NLM_F_REQUEST, 3, &ifinfo(2)));
    dgram.extend(request(21, NLM_F_REQUEST, 4, &ifinfo(1)));
    dgram.extend(request(RTM_GETLINK, NLM_F_REQUEST, 5, &ifinfo(1))); // not a dump
    dgram.extend(request(99, NLM_F_REQUEST, 6, &[]));
    assert_eq!(d.write(&dgram), dgram.len() as i64);
    let want = [0, 0, EPERM, EPERM, EOPNOTSUPP, EOPNOTSUPP];
    for (i, w) in want.iter().enumerate() {
        let m = reply(&d);
        assert_eq!(m.len(), 1);
        assert_eq!(error_of(&m[0]), *w, "request {}", i + 1);
        assert_eq!(m[0].seq, i as u32 + 1);
        assert_eq!(&m[0].body[4..8], &dgram_header_len(&dgram, i), "the request's header comes back");
    }
    assert_eq!(d.poll_events(), 4, "nothing left");
    // A truncated or malformed message ends the datagram
    let mut bad = request(RTM_GETLINK, NLM_F_DUMP, 7, &[0u8; 16]);
    bad[0..4].copy_from_slice(&100u32.to_le_bytes());
    d.write(&bad);
    let mut tiny = request(RTM_GETLINK, NLM_F_DUMP, 7, &[0u8; 16]);
    tiny[0..4].copy_from_slice(&8u32.to_le_bytes());
    d.write(&tiny);
    assert_eq!(d.poll_events(), 4, "no reply to either");
}

/// The length field of the `i`th request in `dgram` (all are 32 bytes but the last).
fn dgram_header_len(dgram: &[u8], i: usize) -> [u8; 4] {
    let mut off = 0;
    for _ in 0..i {
        off += u32::from_le_bytes(dgram[off..off + 4].try_into().unwrap()) as usize;
    }
    dgram[off..off + 4].try_into().unwrap()
}

#[test]
fn receiving_replies() {
    fake::reset();
    let d = open(0);
    let call = |num: u64, a: [u64; 6]| d.socket_call(num, a).unwrap();
    let mut buf = vec![0u8; 4096];
    assert_eq!(call(45, [0, mptr(&mut buf[0]), 4096, MSG_DONTWAIT, 0, 0]), EAGAIN);
    // sendto, then recvfrom with peek, truncation and the source address
    let req = request(RTM_GETLINK, NLM_F_DUMP, 1, &[0u8; 16]);
    assert_eq!(call(44, [0, ptr(&req[0]), req.len() as u64, 0, 0, 0]), req.len() as i64);
    assert_eq!(d.poll_events(), 5);
    let mut sa = [0xffu8; 12];
    let mut salen = 12u32;
    let n = call(45, [0, mptr(&mut buf[0]), 4096, MSG_PEEK, mptr(&mut sa), mptr(&mut salen)]);
    assert!(n > 16);
    assert_eq!(sa, { let mut k = [0u8; 12]; k[0] = 16; k }, "from the kernel");
    assert_eq!(call(45, [0, mptr(&mut buf[0]), 8, MSG_PEEK | MSG_TRUNC, 0, 0]), n, "MSG_TRUNC: the real length");
    assert_eq!(call(45, [0, mptr(&mut buf[0]), 8, MSG_PEEK, 0, 0]), 8);
    assert_eq!(call(45, [0, mptr(&mut buf[0]), 4096, 0, 0, 0]), n, "still there after peeking");
    assert_eq!(d.poll_events(), 4);
    // recvfrom faults
    d.write(&req);
    let mut bad = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad), 16);
    assert_eq!(call(45, [0, mptr(&mut bad), 16, MSG_PEEK, 0, 0]), EFAULT);
    let mut bad_len = 12u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(45, [0, mptr(&mut buf[0]), 16, MSG_PEEK, mptr(&mut sa), mptr(&mut bad_len)]), EFAULT);
    assert_eq!(call(44, [0, mptr(&mut bad), 16, 0, 0, 0]), EFAULT);
}

#[repr(C)]
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

#[test]
fn sendmsg_and_recvmsg_with_iovecs() {
    fake::reset();
    net::eth_up();
    let d = open(0);
    let call = |num: u64, a: [u64; 6]| d.socket_call(num, a).unwrap();
    // The request split over two iovecs
    let req = request(RTM_GETADDR, NLM_F_DUMP, 3, &[2u8, 0, 0, 0, 0, 0, 0, 0]);
    let iov = [(ptr(&req[0]), 10u64), (ptr(&req[10]), (req.len() - 10) as u64)];
    let mut msg = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: ptr(&iov), iovlen: 2, control: 0, controllen: 0, flags: 0, _pad2: 0 };
    assert_eq!(call(46, [0, mptr(&mut msg), 0, 0, 0, 0]), req.len() as i64);
    // Received into two small buffers: truncated
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    let mut sa = [0xffu8; 12];
    let riov = [(mptr(&mut a), 16u64), (mptr(&mut b), 16u64)];
    let mut rmsg = MsgHdr { name: mptr(&mut sa), namelen: 12, _pad: 0, iov: ptr(&riov), iovlen: 2, control: 1, controllen: 99, flags: 0, _pad2: 0 };
    let n = call(47, [0, mptr(&mut rmsg), MSG_PEEK | MSG_TRUNC, 0, 0, 0]);
    assert!(n > 32, "MSG_TRUNC: the datagram's length");
    assert_eq!(rmsg.flags, 0x20, "MSG_TRUNC in msg_flags");
    assert_eq!(rmsg.controllen, 0);
    assert_eq!(rmsg.namelen, 12);
    assert_eq!(sa[0], 16);
    assert_eq!(u16::from_le_bytes([a[4], a[5]]), RTM_NEWADDR);
    // All of it, into one big buffer
    let mut big = vec![0u8; 4096];
    let biov = [(mptr(&mut big[0]), 4096u64)];
    let mut bmsg = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: ptr(&biov), iovlen: 1, control: 0, controllen: 0, flags: -1, _pad2: 0 };
    assert_eq!(call(47, [0, mptr(&mut bmsg), 0, 0, 0, 0]), n);
    assert_eq!(bmsg.flags, 0);
    assert_eq!(parse(&big[..n as usize]).len(), 3);
    assert_eq!(call(47, [0, mptr(&mut bmsg), MSG_DONTWAIT, 0, 0, 0]), EAGAIN);
    // Faults: the header, the iovec array, a buffer
    let mut gone = [0u8; 56];
    fake::bad_ptr(mptr(&mut gone), 56);
    assert_eq!(call(46, [0, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(47, [0, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    let mut bad_iov = [(0u64, 0u64); 1];
    fake::bad_ptr(mptr(&mut bad_iov), 16);
    let mut m2 = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: mptr(&mut bad_iov), iovlen: 1, control: 0, controllen: 0, flags: 0, _pad2: 0 };
    assert_eq!(call(46, [0, mptr(&mut m2), 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(47, [0, mptr(&mut m2), 0, 0, 0, 0]), EFAULT);
    let mut bad_buf = [0u8; 32];
    fake::bad_ptr(mptr(&mut bad_buf), 32);
    let iov3 = [(mptr(&mut bad_buf), 32u64)];
    let mut m3 = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: ptr(&iov3), iovlen: 1, control: 0, controllen: 0, flags: 0, _pad2: 0 };
    assert_eq!(call(46, [0, mptr(&mut m3), 0, 0, 0, 0]), EFAULT);
    d.write(&req);
    assert_eq!(call(47, [0, mptr(&mut m3), 0, 0, 0, 0]), EFAULT);
}

#[test]
fn addresses_and_options() {
    fake::reset();
    fake::IDS.set((71, 70));
    let d = open(0);
    let call = |num: u64, a: [u64; 6]| d.socket_call(num, a).unwrap();
    let name = |num: u64| {
        let mut sa = [0u8; 12];
        let mut len = 12u32;
        assert_eq!(call(num, [0, mptr(&mut sa), mptr(&mut len), 0, 0, 0]), 0);
        (u32::from_le_bytes(sa[4..8].try_into().unwrap()), u32::from_le_bytes(sa[8..12].try_into().unwrap()))
    };
    assert_eq!(name(51), (70, 0));
    let mut sa = [0u8; 12];
    sa[8..12].copy_from_slice(&0x11u32.to_le_bytes());
    assert_eq!(call(49, [0, ptr(&sa), 12, 0, 0, 0]), 0);
    assert_eq!(name(51), (70, 0x11), "port 0 keeps the process ID");
    sa[4..8].copy_from_slice(&5555u32.to_le_bytes());
    assert_eq!(call(49, [0, ptr(&sa), 12, 0, 0, 0]), 0);
    assert_eq!(name(51), (5555, 0x11));
    assert_eq!(name(52), (0, 0), "the kernel");
    assert_eq!(call(51, [0, 0, 0, 0, 0, 0]), 0);
    let mut bad = [0u8; 12];
    fake::bad_ptr(mptr(&mut bad), 12);
    assert_eq!(call(49, [0, mptr(&mut bad), 12, 0, 0, 0]), EFAULT);
    let mut len = 12u32;
    assert_eq!(call(51, [0, mptr(&mut bad), mptr(&mut len), 0, 0, 0]), EFAULT);
    let mut bad_len = 12u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(52, [0, mptr(&mut sa), mptr(&mut bad_len), 0, 0, 0]), EFAULT);
    assert_eq!(call(42, [0; 6]), 0, "connect to the kernel");
    assert_eq!(call(54, [0; 6]), 0, "setsockopt");
    let get = |level: u64, opt: u64| {
        let mut v = 0xdeadu32;
        let mut len = 0u32;
        assert_eq!(call(55, [0, level, opt, mptr(&mut v), mptr(&mut len), 0]), 0);
        v
    };
    assert_eq!((get(1, 3), get(1, 7), get(1, 8), get(1, 38), get(1, 39), get(270, 11)), (3, 212_992, 212_992, 0, 16, 0));
    let mut v = 0u32;
    fake::bad_ptr(mptr(&mut v), 4);
    let mut l = 4u32;
    assert_eq!(call(55, [0, 1, 3, mptr(&mut v), mptr(&mut l), 0]), EFAULT);
    assert_eq!(call(48, [0; 6]), 0);
    for num in [43, 50, 288] {
        assert_eq!(call(num, [0; 6]), EINVAL);
    }
    assert_eq!(d.socket_call(2, [0; 6]), None);
    assert_eq!(d.rdev(), 0);
    assert!(d.path().starts_with("socket:["));
}

#[test]
fn blocking_receives_and_notifications() {
    fake::reset();
    let d = open(0);
    let mut buf = [0u8; 64];
    let mut w = WaitSet::new();
    d.add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 1);
    // A notification arrives while waiting
    let d2 = d.clone();
    fake::on_wait(move |_| assert!(d2.deliver_notification(b"event!!!")));
    assert_eq!(d.read(&mut buf), 8);
    assert_eq!(&buf[..8], b"event!!!");
    assert_eq!(fake::WAITS.get(), 1);
    // A signal ends the wait
    fake::reset();
    fake::on_wait(|_| fake::SIGNAL_PENDING.set(true));
    assert_eq!(d.read(&mut buf), -512);
    fake::reset();
    assert!(blocks(|| d.read(&mut buf)));
    d.set_nonblock(true);
    assert_eq!(d.read(&mut buf), EAGAIN);
}

#[test]
fn proc_net_tables() {
    fake::reset();
    let route = proc_net_text("route").unwrap();
    assert_eq!(route.lines().count(), 1, "the header only");
    assert_eq!(route.len(), 128, "padded to 127 + newline");
    assert!(route.starts_with("Iface\tDestination\tGateway"));
    let if6 = proc_net_text("if_inet6").unwrap();
    assert_eq!(if6, "00000000000000000000000000000001 01 80 10 80       lo\n");
    let r6 = proc_net_text("ipv6_route").unwrap();
    assert_eq!(r6.lines().count(), 1, "::1 only");
    assert!(r6.ends_with("       lo\n"));
    let arp = proc_net_text("arp").unwrap();
    assert_eq!(arp.lines().count(), 1);

    net::eth_up();
    net::with(|n| n.arp.push(([10, 0, 2, 2], [0x52, 0x55, 10, 0, 2, 2])));
    let route = proc_net_text("route").unwrap();
    let rows: Vec<&str> = route.lines().collect();
    assert_eq!(rows.len(), 3);
    assert!(rows[1].starts_with("eth0\t00000000\t0202000A\t0003\t"), "{}", rows[1]);
    assert!(rows[2].starts_with("eth0\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF"), "{}", rows[2]);
    let r6 = proc_net_text("ipv6_route").unwrap();
    assert_eq!(r6.lines().count(), 4, "fe80::/64, ::1, our address, ff00::/8");
    assert!(r6.starts_with("fe800000000000000000000000000000 40 "));
    let if6 = proc_net_text("if_inet6").unwrap();
    assert_eq!(if6.lines().count(), 2);
    assert!(if6.lines().nth(1).unwrap().starts_with("fe80000000000000505400fffe123456 02 40 20 80"));
    let arp = proc_net_text("arp").unwrap();
    assert!(arp.lines().nth(1).unwrap().starts_with("10.0.2.2         0x1         0x2         52:55:0a:00:02:02"));
    net::with(|n| n.iface.gateway = [0; 4]);
    assert_eq!(proc_net_text("route").unwrap().lines().count(), 2);
}

#[test]
fn proc_net_counters() {
    fake::reset();
    net::with(|n| n.counters = [((100, 3), (100, 3)), ((5000, 40), (600, 7))]);
    let snmp = proc_net_text("snmp").unwrap();
    let ip: Vec<&str> = snmp.lines().nth(1).unwrap().split(' ').collect();
    assert_eq!((ip[3], ip[9], ip[10]), ("43", "43", "10"), "InReceives, InDelivers, OutRequests");
    assert!(snmp.contains("Udp: 0 0 0 0 0 0 0 0 0\n"));
    fake::NET_ISOLATED.set(true);
    let snmp = proc_net_text("snmp").unwrap();
    assert!(snmp.lines().nth(1).unwrap().starts_with("Ip: 2 64 0 "));
    let snmp6 = proc_net_text("snmp6").unwrap();
    assert_eq!(snmp6.lines().count(), 28);
    assert!(snmp6.starts_with("Ip6InReceives"));
    assert_eq!(proc_net_text("tcp"), None);
}

#[test]
fn interface_ioctls() {
    fake::reset();
    net::eth_up();
    let ifreq = |name: &str| {
        let mut r = [0u8; 40];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r
    };
    let q = |cmd: u64, name: &str| {
        let mut r = ifreq(name);
        let res = interface_ioctl(cmd, mptr(&mut r)).unwrap();
        (res, r)
    };
    assert_eq!(interface_ioctl(0x5401, 0), None, "not an interface query");
    let (r, b) = q(0x8933, "eth0");
    assert_eq!((r, i32::from_le_bytes(b[16..20].try_into().unwrap())), (0, 2), "SIOCGIFINDEX");
    let (_, b) = q(0x8913, "lo");
    assert_eq!(u16::from_le_bytes([b[16], b[17]]), 0x49, "SIOCGIFFLAGS: UP|LOOPBACK|RUNNING");
    let (_, b) = q(0x8915, "eth0");
    assert_eq!(&b[16..24], &[2, 0, 0, 0, 10, 0, 2, 15], "SIOCGIFADDR");
    let (_, b) = q(0x8919, "eth0");
    assert_eq!(&b[20..24], &[10, 0, 2, 255], "SIOCGIFBRDADDR");
    let (_, b) = q(0x891b, "eth0");
    assert_eq!(&b[20..24], &[255, 255, 255, 0], "SIOCGIFNETMASK");
    let (_, b) = q(0x8921, "lo");
    assert_eq!(i32::from_le_bytes(b[16..20].try_into().unwrap()), 65536, "SIOCGIFMTU");
    let (_, b) = q(0x8927, "eth0");
    assert_eq!(&b[16..24], &[1, 0, 0x52, 0x54, 0, 0x12, 0x34, 0x56], "SIOCGIFHWADDR");
    assert_eq!(q(0x8915, "wlan0").0, ENODEV);
    // SIOCGIFNAME: by index
    let mut r = [0u8; 40];
    r[16..20].copy_from_slice(&2i32.to_le_bytes());
    assert_eq!(interface_ioctl(0x8910, mptr(&mut r)), Some(0));
    assert_eq!(&r[..5], b"eth0\0");
    r[16..20].copy_from_slice(&9i32.to_le_bytes());
    assert_eq!(interface_ioctl(0x8910, mptr(&mut r)), Some(ENODEV));
    let mut bad = [0u8; 40];
    fake::bad_ptr(mptr(&mut bad), 40);
    assert_eq!(interface_ioctl(0x8915, mptr(&mut bad)), Some(EFAULT));
}

#[test]
fn siocgifconf() {
    fake::reset();
    net::eth_up();
    // Length query: no buffer
    let mut conf = [0u8; 16];
    assert_eq!(interface_ioctl(0x8912, mptr(&mut conf)), Some(0));
    assert_eq!(i32::from_le_bytes(conf[0..4].try_into().unwrap()), 80, "two 40-byte ifreqs");
    // As many as fit
    let mut buf = [0u8; 120];
    conf[0..4].copy_from_slice(&60i32.to_le_bytes());
    conf[8..16].copy_from_slice(&mptr(&mut buf).to_le_bytes());
    assert_eq!(interface_ioctl(0x8912, mptr(&mut conf)), Some(0));
    assert_eq!(i32::from_le_bytes(conf[0..4].try_into().unwrap()), 40);
    assert_eq!(&buf[..3], b"lo\0");
    assert_eq!(&buf[20..24], &[127, 0, 0, 1]);
    conf[0..4].copy_from_slice(&120i32.to_le_bytes());
    assert_eq!(interface_ioctl(0x8912, mptr(&mut conf)), Some(0));
    assert_eq!(&buf[40..45], b"eth0\0");
    // Faults
    let mut bad = [0u8; 80];
    fake::bad_ptr(mptr(&mut bad), 80);
    conf[8..16].copy_from_slice(&mptr(&mut bad).to_le_bytes());
    assert_eq!(interface_ioctl(0x8912, mptr(&mut conf)), Some(EFAULT));
    let mut bad_conf = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad_conf), 16);
    assert_eq!(interface_ioctl(0x8912, mptr(&mut bad_conf)), Some(EFAULT));
}
