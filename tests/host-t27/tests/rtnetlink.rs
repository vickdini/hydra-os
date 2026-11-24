//! Routing netlink sockets (`src/compat/linux/rtnetlink.rs`): link, address and route dumps
//! built from the interface net-server reports, the refusals of configuration changes, the
//! socket calls glibc and Chromium make, the `/proc/net` tables and the `SIOCGIF*` ioctls.
#![allow(dead_code, unused_imports)] // (wave10 G10-C: helpers of tests deleted with the kernel copies)

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::rtnetlink::{interface_ioctl, proc_net_text};
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

/// The length field of the `i`th request in `dgram` (all are 32 bytes but the last).
fn dgram_header_len(dgram: &[u8], i: usize) -> [u8; 4] {
    let mut off = 0;
    for _ in 0..i {
        off += u32::from_le_bytes(dgram[off..off + 4].try_into().unwrap()) as usize;
    }
    dgram[off..off + 4].try_into().unwrap()
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
