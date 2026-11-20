//! Socket options of internet sockets (`src/compat/linux/sockopt.rs`): validation, the
//! values Linux reads back, privileges, and the timeouts the socket code uses.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::sockopt::{Options, SockInfo};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EDOM: i64 = -33;
const ENOPROTOOPT: i64 = -92;
const ENOTCONN: i64 = -107;

const SOL: u32 = 1;
const IP: u32 = 0;
const TCP: u32 = 6;
const UDP: u32 = 17;
const IPV6: u32 = 41;

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;

fn info(stream: bool, v6: bool) -> SockInfo {
    SockInfo { kind: 0, v6, listening: false, stream, connected: false, error: 0, tcp_state: 7 }
}

fn int(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn get(o: &Options, level: u32, name: u32, i: &SockInfo) -> Result<Vec<u8>, i64> {
    o.get(level, name, i)
}

fn tv(sec: i64, usec: i64) -> Vec<u8> {
    let mut b = sec.to_le_bytes().to_vec();
    b.extend_from_slice(&usec.to_le_bytes());
    b
}

#[test]
fn unknown_levels_and_options() {
    fake::reset();
    let mut o = Options::default();
    assert_eq!(o.set(99, 1, &int(1), true, false), ENOPROTOOPT);
    assert_eq!(o.set(SOL, 81, &int(1), true, false), ENOPROTOOPT);
    assert_eq!(o.set(IP, 51, &int(1), true, false), ENOPROTOOPT);
    assert_eq!(o.set(TCP, 1, &int(1), false, false), ENOPROTOOPT, "TCP options on a datagram socket");
    assert_eq!(o.set(UDP, 1, &int(1), true, false), ENOPROTOOPT, "UDP options on a stream socket");
    assert_eq!(o.set(UDP, 1, &int(1), false, false), 0, "UDP_CORK");
    assert_eq!(o.set(UDP, 102, &int(1), false, false), 0);
    assert_eq!(o.set(IPV6, 26, &int(1), true, false), ENOPROTOOPT, "IPv6 options on an IPv4 socket");
    assert_eq!(get(&o, 99, 1, &info(true, false)), Err(ENOPROTOOPT));
    // Read-only options
    for name in [3, 4, 17, 28, 30, 31, 38, 39, 19] {
        assert_eq!(o.set(SOL, name, &int(1), true, false), ENOPROTOOPT, "{name}");
    }
    assert_eq!(o.set(IP, 14, &int(1), true, false), ENOPROTOOPT, "IP_MTU");
    assert_eq!(o.set(TCP, 11, &int(1), true, false), ENOPROTOOPT, "TCP_INFO");
}

#[test]
fn socket_level_values() {
    fake::reset();
    let mut o = Options::default();
    let s = info(true, false);
    let d = info(false, true);
    assert_eq!(get(&o, SOL, 3, &s).unwrap(), int(1));
    assert_eq!(get(&o, SOL, 3, &d).unwrap(), int(2));
    assert_eq!(get(&o, SOL, 3, &SockInfo { kind: 2, ..info(false, false) }).unwrap(), int(3));
    assert_eq!(get(&o, SOL, 4, &SockInfo { error: -111, ..info(true, false) }).unwrap(), int(111));
    assert_eq!(get(&o, SOL, 39, &s).unwrap(), int(2));
    assert_eq!(get(&o, SOL, 39, &d).unwrap(), int(10));
    assert_eq!(get(&o, SOL, 38, &s).unwrap(), int(6));
    assert_eq!(get(&o, SOL, 38, &d).unwrap(), int(17));
    assert_eq!(get(&o, SOL, 38, &SockInfo { kind: 1, ..info(false, false) }).unwrap(), int(1));
    assert_eq!(get(&o, SOL, 38, &SockInfo { kind: 2, ..info(false, true) }).unwrap(), int(58));
    assert_eq!(get(&o, SOL, 30, &SockInfo { listening: true, ..info(true, false) }).unwrap(), int(1));
    assert_eq!(get(&o, SOL, 7, &s).unwrap(), int(16_384));
    assert_eq!(get(&o, SOL, 8, &s).unwrap(), int(131_072));
    assert_eq!(get(&o, SOL, 7, &d).unwrap(), int(212_992));
    assert_eq!(get(&o, SOL, 8, &d).unwrap(), int(212_992));
    assert_eq!(get(&o, SOL, 18, &s).unwrap(), int(1));
    assert_eq!(get(&o, SOL, 19, &s).unwrap(), int(1));
    assert_eq!(get(&o, SOL, 13, &s).unwrap(), vec![0; 8]);
    assert_eq!(get(&o, SOL, 25, &s).unwrap(), Vec::<u8>::new());
    assert_eq!(get(&o, SOL, 17, &s).unwrap(), vec![0; 12]);
    assert_eq!(get(&o, SOL, 28, &s), Err(ENOTCONN));
    assert_eq!(get(&o, SOL, 1, &s).unwrap(), int(0), "SO_DEBUG and the like: 0");
    // Booleans read back as 0 or 1
    assert_eq!(o.set(SOL, 9, &int(5), true, false), 0); // SO_KEEPALIVE
    assert_eq!(get(&o, SOL, 9, &s).unwrap(), int(1));
    assert!(o.flag(SOL, 9));
    assert_eq!(o.set(SOL, 9, &[1, 0], true, false), EINVAL, "an int is needed");
    // Buffer sizes: doubled, clamped, minimums
    assert_eq!(o.set(SOL, 7, &int(100_000), true, false), 0);
    assert_eq!(get(&o, SOL, 7, &s).unwrap(), int(200_000));
    assert_eq!(o.set(SOL, 7, &int(10_000_000), true, false), 0);
    assert_eq!(get(&o, SOL, 7, &s).unwrap(), int(425_984));
    assert_eq!(o.set(SOL, 8, &int(1), true, false), 0);
    assert_eq!(get(&o, SOL, 8, &s).unwrap(), int(2304));
    assert_eq!(o.set(SOL, 7, &int(-5), true, false), 0);
    assert_eq!(get(&o, SOL, 7, &s).unwrap(), int(4608));
    assert_eq!(o.set(SOL, 7, &[1], true, false), EINVAL);
    assert_eq!(o.set(SOL, 32, &int(10_000_000), true, false), EPERM, "SO_SNDBUFFORCE");
    fake::CAPS.set(Some(CAP_NET_ADMIN));
    assert_eq!(o.set(SOL, 33, &int(10_000_000), true, false), 0, "SO_RCVBUFFORCE: unclamped");
    assert_eq!(get(&o, SOL, 8, &s).unwrap(), int(20_000_000));
    fake::CAPS.set(Some(0));
    // Priority, mark, linger, low-water mark
    assert_eq!(o.set(SOL, 12, &int(6), true, false), 0);
    assert_eq!(o.set(SOL, 12, &int(7), true, false), EPERM);
    assert_eq!(o.set(SOL, 12, &[1], true, false), EINVAL);
    fake::CAPS.set(Some(CAP_NET_ADMIN));
    assert_eq!(o.set(SOL, 12, &int(7), true, false), 0);
    fake::CAPS.set(Some(0));
    assert_eq!(o.set(SOL, 36, &int(9), true, false), EPERM, "SO_MARK");
    assert_eq!(o.set(SOL, 36, &[9], true, false), EINVAL);
    fake::CAPS.set(Some(CAP_NET_RAW));
    assert_eq!(o.set(SOL, 36, &int(9), true, false), 0);
    assert_eq!(o.set(SOL, 13, &[1, 0, 0, 0, 5, 0, 0, 0], true, false), 0);
    assert_eq!(get(&o, SOL, 13, &s).unwrap(), vec![1, 0, 0, 0, 5, 0, 0, 0]);
    assert_eq!(o.set(SOL, 13, &int(1), true, false), EINVAL);
    assert_eq!(o.set(SOL, 18, &int(-1), true, false), 0);
    assert_eq!(get(&o, SOL, 18, &s).unwrap(), int(i32::MAX));
    assert_eq!(o.set(SOL, 18, &int(0), true, false), 0);
    assert_eq!(get(&o, SOL, 18, &s).unwrap(), int(1));
    assert_eq!(o.set(SOL, 18, &[0], true, false), EINVAL);
    // SO_BINDTODEVICE needs CAP_NET_RAW and a known interface
    assert_eq!(o.set(SOL, 25, b"eth0\0", true, false), 0);
    assert_eq!(o.set(SOL, 25, b"lo", true, false), 0);
    assert_eq!(o.set(SOL, 25, b"", true, false), 0, "unbind");
    assert_eq!(o.set(SOL, 25, b"wlan0", true, false), ENODEV);
    fake::CAPS.set(Some(0));
    assert_eq!(o.set(SOL, 25, b"eth0", true, false), EPERM);
    // Other known socket options: kept as given (at least an int)
    assert_eq!(o.set(SOL, 50, &[1, 2, 3, 4, 5], true, false), 0);
    assert_eq!(o.value(SOL, 50), Some(&[1u8, 2, 3, 4, 5][..]));
    assert_eq!(o.set(SOL, 50, &[1], true, false), EINVAL);
    o.put(SOL, 51, &[7]);
    assert_eq!(o.value(SOL, 51), Some(&[7u8][..]));
}

#[test]
fn timeouts() {
    fake::reset();
    let mut o = Options::default();
    let s = info(true, false);
    assert_eq!((o.rcv_timeout(), o.snd_timeout()), (None, None));
    assert_eq!(get(&o, SOL, 20, &s).unwrap(), tv(0, 0));
    assert_eq!(o.set(SOL, 20, &tv(1, 500_000), true, false), 0);
    assert_eq!(o.rcv_timeout(), Some(1_500_000_000));
    assert_eq!(get(&o, SOL, 66, &s).unwrap(), tv(1, 500_000), "SO_RCVTIMEO_NEW reads the same");
    assert_eq!(o.set(SOL, 67, &tv(0, 1), true, false), 0);
    assert_eq!(o.snd_timeout(), Some(1000));
    assert_eq!(get(&o, SOL, 21, &s).unwrap(), tv(0, 1));
    assert_eq!(o.set(SOL, 21, &tv(-3, 0), true, false), 0, "negative: none");
    assert_eq!(o.snd_timeout(), None);
    assert_eq!(o.set(SOL, 20, &tv(0, 1_000_000), true, false), EDOM);
    assert_eq!(o.set(SOL, 20, &int(1), true, false), EINVAL);
    assert_eq!(o.set(SOL, 20, &tv(i64::MAX, 0), true, false), 0);
    assert_eq!(o.rcv_timeout(), Some(u64::MAX), "saturates");
}

#[test]
fn ip_level() {
    fake::reset();
    let mut o = Options::default();
    let s = info(true, false);
    let d = info(false, false);
    assert_eq!(get(&o, IP, 2, &s).unwrap(), int(64), "IP_TTL default");
    assert_eq!(o.set(IP, 2, &int(10), true, false), 0);
    assert_eq!(get(&o, IP, 2, &s).unwrap(), int(10));
    assert_eq!(o.set(IP, 2, &int(-1), true, false), 0, "back to the default");
    assert_eq!(get(&o, IP, 2, &s).unwrap(), int(64));
    assert_eq!(o.set(IP, 2, &int(0), true, false), EINVAL);
    assert_eq!(o.set(IP, 2, &[], true, false), EINVAL);
    // IP_TOS: TCP keeps its ECN bits; a single byte is accepted
    assert_eq!(o.set(IP, 1, &int(0xff), true, false), 0);
    assert_eq!(get(&o, IP, 1, &s).unwrap(), int(0xfc));
    assert_eq!(o.set(IP, 1, &[0x13], false, false), 0);
    assert_eq!(get(&o, IP, 1, &d).unwrap(), int(0x13));
    assert_eq!(o.set(IP, 1, &[], false, false), EINVAL);
    let mut o = Options::default();
    assert_eq!(get(&o, IP, 10, &s).unwrap(), int(1));
    assert_eq!(o.set(IP, 10, &int(3), true, false), 0);
    assert_eq!(o.set(IP, 10, &int(6), true, false), EINVAL);
    assert_eq!(o.set(IP, 10, &[], true, false), EINVAL);
    assert_eq!(get(&o, IP, 14, &s), Err(ENOTCONN), "IP_MTU unconnected");
    assert_eq!(get(&o, IP, 14, &SockInfo { connected: true, ..info(true, false) }).unwrap(), int(1500));
    assert_eq!(o.set(IP, 19, &int(1), true, false), EPERM, "IP_TRANSPARENT");
    fake::CAPS.set(Some(CAP_NET_ADMIN));
    assert_eq!(o.set(IP, 19, &int(7), true, false), 0);
    assert_eq!(get(&o, IP, 19, &s).unwrap(), int(1));
    assert_eq!(o.set(IP, 19, &[], true, false), EINVAL);
    assert_eq!(get(&o, IP, 33, &s).unwrap(), int(1));
    assert_eq!(o.set(IP, 33, &int(-1), false, false), 0);
    assert_eq!(get(&o, IP, 33, &d).unwrap(), int(1));
    assert_eq!(o.set(IP, 33, &int(200), false, false), 0);
    assert_eq!(o.set(IP, 33, &int(300), false, false), EINVAL);
    assert_eq!(o.set(IP, 33, &[], false, false), EINVAL);
    assert_eq!(o.set(IP, 34, &[0], false, false), 0, "IP_MULTICAST_LOOP");
    assert_eq!(get(&o, IP, 34, &d).unwrap(), int(0));
    assert_eq!(o.set(IP, 12, &int(4), false, false), 0, "IP_RECVTTL");
    assert!(o.flag(IP, 12));
    assert_eq!(o.set(IP, 12, &[], false, false), EINVAL);
    assert_eq!(o.set(IP, 35, &[1, 2], false, false), 0, "other IP options keep short values");
}

#[test]
fn ipv6_level() {
    fake::reset();
    let mut o = Options::default();
    let s = info(true, true);
    assert_eq!(get(&o, IPV6, 16, &s).unwrap(), int(64));
    assert_eq!(get(&o, IPV6, 18, &s).unwrap(), int(1));
    assert_eq!(get(&o, IPV6, 19, &s).unwrap(), int(1));
    assert_eq!(o.set(IPV6, 16, &int(20), true, true), 0);
    assert_eq!(get(&o, IPV6, 16, &s).unwrap(), int(20));
    assert_eq!(o.set(IPV6, 16, &int(-1), true, true), 0);
    assert_eq!(get(&o, IPV6, 16, &s).unwrap(), int(64));
    assert_eq!(o.set(IPV6, 18, &int(256), true, true), EINVAL);
    assert_eq!(o.set(IPV6, 18, &[1], true, true), EINVAL);
    assert_eq!(get(&o, IPV6, 24, &s), Err(ENOTCONN));
    assert_eq!(get(&o, IPV6, 24, &SockInfo { connected: true, ..info(true, true) }).unwrap(), int(65536));
    assert_eq!(o.set(IPV6, 24, &int(1280), true, true), 0);
    assert_eq!(o.set(IPV6, 24, &int(1279), true, true), EINVAL);
    assert_eq!(o.set(IPV6, 26, &int(9), true, true), 0);
    assert_eq!(get(&o, IPV6, 26, &s).unwrap(), int(1));
    assert_eq!(o.set(IPV6, 26, &[1], true, true), EINVAL);
    assert_eq!(o.set(IPV6, 19, &int(0), true, true), 0);
    assert_eq!(get(&o, IPV6, 19, &s).unwrap(), int(0));
}

#[test]
fn tcp_level() {
    fake::reset();
    let mut o = Options::default();
    let s = info(true, false);
    let c = SockInfo { connected: true, tcp_state: 1, ..info(true, false) };
    assert_eq!(get(&o, TCP, 2, &s).unwrap(), int(536));
    assert_eq!(get(&o, TCP, 2, &c).unwrap(), int(1460));
    assert_eq!(get(&o, TCP, 4, &s).unwrap(), int(7200));
    assert_eq!(get(&o, TCP, 5, &s).unwrap(), int(75));
    assert_eq!(get(&o, TCP, 6, &s).unwrap(), int(9));
    assert_eq!(get(&o, TCP, 7, &s).unwrap(), int(6));
    assert_eq!(get(&o, TCP, 13, &s).unwrap(), b"cubic".to_vec());
    let ti = get(&o, TCP, 11, &c).unwrap();
    assert_eq!((ti.len(), ti[0]), (232, 1));
    assert_eq!(u32::from_le_bytes(ti[8..12].try_into().unwrap()), 1_000_000);
    assert_eq!(u32::from_le_bytes(ti[16..20].try_into().unwrap()), 1460);
    assert_eq!(o.set(TCP, 2, &int(0), true, false), 0);
    assert_eq!(o.set(TCP, 2, &int(1400), true, false), 0);
    assert_eq!(o.set(TCP, 2, &int(50), true, false), EINVAL);
    assert_eq!(o.set(TCP, 2, &[1], true, false), EINVAL);
    assert_eq!(o.set(TCP, 4, &int(60), true, false), 0);
    assert_eq!(o.set(TCP, 5, &int(0), true, false), EINVAL);
    assert_eq!(o.set(TCP, 6, &int(127), true, false), 0);
    assert_eq!(o.set(TCP, 7, &int(128), true, false), EINVAL);
    assert_eq!(o.set(TCP, 18, &int(0), true, false), 0);
    assert_eq!(o.set(TCP, 18, &int(-1), true, false), EINVAL);
    assert_eq!(o.set(TCP, 13, b"reno\0", true, false), 0);
    assert_eq!(get(&o, TCP, 13, &s).unwrap(), b"reno".to_vec());
    assert_eq!(o.set(TCP, 13, b"bbr", true, false), ENOENT);
    assert_eq!(o.set(TCP, 1, &int(3), true, false), 0, "TCP_NODELAY");
    assert_eq!(get(&o, TCP, 1, &s).unwrap(), int(1));
    assert_eq!(o.set(TCP, 1, &[1], true, false), EINVAL);
    assert_eq!(o.set(TCP, 20, &[1, 2], true, false), EINVAL, "other TCP options need an int");
    assert_eq!(o.set(TCP, 20, &int(5), true, false), 0);
    assert_eq!(get(&o, TCP, 20, &s).unwrap(), int(5));
    let cl = o.clone();
    assert_eq!(get(&cl, TCP, 20, &s).unwrap(), int(5), "options copy (accept inherits them)");
}
