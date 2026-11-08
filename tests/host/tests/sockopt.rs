//! Tests for `setsockopt`/`getsockopt` emulation in
//! `src/compat/linux/sockopt.rs`. Expected values follow Linux's documented
//! behaviour (socket(7), ip(7), ipv6(7), tcp(7)), which programs such as
//! glibc, curl and Chromium depend on.
//!
//! Capability checks read the fake current task's `CAP_NET_ADMIN` (bit 12)
//! and `CAP_NET_RAW` (bit 13).

use hydra_hosttests::compat::linux::sockopt::{Options, SockInfo};
use hydra_hosttests::fake;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EDOM: i64 = -33;
const ENOPROTOOPT: i64 = -92;
const ENOTCONN: i64 = -107;

const SOL_SOCKET: u32 = 1;
const IPPROTO_IP: u32 = 0;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_IPV6: u32 = 41;

const SO_REUSEADDR: u32 = 2;
const SO_TYPE: u32 = 3;
const SO_ERROR: u32 = 4;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_KEEPALIVE: u32 = 9;
const SO_PRIORITY: u32 = 12;
const SO_LINGER: u32 = 13;
const SO_PEERCRED: u32 = 17;
const SO_RCVLOWAT: u32 = 18;
const SO_RCVTIMEO_OLD: u32 = 20;
const SO_SNDTIMEO_OLD: u32 = 21;
const SO_BINDTODEVICE: u32 = 25;
const SO_ATTACH_FILTER: u32 = 26;
const SO_PEERNAME: u32 = 28;
const SO_ACCEPTCONN: u32 = 30;
const SO_SNDBUFFORCE: u32 = 32;
const SO_RCVBUFFORCE: u32 = 33;
const SO_MARK: u32 = 36;
const SO_PROTOCOL: u32 = 38;
const SO_DOMAIN: u32 = 39;
const SO_SNDTIMEO_NEW: u32 = 67;

const IP_TOS: u32 = 1;
const IP_TTL: u32 = 2;
const IP_MTU_DISCOVER: u32 = 10;
const IP_MTU: u32 = 14;
const IP_TRANSPARENT: u32 = 19;
const IP_MULTICAST_TTL: u32 = 33;
const IP_MULTICAST_LOOP: u32 = 34;

const IPV6_UNICAST_HOPS: u32 = 16;
const IPV6_MULTICAST_HOPS: u32 = 18;
const IPV6_MTU: u32 = 24;
const IPV6_V6ONLY: u32 = 26;

const TCP_NODELAY: u32 = 1;
const TCP_MAXSEG: u32 = 2;
const TCP_KEEPIDLE: u32 = 4;
const TCP_KEEPINTVL: u32 = 5;
const TCP_KEEPCNT: u32 = 6;
const TCP_SYNCNT: u32 = 7;
const TCP_INFO: u32 = 11;
const TCP_CONGESTION: u32 = 13;
const TCP_USER_TIMEOUT: u32 = 18;

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;

fn int(v: i32) -> [u8; 4] {
    v.to_le_bytes()
}

fn as_int(b: &[u8]) -> i32 {
    i32::from_le_bytes(b[..4].try_into().unwrap())
}

fn timeval(sec: i64, usec: i64) -> Vec<u8> {
    [sec.to_le_bytes(), usec.to_le_bytes()].concat()
}

fn tcp() -> SockInfo {
    SockInfo { kind: 0, v6: false, listening: false, stream: true, connected: false, error: 0, tcp_state: 7 }
}

fn udp() -> SockInfo {
    SockInfo { stream: false, ..tcp() }
}

fn tcp6() -> SockInfo {
    SockInfo { v6: true, ..tcp() }
}

/// setsockopt on a TCP/IPv4 socket.
fn set(o: &mut Options, level: u32, name: u32, val: &[u8]) -> i64 {
    o.set(level, name, val, true, false)
}

fn get_int(o: &Options, level: u32, name: u32, info: &SockInfo) -> i32 {
    as_int(&o.get(level, name, info).unwrap())
}

fn with_caps(caps: u64) {
    fake::reset();
    fake::CAPS.set(Some(caps));
}

// --------------------------------------------------------- unknown options

#[test]
fn unknown_levels_and_names_are_enoprotoopt() {
    let mut o = Options::default();
    assert_eq!(set(&mut o, 99, 1, &int(1)), ENOPROTOOPT);
    assert_eq!(set(&mut o, SOL_SOCKET, 0, &int(1)), ENOPROTOOPT);
    assert_eq!(set(&mut o, SOL_SOCKET, 81, &int(1)), ENOPROTOOPT);
    assert_eq!(o.get(IPPROTO_IP, 51, &tcp()), Err(ENOPROTOOPT));
}

#[test]
fn protocol_levels_must_match_the_socket() {
    let mut o = Options::default();
    assert_eq!(o.set(IPPROTO_TCP, TCP_NODELAY, &int(1), false, false), ENOPROTOOPT, "TCP option on UDP");
    assert_eq!(o.set(IPPROTO_UDP, 1, &int(1), true, false), ENOPROTOOPT, "UDP option on TCP");
    assert_eq!(o.set(IPPROTO_UDP, 1, &int(1), false, false), 0, "UDP_CORK on UDP");
    assert_eq!(o.set(IPPROTO_IPV6, IPV6_V6ONLY, &int(1), true, false), ENOPROTOOPT, "IPv6 option on IPv4");
    assert_eq!(o.get(IPPROTO_TCP, TCP_NODELAY, &udp()), Err(ENOPROTOOPT));
}

#[test]
fn read_only_options_cannot_be_set() {
    let mut o = Options::default();
    for name in [SO_TYPE, SO_ERROR, SO_PEERCRED, SO_PEERNAME, SO_ACCEPTCONN, SO_PROTOCOL, SO_DOMAIN] {
        assert_eq!(set(&mut o, SOL_SOCKET, name, &int(1)), ENOPROTOOPT, "SOL_SOCKET {name}");
    }
    assert_eq!(set(&mut o, IPPROTO_IP, IP_MTU, &int(1500)), ENOPROTOOPT);
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_INFO, &[0; 232]), ENOPROTOOPT);
}

// ----------------------------------------------------- SOL_SOCKET: getters

#[test]
fn socket_identity_getters() {
    let o = Options::default();
    assert_eq!(get_int(&o, SOL_SOCKET, SO_TYPE, &tcp()), 1, "SOCK_STREAM");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_TYPE, &udp()), 2, "SOCK_DGRAM");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_TYPE, &SockInfo { kind: 2, ..udp() }), 3, "SOCK_RAW");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_DOMAIN, &tcp()), 2, "AF_INET");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_DOMAIN, &tcp6()), 10, "AF_INET6");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_PROTOCOL, &tcp()), 6);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_PROTOCOL, &udp()), 17);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_PROTOCOL, &SockInfo { kind: 1, ..udp() }), 1, "ICMP");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_PROTOCOL, &SockInfo { kind: 1, v6: true, ..udp() }), 58, "ICMPv6");
    assert_eq!(get_int(&o, SOL_SOCKET, SO_ACCEPTCONN, &SockInfo { listening: true, ..tcp() }), 1);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_ACCEPTCONN, &tcp()), 0);
}

#[test]
fn so_error_reports_positive_errno() {
    let o = Options::default();
    let info = SockInfo { error: -111, ..tcp() }; // ECONNREFUSED stored as a kernel return value
    assert_eq!(get_int(&o, SOL_SOCKET, SO_ERROR, &info), 111);
}

#[test]
fn peer_options_when_unconnected() {
    let o = Options::default();
    assert_eq!(o.get(SOL_SOCKET, SO_PEERNAME, &tcp()), Err(ENOTCONN));
    assert_eq!(o.get(SOL_SOCKET, SO_PEERCRED, &tcp()).unwrap(), vec![0; 12], "struct ucred");
}

// ---------------------------------------------------- SOL_SOCKET: buffers

#[test]
fn buffer_defaults() {
    let o = Options::default();
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &tcp()), 16_384);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVBUF, &tcp()), 131_072);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &udp()), 212_992);
}

#[test]
fn buffer_sizes_are_doubled_clamped_and_floored() {
    let mut o = Options::default();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_SNDBUF, &int(10_000)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &tcp()), 20_000, "Linux doubles the request");

    set(&mut o, SOL_SOCKET, SO_SNDBUF, &int(1_000_000_000));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &tcp()), 2 * 212_992, "capped at wmem_max");

    set(&mut o, SOL_SOCKET, SO_SNDBUF, &int(0));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &tcp()), 4608, "SOCK_MIN_SNDBUF");

    set(&mut o, SOL_SOCKET, SO_RCVBUF, &int(-5));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVBUF, &tcp()), 2304, "negative treated as 0, SOCK_MIN_RCVBUF");

    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVBUF, &[1, 2, 3]), EINVAL);
}

#[test]
fn force_variants_need_net_admin_and_skip_the_cap() {
    with_caps(0);
    let mut o = Options::default();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_SNDBUFFORCE, &int(1_000_000)), EPERM);

    with_caps(CAP_NET_ADMIN);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_SNDBUFFORCE, &int(1_000_000)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_SNDBUF, &tcp()), 2_000_000, "stored under SO_SNDBUF, uncapped");
    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVBUFFORCE, &int(300_000)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVBUF, &tcp()), 600_000);
}

#[test]
fn capability_checks_fail_closed_without_a_task() {
    fake::reset();
    fake::CAPS.set(None);
    let mut o = Options::default();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_SNDBUFFORCE, &int(1)), EPERM);
}

// ------------------------------------------------ SOL_SOCKET: other values

#[test]
fn priority_above_six_needs_net_admin() {
    with_caps(0);
    let mut o = Options::default();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_PRIORITY, &int(6)), 0);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_PRIORITY, &int(7)), EPERM);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_PRIORITY, &int(-1)), EPERM);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_PRIORITY, &[6]), EINVAL, "needs a full int");
    with_caps(CAP_NET_ADMIN);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_PRIORITY, &int(7)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_PRIORITY, &tcp()), 7);
}

#[test]
fn mark_needs_net_admin_or_net_raw() {
    let mut o = Options::default();
    with_caps(0);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_MARK, &int(5)), EPERM);
    with_caps(CAP_NET_RAW);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_MARK, &int(5)), 0);
    with_caps(CAP_NET_ADMIN);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_MARK, &int(6)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_MARK, &tcp()), 6);
}

#[test]
fn linger_normalises_the_onoff_flag() {
    let mut o = Options::default();
    assert_eq!(o.get(SOL_SOCKET, SO_LINGER, &tcp()).unwrap(), vec![0; 8]);
    let val = [int(5), int(30)].concat();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_LINGER, &val), 0);
    let got = o.get(SOL_SOCKET, SO_LINGER, &tcp()).unwrap();
    assert_eq!((as_int(&got[0..4]), as_int(&got[4..8])), (1, 30));
    assert_eq!(set(&mut o, SOL_SOCKET, SO_LINGER, &int(1)), EINVAL, "struct linger is 8 bytes");
}

#[test]
fn rcvlowat_is_at_least_one() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVLOWAT, &tcp()), 1);
    set(&mut o, SOL_SOCKET, SO_RCVLOWAT, &int(0));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVLOWAT, &tcp()), 1);
    set(&mut o, SOL_SOCKET, SO_RCVLOWAT, &int(-3));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVLOWAT, &tcp()), i32::MAX);
    set(&mut o, SOL_SOCKET, SO_RCVLOWAT, &int(512));
    assert_eq!(get_int(&o, SOL_SOCKET, SO_RCVLOWAT, &tcp()), 512);
}

#[test]
fn timeouts_round_trip_through_timeval() {
    let mut o = Options::default();
    assert_eq!((o.rcv_timeout(), o.snd_timeout()), (None, None));
    assert_eq!(o.get(SOL_SOCKET, SO_RCVTIMEO_OLD, &tcp()).unwrap(), timeval(0, 0));

    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(2, 500_000)), 0);
    assert_eq!(o.rcv_timeout(), Some(2_500_000_000));
    assert_eq!(o.get(SOL_SOCKET, SO_RCVTIMEO_OLD, &tcp()).unwrap(), timeval(2, 500_000));

    assert_eq!(set(&mut o, SOL_SOCKET, SO_SNDTIMEO_NEW, &timeval(0, 1)), 0);
    assert_eq!(o.snd_timeout(), Some(1_000));
    assert_eq!(o.get(SOL_SOCKET, SO_SNDTIMEO_OLD, &tcp()).unwrap(), timeval(0, 1), "old and new share state");
}

#[test]
fn timeout_validation() {
    let mut o = Options::default();
    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(1, 1_000_000)), EDOM);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(1, -1)), EDOM);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &[0; 8]), EINVAL);
    set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(5, 0));
    assert_eq!(set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(-1, 0)), 0);
    assert_eq!(o.rcv_timeout(), None, "negative seconds mean no timeout");
    set(&mut o, SOL_SOCKET, SO_RCVTIMEO_OLD, &timeval(i64::MAX, 999_999));
    assert_eq!(o.rcv_timeout(), Some(u64::MAX), "saturates instead of wrapping");
}

#[test]
fn bindtodevice_needs_net_raw_and_a_known_interface() {
    let mut o = Options::default();
    with_caps(0);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_BINDTODEVICE, b"eth0\0"), EPERM);
    with_caps(CAP_NET_RAW);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_BINDTODEVICE, b"eth0\0garbage"), 0);
    assert_eq!(o.get(SOL_SOCKET, SO_BINDTODEVICE, &tcp()).unwrap(), b"eth0");
    assert_eq!(set(&mut o, SOL_SOCKET, SO_BINDTODEVICE, b"lo"), 0);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_BINDTODEVICE, b"wlan0\0"), ENODEV);
    assert_eq!(set(&mut o, SOL_SOCKET, SO_BINDTODEVICE, b""), 0, "empty name unbinds");
    assert_eq!(o.get(SOL_SOCKET, SO_BINDTODEVICE, &tcp()).unwrap(), b"");
}

#[test]
fn boolean_socket_options_normalise_to_zero_or_one() {
    let mut o = Options::default();
    assert!(!o.flag(SOL_SOCKET, SO_REUSEADDR));
    assert_eq!(set(&mut o, SOL_SOCKET, SO_REUSEADDR, &int(42)), 0);
    assert_eq!(get_int(&o, SOL_SOCKET, SO_REUSEADDR, &tcp()), 1);
    assert!(o.flag(SOL_SOCKET, SO_REUSEADDR));
    set(&mut o, SOL_SOCKET, SO_REUSEADDR, &int(0));
    assert!(!o.flag(SOL_SOCKET, SO_REUSEADDR));
    assert_eq!(set(&mut o, SOL_SOCKET, SO_KEEPALIVE, &[1]), EINVAL, "socket-level ints need 4 bytes");
}

#[test]
fn other_known_options_are_stored_verbatim() {
    let mut o = Options::default();
    let filter = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert_eq!(set(&mut o, SOL_SOCKET, SO_ATTACH_FILTER, &filter), 0);
    assert_eq!(o.value(SOL_SOCKET, SO_ATTACH_FILTER), Some(&filter[..]));
    assert_eq!(set(&mut o, SOL_SOCKET, SO_ATTACH_FILTER, &[1, 2]), EINVAL);
}

// ------------------------------------------------------------ IPPROTO_IP

#[test]
fn ip_tos_keeps_ecn_bits_only_for_datagrams() {
    let mut o = Options::default();
    assert_eq!(o.set(IPPROTO_IP, IP_TOS, &int(0xFF), true, false), 0);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TOS, &tcp()), 0xFC);
    o.set(IPPROTO_IP, IP_TOS, &int(0xFF), false, false);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TOS, &udp()), 0xFF);
    assert_eq!(o.set(IPPROTO_IP, IP_TOS, &[0x10], false, false), 0, "IP options accept a single byte");
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TOS, &udp()), 0x10);
    assert_eq!(o.set(IPPROTO_IP, IP_TOS, &[], false, false), EINVAL);
}

#[test]
fn ip_ttl_range_and_reset() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TTL, &tcp()), 64);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TTL, &int(0)), EINVAL);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TTL, &int(256)), EINVAL);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TTL, &int(255)), 0);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TTL, &tcp()), 255);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TTL, &int(-1)), 0, "-1 restores the default");
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TTL, &tcp()), 64);
}

#[test]
fn ip_mtu_discover_and_mtu() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MTU_DISCOVER, &tcp()), 1, "IP_PMTUDISC_WANT");
    assert_eq!(set(&mut o, IPPROTO_IP, IP_MTU_DISCOVER, &int(5)), 0);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_MTU_DISCOVER, &int(6)), EINVAL);
    assert_eq!(o.get(IPPROTO_IP, IP_MTU, &tcp()), Err(ENOTCONN));
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MTU, &SockInfo { connected: true, ..tcp() }), 1500);
}

#[test]
fn ip_transparent_needs_privilege() {
    let mut o = Options::default();
    with_caps(0);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TRANSPARENT, &int(1)), EPERM);
    with_caps(CAP_NET_RAW);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_TRANSPARENT, &int(9)), 0);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_TRANSPARENT, &tcp()), 1);
}

#[test]
fn ip_multicast_options() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MULTICAST_TTL, &udp()), 1);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MULTICAST_LOOP, &udp()), 1);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_MULTICAST_TTL, &int(256)), EINVAL);
    assert_eq!(set(&mut o, IPPROTO_IP, IP_MULTICAST_TTL, &int(-1)), 0);
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MULTICAST_TTL, &udp()), 1, "-1 means the default (1)");
    set(&mut o, IPPROTO_IP, IP_MULTICAST_LOOP, &int(0));
    assert_eq!(get_int(&o, IPPROTO_IP, IP_MULTICAST_LOOP, &udp()), 0);
}

// ----------------------------------------------------------- IPPROTO_IPV6

fn set6(o: &mut Options, name: u32, val: &[u8]) -> i64 {
    o.set(IPPROTO_IPV6, name, val, true, true)
}

#[test]
fn ipv6_hop_limits() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &tcp6()), 64);
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &tcp6()), 1);
    assert_eq!(set6(&mut o, IPV6_UNICAST_HOPS, &int(256)), EINVAL);
    assert_eq!(set6(&mut o, IPV6_UNICAST_HOPS, &[5]), EINVAL, "IPv6 needs a full int");
    assert_eq!(set6(&mut o, IPV6_UNICAST_HOPS, &int(0)), 0);
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &tcp6()), 0);
    assert_eq!(set6(&mut o, IPV6_UNICAST_HOPS, &int(-1)), 0);
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &tcp6()), 64);
}

#[test]
fn ipv6_mtu_minimum_is_1280() {
    let mut o = Options::default();
    assert_eq!(set6(&mut o, IPV6_MTU, &int(1279)), EINVAL);
    assert_eq!(set6(&mut o, IPV6_MTU, &int(1280)), 0);
    let fresh = Options::default();
    assert_eq!(fresh.get(IPPROTO_IPV6, IPV6_MTU, &tcp6()), Err(ENOTCONN));
    assert_eq!(get_int(&fresh, IPPROTO_IPV6, IPV6_MTU, &SockInfo { connected: true, ..tcp6() }), 65536);
}

#[test]
fn ipv6_v6only_is_boolean() {
    let mut o = Options::default();
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_V6ONLY, &tcp6()), 0);
    set6(&mut o, IPV6_V6ONLY, &int(7));
    assert_eq!(get_int(&o, IPPROTO_IPV6, IPV6_V6ONLY, &tcp6()), 1);
}

// ------------------------------------------------------------ IPPROTO_TCP

#[test]
fn tcp_defaults() {
    let o = Options::default();
    let i = tcp();
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_MAXSEG, &i), 536);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_MAXSEG, &SockInfo { connected: true, ..tcp() }), 1460);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_KEEPIDLE, &i), 7200);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_KEEPINTVL, &i), 75);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_KEEPCNT, &i), 9);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_SYNCNT, &i), 6);
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_NODELAY, &i), 0);
    assert_eq!(o.get(IPPROTO_TCP, TCP_CONGESTION, &i).unwrap(), b"cubic");
}

#[test]
fn tcp_integer_ranges() {
    let mut o = Options::default();
    let cases: &[(u32, i32, i64)] = &[
        (TCP_MAXSEG, 0, 0), (TCP_MAXSEG, 87, EINVAL), (TCP_MAXSEG, 88, 0),
        (TCP_MAXSEG, 65535, 0), (TCP_MAXSEG, 65536, EINVAL),
        (TCP_KEEPIDLE, 0, EINVAL), (TCP_KEEPIDLE, 1, 0), (TCP_KEEPIDLE, 32767, 0), (TCP_KEEPIDLE, 32768, EINVAL),
        (TCP_KEEPINTVL, 0, EINVAL), (TCP_KEEPINTVL, 30, 0),
        (TCP_KEEPCNT, 0, EINVAL), (TCP_KEEPCNT, 127, 0), (TCP_KEEPCNT, 128, EINVAL),
        (TCP_SYNCNT, 128, EINVAL), (TCP_SYNCNT, 3, 0),
        (TCP_USER_TIMEOUT, -1, EINVAL), (TCP_USER_TIMEOUT, 0, 0), (TCP_USER_TIMEOUT, 30_000, 0),
    ];
    for &(name, v, want) in cases {
        assert_eq!(set(&mut o, IPPROTO_TCP, name, &int(v)), want, "TCP option {name} = {v}");
    }
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_KEEPIDLE, &tcp()), 32767, "last valid value kept");
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_KEEPIDLE, &[60]), EINVAL, "short value");
}

#[test]
fn tcp_nodelay_is_boolean() {
    let mut o = Options::default();
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_NODELAY, &int(3)), 0);
    assert!(o.flag(IPPROTO_TCP, TCP_NODELAY));
    assert_eq!(get_int(&o, IPPROTO_TCP, TCP_NODELAY, &tcp()), 1);
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_NODELAY, &[1]), EINVAL);
}

#[test]
fn tcp_congestion_accepts_known_algorithms() {
    let mut o = Options::default();
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_CONGESTION, b"reno\0\0\0\0"), 0);
    assert_eq!(o.get(IPPROTO_TCP, TCP_CONGESTION, &tcp()).unwrap(), b"reno");
    assert_eq!(set(&mut o, IPPROTO_TCP, TCP_CONGESTION, b"bbr"), ENOENT);
    assert_eq!(o.get(IPPROTO_TCP, TCP_CONGESTION, &tcp()).unwrap(), b"reno", "failed set keeps the old value");
}

#[test]
fn tcp_info_layout() {
    let o = Options::default();
    let info = o.get(IPPROTO_TCP, TCP_INFO, &SockInfo { tcp_state: 1, ..tcp() }).unwrap();
    assert_eq!(info.len(), 232, "sizeof(struct tcp_info) on Linux 6.x");
    assert_eq!(info[0], 1, "tcpi_state = TCP_ESTABLISHED");
    let u32_at = |o: usize| u32::from_le_bytes(info[o..o + 4].try_into().unwrap());
    assert_eq!(u32_at(8), 1_000_000, "tcpi_rto (us)");
    assert_eq!((u32_at(16), u32_at(20)), (1460, 1460), "tcpi_snd_mss, tcpi_rcv_mss");
}

// ------------------------------------------------------------- Options API

#[test]
fn put_value_and_clone() {
    let mut o = Options::default();
    assert_eq!(o.value(SOL_SOCKET, SO_REUSEADDR), None);
    o.put(SOL_SOCKET, SO_REUSEADDR, &int(1));
    let snapshot = o.clone();
    o.put(SOL_SOCKET, SO_REUSEADDR, &int(0));
    assert!(snapshot.flag(SOL_SOCKET, SO_REUSEADDR), "clone is independent (used by accept)");
    assert!(!o.flag(SOL_SOCKET, SO_REUSEADDR));
}
