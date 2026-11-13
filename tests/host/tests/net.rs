//! Tests for the packet codecs in `src/net`: Ethernet, ARP, IPv4, ICMP, UDP,
//! TCP and DHCP. The interface/driver glue in `net/mod.rs`, `stack.rs` and
//! `e1000.rs` needs hardware and is not covered here.

use hydra_hosttests::net::arp::{ArpCache, ArpPacket};
use hydra_hosttests::net::dhcp::*;
use hydra_hosttests::net::ethernet::{EtherType, EthernetFrame};
use hydra_hosttests::net::icmp::{IcmpPacket, IcmpType};
use hydra_hosttests::net::ipv4::{compute_checksum, IpProtocol, Ipv4Packet};
use hydra_hosttests::net::tcp::{compute_tcp_checksum, TcpFlags, TcpPacket};
use hydra_hosttests::net::udp::UdpPacket;

const MAC_A: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
const IP_A: [u8; 4] = [10, 0, 2, 15];
const IP_B: [u8; 4] = [10, 0, 2, 2];

/// Independent RFC 1071 one's-complement sum, written plainly, for cross-checks.
fn ones_complement_sum(chunks: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = chunks.concat();
    let mut sum = 0u64;
    for pair in bytes.chunks(2) {
        let hi = pair[0] as u64;
        let lo = pair.get(1).copied().unwrap_or(0) as u64;
        sum += (hi << 8) | lo;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ----------------------------------------------------------------- Ethernet

#[test]
fn ethertype_round_trip() {
    assert_eq!(EtherType::from_u16(0x0800), EtherType::Ipv4);
    assert_eq!(EtherType::from_u16(0x0806), EtherType::Arp);
    assert_eq!(EtherType::from_u16(0x86DD), EtherType::Unknown(0x86DD));
    for v in [0x0800u16, 0x0806, 0x86DD, 0, 0xFFFF] {
        assert_eq!(EtherType::from_u16(v).as_u16(), v);
    }
}

#[test]
fn ethernet_serialize_then_parse() {
    let payload = [0xDE; 100];
    let mut buf = [0u8; 1514];
    let n = EthernetFrame::serialize(MAC_B, MAC_A, EtherType::Ipv4, &payload, &mut buf).unwrap();
    assert_eq!(n, 114);
    assert_eq!(&buf[12..14], &[0x08, 0x00], "EtherType is big-endian on the wire");

    let f = EthernetFrame::parse(&buf[..n]).unwrap();
    assert_eq!(f.dst_mac, MAC_B);
    assert_eq!(f.src_mac, MAC_A);
    assert_eq!(f.ethertype, EtherType::Ipv4);
    assert_eq!(f.payload, &payload);
}

#[test]
fn ethernet_pads_short_frames_to_60_bytes() {
    let mut buf = [0xAAu8; 128];
    let n = EthernetFrame::serialize(
        EthernetFrame::BROADCAST_MAC,
        MAC_A,
        EtherType::Arp,
        &[1, 2, 3],
        &mut buf,
    )
    .unwrap();
    assert_eq!(n, 60);
    assert_eq!(&buf[14..17], &[1, 2, 3]);
    assert!(buf[17..60].iter().all(|&b| b == 0), "padding must be zeroed");
    assert_eq!(buf[60], 0xAA, "nothing written past the frame");
}

#[test]
fn ethernet_serialize_rejects_small_buffer() {
    let mut buf = [0u8; 20];
    assert!(EthernetFrame::serialize(MAC_A, MAC_B, EtherType::Ipv4, &[0; 10], &mut buf).is_err());
}

#[test]
#[ignore = "BUG: serialize returns 60 for a short frame even when out_buf is smaller than 60, \
            so the caller's &out_buf[..len] slice panics (src/net/ethernet.rs)"]
fn ethernet_short_frame_length_never_exceeds_buffer() {
    let mut buf = [0u8; 20];
    let n = EthernetFrame::serialize(MAC_A, MAC_B, EtherType::Arp, &[1, 2], &mut buf).unwrap();
    assert!(n <= buf.len(), "returned length {n} exceeds the {}-byte buffer", buf.len());
}

#[test]
fn ethernet_parse_rejects_runts() {
    assert!(EthernetFrame::parse(&[0u8; 13]).is_none());
    let f = EthernetFrame::parse(&[0u8; 14]).unwrap();
    assert!(f.payload.is_empty());
}

// ---------------------------------------------------------------------- ARP

#[test]
fn arp_request_wire_format() {
    let req = ArpPacket::new_request(MAC_A, IP_A, IP_B);
    let mut buf = [0u8; 28];
    assert_eq!(req.serialize(&mut buf), Ok(28));
    assert_eq!(&buf[0..8], &[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    assert_eq!(&buf[8..14], &MAC_A);
    assert_eq!(&buf[14..18], &IP_A);
    assert_eq!(&buf[18..24], &[0; 6], "target MAC is unknown in a request");
    assert_eq!(&buf[24..28], &IP_B);
}

#[test]
fn arp_reply_round_trip() {
    let reply = ArpPacket::new_reply(MAC_B, IP_B, MAC_A, IP_A);
    let mut buf = [0u8; 42];
    reply.serialize(&mut buf).unwrap();
    let p = ArpPacket::parse(&buf).unwrap();
    assert_eq!(p.opcode, 2);
    assert_eq!((p.sender_mac, p.sender_ip, p.target_mac, p.target_ip), (MAC_B, IP_B, MAC_A, IP_A));
}

#[test]
fn arp_parse_rejects_non_ethernet_ipv4() {
    let mut buf = [0u8; 28];
    ArpPacket::new_request(MAC_A, IP_A, IP_B).serialize(&mut buf).unwrap();
    assert!(ArpPacket::parse(&buf[..27]).is_none());
    for (i, v) in [(1, 6u8), (3, 0xDD), (4, 8), (5, 16)] {
        let mut bad = buf;
        bad[i] = v;
        assert!(ArpPacket::parse(&bad).is_none(), "byte {i} = {v:#x} should be rejected");
    }
}

#[test]
fn arp_serialize_rejects_small_buffer() {
    let mut buf = [0u8; 27];
    assert!(ArpPacket::new_request(MAC_A, IP_A, IP_B).serialize(&mut buf).is_err());
}

#[test]
fn arp_cache_insert_lookup_update() {
    let mut cache = ArpCache::new();
    assert_eq!(cache.lookup(IP_A), None);
    cache.insert(IP_A, MAC_A);
    cache.insert(IP_B, MAC_B);
    assert_eq!(cache.lookup(IP_A), Some(MAC_A));
    assert_eq!(cache.lookup(IP_B), Some(MAC_B));
    cache.insert(IP_A, MAC_B);
    assert_eq!(cache.lookup(IP_A), Some(MAC_B), "existing entry is updated in place");
}

#[test]
fn arp_cache_full_overwrites_first_slot() {
    let mut cache = ArpCache::new();
    for i in 0..16u8 {
        cache.insert([192, 168, 0, i], [i; 6]);
    }
    for i in 0..16u8 {
        assert_eq!(cache.lookup([192, 168, 0, i]), Some([i; 6]));
    }
    cache.insert([192, 168, 1, 1], [0xEE; 6]);
    assert_eq!(cache.lookup([192, 168, 1, 1]), Some([0xEE; 6]));
    assert_eq!(cache.lookup([192, 168, 0, 0]), None, "slot 0 was evicted");
    assert_eq!(cache.lookup([192, 168, 0, 15]), Some([15; 6]));
}

// --------------------------------------------------------------------- IPv4

#[test]
fn checksum_rfc1071_example() {
    assert_eq!(compute_checksum(&[0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]), !0xDDF2u16);
}

#[test]
fn checksum_known_ipv4_header() {
    let hdr = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8, 0x00,
        0x01, 0xC0, 0xA8, 0x00, 0xC7,
    ];
    assert_eq!(compute_checksum(&hdr), 0xB861);
}

#[test]
fn checksum_handles_odd_lengths_and_empty() {
    assert_eq!(compute_checksum(&[]), 0xFFFF);
    assert_eq!(compute_checksum(&[0xAB]), !0xAB00u16);
    for len in [1, 3, 17, 1001] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        assert_eq!(compute_checksum(&data), ones_complement_sum(&[&data]), "len {len}");
    }
}

#[test]
fn ip_protocol_round_trip() {
    assert_eq!(IpProtocol::from_u8(1), IpProtocol::Icmp);
    assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);
    assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
    assert_eq!(IpProtocol::from_u8(58), IpProtocol::Unknown(58));
    for v in 0..=255u8 {
        assert_eq!(IpProtocol::from_u8(v).as_u8(), v);
    }
}

#[test]
fn ipv4_serialize_then_parse() {
    let payload = b"udp-or-whatever";
    let mut buf = [0u8; 100];
    let n = Ipv4Packet::serialize(IP_A, IP_B, IpProtocol::Udp, payload, &mut buf).unwrap();
    assert_eq!(n, 20 + payload.len());
    assert_eq!(compute_checksum(&buf[..20]), 0, "header checksum must verify");
    assert_eq!(buf[6] & 0x40, 0x40, "DF bit set");

    let p = Ipv4Packet::parse(&buf[..n]).unwrap();
    assert_eq!((p.version, p.ihl, p.ttl), (4, 5, 64));
    assert_eq!(p.total_length as usize, n);
    assert_eq!(p.protocol, IpProtocol::Udp);
    assert_eq!((p.src_ip, p.dst_ip), (IP_A, IP_B));
    assert_eq!(p.payload, payload);
}

#[test]
fn ipv4_parse_trims_link_layer_padding() {
    let mut buf = [0u8; 46]; // Ethernet minimum payload
    let n = Ipv4Packet::serialize(IP_A, IP_B, IpProtocol::Icmp, &[9; 8], &mut buf).unwrap();
    assert_eq!(n, 28);
    assert_eq!(Ipv4Packet::parse(&buf).unwrap().payload, &[9; 8]);
}

#[test]
fn ipv4_parse_clamps_total_length_to_buffer() {
    let mut buf = [0u8; 40];
    Ipv4Packet::serialize(IP_A, IP_B, IpProtocol::Tcp, &[1; 20], &mut buf).unwrap();
    buf[2] = 0x05; // claims 1280+ bytes
    assert_eq!(Ipv4Packet::parse(&buf).unwrap().payload.len(), 20);
}

#[test]
fn ipv4_parse_skips_options() {
    let mut buf = vec![0u8; 24 + 4];
    buf[0] = 0x46; // IHL 6 => 24-byte header
    buf[3] = 28;
    buf[9] = 6;
    buf[24..28].copy_from_slice(b"data");
    let p = Ipv4Packet::parse(&buf).unwrap();
    assert_eq!(p.ihl, 6);
    assert_eq!(p.payload, b"data");
}

#[test]
fn ipv4_parse_rejects_malformed_headers() {
    let mut buf = [0u8; 40];
    Ipv4Packet::serialize(IP_A, IP_B, IpProtocol::Tcp, &[0; 20], &mut buf).unwrap();
    assert!(Ipv4Packet::parse(&buf[..19]).is_none(), "shorter than a header");

    let mut v6 = buf;
    v6[0] = 0x65;
    assert!(Ipv4Packet::parse(&v6).is_none(), "version 6");

    let mut tiny_ihl = buf;
    tiny_ihl[0] = 0x44;
    assert!(Ipv4Packet::parse(&tiny_ihl).is_none(), "IHL below 5");

    let mut huge_ihl = buf;
    huge_ihl[0] = 0x4F; // 60-byte header in a 40-byte buffer
    assert!(Ipv4Packet::parse(&huge_ihl).is_none());
}

#[test]
fn ipv4_serialize_rejects_small_buffer() {
    let mut buf = [0u8; 25];
    assert!(Ipv4Packet::serialize(IP_A, IP_B, IpProtocol::Udp, &[0; 6], &mut buf).is_err());
}

// --------------------------------------------------------------------- ICMP

#[test]
fn icmp_type_round_trip() {
    assert_eq!(IcmpType::from_u8(0), IcmpType::EchoReply);
    assert_eq!(IcmpType::from_u8(3), IcmpType::DestinationUnreachable);
    assert_eq!(IcmpType::from_u8(8), IcmpType::EchoRequest);
    for v in 0..=255u8 {
        assert_eq!(IcmpType::from_u8(v).as_u8(), v);
    }
}

#[test]
fn icmp_echo_request_round_trip() {
    let mut buf = [0u8; 64];
    let n = IcmpPacket::serialize_echo_request(0x1234, 7, b"ping!", &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(compute_checksum(&buf[..n]), 0, "checksum covers header and odd-length payload");

    let p = IcmpPacket::parse(&buf[..n]).unwrap();
    assert_eq!(p.msg_type, IcmpType::EchoRequest);
    assert_eq!((p.code, p.identifier, p.sequence), (0, 0x1234, 7));
    assert_eq!(p.payload, b"ping!");
}

#[test]
fn icmp_bounds() {
    assert!(IcmpPacket::parse(&[0; 7]).is_none());
    let mut buf = [0u8; 10];
    assert!(IcmpPacket::serialize_echo_request(1, 1, &[0; 3], &mut buf).is_err());
}

// ---------------------------------------------------------------------- UDP

#[test]
fn udp_serialize_then_parse() {
    let mut buf = [0u8; 64];
    let n = UdpPacket::serialize(5353, 53, b"query", &mut buf).unwrap();
    assert_eq!(n, 13);
    let p = UdpPacket::parse(&buf[..n]).unwrap();
    assert_eq!((p.src_port, p.dst_port, p.length, p.checksum), (5353, 53, 13, 0));
    assert_eq!(p.payload, b"query");
}

#[test]
fn udp_parse_honours_length_field() {
    let mut buf = [0u8; 32];
    UdpPacket::serialize(1, 2, b"abc", &mut buf).unwrap();
    assert_eq!(UdpPacket::parse(&buf).unwrap().payload, b"abc", "trailing bytes ignored");

    buf[5] = 200; // length larger than the buffer
    assert_eq!(UdpPacket::parse(&buf).unwrap().payload.len(), 24, "clamped to buffer");

    buf[5] = 3; // length smaller than the header
    assert!(UdpPacket::parse(&buf).unwrap().payload.is_empty());
}

#[test]
fn udp_bounds() {
    assert!(UdpPacket::parse(&[0; 7]).is_none());
    let mut buf = [0u8; 8];
    assert!(UdpPacket::serialize(1, 2, &[0], &mut buf).is_err());
}

// ---------------------------------------------------------------------- TCP

#[test]
fn tcp_flag_bits() {
    let all = [TcpFlags::FIN, TcpFlags::SYN, TcpFlags::RST, TcpFlags::PSH, TcpFlags::ACK, TcpFlags::URG];
    assert_eq!(all, [0x01, 0x02, 0x04, 0x08, 0x10, 0x20]);
}

#[test]
fn tcp_serialize_then_parse() {
    let mut buf = [0u8; 128];
    let n = TcpPacket::serialize(
        IP_A, IP_B, 49152, 80, 0xDEAD_BEEF, 0x0102_0304,
        TcpFlags::PSH | TcpFlags::ACK, 64240, b"GET / HTTP/1.0\r\n\r\n", &mut buf,
    )
    .unwrap();
    assert_eq!(n, 38);
    assert_eq!(buf[12], 0x50, "data offset 5");
    assert_eq!(compute_tcp_checksum(IP_A, IP_B, &buf[..n]), 0, "checksum must verify");

    let p = TcpPacket::parse(&buf[..n]).unwrap();
    assert_eq!((p.src_port, p.dst_port), (49152, 80));
    assert_eq!((p.seq_num, p.ack_num), (0xDEAD_BEEF, 0x0102_0304));
    assert_eq!(p.flags, TcpFlags::PSH | TcpFlags::ACK);
    assert_eq!(p.window_size, 64240);
    assert_eq!(p.payload, b"GET / HTTP/1.0\r\n\r\n");
}

#[test]
fn tcp_checksum_matches_reference() {
    let mut buf = [0u8; 64];
    let n = TcpPacket::serialize(IP_A, IP_B, 1, 2, 3, 4, TcpFlags::SYN, 5, b"odd", &mut buf).unwrap();
    let mut seg = buf[..n].to_vec();
    let stored = u16::from_be_bytes([seg[16], seg[17]]);
    seg[16] = 0;
    seg[17] = 0;
    let pseudo = [&IP_A[..], &IP_B[..], &[0, 6], &(n as u16).to_be_bytes()].concat();
    assert_eq!(stored, ones_complement_sum(&[&pseudo, &seg]));
}

#[test]
fn tcp_checksum_depends_on_pseudo_header() {
    let mut buf = [0u8; 40];
    let n = TcpPacket::serialize(IP_A, IP_B, 1, 2, 3, 4, TcpFlags::ACK, 5, &[], &mut buf).unwrap();
    assert_eq!(compute_tcp_checksum(IP_A, IP_B, &buf[..n]), 0);
    // (Swapping src and dst would still verify: the one's-complement sum is commutative.)
    assert_ne!(compute_tcp_checksum([10, 0, 2, 16], IP_B, &buf[..n]), 0, "wrong src IP must not verify");
}

#[test]
fn tcp_parse_skips_options() {
    let mut buf = vec![0u8; 24 + 2];
    buf[12] = 0x60; // data offset 6 => 4 bytes of options
    buf[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]); // MSS 1460
    buf[24..].copy_from_slice(b"hi");
    assert_eq!(TcpPacket::parse(&buf).unwrap().payload, b"hi");

    buf[12] = 0xF0; // 60-byte header in a 26-byte buffer
    assert!(TcpPacket::parse(&buf).is_none());
}

#[test]
#[ignore = "BUG: parse accepts a data offset below 5 words, so the header is returned as payload \
            (src/net/tcp.rs)"]
fn tcp_parse_rejects_data_offset_below_minimum() {
    let mut buf = [0u8; 24];
    buf[12] = 0x00;
    assert!(TcpPacket::parse(&buf).is_none());
}

#[test]
fn tcp_bounds() {
    assert!(TcpPacket::parse(&[0x50; 19]).is_none());
    let mut buf = [0u8; 20];
    assert!(TcpPacket::serialize(IP_A, IP_B, 1, 2, 3, 4, 0, 5, &[0], &mut buf).is_err());
}

// --------------------------------------------------------------------- DHCP

const XID: u32 = 0xA1B2_C3D4;

#[test]
fn dhcp_discover_layout() {
    let mut buf = [0xEEu8; 400];
    let n = build_dhcp_discover(MAC_A, XID, &mut buf).unwrap();
    assert_eq!(n, 249);
    assert_eq!(&buf[0..4], &[1, 1, 6, 0], "BOOTREQUEST, Ethernet, hlen 6, hops 0");
    assert_eq!(&buf[4..8], &XID.to_be_bytes());
    assert_eq!(&buf[10..12], &[0x80, 0x00], "broadcast flag");
    assert_eq!(&buf[12..16], &[0; 4], "ciaddr");
    assert_eq!(&buf[28..34], &MAC_A);
    assert!(buf[34..236].iter().all(|&b| b == 0), "rest of chaddr, sname, file zeroed");
    assert_eq!(&buf[236..240], &[99, 130, 83, 99], "magic cookie");
    assert_eq!(&buf[240..249], &[53, 1, DHCP_MSG_DISCOVER, 55, 3, 1, 3, 6, 255]);
}

#[test]
fn dhcp_request_layout() {
    let mut buf = [0u8; 300];
    let n = build_dhcp_request(MAC_A, XID, IP_A, IP_B, &mut buf).unwrap();
    assert_eq!(n, 261);
    assert_eq!(&buf[240..243], &[53, 1, DHCP_MSG_REQUEST]);
    assert_eq!(&buf[243..249], &[50, 4, 10, 0, 2, 15]);
    assert_eq!(&buf[249..255], &[54, 4, 10, 0, 2, 2]);
    assert_eq!(&buf[255..261], &[55, 3, 1, 3, 6, 255]);
}

#[test]
fn dhcp_builders_require_300_byte_buffer() {
    let mut buf = [0u8; 299];
    assert!(build_dhcp_discover(MAC_A, XID, &mut buf).is_err());
    assert!(build_dhcp_request(MAC_A, XID, IP_A, IP_B, &mut buf).is_err());
}

fn dhcp_reply(op: u8, xid: u32, yiaddr: [u8; 4], options: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = op;
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[16..20].copy_from_slice(&yiaddr);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(options);
    b
}

#[test]
fn dhcp_parse_offer_with_all_options() {
    let opts = [
        53, 1, DHCP_MSG_OFFER,
        0, 0, // pads
        1, 4, 255, 255, 0, 0,
        3, 8, 10, 0, 2, 2, 10, 0, 2, 3, // two routers: first wins
        6, 4, 8, 8, 8, 8,
        54, 4, 10, 0, 2, 4,
        51, 4, 0, 0, 0x0E, 0x10, // lease time: ignored
        255,
        1, 4, 1, 1, 1, 1, // after END: ignored
    ];
    let (t, lease) = parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &opts), XID).unwrap();
    assert_eq!(t, DHCP_MSG_OFFER);
    assert_eq!(
        lease,
        DhcpLease {
            ip: IP_A,
            subnet_mask: [255, 255, 0, 0],
            router: [10, 0, 2, 2],
            dns_server: [8, 8, 8, 8],
            server_ip: [10, 0, 2, 4],
        }
    );
}

#[test]
fn dhcp_parse_defaults_and_malformed_option_lengths() {
    let opts = [53, 1, DHCP_MSG_ACK, 1, 3, 255, 255, 255, 54, 2, 1, 2, 255];
    let (t, lease) = parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &opts), XID).unwrap();
    assert_eq!(t, DHCP_MSG_ACK);
    assert_eq!(lease.subnet_mask, [255, 255, 255, 0], "3-byte mask ignored, default kept");
    assert_eq!(lease.server_ip, [0; 4], "2-byte server id ignored");
    assert_eq!(DhcpLease::empty().subnet_mask, [255, 255, 255, 0]);
}

#[test]
fn dhcp_parse_rejects_wrong_packets() {
    let opts = [53, 1, DHCP_MSG_OFFER, 255];
    assert!(parse_dhcp_reply(&dhcp_reply(1, XID, IP_A, &opts), XID).is_none(), "BOOTREQUEST");
    assert!(parse_dhcp_reply(&dhcp_reply(2, XID ^ 1, IP_A, &opts), XID).is_none(), "xid");
    let mut bad_cookie = dhcp_reply(2, XID, IP_A, &opts);
    bad_cookie[236] = 0;
    assert!(parse_dhcp_reply(&bad_cookie, XID).is_none(), "cookie");
    assert!(parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &[255]), XID).is_none(), "no message type");
    assert!(parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &[])[..239], XID).is_none(), "short");
}

#[test]
fn dhcp_parse_stops_at_dangling_option_code() {
    let opts = [53, 1, DHCP_MSG_OFFER, 6]; // option 6 with no length byte
    assert_eq!(parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &opts), XID).unwrap().0, DHCP_MSG_OFFER);
}

#[test]
fn dhcp_parse_survives_truncated_option() {
    let opts = [53, 1, DHCP_MSG_OFFER, 6, 200, 8, 8];
    let r = std::panic::catch_unwind(|| parse_dhcp_reply(&dhcp_reply(2, XID, IP_A, &opts), XID));
    assert!(r.is_ok(), "parse_dhcp_reply panicked on a truncated option");
}

#[test]
fn dhcp_discover_is_accepted_by_parser_after_server_rewrite() {
    // A server turns our request into a reply by flipping op and setting yiaddr.
    let mut buf = [0u8; 300];
    let n = build_dhcp_discover(MAC_A, XID, &mut buf).unwrap();
    let mut reply = buf[..n].to_vec();
    reply[0] = 2;
    reply[16..20].copy_from_slice(&IP_A);
    let (t, lease) = parse_dhcp_reply(&reply, XID).unwrap();
    assert_eq!((t, lease.ip), (DHCP_MSG_DISCOVER, IP_A));
}

#[test]
fn arp_cache_lists_its_entries() {
    let mut cache = ArpCache::new();
    assert!(cache.entries().is_empty());
    cache.insert(IP_A, MAC_A);
    cache.insert(IP_B, MAC_B);
    cache.insert(IP_A, MAC_B); // updated in place, not added twice
    let mut e = cache.entries();
    e.sort();
    assert_eq!(e, vec![(IP_B, MAC_B), (IP_A, MAC_B)], "for /proc/net/arp");
}
