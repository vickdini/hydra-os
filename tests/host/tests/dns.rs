//! Tests for the DNS client in `src/net/dns.rs`: host-name cleanup, query
//! encoding (RFC 1035 §4.1), response parsing, and the `resolve` loop running
//! against the scripted fake interface in `fake::NET`.

use hydra_hosttests::fake;
use hydra_hosttests::net::dns::*;
use hydra_hosttests::net::udp::UdpPacket;

const TX: u16 = 0x5432; // the transaction id `resolve` uses

// ------------------------------------------------------------- clean_host

#[test]
fn clean_host_strips_scheme_path_and_port() {
    let cases = [
        ("example.com", "example.com"),
        ("  example.com\n", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com/", "example.com"),
        ("https://example.com:8443/a/b?c=d", "example.com"),
        ("example.com:80", "example.com"),
        ("http://a/b:c", "a"),
        ("ftp://example.com", "ftp"), // only http(s) schemes are recognised
        ("", ""),
    ];
    for (input, want) in cases {
        assert_eq!(clean_host(input), want, "{input:?}");
    }
}

// ----------------------------------------------------------------- query

#[test]
fn query_wire_format() {
    let mut buf = [0u8; 512];
    let n = build_dns_query("www.example.com", 0xBEEF, &mut buf).unwrap();
    let expected: Vec<u8> = [
        &[0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..], // id, RD, QDCOUNT=1
        b"\x03www\x07example\x03com\x00",
        &[0, 1, 0, 1], // QTYPE=A, QCLASS=IN
    ]
    .concat();
    assert_eq!(&buf[..n], &expected[..]);
}

#[test]
fn query_ignores_empty_labels() {
    let mut a = [0u8; 512];
    let mut b = [0u8; 512];
    let n = build_dns_query("example.com.", 1, &mut a).unwrap();
    let m = build_dns_query("example..com", 1, &mut b).unwrap();
    let plain = build_dns_query("example.com", 1, &mut [0u8; 512]).unwrap();
    assert_eq!((n, m), (plain, plain));
    assert_eq!(&a[..n], &b[..m]);
}

#[test]
fn query_label_length_limit() {
    let mut buf = [0u8; 512];
    let ok = format!("{}.com", "a".repeat(63));
    assert!(build_dns_query(&ok, 1, &mut buf).is_ok());
    let too_long = format!("{}.com", "a".repeat(64));
    assert!(build_dns_query(&too_long, 1, &mut buf).is_err());
}

#[test]
fn query_needs_a_512_byte_buffer() {
    assert!(build_dns_query("a.b", 1, &mut [0u8; 511]).is_err());
}

#[test]
fn query_rejects_names_longer_than_253_bytes() {
    let label = "a".repeat(63);
    let name = vec![label.as_str(); 9].join("."); // 575 bytes
    let r = std::panic::catch_unwind(|| build_dns_query(&name, 1, &mut [0u8; 512]));
    assert!(matches!(r, Ok(Err(_))), "expected an error, got {:?}", r.map(|x| x.is_ok()));
    let a63 = "a".repeat(63);
    let at_limit = format!("{a63}.{a63}.{a63}.{}", "a".repeat(61)); // 253 characters, 255 encoded
    assert!(build_dns_query(&at_limit, 1, &mut [0u8; 512]).is_ok(), "the longest legal name");
    assert!(build_dns_query(&format!("{at_limit}a"), 1, &mut [0u8; 512]).is_err(), "one byte more");
}

// -------------------------------------------------------------- response

struct Answer {
    name: Vec<u8>, // encoded owner name or compression pointer
    rtype: u16,
    rdata: Vec<u8>,
}

fn a_record(ip: [u8; 4]) -> Answer {
    Answer { name: vec![0xC0, 0x0C], rtype: 1, rdata: ip.to_vec() }
}

fn response(id: u16, flags: u16, question: &str, answers: &[Answer]) -> Vec<u8> {
    let mut q = [0u8; 512];
    let qlen = build_dns_query(question, id, &mut q).unwrap();
    let mut out = q[..qlen].to_vec();
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    for a in answers {
        out.extend_from_slice(&a.name);
        out.extend_from_slice(&a.rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]); // class IN, TTL 3600
        out.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&a.rdata);
    }
    out
}

const OK: u16 = 0x8180; // QR, RD, RA, NOERROR

#[test]
fn parses_a_record() {
    let r = response(7, OK, "example.com", &[a_record([93, 184, 216, 34])]);
    assert_eq!(parse_dns_response(&r, 7), Ok([93, 184, 216, 34]));
}

#[test]
fn skips_cname_and_aaaa_before_the_a_record() {
    let cname = Answer { name: vec![0xC0, 0x0C], rtype: 5, rdata: b"\x03cdn\x07example\x03net\x00".to_vec() };
    let aaaa = Answer { name: b"\x03cdn\x07example\x03net\x00".to_vec(), rtype: 28, rdata: vec![0x20; 16] };
    let a = Answer { name: b"\x03cdn\x07example\x03net\x00".to_vec(), rtype: 1, rdata: vec![1, 2, 3, 4] };
    let r = response(7, OK, "www.example.com", &[cname, aaaa, a]);
    assert_eq!(parse_dns_response(&r, 7), Ok([1, 2, 3, 4]));
}

#[test]
fn returns_first_a_record() {
    let r = response(7, OK, "example.com", &[a_record([1, 1, 1, 1]), a_record([2, 2, 2, 2])]);
    assert_eq!(parse_dns_response(&r, 7), Ok([1, 1, 1, 1]));
}

#[test]
fn rejects_non_answers() {
    let good = response(7, OK, "example.com", &[a_record([1, 2, 3, 4])]);
    assert!(parse_dns_response(&good[..11], 7).is_err(), "short header");
    assert!(parse_dns_response(&good, 8).is_err(), "transaction id");
    assert!(parse_dns_response(&response(7, 0x0100, "example.com", &[a_record([1, 2, 3, 4])]), 7).is_err(), "query");
    assert!(parse_dns_response(&response(7, 0x8183, "example.com", &[a_record([1, 2, 3, 4])]), 7).is_err(), "NXDOMAIN");
    assert!(parse_dns_response(&response(7, 0x8182, "example.com", &[a_record([1, 2, 3, 4])]), 7).is_err(), "SERVFAIL");
    assert!(parse_dns_response(&response(7, OK, "example.com", &[]), 7).is_err(), "no answers");
    let only_aaaa = Answer { name: vec![0xC0, 0x0C], rtype: 28, rdata: vec![0; 16] };
    assert!(parse_dns_response(&response(7, OK, "example.com", &[only_aaaa]), 7).is_err());
    let bad_len = Answer { name: vec![0xC0, 0x0C], rtype: 1, rdata: vec![1, 2, 3, 4, 5] };
    assert!(parse_dns_response(&response(7, OK, "example.com", &[bad_len]), 7).is_err(), "A with rdlength 5");
}

#[test]
fn truncated_responses_are_errors_not_panics() {
    let r = response(7, OK, "example.com", &[a_record([1, 2, 3, 4])]);
    for cut in 12..r.len() {
        assert!(parse_dns_response(&r[..cut], 7).is_err(), "cut at {cut}");
    }
}

#[test]
fn corrupted_responses_never_panic() {
    let r = response(7, OK, "sub.example.com", &[a_record([1, 2, 3, 4]), a_record([5, 6, 7, 8])]);
    for i in 4..r.len() {
        for v in [0x00, 0x3F, 0xC0, 0xFF] {
            let mut bad = r.clone();
            bad[i] = v;
            let _ = parse_dns_response(&bad, 7);
        }
    }
}

// --------------------------------------------------------------- resolve

const MY_IP: [u8; 4] = [10, 0, 2, 15];
const DNS_IP: [u8; 4] = [10, 0, 2, 3];

fn udp_reply(dns_payload: &[u8], dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + dns_payload.len()];
    let n = UdpPacket::serialize(DNS_PORT, dst_port, dns_payload, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn online(dns: [u8; 4]) {
    fake::reset();
    fake::NET.with_borrow_mut(|n| {
        n.ip = MY_IP;
        n.dns = dns;
        n.nic_present = true;
    });
}

#[test]
fn resolve_sends_one_query_and_returns_the_answer() {
    online([8, 8, 8, 8]);
    let reply = response(TX, OK, "example.com", &[a_record([93, 184, 216, 34])]);
    fake::NET.with_borrow_mut(|n| n.inbox.push_back(([8, 8, 8, 8], udp_reply(&reply, DNS_CLIENT_PORT))));

    assert_eq!(resolve("https://example.com/index.html"), Ok([93, 184, 216, 34]));

    fake::NET.with_borrow(|n| {
        assert_eq!(n.sent.len(), 1);
        let (dst, proto, payload) = &n.sent[0];
        assert_eq!((*dst, *proto), ([8, 8, 8, 8], 17), "UDP to the configured server");
        let udp = UdpPacket::parse(payload).unwrap();
        assert_eq!((udp.src_port, udp.dst_port), (DNS_CLIENT_PORT, DNS_PORT));
        let mut q = [0u8; 512];
        let qn = build_dns_query("example.com", TX, &mut q).unwrap();
        assert_eq!(udp.payload, &q[..qn], "the URL was reduced to its host name");
    });
}

#[test]
fn resolve_falls_back_to_the_qemu_resolver() {
    online([0; 4]);
    let reply = response(TX, OK, "example.com", &[a_record([1, 2, 3, 4])]);
    fake::NET.with_borrow_mut(|n| n.inbox.push_back((DNS_IP, udp_reply(&reply, DNS_CLIENT_PORT))));
    assert_eq!(resolve("example.com"), Ok([1, 2, 3, 4]));
    fake::NET.with_borrow(|n| assert_eq!(n.sent[0].0, DNS_IP));
}

#[test]
fn resolve_ignores_unrelated_traffic() {
    online(DNS_IP);
    let good = response(TX, OK, "example.com", &[a_record([4, 4, 4, 4])]);
    let wrong_id = response(TX + 1, OK, "example.com", &[a_record([6, 6, 6, 6])]);
    fake::NET.with_borrow_mut(|n| {
        n.inbox.push_back(([6, 6, 6, 6], udp_reply(&good, DNS_CLIENT_PORT))); // spoofed source
        n.inbox.push_back((DNS_IP, udp_reply(&good, 9999))); // other port
        n.inbox.push_back((DNS_IP, udp_reply(&wrong_id, DNS_CLIENT_PORT)));
        n.inbox.push_back((DNS_IP, vec![1, 2, 3])); // not even UDP
        n.inbox.push_back((DNS_IP, udp_reply(&good, DNS_CLIENT_PORT)));
    });
    assert_eq!(resolve("example.com"), Ok([4, 4, 4, 4]));
}

#[test]
fn resolve_times_out_after_1500_polls() {
    online(DNS_IP);
    assert!(resolve("example.com").is_err());
    fake::NET.with_borrow(|n| {
        assert_eq!(n.polls, 1500);
        assert_eq!(n.sleeps, 1500, "1 ms between polls");
    });
}

#[test]
fn resolve_runs_dhcp_when_unconfigured() {
    fake::reset();
    fake::NET.with_borrow_mut(|n| {
        n.nic_present = true;
        n.dhcp_ip = Some(MY_IP);
    });
    let reply = response(TX, OK, "example.com", &[a_record([9, 9, 9, 9])]);
    fake::NET.with_borrow_mut(|n| n.inbox.push_back((DNS_IP, udp_reply(&reply, DNS_CLIENT_PORT))));
    assert_eq!(resolve("example.com"), Ok([9, 9, 9, 9]));
    fake::NET.with_borrow(|n| assert_eq!(n.dhcp_calls, 1));
}

#[test]
fn resolve_without_network_fails_fast() {
    fake::reset();
    assert!(resolve("example.com").is_err(), "no NIC, no IP");
    fake::NET.with_borrow(|n| assert!(n.sent.is_empty() && n.dhcp_calls == 0));

    fake::NET.with_borrow_mut(|n| n.nic_present = true); // DHCP fails
    assert!(resolve("example.com").is_err());
    fake::NET.with_borrow(|n| assert!(n.sent.is_empty() && n.dhcp_calls == 1));
}

#[test]
fn resolve_rejects_empty_names() {
    online(DNS_IP);
    assert!(resolve("   ").is_err());
    assert!(resolve("http:///path").is_err());
    fake::NET.with_borrow(|n| assert!(n.sent.is_empty()));
}
