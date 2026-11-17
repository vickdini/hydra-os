//! Tests for the DNS client in net-server's `net/dns.rs`: host-name cleanup, query
//! encoding (RFC 1035 §4.1), response parsing, and the resolver state machine
//! (`Lookup`) net-server drives.

use hydra_hosttests::net::dns::*;

const TX: u16 = 0x5432; // a transaction id

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

// ---------------------------------------------------------------- Lookup
// The resolver runs in net-server as a state machine: it sends `query` (on a UDP socket
// of its own) and feeds replies to `answer`; `timer` schedules retransmissions.

const DNS_IP: [u8; 4] = [10, 0, 2, 3];

#[test]
fn lookup_builds_the_query_for_the_cleaned_host() {
    let l = Lookup::new("https://example.com/index.html", TX, [8, 8, 8, 8], 0).unwrap();
    let mut q = [0u8; 512];
    let qn = build_dns_query("example.com", TX, &mut q).unwrap();
    assert_eq!(l.query, &q[..qn], "the URL was reduced to its host name");
    assert_eq!(l.server, [8, 8, 8, 8]);
}

#[test]
fn lookup_falls_back_to_the_qemu_resolver() {
    assert_eq!(Lookup::new("example.com", TX, [0; 4], 0).unwrap().server, DNS_IP);
}

#[test]
fn lookup_takes_its_answer_and_ignores_unrelated_traffic() {
    let l = Lookup::new("example.com", TX, DNS_IP, 0).unwrap();
    let good = response(TX, OK, "example.com", &[a_record([4, 4, 4, 4])]);
    let wrong_id = response(TX + 1, OK, "example.com", &[a_record([6, 6, 6, 6])]);
    assert_eq!(l.answer([6, 6, 6, 6], &good), None, "spoofed source");
    assert_eq!(l.answer(DNS_IP, &wrong_id), None, "another transaction");
    assert_eq!(l.answer(DNS_IP, &[1]), None, "too short");
    assert_eq!(l.answer(DNS_IP, &good), Some(Ok([4, 4, 4, 4])));
    let nx = response(TX, 0x8183, "example.com", &[]);
    assert!(matches!(l.answer(DNS_IP, &nx), Some(Err(_))), "an error answer ends the lookup");
}

#[test]
fn lookup_retransmits_then_fails() {
    let mut l = Lookup::new("example.com", TX, DNS_IP, 1000).unwrap();
    assert_eq!(l.timer(1000 + DNS_RETRY_TICKS - 1), LookupTimer::Wait);
    let mut t = 1000;
    for _ in 1..DNS_TRIES {
        t += DNS_RETRY_TICKS;
        assert_eq!(l.timer(t), LookupTimer::Resend);
    }
    t += DNS_RETRY_TICKS;
    assert_eq!(l.timer(t), LookupTimer::Failed);
}

#[test]
fn lookup_rejects_empty_names() {
    assert!(Lookup::new("   ", TX, DNS_IP, 0).is_err());
    assert!(Lookup::new("http:///path", TX, DNS_IP, 0).is_err());
}
