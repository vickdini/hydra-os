//! # Network Subsystem: Domain Name System (DNS) Client
//!
//! Provides RFC 1035 UDP-based DNS name resolution for Hydra OS.
//!
//! ## Architectural Role & Design Rationale
//!
//! Rather than forcing users and applications to remember numerical IPv4 addresses (e.g. `142.250.190.46`),
//! the DNS client transparently converts human-readable domain names and URLs (e.g. `google.com`)
//! into 32-bit IPv4 addresses over standard UDP port 53.
//!
//! ## Message Format (RFC 1035)
//!
//! ```text
//! +---------------------+---------------------+
//! |  Transaction ID (16)|   Flags: 0x0100 (16)|
//! +---------------------+---------------------+
//! |  Questions: 0x0001  |   Answer RRs: 0x0000|
//! +---------------------+---------------------+
//! |  Authority RRs: 0x0 |   Additional RRs: 0 |
//! +---------------------+---------------------+
//! | QNAME: \x06google\x03com\x00 (Labels)     |
//! +---------------------+---------------------+
//! | QTYPE: 0x0001 (A)   | QCLASS: 0x0001 (IN) |
//! +---------------------+---------------------+
//! ```

use crate::net::ipv4::IpProtocol;
use crate::net::udp::UdpPacket;
use crate::net::GLOBAL_INTERFACE;

pub const DNS_PORT: u16 = 53;
pub const DNS_CLIENT_PORT: u16 = 53535;

/// Strips protocols (`http://`, `https://`), paths (`/...`), and port numbers (`:80`) from input URLs.
pub fn clean_host(input: &str) -> &str {
    let s = input.trim();
    let s = if let Some(stripped) = s.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("http://") {
        stripped
    } else {
        s
    };

    // Strip path if present
    let host_part = match s.find('/') {
        Some(pos) => &s[..pos],
        None => s,
    };

    // Strip port if present
    match host_part.find(':') {
        Some(pos) => &host_part[..pos],
        None => host_part,
    }
}

/// Constructs an RFC 1035 standard DNS query for an `A` record.
pub fn build_dns_query(
    domain: &str,
    tx_id: u16,
    out_buf: &mut [u8],
) -> Result<usize, &'static str> {
    if out_buf.len() < 512 {
        return Err("Destination buffer too small for DNS query");
    }

    // 1. DNS Header (12 bytes)
    out_buf[0] = (tx_id >> 8) as u8;
    out_buf[1] = (tx_id & 0xFF) as u8;
    out_buf[2] = 0x01; // QR=0, Opcode=0, TC=0, RD=1 (Recursion Desired)
    out_buf[3] = 0x00; // RA=0, Z=0, RCODE=0
    out_buf[4] = 0x00; // QDCOUNT = 1
    out_buf[5] = 0x01;
    out_buf[6] = 0x00; // ANCOUNT = 0
    out_buf[7] = 0x00;
    out_buf[8] = 0x00; // NSCOUNT = 0
    out_buf[9] = 0x00;
    out_buf[10] = 0x00; // ARCOUNT = 0
    out_buf[11] = 0x00;

    // 2. QNAME: Series of length-prefixed labels
    let mut offset = 12;
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err("DNS label exceeds 63 characters");
        }
        out_buf[offset] = label.len() as u8;
        offset += 1;
        out_buf[offset..offset + label.len()].copy_from_slice(label.as_bytes());
        offset += label.len();
    }
    // Null byte terminates the domain name
    out_buf[offset] = 0x00;
    offset += 1;

    // QTYPE: 0x0001 (Type A: Host Address)
    out_buf[offset] = 0x00;
    out_buf[offset + 1] = 0x01;
    offset += 2;

    // QCLASS: 0x0001 (Class IN: Internet)
    out_buf[offset] = 0x00;
    out_buf[offset + 1] = 0x01;
    offset += 2;

    Ok(offset)
}

/// Parses an RFC 1035 DNS response and returns the resolved 4-byte IPv4 address.
pub fn parse_dns_response(buf: &[u8], expected_tx_id: u16) -> Result<[u8; 4], &'static str> {
    if buf.len() < 12 {
        return Err("DNS response payload shorter than 12-byte header");
    }

    // Check Transaction ID
    let tx_id = ((buf[0] as u16) << 8) | (buf[1] as u16);
    if tx_id != expected_tx_id {
        return Err("DNS transaction ID mismatch");
    }

    // Check QR bit (1 = response) and RCODE (0 = no error)
    let flags = ((buf[2] as u16) << 8) | (buf[3] as u16);
    if (flags & 0x8000) == 0 {
        return Err("Received DNS packet is a query, not a response");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err("DNS server returned an error (NXDOMAIN / Name Error)");
    }

    let qdcount = ((buf[4] as u16) << 8) | (buf[5] as u16);
    let ancount = ((buf[6] as u16) << 8) | (buf[7] as u16);

    if ancount == 0 {
        return Err("DNS response contains 0 answer records");
    }

    let mut offset = 12;

    // Skip question section
    for _ in 0..qdcount {
        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                offset += 2;
                break;
            }
            offset += 1 + len;
        }
        // Skip QTYPE (2) + QCLASS (2)
        offset += 4;
    }

    // Parse Answer section
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }

        // Skip Resource Record NAME
        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + len;
        }

        if offset + 10 > buf.len() {
            break;
        }

        let rtype = ((buf[offset] as u16) << 8) | (buf[offset + 1] as u16);
        let _rclass = ((buf[offset + 2] as u16) << 8) | (buf[offset + 3] as u16);
        let rdlength = (((buf[offset + 8] as u16) << 8) | (buf[offset + 9] as u16)) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        // Type 1 is 'A' (IPv4 Address), length 4 bytes
        if rtype == 1 && rdlength == 4 {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[offset..offset + 4]);
            return Ok(ip);
        }

        offset += rdlength;
    }

    Err("No IPv4 (A) record found in DNS answers")
}

/// Resolves a domain name into an IPv4 address using the configured DNS server.
pub fn resolve(domain: &str) -> Result<[u8; 4], &'static str> {
    let clean = clean_host(domain);
    if clean.is_empty() {
        return Err("Domain name cannot be empty");
    }

    let mut iface = GLOBAL_INTERFACE.lock();
    if iface.ip() == [0, 0, 0, 0] {
        if crate::net::e1000::is_present() && crate::net::e1000::is_link_up() {
            drop(iface);
            let _ = crate::net::dhcp_acquire();
            iface = GLOBAL_INTERFACE.lock();
        }
        if iface.ip() == [0, 0, 0, 0] {
            return Err("Network interface has no IP address. Run 'dhcp' first.");
        }
    }

    let dns_server = if iface.dns_server() != [0, 0, 0, 0] {
        iface.dns_server()
    } else {
        // Fallback to standard QEMU/VirtualBox DNS or Cloudflare DNS
        [10, 0, 2, 3]
    };

    let tx_id: u16 = 0x5432;
    let mut dns_buf = [0u8; 512];
    let query_len = build_dns_query(clean, tx_id, &mut dns_buf)?;

    let mut udp_buf = [0u8; 550];
    let udp_len = UdpPacket::serialize(
        DNS_CLIENT_PORT,
        DNS_PORT,
        &dns_buf[..query_len],
        &mut udp_buf,
    )?;

    iface.send_ipv4(dns_server, IpProtocol::Udp, &udp_buf[..udp_len])?;

    // Poll for DNS response
    let mut rx_buf = [0u8; 1518];
    for _ in 0..1500 {
        if let Some((src_ip, payload)) = iface.poll_ipv4(&mut rx_buf) {
            if src_ip == dns_server {
                if let Some(udp) = UdpPacket::parse(payload) {
                    if udp.dst_port == DNS_CLIENT_PORT {
                        if let Ok(ip) = parse_dns_response(udp.payload, tx_id) {
                            return Ok(ip);
                        }
                    }
                }
            }
        }
        crate::arch::pit::sleep_ms(1);
    }

    Err("DNS query timed out: no response from DNS server")
}
