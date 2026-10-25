//! # Network Subsystem: Internet Protocol Version 4 (IPv4)
//!
//! Provides parsing, validation, serialization, and checksum verification of IPv4 datagrams (RFC 791).
//!
//! ## Architectural Role & Design Rationale
//!
//! IPv4 is the foundational network-layer protocol enabling packet routing across local subnets and
//! the global Internet. Every IPv4 datagram contains a minimum 20-byte header with source and destination
//! IP addresses, payload protocol indicator (ICMP, TCP, UDP), and an Internet Checksum guaranteeing
//! header transmission integrity.
//!
//! ## Key Types & Interfaces
//!
//! - [`IpProtocol`]: Enum for encapsulated transport protocols (ICMP, TCP, UDP).
//! - [`Ipv4Packet`]: Structured representation of an IPv4 datagram.
//! - [`compute_checksum()`]: One's complement 16-bit checksum algorithm.

/// Supported transport-layer protocol numbers encapsulated within IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Unknown(u8),
}

impl IpProtocol {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    pub fn from_u8(val: u8) -> Self {
        match val {
            Self::ICMP => IpProtocol::Icmp,
            Self::TCP => IpProtocol::Tcp,
            Self::UDP => IpProtocol::Udp,
            other => IpProtocol::Unknown(other),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match *self {
            IpProtocol::Icmp => Self::ICMP,
            IpProtocol::Tcp => Self::TCP,
            IpProtocol::Udp => Self::UDP,
            IpProtocol::Unknown(val) => val,
        }
    }
}

/// Structured representation of an IPv4 datagram.
pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub id: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parses an IPv4 datagram from a payload slice.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }

        let ver_ihl = buf[0];
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;

        if version != 4 || ihl < 5 {
            return None;
        }

        let header_len = (ihl as usize) * 4;
        if buf.len() < header_len {
            return None;
        }

        let total_length = ((buf[2] as u16) << 8) | (buf[3] as u16);
        let id = ((buf[4] as u16) << 8) | (buf[5] as u16);
        let ttl = buf[8];
        let protocol = IpProtocol::from_u8(buf[9]);

        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&buf[12..16]);
        dst_ip.copy_from_slice(&buf[16..20]);

        let payload_len = (total_length as usize).saturating_sub(header_len).min(buf.len().saturating_sub(header_len));
        let payload = &buf[header_len..header_len + payload_len];

        Some(Self {
            version,
            ihl,
            total_length,
            id,
            ttl,
            protocol,
            src_ip,
            dst_ip,
            payload,
        })
    }

    /// Serializes an IPv4 datagram with a valid 20-byte header and computed checksum.
    pub fn serialize(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: IpProtocol,
        payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        let total_len = 20 + payload.len();
        if out_buf.len() < total_len {
            return Err("Destination buffer too small for IPv4 packet");
        }

        out_buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        out_buf[1] = 0x00; // Type of service
        out_buf[2] = (total_len >> 8) as u8;
        out_buf[3] = (total_len & 0xFF) as u8;
        out_buf[4] = 0x12; // Identification
        out_buf[5] = 0x34;
        out_buf[6] = 0x40; // Don't fragment flag (bit 14 = 1)
        out_buf[7] = 0x00;
        out_buf[8] = 64;   // TTL = 64 hops
        out_buf[9] = protocol.as_u8();
        out_buf[10] = 0x00; // Checksum zeroed during calculation
        out_buf[11] = 0x00;
        out_buf[12..16].copy_from_slice(&src_ip);
        out_buf[16..20].copy_from_slice(&dst_ip);

        // Compute 16-bit Internet Checksum over the 20-byte header
        let cksum = compute_checksum(&out_buf[0..20]);
        out_buf[10] = (cksum >> 8) as u8;
        out_buf[11] = (cksum & 0xFF) as u8;

        out_buf[20..total_len].copy_from_slice(payload);

        Ok(total_len)
    }
}

/// Computes the standard 16-bit one's complement Internet Checksum (RFC 1071).
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }

    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
