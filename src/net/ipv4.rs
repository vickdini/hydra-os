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
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Zero-allocation (`no_std`) parser, serializer, and RFC 1071 checksum calculator.

/// Supported transport-layer protocol numbers encapsulated within IPv4 (RFC 790 / IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// Internet Control Message Protocol (`1`).
    Icmp,
    /// Transmission Control Protocol (`6`).
    Tcp,
    /// User Datagram Protocol (`17`).
    Udp,
    /// Unrecognized or unhandled IPv4 protocol number.
    Unknown(u8),
}

impl IpProtocol {
    /// Raw IPv4 protocol number for ICMP (`1`).
    pub const ICMP: u8 = 1;
    /// Raw IPv4 protocol number for TCP (`6`).
    pub const TCP: u8 = 6;
    /// Raw IPv4 protocol number for UDP (`17`).
    pub const UDP: u8 = 17;

    /// Converts an 8-bit IPv4 protocol field into an [`IpProtocol`] enum variant.
    ///
    /// # Arguments
    /// - `val`: Raw 8-bit protocol identifier from the IPv4 header.
    ///
    /// # Returns
    /// The corresponding [`IpProtocol`] variant.
    pub fn from_u8(val: u8) -> Self {
        match val {
            Self::ICMP => IpProtocol::Icmp,
            Self::TCP => IpProtocol::Tcp,
            Self::UDP => IpProtocol::Udp,
            other => IpProtocol::Unknown(other),
        }
    }

    /// Returns the raw 8-bit protocol number for this [`IpProtocol`].
    pub fn as_u8(&self) -> u8 {
        match *self {
            IpProtocol::Icmp => Self::ICMP,
            IpProtocol::Tcp => Self::TCP,
            IpProtocol::Udp => Self::UDP,
            IpProtocol::Unknown(val) => val,
        }
    }
}

/// Structured zero-copy representation of an IPv4 datagram.
pub struct Ipv4Packet<'a> {
    /// IP version field (always `4` for IPv4).
    pub version: u8,
    /// Internet Header Length in 32-bit words (minimum `5`, i.e., 20 bytes).
    pub ihl: u8,
    /// Total length of the IPv4 datagram (header + payload) in bytes.
    pub total_length: u16,
    /// 16-bit datagram identification field.
    pub id: u16,
    /// Time-To-Live hop limit.
    pub ttl: u8,
    /// Encapsulated transport-layer protocol.
    pub protocol: IpProtocol,
    /// Source 4-byte IPv4 address.
    pub src_ip: [u8; 4],
    /// Destination 4-byte IPv4 address.
    pub dst_ip: [u8; 4],
    /// Borrowed slice containing the transport-layer payload.
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parses an IPv4 datagram from an Ethernet payload slice.
    ///
    /// Validates that the buffer is at least 20 bytes, `version == 4`, and `ihl >= 5`.
    ///
    /// # Arguments
    /// - `buf`: Raw Ethernet payload slice.
    ///
    /// # Returns
    /// `Some(Ipv4Packet)` if the header is valid, or `None` if malformed or truncated.
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

    /// Serializes an IPv4 datagram with a standard 20-byte header and computed RFC 1071 checksum.
    ///
    /// # Arguments
    /// - `src_ip`: Source 4-byte IPv4 address.
    /// - `dst_ip`: Destination 4-byte IPv4 address.
    /// - `protocol`: Encapsulated transport-layer protocol ([`IpProtocol`]).
    /// - `payload`: Transport-layer payload slice.
    /// - `out_buf`: Destination buffer (must be at least `20 + payload.len()` bytes).
    ///
    /// # Returns
    /// `Ok(total_len)` containing the total serialized datagram length in bytes.
    ///
    /// # Errors
    /// Returns `Err` if `out_buf` is smaller than `20 + payload.len()`.
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
///
/// # Arguments
/// - `data`: Byte slice over which to compute the checksum.
///
/// # Returns
/// 16-bit one's complement checksum in host/big-endian order.
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
