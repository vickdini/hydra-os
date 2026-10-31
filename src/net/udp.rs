//! # Network Subsystem: User Datagram Protocol (UDP)
//!
//! Provides parsing and serialization of stateless UDP datagrams (RFC 768).
//!
//! ## Architectural Role & Design Rationale
//!
//! UDP provides lightweight, connectionless datagram transport with 16-bit port multiplexing.
//! In Hydra OS, UDP powers critical network bootstrapping services, including DHCP (Dynamic Host
//! Configuration Protocol, ports 67/68) and DNS (Domain Name System, port 53).
//!
//! ## Key Types & Interfaces
//!
//! - [`UdpPacket`]: Structured representation of a UDP datagram header and payload.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Zero-allocation (`no_std`) UDP datagram parser and serializer.

/// Structured zero-copy representation of a UDP datagram (RFC 768).
pub struct UdpPacket<'a> {
    /// Source 16-bit UDP port number.
    pub src_port: u16,
    /// Destination 16-bit UDP port number.
    pub dst_port: u16,
    /// Total length of the UDP header (8 bytes) plus payload in bytes.
    pub length: u16,
    /// 16-bit UDP checksum (`0` indicates unused in IPv4).
    pub checksum: u16,
    /// Borrowed slice containing the UDP datagram payload.
    pub payload: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    /// Parses a UDP datagram from an IPv4 payload slice.
    ///
    /// # Arguments
    /// - `buf`: Raw IPv4 payload slice.
    ///
    /// # Returns
    /// `Some(UdpPacket)` if `buf` is at least 8 bytes long, or `None` otherwise.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        let src_port = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let dst_port = ((buf[2] as u16) << 8) | (buf[3] as u16);
        let length = ((buf[4] as u16) << 8) | (buf[5] as u16);
        let checksum = ((buf[6] as u16) << 8) | (buf[7] as u16);

        let payload_len = (length as usize).saturating_sub(8).min(buf.len().saturating_sub(8));
        let payload = &buf[8..8 + payload_len];

        Some(Self {
            src_port,
            dst_port,
            length,
            checksum,
            payload,
        })
    }

    /// Serializes a UDP datagram into the destination buffer.
    ///
    /// # Arguments
    /// - `src_port`: Source 16-bit UDP port.
    /// - `dst_port`: Destination 16-bit UDP port.
    /// - `payload`: Datagram payload slice.
    /// - `out_buf`: Destination buffer (must be at least `8 + payload.len()` bytes).
    ///
    /// # Returns
    /// `Ok(total_len)` containing the total serialized UDP datagram length in bytes.
    ///
    /// # Errors
    /// Returns `Err` if `out_buf` is smaller than `8 + payload.len()`.
    pub fn serialize(
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        let total_len = 8 + payload.len();
        if out_buf.len() < total_len {
            return Err("Destination buffer too small for UDP datagram");
        }

        out_buf[0] = (src_port >> 8) as u8;
        out_buf[1] = (src_port & 0xFF) as u8;
        out_buf[2] = (dst_port >> 8) as u8;
        out_buf[3] = (dst_port & 0xFF) as u8;
        out_buf[4] = (total_len >> 8) as u8;
        out_buf[5] = (total_len & 0xFF) as u8;
        out_buf[6] = 0; // Checksum optional in IPv4 (0 = none)
        out_buf[7] = 0;

        out_buf[8..total_len].copy_from_slice(payload);

        Ok(total_len)
    }
}
