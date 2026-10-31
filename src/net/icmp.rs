//! # Network Subsystem: Internet Control Message Protocol (ICMP)
//!
//! Provides generation and validation of ICMP Echo Requests and Replies for network diagnostics (`ping`).
//!
//! ## Architectural Role & Design Rationale
//!
//! ICMP (RFC 792) provides diagnostic and error reporting capabilities at the network layer.
//! The `ping` command relies on ICMP Echo Request (Type 8) and Echo Reply (Type 0) to verify
//! end-to-end IP connectivity and calculate network transit latency.
//!
//! ## Key Types & Interfaces
//!
//! - [`IcmpType`]: Enum distinguishing Echo Request, Echo Reply, and other ICMP control messages.
//! - [`IcmpPacket`]: Structured representation of an ICMP packet with header and checksum.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Uses [`super::ipv4::compute_checksum`] for RFC 792 16-bit one's complement checksums.

use super::ipv4::compute_checksum;

/// ICMP control message type identifiers (RFC 792).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo Reply (`0`).
    EchoReply,
    /// Echo Request (`8`).
    EchoRequest,
    /// Destination Unreachable (`3`).
    DestinationUnreachable,
    /// Unrecognized or unhandled ICMP message type.
    Unknown(u8),
}

impl IcmpType {
    /// Raw ICMP type code for Echo Reply (`0`).
    pub const ECHO_REPLY: u8 = 0;
    /// Raw ICMP type code for Destination Unreachable (`3`).
    pub const DEST_UNREACHABLE: u8 = 3;
    /// Raw ICMP type code for Echo Request (`8`).
    pub const ECHO_REQUEST: u8 = 8;

    /// Converts a raw 8-bit ICMP type field into an [`IcmpType`].
    ///
    /// # Arguments
    /// - `val`: Raw 8-bit type code from the ICMP header.
    ///
    /// # Returns
    /// The corresponding [`IcmpType`] variant.
    pub fn from_u8(val: u8) -> Self {
        match val {
            Self::ECHO_REPLY => IcmpType::EchoReply,
            Self::ECHO_REQUEST => IcmpType::EchoRequest,
            Self::DEST_UNREACHABLE => IcmpType::DestinationUnreachable,
            other => IcmpType::Unknown(other),
        }
    }

    /// Returns the raw 8-bit numeric code for this [`IcmpType`].
    pub fn as_u8(&self) -> u8 {
        match *self {
            IcmpType::EchoReply => Self::ECHO_REPLY,
            IcmpType::EchoRequest => Self::ECHO_REQUEST,
            IcmpType::DestinationUnreachable => Self::DEST_UNREACHABLE,
            IcmpType::Unknown(val) => val,
        }
    }
}

/// Structured zero-copy representation of an ICMP packet.
pub struct IcmpPacket<'a> {
    /// ICMP message type (`EchoRequest`, `EchoReply`, etc.).
    pub msg_type: IcmpType,
    /// ICMP subtype code.
    pub code: u8,
    /// 16-bit Echo Request/Reply identifier.
    pub identifier: u16,
    /// 16-bit Echo Request/Reply sequence number.
    pub sequence: u16,
    /// Borrowed slice containing the ICMP data payload.
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    /// Parses an ICMP packet from an IPv4 payload slice.
    ///
    /// # Arguments
    /// - `buf`: Raw IPv4 payload slice.
    ///
    /// # Returns
    /// `Some(IcmpPacket)` if `buf` is at least 8 bytes long, or `None` otherwise.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        let msg_type = IcmpType::from_u8(buf[0]);
        let code = buf[1];
        let identifier = ((buf[4] as u16) << 8) | (buf[5] as u16);
        let sequence = ((buf[6] as u16) << 8) | (buf[7] as u16);
        let payload = &buf[8..];

        Some(Self {
            msg_type,
            code,
            identifier,
            sequence,
            payload,
        })
    }

    /// Serializes an ICMP Echo Request into the provided buffer with a computed RFC 1071 checksum.
    ///
    /// # Arguments
    /// - `identifier`: 16-bit echo identifier.
    /// - `sequence`: 16-bit echo sequence number.
    /// - `payload`: Echo data bytes to include after the 8-byte header.
    /// - `out_buf`: Destination byte slice (must be at least `8 + payload.len()` bytes).
    ///
    /// # Returns
    /// `Ok(total_len)` containing the total number of bytes written into `out_buf`.
    ///
    /// # Errors
    /// Returns `Err` if `out_buf` is smaller than `8 + payload.len()`.
    pub fn serialize_echo_request(
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        let total_len = 8 + payload.len();
        if out_buf.len() < total_len {
            return Err("Destination buffer too small for ICMP packet");
        }

        out_buf[0] = IcmpType::ECHO_REQUEST;
        out_buf[1] = 0; // Code 0
        out_buf[2] = 0; // Checksum zeroed during computation
        out_buf[3] = 0;
        out_buf[4] = (identifier >> 8) as u8;
        out_buf[5] = (identifier & 0xFF) as u8;
        out_buf[6] = (sequence >> 8) as u8;
        out_buf[7] = (sequence & 0xFF) as u8;

        out_buf[8..total_len].copy_from_slice(payload);

        let cksum = compute_checksum(&out_buf[0..total_len]);
        out_buf[2] = (cksum >> 8) as u8;
        out_buf[3] = (cksum & 0xFF) as u8;

        Ok(total_len)
    }
}
