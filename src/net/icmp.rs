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

use super::ipv4::compute_checksum;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    Unknown(u8),
}

impl IcmpType {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;

    pub fn from_u8(val: u8) -> Self {
        match val {
            Self::ECHO_REPLY => IcmpType::EchoReply,
            Self::ECHO_REQUEST => IcmpType::EchoRequest,
            Self::DEST_UNREACHABLE => IcmpType::DestinationUnreachable,
            other => IcmpType::Unknown(other),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match *self {
            IcmpType::EchoReply => Self::ECHO_REPLY,
            IcmpType::EchoRequest => Self::ECHO_REQUEST,
            IcmpType::DestinationUnreachable => Self::DEST_UNREACHABLE,
            IcmpType::Unknown(val) => val,
        }
    }
}

pub struct IcmpPacket<'a> {
    pub msg_type: IcmpType,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    /// Parses an ICMP packet from an IPv4 payload slice.
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

    /// Serializes an ICMP Echo Request into the provided buffer with computed checksum.
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
