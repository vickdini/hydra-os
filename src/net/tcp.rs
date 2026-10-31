//! # Network Subsystem: Transmission Control Protocol (TCP)
//!
//! Implements a lightweight, reliable stream-oriented transport connection (RFC 793).
//!
//! ## Architectural Role & Design Rationale
//!
//! Applications communicating over the network (e.g., package managers downloading `.tar` archives
//! or HTTP clients) require reliable, ordered, byte-stream delivery.
//!
//! The microkernel TCP engine handles the 3-way connection handshake (SYN, SYN-ACK, ACK),
//! windowed sequence acknowledgment, data payload transfer (PSH-ACK), and clean connection
//! termination (FIN-ACK).
//!
//! ## Key Types & Interfaces
//!
//! - [`TcpFlags`]: Bitmask constants for SYN, ACK, FIN, RST, PSH, and URG.
//! - [`TcpPacket`]: Structured representation of a TCP segment.
//! - [`compute_tcp_checksum()`]: Calculates the 16-bit checksum including the IPv4 pseudo-header.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Zero-allocation (`no_std`) TCP segment parser, serializer, and pseudo-header checksum calculator.

/// Namespace for 8-bit TCP control flag bitmasks (RFC 793).
pub struct TcpFlags;

impl TcpFlags {
    /// No more data from sender (`bit 0`).
    pub const FIN: u8 = 1 << 0;
    /// Synchronize sequence numbers (`bit 1`).
    pub const SYN: u8 = 1 << 1;
    /// Reset the connection (`bit 2`).
    pub const RST: u8 = 1 << 2;
    /// Push function (`bit 3`).
    pub const PSH: u8 = 1 << 3;
    /// Acknowledgment field significant (`bit 4`).
    pub const ACK: u8 = 1 << 4;
    /// Urgent pointer field significant (`bit 5`).
    pub const URG: u8 = 1 << 5;
}

/// Structured zero-copy representation of a TCP segment.
pub struct TcpPacket<'a> {
    /// Source 16-bit TCP port number.
    pub src_port: u16,
    /// Destination 16-bit TCP port number.
    pub dst_port: u16,
    /// 32-bit sequence number of the first data octet in this segment (or ISN if `SYN` is set).
    pub seq_num: u32,
    /// 32-bit acknowledgment number (next sequence number expected by the sender).
    pub ack_num: u32,
    /// Bitmask of [`TcpFlags`] control bits.
    pub flags: u8,
    /// 16-bit receive window size advertised by the sender.
    pub window_size: u16,
    /// Borrowed slice containing the segment's application data payload.
    pub payload: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    /// Parses a TCP segment from an IPv4 payload slice.
    ///
    /// # Arguments
    /// - `buf`: Raw IPv4 payload slice.
    ///
    /// # Returns
    /// `Some(TcpPacket)` if `buf` is at least 20 bytes and contains a valid data offset, or `None` otherwise.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }

        let src_port = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let dst_port = ((buf[2] as u16) << 8) | (buf[3] as u16);
        let seq_num = ((buf[4] as u32) << 24)
            | ((buf[5] as u32) << 16)
            | ((buf[6] as u32) << 8)
            | (buf[7] as u32);
        let ack_num = ((buf[8] as u32) << 24)
            | ((buf[9] as u32) << 16)
            | ((buf[10] as u32) << 8)
            | (buf[11] as u32);

        let data_offset = (buf[12] >> 4) as usize * 4;
        let flags = buf[13];
        let window_size = ((buf[14] as u16) << 8) | (buf[15] as u16);

        if buf.len() < data_offset {
            return None;
        }

        let payload = &buf[data_offset..];

        Some(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            flags,
            window_size,
            payload,
        })
    }

    /// Serializes a TCP segment including the 20-byte standard header and IPv4 pseudo-header checksum.
    ///
    /// # Arguments
    /// - `src_ip`: Source 4-byte IPv4 address (for the pseudo-header checksum).
    /// - `dst_ip`: Destination 4-byte IPv4 address (for the pseudo-header checksum).
    /// - `src_port`: Source 16-bit TCP port.
    /// - `dst_port`: Destination 16-bit TCP port.
    /// - `seq_num`: 32-bit sequence number.
    /// - `ack_num`: 32-bit acknowledgment number.
    /// - `flags`: Bitmask of [`TcpFlags`].
    /// - `window_size`: 16-bit advertised receive window size.
    /// - `payload`: Segment data payload slice.
    /// - `out_buf`: Destination buffer (must be at least `20 + payload.len()` bytes).
    ///
    /// # Returns
    /// `Ok(total_len)` containing the total serialized TCP segment length in bytes.
    ///
    /// # Errors
    /// Returns `Err` if `out_buf` is smaller than `20 + payload.len()`.
    pub fn serialize(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        window_size: u16,
        payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        let total_len = 20 + payload.len();
        if out_buf.len() < total_len {
            return Err("Destination buffer too small for TCP segment");
        }

        out_buf[0] = (src_port >> 8) as u8;
        out_buf[1] = (src_port & 0xFF) as u8;
        out_buf[2] = (dst_port >> 8) as u8;
        out_buf[3] = (dst_port & 0xFF) as u8;

        out_buf[4] = (seq_num >> 24) as u8;
        out_buf[5] = (seq_num >> 16) as u8;
        out_buf[6] = (seq_num >> 8) as u8;
        out_buf[7] = (seq_num & 0xFF) as u8;

        out_buf[8] = (ack_num >> 24) as u8;
        out_buf[9] = (ack_num >> 16) as u8;
        out_buf[10] = (ack_num >> 8) as u8;
        out_buf[11] = (ack_num & 0xFF) as u8;

        out_buf[12] = 0x50; // Data offset 5 (20 bytes)
        out_buf[13] = flags;
        out_buf[14] = (window_size >> 8) as u8;
        out_buf[15] = (window_size & 0xFF) as u8;
        out_buf[16] = 0; // Checksum zeroed during computation
        out_buf[17] = 0;
        out_buf[18] = 0; // Urgent pointer
        out_buf[19] = 0;

        out_buf[20..total_len].copy_from_slice(payload);

        // Compute TCP checksum over IPv4 pseudo-header + TCP segment
        let cksum = compute_tcp_checksum(src_ip, dst_ip, &out_buf[0..total_len]);
        out_buf[16] = (cksum >> 8) as u8;
        out_buf[17] = (cksum & 0xFF) as u8;

        Ok(total_len)
    }
}

/// Computes the 16-bit TCP checksum across the 12-byte IPv4 pseudo-header and TCP segment.
///
/// # Arguments
/// - `src_ip`: Source 4-byte IPv4 address.
/// - `dst_ip`: Destination 4-byte IPv4 address.
/// - `tcp_data`: Serialized TCP header and payload (with the checksum field set to `0`).
///
/// # Returns
/// 16-bit one's complement TCP checksum.
pub fn compute_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_data: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[8] = 0;
    pseudo[9] = 6; // Protocol: TCP (6)
    let tcp_len = tcp_data.len() as u16;
    pseudo[10] = (tcp_len >> 8) as u8;
    pseudo[11] = (tcp_len & 0xFF) as u8;

    let mut sum: u32 = 0;

    // Pseudo-header words
    for i in (0..12).step_by(2) {
        let w = ((pseudo[i] as u32) << 8) | (pseudo[i + 1] as u32);
        sum = sum.wrapping_add(w);
    }

    // TCP segment words
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        let w = ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32);
        sum = sum.wrapping_add(w);
        i += 2;
    }
    if i < tcp_data.len() {
        sum = sum.wrapping_add((tcp_data[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
