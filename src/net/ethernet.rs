//! # Network Subsystem: Ethernet II Frame Protocol
//!
//! Provides parsing and serialization of standard IEEE 802.3 / Ethernet II data-link frames.
//!
//! ## Architectural Role & Design Rationale
//!
//! Ethernet II is the standard link-layer framing protocol for local area networking.
//! Every transmitted and received frame encapsulates a 14-byte header consisting of:
//! - **Destination MAC (6 bytes)**: Physical hardware address of the receiver or `FF:FF:FF:FF:FF:FF` (Broadcast).
//! - **Source MAC (6 bytes)**: Physical hardware address of the sender.
//! - **EtherType (2 bytes)**: Protocol identifier for the encapsulated payload:
//!   - `0x0800`: Internet Protocol Version 4 (IPv4)
//!   - `0x0806`: Address Resolution Protocol (ARP)
//!
//! ## Key Types & Interfaces
//!
//! - [`EtherType`]: Enum representing supported link-layer protocols.
//! - [`EthernetFrame`]: Structured representation of an Ethernet II frame header and payload.

/// Supported IEEE 802.3 EtherType values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Unknown(u16),
}

impl EtherType {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;

    pub fn from_u16(val: u16) -> Self {
        match val {
            Self::IPV4 => EtherType::Ipv4,
            Self::ARP => EtherType::Arp,
            other => EtherType::Unknown(other),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match *self {
            EtherType::Ipv4 => Self::IPV4,
            EtherType::Arp => Self::ARP,
            EtherType::Unknown(val) => val,
        }
    }
}

/// Structured representation of an Ethernet II frame.
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: EtherType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Broadcast hardware MAC address (`FF:FF:FF:FF:FF:FF`).
    pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    /// Parses an Ethernet II frame from a raw byte buffer.
    ///
    /// # Arguments
    /// - `buf`: Raw frame slice received from the network device.
    ///
    /// # Returns
    /// `Some(EthernetFrame)` if `buf` is at least 14 bytes long, or `None`.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 14 {
            return None;
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&buf[0..6]);
        src_mac.copy_from_slice(&buf[6..12]);

        let type_raw = ((buf[12] as u16) << 8) | (buf[13] as u16);
        let ethertype = EtherType::from_u16(type_raw);
        let payload = &buf[14..];

        Some(Self {
            dst_mac,
            src_mac,
            ethertype,
            payload,
        })
    }

    /// Serializes an Ethernet II frame into the target destination buffer.
    ///
    /// # Arguments
    /// - `dst_mac`: Recipient MAC address.
    /// - `src_mac`: Transmitter MAC address.
    /// - `ethertype`: Protocol identifier.
    /// - `payload`: Payload byte slice.
    /// - `out_buf`: Destination byte buffer to serialize into. Must be at least `payload.len() + 14`.
    ///
    /// # Returns
    /// Total bytes written into `out_buf`.
    pub fn serialize(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        ethertype: EtherType,
        payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        let total_len = 14 + payload.len();
        if out_buf.len() < total_len {
            return Err("Destination buffer too small for Ethernet frame serialization");
        }

        out_buf[0..6].copy_from_slice(&dst_mac);
        out_buf[6..12].copy_from_slice(&src_mac);

        let type_val = ethertype.as_u16();
        out_buf[12] = (type_val >> 8) as u8;
        out_buf[13] = (type_val & 0xFF) as u8;

        out_buf[14..total_len].copy_from_slice(payload);

        // Ethernet frames must be at least 60 bytes before FCS/CRC
        let final_len = total_len.max(60);
        if final_len > total_len && out_buf.len() >= final_len {
            out_buf[total_len..final_len].fill(0);
        }

        Ok(final_len)
    }
}
