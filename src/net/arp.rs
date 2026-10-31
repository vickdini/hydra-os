//! # Network Subsystem: Address Resolution Protocol (ARP)
//!
//! Provides dynamic resolution of IPv4 addresses into 48-bit hardware Ethernet MAC addresses (RFC 826).
//!
//! ## Architectural Role & Design Rationale
//!
//! Because Ethernet hardware operates on 48-bit MAC addresses while IP routing operates on 32-bit IPv4 addresses,
//! ARP dynamically bridges the two layers. When communicating with the default gateway (e.g., `10.0.2.2` in QEMU/VirtualBox)
//! or a local host, the microkernel broadcasts an ARP Request (`Who has X.X.X.X? Tell Y.Y.Y.Y`).
//!
//! The driver caches resolved IP-to-MAC associations in a thread-safe ARP cache table to avoid redundant broadcasts.
//!
//! ## Key Types & Interfaces
//!
//! - [`ArpPacket`]: Parsed representation of an RFC 826 ARP message.
//! - [`ArpCache`]: Dynamic fixed-capacity table storing resolved `(IPv4, MAC)` mappings.
//! - [`ARP_TABLE`]: Global spinlock-protected ARP cache singleton.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: No dynamic memory allocation (`no_std`); relies on [`spin::Mutex`] for concurrent cache access.

use spin::Mutex;

/// ARP hardware type constant for Ethernet (10Mb).
const ARP_HARDWARE_ETHERNET: u16 = 0x0001;
/// ARP protocol type constant for IPv4 (`0x0800`).
const ARP_PROTOCOL_IPV4: u16 = 0x0800;
/// ARP operation code for an ARP Request (`1`).
const ARP_OPCODE_REQUEST: u16 = 0x0001;
/// ARP operation code for an ARP Reply (`2`).
const ARP_OPCODE_REPLY: u16 = 0x0002;

/// Structured representation of an Address Resolution Protocol (RFC 826) frame for Ethernet/IPv4.
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    /// Operation code (`1` for Request, `2` for Reply).
    pub opcode: u16,
    /// Hardware MAC address of the sender (6 bytes).
    pub sender_mac: [u8; 6],
    /// Protocol IPv4 address of the sender (4 bytes).
    pub sender_ip: [u8; 4],
    /// Hardware MAC address of the target (6 bytes; zeroed in requests).
    pub target_mac: [u8; 6],
    /// Protocol IPv4 address of the target (4 bytes).
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    /// Parses an ARP packet from a raw Ethernet payload slice.
    ///
    /// Validates that the buffer is at least 28 bytes and specifies Ethernet (`0x0001`, 6-byte hardware addresses)
    /// and IPv4 (`0x0800`, 4-byte protocol addresses).
    ///
    /// # Arguments
    /// - `buf`: Raw byte slice containing the Ethernet payload.
    ///
    /// # Returns
    /// `Some(ArpPacket)` if the packet is a valid Ethernet/IPv4 ARP message, or `None` otherwise.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 28 {
            return None;
        }

        let htype = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let ptype = ((buf[2] as u16) << 8) | (buf[3] as u16);
        let hlen = buf[4];
        let plen = buf[5];
        let opcode = ((buf[6] as u16) << 8) | (buf[7] as u16);

        if htype != ARP_HARDWARE_ETHERNET || ptype != ARP_PROTOCOL_IPV4 || hlen != 6 || plen != 4 {
            return None;
        }

        let mut sender_mac = [0u8; 6];
        let mut sender_ip = [0u8; 4];
        let mut target_mac = [0u8; 6];
        let mut target_ip = [0u8; 4];

        sender_mac.copy_from_slice(&buf[8..14]);
        sender_ip.copy_from_slice(&buf[14..18]);
        target_mac.copy_from_slice(&buf[18..24]);
        target_ip.copy_from_slice(&buf[24..28]);

        Some(Self {
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Serializes an ARP packet into a 28-byte destination buffer.
    ///
    /// # Arguments
    /// - `out`: Destination byte buffer to write the 28-byte ARP frame into.
    ///
    /// # Returns
    /// `Ok(28)` upon writing the serialized ARP packet.
    ///
    /// # Errors
    /// Returns `Err` if `out.len() < 28`.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize, &'static str> {
        if out.len() < 28 {
            return Err("Destination buffer too small for ARP packet");
        }

        out[0] = (ARP_HARDWARE_ETHERNET >> 8) as u8;
        out[1] = (ARP_HARDWARE_ETHERNET & 0xFF) as u8;
        out[2] = (ARP_PROTOCOL_IPV4 >> 8) as u8;
        out[3] = (ARP_PROTOCOL_IPV4 & 0xFF) as u8;
        out[4] = 6; // Hardware address size (MAC)
        out[5] = 4; // Protocol address size (IPv4)
        out[6] = (self.opcode >> 8) as u8;
        out[7] = (self.opcode & 0xFF) as u8;

        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip);
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip);

        Ok(28)
    }

    /// Constructs an ARP Request packet querying the hardware MAC address for `target_ip`.
    ///
    /// # Arguments
    /// - `sender_mac`: Local 6-byte hardware MAC address.
    /// - `sender_ip`: Local 4-byte IPv4 address.
    /// - `target_ip`: Target 4-byte IPv4 address to resolve.
    ///
    /// # Returns
    /// A new [`ArpPacket`] configured with `opcode = 1` (Request) and a zeroed `target_mac`.
    pub fn new_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self {
            opcode: ARP_OPCODE_REQUEST,
            sender_mac,
            sender_ip,
            target_mac: [0; 6],
            target_ip,
        }
    }

    /// Constructs an ARP Reply packet answering that `sender_ip` is located at `sender_mac`.
    ///
    /// # Arguments
    /// - `sender_mac`: Local 6-byte hardware MAC address.
    /// - `sender_ip`: Local 4-byte IPv4 address.
    /// - `target_mac`: Requester's 6-byte hardware MAC address.
    /// - `target_ip`: Requester's 4-byte IPv4 address.
    ///
    /// # Returns
    /// A new [`ArpPacket`] configured with `opcode = 2` (Reply).
    pub fn new_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Self {
        Self {
            opcode: ARP_OPCODE_REPLY,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }
}

/// Maximum number of `(IPv4, MAC)` entries stored in [`ArpCache`].
const ARP_CACHE_CAPACITY: usize = 16;

/// Internal cache slot associating an IPv4 address with a resolved 48-bit MAC address.
#[derive(Clone, Copy)]
struct ArpEntry {
    /// Resolved 4-byte IPv4 address.
    ip: [u8; 4],
    /// Associated 6-byte Ethernet MAC address.
    mac: [u8; 6],
}

/// Fixed-capacity table storing resolved IPv4-to-MAC address mappings.
///
/// Accessed concurrently through [`ARP_TABLE`].
pub struct ArpCache {
    /// Fixed-size array of optional ARP cache entries.
    entries: [Option<ArpEntry>; ARP_CACHE_CAPACITY],
}

impl ArpCache {
    /// Creates a new empty [`ArpCache`].
    ///
    /// # Returns
    /// An empty [`ArpCache`] suitable for `const` static initialization.
    pub const fn new() -> Self {
        Self {
            entries: [None; ARP_CACHE_CAPACITY],
        }
    }

    /// Inserts or updates an `(ip, mac)` mapping in the ARP cache.
    ///
    /// If `ip` already exists in the table, its MAC address is updated in-place. Otherwise,
    /// the mapping is placed into the first empty slot, or overwrites slot `0` if full.
    ///
    /// # Arguments
    /// - `ip`: 4-byte IPv4 address.
    /// - `mac`: Associated 6-byte hardware MAC address.
    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        // If entry already exists, update it
        for entry in self.entries.iter_mut() {
            if let Some(ref mut e) = entry {
                if e.ip == ip {
                    e.mac = mac;
                    return;
                }
            }
        }
        // Otherwise, insert in first free slot
        for entry in self.entries.iter_mut() {
            if entry.is_none() {
                *entry = Some(ArpEntry { ip, mac });
                return;
            }
        }
        // Cache full: overwrite slot 0
        self.entries[0] = Some(ArpEntry { ip, mac });
    }

    /// Looks up the hardware MAC address associated with `ip`.
    ///
    /// # Arguments
    /// - `ip`: 4-byte IPv4 address to query.
    ///
    /// # Returns
    /// `Some([u8; 6])` if the IPv4 address is present in the cache, or `None` on a cache miss.
    pub fn lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for entry in self.entries.iter() {
            if let Some(ref e) = entry {
                if e.ip == ip {
                    return Some(e.mac);
                }
            }
        }
        None
    }
}

/// Global spinlock-protected ARP cache table.
pub static ARP_TABLE: Mutex<ArpCache> = Mutex::new(ArpCache::new());
