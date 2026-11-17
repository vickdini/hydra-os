//! # net-server: the network interface
//!
//! The interface's configuration (MAC, IPv4 address, mask, gateway, DNS server: DHCP fills
//! them in, see `main.rs`), next-hop MAC resolution over ARP, and IPv4 transmission
//! through the network driver ([`crate::nic`]). Moved here from the kernel's `net/mod.rs`.

use spin::Mutex;

use crate::net::arp::{ArpPacket, ARP_TABLE};
use crate::net::ethernet::{EtherType, EthernetFrame};
use crate::net::ipv4::{IpProtocol, Ipv4Packet};
use crate::nic;

/// Manages the local network interface configuration and packet routing.
///
/// Stores the hardware 48-bit MAC address alongside the assigned IPv4 address, subnet mask,
/// default gateway, and DNS server. Synchronized globally via `GLOBAL_INTERFACE`.
pub struct Interface {
    /// Hardware 48-bit Ethernet MAC address.
    mac: [u8; 6],
    /// Assigned local IPv4 address.
    ip: [u8; 4],
    /// Local IPv4 subnet mask.
    subnet_mask: [u8; 4],
    /// Default gateway router IPv4 address.
    gateway: [u8; 4],
    /// Configured recursive DNS server IPv4 address.
    dns_server: [u8; 4],
}

impl Interface {
    /// Creates a new unconfigured network `Interface` with zeroed addresses and a `/24` default mask.
    ///
    /// # Returns
    /// A newly initialized `Interface` instance suitable for `const` static initialization.
    pub const fn new() -> Self {
        Self {
            mac: [0; 6],
            ip: [0, 0, 0, 0],
            subnet_mask: [255, 255, 255, 0],
            gateway: [0, 0, 0, 0],
            dns_server: [0, 0, 0, 0],
        }
    }

    /// Returns the currently assigned 4-byte IPv4 address of this interface.
    ///
    /// # Returns
    ///
    /// The 4-byte IPv4 address array.
    pub fn ip(&self) -> [u8; 4] {
        self.ip
    }

    /// Returns the 4-byte IPv4 subnet mask of this interface.
    ///
    /// # Returns
    ///
    /// The 4-byte IPv4 subnet mask array.
    pub fn subnet_mask(&self) -> [u8; 4] {
        self.subnet_mask
    }

    /// Returns the 4-byte IPv4 address of the default gateway router.
    ///
    /// # Returns
    ///
    /// The 4-byte default gateway IPv4 address.
    pub fn gateway(&self) -> [u8; 4] {
        self.gateway
    }

    /// Returns the 4-byte IPv4 address of the configured DNS server.
    ///
    /// # Returns
    ///
    /// The 4-byte DNS server IPv4 address.
    pub fn dns_server(&self) -> [u8; 4] {
        self.dns_server
    }

    /// Sets the card's MAC address (learned from the driver).
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Assigns the local 4-byte IPv4 address for this interface.
    ///
    /// # Arguments
    /// - `ip`: The 4-byte IPv4 address to assign.
    pub fn set_ip(&mut self, ip: [u8; 4]) {
        self.ip = ip;
    }

    /// Assigns the 4-byte IPv4 subnet mask for this interface.
    ///
    /// # Arguments
    /// - `mask`: The 4-byte subnet mask (e.g., `[255, 255, 255, 0]`).
    pub fn set_subnet_mask(&mut self, mask: [u8; 4]) {
        self.subnet_mask = mask;
    }

    /// Assigns the default gateway router IPv4 address for this interface.
    ///
    /// # Arguments
    /// - `gw`: The 4-byte gateway IPv4 address.
    pub fn set_gateway(&mut self, gw: [u8; 4]) {
        self.gateway = gw;
    }

    /// Assigns the recursive DNS server IPv4 address for this interface.
    ///
    /// # Arguments
    /// - `dns`: The 4-byte DNS server IPv4 address.
    pub fn set_dns_server(&mut self, dns: [u8; 4]) {
        self.dns_server = dns;
    }

    /// Determines whether a target IPv4 address resides within the local subnet.
    ///
    /// Compares the bitwise AND of `self.ip` and `target_ip` against `self.subnet_mask`.
    ///
    /// # Arguments
    /// - `target_ip`: Destination 4-byte IPv4 address to test.
    ///
    /// # Returns
    /// `true` if `target_ip` is on the local link subnet, or `false` if it requires gateway routing.
    pub fn is_in_subnet(&self, target_ip: [u8; 4]) -> bool {
        for i in 0..4 {
            if (self.ip[i] & self.subnet_mask[i]) != (target_ip[i] & self.subnet_mask[i]) {
                return false;
            }
        }
        true
    }

    /// Resolves the destination hardware MAC address for a target IPv4 address, routing via the default gateway if remote.
    ///
    /// First queries [`ARP_TABLE`]; on a cache miss, broadcasts an ARP Request and polls the NIC
    /// for up to ~1500 ms waiting for a matching ARP Reply.
    ///
    /// # Arguments
    /// - `target_ip`: Destination 4-byte IPv4 address to resolve.
    ///
    /// # Returns
    /// `Ok([u8; 6])` containing the resolved next-hop hardware MAC address.
    ///
    /// # Errors
    /// Returns `Err` if frame serialization/transmission fails or if the ARP request times out.
    pub fn resolve_mac(&mut self, target_ip: [u8; 4]) -> Result<[u8; 6], &'static str> {
        let next_hop_ip = if self.is_in_subnet(target_ip) {
            target_ip
        } else if self.gateway != [0, 0, 0, 0] {
            self.gateway
        } else {
            target_ip
        };

        // 1. Check ARP cache table
        if let Some(mac) = ARP_TABLE.lock().lookup(next_hop_ip) {
            return Ok(mac);
        }

        // 2. Broadcast ARP Request (frames queued before it go out first)
        nic::flush();
        let mut arp_buf = [0u8; 28];
        let arp_req = ArpPacket::new_request(self.mac, self.ip, next_hop_ip);
        arp_req.serialize(&mut arp_buf)?;

        let mut eth_buf = [0u8; 64];
        let eth_len = EthernetFrame::serialize(
            EthernetFrame::BROADCAST_MAC,
            self.mac,
            EtherType::Arp,
            &arp_buf,
            &mut eth_buf,
        )?;

        nic::send_frame(&eth_buf[..eth_len])?;
        nic::flush();

        // 3. Poll for incoming ARP Reply (frames that arrive meanwhile and are not the reply
        // are dropped, as in the kernel's stack: their senders retransmit)
        let mut rx_frame = [0u8; 1518];
        for _ in 0..1500 {
            if let Some(len) = nic::receive_one(&mut rx_frame) {
                if let Some(frame) = EthernetFrame::parse(&rx_frame[..len]) {
                    if frame.ethertype == EtherType::Arp {
                        if let Some(arp) = ArpPacket::parse(frame.payload) {
                            if arp.opcode == 2 && arp.sender_ip == next_hop_ip {
                                ARP_TABLE.lock().insert(arp.sender_ip, arp.sender_mac);
                                return Ok(arp.sender_mac);
                            }
                        }
                    }
                }
            }
            hydra_rt::sys::sleep_ms(1);
        }

        Err("ARP request timed out: unable to resolve target MAC address")
    }

    /// Encapsulates an IPv4 payload into an Ethernet frame and transmits it over the physical link.
    ///
    /// Resolves the next-hop MAC address via [`Interface::resolve_mac`], constructs the IPv4 header
    /// and Ethernet II header, and hands the frame to the E1000 driver.
    ///
    /// # Arguments
    /// - `dst_ip`: Destination 4-byte IPv4 address.
    /// - `protocol`: Encapsulated transport-layer protocol ([`IpProtocol`]).
    /// - `payload`: Transport-layer byte slice to encapsulate.
    ///
    /// # Returns
    /// `Ok(())` when the frame has been queued and transmitted by the NIC.
    ///
    /// # Errors
    /// Returns `Err` if MAC resolution fails, buffers are exceeded, or NIC transmission fails.
    pub fn send_ipv4(
        &mut self,
        dst_ip: [u8; 4],
        protocol: IpProtocol,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        let dst_mac = self.resolve_mac(dst_ip)?;

        let mut ip_buf = [0u8; 1518];
        let ip_len = Ipv4Packet::serialize(self.ip, dst_ip, protocol, payload, &mut ip_buf)?;

        let mut eth_buf = [0u8; 1518];
        let eth_len = EthernetFrame::serialize(
            dst_mac,
            self.mac,
            EtherType::Ipv4,
            &ip_buf[..ip_len],
            &mut eth_buf,
        )?;

        nic::send_frame(&eth_buf[..eth_len])
    }
}

/// Global spinlock-protected network interface singleton.
pub static GLOBAL_INTERFACE: Mutex<Interface> = Mutex::new(Interface::new());

