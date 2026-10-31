//! # Network Subsystem: Core Interface Management & Protocol Dispatch
//!
//! Provides the primary network interface abstraction, packet dispatching, ARP resolution, and DHCP automation.
//!
//! ## Architectural Role & Design Rationale
//!
//! The network subsystem acts as the unified bridge between physical link-layer network adapters
//! (e.g., `e1000::E1000Device`) and higher-layer transport and application protocols (ARP, IPv4, ICMP, UDP, TCP, DNS, HTTP).
//!
//! The `Interface` struct manages assigned network parameters (IP, Subnet Mask, Gateway Router, DNS),
//! coordinates hardware packet polling, and transparently resolves destination MAC addresses via ARP.
//!
//! ## Key Types & Interfaces
//!
//! - `Interface`: Encapsulates the local network interface state (MAC, IPv4 address, subnet mask, gateway, DNS) and provides link-layer and IPv4 transmission/polling methods.
//! - `GLOBAL_INTERFACE`: Thread-safe global singleton protecting the primary system network interface.
//! - `init`: Probes PCI for the Intel E1000 NIC and automatically acquires a DHCP lease when link carrier is present.
//! - `dhcp_acquire`: Executes the 4-way RFC 2131 DHCP handshake to configure `GLOBAL_INTERFACE`.
//! - `ping`: Transmits an ICMP Echo Request and measures round-trip time (RTT) in milliseconds.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Hardware Dependencies: Relies on `e1000` for DMA frame transmission/reception and `crate::arch::pit` for millisecond timeout polling.
//! - Concurrency: Protected via [`spin::Mutex`] in `GLOBAL_INTERFACE`.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod e1000;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod ipv4;
pub mod stack;
pub mod tcp;
pub mod udp;

use spin::Mutex;
use crate::net::arp::{ArpPacket, ARP_TABLE};
use crate::net::ethernet::{EtherType, EthernetFrame};
use crate::net::icmp::{IcmpPacket, IcmpType};
use crate::net::ipv4::{IpProtocol, Ipv4Packet};

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

    /// Returns the 6-byte hardware MAC address of this interface.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Returns the currently assigned 4-byte IPv4 address of this interface.
    pub fn ip(&self) -> [u8; 4] {
        self.ip
    }

    /// Returns the 4-byte IPv4 subnet mask of this interface.
    pub fn subnet_mask(&self) -> [u8; 4] {
        self.subnet_mask
    }

    /// Returns the 4-byte IPv4 address of the default gateway router.
    pub fn gateway(&self) -> [u8; 4] {
        self.gateway
    }

    /// Returns the 4-byte IPv4 address of the configured DNS server.
    pub fn dns_server(&self) -> [u8; 4] {
        self.dns_server
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

        // 2. Broadcast ARP Request
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

        e1000::send_frame(&eth_buf[..eth_len])?;

        // 3. Poll for incoming ARP Reply
        let mut rx_frame = [0u8; 1518];
        for _ in 0..1500 {
            if let Some(len) = e1000::receive_frame(&mut rx_frame) {
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
            crate::arch::pit::sleep_ms(1);
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

        e1000::send_frame(&eth_buf[..eth_len])
    }

    /// Polls the network hardware for an incoming IPv4 datagram addressed to this host.
    ///
    /// Automatically intercepts incoming ARP packets to update [`ARP_TABLE`] and reply to ARP requests
    /// targeting this host's IPv4 address.
    ///
    /// # Arguments
    /// - `rx_buf`: Mutable scratch buffer (recommended >= 1518 bytes) to store the received Ethernet frame.
    ///
    /// # Returns
    /// `Some((src_ip, payload))` containing the sender's IPv4 address and a slice into `rx_buf`
    /// covering the IPv4 payload, or `None` if no matching IPv4 frame was available.
    pub fn poll_ipv4<'a>(&mut self, rx_buf: &'a mut [u8]) -> Option<([u8; 4], &'a [u8])> {
        let len = e1000::receive_frame(rx_buf)?;
        let frame = EthernetFrame::parse(&rx_buf[..len])?;

        match frame.ethertype {
            EtherType::Arp => {
                if let Some(arp) = ArpPacket::parse(frame.payload) {
                    ARP_TABLE.lock().insert(arp.sender_ip, arp.sender_mac);

                    // If it's an ARP request for our IP, reply back
                    if arp.opcode == 1 && arp.target_ip == self.ip && self.ip != [0, 0, 0, 0] {
                        let mut arp_reply = [0u8; 28];
                        let reply_pkt = ArpPacket::new_reply(self.mac, self.ip, arp.sender_mac, arp.sender_ip);
                        if reply_pkt.serialize(&mut arp_reply).is_ok() {
                            let mut eth_buf = [0u8; 64];
                            if let Ok(eth_len) = EthernetFrame::serialize(
                                arp.sender_mac,
                                self.mac,
                                EtherType::Arp,
                                &arp_reply,
                                &mut eth_buf,
                            ) {
                                let _ = e1000::send_frame(&eth_buf[..eth_len]);
                            }
                        }
                    }
                }
                None
            }
            EtherType::Ipv4 => {
                let ip_pkt = Ipv4Packet::parse(frame.payload)?;
                // Verify destination is our IP or broadcast
                if ip_pkt.dst_ip == self.ip || ip_pkt.dst_ip == [255, 255, 255, 255] || self.ip == [0, 0, 0, 0] {
                    // Safety: calculate slice range within rx_buf
                    let payload_offset = 14 + (ip_pkt.ihl as usize * 4);
                    let payload_len = ip_pkt.payload.len();
                    if payload_offset + payload_len <= len {
                        Some((ip_pkt.src_ip, &rx_buf[payload_offset..payload_offset + payload_len]))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Global spinlock-protected network interface singleton.
pub static GLOBAL_INTERFACE: Mutex<Interface> = Mutex::new(Interface::new());

/// Initializes the microkernel network subsystem and discovers attached Ethernet hardware.
///
/// Probes the PCI bus for an Intel E1000 NIC, records its hardware MAC address into `GLOBAL_INTERFACE`,
/// and if carrier link is active, attempts an automatic DHCP lease acquisition via `dhcp_acquire`.
pub fn init() {
    match e1000::init() {
        Ok(()) => {
            let mac = e1000::mac_address();
            let mut iface = GLOBAL_INTERFACE.lock();
            iface.mac = mac;
            let is_up = e1000::is_link_up();
            drop(iface);

            crate::console::set_color(
                uefi::proto::console::text::Color::LightGreen,
                uefi::proto::console::text::Color::Black,
            );
            crate::println!(
                "[+] Network Subsystem: Intel E1000 Online (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, Link: {})",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                if is_up { "UP" } else { "DOWN" }
            );

            if is_up {
                crate::console::set_color(
                    uefi::proto::console::text::Color::Yellow,
                    uefi::proto::console::text::Color::Black,
                );
                crate::print!("    - DHCP Lease: Acquiring dynamic IPv4 configuration... ");
                match dhcp_acquire() {
                    Ok(lease) => {
                        crate::console::set_color(
                            uefi::proto::console::text::Color::LightGreen,
                            uefi::proto::console::text::Color::Black,
                        );
                        crate::println!(
                            "ONLINE ({}.{}.{}.{}, GW {}.{}.{}.{}, DNS {}.{}.{}.{})",
                            lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3],
                            lease.router[0], lease.router[1], lease.router[2], lease.router[3],
                            lease.dns_server[0], lease.dns_server[1], lease.dns_server[2], lease.dns_server[3]
                        );
                    }
                    Err(e) => {
                        crate::console::set_color(
                            uefi::proto::console::text::Color::LightRed,
                            uefi::proto::console::text::Color::Black,
                        );
                        crate::println!("Deferred ({})", e);
                    }
                }
            }
        }
        Err(e) => {
            crate::console::set_color(
                uefi::proto::console::text::Color::Yellow,
                uefi::proto::console::text::Color::Black,
            );
            crate::println!("[*] Network Subsystem: No compatible Ethernet adapter detected: {}", e);
        }
    }
}

/// Triggers an automated DHCP 4-way handshake to acquire an IPv4 configuration lease.
///
/// Broadcasts a DHCP Discover message, awaits a DHCP Offer, sends a DHCP Request, and awaits a
/// DHCP Ack before applying the leased IPv4 address, subnet mask, default gateway, and DNS server
/// to `GLOBAL_INTERFACE`.
///
/// # Returns
/// `Ok(DhcpLease)` containing the leased network configuration parameters.
///
/// # Errors
/// Returns `Err` if no Ethernet card is active, packet serialization fails, or the handshake times out.
pub fn dhcp_acquire() -> Result<dhcp::DhcpLease, &'static str> {
    let mut iface = GLOBAL_INTERFACE.lock();
    let mac = iface.mac;
    if mac == [0; 6] {
        return Err("No active Ethernet network card detected");
    }

    let xid: u32 = 0x3903_F326;

    // 1. Send DHCP Discover broadcast
    let mut dhcp_payload = [0u8; 350];
    let dhcp_len = dhcp::build_dhcp_discover(mac, xid, &mut dhcp_payload)?;

    let mut udp_payload = [0u8; 400];
    let udp_len = udp::UdpPacket::serialize(
        dhcp::DHCP_CLIENT_PORT,
        dhcp::DHCP_SERVER_PORT,
        &dhcp_payload[..dhcp_len],
        &mut udp_payload,
    )?;

    let mut ip_payload = [0u8; 450];
    let ip_len = ipv4::Ipv4Packet::serialize(
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        IpProtocol::Udp,
        &udp_payload[..udp_len],
        &mut ip_payload,
    )?;

    let mut eth_payload = [0u8; 500];
    let eth_len = EthernetFrame::serialize(
        EthernetFrame::BROADCAST_MAC,
        mac,
        EtherType::Ipv4,
        &ip_payload[..ip_len],
        &mut eth_payload,
    )?;

    e1000::send_frame(&eth_payload[..eth_len])?;

    // 2. Poll for DHCP Offer
    let mut rx_buf = [0u8; 1518];
    let mut offered_ip: Option<[u8; 4]> = None;
    let mut server_id: Option<[u8; 4]> = None;

    for _ in 0..3000 {
        if let Some(len) = e1000::receive_frame(&mut rx_buf) {
            if let Some(frame) = EthernetFrame::parse(&rx_buf[..len]) {
                if frame.ethertype == EtherType::Ipv4 {
                    if let Some(ip) = Ipv4Packet::parse(frame.payload) {
                        if ip.protocol == IpProtocol::Udp {
                            if let Some(udp) = udp::UdpPacket::parse(ip.payload) {
                                if udp.dst_port == dhcp::DHCP_CLIENT_PORT {
                                    if let Some((msg_type, lease)) = dhcp::parse_dhcp_reply(udp.payload, xid) {
                                        if msg_type == dhcp::DHCP_MSG_OFFER {
                                            offered_ip = Some(lease.ip);
                                            server_id = Some(lease.server_ip);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        crate::arch::pit::sleep_ms(1);
    }

    let offered = offered_ip.ok_or("DHCP Discover timed out (no DHCP Offer received)")?;
    let srv = server_id.unwrap_or([10, 0, 2, 2]);

    // 3. Send DHCP Request
    let req_len = dhcp::build_dhcp_request(mac, xid, offered, srv, &mut dhcp_payload)?;
    let udp_len = udp::UdpPacket::serialize(
        dhcp::DHCP_CLIENT_PORT,
        dhcp::DHCP_SERVER_PORT,
        &dhcp_payload[..req_len],
        &mut udp_payload,
    )?;
    let ip_len = ipv4::Ipv4Packet::serialize(
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        IpProtocol::Udp,
        &udp_payload[..udp_len],
        &mut ip_payload,
    )?;
    let eth_len = EthernetFrame::serialize(
        EthernetFrame::BROADCAST_MAC,
        mac,
        EtherType::Ipv4,
        &ip_payload[..ip_len],
        &mut eth_payload,
    )?;

    e1000::send_frame(&eth_payload[..eth_len])?;

    // 4. Poll for DHCP Ack
    for _ in 0..3000 {
        if let Some(len) = e1000::receive_frame(&mut rx_buf) {
            if let Some(frame) = EthernetFrame::parse(&rx_buf[..len]) {
                if frame.ethertype == EtherType::Ipv4 {
                    if let Some(ip) = Ipv4Packet::parse(frame.payload) {
                        if ip.protocol == IpProtocol::Udp {
                            if let Some(udp) = udp::UdpPacket::parse(ip.payload) {
                                if udp.dst_port == dhcp::DHCP_CLIENT_PORT {
                                    if let Some((msg_type, lease)) = dhcp::parse_dhcp_reply(udp.payload, xid) {
                                        if msg_type == dhcp::DHCP_MSG_ACK {
                                            iface.set_ip(lease.ip);
                                            iface.set_subnet_mask(lease.subnet_mask);
                                            iface.set_gateway(lease.router);
                                            iface.set_dns_server(lease.dns_server);
                                            return Ok(lease);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        crate::arch::pit::sleep_ms(1);
    }

    Err("DHCP Request timed out (no DHCP Ack received)")
}

/// Sends an ICMP Echo Request and waits for an Echo Reply, measuring round-trip latency in milliseconds.
///
/// # Arguments
/// - `target_ip`: Destination 4-byte IPv4 address to ping.
/// - `seq`: ICMP sequence number to tag the request with.
///
/// # Returns
/// `Ok(rtt_ms)` containing the round-trip time in milliseconds.
///
/// # Errors
/// Returns `Err` if the local interface has no assigned IP address, ARP/transmission fails, or the reply times out.
pub fn ping(target_ip: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    let mut iface = GLOBAL_INTERFACE.lock();
    let local_ip = iface.ip;
    if local_ip == [0, 0, 0, 0] {
        return Err("Local network interface has no IP address assigned (run 'dhcp' first)");
    }

    let payload = b"HydraOS_ICMP_Echo_Ping_Payload!";
    let mut icmp_buf = [0u8; 64];
    let icmp_len = icmp::IcmpPacket::serialize_echo_request(0x1337, seq, payload, &mut icmp_buf)?;

    let start_time = crate::arch::pit::uptime_ms();
    iface.send_ipv4(target_ip, IpProtocol::Icmp, &icmp_buf[..icmp_len])?;

    // Poll for Echo Reply
    let mut rx_buf = [0u8; 1518];
    for _ in 0..1500 {
        if let Some((src_ip, payload)) = iface.poll_ipv4(&mut rx_buf) {
            if src_ip == target_ip {
                if let Some(icmp) = IcmpPacket::parse(payload) {
                    if icmp.msg_type == IcmpType::EchoReply && icmp.identifier == 0x1337 && icmp.sequence == seq {
                        let end_time = crate::arch::pit::uptime_ms();
                        return Ok(end_time.saturating_sub(start_time));
                    }
                }
            }
        }
        crate::arch::pit::sleep_ms(1);
    }

    Err("Request timed out (no ICMP Echo Reply received)")
}
