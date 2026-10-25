//! # Network Subsystem: Dynamic Host Configuration Protocol (DHCP) Client
//!
//! Implements an autonomous RFC 2131 DHCP client to acquire IPv4 network parameters dynamically.
//!
//! ## Architectural Role & Design Rationale
//!
//! Rather than requiring administrators to manually configure static IP addresses, default gateways,
//! and subnet masks, the microkernel broadcasts a DHCP Discover datagram during initialization.
//!
//! Upon receiving an offer from a DHCP server (such as the virtualized gateway `10.0.2.2` in VirtualBox/QEMU),
//! the client transitions through the standard 4-way handshake:
//!
//! ```text
//! Hydra OS Client                              DHCP Server (10.0.2.2)
//!       │                                                 │
//!       │ ─── DHCP Discover (Broadcast 255.255.255.255) ─►│
//!       │                                                 │
//!       │ ◄── DHCP Offer (Offered IP: 10.0.2.15) ─────────│
//!       │                                                 │
//!       │ ─── DHCP Request (Requesting 10.0.2.15) ───────►│
//!       │                                                 │
//!       │ ◄── DHCP Ack (Confirmed Lease & Gateway) ───────│
//!       │                                                 │
//! ```
//!
//! ## Key Types & Interfaces
//!
//! - [`DhcpLease`]: Acquired network configuration (Assigned IP, Subnet Mask, Router Gateway, DNS).
//! - [`build_dhcp_discover()`]: Constructs an initial DHCP Discover broadcast datagram.
//! - [`build_dhcp_request()`]: Requests assignment of an offered IPv4 address.
//! - [`parse_dhcp_reply()`]: Parses server offers and acknowledgments, extracting options.

const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99]; // 0x63825363

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

// DHCP Message Types (Option 53)
pub const DHCP_MSG_DISCOVER: u8 = 1;
pub const DHCP_MSG_OFFER: u8 = 2;
pub const DHCP_MSG_REQUEST: u8 = 3;
pub const DHCP_MSG_ACK: u8 = 5;

// DHCP Option Codes
const OPTION_PAD: u8 = 0;
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS_SERVER: u8 = 6;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_MSG_TYPE: u8 = 53;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_PARAM_REQUEST_LIST: u8 = 55;
const OPTION_END: u8 = 255;

/// Acquired network lease containing configuration parameters from the DHCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpLease {
    pub ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub router: [u8; 4],
    pub dns_server: [u8; 4],
    pub server_ip: [u8; 4],
}

impl DhcpLease {
    pub const fn empty() -> Self {
        Self {
            ip: [0, 0, 0, 0],
            subnet_mask: [255, 255, 255, 0],
            router: [0, 0, 0, 0],
            dns_server: [0, 0, 0, 0],
            server_ip: [0, 0, 0, 0],
        }
    }
}

/// Builds a 240-byte standard BOOTP header with DHCP Magic Cookie and Options.
fn init_bootp_packet(
    out_buf: &mut [u8],
    mac: [u8; 6],
    xid: u32,
    client_ip: [u8; 4],
) -> usize {
    out_buf[0..240].fill(0);

    out_buf[0] = 1; // Opcode: BOOTREQUEST
    out_buf[1] = 1; // Hardware Type: Ethernet (10Mb)
    out_buf[2] = 6; // Hardware Address Length
    out_buf[3] = 0; // Hops

    // Transaction ID (XID)
    out_buf[4] = (xid >> 24) as u8;
    out_buf[5] = (xid >> 16) as u8;
    out_buf[6] = (xid >> 8) as u8;
    out_buf[7] = (xid & 0xFF) as u8;

    // Flags: Broadcast bit 15 = 1 (0x8000)
    out_buf[10] = 0x80;
    out_buf[11] = 0x00;

    // Client IP (ciaddr)
    out_buf[12..16].copy_from_slice(&client_ip);

    // Client Hardware Address (chaddr): MAC address followed by 10 zero bytes
    out_buf[28..34].copy_from_slice(&mac);

    // Magic Cookie (0x63825363)
    out_buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    240
}

/// Constructs a DHCP Discover payload.
pub fn build_dhcp_discover(mac: [u8; 6], xid: u32, out_buf: &mut [u8]) -> Result<usize, &'static str> {
    if out_buf.len() < 300 {
        return Err("Destination buffer too small for DHCP Discover packet");
    }

    let mut offset = init_bootp_packet(out_buf, mac, xid, [0, 0, 0, 0]);

    // Option 53: DHCP Message Type = DHCP Discover (1)
    out_buf[offset] = OPTION_MSG_TYPE;
    out_buf[offset + 1] = 1;
    out_buf[offset + 2] = DHCP_MSG_DISCOVER;
    offset += 3;

    // Option 55: Parameter Request List (Subnet Mask, Router, DNS)
    out_buf[offset] = OPTION_PARAM_REQUEST_LIST;
    out_buf[offset + 1] = 3;
    out_buf[offset + 2] = OPTION_SUBNET_MASK;
    out_buf[offset + 3] = OPTION_ROUTER;
    out_buf[offset + 4] = OPTION_DNS_SERVER;
    offset += 5;

    // Option 255: End
    out_buf[offset] = OPTION_END;
    offset += 1;

    Ok(offset)
}

/// Constructs a DHCP Request payload to finalize an offered lease.
pub fn build_dhcp_request(
    mac: [u8; 6],
    xid: u32,
    requested_ip: [u8; 4],
    server_ip: [u8; 4],
    out_buf: &mut [u8],
) -> Result<usize, &'static str> {
    if out_buf.len() < 300 {
        return Err("Destination buffer too small for DHCP Request packet");
    }

    let mut offset = init_bootp_packet(out_buf, mac, xid, [0, 0, 0, 0]);

    // Option 53: DHCP Message Type = DHCP Request (3)
    out_buf[offset] = OPTION_MSG_TYPE;
    out_buf[offset + 1] = 1;
    out_buf[offset + 2] = DHCP_MSG_REQUEST;
    offset += 3;

    // Option 50: Requested IP Address
    out_buf[offset] = OPTION_REQUESTED_IP;
    out_buf[offset + 1] = 4;
    out_buf[offset + 2..offset + 6].copy_from_slice(&requested_ip);
    offset += 6;

    // Option 54: Server Identifier
    out_buf[offset] = OPTION_SERVER_IDENTIFIER;
    out_buf[offset + 1] = 4;
    out_buf[offset + 2..offset + 6].copy_from_slice(&server_ip);
    offset += 6;

    // Option 55: Parameter Request List
    out_buf[offset] = OPTION_PARAM_REQUEST_LIST;
    out_buf[offset + 1] = 3;
    out_buf[offset + 2] = OPTION_SUBNET_MASK;
    out_buf[offset + 3] = OPTION_ROUTER;
    out_buf[offset + 4] = OPTION_DNS_SERVER;
    offset += 5;

    // Option 255: End
    out_buf[offset] = OPTION_END;
    offset += 1;

    Ok(offset)
}

/// Parses an incoming DHCP server reply (Offer or Ack) and extracts lease configuration.
pub fn parse_dhcp_reply(buf: &[u8], expected_xid: u32) -> Option<(u8, DhcpLease)> {
    if buf.len() < 240 {
        return None;
    }

    // Verify Opcode (2 = BOOTREPLY)
    if buf[0] != 2 {
        return None;
    }

    // Verify Transaction ID (XID)
    let xid = ((buf[4] as u32) << 24)
        | ((buf[5] as u32) << 16)
        | ((buf[6] as u32) << 8)
        | (buf[7] as u32);
    if xid != expected_xid {
        return None;
    }

    // Verify Magic Cookie
    if buf[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let mut offered_ip = [0u8; 4];
    offered_ip.copy_from_slice(&buf[16..20]); // yiaddr

    let mut lease = DhcpLease {
        ip: offered_ip,
        subnet_mask: [255, 255, 255, 0],
        router: [0, 0, 0, 0],
        dns_server: [0, 0, 0, 0],
        server_ip: [0, 0, 0, 0],
    };

    let mut msg_type: Option<u8> = None;
    let mut offset = 240;

    // Parse options list
    while offset < buf.len() {
        let opt_code = buf[offset];
        if opt_code == OPTION_PAD {
            offset += 1;
            continue;
        }
        if opt_code == OPTION_END {
            break;
        }

        if offset + 1 >= buf.len() {
            break;
        }
        let opt_len = buf[offset + 1] as usize;
        let opt_data = &buf[offset + 2..offset + 2 + opt_len];

        match opt_code {
            OPTION_MSG_TYPE => {
                if opt_len >= 1 {
                    msg_type = Some(opt_data[0]);
                }
            }
            OPTION_SUBNET_MASK => {
                if opt_len == 4 {
                    lease.subnet_mask.copy_from_slice(opt_data);
                }
            }
            OPTION_ROUTER => {
                if opt_len >= 4 {
                    lease.router.copy_from_slice(&opt_data[0..4]);
                }
            }
            OPTION_DNS_SERVER => {
                if opt_len >= 4 {
                    lease.dns_server.copy_from_slice(&opt_data[0..4]);
                }
            }
            OPTION_SERVER_IDENTIFIER => {
                if opt_len == 4 {
                    lease.server_ip.copy_from_slice(opt_data);
                }
            }
            _ => {}
        }

        offset += 2 + opt_len;
    }

    msg_type.map(|t| (t, lease))
}
