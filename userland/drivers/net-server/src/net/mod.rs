//! # net-server: packet formats
//!
//! The wire formats net-server speaks, as pure parse/serialize code (no I/O): Ethernet II,
//! ARP, IPv4, ICMP, UDP, TCP, and the DHCP and DNS clients' messages and state machines.
//! They were the kernel's `src/net/*.rs`; the host tests (`tests/host`) compile these files,
//! which is why some items are unused here.

#![allow(dead_code)]

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;
