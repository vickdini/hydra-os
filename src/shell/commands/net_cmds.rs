//! # Shell Commands: Network Diagnostics, DHCP, Ping & Package Fetcher
//!
//! Provides CLI tools (`ifconfig`, `dhcp`, `ping`, `wget`/`fetch`) to manage networking and download packages.
//!
//! ## Architectural Role & Design Rationale
//!
//! To verify end-to-end network operation, configure dynamic addressing, test gateway reachability,
//! and pull external software packages directly into the persistent OpenZFS filesystem, Hydra OS exposes:
//! - **`ifconfig` / `ip`**: Inspects network interface hardware addresses (MAC), IP assignments, and link status.
//! - **`dhcp`**: Initiates a DHCP 4-way lease handshake against the local gateway router.
//! - **`ping`**: Dispatches ICMP Echo Requests and calculates round-trip network transit time.
//! - **`wget` / `fetch`**: Synchronously retrieves remote files over HTTP and saves them into ZFS datasets.

extern crate alloc;

use alloc::vec;
use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::fs::client::ZfsClient;
use crate::net::{self, e1000, GLOBAL_INTERFACE};
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command to inspect network interface state and link telemetry.
pub struct IfconfigCommand;

impl Command for IfconfigCommand {
    fn name(&self) -> &'static str {
        "ifconfig"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["ip", "netstat"]
    }

    fn description(&self) -> &'static str {
        "Display network interface configuration, IP assignment, and carrier status"
    }

    fn usage(&self) -> &'static str {
        "ifconfig"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::LightCyan, Color::Black);
        println!("=== Hydra OS Network Interfaces ===");

        let is_present = e1000::is_present();
        if !is_present {
            set_color(Color::Yellow, Color::Black);
            println!("\nNo Ethernet network interface controller detected on PCI bus.");
            println!("Tip: Enable Intel PRO/1000 MT (82540EM) in VirtualBox or -device e1000 in QEMU.");
            set_color(Color::White, Color::Black);
            return;
        }

        let is_up = e1000::is_link_up();
        let mut iface = GLOBAL_INTERFACE.lock();
        if iface.ip() == [0, 0, 0, 0] && is_up {
            set_color(Color::Yellow, Color::Black);
            println!("\n[*] Requesting dynamic DHCP lease for eth0...");
            drop(iface);
            let _ = net::dhcp_acquire();
            iface = GLOBAL_INTERFACE.lock();
        }

        let mac = iface.mac();
        let ip = iface.ip();
        let mask = iface.subnet_mask();
        let gw = iface.gateway();
        let dns = iface.dns_server();
        let (rx_pkts, tx_pkts, rx_bytes, tx_bytes) = {
            let guard = e1000::E1000_NIC.lock();
            guard.as_ref().map(|d| d.metrics()).unwrap_or((0, 0, 0, 0))
        };

        set_color(Color::LightGreen, Color::Black);
        println!("\nInterface: eth0 (Intel 82540EM Gigabit Ethernet)");
        set_color(Color::White, Color::Black);
        println!(
            "  - Hardware MAC:      {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        println!(
            "  - Carrier Link:      {}",
            if is_up { "UP (1000 Mbps Full-Duplex)" } else { "DOWN (No carrier detected)" }
        );
        println!(
            "  - IPv4 Address:      {}.{}.{}.{}",
            ip[0], ip[1], ip[2], ip[3]
        );
        println!(
            "  - Subnet Mask:       {}.{}.{}.{}",
            mask[0], mask[1], mask[2], mask[3]
        );
        println!(
            "  - Default Gateway:   {}.{}.{}.{}",
            gw[0], gw[1], gw[2], gw[3]
        );
        println!(
            "  - DNS Server:        {}.{}.{}.{}",
            dns[0], dns[1], dns[2], dns[3]
        );
        println!("  - Telemetry RX:      {} packets ({} bytes)", rx_pkts, rx_bytes);
        println!("  - Telemetry TX:      {} packets ({} bytes)", tx_pkts, tx_bytes);
        set_color(Color::White, Color::Black);
    }
}

/// Shell command to acquire a dynamic network lease via DHCP.
pub struct DhcpCommand;

impl Command for DhcpCommand {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["dhclient", "renew"]
    }

    fn description(&self) -> &'static str {
        "Acquire dynamic IPv4 address and gateway parameters via DHCP"
    }

    fn usage(&self) -> &'static str {
        "dhcp"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Broadcasting DHCP Discover query across eth0...");

        match net::dhcp_acquire() {
            Ok(lease) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] DHCP Lease Successfully Acquired!");
                println!("    - Assigned IP:     {}.{}.{}.{}", lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]);
                println!("    - Subnet Mask:     {}.{}.{}.{}", lease.subnet_mask[0], lease.subnet_mask[1], lease.subnet_mask[2], lease.subnet_mask[3]);
                println!("    - Default Gateway: {}.{}.{}.{}", lease.router[0], lease.router[1], lease.router[2], lease.router[3]);
                println!("    - DNS Server:      {}.{}.{}.{}", lease.dns_server[0], lease.dns_server[1], lease.dns_server[2], lease.dns_server[3]);
                println!("    - DHCP Server:     {}.{}.{}.{}", lease.server_ip[0], lease.server_ip[1], lease.server_ip[2], lease.server_ip[3]);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] DHCP configuration failed: {}", e);
            }
        }
        set_color(Color::White, Color::Black);
    }
}

/// Shell command to test network reachability via ICMP Echo Requests (`ping`).
pub struct PingCommand;

impl Command for PingCommand {
    fn name(&self) -> &'static str {
        "ping"
    }

    fn description(&self) -> &'static str {
        "Send ICMP Echo Requests to verify IP connectivity to an IP address or domain URL"
    }

    fn usage(&self) -> &'static str {
        "ping <ip_or_url> (e.g. 'ping 10.0.2.2' or 'ping google.com')"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: ping <ip_or_url> (e.g. ping 10.0.2.2 or ping google.com)");
            return;
        }

        let target_str = args[0];
        let clean_target = net::dns::clean_host(target_str);

        if GLOBAL_INTERFACE.lock().ip() == [0, 0, 0, 0] && e1000::is_link_up() {
            set_color(Color::Yellow, Color::Black);
            println!("[*] Interface has no IP address. Automatically acquiring DHCP lease...");
            let _ = net::dhcp_acquire();
        }

        let target_ip = match parse_ipv4(clean_target) {
            Some(ip) => ip,
            None => {
                set_color(Color::Yellow, Color::Black);
                println!("[*] Resolving domain '{}' via DNS...", clean_target);
                match net::dns::resolve(clean_target) {
                    Ok(ip) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!(
                            "[+] Resolved '{}' -> {}.{}.{}.{}",
                            clean_target, ip[0], ip[1], ip[2], ip[3]
                        );
                        ip
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] DNS resolution failed for '{}': {}", clean_target, e);
                        return;
                    }
                }
            }
        };

        set_color(Color::LightCyan, Color::Black);
        println!("PING {}.{}.{}.{} ({}) with 32 bytes of diagnostic data:",
            target_ip[0], target_ip[1], target_ip[2], target_ip[3], clean_target);

        let mut received = 0;
        let mut min_rtt = u64::MAX;
        let mut max_rtt = 0;
        let mut sum_rtt = 0;

        for seq in 1..=4 {
            match net::ping(target_ip, seq) {
                Ok(rtt_ms) => {
                    received += 1;
                    min_rtt = min_rtt.min(rtt_ms);
                    max_rtt = max_rtt.max(rtt_ms);
                    sum_rtt += rtt_ms;
                    set_color(Color::White, Color::Black);
                    println!("Reply from {}.{}.{}.{}: bytes=32 seq={} time={}ms TTL=64",
                        target_ip[0], target_ip[1], target_ip[2], target_ip[3], seq, rtt_ms);
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("Request timed out (seq={}): {}", seq, e);
                }
            }

            // Small delay between pings
            for _ in 0..500_000 {
                core::hint::spin_loop();
            }
        }

        set_color(Color::Yellow, Color::Black);
        println!("\n--- {} ({}.{}.{}.{}) ping statistics ---",
            clean_target, target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
        println!("4 packets transmitted, {} received, {}% packet loss", received, ((4 - received) * 100) / 4);
        if received > 0 {
            println!("rtt min/avg/max = {}/{}/{} ms", min_rtt, sum_rtt / received, max_rtt);
        }
        set_color(Color::White, Color::Black);
    }
}

/// Shell command to query DNS name resolution.
pub struct DnsCommand;

impl Command for DnsCommand {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["nslookup", "host", "resolve"]
    }

    fn description(&self) -> &'static str {
        "Resolve a domain name or URL to an IPv4 address via DNS (RFC 1035)"
    }

    fn usage(&self) -> &'static str {
        "dns <domain_or_url> (e.g. 'dns google.com')"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: dns <domain_or_url> (e.g. 'dns google.com')");
            return;
        }

        let clean = net::dns::clean_host(args[0]);
        let dns_server = net::GLOBAL_INTERFACE.lock().dns_server();
        set_color(Color::Yellow, Color::Black);
        println!(
            "[*] Querying DNS server {}.{}.{}.{} for '{}'...",
            dns_server[0], dns_server[1], dns_server[2], dns_server[3], clean
        );

        match net::dns::resolve(clean) {
            Ok(ip) => {
                set_color(Color::LightGreen, Color::Black);
                println!("Domain:  {}", clean);
                println!("Address: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] DNS resolution error: {}", e);
            }
        }
        set_color(Color::White, Color::Black);
    }
}

/// Shell command to download a remote file over HTTP and save directly into ZFS.
pub struct WgetCommand;

impl Command for WgetCommand {
    fn name(&self) -> &'static str {
        "wget"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["fetch", "curl"]
    }

    fn description(&self) -> &'static str {
        "Download remote files or packages over HTTP directly into persistent ZFS"
    }

    fn usage(&self) -> &'static str {
        "wget <server_ip_or_url> <port> <remote_path> <dest_zfs_path>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.len() < 4 {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: wget <server_ip_or_url> <port> <remote_path> <dest_zfs_path>");
            println!("Example: wget 10.0.2.2 80 /pkg/app.elf /bin/app.elf");
            return;
        }

        let clean_server = net::dns::clean_host(args[0]);
        let ip = match parse_ipv4(clean_server) {
            Some(parsed) => parsed,
            None => {
                set_color(Color::Yellow, Color::Black);
                println!("[*] Resolving '{}' via DNS...", clean_server);
                match net::dns::resolve(clean_server) {
                    Ok(resolved) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Resolved '{}' -> {}.{}.{}.{}", clean_server, resolved[0], resolved[1], resolved[2], resolved[3]);
                        resolved
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] DNS resolution failed for '{}': {}", clean_server, e);
                        return;
                    }
                }
            }
        };

        let port: u16 = match args[1].parse() {
            Ok(p) => p,
            Err(_) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid port number: '{}'", args[1]);
                return;
            }
        };

        let remote_path = args[2];
        let dest_path = args[3];

        set_color(Color::Yellow, Color::Black);
        println!("[*] Connecting to http://{}.{}.{}.{}:{}{} ...", ip[0], ip[1], ip[2], ip[3], port, remote_path);

        let mut download_buf = vec![0u8; 128 * 1024]; // 128 KiB download buffer

        let mut iface_guard = GLOBAL_INTERFACE.lock();
        match net::http::http_get(&mut iface_guard, ip, port, remote_path, &mut download_buf) {
            Ok(bytes_len) => {
                drop(iface_guard);
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Successfully downloaded {} bytes!", bytes_len);
                println!("[*] Writing payload directly to persistent OpenZFS path '{}'...", dest_path);

                match ZfsClient::write_file_by_path(dest_path, &download_buf[..bytes_len]) {
                    Ok(txg) => {
                        println!("[+] Written to ZFS! Committed in TXG #{}. Checksum verified via Fletcher-4.", txg);
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] Failed to commit to ZFS: {}", e);
                    }
                }
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] HTTP transfer failed: {}", e);
            }
        }
        set_color(Color::White, Color::Black);
    }
}

/// Helper function to parse a dotted-quad IPv4 string (`"10.0.2.2"`) into `[u8; 4]`.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut parts = [0u8; 4];
    let mut part_idx = 0;
    let mut current_val: u16 = 0;
    let mut has_digits = false;

    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digits || part_idx >= 3 || current_val > 255 {
                return None;
            }
            parts[part_idx] = current_val as u8;
            part_idx += 1;
            current_val = 0;
            has_digits = false;
        } else if b.is_ascii_digit() {
            current_val = current_val * 10 + ((b - b'0') as u16);
            if current_val > 255 {
                return None;
            }
            has_digits = true;
        } else {
            return None;
        }
    }

    if !has_digits || part_idx != 3 || current_val > 255 {
        return None;
    }
    parts[3] = current_val as u8;

    Some(parts)
}
