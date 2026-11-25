//! # Network: the kernel's side
//!
//! The network protocols (Ethernet, ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS) run in Ring 3,
//! in net-server (`userland/drivers/net-server`), which drives the card through
//! `e1000-driver` itself. What stays in the kernel:
//!
//! - [`client`]: the client of net-server's protocol: sockets for the Linux personality
//!   (`compat/linux/inet.rs`), the interface's state, DHCP renewal and DNS lookups;
//! - [`e1000`]: finding the card on the PCI bus for the supervisor;
//! - the functions below for the shell (and later its admin operations): the boot-time
//!   report, [`ping`] and [`http_get`] on net-server sockets.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0; everything goes through [`crate::ipc::service`] calls to
//!   net-server (endpoint `ENDPOINT_NET_SERVER`).

pub mod client;
pub mod e1000;

/// net-server's DNS code, for [`clean_host`] (one source for both).
#[allow(dead_code)]
#[path = "../../userland/drivers/net-server/src/net/dns.rs"]
mod dns;

use alloc::vec::Vec;

pub use client::{iface, IfaceInfo};
pub use dns::clean_host;

/// Formats an IPv4 address.
fn dotted(ip: [u8; 4]) -> alloc::string::String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Reports the network at boot, once net-server runs: the card, then the DHCP lease
/// (waiting up to 10 s for it).
pub fn init() {
    // net-server was started by the supervisor; it starts DHCP at once and publishes its
    // status area right after registering
    let mut i = iface();
    let deadline = crate::arch::pit::ticks() + 200;
    while !i.running && client::service_running() && crate::arch::pit::ticks() < deadline {
        crate::task::sleep_ms(10);
        i = iface();
    }
    if !i.running {
        crate::console::set_color(uefi::proto::console::text::Color::Yellow, uefi::proto::console::text::Color::Black);
        crate::println!("[*] Network Subsystem: the network server is not running");
        return;
    }
    if !i.present {
        crate::console::set_color(uefi::proto::console::text::Color::Yellow, uefi::proto::console::text::Color::Black);
        crate::println!("[*] Network Subsystem: No compatible Ethernet adapter detected (loopback only)");
        return;
    }
    let m = i.mac;
    crate::console::set_color(uefi::proto::console::text::Color::LightGreen, uefi::proto::console::text::Color::Black);
    crate::println!(
        "[+] Network Subsystem: Intel E1000 Online (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, Link: {}), protocols in net-server",
        m[0], m[1], m[2], m[3], m[4], m[5],
        if i.link { "UP" } else { "NEGOTIATING" }
    );
    crate::console::set_color(uefi::proto::console::text::Color::Yellow, uefi::proto::console::text::Color::Black);
    crate::print!("    - DHCP Lease: Acquiring dynamic IPv4 configuration... ");
    let start = crate::arch::pit::ticks();
    let deadline = start + 1000;
    while i.ip == [0; 4] && crate::arch::pit::ticks() < deadline {
        // wave11 GG: no cable (the link still down after 3 s): no lease to wait for; the boot
        // goes on and net-server keeps trying (the NUC on Wi-Fi waited 10 s here)
        if !i.link && crate::arch::pit::ticks() >= start + 300 {
            break;
        }
        crate::task::sleep_ms(20);
        i = iface();
    }
    if i.ip != [0; 4] {
        crate::console::set_color(uefi::proto::console::text::Color::LightGreen, uefi::proto::console::text::Color::Black);
        crate::println!("ONLINE ({}, GW {}, DNS {})", dotted(i.ip), dotted(i.gateway), dotted(i.dns));
    } else {
        crate::console::set_color(uefi::proto::console::text::Color::LightRed, uefi::proto::console::text::Color::Black);
        crate::println!("Deferred ({}; net-server keeps trying)", if i.link { "no DHCP answer yet" } else { "no link: no cable?" });
    }
}

/// Runs DHCP again and waits for the lease: the interface afterwards.
///
/// # Errors
/// No card, or no DHCP answer.
pub fn dhcp_renew() -> Result<IfaceInfo, &'static str> {
    client::dhcp_renew()?;
    Ok(iface())
}

/// Looks a host name up over DNS.
///
/// # Errors
/// See [`client::resolve`].
pub fn resolve(name: &str) -> Result<[u8; 4], &'static str> {
    let clean = clean_host(name);
    if clean.is_empty() {
        return Err("Domain name cannot be empty");
    }
    client::resolve(clean)
}

/// Sends one ICMP echo request to `target` (sequence `seq`, on a ping socket) and waits up
/// to 1.5 s for the reply: the round trip in milliseconds.
///
/// # Errors
/// No address, no server, or no reply.
pub fn ping(target: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    if !client::is_local(target) && iface().ip == [0; 4] {
        return Err("Local network interface has no IP address assigned (run 'dhcp' first)");
    }
    let id = client::icmp_open(false, false);
    if id == 0 {
        return Err("the network server is not running");
    }
    let mut msg = alloc::vec![8u8, 0, 0, 0, 0, 0];
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(b"HydraOS_ICMP_Echo_Ping_Payload!");
    let start = crate::arch::pit::uptime_ms();
    let r = (|| {
        client::icmp_send(id, target, &msg).map_err(|_| "cannot send the echo request")?;
        while crate::arch::pit::uptime_ms() - start < 1500 {
            if let Some((src, reply, _)) = client::icmp_recv(id, false) {
                // A ping socket gets only echo replies with its identifier
                if src == target && reply.len() >= 8 && u16::from_be_bytes([reply[6], reply[7]]) == seq {
                    return Ok(crate::arch::pit::uptime_ms().saturating_sub(start));
                }
            }
            crate::task::sleep_ms(1);
        }
        Err("Request timed out (no ICMP Echo Reply received)")
    })();
    client::icmp_close(id);
    r
}

/// HTTP/1.0 GET of `path` from `ip:port` over a net-server TCP socket; the response body
/// (headers removed) goes into `out` (truncated to its size): its length. Replaces the
/// kernel's raw-segment HTTP client (`net/http.rs`); waits at most 5 s for the connection
/// and 5 s between received bytes.
///
/// # Errors
/// Connection refused or timed out, or a malformed response.
pub fn http_get(ip: [u8; 4], port: u16, path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    let id = client::tcp_connect(ip, port, None).map_err(|_| "cannot connect (no network?)")?;
    let r = (|| {
        let start = crate::arch::pit::uptime_ms();
        loop {
            match client::tcp_state(id) {
                client::TcpState::SynSent => {}
                client::TcpState::Closed => return Err("connection refused"),
                _ => break,
            }
            if crate::arch::pit::uptime_ms() - start > 5000 {
                return Err("TCP handshake timed out (no SYN-ACK received)");
            }
            crate::task::sleep_ms(2);
        }
        let host = dotted(ip);
        let req = alloc::format!("GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: HydraOS\r\nConnection: close\r\n\r\n", path, host);
        let mut sent = 0;
        while sent < req.len() {
            let n = client::tcp_send(id, &req.as_bytes()[sent..]).map_err(|_| "sending the request failed")?;
            sent += n;
            if n == 0 {
                crate::task::sleep_ms(2);
            }
        }
        let mut resp: Vec<u8> = Vec::new();
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let mut last = crate::arch::pit::uptime_ms();
        loop {
            match client::tcp_recv(id, &mut buf, false) {
                Ok((0, true)) => break,
                Ok((0, false)) => {
                    if crate::arch::pit::uptime_ms() - last > 5000 {
                        return Err("the transfer stalled (no data for 5 s)");
                    }
                    crate::task::sleep_ms(1);
                }
                Ok((n, eof)) => {
                    last = crate::arch::pit::uptime_ms();
                    if resp.len() < out.len() + 64 * 1024 {
                        resp.extend_from_slice(&buf[..n]);
                    }
                    if eof {
                        break;
                    }
                }
                Err(_) => return Err("the connection was reset"),
            }
        }
        let body = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response (no header end)")? + 4;
        let n = (resp.len() - body).min(out.len());
        out[..n].copy_from_slice(&resp[body..body + n]);
        Ok(n)
    })();
    client::tcp_close(id);
    r
}
