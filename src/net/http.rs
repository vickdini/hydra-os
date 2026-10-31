//! # Network Subsystem: HTTP Client & Package Downloader
//!
//! Provides a synchronous HTTP/1.0 client to download remote packages, binaries, and text assets over TCP.
//!
//! ## Architectural Role & Design Rationale
//!
//! To install standalone packages, userland tools, and datasets onto the persistent OpenZFS filesystem,
//! Hydra OS requires an application-layer transfer protocol. The HTTP client initiates a TCP stream connection,
//! dispatches standard HTTP `GET` requests, parses response headers (`200 OK`), strips MIME metadata,
//! and streams the downloaded payload bytes directly into memory or ZFS files.
//!
//! ## Key Types & Interfaces
//!
//! - [`http_get_host()`]: Performs an HTTP/1.0 `GET` request with an explicit `Host:` header.
//! - [`http_get()`]: Convenience wrapper performing an HTTP/1.0 `GET` request using the numerical IPv4 address as `Host:`.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 (Kernel Mode).
//! - Dependencies: Uses [`Interface`] and [`TcpPacket`] for polled TCP connection state management and `crate::arch::pit` for handshake/receive timeouts.

extern crate alloc;

use alloc::format;
use crate::net::{tcp::TcpFlags, tcp::TcpPacket, Interface};

/// Performs an HTTP/1.0 `GET` request to `server_ip:server_port` for `path` with an explicit `Host:` header.
///
/// Establishes a polled 3-way TCP handshake, sends the formatted `GET` request, accumulates response
/// segments while acknowledging data, verifies an HTTP `200 OK` status, and shifts the response body
/// to the start of `out_buf`.
///
/// # Arguments
/// - `iface`: Mutable reference to the local network [`Interface`].
/// - `server_ip`: Target server 4-byte IPv4 address.
/// - `server_port`: Target TCP port (e.g., `80` or `8080`).
/// - `host`: Value for the HTTP `Host:` request header.
/// - `path`: HTTP resource path (e.g., `"/"` or `"/pkg/hello.elf"`).
/// - `out_buf`: Destination byte buffer to receive the HTTP response payload body.
///
/// # Returns
/// `Ok(bytes_downloaded)` containing the length of the HTTP response body written to `out_buf`.
///
/// # Errors
/// Returns `Err` if the interface has no IP, the TCP handshake times out, no data is received,
/// or the server responds with a non-`200` HTTP status code.
pub fn http_get_host(
    iface: &mut Interface,
    server_ip: [u8; 4],
    server_port: u16,
    host: &str,
    path: &str,
    out_buf: &mut [u8],
) -> Result<usize, &'static str> {
    let local_ip = iface.ip();
    if local_ip == [0, 0, 0, 0] {
        return Err("Network interface has no configured IP address (run 'dhcp' first)");
    }

    let local_port = 49152 + ((crate::arch::pit::uptime_ms() % 1000) as u16);
    let mut client_seq: u32 = 1000;
    let mut server_seq: u32 = 0;

    // 1. Send TCP SYN
    let mut tx_buf = [0u8; 1518];
    let tcp_syn_len = TcpPacket::serialize(
        local_ip,
        server_ip,
        local_port,
        server_port,
        client_seq,
        0,
        TcpFlags::SYN,
        8192,
        &[],
        &mut tx_buf,
    )?;
    iface.send_ipv4(server_ip, crate::net::ipv4::IpProtocol::Tcp, &tx_buf[..tcp_syn_len])?;

    // 2. Await TCP SYN-ACK (5-second timeout)
    let mut rx_buf = [0u8; 1518];
    let mut syn_ack_received = false;
    let syn_timeout_ms = 5000;
    let syn_start_ms = crate::arch::pit::uptime_ms();

    while crate::arch::pit::uptime_ms().saturating_sub(syn_start_ms) < syn_timeout_ms {
        if let Some((src_ip, payload)) = iface.poll_ipv4(&mut rx_buf) {
            if src_ip == server_ip {
                if let Some(tcp) = TcpPacket::parse(payload) {
                    if tcp.dst_port == local_port && (tcp.flags & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                        server_seq = tcp.seq_num.wrapping_add(1);
                        client_seq = client_seq.wrapping_add(1);
                        syn_ack_received = true;
                        break;
                    }
                }
            }
        }
        core::hint::spin_loop();
    }

    if !syn_ack_received {
        return Err("TCP connection timed out waiting for SYN-ACK");
    }

    // 3. Send TCP ACK to complete handshake
    let ack_len = TcpPacket::serialize(
        local_ip,
        server_ip,
        local_port,
        server_port,
        client_seq,
        server_seq,
        TcpFlags::ACK,
        8192,
        &[],
        &mut tx_buf,
    )?;
    iface.send_ipv4(server_ip, crate::net::ipv4::IpProtocol::Tcp, &tx_buf[..ack_len])?;

    // 4. Send HTTP GET Request Payload
    let http_req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: HydraOS/0.1\r\nConnection: close\r\n\r\n",
        path, host
    );

    let psh_len = TcpPacket::serialize(
        local_ip,
        server_ip,
        local_port,
        server_port,
        client_seq,
        server_seq,
        TcpFlags::PSH | TcpFlags::ACK,
        8192,
        http_req.as_bytes(),
        &mut tx_buf,
    )?;
    iface.send_ipv4(server_ip, crate::net::ipv4::IpProtocol::Tcp, &tx_buf[..psh_len])?;
    client_seq = client_seq.wrapping_add(http_req.len() as u32);

    // 5. Receive HTTP Response Data (6-second inactivity timeout)
    let mut total_received = 0;
    let mut header_ended = false;
    let mut body_start = 0;
    let mut last_rx_ms = crate::arch::pit::uptime_ms();
    let data_timeout_ms = 6000;
    let mut last_log_kb = 0;

    while crate::arch::pit::uptime_ms().saturating_sub(last_rx_ms) < data_timeout_ms {
        if let Some((src_ip, payload)) = iface.poll_ipv4(&mut rx_buf) {
            if src_ip == server_ip {
                if let Some(tcp) = TcpPacket::parse(payload) {
                    if tcp.dst_port == local_port {
                        if !tcp.payload.is_empty() {
                            last_rx_ms = crate::arch::pit::uptime_ms();
                            let available = out_buf.len().saturating_sub(total_received);
                            let copy_len = tcp.payload.len().min(available);
                            out_buf[total_received..total_received + copy_len].copy_from_slice(&tcp.payload[..copy_len]);
                            total_received += copy_len;
                            server_seq = server_seq.wrapping_add(tcp.payload.len() as u32);

                            // Send ACK for data
                            let data_ack = TcpPacket::serialize(
                                local_ip,
                                server_ip,
                                local_port,
                                server_port,
                                client_seq,
                                server_seq,
                                TcpFlags::ACK,
                                32768,
                                &[],
                                &mut tx_buf,
                            )?;
                            let _ = iface.send_ipv4(server_ip, crate::net::ipv4::IpProtocol::Tcp, &tx_buf[..data_ack]);

                            // Progress telemetry every 1 MB
                            if total_received / 1024 >= last_log_kb + 1024 {
                                last_log_kb = total_received / 1024;
                                crate::console::set_color(uefi::proto::console::text::Color::LightCyan, uefi::proto::console::text::Color::Black);
                                println!("    Downloaded {} KB ...", last_log_kb);
                            }
                        }

                        // Check if connection FIN received
                        if (tcp.flags & TcpFlags::FIN) != 0 {
                            break;
                        }
                    }
                }
            }
        }
        core::hint::spin_loop();
    }

    if total_received == 0 {
        return Err("No response data received from HTTP server");
    }

    // Locate header end: "\r\n\r\n"
    for i in 0..total_received.saturating_sub(3) {
        if out_buf[i] == b'\r' && out_buf[i + 1] == b'\n' && out_buf[i + 2] == b'\r' && out_buf[i + 3] == b'\n' {
            header_ended = true;
            body_start = i + 4;
            break;
        }
    }

    // Verify HTTP status code (must be 200 OK)
    let header_preview = core::str::from_utf8(&out_buf[..total_received.min(128)]).unwrap_or("");
    if let Some(status_line) = header_preview.lines().next() {
        let mut parts = status_line.split_whitespace();
        let _http_ver = parts.next();
        if let Some(status_code) = parts.next() {
            if status_code != "200" {
                return Err("HTTP server returned non-200 status (e.g. 404 Not Found)");
            }
        }
    }

    if header_ended && body_start < total_received {
        let body_len = total_received - body_start;
        // Shift payload body to the beginning of out_buf
        out_buf.copy_within(body_start..total_received, 0);
        Ok(body_len)
    } else {
        Ok(total_received)
    }
}

/// Convenience wrapper performing an HTTP/1.0 `GET` request using the numerical IPv4 address as the `Host:` header.
///
/// # Arguments
/// - `iface`: Mutable reference to the local network [`Interface`].
/// - `server_ip`: Target server 4-byte IPv4 address.
/// - `server_port`: Target TCP port (e.g., `80` or `8080`).
/// - `path`: HTTP resource path (e.g., `"/"` or `"/pkg/hello.elf"`).
/// - `out_buf`: Destination byte buffer to receive the HTTP response payload body.
///
/// # Returns
/// `Ok(bytes_downloaded)` containing the length of the HTTP response body written to `out_buf`.
///
/// # Errors
/// Propagates any connection, timeout, or HTTP status error from [`http_get_host`].
pub fn http_get(
    iface: &mut Interface,
    server_ip: [u8; 4],
    server_port: u16,
    path: &str,
    out_buf: &mut [u8],
) -> Result<usize, &'static str> {
    let host_str = format!("{}.{}.{}.{}", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
    http_get_host(iface, server_ip, server_port, &host_str, path, out_buf)
}

