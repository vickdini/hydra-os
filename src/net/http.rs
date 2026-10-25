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
//! ## Key Functions
//!
//! - [`http_get()`]: Performs an HTTP GET request to the target server IP and port, returning the payload body.

extern crate alloc;

use alloc::format;
use crate::net::{tcp::TcpFlags, tcp::TcpPacket, Interface};

/// Performs an HTTP GET request to `server_ip:port` for the specified `path`.
///
/// # Arguments
/// - `iface`: Network interface handle.
/// - `server_ip`: Target server IPv4 address.
/// - `server_port`: Target TCP port (e.g. 80 or 8080).
/// - `path`: HTTP resource path (e.g. `/` or `/pkg/hello.elf`).
/// - `out_buf`: Destination byte buffer to receive the HTTP response payload body.
///
/// # Returns
/// `Ok(bytes_downloaded)` with payload length, or an error string on timeout/failure.
pub fn http_get(
    iface: &mut Interface,
    server_ip: [u8; 4],
    server_port: u16,
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

    // 2. Await TCP SYN-ACK
    let mut rx_buf = [0u8; 1518];
    let mut syn_ack_received = false;

    for _ in 0..200_000 {
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
        "GET {} HTTP/1.0\r\nHost: {}.{}.{}.{}\r\nUser-Agent: HydraOS/0.1\r\nConnection: close\r\n\r\n",
        path, server_ip[0], server_ip[1], server_ip[2], server_ip[3]
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

    // 5. Receive HTTP Response Data
    let mut total_received = 0;
    let mut header_ended = false;
    let mut body_start = 0;

    for _ in 0..500_000 {
        if let Some((src_ip, payload)) = iface.poll_ipv4(&mut rx_buf) {
            if src_ip == server_ip {
                if let Some(tcp) = TcpPacket::parse(payload) {
                    if tcp.dst_port == local_port && !tcp.payload.is_empty() {
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
                            8192,
                            &[],
                            &mut tx_buf,
                        )?;
                        let _ = iface.send_ipv4(server_ip, crate::net::ipv4::IpProtocol::Tcp, &tx_buf[..data_ack]);

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

    if header_ended && body_start < total_received {
        let body_len = total_received - body_start;
        // Shift payload body to the beginning of out_buf
        out_buf.copy_within(body_start..total_received, 0);
        Ok(body_len)
    } else {
        Ok(total_received)
    }
}
