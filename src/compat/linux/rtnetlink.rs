//! # Routing netlink sockets (`AF_NETLINK`, `NETLINK_ROUTE`)
//!
//! What programs use to list network interfaces, addresses and routes: glibc's
//! `getifaddrs`, Chromium's address tracker, `ip`. A socket answers dump requests for
//! links (`RTM_GETLINK`), addresses (`RTM_GETADDR`) and routes (`RTM_GETROUTE`) with the
//! loopback interface and, once it has an address, the Ethernet interface (`eth0`). A
//! process in a network namespace of its own sees only the loopback interface. Hydra's
//! interfaces do not change after DHCP, so multicast subscribers never get events, and
//! requests that would change the configuration fail with `EOPNOTSUPP`.

use alloc::string::String;
use alloc::vec::Vec;


use super::vfs::{copy_in, copy_out};

const EFAULT: i64 = -14;

const AF_INET: u8 = 2;


/// The Ethernet interface's `(mac, ip, netmask, gateway)`, if it has an address and the
/// caller can see it.
fn ethernet() -> Option<([u8; 6], [u8; 4], [u8; 4], [u8; 4])> {
    let i = crate::net::iface();
    if super::ns::net_isolated() || !i.present {
        return None;
    }
    (i.ip != [0; 4]).then_some((i.mac, i.ip, i.mask, i.gateway))
}

/// Pads `line` with spaces to `width` and ends it (`/proc/net/route` rows are fixed width).
fn padded(mut line: String, width: usize) -> String {
    while line.len() < width {
        line.push(' ');
    }
    line.push('\n');
    line
}

/// An IPv6 address as `/proc/net` shows it: 32 hex digits.
fn hex6(a: &[u8; 16]) -> String {
    a.iter().map(|b| alloc::format!("{:02x}", b)).collect()
}

/// The routing and address tables under `/proc/net` that tools read instead of netlink
/// (Wine's nsiproxy among them: without `route` its gateway table fails, and so does
/// `GetAdaptersAddresses`). The same view as the netlink dumps above.
pub fn proc_net_text(file: &str) -> Option<String> {
    let eth = ethernet();
    let ll = eth.and(crate::net::client::link_local6());
    let mut lo6 = [0u8; 16];
    lo6[15] = 1;
    match file {
        // The interface counters (net-server's; wave10 G10-C: moved here from the deleted
        // in-kernel socket copy, `inet.rs`)
        "dev" => {
            let isolated = super::ns::net_isolated();
            let mut out = String::from(
                "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
            );
            let c = crate::net::client::counters();
            let mut ifaces = alloc::vec![("lo", c[0])];
            if !isolated && crate::net::iface().present {
                ifaces.push(("eth0", c[1]));
            }
            if isolated {
                ifaces[0].1 = ((0, 0), (0, 0));
            }
            for (name, ((rb, rp), (tb, tp))) in ifaces {
                out.push_str(&alloc::format!(
                    "{:>6}:{:8} {:7} {:4} {:4} {:4} {:5} {:10} {:9} {:8} {:7} {:4} {:4} {:4} {:5} {:7} {:10}\n",
                    name, rb, rp, 0, 0, 0, 0, 0, 0, tb, tp, 0, 0, 0, 0, 0, 0
                ));
            }
            Some(out)
        }
        // Addresses and masks as host-order (little-endian) words, as Linux prints them
        "route" => {
            let mut out = padded(String::from("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"), 127);
            if let Some((_, ip, mask, gw)) = eth {
                let w = |a: [u8; 4]| u32::from_le_bytes(a);
                let net = (u32::from_be_bytes(ip) & u32::from_be_bytes(mask)).to_be_bytes();
                if gw != [0; 4] {
                    // RTF_UP | RTF_GATEWAY
                    out.push_str(&padded(alloc::format!("eth0\t{:08X}\t{:08X}\t{:04X}\t0\t0\t100\t{:08X}\t0\t0\t0", 0, w(gw), 3, 0), 127));
                }
                out.push_str(&padded(alloc::format!("eth0\t{:08X}\t{:08X}\t{:04X}\t0\t0\t100\t{:08X}\t0\t0\t0", w(net), 0, 1, w(mask)), 127));
            }
            Some(out)
        }
        // dst, dst prefix, src, src prefix, next hop, metric, refcount, use, flags, device
        "ipv6_route" => {
            let z = [0u8; 16];
            let row = |dst: &[u8; 16], plen: u8, metric: u32, flags: u32, dev: &str| {
                alloc::format!("{} {:02x} {} {:02x} {} {:08x} {:08x} {:08x} {:08x} {:>8}\n", hex6(dst), plen, hex6(&z), 0, hex6(&z), metric, 1, 0, flags, dev)
            };
            let mut out = String::new();
            let mut fe80 = [0u8; 16];
            fe80[0] = 0xfe;
            fe80[1] = 0x80;
            if ll.is_some() {
                out.push_str(&row(&fe80, 64, 256, 0x1, "eth0")); // RTF_UP
            }
            out.push_str(&row(&lo6, 128, 0, 0x8020_0001, "lo")); // local: RTF_UP | RTF_NONEXTHOP | RTF_LOCAL
            if let Some(a) = ll {
                out.push_str(&row(&a, 128, 0, 0x8020_0001, "eth0"));
            }
            if ll.is_some() {
                let mut ff = [0u8; 16];
                ff[0] = 0xff;
                out.push_str(&row(&ff, 8, 256, 0x1, "eth0"));
            }
            Some(out)
        }
        // address, interface index, prefix length, scope (host 0x10, link 0x20), flags, device
        "if_inet6" => {
            let mut out = alloc::format!("{} {:02x} {:02x} {:02x} {:02x} {:>8}\n", hex6(&lo6), 1, 128, 0x10, 0x80, "lo");
            if let Some(a) = ll {
                out.push_str(&alloc::format!("{} {:02x} {:02x} {:02x} {:02x} {:>8}\n", hex6(&a), 2, 64, 0x20, 0x80, "eth0"));
            }
            Some(out)
        }
        "arp" => {
            let mut out = String::from("IP address       HW type     Flags       HW address            Mask     Device\n");
            if eth.is_some() {
                for (ip, m) in crate::net::client::arp_entries() {
                    let ip = alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    let mac = alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]);
                    // ATF_COM: complete
                    out.push_str(&alloc::format!("{:<16} 0x{:<10x}0x{:<10x}{:<17}     *        {}\n", ip, 1, 2, mac, "eth0"));
                }
            }
            Some(out)
        }
        "snmp" => {
            let c = crate::net::client::counters();
            let (rx, tx) = if super::ns::net_isolated() { (0, 0) } else { ((c[0].0).1 + (c[1].0).1, (c[0].1).1 + (c[1].1).1) };
            let zeros = |n: usize| alloc::vec!["0"; n].join(" ");
            Some(alloc::format!(
                "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n\
                 Ip: 2 64 {rx} 0 0 0 0 0 {rx} {tx} 0 0 0 0 0 0 0 0 0 {tx}\n\
                 Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
                 Icmp: {z29}\n\
                 Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
                 Tcp: 1 200 120000 -1 {z11}\n\
                 Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
                 Udp: {z9}\n\
                 UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
                 UdpLite: {z9}\n",
                z29 = zeros(29),
                z11 = zeros(11),
                z9 = zeros(9),
            ))
        }
        "snmp6" => {
            let mut out = String::new();
            for name in [
                "Ip6InReceives", "Ip6InHdrErrors", "Ip6InTooBigErrors", "Ip6InNoRoutes", "Ip6InAddrErrors", "Ip6InUnknownProtos",
                "Ip6InTruncatedPkts", "Ip6InDiscards", "Ip6InDelivers", "Ip6OutForwDatagrams", "Ip6OutRequests", "Ip6OutDiscards",
                "Ip6OutNoRoutes", "Ip6ReasmTimeout", "Ip6ReasmReqds", "Ip6ReasmOKs", "Ip6ReasmFails", "Ip6FragOKs", "Ip6FragFails",
                "Ip6FragCreates", "Icmp6InMsgs", "Icmp6InErrors", "Icmp6OutMsgs", "Icmp6OutErrors", "Udp6InDatagrams", "Udp6NoPorts",
                "Udp6InErrors", "Udp6OutDatagrams",
            ] {
                out.push_str(&alloc::format!("{:<32}\t{}\n", name, 0));
            }
            Some(out)
        }
        _ => None,
    }
}

/// The visible interfaces as `(index, name, flags, mac, ip, netmask, mtu, arphrd)`.
fn interfaces() -> Vec<(i32, &'static str, u16, [u8; 6], [u8; 4], [u8; 4], i32, u16)> {
    let mut out = alloc::vec![(1, "lo", 0x1 | 0x8 | 0x40, [0u8; 6], [127, 0, 0, 1], [255, 0, 0, 0], 65536, 772)];
    if let Some((mac, ip, mask, _)) = ethernet() {
        out.push((2, "eth0", 0x1 | 0x2 | 0x40 | 0x1000, mac, ip, mask, 1500, 1));
    }
    out
}

/// The interface queries of `ioctl` on a socket (`SIOCGIF*`, `struct ifreq`), from the same
/// interfaces netlink reports. glibc's `if_nametoindex` and `if_indextoname` use them.
///
/// # Arguments
/// * `cmd` - `ioctl` request.
/// * `arg` - User pointer to the `struct ifreq` (or `struct ifconf` for `SIOCGIFCONF`).
///
/// # Returns
/// The `ioctl` result, or `None` if `cmd` is not an interface query.
pub fn interface_ioctl(cmd: u64, arg: u64) -> Option<i64> {
    const ENODEV: i64 = -19;
    let ifs = interfaces();
    let sockaddr_in = |ip: [u8; 4]| {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        b[4..8].copy_from_slice(&ip);
        b
    };
    if cmd == 0x8912 {
        // SIOCGIFCONF: an ifreq (name + address) per interface, as many as fit
        let Ok(conf) = copy_in(arg, 16) else { return Some(EFAULT) };
        let cap = i32::from_le_bytes(conf[0..4].try_into().unwrap()).max(0) as usize;
        let buf = u64::from_le_bytes(conf[8..16].try_into().unwrap());
        let mut out = Vec::new();
        for i in &ifs {
            if buf != 0 && out.len() + 40 > cap {
                break;
            }
            let mut r = [0u8; 40];
            r[..i.1.len()].copy_from_slice(i.1.as_bytes());
            r[16..32].copy_from_slice(&sockaddr_in(i.4));
            out.extend_from_slice(&r);
        }
        if buf != 0 && copy_out(buf, &out).is_err() {
            return Some(EFAULT);
        }
        return Some(if copy_out(arg, &(out.len() as i32).to_le_bytes()).is_ok() { 0 } else { EFAULT });
    }
    if !matches!(cmd, 0x8910 | 0x8913 | 0x8915 | 0x8919 | 0x891b | 0x8921 | 0x8927 | 0x8933) {
        return None;
    }
    let Ok(req) = copy_in(arg, 40) else { return Some(EFAULT) };
    let found = if cmd == 0x8910 {
        // SIOCGIFNAME: by index
        let index = i32::from_le_bytes(req[16..20].try_into().unwrap());
        ifs.iter().find(|i| i.0 == index)
    } else {
        let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
        ifs.iter().find(|i| i.1.as_bytes() == &req[..end])
    };
    let Some(&(index, name, flags, mac, ip, mask, mtu, hw)) = found else { return Some(ENODEV) };
    let mut r = [0u8; 40];
    r[..16].copy_from_slice(&req[..16]);
    match cmd {
        0x8910 => {
            r[..16].fill(0);
            r[..name.len()].copy_from_slice(name.as_bytes());
            r[16..20].copy_from_slice(&index.to_le_bytes());
        }
        0x8913 => r[16..18].copy_from_slice(&flags.to_le_bytes()),
        0x8915 => r[16..32].copy_from_slice(&sockaddr_in(ip)),
        0x8919 => r[16..32].copy_from_slice(&sockaddr_in((u32::from_be_bytes(ip) | !u32::from_be_bytes(mask)).to_be_bytes())),
        0x891b => r[16..32].copy_from_slice(&sockaddr_in(mask)),
        0x8921 => r[16..20].copy_from_slice(&mtu.to_le_bytes()),
        0x8927 => {
            r[16..18].copy_from_slice(&hw.to_le_bytes());
            r[18..24].copy_from_slice(&mac);
        }
        _ => r[16..20].copy_from_slice(&index.to_le_bytes()), // SIOCGIFINDEX
    }
    Some(if copy_out(arg, &r).is_ok() { 0 } else { EFAULT })
}
