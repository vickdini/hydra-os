//! # Routing netlink sockets (`AF_NETLINK`, `NETLINK_ROUTE`)
//!
//! What programs use to list network interfaces, addresses and routes: glibc's
//! `getifaddrs`, Chromium's address tracker, `ip`. A socket answers dump requests for
//! links (`RTM_GETLINK`), addresses (`RTM_GETADDR`) and routes (`RTM_GETROUTE`) with the
//! loopback interface and, once it has an address, the Ethernet interface (`eth0`). A
//! process in a network namespace of its own sees only the loopback interface. Hydra's
//! interfaces do not change after DHCP, so multicast subscribers never get events, and
//! requests that would change the configuration fail with `EOPNOTSUPP`.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

const AF_NETLINK: u16 = 16;
const AF_INET: u8 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const MSG_PEEK: u64 = 2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

/// Never woken: replies are queued as requests arrive, so a receive on an empty socket
/// waits for a signal.
static NEVER: WaitQueue = WaitQueue::new();

/// A routing netlink socket.
pub struct RouteSocket {
    /// Port ID (`nl_pid`), the process ID unless bound to another.
    port: AtomicU32,
    groups: AtomicU32,
    nonblock: AtomicBool,
    /// Reply datagrams not yet received.
    replies: Mutex<VecDeque<Vec<u8>>>,
}

/// Creates a routing netlink socket (`socket(AF_NETLINK, SOCK_RAW|SOCK_DGRAM, NETLINK_ROUTE)`).
///
/// # Arguments
/// * `ty` - Socket type and flags.
///
/// # Returns
/// The new descriptor, or a negative errno.
pub fn socket(ty: u64) -> i64 {
    let sock: Arc<dyn CharDevice> = Arc::new(RouteSocket {
        port: AtomicU32::new(super::proc::current_ids().1 as u32),
        groups: AtomicU32::new(0),
        nonblock: AtomicBool::new(ty & SOCK_NONBLOCK != 0),
        replies: Mutex::new(VecDeque::new()),
    });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(sock)) {
        Ok(fd) => {
            fds.set_cloexec(fd, ty & SOCK_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => -24,
    })
}

/// Appends a route attribute (`struct rtattr` and its data, padded to 4 bytes).
fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Appends a netlink message of type `ty` with `body` to `out`.
fn message(out: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, port: u32, body: &[u8]) {
    out.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// The Ethernet interface's `(mac, ip, netmask, gateway)`, if it has an address and the
/// caller can see it.
fn ethernet() -> Option<([u8; 6], [u8; 4], [u8; 4], [u8; 4])> {
    if super::ns::net_isolated() || !crate::net::e1000::is_present() {
        return None;
    }
    let iface = crate::net::GLOBAL_INTERFACE.lock();
    let ip = iface.ip();
    (ip != [0; 4]).then(|| (crate::net::e1000::mac_address(), ip, iface.subnet_mask(), iface.gateway()))
}

/// `RTM_NEWLINK` bodies for the visible interfaces.
fn links() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // ifinfomsg: family, pad, type, index, flags, change
    let link = |kind: u16, index: i32, flags: u32, name: &[u8], mac: &[u8], broadcast: &[u8], mtu: u32| {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&index.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        attr(&mut b, 3, name); // IFLA_IFNAME
        attr(&mut b, 4, &mtu.to_le_bytes()); // IFLA_MTU
        attr(&mut b, 1, mac); // IFLA_ADDRESS
        attr(&mut b, 2, broadcast); // IFLA_BROADCAST
        attr(&mut b, 16, &[6]); // IFLA_OPERSTATE: IF_OPER_UP
        b
    };
    // IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP
    out.push(link(772, 1, 0x1 | 0x8 | 0x40 | 0x10000, b"lo\0", &[0; 6], &[0; 6], 65536));
    if let Some((mac, ..)) = ethernet() {
        // IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP
        out.push(link(1, 2, 0x1 | 0x2 | 0x40 | 0x1000 | 0x10000, b"eth0\0", &mac, &[0xff; 6], 1500));
    }
    out
}

/// `RTM_NEWADDR` bodies for the visible IPv4 addresses.
fn addresses() -> Vec<Vec<u8>> {
    // ifaddrmsg: family, prefix length, flags, scope, index
    let addr = |index: u32, ip: [u8; 4], prefix: u8, scope: u8, label: &[u8], broadcast: Option<[u8; 4]>| {
        let mut b = alloc::vec![AF_INET, prefix, 0x80, scope];
        b.extend_from_slice(&index.to_le_bytes());
        attr(&mut b, 1, &ip); // IFA_ADDRESS
        attr(&mut b, 2, &ip); // IFA_LOCAL
        if let Some(bc) = broadcast {
            attr(&mut b, 4, &bc); // IFA_BROADCAST
        }
        attr(&mut b, 3, label); // IFA_LABEL
        attr(&mut b, 8, &0x80u32.to_le_bytes()); // IFA_FLAGS: IFA_F_PERMANENT
        b
    };
    let mut out = alloc::vec![addr(1, [127, 0, 0, 1], 8, 254, b"lo\0", None)];
    if let Some((_, ip, mask, _)) = ethernet() {
        let prefix = u32::from_be_bytes(mask).count_ones() as u8;
        let bc = (u32::from_be_bytes(ip) | !u32::from_be_bytes(mask)).to_be_bytes();
        out.push(addr(2, ip, prefix, 0, b"eth0\0", Some(bc)));
    }
    out
}

/// `RTM_NEWROUTE` bodies for the main table: the local subnet and the default route.
fn routes() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some((_, ip, mask, gateway)) = ethernet() {
        // rtmsg: family, dst len, src len, tos, table, protocol, scope, type, flags
        let route = |dst_len: u8, protocol: u8, scope: u8| {
            let mut b = alloc::vec![AF_INET, dst_len, 0, 0, 254, protocol, scope, 1];
            b.extend_from_slice(&0u32.to_le_bytes());
            attr(&mut b, 15, &254u32.to_le_bytes()); // RTA_TABLE: main
            b
        };
        let prefix = u32::from_be_bytes(mask).count_ones() as u8;
        if gateway != [0; 4] {
            let mut b = route(0, 16, 0); // RTPROT_DHCP, RT_SCOPE_UNIVERSE
            attr(&mut b, 5, &gateway); // RTA_GATEWAY
            attr(&mut b, 4, &2u32.to_le_bytes()); // RTA_OIF
            out.push(b);
        }
        let mut b = route(prefix, 2, 253); // RTPROT_KERNEL, RT_SCOPE_LINK
        attr(&mut b, 1, &(u32::from_be_bytes(ip) & u32::from_be_bytes(mask)).to_be_bytes()); // RTA_DST
        attr(&mut b, 7, &ip); // RTA_PREFSRC
        attr(&mut b, 4, &2u32.to_le_bytes()); // RTA_OIF
        out.push(b);
    }
    out
}

impl RouteSocket {
    /// Answers the requests in one sent datagram, queueing one reply datagram for each.
    fn handle(&self, data: &[u8]) {
        let port = self.port.load(Ordering::Relaxed);
        let mut off = 0;
        while off + 16 <= data.len() {
            let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            if len < 16 || off + len > data.len() {
                break;
            }
            let ty = u16::from_le_bytes([data[off + 4], data[off + 5]]);
            let flags = u16::from_le_bytes([data[off + 6], data[off + 7]]);
            let seq = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
            let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
            let mut reply = Vec::new();
            let parts = match ty {
                RTM_GETLINK if dump => Some((RTM_NEWLINK, links())),
                RTM_GETADDR if dump => Some((RTM_NEWADDR, addresses())),
                RTM_GETROUTE if dump => Some((RTM_NEWROUTE, routes())),
                _ => None,
            };
            match parts {
                Some((kind, bodies)) => {
                    for b in bodies {
                        message(&mut reply, kind, NLM_F_MULTI, seq, port, &b);
                    }
                    message(&mut reply, NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_le_bytes());
                }
                None => {
                    // nlmsgerr: the error and the request's header
                    let mut b = (EOPNOTSUPP as i32).to_le_bytes().to_vec();
                    b.extend_from_slice(&data[off..off + 16]);
                    message(&mut reply, NLMSG_ERROR, 0, seq, port, &b);
                }
            }
            self.replies.lock().push_back(reply);
            off += (len + 3) & !3;
        }
    }

    /// Takes the next reply datagram (or a copy, with `peek`), waiting for one unless
    /// non-blocking.
    fn next(&self, peek: bool, dontwait: bool) -> Result<Vec<u8>, i64> {
        let take = |q: &mut VecDeque<Vec<u8>>| if peek { q.front().cloned() } else { q.pop_front() };
        if let Some(d) = take(&mut self.replies.lock()) {
            return Ok(d);
        }
        if dontwait || self.nonblock() {
            return Err(EAGAIN);
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&NEVER));
        loop {
            waits.register();
            if super::proc::signal_pending() {
                return Err(super::proc::ERESTARTSYS);
            }
            waits.wait(None);
        }
    }

    /// The socket address of the kernel side (`struct sockaddr_nl`, port 0).
    fn kernel_addr() -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
        b
    }

    /// Reads the `struct iovec` array of a `msghdr` at `msg` as `(base, len)` pairs.
    fn iovecs(msg: &[u8]) -> Result<Vec<(u64, usize)>, i64> {
        let iov = u64::from_le_bytes(msg[16..24].try_into().unwrap());
        let n = (u64::from_le_bytes(msg[24..32].try_into().unwrap()) as usize).min(64);
        let raw = copy_in(iov, n * 16)?;
        Ok(raw.chunks(16).map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap()) as usize)).collect())
    }
}

/// Copies a socket address out (`addr`, `*lenp` capacity), like `put_addr` in [`super::netlink`].
fn put_addr(addr: u64, lenp: u64, data: &[u8]) -> i64 {
    if addr == 0 || lenp == 0 {
        return 0;
    }
    let cap = match copy_in(lenp, 4) {
        Ok(v) => u32::from_le_bytes(v[..4].try_into().unwrap()) as usize,
        Err(e) => return e,
    };
    if copy_out(addr, &data[..cap.min(data.len())]).is_err() || copy_out(lenp, &(data.len() as u32).to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

impl CharDevice for RouteSocket {
    fn read(&self, buf: &mut [u8]) -> i64 {
        match self.next(false, false) {
            Ok(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                n as i64
            }
            Err(e) => e,
        }
    }

    fn write(&self, data: &[u8]) -> i64 {
        self.handle(data);
        data.len() as i64
    }

    fn poll_events(&self) -> u32 {
        // POLLOUT, and POLLIN while a reply waits
        0x0004 | if self.replies.lock().is_empty() { 0 } else { 0x0001 }
    }

    fn add_wait_queues(&self, _waits: &mut WaitSet) {}

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        alloc::format!("socket:[{}]", self as *const _ as usize as u64 & 0xFFFF_FFFF)
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    fn socket_call(&self, num: u64, a: [u64; 6]) -> Option<i64> {
        Some(match num {
            49 => {
                // bind: port 0 keeps the process ID
                let addr = match copy_in(a[1], 12) {
                    Ok(v) => v,
                    Err(e) => return Some(e),
                };
                let port = u32::from_le_bytes(addr[4..8].try_into().unwrap());
                if port != 0 {
                    self.port.store(port, Ordering::Relaxed);
                }
                self.groups.store(u32::from_le_bytes(addr[8..12].try_into().unwrap()), Ordering::Relaxed);
                0
            }
            51 => {
                let mut b = [0u8; 12];
                b[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
                b[4..8].copy_from_slice(&self.port.load(Ordering::Relaxed).to_le_bytes());
                b[8..12].copy_from_slice(&self.groups.load(Ordering::Relaxed).to_le_bytes());
                put_addr(a[1], a[2], &b)
            }
            52 => put_addr(a[1], a[2], &Self::kernel_addr()),
            42 => 0, // connect to the kernel
            54 => 0, // setsockopt: buffer sizes, extended ACKs, strict checking
            55 => {
                let v: u32 = match (a[1], a[2]) {
                    (1, 3) => 3,                // SO_TYPE: SOCK_RAW
                    (1, 7) | (1, 8) => 212_992, // SO_SNDBUF / SO_RCVBUF
                    (1, 38) => 0,               // SO_PROTOCOL: NETLINK_ROUTE
                    (1, 39) => AF_NETLINK as u32,
                    _ => 0,
                };
                if copy_out(a[3], &v.to_le_bytes()).is_err() || copy_out(a[4], &4u32.to_le_bytes()).is_err() {
                    EFAULT
                } else {
                    0
                }
            }
            44 => {
                // sendto
                match copy_in(a[1], (a[2] as usize).min(65536)) {
                    Ok(d) => {
                        self.handle(&d);
                        a[2] as i64
                    }
                    Err(e) => e,
                }
            }
            46 => {
                // sendmsg: the iovecs form one datagram
                let msg = match copy_in(a[1], 56) {
                    Ok(m) => m,
                    Err(e) => return Some(e),
                };
                let mut data = Vec::new();
                for (base, len) in match Self::iovecs(&msg) {
                    Ok(v) => v,
                    Err(e) => return Some(e),
                } {
                    match copy_in(base, len.min(65536)) {
                        Ok(d) => data.extend_from_slice(&d),
                        Err(e) => return Some(e),
                    }
                }
                self.handle(&data);
                data.len() as i64
            }
            45 => {
                // recvfrom
                match self.next(a[3] & MSG_PEEK != 0, a[3] & MSG_DONTWAIT != 0) {
                    Ok(d) => {
                        let n = d.len().min(a[2] as usize);
                        if copy_out(a[1], &d[..n]).is_err() {
                            return Some(EFAULT);
                        }
                        let r = put_addr(a[4], a[5], &Self::kernel_addr());
                        if r != 0 {
                            return Some(r);
                        }
                        if a[3] & MSG_TRUNC != 0 { d.len() as i64 } else { n as i64 }
                    }
                    Err(e) => e,
                }
            }
            47 => {
                // recvmsg
                let msg = match copy_in(a[1], 56) {
                    Ok(m) => m,
                    Err(e) => return Some(e),
                };
                let iovs = match Self::iovecs(&msg) {
                    Ok(v) => v,
                    Err(e) => return Some(e),
                };
                let d = match self.next(a[2] & MSG_PEEK != 0, a[2] & MSG_DONTWAIT != 0) {
                    Ok(d) => d,
                    Err(e) => return Some(e),
                };
                let mut done = 0;
                for (base, len) in iovs {
                    let n = len.min(d.len() - done);
                    if n > 0 && copy_out(base, &d[done..done + n]).is_err() {
                        return Some(EFAULT);
                    }
                    done += n;
                }
                let name = u64::from_le_bytes(msg[0..8].try_into().unwrap());
                if name != 0 && u32::from_le_bytes(msg[8..12].try_into().unwrap()) >= 12 {
                    let _ = copy_out(name, &Self::kernel_addr());
                    let _ = copy_out(a[1] + 8, &12u32.to_le_bytes());
                }
                // msg_controllen 0; msg_flags: MSG_TRUNC if the datagram did not fit
                let _ = copy_out(a[1] + 40, &0u64.to_le_bytes());
                let _ = copy_out(a[1] + 48, &(if done < d.len() { MSG_TRUNC as u32 } else { 0 }).to_le_bytes());
                if a[2] & MSG_TRUNC != 0 { d.len() as i64 } else { done as i64 }
            }
            48 => 0,                 // shutdown
            43 | 50 | 288 => EINVAL, // accept / listen
            _ => return None,
        })
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
