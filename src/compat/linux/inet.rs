//! # Linux Compatibility: IPv4 Internet Sockets (`AF_INET`)
//!
//! Provides TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`) sockets for Linux processes,
//! backed by the in-kernel TCP/IP transport engine in [`crate::net::stack`].
//!
//! ## Architectural Role & Design Rationale
//! Networking applications (`curl`, `apt`, DNS resolvers, SSH clients) interact with the
//! network through standard BSD/POSIX socket system calls (`socket`, `connect`, `bind`,
//! `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`). Blocking operations
//! register on the underlying connection's [`WaitQueue`](crate::task::wait::WaitQueue) and
//! sleep until the network driver task signals packet arrival or state transitions, waking
//! early with `ERESTARTSYS` if a signal arrives.
//!
//! IPv6 is intentionally rejected at socket creation (`AF_INET6` returns `-EAFNOSUPPORT`),
//! causing dual-stack resolvers (`getaddrinfo`) to immediately fall back to IPv4.
//!
//! ## Key Types & Interfaces
//! - [`InetSocket`]: Per-descriptor `AF_INET` socket state wrapping a TCP or UDP handle in [`crate::net::stack`].
//! - [`dispatch()`]: Intercepts socket system calls targeting `AF_INET` descriptors.
//! - [`read()`] / [`write()`]: Stream and datagram I/O paths when accessed via standard VFS `read`/`write`.
//! - [`pending_bytes()`]: Implements `FIONREAD` byte-available queries.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Indirectly kicks the network interface ([`crate::net::stack::kick`])
//!   to poll VirtIO-Net / NIC rings.
//! - Concurrency: Each [`InetSocket`] is wrapped in `Arc<Mutex<InetSocket>>` inside the file table.

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::FileDescriptor;
use crate::memory::vm::prefault_current;
use crate::net::stack;

/// Address family constant for IPv4 Internet sockets.
const AF_INET: u32 = 2;
/// Address family constant for IPv6 sockets (unsupported; rejected with `EAFNOSUPPORT`).
const AF_INET6: u32 = 10;
/// Socket type constant for sequenced, reliable, two-way byte streams (TCP).
const SOCK_STREAM: u32 = 1;
/// Socket type constant for connectionless datagrams (UDP).
const SOCK_DGRAM: u32 = 2;
/// Socket type flag: enable non-blocking mode (`O_NONBLOCK`) on the new socket descriptor.
const SOCK_NONBLOCK: u32 = 0o4000;
/// Socket type flag: atomically mark the new socket descriptor close-on-exec (`FD_CLOEXEC`).
const SOCK_CLOEXEC: u32 = 0o2000000;

/// Message flag: peek at incoming data without removing it from the receive queue.
const MSG_PEEK: u64 = 0x2;
/// Message flag: perform a single send/receive operation without blocking.
const MSG_DONTWAIT: u64 = 0x40;
/// Message flag returned in `msg_flags` when a UDP datagram was larger than the supplied buffer.
const MSG_TRUNC: u64 = 0x20;

/// Negative errno for non-blocking operation that cannot complete immediately.
const EAGAIN: i64 = -11;
/// Negative errno for invalid userland buffer or address pointer.
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
/// Negative errno for invalid argument or malformed `sockaddr_in`.
const EINVAL: i64 = -22;
/// Negative errno for per-process file descriptor table full.
const EMFILE: i64 = -24;
/// Negative errno for socket operation attempted on a non-socket descriptor.
const ENOTSOCK: i64 = -88;
/// Negative errno for UDP send on an unconnected socket without a destination address.
const EDESTADDRREQ: i64 = -89;
/// Negative errno for unsupported socket type or protocol within `AF_INET`.
const EPROTONOSUPPORT: i64 = -93;
/// Negative errno for unsupported socket operation (e.g., `listen`/`accept` on client-only stack).
const EOPNOTSUPP: i64 = -95;
/// Negative errno for unsupported address family (such as `AF_INET6`).
const EAFNOSUPPORT: i64 = -97;
/// Negative errno for `connect` called on an already-connected TCP socket.
const EISCONN: i64 = -106;
/// Negative errno for I/O or `getpeername` on an unconnected socket.
const ENOTCONN: i64 = -107;
/// Negative errno for non-blocking `connect` while a previous connection attempt is still pending.
const EALREADY: i64 = -114;
/// Negative errno for non-blocking `connect` initiated asynchronously.
const EINPROGRESS: i64 = -115;
/// Negative errno for `bind` to an address that is not ours.
const EADDRNOTAVAIL: i64 = -99;
/// Negative errno for write on a broken TCP connection (`SIGPIPE` is also posted unless `MSG_NOSIGNAL`).
const EPIPE: i64 = -32;

/// Represents an open Linux `AF_INET` (IPv4 TCP or UDP) socket.
///
/// # Concurrency & Thread Safety
/// Guarded by `Arc<Mutex<InetSocket>>` in the file descriptor table. Blocking calls release
/// this mutex before sleeping on the underlying transport wait queue in [`crate::net::stack`].
///
/// # Lifetime & Cleanup
/// When dropped, closes any associated TCP connection or UDP port binding in [`crate::net::stack`].
pub struct InetSocket {
    /// `true` for TCP (`SOCK_STREAM`), `false` for UDP (`SOCK_DGRAM`).
    stream: bool,
    /// Whether `O_NONBLOCK` is enabled on this socket description.
    pub nonblock: bool,
    /// Underlying TCP connection handle in [`crate::net::stack`] once `connect` has been called.
    tcp: Option<u32>,
    /// Underlying UDP endpoint handle in [`crate::net::stack`] (created on `bind`, `connect`, or first send).
    udp: Option<u32>,
    /// Local port number requested via `bind(2)` before the transport endpoint is opened.
    bound_port: u16,
    /// Default remote `(ip, port)` destination for a connected UDP socket.
    peer: Option<([u8; 4], u16)>,
    /// Whether the read half of the socket has been shut down via `shutdown(SHUT_RD / SHUT_RDWR)`.
    shut_rd: bool,
    /// Socket options (`setsockopt`).
    opts: super::sockopt::Options,
    /// Local address given to `bind` (`0.0.0.0`: all of ours).
    bound_ip: [u8; 4],
    /// TCP port reservation made by `bind` (or by `listen` without one).
    bind_id: Option<u32>,
    /// Listener handle once `listen` was called.
    listener: Option<u32>,
    /// Owner (the creator's effective user ID), for `/proc/net`.
    uid: u32,
    /// The UDP endpoint was used to send or connect (bound for good: `bind` gives `EINVAL`).
    udp_used: bool,
}

impl Drop for InetSocket {
    fn drop(&mut self) {
        if let Some(id) = self.listener {
            stack::tcp_unlisten(id);
        }
        if let Some(id) = self.bind_id {
            stack::tcp_unbind(id);
        }
        if let Some(id) = self.tcp {
            stack::tcp_close(id);
        }
        if let Some(id) = self.udp {
            stack::udp_close(id);
        }
    }
}

impl InetSocket {
    /// Returns the transport [`WaitQueue`](crate::task::wait::WaitQueue) that announces readiness
    /// changes for this socket (`None` before an underlying TCP/UDP endpoint exists).
    ///
    /// # Returns
    ///
    /// `Some(Arc<WaitQueue>)` if an active transport endpoint exists, or `None`.
    pub fn wait_queue(&mut self) -> Option<Arc<crate::task::wait::WaitQueue>> {
        if !self.stream && self.udp.is_none() {
            let _ = self.udp_id();
        }
        self.tcp.or(self.listener).or(self.udp).and_then(stack::wait_queue)
    }

    /// Evaluates current `poll` / `select` / `epoll` readiness bitmask (`POLLIN = 0x1`,
    /// `POLLOUT = 0x4`, `POLLERR = 0x8`, `POLLHUP = 0x10`).
    ///
    /// # Returns
    ///
    /// Bitmask of poll readiness flags.
    pub fn poll_events(&self) -> u32 {
        if let Some(id) = self.listener {
            // A listening socket is readable when a connection waits to be accepted
            return stack::tcp_acceptable(id) as u32;
        }
        if let Some(id) = self.tcp {
            let (r, w, hup, err) = stack::tcp_poll(id);
            return (r as u32) | (w as u32) << 2 | (err as u32) << 3 | (hup as u32) << 4;
        }
        if self.stream {
            return 0x4; // unconnected stream socket
        }
        let readable = self.udp.map_or(false, stack::udp_readable);
        0x4 | readable as u32
    }

    /// Lazily allocates or returns the existing UDP endpoint handle in [`crate::net::stack`].
    ///
    /// # Returns
    ///
    /// Allocated or existing UDP endpoint index, or a negative Linux errno on error.
    fn udp_id(&mut self) -> Result<u32, i64> {
        if let Some(id) = self.udp {
            return Ok(id);
        }
        let id = stack::udp_open(self.bound_port)?;
        self.udp = Some(id);
        Ok(id)
    }
}

/// Copies `len` bytes from userland address `ptr` into a kernel [`Vec<u8>`].
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to read from.
/// * `len` - Number of bytes to copy.
///
/// # Returns
///
/// Vector of copied bytes on success, or `-EFAULT` if memory cannot be read.
fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
    if ptr == 0 || !prefault_current(ptr, len as u64, false) {
        return Err(EFAULT);
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Ok(v)
}

/// Copies `data` from the kernel into userland address `ptr`.
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to write into.
/// * `data` - Source bytes to write.
///
/// # Returns
///
/// `Ok(())` on success, or `-EFAULT` if memory cannot be written.
fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
    if ptr == 0 || !prefault_current(ptr, data.len() as u64, true) {
        return Err(EFAULT);
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    Ok(())
}

/// Parses a userland `struct sockaddr_in` at `(ptr, len)`, returning `Ok(None)` for `AF_UNSPEC` (disconnect).
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to `sockaddr_in`.
/// * `len` - Length of structure in bytes.
///
/// # Returns
///
/// `Ok(Some((ip, port)))` if valid, `Ok(None)` for disconnect, or negative errno on error.
fn read_sockaddr(ptr: u64, len: u64) -> Result<Option<([u8; 4], u16)>, i64> {
    if len < 2 {
        return Err(EINVAL);
    }
    let raw = copy_in(ptr, (len as usize).min(16))?;
    let family = u16::from_le_bytes([raw[0], raw[1]]) as u32;
    if family == 0 {
        return Ok(None);
    }
    if super::ns::net_isolated() {
        // A network namespace of its own: no interfaces, nothing reachable
        return Err(-101); // ENETUNREACH
    }
    if family == AF_INET6 {
        return Err(EAFNOSUPPORT);
    }
    if family != AF_INET || raw.len() < 8 {
        return Err(EINVAL);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    Ok(Some(([raw[4], raw[5], raw[6], raw[7]], port)))
}

/// Writes a 16-byte `struct sockaddr_in` and its length into userland (`len_ptr` is in/out).
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to write `sockaddr_in`.
/// * `len_ptr` - User pointer to `socklen_t` length field.
/// * `ip` - IPv4 address bytes.
/// * `port` - Port number in host byte order.
///
/// # Returns
///
/// `Ok(())` on success, or `-EFAULT` on memory error.
fn write_sockaddr(ptr: u64, len_ptr: u64, ip: [u8; 4], port: u16) -> Result<(), i64> {
    if ptr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let cap = u32::from_le_bytes(copy_in(len_ptr, 4)?.try_into().unwrap()) as usize;
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    copy_out(ptr, &sa[..cap.min(16)])?;
    copy_out(len_ptr, &16u32.to_le_bytes())
}

/// Looks up file descriptor `fd` in the current task and returns its [`InetSocket`] if it is an `AF_INET` socket.
///
/// # Arguments
///
/// * `fd` - File descriptor index.
///
/// # Returns
///
/// `Some(Arc<Mutex<InetSocket>>)` if descriptor exists and is an inet socket, or `None`.
fn socket_of(fd: u64) -> Option<Arc<Mutex<InetSocket>>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(FileDescriptor::Inet(s)) => Some(s.clone()),
        _ => None,
    })
}

/// Waits until `ready()` returns `Some(...)` for transport endpoint `id`, honoring
/// non-blocking mode and pending signals.
///
/// # Arguments
///
/// * `id` - Transport endpoint index.
/// * `nonblock` - Non-blocking flag.
/// * `ready` - Closure polling readiness.
///
/// # Returns
///
/// Result value produced by `ready()`, or negative Linux errno on error.
fn wait_for<T>(id: u32, nonblock: bool, timeout: Option<u64>, mut ready: impl FnMut() -> Option<Result<T, i64>>) -> Result<T, i64> {
    // SO_RCVTIMEO / SO_SNDTIMEO: a deadline in timer ticks
    let deadline = timeout.map(|ns| {
        let hz = crate::arch::pit::frequency_hz().max(1);
        crate::arch::pit::ticks() + ((ns as u128 * hz as u128).div_ceil(1_000_000_000) as u64).max(1)
    });
    let mut waits = crate::task::wait::WaitSet::new();
    match stack::wait_queue(id) {
        Some(q) if stack::service_running() => waits.add(crate::task::wait::QueueRef::Shared(q)),
        _ => waits.polled = true,
    }
    loop {
        waits.register();
        stack::kick();
        if let Some(r) = ready() {
            return r;
        }
        if nonblock {
            return Err(EAGAIN);
        }
        if super::proc::signal_pending() {
            // With a timeout, an interrupted call is not restarted (Linux: EINTR)
            return Err(if deadline.is_some() { -4 } else { super::proc::ERESTARTSYS });
        }
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            return Err(EAGAIN);
        }
        waits.wait(deadline);
    }
}

/// Initiates or completes a TCP/UDP `connect(2)` operation on `sock`.
///
/// # Arguments
///
/// * `sock` - Target socket mutex.
/// * `addr` - User virtual pointer to destination `sockaddr`.
/// * `len` - Size of `sockaddr` structure.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
fn connect(sock: &Arc<Mutex<InetSocket>>, addr: u64, len: u64) -> i64 {
    let dest = match read_sockaddr(addr, len) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let (nonblock, timeout) = {
        let mut s = sock.lock();
        if !s.stream {
            let _ = s.udp_id();
            s.udp_used = true;
            s.peer = dest;
            return 0;
        }
        if s.listener.is_some() {
            return EISCONN;
        }
        (s.nonblock, s.opts.snd_timeout())
    };
    let (ip, port) = match dest {
        Some(d) => d,
        None => return EAFNOSUPPORT,
    };
    if super::landlock::check_port(port, super::landlock::CONNECT_TCP).is_err() {
        return EACCES;
    }
    let existing = sock.lock().tcp;
    let id = match existing {
        Some(id) => match stack::tcp_state(id) {
            stack::TcpState::SynSent => {
                if nonblock {
                    return EALREADY;
                }
                id
            }
            stack::TcpState::Closed => return stack::tcp_take_error(id).unwrap_or(EISCONN),
            _ => return EISCONN,
        },
        None => {
            let bound = sock.lock().bound_port;
            match stack::tcp_connect(ip, port, if bound != 0 { Some(bound) } else { None }) {
                Ok(id) => {
                    sock.lock().tcp = Some(id);
                    if nonblock {
                        return EINPROGRESS;
                    }
                    id
                }
                Err(e) => return e,
            }
        }
    };
    let r = wait_for(id, false, timeout, || match stack::tcp_state(id) {
        stack::TcpState::SynSent => None,
        stack::TcpState::Closed => Some(Err(stack::tcp_take_error(id).unwrap_or(stack::ECONNREFUSED))),
        _ => Some(Ok(())),
    });
    match r {
        Ok(()) => 0,
        // An interrupted or timed-out connect keeps going in the background, as on Linux
        Err(e) if e == super::proc::ERESTARTSYS => -4,
        Err(EAGAIN) => EINPROGRESS,
        Err(e) => e,
    }
}

/// Every open `AF_INET` socket, for `/proc/net/tcp` and `/proc/net/udp`.
static SOCKETS: Mutex<Vec<alloc::sync::Weak<Mutex<InetSocket>>>> = Mutex::new(Vec::new());

fn current_euid() -> u32 {
    crate::task::with_current_task_mut(|t| t.euid).unwrap_or(0)
}

/// Wraps a new socket and records it.
fn register(sock: InetSocket) -> Arc<Mutex<InetSocket>> {
    let a = Arc::new(Mutex::new(sock));
    let mut all = SOCKETS.lock();
    all.retain(|w| w.strong_count() > 0);
    all.push(Arc::downgrade(&a));
    a
}

/// What `/proc/net` needs of an open socket: `(inode, uid, bound address, peer)`, by the
/// transport handles it uses.
struct Owner {
    inode: u64,
    uid: u32,
    bound_ip: [u8; 4],
    peer: Option<([u8; 4], u16)>,
}

fn owners() -> alloc::collections::BTreeMap<u32, Owner> {
    let socks: Vec<Arc<Mutex<InetSocket>>> = SOCKETS.lock().iter().filter_map(|w| w.upgrade()).collect();
    let mut map = alloc::collections::BTreeMap::new();
    for a in socks {
        let inode = Arc::as_ptr(&a) as usize as u64 & 0xFFFF_FFFF;
        let s = a.lock();
        for id in [s.tcp, s.udp, s.listener].into_iter().flatten() {
            map.insert(id, Owner { inode, uid: s.uid, bound_ip: s.bound_ip, peer: s.peer });
        }
    }
    map
}

/// An address as `/proc/net` prints it: the 32-bit value in host order, then the port.
fn hex_addr((ip, port): ([u8; 4], u16)) -> alloc::string::String {
    alloc::format!("{:08X}:{:04X}", u32::from_le_bytes(ip), port)
}

/// Linux's TCP state numbers.
fn tcp_state_num(s: stack::TcpState) -> u8 {
    use stack::TcpState::*;
    match s {
        Established => 1,
        SynSent => 2,
        SynReceived => 3,
        FinWait1 => 4,
        FinWait2 => 5,
        TimeWait => 6,
        Closed => 7,
        CloseWait => 8,
        LastAck => 9,
        Closing => 11,
    }
}

/// `/proc/net/tcp` and `/proc/net/udp` (`tcp`), or the IPv6 ones (empty: no IPv6 sockets).
pub fn proc_net(file: &str) -> Option<alloc::string::String> {
    let isolated = super::ns::net_isolated();
    let pad = |mut l: alloc::string::String, width: usize| {
        while l.len() < width {
            l.push(' ');
        }
        l.push('\n');
        l
    };
    match file {
        "tcp" | "tcp6" => {
            let mut out = pad(
                alloc::string::String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"),
                149,
            );
            if file == "tcp6" || isolated {
                return Some(out);
            }
            let own = owners();
            let mut rows: Vec<(([u8; 4], u16), ([u8; 4], u16), u8, usize, usize, u32, u64)> = Vec::new();
            for (id, ip, port, waiting, backlog) in stack::listener_list() {
                let o = own.get(&id);
                rows.push(((ip, port), ([0; 4], 0), 0x0A, backlog, waiting, o.map_or(0, |o| o.uid), o.map_or(0, |o| o.inode)));
            }
            for c in stack::tcp_list() {
                let o = own.get(&c.id);
                rows.push((c.local, c.remote, tcp_state_num(c.state), c.tx, c.rx, o.map_or(0, |o| o.uid), o.map_or(0, |o| o.inode)));
            }
            for (i, (l, rem, st, tx, rx, uid, inode)) in rows.into_iter().enumerate() {
                let line = alloc::format!(
                    "{:4}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 1 0000000000000000 100 0 0 10 0",
                    i,
                    hex_addr(l),
                    hex_addr(rem),
                    st,
                    tx,
                    rx,
                    uid,
                    0,
                    inode
                );
                out.push_str(&pad(line, 149));
            }
            Some(out)
        }
        "udp" | "udp6" => {
            let mut out = pad(
                alloc::string::String::from("   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"),
                127,
            );
            if file == "udp6" || isolated {
                return Some(out);
            }
            let own = owners();
            for (i, (id, port, rx)) in stack::udp_list().into_iter().enumerate() {
                let o = own.get(&id);
                let (bound, peer) = o.map_or(([0; 4], None), |o| (o.bound_ip, o.peer));
                let line = alloc::format!(
                    "{:5}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 2 0000000000000000 0",
                    i,
                    hex_addr((bound, port)),
                    hex_addr(peer.unwrap_or(([0; 4], 0))),
                    if peer.is_some() { 1 } else { 7 },
                    0,
                    rx,
                    o.map_or(0, |o| o.uid),
                    0,
                    o.map_or(0, |o| o.inode)
                );
                out.push_str(&pad(line, 127));
            }
            Some(out)
        }
        _ => None,
    }
}

/// `listen(backlog)`: a bound (or automatically bound) TCP socket starts accepting
/// connections; a second call changes the backlog.
fn listen(sock: &Arc<Mutex<InetSocket>>, backlog: u64) -> i64 {
    let mut s = sock.lock();
    if !s.stream {
        return EOPNOTSUPP;
    }
    if s.tcp.is_some() {
        return EINVAL;
    }
    // Linux caps the backlog at net.core.somaxconn (4096); a negative one means the cap
    let b = backlog as i32;
    let backlog = if !(0..=4096).contains(&b) { 4096 } else { b as usize };
    if let Some(id) = s.listener {
        stack::tcp_set_backlog(id, backlog);
        return 0;
    }
    let bind = match s.bind_id {
        Some(b) => b,
        None => match stack::tcp_bind([0; 4], 0, false, false) {
            Ok((id, port)) => {
                s.bind_id = Some(id);
                s.bound_port = port;
                id
            }
            Err(e) => return e,
        },
    };
    match stack::tcp_listen(bind, backlog) {
        Ok(id) => {
            s.listener = Some(id);
            0
        }
        Err(e) => e,
    }
}

/// `accept(addr, addrlen)` / `accept4(..., flags)`: waits for a connection on a listening
/// socket and returns a descriptor for it. The new socket inherits the listener's options.
fn accept(sock: &Arc<Mutex<InetSocket>>, addr: u64, addrlen: u64, flags: u64) -> i64 {
    if flags & !((SOCK_NONBLOCK | SOCK_CLOEXEC) as u64) != 0 {
        return EINVAL;
    }
    let (lid, nonblock, timeout, opts) = {
        let s = sock.lock();
        match s.listener {
            Some(l) => (l, s.nonblock, s.opts.rcv_timeout(), s.opts.clone()),
            None => return EINVAL,
        }
    };
    let cid = match wait_for(lid, nonblock, timeout, || stack::tcp_accept(lid).map(Ok)) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (lport, rip, rport) = stack::tcp_endpoints(cid).unwrap_or((0, [0; 4], 0));
    let conn = InetSocket {
        stream: true,
        nonblock: flags & SOCK_NONBLOCK as u64 != 0,
        tcp: Some(cid),
        udp: None,
        bound_port: lport,
        peer: None,
        shut_rd: false,
        opts,
        bound_ip: stack::tcp_local_ip(cid).unwrap_or([0; 4]),
        bind_id: None,
        listener: None,
        uid: current_euid(),
        udp_used: false,
    };
    let cloexec = flags & SOCK_CLOEXEC as u64 != 0;
    let conn = register(conn);
    let fd = crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(FileDescriptor::Inet(conn.clone())) {
        Ok(fd) => {
            fds.set_cloexec(fd, cloexec);
            fd as i64
        }
        Err(_) => EMFILE,
    });
    if fd >= 0 && addr != 0 {
        if let Err(e) = write_sockaddr(addr, addrlen, rip, rport) {
            return e;
        }
    }
    fd
}

/// Transmits `data` over a TCP stream or UDP datagram socket.
///
/// # Arguments
///
/// * `sock` - Target socket mutex.
/// * `data` - Payload bytes to send.
/// * `flags` - Transmission flags (`MSG_DONTWAIT`, `MSG_NOSIGNAL`).
/// * `dest` - Destination address/port for unconnected UDP sockets.
///
/// # Returns
///
/// Number of bytes sent on success, or a negative Linux errno on error.
fn send(sock: &Arc<Mutex<InetSocket>>, data: &[u8], flags: u64, dest: Option<([u8; 4], u16)>) -> i64 {
    let (stream, nonblock, tcp, timeout) = {
        let s = sock.lock();
        (s.stream, s.nonblock || flags & MSG_DONTWAIT != 0, s.tcp, s.opts.snd_timeout())
    };
    if stream {
        let id = match tcp {
            Some(id) => id,
            None => return ENOTCONN,
        };
        let mut sent = 0;
        while sent < data.len() {
            let r = wait_for(id, nonblock && sent == 0, timeout, || match stack::tcp_send(id, &data[sent..]) {
                Ok(0) => None,
                Ok(n) => Some(Ok(n)),
                Err(e) => Some(Err(e)),
            });
            match r {
                Ok(n) => sent += n,
                Err(e) if sent > 0 => {
                    let _ = e;
                    break;
                }
                Err(e) => {
                    if e == stack::EPIPE || e == stack::ECONNRESET {
                        if flags & 0x4000 == 0 {
                            // MSG_NOSIGNAL not set
                            let (tid, pid) = super::proc::current_ids();
                            super::proc::post_thread(pid, tid, super::proc::SIGPIPE);
                        }
                        return EPIPE;
                    }
                    return e;
                }
            }
            if nonblock {
                break;
            }
        }
        return sent as i64;
    }
    let (ip, port) = match dest.or(sock.lock().peer) {
        Some(d) => d,
        None => return EDESTADDRREQ,
    };
    let id = {
        let mut s = sock.lock();
        s.udp_used = true; // sending binds the port for good (Linux autobind)
        match s.udp_id() {
            Ok(id) => id,
            Err(e) => return e,
        }
    };
    match stack::udp_send(id, ip, port, data) {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// Receives data into `buf`, returning `(bytes_copied, optional_udp_source, was_truncated)`.
///
/// # Arguments
///
/// * `sock` - Target socket mutex.
/// * `buf` - Destination buffer slice.
/// * `flags` - Reception flags (`MSG_DONTWAIT`, `MSG_PEEK`).
///
/// # Returns
///
/// * `Ok((bytes_copied, source_addr, truncated))` on success.
/// * `Err(errno)` on network or socket error.
fn recv(sock: &Arc<Mutex<InetSocket>>, buf: &mut [u8], flags: u64) -> Result<(usize, Option<([u8; 4], u16)>, bool), i64> {
    let (stream, nonblock, tcp, shut_rd, timeout) = {
        let s = sock.lock();
        (s.stream, s.nonblock || flags & MSG_DONTWAIT != 0, s.tcp, s.shut_rd, s.opts.rcv_timeout())
    };
    let peek = flags & MSG_PEEK != 0;
    if stream {
        let id = tcp.ok_or(ENOTCONN)?;
        if shut_rd {
            return Ok((0, None, false));
        }
        let n = wait_for(id, nonblock, timeout, || match stack::tcp_recv(id, buf, peek) {
            Ok((0, false)) => {
                if stack::tcp_state(id) == stack::TcpState::Closed {
                    Some(Ok(0))
                } else {
                    None
                }
            }
            Ok((n, _)) => Some(Ok(n)),
            Err(e) => Some(Err(e)),
        })?;
        return Ok((n, None, false));
    }
    let id = sock.lock().udp_id()?;
    let (ip, port, data) = wait_for(id, nonblock, timeout, || stack::udp_recv(id, peek).map(Ok))?;
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    Ok((n, Some((ip, port)), data.len() > n))
}

/// Reads an array of `struct iovec` `(iov_base, iov_len)` pairs from user memory.
///
/// # Arguments
///
/// * `iov` - User virtual address of `struct iovec` array.
/// * `count` - Number of iovec elements.
///
/// # Returns
///
/// Vector of `(base, len)` pairs on success, or a negative Linux errno on error.
fn read_iovecs(iov: u64, count: u64) -> Result<Vec<(u64, u64)>, i64> {
    if count > 1024 {
        return Err(EINVAL);
    }
    let raw = copy_in(iov, count as usize * 16)?;
    Ok(raw
        .chunks_exact(16)
        .map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap())))
        .collect())
}

/// Implements `sendmsg(2)` on an [`InetSocket`] by gathering all `msg_iov` buffers.
///
/// # Arguments
///
/// * `sock` - Target socket mutex.
/// * `msg` - User pointer to `struct msghdr`.
/// * `flags` - Message flags.
///
/// # Returns
///
/// Number of bytes sent on success, or a negative Linux errno on error.
fn sendmsg(sock: &Arc<Mutex<InetSocket>>, msg: u64, flags: u64) -> i64 {
    let hdr = match copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let u = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
    let (name, namelen, iov, iovlen) = (u(0), u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64, u(16), u(24));
    let dest = if name != 0 {
        match read_sockaddr(name, namelen) {
            Ok(d) => d,
            Err(e) => return e,
        }
    } else {
        None
    };
    let mut data = Vec::new();
    match read_iovecs(iov, iovlen) {
        Ok(v) => {
            for (base, len) in v {
                match copy_in(base, len as usize) {
                    Ok(d) => data.extend_from_slice(&d),
                    Err(e) => return e,
                }
            }
        }
        Err(e) => return e,
    }
    send(sock, &data, flags, dest)
}

/// Implements `recvmsg(2)` on an [`InetSocket`] by scattering received data across `msg_iov`.
///
/// # Arguments
///
/// * `sock` - Target socket mutex.
/// * `msg` - User pointer to `struct msghdr`.
/// * `flags` - Message flags.
///
/// # Returns
///
/// Number of bytes received on success, or a negative Linux errno on error.
fn recvmsg(sock: &Arc<Mutex<InetSocket>>, msg: u64, flags: u64) -> i64 {
    let hdr = match copy_in(msg, 56) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let u = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
    let (name, iov, iovlen) = (u(0), u(16), u(24));
    let iovs = match read_iovecs(iov, iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let total: u64 = iovs.iter().map(|&(_, l)| l).sum();
    let mut buf = alloc::vec![0u8; total as usize];
    let (n, src, trunc) = match recv(sock, &mut buf, flags) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut off = 0;
    for (base, len) in iovs {
        if off >= n {
            break;
        }
        let k = (len as usize).min(n - off);
        if let Err(e) = copy_out(base, &buf[off..off + k]) {
            return e;
        }
        off += k;
    }
    // msg_namelen, msg_controllen and msg_flags
    if let (Some((ip, port)), true) = (src, name != 0) {
        let _ = write_sockaddr(name, msg + 8, ip, port);
    } else {
        let _ = copy_out(msg + 8, &0u32.to_le_bytes());
    }
    let _ = copy_out(msg + 40, &0u64.to_le_bytes());
    let mflags: i32 = if trunc { MSG_TRUNC as i32 } else { 0 };
    let _ = copy_out(msg + 48, &mflags.to_le_bytes());
    n as i64
}

/// Reads bytes from an `AF_INET` socket through `read(2)` or `readv(2)`.
///
/// # Arguments
/// * `sock` - Shared reference to the [`InetSocket`].
/// * `buf` - Destination buffer slice.
///
/// # Returns
/// Number of bytes read on success, `0` on EOF, or a negative errno on failure.
pub fn read(sock: &Arc<Mutex<InetSocket>>, buf: &mut [u8]) -> i64 {
    match recv(sock, buf, 0) {
        Ok((n, _, _)) => n as i64,
        Err(e) => e,
    }
}

/// Writes bytes to an `AF_INET` socket through `write(2)` or `writev(2)`.
///
/// # Arguments
/// * `sock` - Shared reference to the [`InetSocket`].
/// * `data` - Source byte slice to transmit.
///
/// # Returns
/// Number of bytes sent on success, or a negative errno on failure.
pub fn write(sock: &Arc<Mutex<InetSocket>>, data: &[u8]) -> i64 {
    send(sock, data, 0, None)
}

/// Returns the number of unread bytes currently queued on `sock` (for `ioctl(FIONREAD)`).
///
/// # Arguments
/// * `sock` - Shared reference to the [`InetSocket`].
///
/// # Returns
///
/// Number of bytes available for reading.
pub fn pending_bytes(sock: &Arc<Mutex<InetSocket>>) -> usize {
    stack::kick();
    let s = sock.lock();
    if let Some(id) = s.tcp {
        let mut probe = alloc::vec![0u8; 65536];
        return stack::tcp_recv(id, &mut probe, true).map_or(0, |(n, _)| n);
    }
    s.udp.and_then(|id| stack::udp_recv(id, true)).map_or(0, |(_, _, d)| d.len())
}

/// Dispatches Linux socket system calls that operate on `AF_INET` (or `AF_INET6`) sockets.
///
/// Returns `None` if `num` is not a socket syscall or if the target file descriptor is not
/// an `AF_INET` socket (allowing the `AF_UNIX` dispatcher to handle it).
///
/// # Arguments
/// * `num` - Linux `x86_64` system call number.
/// * `a` - The six 64-bit system call register arguments.
///
/// # Returns
/// * `Some(result)` if the call was handled by the `AF_INET` subsystem.
/// * `None` if the call should be delegated to another subsystem.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    if num == 41 {
        // socket(domain, type, protocol)
        let domain = a[0] as u32;
        if domain == AF_INET6 {
            return Some(EAFNOSUPPORT);
        }
        if domain != AF_INET {
            return None;
        }
        let ty = a[1] as u32 & 0xf;
        let stream = match ty {
            SOCK_STREAM => true,
            SOCK_DGRAM => false,
            _ => return Some(EPROTONOSUPPORT),
        };
        let mut sock = InetSocket {
            stream,
            nonblock: a[1] as u32 & SOCK_NONBLOCK != 0,
            tcp: None,
            udp: None,
            bound_port: 0,
            peer: None,
            shut_rd: false,
            opts: Default::default(),
            bound_ip: [0; 4],
            bind_id: None,
            listener: None,
            uid: current_euid(),
            udp_used: false,
        };
        if !stream {
            let _ = sock.udp_id();
        }
        let cloexec = a[1] as u32 & SOCK_CLOEXEC != 0;
        let sock = register(sock);
        return Some(crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(FileDescriptor::Inet(sock.clone())) {
            Ok(fd) => {
                fds.set_cloexec(fd, cloexec);
                fd as i64
            }
            Err(_) => EMFILE,
        }));
    }
    // Remaining calls take a socket descriptor first
    if !matches!(num, 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 | 54 | 55 | 288 | 299 | 307) {
        return None;
    }
    let sock = socket_of(a[0])?;
    Some(match num {
        42 => connect(&sock, a[1], a[2]),
        49 => {
            // bind: remember the local port (address must be ours or INADDR_ANY)
            match read_sockaddr(a[1], a[2]) {
                Ok(Some((ip, port))) => {
                    let mut s = sock.lock();
                    if s.stream && super::landlock::check_port(port, super::landlock::BIND_TCP).is_err() {
                        return Some(EACCES);
                    }
                    if ip != [0; 4] && !stack::is_local(ip) {
                        return Some(EADDRNOTAVAIL);
                    }
                    // Ports below 1024 need CAP_NET_BIND_SERVICE
                    if port != 0 && port < 1024 && !crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 10) != 0).unwrap_or(false) {
                        return Some(EACCES);
                    }
                    if s.stream {
                        if s.bind_id.is_some() || s.tcp.is_some() || s.listener.is_some() {
                            return Some(EINVAL);
                        }
                        let ra = s.opts.flag(1, 2); // SO_REUSEADDR
                        let rp = s.opts.flag(1, 15); // SO_REUSEPORT
                        match stack::tcp_bind(ip, port, ra, rp) {
                            Ok((id, p)) => {
                                s.bind_id = Some(id);
                                s.bound_port = p;
                                s.bound_ip = ip;
                                0
                            }
                            Err(e) => e,
                        }
                    } else if let (Some(id), false) = (s.udp, s.udp_used) {
                        // Opened implicitly (at creation, or to be polled): move it to the port
                        match stack::udp_rebind(id, port) {
                            Ok(()) => {
                                s.udp_used = true;
                                s.bound_ip = ip;
                                0
                            }
                            Err(e) => e,
                        }
                    } else if s.udp.is_some() {
                        EINVAL
                    } else {
                        match stack::udp_open(port) {
                            Ok(id) => {
                                s.udp = Some(id);
                                s.bound_ip = ip;
                                0
                            }
                            Err(e) => e,
                        }
                    }
                }
                Ok(None) => 0,
                Err(e) => e,
            }
        }
        50 => listen(&sock, a[1]),
        43 | 288 => accept(&sock, a[1], a[2], if num == 288 { a[3] } else { 0 }),
        44 => {
            // sendto(fd, buf, len, flags, dest, addrlen)
            let data = match copy_in(a[1], a[2] as usize) {
                Ok(d) => d,
                Err(e) => return Some(e),
            };
            let dest = if a[4] != 0 {
                match read_sockaddr(a[4], a[5]) {
                    Ok(d) => d,
                    Err(e) => return Some(e),
                }
            } else {
                None
            };
            send(&sock, &data, a[3], dest)
        }
        45 => {
            // recvfrom(fd, buf, len, flags, src, addrlen)
            let mut buf = alloc::vec![0u8; a[2] as usize];
            match recv(&sock, &mut buf, a[3]) {
                Ok((n, src, _)) => {
                    if let Err(e) = copy_out(a[1], &buf[..n]) {
                        return Some(e);
                    }
                    if let Some((ip, port)) = src {
                        let _ = write_sockaddr(a[4], a[5], ip, port);
                    }
                    n as i64
                }
                Err(e) => e,
            }
        }
        46 => sendmsg(&sock, a[1], a[2]),
        47 => recvmsg(&sock, a[1], a[2]),
        307 => {
            // sendmmsg(fd, msgvec, vlen, flags): each mmsghdr is a msghdr + msg_len
            let mut sent = 0;
            for i in 0..a[2].min(1024) {
                let m = a[1] + i * 64;
                let r = sendmsg(&sock, m, a[3]);
                if r < 0 {
                    return Some(if sent > 0 { sent } else { r });
                }
                let _ = copy_out(m + 56, &(r as u32).to_le_bytes());
                sent += 1;
            }
            sent
        }
        299 => {
            // recvmmsg(fd, msgvec, vlen, flags, timeout): receive what is available
            let mut got = 0;
            for i in 0..a[2].min(1024) {
                let m = a[1] + i * 64;
                let flags = if got > 0 { a[3] | MSG_DONTWAIT } else { a[3] };
                let r = recvmsg(&sock, m, flags);
                if r < 0 {
                    return Some(if got > 0 { got } else { r });
                }
                let _ = copy_out(m + 56, &(r as u32).to_le_bytes());
                got += 1;
            }
            got
        }
        48 => {
            // shutdown(fd, how): 0 = read, 1 = write, 2 = both
            let mut s = sock.lock();
            if a[1] != 1 {
                s.shut_rd = true;
            }
            match (a[1], s.tcp) {
                (1 | 2, Some(id)) => {
                    stack::tcp_shutdown_write(id);
                    0
                }
                (_, None) if s.stream => ENOTCONN,
                _ => 0,
            }
        }
        51 | 52 => {
            let s = sock.lock();
            let me = crate::net::GLOBAL_INTERFACE.lock().ip();
            let (ip, port) = if num == 51 {
                match (s.tcp.and_then(stack::tcp_endpoints), s.udp) {
                    (Some((lp, _, _)), _) => (s.tcp.and_then(stack::tcp_local_ip).unwrap_or(me), lp),
                    (None, Some(id)) => (if s.bound_ip != [0; 4] { s.bound_ip } else { me }, stack::udp_port(id)),
                    _ => (s.bound_ip, s.bound_port),
                }
            } else {
                match (s.tcp.and_then(stack::tcp_endpoints), s.peer) {
                    (Some((_, rip, rp)), _) => (rip, rp),
                    (None, Some(p)) => p,
                    _ => return Some(ENOTCONN),
                }
            };
            drop(s);
            match write_sockaddr(a[1], a[2], ip, port) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        54 => {
            // setsockopt(fd, level, optname, optval, optlen)
            if (a[4] as i32) < 0 {
                return Some(EINVAL);
            }
            let val = match copy_in(a[3], (a[4] as usize).min(4096)) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let mut s = sock.lock();
            let stream = s.stream;
            s.opts.set(a[1] as u32, a[2] as u32, &val, stream)
        }
        55 => {
            // getsockopt(fd, level, optname, optval, optlen): at most *optlen bytes
            let len = match copy_in(a[4], 4) {
                Ok(b) => i32::from_le_bytes(b[..4].try_into().unwrap()),
                Err(e) => return Some(e),
            };
            if len < 0 {
                return Some(EINVAL);
            }
            let v = {
                let s = sock.lock();
                let state = s.tcp.map(stack::tcp_state);
                let info = super::sockopt::SockInfo {
                    listening: s.listener.is_some(),
                    stream: s.stream,
                    connected: matches!(state, Some(st) if st != stack::TcpState::SynSent && st != stack::TcpState::Closed) || s.peer.is_some(),
                    error: if a[1] == 1 && a[2] == 4 { s.tcp.and_then(stack::tcp_take_error).unwrap_or(0) } else { 0 },
                    tcp_state: match state {
                        Some(stack::TcpState::Established) => 1,
                        Some(stack::TcpState::SynSent) => 2,
                        Some(stack::TcpState::SynReceived) => 3,
                        Some(stack::TcpState::FinWait1) => 4,
                        Some(stack::TcpState::FinWait2) => 5,
                        Some(stack::TcpState::TimeWait) => 6,
                        Some(stack::TcpState::Closed) | None => 7,
                        Some(stack::TcpState::CloseWait) => 8,
                        Some(stack::TcpState::LastAck) => 9,
                        Some(stack::TcpState::Closing) => 11,
                    },
                };
                s.opts.get(a[1] as u32, a[2] as u32, &info)
            };
            match v {
                Ok(v) => {
                    let n = v.len().min(len as usize);
                    match copy_out(a[3], &v[..n]).and_then(|_| copy_out(a[4], &(n as u32).to_le_bytes())) {
                        Ok(()) => 0,
                        Err(e) => e,
                    }
                }
                Err(e) => e,
            }
        }
        _ => ENOTSOCK,
    })
}
