//! # Linux ABI Unix Domain Sockets Subsystem (`AF_UNIX` / `SOCK_STREAM`)
//!
//! Provides in-kernel emulation of POSIX / Linux local inter-process communication sockets.
//! Powers the Wayland display server IPC channel (`/run/user/1000/wayland-0`), desktop compositors,
//! and client graphical runtimes (Qt6, KDE Plasma, Wayland clients).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

use crate::fs::pipe::PipeBuffer;

pub const AF_UNIX: u32 = 1;
pub const AF_LOCAL: u32 = 1;
pub const AF_INET: u32 = 2;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_NONBLOCK: u32 = 0x800;   // 2048
pub const SOCK_CLOEXEC: u32 = 0x80000; // 524288

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

use super::types::*;

/// POSIX `sockaddr_un` structure for `AF_UNIX` address representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxSockaddrUn {
    pub sun_family: u16,      // AF_UNIX (1)
    pub sun_path: [u8; 108],  // Null-terminated path (e.g. "/run/user/1000/wayland-0")
}

impl Default for LinuxSockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX as u16,
            sun_path: [0u8; 108],
        }
    }
}

/// Operational state of a local Unix domain socket.
pub enum UnixSocketRole {
    Unbound,
    Bound(String),
    Listening {
        path: String,
        backlog: usize,
        pending: VecDeque<Arc<Mutex<UnixSocket>>>,
    },
    Connected {
        peer_path: String,
        rx: Arc<Mutex<PipeBuffer>>,
        tx: Arc<Mutex<PipeBuffer>>,
        ancillary_rx: Arc<Mutex<VecDeque<crate::fs::FileDescriptor>>>,
        ancillary_tx: Arc<Mutex<VecDeque<crate::fs::FileDescriptor>>>,
    },
    Closed,
}

/// Thread-safe in-kernel representation of a Unix domain stream socket.
pub struct UnixSocket {
    pub domain: u32,
    pub sock_type: u32,
    pub nonblocking: bool,
    pub role: UnixSocketRole,
}

impl UnixSocket {
    /// Creates a new unbound Unix socket.
    pub fn new(domain: u32, sock_type: u32, nonblocking: bool) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            domain,
            sock_type: sock_type & !(SOCK_NONBLOCK | SOCK_CLOEXEC),
            nonblocking,
            role: UnixSocketRole::Unbound,
        }))
    }

    /// Binds this socket to a named filesystem path in the global socket registry.
    pub fn bind(socket_arc: &Arc<Mutex<Self>>, path: &str) -> Result<(), i64> {
        let mut sock = socket_arc.lock();
        match &sock.role {
            UnixSocketRole::Unbound => {
                let mut reg = GLOBAL_UNIX_SOCKETS.lock();
                if reg.contains_key(path) {
                    return Err(-EADDRINUSE);
                }
                sock.role = UnixSocketRole::Bound(String::from(path));
                reg.insert(String::from(path), socket_arc.clone());
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }

    /// Transitions a bound socket into listening state to accept incoming client connections.
    pub fn listen(&mut self, backlog: usize) -> Result<(), i64> {
        match &self.role {
            UnixSocketRole::Bound(path) => {
                let p = path.clone();
                self.role = UnixSocketRole::Listening {
                    path: p,
                    backlog: if backlog == 0 { 16 } else { backlog },
                    pending: VecDeque::new(),
                };
                Ok(())
            }
            UnixSocketRole::Listening { backlog: b, .. } => {
                // Update backlog if already listening
                let _ = b;
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }

    /// Connects this unbound socket to a listening Unix socket registered at `target_path`.
    pub fn connect(&mut self, target_path: &str) -> Result<(), i64> {
        match &self.role {
            UnixSocketRole::Unbound | UnixSocketRole::Bound(_) => {
                let reg = GLOBAL_UNIX_SOCKETS.lock();
                let server_arc = match reg.get(target_path) {
                    Some(s) => s.clone(),
                    None => return Err(-ECONNREFUSED),
                };
                drop(reg);

                let mut server_sock = server_arc.lock();
                match &mut server_sock.role {
                    UnixSocketRole::Listening { backlog, pending, .. } => {
                        if pending.len() >= *backlog {
                            return Err(-EAGAIN);
                        }

                        // Create cross-connected bidirectional ring-buffers
                        // pipe_c2s: Client writes, Server reads
                        // pipe_s2c: Server writes, Client reads
                        let pipe_c2s = PipeBuffer::new();
                        let pipe_s2c = PipeBuffer::new();
                        let anc_c2s = Arc::new(Mutex::new(VecDeque::new()));
                        let anc_s2c = Arc::new(Mutex::new(VecDeque::new()));

                        // Configure Client socket
                        self.role = UnixSocketRole::Connected {
                            peer_path: String::from(target_path),
                            rx: pipe_s2c.clone(),
                            tx: pipe_c2s.clone(),
                            ancillary_rx: anc_s2c.clone(),
                            ancillary_tx: anc_c2s.clone(),
                        };

                        // Configure and queue Server peer socket
                        let server_peer = Arc::new(Mutex::new(UnixSocket {
                            domain: self.domain,
                            sock_type: self.sock_type,
                            nonblocking: false,
                            role: UnixSocketRole::Connected {
                                peer_path: String::new(),
                                rx: pipe_c2s,
                                tx: pipe_s2c,
                                ancillary_rx: anc_c2s,
                                ancillary_tx: anc_s2c,
                            },
                        }));

                        pending.push_back(server_peer);
                        Ok(())
                    }
                    _ => Err(-ECONNREFUSED),
                }
            }
            _ => Err(-EINVAL),
        }
    }

    /// Accepts an incoming connection from the pending queue.
    pub fn accept(&mut self, nonblock: bool) -> Result<Arc<Mutex<UnixSocket>>, i64> {
        match &mut self.role {
            UnixSocketRole::Listening { pending, .. } => {
                if let Some(conn) = pending.pop_front() {
                    return Ok(conn);
                }

                if nonblock || self.nonblocking {
                    return Err(-EAGAIN);
                }

                // Cooperative wait loop for incoming connection
                for _ in 0..100 {
                    crate::task::yield_now();
                    if let Some(conn) = pending.pop_front() {
                        return Ok(conn);
                    }
                }
                Err(-EAGAIN)
            }
            _ => Err(-EINVAL),
        }
    }

    /// Creates an anonymous cross-connected bidirectional socket pair (`socketpair`).
    pub fn pair(sock_type: u32, nonblocking: bool) -> (Arc<Mutex<Self>>, Arc<Mutex<Self>>) {
        let pipe_a2b = PipeBuffer::new();
        let pipe_b2a = PipeBuffer::new();
        let anc_a2b = Arc::new(Mutex::new(VecDeque::new()));
        let anc_b2a = Arc::new(Mutex::new(VecDeque::new()));

        let sock_a = Arc::new(Mutex::new(UnixSocket {
            domain: AF_UNIX,
            sock_type: sock_type & !(SOCK_NONBLOCK | SOCK_CLOEXEC),
            nonblocking,
            role: UnixSocketRole::Connected {
                peer_path: String::from("[socketpair]"),
                rx: pipe_b2a.clone(),
                tx: pipe_a2b.clone(),
                ancillary_rx: anc_b2a.clone(),
                ancillary_tx: anc_a2b.clone(),
            },
        }));

        let sock_b = Arc::new(Mutex::new(UnixSocket {
            domain: AF_UNIX,
            sock_type: sock_type & !(SOCK_NONBLOCK | SOCK_CLOEXEC),
            nonblocking,
            role: UnixSocketRole::Connected {
                peer_path: String::from("[socketpair]"),
                rx: pipe_a2b,
                tx: pipe_b2a,
                ancillary_rx: anc_a2b,
                ancillary_tx: anc_b2a,
            },
        }));

        (sock_a, sock_b)
    }

    /// Pushes an ancillary file descriptor into the connected peer's reception queue.
    pub fn push_ancillary_fd(&mut self, desc: crate::fs::FileDescriptor) -> Result<(), &'static str> {
        match &self.role {
            UnixSocketRole::Connected { ancillary_tx, .. } => {
                let mut tx = ancillary_tx.lock();
                tx.push_back(desc);
                Ok(())
            }
            _ => Err("Socket not connected"),
        }
    }

    /// Pops an incoming ancillary file descriptor transmitted by the peer.
    pub fn pop_ancillary_fd(&mut self) -> Option<crate::fs::FileDescriptor> {
        match &self.role {
            UnixSocketRole::Connected { ancillary_rx, .. } => {
                let mut rx = ancillary_rx.lock();
                rx.pop_front()
            }
            _ => None,
        }
    }

    /// Reads data from the connected peer's transmission buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        match &self.role {
            UnixSocketRole::Connected { rx, .. } => {
                let mut r = rx.lock();
                Ok(r.read(buf))
            }
            UnixSocketRole::Closed => Ok(0),
            _ => Err("Socket not connected"),
        }
    }

    /// Writes data to the connected peer's reception buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        match &self.role {
            UnixSocketRole::Connected { tx, .. } => {
                let mut t = tx.lock();
                t.write(data)
            }
            UnixSocketRole::Closed => Err("Broken pipe (EPIPE)"),
            _ => Err("Socket not connected"),
        }
    }

    /// Shuts down one or both directions of the socket.
    pub fn shutdown(&mut self, how: u32) -> Result<(), i64> {
        match how {
            SHUT_RD | SHUT_WR | SHUT_RDWR => {
                self.role = UnixSocketRole::Closed;
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }

    /// Evaluates socket readiness against Linux epoll/poll event flags.
    pub fn poll_events(&self) -> u32 {
        let mut events = 0;
        match &self.role {
            UnixSocketRole::Connected { rx, tx, .. } => {
                let r = rx.lock();
                if r.available_read() > 0 {
                    events |= 0x0001; // EPOLLIN
                }
                let t = tx.lock();
                if t.available_write() > 0 {
                    events |= 0x0004; // EPOLLOUT
                }
            }
            UnixSocketRole::Listening { pending, .. } => {
                if !pending.is_empty() {
                    events |= 0x0001; // EPOLLIN (incoming connection ready to accept)
                }
            }
            UnixSocketRole::Closed => {
                events |= 0x0010; // EPOLLHUP
            }
            _ => {}
        }
        events
    }
}

/// Global registry mapping filesystem socket paths (e.g. `/run/user/1000/wayland-0`)
/// to their active listening Unix domain sockets.
pub static GLOBAL_UNIX_SOCKETS: Mutex<BTreeMap<String, Arc<Mutex<UnixSocket>>>> =
    Mutex::new(BTreeMap::new());

/// Unregisters a socket path from the global namespace upon closure.
pub fn unregister_socket(path: &str) {
    let mut reg = GLOBAL_UNIX_SOCKETS.lock();
    reg.remove(path);
}

/// Initializes default Wayland display server socket if not yet registered.
pub fn ensure_wayland_socket() -> Arc<Mutex<UnixSocket>> {
    let path = "/run/user/1000/wayland-0";
    let mut reg = GLOBAL_UNIX_SOCKETS.lock();
    if let Some(sock) = reg.get(path) {
        return sock.clone();
    }

    let sock = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    {
        let mut s = sock.lock();
        s.role = UnixSocketRole::Listening {
            path: String::from(path),
            backlog: 32,
            pending: VecDeque::new(),
        };
    }
    reg.insert(String::from(path), sock.clone());
    sock
}
