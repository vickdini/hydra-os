//! # Linux Compatibility: Unix Domain Sockets Subsystem (`AF_UNIX` / `SOCK_STREAM`)
//!
//! Provides in-kernel emulation of POSIX / Linux local inter-process communication sockets.
//! Powers the Wayland display server IPC channel (`/run/user/1000/wayland-0`), desktop compositors,
//! and client graphical runtimes (Qt6, KDE Plasma, Wayland clients).
//!
//! ## Architectural Role & Design Rationale
//! Graphical desktop protocols such as Wayland rely on bidirectional stream sockets (`AF_UNIX`,
//! `SOCK_STREAM`) paired with `SCM_RIGHTS` ancillary file descriptor passing to share `memfd`
//! pixel buffers between client applications and the compositor without copying pixel data.
//! This module implements an in-memory socket state machine backed by cross-connected
//! [`PipeBuffer`] rings and ancillary descriptor queues.
//!
//! ## Key Types & Interfaces
//! - [`LinuxSockaddrUn`]: C-ABI compatible `sockaddr_un` structure for local filesystem socket paths.
//! - [`UnixSocketRole`]: Lifecycle state of a Unix domain socket (`Unbound`, `Bound`, `Listening`, `Connected`, `Closed`).
//! - [`UnixSocket`]: Thread-safe local socket endpoint supporting `bind`, `listen`, `connect`, `accept`, `pair`, and `SCM_RIGHTS`.
//! - [`GLOBAL_UNIX_SOCKETS`]: Global registry mapping bound socket paths to their listening socket instances.
//!
//! ## Hardware & Dependency Context
//! - **Architecture**: Architecture-independent kernel subsystem (x86_64 Linux ABI constants).
//! - **Dependencies**: Relies on [`crate::fs::pipe::PipeBuffer`] for byte stream buffering,
//!   [`crate::fs::FileDescriptor`] for ancillary `SCM_RIGHTS` passing, and [`crate::task::yield_now`]
//!   for cooperative blocking during `accept`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

use crate::fs::pipe::PipeBuffer;

/// Address family constant for Unix domain local sockets (`AF_UNIX`).
pub const AF_UNIX: u32 = 1;
/// POSIX alias for [`AF_UNIX`] local IPC sockets (`AF_LOCAL`).
pub const AF_LOCAL: u32 = 1;
/// Address family constant for IPv4 network sockets (`AF_INET`).
pub const AF_INET: u32 = 2;

/// Socket type constant for sequenced, reliable, two-way connection-based byte streams (`SOCK_STREAM`).
pub const SOCK_STREAM: u32 = 1;
/// Socket type constant for connectionless, unreliable datagrams (`SOCK_DGRAM`).
pub const SOCK_DGRAM: u32 = 2;
/// Socket type constant for raw network protocol access (`SOCK_RAW`).
pub const SOCK_RAW: u32 = 3;
/// Socket creation flag to enable non-blocking I/O (`SOCK_NONBLOCK`).
pub const SOCK_NONBLOCK: u32 = 0x800;   // 2048
/// Socket creation flag to set close-on-exec (`SOCK_CLOEXEC`).
pub const SOCK_CLOEXEC: u32 = 0x80000; // 524288

/// `shutdown(2)` mode: disallow further receptions (`SHUT_RD`).
pub const SHUT_RD: u32 = 0;
/// `shutdown(2)` mode: disallow further transmissions (`SHUT_WR`).
pub const SHUT_WR: u32 = 1;
/// `shutdown(2)` mode: disallow further receptions and transmissions (`SHUT_RDWR`).
pub const SHUT_RDWR: u32 = 2;

use super::types::*;

/// POSIX `sockaddr_un` structure for `AF_UNIX` address representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxSockaddrUn {
    /// Address family (`AF_UNIX` = `1`).
    pub sun_family: u16,      // AF_UNIX (1)
    /// Null-terminated filesystem path or abstract socket name (e.g., `"/run/user/1000/wayland-0"`).
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
    /// Newly created socket not yet bound or connected.
    Unbound,
    /// Bound to a named filesystem path in [`GLOBAL_UNIX_SOCKETS`].
    Bound(String),
    /// Actively listening for incoming client connections at a bound path.
    Listening {
        /// Bound filesystem path of the listening socket.
        path: String,
        /// Maximum number of unaccepted connections allowed in `pending`.
        backlog: usize,
        /// Queue of server-side connected peer sockets awaiting `accept`.
        pending: VecDeque<Arc<Mutex<UnixSocket>>>,
    },
    /// Connected to a peer socket with bidirectional byte and descriptor channels.
    Connected {
        /// Path of the peer socket (or `"[socketpair]"` for anonymous pairs).
        peer_path: String,
        /// Receive ring buffer (written by the peer's `tx`).
        rx: Arc<Mutex<PipeBuffer>>,
        /// Transmit ring buffer (read by the peer's `rx`).
        tx: Arc<Mutex<PipeBuffer>>,
        /// Queue of incoming ancillary file descriptors sent by the peer via `SCM_RIGHTS`.
        ancillary_rx: Arc<Mutex<VecDeque<crate::fs::FileDescriptor>>>,
        /// Queue of outgoing ancillary file descriptors readable by the peer via `SCM_RIGHTS`.
        ancillary_tx: Arc<Mutex<VecDeque<crate::fs::FileDescriptor>>>,
    },
    /// Shut down or closed; further reads return EOF and writes return `EPIPE`.
    Closed,
}

/// Thread-safe in-kernel representation of a Unix domain stream socket.
///
/// Wrapped in `Arc<Mutex<UnixSocket>>` when stored in file descriptor tables or [`GLOBAL_UNIX_SOCKETS`].
pub struct UnixSocket {
    /// Address family domain (e.g., [`AF_UNIX`]).
    pub domain: u32,
    /// Socket type with creation flags masked off (e.g., [`SOCK_STREAM`]).
    pub sock_type: u32,
    /// Whether operations on this socket should return `-EAGAIN` instead of blocking.
    pub nonblocking: bool,
    /// Current lifecycle state and associated buffers of the socket.
    pub role: UnixSocketRole,
}

impl UnixSocket {
    /// Creates a new unbound Unix socket wrapped in an `Arc<Mutex<Self>>`.
    ///
    /// # Arguments
    /// - `domain`: Address family (typically [`AF_UNIX`]).
    /// - `sock_type`: Socket type bitmask (e.g., [`SOCK_STREAM`], optionally ORed with [`SOCK_NONBLOCK`] or [`SOCK_CLOEXEC`]).
    /// - `nonblocking`: Initial non-blocking I/O flag.
    ///
    /// # Returns
    /// Shared reference to the newly allocated [`UnixSocket`].
    pub fn new(domain: u32, sock_type: u32, nonblocking: bool) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            domain,
            sock_type: sock_type & !(SOCK_NONBLOCK | SOCK_CLOEXEC),
            nonblocking,
            role: UnixSocketRole::Unbound,
        }))
    }

    /// Binds this socket to a named filesystem path in the global socket registry.
    ///
    /// # Arguments
    /// - `socket_arc`: Shared handle to the unbound socket being bound.
    /// - `path`: Filesystem path string to register in [`GLOBAL_UNIX_SOCKETS`].
    ///
    /// # Errors
    /// - `-EADDRINUSE`: Another socket is already registered at `path`.
    /// - `-EINVAL`: The socket is not in the [`UnixSocketRole::Unbound`] state.
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
    ///
    /// # Arguments
    /// - `backlog`: Maximum pending connection queue length (defaults to `16` if `0`).
    ///
    /// # Errors
    /// - `-EINVAL`: The socket is neither [`UnixSocketRole::Bound`] nor already [`UnixSocketRole::Listening`].
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

    /// Connects this unbound or bound socket to a listening Unix socket registered at `target_path`.
    ///
    /// Allocates cross-connected bidirectional [`PipeBuffer`] instances and `SCM_RIGHTS` descriptor
    /// queues, transitioning `self` to [`UnixSocketRole::Connected`] and queuing the server peer
    /// into the listener's `pending` queue.
    ///
    /// # Arguments
    /// - `target_path`: Filesystem path of the target listening socket.
    ///
    /// # Errors
    /// - `-ECONNREFUSED`: No socket is registered at `target_path`, or the target is not listening.
    /// - `-EAGAIN`: The target listener's pending connection backlog is full.
    /// - `-EINVAL`: This socket is already connected, listening, or closed.
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

    /// Accepts an incoming connection from the listening socket's pending queue.
    ///
    /// # Arguments
    /// - `nonblock`: If `true` (or if `self.nonblocking` is set), returns `-EAGAIN` immediately when no connection is queued.
    ///
    /// # Returns
    /// The newly accepted server-side connected [`UnixSocket`].
    ///
    /// # Errors
    /// - `-EAGAIN`: No connection was available before the cooperative poll limit expired.
    /// - `-EINVAL`: This socket is not in the [`UnixSocketRole::Listening`] state.
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

    /// Creates an anonymous cross-connected bidirectional socket pair (`socketpair(2)`).
    ///
    /// # Arguments
    /// - `sock_type`: Socket type bitmask (e.g., [`SOCK_STREAM`]).
    /// - `nonblocking`: Whether both sockets should be created in non-blocking mode.
    ///
    /// # Returns
    /// A tuple `(sock_a, sock_b)` of cross-connected [`UnixSocket`] handles.
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

    /// Pushes an ancillary file descriptor (`SCM_RIGHTS`) into the connected peer's reception queue.
    ///
    /// # Arguments
    /// - `desc`: Cloned [`crate::fs::FileDescriptor`] to transfer to the peer.
    ///
    /// # Errors
    /// Returns `Err("Socket not connected")` if this socket is not in the [`UnixSocketRole::Connected`] state.
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

    /// Pops the next incoming ancillary file descriptor (`SCM_RIGHTS`) transmitted by the peer.
    ///
    /// # Returns
    /// `Some(FileDescriptor)` if a descriptor is queued, or `None` if the queue is empty or the socket is not connected.
    pub fn pop_ancillary_fd(&mut self) -> Option<crate::fs::FileDescriptor> {
        match &self.role {
            UnixSocketRole::Connected { ancillary_rx, .. } => {
                let mut rx = ancillary_rx.lock();
                rx.pop_front()
            }
            _ => None,
        }
    }

    /// Reads available bytes from the connected peer's transmission buffer into `buf`.
    ///
    /// # Arguments
    /// - `buf`: Destination byte slice.
    ///
    /// # Returns
    /// The number of bytes read (`0` on EOF/closed or when no bytes are currently buffered).
    ///
    /// # Errors
    /// Returns `Err("Socket not connected")` if the socket is neither connected nor closed.
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

    /// Writes `data` into the connected peer's reception buffer.
    ///
    /// # Arguments
    /// - `data`: Source byte slice to transmit.
    ///
    /// # Returns
    /// The number of bytes written to the underlying [`PipeBuffer`].
    ///
    /// # Errors
    /// - `Err("Broken pipe (EPIPE)")`: The socket is closed.
    /// - `Err("Socket not connected")`: The socket is not in the [`UnixSocketRole::Connected`] state.
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

    /// Shuts down one or both directions of the socket connection.
    ///
    /// # Arguments
    /// - `how`: One of [`SHUT_RD`], [`SHUT_WR`], or [`SHUT_RDWR`].
    ///
    /// # Errors
    /// - `-EINVAL`: `how` is not a valid shutdown mode.
    pub fn shutdown(&mut self, how: u32) -> Result<(), i64> {
        match how {
            SHUT_RD | SHUT_WR | SHUT_RDWR => {
                self.role = UnixSocketRole::Closed;
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }

    /// Evaluates current socket readiness as a bitmask of Linux `epoll` / `poll` event flags.
    ///
    /// # Returns
    /// Bitmask combining `EPOLLIN` (`0x0001`), `EPOLLOUT` (`0x0004`), and `EPOLLHUP` (`0x0010`).
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
///
/// # Arguments
/// - `path`: Bound filesystem path to remove from [`GLOBAL_UNIX_SOCKETS`].
pub fn unregister_socket(path: &str) {
    let mut reg = GLOBAL_UNIX_SOCKETS.lock();
    reg.remove(path);
}

/// Initializes and returns the default Wayland display server listening socket
/// (`/run/user/1000/wayland-0`) if not yet registered.
///
/// # Returns
/// Shared handle to the listening [`UnixSocket`] for `/run/user/1000/wayland-0`.
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
