//! # Filesystem Subsystem: Per-Process File Descriptor Table & Polymorphic Handles
//!
//! Manages per-process file descriptor tables ([`FdTable`]), shared open file descriptions
//! ([`OpenFile`]), and polymorphic I/O dispatch across all kernel resource types (`FileDescriptor`).
//!
//! ## Architectural Role & Design Rationale
//! In POSIX and Linux, almost every kernel resource—regular ZFS files, console streams,
//! anonymous pipes, Unix/Internet sockets, pseudo-terminals (`pty`), `epoll` instances,
//! `eventfd`, `timerfd`, `signalfd`, `inotify`, and `pidfd`—is referenced by a small
//! non-negative integer index (`0..MAX_FDS`). [`FdTable`] acts as a process's keycard holder,
//! mapping integer descriptors to reference-counted `FileDescriptor` variants and tracking
//! per-descriptor `FD_CLOEXEC` flags alongside the process working directory (`cwd`) and `chroot`.
//!
//! ## Key Types & Interfaces
//! - `FileDescriptor`: Tagged union representing every openable kernel I/O object.
//! - [`OpenFile`]: Shared file description (`ino`, `offset`, `flags`, `path`) across `dup`/`fork`.
//! - [`FdTable`] & [`SharedFdTable`]: Per-process descriptor table and thread-shared `Arc<Mutex<FdTable>>`.
//! - [`MAX_FDS`]: Per-process file descriptor limit (`1024`, matching Linux `RLIMIT_NOFILE`).
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reads/writes UEFI console keys/text on `ConsoleIn`/`ConsoleOut` and ZFS blocks on `Vnode`/`File`.
//! - Concurrency: [`SharedFdTable`] and [`OpenFile`] are synchronized via [`spin::Mutex`].

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::pipe::PipeBuffer;
use crate::fs::ZfsClient;

/// Highest number of file descriptors a process may hold (`1024`, matching Linux default `RLIMIT_NOFILE`).
pub const MAX_FDS: usize = 1024;

/// Bitmask extracting the read/write access mode from `open(2)` flags (`0o3`).
pub const O_ACCMODE: u32 = 0o3;
/// `open(2)` access mode: open for reading only (`0o0`).
pub const O_RDONLY: u32 = 0o0;
/// `open(2)` access mode: open for writing only (`0o1`).
pub const O_WRONLY: u32 = 0o1;
/// `open(2)` access mode: open for both reading and writing (`0o2`).
pub const O_RDWR: u32 = 0o2;
/// `open(2)` status flag: reposition the file offset to the end of the file prior to each write (`0o2000`).
pub const O_APPEND: u32 = 0o2000;

/// Shared open file description for a ZFS inode (`struct file` in Linux VFS).
///
/// # Concurrency & Thread Safety
/// Wrapped in `Arc<Mutex<OpenFile>>` inside [`FileDescriptor::Vnode`]. Duplicated descriptors
/// (`dup`, `dup2`, `fork`) share the same [`OpenFile`] instance so that offset updates and
/// status flag changes (`O_APPEND`, `O_NONBLOCK`) are immediately visible across all aliases.
///
/// # Lifetime & Cleanup
/// Increments the ZFS server's open reference count on creation ([`ZfsClient::open_ref`])
/// so unlinked files remain allocated while open. When the last `Arc` drops, [`Drop::drop`]
/// emits `IN_CLOSE_WRITE` (if writable) and releases the inode reference ([`ZfsClient::release`]).
pub struct OpenFile {
    /// Target ZFS object / inode number.
    pub ino: u64,
    /// Current byte read/write cursor, or the `getdents64` directory cookie for open directories.
    pub offset: u64,
    /// Active `open(2)` status flags (access mode, `O_APPEND`, `O_NONBLOCK`, etc.).
    pub flags: u32,
    /// Normalized absolute path recorded at open time (used for `/proc/self/fd` and diagnostics).
    pub path: String,
}

impl OpenFile {
    /// Creates a new shared [`OpenFile`] description and registers an open reference with ZFS.
    ///
    /// # Arguments
    ///
    /// * `ino` - ZFS inode number of the opened object.
    /// * `flags` - `open(2)` access and status flags.
    /// * `path` - Absolute path string through which the file was opened.
    ///
    /// # Returns
    ///
    /// A reference-counted `Arc<Mutex<OpenFile>>` initialized at byte offset `0`.
    pub fn new(ino: u64, flags: u32, path: String) -> Arc<Mutex<Self>> {
        ZfsClient::open_ref(ino);
        Arc::new(Mutex::new(Self { ino, offset: 0, flags, path }))
    }

    /// Checks whether this open file description permits read operations.
    ///
    /// # Returns
    ///
    /// `true` if the access mode is [`O_RDONLY`] or [`O_RDWR`].
    pub fn readable(&self) -> bool {
        self.flags & O_ACCMODE != O_WRONLY
    }

    /// Checks whether this open file description permits write operations.
    ///
    /// # Returns
    ///
    /// `true` if the access mode is [`O_WRONLY`] or [`O_RDWR`].
    pub fn writable(&self) -> bool {
        self.flags & O_ACCMODE != O_RDONLY
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if self.writable() {
            ZfsClient::notify_close_write(self.ino);
        }
        ZfsClient::release(self.ino);
    }
}

/// Polymorphic kernel handle representing an open file descriptor slot in an [`FdTable`].
///
/// # Concurrency & Thread Safety
/// Cloning a `FileDescriptor` clones its underlying `Arc` handle, sharing the open file
/// description across duplicated descriptors or forked child processes.
#[derive(Clone)]
pub enum FileDescriptor {
    /// Standard console keyboard input stream (default `fd 0` / `stdin`).
    ConsoleIn,
    /// Standard console text output stream (default `fd 1` / `stdout`).
    ConsoleOut,
    /// Standard console error output stream (default `fd 2` / `stderr`).
    ConsoleErr,
    /// Read end of an anonymous unidirectional [`PipeBuffer`].
    PipeRead(Arc<Mutex<PipeBuffer>>),
    /// Write end of an anonymous unidirectional [`PipeBuffer`].
    PipeWrite(Arc<Mutex<PipeBuffer>>),
    /// Legacy Hydra-native connected/listening Unix domain socket.
    Socket(Arc<Mutex<crate::compat::linux::socket::UnixSocket>>),
    /// Linux `epoll` readiness multiplexing instance (`epoll_create1`).
    Epoll(Arc<Mutex<crate::compat::linux::epoll::EpollInstance>>),
    /// Linux event notification counter (`eventfd2`).
    EventFd(Arc<Mutex<crate::compat::linux::eventfd::EventFd>>),
    /// Anonymous RAM-backed file created via `memfd_create`.
    MemFd(Arc<Mutex<crate::compat::linux::memfd::MemFd>>),
    /// Open ZFS inode managed through the Linux VFS layer (`openat`).
    Vnode(Arc<Mutex<OpenFile>>),
    /// Internet (`AF_INET` TCP/UDP) socket managed by the network stack.
    Inet(Arc<Mutex<crate::compat::linux::inet::InetSocket>>),
    /// Master (`/dev/ptmx`) or slave (`/dev/pts/N`) end of a pseudo-terminal pair.
    Pty(Arc<crate::compat::linux::pty::PtyFile>),
    /// Signal delivery file descriptor (`signalfd4`).
    SignalFd(Arc<crate::compat::linux::signalfd::SignalFd>),
    /// Linux `AF_UNIX` stream/datagram socket supporting SCM_RIGHTS ancillary data.
    Unix(Arc<crate::compat::linux::unix::UnixSocket>),
    /// POSIX interval timer exposed as a readable file descriptor (`timerfd_create`).
    TimerFd(Arc<crate::compat::linux::timerfd::TimerFd>),
    /// Filesystem event watch descriptor (`inotify_init1`).
    Inotify(Arc<crate::compat::linux::inotify::Inotify>),
    /// Process reference file descriptor (`pidfd_open` / `CLONE_PIDFD`).
    PidFd(Arc<crate::compat::linux::pidfd::PidFd>),
    /// Path-addressed file handle used for synthetic pseudo-files (`/dev`, `/proc`) and native opens.
    File {
        /// Normalized absolute path of the target file.
        path: String,
        /// Current sequential read/write byte cursor.
        cursor: usize,
        /// Whether read operations are permitted on this descriptor.
        readable: bool,
        /// Whether write operations are permitted on this descriptor.
        writable: bool,
        /// Whether writes always append to the current end of the file.
        append: bool,
    },
}

/// Reads bytes from a synthetic pseudo-file or ZFS path at `offset` into `buf`.
fn read_path_at(path: &str, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
    if let Some(pseudo) = crate::compat::linux::fs::match_pseudo_path(path) {
        return Ok(pseudo.read(offset, buf));
    }
    let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| "File not found")?;
    ZfsClient::read_at(ino, offset as u64, buf).map_err(|_| "ZFS read error")
}

/// Writes `data` to a synthetic pseudo-file or ZFS path at `offset` (or EOF when `offset` is `None`).
fn write_path_at(path: &str, offset: Option<usize>, data: &[u8]) -> Result<(usize, usize), &'static str> {
    if let Some(pseudo) = crate::compat::linux::fs::match_pseudo_path(path) {
        return Ok((pseudo.write(data), offset.unwrap_or(0)));
    }
    let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| "File not found")?;
    let offset = match offset {
        Some(o) => o,
        None => ZfsClient::getattr(ino).map_err(|_| "ZFS stat error")?.size as usize,
    };
    let n = ZfsClient::write_at(ino, offset as u64, data).map_err(|_| "ZFS write error")?;
    Ok((n, offset + n))
}

impl FileDescriptor {
    /// Reads up to `buf.len()` bytes from the descriptor and advances its stream cursor if applicable.
    ///
    /// # Arguments
    ///
    /// * `buf` - Destination buffer for read bytes.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes read (`0` on EOF or when `buf` is empty).
    ///
    /// # Errors
    ///
    /// Returns a static error description if the descriptor is write-only, does not support
    /// direct `read` (e.g., `Epoll`, `PidFd`), or encounters a backing ZFS I/O error.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }

        match self {
            FileDescriptor::ConsoleIn => {
                let mut read_bytes = 0;
                while read_bytes < buf.len() {
                    if let Some(key) = crate::console::read_key() {
                        match key {
                            uefi::proto::console::text::Key::Printable(ch) => {
                                let c = char::from(ch);
                                if (c as u32) <= 127 {
                                    buf[read_bytes] = c as u8;
                                    read_bytes += 1;
                                    // If newline, stop line-buffered read
                                    if c == '\n' || c == '\r' {
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        break;
                    }
                }
                Ok(read_bytes)
            }
            FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => {
                Err("Cannot read from write-only console stream")
            }
            FileDescriptor::PipeRead(pipe) => {
                let mut p = pipe.lock();
                let bytes = p.read(buf);
                Ok(bytes)
            }
            FileDescriptor::PipeWrite(_) => {
                Err("Cannot read from write end of pipe")
            }
            FileDescriptor::Socket(sock) => {
                let mut s = sock.lock();
                s.read(buf)
            }
            FileDescriptor::EventFd(efd) => {
                let mut e = efd.lock();
                e.read(buf)
            }
            FileDescriptor::Epoll(_) => {
                Err("Cannot read from epoll file descriptor")
            }
            FileDescriptor::MemFd(memfd) => {
                let mut m = memfd.lock();
                m.read(buf)
            }
            FileDescriptor::Inet(_) => Err("Internet sockets are read through the Linux socket layer"),
            FileDescriptor::Pty(_) => Err("Pseudo-terminals are read through the Linux terminal layer"),
            FileDescriptor::SignalFd(_) => Err("signalfd is read through the Linux layer"),
            FileDescriptor::Unix(_) => Err("Unix sockets are read through the Linux socket layer"),
            FileDescriptor::TimerFd(_) | FileDescriptor::Inotify(_) => Err("read through the Linux layer"),
            FileDescriptor::PidFd(_) => Err("pidfds are not readable"),
            FileDescriptor::Vnode(file) => {
                let mut f = file.lock();
                if !f.readable() {
                    return Err("File not opened for reading");
                }
                let n = ZfsClient::read_at(f.ino, f.offset, buf).map_err(|_| "ZFS read error")?;
                f.offset += n as u64;
                Ok(n)
            }
            FileDescriptor::File { path, cursor, readable, .. } => {
                if !*readable {
                    return Err("File not opened for reading");
                }
                let n = read_path_at(path, *cursor, buf)?;
                *cursor += n;
                Ok(n)
            }
        }
    }

    /// Reads up to `buf.len()` bytes at an explicit byte `offset` without modifying the file cursor (`pread64`).
    ///
    /// # Arguments
    ///
    /// * `buf` - Destination buffer to populate.
    /// * `offset` - Absolute byte offset from the start of the file.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes read.
    ///
    /// # Errors
    ///
    /// * `Err("Descriptor is not seekable")` - Descriptor is a pipe, socket, console, or special fd.
    /// * `Err("ZFS read error")` / `Err("File not found")` - Underlying storage read failed.
    pub fn pread(&mut self, buf: &mut [u8], offset: usize) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::MemFd(memfd) => Ok(memfd.lock().read_at(offset, buf)),
            FileDescriptor::Vnode(file) => {
                let ino = file.lock().ino;
                ZfsClient::read_at(ino, offset as u64, buf).map_err(|_| "ZFS read error")
            }
            FileDescriptor::File { path, .. } => read_path_at(path, offset, buf),
            _ => Err("Descriptor is not seekable"),
        }
    }

    /// Writes `data` at an explicit byte `offset` without modifying the file cursor (`pwrite64`).
    ///
    /// # Arguments
    ///
    /// * `data` - Source byte slice to write.
    /// * `offset` - Absolute byte offset from the start of the file.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written.
    ///
    /// # Errors
    ///
    /// * `Err("Descriptor is not seekable")` - Descriptor is not a seekable regular/memory file.
    /// * `Err("ZFS write error")` / `Err("File not found")` - Underlying storage write failed.
    pub fn pwrite(&mut self, data: &[u8], offset: usize) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::MemFd(memfd) => Ok(memfd.lock().write_at(offset, data)),
            FileDescriptor::Vnode(file) => {
                let ino = file.lock().ino;
                ZfsClient::write_at(ino, offset as u64, data).map_err(|_| "ZFS write error")
            }
            FileDescriptor::File { path, .. } => write_path_at(path, Some(offset), data).map(|(n, _)| n),
            _ => Err("Descriptor is not seekable"),
        }
    }

    /// Writes `data` to the file descriptor and advances its stream cursor if applicable.
    ///
    /// # Arguments
    ///
    /// * `data` - Payload bytes to write.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the descriptor is read-only, broken (`EPIPE`), or un-writable.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if data.is_empty() {
            return Ok(0);
        }

        match self {
            FileDescriptor::ConsoleIn => {
                Err("Cannot write to read-only console input")
            }
            FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => {
                if let Ok(s) = core::str::from_utf8(data) {
                    crate::console::print_raw(s);
                } else {
                    for &b in data {
                        let ch = [b];
                        if let Ok(s) = core::str::from_utf8(&ch) {
                            crate::console::print_raw(s);
                        }
                    }
                }
                Ok(data.len())
            }
            FileDescriptor::PipeRead(_) => {
                Err("Cannot write to read end of pipe")
            }
            FileDescriptor::PipeWrite(pipe) => {
                let mut p = pipe.lock();
                p.write(data)
            }
            FileDescriptor::Socket(sock) => {
                let mut s = sock.lock();
                s.write(data)
            }
            FileDescriptor::EventFd(efd) => {
                let mut e = efd.lock();
                e.write(data)
            }
            FileDescriptor::Epoll(_) => {
                Err("Cannot write to epoll file descriptor")
            }
            FileDescriptor::MemFd(memfd) => {
                let mut m = memfd.lock();
                m.write(data)
            }
            FileDescriptor::Inet(_) => Err("Internet sockets are written through the Linux socket layer"),
            // Kernel output to a process whose stdout is a pseudo-terminal (never waits:
            // callers may hold the scheduler lock)
            FileDescriptor::Pty(p) => Ok(p.write_nowait(data)),
            FileDescriptor::SignalFd(_) => Err("signalfd is not writable"),
            // Kernel output to a process whose stdout is a socket: best effort, never waits
            FileDescriptor::Unix(_) => Ok(data.len()),
            FileDescriptor::TimerFd(_) | FileDescriptor::Inotify(_) | FileDescriptor::PidFd(_) => Err("not writable"),
            FileDescriptor::Vnode(file) => {
                let mut f = file.lock();
                if !f.writable() {
                    return Err("File not opened for writing");
                }
                if f.flags & O_APPEND != 0 {
                    f.offset = ZfsClient::getattr(f.ino).map_err(|_| "ZFS stat error")?.size;
                }
                let n = ZfsClient::write_at(f.ino, f.offset, data).map_err(|_| "ZFS write error")?;
                f.offset += n as u64;
                Ok(n)
            }
            FileDescriptor::File { path, cursor, writable, append, .. } => {
                if !*writable {
                    return Err("File not opened for writing");
                }
                let at = if *append { None } else { Some(*cursor) };
                let (n, end) = write_path_at(path, at, data)?;
                *cursor = end;
                Ok(n)
            }
        }
    }

    /// Registers the wait queues that announce readiness changes for this descriptor into `waits`.
    ///
    /// Used by `poll`, `ppoll`, `select`, and `epoll_wait`. Marks `waits.polled = true` when
    /// readiness transitions are not pushed via a dedicated wait queue (e.g., nested `epoll`).
    /// Never acquires the global scheduler lock because callers may already hold it.
    ///
    /// # Arguments
    ///
    /// * `waits` - Accumulator of wait queues and timer deadlines for the current blocking multiplexer call.
    pub fn add_wait_queues(&self, waits: &mut crate::task::wait::WaitSet) {
        use crate::task::wait::QueueRef;
        match self {
            FileDescriptor::ConsoleIn | FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => {
                waits.add(QueueRef::Static(&crate::compat::linux::tty::INPUT_WQ));
            }
            FileDescriptor::PipeRead(p) | FileDescriptor::PipeWrite(p) => {
                waits.add(QueueRef::Shared(p.lock().wq.clone()));
            }
            FileDescriptor::Socket(sock) => match &sock.lock().role {
                crate::compat::linux::socket::UnixSocketRole::Connected { rx, tx, .. } => {
                    waits.add(QueueRef::Shared(rx.lock().wq.clone()));
                    waits.add(QueueRef::Shared(tx.lock().wq.clone()));
                }
                _ => waits.polled = true,
            },
            FileDescriptor::Pty(p) => waits.add(QueueRef::Shared(p.pty.wq.clone())),
            // Posting a signal wakes every wait of the process
            FileDescriptor::SignalFd(_) => {}
            FileDescriptor::Unix(s) => s.add_wait_queues(waits),
            FileDescriptor::TimerFd(t) => {
                waits.add(QueueRef::Shared(t.wq.clone()));
                waits.add_deadline(t.clone());
            }
            FileDescriptor::Inotify(i) => waits.add(QueueRef::Shared(i.wq.clone())),
            FileDescriptor::PidFd(_) => waits.add(QueueRef::Static(&crate::compat::linux::pidfd::EXIT_WQ)),
            FileDescriptor::EventFd(e) => waits.add(QueueRef::Shared(e.lock().wq.clone())),
            FileDescriptor::Inet(s) => {
                let s = s.lock();
                match s.wait_queue() {
                    Some(q) if crate::net::stack::service_running() => waits.add(QueueRef::Shared(q)),
                    Some(_) => waits.polled = true,
                    // No endpoint yet: readiness only changes through the owner's own calls
                    None => {}
                }
            }
            // Always ready
            FileDescriptor::Vnode(_) | FileDescriptor::MemFd(_) | FileDescriptor::File { .. } => {}
            // A nested epoll instance's readiness changes are not announced
            FileDescriptor::Epoll(_) => waits.polled = true,
        }
    }

    /// Queries the current non-blocking readiness bitmask (`EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`) of this descriptor.
    ///
    /// # Returns
    ///
    /// Bitwise OR of Linux `EPOLL*` / `POLL*` event flags (`0x0001` readable, `0x0004` writable,
    /// `0x0008` error, `0x0010` hangup).
    pub fn poll_events(&self) -> u32 {
        match self {
            FileDescriptor::ConsoleIn | FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => {
                // Callers pump the keyboard first; this may run under the scheduler lock
                let readable = !crate::compat::linux::tty::attached() || crate::compat::linux::tty::has_input();
                0x0004 | if readable { 0x0001 } else { 0 }
            }
            FileDescriptor::PipeRead(pipe) => {
                let p = pipe.lock();
                let mut ev = 0;
                if p.available_read() > 0 { ev |= 0x0001; } // EPOLLIN
                if p.writers_count() == 0 { ev |= 0x0010; } // EPOLLHUP
                ev
            }
            FileDescriptor::PipeWrite(pipe) => {
                let p = pipe.lock();
                let mut ev = 0;
                if p.available_write() > 0 { ev |= 0x0004; } // EPOLLOUT
                if p.readers_count() == 0 { ev |= 0x0008; }  // EPOLLERR
                ev
            }
            FileDescriptor::Socket(sock) => {
                sock.lock().poll_events()
            }
            FileDescriptor::EventFd(efd) => {
                efd.lock().poll_events()
            }
            FileDescriptor::File { readable, writable, .. } => {
                let mut ev = 0;
                if *readable { ev |= 0x0001; }
                if *writable { ev |= 0x0004; }
                ev
            }
            FileDescriptor::Inet(s) => s.lock().poll_events(),
            FileDescriptor::Pty(p) => p.poll_events(),
            FileDescriptor::SignalFd(s) => s.poll_events(),
            FileDescriptor::Unix(s) => s.poll_events(),
            FileDescriptor::TimerFd(t) => t.poll_events(),
            FileDescriptor::Inotify(i) => i.poll_events(),
            FileDescriptor::PidFd(p) => p.poll_events(),
            // Regular files are always ready
            FileDescriptor::Vnode(_) | FileDescriptor::MemFd(_) => 0x0001 | 0x0004,
            FileDescriptor::Epoll(_) => 0,
        }
    }
}

/// Thread-shared file descriptor table (`Arc<Mutex<FdTable>>`) used by threads created with `CLONE_FILES`.
pub type SharedFdTable = Arc<Mutex<FdTable>>;

/// Per-process File Descriptor Table and filesystem context (working directory, `umask`, and `chroot`).
///
/// # Concurrency & Thread Safety
/// Wrapped in [`SharedFdTable`] (`Arc<Mutex<FdTable>>`) on each task so threads sharing
/// `CLONE_FILES` observe descriptor allocations and closures atomically.
///
/// # Lifetime & Cleanup
/// On `fork`, [`FdTable::fork_copy()`] clones the table and increments pipe reader/writer
/// counts. On `execve`, [`FdTable::close_on_exec()`] closes descriptors with `FD_CLOEXEC`.
/// On task exit, [`FdTable::close_all()`] releases all remaining descriptors when the last
/// thread sharing the table exits.
#[derive(Clone)]
pub struct FdTable {
    /// Sparse vector of open descriptors indexed by file descriptor number (`0..MAX_FDS`).
    fds: Vec<Option<FileDescriptor>>,
    /// Per-descriptor close-on-exec (`FD_CLOEXEC`) flag array parallel to `fds`.
    cloexec: Vec<bool>,
    /// Current working directory ZFS inode number (`0` denotes the filesystem root).
    pub cwd_ino: u64,
    /// Normalized current working directory path string returned by `getcwd(2)`.
    pub cwd_path: String,
    /// File mode creation mask (`umask(2)`), initialized to `0o022`.
    pub umask: u32,
    /// Root directory ZFS inode for path resolution (`chroot(2)`; `0` denotes the pool root).
    pub root_ino: u64,
}

impl FdTable {
    /// Constructs a completely empty [`FdTable`] with no allocated descriptors (`const`-compatible).
    ///
    /// # Returns
    ///
    /// An empty [`FdTable`] with `umask = 0o022` and root working directory.
    pub const fn empty() -> Self {
        Self {
            fds: Vec::new(),
            cloexec: Vec::new(),
            cwd_ino: 0,
            cwd_path: String::new(),
            umask: 0o022,
            root_ino: 0,
        }
    }

    /// Grows `fds` and `cloexec` vectors if necessary so index `fd` is valid.
    fn ensure(&mut self, fd: usize) {
        if self.fds.len() <= fd {
            self.fds.resize(fd + 1, None);
            self.cloexec.resize(fd + 1, false);
        }
    }

    /// Populates standard streams (`0` = `ConsoleIn`, `1` = `ConsoleOut`, `2` = `ConsoleErr`)
    /// and sets `cwd_path = "/"` if they are not already initialized.
    pub fn init_default(&mut self) {
        self.ensure(2);
        if self.fds[0].is_none() {
            self.fds[0] = Some(FileDescriptor::ConsoleIn);
        }
        if self.fds[1].is_none() {
            self.fds[1] = Some(FileDescriptor::ConsoleOut);
        }
        if self.fds[2].is_none() {
            self.fds[2] = Some(FileDescriptor::ConsoleErr);
        }
        if self.cwd_path.is_empty() {
            self.cwd_path = String::from("/");
        }
    }

    /// Constructs a new [`FdTable`] pre-populated with standard console streams (`stdin`, `stdout`, `stderr`).
    ///
    /// # Returns
    ///
    /// A ready-to-use [`FdTable`] with descriptors `0`, `1`, and `2` open.
    pub fn new_default() -> Self {
        let mut table = Self::empty();
        table.init_default();
        table
    }

    /// Allocates the lowest available file descriptor slot at or above `min` (`fcntl` `F_DUPFD`).
    ///
    /// Clears the `FD_CLOEXEC` flag on the newly allocated slot.
    ///
    /// # Arguments
    ///
    /// * `desc` - `FileDescriptor` to install.
    /// * `min` - Minimum acceptable descriptor index (`0..MAX_FDS`).
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Allocated descriptor index in `min..MAX_FDS`.
    ///
    /// # Errors
    ///
    /// * `Err("Process file descriptor table is full (EMFILE)")` - No free slot exists in `min..MAX_FDS`.
    pub fn alloc_fd_from(&mut self, desc: FileDescriptor, min: usize) -> Result<usize, &'static str> {
        let free = (min..MAX_FDS).find(|&i| self.fds.get(i).map_or(true, |d| d.is_none()));
        match free {
            Some(i) => {
                self.ensure(i);
                self.fds[i] = Some(desc);
                self.cloexec[i] = false;
                Ok(i)
            }
            None => Err("Process file descriptor table is full (EMFILE)"),
        }
    }

    /// Allocates the lowest available file descriptor index starting from `0`.
    ///
    /// # Arguments
    ///
    /// * `desc` - `FileDescriptor` to install.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Allocated descriptor index.
    ///
    /// # Errors
    ///
    /// * `Err("Process file descriptor table is full (EMFILE)")` - All `MAX_FDS` slots are occupied.
    pub fn alloc_fd(&mut self, desc: FileDescriptor) -> Result<usize, &'static str> {
        self.alloc_fd_from(desc, 0)
    }

    /// Retrieves an immutable reference to the `FileDescriptor` at index `fd`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor index to look up.
    ///
    /// # Returns
    ///
    /// `Some(&FileDescriptor)` if `fd` is within bounds and open, or `None` otherwise.
    pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
        self.fds.get(fd).and_then(|d| d.as_ref())
    }

    /// Retrieves a mutable reference to the `FileDescriptor` at index `fd`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor index to look up.
    ///
    /// # Returns
    ///
    /// `Some(&mut FileDescriptor)` if `fd` is within bounds and open, or `None` otherwise.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
        self.fds.get_mut(fd).and_then(|d| d.as_mut())
    }

    /// Replaces the descriptor at `fd` with `desc`, returning whatever descriptor was previously stored there.
    ///
    /// Resets `FD_CLOEXEC` for `fd` to `false`.
    ///
    /// # Arguments
    ///
    /// * `fd` - Target descriptor index (`0..MAX_FDS`).
    /// * `desc` - New `FileDescriptor` (or `None` to clear the slot).
    ///
    /// # Returns
    ///
    /// The previous `Option<FileDescriptor>`, or `None` if `fd >= MAX_FDS`.
    pub fn set_fd(&mut self, fd: usize, desc: Option<FileDescriptor>) -> Option<FileDescriptor> {
        if fd >= MAX_FDS {
            return None;
        }
        self.ensure(fd);
        self.cloexec[fd] = false;
        core::mem::replace(&mut self.fds[fd], desc)
    }

    /// Queries the close-on-exec (`FD_CLOEXEC`) flag for descriptor `fd`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor index.
    ///
    /// # Returns
    ///
    /// `true` if `FD_CLOEXEC` is set on `fd`, `false` otherwise.
    pub fn cloexec(&self, fd: usize) -> bool {
        self.cloexec.get(fd).copied().unwrap_or(false)
    }

    /// Sets or clears the close-on-exec (`FD_CLOEXEC`) flag for descriptor `fd`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor index.
    /// * `on` - `true` to close `fd` on `execve`, `false` to preserve it across `execve`.
    pub fn set_cloexec(&mut self, fd: usize, on: bool) {
        if fd < self.cloexec.len() {
            self.cloexec[fd] = on;
        }
    }

    /// Closes the file descriptor at index `fd` and decrements pipe/socket endpoint counts as needed.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor index to close.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Descriptor was open and has now been closed.
    ///
    /// # Errors
    ///
    /// * `Err("File descriptor not open (EBADF)")` - `fd` was out of bounds or not open.
    pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
        let desc = match self.fds.get_mut(fd).and_then(|d| d.take()) {
            Some(d) => d,
            None => return Err("File descriptor not open (EBADF)"),
        };
        self.cloexec[fd] = false;
        match desc {
            FileDescriptor::PipeRead(pipe) => {
                pipe.lock().drop_reader();
            }
            FileDescriptor::PipeWrite(pipe) => {
                pipe.lock().drop_writer();
            }
            FileDescriptor::Socket(sock) => {
                let mut s = sock.lock();
                let _ = s.shutdown(crate::compat::linux::socket::SHUT_RDWR);
            }
            _ => {}
        }
        Ok(())
    }

    /// Duplicates `oldfd` onto `newfd`, closing `newfd` first if it was already open (POSIX `dup2`).
    ///
    /// If `oldfd == newfd` and `oldfd` is open, returns `Ok(newfd)` without closing or changing
    /// `FD_CLOEXEC`. Otherwise clears `FD_CLOEXEC` on `newfd` and increments pipe reader/writer
    /// reference counts if `oldfd` refers to a pipe.
    ///
    /// # Arguments
    ///
    /// * `oldfd` - Open source file descriptor index.
    /// * `newfd` - Target file descriptor index (`0..MAX_FDS`).
    ///
    /// # Returns
    ///
    /// * `Ok(newfd)` - Target descriptor index on success.
    ///
    /// # Errors
    ///
    /// * `Err("Bad file descriptor (EBADF)")` - `newfd >= MAX_FDS`.
    /// * `Err("Source file descriptor not open (EBADF)")` - `oldfd` is not open.
    pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
        if newfd >= MAX_FDS {
            return Err("Bad file descriptor (EBADF)");
        }
        let desc = self.get(oldfd).cloned().ok_or("Source file descriptor not open (EBADF)")?;
        if oldfd == newfd {
            return Ok(newfd);
        }
        match &desc {
            FileDescriptor::PipeRead(pipe) => pipe.lock().add_reader(),
            FileDescriptor::PipeWrite(pipe) => pipe.lock().add_writer(),
            _ => {}
        }
        let _ = self.close(newfd);
        self.ensure(newfd);
        self.fds[newfd] = Some(desc);
        self.cloexec[newfd] = false;
        Ok(newfd)
    }

    /// Clones the entire descriptor table for a child process (`fork` / `clone` without `CLONE_FILES`).
    ///
    /// Increments reader and writer reference counts on all open [`PipeBuffer`] descriptors so
    /// pipes remain open until both parent and child close their ends.
    ///
    /// # Returns
    ///
    /// An independent [`FdTable`] sharing the underlying open file descriptions.
    pub fn fork_copy(&self) -> Self {
        for desc in self.fds.iter().flatten() {
            match desc {
                FileDescriptor::PipeRead(pipe) => pipe.lock().add_reader(),
                FileDescriptor::PipeWrite(pipe) => pipe.lock().add_writer(),
                _ => {}
            }
        }
        self.clone()
    }

    /// Closes every open descriptor in the table (invoked during process termination).
    pub fn close_all(&mut self) {
        for fd in 0..self.fds.len() {
            let _ = self.close(fd);
        }
    }

    /// Wraps this [`FdTable`] in an `Arc<Mutex<FdTable>>` ([`SharedFdTable`]) for thread sharing.
    ///
    /// # Returns
    ///
    /// A reference-counted [`SharedFdTable`].
    pub fn into_shared(self) -> SharedFdTable {
        Arc::new(Mutex::new(self))
    }

    /// Closes all descriptors marked with `FD_CLOEXEC` during an `execve(2)` transition.
    pub fn close_on_exec(&mut self) {
        for fd in 0..self.fds.len() {
            if self.cloexec(fd) {
                let _ = self.close(fd);
            }
        }
    }

    /// Duplicates `oldfd` into the lowest available descriptor slot at or above `min` (`dup` / `F_DUPFD`).
    ///
    /// Increments pipe reader/writer reference counts if `oldfd` refers to a pipe.
    ///
    /// # Arguments
    ///
    /// * `oldfd` - Open source file descriptor index.
    /// * `min` - Minimum descriptor index to allocate (`0` for `dup(2)`).
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Newly allocated duplicate descriptor index.
    ///
    /// # Errors
    ///
    /// * `Err("Source file descriptor not open (EBADF)")` - `oldfd` is not open.
    /// * `Err("Process file descriptor table is full (EMFILE)")` - No free slot at or above `min`.
    pub fn dup_from(&mut self, oldfd: usize, min: usize) -> Result<usize, &'static str> {
        let desc = self.get(oldfd).cloned().ok_or("Source file descriptor not open (EBADF)")?;
        match &desc {
            FileDescriptor::PipeRead(pipe) => pipe.lock().add_reader(),
            FileDescriptor::PipeWrite(pipe) => pipe.lock().add_writer(),
            _ => {}
        }
        self.alloc_fd_from(desc, min)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new_default()
    }
}
