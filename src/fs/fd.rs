use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::pipe::PipeBuffer;
use crate::fs::ZfsClient;

/// Highest number of descriptors a process may hold (Linux default `RLIMIT_NOFILE`).
pub const MAX_FDS: usize = 1024;

/// Linux `open(2)` flags used by the file layer.
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_APPEND: u32 = 0o2000;

/// An open file description for a ZFS inode (shared by `dup`ed descriptors).
pub struct OpenFile {
    pub ino: u64,
    /// File offset, or the `getdents64` cookie for directories.
    pub offset: u64,
    /// `open(2)` status flags (access mode, `O_APPEND`, `O_NONBLOCK`, ...).
    pub flags: u32,
    /// Absolute path at open time (for `/proc/self/fd` and diagnostics).
    pub path: String,
}

impl OpenFile {
    pub fn new(ino: u64, flags: u32, path: String) -> Arc<Mutex<Self>> {
        ZfsClient::open_ref(ino);
        Arc::new(Mutex::new(Self { ino, offset: 0, flags, path }))
    }

    pub fn readable(&self) -> bool {
        self.flags & O_ACCMODE != O_WRONLY
    }

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

/// Types of file descriptors supported by Hydra OS.
#[derive(Clone)]
pub enum FileDescriptor {
    ConsoleIn,
    ConsoleOut,
    ConsoleErr,
    PipeRead(Arc<Mutex<PipeBuffer>>),
    PipeWrite(Arc<Mutex<PipeBuffer>>),
    Socket(Arc<Mutex<crate::compat::linux::socket::UnixSocket>>),
    Epoll(Arc<Mutex<crate::compat::linux::epoll::EpollInstance>>),
    EventFd(Arc<Mutex<crate::compat::linux::eventfd::EventFd>>),
    MemFd(Arc<Mutex<crate::compat::linux::memfd::MemFd>>),
    /// A ZFS inode opened through the Linux VFS.
    Vnode(Arc<Mutex<OpenFile>>),
    /// An internet (TCP/UDP) socket; I/O goes through the Linux socket layer.
    Inet(Arc<Mutex<crate::compat::linux::inet::InetSocket>>),
    /// An end of a pseudo-terminal (`/dev/ptmx` master or `/dev/pts/N` slave).
    Pty(Arc<crate::compat::linux::pty::PtyFile>),
    /// Signals received as data (`signalfd`).
    SignalFd(Arc<crate::compat::linux::signalfd::SignalFd>),
    /// A Unix domain socket (`AF_UNIX`).
    Unix(Arc<crate::compat::linux::unix::UnixSocket>),
    /// A timer read as a descriptor (`timerfd`).
    TimerFd(Arc<crate::compat::linux::timerfd::TimerFd>),
    /// File-system change notifications (`inotify`).
    Inotify(Arc<crate::compat::linux::inotify::Inotify>),
    /// A process (`pidfd_open`, `CLONE_PIDFD`).
    PidFd(Arc<crate::compat::linux::pidfd::PidFd>),
    /// A path-addressed file: pseudo files (`/dev`, `/proc`) and Hydra-native opens.
    File {
        path: String,
        cursor: usize,
        readable: bool,
        writable: bool,
        append: bool,
    },
}

fn read_path_at(path: &str, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
    if let Some(pseudo) = crate::compat::linux::fs::match_pseudo_path(path) {
        return Ok(pseudo.read(offset, buf));
    }
    let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| "File not found")?;
    ZfsClient::read_at(ino, offset as u64, buf).map_err(|_| "ZFS read error")
}

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
    /// Reads data from the file descriptor into `buf`.
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

    /// Reads at an absolute `offset` without moving the file cursor (`pread64`).
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

    /// Writes at an absolute `offset` without moving the file cursor (`pwrite64`).
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

    /// Writes data from `data` into the file descriptor.
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

    /// Evaluates readiness flags for epoll and poll multiplexing.
    /// Adds the wait queues that announce this descriptor's readiness changes to `waits`,
    /// or marks the set polled when changes are not announced (eventfd, epoll, listening
    /// sockets). Does not take the scheduler lock (callers may hold it).
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

/// A descriptor table shared by the threads of a process (`CLONE_FILES`).
pub type SharedFdTable = Arc<Mutex<FdTable>>;

/// Per-process File Descriptor Table plus the process's working directory.
#[derive(Clone)]
pub struct FdTable {
    fds: Vec<Option<FileDescriptor>>,
    /// `FD_CLOEXEC` flag per descriptor.
    cloexec: Vec<bool>,
    /// Working directory inode (0 = filesystem root).
    pub cwd_ino: u64,
    /// Working directory path, as returned by `getcwd`.
    pub cwd_path: String,
    /// File creation mask (`umask`).
    pub umask: u32,
    /// Root directory inode for path resolution (`chroot`; 0 = pool root).
    pub root_ino: u64,
}

impl FdTable {
    /// Constructs an empty file descriptor table (usable in const context).
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

    fn ensure(&mut self, fd: usize) {
        if self.fds.len() <= fd {
            self.fds.resize(fd + 1, None);
            self.cloexec.resize(fd + 1, false);
        }
    }

    /// Initializes standard streams (stdin, stdout, stderr) if not already populated.
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

    /// Constructs a standard Unix-like file descriptor table with stdin (0), stdout (1), stderr (2).
    pub fn new_default() -> Self {
        let mut table = Self::empty();
        table.init_default();
        table
    }

    /// Allocates the lowest available descriptor at or above `min` (`F_DUPFD`).
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

    /// Allocates the lowest available file descriptor index.
    pub fn alloc_fd(&mut self, desc: FileDescriptor) -> Result<usize, &'static str> {
        self.alloc_fd_from(desc, 0)
    }

    /// Retrieves an immutable reference to the file descriptor at `fd`.
    pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
        self.fds.get(fd).and_then(|d| d.as_ref())
    }

    /// Retrieves a mutable reference to the file descriptor at `fd`.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
        self.fds.get_mut(fd).and_then(|d| d.as_mut())
    }

    /// Replaces the descriptor at `fd` with `desc`, returning the previous descriptor.
    pub fn set_fd(&mut self, fd: usize, desc: Option<FileDescriptor>) -> Option<FileDescriptor> {
        if fd >= MAX_FDS {
            return None;
        }
        self.ensure(fd);
        self.cloexec[fd] = false;
        core::mem::replace(&mut self.fds[fd], desc)
    }

    /// Reads the `FD_CLOEXEC` flag.
    pub fn cloexec(&self, fd: usize) -> bool {
        self.cloexec.get(fd).copied().unwrap_or(false)
    }

    /// Sets the `FD_CLOEXEC` flag.
    pub fn set_cloexec(&mut self, fd: usize, on: bool) {
        if fd < self.cloexec.len() {
            self.cloexec[fd] = on;
        }
    }

    /// Closes the file descriptor at index `fd`, adjusting pipe refcounts if applicable.
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

    /// Duplicates `oldfd` into `newfd`, closing `newfd` if already open (like POSIX `dup2`).
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

    /// Copies the table for a new process or thread (`fork`/`clone`): descriptors share
    /// their open file descriptions, and pipe ends gain a reference each.
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

    /// Closes every descriptor (process exit).
    pub fn close_all(&mut self) {
        for fd in 0..self.fds.len() {
            let _ = self.close(fd);
        }
    }

    /// Wraps the table for sharing between threads.
    pub fn into_shared(self) -> SharedFdTable {
        Arc::new(Mutex::new(self))
    }

    /// Closes descriptors marked close-on-exec (`execve`).
    pub fn close_on_exec(&mut self) {
        for fd in 0..self.fds.len() {
            if self.cloexec(fd) {
                let _ = self.close(fd);
            }
        }
    }

    /// Duplicates `oldfd` onto the lowest free descriptor at or above `min`.
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
