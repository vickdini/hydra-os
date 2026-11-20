//! *mirror* of `src/fs/fd.rs`: the descriptor enum (same variants), the open file
//! description and the descriptor table, with the kernel's semantics for what the file
//! layer uses (lowest free number, close-on-exec flags, `dup` and pipe end counts).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::compat::linux as lx;
use crate::fs::pipe::PipeBuffer;
use crate::fs::ZfsClient;

pub const MAX_FDS: usize = 1024;
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_APPEND: u32 = 0o2000;
pub const O_PATH: u32 = 0o10000000;

/// *mirror* An open file description of the pool.
pub struct OpenFile {
    pub ino: u64,
    pub offset: u64,
    pub flags: u32,
    pub path: String,
    pub mnt: usize,
    pub foreign: Option<(u64, u64, usize)>,
    pub no_truncate: bool,
    pub nonotify: bool,
    pub fan_dir: u64,
    pub is_dir: bool,
}

impl OpenFile {
    pub fn new(ino: u64, flags: u32, path: String) -> Arc<Mutex<Self>> {
        ZfsClient::open_ref(ino);
        Arc::new(Mutex::new(Self { ino, offset: 0, flags, path, mnt: 0, foreign: None, no_truncate: false, nonotify: false, fan_dir: 0, is_dir: false }))
    }

    pub fn fan(&self, mask: u64) {
        if lx::fanotify::active() && !self.nonotify && self.flags & O_PATH == 0 {
            lx::fanotify::file_event(self.ino, self.fan_dir, &self.path, mask, self.is_dir);
        }
    }

    pub fn readable(&self) -> bool {
        self.flags & O_ACCMODE != O_WRONLY && self.flags & O_PATH == 0
    }

    pub fn writable(&self) -> bool {
        self.flags & O_ACCMODE != O_RDONLY && self.flags & O_PATH == 0
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        lx::locks::release_file(self as *const OpenFile as usize);
        self.fan(if self.writable() { lx::fanotify::FAN_CLOSE_WRITE } else { lx::fanotify::FAN_CLOSE_NOWRITE });
        ZfsClient::release(self.ino);
    }
}

/// *mirror* Same variants as the kernel's.
#[derive(Clone)]
pub enum FileDescriptor {
    ConsoleIn,
    ConsoleOut,
    ConsoleErr,
    PipeRead(Arc<Mutex<PipeBuffer>>),
    PipeWrite(Arc<Mutex<PipeBuffer>>),
    Socket(Arc<Mutex<lx::socket::UnixSocket>>),
    Epoll(Arc<Mutex<lx::epoll::EpollInstance>>),
    EventFd(Arc<Mutex<lx::eventfd::EventFd>>),
    MemFd { memfd: Arc<Mutex<lx::memfd::MemFd>>, flags: u32 },
    Vnode(Arc<Mutex<OpenFile>>),
    Inet(Arc<Mutex<lx::inet::InetSocket>>),
    Pty(Arc<lx::pty::PtyFile>),
    SignalFd(Arc<lx::signalfd::SignalFd>),
    Unix(Arc<lx::unix::UnixSocket>),
    TimerFd(Arc<lx::timerfd::TimerFd>),
    Inotify(Arc<lx::inotify::Inotify>),
    PidFd(Arc<lx::pidfd::PidFd>),
    Device(Arc<dyn lx::chardev::CharDevice>),
    File { path: String, cursor: usize, readable: bool, writable: bool, append: bool, shown: Option<String> },
}

impl FileDescriptor {
    /// A by-name file (test helper).
    pub fn file(path: &str) -> Self {
        FileDescriptor::File { path: String::from(path), cursor: 0, readable: true, writable: true, append: false, shown: None }
    }
}

pub type SharedFdTable = Arc<Mutex<FdTable>>;

/// *mirror* A process's descriptor table.
pub struct FdTable {
    fds: Vec<Option<FileDescriptor>>,
    cloexec: Vec<bool>,
    pub cwd_ino: u64,
    pub cwd_path: String,
    pub umask: u32,
    pub root_ino: u64,
    pub root_mnt: usize,
    pub cwd_mnt: usize,
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FdTable {
    pub fn new() -> Self {
        FdTable { fds: Vec::new(), cloexec: Vec::new(), cwd_ino: 0, cwd_path: String::from("/"), umask: 0o022, root_ino: 0, root_mnt: 0, cwd_mnt: 0 }
    }

    fn ensure(&mut self, fd: usize) {
        if self.fds.len() <= fd {
            self.fds.resize(fd + 1, None);
            self.cloexec.resize(fd + 1, false);
        }
    }

    pub fn alloc_fd_from(&mut self, desc: FileDescriptor, min: usize) -> Result<usize, &'static str> {
        let limit = lx::limits::nofile();
        let free = (min..limit).find(|&i| self.fds.get(i).map_or(true, |d| d.is_none()));
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

    pub fn alloc_fd(&mut self, desc: FileDescriptor) -> Result<usize, &'static str> {
        self.alloc_fd_from(desc, 0)
    }

    pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
        self.fds.get(fd).and_then(|d| d.as_ref())
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
        self.fds.get_mut(fd).and_then(|d| d.as_mut())
    }

    /// Puts `desc` at `fd` (test helper; whatever was there is dropped).
    pub fn set_fd(&mut self, fd: usize, desc: Option<FileDescriptor>) -> Option<FileDescriptor> {
        self.ensure(fd);
        self.cloexec[fd] = false;
        core::mem::replace(&mut self.fds[fd], desc)
    }

    pub fn cloexec(&self, fd: usize) -> bool {
        self.cloexec.get(fd).copied().unwrap_or(false)
    }

    pub fn set_cloexec(&mut self, fd: usize, on: bool) {
        if fd < self.cloexec.len() {
            self.cloexec[fd] = on;
        }
    }

    pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
        let desc = match self.fds.get_mut(fd).and_then(|d| d.take()) {
            Some(d) => d,
            None => return Err("File descriptor not open (EBADF)"),
        };
        self.cloexec[fd] = false;
        match desc {
            FileDescriptor::PipeRead(pipe) => pipe.lock().drop_reader(),
            FileDescriptor::PipeWrite(pipe) => pipe.lock().drop_writer(),
            FileDescriptor::Vnode(f) => {
                let ino = f.lock().ino;
                lx::locks::closed(ino);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
        if newfd >= lx::limits::nofile() {
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

    pub fn dup_from(&mut self, oldfd: usize, min: usize) -> Result<usize, &'static str> {
        let desc = self.get(oldfd).cloned().ok_or("Source file descriptor not open (EBADF)")?;
        match &desc {
            FileDescriptor::PipeRead(pipe) => pipe.lock().add_reader(),
            FileDescriptor::PipeWrite(pipe) => pipe.lock().add_writer(),
            _ => {}
        }
        self.alloc_fd_from(desc, min)
    }

    /// Open descriptor numbers (test helper).
    pub fn open_fds(&self) -> Vec<usize> {
        (0..self.fds.len()).filter(|&i| self.fds[i].is_some()).collect()
    }
}
