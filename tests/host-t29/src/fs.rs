//! *stub* `crate::fs`: descriptors, the descriptor table and the ZFS client, faked.

use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

/// The descriptor table's size (the kernel's `fs::fd::MAX_FDS`).
pub const MAX_FDS: usize = 1024;

pub type FdTable = crate::fake::FdTable;
pub type SharedFdTable = Arc<Mutex<FdTable>>;

/// *stub* An open ZFS file (`FileDescriptor::Vnode`).
#[derive(Default, Debug)]
pub struct OpenFile {
    pub ino: u64,
    pub path: String,
    pub offset: u64,
    pub readable: bool,
    pub writable: bool,
}

/// The kernel's pipe buffer (real).
#[path = "../../../src/fs/pipe.rs"]
pub mod pipe;
pub use pipe::PipeBuffer;

/// *stub* A fake object behind a descriptor whose real type is not compiled here.
#[derive(Default, Debug)]
pub struct FakeObj {
    pub name: String,
    /// An eventfd's wait queue (edge-triggered epoll reads its wake count).
    pub wq: Arc<crate::task::wait::WaitQueue>,
}

impl FakeObj {
    pub fn named(name: &str) -> Arc<Mutex<FakeObj>> {
        Arc::new(Mutex::new(FakeObj { name: name.into(), ..Default::default() }))
    }
}

/// *stub* A Linux `AF_UNIX` socket (`FileDescriptor::Unix`): only its peer.
#[derive(Default, Debug)]
pub struct FakeUnix {
    /// `SO_PEERCRED`: (pid, uid, gid).
    pub peer: Option<(u32, u32, u32)>,
}
impl FakeUnix {
    pub fn peer_cred(&self) -> Option<(u32, u32, u32)> {
        self.peer
    }
}

/// *stub* The kernel's descriptor enum, with the variants the code under test matches
/// (the payloads are fakes where the real object is not compiled here).
#[derive(Clone)]
pub enum FileDescriptor {
    ConsoleIn,
    ConsoleOut,
    ConsoleErr,
    PipeRead(Arc<Mutex<PipeBuffer>>),
    PipeWrite(Arc<Mutex<PipeBuffer>>),
    Socket(Arc<Mutex<crate::compat::linux::socket::UnixSocket>>),
    Epoll(Arc<Mutex<crate::compat::linux::epoll::EpollInstance>>),
    EventFd(Arc<Mutex<FakeObj>>),
    MemFd { memfd: Arc<Mutex<crate::compat::linux::memfd::MemFd>>, flags: u32 },
    Vnode(Arc<Mutex<OpenFile>>),
    Inet(Arc<Mutex<FakeObj>>),
    Unix(Arc<FakeUnix>),
    PidFd(Arc<u64>),
    Pty(Arc<FakeObj>),
    SignalFd(Arc<FakeObj>),
    TimerFd(Arc<FakeObj>),
    Inotify(Arc<FakeObj>),
    Device(Arc<dyn crate::compat::linux::chardev::CharDevice>),
    File { path: String, cursor: usize, readable: bool, writable: bool, append: bool, shown: Option<String> },
}

impl FileDescriptor {
    /// A plain path-addressed file.
    pub fn file(path: &str) -> FileDescriptor {
        FileDescriptor::File { path: path.into(), cursor: 0, readable: true, writable: true, append: false, shown: None }
    }

    /// *mirror* of the kernel's identity of the open file description.
    pub fn object_id(&self) -> usize {
        fn of<T: ?Sized>(a: &Arc<T>) -> usize {
            Arc::as_ptr(a) as *const u8 as usize
        }
        match self {
            FileDescriptor::ConsoleIn => 1,
            FileDescriptor::ConsoleOut => 2,
            FileDescriptor::ConsoleErr => 3,
            FileDescriptor::PipeRead(a) | FileDescriptor::PipeWrite(a) => of(a),
            FileDescriptor::Socket(a) => of(a),
            FileDescriptor::Epoll(a) => of(a),
            FileDescriptor::EventFd(a) | FileDescriptor::Inet(a) => of(a),
            FileDescriptor::Unix(a) => of(a),
            FileDescriptor::MemFd { memfd, .. } => of(memfd),
            FileDescriptor::Vnode(a) => of(a),
            FileDescriptor::PidFd(a) => of(a),
            FileDescriptor::Pty(a) | FileDescriptor::SignalFd(a) | FileDescriptor::TimerFd(a) | FileDescriptor::Inotify(a) => of(a),
            FileDescriptor::Device(a) => of(a),
            FileDescriptor::File { path, .. } => path.as_ptr() as usize,
        }
    }

    /// *stub* Reads: files from `fake::ZFS_FILES` at the cursor, inodes from
    /// `fake::INODES`, pipes, sockets and memfds from the real objects; the console reads
    /// nothing.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::ConsoleIn => Ok(0),
            FileDescriptor::File { path, cursor, readable, .. } => {
                if !*readable {
                    return Err("File not opened for reading");
                }
                let n = crate::fake::ZFS_FILES.with_borrow(|m| {
                    let d = m.get(path.as_str()).map(|d| d.as_slice()).unwrap_or(&[]);
                    let start = (*cursor).min(d.len());
                    let n = buf.len().min(d.len() - start);
                    buf[..n].copy_from_slice(&d[start..start + n]);
                    n
                });
                *cursor += n;
                Ok(n)
            }
            FileDescriptor::Vnode(f) => {
                let mut f = f.lock();
                if !f.readable {
                    return Err("File not opened for reading");
                }
                let n = crate::fake::ZfsClient::read_at(f.ino, f.offset, buf).map_err(|_| "I/O error")?;
                f.offset += n as u64;
                Ok(n)
            }
            FileDescriptor::PipeRead(p) => Ok(p.lock().read(buf)),
            FileDescriptor::Socket(s) => s.lock().read(buf),
            FileDescriptor::MemFd { memfd, .. } => memfd.lock().read(buf),
            _ => Err("Bad file descriptor"),
        }
    }

    /// *stub* Writes: the console to `fake::CONSOLE`, files to `fake::ZFS_FILES`.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => {
                crate::fake::CONSOLE.with_borrow_mut(|c| c.extend_from_slice(data));
                Ok(data.len())
            }
            FileDescriptor::File { path, cursor, writable, append, .. } => {
                if !*writable {
                    return Err("File not opened for writing");
                }
                crate::fake::ZFS_FILES.with_borrow_mut(|m| {
                    let d = m.entry(path.clone()).or_default();
                    if *append {
                        *cursor = d.len();
                    }
                    let end = *cursor + data.len();
                    if d.len() < end {
                        d.resize(end, 0);
                    }
                    d[*cursor..end].copy_from_slice(data);
                    *cursor = end;
                });
                Ok(data.len())
            }
            FileDescriptor::Vnode(f) => {
                let mut f = f.lock();
                if !f.writable {
                    return Err("File not opened for writing");
                }
                let n = crate::fake::ZfsClient::write_at(f.ino, f.offset, data).map_err(|_| crate::fake::WRITE_ERROR.get())?;
                f.offset += n as u64;
                Ok(n)
            }
            FileDescriptor::PipeWrite(p) => p.lock().write(data),
            FileDescriptor::Socket(s) => s.lock().write(data),
            FileDescriptor::MemFd { memfd, .. } => memfd.lock().write(data),
            _ => Err("Bad file descriptor"),
        }
    }

    /// *stub* Positioned read (files and inodes; others: illegal seek).
    pub fn pread(&mut self, buf: &mut [u8], offset: usize) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::File { cursor, .. } => {
                let saved = *cursor;
                *cursor = offset;
                let r = self.read(buf);
                if let FileDescriptor::File { cursor, .. } = self {
                    *cursor = saved;
                }
                r
            }
            FileDescriptor::Vnode(f) => crate::fake::ZfsClient::read_at(f.lock().ino, offset as u64, buf).map_err(|_| "I/O error"),
            FileDescriptor::MemFd { memfd, .. } => Ok(memfd.lock().read_at(offset, buf)),
            _ => Err("Illegal seek"),
        }
    }

    /// *stub* Positioned write.
    pub fn pwrite(&mut self, data: &[u8], offset: usize) -> Result<usize, &'static str> {
        match self {
            FileDescriptor::File { cursor, .. } => {
                let saved = *cursor;
                *cursor = offset;
                let r = self.write(data);
                if let FileDescriptor::File { cursor, .. } = self {
                    *cursor = saved;
                }
                r
            }
            FileDescriptor::Vnode(f) => crate::fake::ZfsClient::write_at(f.lock().ino, offset as u64, data).map_err(|_| "I/O error"),
            FileDescriptor::MemFd { memfd, .. } => Ok(memfd.lock().write_at(offset, data)),
            _ => Err("Illegal seek"),
        }
    }
}

pub mod fd {
    pub use super::{FileDescriptor, OpenFile, MAX_FDS};
    pub const EFBIG_MSG: &str = "File too large";
    pub const ENOSPC_MSG: &str = "No space left on device";
    /// *mirror* of the kernel's error-message mapping (the messages the fakes use).
    pub fn io_errno(e: &str) -> Option<i64> {
        match e {
            EFBIG_MSG => Some(-27),
            ENOSPC_MSG => Some(-28),
            "Bad file descriptor" => Some(-9),
            "Broken pipe" => Some(-32),
            "Resource temporarily unavailable" => Some(-11),
            "Illegal seek" => Some(-29),
            _ => None,
        }
    }
}

impl OpenFile {
    pub fn readable(&self) -> bool {
        self.readable
    }
    pub fn writable(&self) -> bool {
        self.writable
    }
}

/// *stub* No boot volume on the host.
pub mod bootfs {
    pub fn read_boot_file(_path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
        Err("not found")
    }
}

pub mod client {
    pub use crate::fake::{FileStat, ZfsClient};
}
pub use client::ZfsClient;

pub mod zfs {
    #[path = "../../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
    #[path = "../../../../../src/fs/zfs/types.rs"]
    pub mod types;
    pub mod zpl {
        pub use super::fsproto::{
            Attr, ReaddirEntry, SetAttr, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ELOOP, EMLINK, ENAMETOOLONG, ENOENT, ENOSPC,
            ENOTDIR, ENOTEMPTY, EPERM, EXDEV,
        };
        pub type ZplResult<T> = Result<T, i64>;
    }
    pub use types::{DnodeType, ZFS_BLOCK_SIZE};
}
