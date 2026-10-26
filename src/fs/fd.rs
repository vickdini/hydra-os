use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::pipe::PipeBuffer;
use crate::fs::ZfsClient;

pub const MAX_FDS: usize = 16;

/// Types of file descriptors supported by Hydra OS.
#[derive(Clone)]
pub enum FileDescriptor {
    ConsoleIn,
    ConsoleOut,
    ConsoleErr,
    PipeRead(Arc<Mutex<PipeBuffer>>),
    PipeWrite(Arc<Mutex<PipeBuffer>>),
    File {
        path: String,
        cursor: usize,
        readable: bool,
        writable: bool,
        append: bool,
    },
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
            FileDescriptor::File {
                path,
                cursor,
                readable,
                ..
            } => {
                if !*readable {
                    return Err("File not opened for reading");
                }
                let mut temp = alloc::vec![0u8; 65536];
                let total_bytes = ZfsClient::read_file_by_path(path, &mut temp)?;
                if *cursor >= total_bytes {
                    return Ok(0); // EOF
                }
                let available = total_bytes - *cursor;
                let to_copy = buf.len().min(available);
                buf[..to_copy].copy_from_slice(&temp[*cursor..*cursor + to_copy]);
                *cursor += to_copy;
                Ok(to_copy)
            }
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
            FileDescriptor::File {
                path,
                cursor,
                writable,
                append,
                ..
            } => {
                if !*writable {
                    return Err("File not opened for writing");
                }
                if *append {
                    let mut temp = alloc::vec![0u8; 65536];
                    let existing_bytes = ZfsClient::read_file_by_path(path, &mut temp).unwrap_or(0);
                    let mut combined = Vec::with_capacity(existing_bytes + data.len());
                    combined.extend_from_slice(&temp[..existing_bytes]);
                    combined.extend_from_slice(data);
                    ZfsClient::write_file_by_path(path, &combined)?;
                    *cursor = combined.len();
                    Ok(data.len())
                } else {
                    if *cursor == 0 {
                        ZfsClient::write_file_by_path(path, data)?;
                        *cursor = data.len();
                        Ok(data.len())
                    } else {
                        let mut temp = alloc::vec![0u8; 65536];
                        let existing_bytes = ZfsClient::read_file_by_path(path, &mut temp).unwrap_or(0);
                        let mut combined = Vec::from(&temp[..existing_bytes]);
                        if *cursor + data.len() > combined.len() {
                            combined.resize(*cursor + data.len(), 0);
                        }
                        combined[*cursor..*cursor + data.len()].copy_from_slice(data);
                        ZfsClient::write_file_by_path(path, &combined)?;
                        *cursor += data.len();
                        Ok(data.len())
                    }
                }
            }
        }
    }
}

/// Per-process File Descriptor Table (supports up to MAX_FDS open files/pipes/streams).
#[derive(Clone)]
pub struct FdTable {
    fds: [Option<FileDescriptor>; MAX_FDS],
}

impl FdTable {
    /// Constructs an empty file descriptor table (usable in const context).
    pub const fn empty() -> Self {
        const NONE: Option<FileDescriptor> = None;
        Self {
            fds: [NONE; MAX_FDS],
        }
    }

    /// Initializes standard streams (stdin, stdout, stderr) if not already populated.
    pub fn init_default(&mut self) {
        if self.fds[0].is_none() {
            self.fds[0] = Some(FileDescriptor::ConsoleIn);
        }
        if self.fds[1].is_none() {
            self.fds[1] = Some(FileDescriptor::ConsoleOut);
        }
        if self.fds[2].is_none() {
            self.fds[2] = Some(FileDescriptor::ConsoleErr);
        }
    }

    /// Constructs a standard Unix-like file descriptor table with stdin (0), stdout (1), stderr (2).
    pub fn new_default() -> Self {
        let mut table = Self::empty();
        table.init_default();
        table
    }

    /// Allocates the lowest available file descriptor index.
    pub fn alloc_fd(&mut self, desc: FileDescriptor) -> Result<usize, &'static str> {
        for i in 0..MAX_FDS {
            if self.fds[i].is_none() {
                self.fds[i] = Some(desc);
                return Ok(i);
            }
        }
        Err("Process file descriptor table is full (EMFILE)")
    }

    /// Retrieves an immutable reference to the file descriptor at `fd`.
    pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
        if fd < MAX_FDS {
            self.fds[fd].as_ref()
        } else {
            None
        }
    }

    /// Retrieves a mutable reference to the file descriptor at `fd`.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
        if fd < MAX_FDS {
            self.fds[fd].as_mut()
        } else {
            None
        }
    }

    /// Replaces the descriptor at `fd` with `desc`, returning the previous descriptor.
    pub fn set_fd(&mut self, fd: usize, desc: Option<FileDescriptor>) -> Option<FileDescriptor> {
        if fd < MAX_FDS {
            let old = self.fds[fd].take();
            self.fds[fd] = desc;
            old
        } else {
            None
        }
    }

    /// Closes the file descriptor at index `fd`, adjusting pipe refcounts if applicable.
    pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
        if fd >= MAX_FDS {
            return Err("Bad file descriptor (EBADF)");
        }

        if let Some(desc) = self.fds[fd].take() {
            match desc {
                FileDescriptor::PipeRead(pipe) => {
                    pipe.lock().drop_reader();
                }
                FileDescriptor::PipeWrite(pipe) => {
                    pipe.lock().drop_writer();
                }
                _ => {}
            }
            Ok(())
        } else {
            Err("File descriptor not open (EBADF)")
        }
    }

    /// Duplicates `oldfd` into `newfd`, closing `newfd` if already open (like POSIX `dup2`).
    pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
        if oldfd >= MAX_FDS || newfd >= MAX_FDS {
            return Err("Bad file descriptor (EBADF)");
        }

        if oldfd == newfd {
            if self.fds[oldfd].is_some() {
                return Ok(newfd);
            } else {
                return Err("Bad file descriptor (EBADF)");
            }
        }

        let clone_desc = match &self.fds[oldfd] {
            Some(desc) => {
                match desc {
                    FileDescriptor::PipeRead(pipe) => {
                        pipe.lock().add_reader();
                    }
                    FileDescriptor::PipeWrite(pipe) => {
                        pipe.lock().add_writer();
                    }
                    _ => {}
                }
                desc.clone()
            }
            None => return Err("Source file descriptor not open (EBADF)"),
        };

        // Close existing newfd if open
        let _ = self.close(newfd);

        self.fds[newfd] = Some(clone_desc);
        Ok(newfd)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        const NONE: Option<FileDescriptor> = None;
        Self {
            fds: [NONE; MAX_FDS],
        }
    }
}
