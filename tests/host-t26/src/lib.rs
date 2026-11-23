//! Host build of the Linux file layer (test wave, group 26).
//!
//! The kernel's own files are compiled through `#[path]` at the module paths the kernel
//! uses, so `crate::` and `super::` references inside them resolve unchanged:
//!
//! - **under test**: `compat/linux/{vfs, mount, fuse, fs, fanotify, inotify, locks, acl,
//!   xfer, efivars, recent, aio, live}.rs`;
//! - **real helpers**: `fs/pipe.rs`, `fs/gpt.rs`, `fs/zfs/{fsproto, types}.rs`,
//!   `compat/linux/types.rs`.
//!
//! Everything else they call (the file server, the descriptor table, the scheduler, the
//! terminal, sockets, Landlock, ...) is a stand-in from [`fake`], placed at the same path.
//! The file server is an in-memory file system ([`fake::MemFs`]) with the server's walk
//! semantics, so path resolution, permissions and directory operations run for real.

#![allow(dead_code, unused_imports, clippy::all)]

extern crate alloc;

pub mod fake;
pub mod testkit;
pub mod testkit_fuse;

/// Tests that reach `pub(crate)` items of the kernel files.
#[cfg(test)]
mod unit;

/// *stub* Kernel console output; discarded on the host.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

/// *stub* Kernel log output; discarded on the host.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

pub mod arch {
    pub use crate::fake::arch::*;
}

pub mod memory {
    pub use crate::fake::memory::*;
}

pub mod task {
    pub use crate::fake::task::*;
}

pub mod lx {
    pub use crate::fake::lx::*;
}

pub mod ipc {
    /// *mirror* of the protocol numbers the file layer uses.
    pub mod protocol {
        pub const LX_OBJ_KIND_PIPE_R: u32 = 16;
        pub const LX_OBJ_KIND_PIPE_W: u32 = 17;
        pub const LX_OBJ_KIND_PIDFD: u32 = 22;
        pub const LX_KCALL_REOPEN: u64 = 0x6780;
        pub const LX_KCALL_FCNTL: u64 = 0x6782;
        pub const LX_KCALL_FIFO: u64 = 0x6783;
        // wave9 G6b-2
        pub const LX_OBJ_KIND_FUSE: u32 = 72;
        pub const LX_MNT_FUSE: u32 = 4;
    }
}

pub mod fs {
    #[path = "../../../../src/fs/pipe.rs"]
    pub mod pipe;
    #[path = "../../../../src/fs/gpt.rs"]
    pub mod gpt;

    pub use crate::fake::fd;
    /// wave7 G7-7: the real shared offset of by-path descriptors.
    #[path = "../../../../src/fs/cursor.rs"]
    pub mod cursor;
    pub use cursor::FileCursor;
    pub use crate::fake::zfs_client::ZfsClient;
    pub use fd::{FdTable, FileDescriptor, SharedFdTable, MAX_FDS};
    pub use pipe::PipeBuffer;

    /// *stub*
    pub mod blockdev {
        pub fn flush_all() {
            crate::fake::count("blockdev_flush");
        }
    }

    pub mod zfs {
        #[path = "../../../../../src/fs/zfs/fsproto.rs"]
        pub mod fsproto;
        #[path = "../../../../../src/fs/zfs/types.rs"]
        pub mod types;

        /// *mirror* of the kernel's re-exports.
        pub mod zpl {
            pub use super::fsproto::{
                Attr, ReaddirEntry, SetAttr, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ELOOP, EMLINK, ENAMETOOLONG, ENOENT, ENOSPC,
                ENOTDIR, ENOTEMPTY, EPERM, EXDEV,
            };
            pub type ZplResult<T> = Result<T, i64>;
        }
        pub use crate::fake::zfs_server::{with_server, ZfsServer};
    }
}

pub mod compat {
    pub mod linux {
        // ---------------------------------------------------------- under test
        #[path = "../../../../../src/compat/linux/acl.rs"]
        pub mod acl;
        #[path = "../../../../../src/compat/linux/aio.rs"]
        pub mod aio;
        #[path = "../../../../../src/compat/linux/efivars.rs"]
        pub mod efivars;
        #[path = "../../../../../src/compat/linux/fanotify.rs"]
        pub mod fanotify;
        #[path = "../../../../../src/compat/linux/fs.rs"]
        pub mod fs;
        #[path = "../../../../../src/compat/linux/fuse.rs"]
        pub mod fuse;
        // wave9 G6b-2: FUSE inodes of vfs-server's (stub: no vfs-server on the host)
        #[path = "../../../../host-w9-fuse/stub/fuse_svc.rs"]
        pub mod fuse_svc;
        #[path = "../../../../../src/compat/linux/inotify.rs"]
        pub mod inotify;
        #[path = "../../../../../src/compat/linux/live.rs"]
        pub mod live;
        #[path = "../../../../../src/compat/linux/locks.rs"]
        pub mod locks;
        #[path = "../../../../../src/compat/linux/mount.rs"]
        pub mod mount;
        // wave8 GF: the table format mount.rs exchanges with vfs-server
        #[path = "../../../../../src/compat/linux/mntrec.rs"]
        pub mod mntrec;
        #[path = "../../../../../src/compat/linux/recent.rs"]
        pub mod recent;
        #[path = "../../../../../src/compat/linux/vfs.rs"]
        pub mod vfs;
        #[path = "../../../../../src/compat/linux/xfer.rs"]
        pub mod xfer;

        // -------------------------------------------------------- real helpers
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        // --------------------------------------------------------------- stubs
        pub use crate::fake::linux::*;
    }
}
