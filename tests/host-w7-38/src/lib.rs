//! Host build of vfs-server's mount tables and tmpfs (wave 7, Group 7-3).
//!
//! The server's files are compiled through `#[path]` at the module paths the server uses:
//! `mtab.rs` and `tmpfs.rs` (pure: `core` and `alloc` only), and for the walk over the
//! tables also `mount.rs` with Group 7-1's `walk.rs`, `ctx.rs`, `perm.rs` and the kernel's
//! protocol files; `lock` is a plain spin lock of the program's `YLock` shape. The tests
//! are in `mount_tests.rs`, `tmpfs_tests.rs` and `walk_tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/mtab.rs"]
pub mod mtab;
#[path = "../../../userland/drivers/vfs-server/src/tmpfs.rs"]
pub mod tmpfs;

/// The kernel's protocol (service ids, `LxCall`).
#[path = "../../../src/ipc/protocol.rs"]
pub mod proto;

/// The ZFS request protocol (attributes) and the on-disk types it uses.
pub mod fs {
    #[path = "../../../../src/fs/zfs/types.rs"]
    pub mod types;
    #[path = "../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
}

/// A plain spin lock of the program's `YLock` shape.
pub mod lock {
    pub struct YLock<T> {
        inner: spin::Mutex<T>,
    }
    impl<T> YLock<T> {
        pub const fn new(v: T) -> Self {
            Self { inner: spin::Mutex::new(v) }
        }
        pub fn lock(&self) -> spin::MutexGuard<'_, T> {
            self.inner.lock()
        }
    }
}

#[path = "../../../userland/drivers/vfs-server/src/ctx.rs"]
pub mod ctx;
#[path = "../../../userland/drivers/vfs-server/src/perm.rs"]
pub mod perm;
#[path = "../../../userland/drivers/vfs-server/src/walk.rs"]
pub mod walk;
#[path = "../../../userland/drivers/vfs-server/src/mount.rs"]
pub mod mount;

#[cfg(test)]
mod mount_tests;
#[cfg(test)]
mod walk_tests;
#[cfg(test)]
mod tmpfs_tests;
