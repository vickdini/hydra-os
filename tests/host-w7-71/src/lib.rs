//! Group 7-1's host build of vfs-server's logic: the path walk, the caches, the permission
//! checks and the boot mount table (in `walk.rs`) (`userland/drivers/vfs-server/src`), compiled from their
//! own sources through `#[path]` under the module names the program uses, so `crate::`
//! references resolve unchanged. The zfs-server client and the service glue (`zfs.rs`,
//! `be.rs`, `main.rs`) need the kernel and are tested in QEMU (`tests/linux/vfswalk.c`).
//! [`fake`] is an in-memory file system implementing the walk's `Backend`.

#![allow(dead_code)]

extern crate alloc;

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

/// A plain spin lock of the program's `YLock` shape (the program's yields to the kernel).
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

#[path = "../../../userland/drivers/vfs-server/src/cache.rs"]
pub mod cache;
#[path = "../../../userland/drivers/vfs-server/src/ctx.rs"]
pub mod ctx;
#[path = "../../../userland/drivers/vfs-server/src/perm.rs"]
pub mod perm;
#[path = "../../../userland/drivers/vfs-server/src/walk.rs"]
pub mod walk;

pub mod fake;
