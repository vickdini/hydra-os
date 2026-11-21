//! Group 7-7's host build of vfs-server's `kmounts.rs` (the copy of the kernel's mount tables
//! the calls walk with) together with the walk, caches and permissions it works with
//! (`userland/drivers/vfs-server/src`), compiled from their own sources through `#[path]`
//! under the program's module names, so `crate::` references resolve unchanged. The tests
//! are unit tests of this crate (`cfg(test)`: `kmounts::pull` is the host stand-in there).
//! The fake file system is Group 7-1's (`tests/host-w7-71/src/fake.rs`).

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (service ids, `LxCall`, `LxMntRec`).
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

/// *stub* The calls' "redirect to the kernel" answer (`calls::rules::KERNEL`).
pub mod calls {
    pub const KERNEL: i64 = i64::MIN;
}

#[path = "../../../userland/drivers/vfs-server/src/cache.rs"]
pub mod cache;
#[path = "../../../userland/drivers/vfs-server/src/ctx.rs"]
pub mod ctx;
#[path = "../../../userland/drivers/vfs-server/src/kmounts.rs"]
pub mod kmounts;
#[path = "../../../userland/drivers/vfs-server/src/perm.rs"]
pub mod perm;
#[path = "../../../userland/drivers/vfs-server/src/walk.rs"]
pub mod walk;

#[path = "../../host-w7-71/src/fake.rs"]
pub mod fake;

#[cfg(test)]
mod tests;
