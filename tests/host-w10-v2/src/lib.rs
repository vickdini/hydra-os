//! Group V2's host build (wave 10): vfs-server's walk with its new path record (`walk.rs`,
//! `walk::Track`) and served-name hook on the fake file system of Group 7-1's tests, the
//! names other services serve in `/sys` and `/dev` (`calls/served.rs`), the trees `statfs`
//! shows (the kernel's `src/lx/fstree.rs`, shared with vfs-server) and tty-server's
//! `/dev/pts` names (`devpts.rs`), compiled from their own sources through `#[path]` under
//! the module names the programs use. The calls themselves are tested in QEMU (`devwalk`).

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

#[path = "../../../userland/drivers/vfs-server/src/cache.rs"]
pub mod cache;
#[path = "../../../userland/drivers/vfs-server/src/ctx.rs"]
pub mod ctx;
#[path = "../../../userland/drivers/vfs-server/src/perm.rs"]
pub mod perm;
#[path = "../../../userland/drivers/vfs-server/src/walk.rs"]
pub mod walk;
#[path = "../../host-w7-71/src/fake.rs"]
pub mod fake;

/// vfs-server's served names.
pub mod calls {
    #[path = "../../../../userland/drivers/vfs-server/src/calls/served.rs"]
    pub mod served;
}

/// The kernel's tree rules (shared with vfs-server).
#[path = "../../../src/lx/fstree.rs"]
pub mod fstree;

/// tty-server's `/dev/pts` names.
#[path = "../../../userland/drivers/tty-server/src/devpts.rs"]
pub mod devpts;
