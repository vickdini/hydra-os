//! Group 7-2's host build of vfs-server's file calls (`userland/drivers/vfs-server/src/calls`):
//! the parts that depend only on their inputs (`enc.rs`: the result layouts; `rules.rs`: the
//! calls' decisions), compiled from their own sources through `#[path]` under the module
//! names the program uses, so `crate::` references resolve unchanged. The rest of the calls
//! (the walk, the zfs-server client, the kernel primitives) is tested in QEMU.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (`LxCall`, `LxFhDesc`, the `LX_*` constants).
#[path = "../../../src/ipc/protocol.rs"]
pub mod proto;

/// The ZFS request protocol (attributes, directory entries) and the on-disk types it uses.
pub mod fs {
    #[path = "../../../../src/fs/zfs/types.rs"]
    pub mod types;
    #[path = "../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
}

/// The file calls' pure modules.
pub mod calls {
    #[path = "../../../../userland/drivers/vfs-server/src/calls/enc.rs"]
    pub mod enc;
    #[path = "../../../../userland/drivers/vfs-server/src/calls/rules.rs"]
    pub mod rules;
}
