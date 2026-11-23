//! Group V1's host build (wave 10) of vfs-server's change-call decisions: `calls/acl.rs`
//! (POSIX ACL creation, chmod and set rules on the xattr bytes) and the new parts of
//! `calls/rules.rs` (times, xattr namespaces, which opens are served), compiled from their
//! own sources through `#[path]` under the module names the program uses. The calls
//! themselves (walks, zfs-server, the kernel's handles) are tested in QEMU (`vfschange`).

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (`LxCall`, `LxFhDesc`, the `LX_*` constants).
#[path = "../../../src/ipc/protocol.rs"]
pub mod proto;

/// The file calls' pure modules.
pub mod calls {
    #[path = "../../../../userland/drivers/vfs-server/src/calls/acl.rs"]
    pub mod acl;
    #[path = "../../../../userland/drivers/vfs-server/src/calls/rules.rs"]
    pub mod rules;
}
