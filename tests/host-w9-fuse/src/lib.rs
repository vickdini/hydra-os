//! Group 6b-2's host build of vfs-server's FUSE wire format and connection tables
//! (`userland/drivers/vfs-server/src/fuse/wire.rs`), compiled from its own source. The
//! engine around it (`fuse/mod.rs`) needs the kernel and is tested in QEMU
//! (`tests/linux/fuse_test.c`).

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/fuse/wire.rs"]
pub mod wire;
