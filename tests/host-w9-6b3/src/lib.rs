//! Group 6b-3's host build of vfs-server's Landlock decisions
//! (`userland/drivers/vfs-server/src/policy/ll.rs`), compiled from its own source. The glue
//! around it (`policy/mod.rs`: domain copies, parent chains, the kernel's ABAC answers)
//! needs the kernel and is tested in QEMU (`tests/linux/landlock_test.c`, `abac_test.c`).

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/policy/ll.rs"]
pub mod ll;
