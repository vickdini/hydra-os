//! Group 7-5's host build: linux-server's `execplan.rs` (the `#!` line, `PT_INTERP`, the
//! argv of scripts, the plan's bytes), the kernel's `lx/xplan.rs` (the plan decoded) and
//! vfs-server's `xpath.rs` (the path `/proc/self/exe` shows), each compiled from its own
//! source through `#[path]`. vfs-server's walk, context and fake file system come from
//! Group 7-1's crate (`tests/host-w7-71`), under the module names the program uses.

#![allow(dead_code)]

extern crate alloc;

pub use hydra_hosttests_w7_71::{ctx, fake, fs, walk};

#[path = "../../../userland/drivers/linux-server/src/execplan.rs"]
pub mod execplan;
#[path = "../../../src/lx/xplan.rs"]
pub mod xplan;
#[path = "../../../userland/drivers/vfs-server/src/xpath.rs"]
pub mod xpath;
