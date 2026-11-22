//! Group T's host build (wave 8): tty-server's line discipline (`ldisc.rs`) and its table of
//! terminals (`ttys.rs`: pseudo-terminal pairs, the console terminal, waiting calls,
//! hang-ups), and the encodings of the kernel's `src/lx/console.rs` (its kernel glue is
//! `cfg(target_os = "uefi")`), each compiled from its own source through `#[path]` under the
//! module names they use.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol, where the kernel's files find it.
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

/// tty-server's name for it (`crate::proto`).
pub use ipc::protocol as proto;

#[path = "../../../userland/drivers/tty-server/src/ldisc.rs"]
pub mod ldisc;
#[path = "../../../userland/drivers/tty-server/src/ttys.rs"]
pub mod ttys;

/// The kernel's `src/lx` file under test.
pub mod lx {
    #[path = "../../../../src/lx/console.rs"]
    pub mod console;
}
