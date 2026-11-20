//! Group 32's host build of the kernel's `src/arch` and `src/memory` (test wave).
//!
//! Each module below compiles the kernel's own source file through `#[path]`, at the
//! module path the kernel uses, so `crate::` and `super::` references resolve unchanged.
//! The real arch and memory files see each other; everything outside those two
//! directories (scheduler, Linux layer, console, IPC...) is a *stub* here, placed at the
//! same `crate::` path and kept to what the files under test call.
//!
//! Hardware access goes to fakes: the shimmed `x86_64` crate (`shim/x86_64`: port I/O,
//! control registers, `cli`/`sti`/`hlt`, TLB flushes) and [`host`] (the kernel's own
//! `asm!` seams: `gs`, MSRs, debug registers).
//!
//! Paths inside an inline `mod` block are resolved relative to a directory named after
//! that module, hence the extra `../` per nesting level.

#![allow(dead_code, unused_imports, unused_variables, unused_mut, static_mut_refs, clippy::all)]

extern crate alloc;

pub mod host;

/// *stub* Kernel console output: kept per thread in [`stubs::LOG`].
#[macro_export]
macro_rules! println {
    () => {{
        $crate::stubs::log(alloc::string::String::new());
    }};
    ($($arg:tt)*) => {{
        $crate::stubs::log(alloc::format!($($arg)*));
    }};
}

/// *stub* Kernel log output: kept per thread in [`stubs::LOG`] so tests can check it.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        $crate::stubs::log(alloc::format!($($arg)*));
    }};
}

/// *stub* Same as `kprintln`.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::stubs::log(alloc::format!($($arg)*));
    }};
}

pub mod stubs;

/// The kernel's own `src/arch/mod.rs`: every arch file, at its kernel path.
#[path = "../../../src/arch/mod.rs"]
pub mod arch;

/// The kernel's own `src/memory/mod.rs`.
#[path = "../../../src/memory/mod.rs"]
pub mod memory;

pub mod compat {
    pub mod linux {
        pub use crate::stubs::linux::*;
    }
}

pub use stubs::{admin, console, lx, personality, task, video};

pub mod fs {
    pub use crate::stubs::fs::*;
    #[path = "../../../../src/fs/gpt.rs"]
    pub mod gpt;
}

/// The real capability and message types; the service layer is a stub.
pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    pub use crate::stubs::ipc::{endpoint, service};
    pub use message::Message;
}

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

/// *stub*
pub mod net {
    pub fn init() {
        crate::stubs::call("net::init".into());
    }
}
