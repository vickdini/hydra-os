//! Host build of zfs-server's intent log (wave 8, Group Z).
//!
//! The server's own ZFS code (`zfs/*`, `client.rs`, `serve.rs`, `frames.rs`, `events.rs`),
//! the log format (`zil.rs`) and its glue (`durable.rs`), compiled through `#[path]` at the
//! module paths the server uses, with the few things the server gets from `hydra-rt` given
//! here: no disk driver (the pool is a RAM disk the tests keep across a simulated kill), a
//! clock the tests set. The tests are in `zil_tests.rs` (the format) and `replay_tests.rs`
//! (requests, kill, re-import, replay).

#![allow(dead_code, unused_imports, clippy::all)]

extern crate alloc;

/// The ZFS sources' `println!` (quiet unless `ZIL_VERBOSE` is set).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let s = alloc::format!($($arg)*);
        if std::env::var_os("ZIL_VERBOSE").is_some() {
            std::println!("{}", s);
        }
    }};
}

/// The ZFS sources' `kprintln!`.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => { $crate::println!($($arg)*) };
}

/// The OpenZFS implementation (zfs-server's).
pub mod zfs {
    #[path = "../../../../src/fs/zfs/types.rs"]
    pub mod types;
    #[path = "../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/dmu.rs"]
    pub mod dmu;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/selftest.rs"]
    pub mod selftest;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/server.rs"]
    pub mod server;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/spa.rs"]
    pub mod spa;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/zap.rs"]
    pub mod zap;
    #[path = "../../../../userland/drivers/zfs-server/src/zfs/zpl.rs"]
    pub mod zpl;
}

pub mod fs {
    #[path = "../../../../userland/drivers/zfs-server/src/client.rs"]
    pub mod client;
}

#[path = "../../../userland/drivers/zfs-server/src/serve.rs"]
pub mod serve;
#[path = "../../../userland/drivers/zfs-server/src/zil.rs"]
pub mod zil;
#[path = "../../../userland/drivers/zfs-server/src/durable.rs"]
pub mod durable;

pub mod memory {
    #[path = "../../../../userland/drivers/zfs-server/src/frames.rs"]
    pub mod frame_allocator;
}

pub mod compat {
    pub mod linux {
        #[path = "../../../../../userland/drivers/zfs-server/src/events.rs"]
        pub mod inotify;
    }
}

/// The clock: the request's frozen time, or the tests' clock (advanced by hand).
pub mod arch {
    pub mod rtc {
        use core::sync::atomic::{AtomicU64, Ordering};

        /// The tests' clock in nanoseconds.
        pub static CLOCK_NS: AtomicU64 = AtomicU64::new(1_700_000_000_000_000_000);

        /// The real clock as the server reads it (`hydra_rt::sys::clock`): moves 1 µs per read.
        pub fn real() -> (u64, u32) {
            let ns = CLOCK_NS.fetch_add(1000, Ordering::Relaxed);
            (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
        }

        pub fn now() -> (u64, u32) {
            crate::durable::frozen().unwrap_or_else(real)
        }
    }
}

/// No disk driver on the host: the pool is a RAM disk.
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;

    #[derive(Clone, Copy, Debug)]
    pub struct Message {
        pub label: u32,
        pub args: [u64; 4],
    }

    impl Message {
        pub fn new(label: u32) -> Self {
            Self { label, args: [0; 4] }
        }

        pub fn with_args(label: u32, args: [u64; 4]) -> Self {
            Self { label, args }
        }
    }

    pub mod service {
        use super::Message;

        pub const WINDOW_PAGES: u64 = 64;
        pub const WINDOW_SIZE: usize = (WINDOW_PAGES * 4096) as usize;
        pub const CALL_TIMEOUT_TICKS: u64 = 500;

        pub fn is_online(_endpoint: u32) -> bool {
            false
        }

        pub fn window(_endpoint: u32) -> Option<&'static mut [u8]> {
            None
        }

        pub fn call(_endpoint: u32, _request: Message, _timeout_ticks: u64) -> Result<Message, i64> {
            Err(-5)
        }

        pub fn call_grant(_endpoint: u32, _request: Message, _timeout_ticks: u64, _addr: u64, _len: u64, _server_writes: bool) -> Result<Message, i64> {
            Err(-5)
        }
    }
}

pub mod task {
    pub mod supervisor {
        pub fn revive(_endpoint: u32) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod zil_tests;
#[cfg(test)]
mod replay_tests;
