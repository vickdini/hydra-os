//! Host build of Group D's code (wave 8, the display service).
//!
//! Compiled through `#[path]` at the module paths the code uses:
//! - the kernel's screen-owner decisions, `src/ipc/screen/policy.rs` (as `ipc::screen::policy`,
//!   with the kernel's protocol as `ipc::protocol`);
//! - display-server's native core (`native.rs`) and Linux DRM layer (`kms.rs`), with the
//!   protocol as `proto`.
//!
//! The DRM layer runs against a fake caller ([`fakes::FakeEnv`]: "user pointers" are host
//! pointers) and a fake screen ([`fakes::FakeScreen`]: memory, a settable state and clock).

#![allow(dead_code)]

extern crate alloc;

pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    pub mod screen {
        #[path = "../../../../../src/ipc/screen/policy.rs"]
        pub mod policy;
    }
}

/// display-server's view of the protocol.
pub mod proto {
    pub use crate::ipc::protocol::*;
}

#[path = "../../../userland/drivers/display-server/src/native.rs"]
pub mod native;
#[path = "../../../userland/drivers/display-server/src/kms.rs"]
pub mod kms;

pub mod fakes;

#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod kms_tests;
