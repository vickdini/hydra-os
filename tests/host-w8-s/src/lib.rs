//! Group S's host build (wave 8): sound-server's `params.rs` (the `HW_REFINE` negotiation)
//! and `pcm.rs` (the PCM state machine and the mixer, driven through a fake controller in
//! the tests), and the kernel's `ipc/sound_page.rs` (the status page `/proc/asound` reads),
//! each compiled from its own source through `#[path]`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/sound-server/src/params.rs"]
pub mod params;
#[path = "../../../userland/drivers/sound-server/src/pcm.rs"]
pub mod pcm;

/// The kernel's `ipc` files, under the module path they use (`crate::ipc::protocol`).
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    #[allow(clippy::all)]
    pub mod protocol;
    #[path = "../../../../src/ipc/sound_page.rs"]
    pub mod sound_page;
}
