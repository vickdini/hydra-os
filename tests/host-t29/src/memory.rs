//! `crate::memory`: the real frame allocator and VM code; paging stubbed.

#[path = "../../../src/memory/frame_allocator.rs"]
pub mod frame_allocator;

#[path = "../../../src/memory/vm.rs"]
pub mod vm;

/// *stub*
pub mod paging {
    pub use crate::fake::{make_user_accessible, AddressSpace};
    pub static KERNEL_SPACE: spin::Mutex<Option<AddressSpace>> = spin::Mutex::new(None);
}
