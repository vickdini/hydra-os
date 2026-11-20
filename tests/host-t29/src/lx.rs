//! *stub* `crate::lx`: the forwarding to the ring-3 Linux server. Notes and calls are
//! recorded; nothing is forwarded.

use crate::arch::syscall::SyscallFrame;

/// *stub* A notification for the Linux server (recorded).
pub fn note(kind: u64, a: u64, b: u64, c: u64) {
    crate::fake::rec(alloc::format!("lx::note({kind},{a},{b},{c})"));
}
/// *stub* Nothing is forwarded unless a test sets `fake::LX_FORWARD`.
pub fn forward(frame: &SyscallFrame) -> Option<i64> {
    crate::fake::LX_FORWARD.with_borrow(|m| m.get(&frame.rax).copied())
}
pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    crate::fake::rec(alloc::format!("lx::call_plain({nr},{:?})", args));
    crate::fake::ret("lx::call_plain")
}
pub fn step4() -> bool {
    false
}
pub fn summary() -> alloc::string::String {
    alloc::string::String::new()
}
pub mod mem {
    pub fn server_mmap(
        _dev: &alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>,
        _args: [u64; 6],
    ) -> Result<(alloc::sync::Arc<dyn crate::memory::vm::MappedObject>, i64, u64), i64> {
        Err(-19) // ENODEV
    }
}
pub mod obj {
    pub struct ServerObject;
    impl ServerObject {
        pub fn kind(&self) -> u32 {
            0
        }
        pub fn tag(&self) -> u64 {
            0
        }
    }
}
