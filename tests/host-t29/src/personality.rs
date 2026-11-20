//! The personality hook: its pure tables (`abi.rs`) and a recorded current personality.

#[path = "../../../src/personality/abi.rs"]
pub mod abi;

use crate::task::TaskPersonality;

/// *stub* A frame builder of another personality.
pub type FrameFn = fn(
    &mut crate::compat::linux::proc::UserRegs,
    &crate::arch::idt::FpuState,
    u32,
    &crate::compat::linux::proc::SigAction,
    u64,
    u16,
) -> bool;
/// *stub* Host tasks are Linux tasks: Linux's frame.
pub fn frame_builder() -> Option<FrameFn> {
    None
}
/// *mirror* of the kernel's choice (FreeBSD binaries run as FreeBSD; macOS not served).
pub fn choose(head: &[u8], _path: &str) -> Result<TaskPersonality, i64> {
    match abi::classify(head) {
        abi::Kind::Linux => Ok(TaskPersonality::Linux),
        abi::Kind::FreeBsd => Ok(TaskPersonality::FreeBsd),
        _ => Err(-8), // ENOEXEC
    }
}
/// *stub* Recorded.
pub fn set_current(p: TaskPersonality) {
    crate::fake::rec(alloc::format!("personality::set_current({})", p.as_str()));
}
/// *mirror* of the kernel's check (without its log line).
pub fn interp_agrees(pers: TaskPersonality, interp_head: &[u8], _interp: &str) -> bool {
    let k = abi::classify(interp_head);
    match pers {
        TaskPersonality::FreeBsd => k == abi::Kind::FreeBsd,
        _ => k == abi::Kind::Linux,
    }
}
