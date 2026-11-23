//! hydra-rt's kept-state format (`hydra-rt/src/kept.rs`, plain `core`) under the crate name
//! the service files use, with *stubs* for the system calls `arena.rs` and `kstore.rs`
//! make (no kernel on the host).

#![allow(dead_code)]

/// *stub* the runtime's log line: standard output.
#[macro_export]
macro_rules! println {
    ($($t:tt)*) => { std::println!($($t)*) };
}

#[path = "../../../userland/drivers/hydra-rt/src/kept.rs"]
pub mod kept;

/// *stub* the protocol numbers `kstore.rs` uses (values as in `src/ipc/protocol.rs`).
pub mod protocol {
    pub const LX_CALL_RESEND_OFF: usize = 0x1F8;
    pub const LX_CALL_PARTIAL_OFF: usize = 0x1E8;
    pub const LX_OBJ_PARTIAL: u64 = 71;
}

/// *stub* the system calls: `lx_obj` records what it was asked.
pub mod sys {
    use std::sync::Mutex;
    pub static CALLS: Mutex<Vec<(u64, u64, u64, u64)>> = Mutex::new(Vec::new());
    pub fn lx_obj(op: u64, a: u64, b: u64, c: u64) -> Result<u64, i64> {
        CALLS.lock().unwrap().push((op, a, b, c));
        Ok(0)
    }
}

/// *stub* memory objects: none on the host (the arena of the process stays empty).
pub mod mem {
    pub const PROT_RW: u32 = 3;
    pub struct MemObj;
    impl MemObj {
        pub fn anon(_size: u64) -> Result<MemObj, i64> {
            Err(-12)
        }
        pub fn map(&self, _o: u64, _l: u64, _p: u32) -> Result<*mut u8, i64> {
            Err(-12)
        }
        pub fn into_raw(self) -> u32 {
            0
        }
    }
}
