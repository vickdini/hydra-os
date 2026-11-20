//! Helpers shared by the test binaries.

#![allow(dead_code)]

pub use hydra_hosttests_t27::fake;

/// Serialises tests that share global state (the interval and POSIX timer tables, which a
/// daemon scans whole). A failed test poisons the lock; later tests still run.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs `f`, expecting the fake's "would block" panic.
pub fn blocks<R>(f: impl FnOnce() -> R) -> bool {
    fake::quiet_expected_panics();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match r {
        Ok(_) => false,
        Err(e) => {
            let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            assert!(msg.contains(fake::wait::WOULD_BLOCK), "unexpected panic: {msg}");
            true
        }
    }
}

/// The address of a value, as a user pointer.
pub fn ptr<T>(v: &T) -> u64 {
    v as *const T as u64
}

/// The address of a mutable value, as a user pointer.
pub fn mptr<T>(v: &mut T) -> u64 {
    v as *mut T as u64
}

/// A `struct timespec` / `timeval` pair.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Pair(pub i64, pub i64);

/// A `struct itimerspec` / `itimerval` (interval, value).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Spec {
    pub interval: Pair,
    pub value: Pair,
}

impl Spec {
    pub fn new(isec: i64, insub: i64, vsec: i64, vsub: i64) -> Spec {
        Spec { interval: Pair(isec, insub), value: Pair(vsec, vsub) }
    }
}

pub const MS: i64 = 1_000_000;
