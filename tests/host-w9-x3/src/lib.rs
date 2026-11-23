//! Group X3's host build (wave 9): lx-ipc's kept data arena (`lx-ipc/src/arena.rs`: the
//! allocator, chains of segments, their images and restore with every check) and its kept
//! records (`lx-ipc/src/kstore.rs`: ids, records across a "restart", the byte image),
//! compiled from their own sources through `#[path]` at the module paths the service uses.
//! The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/lx-ipc/src/arena.rs"]
pub mod arena;
#[path = "../../../userland/drivers/lx-ipc/src/kstore.rs"]
pub mod kstore;

/// *stub* linux-server's yielding lock (`lock.rs` yields through a system call): a spin
/// lock with the same interface.
pub mod lock {
    pub struct YLock<T> {
        inner: spin::Mutex<T>,
    }

    impl<T> YLock<T> {
        pub const fn new(v: T) -> Self {
            Self { inner: spin::Mutex::new(v) }
        }

        pub fn lock(&self) -> spin::MutexGuard<'_, T> {
            self.inner.lock()
        }
    }
}

#[cfg(test)]
mod tests;
