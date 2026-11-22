//! Group X2's host build (wave 8): lx-net's kept records (`lx-net/src/sockkept.rs`: the
//! record store over `hydra_rt::kept`, the Internet and netlink socket records) and the
//! socket options saved in them (`lx-net/src/sockopt.rs`), compiled from their own sources
//! through `#[path]` at the module paths the service uses. The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/lx-net/src/sockkept.rs"]
pub mod sockkept;
#[path = "../../../userland/drivers/lx-net/src/sockopt.rs"]
pub mod sockopt;

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
