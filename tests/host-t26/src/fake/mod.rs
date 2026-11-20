//! Host stand-ins for everything the Linux file layer calls outside its own files.
//!
//! State lives in thread-locals (each test runs on its own thread) and in a few globals.
//! The kernel files under test keep global tables of their own (locks, mount namespaces,
//! FUSE connections, fanotify groups...), so every test starts with [`setup`], which takes a
//! process-wide lock (tests run one at a time) and resets the fakes: a fresh in-memory pool
//! ([`memfs`]), a root task with every capability and an empty descriptor table.
//!
//! Hooks let a test play the parts of other threads: [`task::wait::on_wait`] runs when the
//! code under test would sleep (a FUSE daemon answering, a lock holder letting go), and
//! [`linux::set_nested`] answers the nested system calls of `xfer`, `aio` and `recent`.

use std::cell::RefCell;
use std::collections::BTreeMap;

pub mod arch;
pub mod fd;
pub mod firmware;
pub mod linux;
pub mod lx;
pub mod memfs;
pub mod memory;
pub mod task;
pub mod zfs_client;
pub mod zfs_server;

thread_local! {
    static COUNTERS: RefCell<BTreeMap<&'static str, u64>> = const { RefCell::new(BTreeMap::new()) };
}

/// Counts an event a stub saw (read back with [`counter`]).
pub fn count(name: &'static str) {
    COUNTERS.with_borrow_mut(|c| *c.entry(name).or_insert(0) += 1);
}

/// How often [`count`] was called with `name` since the last [`setup`].
pub fn counter(name: &'static str) -> u64 {
    COUNTERS.with_borrow(|c| c.get(name).copied().unwrap_or(0))
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A test's hold on the fakes (tests run one at a time while it lives).
pub struct Env {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Env {
    fn drop(&mut self) {
        // Descriptors close (and their objects drop) before the next test starts
        task::clear_tasks();
    }
}

/// Starts a test: serialises it against the others and resets every fake.
pub fn setup() -> Env {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    forget_kernel_state();
    COUNTERS.with_borrow_mut(|c| c.clear());
    arch::reset();
    memory::reset();
    memfs::reset();
    zfs_server::reset();
    linux::reset();
    lx::reset();
    task::reset();
    firmware::reset();
    Env { _guard: guard }
}

/// Clears what earlier tests left in the kernel files' global tables (through their own
/// calls), so each test starts from an empty system.
fn forget_kernel_state() {
    use crate::compat::linux as lx;
    for m in lx::fuse::ns0_snapshot() {
        lx::fuse::ns0_remove(m.conn.root());
    }
    lx::locks::process_exited(task::SELF_PID);
    lx::aio::forget_process(task::SELF_PID);
}

/// A NUL-terminated copy of `s` that stays alive for the test: its address is a "user
/// pointer" (user memory is host memory here).
pub fn cstr(s: &str) -> u64 {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    leak(v)
}

/// Keeps `v` alive for the rest of the test binary; returns its address.
pub fn leak(v: Vec<u8>) -> u64 {
    let b = v.into_boxed_slice();
    Box::leak(b).as_mut_ptr() as u64
}

/// A zeroed buffer of `n` bytes at a stable address (user memory for results).
pub fn buf(n: usize) -> u64 {
    leak(vec![0u8; n.max(1)])
}

/// Reads `n` bytes at user address `p`.
pub fn read(p: u64, n: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(p as *const u8, n).to_vec() }
}

/// Writes `data` at user address `p`.
pub fn write(p: u64, data: &[u8]) {
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), p as *mut u8, data.len()) }
}

/// The little-endian u64 at user address `p`.
pub fn read_u64(p: u64) -> u64 {
    u64::from_le_bytes(read(p, 8).try_into().unwrap())
}

/// The little-endian u32 at user address `p`.
pub fn read_u32(p: u64) -> u32 {
    u32::from_le_bytes(read(p, 4).try_into().unwrap())
}

/// The little-endian i32 at user address `p`.
pub fn read_i32(p: u64) -> i32 {
    i32::from_le_bytes(read(p, 4).try_into().unwrap())
}
