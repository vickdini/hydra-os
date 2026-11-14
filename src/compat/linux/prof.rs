//! Kernel-side profile of Linux programs: how often each system call runs and how long it
//! takes, and how long page faults take by kind. Off until `linux prof on`; when off, each
//! hook costs one relaxed load.
//!
//! Times include waiting (a `futex` wait counts its whole wait), so blocking calls show
//! large totals by nature; the calls that never block are the ones whose time is the
//! kernel's own cost.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// Whether the hooks record anything.
pub static ON: AtomicBool = AtomicBool::new(false);

/// Linux x86-64 system call numbers below this are counted one by one.
const NR_MAX: usize = 512;

/// Calls and nanoseconds per system call number.
static CALLS: [AtomicU64; NR_MAX] = [const { AtomicU64::new(0) }; NR_MAX];
static NANOS: [AtomicU64; NR_MAX] = [const { AtomicU64::new(0) }; NR_MAX];

/// Page fault kinds: a page already present (copy-on-write or a permission upgrade), a
/// new zero page, a page of a mapped object (a file, memfd, ...), and faults that failed
/// (signals). `FILE_READ` is not a fault: it is each page a mapped file reads from the
/// pool on a cache miss, inside an object fault or for the loader.
/// A fault on a page already present.
pub const FAULT_PRESENT: usize = 0;
/// A fault that maps a new zero page.
pub const FAULT_ANON: usize = 1;
/// A fault on a mapped object's page.
pub const FAULT_OBJECT: usize = 2;
/// A fault that failed.
pub const FAULT_FAILED: usize = 3;
/// A mapped file's page read from the pool.
pub const FILE_READ: usize = 4;
const FAULT_KINDS: usize = 5;
const FAULT_NAMES: [&str; FAULT_KINDS] =
    ["fault: present (CoW/upgrade)", "fault: anonymous (zero page)", "fault: mapped object", "fault: failed", "mapped file page read from the pool"];
static FAULTS: [AtomicU64; FAULT_KINDS] = [const { AtomicU64::new(0) }; FAULT_KINDS];
static FAULT_NANOS: [AtomicU64; FAULT_KINDS] = [const { AtomicU64::new(0) }; FAULT_KINDS];

/// Start time for a hook, or 0 when profiling is off.
#[inline]
pub fn start() -> u64 {
    if ON.load(Relaxed) { crate::arch::pit::now_ns().max(1) } else { 0 }
}

/// Records system call `nr` started at `t0` (from [`start`]).
#[inline]
pub fn syscall(nr: u64, t0: u64) {
    if t0 != 0 && (nr as usize) < NR_MAX {
        CALLS[nr as usize].fetch_add(1, Relaxed);
        NANOS[nr as usize].fetch_add(crate::arch::pit::now_ns().saturating_sub(t0), Relaxed);
    }
}

/// Records a page fault of `kind` started at `t0` (from [`start`]).
#[inline]
pub fn fault(kind: usize, t0: u64) {
    if t0 != 0 && kind < FAULT_KINDS {
        FAULTS[kind].fetch_add(1, Relaxed);
        FAULT_NANOS[kind].fetch_add(crate::arch::pit::now_ns().saturating_sub(t0), Relaxed);
    }
}

/// Clears every counter.
pub fn reset() {
    for i in 0..NR_MAX {
        CALLS[i].store(0, Relaxed);
        NANOS[i].store(0, Relaxed);
    }
    for i in 0..FAULT_KINDS {
        FAULTS[i].store(0, Relaxed);
        FAULT_NANOS[i].store(0, Relaxed);
    }
}

/// Prints the page faults by kind and the `top` system calls by total time.
pub fn show(top: usize) {
    crate::println!("[prof] page faults:");
    for k in 0..FAULT_KINDS {
        let n = FAULTS[k].load(Relaxed);
        let ns = FAULT_NANOS[k].load(Relaxed);
        crate::println!("[prof]   {:>9} {:>9} ms {:>7} us/each  {}", n, ns / 1_000_000, if n > 0 { ns / n / 1000 } else { 0 }, FAULT_NAMES[k]);
    }
    let mut rows: alloc::vec::Vec<(u64, u64, usize)> =
        (0..NR_MAX).map(|i| (NANOS[i].load(Relaxed), CALLS[i].load(Relaxed), i)).filter(|r| r.1 > 0).collect();
    rows.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    crate::println!("[prof] system calls by total time (blocking calls include their waits):");
    for (ns, n, nr) in rows.into_iter().take(top) {
        crate::println!("[prof]   nr {:>3} {:>9} calls {:>9} ms {:>7} us/each", nr, n, ns / 1_000_000, ns / n / 1000);
    }
}
