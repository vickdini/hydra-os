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

/// File-server requests by operation (`FS_*` code minus 0x3100): count and round-trip time.
const FS_OPS: usize = 64;
static FS_CALLS: [AtomicU64; FS_OPS] = [const { AtomicU64::new(0) }; FS_OPS];
static FS_NANOS: [AtomicU64; FS_OPS] = [const { AtomicU64::new(0) }; FS_OPS];
const FS_NAMES: [&str; 0x24] = [
    "?", "root", "lookup", "resolve", "getattr", "setattr", "read", "write", "create", "mknod", "mkdir", "symlink",
    "readlink", "link", "unlink", "rmdir", "rename", "readdir", "statfs", "open_ref", "release", "notify", "sync",
    "sync_if_dirty", "snapshot", "pool_status", "object_info", "datasets", "selftest", "verify", "fsck",
    "resolve_mnt", "getxattr", "setxattr", "listxattr", "removexattr",
];

/// Records a file-server request `op` (an `FS_*` code) started at `t0` (from [`start`]).
#[inline]
pub fn fs_request(op: u32, t0: u64) {
    let i = op.wrapping_sub(0x3100) as usize;
    if t0 != 0 && i < FS_OPS {
        FS_CALLS[i].fetch_add(1, Relaxed);
        FS_NANOS[i].fetch_add(crate::arch::pit::now_ns().saturating_sub(t0), Relaxed);
    }
}

/// The task whose user-mode instruction pointer is sampled at each timer tick (0: none),
/// and the samples (a ring of the last [`SAMPLES`]).
pub static SAMPLE_TASK: AtomicU64 = AtomicU64::new(0);
const SAMPLES: usize = 16384;
static SAMPLE_AT: AtomicU64 = AtomicU64::new(0);
static SAMPLE_RIP: [AtomicU64; SAMPLES] = [const { AtomicU64::new(0) }; SAMPLES];

/// Records a tick that interrupted task `task` at `rip` (user mode only).
#[inline]
pub fn sample(task: u64, rip: u64, cs: u64) {
    let want = SAMPLE_TASK.load(Relaxed);
    if want != 0 && want == task && cs & 3 == 3 {
        let i = SAMPLE_AT.fetch_add(1, Relaxed) as usize % SAMPLES;
        SAMPLE_RIP[i].store(rip, Relaxed);
    }
}

/// Starts sampling `task` (0 stops), clearing earlier samples.
pub fn sample_start(task: u64) {
    SAMPLE_AT.store(0, Relaxed);
    SAMPLE_TASK.store(task, Relaxed);
}

/// Prints the sampled instruction pointers, most frequent first (`top` of them).
pub fn sample_show(top: usize) {
    let n = (SAMPLE_AT.load(Relaxed) as usize).min(SAMPLES);
    let mut rips: alloc::vec::Vec<u64> = (0..n).map(|i| SAMPLE_RIP[i].load(Relaxed)).collect();
    rips.sort_unstable();
    let mut counts: alloc::vec::Vec<(usize, u64)> = alloc::vec::Vec::new();
    for r in rips {
        match counts.last_mut() {
            Some((c, x)) if *x == r => *c += 1,
            _ => counts.push((1, r)),
        }
    }
    counts.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    crate::println!("[sample] {} samples of task {}", n, SAMPLE_TASK.load(Relaxed));
    for (c, r) in counts.into_iter().take(top) {
        crate::println!("[sample] {:>6} {:#x}", c, r);
    }
}

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
    for i in 0..FS_OPS {
        FS_CALLS[i].store(0, Relaxed);
        FS_NANOS[i].store(0, Relaxed);
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
    crate::println!("[prof] file-server requests (round trip, from the kernel):");
    for i in 0..FS_OPS {
        let n = FS_CALLS[i].load(Relaxed);
        if n > 0 {
            let ns = FS_NANOS[i].load(Relaxed);
            crate::println!("[prof]   {:>9} {:>9} ms {:>7} us/each  {}", n, ns / 1_000_000, ns / n / 1000, FS_NAMES.get(i).copied().unwrap_or("?"));
        }
    }
    let mut rows: alloc::vec::Vec<(u64, u64, usize)> =
        (0..NR_MAX).map(|i| (NANOS[i].load(Relaxed), CALLS[i].load(Relaxed), i)).filter(|r| r.1 > 0).collect();
    rows.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    crate::println!("[prof] system calls by total time (blocking calls include their waits):");
    for (ns, n, nr) in rows.into_iter().take(top) {
        crate::println!("[prof]   nr {:>3} {:>9} calls {:>9} ms {:>7} us/each", nr, n, ns / 1_000_000, ns / n / 1000);
    }
}
