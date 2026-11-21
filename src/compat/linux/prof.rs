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

/// Inter-processor interrupts sent while profiling: [wakeup kicks, others] x [count, ns
/// spent sending].
static IPI: [[AtomicU64; 2]; 2] = [const { [const { AtomicU64::new(0) }; 2] }; 2];

/// Records an inter-processor interrupt sent (`kick`: an idle CPU woken), started at `t0`
/// (from [`start`]).
#[inline]
pub fn ipi_sent(kick: bool, t0: u64) {
    if t0 != 0 {
        let k = if kick { 0 } else { 1 };
        IPI[k][0].fetch_add(1, Relaxed);
        IPI[k][1].fetch_add(crate::arch::pit::now_ns().saturating_sub(t0), Relaxed);
    }
}

/// Disk driver calls (reads, other requests, vectored reads), the blocks they moved and
/// their time.
static DISK: [[AtomicU64; 3]; 3] = [const { [const { AtomicU64::new(0) }; 3] }; 3];

/// Kinds of disk driver calls for [`disk_call`].
pub const DISK_READ: usize = 0;
/// Requests other than reads.
pub const DISK_OTHER: usize = 1;
/// Vectored reads (several runs in one request).
pub const DISK_READV: usize = 2;

/// Records a call to the disk driver started at `t0`: a request of `kind` (DISK_READ...)
/// moving `blocks` blocks.
#[inline]
pub fn disk_call(kind: usize, blocks: u64, t0: u64) {
    if t0 != 0 && kind < DISK.len() {
        let d = &DISK[kind];
        d[0].fetch_add(1, Relaxed);
        d[1].fetch_add(blocks, Relaxed);
        d[2].fetch_add(crate::arch::pit::now_ns().saturating_sub(t0), Relaxed);
    }
}

/// The task whose user-mode instruction pointer is sampled at each timer tick (0: none),
/// and the samples (a ring of the last [`SAMPLES`]).
pub static SAMPLE_TASK: AtomicU64 = AtomicU64::new(0);
/// Whether ticks in kernel mode are sampled too.
static SAMPLE_KERNEL: AtomicBool = AtomicBool::new(false);
const SAMPLES: usize = 16384;
static SAMPLE_AT: AtomicU64 = AtomicU64::new(0);
static SAMPLE_RIP: [AtomicU64; SAMPLES] = [const { AtomicU64::new(0) }; SAMPLES];

/// Records a tick that interrupted task `task` at `rip` (in user mode, or in either mode
/// when kernel ticks are sampled too).
#[inline]
pub fn sample(task: u64, rip: u64, cs: u64) {
    let want = SAMPLE_TASK.load(Relaxed);
    // u64::MAX: every task
    if want != 0 && (want == task || want == u64::MAX) && (cs & 3 == 3 || SAMPLE_KERNEL.load(Relaxed)) {
        let i = SAMPLE_AT.fetch_add(1, Relaxed) as usize % SAMPLES;
        SAMPLE_RIP[i].store(rip, Relaxed);
    }
}

/// Starts sampling `task` (0 stops) in user mode, or in both modes when `kernel`,
/// clearing earlier samples.
pub fn sample_start(task: u64, kernel: bool) {
    SAMPLE_AT.store(0, Relaxed);
    SAMPLE_KERNEL.store(kernel, Relaxed);
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

/// Calls and faults at least this long (milliseconds; 0: none) are recorded one by one while
/// profiling, with the time since boot, so waits can be lined up with a program's own
/// timestamped trace (`linux prof waits <ms>`, then `linux prof waits show`). They go to a
/// ring in memory, not the console: printing each one would itself stall the programs.
pub static SLOW_MS: AtomicU64 = AtomicU64::new(0);

/// One recorded slow call or fault.
#[derive(Clone, Copy)]
struct Slow {
    t0: u64,
    ns: u64,
    pid: u64,
    tid: u64,
    /// The system call (`u64::MAX`: a page fault).
    nr: u64,
    args: [u64; 3],
    ret: i64,
    exe: [u8; 24],
}

const SLOW_MAX: usize = 32768;
static SLOWS: spin::Mutex<alloc::vec::Vec<Slow>> = spin::Mutex::new(alloc::vec::Vec::new());

/// Records system call `nr` (`u64::MAX`: a page fault) returning `r` if it took at least [`SLOW_MS`].
pub fn slow(nr: u64, r: i64, a0: u64, a1: u64, a2: u64, t0: u64) {
    let lim = SLOW_MS.load(Relaxed);
    if t0 == 0 || lim == 0 {
        return;
    }
    let ns = crate::arch::pit::now_ns().saturating_sub(t0);
    if ns < lim * 1_000_000 {
        return;
    }
    let (tid, pid) = super::proc::current_ids();
    // The end of the command line (Wine's programs all run as wine-preloader: their last
    // argument tells them apart)
    let mut exe = [0u8; 24];
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten();
    if let Some((start, end)) = mm.and_then(|m| m.try_lock().map(|g| (g.args.0, g.args.1))) {
        if start != 0 && end > start {
            let end = end - 1;
            let from = start.max(end.saturating_sub(24));
            let n = (end - from) as usize;
            unsafe { core::ptr::copy_nonoverlapping(from as *const u8, exe.as_mut_ptr(), n) };
            for b in exe[..n].iter_mut() {
                if *b == 0 {
                    *b = b' ';
                }
            }
        }
    }
    // A sleep: the time asked for (instead of the pointer)
    let a2 = match nr {
        230 if a2 != 0 => unsafe { core::ptr::read_unaligned(a2 as *const u64) * 1_000_000_000 + core::ptr::read_unaligned((a2 + 8) as *const u64) },
        _ => a2,
    };
    let a0 = match nr {
        35 if a0 != 0 => unsafe { core::ptr::read_unaligned(a0 as *const u64) * 1_000_000_000 + core::ptr::read_unaligned((a0 + 8) as *const u64) },
        _ => a0,
    };
    let mut v = SLOWS.lock();
    if v.len() < SLOW_MAX {
        v.push(Slow { t0, ns, pid, tid, nr, args: [a0, a1, a2], ret: r, exe });
    }
}

/// Prints the recorded slow calls and faults in start order and forgets them.
pub fn slow_show() {
    let mut v = core::mem::take(&mut *SLOWS.lock());
    v.sort_unstable_by_key(|s| s.t0);
    crate::println!("[wait] {} slow calls", v.len());
    for s in v {
        let ms = s.t0 / 1_000_000;
        let len = s.exe.iter().position(|&b| b == 0).unwrap_or(24);
        let exe = core::str::from_utf8(&s.exe[..len]).unwrap_or("?").trim();
        if s.nr == u64::MAX {
            crate::println!("[wait] {}.{:03} +{}.{:01}ms {}/{} {} fault {:#x} kind {}", ms / 1000, ms % 1000, s.ns / 1_000_000,
                s.ns / 100_000 % 10, s.pid, s.tid, exe, s.args[0], s.args[1]);
        } else {
            crate::println!("[wait] {}.{:03} +{}.{:01}ms {}/{} {} nr {} ({:#x}, {:#x}, {:#x}) -> {}", ms / 1000, ms % 1000,
                s.ns / 1_000_000, s.ns / 100_000 % 10, s.pid, s.tid, exe, s.nr, s.args[0], s.args[1], s.args[2], s.ret);
        }
    }
}

/// Wakeup latency while profiling: from a wait queue's wakeup to the scheduler marking the
/// task ready (`PENDING`), and from ready to running on a CPU (`RUN`), as histograms.
const WAKE_SLOTS: usize = 4096;
static WAKE_REQ: [AtomicU64; WAKE_SLOTS] = [const { AtomicU64::new(0) }; WAKE_SLOTS];
static READY_AT: [AtomicU64; WAKE_SLOTS] = [const { AtomicU64::new(0) }; WAKE_SLOTS];
const LAT_BOUNDS_US: [u64; 6] = [10, 50, 200, 1000, 5000, 20000];
static LAT_PENDING: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
static LAT_RUN: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
static LAT_KICK: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

/// A halted idle CPU woke `ns` after another CPU sent it a wakeup kick.
#[inline]
pub fn kick_latency(ns: u64) {
    if ON.load(Relaxed) {
        lat_add(&LAT_KICK, ns);
    }
}

fn lat_add(h: &[AtomicU64; 7], ns: u64) {
    let us = ns / 1000;
    let i = LAT_BOUNDS_US.iter().position(|&b| us < b).unwrap_or(6);
    h[i].fetch_add(1, Relaxed);
}

/// A wait queue woke task `id` (its wakeup waits for the scheduler).
#[inline]
pub fn wake_requested(id: u64) {
    if ON.load(Relaxed) {
        let _ = WAKE_REQ[id as usize % WAKE_SLOTS].compare_exchange(0, crate::arch::pit::now_ns().max(1), Relaxed, Relaxed);
    }
}

/// The scheduler made task `id` ready to run.
#[inline]
pub fn wake_applied(id: u64) {
    if ON.load(Relaxed) {
        let now = crate::arch::pit::now_ns().max(1);
        let t = WAKE_REQ[id as usize % WAKE_SLOTS].swap(0, Relaxed);
        if t != 0 {
            lat_add(&LAT_PENDING, now.saturating_sub(t));
        }
        READY_AT[id as usize % WAKE_SLOTS].store(now, Relaxed);
    }
}

/// A wakeup of task `id` found it not waiting (it keeps it for its next wait).
#[inline]
pub fn wake_dropped(id: u64) {
    if ON.load(Relaxed) {
        WAKE_REQ[id as usize % WAKE_SLOTS].store(0, Relaxed);
    }
}

/// Task `id` was switched in on a CPU.
#[inline]
pub fn switched_in(id: u64) {
    if ON.load(Relaxed) {
        let t = READY_AT[id as usize % WAKE_SLOTS].swap(0, Relaxed);
        if t != 0 {
            lat_add(&LAT_RUN, crate::arch::pit::now_ns().saturating_sub(t));
        }
    }
}

fn lat_show(name: &str, h: &[AtomicU64; 7]) {
    let v: alloc::vec::Vec<u64> = h.iter().map(|c| c.load(Relaxed)).collect();
    crate::println!(
        "[prof] {}: <10us {} <50us {} <200us {} <1ms {} <5ms {} <20ms {} more {}",
        name, v[0], v[1], v[2], v[3], v[4], v[5], v[6]
    );
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
    for d in DISK.iter() {
        for c in d.iter() {
            c.store(0, Relaxed);
        }
    }
    for k in IPI.iter() {
        for c in k.iter() {
            c.store(0, Relaxed);
        }
    }
    for i in 0..7 {
        LAT_PENDING[i].store(0, Relaxed);
        LAT_RUN[i].store(0, Relaxed);
        LAT_KICK[i].store(0, Relaxed);
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
    for (k, name) in ["disk reads", "other disk requests", "vectored disk reads"].iter().enumerate() {
        let (n, b, ns) = (DISK[k][0].load(Relaxed), DISK[k][1].load(Relaxed), DISK[k][2].load(Relaxed));
        crate::println!("[prof]   {:>9} {:>9} ms {:>7} us/each  {} ({} blocks)", n, ns / 1_000_000, if n > 0 { ns / n / 1000 } else { 0 }, name, b);
    }
    for (k, name) in ["wakeup IPIs (idle CPU kicks)", "other IPIs (TLB flushes)"].iter().enumerate() {
        let (n, ns) = (IPI[k][0].load(Relaxed), IPI[k][1].load(Relaxed));
        crate::println!("[prof]   {:>9} {:>9} ms {:>7} ns/each  {} sent", n, ns / 1_000_000, if n > 0 { ns / n } else { 0 }, name);
    }
    crate::println!("[prof] deepest kernel stack use of an ended task: {} bytes", crate::task::scheduler::MAX_KSTACK_USE.load(Relaxed));
    crate::println!("[prof] tlb: {}", crate::arch::pcid::summary());
    crate::println!("[prof] lx: {}", crate::lx::summary());
    // wave7 G7-7: the file service's share again on short lines of their own (the long line
    // above can be lost on a busy serial console)
    crate::println!("[prof] {}", crate::lx::fileh::summary());
    crate::println!("[prof] {}", crate::lx::xexec::summary());
    lat_show("wakeup -> ready", &LAT_PENDING);
    lat_show("ready -> running", &LAT_RUN);
    lat_show("kick -> halted CPU awake", &LAT_KICK);
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
