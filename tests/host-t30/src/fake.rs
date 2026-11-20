//! Stand-ins for what the forwarding core and IPC call outside `src/lx` and `src/ipc`:
//! physical memory and address spaces, descriptor tables, the Linux process table, and the
//! hardware hooks (IOMMU, PIC, PCI, fw_cfg). Each records what it was asked so the tests can
//! check it, and most can be told to fail.
//!
//! State is global (the kernel's is), reset by [`reset`] at the start of every test world
//! (`world::Sim::new`); tests run one at a time (`world::serial`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Everything the fakes record, reset by [`reset`].
#[derive(Default)]
pub struct Rec {
    /// `kprintln!` lines.
    pub log: Vec<String>,
    /// `iommu::map_dma` / `unmap_dma` calls: `(map?, endpoint, phys, len)`.
    pub dma: Vec<(bool, u32, u64, u64)>,
    /// Make the next `map_dma` calls fail (count).
    pub dma_fail: usize,
    /// PIC mask/unmask: `(mask?, irq)`.
    pub pic: Vec<(bool, u8)>,
    /// fw_cfg files.
    pub fwcfg: BTreeMap<String, Vec<u8>>,
    /// `supervisor::revive` answers by endpoint (missing: false), and the calls made.
    pub revive: BTreeMap<u32, bool>,
    pub revived: Vec<u32>,
    /// Signals posted: `(pid, tid or 0, sig, code, spid, suid, value)`.
    pub posted: Vec<(u64, u64, u32, i32, u32, u32, u64)>,
    /// `unix::server_call`s: `(num, args)`; and its answer.
    pub unix_calls: Vec<(u64, [u64; 6])>,
    pub unix_answer: i64,
    /// `bpf::set_server_device_programs` data, and its answer.
    pub bpf_programs: Vec<Vec<u8>>,
    /// `landlock::check_port_of` answer.
    pub landlock: Option<i64>,
    /// Text of `/proc/<pid>/...` files.
    pub proc_files: BTreeMap<String, Vec<u8>>,
    /// net-server readiness words by handle.
    pub net_words: BTreeMap<u32, u64>,
    /// `admin::linux::plasma` calls.
    pub plasma: usize,
    pub display_manager: bool,
    /// `serial_write` text.
    pub serial: String,
    /// `sys_munmap` calls.
    pub munmaps: Vec<(u64, u64)>,
    /// PCI: whether `enable_msi`/`enable_msix` succeed; `msix` table address.
    pub msi_ok: bool,
    pub msix_table: Option<u64>,
    /// `prof::disk_call`s: `(kind, blocks)`.
    pub disk_calls: Vec<(usize, u64)>,
    /// The vvar page address `map_vvar` returns.
    pub vvar: Option<u64>,
}

pub static REC: Mutex<Option<Rec>> = Mutex::new(None);

/// Runs `f` on the record.
pub fn rec<R>(f: impl FnOnce(&mut Rec) -> R) -> R {
    let mut g = REC.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Rec::default))
}

/// Pages a user copy finds missing (faulted in by `prefault_current` unless also bad).
pub static MISSING: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// Pages that cannot be faulted in (a bad pointer).
pub static BAD: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// The per-thread "signal pending" marks: thread id -> pending.
pub static SIGNALS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// `compat::linux::ident_epoch`.
pub static EPOCH: AtomicU64 = AtomicU64::new(1);
/// Traced threads.
pub static TRACED: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// `ns::net_isolated`, `ns::ipc_ns`.
pub static NET_ISOLATED: AtomicBool = AtomicBool::new(false);
pub static IPC_NS: AtomicU64 = AtomicU64::new(0);
/// `smp::online()`.
pub static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);
/// Spins in `serve_tlb` (a spin lock held across a switch would spin forever).
pub static SPINS: AtomicU64 = AtomicU64::new(0);
/// Frame allocations to refuse (count).
pub static ALLOC_FAIL: AtomicUsize = AtomicUsize::new(0);
/// `userfaultfd::active`.
pub static UFFD: AtomicBool = AtomicBool::new(false);

/// Back to a clean slate (every test world starts here).
pub fn reset() {
    *REC.lock().unwrap_or_else(|e| e.into_inner()) = Some(Rec { msi_ok: true, ..Default::default() });
    MISSING.lock().unwrap().clear();
    BAD.lock().unwrap().clear();
    SIGNALS.lock().unwrap().clear();
    TRACED.lock().unwrap().clear();
    EPOCH.fetch_add(1, Ordering::AcqRel);
    NET_ISOLATED.store(false, Ordering::Release);
    IPC_NS.store(0, Ordering::Release);
    ONLINE_CPUS.store(1, Ordering::Release);
    SPINS.store(0, Ordering::Release);
    ALLOC_FAIL.store(0, Ordering::Release);
    UFFD.store(false, Ordering::Release);
    crate::memory::vm::CURRENT_MM.store(std::ptr::null_mut(), Ordering::Release);
    *crate::compat::linux::proc::PROCS.lock() = BTreeMap::new();
    crate::compat::linux::TRACE_SYSCALLS.store(false, Ordering::Release);
}

/// The `kprintln!` lines so far.
pub fn log() -> Vec<String> {
    rec(|r| r.log.clone())
}

/// Whether some `kprintln!` line contains `s`.
pub fn logged(s: &str) -> bool {
    rec(|r| r.log.iter().any(|l| l.contains(s)))
}

/// Marks thread `tid` as having a signal pending (or not).
pub fn set_signal(tid: u64, on: bool) {
    let mut s = SIGNALS.lock().unwrap();
    if on {
        s.insert(tid);
    } else {
        s.remove(&tid);
    }
}

/// The page of `addr`.
pub fn page(addr: u64) -> u64 {
    addr & !0xFFF
}

/// Makes the page(s) of `addr..addr+len` missing for user copies until faulted in.
pub fn make_missing(addr: u64, len: u64) {
    let mut m = MISSING.lock().unwrap();
    let mut p = page(addr);
    while p < addr + len.max(1) {
        m.insert(p);
        p += 4096;
    }
}

/// Makes the page of `addr` bad (never faulted in).
pub fn make_bad(addr: u64) {
    BAD.lock().unwrap().insert(page(addr));
    MISSING.lock().unwrap().insert(page(addr));
}

/// Gives the current task an address space for user copies (`CURRENT_MM` non-null).
pub fn user_space_on() {
    static DUMMY: u8 = 0;
    crate::memory::vm::CURRENT_MM.store(&DUMMY as *const u8 as *mut u8, Ordering::Release);
}

/// The fake `rep movsb` with fault fix-up: copies until a byte on a missing page; returns
/// the bytes NOT copied.
pub fn uaccess_copy(dst: *mut u8, src: *const u8, n: usize) -> usize {
    let missing = MISSING.lock().unwrap().clone();
    for i in 0..n {
        let s = src as u64 + i as u64;
        let d = dst as u64 + i as u64;
        if missing.contains(&page(s)) || missing.contains(&page(d)) {
            return n - i;
        }
        // SAFETY: tests pass host buffers valid for `n` bytes
        unsafe { *dst.add(i) = *src.add(i) };
    }
    0
}

/// The fake string copy: the length without its NUL (the NUL copied), -1 without a NUL
/// within `max`, -2 - k for a fault at `src + k`.
pub fn uaccess_str(dst: *mut u8, src: *const u8, max: usize) -> isize {
    let missing = MISSING.lock().unwrap().clone();
    for i in 0..max {
        let s = src as u64 + i as u64;
        if missing.contains(&page(s)) {
            return -2 - i as isize;
        }
        // SAFETY: tests pass host buffers valid up to the NUL or `max`
        let b = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = b };
        if b == 0 {
            return i as isize;
        }
    }
    -1
}

/// `prefault_current`: a missing page comes in unless it is bad.
pub fn prefault(addr: u64, len: u64) -> bool {
    // (the first 64 KiB are never mapped)
    if addr < 0x10000 {
        return false;
    }
    let bad = BAD.lock().unwrap();
    let mut m = MISSING.lock().unwrap();
    let mut p = page(addr);
    let end = addr.saturating_add(len.max(1));
    while p < end {
        if bad.contains(&p) {
            return false;
        }
        m.remove(&p);
        p += 4096;
    }
    true
}

// ----------------------------------------------------------------------
// Physical memory: host allocations, "physical" address = host address
// ----------------------------------------------------------------------

/// Reference counts of the frames handed out (by physical address).
pub static FRAME_REFS: Mutex<BTreeMap<u64, i64>> = Mutex::new(BTreeMap::new());

/// Frame `phys`'s reference count (0 when unknown).
pub fn frame_refs(phys: u64) -> i64 {
    FRAME_REFS.lock().unwrap().get(&phys).copied().unwrap_or(0)
}

/// `n` zeroed, page-aligned bytes that live for the rest of the run (a "physical" range).
pub fn alloc_pages(pages: usize) -> u64 {
    let layout = std::alloc::Layout::from_size_align(pages.max(1) * 4096, 4096).unwrap();
    // SAFETY: non-zero size
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!p.is_null());
    p as u64
}

pub static MSG_UNUSED: AtomicU64 = AtomicU64::new(0);
