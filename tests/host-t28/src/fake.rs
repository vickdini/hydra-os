//! Host stand-ins for the kernel services Group 28's device files call.
//!
//! Most state lives in thread-locals (the test harness runs each `#[test]` on its own
//! thread, so tests configure the fakes freely and still run in parallel). What the
//! kernel files themselves keep in globals (the console terminal, the DRM state, the ALSA
//! streams, the evdev ring) is shared by every test of one binary: such tests hold
//! `common::serial()`. The fakes reached from those globals' code paths that must outlive
//! one thread (the display, spawned tasks, the sound service, the disks) are globals too.
//!
//! `lib.rs` re-exports these items at the module paths the kernel uses.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ===================================================================== clock

thread_local! {
    /// Timer ticks reported by `pit::ticks()` (the fake PIT runs at 1000 Hz).
    pub static TICKS: Cell<u64> = const { Cell::new(1_000) };
}

pub fn ticks() -> u64 {
    TICKS.get()
}
pub fn frequency_hz() -> u64 {
    1000
}
pub fn now_ns() -> u64 {
    TICKS.get() * 1_000_000
}
/// `rtc::wall_base_ns`: wall-clock nanoseconds at boot (2026-01-01T00:00:00Z).
pub fn wall_base_ns() -> i64 {
    1_767_225_600 * 1_000_000_000
}
/// Advances the fake clock.
pub fn advance(ticks: u64) {
    TICKS.set(TICKS.get() + ticks);
}

// ============================================================ user memory

/// User pointers at or above this address fault (`prefault_current` fails).
pub const BAD_PTR: u64 = 0x0000_dead_0000_0000;

/// `vm::prefault_current`: user pointers are host pointers; null and [`BAD_PTR`] and above
/// fault.
pub fn prefault_current(ptr: u64, len: u64, _write: bool) -> bool {
    ptr != 0 && ptr < BAD_PTR && ptr.checked_add(len).map_or(false, |e| e <= BAD_PTR)
}

// ============================================================= processes

thread_local! {
    /// What `signal_pending()` reports.
    pub static SIGNAL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// (tid, tgid) of the current task.
    pub static IDS: Cell<(u64, u64)> = const { Cell::new((1, 1)) };
    /// `proc::session_of`: pid -> (session, process group).
    pub static SESSIONS: RefCell<BTreeMap<u64, (u64, u64)>> = const { RefCell::new(BTreeMap::new()) };
    /// Signals sent to process groups: (pgid, signal).
    pub static GROUP_SIGNALS: RefCell<Vec<(u64, u32)>> = const { RefCell::new(Vec::new()) };
    /// What `proc::ignores_or_blocks` reports.
    pub static IGNORES: Cell<bool> = const { Cell::new(false) };
    /// What `proc::cpu_times` reports.
    pub static CPU_TIMES: Cell<(u64, u64, u64, u64)> = const { Cell::new((0, 0, 0, 0)) };
    /// Effective capabilities of the current task (`None`: no task).
    pub static CAPS: Cell<Option<u64>> = const { Cell::new(Some(0)) };
    /// Personality and priority of the current task (seen through the scheduler).
    pub static TASK_SCHED: Cell<(crate::task::TaskPersonality, crate::task::TaskPriority)> =
        const { Cell::new((crate::task::TaskPersonality::Linux, crate::task::TaskPriority::Normal)) };
    /// A closure run instead of sleeping (`WaitSet::wait`): it changes what the loop sees.
    pub static ON_WAIT: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    /// Number of sleeps (`WaitSet::wait` and `wait::wait`).
    pub static WAITS: Cell<u64> = const { Cell::new(0) };
}

pub fn current_ids() -> (u64, u64) {
    IDS.get()
}
pub fn session_of(pid: u64) -> Option<(u64, u64)> {
    SESSIONS.with_borrow(|m| m.get(&pid).copied())
}
pub fn post_group(pgid: u64, sig: u32) -> usize {
    GROUP_SIGNALS.with_borrow_mut(|v| v.push((pgid, sig)));
    1
}
/// Takes the recorded group signals.
pub fn take_group_signals() -> Vec<(u64, u32)> {
    GROUP_SIGNALS.with_borrow_mut(std::mem::take)
}

/// The parts of the kernel's `Process` the code under test reads.
#[derive(Default)]
pub struct Process {
    pub personality: u32,
}

/// The process table (shared by all test threads, like the kernel's): use distinct pids.
pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

/// Runs a closure instead of sleeping in the next waits (until [`clear_on_wait`]).
pub fn on_wait(f: impl FnMut() + 'static) {
    ON_WAIT.with_borrow_mut(|w| *w = Some(Box::new(f)));
}
pub fn clear_on_wait() {
    ON_WAIT.with_borrow_mut(|w| *w = None);
}

// ====================================================== tasks, scheduler

pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let caps = CAPS.get()?;
    let (personality, priority) = TASK_SCHED.get();
    let mut t = Task { caps: Caps { effective: caps }, id: TaskId(IDS.get().0), personality, priority };
    let r = f(&mut t);
    CAPS.set(Some(t.caps.effective));
    TASK_SCHED.set((t.personality, t.priority));
    Some(r)
}

pub struct Caps {
    pub effective: u64,
}

/// The parts of the kernel's `Task` the code under test reads.
pub struct Task {
    pub caps: Caps,
    pub id: TaskId,
    pub personality: crate::task::TaskPersonality,
    pub priority: crate::task::TaskPriority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId(pub u64);

/// Stand-in for `task::SCHEDULER`: its only task is the current one.
pub struct Scheduler;
pub static SCHEDULER: Scheduler = Scheduler;
pub struct SchedulerGuard;

impl Scheduler {
    pub fn lock(&self) -> SchedulerGuard {
        SchedulerGuard
    }
}

impl SchedulerGuard {
    pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        if id.0 != IDS.get().0 {
            return None;
        }
        with_current_task_mut(f)
    }
}

/// Kernel tasks started by the code under test: (name, entry). Never run on their own:
/// a test may call an entry.
pub static SPAWNED: Mutex<Vec<(&'static str, fn())>> = Mutex::new(Vec::new());

pub fn spawn(name: &'static str, entry: fn(), _priority: crate::task::TaskPriority) -> TaskId {
    let mut s = SPAWNED.lock().unwrap_or_else(|e| e.into_inner());
    s.push((name, entry));
    TaskId(1000 + s.len() as u64)
}
/// How often a task called `name` was spawned so far.
pub fn spawned(name: &str) -> usize {
    SPAWNED.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(n, _)| *n == name).count()
}
/// The entry of the last task spawned as `name`.
pub fn spawned_entry(name: &str) -> Option<fn()> {
    SPAWNED.lock().unwrap_or_else(|e| e.into_inner()).iter().rev().find(|(n, _)| *n == name).map(|(_, f)| *f)
}

thread_local! {
    /// Milliseconds slept through `task::sleep_ms`.
    pub static SLEPT_MS: Cell<u64> = const { Cell::new(0) };
}
pub fn sleep_ms(ms: u64) {
    SLEPT_MS.set(SLEPT_MS.get() + ms);
    advance(ms);
}

/// Threads whose priority was put back (`extra::reapply_priority`).
pub static REAPPLIED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
pub fn reapply_priority(tid: u64) {
    REAPPLIED.lock().unwrap_or_else(|e| e.into_inner()).push(tid);
}

// ============================================================ wait queues

pub mod wait {
    use super::*;

    /// Counts its wake-ups; never actually sleeps.
    pub struct WaitQueue {
        wakes: AtomicU64,
    }

    impl Default for WaitQueue {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WaitQueue {
        pub const fn new() -> Self {
            WaitQueue { wakes: AtomicU64::new(0) }
        }
        pub fn new_shared() -> Arc<Self> {
            Arc::new(WaitQueue::new())
        }
        pub fn register(&self) {}
        pub fn unregister(&self) {}
        pub fn wake_all(&self) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
        /// Wake-ups so far.
        pub fn wakes(&self) -> u64 {
            self.wakes.load(Ordering::Relaxed)
        }
    }

    pub enum QueueRef {
        Static(&'static WaitQueue),
        Shared(Arc<WaitQueue>),
    }

    impl QueueRef {
        /// The queue (for assertions).
        pub fn queue(&self) -> &WaitQueue {
            match self {
                QueueRef::Static(q) => q,
                QueueRef::Shared(q) => q,
            }
        }
    }

    #[derive(Default)]
    pub struct WaitSet {
        pub queues: Vec<QueueRef>,
    }

    /// Message of the panic raised when code under test would go to sleep for good.
    pub const WOULD_BLOCK: &str = "fake WaitSet::wait: the operation would block";

    /// One sleep: the [`ON_WAIT`] closure runs if one is set; otherwise a sleep with a
    /// deadline (in ticks) moves the fake clock to it, and one without panics with
    /// [`WOULD_BLOCK`] (tests catch it).
    fn sleep(deadline: Option<u64>) {
        WAITS.set(WAITS.get() + 1);
        let hook = ON_WAIT.with_borrow_mut(|w| w.take());
        if let Some(mut f) = hook {
            f();
            ON_WAIT.with_borrow_mut(|w| {
                if w.is_none() {
                    *w = Some(f);
                }
            });
            return;
        }
        match deadline {
            Some(d) => TICKS.set(TICKS.get().max(d)),
            None => panic!("{}", WOULD_BLOCK),
        }
    }

    impl WaitSet {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn register(&self) {}
        pub fn wait(&self, deadline: Option<u64>) {
            sleep(deadline)
        }
    }

    /// Free-function form of [`WaitSet::wait`].
    pub fn wait(deadline: Option<u64>) {
        sleep(deadline)
    }
}

// ====================================================== descriptor table

pub struct Fds {
    pub next: usize,
    pub limit: usize,
    pub open: BTreeMap<usize, (crate::fs::FileDescriptor, bool)>,
}

impl Default for Fds {
    fn default() -> Self {
        Self { next: 3, limit: 1024, open: BTreeMap::new() }
    }
}

impl Fds {
    pub fn alloc_fd(&mut self, d: crate::fs::FileDescriptor) -> Result<usize, &'static str> {
        if self.next >= self.limit {
            return Err("Too many open files");
        }
        let fd = self.next;
        self.next += 1;
        self.open.insert(fd, (d, false));
        Ok(fd)
    }
    pub fn set_cloexec(&mut self, fd: usize, on: bool) {
        if let Some(e) = self.open.get_mut(&fd) {
            e.1 = on;
        }
    }
    pub fn get(&self, fd: usize) -> Option<&crate::fs::FileDescriptor> {
        self.open.get(&fd).map(|e| &e.0)
    }
    /// Test helper: install `d` at descriptor `fd`.
    pub fn install(&mut self, fd: usize, d: crate::fs::FileDescriptor) {
        self.open.insert(fd, (d, false));
    }
    /// Whether descriptor `fd` is close-on-exec.
    pub fn cloexec(&self, fd: usize) -> bool {
        self.open.get(&fd).map_or(false, |e| e.1)
    }
}

thread_local! {
    pub static FDS: RefCell<Fds> = RefCell::new(Fds::default());
}

pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut Fds) -> R) -> R {
    FDS.with_borrow_mut(f)
}

// ================================================================ console

thread_local! {
    /// What the console printed (`console::print_raw`).
    pub static CONSOLE_OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Keystrokes `console::read_key` hands out.
    pub static KEYS: RefCell<VecDeque<uefi::proto::console::text::Key>> = const { RefCell::new(VecDeque::new()) };
    /// (cols, rows) of the text console.
    pub static CONSOLE_SIZE: Cell<(usize, usize)> = const { Cell::new((100, 37)) };
}

pub fn print_raw(s: &str) {
    CONSOLE_OUT.with_borrow_mut(|v| v.extend_from_slice(s.as_bytes()));
}
pub fn read_key() -> Option<uefi::proto::console::text::Key> {
    KEYS.with_borrow_mut(|k| k.pop_front())
}
/// Takes what the console printed.
pub fn take_console() -> Vec<u8> {
    CONSOLE_OUT.with_borrow_mut(std::mem::take)
}
/// Queues printable keystrokes.
pub fn type_keys(s: &str) {
    use uefi::proto::console::text::Key;
    KEYS.with_borrow_mut(|k| {
        for c in s.chars() {
            k.push_back(Key::Printable(uefi::Char16::try_from(c).unwrap()));
        }
    });
}
pub fn dimensions() -> (usize, usize) {
    CONSOLE_SIZE.get()
}

// ================================================================ display

/// The boot framebuffer the console lends to the DRM driver.
pub struct Display {
    /// (width, height) the video mode reports (`None`: no video mode).
    pub mode: Option<(usize, usize)>,
    /// Pixels (stride `stride`, 4 bytes each); leaked, so pointers stay valid.
    pub fb: &'static mut [u8],
    pub stride: usize,
    pub bgr: bool,
    /// The console has the screen (`release_display` fails while the DRM driver has it).
    pub console_owns: bool,
    /// `release_display` refuses (no framebuffer).
    pub refuse: bool,
    pub panicked: bool,
    pub releases: u32,
    pub reclaims: u32,
}

pub static DISPLAY: Mutex<Option<Display>> = Mutex::new(None);

/// Sets up a `w` x `h` framebuffer (stride `w`), owned by the console.
pub fn set_display(w: usize, h: usize, bgr: bool) {
    let fb: &'static mut [u8] = Box::leak(vec![0u8; w * h * 4].into_boxed_slice());
    *DISPLAY.lock().unwrap_or_else(|e| e.into_inner()) = Some(Display {
        mode: Some((w, h)),
        fb,
        stride: w,
        bgr,
        console_owns: true,
        refuse: false,
        panicked: false,
        releases: 0,
        reclaims: 0,
    });
}
/// Runs `f` on the display.
pub fn with_display<R>(f: impl FnOnce(&mut Display) -> R) -> R {
    f(DISPLAY.lock().unwrap_or_else(|e| e.into_inner()).as_mut().expect("no fake display"))
}
/// Pixel `(x, y)` of the screen as bytes.
pub fn pixel(x: usize, y: usize) -> [u8; 4] {
    with_display(|d| {
        let o = (y * d.stride + x) * 4;
        d.fb[o..o + 4].try_into().unwrap()
    })
}

/// `video::VideoModeInfo`, the fields the code under test reads.
pub struct VideoModeInfo {
    pub width: usize,
    pub height: usize,
}
pub fn get_video_info() -> Option<VideoModeInfo> {
    DISPLAY.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|d| d.mode).map(|(width, height)| VideoModeInfo { width, height })
}
pub fn release_display() -> Option<(*mut u8, usize, usize, usize, bool)> {
    let mut g = DISPLAY.lock().unwrap_or_else(|e| e.into_inner());
    let d = g.as_mut()?;
    if d.refuse || !d.console_owns {
        return None;
    }
    d.console_owns = false;
    d.releases += 1;
    let (w, h) = d.mode.unwrap_or((0, 0));
    Some((d.fb.as_mut_ptr(), w, h, d.stride, d.bgr))
}
pub fn reclaim_display() {
    if let Some(d) = DISPLAY.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        d.console_owns = true;
        d.reclaims += 1;
    }
}
pub fn panicked() -> bool {
    DISPLAY.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map_or(false, |d| d.panicked)
}

// ===================================================================== PCI

/// `arch::pci::PciDevice`, the fields the code under test reads.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
}

thread_local! {
    /// Devices by (class, subclass).
    pub static PCI: RefCell<BTreeMap<(u8, u8), PciDevice>> = const { RefCell::new(BTreeMap::new()) };
    /// Configuration dwords by (bus, device, function, offset & !3).
    pub static PCI_CONFIG: RefCell<BTreeMap<(u8, u8, u8, u8), u32>> = const { RefCell::new(BTreeMap::new()) };
}

pub fn find_class(class: u8, subclass: u8) -> Option<PciDevice> {
    PCI.with_borrow(|m| m.get(&(class, subclass)).copied())
}
pub fn pci_read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    PCI_CONFIG.with_borrow(|m| m.get(&(bus, device, function, offset & !3)).copied().unwrap_or(0))
}
pub fn pci_read_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    (pci_read_u32(bus, device, function, offset) >> ((offset & 3) * 8)) as u8
}

// ======================================================= boot disk, live

/// `arch::bootdisk::BootInfo`.
#[derive(Clone, Default)]
pub struct BootInfo {
    pub boot_part: Option<[u8; 16]>,
    pub live: bool,
    pub setup_conf: Option<Vec<u8>>,
}

thread_local! {
    pub static BOOT_INFO: RefCell<BootInfo> = RefCell::new(BootInfo::default());
    /// `live::is_live`.
    pub static LIVE: Cell<bool> = const { Cell::new(false) };
    /// Roots `abac::boot_load` was called with.
    pub static ABAC_LOADS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// `net::iface().dns`.
    pub static DNS: Cell<[u8; 4]> = const { Cell::new([0; 4]) };
    /// `arch::vmmouse::present`.
    pub static VMMOUSE: Cell<bool> = const { Cell::new(false) };
    /// `efivars::snapshot`.
    pub static EFIVARS: RefCell<Option<Vec<(String, Vec<u8>)>>> = const { RefCell::new(None) };
    /// Result of `iommu::map_dma`.
    pub static IOMMU_FAILS: Cell<bool> = const { Cell::new(false) };
}

pub fn boot_info() -> BootInfo {
    BOOT_INFO.with_borrow(|b| b.clone())
}

/// `net::IfaceInfo`, the field the code under test reads.
pub struct IfaceInfo {
    pub dns: [u8; 4],
}
pub fn iface() -> IfaceInfo {
    IfaceInfo { dns: DNS.get() }
}

// ============================================================ the disks

/// `fs::blockdev::Partition`.
#[derive(Clone, Debug)]
pub struct Partition {
    pub number: u32,
    pub start: u64,
    pub len: u64,
    pub entry: Option<crate::fs::gpt::Part>,
}

/// `fs::blockdev::Disk` (same fields and helpers).
#[derive(Clone, Debug)]
pub struct Disk {
    pub name: String,
    pub endpoint: u32,
    pub unit: u64,
    pub bytes: u64,
    pub sector_size: u32,
    pub model: String,
    pub removable: bool,
    pub pool: Option<(u64, u64)>,
    pub table: Option<(crate::fs::gpt::Kind, crate::fs::gpt::Guid)>,
    pub parts: Vec<Partition>,
    pub generation: u64,
}

impl Disk {
    /// Mirror of the kernel's: whether `[start, end)` overlaps the pool's partition.
    pub fn touches_pool(&self, start: u64, end: u64) -> bool {
        self.pool.map_or(false, |(ps, pl)| start < ps + pl && ps < end)
    }
    /// Mirror of the kernel's.
    pub fn part(&self, n: u32) -> Option<&Partition> {
        self.parts.iter().find(|p| p.number == n)
    }
}

/// A fake disk: its description and its bytes.
pub struct FakeDisk {
    pub disk: Disk,
    pub data: Vec<u8>,
    /// Errors to return (`read_at`/`write_at`/`flush`/...): `Some(errno)`.
    pub fail: Option<i64>,
}

thread_local! {
    pub static DISKS: RefCell<Vec<FakeDisk>> = const { RefCell::new(Vec::new()) };
    /// Calls of the partition-changing operations: ("reread", disk) / ("blkpg", disk, op,
    /// number, start, len) / ("flush", disk) / ("zero", disk, offset, len).
    pub static DISK_OPS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// A disk named `name` of `bytes` bytes, without partitions.
pub fn add_disk(name: &str, bytes: u64) -> usize {
    DISKS.with_borrow_mut(|d| {
        d.push(FakeDisk {
            disk: Disk {
                name: name.into(),
                endpoint: 0,
                unit: 0,
                bytes,
                sector_size: 512,
                model: String::new(),
                removable: false,
                pool: None,
                table: None,
                parts: Vec::new(),
                generation: 0,
            },
            data: vec![0; bytes as usize],
            fail: None,
        });
        d.len() - 1
    })
}
pub fn with_disk<R>(i: usize, f: impl FnOnce(&mut FakeDisk) -> R) -> R {
    DISKS.with_borrow_mut(|d| f(&mut d[i]))
}

pub mod blockdev {
    pub use super::{Disk, Partition};
    use super::{DISKS, DISK_OPS};

    fn op(s: String) {
        DISK_OPS.with_borrow_mut(|v| v.push(s));
    }
    fn fail(idx: usize) -> Result<(), i64> {
        DISKS.with_borrow(|d| match d.get(idx) {
            None => Err(-6),
            Some(d) => d.fail.map_or(Ok(()), Err),
        })
    }
    pub fn disks() -> Vec<Disk> {
        DISKS.with_borrow(|d| d.iter().map(|d| d.disk.clone()).collect())
    }
    pub fn disk(idx: usize) -> Option<Disk> {
        DISKS.with_borrow(|d| d.get(idx).map(|d| d.disk.clone()))
    }
    pub fn read_at(idx: usize, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        fail(idx)?;
        DISKS.with_borrow(|d| {
            let data = &d[idx].data;
            let o = (offset as usize).min(data.len());
            let n = buf.len().min(data.len() - o);
            buf[..n].copy_from_slice(&data[o..o + n]);
            Ok(n)
        })
    }
    pub fn write_at(idx: usize, offset: u64, src: &[u8]) -> Result<usize, i64> {
        fail(idx)?;
        DISKS.with_borrow_mut(|d| {
            let fd = &mut d[idx];
            if fd.disk.touches_pool(offset, offset + src.len() as u64) {
                return Err(-16);
            }
            let o = (offset as usize).min(fd.data.len());
            let n = src.len().min(fd.data.len() - o);
            fd.data[o..o + n].copy_from_slice(&src[..n]);
            Ok(n)
        })
    }
    pub fn zero_range(idx: usize, offset: u64, len: u64) -> Result<(), i64> {
        fail(idx)?;
        op(format!("zero {idx} {offset} {len}"));
        DISKS.with_borrow_mut(|d| {
            let data = &mut d[idx].data;
            let end = ((offset + len) as usize).min(data.len());
            data[offset as usize..end].fill(0);
        });
        Ok(())
    }
    pub fn flush(idx: usize) -> Result<(), i64> {
        fail(idx)?;
        op(format!("flush {idx}"));
        Ok(())
    }
    pub fn reread(idx: usize) -> Result<(), i64> {
        fail(idx)?;
        op(format!("reread {idx}"));
        Ok(())
    }
    pub fn blkpg(idx: usize, op_: u32, number: u32, start: u64, len: u64) -> Result<(), i64> {
        fail(idx)?;
        op(format!("blkpg {idx} {op_} {number} {start} {len}"));
        Ok(())
    }
}

// ======================================================= the sound service

/// The sound driver as the kernel's IPC service layer shows it.
pub struct SoundService {
    pub online: bool,
    /// Answers each call: (endpoint, request) -> reply.
    pub responder: Option<Box<dyn FnMut(u32, &crate::ipc::Message) -> Result<crate::ipc::Message, i64> + Send>>,
    /// Requests so far: (endpoint, label, args).
    pub calls: Vec<(u32, u32, [u64; 4])>,
    /// The shared window (leaked, as the kernel's lives as long as the service).
    pub window: Option<&'static mut [u8]>,
}

pub static SOUND: Mutex<SoundService> = Mutex::new(SoundService { online: false, responder: None, calls: Vec::new(), window: None });

pub fn sound<R>(f: impl FnOnce(&mut SoundService) -> R) -> R {
    f(&mut SOUND.lock().unwrap_or_else(|e| e.into_inner()))
}

pub mod service {
    use super::*;

    pub const CALL_TIMEOUT_TICKS: u64 = 500;

    /// Kernel memory a driver reaches by DMA: `pages` zeroed host pages (physical address
    /// = host address, as `phys_to_virt` is the identity on the host).
    pub struct ContiguousFrames {
        pub base: u64,
        pub pages: u64,
    }

    impl ContiguousFrames {
        pub fn allocate(pages: u64) -> Option<Arc<Self>> {
            let layout = std::alloc::Layout::from_size_align((pages * 4096) as usize, 4096).ok()?;
            let p = unsafe { std::alloc::alloc_zeroed(layout) };
            (!p.is_null()).then(|| Arc::new(ContiguousFrames { base: p as u64, pages }))
        }
        /// The memory as bytes.
        ///
        /// # Safety
        /// As the kernel's: the caller keeps accesses apart.
        #[allow(clippy::mut_from_ref)]
        pub unsafe fn bytes(&self) -> &mut [u8] {
            core::slice::from_raw_parts_mut(self.base as *mut u8, (self.pages * 4096) as usize)
        }
    }

    pub struct WindowGuard;

    pub fn is_online(_endpoint: u32) -> bool {
        sound(|s| s.online)
    }
    pub fn hold_window(_endpoint: u32) -> WindowGuard {
        WindowGuard
    }
    pub fn window(_endpoint: u32) -> Option<&'static mut [u8]> {
        sound(|s| s.window.as_mut().map(|w| unsafe { core::slice::from_raw_parts_mut(w.as_mut_ptr(), w.len()) }))
    }
    pub fn call(endpoint: u32, request: crate::ipc::Message, _timeout: u64) -> Result<crate::ipc::Message, i64> {
        let mut g = SOUND.lock().unwrap_or_else(|e| e.into_inner());
        g.calls.push((endpoint, request.label, request.args));
        match g.responder.as_mut() {
            Some(f) => f(endpoint, &request),
            None => Err(-110),
        }
    }
}

// ========================================================= the file server

/// An inode of the in-memory file system behind the fake `ZfsServer`.
#[derive(Clone)]
pub struct Inode {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub data: Vec<u8>,
    /// Directory entries (name -> inode), sorted.
    pub entries: BTreeMap<Vec<u8>, u64>,
}

/// An in-memory file system, as the ZFS file server's calls see it.
pub struct Fs {
    pub inodes: BTreeMap<u64, Inode>,
    pub next: u64,
    /// Operations that fail with an errno: (name, inode or 0 for any).
    pub fail: Vec<(&'static str, i64)>,
    /// Operation counts by name (for "nothing rewritten" checks).
    pub ops: BTreeMap<&'static str, u64>,
}

pub const ROOT_INO: u64 = 1;

impl Fs {
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(ROOT_INO, Inode { mode: 0o040755, uid: 0, gid: 0, rdev: 0, data: Vec::new(), entries: BTreeMap::new() });
        Fs { inodes, next: 2, fail: Vec::new(), ops: BTreeMap::new() }
    }
}

impl Default for Fs {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    pub static FS: RefCell<Fs> = RefCell::new(Fs::new());
    /// `with_server` fails with this errno (the pool is not mounted).
    pub static SERVER_DOWN: Cell<Option<i64>> = const { Cell::new(None) };
}

pub fn with_fs<R>(f: impl FnOnce(&mut Fs) -> R) -> R {
    FS.with_borrow_mut(f)
}

/// Walks `path` (absolute, no symlinks followed except along the way when `follow`).
pub fn fs_lookup(path: &str) -> Option<u64> {
    with_fs(|fs| fs_walk(fs, ROOT_INO, path, true, 0))
}

fn fs_walk(fs: &Fs, base: u64, path: &str, follow: bool, hops: u32) -> Option<u64> {
    if hops > 40 {
        return None;
    }
    let mut cur = if path.starts_with('/') { ROOT_INO } else { base };
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    for (i, c) in comps.iter().enumerate() {
        let dir = fs.inodes.get(&cur)?;
        let next = *dir.entries.get(c.as_bytes())?;
        let node = fs.inodes.get(&next)?;
        if node.mode & 0o170000 == 0o120000 && (follow || i + 1 < comps.len()) {
            let target = String::from_utf8_lossy(&node.data).into_owned();
            cur = fs_walk(fs, cur, &target, true, hops + 1)?;
        } else {
            cur = next;
        }
    }
    Some(cur)
}

/// Creates the directories of `path` and returns its inode.
pub fn fs_mkdir_p(path: &str) -> u64 {
    with_fs(|fs| {
        let mut cur = ROOT_INO;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            let existing = fs.inodes[&cur].entries.get(c.as_bytes()).copied();
            cur = match existing {
                Some(i) => i,
                None => {
                    let i = fs.next;
                    fs.next += 1;
                    fs.inodes.insert(i, Inode { mode: 0o040755, uid: 0, gid: 0, rdev: 0, data: Vec::new(), entries: BTreeMap::new() });
                    fs.inodes.get_mut(&cur).unwrap().entries.insert(c.as_bytes().to_vec(), i);
                    i
                }
            };
        }
        cur
    })
}

fn fs_add(path: &str, mode: u32, data: &[u8]) -> u64 {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let d = fs_mkdir_p(dir);
    with_fs(|fs| {
        if let Some(old) = fs.inodes[&d].entries.get(name.as_bytes()).copied() {
            let n = fs.inodes.get_mut(&old).unwrap();
            n.mode = mode;
            n.data = data.to_vec();
            return old;
        }
        let i = fs.next;
        fs.next += 1;
        fs.inodes.insert(i, Inode { mode, uid: 0, gid: 0, rdev: 0, data: data.to_vec(), entries: BTreeMap::new() });
        fs.inodes.get_mut(&d).unwrap().entries.insert(name.as_bytes().to_vec(), i);
        i
    })
}

/// Writes a regular file (mode 0644), creating its directories.
pub fn fs_write(path: &str, data: &[u8]) -> u64 {
    fs_add(path, 0o100644, data)
}
/// Creates a symlink.
pub fn fs_symlink(path: &str, target: &str) -> u64 {
    fs_add(path, 0o120777, target.as_bytes())
}
/// The contents of a regular file (following symlinks), if it exists.
pub fn fs_read(path: &str) -> Option<Vec<u8>> {
    let i = fs_lookup(path)?;
    with_fs(|fs| Some(fs.inodes[&i].data.clone()))
}
/// The contents of a regular file as text (panics if missing).
pub fn fs_text(path: &str) -> String {
    String::from_utf8(fs_read(path).unwrap_or_else(|| panic!("missing {path}"))).unwrap()
}
/// The inode at `path` (not following a final symlink).
pub fn fs_node(path: &str) -> Option<Inode> {
    with_fs(|fs| {
        let i = fs_walk(fs, ROOT_INO, path, false, 0)?;
        fs.inodes.get(&i).cloned()
    })
}
/// The target of the symlink at `path`.
pub fn fs_readlink(path: &str) -> Option<String> {
    let n = fs_node(path)?;
    (n.mode & 0o170000 == 0o120000).then(|| String::from_utf8(n.data).unwrap())
}

pub mod zfs {
    use super::*;
    pub use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

    /// The fake file server (state in [`FS`]).
    pub struct ZfsServer;

    fn count(op: &'static str) -> Result<(), i64> {
        with_fs(|fs| {
            *fs.ops.entry(op).or_insert(0) += 1;
            match fs.fail.iter().find(|(o, _)| *o == op) {
                Some((_, e)) => Err(*e),
                None => Ok(()),
            }
        })
    }

    fn new_node(fs: &mut Fs, dir: u64, name: &[u8], node: Inode) -> Result<u64, i64> {
        let d = fs.inodes.get(&dir).ok_or(-2i64)?;
        if d.mode & 0o170000 != 0o040000 {
            return Err(-20);
        }
        if d.entries.contains_key(name) {
            return Err(-17);
        }
        let i = fs.next;
        fs.next += 1;
        fs.inodes.insert(i, node);
        fs.inodes.get_mut(&dir).unwrap().entries.insert(name.to_vec(), i);
        Ok(i)
    }

    impl ZfsServer {
        pub fn root_obj(&self) -> u64 {
            ROOT_INO
        }
        pub fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<u64, i64> {
            count("lookup")?;
            with_fs(|fs| {
                let d = fs.inodes.get(&dir).ok_or(-2i64)?;
                if d.mode & 0o170000 != 0o040000 {
                    return Err(-20);
                }
                // "." and ".." as the ZPL answers them
                if name == b"." {
                    return Ok(dir);
                }
                if name == b".." {
                    return Ok(fs.inodes.iter().find(|(_, n)| n.entries.values().any(|&c| c == dir)).map_or(ROOT_INO, |(&i, _)| i));
                }
                d.entries.get(name).copied().ok_or(-2)
            })
        }
        pub fn getattr(&mut self, ino: u64) -> Result<Attr, i64> {
            count("getattr")?;
            with_fs(|fs| {
                let n = fs.inodes.get(&ino).ok_or(-2i64)?;
                Ok(Attr { ino, mode: n.mode, uid: n.uid, gid: n.gid, rdev: n.rdev, size: n.data.len() as u64, nlink: 1, ..Default::default() })
            })
        }
        pub fn setattr(&mut self, ino: u64, set: SetAttr) -> Result<Attr, i64> {
            count("setattr")?;
            with_fs(|fs| {
                let n = fs.inodes.get_mut(&ino).ok_or(-2i64)?;
                if let Some(m) = set.mode {
                    n.mode = (n.mode & 0o170000) | (m & 0o7777);
                }
                if let Some(u) = set.uid {
                    n.uid = u;
                }
                if let Some(g) = set.gid {
                    n.gid = g;
                }
                if let Some(s) = set.size {
                    n.data.resize(s as usize, 0);
                }
                Ok::<(), i64>(())
            })?;
            self.getattr(ino)
        }
        pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
            count("read")?;
            with_fs(|fs| {
                let n = fs.inodes.get(&ino).ok_or(-2i64)?;
                let o = (offset as usize).min(n.data.len());
                let k = buf.len().min(n.data.len() - o);
                buf[..k].copy_from_slice(&n.data[o..o + k]);
                Ok(k)
            })
        }
        pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
            count("write")?;
            with_fs(|fs| {
                let n = fs.inodes.get_mut(&ino).ok_or(-2i64)?;
                let end = offset as usize + data.len();
                if n.data.len() < end {
                    n.data.resize(end, 0);
                }
                n.data[offset as usize..end].copy_from_slice(data);
                Ok(data.len())
            })
        }
        pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
            count("create")?;
            with_fs(|fs| new_node(fs, dir, name, Inode { mode: 0o100000 | perm, uid, gid, rdev: 0, data: Vec::new(), entries: BTreeMap::new() }))
        }
        pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> Result<u64, i64> {
            count("mknod")?;
            with_fs(|fs| new_node(fs, dir, name, Inode { mode, uid, gid, rdev, data: Vec::new(), entries: BTreeMap::new() }))
        }
        pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
            count("mkdir")?;
            with_fs(|fs| new_node(fs, dir, name, Inode { mode: 0o040000 | perm, uid, gid, rdev: 0, data: Vec::new(), entries: BTreeMap::new() }))
        }
        pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64, i64> {
            count("symlink")?;
            with_fs(|fs| new_node(fs, dir, name, Inode { mode: 0o120777, uid, gid, rdev: 0, data: target.to_vec(), entries: BTreeMap::new() }))
        }
        pub fn readlink(&mut self, ino: u64) -> Result<Vec<u8>, i64> {
            count("readlink")?;
            with_fs(|fs| {
                let n = fs.inodes.get(&ino).ok_or(-2i64)?;
                if n.mode & 0o170000 != 0o120000 {
                    return Err(-22);
                }
                Ok(n.data.clone())
            })
        }
        pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
            count("unlink")?;
            with_fs(|fs| {
                let d = fs.inodes.get_mut(&dir).ok_or(-2i64)?;
                let i = *d.entries.get(name).ok_or(-2i64)?;
                if fs.inodes[&i].mode & 0o170000 == 0o040000 {
                    return Err(-21);
                }
                fs.inodes.get_mut(&dir).unwrap().entries.remove(name);
                fs.inodes.remove(&i);
                Ok(())
            })
        }
        pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
            count("rmdir")?;
            with_fs(|fs| {
                let i = *fs.inodes.get(&dir).ok_or(-2i64)?.entries.get(name).ok_or(-2i64)?;
                let n = &fs.inodes[&i];
                if n.mode & 0o170000 != 0o040000 {
                    return Err(-20);
                }
                if !n.entries.is_empty() {
                    return Err(-39);
                }
                fs.inodes.get_mut(&dir).unwrap().entries.remove(name);
                fs.inodes.remove(&i);
                Ok(())
            })
        }
        /// Entries after `cookie` (an index), at most `max`, with "." and ".." first.
        pub fn readdir(&mut self, dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
            count("readdir")?;
            with_fs(|fs| {
                let d = fs.inodes.get(&dir).ok_or(-2i64)?;
                if d.mode & 0o170000 != 0o040000 {
                    return Err(-20);
                }
                let mut all: Vec<(Vec<u8>, u64)> = vec![(b".".to_vec(), dir), (b"..".to_vec(), dir)];
                all.extend(d.entries.iter().map(|(k, v)| (k.clone(), *v)));
                Ok(all
                    .into_iter()
                    .enumerate()
                    .skip(cookie as usize)
                    .take(max)
                    .map(|(i, (name, ino))| ReaddirEntry { name, ino, dtype: 0, next_cookie: i as u64 + 1 })
                    .collect())
            })
        }
    }

    pub fn with_server<R>(f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
        if let Some(e) = SERVER_DOWN.get() {
            return Err(e);
        }
        f(&mut ZfsServer)
    }
}

/// `fs::ZfsClient`: path resolution in the in-memory file system.
pub struct ZfsClient;
impl ZfsClient {
    pub fn resolve(_base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
        let p = String::from_utf8_lossy(path).into_owned();
        with_fs(|fs| fs_walk(fs, ROOT_INO, &p, follow, 0)).ok_or(-2)
    }
}

// ===================================================== the rest of Linux

thread_local! {
    /// `vfs::set_times` calls: (dirfd, path pointer, times).
    pub static SET_TIMES: RefCell<Vec<(i64, u64, Option<[(i64, u32); 2]>)>> = const { RefCell::new(Vec::new()) };
    /// `vfs::dispatch(getdents64)`: the result and the records it writes to the buffer.
    pub static GETDENTS64: RefCell<Option<(i64, Vec<u8>)>> = const { RefCell::new(None) };
    /// `lx::dev_open` claims every device with this result (a Linux service's major).
    pub static LX_DEV_OPEN: Cell<Option<i64>> = const { Cell::new(None) };
}
