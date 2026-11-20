//! The fake machine behind the stubs in `lib.rs`.
//!
//! State a test sets up (files of the pool, tasks, services, keys, the clock, the network
//! server's answers) lives in one thread-local [`State`]; [`reset`] clears it and takes the
//! global test lock, because the kernel files keep global state of their own (the console,
//! the admin session, the socket handles). Every test starts with `let _g = fake::reset();`.
//!
//! What the kernel files did is logged ([`State::log`]) in plain words, so tests can check
//! the effects ("spawn_chroot /ubuntu /usr/sbin/unix_chkpwd", "notify 9 2", ...).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use uefi::proto::console::text::{Key, ScanCode};
use uefi::Char16;

use crate::ipc::Message;

/// A fake task.
#[derive(Default, Clone)]
pub struct FakeTask {
    /// How many more times `is_task_alive` answers yes.
    pub alive_checks: u32,
    /// Its exit status (`proc::take_status`).
    pub status: Option<i32>,
}

/// The network or block server's answer to one call: `(endpoint, request, kind)` where
/// kind is "call", "once" or "queued".
pub type Handler = Box<dyn FnMut(u32, &Message, &str) -> Result<Message, i64>>;

/// Everything a test can set up.
#[derive(Default)]
pub struct State {
    /// Fake clock in nanoseconds (ticks are 10 ms).
    pub clock_ns: u64,
    /// Called on every sleep (`task::sleep_ms`, `WaitSet::wait`): lets a test change the
    /// world while kernel code waits.
    pub on_sleep: Option<Box<dyn FnMut(&mut State)>>,
    /// Keys the keyboard (hardware mode) will deliver.
    pub keys: VecDeque<Key>,
    /// Keys the UEFI console input will deliver.
    pub uefi_keys: VecDeque<Key>,
    /// QEMU fw_cfg files.
    pub fwcfg: BTreeMap<String, Vec<u8>>,
    /// Files on the EFI partition (`bootfs::file_exists`).
    pub boot_files: BTreeSet<String>,
    /// Files of the pool.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Directories of the pool.
    pub dirs: BTreeSet<String>,
    /// Pool operations fail with this message.
    pub fs_fail: Option<&'static str>,
    /// The pool's status, if the file server answers.
    pub pool: Option<(u64, u64, u64, u64)>,
    /// The pool's disk.
    pub disk: Option<(u64, bool, bool, String)>,
    /// Datasets `(name, mount, txg, snapshot)`; `None`: the file server does not answer.
    pub datasets: Option<Vec<(String, String, u64, bool)>>,
    /// What the kernel did, in words.
    pub log: Vec<String>,
    /// Tasks by id.
    pub tasks: BTreeMap<u64, FakeTask>,
    /// The next task id handed out by a spawn.
    pub next_tid: u64,
    /// Spawns fail with this message.
    pub spawn_fail: Option<&'static str>,
    /// The program loader refuses images.
    pub not_loadable: bool,
    /// The running task.
    pub current_tid: u64,
    /// Its personality.
    pub personality: Option<crate::task::TaskPersonality>,
    /// Credentials set on tasks: id -> (uid, gid, euid, egid, suid, sgid).
    pub creds: BTreeMap<u64, [u32; 6]>,
    /// Task snapshots (`get_task_snapshots`); `scheduler_active` false: not yet active.
    pub snapshots: Vec<crate::task::TaskSnapshot>,
    /// Whether the scheduler runs.
    pub scheduler_inactive: bool,
    /// Tasks `task_named` finds.
    pub named: BTreeMap<String, u64>,
    /// Services (`get_service_snapshots`).
    pub services: Vec<crate::task::supervisor::ServiceSnapshot>,
    /// Service control fails with this message.
    pub service_fail: Option<&'static str>,
    /// Endpoints online.
    pub online: BTreeSet<u32>,
    /// Server process of an endpoint.
    pub servers: BTreeMap<u32, u64>,
    /// Service windows (allocated on first use, 4 MiB each, leaked).
    pub windows: BTreeMap<u32, usize>,
    /// Answers to service calls.
    pub handler: Option<Handler>,
    /// Calls made: `(endpoint, label, args, kind)`.
    pub calls: Vec<(u32, u32, [u64; 4], String)>,
    /// `request_list` and `irq_stats` answers.
    pub requests: Vec<(u64, u32, u64, &'static str, crate::ipc::service::CallMode)>,
    /// IRQ statistics.
    pub irqs: Vec<(u8, u64, u64, u64, u32, bool)>,
    /// IOMMU: on, test enabled, the adapter's source id, faults.
    pub iommu_on: bool,
    pub iommu_test: bool,
    pub iommu_dev: Option<u16>,
    pub iommu_faults: Vec<crate::arch::iommu::FaultRecord>,
    /// Faults the next `poll_faults` adds.
    pub iommu_new_faults: Vec<crate::arch::iommu::FaultRecord>,
    /// No memory for `ContiguousFrames`.
    pub no_frames: bool,
    /// The live session (`live::is_live`).
    pub live: bool,
    /// `prefault_current` refuses.
    pub prefault_fails: bool,
    /// The heap's self-test fails with this.
    pub heap_test_fail: Option<&'static str>,
    /// The heap is not set up (console output goes straight to the screen).
    pub heap_uninit: bool,
    /// The current task has no fd 1.
    pub no_fd1: bool,
    /// What the current task wrote on fd 1.
    pub out: String,
    /// Kernel log lines (`klog`).
    pub klog: String,
    /// The real-time clock answers (`uefi::runtime::get_time` under `with_kernel_tables`).
    pub rtc: Option<(u16, u8, u8, u8, u8, u8)>,
    /// MSRs.
    pub msrs: BTreeMap<u32, u64>,
    /// MSR writes are ignored (the read-back test fails).
    pub msr_stuck: bool,
    /// Page table translation answers.
    pub translate: Option<(u64, u64, x86_64::structures::paging::PageTableFlags)>,
    /// Device files fail with this.
    pub devices_fail: Option<&'static str>,
    /// The network interface (`net::client::iface` reads the real status area; this is
    /// for stubs that need it without one).
    pub pci: Vec<(u16, u16, u64)>,
    /// The kernel heap stats.
    pub heap: (u64, usize, usize, usize),
    /// Physical memory: total, allocated, free.
    pub phys: (u64, u64, u64),
    /// Frames the frame allocator still gives, and how many it gave.
    pub frames_left: u64,
    pub frames_given: u64,
    /// Where the image was loaded (`relocate::image_phys`).
    pub image_phys: Option<u64>,
    /// The hardware takeover fails with this.
    pub takeover_fail: Option<&'static str>,
    /// The heap's set-up fails with this.
    pub heap_init_fail: Option<&'static str>,
    /// Hydra's page table root cannot be made.
    pub kernel_space_fail: Option<&'static str>,
    /// Kernel tasks spawned (`task::spawn`): name and entry, for the test to run.
    pub kernel_fns: Vec<(&'static str, fn())>,
    /// What went to COM1 without the console (`raw_serial`).
    pub serial: String,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Runs `f` on the fake machine.
pub fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// Appends `s` to the log.
pub fn log(s: impl Into<String>) {
    with(|st| st.log.push(s.into()));
}

/// The log so far (cleared).
pub fn take_log() -> Vec<String> {
    with(|s| std::mem::take(&mut s.log))
}

/// Whether the log has an entry starting with `prefix`.
pub fn logged(prefix: &str) -> bool {
    with(|s| s.log.iter().any(|l| l.starts_with(prefix)))
}

/// What the current task wrote on fd 1 so far (cleared).
pub fn take_out() -> String {
    with(|s| std::mem::take(&mut s.out))
}

/// The kernel log so far (cleared).
pub fn take_klog() -> String {
    with(|s| std::mem::take(&mut s.klog))
}

/// The global test lock: the kernel files keep global state.
static LOCK: Mutex<()> = Mutex::new(());

/// A fresh fake machine, and the global test lock (held until the guard drops).
pub fn reset() -> MutexGuard<'static, ()> {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    STATE.with(|s| {
        let mut st = s.borrow_mut();
        *st = State::default();
        st.next_tid = 100;
        st.current_tid = 7;
        st.heap = (0xFFFF_9000_0000_0000, 8 << 20, 1 << 20, 7 << 20);
        st.phys = (512 << 20, 64 << 20, 448 << 20);
    });
    crate::uefi_fake::install();
    crate::uefi_fake::reset();
    g
}

/// Ticks of the fake clock (100 Hz).
pub fn ticks() -> u64 {
    with(|s| s.clock_ns / 10_000_000)
}

/// Moves the fake clock on by `ns` and runs the sleep hook.
pub fn advance(ns: u64) {
    let hook = with(|s| {
        s.clock_ns += ns;
        s.on_sleep.take()
    });
    // A kernel loop that never ends in a test: fail instead of spinning forever
    assert!(with(|s| s.clock_ns) < 36_000_000_000_000, "the fake clock passed 10 hours: a kernel loop does not end");
    if let Some(mut h) = hook {
        with(|s| h(s));
        with(|s| {
            if s.on_sleep.is_none() {
                s.on_sleep = Some(h);
            }
        });
    }
}

/// A printable key.
pub fn key(c: char) -> Key {
    Key::Printable(Char16::try_from(c).unwrap())
}

/// A special key.
pub fn special(sc: u16) -> Key {
    Key::Special(ScanCode(sc))
}

/// Queues the keys of `s` (hardware mode keyboard).
pub fn type_keys(s: &str) {
    with(|st| st.keys.extend(s.chars().map(key)));
}

/// Adds a file to the pool (and its parent directories).
pub fn file(path: &str, data: &[u8]) {
    with(|s| {
        s.files.insert(path.to_string(), data.to_vec());
        let mut p = path.to_string();
        while let Some(i) = p.rfind('/') {
            p.truncate(i);
            s.dirs.insert(if p.is_empty() { "/".to_string() } else { p.clone() });
        }
    });
}

/// Adds a directory to the pool.
pub fn dir(path: &str) {
    with(|s| {
        s.dirs.insert(path.to_string());
    });
}

/// A task that is alive for `checks` more `is_task_alive` calls, then exits with `status`.
pub fn task(id: u64, checks: u32, status: Option<i32>) {
    with(|s| {
        s.tasks.insert(id, FakeTask { alive_checks: checks, status });
    });
}
