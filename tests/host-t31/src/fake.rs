//! Fake state behind the stubs in `lib.rs` (Group 31).
//!
//! Unlike `tests/host`'s fakes, most state here is global, not thread-local:
//! the scheduler is one global object that several test threads (fake CPUs)
//! use at once. Tests that touch it hold `common::serial()` and call [`reset`].
//!
//! The calling thread's CPU number ([`set_cpu`]) is thread-local: each test
//! thread plays one CPU, `arch::percpu::cpu()` returns its number.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

pub const MAX_CPUS: usize = 16;

// ------------------------------------------------------------------- CPUs

thread_local! {
    static CPU: Cell<usize> = const { Cell::new(0) };
}

/// Makes the calling thread play CPU `c`.
pub fn set_cpu(c: usize) {
    CPU.with(|x| x.set(c));
}

/// The CPU the calling thread plays.
pub fn cpu() -> usize {
    CPU.with(|x| x.get())
}

/// CPUs online (`arch::smp::online`).
pub static ONLINE: AtomicUsize = AtomicUsize::new(1);
/// Each CPU's "leaving" word (`arch::percpu`): task id + 1 whose stack it is leaving.
pub static LEAVING: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Each CPU's kernel stack top for system calls (`set_kernel_rsp`).
pub static KERNEL_RSP: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Each CPU's TSS RSP0 (`gdt::set_privilege_stack`).
pub static RSP0: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Each CPU's FS base MSR.
pub static FS_BASE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

// ------------------------------------------------------------ kernel lock, kicks

/// Whether the calling CPU holds the kernel lock (`smp::bkl_held`).
pub static BKL_HELD: AtomicBool = AtomicBool::new(true);
/// `smp::bkl_exit` calls.
pub static BKL_EXITS: AtomicUsize = AtomicUsize::new(0);
/// Hook run by `smp::bkl_exit` (lets a test end a wait that drops the kernel lock).
pub static BKL_EXIT_HOOK: Mutex<Option<fn()>> = Mutex::new(None);
/// `smp::bkl_enter`/`bkl_enter_idle` calls.
pub static BKL_ENTERS: AtomicUsize = AtomicUsize::new(0);
/// `smp::kick_idle` calls.
pub static KICK_IDLE: AtomicUsize = AtomicUsize::new(0);
/// wave11 GR: threads with a signal pending (`compat::linux::proc::signal_pending_for`).
pub static SIGNALLED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// CPUs `smp::kick_cpu` was called for.
pub static KICKED_CPUS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
/// What `smp::kick_pending` answers.
pub static KICK_PENDING: AtomicBool = AtomicBool::new(false);
/// `smp::switch_kick` arguments.
pub static SWITCH_KICKS: Mutex<Vec<bool>> = Mutex::new(Vec::new());
/// `smp::serve_tlb` calls (each one a spin while the scheduler lock was busy).
pub static SERVE_TLB: AtomicUsize = AtomicUsize::new(0);
/// What `smp::idle_poll` answers.
pub static IDLE_POLL: AtomicBool = AtomicBool::new(false);
/// What `smp::idle_halting` answers.
pub static IDLE_HALTING: AtomicBool = AtomicBool::new(true);
/// What `smp::idle_halt_ended` answers.
pub static IDLE_HALT_ENDED: AtomicBool = AtomicBool::new(false);
/// CR3 values `pcid::load_cr3` loaded.
pub static CR3_LOADS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

// ------------------------------------------------------------------- clock

/// Timer ticks since boot (`pit::ticks`).
pub static TICKS: AtomicU64 = AtomicU64::new(1_000);
/// Nanoseconds since boot (`pit::now_ns`); 0: derived from the ticks.
pub static NOW_NS: AtomicU64 = AtomicU64::new(0);
/// Whether the timer runs (`pit::is_active`).
pub static PIT_ACTIVE: AtomicBool = AtomicBool::new(true);
/// Ticks slept through `pit::sleep_ticks` / `pit::sleep_ms` (the fake clock moves).
pub static PIT_SLEPT: AtomicU64 = AtomicU64::new(0);
/// Hook run by `pit::now_ns` (lets a test move the clock while code spins on it).
pub static NOW_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

pub const TICK_NS: u64 = 10_000_000;

pub fn ticks() -> u64 {
    TICKS.load(Ordering::SeqCst)
}
pub fn set_ticks(t: u64) {
    TICKS.store(t, Ordering::SeqCst);
}
pub fn now_ns() -> u64 {
    let hook = *NOW_HOOK.lock().unwrap();
    if let Some(h) = hook {
        h();
    }
    match NOW_NS.load(Ordering::SeqCst) {
        0 => ticks() * TICK_NS,
        n => n,
    }
}
pub fn sleep_ticks(t: u64) {
    PIT_SLEPT.fetch_add(t, Ordering::SeqCst);
    TICKS.fetch_add(t, Ordering::SeqCst);
    let n = NOW_NS.load(Ordering::SeqCst);
    if n != 0 {
        NOW_NS.store(n + t * TICK_NS, Ordering::SeqCst);
    }
}

// ------------------------------------------------------------------- yields

/// How the host's stand-in for `int 0x81` (the yield vector) behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum YieldMode {
    /// Only counts the yield.
    Count,
    /// The CPU waits until its current task may run again (not blocked or
    /// sleeping), as the real CPU would run other work and later resume it.
    /// Panics after [`YIELD_TIMEOUT_MS`]: a task nobody wakes (lost wakeup).
    WaitRunnable,
    /// Runs [`YIELD_HOOK`].
    Hook,
}

pub static YIELD_MODE: Mutex<YieldMode> = Mutex::new(YieldMode::Count);
pub static YIELD_HOOK: Mutex<Option<fn()>> = Mutex::new(None);
/// Yields so far (all CPUs).
pub static YIELDS: AtomicUsize = AtomicUsize::new(0);
pub static YIELD_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5_000);

/// The host's `int 0x81`.
pub fn host_yield() {
    YIELDS.fetch_add(1, Ordering::SeqCst);
    let mode = *YIELD_MODE.lock().unwrap();
    match mode {
        YieldMode::Count => {}
        YieldMode::Hook => {
            let h = *YIELD_HOOK.lock().unwrap();
            if let Some(h) = h {
                h();
            }
        }
        YieldMode::WaitRunnable => wait_runnable(),
    }
}

/// Waits until the calling CPU's current task is ready or running again (then marks
/// it running), applying deferred wakeups meanwhile as a timer tick would.
pub fn wait_runnable() {
    use crate::task::TaskState;
    let start = std::time::Instant::now();
    let limit = std::time::Duration::from_millis(YIELD_TIMEOUT_MS.load(Ordering::Relaxed));
    loop {
        {
            let mut s = crate::task::SCHEDULER.lock();
            s.apply_wakes();
            let r = s.current_task_mut(|t| {
                if matches!(t.state, TaskState::Ready | TaskState::Running) {
                    t.state = TaskState::Running;
                    true
                } else {
                    false
                }
            });
            if r != Some(false) {
                return;
            }
        }
        if start.elapsed() > limit {
            let id = crate::task::SCHEDULER.lock().current_task_id().0;
            panic!("lost wakeup: task {} on cpu {} was never woken", id, cpu());
        }
        std::thread::yield_now();
    }
}

/// Native system calls made through `syscall::user` (number, arguments).
pub static SYSCALLS: Mutex<Vec<(u64, [u64; 3])>> = Mutex::new(Vec::new());
/// What the next native system calls return (front first; empty: 0).
pub static SYSCALL_RETURNS: Mutex<Vec<i64>> = Mutex::new(Vec::new());
/// Hook for system calls that write through a pointer argument (`SYS_PIPE`).
pub static SYSCALL_HOOK: Mutex<Option<fn(u64, [u64; 3])>> = Mutex::new(None);

/// The host's `syscall` instruction.
pub fn host_syscall(num: u64, args: [u64; 3]) -> i64 {
    SYSCALLS.lock().unwrap().push((num, args));
    let hook = *SYSCALL_HOOK.lock().unwrap();
    if let Some(h) = hook {
        h(num, args);
    }
    let mut r = SYSCALL_RETURNS.lock().unwrap();
    if r.is_empty() {
        0
    } else {
        r.remove(0)
    }
}

// ------------------------------------------------------------------- console

/// Everything written to the serial port.
pub static SERIAL: Mutex<String> = Mutex::new(String::new());
/// Kernel log lines (`kprintln!`).
pub static KLOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// What `console::check_interrupt` answers (Ctrl+C).
pub static CTRL_C: AtomicBool = AtomicBool::new(false);

pub fn klog(s: String) {
    KLOG.lock().unwrap().push(s);
}

pub fn klog_has(part: &str) -> bool {
    KLOG.lock().unwrap().iter().any(|l| l.contains(part))
}

pub fn serial_has(part: &str) -> bool {
    SERIAL.lock().unwrap().contains(part)
}

// ------------------------------------------------------------------- processes

/// `proc::register_process` calls: (pid, ppid, tid, inherit_from).
pub static REG_PROCS: Mutex<Vec<(u64, u64, u64, Option<u64>)>> = Mutex::new(Vec::new());
/// `proc::register_thread` calls: (pid, tid, creator).
pub static REG_THREADS: Mutex<Vec<(u64, u64, u64)>> = Mutex::new(Vec::new());
/// `proc::thread_exited` calls: (pid, tid).
pub static EXITED: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
/// `proc::parent_of` answers (pid -> ppid; missing: 1).
pub static PARENTS: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());
/// `ident_changed` calls.
pub static IDENT_CHANGED: AtomicUsize = AtomicUsize::new(0);
/// What `admin::acct_on` answers, and the tasks `admin::note_task` saw (tgid, exe).
pub static ACCT_ON: AtomicBool = AtomicBool::new(false);
pub static ACCT: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
/// Futex keys woken by the clear-tid wake: (space, uaddr); and the ids it returns.
pub static FUTEX_WAKES: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
pub static FUTEX_WOKEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// Robust lists walked: (head, tid, space); and the ids the walk wakes.
pub static ROBUST: Mutex<Vec<(u64, u32, u64)>> = Mutex::new(Vec::new());
pub static ROBUST_WOKEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// Profiler events: (kind, task id).
pub static PROF: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());
/// perf ticks and switches: (kind, tgid).
pub static PERF: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());
/// `vm::retire_mm` stand-in should refuse (keep the address space).
pub static RETIRE_REFUSES: AtomicBool = AtomicBool::new(false);
/// Files for `mm::inode_source` (inode -> bytes).
pub static INODES: Mutex<BTreeMap<u64, Vec<u8>>> = Mutex::new(BTreeMap::new());
/// Paths `ZfsClient::resolve` / `resolve_in` know (path -> inode).
pub static PATHS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
/// Files read by path (`ZfsClient::file_stat`/`read_file_by_path`).
pub static FILES: Mutex<BTreeMap<String, Vec<u8>>> = Mutex::new(BTreeMap::new());
/// Files on the boot volume (`bootfs::read_boot_file`).
pub static BOOT_FILES: Mutex<BTreeMap<String, Vec<u8>>> = Mutex::new(BTreeMap::new());
/// Whether firmware boot services were left (`boot_services::is_hardware_takeover_complete`).
pub static TAKEOVER: AtomicBool = AtomicBool::new(true);
/// Address ranges made user accessible (`paging::make_user_accessible`).
pub static USER_RANGES: Mutex<Vec<(u64, usize)>> = Mutex::new(Vec::new());
/// Descriptor tables closed (`FdTable::close_all`).
pub static FDS_CLOSED: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------------- services

/// Endpoints online (`service::is_online`), with their server task.
pub static SERVERS: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());
/// Whether another task holds a service window (`service::window_held_by_other`).
pub static WINDOW_HELD: AtomicBool = AtomicBool::new(false);
/// Windows held: (endpoint, task) (`service::holds_window`, `window_holders`).
pub static WINDOW_HOLDERS: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());
/// Endpoint -> callers with a queued request to it (`service::serves_queued_for`).
pub static QUEUED: Mutex<BTreeMap<u32, Vec<u64>>> = Mutex::new(BTreeMap::new());
/// Endpoint aliases (`service::primary_of`).
pub static PRIMARY: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());
/// Service-call log: (what, endpoint, a, b) for grants, unregister, release_irqs...
pub static SVC_LOG: Mutex<Vec<(&'static str, u32, u64, u64)>> = Mutex::new(Vec::new());
/// (wave7 GB) `(endpoint, task)`: registered by "another driver" right after the next
/// `server_of(endpoint)` (a race with the supervisor's look).
pub static REGISTER_AFTER_LOOK: Mutex<Option<(u32, u64)>> = Mutex::new(None);
/// Answer to `service::call` / `call_once_mode`: hook(endpoint, request) -> reply.
pub static CALL_HOOK: Mutex<Option<fn(u32, crate::ipc::Message) -> Result<crate::ipc::Message, i64>>> = Mutex::new(None);
/// MSI line per (bus, device, function) (`service::msi_line`), and MSI-X.
pub static MSI: Mutex<BTreeMap<(u8, u8, u8), u8>> = Mutex::new(BTreeMap::new());
pub static MSIX: Mutex<BTreeMap<(u8, u8, u8), (u8, u64, u32, u32)>> = Mutex::new(BTreeMap::new());
/// Linux services hosted by an endpoint (`lx::svc::host_by_endpoint`).
pub static LX_HOSTS: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());
/// Restart-ladder state (`lx::restart`): may_restart answer and the calls made.
pub static LX_MAY_RESTART: AtomicBool = AtomicBool::new(true);
pub static LX_LOG: Mutex<Vec<(&'static str, u8)>> = Mutex::new(Vec::new());
/// `lx::watch` / `lx::init` / `lx::dump` calls.
pub static LX_CALLS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
/// Next due linux-server timer (`lx::timer::next_due`), and whether `fire` posts.
pub static LX_TIMER_DUE: AtomicU64 = AtomicU64::new(u64::MAX);
pub static LX_TIMER_POSTS: AtomicBool = AtomicBool::new(false);

// ------------------------------------------------------------------- PCI

/// A fake PCI function: its device record and configuration space.
#[derive(Clone)]
pub struct FakePci {
    pub dev: crate::arch::pci::PciDevice,
    pub config: [u8; 256],
    pub bars: [(u64, u64); 6],
}

pub static PCI: Mutex<Vec<FakePci>> = Mutex::new(Vec::new());
/// Devices bus mastering was enabled for; IOMMU attaches: (endpoint, name).
pub static BUS_MASTERS: Mutex<Vec<(u8, u8, u8)>> = Mutex::new(Vec::new());
pub static IOMMU_ATTACH: Mutex<Vec<(u32, &'static str)>> = Mutex::new(Vec::new());
pub static IOMMU_DMA_TEST: AtomicBool = AtomicBool::new(false);
pub static IOMMU_POLLS: AtomicUsize = AtomicUsize::new(0);
/// `bootdisk::driver_arg` / `new_guid_id` answers.
pub static BOOTDISK_ARG: Mutex<Option<String>> = Mutex::new(None);
pub static NEW_GUID: Mutex<Option<u64>> = Mutex::new(None);
/// e1000 adapter (`net::e1000::find_adapter`): device, BAR0, model.
pub static E1000: Mutex<Option<(crate::arch::pci::PciDevice, u64, &'static str)>> = Mutex::new(None);
/// `snd::set_controller` calls (slot); `snd::start` / `usb_input::start` calls.
pub static SND: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub static STARTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
/// Total usable RAM the frame allocator reports to `zfs_args` (bytes; 0: the real one).
pub static RAM: AtomicU64 = AtomicU64::new(0);

/// Adds a PCI function; returns its index for the other `pci_*` helpers.
#[allow(clippy::too_many_arguments)]
pub fn pci_add(bus: u8, device: u8, function: u8, vendor: u16, dev_id: u16, class: u8, sub: u8, prog_if: u8) -> usize {
    let mut config = [0u8; 256];
    config[0x09] = prog_if;
    let dev = crate::arch::pci::PciDevice {
        bus,
        device,
        function,
        vendor_id: vendor,
        device_id: dev_id,
        class_id: class,
        subclass_id: sub,
        bar0: 0,
        irq_line: 11,
    };
    let mut p = PCI.lock().unwrap();
    p.push(FakePci { dev, config, bars: [(0, 0); 6] });
    p.len() - 1
}

pub fn pci_set_bar(i: usize, bar: usize, addr: u64, size: u64) {
    PCI.lock().unwrap()[i].bars[bar] = (addr, size);
}

pub fn pci_poke32(i: usize, off: usize, v: u32) {
    PCI.lock().unwrap()[i].config[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn pci_peek32(i: usize, off: usize) -> u32 {
    let p = PCI.lock().unwrap();
    u32::from_le_bytes(p[i].config[off..off + 4].try_into().unwrap())
}

pub fn pci_find(bus: u8, device: u8, function: u8) -> Option<usize> {
    PCI.lock().unwrap().iter().position(|p| (p.dev.bus, p.dev.device, p.dev.function) == (bus, device, function))
}

// ------------------------------------------------------------------- reset

/// Puts every fake back to its start state, and the scheduler, the deferred wakeups,
/// the parked tasks and the per-CPU task markers. Call with `common::serial()` held.
pub fn reset() {
    set_cpu(0);
    x86_64::set_cr3(0x1000);
    ONLINE.store(1, Ordering::SeqCst);
    for a in LEAVING.iter().chain(KERNEL_RSP.iter()).chain(RSP0.iter()).chain(FS_BASE.iter()) {
        a.store(0, Ordering::SeqCst);
    }
    BKL_HELD.store(true, Ordering::SeqCst);
    BKL_EXITS.store(0, Ordering::SeqCst);
    BKL_ENTERS.store(0, Ordering::SeqCst);
    KICK_IDLE.store(0, Ordering::SeqCst);
    KICKED_CPUS.lock().unwrap().clear();
    KICK_PENDING.store(false, Ordering::SeqCst);
    SWITCH_KICKS.lock().unwrap().clear();
    SERVE_TLB.store(0, Ordering::SeqCst);
    IDLE_POLL.store(false, Ordering::SeqCst);
    IDLE_HALTING.store(true, Ordering::SeqCst);
    IDLE_HALT_ENDED.store(false, Ordering::SeqCst);
    CR3_LOADS.lock().unwrap().clear();
    TICKS.store(1_000, Ordering::SeqCst);
    NOW_NS.store(0, Ordering::SeqCst);
    PIT_ACTIVE.store(true, Ordering::SeqCst);
    PIT_SLEPT.store(0, Ordering::SeqCst);
    *NOW_HOOK.lock().unwrap() = None;
    *YIELD_MODE.lock().unwrap() = YieldMode::Count;
    *YIELD_HOOK.lock().unwrap() = None;
    YIELDS.store(0, Ordering::SeqCst);
    YIELD_TIMEOUT_MS.store(5_000, Ordering::SeqCst);
    SYSCALLS.lock().unwrap().clear();
    SYSCALL_RETURNS.lock().unwrap().clear();
    *SYSCALL_HOOK.lock().unwrap() = None;
    SERIAL.lock().unwrap().clear();
    KLOG.lock().unwrap().clear();
    CTRL_C.store(false, Ordering::SeqCst);
    REG_PROCS.lock().unwrap().clear();
    REG_THREADS.lock().unwrap().clear();
    EXITED.lock().unwrap().clear();
    PARENTS.lock().unwrap().clear();
    IDENT_CHANGED.store(0, Ordering::SeqCst);
    ACCT_ON.store(false, Ordering::SeqCst);
    ACCT.lock().unwrap().clear();
    FUTEX_WAKES.lock().unwrap().clear();
    FUTEX_WOKEN.lock().unwrap().clear();
    ROBUST.lock().unwrap().clear();
    ROBUST_WOKEN.lock().unwrap().clear();
    PROF.lock().unwrap().clear();
    PERF.lock().unwrap().clear();
    RETIRE_REFUSES.store(false, Ordering::SeqCst);
    INODES.lock().unwrap().clear();
    PATHS.lock().unwrap().clear();
    FILES.lock().unwrap().clear();
    BOOT_FILES.lock().unwrap().clear();
    TAKEOVER.store(true, Ordering::SeqCst);
    USER_RANGES.lock().unwrap().clear();
    FDS_CLOSED.store(0, Ordering::SeqCst);
    SERVERS.lock().unwrap().clear();
    WINDOW_HELD.store(false, Ordering::SeqCst);
    WINDOW_HOLDERS.lock().unwrap().clear();
    QUEUED.lock().unwrap().clear();
    PRIMARY.lock().unwrap().clear();
    SVC_LOG.lock().unwrap().clear();
    *REGISTER_AFTER_LOOK.lock().unwrap() = None;
    *CALL_HOOK.lock().unwrap() = None;
    MSI.lock().unwrap().clear();
    MSIX.lock().unwrap().clear();
    LX_HOSTS.lock().unwrap().clear();
    LX_MAY_RESTART.store(true, Ordering::SeqCst);
    LX_LOG.lock().unwrap().clear();
    LX_CALLS.lock().unwrap().clear();
    LX_TIMER_DUE.store(u64::MAX, Ordering::SeqCst);
    LX_TIMER_POSTS.store(false, Ordering::SeqCst);
    PCI.lock().unwrap().clear();
    BUS_MASTERS.lock().unwrap().clear();
    IOMMU_ATTACH.lock().unwrap().clear();
    IOMMU_DMA_TEST.store(false, Ordering::SeqCst);
    IOMMU_POLLS.store(0, Ordering::SeqCst);
    *BOOTDISK_ARG.lock().unwrap() = None;
    *NEW_GUID.lock().unwrap() = None;
    *E1000.lock().unwrap() = None;
    SND.lock().unwrap().clear();
    STARTS.lock().unwrap().clear();
    RAM.store(0, Ordering::SeqCst);
    crate::arch::idt::reset();
    crate::arch::syscall::reset();

    // The kernel's own globals my files keep
    use crate::task;
    task::scheduler::reap_dead_tasks();
    {
        let mut s = task::SCHEDULER.lock();
        *s = task::scheduler::Scheduler::new();
        s.apply_wakes(); // drains the deferred wakeups (no task to wake)
        // Clears the lock-free hand-off and deferred-call flags the last test may have left
        s.begin_handoff(u64::MAX, 0);
        s.end_handoff(u64::MAX);
    }
    KICK_IDLE.store(0, Ordering::SeqCst);
    task::PREEMPT_POINTS.on(0).store(0, Ordering::SeqCst);
    for c in 0..MAX_CPUS {
        task::CURRENT_RETIRED[c].store(false, Ordering::SeqCst);
        task::CURRENT_TID.on(c).store(0, Ordering::SeqCst);
        task::PREEMPT_POINTS.on(c).store(0, Ordering::SeqCst);
        task::CURRENT_SYSCALL.on(c).store(u64::MAX, Ordering::SeqCst);
        task::CURRENT_SYSCALL_ARGS[0].on(c).store(0, Ordering::SeqCst);
        task::CURRENT_SYSCALL_ARGS[1].on(c).store(0, Ordering::SeqCst);
        task::CURRENT_KSTACK[0].on(c).store(0, Ordering::SeqCst);
        task::CURRENT_KSTACK[1].on(c).store(0, Ordering::SeqCst);
        task::TICK_DEFERRED.on(c).store(0, Ordering::SeqCst);
        task::TICK_YIELD.on(c).store(0, Ordering::SeqCst);
        task::scheduler::DIRECT_TO.on(c).store(0, Ordering::SeqCst);
        task::scheduler::DIRECT_HINT.on(c).store(0, Ordering::SeqCst);
        task::scheduler::DIRECT_GUARD.on(c).store(0, Ordering::SeqCst);
        task::scheduler::BLOCK_NOBKL.on(c).store(0, Ordering::SeqCst);
        task::scheduler::CURRENT_IDX.on(c).store(0, Ordering::SeqCst);
        for k in 0..3 {
            task::scheduler::CPU_TIMES[c][k].store(0, Ordering::SeqCst);
        }
    }
    for l in task::scheduler::LOAD_AVG.iter() {
        l.store(0, Ordering::SeqCst);
    }
    *BKL_EXIT_HOOK.lock().unwrap() = None;
    task::HR_EARLIEST.store(u64::MAX, Ordering::SeqCst);
    task::STARTED.store(false, Ordering::SeqCst);
    *task::SUPERVISOR.lock() = task::Supervisor::new();
    crate::fs::zfs::POOL_ON_USB.store(false, Ordering::SeqCst);
}
