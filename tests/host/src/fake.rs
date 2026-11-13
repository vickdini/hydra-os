//! Host stand-ins for the kernel services that the modules under test call.
//!
//! The kernel files compiled by this crate reach out to the scheduler, the
//! file-descriptor table, the ZFS client, the NIC and the page tables. Here
//! each of those is a small fake whose state lives in thread-locals. The test
//! harness runs every `#[test]` on its own thread, so tests can configure the
//! fakes freely and still run in parallel. Call [`reset`] at the start of a
//! test if it relies on a clean slate.
//!
//! `lib.rs` re-exports these items at the module paths the kernel uses
//! (`crate::task::wait::WaitQueue`, `crate::fs::client::ZfsClient`, ...).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

thread_local! {
    /// Effective capability bits of the "current task". `None` = no task.
    pub static CAPS: Cell<Option<u64>> = const { Cell::new(Some(0)) };
    /// What `signal_pending()` reports.
    pub static SIGNAL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// Number of `WaitQueue::wake_all` calls.
    pub static WAKES: Cell<usize> = const { Cell::new(0) };
    /// Files visible through `ZfsClient` (path -> contents). Writes land here too.
    pub static ZFS_FILES: RefCell<BTreeMap<String, Vec<u8>>> = RefCell::new(BTreeMap::new());
    /// Directories created through `ZfsClient::create_dir_all`, in call order.
    pub static ZFS_DIRS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// Paths for which `write_file_by_path_batch` fails.
    pub static ZFS_WRITE_FAILS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// Number of `ZfsClient::sync` calls.
    pub static ZFS_SYNCS: Cell<usize> = const { Cell::new(0) };
    /// Files on the FAT boot volume (`shell::fs::read_boot_file`).
    pub static BOOT_FILES: RefCell<BTreeMap<String, Vec<u8>>> = RefCell::new(BTreeMap::new());
    /// Ranges passed to `make_user_accessible`.
    pub static USER_RANGES: RefCell<Vec<(u64, usize)>> = RefCell::new(Vec::new());
    /// Make `make_user_accessible` fail with this message.
    pub static PAGING_ERROR: Cell<Option<&'static str>> = const { Cell::new(None) };
    /// File-descriptor table of the current task.
    pub static FDS: RefCell<Fds> = RefCell::new(Fds::default());
    /// Fake network interface state.
    pub static NET: RefCell<Net> = RefCell::new(Net::default());
}

/// Restore every fake to its initial state.
pub fn reset() {
    CAPS.set(Some(0));
    SIGNAL_PENDING.set(false);
    WAKES.set(0);
    ZFS_FILES.with_borrow_mut(|m| m.clear());
    ZFS_DIRS.with_borrow_mut(|v| v.clear());
    ZFS_WRITE_FAILS.with_borrow_mut(|v| v.clear());
    ZFS_SYNCS.set(0);
    BOOT_FILES.with_borrow_mut(|m| m.clear());
    USER_RANGES.with_borrow_mut(|v| v.clear());
    PAGING_ERROR.set(None);
    FDS.with_borrow_mut(|f| *f = Fds::default());
    NET.with_borrow_mut(|n| *n = Net::default());
    NX_ENABLED.set(true);
    IN_USERNS.set(false);
    SIGKILL_PENDING.set(false);
    TASK_MM.with_borrow_mut(|m| *m = None);
    CREDS.set((0, 0));
    UID.set(0);
    POSTED.with_borrow_mut(|v| v.clear());
    IDS.set((1, 1));
    TICKS.set(1_000);
    INODES.with_borrow_mut(|m| m.clear());
    INODE_PATHS.with_borrow_mut(|m| m.clear());
    INODE_REFS.with_borrow_mut(|m| m.clear());
    INODE_READ_FAILS.set(false);
    TREE.with_borrow_mut(|t| t.clear());
    SECCOMP.set(Default::default());
    SIBLINGS.with_borrow_mut(|v| v.clear());
    SIGSYS.with_borrow_mut(|v| v.clear());
    TRACER.with_borrow_mut(|t| *t = None);
}

// ------------------------------------------------------------------- tasks

/// Capability set of a task, as far as the code under test looks at it.
pub struct Caps {
    pub effective: u64,
    /// Capabilities held only inside a user namespace (not over the host).
    pub in_userns: bool,
}

impl Caps {
    pub fn has(&self, mask: u64) -> bool {
        self.effective & mask == mask
    }
}

/// The parts of the kernel's `Task` the code under test reads.
pub struct Task {
    pub caps: Caps,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// Address space of the current task (see [`TASK_MM`]).
    pub mm: Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>,
    /// seccomp / no_new_privs / Landlock state (see [`SECCOMP`]).
    pub seccomp: crate::compat::linux::seccomp::State,
    pub id: TaskId,
    pub tgid: u64,
}

/// Thread id, as in the kernel's `task::TaskId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId(pub u64);

impl Task {
    /// Another thread of the current process, for [`SIBLINGS`].
    pub fn sibling(tid: u64) -> Task {
        Task {
            caps: Caps { effective: 0, in_userns: false },
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            mm: None,
            seccomp: Default::default(),
            id: TaskId(tid),
            tgid: IDS.get().1,
        }
    }
}

thread_local! {
    /// Whether the current task's capabilities come from a user namespace.
    pub static IN_USERNS: Cell<bool> = const { Cell::new(false) };
    /// What `proc::sigkill_pending()` reports.
    pub static SIGKILL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// Real uid of the current task.
    pub static UID: Cell<u32> = const { Cell::new(0) };
    /// Signals posted through `proc::post_with_info`: (pid, sig, code, sender pid, sender uid, value).
    pub static POSTED: RefCell<Vec<(u64, u32, i32, u32, u32, u64)>> = const { RefCell::new(Vec::new()) };
    /// (euid, egid) of the current task.
    pub static CREDS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
    /// (tid, tgid) of the current task, as `proc::current_ids()` reports it.
    pub static IDS: Cell<(u64, u64)> = const { Cell::new((1, 1)) };
    /// IPC namespace of the current task. Give each test its own to isolate
    /// it from others sharing the kernel's global SysV tables.
    pub static IPC_NS: Cell<u64> = const { Cell::new(0) };
    /// Timer ticks reported by `pit::ticks()`.
    pub static TICKS: Cell<u64> = const { Cell::new(1_000) };
    /// The current task's address space, as `current_mm()` sees it.
    pub static TASK_MM: RefCell<Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>> = const { RefCell::new(None) };
}

pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let effective = CAPS.get()?;
    let mm = TASK_MM.with_borrow(|m| m.clone());
    let (euid, egid) = CREDS.get();
    let (tid, tgid) = IDS.get();
    let seccomp = SECCOMP.take();
    let mut t = Task {
        caps: Caps { effective, in_userns: IN_USERNS.get() },
        uid: UID.get(),
        gid: egid,
        euid,
        egid,
        mm,
        seccomp,
        id: TaskId(tid),
        tgid,
    };
    let r = f(&mut t);
    CAPS.set(Some(t.caps.effective));
    SECCOMP.set(t.seccomp);
    Some(r)
}

thread_local! {
    /// The current task's seccomp/Landlock state; persists across calls.
    pub static SECCOMP: RefCell<crate::compat::linux::seccomp::State> = RefCell::new(Default::default());
    /// Other threads of the current process (seen through `task::SCHEDULER`).
    pub static SIBLINGS: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
    /// SIGSYS deliveries from seccomp RET_TRAP: (syscall nr, ip, data).
    pub static SIGSYS: RefCell<Vec<(i32, u64, i32)>> = const { RefCell::new(Vec::new()) };
    /// A ptrace tracer for seccomp RET_TRACE stops; `None` = not traced.
    pub static TRACER: RefCell<Option<Box<dyn FnMut(&mut crate::arch::syscall::SyscallFrame, u16) -> Result<(), i64>>>> =
        RefCell::new(None);
}

/// Stand-in for `task::SCHEDULER`: its tasks are the current one plus [`SIBLINGS`].
pub struct Scheduler;

pub static SCHEDULER: Scheduler = Scheduler;

pub struct SchedulerGuard;

impl Scheduler {
    pub fn lock(&self) -> SchedulerGuard {
        SchedulerGuard
    }
}

impl SchedulerGuard {
    pub fn for_each_task_mut(&mut self, mut f: impl FnMut(&mut Task)) {
        with_current_task_mut(|t| f(t));
        SIBLINGS.with_borrow_mut(|v| v.iter_mut().for_each(|t| f(t)));
    }
    pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        if tgid == IDS.get().1 {
            with_current_task_mut(|t| f(t))
        } else {
            None
        }
    }
}

/// `proc::die_by_signal`: the task would be killed. Reported as a panic
/// with the message "killed by signal N", which tests catch.
pub fn die_by_signal(sig: u32) -> ! {
    panic!("killed by signal {sig}")
}

pub fn force_seccomp_sigsys(nr: i32, ip: u64, errno: i32) {
    SIGSYS.with_borrow_mut(|v| v.push((nr, ip, errno)));
}

pub fn seccomp_stop(frame: &mut crate::arch::syscall::SyscallFrame, data: u16) -> Option<Result<(), i64>> {
    TRACER.with_borrow_mut(|t| t.as_mut().map(|f| f(frame, data)))
}

/// Minimal fd table: hands out increasing numbers up to `limit`.
pub struct Fds {
    pub next: usize,
    pub limit: usize,
    pub umask: u32,
    pub open: BTreeMap<usize, (crate::fs::FileDescriptor, bool)>,
}

impl Default for Fds {
    fn default() -> Self {
        Self { next: 3, limit: 1024, umask: 0o022, open: BTreeMap::new() }
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

    /// Readiness (EPOLL* bits) of a descriptor, from the real objects behind
    /// it: eventfd and devices report their own state; regular files are
    /// always readable and writable, as on Linux.
    pub fn readiness(&self, desc: &crate::fs::FileDescriptor) -> u32 {
        use crate::fs::FileDescriptor::*;
        match desc {
            EventFd(e) => e.lock().poll_events(),
            Device(d) => d.poll_events(),
            File { .. } | Vnode(_) | MemFd { .. } => 0x1 | 0x4,
        }
    }

    pub fn add_wait_queues_for(&self, desc: &crate::fs::FileDescriptor, waits: &mut wait::WaitSet) {
        match desc {
            crate::fs::FileDescriptor::EventFd(e) => waits.add(wait::QueueRef::Shared(e.lock().wq.clone())),
            crate::fs::FileDescriptor::Device(d) => d.add_wait_queues(waits),
            _ => {}
        }
    }

    /// Test helper: close a descriptor (drop it from the table).
    pub fn close(&mut self, fd: usize) {
        self.open.remove(&fd);
    }

    /// Test helper: install `d` at a specific descriptor number.
    pub fn install(&mut self, fd: usize, d: crate::fs::FileDescriptor) {
        self.open.insert(fd, (d, false));
    }
}

/// An open ZFS file (`FileDescriptor::Vnode`), as far as `mmap` looks at it.
pub struct Vnode {
    pub ino: u64,
    pub path: String,
    pub readable: bool,
    pub writable: bool,
}

impl Vnode {
    pub fn readable(&self) -> bool {
        self.readable
    }
    pub fn writable(&self) -> bool {
        self.writable
    }
}



pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut Fds) -> R) -> R {
    FDS.with_borrow_mut(f)
}

// ------------------------------------------------------------- wait queues

pub mod wait {
    use super::*;

    /// Records wake-ups; never actually sleeps.
    #[derive(Default)]
    pub struct WaitQueue;

    impl WaitQueue {
        pub const fn new() -> Self {
            WaitQueue
        }
        pub fn new_shared() -> Arc<Self> {
            Arc::new(WaitQueue)
        }
        pub fn register(&self) {}
        pub fn unregister(&self) {}
        pub fn wake_all(&self) {
            WAKES.set(WAKES.get() + 1);
        }
    }

    pub enum QueueRef {
        Static(&'static WaitQueue),
        Shared(Arc<WaitQueue>),
    }

    #[derive(Default)]
    pub struct WaitSet {
        queues: Vec<QueueRef>,
    }

    /// Message of the panic raised when code under test would go to sleep.
    pub const WOULD_BLOCK: &str = "fake WaitSet::wait: the operation would block";

    impl WaitSet {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn register(&self) {}
        /// A host test has nobody to wake it, so blocking is reported as a
        /// panic that tests can catch and assert on.
        pub fn wait(&self, _deadline: Option<u64>) {
            panic!("{}", WOULD_BLOCK);
        }
    }

    /// Free-function form of [`WaitSet::wait`]: also reports blocking as a panic.
    pub fn wait(_deadline: Option<u64>) {
        panic!("{}", WOULD_BLOCK);
    }
}

// ---------------------------------------------------------------- ZFS client

pub struct FileStat {
    pub size: u64,
}

pub struct ZfsClient;

impl ZfsClient {
    pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
        ZFS_FILES.with_borrow(|m| m.get(path).map(|d| FileStat { size: d.len() as u64 }).ok_or("ENOENT"))
    }

    pub fn read_file_by_path(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        ZFS_FILES.with_borrow(|m| {
            let d = m.get(path).ok_or("ENOENT")?;
            let n = d.len().min(out.len());
            out[..n].copy_from_slice(&d[..n]);
            Ok(n)
        })
    }

    pub fn create_dir_all(path: &str) -> Result<(), &'static str> {
        ZFS_DIRS.with_borrow_mut(|v| v.push(path.to_string()));
        Ok(())
    }

    pub fn write_file_by_path_batch(path: &str, data: &[u8]) -> Result<(), &'static str> {
        if ZFS_WRITE_FAILS.with_borrow(|v| v.iter().any(|p| p == path)) {
            return Err("EIO");
        }
        ZFS_FILES.with_borrow_mut(|m| m.insert(path.to_string(), data.to_vec()));
        Ok(())
    }

    pub fn sync() -> Result<(), &'static str> {
        ZFS_SYNCS.set(ZFS_SYNCS.get() + 1);
        Ok(())
    }

    // Inode-level calls, backed by INODES / INODE_PATHS / INODE_REFS.

    pub fn getattr(ino: u64) -> Result<crate::fs::zfs::fsproto::Attr, i64> {
        if let Some(mode) = TREE.with_borrow(|t| t.get(&ino).map(|n| n.mode())) {
            return Ok(crate::fs::zfs::fsproto::Attr { ino, mode, ..Default::default() });
        }
        INODES.with_borrow(|m| {
            let d = m.get(&ino).ok_or(-2i64)?;
            Ok(crate::fs::zfs::fsproto::Attr { ino, size: d.len() as u64, mode: 0o100644, ..Default::default() })
        })
    }

    pub fn read_at(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        if INODE_READ_FAILS.get() {
            return Err(-5);
        }
        INODES.with_borrow(|m| {
            let d = m.get(&ino).ok_or(-2i64)?;
            let start = (offset as usize).min(d.len());
            let n = buf.len().min(d.len() - start);
            buf[..n].copy_from_slice(&d[start..start + n]);
            Ok(n)
        })
    }

    pub fn open_ref(ino: u64) {
        INODE_REFS.with_borrow_mut(|m| *m.entry(ino).or_insert(0) += 1);
    }

    pub fn release(ino: u64) {
        // Tolerate drops during thread teardown, when thread-locals are gone.
        let _ = INODE_REFS.try_with(|m| *m.borrow_mut().entry(ino).or_insert(0) -= 1);
    }

    /// Path lookup: in the fake tree (see [`mkdir_p`]) when one exists,
    /// otherwise in [`INODE_PATHS`].
    pub fn resolve(base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
        if TREE.with_borrow(|t| !t.is_empty()) {
            return tree_resolve(base, path, follow);
        }
        let path = String::from_utf8_lossy(path).into_owned();
        INODE_PATHS.with_borrow(|m| m.get(&path).copied().ok_or(-2))
    }

    pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
        TREE.with_borrow(|t| match t.get(&ino).map(|n| &n.kind) {
            Some(NodeKind::Symlink(target)) => Ok(target.as_bytes().to_vec()),
            Some(_) => Err(-22),
            None => Err(-2),
        })
    }
}

thread_local! {
    /// Inode contents for the inode-level `ZfsClient` calls.
    pub static INODES: RefCell<BTreeMap<u64, Vec<u8>>> = RefCell::new(BTreeMap::new());
    /// Path -> inode, for `ZfsClient::resolve`.
    pub static INODE_PATHS: RefCell<BTreeMap<String, u64>> = RefCell::new(BTreeMap::new());
    /// `open_ref` minus `release` per inode.
    pub static INODE_REFS: RefCell<BTreeMap<u64, i64>> = RefCell::new(BTreeMap::new());
    /// Make `read_at` fail with EIO.
    pub static INODE_READ_FAILS: Cell<bool> = const { Cell::new(false) };
}

pub fn read_boot_file(path: &str) -> Result<Vec<u8>, &'static str> {
    BOOT_FILES.with_borrow(|m| m.get(path).cloned().ok_or("not found"))
}

// ------------------------------------------------------------------- paging

pub fn make_user_accessible(start: x86_64::VirtAddr, size: usize) -> Result<(), &'static str> {
    if let Some(e) = PAGING_ERROR.get() {
        return Err(e);
    }
    USER_RANGES.with_borrow_mut(|v| v.push((start.as_u64(), size)));
    Ok(())
}

// ------------------------------------------------------------------ network

/// Scripted network: `send_ipv4` records packets, `poll_ipv4` returns the
/// queued replies one per call.
#[derive(Default)]
pub struct Net {
    pub ip: [u8; 4],
    pub dns: [u8; 4],
    pub nic_present: bool,
    /// IP that `dhcp_acquire` assigns (if the NIC is present).
    pub dhcp_ip: Option<[u8; 4]>,
    pub dhcp_calls: usize,
    pub sent: Vec<([u8; 4], u8, Vec<u8>)>,
    /// (source IP, IPv4 payload) pairs handed out by `poll_ipv4`.
    pub inbox: std::collections::VecDeque<([u8; 4], Vec<u8>)>,
    pub polls: usize,
    pub sleeps: u64,
}

/// Zero-sized handle; the state lives in [`NET`] for the calling thread.
pub struct Interface;

impl Interface {
    pub const fn new() -> Self {
        Interface
    }
    pub fn ip(&self) -> [u8; 4] {
        NET.with_borrow(|n| n.ip)
    }
    pub fn dns_server(&self) -> [u8; 4] {
        NET.with_borrow(|n| n.dns)
    }
    pub fn send_ipv4(
        &mut self,
        dst: [u8; 4],
        proto: crate::net::ipv4::IpProtocol,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        NET.with_borrow_mut(|n| n.sent.push((dst, proto.as_u8(), payload.to_vec())));
        Ok(())
    }
    pub fn poll_ipv4<'a>(&mut self, rx: &'a mut [u8]) -> Option<([u8; 4], &'a [u8])> {
        let (src, data) = NET.with_borrow_mut(|n| {
            n.polls += 1;
            n.inbox.pop_front()
        })?;
        rx[..data.len()].copy_from_slice(&data);
        Some((src, &rx[..data.len()]))
    }
}

pub fn nic_present() -> bool {
    NET.with_borrow(|n| n.nic_present)
}

pub fn dhcp_acquire() -> Result<crate::net::dhcp::DhcpLease, &'static str> {
    NET.with_borrow_mut(|n| {
        n.dhcp_calls += 1;
        let ip = n.dhcp_ip.ok_or("DHCP timed out")?;
        n.ip = ip;
        Ok(crate::net::dhcp::DhcpLease { ip, ..crate::net::dhcp::DhcpLease::empty() })
    })
}

pub fn sleep_ms(ms: u64) {
    NET.with_borrow_mut(|n| n.sleeps += ms);
}

// ---------------------------------------------------- address-space plumbing

thread_local! {
    /// Whether the fake EFER reports NX (execute-disable) as enabled.
    pub static NX_ENABLED: Cell<bool> = const { Cell::new(true) };
}

/// `rdmsr` stand-in: only IA32_EFER (0xC000_0080) is meaningful.
///
/// # Safety
/// Always safe on the host; `unsafe` only to match the kernel signature.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    match msr {
        0xC000_0080 if NX_ENABLED.get() => 1 << 11,
        _ => 0,
    }
}

/// Stand-in for `paging::AddressSpace`: only user address spaces are built,
/// laid out like the kernel's (a fresh PML4 whose entry 0 points at a private,
/// empty low PDPT) minus the shared kernel half, which host tests never touch.
pub struct AddressSpace {
    pml4: x86_64::PhysAddr,
}

impl AddressSpace {
    pub fn create_user_space(
        alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager,
    ) -> Result<Self, &'static str> {
        use x86_64::structures::paging::PageTableFlags as F;
        let pml4 = alloc.allocate_zeroed_frame().ok_or("Out of memory: PML4")?;
        let pdpt = alloc.allocate_zeroed_frame().ok_or("Out of memory: low PDPT")?;
        let table = unsafe { &mut *(pml4.start_address().as_u64() as *mut x86_64::structures::paging::PageTable) };
        table[0].set_addr(pdpt.start_address(), F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE);
        Ok(Self { pml4: pml4.start_address() })
    }

    pub fn pml4_physical_address(&self) -> x86_64::PhysAddr {
        self.pml4
    }

    /// Never called: `KERNEL_SPACE` stays `None` on the host.
    ///
    /// # Safety
    /// Not reachable.
    pub unsafe fn map_page(
        &mut self,
        _page: x86_64::structures::paging::Page,
        _frame: x86_64::structures::paging::PhysFrame,
        _flags: x86_64::structures::paging::PageTableFlags,
        _alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager,
    ) -> Result<(), &'static str> {
        Err("no kernel address space on the host")
    }
}


// ------------------------------------------------------- processes, clocks

pub fn current_ids() -> (u64, u64) {
    IDS.get()
}

/// The parts of the kernel's `Process` the code under test reads.
#[derive(Default)]
pub struct Process {
    pub ppid: u64,
    pub groups: Vec<u32>,
    /// cgroup path below the cgroup root, as in the kernel.
    pub cgroup: Option<Arc<str>>,
}

/// Process table (shared by all test threads, like the kernel's). Key by
/// the tgid set in [`IDS`].
pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

pub fn ticks() -> u64 {
    TICKS.get()
}

pub fn frequency_hz() -> u64 {
    1000
}

/// Nanoseconds since boot, from the tick counter.
pub fn now_ns() -> u64 {
    TICKS.get() * 1_000_000
}

/// Deterministic "random" bytes (a counter), so tests are repeatable.
pub fn random_fill(buf: &mut [u8]) {
    static NEXT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);
    for b in buf {
        *b = NEXT.fetch_add(37, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Milliseconds since boot: the tick counter (the fake PIT runs at 1 kHz).
pub fn uptime_ms() -> u64 {
    TICKS.get()
}

/// `pit::clock_state`: (base_ns, base_frac, base_tsc, mult) for the vDSO,
/// derived from the tick counter.
pub fn clock_state() -> (u64, u64, u64, u64) {
    (TICKS.get() * 1_000_000, 0, 0, 0)
}

/// `rtc::wall_base_ns`: wall-clock nanoseconds at boot (the fixed RTC instant).
pub fn wall_base_ns() -> i64 {
    1_767_225_600 * 1_000_000_000
}

/// RTC time: a fixed instant (2026-01-01T00:00:00Z).
pub fn rtc_now() -> (u64, u32) {
    (1_767_225_600, 0)
}

// ------------------------------------------------------------------- per-CPU

/// Single-CPU stand-in for `arch::percpu::PerCpuPtr` (same methods).
pub struct PerCpuPtr<T>(core::sync::atomic::AtomicPtr<T>);

impl<T> PerCpuPtr<T> {
    pub const fn new() -> Self {
        Self(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()))
    }
    pub fn load(&self, o: core::sync::atomic::Ordering) -> *mut T {
        self.0.load(o)
    }
    pub fn store(&self, v: *mut T, o: core::sync::atomic::Ordering) {
        self.0.store(v, o)
    }
    pub fn swap(&self, v: *mut T, o: core::sync::atomic::Ordering) -> *mut T {
        self.0.swap(v, o)
    }
}

// ------------------------------------------------------- fake directory tree

/// A node of the fake directory tree used by path-walking code (Landlock).
pub enum NodeKind {
    Dir(BTreeMap<String, u64>),
    File,
    Symlink(String),
}

pub struct Node {
    pub parent: u64,
    pub kind: NodeKind,
}

impl Node {
    fn mode(&self) -> u32 {
        match self.kind {
            NodeKind::Dir(_) => 0o040755,
            NodeKind::File => 0o100644,
            NodeKind::Symlink(_) => 0o120777,
        }
    }
}

/// Inode of the fake tree's root directory.
pub const ROOT: u64 = 1;

/// Same limit as the kernel's `fs::client::SYMLOOP_MAX`.
const SYMLOOP_MAX: usize = 40;

thread_local! {
    pub static TREE: RefCell<BTreeMap<u64, Node>> = const { RefCell::new(BTreeMap::new()) };
}

fn ensure_root(t: &mut BTreeMap<u64, Node>) {
    if t.is_empty() {
        t.insert(ROOT, Node { parent: ROOT, kind: NodeKind::Dir(BTreeMap::new()) });
    }
}

fn tree_add(parent: u64, name: &str, kind: NodeKind) -> u64 {
    TREE.with_borrow_mut(|t| {
        ensure_root(t);
        if let Some(NodeKind::Dir(children)) = t.get(&parent).map(|n| &n.kind) {
            if let Some(&existing) = children.get(name) {
                return existing;
            }
        }
        let ino = 100_000 + t.len() as u64;
        t.insert(ino, Node { parent, kind });
        if let Some(Node { kind: NodeKind::Dir(children), .. }) = t.get_mut(&parent) {
            children.insert(name.to_string(), ino);
        }
        ino
    })
}

/// Create a directory (and its parents) in the fake tree; returns its inode.
pub fn mkdir_p(path: &str) -> u64 {
    TREE.with_borrow_mut(ensure_root);
    let mut cur = ROOT;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        cur = tree_add(cur, comp, NodeKind::Dir(BTreeMap::new()));
    }
    cur
}

fn parent_and_name(path: &str) -> (u64, String) {
    let path = path.trim_end_matches('/');
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    (mkdir_p(dir), name.to_string())
}

/// Create a regular file (and parent directories); returns its inode.
pub fn mkfile(path: &str) -> u64 {
    let (dir, name) = parent_and_name(path);
    tree_add(dir, &name, NodeKind::File)
}

/// Create a symlink at `path` pointing to `target`; returns its inode.
pub fn mklink(path: &str, target: &str) -> u64 {
    let (dir, name) = parent_and_name(path);
    tree_add(dir, &name, NodeKind::Symlink(target.to_string()))
}

/// Walk `path` from `base` (0 or an absolute path: the root), following
/// symlinks in the middle always and at the end if `follow`, at most
/// SYMLOOP_MAX in total, like the kernel's `resolve_at`.
fn tree_resolve(base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
    let path = String::from_utf8_lossy(path).into_owned();
    let mut cur = if path.starts_with('/') || base == 0 { ROOT } else { base };
    let mut todo: std::collections::VecDeque<String> =
        path.split('/').filter(|c| !c.is_empty()).map(String::from).collect();
    let mut links = 0;
    TREE.with_borrow(|t| {
        while let Some(comp) = todo.pop_front() {
            let node = t.get(&cur).ok_or(-2i64)?;
            let NodeKind::Dir(children) = &node.kind else { return Err(-20) };
            if comp == "." {
                continue;
            }
            if comp == ".." {
                cur = node.parent;
                continue;
            }
            let next = *children.get(&comp).ok_or(-2i64)?;
            if let NodeKind::Symlink(target) = &t[&next].kind {
                if !todo.is_empty() || follow {
                    links += 1;
                    if links > SYMLOOP_MAX {
                        return Err(-40);
                    }
                    if target.starts_with('/') {
                        cur = ROOT;
                    }
                    for c in target.split('/').filter(|c| !c.is_empty()).rev() {
                        todo.push_front(c.to_string());
                    }
                    continue;
                }
            }
            cur = next;
        }
        Ok(cur)
    })
}
