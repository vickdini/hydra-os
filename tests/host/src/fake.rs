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
    IDS.set((1, 1));
    TICKS.set(1_000);
    INODES.with_borrow_mut(|m| m.clear());
    INODE_PATHS.with_borrow_mut(|m| m.clear());
    INODE_REFS.with_borrow_mut(|m| m.clear());
    INODE_READ_FAILS.set(false);
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
    pub euid: u32,
    pub egid: u32,
    /// Address space of the current task (see [`TASK_MM`]).
    pub mm: Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>,
}

thread_local! {
    /// Whether the current task's capabilities come from a user namespace.
    pub static IN_USERNS: Cell<bool> = const { Cell::new(false) };
    /// What `proc::sigkill_pending()` reports.
    pub static SIGKILL_PENDING: Cell<bool> = const { Cell::new(false) };
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
    let mut t = Task { caps: Caps { effective, in_userns: IN_USERNS.get() }, euid, egid, mm };
    let r = f(&mut t);
    CAPS.set(Some(t.caps.effective));
    Some(r)
}

/// Minimal fd table: hands out increasing numbers up to `limit`.
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
}

impl Vnode {
    pub fn readable(&self) -> bool {
        self.readable
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

    pub fn resolve(_base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
        let path = String::from_utf8_lossy(path).into_owned();
        INODE_PATHS.with_borrow(|m| m.get(&path).copied().ok_or(-2))
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
pub struct Process {
    pub groups: Vec<u32>,
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
