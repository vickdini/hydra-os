//! # IPC Subsystem: Driver Services
//!
//! Request/reply calls from the kernel (or another driver) to driver and server processes
//! that run in Ring 3, each in an address space of its own.
//!
//! ## Architectural Role & Design Rationale
//!
//! A service is an endpoint ([`ENDPOINT_BLOCK_DEV`], ...) with at most one server: the
//! process the supervisor started for it ([`crate::task::spawn_service`]). The server
//! registers (`register`), then loops receiving a request (`recv`) and answering it
//! (`reply`). A client calls (`call`) and gets the reply.
//!
//! Bulk data travels through the service's window: physically contiguous memory mapped
//! into the server and reachable by the kernel through its identity mapping of physical
//! memory. The client copies a request's data into the window before the call and the
//! reply's data out after it; messages carry offsets and lengths, never pointers.
//!
//! Kernel callers are often deep inside a subsystem with its locks held (the file system
//! asking the disk driver for a block). A call therefore hands the CPU to the server and
//! lets nothing else run until it replies (see [`crate::task::scheduler::Scheduler::begin_handoff`]),
//! exactly as an in-kernel driver would have run in the caller's place: no other task can
//! contend for those locks. A server that crashes or misses the deadline ends the call
//! with an error and is restarted by the supervisor.
//!
//! Requests and replies use separate slots, so neither side can pick up its own message.
//!
//! ## Device access
//!
//! Driver processes get only what the supervisor granted their service: physical ranges
//! they may map (`set_grants`; the framebuffer, a NIC's registers), DMA memory they
//! allocate themselves (`dma_alloc`), and interrupt lines (`irq_register`). Interrupts
//! never run driver code or take locks: the handler masks the line, counts it and wakes
//! the driver (`irq_raised`); the driver unmasks it when it waits again (`irq_wait`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::endpoint::{ENDPOINT_BLOCK_DEV, ENDPOINT_DISPLAY_DEV, ENDPOINT_NET_DEV, ENDPOINT_ZFS_SERVER};
use super::Message;
use crate::memory::vm::{Backing, MappedObject};
use crate::task::wait::WaitQueue;

/// Size of each service's data window (256 KiB: a ZFS block plus headers, or a batch of
/// network frames).
pub const WINDOW_PAGES: u64 = 64;

/// Window size in bytes.
pub const WINDOW_SIZE: usize = (WINDOW_PAGES * 4096) as usize;

/// Default time a call may take before the caller gives up (5 s at 100 Hz).
pub const CALL_TIMEOUT_TICKS: u64 = 500;

const EINTR: i64 = -4;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EPERM: i64 = -1;
const ETIMEDOUT: i64 = -110;
const EDEADLK: i64 = -35;

/// `PROT_READ | PROT_WRITE` for mappings made here.
const PROT_RW: u32 = 3;

/// Message layout shared with Ring 3 programs (`hydra-rt`): a label and four words.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WireMessage {
    /// Operation or reply code.
    pub label: u64,
    /// Arguments.
    pub args: [u64; 4],
}

impl From<Message> for WireMessage {
    /// Converts an in-kernel `Message` into a user-space wire representation.
    ///
    /// # Arguments
    ///
    /// * `m` - The source kernel message.
    ///
    /// # Returns
    ///
    /// The formatted `WireMessage`.
    fn from(m: Message) -> Self {
        Self { label: m.label as u64, args: m.args }
    }
}

impl From<WireMessage> for Message {
    /// Converts a user-space `WireMessage` into an in-kernel `Message`.
    ///
    /// # Arguments
    ///
    /// * `w` - The source wire message read from user memory.
    ///
    /// # Returns
    ///
    /// The deserialized kernel `Message`.
    fn from(w: WireMessage) -> Self {
        Message::with_args(w.label as u32, w.args)
    }
}

/// Physically contiguous memory owned by the kernel and mapped into processes: a
/// service's window or a driver's DMA buffer. Freed when the last mapping goes away.
pub struct ContiguousFrames {
    /// Physical address of the first page.
    pub base: u64,
    /// Number of 4 KiB pages.
    pub pages: u64,
}

impl ContiguousFrames {
    /// Allocates `pages` zeroed, physically contiguous 4 KiB frames.
    ///
    /// # Arguments
    ///
    /// * `pages` - Number of contiguous 4 KiB pages to allocate.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ContiguousFrames>)` if allocation succeeds; `None` if contiguous physical memory is exhausted.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn allocate(pages: u64) -> Option<Arc<Self>> {
        let mut fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
        let first = fa.allocate_contiguous_frames(pages as usize)?;
        let base = first.start_address().as_u64();
        for i in 0..pages {
            fa.adopt(PhysFrame::containing_address(PhysAddr::new(base + i * 4096)));
        }
        drop(fa);
        unsafe { core::ptr::write_bytes(crate::memory::frame_allocator::phys_to_virt(base), 0, (pages * 4096) as usize) };
        Some(Arc::new(Self { base, pages }))
    }

    /// Accesses the contiguous memory as a mutable byte slice through the kernel's direct map.
    ///
    /// # Returns
    ///
    /// Mutable byte slice spanning all allocated pages.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the server daemon is not actively writing to the memory
    /// while the slice is held, to avoid data races.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub unsafe fn bytes(&self) -> &'static mut [u8] {
        core::slice::from_raw_parts_mut(crate::memory::frame_allocator::phys_to_virt(self.base), (self.pages * 4096) as usize)
    }
}

impl MappedObject for ContiguousFrames {
    /// Resolves the physical frame for the given page offset within this contiguous range.
    ///
    /// # Arguments
    ///
    /// * `pgoff` - 0-based page offset from the start of the contiguous allocation.
    ///
    /// # Returns
    ///
    /// `Some(PhysFrame)` if `pgoff < self.pages`; `None` if out of bounds.
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        (pgoff < self.pages).then(|| PhysFrame::containing_address(PhysAddr::new(self.base + pgoff * 4096)))
    }
}

impl Drop for ContiguousFrames {
    /// Decrements the reference counts of all underlying physical frames.
    fn drop(&mut self) {
        for i in 0..self.pages {
            crate::memory::frame_allocator::frame_ref_dec(PhysFrame::containing_address(PhysAddr::new(self.base + i * 4096)));
        }
    }
}

/// Device memory (registers, a framebuffer) granted to a driver; never freed.
struct DeviceRange {
    base: u64,
    pages: u64,
}

impl MappedObject for DeviceRange {
    /// Resolves the physical frame for a page offset within the granted device memory range.
    ///
    /// # Arguments
    ///
    /// * `pgoff` - 0-based page offset from the device memory base address.
    ///
    /// # Returns
    ///
    /// `Some(PhysFrame)` if `pgoff < self.pages`; `None` if out of bounds.
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        (pgoff < self.pages).then(|| PhysFrame::containing_address(PhysAddr::new(self.base + pgoff * 4096)))
    }
}

// ----------------------------------------------------------------------
// Requests in flight
// ----------------------------------------------------------------------
//
// Every call is a request in one table shared by all services: several may be outstanding
// per service, the server takes them in any order (`recv` hands out the request's ID) and
// its reply names the request it answers (`reply` by ID), so replies can never reach the
// wrong caller, whatever order they come in and whichever CPU runs them.
//
// How the caller waits depends on what it holds ([`CallMode`]):
// - `Handoff`: the caller may hold kernel locks (the file system asking for a block). The
//   CPU goes to the server and no other kernel code runs until the reply (the scheduler's
//   hand-off, as before).
// - `Queued`: the caller holds no kernel locks (the USB input task, the watchdog's
//   heartbeats, a driver process not serving a hand-off). It sleeps until the reply and
//   everything else keeps running; a hung server delays only this caller.

/// How a call waits for its reply (see the section comment above).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallMode {
    /// Strict hand-off: only the server runs until it replies (callers that may hold
    /// kernel locks).
    Handoff,
    /// Queued: the caller sleeps; other tasks run meanwhile (callers holding no locks).
    Queued,
}

/// Requests outstanding at once, over all services.
pub const MAX_REQUESTS: usize = 64;

/// Where a request is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReqState {
    Free,
    /// Waiting for the server to take it.
    Queued,
    /// Taken by the server (`recv`), not answered yet.
    Delivered,
    /// Answered; the caller takes the reply.
    Replied,
    /// Ended without a reply (`error`): its server went away.
    Failed,
}

/// One request (an entry of [`REQUESTS`]).
#[derive(Clone, Copy)]
struct Request {
    state: ReqState,
    /// Unique, never 0.
    id: u64,
    /// Endpoint whose server process takes it (the slot owner: a primary for its aliases).
    owner: u32,
    /// Endpoint it was made on.
    endpoint: u32,
    msg: Message,
    reply: Message,
    /// Why it failed (`Failed`).
    error: i64,
    /// Task waiting for the reply.
    caller: u64,
    mode: CallMode,
    /// The caller gave up (deadline): the entry goes when the server answers or dies.
    abandoned: bool,
    /// Pages lent to the server for this request (an index into [`GRANTS`] plus one; 0: none).
    grant: u8,
}

impl Request {
    const FREE: Self = Self {
        state: ReqState::Free,
        id: 0,
        owner: 0,
        endpoint: 0,
        msg: Message::new(0),
        reply: Message::new(0),
        error: 0,
        caller: 0,
        mode: CallMode::Handoff,
        abandoned: false,
        grant: 0,
    };
}

/// The requests in flight. Taken only with interrupts off ([`requests`]) and never while
/// the scheduler lock is wanted (the scheduler reads [`QUEUED_CALLER`] instead).
static REQUESTS: Mutex<[Request; MAX_REQUESTS]> = Mutex::new([Request::FREE; MAX_REQUESTS]);
/// The caller of each queued-mode request waits here.
static REQ_WQ: [WaitQueue; MAX_REQUESTS] = [const { WaitQueue::new() }; MAX_REQUESTS];
/// Next request ID.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Lock-free mirror for the scheduler: per entry, the caller of a queued-mode request still
/// waiting (0: none) and the endpoint serving it.
static QUEUED_CALLER: [AtomicU64; MAX_REQUESTS] = [const { AtomicU64::new(0) }; MAX_REQUESTS];
static QUEUED_OWNER: [AtomicU32; MAX_REQUESTS] = [const { AtomicU32::new(0) }; MAX_REQUESTS];

/// Runs `f` on the request table with interrupts off (see [`holders`]).
fn requests<R>(f: impl FnOnce(&mut [Request; MAX_REQUESTS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut REQUESTS.lock()))
}

/// Internal: the server of a call died (the call is retried after a restart).
const ESRCH: i64 = -3;
const EIO: i64 = -5;

/// Whether some queued-mode request whose caller satisfies `waits` is served by the
/// service with endpoint `ep` (the scheduler lets such a server run during another call's
/// hand-off when that call depends on it). Lock-free.
pub fn serves_queued_for(ep: u32, waits: impl Fn(u64) -> bool) -> bool {
    (0..MAX_REQUESTS).any(|i| {
        let c = QUEUED_CALLER[i].load(Ordering::Acquire);
        c != 0 && QUEUED_OWNER[i].load(Ordering::Acquire) == ep && waits(c)
    })
}

/// Requests in flight, as `(id, endpoint, caller, state, mode)`, for diagnostics.
pub fn request_list() -> Vec<(u64, u32, u64, &'static str, CallMode)> {
    requests(|t| {
        t.iter()
            .filter(|r| r.state != ReqState::Free)
            .map(|r| {
                let s = match (r.state, r.abandoned) {
                    (_, true) => "abandoned",
                    (ReqState::Queued, _) => "queued",
                    (ReqState::Delivered, _) => "delivered",
                    (ReqState::Replied, _) => "replied",
                    _ => "failed",
                };
                (r.id, r.endpoint, r.caller, s, r.mode)
            })
            .collect()
    })
}

/// One driver service.
pub struct Service {
    /// Endpoint number.
    pub endpoint: u32,
    /// Task serving it (0: none registered).
    server: AtomicU64,
    /// The server waiting for a request.
    recv_wq: WaitQueue,
    /// Data window, allocated on first registration and kept across server restarts.
    window: Mutex<Option<Arc<ContiguousFrames>>>,
    /// Physical ranges its server may map.
    grants: Mutex<Vec<(u64, u64)>>,
    /// Kernel queue woken when its driver's interrupt arrives (the client then asks the
    /// driver what happened).
    irq_notify: AtomicPtr<WaitQueue>,
    /// Services whose servers may call this one and map its window (the file server uses
    /// the disk driver).
    clients: Mutex<Vec<u32>>,
    /// The endpoint whose server also serves this one and whose request queue (and server
    /// wait queue) it uses: that process takes the requests of both, whichever endpoint
    /// they came through (0: none, the service has its own). The USB driver serves the USB
    /// disks this way next to its input endpoint.
    primary: u32,
}

impl Service {
    const fn new(endpoint: u32) -> Self {
        Self::with_primary(endpoint, 0)
    }

    const fn with_primary(endpoint: u32, primary: u32) -> Self {
        Self {
            primary,
            endpoint,
            server: AtomicU64::new(0),
            recv_wq: WaitQueue::new(),
            window: Mutex::new(None),
            grants: Mutex::new(Vec::new()),
            irq_notify: AtomicPtr::new(core::ptr::null_mut()),
            clients: Mutex::new(Vec::new()),
        }
    }
}

/// Grants permission for a client service daemon to attach to an endpoint's shared window.
///
/// # Arguments
///
/// * `endpoint` - Target service endpoint whose window will be shared.
/// * `client` - Calling service endpoint permitted to attach.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn allow_client(endpoint: u32, client: u32) {
    if let Some(svc) = service(endpoint) {
        let mut clients = svc.clients.lock();
        if !clients.contains(&client) {
            clients.push(client);
        }
    }
}

/// Maps the shared memory window of `endpoint` into the calling driver's address space.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint identifier whose window should be mapped.
///
/// # Returns
///
/// Virtual user-space base address of the mapped window on success, or a negative errno.
///
/// # Errors
///
/// - `-EPERM`: The caller is not a registered service or lacks permission from `allow_client`.
/// - `-ENODEV`: The requested service does not exist or has no registered server daemon.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn attach(endpoint: u32) -> Result<u64, i64> {
    let me = crate::task::current_service().ok_or(EPERM)?;
    let svc = service(endpoint).ok_or(ENODEV)?;
    if !svc.clients.lock().contains(&me) {
        return Err(EPERM);
    }
    if svc.server.load(Ordering::Acquire) == 0 {
        return Err(ENODEV);
    }
    let window = svc.window.lock().clone().ok_or(ENODEV)?;
    map_into_current(window, WINDOW_PAGES)
}

/// The services, one per system endpoint.
static SERVICES: [Service; 7] = [
    Service::new(ENDPOINT_ZFS_SERVER),
    Service::new(ENDPOINT_BLOCK_DEV),
    Service::new(ENDPOINT_NET_DEV),
    Service::new(ENDPOINT_DISPLAY_DEV),
    Service::new(crate::ipc::protocol::ENDPOINT_INPUT_DEV),
    Service::new(crate::ipc::protocol::ENDPOINT_SOUND_DEV),
    Service::with_primary(crate::ipc::protocol::ENDPOINT_USB_DISK, crate::ipc::protocol::ENDPOINT_INPUT_DEV),
];

/// The service whose server takes `svc`'s requests (itself, or its primary).
fn slot_owner(svc: &'static Service) -> &'static Service {
    if svc.primary == 0 {
        return svc;
    }
    service(svc.primary).unwrap_or(svc)
}

/// The endpoint whose process serves `endpoint` and is supervised under it: its primary,
/// if it has one (the USB disks are served by the USB driver).
pub fn primary_of(endpoint: u32) -> u32 {
    match service(endpoint) {
        Some(s) if s.primary != 0 => s.primary,
        _ => endpoint,
    }
}

/// Resolves the static `Service` descriptor corresponding to `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Target numeric endpoint ID.
///
/// # Returns
///
/// `Some(&'static Service)` if matched; `None` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn service(endpoint: u32) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.endpoint == endpoint)
}

/// Checks whether an authoritative server daemon is currently registered on `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint to query.
///
/// # Returns
///
/// `true` if an active daemon is registered; `false` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn is_online(endpoint: u32) -> bool {
    service(endpoint).map_or(false, |s| s.server.load(Ordering::Acquire) != 0)
}

/// Retrieves the task ID of the process currently serving `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint to inspect.
///
/// # Returns
///
/// Numeric task ID of the registered server, or `0` if vacant.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn server_of(endpoint: u32) -> u64 {
    service(endpoint).map_or(0, |s| s.server.load(Ordering::Acquire))
}

/// Obtains a kernel-accessible mutable slice of the service's shared data window.
///
/// # Arguments
///
/// * `endpoint` - Target service endpoint.
///
/// # Returns
///
/// `Some(&'static mut [u8])` spanning 256 KiB if allocated; `None` if vacant.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
    let svc = service(endpoint)?;
    let w = svc.window.lock().clone()?;
    // The window lives as long as the service (it is never replaced once allocated)
    Some(unsafe { w.bytes() })
}

/// Tasks using a service's window, by endpoint: `(task, depth, quiet)` (a task may nest
/// uses; a quiet holder makes queued calls and holds no kernel locks, see
/// [`hold_window_queued`]).
static WINDOW_HOLDERS: Mutex<alloc::collections::BTreeMap<u32, (u64, u32, bool)>> = Mutex::new(alloc::collections::BTreeMap::new());
/// Windows held by holders that are not quiet (a lock-free check for [`window_held_by_other`]).
static WINDOWS_HELD: AtomicU32 = AtomicU32::new(0);

/// Runs `f` on the window holders with interrupts off: the lock is taken where interrupts
/// may be on (waiting loops), and an interrupt handler waiting for the kernel lock while
/// this CPU held it would stall the kernel lock's holder, which may want it too.
fn holders<R>(f: impl FnOnce(&mut alloc::collections::BTreeMap<u32, (u64, u32, bool)>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut WINDOW_HOLDERS.lock()))
}

/// A task's use of a service's window, from writing a request into it until it has read
/// the reply out of it; released when dropped.
pub struct WindowGuard {
    endpoint: u32,
}

/// Takes `endpoint`'s window for the calling task until the guard is dropped (nested uses
/// by the same task are fine). With one CPU the window is always free here: during a call
/// only its server runs, and the caller runs first when it ends. With several, another
/// task's call (or its reading of the reply) may be in progress: wait for it, without the
/// kernel lock.
pub fn hold_window(endpoint: u32) -> WindowGuard {
    hold_window_as(endpoint, false)
}

/// [`hold_window`] for a caller that makes only queued calls ([`call_queued`]) with it and
/// holds no kernel locks: other kernel code need not wait while it holds the window.
pub fn hold_window_queued(endpoint: u32) -> WindowGuard {
    hold_window_as(endpoint, true)
}

fn hold_window_as(endpoint: u32, quiet: bool) -> WindowGuard {
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    loop {
        let taken = holders(|h| match h.get_mut(&endpoint) {
            None => {
                h.insert(endpoint, (me, 1, quiet));
                if !quiet {
                    WINDOWS_HELD.fetch_add(1, Ordering::AcqRel);
                }
                true
            }
            Some((t, d, _)) if *t == me => {
                *d += 1;
                true
            }
            Some(_) => false,
        });
        if taken {
            return WindowGuard { endpoint };
        }
        crate::arch::smp::bkl_exit();
        crate::task::preemptible(|| {
            let was = x86_64::instructions::interrupts::are_enabled();
            x86_64::instructions::interrupts::enable();
            while holders(|h| h.contains_key(&endpoint)) {
                crate::arch::smp::bkl_exit();
                core::hint::spin_loop();
            }
            if !was {
                x86_64::instructions::interrupts::disable();
            }
        });
        crate::arch::smp::bkl_enter();
    }
}

impl Drop for WindowGuard {
    fn drop(&mut self) {
        holders(|h| {
            if let Some((_, d, quiet)) = h.get_mut(&self.endpoint) {
                *d -= 1;
                if *d == 0 {
                    if !*quiet {
                        WINDOWS_HELD.fetch_sub(1, Ordering::AcqRel);
                    }
                    h.remove(&self.endpoint);
                }
            }
        });
        // Kernel-mode tasks held back while the window was in use may run now
        crate::task::scheduler::call_ended();
    }
}

/// Whether a task other than `task` holds a service window (its call, or its reading of
/// the reply, is in progress).
pub fn window_held_by_other(task: u64) -> bool {
    WINDOWS_HELD.load(Ordering::Acquire) > 0 && holders(|h| h.values().any(|(t, _, quiet)| *t != task && !*quiet))
}

/// Releases the service windows task `id` holds (it ended in the middle of a call: it never
/// resumes to drop its guards).
pub fn release_windows(id: u64) {
    holders(|h| {
        let gone = h.values().filter(|(t, _, quiet)| *t == id && !*quiet).count();
        h.retain(|_, (t, _, _)| *t != id);
        if gone > 0 {
            WINDOWS_HELD.fetch_sub(gone as u32, Ordering::AcqRel);
        }
    })
}

/// The tasks holding service windows, as `(endpoint, task)`, for diagnostics.
pub fn window_holders() -> alloc::vec::Vec<(u32, u64)> {
    holders(|h| h.iter().map(|(e, (t, _, _))| (*e, *t)).collect())
}

/// Whether `task` holds a service window.
pub fn holds_window(task: u64) -> bool {
    holders(|h| h.values().any(|(t, _, _)| *t == task))
}

/// Sets the physical address ranges `(base, length)` the server of `endpoint` is permitted to map.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint to configure.
/// * `grants` - Vector of `(physical_base, length_bytes)` tuples.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn set_grants(endpoint: u32, grants: Vec<(u64, u64)>) {
    if let Some(svc) = service(endpoint) {
        *svc.grants.lock() = grants;
    }
}

/// Registers a kernel wait queue to be notified whenever an interrupt arrives for `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Target service endpoint.
/// * `wq` - Wait queue to wake upon hardware IRQ arrival.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn notify_on_irq(endpoint: u32, wq: &'static WaitQueue) {
    if let Some(svc) = service(endpoint) {
        svc.irq_notify.store(wq as *const WaitQueue as *mut WaitQueue, Ordering::Release);
    }
}

/// Unregisters the server currently bound to `endpoint` (it died or is being replaced):
/// every request waiting for it fails, so its callers get an error at once (hand-off
/// callers resume, queued callers wake) instead of waiting for their deadlines.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint to detach.
pub fn unregister(endpoint: u32) {
    if let Some(svc) = service(endpoint) {
        let server = svc.server.swap(0, Ordering::AcqRel);
        // The endpoints its process also served go with it
        for alias in SERVICES.iter().filter(|s| s.primary == endpoint) {
            alias.server.store(0, Ordering::Release);
        }
        let owner = slot_owner(svc).endpoint;
        let mut ended: [(usize, u64, CallMode); MAX_REQUESTS] = [(0, 0, CallMode::Queued); MAX_REQUESTS];
        let mut n = 0;
        let mut grants: [u8; MAX_REQUESTS] = [0; MAX_REQUESTS];
        let mut g = 0;
        requests(|t| {
            for (i, r) in t.iter_mut().enumerate() {
                if r.owner != owner || !matches!(r.state, ReqState::Queued | ReqState::Delivered) {
                    continue;
                }
                if r.grant != 0 {
                    grants[g] = r.grant;
                    g += 1;
                    r.grant = 0;
                }
                if r.abandoned {
                    *r = Request::FREE;
                    continue;
                }
                r.state = ReqState::Failed;
                r.error = ESRCH;
                ended[n] = (i, r.caller, r.mode);
                n += 1;
            }
        });
        for &gr in &grants[..g] {
            release_grant(gr);
        }
        for &(i, caller, mode) in &ended[..n] {
            match mode {
                CallMode::Handoff => {
                    x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().end_handoff_of(caller))
                }
                CallMode::Queued => REQ_WQ[i].wake_all(),
            }
        }
        // Callers waiting for it to start (`supervisor::await_registration`)
        if server != 0 {
            x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().end_handoffs_to(server));
        }
    }
}

/// Calls the server of `endpoint` with `request` and returns its reply, reviving dead daemons if needed.
///
/// A strict hand-off ([`CallMode::Handoff`]): for callers that may hold kernel locks. If
/// the server dies or misses the deadline, it is revived through the supervisor and the
/// call is retried once.
///
/// # Errors
///
/// - `-ENODEV`: No server daemon is registered or revival failed.
/// - `-EBUSY`: Too many requests in flight.
/// - `-ETIMEDOUT`: Server failed to reply within `timeout_ticks`.
/// - `-EIO`: The server died and could not be restarted.
pub fn call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    call_mode(endpoint, request, timeout_ticks, CallMode::Handoff)
}

/// As [`call`], but the caller sleeps while the server works and every other task keeps
/// running ([`CallMode::Queued`]). Only for callers that hold no kernel locks (nor a
/// service window another task may need): a kernel task in its main loop, a driver
/// process. A hung server then delays only this caller.
pub fn call_queued(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    call_mode(endpoint, request, timeout_ticks, CallMode::Queued)
}

/// How a driver process's call (`SYS_SVC_CALL`) waits: a hand-off when the driver serves
/// or waits in a hand-off (it works for a caller that may hold kernel locks, as the file
/// server reading a block for the kernel), queued otherwise.
pub fn driver_call_mode() -> CallMode {
    let me = crate::task::SCHEDULER.lock();
    if me.in_handoff(me.current_task_id().0) {
        CallMode::Handoff
    } else {
        CallMode::Queued
    }
}

/// [`call`] with an explicit [`CallMode`].
pub fn call_mode(endpoint: u32, request: Message, timeout_ticks: u64, mode: CallMode) -> Result<Message, i64> {
    call_with(endpoint, request, timeout_ticks, mode, None)
}

/// [`call_mode`], lending `grant` (pages of the caller, see [`Grant`]) to the server for
/// the request.
pub fn call_with(endpoint: u32, request: Message, timeout_ticks: u64, mode: CallMode, grant: Option<&GrantSpec>) -> Result<Message, i64> {
    let svc = service(endpoint).ok_or(ENODEV)?;
    if !crate::task::is_active() {
        return Err(ENODEV);
    }
    if svc.server.load(Ordering::Acquire) == 0 && !crate::task::supervisor::revive(endpoint) {
        return Err(ENODEV);
    }
    let t0 = crate::compat::linux::prof::start();
    let r = match call_once_with(endpoint, request, timeout_ticks, mode, grant) {
        // The server died (or hung and was found dead at the deadline): once more, with
        // its successor
        Err(ESRCH) | Err(ETIMEDOUT) if !server_alive(svc) => {
            if crate::task::supervisor::revive(endpoint) {
                match call_once_with(endpoint, request, timeout_ticks, mode, grant) {
                    Err(ESRCH) => Err(EIO),
                    r => r,
                }
            } else {
                Err(EIO)
            }
        }
        Err(ESRCH) => Err(EIO),
        r => r,
    };
    if endpoint == super::protocol::ENDPOINT_BLOCK_DEV {
        use crate::compat::linux::prof::{DISK_OTHER, DISK_READ, DISK_READV};
        let (kind, blocks) = match request.label {
            super::protocol::MSG_BLOCK_READ => (DISK_READ, request.args[1]),
            // The reply says how many blocks the runs had
            super::protocol::MSG_BLOCK_READV => (DISK_READV, r.as_ref().map_or(0, |m| m.args[1])),
            _ => (DISK_OTHER, request.args[1]),
        };
        crate::compat::linux::prof::disk_call(kind, blocks, t0);
    }
    r
}

/// Checks whether the registered server process for `svc` is still running.
fn server_alive(svc: &Service) -> bool {
    let server = svc.server.load(Ordering::Acquire);
    server != 0 && crate::task::is_task_alive(crate::task::TaskId(server))
}

/// Issues one hand-off call without reviving a failed server (the watchdog's heartbeat).
///
/// # Errors
///
/// - `-ENODEV`: No server registered or multitasking not active.
/// - `-EDEADLK`: Server attempted to call its own service endpoint.
/// - `-EBUSY`: Too many requests in flight.
/// - `-ETIMEDOUT`: Server failed to reply before deadline.
/// - `-ESRCH`: The server went away before replying.
pub fn call_once(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    call_once_with(endpoint, request, timeout_ticks, CallMode::Handoff, None)
}

/// [`call_once`] with an explicit [`CallMode`].
pub fn call_once_mode(endpoint: u32, request: Message, timeout_ticks: u64, mode: CallMode) -> Result<Message, i64> {
    call_once_with(endpoint, request, timeout_ticks, mode, None)
}

/// One call: queues the request, waits as `mode` says, takes the reply.
fn call_once_with(endpoint: u32, request: Message, timeout_ticks: u64, mode: CallMode, grant: Option<&GrantSpec>) -> Result<Message, i64> {
    let svc = service(endpoint).ok_or(ENODEV)?;
    let server = svc.server.load(Ordering::Acquire);
    if server == 0 || !crate::task::is_active() {
        return Err(ENODEV);
    }
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    let owner = slot_owner(svc);
    // A server calling its own service would wait for itself
    if me == server || crate::task::current_service().is_some_and(|s| s == owner.endpoint) {
        return Err(EDEADLK);
    }
    // The pages lent with it, pinned for as long as the server may use them
    let gidx = match grant {
        Some(spec) => make_grant(spec, endpoint)?,
        None => 0,
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let slot = requests(|t| {
        let i = t.iter().position(|r| r.state == ReqState::Free)?;
        t[i] = Request {
            state: ReqState::Queued,
            id,
            owner: owner.endpoint,
            endpoint,
            msg: request,
            reply: Message::new(0),
            error: 0,
            caller: me,
            mode,
            abandoned: false,
            grant: gidx,
        };
        Some(i)
    });
    let Some(i) = slot else {
        release_grant(gidx);
        crate::kprintln!("[service] call to {:#x}: too many requests in flight", endpoint);
        return Err(EBUSY);
    };
    if mode == CallMode::Queued {
        QUEUED_OWNER[i].store(owner.endpoint, Ordering::Release);
        QUEUED_CALLER[i].store(me, Ordering::Release);
    }
    owner.recv_wq.wake_all();
    let deadline = crate::arch::pit::ticks() + timeout_ticks;
    let mut interrupted = false;
    match mode {
        CallMode::Handoff => {
            let handed = x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().begin_handoff(server, deadline));
            if !handed {
                // Not taken by the server yet (it runs no sooner than this CPU lets it):
                // withdrawn below as an unanswered queued request
                crate::kprintln!("[service] call to {:#x}: no handoff slot", endpoint);
            } else {
                crate::task::yield_now();
            }
        }
        CallMode::Queued => {
            let done = || requests(|t| t[i].id != id || matches!(t[i].state, ReqState::Replied | ReqState::Failed));
            loop {
                REQ_WQ[i].register();
                if done() {
                    break;
                }
                let now = crate::arch::pit::ticks();
                if now >= deadline || !crate::task::is_task_alive(crate::task::TaskId(server)) {
                    break;
                }
                if crate::compat::linux::proc::signal_pending() {
                    interrupted = true;
                    break;
                }
                // Woken by the reply (or the server's end); a look every 100 ms meanwhile
                crate::task::wait::wait(Some(deadline.min(now + 10)));
            }
            REQ_WQ[i].unregister();
            QUEUED_CALLER[i].store(0, Ordering::Release);
        }
    }
    // The reply, or the request withdrawn: not yet taken, it goes now; taken, it stays
    // (abandoned) until the server answers or goes, since the server may still use its
    // pages and window
    let (result, free_grant) = requests(|t| {
        let r = &mut t[i];
        if r.id != id {
            return (Err(ETIMEDOUT), 0);
        }
        let result = match r.state {
            ReqState::Replied => Ok(r.reply),
            ReqState::Failed => Err(r.error),
            ReqState::Queued => Err(ETIMEDOUT),
            _ => {
                r.abandoned = true;
                return (Err(ETIMEDOUT), 0);
            }
        };
        let g = r.grant;
        *r = Request::FREE;
        (result, g)
    });
    release_grant(free_grant);
    match result {
        Err(ETIMEDOUT) if interrupted => Err(EINTR),
        Err(ETIMEDOUT) if !crate::task::is_task_alive(crate::task::TaskId(server)) => Err(ESRCH),
        Err(ETIMEDOUT) => {
            crate::kprintln!(
                "[service] call to {:#x} by task {}: no reply (cpu {}, tick {} deadline {}, {:?})",
                endpoint,
                me,
                crate::arch::percpu::cpu(),
                crate::arch::pit::ticks(),
                deadline,
                mode
            );
            Err(ETIMEDOUT)
        }
        r => r,
    }
}

// ----------------------------------------------------------------------
// Page grants
// ----------------------------------------------------------------------
//
// A caller may lend pages of its own memory to the server for one request instead of
// copying the data through the service window: a disk read lands straight in the caller's
// buffer (the AHCI driver points the adapter's DMA at it), a disk write is taken straight
// from it. The kernel pins the pages for as long as the server may use them (until it
// answers, or goes away, even if the caller stopped waiting) and tells the server their
// physical addresses ([`grant_segments`]); nothing is mapped into the server.
//
// (With an IOMMU, the segments must also enter the server's device's DMA domain while the
// grant lasts: see `make_grant` / `release_grant`.)

/// Most address ranges lent with one request.
pub const GRANT_RANGES: usize = 4;
/// Most pages one grant pins (256 KiB of data plus a partial page at each end of each range).
const GRANT_PAGES: usize = 64 + 2 * GRANT_RANGES;
/// Grants alive at once.
const MAX_GRANTS: usize = 16;

/// What a caller lends: `n` ranges `(address, length)` of its own memory, and whether the
/// server writes into them (a read from a device) or only reads them.
#[derive(Clone, Copy)]
pub struct GrantSpec {
    /// The ranges (user addresses of the calling process).
    pub ranges: [(u64, u64); GRANT_RANGES],
    /// How many of `ranges` are used.
    pub n: usize,
    /// The server (its device) writes into the pages.
    pub server_writes: bool,
}

/// A pinned grant.
#[derive(Clone, Copy)]
struct Grant {
    used: bool,
    /// Physical segments `(address, length)`, in the order of the ranges' bytes (physically
    /// adjacent pieces merged).
    segs: [(u64, u64); GRANT_PAGES],
    nsegs: usize,
    /// The pinned frames (one reference each).
    frames: [u64; GRANT_PAGES],
    nframes: usize,
    server_writes: bool,
}

impl Grant {
    const FREE: Self = Self { used: false, segs: [(0, 0); GRANT_PAGES], nsegs: 0, frames: [0; GRANT_PAGES], nframes: 0, server_writes: false };
}

static GRANTS: Mutex<[Grant; MAX_GRANTS]> = Mutex::new([Grant::FREE; MAX_GRANTS]);

/// Grants made since boot (`service status`).
pub static GRANTS_MADE: AtomicU64 = AtomicU64::new(0);

/// Pins the pages `spec` describes in the calling process and records them as a grant.
///
/// # Returns
///
/// The grant's index plus one (what [`Request::grant`] holds).
///
/// # Errors
///
/// - `-EINVAL`: Too many ranges or pages, or a caller without an address space of its own.
/// - `-EFAULT`: A page is not mapped (or not writable when the server writes).
/// - `-EBUSY`: Too many grants alive.
fn make_grant(spec: &GrantSpec, _endpoint: u32) -> Result<u8, i64> {
    use crate::memory::frame_allocator::{frame_ref_dec, frame_ref_inc};
    if spec.n == 0 || spec.n > GRANT_RANGES {
        return Err(EINVAL);
    }
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().ok_or(EINVAL)?;
    let mut g = Grant::FREE;
    g.server_writes = spec.server_writes;
    let pin = |g: &mut Grant| -> Result<(), i64> {
        let mut mm = mm.lock();
        for &(addr, len) in &spec.ranges[..spec.n] {
            if len == 0 {
                continue;
            }
            let end = addr.checked_add(len).ok_or(EINVAL)?;
            let mut at = addr;
            while at < end {
                let page = at & !0xFFF;
                let piece = (page + 4096).min(end) - at;
                if g.nframes == GRANT_PAGES {
                    return Err(EINVAL);
                }
                // Present (and private and writable, when the device writes into it)
                mm.handle_fault(at, spec.server_writes, false).map_err(|_| EFAULT)?;
                let phys = mm.translate(page).ok_or(EFAULT)?.as_u64();
                frame_ref_inc(PhysFrame::containing_address(PhysAddr::new(phys)));
                g.frames[g.nframes] = phys;
                g.nframes += 1;
                let seg = phys + (at - page);
                match g.nsegs.checked_sub(1).map(|l| g.segs[l]) {
                    Some((b, l)) if b + l == seg => g.segs[g.nsegs - 1].1 += piece,
                    _ => {
                        g.segs[g.nsegs] = (seg, piece);
                        g.nsegs += 1;
                    }
                }
                at += piece;
            }
        }
        Ok(())
    };
    if let Err(e) = pin(&mut g) {
        for &f in &g.frames[..g.nframes] {
            frame_ref_dec(PhysFrame::containing_address(PhysAddr::new(f)));
        }
        return Err(e);
    }
    g.used = true;
    let idx = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut t = GRANTS.lock();
        let i = t.iter().position(|x| !x.used)?;
        t[i] = g;
        Some(i)
    });
    match idx {
        Some(i) => {
            GRANTS_MADE.fetch_add(1, Ordering::Relaxed);
            Ok(i as u8 + 1)
        }
        None => {
            for &f in &g.frames[..g.nframes] {
                frame_ref_dec(PhysFrame::containing_address(PhysAddr::new(f)));
            }
            Err(EBUSY)
        }
    }
}

/// Unpins grant `g` (an index plus one; 0: none).
fn release_grant(g: u8) {
    if g == 0 {
        return;
    }
    let grant = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut t = GRANTS.lock();
        let x = t[g as usize - 1];
        t[g as usize - 1] = Grant::FREE;
        x
    });
    for &f in &grant.frames[..grant.nframes] {
        crate::memory::frame_allocator::frame_ref_dec(PhysFrame::containing_address(PhysAddr::new(f)));
    }
}

/// The physical segments `(address, length)` lent with request `id`, for its server to
/// point a device's DMA at (`SYS_SVC_GRANT`).
///
/// # Arguments
///
/// * `endpoint` - Endpoint the caller serves (the request's, or its primary's).
/// * `id` - The request, as [`recv`] returned it; it must be delivered and unanswered.
///
/// # Errors
///
/// - `-EPERM`: The caller does not serve `endpoint`.
/// - `-EINVAL`: No such request in progress, or it lends nothing.
pub fn grant_segments(endpoint: u32, id: u64) -> Result<(Vec<(u64, u64)>, bool), i64> {
    let svc = slot_owner(own_service(endpoint)?);
    let g = requests(|t| t.iter().find(|r| r.id == id && r.owner == svc.endpoint && r.state == ReqState::Delivered).map(|r| r.grant)).ok_or(EINVAL)?;
    if g == 0 {
        return Err(EINVAL);
    }
    Ok(x86_64::instructions::interrupts::without_interrupts(|| {
        let t = GRANTS.lock();
        let x = &t[g as usize - 1];
        (x.segs[..x.nsegs].to_vec(), x.server_writes)
    }))
}

// ----------------------------------------------------------------------
// Server side (system calls from driver processes)
// ----------------------------------------------------------------------

/// Validates that the calling process is authorized to serve `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Target endpoint index.
///
/// # Returns
///
/// `Ok(&'static Service)` if authorized; negative errno on error.
///
/// # Errors
///
/// - `-EPERM`: Calling task does not match the designated service endpoint.
/// - `-ENODEV`: Endpoint does not exist in the service registry.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn own_service(endpoint: u32) -> Result<&'static Service, i64> {
    // Its own endpoint, or one its endpoint is the primary of
    let me = crate::task::current_service();
    if me != Some(endpoint) && (me.is_none() || me != Some(primary_of(endpoint))) {
        return Err(EPERM);
    }
    service(endpoint).ok_or(ENODEV)
}

/// Maps a kernel object into the virtual memory space of the currently running process.
///
/// # Arguments
///
/// * `obj` - Mappable memory object (e.g. `ContiguousFrames` or `DeviceRange`).
/// * `pages` - Total count of 4 KiB pages to map.
///
/// # Returns
///
/// Virtual user-space address allocated for the mapping on success, or a negative errno.
///
/// # Errors
///
/// Returns `-EFAULT` if the task lacks an active virtual address space, or mmap errors.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn map_into_current(obj: Arc<dyn MappedObject>, pages: u64) -> Result<u64, i64> {
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().ok_or(EFAULT)?;
    let addr = mm.lock().mmap(0, pages * 4096, PROT_RW, true, false, false, Backing::Object { obj, pgoff: 0 })?;
    Ok(addr)
}

/// Registers the calling process as the authoritative server daemon for `endpoint`.
///
/// Maps the 256 KiB shared window into the process's address space and resumes any
/// kernel caller waiting for this service.
///
/// # Arguments
///
/// * `endpoint` - Endpoint number to register.
///
/// # Returns
///
/// User-space virtual address of the mapped 256 KiB shared window.
///
/// # Errors
///
/// - `-EPERM`: Caller is not designated for this endpoint.
/// - `-ENOMEM`: Physical contiguous frame allocation failed.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn register(endpoint: u32) -> Result<u64, i64> {
    let svc = own_service(endpoint)?;
    let window = {
        let mut w = svc.window.lock();
        if w.is_none() {
            *w = Some(ContiguousFrames::allocate(WINDOW_PAGES).ok_or(ENOMEM)?);
        }
        w.clone().unwrap()
    };
    let addr = map_into_current(window, WINDOW_PAGES)?;
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    svc.server.store(me, Ordering::Release);
    // A kernel caller waiting for this server to start resumes now
    x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().end_handoff(me));
    Ok(addr)
}

/// Blocks the calling server until a request arrives on `endpoint` (or an endpoint it is the
/// primary of) and takes it. Requests whose callers wait in a hand-off come first (the
/// kernel waits on them), then the oldest.
///
/// # Returns
///
/// `(request ID, request)`: the reply names the ID ([`reply`]).
///
/// # Errors
///
/// - `-EPERM`: Caller does not own this endpoint.
/// - `-EINTR`: Interrupted by a pending signal.
pub fn recv(endpoint: u32) -> Result<(u64, Message), i64> {
    let svc = slot_owner(own_service(endpoint)?);
    loop {
        svc.recv_wq.register();
        let got = requests(|t| {
            let i = t
                .iter()
                .enumerate()
                .filter(|(_, r)| r.state == ReqState::Queued && r.owner == svc.endpoint)
                .min_by_key(|(_, r)| (r.mode != CallMode::Handoff, r.id))
                .map(|(i, _)| i)?;
            t[i].state = ReqState::Delivered;
            Some((t[i].id, t[i].msg))
        });
        if let Some(req) = got {
            svc.recv_wq.unregister();
            return Ok(req);
        }
        crate::task::wait::wait(None);
        if crate::compat::linux::proc::signal_pending() {
            svc.recv_wq.unregister();
            return Err(EINTR);
        }
    }
}

/// Answers request `id` (0: the oldest one taken and not answered, for servers that answer
/// in order) and wakes its caller; a hand-off caller gets the CPU back at once.
///
/// # Errors
///
/// - `-EINVAL`: No such request taken by this service and unanswered.
pub fn reply(endpoint: u32, id: u64, answer: Message) -> Result<(), i64> {
    let svc = slot_owner(own_service(endpoint)?);
    let found = requests(|t| {
        let i = if id != 0 {
            t.iter().position(|r| r.id == id && r.owner == svc.endpoint && r.state == ReqState::Delivered)
        } else {
            t.iter()
                .enumerate()
                .filter(|(_, r)| r.owner == svc.endpoint && r.state == ReqState::Delivered)
                .min_by_key(|(_, r)| r.id)
                .map(|(i, _)| i)
        }?;
        let r = &mut t[i];
        let g = core::mem::take(&mut r.grant);
        if r.abandoned {
            // Its caller gave up: nobody takes the answer
            *r = Request::FREE;
            return Some((i, 0, CallMode::Queued, g));
        }
        r.state = ReqState::Replied;
        r.reply = answer;
        Some((i, r.caller, r.mode, g))
    });
    let Some((i, caller, mode, grant)) = found else { return Err(EINVAL) };
    // The server is done with the lent pages
    release_grant(grant);
    if caller == 0 {
        return Ok(());
    }
    match mode {
        CallMode::Handoff => {
            x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().end_handoff_of(caller));
            crate::task::yield_now();
        }
        CallMode::Queued => REQ_WQ[i].wake_all(),
    }
    Ok(())
}

/// Maps physical device memory into the driver's address space if permitted by supervisor grants.
///
/// # Arguments
///
/// * `phys` - Page-aligned physical start address.
/// * `len` - Length of the physical memory range in bytes.
///
/// # Returns
///
/// Virtual user-space base address of the mapped MMIO window on success.
///
/// # Errors
///
/// - `-EINVAL`: Unaligned address or zero length.
/// - `-EPERM`: The requested physical range is not permitted by any supervisor grant.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn physmap(phys: u64, len: u64) -> Result<u64, i64> {
    let endpoint = crate::task::current_service().ok_or(EPERM)?;
    let svc = service(endpoint).ok_or(ENODEV)?;
    if phys & 0xFFF != 0 || len == 0 {
        return Err(EINVAL);
    }
    let end = phys.checked_add(len).ok_or(EINVAL)?;
    let granted = svc.grants.lock().iter().any(|&(b, l)| phys >= b && end <= b + l);
    if !granted {
        return Err(EPERM);
    }
    let pages = (len + 4095) / 4096;
    map_into_current(Arc::new(DeviceRange { base: phys, pages }), pages)
}

/// Allocates physically contiguous memory for device DMA and maps it into the calling driver.
///
/// # Arguments
///
/// * `len` - Requested buffer size in bytes (must be <= 16 MiB).
///
/// # Returns
///
/// Tuple `(user_addr, phys_addr)` on success.
///
/// # Errors
///
/// - `-EINVAL`: Length is zero or exceeds 16 MiB.
/// - `-ENOMEM`: Physical contiguous allocation failed.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn dma_alloc(len: u64) -> Result<(u64, u64), i64> {
    crate::task::current_service().ok_or(EPERM)?;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(EINVAL);
    }
    let pages = (len + 4095) / 4096;
    let mem = ContiguousFrames::allocate(pages).ok_or(ENOMEM)?;
    let phys = mem.base;
    let addr = map_into_current(mem, pages)?;
    Ok((addr, phys))
}

/// Validates whether the calling driver is authorized to access legacy x86 I/O ports.
///
/// # Returns
///
/// `Ok(())` if the current task is a registered driver daemon; `-EPERM` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn iopl_allowed() -> Result<(), i64> {
    crate::task::current_service().map(|_| ()).ok_or(EPERM)
}

// ----------------------------------------------------------------------
// Interrupts
// ----------------------------------------------------------------------

/// Interrupt lines a driver can own: the legacy PIC's 0..16, then message-signalled
/// interrupts (MSI) from [`MSI_FIRST_LINE`] on, one per PCI function (see [`msi_line`]).
const IRQ_LINES: usize = 32;
/// The first MSI line; MSI line `n` arrives on IDT vector `MSI_VECTOR_BASE + n - 16`.
pub const MSI_FIRST_LINE: u8 = 16;

/// Task owning each line (0: the kernel).
static IRQ_OWNER: [AtomicU64; IRQ_LINES] = [const { AtomicU64::new(0) }; IRQ_LINES];
/// Interrupts raised since the owner last waited.
static IRQ_PENDING: [AtomicU32; IRQ_LINES] = [const { AtomicU32::new(0) }; IRQ_LINES];
/// Owner waiting for its interrupt.
static IRQ_WQ: [WaitQueue; IRQ_LINES] = [const { WaitQueue::new() }; IRQ_LINES];
/// Interrupts delivered to drivers since boot, per line (`service status`).
static IRQ_COUNT: [AtomicU64; IRQ_LINES] = [const { AtomicU64::new(0) }; IRQ_LINES];

/// Client wakes per line (diagnostics).
static IRQ_NOTIFIED: [AtomicU64; IRQ_LINES] = [const { AtomicU64::new(0) }; IRQ_LINES];

/// The PCI function each MSI line belongs to (`bus << 16 | device << 8 | function`, plus
/// one; 0: free). A restarted driver gets the same line for its device.
static MSI_DEVICE: [AtomicU32; IRQ_LINES - MSI_FIRST_LINE as usize] = [const { AtomicU32::new(0) }; IRQ_LINES - MSI_FIRST_LINE as usize];

/// Masks a line while its driver works: a PIC line is masked at the controller; an MSI
/// line needs nothing (messages are edge events, counted in [`IRQ_PENDING`] until the
/// driver waits again).
fn mask_line(irq: u8) {
    if irq < MSI_FIRST_LINE {
        crate::arch::pic::mask_irq(irq);
    }
}

/// Unmasks a line (see [`mask_line`]).
fn unmask_line(irq: u8) {
    if irq < MSI_FIRST_LINE {
        crate::arch::pic::unmask_irq(irq);
    }
}

/// Gives PCI function `dev` an MSI line and programs the device to signal it to the boot
/// processor; the supervisor passes the line to the device's driver, which registers it
/// like a legacy one ([`irq_register`]). The same device always gets the same line.
///
/// # Arguments
///
/// * `dev` - The PCI function.
///
/// # Returns
///
/// `Some(line)`, or `None` if the device has no MSI capability or the lines are used up.
pub fn msi_line(dev: &crate::arch::pci::PciDevice) -> Option<u8> {
    let key = ((dev.bus as u32) << 16 | (dev.device as u32) << 8 | dev.function as u32) + 1;
    let idx = MSI_DEVICE.iter().position(|d| d.load(Ordering::Acquire) == key).or_else(|| {
        MSI_DEVICE.iter().position(|d| d.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire).is_ok())
    })?;
    let vector = crate::arch::idt::MSI_VECTOR_BASE + idx as u64;
    if !crate::arch::pci::enable_msi(dev, crate::arch::smp::boot_apic_id(), vector as u8) {
        MSI_DEVICE[idx].store(0, Ordering::Release);
        return None;
    }
    Some(MSI_FIRST_LINE + idx as u8)
}

/// As [`msi_line`], for a device that offers only MSI-X (QEMU's `qemu-xhci`): the device's
/// MSI-X is enabled and its line allocated; its driver writes vector 0 of the table
/// (it maps the BAR holding it) with the message address and data returned here.
///
/// # Arguments
///
/// * `dev` - The PCI function.
///
/// # Returns
///
/// `Some((line, table physical address, message address, message data))`.
pub fn msix_line(dev: &crate::arch::pci::PciDevice) -> Option<(u8, u64, u32, u32)> {
    let key = ((dev.bus as u32) << 16 | (dev.device as u32) << 8 | dev.function as u32) + 1;
    let idx = MSI_DEVICE.iter().position(|d| d.load(Ordering::Acquire) == key).or_else(|| {
        MSI_DEVICE.iter().position(|d| d.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire).is_ok())
    })?;
    let Some(table) = crate::arch::pci::enable_msix(dev) else {
        MSI_DEVICE[idx].store(0, Ordering::Release);
        return None;
    };
    let vector = crate::arch::idt::MSI_VECTOR_BASE as u32 + idx as u32;
    let addr = 0xFEE0_0000 | (crate::arch::smp::boot_apic_id() & 0xFF) << 12;
    Some((MSI_FIRST_LINE + idx as u8, table, addr, vector))
}

/// Queries diagnostics for all hardware IRQ lines currently owned by userland drivers.
///
/// # Returns
///
/// A vector of tuples `(irq_line, owner_task, total_interrupts, client_wakes, pending_count, is_masked)`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn irq_stats() -> Vec<(u8, u64, u64, u64, u32, bool)> {
    let imr = unsafe { (x86_64::instructions::port::Port::<u8>::new(0x21).read() as u16) | (x86_64::instructions::port::Port::<u8>::new(0xA1).read() as u16) << 8 };
    (0..IRQ_LINES)
        .filter_map(|i| {
            let owner = IRQ_OWNER[i].load(Ordering::Acquire);
            (owner != 0).then(|| {
                (i as u8, owner, IRQ_COUNT[i].load(Ordering::Relaxed), IRQ_NOTIFIED[i].load(Ordering::Relaxed), IRQ_PENDING[i].load(Ordering::Relaxed), i < 16 && imr & (1 << i) != 0)
            })
        })
        .collect()
}

/// Endpoint of the service whose driver owns each line (its client is woken too, see
/// [`notify_on_irq`]).
static IRQ_SERVICE: [AtomicU32; IRQ_LINES] = [const { AtomicU32::new(0) }; IRQ_LINES];

/// Registers a legacy IRQ interrupt line to the calling driver daemon and unmasks it in the PIC.
///
/// # Arguments
///
/// * `irq` - Hardware IRQ line number (must not be 0, 1, 2, or 12).
///
/// # Returns
///
/// `Ok(())` on successful registration, or a negative errno.
///
/// # Errors
///
/// - `-EPERM`: Calling task is not a designated driver service.
/// - `-EINVAL`: Invalid IRQ line or reserved kernel line (timer, keyboard, cascade, mouse).
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn irq_register(irq: u64) -> Result<(), i64> {
    crate::task::current_service().ok_or(EPERM)?;
    // The timer, the keyboard, the cascade and the mouse stay with the kernel; an MSI
    // line must have been given to a device first
    if irq >= IRQ_LINES as u64 || matches!(irq, 0 | 1 | 2 | 12) {
        return Err(EINVAL);
    }
    if irq >= MSI_FIRST_LINE as u64 && MSI_DEVICE[(irq - MSI_FIRST_LINE as u64) as usize].load(Ordering::Acquire) == 0 {
        return Err(EINVAL);
    }
    let endpoint = crate::task::current_service().ok_or(EPERM)?;
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    IRQ_PENDING[irq as usize].store(0, Ordering::Release);
    IRQ_SERVICE[irq as usize].store(endpoint, Ordering::Release);
    IRQ_OWNER[irq as usize].store(me, Ordering::Release);
    unmask_line(irq as u8);
    if (8..16).contains(&irq) {
        crate::arch::pic::unmask_irq(2); // the cascade to the second controller
    }
    Ok(())
}

/// Invoked by low-level hardware ISR when an IRQ line triggers.
///
/// Masks the IRQ in the PIC, increments pending counters, wakes the driver's wait queue,
/// and notifies any registered client wait queues.
///
/// # Arguments
///
/// * `irq` - Hardware IRQ line that fired.
///
/// # Returns
///
/// `true` if the line was registered to a userland driver; `false` if unhandled.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn irq_raised(irq: u8) -> bool {
    let owner = IRQ_OWNER.get(irq as usize).map_or(0, |o| o.load(Ordering::Acquire));
    if owner == 0 {
        return false;
    }
    mask_line(irq);
    IRQ_COUNT[irq as usize].fetch_add(1, Ordering::Relaxed);
    IRQ_PENDING[irq as usize].fetch_add(1, Ordering::AcqRel);
    IRQ_WQ[irq as usize].wake_all();
    let notify = service(IRQ_SERVICE[irq as usize].load(Ordering::Acquire)).map_or(core::ptr::null_mut(), |s| s.irq_notify.load(Ordering::Acquire));
    if !notify.is_null() {
        IRQ_NOTIFIED[irq as usize].fetch_add(1, Ordering::Relaxed);
        unsafe { (*notify).wake_all() };
    }
    true
}

/// Acknowledges an interrupt without sleeping, resetting the pending count and unmasking the line.
///
/// # Arguments
///
/// * `irq` - Hardware IRQ line to acknowledge.
///
/// # Returns
///
/// The number of interrupts that accumulated since the last wait or acknowledgment.
///
/// # Errors
///
/// - `-EPERM`: Caller is not the registered owner of this IRQ line.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn irq_ack(irq: u64) -> Result<u32, i64> {
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    if irq >= IRQ_LINES as u64 || IRQ_OWNER[irq as usize].load(Ordering::Acquire) != me {
        return Err(EPERM);
    }
    let n = IRQ_PENDING[irq as usize].swap(0, Ordering::AcqRel);
    unmask_line(irq as u8);
    Ok(n)
}

/// Unmasks an IRQ line and blocks the calling driver daemon until the next interrupt fires or deadline expires.
///
/// # Arguments
///
/// * `irq` - Hardware IRQ line to await.
/// * `timeout_ticks` - Maximum wait duration in 10 ms ticks (0 for infinite wait).
///
/// # Returns
///
/// Number of interrupts accumulated since previous wait (0 on timeout).
///
/// # Errors
///
/// - `-EPERM`: Caller does not own this IRQ line.
/// - `-EINTR`: Interrupted by a signal.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn irq_wait(irq: u64, timeout_ticks: u64) -> Result<u32, i64> {
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    if irq >= IRQ_LINES as u64 || IRQ_OWNER[irq as usize].load(Ordering::Acquire) != me {
        return Err(EPERM);
    }
    let deadline = (timeout_ticks != 0).then(|| crate::arch::pit::ticks() + timeout_ticks);
    unmask_line(irq as u8);
    loop {
        IRQ_WQ[irq as usize].register();
        let n = IRQ_PENDING[irq as usize].swap(0, Ordering::AcqRel);
        if n > 0 {
            IRQ_WQ[irq as usize].unregister();
            return Ok(n);
        }
        if deadline.map_or(false, |d| crate::arch::pit::ticks() >= d) {
            IRQ_WQ[irq as usize].unregister();
            return Ok(0);
        }
        crate::task::wait::wait(deadline);
        if crate::compat::linux::proc::signal_pending() {
            IRQ_WQ[irq as usize].unregister();
            return Err(EINTR);
        }
    }
}

/// Relinquishes all IRQ lines owned by an exiting task back to the kernel.
///
/// # Arguments
///
/// * `id` - Task ID of the terminating process.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn release_irqs(id: u64) {
    for (irq, owner) in IRQ_OWNER.iter().enumerate() {
        if owner.compare_exchange(id, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            mask_line(irq as u8);
            IRQ_SERVICE[irq].store(0, Ordering::Release);
        }
    }
}
