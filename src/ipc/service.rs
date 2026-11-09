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
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 4096) as usize) };
        Some(Arc::new(Self { base, pages }))
    }

    /// Accesses the contiguous memory as a mutable byte slice from the kernel's identity mapping.
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
        core::slice::from_raw_parts_mut(self.base as *mut u8, (self.pages * 4096) as usize)
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

/// The call in progress on a service.
#[derive(Default)]
struct CallSlot {
    /// Call number, to tell a late reply to an abandoned call from the current one.
    seq: u64,
    /// The request, until the call ends.
    request: Option<Message>,
    /// Whether the server has received the request.
    delivered: bool,
    /// The server's answer.
    reply: Option<Message>,
}

/// One driver service.
pub struct Service {
    /// Endpoint number.
    pub endpoint: u32,
    /// Task serving it (0: none registered).
    server: AtomicU64,
    /// The call in progress.
    slot: Mutex<CallSlot>,
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
}

impl Service {
    const fn new(endpoint: u32) -> Self {
        Self {
            endpoint,
            server: AtomicU64::new(0),
            slot: Mutex::new(CallSlot { seq: 0, request: None, delivered: false, reply: None }),
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
static SERVICES: [Service; 4] = [
    Service::new(ENDPOINT_ZFS_SERVER),
    Service::new(ENDPOINT_BLOCK_DEV),
    Service::new(ENDPOINT_NET_DEV),
    Service::new(ENDPOINT_DISPLAY_DEV),
];

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

/// Tasks using a service's window, by endpoint: `(task, depth)` (a task may nest uses).
static WINDOW_HOLDERS: Mutex<alloc::collections::BTreeMap<u32, (u64, u32)>> = Mutex::new(alloc::collections::BTreeMap::new());
/// Windows held (a lock-free check for [`window_held_by_other`]).
static WINDOWS_HELD: AtomicU32 = AtomicU32::new(0);

/// Runs `f` on the window holders with interrupts off: the lock is taken where interrupts
/// may be on (waiting loops), and an interrupt handler waiting for the kernel lock while
/// this CPU held it would stall the kernel lock's holder, which may want it too.
fn holders<R>(f: impl FnOnce(&mut alloc::collections::BTreeMap<u32, (u64, u32)>) -> R) -> R {
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
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    loop {
        let taken = holders(|h| match h.get_mut(&endpoint) {
            None => {
                h.insert(endpoint, (me, 1));
                WINDOWS_HELD.fetch_add(1, Ordering::AcqRel);
                true
            }
            Some((t, d)) if *t == me => {
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
            if let Some((_, d)) = h.get_mut(&self.endpoint) {
                *d -= 1;
                if *d == 0 {
                    h.remove(&self.endpoint);
                    WINDOWS_HELD.fetch_sub(1, Ordering::AcqRel);
                }
            }
        })
    }
}

/// Whether a task other than `task` holds a service window (its call, or its reading of
/// the reply, is in progress).
pub fn window_held_by_other(task: u64) -> bool {
    WINDOWS_HELD.load(Ordering::Acquire) > 0 && holders(|h| h.values().any(|(t, _)| *t != task))
}

/// Releases the service windows task `id` holds (it ended in the middle of a call: it never
/// resumes to drop its guards).
pub fn release_windows(id: u64) {
    holders(|h| {
        let before = h.len();
        h.retain(|_, (t, _)| *t != id);
        let gone = before - h.len();
        if gone > 0 {
            WINDOWS_HELD.fetch_sub(gone as u32, Ordering::AcqRel);
        }
    })
}

/// The tasks holding service windows, as `(endpoint, task)`, for diagnostics.
pub fn window_holders() -> alloc::vec::Vec<(u32, u64)> {
    holders(|h| h.iter().map(|(e, (t, _))| (*e, *t)).collect())
}

/// Whether `task` holds a service window.
pub fn holds_window(task: u64) -> bool {
    WINDOWS_HELD.load(Ordering::Acquire) > 0 && holders(|h| h.values().any(|(t, _)| *t == task))
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

/// Unregisters the server currently bound to `endpoint`, terminating active CPU handoffs.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint to detach.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn unregister(endpoint: u32) {
    if let Some(svc) = service(endpoint) {
        let server = svc.server.swap(0, Ordering::AcqRel);
        if server != 0 {
            crate::task::SCHEDULER.lock().end_handoff(server);
        }
        let mut slot = svc.slot.lock();
        slot.request = None;
        slot.reply = None;
    }
}

/// Calls the server of `endpoint` with `request` and returns its reply, reviving dead daemons if needed.
///
/// Performs direct CPU handoff to the server daemon. If the daemon has crashed or faults,
/// revives the daemon on-the-spot through the supervisor and retries the call once.
///
/// # Arguments
///
/// * `endpoint` - Target service endpoint.
/// * `request` - Message containing protocol opcode and arguments.
/// * `timeout_ticks` - Maximum duration to await a response in 10 ms timer ticks.
///
/// # Returns
///
/// `Ok(Message)` containing the server's reply, or negative errno on error.
///
/// # Errors
///
/// - `-ENODEV`: No server daemon is registered or revival failed.
/// - `-EBUSY`: Another call is currently in flight or handoff failed.
/// - `-ETIMEDOUT`: Server failed to reply within `timeout_ticks`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    let svc = service(endpoint).ok_or(ENODEV)?;
    if !crate::task::is_active() {
        return Err(ENODEV);
    }
    if svc.server.load(Ordering::Acquire) == 0 && !crate::task::supervisor::revive(endpoint) {
        return Err(ENODEV);
    }
    match call_once(endpoint, request, timeout_ticks) {
        Err(ETIMEDOUT) if !server_alive(svc) && crate::task::supervisor::revive(endpoint) => call_once(endpoint, request, timeout_ticks),
        r => r,
    }
}

/// Checks whether the registered server process for `svc` is still running.
///
/// # Arguments
///
/// * `svc` - Service descriptor to query.
///
/// # Returns
///
/// `true` if the server task exists and is alive; `false` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn server_alive(svc: &Service) -> bool {
    let server = svc.server.load(Ordering::Acquire);
    server != 0 && crate::task::is_task_alive(crate::task::TaskId(server))
}

/// Issues a service call without reviving a failed server daemon.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint identifier.
/// * `request` - Request message payload.
/// * `timeout_ticks` - Deadline in timer ticks (10 ms units).
///
/// # Returns
///
/// `Ok(Message)` containing reply on success, or a negative errno.
///
/// # Errors
///
/// - `-ENODEV`: No server registered or multitasking not active.
/// - `-EDEADLK`: Server attempted to call its own service endpoint.
/// - `-EBUSY`: Another request is pending in the call slot.
/// - `-ETIMEDOUT`: Server failed to reply before deadline.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn call_once(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    let svc = service(endpoint).ok_or(ENODEV)?;
    let server = svc.server.load(Ordering::Acquire);
    if server == 0 || !crate::task::is_active() {
        return Err(ENODEV);
    }
    if crate::task::SCHEDULER.lock().current_task_id().0 == server {
        return Err(EDEADLK); // a server calling its own service would wait for itself
    }
    let seq = {
        let mut slot = svc.slot.lock();
        if slot.request.is_some() {
            crate::kprintln!("[service] call to {:#x} by task {}: busy (cpu {})", endpoint, crate::task::SCHEDULER.lock().current_task_id().0, crate::arch::percpu::cpu());
            return Err(EBUSY);
        }
        slot.seq += 1;
        slot.request = Some(request);
        slot.delivered = false;
        slot.reply = None;
        slot.seq
    };
    svc.recv_wq.wake_all();
    let deadline = crate::arch::pit::ticks() + timeout_ticks;
    let handed = x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().begin_handoff(server, deadline));
    if !handed {
        svc.slot.lock().request = None;
        crate::kprintln!("[service] call to {:#x}: no handoff slot", endpoint);
        return Err(EBUSY);
    }
    crate::task::yield_now();
    let mut slot = svc.slot.lock();
    match slot.reply.take() {
        Some(reply) if slot.seq == seq => Ok(reply),
        _ => {
            // No answer: abandon the call (a late reply is ignored)
            slot.request = None;
            drop(slot);
            crate::kprintln!(
                "[service] call to {:#x} by task {}: no reply (cpu {}, tick {} deadline {})",
                endpoint,
                crate::task::SCHEDULER.lock().current_task_id().0,
                crate::arch::percpu::cpu(),
                crate::arch::pit::ticks(),
                deadline
            );
            Err(ETIMEDOUT)
        }
    }
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
    if crate::task::current_service() != Some(endpoint) {
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

/// Blocks the calling driver daemon until a request arrives on its designated `endpoint`.
///
/// # Arguments
///
/// * `endpoint` - Endpoint served by the caller.
///
/// # Returns
///
/// `Ok(Message)` containing the received client request.
///
/// # Errors
///
/// - `-EPERM`: Caller does not own this endpoint.
/// - `-EINTR`: Interrupted by a pending signal.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn recv(endpoint: u32) -> Result<Message, i64> {
    let svc = own_service(endpoint)?;
    loop {
        svc.recv_wq.register();
        {
            let mut slot = svc.slot.lock();
            if let (Some(req), false) = (slot.request, slot.delivered) {
                slot.delivered = true;
                drop(slot);
                svc.recv_wq.unregister();
                return Ok(req);
            }
        }
        crate::task::wait::wait(None);
        if crate::compat::linux::proc::signal_pending() {
            svc.recv_wq.unregister();
            return Err(EINTR);
        }
    }
}

/// Dispatches a reply to the active request on `endpoint` and yields the CPU back to the caller.
///
/// # Arguments
///
/// * `endpoint` - Service endpoint identifier.
/// * `answer` - Response message to return to the waiting client.
///
/// # Returns
///
/// `Ok(())` on success, or a negative errno.
///
/// # Errors
///
/// - `-EINVAL`: No active undelivered request in the service slot.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn reply(endpoint: u32, answer: Message) -> Result<(), i64> {
    let svc = own_service(endpoint)?;
    {
        let mut slot = svc.slot.lock();
        if slot.request.is_none() || !slot.delivered {
            return Err(EINVAL);
        }
        slot.request = None;
        slot.reply = Some(answer);
    }
    let me = svc.server.load(Ordering::Acquire);
    x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().end_handoff(me));
    crate::task::yield_now();
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

/// Task owning each legacy IRQ line (0: the kernel).
static IRQ_OWNER: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
/// Interrupts raised since the owner last waited.
static IRQ_PENDING: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
/// Owner waiting for its interrupt.
static IRQ_WQ: [WaitQueue; 16] = [const { WaitQueue::new() }; 16];
/// Interrupts delivered to drivers since boot, per line (`service status`).
static IRQ_COUNT: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

/// Client wakes per line (diagnostics).
static IRQ_NOTIFIED: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

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
    (0..16)
        .filter_map(|i| {
            let owner = IRQ_OWNER[i].load(Ordering::Acquire);
            (owner != 0).then(|| {
                (i as u8, owner, IRQ_COUNT[i].load(Ordering::Relaxed), IRQ_NOTIFIED[i].load(Ordering::Relaxed), IRQ_PENDING[i].load(Ordering::Relaxed), imr & (1 << i) != 0)
            })
        })
        .collect()
}

/// Endpoint of the service whose driver owns each line (its client is woken too, see
/// [`notify_on_irq`]).
static IRQ_SERVICE: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];

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
    // The timer, the keyboard, the cascade and the mouse stay with the kernel
    if irq >= 16 || matches!(irq, 0 | 1 | 2 | 12) {
        return Err(EINVAL);
    }
    let endpoint = crate::task::current_service().ok_or(EPERM)?;
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    IRQ_PENDING[irq as usize].store(0, Ordering::Release);
    IRQ_SERVICE[irq as usize].store(endpoint, Ordering::Release);
    IRQ_OWNER[irq as usize].store(me, Ordering::Release);
    crate::arch::pic::unmask_irq(irq as u8);
    if irq >= 8 {
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
    crate::arch::pic::mask_irq(irq);
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
    if irq >= 16 || IRQ_OWNER[irq as usize].load(Ordering::Acquire) != me {
        return Err(EPERM);
    }
    let n = IRQ_PENDING[irq as usize].swap(0, Ordering::AcqRel);
    crate::arch::pic::unmask_irq(irq as u8);
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
    if irq >= 16 || IRQ_OWNER[irq as usize].load(Ordering::Acquire) != me {
        return Err(EPERM);
    }
    let deadline = (timeout_ticks != 0).then(|| crate::arch::pit::ticks() + timeout_ticks);
    crate::arch::pic::unmask_irq(irq as u8);
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
            crate::arch::pic::mask_irq(irq as u8);
            IRQ_SERVICE[irq].store(0, Ordering::Release);
        }
    }
}
