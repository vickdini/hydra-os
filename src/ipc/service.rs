//! # IPC Subsystem: Driver Services
//!
//! Request/reply calls from the kernel (or another driver) to driver and server processes
//! that run in Ring 3, each in an address space of its own.
//!
//! ## Architectural Role & Design Rationale
//!
//! A service is an endpoint ([`ENDPOINT_BLOCK_DEV`], ...) with at most one server: the
//! process the supervisor started for it ([`crate::task::spawn_service`]). The server
//! registers ([`register`]), then loops receiving a request ([`recv`]) and answering it
//! ([`reply`]). A client calls ([`call`]) and gets the reply.
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
//! they may map ([`set_grants`]; the framebuffer, a NIC's registers), DMA memory they
//! allocate themselves ([`dma_alloc`]), and interrupt lines ([`irq_register`]). Interrupts
//! never run driver code or take locks: the handler masks the line, counts it and wakes
//! the driver ([`irq_raised`]); the driver unmasks it when it waits again ([`irq_wait`]).

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
    fn from(m: Message) -> Self {
        Self { label: m.label as u64, args: m.args }
    }
}

impl From<WireMessage> for Message {
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
    /// Allocates `pages` zeroed, physically contiguous pages.
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

    /// The memory as the kernel sees it (physical memory is identity-mapped).
    ///
    /// # Safety
    /// The caller must not hold the slice across a point where the server may write it.
    pub unsafe fn bytes(&self) -> &'static mut [u8] {
        core::slice::from_raw_parts_mut(self.base as *mut u8, (self.pages * 4096) as usize)
    }
}

impl MappedObject for ContiguousFrames {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        (pgoff < self.pages).then(|| PhysFrame::containing_address(PhysAddr::new(self.base + pgoff * 4096)))
    }
}

impl Drop for ContiguousFrames {
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
        }
    }
}

/// The services, one per system endpoint.
static SERVICES: [Service; 4] = [
    Service::new(ENDPOINT_ZFS_SERVER),
    Service::new(ENDPOINT_BLOCK_DEV),
    Service::new(ENDPOINT_NET_DEV),
    Service::new(ENDPOINT_DISPLAY_DEV),
];

/// The service on `endpoint`.
pub fn service(endpoint: u32) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.endpoint == endpoint)
}

/// Whether a server is registered on `endpoint`.
pub fn is_online(endpoint: u32) -> bool {
    service(endpoint).map_or(false, |s| s.server.load(Ordering::Acquire) != 0)
}

/// Task serving `endpoint` (0 if none).
pub fn server_of(endpoint: u32) -> u64 {
    service(endpoint).map_or(0, |s| s.server.load(Ordering::Acquire))
}

/// The service window as the kernel sees it, once a server has registered.
pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
    let svc = service(endpoint)?;
    let w = svc.window.lock().clone()?;
    // The window lives as long as the service (it is never replaced once allocated)
    Some(unsafe { w.bytes() })
}

/// Sets the physical ranges (`(base, length)`) the server of `endpoint` may map.
pub fn set_grants(endpoint: u32, grants: Vec<(u64, u64)>) {
    if let Some(svc) = service(endpoint) {
        *svc.grants.lock() = grants;
    }
}

/// Wakes `wq` whenever the interrupt of `endpoint`'s driver arrives.
pub fn notify_on_irq(endpoint: u32, wq: &'static WaitQueue) {
    if let Some(svc) = service(endpoint) {
        svc.irq_notify.store(wq as *const WaitQueue as *mut WaitQueue, Ordering::Release);
    }
}

/// Forgets the server of `endpoint` (it died or is being replaced), failing a call in
/// progress.
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

/// Calls the server of `endpoint` with `request` and returns its reply.
///
/// Data for the request must already be in the window ([`window`]). Fails with `-ENODEV`
/// if no server is registered, `-EBUSY` if a call is already in progress (a server
/// calling itself), and `-ETIMEDOUT` if the server does not answer within `timeout_ticks`.
/// A server that is gone (it crashed) is restarted and the call made again, once.
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

/// Whether the registered server of `svc` is still running.
fn server_alive(svc: &Service) -> bool {
    let server = svc.server.load(Ordering::Acquire);
    server != 0 && crate::task::is_task_alive(crate::task::TaskId(server))
}

/// [`call`] without restarting a dead server (the supervisor's heartbeat).
pub fn call_once(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    let svc = service(endpoint).ok_or(ENODEV)?;
    let server = svc.server.load(Ordering::Acquire);
    if server == 0 || !crate::task::is_active() {
        return Err(ENODEV);
    }
    let seq = {
        let mut slot = svc.slot.lock();
        if slot.request.is_some() {
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
        return Err(EBUSY);
    }
    crate::task::yield_now();
    let mut slot = svc.slot.lock();
    match slot.reply.take() {
        Some(reply) if slot.seq == seq => Ok(reply),
        _ => {
            // No answer: abandon the call (a late reply is ignored)
            slot.request = None;
            Err(ETIMEDOUT)
        }
    }
}

// ----------------------------------------------------------------------
// Server side (system calls from driver processes)
// ----------------------------------------------------------------------

/// The current task's service, if it serves `endpoint`.
fn own_service(endpoint: u32) -> Result<&'static Service, i64> {
    if crate::task::current_service() != Some(endpoint) {
        return Err(EPERM);
    }
    service(endpoint).ok_or(ENODEV)
}

/// Maps `obj` (`pages` long) shared and writable into the current process.
fn map_into_current(obj: Arc<dyn MappedObject>, pages: u64) -> Result<u64, i64> {
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().ok_or(EFAULT)?;
    let addr = mm.lock().mmap(0, pages * 4096, PROT_RW, true, false, false, Backing::Object { obj, pgoff: 0 })?;
    Ok(addr)
}

/// `SYS_SVC_REGISTER`: makes the calling driver process the server of `endpoint` and maps
/// the service window into it. Returns the window's address (its size is [`WINDOW_SIZE`]).
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

/// `SYS_SVC_RECV`: waits for the next request on `endpoint` (served by the caller).
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

/// `SYS_SVC_REPLY`: answers the request received on `endpoint` and lets its caller run.
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

/// `SYS_PHYSMAP`: maps granted device memory `[phys, phys + len)` into the calling driver.
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

/// `SYS_DMA_ALLOC`: allocates `len` bytes of physically contiguous memory for device DMA
/// and maps it into the calling driver. Returns `(address, physical address)`; the memory
/// is freed when the driver unmaps it or exits.
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

/// `SYS_IOPL`: lets the calling driver use I/O ports (sets IOPL 3 in the flags it returns
/// to user mode with).
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

/// Lines owned by drivers: `(line, owner task, interrupts since boot, client wakes,
/// pending, masked now)`.
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

/// `SYS_IRQ_REGISTER`: routes interrupt line `irq` to the calling driver.
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

/// Called by the interrupt handler: if a driver owns `irq`, masks the line (its device
/// keeps asserting it until the driver acknowledges it), counts it and wakes the driver.
/// Returns whether a driver owns it. Never blocks or allocates.
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

/// `SYS_IRQ_ACK`: the driver has serviced its device: unmasks `irq` without waiting.
/// Returns the number of interrupts since the last wait or acknowledgement.
pub fn irq_ack(irq: u64) -> Result<u32, i64> {
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    if irq >= 16 || IRQ_OWNER[irq as usize].load(Ordering::Acquire) != me {
        return Err(EPERM);
    }
    let n = IRQ_PENDING[irq as usize].swap(0, Ordering::AcqRel);
    crate::arch::pic::unmask_irq(irq as u8);
    Ok(n)
}

/// `SYS_IRQ_WAIT`: unmasks `irq` (the driver has serviced its device) and waits up to
/// `timeout_ticks` (0: forever) for it. Returns the number of interrupts since the last wait.
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

/// Returns the interrupt lines of task `id` to the kernel (it exited).
pub fn release_irqs(id: u64) {
    for (irq, owner) in IRQ_OWNER.iter().enumerate() {
        if owner.compare_exchange(id, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            crate::arch::pic::mask_irq(irq as u8);
            IRQ_SERVICE[irq].store(0, Ordering::Release);
        }
    }
}
