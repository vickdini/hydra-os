//! # The screen lent to the display service (wave 8, Group D)
//!
//! `docs/display-input-design.md` sections 3.2, 3.6 and 5: the display service
//! (`userland/drivers/display-server`, endpoint 0x23) draws the desktop's pictures on the
//! firmware framebuffer, which the kernel's text console **lends** it. Everything the
//! console needs to work without user space stays here:
//!
//! - **The mapping** ([`SCREEN_MAP`]): the service maps the screen once, as a memory object
//!   whose framebuffer pages lead to the framebuffer while the screen is lent and to one
//!   scratch page otherwise, followed by a status page (the state word, the service's
//!   "copying" word). **Taking the screen back is a remapping:** the state word changes,
//!   then the service's mapping is zapped (`Mm::discard`, with the TLB shootdown), so
//!   every later write refaults onto the scratch page. The kernel never waits for the
//!   service: a stuck or crashed service cannot keep the console off the screen.
//! - **The screen's owner** (`SCREEN_CONSOLE` / `SHOWN` / `HIDDEN` / `PANIC`; the decisions
//!   are [`policy`]): the service asks for the screen on its session's first picture
//!   ([`SCREEN_TAKE`], which also ends the boot splash) and gives it back when no session
//!   needs it ([`SCREEN_GIVE`]); the hot keys hide and show the session; the service's
//!   death ([`service_gone`]) and a kernel panic ([`panic_stop`]) give it to the console.
//!   Input is routed to the session only while it shows ([`route_input`]: the call agreed
//!   with Group I).
//! - **The hot keys' switch target**: `keyboard.rs` asks `drm::request_vt_switch`, which
//!   comes here through the hooks installed at the first mapping; the switch itself runs in
//!   the `screend` kernel task (the zap and the copies are not interrupt work).
//! - **Notifications**: the service's screen thread waits in [`SCREEN_WAIT`] for a state
//!   change (or its next emulated vertical blank, a precise deadline).
//!
//! With `lx=kernel` or `lx.display=kernel` the service never maps the screen and the
//! kernel's `compat/linux/drm.rs` borrows it from the console as before.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::ipc::protocol::{
    ScreenInfo, ENDPOINT_DISPLAY_DEV, SCREEN_CONSOLE, SCREEN_GIVE, SCREEN_HIDDEN, SCREEN_INFO, SCREEN_KICK, SCREEN_MAP, SCREEN_NOW, SCREEN_PANIC, SCREEN_REFRESH_MHZ, SCREEN_SHOWN,
    SCREEN_ST_COPYING, SCREEN_ST_GEN, SCREEN_ST_STATE, SCREEN_TAKE, SCREEN_WAIT,
};
use crate::memory::vm::{Backing, MappedObject, Mm, PAGE_SIZE};
use crate::task::wait::WaitQueue;

pub mod policy;
use policy::{Event, Page};

const EPERM: i64 = -1;
const ENXIO: i64 = -6;
const ENODEV: i64 = -19;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

/// The state (`SCREEN_*`), read without the lock (the mapping's page lookups, the hot keys).
static STATE: AtomicU32 = AtomicU32::new(SCREEN_CONSOLE);
/// Bumped by every state change.
static GEN: AtomicU64 = AtomicU64::new(1);
/// The display service mapped the screen at least once this boot (its hooks are in).
static SERVICE: AtomicBool = AtomicBool::new(false);
/// The service's screen thread asked to stop waiting ([`SCREEN_KICK`]).
static KICKED: AtomicBool = AtomicBool::new(false);
/// Its waiters.
static WAITQ: WaitQueue = WaitQueue::new();
/// The hot keys' request for `screend`: 0 none, 1 hide (to the console), 2 show.
static REQUEST: AtomicU8 = AtomicU8::new(0);
static REQUEST_WQ: WaitQueue = WaitQueue::new();
static SCREEND: AtomicBool = AtomicBool::new(false);
/// The display service died: `screend` ends the desktop session (decision 28).
static END_SESSION: AtomicBool = AtomicBool::new(false);
/// The status page (its kernel address; 0 until the first mapping) and the scratch page's
/// frame, allocated once and kept for good.
static STATUS_VIRT: AtomicU64 = AtomicU64::new(0);
static STATUS_FRAME: AtomicU64 = AtomicU64::new(0);
static SINK_FRAME: AtomicU64 = AtomicU64::new(0);
/// Counters for the diagnostics line.
static TAKES: AtomicU64 = AtomicU64::new(0);
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// The transitions and the service's mapping, serialized.
struct Inner {
    /// The service's address space and the framebuffer part of its mapping `[start, end)`.
    mapping: Option<(Arc<Mutex<Mm>>, u64, u64)>,
}

static INNER: Mutex<Inner> = Mutex::new(Inner { mapping: None });

/// The screen as a mapped object (one for the whole boot).
struct ScreenObject {
    fb_phys: u64,
    fb_pages: u64,
}

impl MappedObject for ScreenObject {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        let lent = STATE.load(Ordering::Acquire) == SCREEN_SHOWN;
        let addr = match policy::page_of(pgoff, self.fb_phys, self.fb_pages, lent) {
            Page::Framebuffer(a) => a,
            Page::Sink => SINK_FRAME.load(Ordering::Acquire),
            Page::Status => STATUS_FRAME.load(Ordering::Acquire),
            Page::None => return None,
        };
        (addr != 0).then(|| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

static OBJECT: Mutex<Option<Arc<ScreenObject>>> = Mutex::new(None);

/// The framebuffer: (physical address, bytes, width, height, stride in pixels, BGR).
fn fb() -> Option<(u64, u64, u32, u32, u32, bool)> {
    let (phys, bytes) = crate::video::gop::framebuffer_phys()?;
    let i = crate::video::get_video_info()?;
    Some((phys, bytes.max(i.stride as u64 * i.height as u64 * 4), i.width as u32, i.height as u32, i.stride as u32, i.is_bgr))
}

/// Writes status word `i`.
fn status_set(i: usize, v: u32) {
    let p = STATUS_VIRT.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: the status page is a frame kept for good; words are u32-aligned
        unsafe { (*(p as *const AtomicU32).add(i)).store(v, Ordering::SeqCst) };
    }
}

/// Reads status word `i`.
fn status_get(i: usize) -> u32 {
    let p = STATUS_VIRT.load(Ordering::Acquire);
    if p == 0 {
        return 0;
    }
    // SAFETY: as `status_set`
    unsafe { (*(p as *const AtomicU32).add(i)).load(Ordering::SeqCst) }
}

// wave8 GD begin: the routing call agreed with Group I (NOTES.md, wave 8): one place
/// Input goes to the desktop session (`on`) or back to the console (held keys released).
fn route_input(on: bool) {
    crate::compat::linux::evdev::set_routing(on);
    if !on {
        crate::compat::linux::evdev::release_held_keys();
    }
}
// wave8 GD end

/// Carries out event `ev`; returns the state afterwards. The whole transition runs under
/// [`INNER`] (a `Take` must not lend the screen while a `Give` before it has not yet given
/// it back to the console); only a panic changes the state without it.
fn apply(ev: Event) -> u32 {
    let mut inner = INNER.lock();
    let st = STATE.load(Ordering::Acquire);
    // (a hot key queued before a session ended must not hide the next one)
    if matches!(ev, Event::Give | Event::Gone) {
        REQUEST.store(0, Ordering::Release);
    }
    let release = if policy::needs_release(st, ev) { crate::video::console::release_display().is_some() } else { false };
    let (new, act) = policy::step(st, ev, release);
    if ev == Event::Gone && !act.zap {
        // (the dead instance's address space is not kept alive by our record)
        inner.mapping = None;
    }
    if new == st && !act.notify {
        return st;
    }
    // A panic on another CPU since the load wins: the console keeps the screen
    if STATE.compare_exchange(st, new, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return SCREEN_PANIC;
    }
    status_set(SCREEN_ST_STATE, new);
    if STATE.load(Ordering::SeqCst) == SCREEN_PANIC {
        status_set(SCREEN_ST_STATE, SCREEN_PANIC);
        return SCREEN_PANIC;
    }
    if act.zap {
        if let Some((mm, start, end)) = inner.mapping.as_ref() {
            let mut m = mm.lock();
            m.discard(*start, *end);
            // Lent: the framebuffer's pages are mapped now, not one fault at a time during
            // the service's next copy (a fault from user mode costs several times more)
            if new == SCREEN_SHOWN {
                let _ = m.prefault(*start, *end - *start, true);
            }
        }
    }
    if ev == Event::Gone {
        inner.mapping = None;
    }
    if let Some(on) = act.route {
        route_input(on);
    }
    if act.reclaim {
        crate::video::console::reclaim_display();
    }
    if act.notify {
        let g = GEN.fetch_add(1, Ordering::AcqRel) + 1;
        status_set(SCREEN_ST_GEN, g as u32);
        WAITQ.wake_all();
    }
    drop(inner);
    new
}

/// The `screend` task: carries out the hot keys' switches.
fn screend_main() {
    loop {
        REQUEST_WQ.register();
        if END_SESSION.swap(false, Ordering::AcqRel) {
            end_session();
            continue;
        }
        match REQUEST.swap(0, Ordering::AcqRel) {
            1 => {
                apply(Event::Hide);
                SWITCHES.fetch_add(1, Ordering::Relaxed);
            }
            2 => {
                apply(Event::Show);
                SWITCHES.fetch_add(1, Ordering::Relaxed);
            }
            _ => crate::task::wait::wait(None),
        }
    }
}

/// The hot keys (keyboard interrupt, through `drm::request_vt_switch`): `true` if the switch
/// is the display service's session's (queued for `screend`), `false` to let the kernel's
/// own DRM device handle it.
fn hotkey_switch(to_session: bool) -> bool {
    if !policy::service_switch(STATE.load(Ordering::Acquire)) {
        return false;
    }
    REQUEST.store(if to_session { 2 } else { 1 }, Ordering::Release);
    REQUEST_WQ.wake_all();
    true
}

/// Whether the display service's session is hidden behind the console (Ctrl+Alt+F2 goes
/// back to it).
pub fn session_hidden() -> bool {
    STATE.load(Ordering::Acquire) == SCREEN_HIDDEN
}

/// The display service went away (`lx::server_gone`): the console takes the screen at once;
/// `screend` then ends the desktop session.
pub fn service_gone() {
    if SERVICE.load(Ordering::Acquire) {
        let st = apply(Event::Gone);
        crate::kprintln!("[screen] display service gone: the console has the screen (state {})", st);
        END_SESSION.store(true, Ordering::Release);
        REQUEST_WQ.wake_all();
    }
}

/// Most descriptors looked at per process when ending the session.
const SCAN_FDS: usize = 8192;

/// Decision 28: a crash of the display service ends the desktop session. Its compositor does
/// not end by itself when its `/dev/dri/card0` fails (kwin keeps running with no output), so
/// the programs that hold a descriptor of the dead instance are asked to end (`SIGTERM`):
/// the compositor exits, the session ends and SDDM shows the login screen again once the
/// restarted service serves. Root's programs are left alone (hydra-logind keeps the devices
/// it hands out); programs without a window keep running. KDE's `kwin_wayland_wrapper`
/// starts the compositor again when it dies (a bare desktop without its shell): when it is a
/// holder's parent it is asked to end first.
fn end_session() {
    // The dead instance's objects go stale right after the call that woke us
    crate::task::sleep_ms(200);
    let host = crate::lx::svc::host_of(crate::ipc::protocol::LXS_DISPLAY);
    let mut tables: alloc::vec::Vec<(u64, u32, crate::fs::SharedFdTable)> = alloc::vec::Vec::new();
    x86_64::instructions::interrupts::without_interrupts(|| {
        crate::task::SCHEDULER.lock().for_each_task_mut(|t| {
            if t.personality == crate::task::TaskPersonality::Linux && !tables.iter().any(|x| x.0 == t.tgid) {
                tables.push((t.tgid, t.euid, t.fds.clone()));
            }
        })
    });
    let mut ended = alloc::vec::Vec::new();
    for (tgid, euid, fds) in tables {
        if euid == 0 {
            continue;
        }
        let holds = {
            let f = fds.lock();
            (0..SCAN_FDS).any(|fd| match f.get(fd) {
                Some(crate::fs::FileDescriptor::Device(d)) => d.as_server().is_some_and(|o| o.svc() == host && o.kind() == crate::ipc::protocol::LX_OBJ_KIND_DRM && o.slot().is_none()),
                _ => false,
            })
        };
        if !holds {
            continue;
        }
        let parent = crate::compat::linux::proc::PROCS.lock().get(&tgid).map(|p| p.ppid);
        if let Some(ppid) = parent.filter(|&p| p > 1) {
            let comm = crate::compat::linux::fs::proc_pid_file_text(&alloc::format!("{}/comm", ppid)).unwrap_or_default();
            if comm.starts_with(b"kwin_wayland_wr") && crate::compat::linux::proc::post_process(ppid, 15) {
                ended.push(ppid);
            }
        }
        if crate::compat::linux::proc::post_process(tgid, 15) {
            ended.push(tgid);
        }
    }
    crate::kprintln!("[screen] display service gone: the desktop session ends (SIGTERM to {:?})", ended);
}

/// A kernel panic (`video::console::panic_reclaim`, before the console is copied back): no
/// lock is taken. The state word tells the service to stop; a copy it started before is
/// given a little time to end (it reads the state after raising its "copying" word).
fn panic_stop() {
    STATE.store(SCREEN_PANIC, Ordering::SeqCst);
    status_set(SCREEN_ST_STATE, SCREEN_PANIC);
    for _ in 0..20_000_000u32 {
        if status_get(SCREEN_ST_COPYING) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Whether the display service serves `/dev/dri/card0` this boot (it mapped the screen).
pub fn served() -> bool {
    SERVICE.load(Ordering::Acquire)
}

/// One line for the diagnostics (`service info` / the kernel log).
pub fn summary() -> alloc::string::String {
    alloc::format!(
        "[screen] state {} gen {} service {} takes {} switches {}",
        STATE.load(Ordering::Relaxed),
        GEN.load(Ordering::Relaxed),
        SERVICE.load(Ordering::Relaxed),
        TAKES.load(Ordering::Relaxed),
        SWITCHES.load(Ordering::Relaxed)
    )
}

/// Allocates the status and scratch pages (once; under [`INNER`]).
fn pages_init() -> Result<(), i64> {
    if STATUS_FRAME.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let status = crate::memory::frame_allocator::alloc_user_frame().ok_or(ENOMEM)?;
    let Some(sink) = crate::memory::frame_allocator::alloc_user_frame() else {
        crate::memory::frame_allocator::frame_ref_dec(status);
        return Err(ENOMEM);
    };
    let (s, k) = (status.start_address().as_u64(), sink.start_address().as_u64());
    STATUS_VIRT.store(crate::memory::frame_allocator::phys_to_virt(s) as u64, Ordering::Release);
    status_set(SCREEN_ST_STATE, STATE.load(Ordering::Acquire));
    status_set(SCREEN_ST_GEN, GEN.load(Ordering::Acquire) as u32);
    SINK_FRAME.store(k, Ordering::Release);
    STATUS_FRAME.store(s, Ordering::Release);
    Ok(())
}

/// [`SCREEN_MAP`]: maps the screen into the calling display service.
fn map() -> Result<u64, i64> {
    let (phys, bytes, ..) = fb().ok_or(ENXIO)?;
    let fb_pages = policy::fb_pages(bytes);
    let obj = OBJECT.lock().get_or_insert_with(|| Arc::new(ScreenObject { fb_phys: phys, fb_pages })).clone();
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().ok_or(EFAULT)?;
    let mut inner = INNER.lock();
    pages_init()?;
    // Mapped already by this instance: the same mapping (a second one would escape the zaps)
    if let Some((m, start, _)) = inner.mapping.as_ref() {
        if Arc::ptr_eq(m, &mm) {
            return Ok(*start);
        }
    }
    let obj: Arc<dyn MappedObject> = obj;
    let len = (fb_pages + 1) * PAGE_SIZE;
    let addr = {
        let mut m = mm.lock();
        let a = m.mmap(0, len, 3, true, false, false, Backing::Object { obj, pgoff: 0 })?;
        m.set_name(a, a + len, Some("[screen]"));
        a
    };
    inner.mapping = Some((mm, addr, addr + fb_pages * PAGE_SIZE));
    drop(inner);
    if !SERVICE.swap(true, Ordering::AcqRel) {
        crate::compat::linux::drm::set_screen_hooks(hotkey_switch, session_hidden);
        crate::video::console::set_panic_hook(panic_stop);
    }
    if !SCREEND.swap(true, Ordering::AcqRel) {
        crate::task::spawn("screend", screend_main, crate::task::TaskPriority::High);
    }
    crate::kprintln!("[screen] display service mapped the screen ({} pages at {:#x})", fb_pages, addr);
    Ok(addr)
}

/// [`SCREEN_INFO`].
fn info(buf: u64) -> i64 {
    let Some((_, bytes, w, h, stride, bgr)) = fb() else { return ENXIO };
    let mut i = ScreenInfo { width: w, height: h, stride, bgr: bgr as u32, fb_bytes: policy::fb_pages(bytes) * PAGE_SIZE, refresh_mhz: SCREEN_REFRESH_MHZ, ..Default::default() };
    i.state = STATE.load(Ordering::Acquire);
    i.gen = GEN.load(Ordering::Acquire);
    let slot = crate::compat::linux::devices::vga_slot();
    let n = slot.len().min(15);
    i.slot[..n].copy_from_slice(&slot.as_bytes()[..n]);
    // SAFETY: a plain `repr(C)` struct of integers
    let bytes = unsafe { core::slice::from_raw_parts(&i as *const ScreenInfo as *const u8, core::mem::size_of::<ScreenInfo>()) };
    match crate::compat::linux::vfs::copy_out(buf, bytes) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// [`SCREEN_WAIT`]: until the generation differs from `gen`, a kick, or `deadline_ns`.
fn wait(gen: u64, deadline_ns: u64) -> i64 {
    let cap = crate::arch::pit::now_ns() + 1_000_000_000;
    let deadline = if deadline_ns == 0 { cap } else { deadline_ns.min(cap) };
    loop {
        WAITQ.register();
        let g = GEN.load(Ordering::Acquire);
        if g != gen || KICKED.swap(false, Ordering::AcqRel) || crate::arch::pit::now_ns() >= deadline {
            WAITQ.unregister();
            return policy::wait_value(STATE.load(Ordering::Acquire), g);
        }
        crate::task::wait::wait_ns(Some(deadline));
    }
}

/// `SYS_SCREEN(op, a, b)` (native 73): the display service's screen operations.
pub fn sys_screen(op: u64, a: u64, b: u64) -> i64 {
    if crate::task::current_service() != Some(ENDPOINT_DISPLAY_DEV) {
        return EPERM;
    }
    // `lx.display=kernel` / `lx=kernel`: the kernel's `drm.rs` has the screen; the service
    // learns it from its first call and exits
    if crate::lx::svc::mode(crate::ipc::protocol::LXS_DISPLAY) != crate::lx::svc::SvcMode::Forward || crate::lx::all_kernel() {
        return ENODEV;
    }
    match op {
        SCREEN_INFO => info(a),
        SCREEN_MAP => map().map_or_else(|e| e, |x| x as i64),
        SCREEN_TAKE => {
            if fb().is_none() {
                return ENXIO;
            }
            // Only a service that mapped the screen (its hooks are in, its death is noticed)
            if !SERVICE.load(Ordering::Acquire) || INNER.lock().mapping.is_none() {
                return EINVAL;
            }
            TAKES.fetch_add(1, Ordering::Relaxed);
            match apply(Event::Take) {
                SCREEN_PANIC | SCREEN_CONSOLE => ENXIO,
                s => s as i64,
            }
        }
        SCREEN_GIVE => {
            apply(Event::Give);
            0
        }
        SCREEN_WAIT => wait(a, b),
        SCREEN_NOW => crate::arch::pit::now_ns() as i64,
        SCREEN_KICK => {
            KICKED.store(true, Ordering::Release);
            WAITQ.wake_all();
            0
        }
        _ => EINVAL,
    }
}
