//! # The raw input ring (wave 8, Group I)
//!
//! Keyboard and pointer input reaches Linux programs through the input service
//! (`userland/drivers/input-server`, endpoint [`ENDPOINT_INPUT_SERVER`]), which serves
//! `/dev/input/event*`. The interrupt paths stay in the kernel (`arch/keyboard.rs`,
//! `arch/mouse.rs`, `arch/usb_input.rs`): they append **raw records** (a scancode byte, a
//! pointer report) to a ring in kernel memory and raise a notification
//! ([`NOTIFY_INPUT`]); the service maps the ring (a memory object, `SYS_LX_OBJ`
//! [`LX_OBJ_INPUT_RING`]), translates the records into Linux events and hands them to its
//! open files (`docs/display-input-design.md`, sections 3.2 and 5).
//!
//! - **The ring** ([`INPUT_RING_BYTES`]): a header page (`head`, written here; `tail`,
//!   written by the consumer; `drops`) and a page of [`InputRec`]s. It belongs to the
//!   kernel, so it outlives a crash of the service: what is typed while the service
//!   restarts waits in it for the new instance.
//! - **One consumer:** the service when input is forwarded ([`forwarded`]); the kernel's own
//!   copy (`compat/linux/evdev.rs`, `lx=kernel` / `lx.input=kernel`) otherwise. Both read
//!   the same ring through `ipc/input_ring.rs`.
//! - **Routing** ([`set_routing`]): records are appended only while a desktop session shows
//!   on the screen; the console keeps the keyboard otherwise. The kernel decides it from the
//!   screen's owner (the display side calls it); turning it off appends a
//!   [`INPUT_REC_RELEASE`] record, so the session sees every held key go up.
//! - **Hot keys** stay in `arch/keyboard.rs`; the screen switch they ask for goes through
//!   [`hotkey_switch`] / [`session_hidden`].
//!
//! Producers run with interrupts off (interrupt handlers, the USB input task); the
//! producer lock is a spin lock taken only there. Nothing here allocates after [`init`].

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::input_ring::RingView;
use crate::ipc::protocol::{
    InputRec, ENDPOINT_INPUT_SERVER, INPUT_REC_ABS, INPUT_REC_KEY, INPUT_REC_REL, INPUT_REC_RELEASE, INPUT_RING_BYTES, LXS_INPUT, LX_OBJ_INPUT_CTL, LX_OBJ_INPUT_RING, NOTIFY_INPUT,
};
use crate::task::wait::WaitQueue;

const EPERM: i64 = -1;
const ENOMEM: i64 = -12;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;

/// Woken whenever a record is appended (the kernel's own evdev copy waits here).
pub static INPUT_WQ: WaitQueue = WaitQueue::new();

/// Input goes to the session (true) or stays with the console (false).
static ROUTING: AtomicBool = AtomicBool::new(false);
/// Kernel (direct-map) address of the ring (0: not set up yet).
static RING: AtomicU64 = AtomicU64::new(0);
/// The ring as a memory object (handed to the service).
static RING_OBJ: Mutex<Option<Arc<crate::memory::vm::MemObject>>> = Mutex::new(None);
/// Serializes producers (taken with interrupts off).
static PRODUCER: Mutex<()> = Mutex::new(());

/// Sets the ring up (once, at boot, before the input interrupts are enabled).
pub fn init() {
    if RING.load(Ordering::Acquire) != 0 {
        return;
    }
    let pages = (INPUT_RING_BYTES / 4096) as u64;
    let Some(frames) = crate::ipc::service::ContiguousFrames::allocate(pages) else {
        crate::kprintln!("[input] no memory for the input ring");
        return;
    };
    let base = frames.base;
    // The frames stay the kernel's for good (the object does not own them)
    core::mem::forget(frames);
    let va = crate::memory::frame_allocator::phys_to_virt(base) as u64;
    // SAFETY: fresh zeroed frames reached through the direct map, never freed
    unsafe { RingView::new(va as *mut u8) }.format();
    *RING_OBJ.lock() = Some(crate::lx::mem::frames(base, pages));
    RING.store(va, Ordering::Release);
}

/// The ring (`None` before [`init`]).
#[inline]
fn ring() -> Option<RingView> {
    let va = RING.load(Ordering::Acquire);
    // SAFETY: set by `init` to the direct-map address of the ring's frames, never freed
    (va != 0).then(|| unsafe { RingView::new(va as *mut u8) })
}

/// Whether input is forwarded to the input service (not `lx=kernel` / `lx.input=kernel`).
#[inline]
pub fn forwarded() -> bool {
    !crate::lx::all_kernel() && crate::lx::svc::mode(LXS_INPUT) == crate::lx::svc::SvcMode::Forward
}

/// Sends the keyboard and pointer to the desktop session (`true`) or back to the console
/// (`false`). Turning it off queues a "release every held key" record.
pub fn set_routing(on: bool) {
    let was = ROUTING.swap(on, Ordering::AcqRel);
    if was && !on {
        x86_64::instructions::interrupts::without_interrupts(|| append(InputRec { kind: INPUT_REC_RELEASE, ..InputRec::default() }));
    }
}

/// True while input goes to the session.
#[inline]
pub fn routing() -> bool {
    ROUTING.load(Ordering::Acquire)
}

/// Appends `r` (stamped now) and wakes the consumer. With interrupts off.
fn append(mut r: InputRec) {
    let Some(ring) = ring() else { return };
    r.time = crate::arch::pit::now_ns();
    let ok = {
        let _g = PRODUCER.lock();
        ring.push(r)
    };
    if !ok {
        return;
    }
    INPUT_WQ.wake_all();
    if forwarded() {
        crate::ipc::service::notify(ENDPOINT_INPUT_SERVER, NOTIFY_INPUT);
    }
}

/// Appends `r` if input is routed to the session.
fn push(r: InputRec) {
    if routing() {
        append(r);
    }
}

/// Keyboard: one set-1 scancode byte (`0xE0` prefixes included). With interrupts off.
pub fn push_scancode(code: u8) {
    push(InputRec { kind: INPUT_REC_KEY, code, ..InputRec::default() });
}

/// A relative pointer report: `dx` right, `dy` down, `wheel` positive away from the user,
/// buttons bit 0 left, 1 right, 2 middle. With interrupts off.
pub fn push_mouse(dx: i32, dy: i32, wheel: i32, buttons: u8) {
    let clamp = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16 as u16;
    push(InputRec { kind: INPUT_REC_REL, x: clamp(dx), y: clamp(dy), wheel: wheel.clamp(-127, 127) as i8, buttons, ..InputRec::default() });
}

/// An absolute pointer report: position 0..=0xFFFF on both axes. With interrupts off.
pub fn push_abs(x: u16, y: u16, wheel: i8, buttons: u8) {
    push(InputRec { kind: INPUT_REC_ABS, x, y, wheel, buttons, ..InputRec::default() });
}

/// Whether records wait in the ring.
pub fn pending() -> bool {
    ring().is_some_and(|r| r.pending())
}

/// Takes every waiting record, oldest first (the kernel's own consumer, `evdev.rs`; never
/// while the input service consumes). Returns how many were taken.
pub fn drain(f: impl FnMut(InputRec)) -> usize {
    ring().map_or(0, |r| r.take(f))
}

/// `(appended, taken, dropped)` so far.
pub fn counters() -> (u64, u64, u64) {
    ring().map_or((0, 0, 0), |r| r.counters())
}

/// `SYS_LX_OBJ` operations [`LX_OBJ_INPUT_RING`] and [`LX_OBJ_INPUT_CTL`] of host `h`.
pub fn obj_op(h: crate::ipc::protocol::SvcId, op: u64, a: u64, _b: u64, _c: u64) -> i64 {
    if crate::lx::svc::host_of(LXS_INPUT) != h {
        return EPERM;
    }
    match op {
        LX_OBJ_INPUT_RING => {
            let Some(ep) = crate::task::current_service() else { return EPERM };
            let Some(obj) = RING_OBJ.lock().clone() else { return ENODEV };
            match crate::lx::mem::give(ep, obj) {
                Ok(handle) => handle as i64,
                Err(_) => ENOMEM,
            }
        }
        // `a` = 0: whether input is forwarded to the service (1) or served by the kernel (0)
        LX_OBJ_INPUT_CTL if a == 0 => forwarded() as i64,
        LX_OBJ_INPUT_CTL => EINVAL,
        _ => EINVAL,
    }
}

/// How long an `open` of `/dev/input/event*` waits for a restarting input service (ms).
const OPEN_WAIT_MS: u64 = 5_000;

/// `open` of a character device of major 13 while input is forwarded: the input service's
/// (waiting up to [`OPEN_WAIT_MS`] for one that is restarting), never the kernel copy's.
pub fn open(rdev: u64, flags: u32) -> Result<Arc<dyn crate::compat::linux::chardev::CharDevice>, i64> {
    let deadline = crate::arch::pit::ticks() + OPEN_WAIT_MS / 10;
    loop {
        if let Some(r) = crate::lx::dev_open(rdev, flags) {
            return r;
        }
        if crate::arch::pit::ticks() >= deadline || crate::compat::linux::proc::signal_pending() {
            return Err(ENODEV);
        }
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + 5));
    }
}

/// A status line (`service list` / the boot log).
pub fn summary() -> alloc::string::String {
    let (h, t, d) = counters();
    alloc::format!("input ring: {} appended, {} taken, {} dropped, routing {}, {}", h, t, d, routing(), if forwarded() { "input-server" } else { "kernel evdev" })
}

// The hot keys' screen switch (`drm::request_vt_switch` goes to Group D's `screen.rs`)
/// Ctrl+Alt+F1 (`to_session` false: show the console) or Ctrl+Alt+F2 (`true`: back to the
/// hidden desktop session). Called from the keyboard interrupt.
pub fn hotkey_switch(to_session: bool) {
    crate::compat::linux::drm::request_vt_switch(to_session);
}

/// Whether a desktop session is hidden behind the console (Ctrl+Alt+F2 may show it).
pub fn session_hidden() -> bool {
    crate::compat::linux::drm::session_hidden()
}
