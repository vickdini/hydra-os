// *stub* (wave8 GI) `src/ipc/input.rs` on the host: the same raw input ring (the real
// `ipc/input_ring.rs`) in host memory, routing with the release record, and the kernel
// copy as the only consumer (`forwarded()` is false), so `evdev.rs`, `keyboard.rs` and
// `mouse.rs` run unchanged.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::input_ring::RingView;
use super::protocol::{InputRec, INPUT_REC_ABS, INPUT_REC_KEY, INPUT_REC_REL, INPUT_REC_RELEASE, INPUT_RING_BYTES};
use crate::task::wait::WaitQueue;

/// Woken whenever a record is appended.
pub static INPUT_WQ: WaitQueue = WaitQueue::new();
static ROUTING: AtomicBool = AtomicBool::new(false);
static RING: AtomicUsize = AtomicUsize::new(0);
static PRODUCER: spin::Mutex<()> = spin::Mutex::new(());
/// Hot-key switches asked for (`(to_session, count)` for the tests).
pub static SWITCHES: spin::Mutex<Vec<bool>> = spin::Mutex::new(Vec::new());
/// What `session_hidden` answers.
pub static HIDDEN: AtomicBool = AtomicBool::new(false);

fn ring() -> RingView {
    let mut a = RING.load(Ordering::Acquire);
    if a == 0 {
        let mem: &'static mut [u64] = Box::leak(vec![0u64; INPUT_RING_BYTES / 8].into_boxed_slice());
        let p = mem.as_mut_ptr() as usize;
        // SAFETY: leaked, aligned, INPUT_RING_BYTES long
        unsafe { RingView::new(p as *mut u8) }.format();
        a = match RING.compare_exchange(0, p, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => p,
            Err(other) => other,
        };
    }
    // SAFETY: as above
    unsafe { RingView::new(a as *mut u8) }
}

pub fn forwarded() -> bool {
    false
}

pub fn set_routing(on: bool) {
    let was = ROUTING.swap(on, Ordering::AcqRel);
    if was && !on {
        append(InputRec { kind: INPUT_REC_RELEASE, ..InputRec::default() });
    }
}

pub fn routing() -> bool {
    ROUTING.load(Ordering::Acquire)
}

fn append(mut r: InputRec) {
    r.time = crate::arch::pit::now_ns();
    let ok = {
        let _g = PRODUCER.lock();
        ring().push(r)
    };
    if ok {
        INPUT_WQ.wake_all();
    }
}

fn push(r: InputRec) {
    if routing() {
        append(r);
    }
}

pub fn push_scancode(code: u8) {
    push(InputRec { kind: INPUT_REC_KEY, code, ..InputRec::default() });
}

pub fn push_mouse(dx: i32, dy: i32, wheel: i32, buttons: u8) {
    let clamp = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16 as u16;
    push(InputRec { kind: INPUT_REC_REL, x: clamp(dx), y: clamp(dy), wheel: wheel.clamp(-127, 127) as i8, buttons, ..InputRec::default() });
}

pub fn push_abs(x: u16, y: u16, wheel: i8, buttons: u8) {
    push(InputRec { kind: INPUT_REC_ABS, x, y, wheel, buttons, ..InputRec::default() });
}

pub fn pending() -> bool {
    ring().pending()
}

pub fn drain(f: impl FnMut(InputRec)) -> usize {
    ring().take(f)
}

pub fn counters() -> (u64, u64, u64) {
    ring().counters()
}

pub fn hotkey_switch(to_session: bool) {
    SWITCHES.lock().push(to_session);
}

pub fn session_hidden() -> bool {
    HIDDEN.load(Ordering::Relaxed)
}

/// `mouse::init` sets the ring up.
pub fn init() {}
