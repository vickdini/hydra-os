//! Tests of `src/lx/obj.rs`: server objects (install, adopt, stale, close notes),
//! `SYS_LX_OBJ`, descriptor passing, `sig_post` / `sig_take`.

use super::*;

/// Host `x` back to no objects and no area.
pub(crate) fn reset_objs(x: &Host) {
    x.objs.gen.store(0, Ordering::Release);
    x.objs.area.store(0, Ordering::Release);
    x.objs.reg.lock().clear();
    x.objs.pins.lock().clear();
    x.objs.kept.lock().clear();
}

/// The later-write queue back to empty.
pub(crate) fn reset() {
    LATER.lock().clear();
    LATER_TASK.store(false, Ordering::Release);
}

/// A kernel device that is no server object.
pub(crate) struct Plain;

impl CharDevice for Plain {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::from("plain")
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
}

/// Host `x` without objects and without its object area (made again on next use).
pub(crate) fn drop_area(x: &Host) {
    reset_objs(x);
    *x.objs.frames.lock() = None;
}
