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
