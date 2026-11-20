//! Tests of `src/ipc/service.rs`: requests by id, hand-off and queued calls, the direct
//! path, grants, notifications and doorbells, windows, device access, interrupts.

use super::*;

/// Every request, grant, window holder, interrupt line and service back to boot state
/// (windows, once allocated, are kept: as in the kernel).
pub(crate) fn reset() {
    *REQUESTS.lock() = [Request::FREE; MAX_REQUESTS];
    for i in 0..MAX_REQUESTS {
        QUEUED_CALLER[i].store(0, Ordering::Release);
        QUEUED_OWNER[i].store(0, Ordering::Release);
        REQ_ANSWERED[i].store(false, Ordering::Release);
    }
    for s in SERVICES.iter() {
        s.server.store(0, Ordering::Release);
        s.grants.lock().clear();
        s.irq_notify.store(core::ptr::null_mut(), Ordering::Release);
        s.clients.lock().clear();
        s.notify.store(0, Ordering::Release);
        s.irq_forward.store(0, Ordering::Release);
        s.signal_hook.store(0, Ordering::Release);
        s.parked.store(0, Ordering::Release);
        s.parked_idx.store(0, Ordering::Release);
    }
    WINDOW_HOLDERS.lock().clear();
    WINDOWS_HELD.store(0, Ordering::Release);
    *GRANTS.lock() = [Grant::FREE; MAX_GRANTS];
    GRANTS_MADE.store(0, Ordering::Release);
    for i in 0..IRQ_LINES {
        IRQ_OWNER[i].store(0, Ordering::Release);
        IRQ_PENDING[i].store(0, Ordering::Release);
        IRQ_COUNT[i].store(0, Ordering::Release);
        IRQ_NOTIFIED[i].store(0, Ordering::Release);
        IRQ_SERVICE[i].store(0, Ordering::Release);
    }
    for d in MSI_DEVICE.iter() {
        d.store(0, Ordering::Release);
    }
    DIRECT_ON.store(true, Ordering::Release);
    for c in [&DIRECT_SWITCHED, &DIRECT_WOKEN, &DIRECT_BACK, &DIRECT_SPUN] {
        c.store(0, Ordering::Release);
    }
}

/// Notification bits raised for `endpoint`'s server and not taken yet.
pub(crate) fn pending_bits(endpoint: u32) -> u64 {
    service(endpoint).map_or(0, |s| slot_owner(s).notify.load(Ordering::Acquire))
}
