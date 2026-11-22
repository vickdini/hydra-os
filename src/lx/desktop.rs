//! # The desktop after an lx-ipc crash (wave 8, Group X2)
//!
//! lx-ipc is FailObjects (`docs/linux-services-design.md` 2.3): when it dies, every pipe and
//! Unix socket of the old instance fails. Console programs live on; the graphical session
//! does not, because it lives on D-Bus and Wayland sockets, and neither does the login
//! screen's daemon (its own sockets died with them), so the user decision 12 says: the
//! session ends and the login screen returns.
//!
//! The kernel knows which processes belong to the desktop: the login screen's launcher
//! (`admin::linux::plasma` marks it, [`mark`]) and every process forked from one of them,
//! daemons included ([`inherit`], from `proc::register_process`). Programs started from the
//! console are not in the set. When lx-ipc's process goes away under FailObjects
//! ([`ipc_gone`]), a kernel task waits for the new instance, ends every desktop process
//! (`SIGKILL`), waits for them to go and starts the login screen again.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// The desktop's processes (pids; ended ones are dropped when found).
static PIDS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// A recovery runs.
static RECOVERING: AtomicBool = AtomicBool::new(false);

/// Process `pid` is the login screen's launcher (the root of the desktop).
pub fn mark(pid: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        PIDS.lock().insert(pid);
    });
}

/// Process `child` was forked from `parent`: a desktop process's child is one too.
pub fn inherit(parent: u64, child: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut p = PIDS.lock();
        if p.contains(&parent) {
            p.insert(child);
        }
    });
}

/// Whether `pid` is a desktop process.
pub fn is_desktop(pid: u64) -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().contains(&pid))
}

/// The desktop processes still alive (by `alive`), the set trimmed to them.
fn alive_members(alive: impl Fn(u64) -> bool) -> Vec<u64> {
    let all: Vec<u64> = x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().iter().copied().collect());
    let live: Vec<u64> = all.into_iter().filter(|&p| alive(p)).collect();
    x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().retain(|p| live.contains(p)));
    live
}

/// lx-ipc's process went away and its objects failed (not a Transparent restart): if the
/// login screen was started, the desktop is ended and the login screen started again once
/// the new instance is online. `true` if a recovery was started.
pub fn ipc_gone() -> bool {
    if !crate::admin::linux::display_manager_started() || RECOVERING.swap(true, Ordering::AcqRel) {
        return false;
    }
    crate::task::spawn("lx-desktop", recover_task, crate::task::TaskPriority::Normal);
    true
}

fn recover_task() {
    let ipc = crate::ipc::protocol::LXS_IPC;
    // The supervisor restarts lx-ipc within about a second
    let deadline = crate::arch::pit::ticks() + 60 * crate::arch::pit::frequency_hz().max(1);
    while !super::svc::online(ipc) && crate::arch::pit::ticks() < deadline {
        crate::task::sleep_ms(100);
    }
    let live = alive_members(|p| !crate::compat::linux::proc::has_exited(p));
    for &p in &live {
        crate::compat::linux::proc::post_process(p, 9);
    }
    crate::kprintln!("[lx] ipc restarted: ending the desktop ({} processes) and starting the login screen again", live.len());
    // They go within a few seconds (at most 10)
    let until = crate::arch::pit::ticks() + 10 * crate::arch::pit::frequency_hz().max(1);
    while crate::arch::pit::ticks() < until && !alive_members(|p| !crate::compat::linux::proc::has_exited(p)).is_empty() {
        crate::task::sleep_ms(100);
    }
    crate::task::close_retired();
    x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().clear());
    if super::svc::online(ipc) {
        crate::admin::linux::plasma("/ubuntu", false);
    } else {
        crate::kprintln!("[lx] ipc did not come back; the login screen is not started again");
    }
    RECOVERING.store(false, Ordering::Release);
    crate::task::exit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn children_of_the_desktop_are_the_desktop() {
        PIDS.lock().clear();
        mark(10);
        inherit(10, 11);
        inherit(11, 12);
        inherit(99, 100); // a console program's child
        assert!(is_desktop(12) && !is_desktop(100));
        let live = alive_members(|p| p != 11);
        assert_eq!(live, alloc::vec![10, 12]);
        assert!(!is_desktop(11));
    }
}
