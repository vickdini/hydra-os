//! # The desktop after an lx-ipc crash (wave 8, Group X2)
//!
//! lx-ipc is Transparent since wave 9 (Group X3: its buffers and tables are kept objects, a
//! restart takes them back and nothing here runs); a second crash within 30 s drops it to
//! FailObjects (`docs/linux-services-design.md` 2.3, 5.2): then every pipe and Unix socket
//! of the old instance fails. Console programs live on; the graphical session
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
/// The next process the kernel starts is the desktop's root ([`expect_root`]).
static ROOT_PENDING: AtomicBool = AtomicBool::new(false);
/// Pids added since the set was last trimmed of ended processes.
static ADDED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The login screen's launcher is about to be started: the next process started by the
/// kernel (not forked) is the desktop's root, marked before it can run and fork
/// ([`root_started`], from `proc::register_process`).
pub fn expect_root() {
    ROOT_PENDING.store(true, Ordering::Release);
}

/// The expected root was not started after all (the start failed).
pub fn cancel_root() {
    ROOT_PENDING.store(false, Ordering::Release);
}

/// Process `pid` was started by the kernel (not forked): the desktop's root if one is
/// expected.
pub fn root_started(pid: u64) {
    if ROOT_PENDING.swap(false, Ordering::AcqRel) {
        mark(pid);
    }
}

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
    // Now and then the ended ones go (the set would grow for the whole uptime)
    if ADDED.fetch_add(1, Ordering::Relaxed) % 1024 == 1023 {
        alive_members(|p| !crate::compat::linux::proc::has_exited(p));
    }
}

/// Whether `pid` is a desktop process.
pub fn is_desktop(pid: u64) -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().contains(&pid))
}

/// The desktop processes still alive (by `alive`), the set trimmed to them.
fn alive_members(alive: impl Fn(u64) -> bool) -> Vec<u64> {
    let all: Vec<u64> = x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().iter().copied().collect());
    let (live, dead): (Vec<u64>, Vec<u64>) = all.into_iter().partition(|&p| alive(p));
    // (only pids seen dead go: one added meanwhile stays)
    x86_64::instructions::interrupts::without_interrupts(|| PIDS.lock().retain(|p| !dead.contains(p)));
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
    if !super::svc::online(ipc) {
        // (the desktop is left as it is: without lx-ipc no login screen could replace it)
        crate::kprintln!("[lx] ipc did not come back; the desktop is not restarted");
        RECOVERING.store(false, Ordering::Release);
        crate::task::exit();
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
    crate::admin::linux::plasma("/ubuntu", false);
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
        // The root expected before it runs: marked at its start, its children follow
        expect_root();
        root_started(50);
        root_started(51); // (the next kernel start is not the root)
        inherit(50, 52);
        assert!(is_desktop(50) && is_desktop(52) && !is_desktop(51));
    }
}
