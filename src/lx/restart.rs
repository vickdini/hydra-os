//! # Restart support for every Linux service (wave 6, Group 21: "R3")
//!
//! What happens when a Linux service (linux-server today; vfs-server, lx-net, lx-ipc,
//! lx-sec, ... as they split out) dies, and how its new instance takes over
//! (`docs/linux-services-design.md`, section 5). One mechanism for every service:
//!
//! - **Restart classes** ([`RestartClass`], design 5.2), per service:
//!   - *Transparent*: callers wait for the new instance (at most 30 s, interruptible);
//!     calls that were queued or answered "pending" are sent again, calls being served are
//!     sent again only if they are marked idempotent ([`restart_policy::idempotent`]),
//!     the others fail with `EIO`. Objects the new instance adopts keep working.
//!   - *FailObjects*: calls in flight fail with `EIO`, the old instance's objects fail with
//!     a per-kind error ([`restart_policy::stale_errno`]); new calls wait for the new
//!     instance; programs live.
//!   - *EndLinux*: the user's decision 6, today's crash policy (every Linux program ends,
//!     the login screen returns): linux-server keeps it while it hosts unkept state.
//! - **The ladder** ([`restart_policy::Ladder`]): a second crash within 30 s of a restart
//!   drops one class and resets the kept state; a third stops restarting the service.
//! - **Kept state** (`LX_SVC_KEPT`): memory a service keeps across its own restarts, owned
//!   here (not by the process); the service checks it (version, checksums: hydra-rt's
//!   `kept` module) before it uses it. The ladder drops it.
//! - **Revalidation** (`LX_SVC_LIST`, `LX_SVC_DEAD`, `LX_SVC_ADOPT`): the new instance of a
//!   Transparent service gets the `(slot, kind, key)` of every live object of the old one,
//!   rebinds each or marks it dead, and adopts the rest before it goes online. A service
//!   that never adopts gets FailObjects for its objects (the safe default).
//!
//! The decisions themselves are in [`restart_policy`] (host-tested); this module keeps the
//! per-service state, makes callers wait, and serves the service's primitives. The
//! supervisor (`task::supervisor`) configures each service's class and asks whether to
//! restart; `lx::server_gone` asks how to treat the calls and objects in flight.
//!
//! ## Concurrency
//!
//! The state is one spin lock taken with interrupts off, never across a wait; the
//! "restarting" flags are atomics read on the call path without the lock. A caller waiting
//! for a restarting service holds the kernel lock (taken here if the lock-free path came
//! without it): restarts are rare, so this path is never hot.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

pub use super::restart_policy::{RestartClass, LX_RESEND, LX_RESEND_MAYBE};
use super::restart_policy::{self, Decision, Ladder, WAIT_MS};
use crate::ipc::protocol::{LxSvcObj, LX_SVC_ADOPT, LX_SVC_DEAD, LX_SVC_INFO, LX_SVC_KEPT, LX_SVC_LIST};
use crate::task::wait::WaitQueue;

const EPERM: i64 = -1;
const EIO: i64 = -5;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;

/// Service ids (Group 19's `SvcId`, `LXS_*`): 0 is the kernel, 1..16 the services.
pub const MAX_SVC: usize = 16;
/// linux-server's id (`LXS_LINUX`).
pub const SVC_LINUX: u8 = 1;
/// Most pages of a kept-state object (2 MiB: lx-sec's keyrings take about 1 MiB; bulk data
/// goes in Group 23's kept memory objects). Physically contiguous until Group 23's memory
/// objects replace the frames.
pub const KEPT_MAX_PAGES: u64 = 512;

/// Where a service is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Serving (or never started).
    Up,
    /// Dead, a new instance is coming; callers wait (Transparent and FailObjects only).
    Restarting,
    /// Given up by the ladder or the supervisor: calls fail with `EIO`.
    Down,
}

/// One service's restart state.
struct Svc {
    ladder: Ladder,
    /// Set by a boot word: the supervisor's configuration does not change it.
    pinned: bool,
    phase: Phase,
    /// How the last crash was handled.
    last: Option<Decision>,
    /// When the last crash was handled (ms since boot): callers wait until 30 s after it.
    since_ms: u64,
    /// The next going-away is a deliberate restart (`service restart`), not a crash.
    deliberate: bool,
    /// The new instance adopted the old instance's live objects (`LX_SVC_ADOPT`).
    adopted: bool,
    /// The service has a kept-state object (Group 23's kept memory object index 0,
    /// `lx::mem`), and whether the current instance got it new (zeroed).
    kept: bool,
    kept_new: bool,
}

impl Svc {
    const NEW: Self = Self {
        // (a service the supervisor did not configure: FailObjects, as Group 19's default)
        ladder: Ladder::new(RestartClass::FailObjects),
        pinned: false,
        phase: Phase::Up,
        last: None,
        since_ms: 0,
        deliberate: false,
        adopted: false,
        kept: false,
        kept_new: false,
    };
}

static STATE: Mutex<[Svc; MAX_SVC]> = Mutex::new([const { Svc::NEW }; MAX_SVC]);

fn state<R>(f: impl FnOnce(&mut [Svc; MAX_SVC]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut STATE.lock()))
}

/// Per service: callers should wait for it (its phase is [`Phase::Restarting`]). Read on
/// the call path without the lock.
static RESTARTING: [AtomicBool; MAX_SVC] = [const { AtomicBool::new(false) }; MAX_SVC];
/// Per service: given up (calls fail with `EIO`).
static DOWN: [AtomicBool; MAX_SVC] = [const { AtomicBool::new(false) }; MAX_SVC];
/// Per service: the callers waiting for it to be online again.
static ONLINE_WQ: [WaitQueue; MAX_SVC] = [const { WaitQueue::new() }; MAX_SVC];

/// Calls sent again to a restarted service since boot.
pub static RESENT: AtomicU64 = AtomicU64::new(0);
/// Calls that waited for a restarting service since boot.
pub static WAITED: AtomicU64 = AtomicU64::new(0);
/// Calls failed with `EIO` because their service died while serving them (not idempotent),
/// or did not come back in time.
pub static FAILED: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    crate::arch::pit::now_ns() / 1_000_000
}

fn idx(svc: u8) -> usize {
    (svc as usize).min(MAX_SVC - 1)
}

// ----------------------------------------------------------------------
// Configuration (the supervisor, boot words)
// ----------------------------------------------------------------------

/// The supervisor gives service `svc` its class (at start). A boot word
/// (`lx.<name>.restart=...`, [`boot_word`]) given earlier wins.
pub fn configure(svc: u8, class: RestartClass) {
    state(|s| {
        let v = &mut s[idx(svc)];
        if !v.pinned {
            v.ladder = Ladder::new(class);
        }
    });
}

/// QEMU's fw_cfg `opt/hydra/restart.<name>` or a boot option word `lx.<name>.restart=<class>`
/// sets service `svc`'s class (the user's policy, design 5.2: EndLinux "available to the user
/// as a policy for any service"; for tests, Transparent for linux-server).
pub fn boot_word(svc: u8, class: RestartClass) {
    state(|s| {
        let v = &mut s[idx(svc)];
        v.ladder = Ladder::new(class);
        v.pinned = true;
    });
    crate::kprintln!("[lx] restart class of service {}: {} (set at boot)", svc, class.name());
}

/// Reads the fw_cfg file `opt/hydra/restart.<name>` (`transparent`, `failobjects` or
/// `endlinux`) for service `svc`, if QEMU has one.
pub fn fw_cfg(svc: u8, name: &str) {
    let mut cfg = [0u8; 16];
    let file = alloc::format!("opt/hydra/restart.{}", name);
    if let Some(n) = crate::arch::fwcfg::read_file_into(&file, &mut cfg) {
        let v = cfg[..n].trim_ascii();
        match RestartClass::parse(v) {
            Some(c) => boot_word(svc, c),
            None => crate::kprintln!("[lx] {}: unknown restart class", file),
        }
    }
}

/// Service `svc`'s class now (the configured one, lowered by the ladder after a crash loop).
pub fn class(svc: u8) -> RestartClass {
    state(|s| s[idx(svc)].ladder.current)
}

/// The next going-away of `svc` is a deliberate restart (`service restart`): not counted by
/// the ladder.
pub fn deliberate(svc: u8) {
    state(|s| {
        let v = &mut s[idx(svc)];
        v.deliberate = true;
        if v.phase == Phase::Down {
            v.phase = Phase::Up;
        }
    });
    // (a service the ladder gave up may be restarted by hand)
    DOWN[idx(svc)].store(false, Ordering::Release);
}

/// `service start` of a service (one the ladder gave up, or stopped): a fresh ladder, and
/// its callers wait for the new instance from now on (its old objects stay stale).
pub fn started_by_hand(svc: u8) {
    let i = idx(svc);
    let now = now_ms();
    let waiting = state(|s| {
        let v = &mut s[i];
        v.ladder.reset();
        if v.phase != Phase::Down {
            return false;
        }
        v.phase = Phase::Restarting;
        v.since_ms = now;
        v.last = Some(Decision { class: RestartClass::FailObjects, reset_kept: false, restart: true });
        true
    });
    DOWN[i].store(false, Ordering::Release);
    if waiting {
        RESTARTING[i].store(true, Ordering::Release);
    }
}

// ----------------------------------------------------------------------
// The service died / came back
// ----------------------------------------------------------------------

/// Service `svc` went away (called first by `lx::server_gone`): decides how this going-away
/// is handled (the ladder), and from now on callers wait for the new instance (Transparent
/// and FailObjects) or fail (the ladder gave up).
pub fn gone(svc: u8) -> Decision {
    let i = idx(svc);
    let now = now_ms();
    let d = state(|s| {
        let v = &mut s[i];
        let d = if core::mem::take(&mut v.deliberate) { v.ladder.deliberate(now) } else { v.ladder.crash(now) };
        if d.restart {
            v.ladder.restarted(now);
        }
        if d.reset_kept {
            // The kept state is suspect: the next instance gets a zeroed one (the object
            // itself is dropped below, outside this lock)
            v.kept = false;
        }
        v.adopted = false;
        v.last = Some(d);
        v.since_ms = now;
        v.phase = match (d.restart, d.class) {
            (false, _) => Phase::Down,
            (true, RestartClass::EndLinux) => Phase::Up,
            (true, _) => Phase::Restarting,
        };
        d
    });
    if d.reset_kept {
        super::mem::drop_kept(svc);
    }
    RESTARTING[i].store(d.restart && d.class != RestartClass::EndLinux, Ordering::Release);
    DOWN[i].store(!d.restart, Ordering::Release);
    crate::kprintln!(
        "[lx] service {} went away: handled as {}{}{}",
        svc,
        d.class.name(),
        if d.reset_kept { ", kept state reset (second crash within 30 s)" } else { "" },
        if d.restart { "" } else { "; not restarted again (third crash within 30 s): its calls fail with EIO" }
    );
    // Callers already waiting see the new phase
    ONLINE_WQ[i].wake_all();
    d
}

/// Whether the supervisor should start a new instance of `svc` (the ladder did not give up).
pub fn may_restart(svc: u8) -> bool {
    !DOWN[idx(svc)].load(Ordering::Acquire)
}

/// Whether `svc`'s new instance adopted the old instance's objects (a Transparent restart
/// and `LX_SVC_ADOPT`): asked at `LX_CTL_ONLINE`, before [`online`]. If not, the caller
/// makes the old objects stale.
pub fn adopting(svc: u8) -> bool {
    state(|s| {
        let v = &s[idx(svc)];
        v.adopted && v.phase == Phase::Restarting && v.last.is_some_and(|d| d.class == RestartClass::Transparent)
    })
}

/// Service `svc`'s new instance is online (`LX_CTL_ONLINE`, after the server's online flag
/// is set): waiting callers go on.
pub fn online(svc: u8) {
    let i = idx(svc);
    state(|s| {
        let v = &mut s[i];
        v.phase = Phase::Up;
        v.adopted = false;
        // (a deliberate restart whose going-away was not seen: not left for the next crash)
        v.deliberate = false;
    });
    RESTARTING[i].store(false, Ordering::Release);
    DOWN[i].store(false, Ordering::Release);
    ONLINE_WQ[i].wake_all();
}

/// Whether callers of `svc` should wait for it rather than fail (it is restarting).
#[inline]
pub fn restarting(svc: u8) -> bool {
    RESTARTING[idx(svc)].load(Ordering::Acquire)
}

/// Whether `svc` is being restarted Transparently: its objects stay (not stale) meanwhile.
pub fn keeps_objects(svc: u8) -> bool {
    restarting(svc) && state(|s| s[idx(svc)].last.is_some_and(|d| d.class == RestartClass::Transparent))
}

/// Whether `svc` was given up: its calls fail with `EIO`.
#[inline]
pub fn down(svc: u8) -> bool {
    DOWN[idx(svc)].load(Ordering::Acquire)
}

/// Waits until `svc` is online again (`is_online`), for a caller of a restarting service
/// (design 5.1, point 2): at most 30 s after the crash, then `EIO`; a signal ends the wait
/// with `ERESTARTSYS` (the call starts again for an `SA_RESTART` handler, `EINTR`
/// otherwise). Takes the kernel lock if the caller came without it (the lock-free path's
/// exit gives it back).
pub fn wait_online(svc: u8, is_online: &dyn Fn() -> bool) -> Result<(), i64> {
    let i = idx(svc);
    if is_online() {
        return Ok(());
    }
    if !restarting(svc) {
        return Err(EIO);
    }
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
    }
    WAITED.fetch_add(1, Ordering::Relaxed);
    let since = state(|s| s[i].since_ms);
    let freq = crate::arch::pit::frequency_hz().max(1);
    loop {
        ONLINE_WQ[i].register();
        if is_online() {
            ONLINE_WQ[i].unregister();
            return Ok(());
        }
        if !restarting(svc) {
            ONLINE_WQ[i].unregister();
            FAILED.fetch_add(1, Ordering::Relaxed);
            return Err(EIO);
        }
        let now = now_ms();
        if now >= since + WAIT_MS {
            ONLINE_WQ[i].unregister();
            FAILED.fetch_add(1, Ordering::Relaxed);
            crate::kprintln!("[lx] service {} did not come back within 30 s: a call fails with EIO", svc);
            return Err(EIO);
        }
        if crate::compat::linux::proc::signal_pending() {
            ONLINE_WQ[i].unregister();
            return Err(crate::compat::linux::proc::ERESTARTSYS);
        }
        // Woken when the service is online (or gives up); a look every 100 ms besides
        let wait_ms = (since + WAIT_MS - now).min(100);
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + (wait_ms * freq).div_ceil(1000).max(1)));
    }
}

/// A forwarded call of `svc` (number `nr`, arguments `args`; [`install_mark`] taken when the
/// call began) got `r` from a dead Transparent instance ([`LX_RESEND`], [`LX_RESEND_MAYBE`]):
/// `Ok(())` once it may be sent again (the service is back), or the error to return.
pub fn resend(svc: u8, r: i64, nr: u64, args: &[u64; 6], mark: u64, is_online: &dyn Fn() -> bool) -> Result<(), i64> {
    // Descriptors the dead instance installed for this call (its answer was lost): the
    // program never learned their numbers; the new instance installs its own
    close_installed(mark);
    // wave7 GB: an add_key being served when lx-sec died (its answer lost) is sent again
    // unless it makes a keyring: the new instance finds the key the old one committed and
    // updates it in place (same serial); only a keyring would be made anew
    let r = if r == restart_policy::LX_RESEND_MAYBE && nr == restart_policy::NR_ADD_KEY && add_key_is_update(args[0]) { restart_policy::LX_RESEND } else { r };
    if let Err(e) = restart_policy::after_crash(r, nr, args) {
        FAILED.fetch_add(1, Ordering::Relaxed);
        return Err(e);
    }
    wait_online(svc, is_online)?;
    RESENT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

// wave7 GB begin
/// Whether an `add_key` whose type string is at user address `ty` (the caller's memory)
/// updates a key of that type and description in place when it exists: every type but
/// `keyring` ([`restart_policy::add_key_resendable`]).
fn add_key_is_update(ty: u64) -> bool {
    let mut b = [0u8; 16];
    matches!(super::copy::read_user_str(ty, &mut b), Ok(Some(n)) if restart_policy::add_key_resendable(&b[..n]))
}
// wave7 GB end

// ----------------------------------------------------------------------
// Descriptors installed for a call whose answer was lost
// ----------------------------------------------------------------------

/// `(install number + 1, caller thread, descriptor)` of recent installs, for
/// [`close_installed`] (a ring: only installs of the last moments before a crash matter).
static INSTALLS: Mutex<[(u64, u64, i32); 64]> = Mutex::new([(0, 0, -1); 64]);
/// Installs since boot.
static INSTALL_NEXT: AtomicU64 = AtomicU64::new(0);

/// The install count now: taken when a forwarded call begins; installs for its caller from
/// then on belong to that call (a thread makes one call at a time).
#[inline]
pub fn install_mark() -> u64 {
    INSTALL_NEXT.load(Ordering::Relaxed)
}

/// `LX_OBJ_INSTALL` put descriptor `fd` in the table of thread `client` (a request's caller).
pub fn installed(client: u64, fd: i32) {
    let n = INSTALL_NEXT.fetch_add(1, Ordering::Relaxed);
    x86_64::instructions::interrupts::without_interrupts(|| INSTALLS.lock()[n as usize % 64] = (n + 1, client, fd));
}

/// Closes the descriptors installed for the calling thread since install count `mark`.
fn close_installed(mark: u64) {
    let me = crate::task::CURRENT_TID.load(Ordering::Acquire);
    let mut fds = [-1i32; 8];
    let mut n = 0;
    x86_64::instructions::interrupts::without_interrupts(|| {
        for e in INSTALLS.lock().iter_mut() {
            if e.0 > mark && e.1 == me && e.2 >= 0 && n < fds.len() {
                fds[n] = e.2;
                n += 1;
                *e = (0, 0, -1);
            }
        }
    });
    if n == 0 {
        return;
    }
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
    }
    for &fd in &fds[..n] {
        let _ = crate::task::with_current_fds_mut(|t| t.close(fd as usize));
    }
    crate::kprintln!("[lx] closed {} descriptor(s) installed for a call lost in a restart", n);
}

// ----------------------------------------------------------------------
// The service's primitives (`SYS_LX_SVC` ops 16..23)
// ----------------------------------------------------------------------

/// `SYS_LX_SVC` ops 16..23 for the calling service `svc` (found by the caller from its
/// registered endpoint).
pub fn svc_op(svc: u8, op: u64, a: u64, b: u64, c: u64) -> i64 {
    let Some(x) = super::svc::host(svc) else { return EPERM };
    if svc == 0 || svc as usize >= MAX_SVC {
        return EPERM;
    }
    match op {
        LX_SVC_KEPT => kept(svc, a),
        LX_SVC_LIST => list(x, a, b, c),
        LX_SVC_DEAD => {
            if a as usize >= crate::ipc::protocol::LX_OBJ_SLOTS {
                return EINVAL;
            }
            super::obj::mark_dead(x, a as usize);
            0
        }
        LX_SVC_ADOPT => {
            if restarting(svc) && keeps_objects(svc) {
                state(|s| s[idx(svc)].adopted = true);
                0
            } else {
                // Nothing to adopt (a first start, or not a Transparent restart)
                EINVAL
            }
        }
        LX_SVC_INFO => state(|s| {
            let v = &s[idx(svc)];
            (v.ladder.configured as i64) | (v.ladder.current as i64) << 4 | ((v.ladder.crashes.min(0xFFFF)) as i64) << 8 | (v.kept_new as i64) << 24
        }),
        _ => EINVAL,
    }
}

/// [`LX_SVC_KEPT`]: maps service `svc`'s kept-state object of `size` bytes into the caller.
fn kept(svc: u8, size: u64) -> i64 {
    let pages = size.div_ceil(4096);
    if pages == 0 || pages > KEPT_MAX_PAGES {
        return EINVAL;
    }
    // Group 23's kept memory object index 0 of this service (made zeroed the first time)
    let (obj, new) = match super::mem::kept_get_or_create(svc, 0, pages * 4096) {
        Ok(k) => k,
        Err(e) => return e,
    };
    // A different size is a different layout: the service must reset it itself
    if obj.pages() != pages {
        return EBUSY;
    }
    state(|s| {
        let v = &mut s[idx(svc)];
        v.kept = true;
        v.kept_new = new;
    });
    match super::mem::map_current(obj, 0, pages * 4096, 3, None) {
        Ok(addr) => addr as i64,
        Err(e) => e,
    }
}

/// [`LX_SVC_LIST`]: the live objects of service `svc` from slot `start` on, written to the
/// caller's `buf` (`cap` entries).
fn list(x: &super::svc::Host, buf: u64, cap: u64, start: u64) -> i64 {
    let cap = cap.min(crate::ipc::protocol::LX_OBJ_SLOTS as u64) as usize;
    if cap == 0 {
        return 0;
    }
    let mut out: alloc::vec::Vec<LxSvcObj> = alloc::vec::Vec::with_capacity(cap);
    super::obj::list_live(x, start as usize, cap, &mut out);
    let n = out.len();
    // SAFETY: LxSvcObj is plain integers; the slice covers exactly the n entries
    let bytes = unsafe { core::slice::from_raw_parts(out.as_ptr() as *const u8, n * core::mem::size_of::<LxSvcObj>()) };
    match crate::compat::linux::vfs::copy_out(buf, bytes) {
        Ok(()) => n as i64,
        Err(_) => EFAULT,
    }
}

/// One line per service with restart state, for `linux prof show` and the task dump.
pub fn summary() -> alloc::string::String {
    let mut out = alloc::format!(
        "restarts: {} calls waited, {} sent again, {} failed;",
        WAITED.load(Ordering::Relaxed),
        RESENT.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed)
    );
    state(|s| {
        for (i, v) in s.iter().enumerate() {
            if v.ladder.crashes == 0 && !v.pinned && !v.kept {
                continue;
            }
            out.push_str(&alloc::format!(
                " svc {}: {} (now {}), {} crashes, {:?}{};",
                i,
                v.ladder.configured.name(),
                v.ladder.current.name(),
                v.ladder.crashes,
                v.phase,
                if v.kept { ", kept state" } else { "" }
            ));
        }
    });
    out
}

// Host tests (test wave, Group 30): tests/host-t30 compiles this file with them
#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_restart.rs"]
pub(crate) mod tests;
