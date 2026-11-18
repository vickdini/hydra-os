//! Timeouts of blocked calls: deadlines in the kernel's 100 Hz ticks. The main thread
//! wakes at the earliest one ([`crate::next_deadline`]) and answers the calls whose time
//! has come; a worker that queues a timed wait wakes it ([`kick`]).

use hydra_rt::protocol::LX_CTL_WAKE;
use hydra_rt::sys;

use crate::client::Cx;

const EINVAL: i64 = -22;
/// Ticks per second.
const HZ: u128 = 100;

/// Reads a `struct timespec` at `ptr` of the caller: `(seconds, nanoseconds)`, checked.
fn timespec(cx: &Cx, ptr: u64) -> Result<(i64, i64), i64> {
    let raw = cx.copy_in(ptr, 16)?;
    let s = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    let ns = i64::from_le_bytes(raw[8..16].try_into().unwrap());
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    Ok((s, ns))
}

/// The tick deadline of an absolute `CLOCK_REALTIME` timeout at `ptr` (0: none).
pub fn absolute(cx: &Cx, ptr: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let (s, ns) = timespec(cx, ptr)?;
    let (rs, rns) = sys::clock();
    let left = (s as i128 * 1_000_000_000 + ns as i128) - (rs as i128 * 1_000_000_000 + rns as i128);
    let ticks = if left > 0 { ((left as u128 * HZ).div_ceil(1_000_000_000)) as u64 } else { 0 };
    Ok(Some(sys::uptime_ticks() + ticks))
}

/// The tick deadline of a relative timeout at `ptr` (0: none).
#[allow(dead_code)]
pub fn relative(cx: &Cx, ptr: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let (s, ns) = timespec(cx, ptr)?;
    let ticks = ((s as u128 * 1_000_000_000 + ns as u128) * HZ).div_ceil(1_000_000_000) as u64;
    Ok(Some(sys::uptime_ticks() + ticks))
}

/// The real-time clock without a system call: `(TSC, nanoseconds since 1970)` as the main
/// thread last read them (it does at least once a second), and the TSC's rate (nanoseconds
/// per 2^32 cycles) from its last two readings.
static CLOCK: crate::lock::YLock<(u64, u64, u64)> = crate::lock::YLock::new((0, 0, 0));

fn rdtsc() -> u64 {
    // SAFETY: rdtsc only reads the time-stamp counter
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Takes a new reading of the real-time clock (the main thread, every time it wakes).
pub fn update_clock() {
    let (s, ns) = sys::clock();
    let now = s * 1_000_000_000 + ns as u64;
    let tsc = rdtsc();
    let mut c = CLOCK.lock();
    let (t0, n0, _) = *c;
    let rate = if t0 != 0 && tsc > t0 + 1_000_000 && now > n0 { (((now - n0) as u128) << 32) / (tsc - t0) as u128 } else { c.2 as u128 };
    *c = (tsc, now, rate as u64);
}

/// Seconds since 1970 (`sem_otime`, `msg_stime`): the last reading moved on by the TSC; a
/// clock call until two readings were taken.
pub fn now_secs() -> u64 {
    let (t0, n0, rate) = *CLOCK.lock();
    if rate == 0 {
        return sys::clock().0;
    }
    let ns = n0 + ((rdtsc().saturating_sub(t0) as u128 * rate as u128) >> 32) as u64;
    ns / 1_000_000_000
}

/// Whether deadline `d` has passed.
pub fn passed(d: Option<u64>) -> bool {
    d.is_some_and(|d| sys::uptime_ticks() >= d)
}

/// A timed wait was queued: the main thread looks at its deadlines again.
pub fn kick() {
    let _ = sys::lx_ctl(LX_CTL_WAKE);
}
