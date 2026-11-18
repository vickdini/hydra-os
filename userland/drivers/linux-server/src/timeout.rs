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

/// Whether deadline `d` has passed.
pub fn passed(d: Option<u64>) -> bool {
    d.is_some_and(|d| sys::uptime_ticks() >= d)
}

/// A timed wait was queued: the main thread looks at its deadlines again.
pub fn kick() {
    let _ = sys::lx_ctl(LX_CTL_WAKE);
}
