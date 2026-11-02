//! # CMOS Real-Time Clock
//!
//! Reads the battery-backed MC146818 RTC once at boot to establish the wall-clock time,
//! then advances it with the PIT tick counter. Provides Unix-epoch timestamps for the
//! filesystem and `CLOCK_REALTIME`.

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::port::Port;

/// Unix time (seconds) at PIT tick 0, derived from the RTC reading at boot.
static BOOT_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Reads a single byte from a specified CMOS register index.
///
/// Disables NMI (Non-Maskable Interrupts) by setting bit 7 of the index port `0x70`,
/// writes the target register index, and reads the resulting value from data port `0x71`.
///
/// # Arguments
///
/// * `reg` - CMOS register index (0x00..0x7F) to inspect.
///
/// # Returns
///
/// The 8-bit value stored in the requested CMOS register.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn cmos_read(reg: u8) -> u8 {
    let mut index: Port<u8> = Port::new(0x70);
    let mut data: Port<u8> = Port::new(0x71);
    unsafe {
        index.write(reg | 0x80); // keep NMI disabled while selecting
        data.read()
    }
}

/// Checks whether an internal RTC time update cycle is currently in progress.
///
/// Inspects bit 7 of Status Register A (0x0A). When this bit is set, the RTC is
/// updating its internal registers and reads may produce inconsistent or corrupted values.
///
/// # Returns
///
/// `true` if an update is underway; `false` if safe to read time registers.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn update_in_progress() -> bool {
    cmos_read(0x0A) & 0x80 != 0
}

/// Reads raw CMOS time registers after ensuring no update cycle is occurring.
///
/// # Returns
///
/// A 7-byte array containing `[seconds, minutes, hours, day, month, year, century]`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn read_raw() -> [u8; 7] {
    while update_in_progress() {}
    [cmos_read(0x00), cmos_read(0x02), cmos_read(0x04), cmos_read(0x07), cmos_read(0x08), cmos_read(0x09), cmos_read(0x32)]
}

/// Computes the number of days from the Unix epoch (1970-01-01) to a given civil date.
///
/// Implements the proleptic Gregorian calendar algorithm.
///
/// # Arguments
///
/// * `y` - Year (e.g., 2026).
/// * `m` - Month (1..=12).
/// * `d` - Day of month (1..=31).
///
/// # Returns
///
/// Number of elapsed days since January 1, 1970 (can be negative for dates prior to 1970).
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Reads the battery-backed RTC and initializes the monotonic system boot epoch.
///
/// Must be invoked once during bootstrap after the PIT timer is active. Samples the
/// RTC repeatedly until two consecutive reads agree to prevent rollover race conditions,
/// converts BCD/binary values to civil time, and stores the Unix epoch baseline.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn init() {
    // Read until two consecutive samples agree, so we never catch a rollover mid-read
    let mut a = read_raw();
    loop {
        let b = read_raw();
        if a == b {
            break;
        }
        a = b;
    }
    let status_b = cmos_read(0x0B);
    let bcd = status_b & 0x04 == 0;
    let conv = |v: u8| -> i64 {
        if bcd {
            ((v & 0x0F) + (v >> 4) * 10) as i64
        } else {
            v as i64
        }
    };
    let sec = conv(a[0]);
    let min = conv(a[1]);
    let mut hour = conv(a[2] & 0x7F);
    if status_b & 0x02 == 0 && a[2] & 0x80 != 0 {
        hour = (hour % 12) + 12; // 12-hour mode, PM
    }
    let day = conv(a[3]);
    let month = conv(a[4]);
    let century = if a[6] != 0 { conv(a[6]) } else { 20 };
    let year = century * 100 + conv(a[5]);

    let unix = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    let elapsed = crate::arch::pit::ticks() / 100;
    BOOT_EPOCH.store((unix.max(0) as u64).saturating_sub(elapsed), Ordering::SeqCst);
}

/// Returns the current wall-clock time as (seconds, nanoseconds) since the Unix epoch.
///
/// Computes real-time clock values by adding elapsed PIT timer ticks to the initial
/// boot epoch captured by `init()`.
///
/// # Returns
///
/// A tuple `(secs, nanos)` where `secs` is seconds since 1970-01-01T00:00:00Z and
/// `nanos` is sub-second nanoseconds within the current second.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn now() -> (u64, u32) {
    let ticks = crate::arch::pit::ticks();
    let freq = crate::arch::pit::frequency_hz().max(1);
    let secs = BOOT_EPOCH.load(Ordering::Relaxed) + ticks / freq;
    let nanos = ((ticks % freq) * 1_000_000_000 / freq) as u32;
    (secs, nanos)
}
