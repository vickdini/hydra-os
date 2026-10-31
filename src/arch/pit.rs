//! # Architecture Layer: 8254 Programmable Interval Timer (PIT)
//!
//! Provides hardware periodic timer interrupt generation, tick accounting, uptime metrics,
//! and low-power CPU sleep primitives for Hydra OS.
//!
//! ## Architectural Role & Design Rationale
//!
//! The 8254 PIT oscillates at an architectural base frequency of 1.193182 MHz. By programming
//! Channel 0 in Mode 3 (square-wave generator) with an appropriate 16-bit divisor, the timer
//! fires IRQ 0 (IDT vector 32) at 100 Hz (every 10 ms). This periodic interrupt drives the
//! preemptive scheduler's round-robin timeslice accounting and enables non-spinning thread sleeping.
//!
//! ## Key Types & Interfaces
//!
//! - `init`: Programs PIT Channel 0 divisor registers for the specified frequency in Hz.
//! - `ticks`: Returns the atomic monotonic counter of elapsed timer interrupts.
//! - `uptime_ms` / `uptime_seconds`: Converts raw ticks into human-readable wall clock uptime.
//! - `sleep_ms` / `sleep_ticks`: Halts the CPU via `HLT` until the required time elapses.
//! - `on_timer_tick`: Increments the tick counter from the IRQ 0 ISR.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 kernel execution.
//! - I/O Ports: Channel 0 Data `0x40`, Mode/Command Register `0x43`.
//! - Concurrency: Lock-free atomic synchronization (`AtomicU64`, `AtomicBool`).

use core::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use x86_64::instructions::port::Port;

const PIT_BASE_FREQUENCY_HZ: u32 = 1_193_182;
const PIT_CHANNEL_0_DATA: u16 = 0x40;
const PIT_COMMAND_PORT: u16 = 0x43;

// Square Wave Mode 3, Channel 0, lobyte/hibyte, 16-bit binary
const PIT_CMD_CHANNEL0_SQUARE_WAVE: u8 = 0x36;

static TICKS: AtomicU64 = AtomicU64::new(0);
static TIMER_ACTIVE: AtomicBool = AtomicBool::new(false);
static FREQUENCY: AtomicU64 = AtomicU64::new(100);

/// Initializes the 8254 Programmable Interval Timer (PIT) on Channel 0.
/// Configures square wave generator (Mode 3) at the requested frequency in Hz.
pub fn init(frequency_hz: u32) {
    let freq = frequency_hz.max(18).min(PIT_BASE_FREQUENCY_HZ);
    let divisor = (PIT_BASE_FREQUENCY_HZ + freq / 2) / freq;
    let divisor = divisor.clamp(1, 65535) as u16;

    unsafe {
        Port::<u8>::new(PIT_COMMAND_PORT).write(PIT_CMD_CHANNEL0_SQUARE_WAVE);
        Port::<u8>::new(PIT_CHANNEL_0_DATA).write((divisor & 0xFF) as u8);
        Port::<u8>::new(PIT_CHANNEL_0_DATA).write(((divisor >> 8) & 0xFF) as u8);
    }

    FREQUENCY.store(freq as u64, Ordering::SeqCst);
    TIMER_ACTIVE.store(true, Ordering::SeqCst);
}

/// Called exclusively by the IRQ 0 (Vector 32) interrupt service routine.
pub fn on_timer_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Returns whether the PIT hardware timer has been activated.
pub fn is_active() -> bool {
    TIMER_ACTIVE.load(Ordering::Relaxed)
}

/// Returns the configured timer frequency in Hz.
pub fn frequency_hz() -> u64 {
    FREQUENCY.load(Ordering::Relaxed)
}

/// Returns the total number of hardware timer ticks since initialization.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Returns system uptime in milliseconds based on timer ticks.
pub fn uptime_ms() -> u64 {
    let t = ticks();
    let freq = frequency_hz();
    if freq == 0 {
        return 0;
    }
    (t.saturating_mul(1000)) / freq
}

/// Returns system uptime in seconds based on timer ticks.
pub fn uptime_seconds() -> u64 {
    let t = ticks();
    let freq = frequency_hz();
    if freq == 0 {
        return 0;
    }
    t / freq
}

/// Blocks execution for a specified number of timer ticks using low-power CPU halts.
pub fn sleep_ticks(count: u64) {
    if count == 0 {
        return;
    }
    let target = ticks().saturating_add(count);
    while ticks() < target {
        if x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Blocks execution for the specified duration in milliseconds.
/// If interrupts are enabled, halts the CPU between timer ticks.
/// If interrupts are disabled, falls back to RDTSC cycle spinning.
pub fn sleep_ms(ms: u64) {
    if ms == 0 {
        return;
    }

    if is_active() && x86_64::instructions::interrupts::are_enabled() {
        let freq = frequency_hz();
        let ticks_to_sleep = (ms.saturating_mul(freq) + 999) / 1000;
        sleep_ticks(ticks_to_sleep.max(1));
    } else {
        // Fallback to RDTSC spin-loop if PIT interrupts are not active
        let nanos = (ms as u128) * 1_000_000;
        let cycles = (nanos as u64).saturating_mul(2);
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < cycles {
            core::hint::spin_loop();
        }
    }
}
