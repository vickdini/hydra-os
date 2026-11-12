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

/// Timer interrupts so far (they measure the time stamp counter's rate).
static TICKS: AtomicU64 = AtomicU64::new(0);
/// The clock's anchor, read consistently: `(nanoseconds since boot, their 32-bit fraction,
/// time stamp counter value there, nanoseconds per cycle in 32.32 fixed point (0: not
/// measured yet))`. The vDSO computes [`now_ns`] from it in user mode.
pub fn clock_state() -> (u64, u64, u64, u64) {
    loop {
        let s = CLOCK_SEQ.load(Ordering::Acquire);
        if s & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let v = (BASE_NS.load(Ordering::Relaxed), BASE_FRAC.load(Ordering::Relaxed), BASE_TSC.load(Ordering::Relaxed), MULT.load(Ordering::Relaxed));
        if CLOCK_SEQ.load(Ordering::Acquire) == s {
            return v;
        }
    }
}

/// Nanoseconds per tick.
pub fn tick_ns() -> u64 {
    1_000_000_000 / frequency_hz().max(1)
}
static TIMER_ACTIVE: AtomicBool = AtomicBool::new(false);
static FREQUENCY: AtomicU64 = AtomicU64::new(100);

/// Initializes the 8254 Programmable Interval Timer (PIT) on Channel 0.
///
/// Configures Channel 0 in Mode 3 (square-wave generator) at the requested frequency in Hz.
/// Calculates the nearest 16-bit divisor of the architectural base oscillator frequency
/// (1,193,182 Hz) and writes the low and high bytes to I/O port `0x40`.
///
/// # Arguments
///
/// * `frequency_hz` - Desired periodic interrupt frequency in Hertz (clamped between 18 Hz and 1,193,182 Hz; standard is 100 Hz).
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
    // The time stamp counter's rate, measured now rather than from the ticks (which a
    // virtual machine may deliver late or merge: the clock would run slow)
    let mult = calibrate_tsc();
    if mult != 0 {
        let seq = CLOCK_SEQ.load(Ordering::Relaxed);
        CLOCK_SEQ.store(seq | 1, Ordering::Release);
        core::sync::atomic::fence(Ordering::SeqCst);
        BASE_TSC.store(unsafe { core::arch::x86_64::_rdtsc() }, Ordering::Relaxed);
        MULT.store(mult, Ordering::Relaxed);
        CALIBRATED.store(true, Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::SeqCst);
        CLOCK_SEQ.store((seq | 1) + 1, Ordering::Release);
    }
    TIMER_ACTIVE.store(true, Ordering::SeqCst);
}

/// The time stamp counter's rate was measured by [`calibrate_tsc`] (the ticks then do not
/// change it).
static CALIBRATED: AtomicBool = AtomicBool::new(false);

/// Measures the time stamp counter against the PIT's channel 2, polled (no interrupts, so
/// none can be lost): the cycles of a 50 ms countdown, as Linux calibrates it.
///
/// # Returns
/// Nanoseconds per cycle, 32.32 fixed point; 0 if the countdown never ended.
fn calibrate_tsc() -> u64 {
    // 50 ms of the PIT's 1.193182 MHz input
    let latch: u32 = PIT_BASE_FREQUENCY_HZ / 20;
    let mut gate = Port::<u8>::new(0x61);
    let (t0, t1, done) = unsafe {
        let saved = gate.read();
        // Channel 2's gate on, the speaker off
        gate.write((saved & !0x02) | 0x01);
        // Channel 2, low then high byte, mode 0 (interrupt on terminal count: OUT rises at 0)
        Port::<u8>::new(PIT_COMMAND_PORT).write(0xB0);
        Port::<u8>::new(0x42).write(latch as u8);
        Port::<u8>::new(0x42).write((latch >> 8) as u8);
        let t0 = core::arch::x86_64::_rdtsc();
        let mut spins = 0u64;
        let mut done = true;
        while gate.read() & 0x20 == 0 {
            spins += 1;
            if spins > 50_000_000 {
                done = false;
                break;
            }
        }
        let t1 = core::arch::x86_64::_rdtsc();
        gate.write(saved);
        (t0, t1, done)
    };
    if !done || t1 <= t0 {
        return 0;
    }
    let ns = latch as u128 * 1_000_000_000 / PIT_BASE_FREQUENCY_HZ as u128;
    ((ns << 32) / (t1 - t0) as u128) as u64
}

/// Increments the monotonic tick counter.
///
/// Invoked exclusively by the IRQ 0 (IDT vector 32) interrupt service routine.
/// Uses atomic relaxed ordering to ensure minimal latency in the interrupt handler.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn on_timer_tick() {
    // The time stamp counter at this tick, and the long-run cycles per tick (all cycles
    // since the first tick over the ticks since: bursts of late ticks do not skew it)
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let first = FIRST_TICK_TSC.load(Ordering::Relaxed);
    let ticks = TICKS.load(Ordering::Relaxed) + 1;
    TICKS.store(ticks, Ordering::Relaxed);
    let mut cpt = 0;
    if first == 0 {
        FIRST_TICK_TSC.store(now, Ordering::Relaxed);
        FIRST_TICK.store(ticks, Ordering::Relaxed);
    } else {
        let n = ticks - FIRST_TICK.load(Ordering::Relaxed);
        if n >= 10 && now > first {
            cpt = (now - first) / n;
        }
    }
    // The clock goes on from its anchor along the time stamp counter (a late tick does not
    // hold it back); until the counter's rate is known, it counts ticks
    let period = tick_ns();
    let seq = CLOCK_SEQ.load(Ordering::Relaxed);
    CLOCK_SEQ.store(seq | 1, Ordering::Release);
    core::sync::atomic::fence(Ordering::SeqCst);
    let mult = MULT.load(Ordering::Relaxed);
    if mult == 0 {
        BASE_NS.store(ticks * period, Ordering::Relaxed);
        BASE_FRAC.store(0, Ordering::Relaxed);
    } else {
        let delta = now.saturating_sub(BASE_TSC.load(Ordering::Relaxed));
        let total = delta as u128 * mult as u128 + BASE_FRAC.load(Ordering::Relaxed) as u128;
        BASE_NS.fetch_add((total >> 32) as u64, Ordering::Relaxed);
        BASE_FRAC.store(total as u32 as u64, Ordering::Relaxed);
    }
    BASE_TSC.store(now, Ordering::Relaxed);
    if cpt != 0 && !CALIBRATED.load(Ordering::Relaxed) {
        // Nanoseconds per cycle, as a 32.32 fixed-point number: the new rate counts from here
        MULT.store((((period as u128) << 32) / cpt as u128) as u64, Ordering::Relaxed);
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    CLOCK_SEQ.store((seq | 1) + 1, Ordering::Release);
    // The vDSO's copy of the clock
    crate::arch::vdso::publish();
}

/// The clock's anchor: nanoseconds since boot (`BASE_NS` and a 32-bit fraction
/// `BASE_FRAC`) at time stamp counter value `BASE_TSC`, and the nanoseconds per cycle
/// (`MULT`, 32.32 fixed point; 0 until measured), consistent while `CLOCK_SEQ` is even and
/// unchanged.
static CLOCK_SEQ: AtomicU64 = AtomicU64::new(0);
static BASE_NS: AtomicU64 = AtomicU64::new(0);
static BASE_FRAC: AtomicU64 = AtomicU64::new(0);
static BASE_TSC: AtomicU64 = AtomicU64::new(0);
static MULT: AtomicU64 = AtomicU64::new(0);

/// Time stamp counter value at the last tick.
/// Time stamp counter and tick count at the first tick seen.
static FIRST_TICK_TSC: AtomicU64 = AtomicU64::new(0);
static FIRST_TICK: AtomicU64 = AtomicU64::new(0);
/// Measured time stamp counter cycles per tick (0 for the first ten ticks).

/// Nanoseconds since boot, with sub-tick resolution: the time stamp counter's progress
/// since the clock's anchor (moved on at every tick, along the same line, so it never goes
/// backwards). Ticks are derived from it ([`ticks`]), so timeouts in ticks and this clock
/// agree; the vDSO computes it the same way in user mode.
pub fn now_ns() -> u64 {
    let (base, frac, base_tsc, mult) = clock_state();
    if mult == 0 {
        return base;
    }
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let total = tsc.saturating_sub(base_tsc) as u128 * mult as u128 + frac as u128;
    base + (total >> 32) as u64
}

/// Checks whether the PIT hardware timer has been activated.
///
/// # Returns
///
/// `true` if `init()` has successfully programmed Channel 0; `false` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn is_active() -> bool {
    TIMER_ACTIVE.load(Ordering::Relaxed)
}

/// Returns the configured timer frequency in Hertz.
///
/// # Returns
///
/// The frequency in Hz programmed into Channel 0 (typically 100 Hz).
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn frequency_hz() -> u64 {
    FREQUENCY.load(Ordering::Relaxed)
}

/// Returns the total number of hardware timer ticks elapsed since initialization.
///
/// # Returns
///
/// Monotonic count of 10 ms timer ticks accumulated by IRQ 0.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn ticks() -> u64 {
    // From the clock: timeouts in ticks and CLOCK_MONOTONIC never disagree
    now_ns() / tick_ns()
}

/// Computes the system uptime in milliseconds based on elapsed timer ticks.
///
/// # Returns
///
/// System uptime expressed in milliseconds. Returns `0` if the timer frequency is unset.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn uptime_ms() -> u64 {
    let t = ticks();
    let freq = frequency_hz();
    if freq == 0 {
        return 0;
    }
    (t.saturating_mul(1000)) / freq
}

/// Computes the system uptime in seconds based on elapsed timer ticks.
///
/// # Returns
///
/// System uptime expressed in whole seconds. Returns `0` if the timer frequency is unset.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn uptime_seconds() -> u64 {
    let t = ticks();
    let freq = frequency_hz();
    if freq == 0 {
        return 0;
    }
    t / freq
}

/// Blocks execution for a specified number of timer ticks using low-power CPU halts.
///
/// When interrupts are enabled, halts the processor (`HLT`) until the next hardware interrupt
/// arrives, reducing power dissipation. If interrupts are disabled, performs a hint spin loop.
///
/// # Arguments
///
/// * `count` - Number of timer ticks (10 ms increments at 100 Hz) to wait.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn sleep_ticks(count: u64) {
    if count == 0 {
        return;
    }
    let target = ticks().saturating_add(count);
    // At a preemption point (no locks held) the kernel lock is let go while halted: other
    // CPUs run kernel code meanwhile (the console shell waits for keys this way)
    let release = crate::task::is_active() && crate::task::PREEMPT_POINTS.load(core::sync::atomic::Ordering::Relaxed) > 0;
    while ticks() < target {
        if x86_64::instructions::interrupts::are_enabled() {
            if release {
                crate::arch::smp::bkl_exit();
            }
            x86_64::instructions::hlt();
            if release {
                crate::arch::smp::bkl_enter_idle();
            }
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Blocks execution for the specified duration in milliseconds.
///
/// If PIT interrupts are enabled and active, computes the required tick count and halts
/// the processor via `sleep_ticks()`. If interrupts are disabled, falls back to RDTSC
/// cycle spinning.
///
/// # Arguments
///
/// * `ms` - Duration in milliseconds to pause execution.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
