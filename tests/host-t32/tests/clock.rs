//! Time: `arch/pit.rs` (PIT programming, TSC calibration, the clock), `arch/rtc.rs` (CMOS
//! wall clock), `arch/boottime.rs`, and `arch/random.rs` (ChaCha20 generator).
//!
//! The clock is global, as in the kernel: every test here holds [`serial`]. The fake time
//! stamp counter (`host::TSC`) moves on by `host::TSC_STEP` cycles at every read.

use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::{boottime, pit, random, rtc};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

/// A PIT whose channel 2 output rises after `reads` reads of port 0x61.
fn pit_ports(reads: u32) {
    let mut n = 0;
    hw::set_port_handler(move |op| {
        if op.port == 0x61 && op.write.is_none() {
            n += 1;
            return if n > reads { 0x20 } else { 0x00 };
        }
        0
    });
}

/// A calibrated clock (1000 cycles = 50 ms: 50 us per cycle), the counter then moving by
/// `step` cycles per read (0: frozen).
fn clock(step: u64) {
    pit_ports(0);
    host::TSC_STEP.store(1000, SeqCst);
    pit::init(100);
    host::TSC_STEP.store(step, SeqCst);
    hw::clear_ports();
}

#[test]
fn init_programs_channel_0_and_calibrates() {
    let _g = serial();
    pit_ports(3);
    host::TSC_STEP.store(1000, SeqCst);
    pit::init(100);
    let w = hw::port_writes();
    // Channel 0, square wave, divisor 11932 (1193182 / 100, rounded)
    assert_eq!(&w[0..3], &[(0x43, 0x36), (0x40, (11932 & 0xFF) as u32), (0x40, (11932 >> 8) as u32)]);
    // Channel 2 for 50 ms: gate on, speaker off, mode 0, latch 59659
    assert_eq!(w[3], (0x61, 0x01));
    assert_eq!(&w[4..7], &[(0x43, 0xB0), (0x42, 59659 & 0xFF), (0x42, 59659 >> 8)]);
    assert_eq!(w[7], (0x61, 0x00), "gate restored");
    assert!(pit::is_active());
    assert_eq!(pit::frequency_hz(), 100);
    assert_eq!(pit::tick_ns(), 10_000_000);
    // The counter moved 5 reads (t0, four reads of 0x61 in between do not read it: 1 step)
    let (_, _, base_tsc, mult) = pit::clock_state();
    let ns = 59659u128 * 1_000_000_000 / 1_193_182;
    assert_eq!(mult, ((ns << 32) / 1000) as u64, "50 ms over 1000 cycles");
    assert!(base_tsc != 0);
    // From now on the clock follows the counter: 1000 cycles = 50 ms
    let a = pit::now_ns();
    let b = pit::now_ns();
    assert_eq!(b - a, ns as u64);
}

#[test]
fn frequency_is_clamped() {
    let _g = serial();
    pit_ports(0);
    pit::init(1); // below 19 Hz: 18 Hz's divisor (66288) would not fit 16 bits
    assert_eq!(pit::frequency_hz(), 19);
    let w = hw::port_writes();
    let div = w[1].1 | (w[2].1 << 8);
    // 19 Hz: divisor 62799 (19.0001 Hz): the reported rate is the programmed one (the old
    // 18 Hz floor programmed 65535 = 18.2 Hz and reported 18)
    assert_eq!(div, 62799);
    pit::init(18);
    assert_eq!(pit::frequency_hz(), 19);
    // The rate kept is the divisor's, rounded: 1000 Hz = divisor 1193 = 1000.15 Hz
    pit::init(1000);
    assert_eq!(pit::frequency_hz(), 1000);
    pit::init(400_000); // divisor 3 = 397,727 Hz
    assert_eq!(pit::frequency_hz(), 397_727);
    pit::init(5_000_000);
    assert_eq!(pit::frequency_hz(), 1_193_182);
    let w = hw::port_writes();
    let i = w.iter().rposition(|&(p, v)| p == 0x43 && v == 0x36).unwrap();
    assert_eq!((w[i + 1].1, w[i + 2].1), (1, 0), "divisor 1");
    pit::init(100);
}

#[test]
fn ticks_advance_the_clock() {
    let _g = serial();
    clock(0); // a frozen counter: only ticks move time
    let (ns0, ..) = pit::clock_state();
    let t0 = pit::now_ns();
    host::TSC.fetch_add(200, SeqCst);
    pit::on_timer_tick();
    let (ns1, _, tsc1, mult) = pit::clock_state();
    assert_eq!(tsc1, host::TSC.load(SeqCst));
    // The tick moved the base along the counter: 200 cycles at `mult`
    assert!(ns1 > ns0);
    assert_eq!(pit::now_ns(), ns1, "no cycles since the tick");
    assert!(pit::now_ns() >= t0);
    host::TSC.fetch_add(100, SeqCst);
    assert_eq!(pit::now_ns(), ns1 + ((100u128 * mult as u128) >> 32) as u64);
    // Ticks, uptime and seconds come from the clock
    let t = pit::ticks();
    assert_eq!(t, pit::now_ns() / pit::tick_ns());
    assert_eq!(pit::uptime_ms(), t * 1000 / 100);
    assert_eq!(pit::uptime_seconds(), t / 100);
    host::TSC_STEP.store(1000, SeqCst);
}

#[test]
fn sleep_ms_spins_without_interrupts() {
    let _g = serial();
    clock(1000);
    hw::set_if(false);
    let before = host::TSC.load(SeqCst);
    pit::sleep_ms(3);
    // Two cycles per nanosecond assumed: 6 million cycles
    assert!(host::TSC.load(SeqCst) - before >= 6_000_000);
    assert_eq!(hw::hlts(), 0);
    pit::sleep_ms(0);
    pit::sleep_ticks(0);
}

#[test]
fn sleep_ms_halts_with_interrupts() {
    let _g = serial();
    clock(50); // 2.5 ms per read: several reads per tick
    hw::set_if(true);
    let before = pit::ticks();
    pit::sleep_ms(25); // 3 ticks at 100 Hz (rounded up)
    assert!(pit::ticks() >= before + 3);
    assert!(hw::hlts() >= 1, "waited with hlt");
    host::TSC_STEP.store(1000, SeqCst);
}

#[test]
fn sleep_ticks_without_interrupts_spins() {
    let _g = serial();
    clock(50);
    hw::set_if(false);
    let before = pit::ticks();
    pit::sleep_ticks(2);
    assert!(pit::ticks() >= before + 2);
    assert_eq!(hw::hlts(), 0);
    hw::set_if(true);
    host::TSC_STEP.store(1000, SeqCst);
}

#[test]
fn sleep_at_a_preemption_point_lets_the_kernel_lock_go() {
    let _g = serial();
    clock(50);
    hw::set_if(true);
    stubs::task::ACTIVE.set(true);
    stubs::task::PREEMPT_POINTS.store(1, SeqCst);
    use hydra_hosttests_t32::arch::smp;
    assert!(smp::bkl_try_enter());
    let held_while_halted = std::rc::Rc::new(std::cell::Cell::new(true));
    let h = held_while_halted.clone();
    hw::set_hlt_hook(Some(Box::new(move || h.set(h.get() && smp::bkl_held()))));
    pit::sleep_ticks(2);
    hw::set_hlt_hook(None);
    assert!(!held_while_halted.get(), "the lock is released while halted");
    assert!(smp::bkl_held(), "and held again after");
    smp::bkl_exit();
    stubs::task::PREEMPT_POINTS.store(0, SeqCst);
    stubs::task::ACTIVE.set(false);
    host::TSC_STEP.store(1000, SeqCst);
}

#[test]
fn early_ticks_count_until_calibrated() {
    // Before the counter's rate is known (no calibration: PIT gate never rises in time is
    // not reachable here), ticks set the clock: after 10 ticks the rate is taken from them
    let _g = serial();
    clock(1000);
    let (_, _, _, mult) = pit::clock_state();
    assert!(mult != 0);
    // A tick keeps the calibrated rate (CALIBRATED): the measured cycles per tick do not
    // replace it
    for _ in 0..12 {
        pit::on_timer_tick();
    }
    assert_eq!(pit::clock_state().3, mult);
}

/// The boot epoch `rtc::init` derives from this CMOS, relative to a reference CMOS at
/// 2000-01-01 00:00:00 (binary, 24-hour): the clock's elapsed time and any wall-clock
/// offset left by another test cancel out. In nanoseconds.
fn epoch_vs_2000(set: impl FnOnce()) -> i64 {
    let mut r = [0u8; 0x40];
    r[0x07] = 1;
    r[0x08] = 1;
    r[0x09] = 0;
    r[0x32] = 20;
    r[0x0B] = 0x06;
    cmos(r);
    rtc::init();
    let reference = rtc::wall_base_ns();
    set();
    rtc::init();
    rtc::wall_base_ns() - reference + 946_684_800 * 1_000_000_000
}

/// A CMOS with these registers (index port 0x70, data 0x71).
fn cmos(regs: [u8; 0x40]) {
    let mut sel = 0u8;
    hw::set_port_handler(move |op| match (op.port, op.write) {
        (0x70, Some(v)) => {
            sel = v as u8 & 0x7F;
            0
        }
        (0x71, None) => regs[sel as usize] as u32,
        _ => 0,
    });
}

#[test]
fn rtc_reads_bcd_time() {
    let _g = serial();
    clock(0);
    let mut r = [0u8; 0x40];
    // 2026-11-20 13:45:30, BCD, 24-hour (status B bit 1)
    r[0x00] = 0x30;
    r[0x02] = 0x45;
    r[0x04] = 0x13;
    r[0x07] = 0x20;
    r[0x08] = 0x11;
    r[0x09] = 0x26;
    r[0x32] = 0x20;
    r[0x0B] = 0x02;
    let got = epoch_vs_2000(|| cmos(r));
    // Every index write keeps NMI off (bit 7)
    assert!(hw::port_writes().iter().filter(|w| w.0 == 0x70).all(|w| w.1 & 0x80 != 0));
    assert_eq!(got, 1_795_182_330 * 1_000_000_000); // 2026-11-20 13:45:30 UTC
    let (s, _) = rtc::now();
    assert!(s > 1_795_000_000);
}

#[test]
fn rtc_binary_12_hour_pm_and_default_century() {
    let _g = serial();
    clock(0);
    let mut r = [0u8; 0x40];
    // 1999-12-31 11 PM 59:58, binary (status B bit 2), 12-hour, century register empty
    r[0x00] = 58;
    r[0x02] = 59;
    r[0x04] = 11 | 0x80;
    r[0x07] = 31;
    r[0x08] = 12;
    r[0x09] = 99;
    r[0x0B] = 0x04;
    // The century defaults to 20: 2099-12-31 23:59:58
    assert_eq!(epoch_vs_2000(|| cmos(r)), 4_102_444_798 * 1_000_000_000);
}

#[test]
fn rtc_waits_out_updates_and_rollovers() {
    let _g = serial();
    clock(0);
    // The first sample is taken mid-update (UIP set twice), then a rollover changes the
    // seconds between two samples: init reads until two agree
    let got = epoch_vs_2000(|| {
    let mut uip = 2;
    let mut sec_reads = 0;
    let mut sel = 0u8;
    hw::set_port_handler(move |op| match (op.port, op.write) {
        (0x70, Some(v)) => {
            sel = v as u8 & 0x7F;
            0
        }
        (0x71, None) => match sel {
            0x0A => {
                if uip > 0 {
                    uip -= 1;
                    0x80
                } else {
                    0
                }
            }
            0x00 => {
                sec_reads += 1;
                if sec_reads == 1 { 0x58 } else { 0x59 }
            }
            0x0B => 0x02,
            0x07 | 0x08 => 0x01,
            0x09 => 0x99,
            0x32 => 0x20,
            _ => 0,
        },
        _ => 0,
    });
    });
    // 2099-01-01 00:00:59: the agreeing samples, not the first
    assert_eq!(got, 4_070_908_859 * 1_000_000_000);
}

#[test]
fn rtc_set_now_moves_the_wall_clock() {
    let _g = serial();
    clock(0);
    cmos([0; 0x40]);
    rtc::init();
    rtc::set_now(2_000_000_000, 500);
    let (s, ns) = rtc::now();
    // set_now's base is the tick count; now() reads the finer clock: within a tick
    let t = s as i128 * 1_000_000_000 + ns as i128;
    let want = 2_000_000_000i128 * 1_000_000_000 + 500;
    assert!((t - want).abs() < 10_000_000, "{t} vs {want}");
    // Far in the past: clamped at 0
    rtc::set_now(0, 0);
    assert!(rtc::now().0 < 10);
    host::TSC_STEP.store(1000, SeqCst);
}

#[test]
fn boottime_reports_stages() {
    let _g = serial();
    // Nothing until the clock is calibrated... (it is, from the other tests or here)
    clock(1000);
    boottime::mark("first");
    boottime::mark("second");
    boottime::report();
    let log = stubs::take_log();
    let lines: Vec<_> = log.iter().filter(|l| l.starts_with("[boottime]")).collect();
    assert!(lines.iter().any(|l| l.ends_with("first")), "{log:?}");
    assert!(lines.iter().any(|l| l.ends_with("second")));
    // Stages after the 48th are not kept
    for _ in 0..60 {
        boottime::mark("many");
    }
    boottime::report();
    let n = stubs::take_log().iter().filter(|l| l.starts_with("[boottime]")).count();
    assert_eq!(n, 48);
}

#[test]
fn random_fill_gives_fresh_bytes() {
    let _g = serial();
    let mut a = [0u8; 100];
    let mut b = [0u8; 100];
    random::fill(&mut a);
    random::fill(&mut b);
    assert_ne!(a, b);
    assert!(a.iter().any(|&x| x != 0));
    // Lengths across block boundaries, and empty
    for n in [0usize, 1, 31, 32, 33, 64, 65, 200] {
        let mut v = vec![0u8; n];
        random::fill(&mut v);
        if n >= 16 {
            assert!(v.iter().filter(|&&x| x == 0).count() < n / 4, "len {n}: {v:?}");
        }
    }
    // Byte frequencies are roughly flat over many bytes
    let mut big = vec![0u8; 1 << 16];
    random::fill(&mut big);
    let mut hist = [0u32; 256];
    for &x in &big {
        hist[x as usize] += 1;
    }
    let (lo, hi) = (hist.iter().min().unwrap(), hist.iter().max().unwrap());
    assert!(*lo > 150 && *hi < 380, "{lo}..{hi}");
}
