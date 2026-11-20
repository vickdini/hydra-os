//! The kernel-side profile (`src/compat/linux/prof.rs`): call/fault/file-server/disk/IPI
//! tallies, wakeup latency histograms, rip samples and slow-call records, and the reports
//! the `linux prof` command prints.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::prof;
use hydra_hosttests_t33::fake;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    prof::reset();
    prof::ON.store(false, Relaxed);
    g
}

fn advance_ms(ms: u64) {
    fake::TICKS.set(fake::TICKS.get() + ms);
}

#[test]
fn off_costs_nothing_and_counts_nothing() {
    let _g = serial();
    assert_eq!(prof::start(), 0);
    prof::syscall(1, 0);
    prof::fault(prof::FAULT_ANON, 0);
    prof::fs_request(0x3104, 0);
    prof::disk_call(prof::DISK_READ, 8, 0);
    prof::ipi_sent(true, 0);
    prof::kick_latency(5_000);
    prof::wake_requested(3);
    prof::wake_applied(3);
    prof::switched_in(3);
    prof::show(10);
    let out = fake::console_take();
    assert!(out.contains("[prof]           0         0 ms       0 us/each  fault: anonymous (zero page)"), "{out}");
    assert!(!out.contains("nr "), "no system call rows");
    assert!(out.contains("wakeup -> ready: <10us 0 <50us 0"));
}

#[test]
fn tallies_appear_in_the_report() {
    let _g = serial();
    prof::ON.store(true, Relaxed);
    // Two calls of 1 (2 ms each), one of 0 (5 ms)
    for (nr, ms) in [(1u64, 2u64), (1, 2), (0, 5)] {
        let t0 = prof::start();
        assert_ne!(t0, 0);
        advance_ms(ms);
        prof::syscall(nr, t0);
    }
    prof::syscall(4096, prof::start()); // past the table: ignored
    let t0 = prof::start();
    advance_ms(3);
    prof::fault(prof::FAULT_OBJECT, t0);
    prof::fault(99, t0); // unknown kind: ignored
    let t0 = prof::start();
    advance_ms(1);
    prof::fs_request(0x3104, t0); // getattr
    prof::fs_request(0x3200, t0); // out of range
    prof::disk_call(prof::DISK_READV, 16, t0);
    prof::disk_call(7, 16, t0);
    prof::ipi_sent(false, t0);
    hydra_hosttests_t33::task::scheduler::MAX_KSTACK_USE.store(12345, Relaxed);
    prof::show(1);
    let out = fake::console_take();
    assert!(out.contains("nr   0         1 calls         5 ms    5000 us/each"), "{out}");
    assert!(!out.contains("nr   1 "), "only the top row");
    assert!(out.contains("fault: mapped object"));
    assert!(out.contains("        1         3 ms    3000 us/each  fault: mapped object"), "{out}");
    assert!(out.contains("        1         1 ms    1000 us/each  getattr"), "{out}");
    assert!(out.contains("vectored disk reads (16 blocks)"));
    assert!(out.contains("other IPIs (TLB flushes) sent"));
    assert!(out.contains("deepest kernel stack use of an ended task: 12345 bytes"));
    assert!(out.contains("tlb: PCID off (host)") && out.contains("lx: lx: host"));
    prof::show(5);
    assert!(fake::console_take().contains("nr   1         2 calls         4 ms    2000 us/each"));
    // reset clears all of it
    prof::reset();
    prof::show(5);
    let out = fake::console_take();
    assert!(!out.contains("nr ") && !out.contains("getattr"));
}

#[test]
fn wakeup_latency_histograms() {
    let _g = serial();
    prof::ON.store(true, Relaxed);
    // Requested, applied 3 ms later, running 30 ms after that
    prof::wake_requested(7);
    advance_ms(3);
    prof::wake_applied(7);
    advance_ms(30);
    prof::switched_in(7);
    // A dropped request makes no sample; a second request keeps the first time
    prof::wake_requested(8);
    prof::wake_dropped(8);
    prof::wake_applied(8);
    prof::switched_in(9); // never made ready
    prof::kick_latency(5_000); // 5 us
    prof::kick_latency(60_000); // 60 us
    prof::show(0);
    let out = fake::console_take();
    assert!(out.contains("wakeup -> ready: <10us 0 <50us 0 <200us 0 <1ms 0 <5ms 1 <20ms 0 more 0"), "{out}");
    assert!(out.contains("ready -> running: <10us 0 <50us 0 <200us 0 <1ms 0 <5ms 0 <20ms 0 more 1"), "{out}");
    assert!(out.contains("kick -> halted CPU awake: <10us 1 <50us 0 <200us 1"), "{out}");
}

#[test]
fn rip_samples() {
    let _g = serial();
    prof::sample(5, 0x1000, 0x33); // not started
    prof::sample_start(5, false);
    for _ in 0..3 {
        prof::sample(5, 0x1000, 0x33);
    }
    prof::sample(5, 0x2000, 0x33);
    prof::sample(6, 0x3000, 0x33); // another task
    prof::sample(5, 0xFFFF_8000_0000_1000, 0x08); // kernel code: not sampled
    prof::sample_show(5);
    let out = fake::console_take();
    assert!(out.contains("[sample] 4 samples of task 5"), "{out}");
    let rows: Vec<&str> = out.lines().skip(1).collect();
    assert_eq!(rows[0].trim(), "[sample]      3 0x1000");
    assert_eq!(rows[1].trim(), "[sample]      1 0x2000");
    // Every task, kernel code too
    prof::sample_start(u64::MAX, true);
    prof::sample(1, 0xAA, 0x08);
    prof::sample(2, 0xAA, 0x33);
    prof::sample_show(1);
    assert!(fake::console_take().contains("[sample]      2 0xaa"));
    prof::sample_start(0, false);
}

#[test]
fn slow_calls_are_recorded_and_listed() {
    let _g = serial();
    prof::slow(1, 0, 0, 0, 0, 0); // never started
    prof::SLOW_MS.store(10, Relaxed);
    let t0 = prof::start();
    assert_eq!(t0, 0, "prof is off: start() is 0");
    let t0 = fake::now_ns();
    prof::slow(1, 0, 0, 0, 0, t0); // took 0 ms: not slow
    advance_ms(25);
    fake::IDS.set((11, 10));
    prof::slow(7, -4, 1, 2, 3, t0);
    // nanosleep and clock_nanosleep show the time asked for
    let ts: [u64; 2] = [2, 500];
    prof::slow(35, 0, ts.as_ptr() as u64, 0, 0, t0);
    prof::slow(230, 0, 0, 0, ts.as_ptr() as u64, t0);
    prof::slow(230, 0, 0, 0, 0, t0);
    // A slow page fault (nr u64::MAX)
    prof::slow(u64::MAX, 0, 0xdead_0000, 2, 0, t0);
    prof::slow_show();
    let out = fake::console_take();
    assert!(out.contains("[wait] 5 slow calls"), "{out}");
    assert!(out.contains("+25.0ms 10/11  nr 7 (0x1, 0x2, 0x3) -> -4"), "{out}");
    assert!(out.contains("nr 35 (0x773595f4, 0x0, 0x0)"), "2 s 500 ns: {out}");
    assert!(out.contains("nr 230 (0x0, 0x0, 0x773595f4)"), "{out}");
    assert!(out.contains("fault 0xdead0000 kind 2"), "{out}");
    // Listed once: the records are taken
    prof::slow_show();
    assert!(fake::console_take().contains("[wait] 0 slow calls"));
    prof::SLOW_MS.store(0, Relaxed);
}
