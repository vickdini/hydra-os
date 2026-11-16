//! Time spent serving block requests, measured with the time-stamp counter and printed
//! once per GiB moved: how fast the driver and the device are, apart from the file
//! system above them. Shared by the disk drivers (`#[path]`-included).

use hydra_rt::{println, sys};

/// Bytes moved between two reports.
const REPORT_BYTES: u64 = 1 << 30;

/// Reads the time-stamp counter.
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Request counters of one driver.
pub struct IoStats {
    name: &'static str,
    /// Counter ticks per microsecond (measured at start-up against the uptime clock).
    tsc_per_us: u64,
    reads: u64,
    writes: u64,
    bytes: u64,
    cycles: u64,
}

impl IoStats {
    /// Measures the counter's rate (about 50 ms) and starts counting.
    pub fn new(name: &'static str) -> Self {
        // Start on a tick boundary so that the span is whole ticks
        let t0 = sys::uptime_ticks();
        while sys::uptime_ticks() == t0 {
            core::hint::spin_loop();
        }
        let (t1, c1) = (sys::uptime_ticks(), rdtsc());
        while sys::uptime_ticks() < t1 + 5 {
            core::hint::spin_loop();
        }
        let (t2, c2) = (sys::uptime_ticks(), rdtsc());
        let us = (t2 - t1) * 10_000;
        Self { name, tsc_per_us: ((c2 - c1) / us.max(1)).max(1), reads: 0, writes: 0, bytes: 0, cycles: 0 }
    }

    /// The counter now, for [`IoStats::done`].
    pub fn start(&self) -> u64 {
        rdtsc()
    }

    /// Counts one request of `bytes` begun at `start`; prints a report each GiB.
    pub fn done(&mut self, start: u64, bytes: u64, write: bool) {
        self.cycles += rdtsc().wrapping_sub(start);
        if write {
            self.writes += 1;
        } else {
            self.reads += 1;
        }
        self.bytes += bytes;
        if self.bytes >= REPORT_BYTES {
            let us = (self.cycles / self.tsc_per_us).max(1);
            let reqs = self.reads + self.writes;
            println!(
                "[{}] io: {} reads + {} writes, {} MiB in {} ms busy: {} us/request, {} MB/s",
                self.name,
                self.reads,
                self.writes,
                self.bytes >> 20,
                us / 1000,
                us / reqs.max(1),
                self.bytes / us
            );
            self.reads = 0;
            self.writes = 0;
            self.bytes = 0;
            self.cycles = 0;
        }
    }
}
