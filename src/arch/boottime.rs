//! # Boot timing
//!
//! [`mark`] notes the time stamp counter at a boot stage; [`report`] prints how long each
//! stage took once the clock is calibrated (the counter's rate is not known earlier). Used to
//! see where boot time goes, from the kernel's entry to the shell.

use core::sync::atomic::{AtomicUsize, Ordering};

const MAX: usize = 48;

static COUNT: AtomicUsize = AtomicUsize::new(0);
static mut MARKS: [(&str, u64); MAX] = [("", 0); MAX];

fn tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Notes that boot stage `name` begins now.
pub fn mark(name: &'static str) {
    let i = COUNT.fetch_add(1, Ordering::AcqRel);
    if i < MAX {
        unsafe { (*core::ptr::addr_of_mut!(MARKS))[i] = (name, tsc()) };
    }
}

/// Prints each stage's duration (milliseconds) and its start since the kernel's entry.
pub fn report() {
    let n = COUNT.load(Ordering::Acquire).min(MAX);
    let (_, _, _, mult) = super::pit::clock_state();
    if n == 0 || mult == 0 {
        return;
    }
    let ms = |cycles: u64| ((cycles as u128 * mult as u128) >> 32) as u64 / 1_000_000;
    let marks = unsafe { &*core::ptr::addr_of!(MARKS) };
    let start = marks[0].1;
    let end = tsc();
    for i in 0..n {
        let next = if i + 1 < n { marks[i + 1].1 } else { end };
        crate::kprintln!("[boottime] {:>6} ms  +{:>5} ms  {}", ms(marks[i].1 - start), ms(next - marks[i].1), marks[i].0);
    }
}
