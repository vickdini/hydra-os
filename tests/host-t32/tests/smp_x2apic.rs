//! `arch/smp.rs` in x2APIC mode (own binary: a CPU never leaves it).
//!
//! Each test thread plays a CPU (`host::set_cpu`); the lock and the flush bookkeeping are
//! global, as in the kernel, so every test holds [`serial`].

use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex, MutexGuard};

use hydra_hosttests_t32::arch::smp;
use hydra_hosttests_t32::{host, stubs};


fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

#[test]
fn x2apic_ipis_are_one_msr_write() {
    let _g = serial();
    smp::host_bring_online(2);
    // CPU 0 switches to x2APIC (the CPU has it, the APIC base MSR says enabled, xAPIC)
    host::set_cpu(0);
    host::X2APIC.set(true);
    host::wrmsr(0x1B, 0xFEE0_0000 | 1 << 11);
    smp::start_aps(); // no trampoline: only x2APIC on
    assert!(smp::x2apic_on());
    assert_eq!(host::rdmsr(0x1B) & (1 << 10), 1 << 10);
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let t = std::thread::spawn(move || {
        host::set_cpu(1);
        while !s.load(SeqCst) {
            smp::serve_tlb();
        }
    });
    host::MSR_WRITES.with_borrow_mut(|w| w.clear());
    smp::LOADED_CR3[1].store(0x5000, SeqCst);
    smp::shootdown(Some(0x5000), Some(0x1000));
    // ICR as MSR 0x830: destination in the high half
    assert_eq!(host::MSR_WRITES.with_borrow(|w| w.clone()), vec![(0x830, 1u64 << 32 | 0x4000 | 0x42)]);
    // Register reads go to MSRs too
    host::wrmsr(0x802, 7);
    assert_eq!(smp::apic_id(), 7, "x2APIC ID: the full register");
    smp::lapic_eoi();
    assert_eq!(host::MSR_WRITES.with_borrow(|w| *w.last().unwrap()), (0x80B, 0));
    smp::kick_cpu(1);
    assert_eq!(host::MSR_WRITES.with_borrow(|w| *w.last().unwrap()), (0x830, 1u64 << 32 | 0x4042));
    smp::kick_cpu(99); // no such CPU
    stop.store(true, SeqCst);
    t.join().unwrap();
    smp::host_bring_online(1);
}

