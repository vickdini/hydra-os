//! `arch/smp.rs` shootdowns with PCID on (own binary: PCID stays on): the requester marks
//! other CPUs' slots stale and flushes its own ID or slot; the served CPU flushes its
//! current ID, or every ID for a change of the kernel's tables.

use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use hydra_hosttests_t32::arch::{pcid, smp};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

#[test]
fn shootdowns_with_pcid() {
    host::reset();
    stubs::reset();
    smp::host_bring_online(2);
    host::set_cpu(0);
    hw::set_cr(3, 0x8000);
    pcid::init_with(true, true);
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    host::MMIO.with_borrow_mut(|m| {
        *m = Some(Box::new(move |a, w| {
            if let Some(v) = w {
                l.lock().unwrap().push((a & 0xFFF, v));
            }
            0
        }))
    });
    let (a, b) = (0x10_0000u64, 0x20_0000u64);
    pcid::load_cr3(b);
    pcid::load_cr3(a); // CPU 0 runs A, has B cached
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let t = std::thread::spawn(move || {
        host::set_cpu(1);
        hw::set_cr(3, 0x8000);
        pcid::load_cr3(a); // CPU 1 runs A too
        let before = host::CR3_WRITES.with_borrow(|w| w.len());
        while !s.load(SeqCst) {
            smp::serve_tlb();
        }
        let w = host::CR3_WRITES.with_borrow(|w| w[before..].to_vec());
        (w, host::INVPCID.with_borrow(|v| v.clone()))
    });
    while smp::LOADED_CR3[1].load(SeqCst) != a {
        std::hint::spin_loop();
    }
    host::INVPCID.with_borrow_mut(|v| v.clear());
    hw::FLUSHED.with_borrow_mut(|f| f.clear());
    // A page of A: local invlpg (A is loaded), CPU 1 gets an IPI
    smp::shootdown(Some(a), Some(0x3000));
    assert_eq!(hw::FLUSHED.with_borrow(|f| f.clone()), vec![0x3000]);
    assert_eq!(log.lock().unwrap().iter().filter(|e| e.0 == 0x300).count(), 1);
    // B (cached here, loaded nowhere): INVPCID of its ID here, no IPI
    smp::shootdown(Some(b), None);
    assert_eq!(host::INVPCID.with_borrow(|v| v.len()), 1);
    assert_eq!(log.lock().unwrap().iter().filter(|e| e.0 == 0x300).count(), 1);
    // The kernel's tables: every ID everywhere
    smp::shootdown(None, Some(0xFFFF_8000_0000_0000));
    assert_eq!(host::INVPCID.with_borrow(|v| *v.last().unwrap()), (0xFFFF, None));
    assert_eq!(log.lock().unwrap().iter().filter(|e| e.0 == 0x300).count(), 2);
    stop.store(true, SeqCst);
    let (cr3s, inv) = t.join().unwrap();
    // CPU 1: its current ID flushed (CR3 write without bit 63) for A; all IDs for the kernel
    assert_eq!(cr3s.len(), 1, "{cr3s:x?}");
    assert_eq!(cr3s[0] >> 63, 0);
    assert_eq!(cr3s[0] & 0x000F_FFFF_FFFF_F000, a);
    assert!(inv.contains(&(0xFFFF, None)), "{inv:?}");
    smp::host_bring_online(1);
}
