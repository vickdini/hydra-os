//! `arch/smp.rs` and `arch/percpu.rs`: the kernel lock (with real threads as CPUs), TLB
//! shootdowns between CPUs, idle kicks, MADT discovery, the local APIC in both modes and
//! the start-up of the other processors (which never answer here).
//!
//! Each test thread plays a CPU (`host::set_cpu`); the lock and the flush bookkeeping are
//! global, as in the kernel, so every test holds [`serial`].

mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, MutexGuard};

use common::acpi;
use hydra_hosttests_t32::arch::{percpu, pit, smp};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

/// A calibrated clock whose time moves 2.5 ms per counter read (waiting loops end).
fn clock() {
    hw::set_port_handler(|op| if op.port == 0x61 { 0x20 } else { 0 });
    host::TSC_STEP.store(1000, SeqCst);
    pit::init(100);
    host::TSC_STEP.store(50, SeqCst);
    hw::clear_ports();
}

/// A local APIC model on this thread: reads give `id << 24` for the ID register and 0
/// otherwise (IPIs delivered at once); writes are logged.
fn lapic(id: u32) -> Arc<Mutex<Vec<(u64, u32)>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    host::MMIO.with_borrow_mut(|m| {
        *m = Some(Box::new(move |a, w| match w {
            Some(v) => {
                l.lock().unwrap().push((a & 0xFFF, v));
                0
            }
            None if a & 0xFFF == 0x20 => id << 24,
            None => 0,
        }))
    });
    log
}

// ------------------------------------------------------------------- the kernel lock

#[test]
fn kernel_lock_basics() {
    let _g = serial();
    host::set_cpu(1);
    assert!(!smp::bkl_held());
    smp::bkl_enter();
    assert!(smp::bkl_held());
    assert_eq!(smp::bkl_owner(), 1);
    // Owned by the CPU: entering again is a no-op, one exit releases
    smp::bkl_enter();
    assert!(smp::bkl_try_enter());
    smp::bkl_exit();
    assert!(!smp::bkl_held());
    assert_eq!(smp::bkl_owner(), usize::MAX);
    // Exit without holding it: nothing
    smp::bkl_exit();
    // Another CPU holds it: try fails, and our exit does not release theirs
    host::set_cpu(2);
    assert!(smp::bkl_try_enter());
    host::set_cpu(1);
    assert!(!smp::bkl_try_enter());
    smp::bkl_exit();
    assert_eq!(smp::bkl_owner(), 2);
    host::set_cpu(2);
    smp::bkl_exit();
    // The idle entry spins with interrupts on until it gets it
    host::set_cpu(3);
    hw::set_if(false);
    smp::bkl_enter_idle();
    assert!(smp::bkl_held());
    smp::bkl_exit();
    // ...waiting with interrupts on while another CPU has it
    host::set_cpu(2);
    assert!(smp::bkl_try_enter());
    let ready = Arc::new(AtomicBool::new(false));
    let r2 = ready.clone();
    let t = std::thread::spawn(move || {
        host::set_cpu(3);
        hw::set_if(false);
        r2.store(true, SeqCst);
        smp::bkl_enter_idle();
        let on = hw::if_flag();
        smp::bkl_exit();
        on
    });
    while !ready.load(SeqCst) {
        std::hint::spin_loop();
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    smp::bkl_exit();
    assert!(t.join().unwrap(), "interrupts enabled while waiting");
    // Interrupts as they were around enter/exit
    hw::set_if(true);
    smp::bkl_enter();
    assert!(hw::if_flag());
    smp::bkl_exit();
}

#[test]
fn kernel_lock_excludes_and_is_fair_across_cpus() {
    let _g = serial();
    let inside = Arc::new(AtomicUsize::new(0));
    let overlaps = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for cpu in 0..4 {
        let (inside, overlaps, total) = (inside.clone(), overlaps.clone(), total.clone());
        threads.push(std::thread::spawn(move || {
            host::set_cpu(cpu);
            for i in 0..2000 {
                if i % 3 == 0 {
                    while !smp::bkl_try_enter() {
                        std::hint::spin_loop();
                    }
                } else {
                    smp::bkl_enter();
                }
                assert!(smp::bkl_held());
                if inside.fetch_add(1, SeqCst) != 0 {
                    overlaps.fetch_add(1, SeqCst);
                }
                total.fetch_add(1, SeqCst);
                std::hint::spin_loop();
                inside.fetch_sub(1, SeqCst);
                smp::bkl_exit();
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(overlaps.load(SeqCst), 0, "two CPUs in the kernel at once");
    assert_eq!(total.load(SeqCst), 8000);
    assert_eq!(smp::bkl_owner(), usize::MAX);
}

#[test]
fn waiting_for_the_lock_serves_flush_requests() {
    // CPU 1 holds the lock and shoots down CPU 2's TLB; CPU 2 waits for the lock with
    // interrupts off: it must serve the flush from its wait loop, or both wait forever
    let _g = serial();
    smp::host_bring_online(3);
    host::set_cpu(1);
    let _l = lapic(1);
    smp::bkl_enter();
    smp::LOADED_CR3[2].store(0xAB000, SeqCst);
    let started = Arc::new(AtomicBool::new(false));
    let s2 = started.clone();
    let t2 = std::thread::spawn(move || {
        host::set_cpu(2);
        s2.store(true, SeqCst);
        smp::bkl_enter(); // spins, serving flushes
        let flushes = hw::CR_WRITES.with_borrow(|w| w.len());
        smp::bkl_exit();
        flushes
    });
    while !started.load(SeqCst) {
        std::hint::spin_loop();
    }
    smp::shootdown(Some(0xAB000), Some(0x4000));
    smp::bkl_exit();
    assert_eq!(t2.join().unwrap(), 2, "CPU 2 flushed once (PGE toggled off and on)");
    smp::host_bring_online(1);
}

// ------------------------------------------------------------------- shootdowns

#[test]
fn shootdown_reaches_the_cpus_that_have_the_tables() {
    let _g = serial();
    smp::host_bring_online(3);
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicU32::new(0));
    let mut others = Vec::new();
    for cpu in [1usize, 2] {
        let (stop, served) = (stop.clone(), served.clone());
        others.push(std::thread::spawn(move || {
            host::set_cpu(cpu);
            hw::set_cr(4, 0x6A0); // PGE on: flushes toggle it
            hw::CR_WRITES.with_borrow_mut(|w| w.clear());
            while !stop.load(SeqCst) {
                smp::serve_tlb();
                std::hint::spin_loop();
            }
            let w = hw::CR_WRITES.with_borrow(|w| w.clone());
            served.fetch_add((w.len() / 2) as u32, SeqCst);
            w
        }));
    }
    host::set_cpu(0);
    let ipis = lapic(0);
    smp::LOADED_CR3[1].store(0x111000, SeqCst);
    smp::LOADED_CR3[2].store(0x222000, SeqCst);
    // A user page of 0x111000's process: CPU 1 only
    smp::shootdown(Some(0x111000), Some(0x7000));
    assert_eq!(hw::FLUSHED.with_borrow(|f| f.clone()), vec![0x7000], "local invlpg");
    {
        let l = ipis.lock().unwrap();
        // xAPIC: destination in ICR high, then the fixed IPI to vector 0x42
        assert_eq!(*l, vec![(0x310, 1 << 24), (0x300, 0x4000 | 0x42)]);
    }
    // A kernel change (no address space): every live CPU, local full flush
    ipis.lock().unwrap().clear();
    hw::set_cr(4, 0x620); // no PGE: a full flush reloads CR3
    smp::shootdown(None, None);
    assert_eq!(ipis.lock().unwrap().len(), 4, "two IPIs");
    assert_eq!(hw::CR_WRITES.with_borrow(|w| w.iter().filter(|e| e.0 == 3).count()), 1, "local CR3 reload");
    // Nobody else has these tables: no IPI
    ipis.lock().unwrap().clear();
    smp::shootdown(Some(0x333000), None);
    assert!(ipis.lock().unwrap().is_empty());
    stop.store(true, SeqCst);
    let w1 = others.remove(0).join().unwrap();
    let w2 = others.remove(0).join().unwrap();
    // CPU 1 served two requests, CPU 2 one; each by toggling PGE twice
    assert_eq!(w1.len(), 4, "{w1:x?}");
    assert_eq!(w2.len(), 2, "{w2:x?}");
    assert_eq!(w1[0], (4, 0x620));
    assert_eq!(w1[1], (4, 0x6A0));
    smp::host_bring_online(1);
}

#[test]
fn shootdown_on_one_cpu_is_local() {
    let _g = serial();
    smp::host_bring_online(1);
    host::set_cpu(0);
    let ipis = lapic(0);
    smp::LOADED_CR3[1].store(0x111000, SeqCst);
    smp::shootdown(Some(0x111000), Some(0x9000));
    assert!(ipis.lock().unwrap().is_empty());
    assert_eq!(hw::FLUSHED.with_borrow(|f| f.clone()), vec![0x9000]);
    // serve_tlb with nothing pending does nothing
    smp::serve_tlb();
    assert!(hw::CR_WRITES.with_borrow(|w| w.is_empty()));
}

// ------------------------------------------------------------------- idle and kicks

#[test]
fn idle_halting_and_kicks() {
    let _g = serial();
    clock();
    smp::host_bring_online(3);
    let _l = lapic(0);
    // CPU 2 goes idle and halts
    host::set_cpu(2);
    let gen = smp::runnable_gen();
    assert!(smp::idle_halting(gen));
    // A wakeup elsewhere (not in a system call): CPU 2 gets an IPI at once
    host::set_cpu(0);
    stubs::take_calls();
    smp::kick_idle();
    assert!(smp::runnable_gen() > gen);
    assert_eq!(stubs::take_calls(), vec!["prof::ipi_sent true"]);
    host::set_cpu(2);
    assert!(smp::idle_halt_ended(), "woken by the kick");
    // Halting with a stale generation: not allowed (a task became runnable meanwhile)
    assert!(!smp::idle_halting(gen));
    // A halt that ended by itself (its timer): not a kick
    let g2 = smp::runnable_gen();
    assert!(smp::idle_halting(g2));
    assert!(!smp::idle_halt_ended());
    // Pending wakeups also forbid halting
    stubs::answer("wait::wakes_pending", 1);
    assert!(!smp::idle_halting(smp::runnable_gen()));
    smp::IDLE_POLL_NS.store(1_000_000_000, SeqCst);
    assert!(smp::idle_poll(), "a wakeup pending: stop polling");
    stubs::answer("wait::wakes_pending", 0);
    assert!(!smp::idle_poll(), "nothing within the poll time");
    smp::IDLE_POLL_NS.store(200_000, SeqCst);
    // No CPU halted: a kick sends nothing
    host::set_cpu(0);
    smp::kick_idle();
    assert!(stubs::take_calls().is_empty());
    smp::host_bring_online(1);
}

#[test]
fn kicks_from_a_system_call_wait_for_its_end() {
    let _g = serial();
    smp::host_bring_online(2);
    let _l = lapic(0);
    host::set_cpu(1);
    assert!(smp::idle_halting(smp::runnable_gen()));
    host::set_cpu(0);
    smp::bkl_enter();
    stubs::task::CURRENT_SYSCALL.store(39, SeqCst);
    stubs::take_calls();
    smp::kick_idle();
    assert!(smp::kick_pending(), "deferred");
    assert!(stubs::take_calls().is_empty());
    // The call ends: the kick goes out
    smp::flush_kick();
    assert!(!smp::kick_pending());
    assert_eq!(stubs::take_calls(), vec!["prof::ipi_sent true"]);
    // A switch with no other task ready drops the deferred kick
    host::set_cpu(1);
    assert!(smp::idle_halt_ended());
    assert!(smp::idle_halting(smp::runnable_gen()));
    host::set_cpu(0);
    smp::kick_idle();
    smp::switch_kick(false, 0);
    assert!(!smp::kick_pending());
    assert!(stubs::take_calls().is_empty());
    smp::kick_idle();
    smp::switch_kick(true, 0);
    assert_eq!(stubs::take_calls(), vec!["prof::ipi_sent true"]);
    stubs::task::CURRENT_SYSCALL.store(u64::MAX, SeqCst);
    smp::bkl_exit();
    host::set_cpu(1);
    smp::idle_halt_ended();
    smp::host_bring_online(1);
}

// ------------------------------------------------------------------- discovery

#[test]
fn madt_discovery() {
    let _g = serial();
    clock();
    host::set_cpu(0);
    let log = lapic(0);
    // Three enabled CPUs (one an x2APIC entry), a disabled one, an online-capable one, and
    // an address override
    let madt = acpi::madt(
        0xFEE0_0000,
        &[
            acpi::lapic_entry(0, 0, 1),
            acpi::lapic_entry(1, 2, 1),
            acpi::lapic_entry(2, 4, 0),
            acpi::lapic_entry(3, 6, 2),
            acpi::x2apic_entry(0x101, 1),
            acpi::x2apic_entry(0x102, 0),
            acpi::lapic_override(0xFEE0_0000),
        ],
    );
    host::RSDP.set(Some(acpi::rsdp(vec![acpi::table(b"FACP", &[0; 4]), madt], true)));
    host::LOW_PAGES.set(None);
    smp::discover();
    let l = stubs::take_log();
    assert!(l.iter().any(|s| s.contains("no memory below 1 MiB")), "{l:?}");
    assert!(l.iter().any(|s| s == "[smp] 4 CPU(s) in the MADT, local APIC at 0xfee00000"), "{l:?}");
    assert_eq!(smp::present(), 4);
    assert_eq!(smp::boot_apic_id(), 0);
    let _ = log;
}

#[test]
fn madt_missing_or_broken() {
    let _g = serial();
    host::set_cpu(0);
    let _l = lapic(3);
    host::RSDP.set(None);
    smp::discover();
    assert_eq!(stubs::take_log(), vec!["[smp] no ACPI tables: one CPU"]);
    assert_eq!(smp::boot_apic_id(), 3);
    // An RSDT (ACPI 1) with a MADT whose checksum is wrong
    let mut madt = acpi::madt(0xFEE0_0000, &[acpi::lapic_entry(0, 0, 1)]);
    madt[9] ^= 1;
    host::RSDP.set(Some(acpi::rsdp(vec![madt], false)));
    smp::discover();
    assert_eq!(stubs::take_log(), vec!["[smp] no MADT: one CPU"]);
    // A bad RSDP: nothing
    let mut r = vec![0u8; 36];
    r[..8].copy_from_slice(b"RSD PTR!");
    host::RSDP.set(Some(acpi::leak(r)));
    smp::discover();
    assert!(stubs::take_log().is_empty());
    // A MADT entry of length 0 ends the walk
    let mut m = acpi::madt(0xFEE0_0000, &[acpi::lapic_entry(0, 0, 1), (0, vec![])]);
    let n = m.len();
    m[n - 1] = 0; // the empty entry's length byte
    let sum = m.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    m[9] = m[9].wrapping_sub(sum);
    host::RSDP.set(Some(acpi::rsdp(vec![m], true)));
    smp::discover();
    assert!(stubs::take_log().iter().any(|s| s.contains("1 CPU(s) in the MADT")));
}

#[test]
fn starting_processors_that_never_answer() {
    let _g = serial();
    smp::host_bring_online(1);
    clock();
    host::set_cpu(0);
    let ipis = lapic(0);
    // The start-up page (2 pages) and the boot tables CR3 points at, in an arena
    let arena = common::Arena::new(7);
    let tramp = arena.base;
    hw::set_cr(3, arena.base + 0x10000);
    host::LOW_PAGES.set(Some(tramp));
    let madt = acpi::madt(0xFEE0_0000, &[acpi::lapic_entry(0, 0, 1), acpi::lapic_entry(1, 1, 1)]);
    host::RSDP.set(Some(acpi::rsdp(vec![madt], true)));
    smp::discover();
    stubs::take_log();
    ipis.lock().unwrap().clear();
    host::X2APIC.set(false);
    smp::start_aps();
    let l = stubs::take_log();
    assert!(l.iter().any(|s| s == "[smp] CPU with APIC id 1 did not start"), "{l:?}");
    assert!(l.iter().any(|s| s == "[smp] 1 CPU(s) online"), "{l:?}");
    // INIT, then STARTUP twice (no answer to the first), at the page's vector
    let icr: Vec<u32> = ipis.lock().unwrap().iter().filter(|e| e.0 == 0x300).map(|e| e.1).collect();
    let vector = (tramp >> 12) as u32;
    assert_eq!(icr, vec![0x4500, 0x4600 | vector, 0x4600 | vector]);
    // The start-up code was copied there, the boot PML4 copy behind it
    assert_eq!(unsafe { *(tramp as *const u8) }, 0xFA, "cli");
    assert_eq!(smp::online(), 1);
}

// ------------------------------------------------------------------- per-CPU data

#[test]
fn per_cpu_blocks_and_counters() {
    let _g = serial();
    // Each CPU's block: GS base at it, the kernel GS base 0
    host::set_cpu(5);
    percpu::init_this_cpu(5);
    let w = host::MSR_WRITES.with_borrow(|w| w.clone());
    assert_eq!(w.len(), 2);
    assert_eq!(w[0].0, 0xC000_0101);
    assert_eq!(w[1], (0xC000_0102, 0));
    let block = w[0].1;
    unsafe {
        assert_eq!(*(block as *const u64), block, "self pointer");
        assert_eq!(*((block + 8) as *const u64), 5, "the CPU index at gs:[8]");
    }
    percpu::set_kernel_rsp(0xFFFF_8000_1234_0000);
    assert_eq!(percpu::kernel_rsp_of(5), 0xFFFF_8000_1234_0000);
    assert_eq!(unsafe { *((block + 16) as *const u64) }, 0xFFFF_8000_1234_0000, "gs:[16]");
    // Leaving marks: task id + 1, seen from other CPUs among those online
    smp::host_bring_online(8);
    percpu::set_leaving(41);
    assert_eq!(percpu::leaving_of(5), 42);
    assert!(!percpu::leaving_elsewhere(41), "this CPU's own mark");
    host::set_cpu(6);
    assert!(percpu::leaving_elsewhere(41));
    assert!(!percpu::leaving_elsewhere(40));
    smp::host_bring_online(4);
    assert!(!percpu::leaving_elsewhere(41), "CPU 5 not online");
    host::set_cpu(5);
    percpu::set_leaving(u64::MAX - 1); // clear (id + 1 wraps to the "none" value only for MAX)
    smp::host_bring_online(1);

    // Per-CPU counters act on the calling CPU's slot
    static C64: percpu::PerCpuU64 = percpu::PerCpuU64::new(10);
    static C32: percpu::PerCpuU32 = percpu::PerCpuU32::new();
    static P: percpu::PerCpuPtr<u32> = percpu::PerCpuPtr::new();
    host::set_cpu(1);
    assert_eq!(C64.load(SeqCst), 10);
    C64.store(20, SeqCst);
    assert_eq!(C64.fetch_add(5, SeqCst), 20);
    assert_eq!(C64.swap(1, SeqCst), 25);
    host::set_cpu(2);
    assert_eq!(C64.load(SeqCst), 10, "CPU 2's own slot");
    assert_eq!(C64.on(1).load(SeqCst), 1);
    C32.store(3, SeqCst);
    assert_eq!(C32.fetch_add(2, SeqCst), 3);
    assert_eq!(C32.fetch_sub(1, SeqCst), 5);
    assert_eq!(C32.swap(9, SeqCst), 4);
    assert_eq!(C32.load(SeqCst), 9);
    host::set_cpu(3);
    assert_eq!(C32.load(SeqCst), 0);
    let mut x = 5u32;
    P.store(&mut x, SeqCst);
    assert_eq!(P.load(SeqCst), &mut x as *mut u32);
    host::set_cpu(4);
    assert!(P.load(SeqCst).is_null());
    assert!(P.swap(&mut x, SeqCst).is_null());
}

// wave11 GD begin
#[test]
fn a_high_priority_wakeup_preempts_the_cpu_with_the_least_urgent_work() {
    // The choice: another live CPU running lower priority work, the lowest
    let cpus = [(true, 2u8, 0u32), (true, 0, 0), (true, 3, 0), (false, 0, 0)];
    assert_eq!(smp::preempt_victim(0, 4, 3, 0, |c| cpus[c]), Some(1));
    assert_eq!(smp::preempt_victim(1, 4, 3, 0, |c| cpus[c]), Some(0));
    assert_eq!(smp::preempt_victim(1, 3, 2, 0, |c| cpus[c]), None, "nothing less urgent elsewhere");
    assert_eq!(smp::preempt_victim(0, 1, 4, 0, |c| cpus[c]), None, "only this CPU");
    // A normal task: only a CPU running a busy normal thread that used far more
    let busy = smp::PREEMPT_BUSY;
    let cpus = [(true, 2u8, busy * 2), (true, 2, busy * 3), (true, 2, busy / 2), (false, 2, busy * 9)];
    assert_eq!(smp::preempt_victim(9, 4, 2, 64, |c| cpus[c]), Some(1), "the busiest");
    assert_eq!(smp::preempt_victim(9, 4, 2, busy, |c| cpus[c]), None, "not light enough");
    assert_eq!(smp::preempt_victim(9, 3, 1, 0, |c| cpus[c]), None, "a low priority task never");
    // The machinery: two CPUs, none halted, both running normal work
    let _g = serial();
    smp::host_bring_online(2);
    let _l = lapic(0);
    host::set_cpu(1);
    smp::idle_halt_ended();
    smp::set_cur_prio(2, 0);
    host::set_cpu(0);
    smp::set_cur_prio(2, 0);
    let sent = smp::RESCHED_SENT.load(SeqCst);
    // A normal task woken: it waits for a tick
    smp::kick_for(2, 0);
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent);
    // ...unless the other CPU runs a busy normal thread
    host::set_cpu(1);
    smp::set_cur_prio(2, smp::PREEMPT_BUSY * 4);
    host::set_cpu(0);
    smp::kick_for(2, 0);
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent + 1);
    smp::kick_for(2, 0);
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent + 1, "asked already");
    host::set_cpu(1);
    assert!(smp::take_resched());
    smp::set_cur_prio(2, 0);
    host::set_cpu(0);
    let sent = sent + 1;
    // A high priority one: CPU 1 is asked once
    smp::kick_for(3, 0);
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent + 1);
    assert!(!smp::take_resched(), "not this CPU");
    host::set_cpu(1);
    assert!(smp::take_resched());
    assert!(!smp::take_resched());
    // Deferred in a system call: sent at its end only if high work is left over
    host::set_cpu(0);
    stubs::task::CURRENT_SYSCALL.store(39, SeqCst);
    smp::bkl_enter();
    smp::kick_for(3, 0);
    smp::switch_kick(true, 2);
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent + 1, "this CPU ran the woken task");
    smp::kick_for(3, 0);
    smp::flush_kick();
    assert_eq!(smp::RESCHED_SENT.load(SeqCst), sent + 2);
    stubs::task::CURRENT_SYSCALL.store(u64::MAX, SeqCst);
    smp::bkl_exit();
    host::set_cpu(1);
    assert!(smp::take_resched());
    host::set_cpu(0);
    smp::host_bring_online(1);
}
// wave11 GD end
