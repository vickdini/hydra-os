//! # Symmetric multiprocessing: finding and starting the other CPUs
//!
//! The firmware describes the processors in the ACPI MADT ("APIC" table), found through
//! the RSDP in the UEFI configuration table. [`discover`] reads it while boot services
//! still run (and reserves two pages below 1 MiB for the start-up code); [`start_aps`]
//! later starts every other processor (application processor, AP) with the INIT and
//! STARTUP inter-processor interrupts of the local APIC.
//!
//! An AP starts in real mode at the start-up page. The trampoline ([`ap_tramp_start`])
//! enters protected mode with a small GDT of its own, turns on long mode with a copy of
//! the kernel's top-level page table in low memory (CR3 must be below 4 GiB there), then
//! switches to the kernel's own page tables and stack and calls [`ap_main`] with the
//! CPU's index. The trampoline is position independent: the real-mode code finds its
//! physical address in CS, and the long-mode code addresses its data relative to RIP.
//!
//! [`ap_main`] loads a GDT and TSS of the CPU's own, the shared IDT, the system call MSRs,
//! and enables its local APIC; the CPU is then online and waits.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use spin::Mutex;

/// Most CPUs Hydra runs on.
pub const MAX_CPUS: usize = 16;

/// Physical address of the local APIC's registers (the MADT's, usually 0xFEE0_0000).
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0xFEE0_0000);
/// Local APIC IDs of the usable processors, the boot processor's included.
static APIC_IDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
/// Physical address of the two start-up pages below 1 MiB (code, page table copy).
static TRAMPOLINE: AtomicU64 = AtomicU64::new(0);
/// CPUs running (the boot processor included).
static ONLINE: AtomicUsize = AtomicUsize::new(1);
/// Set by an AP when it has taken its start-up stack and data (the next may start).
static AP_STARTED: AtomicBool = AtomicBool::new(false);
/// The boot processor's control registers, which every AP copies.
static BSP_CR0: AtomicU64 = AtomicU64::new(0);
static BSP_CR4: AtomicU64 = AtomicU64::new(0);
/// Local APIC ID of each online CPU, by index (index 0: the boot processor).
static CPU_APIC: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];

// Local APIC registers
const LAPIC_ID: u64 = 0x20;
const LAPIC_SVR: u64 = 0xF0;
const LAPIC_ESR: u64 = 0x280;
const LAPIC_ICR_LOW: u64 = 0x300;
const LAPIC_ICR_HIGH: u64 = 0x310;

/// Number of CPUs online.
pub fn online() -> usize {
    ONLINE.load(Ordering::Acquire)
}

/// Number of usable CPUs the firmware describes (at least 1).
pub fn present() -> usize {
    APIC_IDS.lock().len().max(1)
}

fn lapic_read(reg: u64) -> u32 {
    unsafe { core::ptr::read_volatile((LAPIC_BASE.load(Ordering::Relaxed) + reg) as *const u32) }
}

fn lapic_write(reg: u64, v: u32) {
    unsafe { core::ptr::write_volatile((LAPIC_BASE.load(Ordering::Relaxed) + reg) as *mut u32, v) }
}

/// This CPU's local APIC ID.
pub fn apic_id() -> u32 {
    lapic_read(LAPIC_ID) >> 24
}

// ----------------------------------------------------------------------
// Discovery (boot services still running)
// ----------------------------------------------------------------------

fn sum_ok(p: *const u8, len: usize) -> bool {
    (0..len).fold(0u8, |s, i| s.wrapping_add(unsafe { *p.add(i) })) == 0
}

unsafe fn rd32(p: u64) -> u32 {
    core::ptr::read_unaligned(p as *const u32)
}

unsafe fn rd64(p: u64) -> u64 {
    core::ptr::read_unaligned(p as *const u64)
}

/// Reads the processors from the ACPI MADT and reserves the start-up pages. Called before
/// `ExitBootServices`.
pub fn discover() {
    let rsdp = uefi::system::with_config_table(|t| {
        t.iter()
            .find(|e| e.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
            .or_else(|| t.iter().find(|e| e.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID))
            .map(|e| e.address as u64)
    });
    let Some(rsdp) = rsdp else {
        crate::kprintln!("[smp] no ACPI tables: one CPU");
        return;
    };
    let mut ids = Vec::new();
    unsafe {
        if core::slice::from_raw_parts(rsdp as *const u8, 8) != b"RSD PTR " {
            return;
        }
        let revision = *((rsdp + 15) as *const u8);
        // The XSDT (64-bit entries), or the RSDT of ACPI 1
        let (sdt, entry) = if revision >= 2 && rd64(rsdp + 24) != 0 { (rd64(rsdp + 24), 8) } else { (rd32(rsdp + 16) as u64, 4) };
        let len = rd32(sdt + 4) as u64;
        let mut madt = 0;
        let mut at = sdt + 36;
        while at + entry <= sdt + len {
            let t = if entry == 8 { rd64(at) } else { rd32(at) as u64 };
            if core::slice::from_raw_parts(t as *const u8, 4) == b"APIC" {
                madt = t;
            }
            at += entry;
        }
        if madt == 0 || !sum_ok(madt as *const u8, rd32(madt + 4) as usize) {
            crate::kprintln!("[smp] no MADT: one CPU");
            return;
        }
        LAPIC_BASE.store(rd32(madt + 36) as u64, Ordering::Relaxed);
        let end = madt + rd32(madt + 4) as u64;
        let mut p = madt + 44;
        while p + 2 <= end {
            let (ty, len) = (*(p as *const u8), *((p + 1) as *const u8) as u64);
            if len < 2 {
                break;
            }
            match ty {
                // Processor local APIC: enabled, or online capable
                0 if rd32(p + 4) & 3 != 0 => ids.push(*((p + 3) as *const u8) as u32),
                // Processor local x2APIC
                9 if rd32(p + 8) & 3 != 0 => ids.push(rd32(p + 4)),
                // Local APIC address override
                5 => LAPIC_BASE.store(rd64(p + 4), Ordering::Relaxed),
                _ => {}
            }
            p += len;
        }
    }
    ids.truncate(MAX_CPUS);
    // Executable pages below 1 MiB for the start-up code (real mode runs there)
    if ids.len() > 1 {
        match uefi::boot::allocate_pages(uefi::boot::AllocateType::MaxAddress(0x9_F000), uefi::boot::MemoryType::LOADER_CODE, 2) {
            Ok(p) => TRAMPOLINE.store(p.as_ptr() as u64, Ordering::Relaxed),
            Err(_) => crate::kprintln!("[smp] no memory below 1 MiB for the start-up code: one CPU"),
        }
    }
    crate::kprintln!("[smp] {} CPU(s) in the MADT, local APIC at {:#x}", ids.len(), LAPIC_BASE.load(Ordering::Relaxed));
    *APIC_IDS.lock() = ids;
}

// ----------------------------------------------------------------------
// The start-up code
// ----------------------------------------------------------------------

core::arch::global_asm!(
    ".globl ap_tramp_start",
    ".globl ap_tramp_end",
    ".globl ap_cr3_low",
    ".globl ap_cr3_real",
    ".globl ap_stack",
    ".globl ap_cpu",
    ".globl ap_entry",
    ".balign 4096",
    ".code16",
    "ap_tramp_start:",
    "cli",
    "cld",
    "mov ax, cs",
    "mov ds, ax",
    "xor ebx, ebx",
    "mov bx, ax",
    "shl ebx, 4", // ebx: the trampoline's physical address
    "lea eax, [ebx + O_GDT]",
    "mov dword ptr [O_GDTR + 2], eax",
    "lea eax, [ebx + O_PM32]",
    "mov dword ptr [O_FAR32], eax",
    "lgdt [O_GDTR]",
    "mov eax, cr0",
    "or eax, 1",
    "mov cr0, eax",
    // jmp far dword [ap_far32] (o32 FF /5)
    ".byte 0x66, 0xFF, 0x2E",
    ".word ap_far32 - ap_tramp_start",
    ".code32",
    "ap_pm32:",
    "mov ax, 0x10",
    "mov ds, ax",
    "mov es, ax",
    "mov ss, ax",
    "mov fs, ax",
    "mov gs, ax",
    // PAE, OSFXSR, OSXMMEXCPT
    "mov eax, cr4",
    "or eax, 0x620",
    "mov cr4, eax",
    "mov eax, dword ptr [ebx + O_CR3_LOW]",
    "mov cr3, eax",
    // EFER: long mode, no-execute
    "mov ecx, 0xC0000080",
    "rdmsr",
    "or eax, 0x900",
    "wrmsr",
    // PG, WP, NE, MP, PE; not EM
    "mov eax, cr0",
    "or eax, 0x80010023",
    "and eax, 0xFFFFFFFB",
    "mov cr0, eax",
    "lea eax, [ebx + O_LM64]",
    "mov dword ptr [ebx + O_FAR64], eax",
    // jmp far dword [ebx + ap_far64] (FF /5, disp32)
    ".byte 0xFF, 0xAB",
    ".long ap_far64 - ap_tramp_start",
    ".code64",
    "ap_lm64:",
    "mov ax, 0x10",
    "mov ds, ax",
    "mov es, ax",
    "mov ss, ax",
    "mov rax, qword ptr [rip + ap_cr3_real]",
    "mov cr3, rax",
    "mov rsp, qword ptr [rip + ap_stack]",
    // ap_main(cpu): the Microsoft x64 convention of the UEFI target (first argument in
    // rcx, 32 bytes of shadow space)
    "mov rcx, qword ptr [rip + ap_cpu]",
    "mov rax, qword ptr [rip + ap_entry]",
    "sub rsp, 32",
    "call rax",
    "2:",
    "hlt",
    "jmp 2b",
    ".balign 16",
    "ap_gdt:",
    ".quad 0",
    ".quad 0x00CF9A000000FFFF", // 0x08: 32-bit code
    ".quad 0x00CF92000000FFFF", // 0x10: data
    ".quad 0x00AF9A000000FFFF", // 0x18: 64-bit code
    "ap_gdtr:",
    ".word 31",
    ".long 0",
    "ap_far32:",
    ".long 0",
    ".word 0x08",
    "ap_far64:",
    ".long 0",
    ".word 0x18",
    ".balign 8",
    "ap_cr3_low: .quad 0",
    "ap_cr3_real: .quad 0",
    "ap_stack: .quad 0",
    "ap_cpu: .quad 0",
    "ap_entry: .quad 0",
    "ap_tramp_end:",
    ".set O_GDT, ap_gdt - ap_tramp_start",
    ".set O_GDTR, ap_gdtr - ap_tramp_start",
    ".set O_PM32, ap_pm32 - ap_tramp_start",
    ".set O_FAR32, ap_far32 - ap_tramp_start",
    ".set O_CR3_LOW, ap_cr3_low - ap_tramp_start",
    ".set O_LM64, ap_lm64 - ap_tramp_start",
    ".set O_FAR64, ap_far64 - ap_tramp_start",
    ".text",
);

extern "C" {
    static ap_tramp_start: u8;
    static ap_tramp_end: u8;
    static ap_cr3_low: u8;
    static ap_cr3_real: u8;
    static ap_stack: u8;
    static ap_cpu: u8;
    static ap_entry: u8;
}

/// Offset of start-up symbol `sym` in the trampoline.
fn off(sym: &u8) -> u64 {
    sym as *const u8 as u64 - unsafe { &ap_tramp_start as *const u8 as u64 }
}

/// Busy-waits `ns` nanoseconds (the clock runs: interrupts are on).
fn delay_ns(ns: u64) {
    let end = crate::arch::pit::now_ns() + ns;
    while crate::arch::pit::now_ns() < end {
        core::hint::spin_loop();
    }
}

/// Sends an inter-processor interrupt (`icr`: the command word) to local APIC `apic`.
fn send_ipi(apic: u32, icr: u32) {
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_ICR_HIGH, apic << 24);
    lapic_write(LAPIC_ICR_LOW, icr);
    // Delivery status (bit 12) clears when the IPI was sent
    let end = crate::arch::pit::now_ns() + 10_000_000;
    while lapic_read(LAPIC_ICR_LOW) & (1 << 12) != 0 && crate::arch::pit::now_ns() < end {
        core::hint::spin_loop();
    }
}

/// Starts every other processor the MADT lists; each comes online and waits. Called by
/// the boot processor with interrupts on.
pub fn start_aps() {
    let tramp = TRAMPOLINE.load(Ordering::Relaxed);
    let ids = APIC_IDS.lock().clone();
    if tramp == 0 || ids.len() < 2 {
        return;
    }
    let me = apic_id();
    CPU_APIC[0].store(me, Ordering::Relaxed);
    let cr0 = x86_64::registers::control::Cr0::read_raw();
    let cr4 = x86_64::registers::control::Cr4::read_raw();
    BSP_CR0.store(cr0, Ordering::Relaxed);
    BSP_CR4.store(cr4, Ordering::Relaxed);
    let cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    unsafe {
        // The code, and a copy of the top-level page table below 4 GiB for the switch
        let len = off(&ap_tramp_end) as usize;
        core::ptr::copy_nonoverlapping(&ap_tramp_start as *const u8, tramp as *mut u8, len);
        core::ptr::copy_nonoverlapping(cr3 as *const u8, (tramp + 4096) as *mut u8, 4096);
        let put = |sym: &u8, v: u64| core::ptr::write_volatile((tramp + off(sym)) as *mut u64, v);
        put(&ap_cr3_low, tramp + 4096);
        put(&ap_cr3_real, cr3);
        put(&ap_entry, ap_main as *const () as u64);
    }
    let mut next = 1;
    for &id in ids.iter().filter(|&&i| i != me) {
        if next >= MAX_CPUS {
            break;
        }
        // Its stack (never freed: the CPU keeps it)
        let stack: &'static mut [u8] = alloc::vec![0u8; 64 * 1024].leak();
        let top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
        unsafe {
            core::ptr::write_volatile((tramp + off(&ap_stack)) as *mut u64, top);
            core::ptr::write_volatile((tramp + off(&ap_cpu)) as *mut u64, next as u64);
        }
        AP_STARTED.store(false, Ordering::SeqCst);
        CPU_APIC[next].store(id, Ordering::Relaxed);
        let vector = (tramp >> 12) as u32;
        send_ipi(id, 0x4500); // INIT
        delay_ns(10_000_000);
        send_ipi(id, 0x4600 | vector); // STARTUP
        delay_ns(200_000);
        if !AP_STARTED.load(Ordering::SeqCst) {
            send_ipi(id, 0x4600 | vector);
        }
        let end = crate::arch::pit::now_ns() + 500_000_000;
        while !AP_STARTED.load(Ordering::SeqCst) && crate::arch::pit::now_ns() < end {
            core::hint::spin_loop();
        }
        if AP_STARTED.load(Ordering::SeqCst) {
            next += 1;
        } else {
            CPU_APIC[next].store(u32::MAX, Ordering::Relaxed);
            crate::kprintln!("[smp] CPU with APIC id {} did not start", id);
        }
    }
    // Wait for the started ones to finish their set-up
    let end = crate::arch::pit::now_ns() + 500_000_000;
    while ONLINE.load(Ordering::Acquire) < next && crate::arch::pit::now_ns() < end {
        core::hint::spin_loop();
    }
    crate::kprintln!("[smp] {} CPU(s) online", ONLINE.load(Ordering::Acquire));
}

/// An application processor, in long mode on the kernel's page tables and its own stack.
extern "C" fn ap_main(cpu: u64) -> ! {
    // Its start-up data is no longer needed: the next CPU may start
    AP_STARTED.store(true, Ordering::SeqCst);
    let cpu = cpu as usize;
    unsafe {
        x86_64::registers::control::Cr4::write_raw(BSP_CR4.load(Ordering::Relaxed));
        x86_64::registers::control::Cr0::write_raw(BSP_CR0.load(Ordering::Relaxed));
    }
    crate::arch::gdt::load_for_ap(cpu);
    crate::arch::idt::load_on_this_cpu();
    crate::arch::syscall::init();
    // Local APIC on, spurious interrupts to vector 0xFF
    lapic_write(LAPIC_SVR, 0x1FF);
    ONLINE.fetch_add(1, Ordering::AcqRel);
    crate::kprintln!("[smp] CPU {} online (APIC id {})", cpu, apic_id());
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}
