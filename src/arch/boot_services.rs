//! # Architecture Layer: UEFI Boot Services Exit & Hardware Takeover
//!
//! Orchestrates the one-way transition from UEFI firmware boot services to autonomous
//! Hydra OS microkernel hardware control.
//!
//! ## Architectural Role & Design Rationale
//!
//! When Hydra OS is launched by the UEFI firmware loader, the CPU executes with firmware-owned
//! descriptor tables (GDT/IDT), firmware page tables (`CR3`), and firmware-managed timer/console
//! protocols. To become a true standalone operating system, Hydra OS must call `ExitBootServices`
//! to reclaim all boot-service memory and install its own architectural tables and device drivers.
//!
//! `take_hardware_ownership` performs this transition atomically:
//! 1. Switches console output to the autonomous GOP framebuffer (`VideoConsole`) and `COM1` serial port.
//! 2. Terminates UEFI Boot Services via `uefi::boot::exit_boot_services`.
//! 3. Loads Hydra's 64-bit GDT, TSS (with IST 1 for Double Faults), IDT, and 4-level PML4 page table (`CR3`).
//! 4. Remaps the dual-8259 PIC, starts the 100 Hz 8254 PIT timer, initializes the CMOS RTC, 8042 PS/2 keyboard, and `SYSCALL` MSRs.
//! 5. Enables CPU interrupts (`sti`) and brings up the Intel E1000 network stack via DHCP if present.
//!
//! ## Key Types & Interfaces
//!
//! - `HardwareTakeoverStats`: Diagnostic snapshot of descriptor selectors, `CR3`, and memory map size captured during takeover.
//! - `take_hardware_ownership`: Executes the irreversible UEFI exit and bare-metal initialization sequence.
//! - `is_hardware_takeover_complete`: Queries whether the kernel has already exited UEFI Boot Services.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (Kernel supervisor mode).
//! - **Hardware Interaction**: `CR3`, `CR4`, `GDTR`, `IDTR`, `TR`, `EFER`/`STAR`/`LSTAR`/`FMASK` MSRs, 8259 PIC, 8254 PIT, CMOS RTC, 8042 PS/2, and E1000 NIC.
//! - **Concurrency**: Guarded by the static `TAKEOVER_DONE` [`spin::Mutex`] to guarantee single execution.

use spin::Mutex;
use uefi::mem::memory_map::MemoryMap;
use uefi::proto::console::text::Color;
use x86_64::registers::control::Cr3;

use crate::console::{clear_screen, enable_standalone_video, set_color, set_hardware_mode};
use crate::println;

/// Statistics and architectural register values captured during bare-metal hardware takeover.
///
/// # Concurrency & Thread Safety
/// Immutable `Copy` value returned once upon completion of `take_hardware_ownership`.
#[derive(Debug, Clone, Copy)]
pub struct HardwareTakeoverStats {
    /// Total number of UEFI memory map descriptors returned by `ExitBootServices`.
    pub memory_map_entries: usize,
    /// Loaded 64-bit kernel code segment selector (`CS`, typically `0x08`).
    pub gdt_code_selector: u16,
    /// Loaded kernel data/stack segment selector (`DS`/`SS`, typically `0x10`).
    pub gdt_data_selector: u16,
    /// Loaded Task State Segment selector (`TR`, `0x40`).
    pub tss_selector: u16,
    /// Physical address of the active 4-level PML4 root page table in `CR3`.
    pub active_cr3_pml4: u64,
    /// Virtual base address of the linear GOP video framebuffer.
    pub framebuffer_virt: u64,
}

/// Ensures `take_hardware_ownership` can only be executed once per boot.
static TAKEOVER_DONE: Mutex<bool> = Mutex::new(false);

/// Checks if hardware ownership has already been taken from UEFI firmware.
///
/// # Returns
///
/// `true` if `ExitBootServices` and bare-metal initialization have completed, `false` otherwise.
pub fn is_hardware_takeover_complete() -> bool {
    *TAKEOVER_DONE.lock()
}

/// The physical ranges the kernel keeps reachable in every address space's low 512 GiB
/// (step 3a of the takeover): every non-free region of the final memory map (in the
/// higher half, below 2 GiB only device memory), the heap when it is not in the direct
/// map, always [2 GiB, 4 GiB), the 64 KiB around the boot stack `sp`, and the
/// framebuffer `fb`. `entries` are (type, start, pages).
pub fn kernel_low_ranges(
    entries: impl Iterator<Item = (uefi::boot::MemoryType, u64, u64)>,
    high: bool,
    heap: Option<(u64, u64)>,
    sp: u64,
    fb: Option<u64>,
) -> alloc::vec::Vec<(u64, u64)> {
    use uefi::boot::MemoryType as T;
    let mut ranges: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for (ty, start, pages) in entries {
        let device = matches!(ty, T::MMIO | T::MMIO_PORT_SPACE);
        if ty != T::CONVENTIONAL && !(high && !device && start < (2 << 30)) {
            ranges.push((start, start + pages * 4096));
        }
    }
    if let Some(h) = heap {
        ranges.push(h);
    }
    ranges.push((2 << 30, 4 << 30));
    ranges.push((sp & !0xFFFF, (sp | 0xFFFF) + 1));
    if let Some(fb) = fb {
        ranges.push((fb, fb + 1));
    }
    ranges
}

/// Takes full hardware ownership from UEFI firmware and initializes all bare-metal kernel subsystems.
///
/// Performs the following ordered sequence:
/// 1. Activates autonomous linear framebuffer console (`VideoConsole`).
/// 2. Enables standalone hardware mode for console I/O and PS/2 keyboard.
/// 3. Calls `uefi::boot::exit_boot_services` to terminate UEFI firmware control.
/// 4. Loads Hydra's 64-bit GDT into `GDTR` and reloads `CS` (`0x08`), `DS`/`ES`/`FS`/`GS`/`SS` (`0x10`).
/// 5. Loads Hydra's TSS into `TR` (`0x40`) and enables IST 1 on IDT Double Fault.
/// 6. Switches CPU `CR3` to Hydra's autonomous 4-level PML4 paging table.
/// 7. Updates IDT entries with Hydra's kernel code selector, initializes PIC/PIT/RTC/PS2/SYSCALL, and enables interrupts.
///
/// # Returns
///
/// * `Ok(HardwareTakeoverStats)` - Summary of active selectors, `CR3`, and memory map entries.
/// * `Err(&'static str)` - If takeover was already performed or the GOP framebuffer is unavailable.
///
/// # Errors
///
/// - Returns `Err("Hardware takeover (ExitBootServices) has already been executed.")` on duplicate invocation.
/// - Returns `Err("Hardware GOP framebuffer driver not available.")` if video initialization failed.
pub fn take_hardware_ownership() -> Result<HardwareTakeoverStats, &'static str> {
    let mut done = TAKEOVER_DONE.lock();
    if *done {
        return Err("Hardware takeover (ExitBootServices) has already been executed.");
    }

    // 1. Ensure GOP Linear Framebuffer driver is initialized
    let fb_virt = if let Some(info) = crate::video::get_video_info() {
        info.base_ptr as u64
    } else {
        return Err("Hardware GOP framebuffer driver not available.");
    };

    // 2. Route all console printing to VideoConsole
    enable_standalone_video(true);
    set_hardware_mode(true);

    // 2b. The processors (ACPI MADT) and the start-up pages for the others
    crate::arch::crumb::step("takeover: console on the framebuffer; reading the MADT"); // wave11 GH
    crate::arch::smp::discover();
    crate::arch::crumb::step("takeover: MADT read; DMAR next"); // wave11 GH
    // 2c. The IOMMU's ACPI table (DMAR) and boot options
    crate::arch::iommu::discover();
    // 2d. PCID's off switches
    crate::arch::pcid::discover();
    crate::arch::crumb::step("takeover: DMAR and PCID read; FADT next"); // wave11 GH
    // 2e. ACPI power-off and reset values (wave11 GH)
    crate::arch::power::discover();

    crate::arch::crumb::end("takeover: ExitBootServices next (last breadcrumb)"); // wave11 GH
    // 3. Terminate UEFI Boot Services
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    let entries_count = memory_map.entries().count();

    // 3a. Which GiB slots of the low 512 GiB the kernel keeps in every address space: all
    // it reaches at physical addresses (anything but free RAM in the final memory map:
    // its image, firmware data, ACPI, devices; its heap and boot stack), and always
    // [2 GiB, 4 GiB) (image, PCI hole, APICs). Programs get the rest.
    {
        // In the higher half (arch::relocate) the image, its stack, the heap and the page
        // tables are reached at high addresses, and the firmware's own memory (runtime
        // services, ACPI tables, reserved RAM) only with the kernel's tables loaded
        // (power::firmware_call): below 2 GiB, the low window, only device memory counts
        let high = crate::arch::relocate::image_phys().is_some();
        let heap = (!crate::memory::heap::in_direct_map()).then(crate::memory::heap::range);
        let sp: u64;
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
        let fb = crate::video::get_video_info().map(|info| info.base_ptr as u64);
        let ranges = kernel_low_ranges(memory_map.entries().map(|d| (d.ty, d.phys_start, d.page_count)), high, heap, sp, fb);
        crate::memory::vm::init_low_layout(&ranges);
        let kept: alloc::vec::Vec<usize> = (1..512).filter(|&i| crate::memory::vm::kernel_low_slot(i)).collect();
        crate::kprintln!(
            "[vm] programs' low window [0x10000, {:#x}); kernel keeps GiB slots {:?} (heap at {:#x}, image at {:#x} -> {:#x})",
            crate::memory::vm::low_user_end(),
            kept,
            crate::memory::heap::range().0,
            crate::arch::relocate::image_phys().map_or(0, |i| i.0),
            crate::arch::relocate::KERNEL_BASE
        );
    }

    // 3b. XSAVE and the AVX registers where the CPU has them (task switches, system calls
    // and signals then save and restore them); otherwise FXSAVE and no AVX
    crate::arch::idt::enable_xsave(true);

    // 4. Load Hydra's GDT and reload segments
    crate::arch::gdt::load_and_switch();
    let selectors = crate::arch::gdt::get_selectors();

    // 5. Update IDT with kernel CS (0x08) and enable IST 1 for Double Fault
    crate::arch::idt::enable_double_fault_ist();
    crate::arch::idt::reload_with_kernel_cs(selectors.kernel_code_selector.0);

    // 6. Switch CR3 to Hydra's autonomous PML4 table
    if let Some(ref space) = *crate::memory::paging::KERNEL_SPACE.lock() {
        unsafe {
            space.switch();
        }
    }
    let cr3_frame = Cr3::read().0.start_address().as_u64();
    // Tagged TLB entries (before the other processors start: they copy this CPU's CR4)
    crate::arch::pcid::init();
    crate::task::update_cr3(cr3_frame);
    crate::memory::paging::KERNEL_PML4.store(cr3_frame, core::sync::atomic::Ordering::SeqCst);
    // Hydra's tables hold the direct map of physical memory: use it from now on
    crate::memory::frame_allocator::enable_direct_map();
    // Global kernel pages (wave 4): the kernel half's TLB entries survive CR3 writes
    crate::arch::pcid::enable_global();

    // 7. Initialize and remap legacy 8259 dual-PIC (Master: IRQ 0..7 -> 32..39, Slave: IRQ 8..15 -> 40..47)
    crate::arch::pic::init();

    // 8. Initialize 8254 PIT timer to 100 Hz (10ms tick interval on IRQ 0)
    crate::arch::pit::init(100);
    crate::arch::rtc::init();

    // 8b. Initialize 8042 PS/2 Keyboard Controller for IRQ 1 interrupts
    crate::arch::keyboard::init();
    crate::arch::mouse::enable_irq();

    // 8c. Initialize fast x86_64 hardware system call MSRs (EFER, STAR, LSTAR, FMASK)
    crate::arch::syscall::init();

    *done = true;

    // Clear display buffer and scrollback history so takeover begins on a clean screen
    crate::console::clear_scrollback();
    clear_screen();

    // Display takeover banner on standalone framebuffer
    set_color(Color::LightGreen, Color::Black);
    println!("\n============================================================");
    println!(" [+] HYDRA MICROKERNEL: FULL HARDWARE TAKEOVER COMPLETE!    ");
    println!("============================================================");
    println!("  - UEFI Boot Services : TERMINATED (ExitBootServices invoked)");
    println!("  - Memory Map Entries : {} descriptors captured", entries_count);
    println!("  - GDT & TSS Status   : Hydra Ring 0 CS={:#x}, DS={:#x}, TR={:#x}",
        selectors.kernel_code_selector.0,
        selectors.kernel_data_selector.0,
        selectors.tss_selector.0
    );
    println!("  - System Calls (MSR) : Hardware SYSCALL/SYSRET (LSTAR/STAR configured)");
    println!("  - Interrupts & IDT   : Hydra 256 gates (Double Fault on TSS IST1)");
    println!("  - IRQ & Hardware     : 8259 PIC Remapped [32..47], PIT Timer @ 100 Hz (STI active)");
    println!("  - Virtual Memory     : Autonomous PML4 Root at PhysAddr {:#x}", cr3_frame);
    println!("  - Display & Input    : 1024x768 Linear Framebuffer & 8042 PS/2 Keyboard (IRQ 1)");
    println!("============================================================\n");

    // 9. Enable CPU hardware interrupts (sti) after banner rendering completes
    x86_64::instructions::interrupts::enable();
    // 9a. PCID's self-test (one CPU yet): stale TLB entries must never be used
    match crate::memory::vm::tlb_self_test() {
        Ok(s) => crate::kprintln!("[pcid] self-test {}", s),
        Err(e) => {
            crate::kprintln!("[pcid] SELF-TEST FAILED: {}", e);
            crate::arch::pcid::disable("its boot self-test failed");
        }
    }
    // 9a'. Global kernel pages' self-test: kept across a CR3 switch, removed by shootdowns
    match crate::memory::vm::global_self_test() {
        Ok(s) => crate::kprintln!("[pge] self-test {}", s),
        Err(e) => {
            crate::kprintln!("[pge] SELF-TEST FAILED: {}", e);
            crate::arch::pcid::disable_global("its boot self-test failed");
        }
    }
    // 9b. The other processors come online (and wait)
    crate::arch::smp::start_aps();
    // Driver programs run from here on (the takeover lock is released first: they run
    // while their registration is awaited)
    drop(done);
    // DMA remapping on before any driver programs its device
    crate::arch::iommu::init();
    crate::task::supervisor::start_all();

    // 10. The network: net-server (started above) brings the card up and runs DHCP;
    // report it once the lease is there
    crate::net::init();
    println!();
    crate::fs::client::start_txg_sync();

    Ok(HardwareTakeoverStats {
        memory_map_entries: entries_count,
        gdt_code_selector: selectors.kernel_code_selector.0,
        gdt_data_selector: selectors.kernel_data_selector.0,
        tss_selector: selectors.tss_selector.0,
        active_cr3_pml4: cr3_frame,
        framebuffer_virt: fb_virt,
    })
}
