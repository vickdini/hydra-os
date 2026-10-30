use spin::Mutex;
use uefi::mem::memory_map::MemoryMap;
use uefi::proto::console::text::Color;
use x86_64::registers::control::Cr3;

use crate::console::{clear_screen, enable_standalone_video, set_color, set_hardware_mode};
use crate::println;

/// Statistics captured during hardware takeover.
#[derive(Debug, Clone, Copy)]
pub struct HardwareTakeoverStats {
    pub memory_map_entries: usize,
    pub gdt_code_selector: u16,
    pub gdt_data_selector: u16,
    pub tss_selector: u16,
    pub active_cr3_pml4: u64,
    pub framebuffer_virt: u64,
}

static TAKEOVER_DONE: Mutex<bool> = Mutex::new(false);

/// Checks if hardware ownership has already been taken.
pub fn is_hardware_takeover_complete() -> bool {
    *TAKEOVER_DONE.lock()
}

/// Takes full hardware ownership from UEFI firmware:
/// 1. Activates autonomous linear framebuffer console (VideoConsole).
/// 2. Enables standalone hardware mode for console I/O and PS/2 keyboard.
/// 3. Calls `uefi::boot::exit_boot_services` to terminate UEFI firmware control.
/// 4. Loads Hydra's 64-bit GDT into GDTR and reloads CS (0x08), DS/ES/FS/GS/SS (0x10).
/// 5. Loads Hydra's TSS into TR (0x28) and enables IST 1 on IDT Double Fault.
/// 6. Switches CPU CR3 to Hydra's autonomous 4-level PML4 paging table.
/// 7. Updates IDT entries with Hydra's kernel code selector.
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

    // 3. Terminate UEFI Boot Services
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    let entries_count = memory_map.entries().count();

    // 3b. Task switches and syscalls save x87/SSE state with FXSAVE only. Disable XSAVE
    // so user code (glibc's CPU feature detection) never enables AVX registers that would
    // not be preserved.
    unsafe {
        use x86_64::registers::control::{Cr4, Cr4Flags};
        Cr4::update(|flags| flags.remove(Cr4Flags::OSXSAVE));
    }

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
    crate::task::update_cr3(cr3_frame);

    // 7. Initialize and remap legacy 8259 dual-PIC (Master: IRQ 0..7 -> 32..39, Slave: IRQ 8..15 -> 40..47)
    crate::arch::pic::init();

    // 8. Initialize 8254 PIT timer to 100 Hz (10ms tick interval on IRQ 0)
    crate::arch::pit::init(100);
    crate::arch::rtc::init();

    // 8b. Initialize 8042 PS/2 Keyboard Controller for IRQ 1 interrupts
    crate::arch::keyboard::init();

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

    // 10. Automatically initialize and configure network adapter via DHCP
    if crate::net::e1000::is_present() {
        set_color(Color::Yellow, Color::Black);
        crate::print!("[*] Network: Autonegotiating carrier link and DHCP lease... ");
        for _ in 0..100 {
            if crate::net::e1000::is_link_up() {
                break;
            }
            crate::arch::pit::sleep_ms(10);
        }

        if crate::net::e1000::is_link_up() {
            match crate::net::dhcp_acquire() {
                Ok(lease) => {
                    set_color(Color::LightGreen, Color::Black);
                    println!(
                        "ONLINE ({}.{}.{}.{}, Gateway {}.{}.{}.{}, DNS {}.{}.{}.{})",
                        lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3],
                        lease.router[0], lease.router[1], lease.router[2], lease.router[3],
                        lease.dns_server[0], lease.dns_server[1], lease.dns_server[2], lease.dns_server[3]
                    );
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("Deferred ({})", e);
                }
            }
        } else {
            set_color(Color::Yellow, Color::Black);
            println!("Link Down (No carrier)");
        }
        println!();
    }

    Ok(HardwareTakeoverStats {
        memory_map_entries: entries_count,
        gdt_code_selector: selectors.kernel_code_selector.0,
        gdt_data_selector: selectors.kernel_data_selector.0,
        tss_selector: selectors.tss_selector.0,
        active_cr3_pml4: cr3_frame,
        framebuffer_virt: fb_virt,
    })
}
