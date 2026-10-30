#![no_std]
#![no_main]

extern crate alloc;

pub mod arch;
pub mod capability;
#[macro_use]
pub mod console;
pub mod fs;
pub mod ipc;
pub mod memory;
pub mod shell;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod video;
pub mod net;
pub mod compress;
pub mod pkg;
pub mod compat;


use core::panic::PanicInfo;
use uefi::prelude::*;
use uefi::proto::console::text::Color;
use x86_64::VirtAddr;

use capability::{table::CapabilityTable, CapType, Capability, Rights};
use ipc::{Endpoint, Message};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    console::set_color(Color::LightRed, Color::Black);
    println!("\n[!] KERNEL PANIC: {:?}", _info);
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    console::clear_screen();
    console::set_color(Color::LightCyan, Color::Black);
    println!("============================================================");
    println!("                HYDRA MICROKERNEL v0.1.0                     ");
    println!("     UNIX-like Distributed Cloud/Fog/Edge Operating System  ");
    println!("============================================================\n");

    // 1. GDT & TSS Setup
    console::set_color(Color::Yellow, Color::Black);
    println!("[*] Step 1: Initializing GDT, TSS & Ring 3 Segments...");
    arch::gdt::init();
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] GDT loaded successfully.");

    // 1b. IDT & Hardware Exception Gates Setup
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 1b: Initializing IDT & Exception Handling Gates...");
    arch::idt::init();
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] IDT loaded successfully (256 gates, double-fault IST stack attached).");

    // Test CPU exception dispatch with non-fatal breakpoint trap
    unsafe {
        core::arch::asm!("int3");
    }
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] CPU exception dispatch verified: resumed cleanly from #BP trap.");

    // 2. CPU State
    let cpu = arch::cpu::read_state();
    console::set_color(Color::White, Color::Black);
    println!("    - CR0: {:?}", cpu.cr0);
    println!("    - CR3 (Active PML4 Root): {:#x}", cpu.cr3_frame.as_u64());
    println!("    - CR4: {:?}", cpu.cr4);

    // 3. Memory Subsystem: UEFI Memory Map & Physical Frame Allocator
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 2: Discovering Memory & Initializing Frame Allocator...");
    memory::frame_allocator::init_memory_from_uefi();

    let (usable_mb, allocated_kb) = {
        let alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
        (
            alloc.total_usable_memory() / (1024 * 1024),
            alloc.allocated_memory() / 1024,
        )
    };
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] Physical Memory Manager Online:");
    println!("    - Total Usable RAM: {} MiB", usable_mb);
    println!("    - Allocated: {} KiB", allocated_kb);

    // Allocate a test physical frame
    let test_frame = {
        let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
        alloc.allocate_frame()
    };
    if let Some(frame) = test_frame {
        println!(
            "    - Allocated Test Frame: {:#x}",
            frame.start_address().as_u64()
        );
    }

    // 3b. Dynamic Kernel Heap Allocator Setup
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 2b: Initializing Dynamic Kernel Heap Allocator...");
    match memory::heap::init() {
        Ok(stats) => {
            console::set_color(Color::LightGreen, Color::Black);
            println!("[+] Kernel Heap Online:");
            println!("    - Start Address: {:#x}", stats.start_address);
            println!(
                "    - Total Size:    {} MiB ({} bytes)",
                stats.total_bytes / (1024 * 1024),
                stats.total_bytes
            );
            println!("    - Available:     {} MiB", stats.free_bytes / (1024 * 1024));

            if let Err(e) = memory::heap::self_test() {
                console::set_color(Color::LightRed, Color::Black);
                println!("[!] Heap Self-Test Failed: {}", e);
            } else {
                println!("    - Self-Test:     PASSED (Box, Vec, String, RAII drops verified)");
            }
        }
        Err(e) => {
            console::set_color(Color::LightRed, Color::Black);
            println!("[!] Failed to initialize kernel heap: {}", e);
        }
    }


    // 4. Virtual Memory: 4-Level Paging (PML4) & Autonomous Kernel Address Space
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 3: Initializing Autonomous 4-Level Paging (PML4)...");
    let active_space = memory::paging::AddressSpace::active();
    let sample_virt = VirtAddr::new(main as *const () as usize as u64);
    let sample_phys = unsafe { active_space.translate_addr(sample_virt) };
    console::set_color(Color::LightGreen, Color::Black);
    if let Some(phys) = sample_phys {
        println!(
            "[+] Firmware Boot Translation: VirtAddr {:#x} -> PhysAddr {:#x}",
            sample_virt.as_u64(),
            phys.as_u64()
        );
    }

    // Allocate Hydra's own PML4 table in conventional memory (owned by the OS)
    let kernel_space_res = {
        let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
        memory::paging::init_kernel_space(&mut alloc)
    };

    match kernel_space_res {
        Ok(pml4_phys) => {
            println!(
                "[+] Hydra Autonomous PML4 Root Initialized at PhysAddr {:#x}",
                pml4_phys.as_u64()
            );

            // Test dynamic page mapping & unmapping on Hydra's autonomous address space
            let mut guard = memory::paging::KERNEL_SPACE.lock();
            if let Some(ref mut space) = *guard {
                let test_map_frame = {
                    let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
                    alloc.allocate_frame()
                };

                if let Some(frame) = test_map_frame {
                    use x86_64::structures::paging::{Page, PageTableFlags};
                    let test_page = Page::containing_address(VirtAddr::new(0x0000_7000_0000_0000));
                    let map_res = unsafe {
                        let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
                        space.map_page(
                            test_page,
                            frame,
                            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                            &mut alloc,
                        )
                    };

                    if map_res.is_ok() {
                        let (mapped_frame, flags) = unsafe { space.translate_page(test_page) }.unwrap();
                        println!(
                            "[+] Dynamic Page Mapping: Page {:#x} -> Frame {:#x} (flags: {:?})",
                            test_page.start_address().as_u64(),
                            mapped_frame.start_address().as_u64(),
                            flags
                        );

                        let unmap_res = unsafe { space.unmap_page(test_page) };
                        if unmap_res.is_ok() {
                            println!("    - Dynamic Unmap & TLB Invalidation: PASSED");
                        }
                    }
                }
            }
        }
        Err(e) => {
            console::set_color(Color::LightRed, Color::Black);
            println!("[!] Failed to initialize autonomous PML4: {}", e);
        }
    }

    // 4b. Hardware Display Discovery: UEFI Graphics Output Protocol (GOP)
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 3b: Initializing UEFI GOP Framebuffer & Standalone Console...");
    match video::init_gop() {
        Ok(info) => {
            console::set_color(Color::LightGreen, Color::Black);
            println!("[+] Hardware Linear Framebuffer Online:");
            println!("    - Resolution:   {}x{} (32 bpp)", info.width, info.height);
            println!("    - Stride/Pitch: {} pixels/line ({} bytes)", info.stride, info.stride * 4);
            println!(
                "    - Pixel Format: {}",
                if info.is_bgr {
                    "BGR888 (Little-Endian)"
                } else {
                    "RGB888"
                }
            );
            println!(
                "    - Video RAM:    {:#x} ({} MiB)",
                info.base_ptr as u64,
                info.size / (1024 * 1024)
            );
            println!(
                "    - Text Matrix:  {} columns x {} rows (8x16 font)",
                info.text_cols, info.text_rows
            );
            println!("    - VMM Mapping:  Identity-mapped in Hydra Autonomous PML4");
        }
        Err(e) => {
            console::set_color(Color::Yellow, Color::Black);
            println!("[-] GOP not available: {} (fallback to UEFI text console)", e);
        }
    }

    // 5. Capability-Based Security Model
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 4: Initializing Task Capability Space...");

    let mut cap_table = CapabilityTable::new();
    let root_cap = Capability::new(
        CapType::AddressSpace {
            root_cr3: cpu.cr3_frame.as_u64(),
        },
        Rights::ALL,
    );
    let slot0 = cap_table.insert(root_cap).unwrap();
    let ep_cap = Capability::new(
        CapType::Endpoint { endpoint_id: 1 },
        Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::CALL.0),
    );
    let slot1 = cap_table.insert(ep_cap).unwrap();
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] Capability Table configured:");
    println!("    - Slot {}: CapType::AddressSpace with Rights::ALL", slot0);
    println!(
        "    - Slot {}: CapType::Endpoint (id=1) with READ|WRITE|CALL",
        slot1
    );

    // 6. Fast Capability-Mediated IPC Rendezvous
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 5: Testing Microkernel IPC Rendezvous...");
    let mut endpoint = Endpoint::new(1);
    let msg = Message::with_args(0x1001, [42, 1337, 0, 0]).with_cap(ep_cap);
    endpoint.send(msg).unwrap();
    console::set_color(Color::LightGreen, Color::Black);
    println!(
        "[+] IPC Message queued on Endpoint #{}: label={:#x}, args={:?}",
        endpoint.id(),
        msg.label,
        msg.args
    );

    if let Some(received) = endpoint.receive() {
        println!(
            "[+] IPC Message received from Endpoint #{}: label={:#x}, args={:?}",
            endpoint.id(),
            received.label,
            received.args
        );
    }

    // 7. ZFS Microkernel File Server Initialization
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 6: Initializing Storage Subsystem & ZFS File Server...");
    crate::arch::rtc::init();
    crate::arch::ata::init();
    crate::arch::mouse::init();
    net::init();
    fs::init_server();
    fs::ZfsClient::sync_boot_binaries();
    console::set_color(Color::LightGreen, Color::Black);
    println!(
        "[+] ZFS File Server Online (Endpoint #{:#x}):",
        fs::zfs::ENDPOINT_ZFS_SERVER
    );
    if let Ok((total_mb, alloc_kb, _, txg)) = fs::ZfsClient::pool_status() {
        println!(
            "    - Storage Pool: 'hydrapool' ({} MiB, {} MiB used, TXG #{}, Fletcher-4, CoW)",
            total_mb,
            alloc_kb / 1024,
            txg
        );
    }
    println!("    - Persistence : {}", if crate::arch::ata::is_drive_present() { "Active (Primary Master ATA Hard Disk)" } else { "In-Memory RAM Fallback" });
    println!("    - Datasets: hydrapool/root (/), hydrapool/bin (/bin), hydrapool/home (/root)");

    // 8. Preemptive Multitasking & Scheduler Initialization
    console::set_color(Color::Yellow, Color::Black);
    println!("\n[*] Step 7: Initializing Multitasking Scheduler...");
    let active_cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    task::init(active_cr3);
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] Multitasking Subsystem Online:");
    println!("    - Main Thread registered: Task #0 ('shell')");
    println!("    - Background Idle Thread: Task #1 ('idle', priority 0)");
    println!("    - Round-Robin Timeslice : {} ms (100 Hz timer tick preemption)",
        task::scheduler::DEFAULT_TIMESLICE_TICKS * 10
    );

    console::set_color(Color::LightCyan, Color::Black);
    println!("\n============================================================");
    println!(" [+] HYDRA MICROKERNEL PHASE 1 & 2 SUBSYSTEMS OPERATIONAL!  ");
    println!("============================================================");

    // Hand over execution to the interactive microkernel shell
    shell::run();
}
