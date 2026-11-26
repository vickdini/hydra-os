//! # Hydra OS: Microkernel Entry Point & Bootstrap Orchestrator
//!
//! Native 64-bit UEFI operating system kernel entry point, subsystem bootstrap sequence,
//! and bare-metal panic handler.
//!
//! ## Architectural Role & Design Rationale
//!
//! Unlike legacy BIOS kernels that start in 16-bit real mode and require multi-stage assembly
//! trampolines to enter 64-bit long mode, Hydra OS executes directly as a native PE32+ UEFI
//! application (`BOOTX64.EFI`). This root module orchestrates the sequential bring-up of all
//! microkernel subsystems—from CPU segmentation and exception handling to physical/virtual memory,
//! capability tables, IPC endpoints, the OpenZFS file server, and preemptive multitasking—before
//! handing control to the interactive microkernel shell.
//!
//! ## Key Types & Interfaces
//!
//! - [`arch`]: Hardware abstraction layer (GDT, IDT, PIC, PIT, RTC, PS/2, PCI, ATA, SYSCALL).
//! - [`memory`]: Physical frame allocator, 8 MiB kernel heap, 4-level PML4 paging, and per-process VM.
//! - [`capability`] & [`ipc`]: Object-capability security model (CSpace) and message-passing endpoints.
//! - [`fs`] & [`net`]: OpenZFS copy-on-write file server, POSIX file descriptors, and Intel E1000 TCP/IP stack.
//! - [`task`] & [`compat`]: Preemptive round-robin scheduler, ELF64 loader, and Linux ABI compatibility layer.
//!
//! ## Hardware & Dependency Context
//!
//! - CPU Privilege Level: Ring 0 (Supervisor Mode) at boot; spawns Ring 3 userland tasks.
//! - Hardware Interaction: UEFI System Table at boot, transitioning to autonomous hardware control.
//! - Concurrency: Single-core bootstrap transitioning into 100 Hz preemptive multitasking.
//!
//! ## Dataflow & Architectural Diagram
//!
//! ```text
//! +---------------+     +---------------+     +------------------+     +-----------------+
//! | UEFI Firmware | --> | GDT / IDT /   | --> | Frame Allocator, | --> | CSpace & IPC    |
//! | (BOOTX64.EFI) |     | CPU State     |     | Heap & PML4 VMM  |     | Rendezvous      |
//! +---------------+     +---------------+     +------------------+     +-----------------+
//!                                                                               |
//! +---------------+     +---------------+     +------------------+              v
//! | Interactive   | <-- | Preemptive    | <-- | ZFS File Server  | <------------+
//! | Shell & Linux |     | Scheduler     |     | & E1000 Network  |
//! +---------------+     +---------------+     +------------------+
//! ```

#![no_std]
#![no_main]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

extern crate alloc;

// The kernel's modules. The host tests (`tests/host-t34`) compile this file as a module of
// their own crate, which brings its own (real files and stubs): there it has none of these.
#[cfg(not(target_os = "uefi"))]
use crate::{admin, arch, console, fs, memory, task, video};

/// Hardware architecture abstraction layer for `x86_64` CPUs and legacy PC peripherals.
#[cfg(target_os = "uefi")]
pub mod admin; // group 4: the admin interface for the Ring 3 shell
#[cfg(target_os = "uefi")]
pub mod arch;
// wave9 GP2: memcpy/memset fast for small copies (hydra-rt's, one source)
#[path = "../userland/drivers/hydra-rt/src/memfast.rs"]
mod memfast;
/// Object-capability security model, access rights bitmasks, and per-task CSpace tables.
#[cfg(target_os = "uefi")]
pub mod capability;
/// Thread-safe formatted text output over UEFI SimpleTextOutput and the GOP framebuffer console.
#[macro_use]
#[cfg(target_os = "uefi")]
pub mod console;
/// Virtual File System (VFS) descriptors, anonymous pipes, and the OpenZFS microkernel file server.
#[cfg(target_os = "uefi")]
pub mod fs;
/// Inter-Process Communication (IPC) message structures and bounded wait-queue endpoints.
#[cfg(target_os = "uefi")]
pub mod ipc;
/// Wave 3: forwarding Linux system calls to the ring-3 Linux server.
#[cfg(target_os = "uefi")]
pub mod lx;
/// Wave 5: personalities (programs of other systems: FreeBSD, macOS), the hook.
#[cfg(target_os = "uefi")]
pub mod personality;
/// Physical frame allocation, dynamic kernel heap, 4-level PML4 paging, and process virtual memory.
#[cfg(target_os = "uefi")]
pub mod memory;
/// The emergency prompt: the tiny in-kernel console for when user space is broken (the console
/// shell is the ring-3 `hydra-shell`, started by `admin::boot`).
#[cfg(target_os = "uefi")]
pub mod shell;
/// Sleep-capable kernel synchronization primitives (wait queues, mutexes, semaphores, condvars, channels).
#[cfg(target_os = "uefi")]
pub mod sync;
/// System call ABI definitions, statistics, and userland wrapper routines.
#[cfg(target_os = "uefi")]
pub mod syscall;
/// Preemptive round-robin task scheduler, Task Control Blocks (TCB), and ELF64 binary loader.
#[cfg(target_os = "uefi")]
pub mod task;
/// The emergency text console on the UEFI GOP framebuffer, its bitmap font, and the boot splash.
#[cfg(target_os = "uefi")]
pub mod video;
/// Intel 82540EM (e1000) Gigabit Ethernet driver and full TCP/UDP/IPv4/DNS/DHCP/HTTP network stack.
#[cfg(target_os = "uefi")]
pub mod net;
/// Lossless DEFLATE (RFC 1951) and GZIP (RFC 1952) decompression routines for package extraction.
#[cfg(target_os = "uefi")]
pub mod compress;
/// Archive parsers (`ar`, `tar`, `.deb`) and Debian/Ubuntu root filesystem provisioning.
#[cfg(target_os = "uefi")]
pub mod pkg;
/// Operating system personality and binary compatibility layers (Linux `x86_64` ABI emulation).
#[cfg(target_os = "uefi")]
pub mod compat;


use core::panic::PanicInfo;
use uefi::prelude::*;
use uefi::proto::console::text::Color;
use x86_64::VirtAddr;

use crate::capability::{table::CapabilityTable, CapType, Capability, Rights};
use crate::ipc::{Endpoint, Message};

/// Bare-metal kernel panic handler invoked on unrecoverable runtime faults or assertions.
///
/// Formats the panic location and payload to the active console in bright red, masks all
/// maskable CPU hardware interrupts (`CLI`), and enters an infinite low-power halt loop (`HLT`).
///
/// # Arguments
///
/// * `_info` - Diagnostic metadata describing the source file, line number, and panic message.
///
/// # Returns
///
/// This function never returns (`!`). It disables interrupts and halts the CPU indefinitely.
#[cfg_attr(target_os = "uefi", panic_handler)]
fn panic(_info: &PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    report_panic(_info);
    crate::arch::bootlog::after_panic(); // wave11 GH: restarts to save the log (stick, disk)
    loop {
        x86_64::instructions::hlt();
    }
}

/// What a kernel panic shows: the message on COM1 first (no locks and no allocation: the
/// panic may be an allocation failure, or happen while the console is locked) with the
/// heap's state, then on the console, taken back from the boot logo or a desktop session.
///
/// # Arguments
///
/// * `info` - The panic (its location and message).
pub fn report_panic(info: &(impl core::fmt::Display + core::fmt::Debug)) {
    {
        use core::fmt::Write;
        let mut com1 = crate::arch::raw_serial::RawSerial;
        let _ = write!(com1, "\n[!] KERNEL PANIC: {}\n", info);
        if let Some(h) = crate::memory::heap::try_stats() {
            let _ = write!(com1, "[!] heap: {} KiB used, {} KiB free of {} KiB\n", h.used_bytes / 1024, h.free_bytes / 1024, h.total_bytes / 1024);
        }
    }
    video::splash::panic_reveal();
    console::set_color(Color::LightRed, Color::Black);
    println!("\n[!] KERNEL PANIC: {:?}", info);
}

/// Boot step 3b: reports the framebuffer GOP gave (`info`) and puts the boot logo on it.
pub fn framebuffer_online(info: &video::VideoModeInfo) {
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
    video::splash::start();
}

/// Native UEFI application entry point (`efi_main`) and kernel bootstrap orchestrator.
///
/// Executes the staged initialization sequence for the Hydra Microkernel:
/// 1. Initializes the Global Descriptor Table (GDT), Task State Segment (TSS), and Interrupt Descriptor Table (IDT).
/// 2. Discovers physical RAM from the UEFI memory map and initializes the physical frame allocator and 8 MiB heap.
/// 3. Constructs Hydra's autonomous 4-level PML4 page table and initializes the UEFI GOP linear framebuffer.
/// 4. Verifies the capability table (CSpace) and IPC endpoint subsystem.
/// 5. Initializes the RTC, ATA disk driver, PS/2 mouse, E1000 NIC, and OpenZFS storage pool (`hydrapool`).
/// 6. Starts the preemptive round-robin task scheduler and launches the interactive microkernel shell.
///
/// # Returns
///
/// Returns [`Status::SUCCESS`] if the shell ever terminates normally (in practice, the kernel runs until poweroff).
#[cfg_attr(target_os = "uefi", entry)]
fn main() -> Status {
    // wave11 GG: execute-disable on the boot processor before any page table is built (the
    // APs set it in their start-up code; the NUC's firmware leaves it off: NUC run 12)
    arch::cpu::BSP_FIRMWARE_EFER.store(unsafe { arch::syscall::rdmsr(0xC000_0080) }, core::sync::atomic::Ordering::Relaxed);
    // wave11 GH: debug words for QEMU, whose firmware turns NXE on and uses NX itself:
    // "nxe=fw-off nxe=nofix" reproduces the NUC without the fix (the boot processor builds
    // its entries without NX and runs with NXE off once the firmware is gone; the APs set it)
    if arch::bootopts::early_word(b"nxe=fw-off") && arch::bootopts::early_word(b"nxe=nofix") {
        memory::vm::NX_SIM_OFF.store(true, core::sync::atomic::Ordering::SeqCst);
    } else {
        arch::cpu::enable_nx();
    }
    // First of all, before anything stores a pointer: the image moves to the higher half
    // (out of the low addresses programs need, wherever the firmware loaded it)
    arch::relocate::go_high(boot);
    boot()
}

/// The kernel's boot sequence, in the higher half (see [`arch::relocate`]).
pub fn boot() -> ! {
    arch::boottime::mark("entry (UEFI helpers)");
    uefi::helpers::init().unwrap();
    // wave11 GH: the boot log's memory (a crashed start's log is kept for its file), then
    // the boot words and the start menu, before anything reads them
    arch::bootlog::early();
    arch::bootopts::init();
    // The Hydra logo instead of boot messages, unless the boot entry asks for them
    video::splash::decide();
    // The boot processor's per-CPU data, and the kernel lock it holds while in the kernel
    arch::boottime::mark("banner");
    arch::percpu::init_this_cpu(0);
    arch::smp::bkl_enter();

    console::clear_screen();
    console::set_color(Color::LightCyan, Color::Black);
    println!("============================================================");
    println!("                HYDRA MICROKERNEL v0.1.0                     ");
    println!("     UNIX-like Distributed Cloud/Fog/Edge Operating System  ");
    println!("============================================================\n");

    // 1. GDT & TSS Setup
    console::set_color(Color::Yellow, Color::Black);
    arch::boottime::mark("GDT, IDT");
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
    x86_64::instructions::interrupts::int3();
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
    // The heap in the higher half comes from the firmware's free memory, before the frame
    // allocator takes what is left (memory::heap::init_direct)
    if arch::relocate::image_phys().is_some() {
        let _ = memory::heap::init();
    }
    arch::boottime::mark("memory map, frame allocator");
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
    arch::boottime::mark("heap");
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
    arch::boottime::mark("paging");
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
    arch::boottime::mark("framebuffer console");
    println!("\n[*] Step 3b: Initializing UEFI GOP Framebuffer & Standalone Console...");
    match video::init_gop() {
        Ok(info) => framebuffer_online(&info),
        Err(e) => {
            console::set_color(Color::Yellow, Color::Black);
            println!("[-] GOP not available: {} (fallback to UEFI text console)", e);
        }
    }

    // 5. Capability-Based Security Model
    console::set_color(Color::Yellow, Color::Black);
    arch::boottime::mark("capabilities, IPC test");
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

    // Where the image was loaded, to symbolize addresses with a linker map (as the watchdog's
    // `anchor`)
    crate::kprintln!("[boot] anchor (hydra_syscall_dispatcher) = {:#x}", crate::arch::syscall::hydra_syscall_dispatcher as *const () as usize);

    // 7. Devices the kernel keeps, and what the boot volume provides (it is unreachable
    //    after the hardware takeover)
    console::set_color(Color::Yellow, Color::Black);
    println!("
[*] Step 6: Initializing Devices & Reading the Boot Volume...");
    crate::arch::rtc::init();
    crate::arch::mouse::init();
    arch::boottime::mark("reading the boot files");
    arch::bootdisk::detect();
    arch::bootlog::prepare_file(); // wave11 GH: \logs\bootNNN.txt on the EFI partition
    let boot_files = fs::ZfsClient::read_boot_files();
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] Boot volume: {} files staged for the pool", boot_files.len());

    // 8. Preemptive Multitasking & Scheduler Initialization
    console::set_color(Color::Yellow, Color::Black);
    println!("
[*] Step 7: Initializing Multitasking Scheduler...");
    arch::boottime::mark("scheduler");
    let active_cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    task::init(active_cr3);
    console::set_color(Color::LightGreen, Color::Black);
    println!("[+] Multitasking Subsystem Online:");
    println!("    - Main Thread registered: Task #0 ('shell')");
    println!("    - Background Idle Thread: Task #1 ('idle', priority 0)");
    println!("    - Round-Robin Timeslice : {} ms (100 Hz timer tick preemption)",
        task::scheduler::DEFAULT_TIMESLICE_TICKS * 10
    );
    arch::boottime::mark("supervisor");
    task::supervisor_init();

    // Group 4: the boot options of the console (the emergency prompt), read while the
    // firmware's boot volume is still reachable
    crate::admin::boot::discover();

    // 9. Hardware takeover: the kernel leaves the firmware behind and the driver programs
    //    (the disk driver among them) start in Ring 3
    arch::boottime::mark("hardware takeover (CPUs, drivers, network)");
    if let Err(e) = crate::arch::boot_services::take_hardware_ownership() {
        console::set_color(Color::LightRed, Color::Black);
        println!("[!] Hardware takeover failed: {}", e);
    }

    // 10. ZFS file server, on the disk driver
    console::set_color(Color::Yellow, Color::Black);
    println!("[*] Step 8: Initializing the ZFS File Server...");
    arch::boottime::mark("ZFS file server");
    fs::init_server();
    arch::boottime::mark("importing the boot files");
    fs::ZfsClient::import_boot_files(boot_files);
    fs::firstboot::import_into_pool(); // Group G: installer first-boot settings
    arch::boottime::mark("disks");
    fs::blockdev::scan();
    // wave11 GH: the boot log's writer (the boot disk is known now), and a restart that
    // saves the log when the pool's disk never came
    arch::bootlog::start_writer();
    arch::bootlog::check_pool();
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
    println!("    - Persistence : {}", if fs::zfs::disk_info().is_some() { "Active (disk, through the Ring 3 ata-driver)" } else { "In-Memory RAM Fallback" });
    println!("    - Datasets: hydrapool/root (/), hydrapool/bin (/bin), hydrapool/home (/root)");

    console::set_color(Color::LightCyan, Color::Black);
    println!("
============================================================");
    println!(" [+] HYDRA MICROKERNEL PHASE 1 & 2 SUBSYSTEMS OPERATIONAL!  ");
    println!("============================================================");

    // Hand over execution to the interactive microkernel shell
    arch::boottime::mark("shell");
    arch::boottime::report();
    admin::boot::run();
}
