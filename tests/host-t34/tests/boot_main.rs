//! `src/main.rs`: the boot sequence (its order and its reports, every subsystem a stub) and
//! the panic report.

mod common;
use common::*;

/// Runs the kernel's boot until the console shell is started (the boot never returns).
fn boot() -> (Vec<String>, String) {
    fake::with(|s| {
        s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec());
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.log.iter().any(|l| l.starts_with("spawn_native hydra-shell")) {
                panic!("booted");
            }
        }));
    });
    expect_panic("booted", || {
        k::kmain::boot();
    });
    (fake::take_log(), fake::take_out())
}

fn position(log: &[String], what: &str) -> usize {
    log.iter().position(|l| l == what).unwrap_or_else(|| panic!("{:?} not in {:#?}", what, log))
}

#[test]
fn the_boot_sequence_in_order() {
    let _g = setup();
    fake::with(|s| {
        s.image_phys = Some(0x100_0000);
        s.frames_left = 10;
        s.pool = Some((4096, 2048, 100, 33));
        s.disk = Some((1 << 20, true, true, "QEMU".into()));
        s.boot_files.insert("hydra/x".into());
    });
    let (log, out) = boot();
    let steps = [
        "mark entry (UEFI helpers)",
        "mark banner",
        "percpu::init_this_cpu 0",
        "smp::bkl_enter",
        "mark GDT, IDT",
        "gdt::init",
        "idt::init",
        "mark memory map, frame allocator",
        "frame_allocator::init_memory_from_uefi",
        "mark heap",
        "mark paging",
        "init_kernel_space",
        "map_page 0x700000000000",
        "unmap_page 0x700000000000",
        "mark framebuffer console",
        "mark capabilities, IPC test",
        "rtc::init",
        "mouse::init",
        "mark reading the boot files",
        "bootdisk::detect",
        "read_boot_files",
        "mark scheduler",
        "task::init 0x12345000",
        "mark supervisor",
        "task::supervisor_init",
        "personality_init",
        "mark hardware takeover (CPUs, drivers, network)",
        "take_hardware_ownership",
        "mark ZFS file server",
        "fs::init_server",
        "mark importing the boot files",
        "import_boot_files 1",
        "firstboot::import_into_pool",
        "mark disks",
        "blockdev::scan",
        "mark shell",
        "boottime::report",
    ];
    let pos: Vec<usize> = steps.iter().map(|s| position(&log, s)).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "out of order: {:#?}", log);
    // The heap comes up from the firmware's memory first when the image was relocated
    assert_eq!(log.iter().filter(|l| *l == "heap::init").count(), 2);
    for want in [
        "                HYDRA MICROKERNEL v0.1.0                     ",
        "[+] GDT loaded successfully.",
        "[+] CPU exception dispatch verified: resumed cleanly from #BP trap.",
        "    - CR3 (Active PML4 Root): 0x12345000",
        "    - Total Usable RAM: 512 MiB",
        "    - Allocated: 65536 KiB",
        "    - Allocated Test Frame: 0x101000",
        "    - Total Size:    8 MiB (8388608 bytes)",
        "    - Self-Test:     PASSED",
        "[+] Hydra Autonomous PML4 Root Initialized at PhysAddr 0x200000",
        "[+] Dynamic Page Mapping: Page 0x700000000000 -> Frame 0x102000",
        "    - Dynamic Unmap & TLB Invalidation: PASSED",
        "[-] GOP not available: Failed to find GraphicsOutput protocol handle (fallback to UEFI text console)",
        "    - Slot 0: CapType::AddressSpace with Rights::ALL",
        "    - Slot 1: CapType::Endpoint (id=1) with READ|WRITE|CALL",
        "[+] IPC Message queued on Endpoint #1: label=0x1001, args=[42, 1337, 0, 0]",
        "[+] IPC Message received from Endpoint #1: label=0x1001, args=[42, 1337, 0, 0]",
        "[+] Boot volume: 1 files staged for the pool",
        "    - Round-Robin Timeslice : 20 ms",
        "    - Storage Pool: 'hydrapool' (4096 MiB, 2 MiB used, TXG #33, Fletcher-4, CoW)",
        "    - Persistence : Active (disk, through the Ring 3 ata-driver)",
        " [+] HYDRA MICROKERNEL PHASE 1 & 2 SUBSYSTEMS OPERATIONAL!  ",
        "[*] Hydra shell (the desktop was not started",
    ] {
        assert!(out.contains(want), "{:?} not in the boot output:\n{}", want, out);
    }
    // The load anchor goes to the kernel log
    assert!(fake::take_klog().contains("[boot] anchor (hydra_syscall_dispatcher) = 0x"));
}

#[test]
fn boot_reports_failures_and_goes_on() {
    let _g = setup();
    fake::with(|s| {
        s.heap_init_fail = Some("no memory for the heap");
        s.kernel_space_fail = Some("no frame for the PML4");
        s.takeover_fail = Some("ExitBootServices failed");
        s.heap_test_fail = Some("never reached");
    });
    let (log, out) = boot();
    // Not relocated: one heap set-up only
    assert_eq!(log.iter().filter(|l| *l == "heap::init").count(), 1);
    assert!(out.contains("[!] Failed to initialize kernel heap: no memory for the heap"));
    assert!(!out.contains("Allocated Test Frame"));
    assert!(out.contains("[!] Failed to initialize autonomous PML4: no frame for the PML4"));
    assert!(out.contains("[!] Hardware takeover failed: ExitBootServices failed"));
    assert!(out.contains("    - Persistence : In-Memory RAM Fallback"));
    assert!(!out.contains("Storage Pool"));
    assert!(position(&log, "take_hardware_ownership") < position(&log, "fs::init_server"));
}

#[test]
fn boot_with_a_failing_heap_test_and_no_frames() {
    let _g = setup();
    fake::with(|s| {
        s.heap_test_fail = Some("Vec mismatch");
        s.frames_left = 0;
    });
    let (log, out) = boot();
    assert!(out.contains("[!] Heap Self-Test Failed: Vec mismatch"));
    // The page table exists but there is no frame to test a mapping with
    assert!(out.contains("[+] Hydra Autonomous PML4 Root Initialized"));
    assert!(!log.iter().any(|l| l.starts_with("map_page")));
}

#[test]
fn the_firmware_translation_of_the_kernel() {
    let _g = setup();
    fake::with(|s| s.translate = Some((0x7000_0000, 0x7000_0000, x86_64::structures::paging::PageTableFlags::PRESENT)));
    let (_, out) = boot();
    assert!(out.contains("[+] Firmware Boot Translation: VirtAddr 0x"));
    assert!(out.contains("-> PhysAddr 0x7000"));
}

#[test]
fn the_panic_report() {
    let _g = setup();
    let fb = video(80, 32);
    k::video::splash::decide();
    k::video::splash::start();
    assert!(fb.iter().any(|&b| b != 0), "the logo shows");
    k::kmain::report_panic(&"page fault at 0xdead");
    // COM1 first, with the heap's state
    assert_eq!(fake::with(|s| s.serial.clone()), "\n[!] KERNEL PANIC: page fault at 0xdead\n[!] heap: 1024 KiB used, 7168 KiB free of 8192 KiB\n");
    // Then the console, over the boot logo, in light red
    assert!(!k::video::splash::is_active());
    assert_eq!(k::console::CONSOLE.lock().current_attr, 0x0C);
    assert_eq!(fake::take_out(), "\n[!] KERNEL PANIC: \"page fault at 0xdead\"\n");
    // The logo made way for the console's (empty, black) screen
    assert!(fb.iter().all(|&b| b == 0));
    // Without a heap: no heap line
    fake::with(|s| {
        s.serial.clear();
        s.heap_uninit = true;
    });
    k::kmain::report_panic(&"double fault");
    assert_eq!(fake::with(|s| s.serial.clone()), "\n[!] KERNEL PANIC: double fault\n");
}

#[test]
fn the_framebuffer_report() {
    let _g = setup();
    let mem: &'static mut [u8] = Box::leak(vec![0u8; 3 << 20].into_boxed_slice());
    let info = k::video::gop::mode_info_for(mem.as_mut_ptr(), 3 << 20, 64, 48, 72, uefi::proto::console::gop::PixelFormat::Bgr);
    k::video::gop::install(info);
    k::video::splash::decide();
    k::kmain::framebuffer_online(&info);
    let out = fake::take_out();
    assert!(out.starts_with("[+] Hardware Linear Framebuffer Online:\n    - Resolution:   64x48 (32 bpp)\n    - Stride/Pitch: 72 pixels/line (288 bytes)\n    - Pixel Format: BGR888 (Little-Endian)\n"), "{}", out);
    assert!(out.contains("(3 MiB)\n    - Text Matrix:  8 columns x 3 rows (8x16 font)\n    - VMM Mapping:  Identity-mapped in Hydra Autonomous PML4\n"));
    // The boot logo goes up on it
    assert!(k::video::splash::is_active());
    k::video::splash::compositor_took();
    let info = k::video::gop::mode_info_for(mem.as_mut_ptr(), 1, 64, 48, 64, uefi::proto::console::gop::PixelFormat::Rgb);
    k::kmain::framebuffer_online(&info);
    assert!(fake::take_out().contains("    - Pixel Format: RGB888\n"));
}
