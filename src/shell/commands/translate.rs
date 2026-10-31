//! # Shell Commands: Virtual Address Translation & Dynamic Paging (`translate`, `map`, `unmap`)
//!
//! Provides diagnostic commands to inspect 4-level PML4 page walks, dynamically map
//! virtual pages to physical frames, and unmap pages with TLB invalidation.

use uefi::proto::console::text::Color;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame};
use x86_64::{PhysAddr, VirtAddr};

use crate::console::set_color;
use crate::memory;
use crate::shell::command::{parse_hex, Command};
use crate::shell::state::ShellState;

/// Shell command walking the 4-level PML4 paging table to translate virtual addresses.
pub struct TranslateCommand;

impl Command for TranslateCommand {
    fn name(&self) -> &'static str {
        "translate"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["v2p"]
    }

    fn description(&self) -> &'static str {
        "Walk PML4 4-level paging to translate a virtual address to physical and show flags"
    }

    fn usage(&self) -> &'static str {
        "translate <virtual_address_hex> (e.g. translate 0x400000)"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let s = match args.first() {
            Some(val) => *val,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: {}", self.usage());
                state.last_status = 1;
                return;
            }
        };

        let addr_u64 = match parse_hex(s) {
            Some(val) => val,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid hexadecimal address: '{}'", s);
                state.last_status = 1;
                return;
            }
        };

        let virt = VirtAddr::new(addr_u64);
        let address_space = memory::paging::AddressSpace::active();
        let page = Page::containing_address(virt);
        let page_info = unsafe { address_space.translate_page(page) };
        let phys_opt = unsafe { address_space.translate_addr(virt) };

        set_color(Color::LightCyan, Color::Black);
        println!("\n4-Level PML4 Page Table Walk for {:#x}:", virt.as_u64());
        set_color(Color::White, Color::Black);
        println!("  PML4 Index (L4):    {}", u16::from(virt.p4_index()));
        println!("  PDPT Index (L3):    {}", u16::from(virt.p3_index()));
        println!("  PD Index   (L2):    {}", u16::from(virt.p2_index()));
        println!("  PT Index   (L1):    {}", u16::from(virt.p1_index()));
        println!("  Page Offset:        {:#x}", virt.as_u64() & 0xFFF);

        match phys_opt {
            Some(phys) => {
                set_color(Color::LightGreen, Color::Black);
                println!("  Status:             MAPPED");
                println!("  Physical Target:    {:#x}", phys.as_u64());

                if let Some((frame, flags)) = page_info {
                    println!("  Base Frame:         {:#x}", frame.start_address().as_u64());
                    print!("  Protection Flags:   ");
                    if flags.contains(PageTableFlags::PRESENT) {
                        print!("[PRESENT] ");
                    }
                    if flags.contains(PageTableFlags::WRITABLE) {
                        print!("[WRITABLE] ");
                    } else {
                        print!("[READ-ONLY] ");
                    }
                    if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                        print!("[USER/RING-3] ");
                    } else {
                        print!("[SUPERVISOR/RING-0] ");
                    }
                    if flags.contains(PageTableFlags::NO_EXECUTE) {
                        print!("[NO-EXECUTE] ");
                    } else {
                        print!("[EXECUTABLE] ");
                    }
                    println!();
                }
                println!();
                state.last_status = 0;
            }
            None => {
                set_color(Color::Yellow, Color::Black);
                println!("  Status:             NOT MAPPED (Page Fault on access)\n");
                state.last_status = 1;
            }
        }
    }
}

/// Shell command dynamically mapping a virtual page to a physical frame.
pub struct MapCommand;

impl Command for MapCommand {
    fn name(&self) -> &'static str {
        "map"
    }

    fn description(&self) -> &'static str {
        "Map a 4 KiB virtual page to a physical frame with specified flags"
    }

    fn usage(&self) -> &'static str {
        "map <virt_hex> <phys_hex> [ro | rw | user | nx]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.len() < 2 {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            state.last_status = 1;
            return;
        }

        let virt_u64 = match parse_hex(args[0]) {
            Some(v) => v,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid virtual address: '{}'", args[0]);
                state.last_status = 1;
                return;
            }
        };

        let phys_u64 = match parse_hex(args[1]) {
            Some(p) => p,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid physical address: '{}'", args[1]);
                state.last_status = 1;
                return;
            }
        };

        let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if let Some(&perm) = args.get(2) {
            match perm {
                "ro" => flags = PageTableFlags::PRESENT,
                "rw" => flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                "user" => {
                    flags = PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE;
                }
                "nx" => {
                    flags = PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE;
                }
                _ => {}
            }
        }

        let page = Page::containing_address(VirtAddr::new(virt_u64));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys_u64));

        let mut guard = memory::paging::KERNEL_SPACE.lock();
        let space = match guard.as_mut() {
            Some(s) => s,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error: Kernel address space not initialized");
                state.last_status = 1;
                return;
            }
        };

        let res = unsafe {
            let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
            space.map_page(page, frame, flags, &mut alloc)
        };

        match res {
            Ok(()) => {
                set_color(Color::LightGreen, Color::Black);
                println!(
                    "[+] Successfully mapped Page {:#x} -> Frame {:#x} in Hydra PML4 (flags: {:?})",
                    page.start_address().as_u64(),
                    frame.start_address().as_u64(),
                    flags
                );
                state.last_status = 0;
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to map page: {}", e);
                state.last_status = 1;
            }
        }
    }
}

/// Shell command unmapping a virtual page and invalidating the CPU TLB entry.
pub struct UnmapCommand;

impl Command for UnmapCommand {
    fn name(&self) -> &'static str {
        "unmap"
    }

    fn description(&self) -> &'static str {
        "Unmap a 4 KiB virtual page and flush the CPU TLB"
    }

    fn usage(&self) -> &'static str {
        "unmap <virt_hex>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let s = match args.first() {
            Some(v) => *v,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: {}", self.usage());
                state.last_status = 1;
                return;
            }
        };

        let virt_u64 = match parse_hex(s) {
            Some(v) => v,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid virtual address: '{}'", s);
                state.last_status = 1;
                return;
            }
        };

        let page = Page::containing_address(VirtAddr::new(virt_u64));
        let mut guard = memory::paging::KERNEL_SPACE.lock();
        let space = match guard.as_mut() {
            Some(s) => s,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error: Kernel address space not initialized");
                state.last_status = 1;
                return;
            }
        };

        let res = unsafe { space.unmap_page(page) };

        match res {
            Ok(prev_frame) => {
                set_color(Color::LightGreen, Color::Black);
                println!(
                    "[+] Successfully unmapped Page {:#x} (previously mapped to Frame {:#x})",
                    page.start_address().as_u64(),
                    prev_frame.start_address().as_u64()
                );
                state.last_status = 0;
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to unmap page: {}", e);
                state.last_status = 1;
            }
        }
    }
}
