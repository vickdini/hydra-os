//! # Shell Commands: Physical & Heap Memory Diagnostics (`mem`, `alloc`, `heap`)
//!
//! Provides commands to inspect frame allocator statistics, test on-demand frame allocation,
//! and display dynamic kernel heap utilization.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::memory;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command inspecting physical and virtual memory metrics.
pub struct MemCommand;

impl Command for MemCommand {
    fn name(&self) -> &'static str {
        "mem"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["memory"]
    }

    fn description(&self) -> &'static str {
        "Show physical memory allocator and dynamic heap statistics"
    }

    fn usage(&self) -> &'static str {
        "mem"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        let alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
        let total_bytes = alloc.total_usable_memory();
        let alloc_bytes = alloc.allocated_memory();
        let free_bytes = alloc.free_memory();

        set_color(Color::LightCyan, Color::Black);
        println!("\nPhysical Memory Manager Statistics:");
        set_color(Color::White, Color::Black);
        println!("  Total Usable RAM:   {} bytes ({} MiB)", total_bytes, total_bytes / (1024 * 1024));
        println!("  Allocated Frames:   {} bytes ({} KiB, {} frames)",
            alloc_bytes, alloc_bytes / 1024, alloc_bytes / memory::frame_allocator::PAGE_SIZE);
        println!("  Free Memory:        {} bytes ({} MiB)", free_bytes, free_bytes / (1024 * 1024));
        println!("  Base Page Size:     {} bytes (4 KiB)", memory::frame_allocator::PAGE_SIZE);

        let heap_stats = memory::heap::stats();
        set_color(Color::LightCyan, Color::Black);
        println!("\nDynamic Kernel Heap Allocator:");
        set_color(Color::White, Color::Black);
        if heap_stats.is_initialized {
            println!("  Heap Status:        ONLINE");
            println!("  Start Address:      {:#x}", heap_stats.start_address);
            println!("  Total Heap Size:    {} bytes ({} MiB)",
                heap_stats.total_bytes, heap_stats.total_bytes / (1024 * 1024));
            println!("  Used Heap Memory:   {} bytes ({} KiB)",
                heap_stats.used_bytes, heap_stats.used_bytes / 1024);
            println!("  Free Heap Memory:   {} bytes ({} KiB)",
                heap_stats.free_bytes, heap_stats.free_bytes / 1024);
        } else {
            println!("  Heap Status:        OFFLINE (not initialized)");
        }
        println!();
    }
}

/// Shell command allocating a physical 4 KiB frame on demand.
pub struct AllocCommand;

impl Command for AllocCommand {
    fn name(&self) -> &'static str {
        "alloc"
    }

    fn description(&self) -> &'static str {
        "Allocate a physical 4 KiB memory frame on demand"
    }

    fn usage(&self) -> &'static str {
        "alloc"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        let frame_opt = {
            let mut alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
            alloc.allocate_frame()
        };

        match frame_opt {
            Some(frame) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Successfully allocated 4 KiB frame at physical address: {:#x}",
                    frame.start_address().as_u64());
            }
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error: Out of Physical Memory (OOM).");
            }
        }
    }
}

/// Shell command reporting dynamic kernel heap allocation metrics.
pub struct HeapCommand;

impl Command for HeapCommand {
    fn name(&self) -> &'static str {
        "heap"
    }

    fn description(&self) -> &'static str {
        "Inspect or test the dynamic kernel heap allocator"
    }

    fn usage(&self) -> &'static str {
        "heap [stats | test]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let subcmd = args.get(0).copied().unwrap_or("stats");

        match subcmd {
            "test" => {
                set_color(Color::LightCyan, Color::Black);
                println!("[*] Running dynamic heap allocation self-test suite...");
                match memory::heap::self_test() {
                    Ok(()) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Heap self-test PASSED:");
                        println!("    - Box<u64> heap allocation & dereference verified");
                        println!("    - Vec<usize> dynamic buffer reallocation (1,000 items) verified");
                        println!("    - alloc::format! dynamic string verified");
                        println!("    - RAII drop cleanup verified without memory leaks");
                        state.last_status = 0;
                    }
                    Err(err) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] Heap self-test FAILED: {}", err);
                        state.last_status = 1;
                    }
                }
            }
            "stats" | _ => {
                let stats = memory::heap::stats();
                set_color(Color::LightCyan, Color::Black);
                println!("\nDynamic Kernel Heap Statistics:");
                set_color(Color::White, Color::Black);
                if stats.is_initialized {
                    println!("  Status:             ONLINE");
                    println!("  Base Physical/Virt: {:#x}", stats.start_address);
                    println!("  Total Size:         {} bytes ({} MiB)",
                        stats.total_bytes, stats.total_bytes / (1024 * 1024));
                    println!("  Used Memory:        {} bytes ({} KiB)",
                        stats.used_bytes, stats.used_bytes / 1024);
                    println!("  Free Memory:        {} bytes ({} KiB)",
                        stats.free_bytes, stats.free_bytes / 1024);
                    let usage_pct = if stats.total_bytes > 0 {
                        (stats.used_bytes * 100) / stats.total_bytes
                    } else {
                        0
                    };
                    println!("  Heap Utilization:   {}%\n", usage_pct);
                    state.last_status = 0;
                } else {
                    println!("  Status:             OFFLINE\n");
                    state.last_status = 1;
                }
            }
        }
    }
}

