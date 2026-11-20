# Group 32 (arch + memory): what the host tests cannot run

The host build (`tests/host-t32`) compiles every file of `src/arch` and `src/memory`
through the kernel's own `mod.rs`. Hardware access goes to fakes:

- `shim/x86_64`: port I/O (a scripted bus per test thread), CR0/CR2/CR3/CR4, `cli`/`sti`/
  `hlt`, TLB flushes, `lgdt`/`lidt`/`ltr`;
- `src/host.rs`: the kernel's own `asm!` and firmware calls, which have a
  `#[cfg(not(target_os = "uefi"))]` twin in the kernel file (`gs` per-CPU words, MSRs,
  debug and segment registers, CR0.WP, CR3/INVPCID, XSETBV, CPUID, the TSC in `pit`, MMIO
  of the local APIC and the VT-d units, the vmmouse backdoor, the ACPI RSDP, UEFI load
  options, low pages, the boot partition). The kernel (target `x86_64-unknown-uefi`) never
  compiles the twins; the `#[cfg(target_os = "uefi")]` originals are not compiled on the
  host, so they do not count as lines there.

What remains below is code the host build compiles but cannot (or must not) run. It is
kept thin: the logic around it was moved into testable functions.

| File | Function / lines | Why |
|---|---|---|
| `src/arch/mod.rs`, `src/memory/mod.rs` | whole file | module declarations only: no code (the coverage tool lists them as "not compiled") |
| `src/arch/idt.rs` | `global_asm!` trap stubs (`common_trap_handler`, `asm_trap_*`, `asm_irq_*`, `asm_direct_switch`) | the first and last instructions of a trap; not instrumented code (assembly) |
| `src/arch/idt.rs` | `hydra_exception_handler`, `hydra_direct_switch_handler` (one line each) | the `extern "C"` entries the assembly calls; their bodies (`exception_handler`, `direct_switch_handler`) are tested |
| `src/arch/idt.rs` | `kernel_fault_stack`, the walk of the current task's kernel stack (`top >> 47 == 0x1_FFFF` branch) and the stack dump | needs a higher-half kernel stack; host addresses are low, so only the register line runs |
| `src/arch/idt.rs` | `print_cpu_dump`, the scan for code addresses | runs, but finds nothing (no kernel image near the anchor on the host) |
| `src/arch/syscall.rs` | `global_asm!` entry (`asm_syscall_entry`, `asm_syscall32_ignore`), `hydra_syscall_dispatcher` (one line) | assembly entry and its `extern "C"` wrapper; the body (`syscall_dispatch`) is tested |
| `src/arch/smp.rs` | `global_asm!` start-up trampoline, `ap_main`, `start_lapic_timer` | real-mode/long-mode bring-up of a second processor and its timer: runs only on a started AP. `start_aps` itself is tested up to the APs not answering |
| `src/arch/relocate.rs` | `go_high` after the stack allocation: the CR3 switch, the relocation through the high alias, the jump | switches the real CPU's page tables and jumps; the host twin of the stack allocation returns `None`, so `go_high` returns right before (everything up to there is tested on the test program's own PE image) |
| `src/arch/boot_services.rs` | `take_hardware_ownership` after the framebuffer check | `ExitBootServices` and the whole takeover sequence (GDT/IDT/CR3 switch, direct map on, PIC/PIT/keyboard/syscall MSRs, APs, drivers); each step is tested in its own file. Its range computation is `kernel_low_ranges` (tested) |
| `src/memory/heap.rs` | `init_direct`, the UEFI `allocate_pages` fallback in `init` | firmware memory map and boot services (higher-half boot only) |
| `src/memory/frame_allocator.rs` | `init_memory_from_uefi` | firmware memory map |
| `src/arch/power.rs` | the last line of `power_off`/`reboot` (`uefi::runtime::reset`) | runs, and panics on the host (no runtime services): the tests catch that |
| `src/arch/pit.rs` | `calibrate_tsc`'s give-up after 50 million polls | would poll the fake port 50 million times (seconds, and the port log) |

## boot_services.rs below 70 %

`take_hardware_ownership` is the takeover sequence itself (about 90 of the file's 122
counted lines): after the framebuffer check it calls `ExitBootServices`, then switches the
real CPU's tables and turns on the direct map, which the test process cannot survive. Its
pieces are tested where they live (smp/iommu/pcid discovery, gdt, idt, paging, pcid, pic,
pit, rtc, keyboard, mouse, syscall, vm self-tests), and its only computation was moved
into `kernel_low_ranges` (tested). Testable lines of the file: all covered.
