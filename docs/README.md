# Hydra OS - Codebase Documentation Index

Welcome to the technical documentation for **Hydra OS**. Every source code file in the repository is documented with real-world analogies, conceptual explanations, architectural diagrams, and API breakdowns designed to be accessible to anyone with general programming knowledge.

---

## 🗺️ Documentation Directory Map

```
docs/
├── README.md                      # This Index
├── DOCUMENTATION_STANDARD.md      # Rustdoc-compatible source code documentation standard
├── build.md                       # Build automation script (build.rs)
└── src/
    ├── main.md                    # Kernel entry point & bootstrap orchestrator (src/main.rs)
    ├── console.md                 # Thread-safe console & formatting macros (src/console.rs)
    ├── vfs.md                     # Unix File Descriptors, Pipes, Syscalls & Pipelines (src/fs/)
    ├── zfs.md                     # Microkernel ZFS File Server & SPA CoW (src/fs/zfs/)
    ├── arch/
    │   ├── mod.md                 # Architecture-specific module root (src/arch/mod.rs)
    │   ├── boot_services.md       # Hardware takeover & ExitBootServices (src/arch/boot_services.rs)
    │   ├── gdt.md                 # Global Descriptor Table, TSS & Rings (src/arch/gdt.rs)
    │   ├── idt.md                 # Interrupt Descriptor Table & Exception Gates (src/arch/idt.rs)
    │   ├── cpu.md                 # Control registers & CPU diagnostics (src/arch/cpu.rs)
    │   └── x86_64/
    │       └── boot.md            # Legacy BIOS boot assembly (header.asm, main.asm, main64.asm)
    ├── memory/
    │   ├── mod.md                 # Memory management module root (src/memory/mod.rs)
    │   ├── frame_allocator.md     # Physical memory manager & 4 KiB frames (src/memory/frame_allocator.rs)
    │   ├── heap.md                # Dynamic kernel heap allocator & alloc crate (src/memory/heap.rs)
    │   └── paging.md              # Virtual memory & 4-level PML4 translation (src/memory/paging.rs)
    ├── capability/
    │   ├── mod.md                 # Capability types & Rights bitflags (src/capability/mod.rs)
    │   └── table.md               # Task capability table & CSpace (src/capability/table.rs)
    ├── video.md                   # Hardware GOP display driver & framebuffer console (src/video/)
    ├── shell.md                   # Interactive microkernel shell & command REPL (src/shell.rs)
    └── ipc/
        ├── mod.md                 # IPC subsystem root (src/ipc/mod.rs)
        ├── message.md             # Fast register payload & transferred caps (src/ipc/message.rs)
        └── endpoint.md            # Message rendezvous channels (src/ipc/endpoint.rs)
```

---

## 📚 Module Reference Table

| Subsystem | Source File | Documentation | Key Concepts & Analogies |
| :--- | :--- | :--- | :--- |
| **Boot & Main** | [`src/main.rs`](file:///d:/os/src/main.rs) | [docs/src/main.md](file:///d:/os/docs/src/main.md) | Entry point, boot sequence, hardware diagnostics, and panic handler. |
| **Console I/O** | [`src/console.rs`](file:///d:/os/src/console.rs) | [docs/src/console.md](file:///d:/os/docs/src/console.md) | Thread-safe `print!` / `println!` macros, keyboard input, screen formatting. |
| **Video & GOP** | [`src/video/`](file:///d:/os/src/video) | [docs/src/video.md](file:///d:/os/docs/src/video.md) | UEFI GOP linear framebuffer, 8x16 bitmap font, and standalone graphical console. |
| **Interactive Shell**| [`src/shell.rs`](file:///d:/os/src/shell.rs) | [docs/src/shell.md](file:///d:/os/docs/src/shell.md) | Command REPL, real-time memory/CPU inspection, CSpace manipulation, IPC testing. |
| **GDT & TSS** | [`src/arch/gdt.rs`](file:///d:/os/src/arch/gdt.rs) | [docs/src/arch/gdt.md](file:///d:/os/docs/src/arch/gdt.md) | Ring 0 / Ring 3 privilege levels, Task State Segment, double-fault stack. |
| **IDT & Traps** | [`src/arch/idt.rs`](file:///d:/os/src/arch/idt.rs) | [docs/src/arch/idt.md](file:///d:/os/docs/src/arch/idt.md) | 256-gate IDT, assembly exception trampolines, IST double fault isolation, #BP/#PF dispatchers. |
| **Hardware Takeover** | [`src/arch/boot_services.rs`](file:///d:/os/src/arch/boot_services.rs) | [docs/src/arch/boot_services.md](file:///d:/os/docs/src/arch/boot_services.md) | ExitBootServices, GDT/TSS switch, autonomous CR3 PML4, and PS/2 keyboard takeover. |
| **CPU Control** | [`src/arch/cpu.rs`](file:///d:/os/src/arch/cpu.rs) | [docs/src/arch/cpu.md](file:///d:/os/docs/src/arch/cpu.md) | Control registers (`CR0`, `CR2`, `CR3`, `CR4`), paging roots. |
| **Arch Root** | [`src/arch/mod.rs`](file:///d:/os/src/arch/mod.rs) | [docs/src/arch/mod.md](file:///d:/os/docs/src/arch/mod.md) | Architecture abstraction layer for hardware independence. |
| **Physical Memory**| [`src/memory/frame_allocator.rs`](file:///d:/os/src/memory/frame_allocator.rs) | [docs/src/memory/frame_allocator.md](file:///d:/os/docs/src/memory/frame_allocator.md) | UEFI memory map parsing, 4 KiB frame allocator ("parking lot attendant"). |
| **Dynamic Heap** | [`src/memory/heap.rs`](file:///d:/os/src/memory/heap.rs) | [docs/src/memory/heap.md](file:///d:/os/docs/src/memory/heap.md) | Dynamic kernel heap allocator, `#[global_allocator]`, `Box`/`Vec`/`String` support. |
| **Virtual Memory** | [`src/memory/paging.rs`](file:///d:/os/src/memory/paging.rs) | [docs/src/memory/paging.md](file:///d:/os/docs/src/memory/paging.md) | 4-level x86_64 paging tree (PML4), address translation, page protection. |
| **Memory Root** | [`src/memory/mod.rs`](file:///d:/os/src/memory/mod.rs) | [docs/src/memory/mod.md](file:///d:/os/docs/src/memory/mod.md) | Physical and virtual memory coordinator. |
| **Capability Core**| [`src/capability/mod.rs`](file:///d:/os/src/capability/mod.rs) | [docs/src/capability/mod.md](file:///d:/os/docs/src/capability/mod.md) | Security keycards (`Rights::READ`, `WRITE`, `EXECUTE`, `GRANT`, `CALL`). |
| **Capability Table**| [`src/capability/table.rs`](file:///d:/os/src/capability/table.rs) | [docs/src/capability/table.md](file:///d:/os/docs/src/capability/table.md) | Per-task CSpace keyring, permission checking, access revocation. |
| **IPC Message** | [`src/ipc/message.rs`](file:///d:/os/src/ipc/message.rs) | [docs/src/ipc/message.md](file:///d:/os/docs/src/ipc/message.md) | Registered courier package: 4 fast inline register arguments + security token. |
| **IPC Endpoint** | [`src/ipc/endpoint.rs`](file:///d:/os/src/ipc/endpoint.rs) | [docs/src/ipc/endpoint.md](file:///d:/os/docs/src/ipc/endpoint.md) | Postal mailbox rendezvous point, FIFO circular ring buffer. |
| **IPC Root** | [`src/ipc/mod.rs`](file:///d:/os/src/ipc/mod.rs) | [docs/src/ipc/mod.md](file:///d:/os/docs/src/ipc/mod.md) | Inter-process communication module export. |
| **Build Automation**| [`build.rs`](file:///d:/os/build.rs) | [docs/build.md](file:///d:/os/docs/build.md) | NASM assembly build script and link configuration. |
| **Legacy Boot** | [`src/arch/x86_64/boot/`](file:///d:/os/src/arch/x86_64/boot) | [docs/src/arch/x86_64/boot.md](file:///d:/os/docs/src/arch/x86_64/boot.md) | Multiboot2 header and 32-bit to 64-bit assembly trampoline. |

---

## 🚀 Boot Sequence Chronological Topic Order

When understanding or reviewing Hydra OS from initial hardware power-on through microkernel readiness, the documentation is structured sequentially:

1. **Firmware Handoff & Bootstrapping**:
   - [Legacy Boot Trampoline & Long Mode Switch](file:///d:/os/docs/src/arch/x86_64/boot.md) (Multiboot2 header, 32-bit to 64-bit Long Mode switch)
   - [Build Automation & Assembly Pipeline](file:///d:/os/docs/build.md) (NASM toolchain and UEFI link settings)
2. **UEFI Entry & Bootstrap Orchestration**:
   - [Kernel Entry Point & Bootstrap Pipeline](file:///d:/os/docs/src/main.md) (UEFI `main()`, panic handler, subsystem coordination, shell handover)
3. **Early Diagnostic Output & Keyboard Input**:
   - [UEFI Console & Formatting](file:///d:/os/docs/src/console.md) (`print!`, `println!`, thread-safe `CONSOLE` spinlock, keyboard polling, cursor management)
4. **CPU Architecture & Hardware Isolation (Step 1 & 2)**:
   - [Architecture Abstraction Layer](file:///d:/os/docs/src/arch/mod.md) (Hardware abstraction root)
   - [Global Descriptor Table (GDT) & TSS](file:///d:/os/docs/src/arch/gdt.md) (Ring 0 / Ring 3 privilege levels, Task State Segment, Double Fault IST stack)
   - [Interrupt Descriptor Table (IDT) & Hardware Exceptions](file:///d:/os/docs/src/arch/idt.md) (256-gate IDT, assembly trampolines, IST double-fault stack, #BP/#PF traps)
   - [Hardware Takeover & ExitBootServices](file:///d:/os/docs/src/arch/boot_services.md) (Termination of UEFI firmware, GDT/TSS switch, CR3 PML4 takeover, PS/2 keyboard)
   - [CPU Control Registers & Diagnostics](file:///d:/os/docs/src/arch/cpu.md) (CR0 protection, CR2 fault addresses, CR3 PML4 paging root, CR4 extensions)
5. **Physical & Virtual Memory Management (Step 3 & 4)**:
   - [Memory Subsystem Coordinator](file:///d:/os/docs/src/memory/mod.md) (Memory management root)
   - [Physical Memory & Frame Allocator](file:///d:/os/docs/src/memory/frame_allocator.md) (UEFI memory map parsing, 1 MiB low memory reservation, 4 KiB frame allocator)
   - [Virtual Memory & 4-Level Paging](file:///d:/os/docs/src/memory/paging.md) (x86_64 PML4 translation, 2 MiB / 1 GiB huge page decoding)
6. **Capability Security Model (Step 5)**:
   - [Capability Security Primitives](file:///d:/os/docs/src/capability/mod.md) (Security keycards, `Rights` bitflags, `CapType` kernel resource identifiers)
   - [Task Capability Space & Table](file:///d:/os/docs/src/capability/table.md) (Per-task CSpace table, fixed 256-slot array storage, rights verification)
7. **Inter-Process Communication (Step 6)**:
   - [IPC Subsystem Root](file:///d:/os/docs/src/ipc/mod.md) (Microkernel message passing architecture)
   - [IPC Fast Register Messages](file:///d:/os/docs/src/ipc/message.md) (4 fast inline register payload words, labels, transferred capability tokens)
   - [IPC Endpoints & Mailbox Rendezvous](file:///d:/os/docs/src/ipc/endpoint.md) (Circular FIFO ring buffers, rendezvous channels, thread-safe `SharedEndpoint`)
8. **Interactive User Space & Subsystem Diagnostics**:
   - [Interactive Microkernel Shell](file:///d:/os/docs/src/shell.md) (Command REPL, real-time memory/CPU inspection, CSpace manipulation, IPC testing, RTC clock, reboot/shutdown)

---

## 📄 Generating the Unified Documentation PDF

You can generate a single, professional PDF manual containing all documentation files, automatically formatted and ordered by the boot sequence topics:

### Windows:
```cmd
generate_pdf.bat
```
or
```powershell
python scripts\generate_docs_pdf.py
```

### Linux / WSL / macOS:
```bash
make docs-pdf
```
or
```bash
python3 scripts/generate_docs_pdf.py
```

The compiled PDF is generated at [`docs/Hydra_OS_Documentation.pdf`](file:///d:/os/docs/Hydra_OS_Documentation.pdf) and mirrored to [`dist/Hydra_OS_Documentation.pdf`](file:///d:/os/dist/Hydra_OS_Documentation.pdf).
An HTML version suitable for browser inspection or custom printing is also created at [`docs/Hydra_OS_Documentation.html`](file:///d:/os/docs/Hydra_OS_Documentation.html).

