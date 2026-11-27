# Virtual Memory & Paging Documentation

- **Source File**: [`src/memory/paging.rs`](file:///d:/os/src/memory/paging.rs)
- **Subsystem**: Memory Management (Virtual Layer & Hardware MMU)

---

## 1. Conceptual Overview

Modern 64-bit CPUs do not let user programs or high-level kernel functions read and write directly to physical RAM chips. Instead, they use **Virtual Memory**.

Every address a program interacts with is a **Virtual Address**. The hardware Memory Management Unit (MMU) consults a multi-level tree of translation tables (called **Page Tables**) to convert that virtual address into a **Physical Address** in RAM.

### Benefits of Paging
1. **Isolation**: Process A and Process B can both have code at virtual address `0x400000`, but they map to completely different physical RAM chips.
2. **Protection**: Pages can be marked read-only, non-executable (NX/XD bit to prevent malware buffer-overflow attacks), or kernel-only.
3. **Continuity**: Large buffers appear contiguous in virtual memory even if physical frames are scattered across RAM.

---

## 2. 4-Level Paging Architecture (x86_64)

In 64-bit x86 architecture, translating a 48-bit canonical virtual address uses a 4-level tree:

```
Virtual Address:
[ PML4 Index (9 bits) | PDPT Index (9 bits) | PD Index (9 bits) | PT Index (9 bits) | Offset (12 bits) ]
        |                      |                     |                  |                     |
        v                      v                     v                  v                     v
   [ CR3 Register ]
        |
        +---> PML4 Table (Level 4)
                  |
                  +---> PDPT Table (Level 3 - Page Directory Pointer Table)
                            |
                            +---> PD Table (Level 2 - Page Directory)
                                      |
                                      +---> PT Table (Level 1 - Page Table)
                                                |
                                                +---> Physical Frame (4 KiB) + Offset
```

- **CR3**: The CPU control register holding the physical address of the active Level 4 (PML4) table.

---

## 3. The `AddressSpace` Struct

```rust
pub struct AddressSpace {
    pml4_phys: PhysAddr,
}
```

Represents a virtual memory context anchored by its PML4 root table.

---

## 4. API Reference & Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `active()` | `fn() -> Self` | Attaches to the active address space by reading `CR3`. |
| `from_pml4()` | `const fn(PhysAddr) -> Self` | Creates an address space handle for a given root PML4 table. |
| `switch()` | `unsafe fn(&self)` | Loads this address space's PML4 root through `arch::pcid::load_cr3` (the one `CR3` helper). |
| `translate_addr()` | `unsafe fn(&self, VirtAddr) -> Option<PhysAddr>` | Walks PML4 hierarchy to translate any virtual address to its physical address. |
| `translate_page()` | `unsafe fn(&self, Page) -> Option<(PhysFrame, PageTableFlags)>` | Queries mapped frame and protection flags (`PRESENT`, `WRITABLE`, `USER`, `NX`). |
| `map_page()` | `unsafe fn(&mut self, Page, PhysFrame, PageTableFlags, &mut PhysicalMemoryManager) -> Result<(), &'static str>` | Allocates missing intermediate tables (PDPT, PD, PT) on demand, maps a 4 KiB page, and flushes the TLB. |
| `unmap_page()` | `unsafe fn(&mut self, Page) -> Result<PhysFrame, &'static str>` | Clears the page table entry, flushes the TLB via `invlpg`, and returns the previously mapped frame. |
| `update_flags()` | `unsafe fn(&mut self, Page, PageTableFlags) -> Result<(), &'static str>` | Updates protection bits for an existing mapped page and invalidates TLB. |
| `identity_map()` | `unsafe fn(&mut self, PhysFrame, PageTableFlags, &mut PhysicalMemoryManager) -> Result<(), &'static str>` | Maps a physical frame 1:1 (`virt = phys`), essential for MMIO (APIC, GOP framebuffer). |
| `map_range()` | `unsafe fn(&mut self, Page, PhysFrame, usize, PageTableFlags, &mut PhysicalMemoryManager) -> Result<(), &'static str>` | Maps a contiguous sequence of virtual pages to physical frames. |
| `create_user_space()`| `fn(&mut PhysicalMemoryManager) -> Result<Self, &'static str>` | Allocates a new PML4 table, mirrors higher-half kernel entries, and leaves lower-half empty for isolated Ring 3 user tasks. |

---

## 5. Interactive Shell Commands

Hydra provides built-in commands to inspect and modify virtual memory mappings dynamically:

```text
hydra> translate 0x400000
4-Level PML4 Page Table Walk for 0x400000:
  PML4 Index (L4):    0
  PDPT Index (L3):    0
  PD Index   (L2):    2
  PT Index   (L1):    0
  Page Offset:        0x0
  Status:             MAPPED
  Physical Target:    0x400000
  Base Frame:         0x400000
  Protection Flags:   [PRESENT] [WRITABLE] [SUPERVISOR/RING-0] [EXECUTABLE]

hydra> map 0x7000000000 0x1000000 rw
[+] Successfully mapped Page 0x7000000000 -> Frame 0x1000000 (flags: PageTableFlags(PRESENT | WRITABLE))

hydra> unmap 0x7000000000
[+] Successfully unmapped Page 0x7000000000 (previously mapped to Frame 0x1000000)
```

---

## 6. The kernel and programs' low 2 GiB (wave 12, Group V)

Programs need the low 2 GiB of their address space for themselves: 32-bit code, `MAP_32BIT`,
non-PIE executables, Wine (which maps `0x7ffe0000`). The kernel keeps a GiB "slot" of that range
in every address space only if it reaches something there at its physical (identity) address
after the takeover; the boot log says which slots it keeps:

```text
[vm] programs' low window [0x10000, 0x80000000); kernel keeps GiB slots [2, 3] (...)
[boot] higher half: late (image stays at 0x9d228000+0x8e5000; after ExitBootServices: stack on the heap at 0x8d7024a0, ...)
```

There are three paths (`src/arch/relocate.rs`, `HighPath`), and the second line says which ran:

| Path | When | What |
|---|---|---|
| **early** | the firmware loaded the image outside [2 GiB, 4 GiB) (QEMU at 2, 4 and 6 GB), or the boot word `high=early` | `go_high` moves the image, its stack and the heap to the higher half at the entry point, before `ExitBootServices` |
| **late** (default otherwise) | the image is in [2 GiB, 4 GiB) (the NUC; QEMU at 2.5 GB), or the boot word `high=late` | all of boot services runs at the load address, exactly as the firmware gave it (the NUC's firmware stops when kernel code runs high while it runs, wave 11). After `ExitBootServices` the kernel moves to a 1 MiB stack on its heap and keeps no firmware memory below 2 GiB: what it reaches there later goes through the direct map (frames, the boot log's block) or its own tables (runtime services, ACPI). The frames handed out before the direct map is on come from 2 GiB up (when at least 192 MiB are free there; else slot 1 stays kept), since they are reached at identity addresses until then. The image itself stays where it is: in [2, 4) GiB it takes nothing from programs; elsewhere its range stays kept |
| **off** | the boot word `high=off` (also in safe mode and start menu entry 0); only this word gives the layout before wave 12 (`nohigh` and the N key at the breadcrumb prompt only skip the early move: the late path follows) | the path before wave 12: the firmware's stack, and every region of the final memory map below 2 GiB that is not free stays kept |

Measured in QEMU (wave 12): 2.5 GB, late: window 2 GiB, `wine cmd /c ver` works (with
`high=off` the window is 1 GiB, kept by a 2 MiB loader-data block, the boot log's memory at
`0x7000_0000`, and Wine fails: "failed to map the shared user data"). 2 GB and 4/6 GB: early
(the image loads at `0x7d222000` and `0x1_0000_0000`), window 2 GiB; `--high late` works at 4 and
6 GB; at 2 GB with `high=late` the image and the heap lie below 2 GiB, so slot 1 stays kept.

Test harness: `tools/hydra_run.py --high late|early|off` (QEMU's `fw_cfg opt/hydra/high`, read
only in a virtual machine). On a stick: the word in `\hydra\options.txt`, or start menu entry 0.
