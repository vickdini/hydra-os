# Architecture Module Overview

- **Source File**: [`src/arch/mod.rs`](file:///d:/os/src/arch/mod.rs)
- **Subsystem**: Architecture-Specific Primitives (x86_64)

---

## 1. Role in Hydra OS

The `arch` module isolates all processor-specific and machine-dependent code away from the rest of the generic microkernel.

When Hydra is ported to other CPU architectures (such as ARM64 or RISC-V), only the implementations inside `arch` need to be swapped out.

---

## 2. Submodules

- [`gdt.rs`](file:///d:/os/docs/src/arch/gdt.md): Manages the Global Descriptor Table, Ring 0 / Ring 3 segmentation, and Task State Segment (TSS).
- [`cpu.rs`](file:///d:/os/docs/src/arch/cpu.md): Provides interfaces for reading x86 control registers (`CR0`, `CR2`, `CR3`, `CR4`).
- [`pcid.rs`](file:///d:/os/docs/src/arch/pcid.md): PCID (tagged TLB entries) and `load_cr3`, the one helper that writes `CR3`.
