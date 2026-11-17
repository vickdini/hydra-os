# PCID (Tagged TLB) and the CR3 Helper

- **Source File**: [`src/arch/pcid.rs`](file:///d:/os/src/arch/pcid.rs)
- **Subsystem**: Architecture / Memory translation
- **Related**: `src/arch/smp.rs` (TLB shootdowns), `src/memory/vm.rs` (`Mm` teardown, boot self-test)

---

## 1. Why

The TLB caches virtual-to-physical translations. Without PCID, every write of `CR3` (every switch between address spaces: task switches, calls into Ring 3 servers and drivers) throws the whole TLB away, and the next instructions refill it from the page tables.

With PCID (process-context identifiers, `CR4.PCIDE`), the CPU tags each TLB entry with the 12-bit ID in `CR3`'s low bits. A `CR3` write with bit 63 set keeps the entries, so switching back to an address space finds its translations still cached.

The danger is the other side: an entry kept for an address space that was changed meanwhile is a **stale translation**, which is silent memory corruption. Everything below is about never using one.

---

## 2. The one CR3 helper

```rust
pub fn crate::arch::pcid::load_cr3(pml4: u64)
```

- `pml4`: the physical address of the top-level table (no flag bits), as tasks keep it in `regs.cr3` and `Mm::cr3()` returns it.
- It is the **only** way `CR3` is written after boot. The raw writes left are the boot paths before the kernel runs on its own tables (`main.asm`, `relocate.rs`, the AP trampoline).
- It records the root in `smp::LOADED_CR3[cpu]` first (shootdowns read it), then picks the CPU's ID for the root, and writes `CR3` with bit 63 only when that ID's entries are known to be valid.
- It takes no lock and never waits. It disables interrupts while it runs if they are on.
- With PCID off, it is a plain `mov cr3` (a full flush), as before.

Callers: the scheduler's task switch, `execve`, the firmware-call helpers (`paging::with_kernel_tables`, `load_kernel_tables_for_good`), `AddressSpace::switch`.

---

## 3. IDs: a per-CPU cache of roots

Each CPU has 4095 slots (IDs 1 to 4095; ID 0 belongs to the boot tables and is never used without a flush). A root hashes to exactly one slot, and its ID on that CPU is the slot number. A slot holds the root whose entries the ID's TLB entries belong to, plus a `STALE` bit:

| Slot holds | Load of the root |
|---|---|
| the root | keeps the entries (bit 63) |
| the root + `STALE` | flushes the ID, clears `STALE` |
| anything else (empty, a colliding root) | takes the slot over, flushes the ID |

More address spaces than slots simply take turns on colliding slots, always with a flush before reuse.

---

## 4. Shootdowns (`arch::smp::shootdown`)

A change to an address space's page tables (unmap, `mprotect`, copy-on-write, `fork`'s write-protection) must reach every CPU that may still cache the old entry. With PCID, that includes CPUs that ran the address space earlier and switched away.

- **The changing CPU:** flushes the address (`invlpg`) if the root is loaded there. Otherwise, if its slot holds the root, it flushes that ID with `INVPCID`, or marks the slot `STALE` where there is no `INVPCID`.
- **Other CPUs:** their slot for the root is marked `STALE` (their next load of it flushes). Every CPU that has the root loaded *now* is interrupted and flushes its current ID at once, as before PCID.
- **Ordering:** the loading CPU writes `LOADED_CR3` before it reads the slot; the changing CPU marks slots before it reads `LOADED_CR3`. Both are sequentially consistent, so either the loader sees `STALE`, or the changer sees the root loaded and interrupts that CPU.
- **The kernel's shared tables** (`shootdown(None, ..)`: the kernel half and the identity map every address space shares): every ID on every CPU is flushed (`INVPCID` "all contexts", or a toggle of `CR4.PGE`).
- **Teardown:** `Mm`'s drop calls `pcid::forget(root)` before its frames are freed, so a later root at the same physical address never inherits its entries.

---

## 5. Turning it on and off

- PCID is used when CPUID reports it (leaf 1, ECX bit 17); `INVPCID` when leaf 7 reports it (EBX bit 10).
- Boot log: `[pcid] PCID on: tagged TLB, 4095 IDs per CPU, INVPCID yes`, or a `PCID off` line with the reason.
- Off switches (read before `ExitBootServices`):
  - the boot entry's load option `nopcid` (or `pcid=off`);
  - a file `\hydra\nopcid` on the EFI system partition;
  - QEMU's `-fw_cfg name=opt/hydra/pcid,string=off` (`tools/hydra_run.py --pcid-off`).

---

## 6. Boot self-test

Before the other processors start, `memory::vm::tlb_self_test` builds two address spaces A and B, caches a page of A, loads B, points A's entry at another frame, and checks that each invalidation (page and whole-space shootdown, with and without `INVPCID`, another CPU's stale mark, `forget`, the all-ID flush) makes the new frame visible when A is loaded again. Its control step (no invalidation) must still show the old frame: proof that the CPU really keeps entries across `CR3` switches.

- `[pcid] self-test passed (the CPU kept a switched-away address space's entries, ...)`: all good.
- `... passed, but inconclusive`: the CPU or hypervisor dropped the entries by itself.
- `[pcid] SELF-TEST FAILED: ...`: PCID is turned off again for this boot.

---

## 7. Counters

`linux prof show` prints one `[prof] tlb:` line: CR3 loads that kept the TLB, loads that took a slot over or found it stale, remote slots marked stale, `INVPCID` single-ID flushes and all-ID flushes.
