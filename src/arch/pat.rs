//! # Page attribute table: write-combining framebuffer memory (wave 11, Group G)
//!
//! On real hardware the firmware's framebuffer lies in a range its memory type range
//! registers (MTRRs) make uncacheable: every 4-byte store is its own bus transaction, so a
//! 1920x1080 picture took ~90 ms to copy on the user's NUC (6 pictures a second, a lagging
//! pointer). Write-combining (WC) memory gathers stores into 64-byte bursts (and a PAT WC
//! type wins over an MTRR UC range), which makes the same copy a few milliseconds.
//!
//! The PAT (`IA32_PAT`, MSR 0x277) holds 8 memory types; a page table entry selects one
//! with its PAT, PCD and PWT bits. As Linux does, entry 1 (**PWT alone**) becomes WC
//! instead of the power-on write-through (nothing in the kernel asks for write-through;
//! Linux also changes entries 5 and 7, Hydra does not); the other entries stay as the
//! firmware left them (the power-on default: entry 0 write-back, entry 3 uncacheable,
//! ...). Firmware page-table entries with PWT alone (write-through regions, none known on
//! the machines Hydra runs on) become write-combining too. Every CPU gets the same value
//! (the boot processor at takeover, each application processor as it starts).
//!
//! Two mappings of the framebuffer are WC:
//! - the display service's `[screen]` mapping (`ipc::screen`: its pages come from a
//!   [`crate::memory::vm::MappedObject`] whose `write_combining` says so);
//! - the kernel console's, [`alias_wc`]: the framebuffer's pages in the direct map
//!   (`DIRECT_MAP_BASE + phys`, 2 MiB pages there), whose 2 MiB (or 1 GiB) entries that
//!   cover it are split into 4 KiB ones so that only the framebuffer's own pages change;
//! - and its old identity mapping (the boot logo's), changed the same way, so that no
//!   alias of another memory type remains (Intel SDM 11.12.4).
//!
//! QEMU (KVM) gives emulated device memory write-back whatever the guest asks, so the
//! change is invisible there.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use x86_64::structures::paging::PageTableFlags;

/// The PAT MSR.
pub const IA32_PAT: u32 = 0x277;
/// Memory type encodings in a PAT entry.
pub const MT_UC: u64 = 0x00;
/// Write-combining.
pub const MT_WC: u64 = 0x01;
/// Write-through.
pub const MT_WT: u64 = 0x04;
/// Write-back.
pub const MT_WB: u64 = 0x06;
/// The PAT entry WC goes into (selected by PWT = 1, PCD = 0, PAT = 0).
pub const WC_ENTRY: u32 = 1;

/// Page table entry bits (4 KiB leaf: PAT is bit 7; 2 MiB / 1 GiB leaf: PAT is bit 12,
/// bit 7 says "large page").
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_PS: u64 = 1 << 7;
const PTE_PAT_4K: u64 = 1 << 7;
const PTE_PAT_LARGE: u64 = 1 << 12;
const PTE_PRESENT: u64 = 1;
/// Address bits of a table pointer / 4 KiB leaf.
const ADDR_4K: u64 = 0x000F_FFFF_FFFF_F000;

/// Whether the PAT holds WC in [`WC_ENTRY`] on the boot processor (then on all).
static ON: AtomicBool = AtomicBool::new(false);
/// The value written on the boot processor; the others copy it.
static VALUE: AtomicU64 = AtomicU64::new(0);

/// The PAT value `old` with entry [`WC_ENTRY`] set to write-combining.
pub fn with_wc(old: u64) -> u64 {
    let shift = WC_ENTRY * 8;
    (old & !(0xFF << shift)) | (MT_WC << shift)
}

/// The memory type a 4 KiB leaf entry's PAT/PCD/PWT bits select under `pat`.
pub fn type_of_4k(pat: u64, entry: u64) -> u64 {
    let idx = ((entry & PTE_PAT_4K != 0) as u64) << 2 | ((entry & PTE_PCD != 0) as u64) << 1 | (entry & PTE_PWT != 0) as u64;
    (pat >> (idx * 8)) & 0xFF
}

/// Whether the CPU has a PAT (CPUID.1:EDX bit 16; every x86_64 CPU does).
fn cpu_has_pat() -> bool {
    core::arch::x86_64::__cpuid(1).edx & (1 << 16) != 0
}

/// Boot processor, at takeover (before the other processors start): writes WC into PAT
/// entry 1. Nothing maps with PWT alone before this, so no cache or TLB flush is needed.
pub fn init_bsp() {
    if !cpu_has_pat() {
        crate::kprintln!("[pat] no page attribute table: the framebuffer stays uncached");
        return;
    }
    // SAFETY: the PAT MSR exists (CPUID above); only entry 1 changes
    let old = unsafe { super::syscall::rdmsr(IA32_PAT) };
    let new = with_wc(old);
    unsafe { super::syscall::wrmsr(IA32_PAT, new) };
    VALUE.store(new, Ordering::SeqCst);
    ON.store(true, Ordering::SeqCst);
    if old != new {
        crate::kprintln!("[pat] entry {} is write-combining (PAT {:#018x}, was {:#018x})", WC_ENTRY, new, old);
    }
}

/// An application processor as it starts: the boot processor's PAT value.
pub fn init_ap() {
    if ON.load(Ordering::Acquire) {
        // SAFETY: as on the boot processor (the same CPU model)
        unsafe { super::syscall::wrmsr(IA32_PAT, VALUE.load(Ordering::Acquire)) };
    }
}

/// Whether write-combining mappings are available.
pub fn enabled() -> bool {
    ON.load(Ordering::Acquire)
}

/// The page table flags that make a 4 KiB mapping write-combining (none when the PAT is
/// not set up: the mapping then keeps the default type).
pub fn wc_flags() -> PageTableFlags {
    if enabled() {
        PageTableFlags::WRITE_THROUGH
    } else {
        PageTableFlags::empty()
    }
}

/// The 512 entries a large leaf `entry` of `size` bytes (2 MiB or 1 GiB) splits into:
/// the same memory with the same rights and type, in pages of `size / 512` bytes (1 GiB
/// into 2 MiB leaves, 2 MiB into 4 KiB leaves, whose PAT bit moves from bit 12 to bit 7).
pub fn split_large(entry: u64, size: u64) -> [u64; 512] {
    let step = size / 512;
    let pat = entry & PTE_PAT_LARGE != 0;
    let base = entry & ADDR_4K & !(size - 1);
    // Rights and type bits below bit 12, NX and the software bits above the address
    let low = entry & 0xFFF & !PTE_PS;
    let high = entry & !(ADDR_4K | 0xFFF);
    let mut out = [0u64; 512];
    for (i, e) in out.iter_mut().enumerate() {
        let addr = base + i as u64 * step;
        *e = if step == 4096 {
            addr | high | low | if pat { PTE_PAT_4K } else { 0 }
        } else {
            addr | high | low | PTE_PS | if pat { PTE_PAT_LARGE } else { 0 }
        };
    }
    out
}

/// A 4 KiB leaf `entry` made write-combining (PWT on; PCD and PAT off).
pub fn make_wc(entry: u64) -> u64 {
    (entry | PTE_PWT) & !(PTE_PCD | PTE_PAT_4K)
}

/// Splits the large leaf at `*slot` (of `size` bytes) into a new table; `false` if no
/// memory for it.
///
/// # Safety
///
/// `slot` is an entry of the kernel's live page tables; only the boot processor runs.
unsafe fn split_slot(slot: *mut u64, size: u64) -> bool {
    let Some(frame) = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock().allocate_zeroed_frame() else {
        return false;
    };
    let table_phys = frame.start_address().as_u64();
    let table = crate::memory::frame_allocator::phys_to_virt(table_phys) as *mut u64;
    let old = slot.read_volatile();
    for (i, e) in split_large(old, size).iter().enumerate() {
        table.add(i).write_volatile(*e);
    }
    // A table pointer: present, writable, kernel-only (the leaves carry NX and global)
    slot.write_volatile(table_phys | PTE_PRESENT | 2);
    true
}

/// Makes the 4 KiB leaves mapping `[va, va + pages * 4096)` to `[phys, ...)` in the
/// kernel's tables at `pml4` write-combining, splitting large entries on the way.
/// `Err(i)`: page `i` is not mapped there (or maps other memory); pages before it changed.
///
/// # Safety
///
/// The kernel's own tables; one CPU running.
unsafe fn wc_range(pml4: u64, va: u64, phys: u64, pages: u64) -> Result<(), u64> {
    let p2v = crate::memory::frame_allocator::phys_to_virt;
    for i in 0..pages {
        let va = va + i * 4096;
        let l4 = (p2v(pml4) as *mut u64).add(((va >> 39) & 511) as usize);
        let e4 = l4.read_volatile();
        if e4 & PTE_PRESENT == 0 {
            return Err(i);
        }
        let l3 = (p2v(e4 & ADDR_4K) as *mut u64).add(((va >> 30) & 511) as usize);
        let e3 = l3.read_volatile();
        if e3 & PTE_PRESENT == 0 || (e3 & PTE_PS != 0 && !split_slot(l3, 1 << 30)) {
            return Err(i);
        }
        let e3 = l3.read_volatile();
        let l2 = (p2v(e3 & ADDR_4K) as *mut u64).add(((va >> 21) & 511) as usize);
        let e2 = l2.read_volatile();
        if e2 & PTE_PRESENT == 0 || (e2 & PTE_PS != 0 && !split_slot(l2, 1 << 21)) {
            return Err(i);
        }
        let e2 = l2.read_volatile();
        let l1 = (p2v(e2 & ADDR_4K) as *mut u64).add(((va >> 12) & 511) as usize);
        let e1 = l1.read_volatile();
        if e1 & PTE_PRESENT == 0 || e1 & ADDR_4K != phys + i * 4096 {
            return Err(i);
        }
        l1.write_volatile(make_wc(e1));
    }
    Ok(())
}

/// Writes back and drops every cache line of this CPU (`wbinvd`): lines of the
/// framebuffer cached through its old write-back mapping must not be written over the
/// picture later.
fn write_back_caches() {
    #[cfg(target_os = "uefi")]
    // SAFETY: ring 0; only the boot processor runs (no other CPU holds lines to flush)
    unsafe {
        core::arch::asm!("wbinvd", options(nostack, preserves_flags))
    };
}

/// Makes the kernel's direct-map view of `[phys, phys + len)` write-combining and
/// returns its address (`DIRECT_MAP_BASE + phys`); its identity mapping (`phys`, kept
/// for the boot logo) is made write-combining as well where it exists, so no alias of
/// another memory type remains. `None` if the PAT is not set up, the direct map does not
/// cover the range, or there is no memory for the split tables (the caller then keeps
/// its old mapping). Boot processor only, at takeover, after the direct map was enabled
/// and before the other processors start.
pub fn alias_wc(phys: u64, len: u64) -> Option<u64> {
    if !enabled() || len == 0 || phys & 0xFFF != 0 {
        return None;
    }
    let base = crate::memory::frame_allocator::DIRECT_MAP_BASE;
    let pml4 = crate::memory::paging::KERNEL_PML4.load(Ordering::SeqCst) & ADDR_4K;
    if pml4 == 0 {
        return None;
    }
    let pages = len.div_ceil(4096);
    // SAFETY: the kernel's own tables, one CPU running
    let direct = unsafe { wc_range(pml4, base + phys, phys, pages) };
    // The identity alias: as many of its pages as are mapped there
    let identity = match unsafe { wc_range(pml4, phys, phys, pages) } {
        Ok(()) => pages,
        Err(i) => i,
    };
    // Lines cached through the old write-back types out, then the old (large, global)
    // TLB entries
    write_back_caches();
    for i in 0..pages {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(base + phys + i * 4096));
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(phys + i * 4096));
    }
    IDENTITY_WC.store(identity, Ordering::Release);
    direct.ok()?;
    Some(base + phys)
}

/// How many pages of the framebuffer's identity mapping [`alias_wc`] made write-combining.
static IDENTITY_WC: AtomicU64 = AtomicU64::new(0);

/// See [`IDENTITY_WC`].
pub fn identity_wc_pages() -> u64 {
    IDENTITY_WC.load(Ordering::Acquire)
}
