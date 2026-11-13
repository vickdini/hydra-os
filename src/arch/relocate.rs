//! The kernel image in the higher half.
//!
//! UEFI loads the image wherever it finds room in physical memory, at the identity address:
//! on a machine with little memory that is in the low 2 GiB, which every program needs for
//! itself (32-bit code, `MAP_32BIT`, non-PIE executables, Wine). So the first thing the
//! kernel does, before anything stores a pointer, is map the image a second time at
//! [`KERNEL_BASE`] (the top 2 GiB, in every address space as all of the kernel half is),
//! add the difference to every absolute address the image holds (its base relocations,
//! the same table the UEFI loader applied), and move there with a new stack
//! ([`go_high`]). From then on code, statics and the boot stack are reached at high
//! addresses, wherever the image sits in physical memory, as on Linux.
//!
//! The identity mapping stays during boot (the firmware runs at its own addresses), but
//! nothing of the kernel's is reached through it any more.

use core::sync::atomic::{AtomicU64, Ordering};

/// Virtual address of the image's first byte in the higher half (the top 2 GiB).
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
/// Bottom of the boot stack's high mapping (an unmapped guard page below it).
const STACK_BOTTOM: u64 = KERNEL_BASE + 0x4000_0000;
/// Size of the boot stack (the boot processor's kernel code, the shell task).
const STACK_SIZE: u64 = 1024 * 1024;

/// Physical (and identity) address of the image, once it runs high (0 before).
static IMAGE_PHYS: AtomicU64 = AtomicU64::new(0);
/// Size of the image in bytes.
static IMAGE_SIZE: AtomicU64 = AtomicU64::new(0);
/// The boot stack's physical range start.
static STACK_PHYS: AtomicU64 = AtomicU64::new(0);

extern "C" {
    /// The image's DOS header (defined by the linker).
    static __ImageBase: u8;
}

/// The image's physical range `(start, size)` when it runs in the higher half.
pub fn image_phys() -> Option<(u64, u64)> {
    let p = IMAGE_PHYS.load(Ordering::Relaxed);
    (p != 0).then(|| (p, IMAGE_SIZE.load(Ordering::Relaxed)))
}

/// The boot stack's physical range `(start, size)` when it runs in the higher half.
pub fn stack_phys() -> Option<(u64, u64)> {
    let p = STACK_PHYS.load(Ordering::Relaxed);
    (p != 0).then_some((p, STACK_SIZE))
}

const PRESENT: u64 = 1;
const WRITABLE: u64 = 2;
const ADDR: u64 = 0x000F_FFFF_FFFF_F000;

/// A zeroed page from the firmware (boot loader data: never handed to the frame allocator).
fn page() -> Option<u64> {
    let p = uefi::boot::allocate_pages(uefi::boot::AllocateType::AnyPages, uefi::boot::MemoryType::LOADER_DATA, 1).ok()?;
    unsafe { core::ptr::write_bytes(p.as_ptr(), 0, 4096) };
    Some(p.as_ptr() as u64)
}

/// Maps the 4 KiB page `va` to `pa` (present, writable, executable) in the tables rooted at
/// `pml4` (physical, reached at identity addresses during boot).
fn map(pml4: u64, va: u64, pa: u64) -> Option<()> {
    let mut table = pml4;
    for shift in [39u64, 30, 21] {
        let e = (table + ((va >> shift) & 511) * 8) as *mut u64;
        unsafe {
            if *e & PRESENT == 0 {
                *e = page()? | PRESENT | WRITABLE;
            }
            table = *e & ADDR;
        }
    }
    unsafe { *((table + ((va >> 12) & 511) * 8) as *mut u64) = pa | PRESENT | WRITABLE };
    Some(())
}

/// Whether the firmware's memory type `ty` is RAM (what the direct map covers).
fn is_ram(ty: uefi::boot::MemoryType) -> bool {
    use uefi::boot::MemoryType as T;
    matches!(
        ty,
        T::CONVENTIONAL
            | T::LOADER_CODE
            | T::LOADER_DATA
            | T::BOOT_SERVICES_CODE
            | T::BOOT_SERVICES_DATA
            | T::RUNTIME_SERVICES_CODE
            | T::RUNTIME_SERVICES_DATA
            | T::ACPI_RECLAIM
            | T::ACPI_NON_VOLATILE
            | T::PERSISTENT_MEMORY
    )
}

/// Adds the direct map of physical memory to the tables rooted at `pml4`: all RAM and at
/// least the first 4 GiB (firmware and devices) at
/// [`crate::memory::frame_allocator::DIRECT_MAP_BASE`], 2 MiB pages, never executable.
/// The heap is reached there from the start (so it is in every address space whatever
/// its physical address), and every frame later.
fn direct_map(pml4: u64) -> Option<()> {
    use uefi::mem::memory_map::MemoryMap;
    let top = {
        let map = uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA).ok()?;
        map.entries().filter(|d| is_ram(d.ty)).map(|d| d.phys_start + d.page_count * 4096).max().unwrap_or(0).max(4 << 30)
    };
    let gib = (top + (1 << 30) - 1) >> 30;
    let base_idx = (crate::memory::frame_allocator::DIRECT_MAP_BASE >> 39) & 511;
    if gib > 255 * 512 {
        return None;
    }
    let nx = if crate::memory::vm::nx_enabled() { 1u64 << 63 } else { 0 };
    for g in 0..gib {
        let e4 = (pml4 + (base_idx + g / 512) * 8) as *mut u64;
        unsafe {
            if *e4 & PRESENT == 0 {
                *e4 = page()? | PRESENT | WRITABLE;
            }
            let pd = page()?;
            for i in 0..512u64 {
                *((pd + i * 8) as *mut u64) = ((g << 30) + (i << 21)) | PRESENT | WRITABLE | 0x80 | nx;
            }
            *(((*e4 & ADDR) + (g % 512) * 8) as *mut u64) = pd | PRESENT | WRITABLE;
        }
    }
    Some(())
}

/// The image's base relocation table `(rva, size)` and size of image, from its PE header.
unsafe fn pe_info(base: u64) -> Option<((u32, u32), u64)> {
    let rd32 = |a: u64| core::ptr::read_unaligned(a as *const u32);
    let nt = base + rd32(base + 0x3c) as u64;
    if rd32(nt) != 0x0000_4550 {
        return None; // "PE\0\0"
    }
    let opt = nt + 24;
    if core::ptr::read_unaligned(opt as *const u16) != 0x20b {
        return None; // PE32+
    }
    let size = rd32(opt + 56) as u64;
    let n_dirs = rd32(opt + 108);
    if n_dirs <= 5 {
        return None;
    }
    Some(((rd32(opt + 112 + 5 * 8), rd32(opt + 112 + 5 * 8 + 4)), size))
}

/// Walks the base relocation blocks at `table` (`len` bytes), calling `f(rva)` for each
/// 64-bit (`IMAGE_REL_BASED_DIR64`) entry. Returns `false` for any other kind (but
/// padding), or a malformed block.
unsafe fn each_reloc(table: u64, len: u64, mut f: impl FnMut(u64)) -> bool {
    let mut at = table;
    while at + 8 <= table + len {
        let page_rva = core::ptr::read_unaligned(at as *const u32) as u64;
        let block = core::ptr::read_unaligned((at + 4) as *const u32) as u64;
        if block < 8 || at + block > table + len {
            return false;
        }
        for i in 0..(block - 8) / 2 {
            let e = core::ptr::read_unaligned((at + 8 + i * 2) as *const u16);
            match e >> 12 {
                0 => {}
                10 => f(page_rva + (e & 0xfff) as u64),
                _ => return false,
            }
        }
        at += block;
    }
    true
}

/// Moves the running kernel to [`KERNEL_BASE`] and calls `next` there on a new stack; does
/// not return. Returns only if that is impossible (the image cannot be read, an unknown
/// relocation kind, no memory, the slot already in use), before changing anything; the
/// kernel then goes on at its identity addresses.
///
/// Must run first in the entry point: a pointer stored before this (in a static, or on
/// the heap) keeps the identity address, which programs' address spaces do not map.
pub fn go_high(next: fn() -> !) {
    unsafe {
        let base = core::ptr::addr_of!(__ImageBase) as u64;
        if base >= KERNEL_BASE {
            return;
        }
        let Some(((rva, len), size)) = pe_info(base) else { return };
        if rva == 0 || len == 0 || size == 0 || size > 0x3000_0000 {
            return;
        }
        // Every relocation must be one this code applies, checked before touching any
        if !each_reloc(base + rva as u64, len as u64, |_| {}) {
            return;
        }
        // Hydra's top-level table: the firmware's entries (its identity map) and the top
        // entry for the image, which the firmware must not use
        let fw = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
        // The firmware uses the low half only
        if (256..512).any(|i| *((fw + i * 8) as *const u64) & PRESENT != 0) {
            return;
        }
        let Some(pml4) = page() else { return };
        core::ptr::copy_nonoverlapping(fw as *const u64, pml4 as *mut u64, 512);
        if direct_map(pml4).is_none() {
            return;
        }
        let size = (size + 4095) & !4095;
        for off in (0..size).step_by(4096) {
            if map(pml4, KERNEL_BASE + off, base + off).is_none() {
                return;
            }
        }
        let Ok(stack) = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            uefi::boot::MemoryType::LOADER_DATA,
            (STACK_SIZE / 4096) as usize,
        ) else {
            return;
        };
        let stack = stack.as_ptr() as u64;
        for off in (0..STACK_SIZE).step_by(4096) {
            if map(pml4, STACK_BOTTOM + off, stack + off).is_none() {
                return;
            }
        }
        // Nothing can fail from here on
        x86_64::instructions::interrupts::without_interrupts(|| {
            core::arch::asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags));
        });
        let delta = KERNEL_BASE.wrapping_sub(base);
        // Written through the high alias: the firmware may have made the identity pages
        // of read-only sections read-only
        each_reloc(base + rva as u64, len as u64, |r| {
            let p = (KERNEL_BASE + r) as *mut u64;
            core::ptr::write_unaligned(p, core::ptr::read_unaligned(p).wrapping_add(delta));
        });
        crate::memory::frame_allocator::enable_direct_map();
        IMAGE_PHYS.store(base, Ordering::SeqCst);
        IMAGE_SIZE.store(size, Ordering::SeqCst);
        STACK_PHYS.store(stack, Ordering::SeqCst);
        let target = (next as usize as u64).wrapping_add(delta);
        let top = STACK_BOTTOM + STACK_SIZE;
        // The Microsoft x64 convention of the UEFI target: 32 bytes of shadow space, the
        // stack 16-byte aligned at the call
        core::arch::asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "sub rsp, 32",
            "call {target}",
            "ud2",
            top = in(reg) top,
            target = in(reg) target,
            options(noreturn)
        );
    }
}
