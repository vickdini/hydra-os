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

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

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

/// wave11 GH: moves to the kernel's own stack in the higher half (the one [`go_high`] mapped)
/// and calls `next` there; does not return. [`go_high`] leaves the kernel on the firmware's
/// stack: the firmware's own code runs on the caller's stack, and a real firmware (the
/// NUC's) stops when that is at a higher-half address (its drivers use stack buffers for
/// DMA or cut addresses to 32 bits). So this is called once `ExitBootServices` is done.
/// Without the move (`nohigh`, or the move impossible) `next` simply runs on the current
/// stack.
pub fn run_on_kernel_stack(next: fn() -> !) -> ! {
    // wave12 GV begin: without the early move, the late path (unless high=off): a stack on
    // the kernel's heap, which every address space reaches, instead of the firmware's (boot
    // services memory, maybe below 2 GiB)
    let top = if STACK_PHYS.load(Ordering::SeqCst) != 0 {
        set_path(HighPath::Early);
        STACK_BOTTOM + STACK_SIZE
    } else {
        let p = path_after_firmware(false, off_word());
        set_path(p);
        if p != HighPath::Late {
            crate::arch::boot_services::mark(4, "high=off: staying on the firmware's stack");
            next();
        }
        let stack = alloc::vec![0u8; STACK_SIZE as usize].leak();
        let lo = stack.as_ptr() as u64;
        LATE_STACK.store(lo, Ordering::SeqCst);
        let mut line = crate::console::FixedBuf::new();
        let _ = core::fmt::Write::write_fmt(&mut line, format_args!("late path: to a {} KiB stack on the heap at {:#x}", STACK_SIZE >> 10, lo));
        crate::arch::boot_services::mark(4, line.as_str());
        (lo + STACK_SIZE) & !15
    };
    // wave12 GV end
    unsafe {
        // The Microsoft x64 convention of the UEFI target: 32 bytes of shadow space, the
        // stack 16-byte aligned at the call
        core::arch::asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "sub rsp, 32",
            "call {target}",
            "ud2",
            top = in(reg) top,
            target = in(reg) next as usize as u64,
            options(noreturn)
        );
    }
}

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
#[cfg(target_os = "uefi")]
fn page() -> Option<u64> {
    let p = uefi::boot::allocate_pages(uefi::boot::AllocateType::MaxAddress(0xFFFF_FFFF), uefi::boot::MemoryType::LOADER_DATA, 1).ok()?;
    unsafe { core::ptr::write_bytes(p.as_ptr(), 0, 4096) };
    Some(p.as_ptr() as u64)
}

/// Host build (unit tests): a zeroed frame of the frame allocator, unless the test thread
/// says the firmware is out of memory.
#[cfg(not(target_os = "uefi"))]
fn page() -> Option<u64> {
    if crate::host::RELOC_NO_MEMORY.get() {
        return None;
    }
    crate::memory::frame_allocator::FRAME_ALLOCATOR.lock().allocate_zeroed_frame().map(|f| f.start_address().as_u64())
}

/// The end of RAM in the firmware's memory map (at least 4 GiB).
#[cfg(target_os = "uefi")]
fn ram_top() -> Option<u64> {
    use uefi::mem::memory_map::MemoryMap;
    let map = uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA).ok()?;
    Some(map.entries().filter(|d| is_ram(d.ty)).map(|d| d.phys_start + d.page_count * 4096).max().unwrap_or(0).max(4 << 30))
}

/// Host build (unit tests): the test thread's end of RAM.
#[cfg(not(target_os = "uefi"))]
fn ram_top() -> Option<u64> {
    Some(crate::host::RAM_TOP.get().max(4 << 30))
}

/// The kernel stack for the higher half, from the firmware.
#[cfg(target_os = "uefi")]
fn stack_pages() -> Option<u64> {
    uefi::boot::allocate_pages(uefi::boot::AllocateType::MaxAddress(0xFFFF_FFFF), uefi::boot::MemoryType::LOADER_DATA, (STACK_SIZE / 4096) as usize)
        .ok()
        .map(|p| p.as_ptr() as u64)
}

/// Host build (unit tests): none (what follows switches the real CPU's tables).
#[cfg(not(target_os = "uefi"))]
fn stack_pages() -> Option<u64> {
    None
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
pub fn is_ram(ty: uefi::boot::MemoryType) -> bool {
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
    let top = ram_top()?;
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

// wave11 GH begin
/// Where the firmware loaded the image `(start, size)` while it still runs there (before
/// [`go_high`]): `None` if its header cannot be read.
pub fn load_range() -> Option<(u64, u64)> {
    unsafe {
        let base = core::ptr::addr_of!(__ImageBase) as u64;
        if base >= KERNEL_BASE {
            return None;
        }
        pe_info(base).map(|(_, size)| (base, size))
    }
}

/// Whether the image lies inside [2 GiB, 4 GiB): the slot of the low half the kernel keeps
/// in every address space anyway (PCI hole, APICs), so staying there takes nothing from
/// programs. Then the move to the higher half is skipped (the NUC's firmware, wave 11: an
/// AMI/Intel firmware stops in its first file read when the kernel's code runs high before
/// ExitBootServices, even with its own CR3, stack and IDT).
pub fn in_kept_low_slot(start: u64, size: u64) -> bool {
    start >= 2 << 30 && start.saturating_add(size) <= 4 << 30
}
// wave11 GH end

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
        crate::arch::crumb::step("go_high: reading the PE header");
        let Some(((rva, len), size)) = pe_info(base) else { return };
        if rva == 0 || len == 0 || size == 0 || size > 0x3000_0000 {
            return;
        }
        // Every relocation must be one this code applies, checked before touching any
        if !each_reloc(base + rva as u64, len as u64, |_| {}) {
            return;
        }
        crate::arch::crumb::step("go_high: relocations checked");
        // Hydra's top-level table: the firmware's entries (its identity map) and the top
        // entry for the image, which the firmware must not use
        let fw = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
        // The firmware uses the low half only
        if (256..512).any(|i| *((fw + i * 8) as *const u64) & PRESENT != 0) {
            return;
        }
        // wave11 GH: the higher-half entries go into the FIRMWARE's own top-level table and CR3
        // stays the firmware's: a real firmware (the NUC's) never returned from its first file
        // read under a copy of its tables at another address. The upper half is unused by
        // the firmware (checked above); its table pages may be write-protected (CR0.WP is
        // cleared while they are written). Hydra's own tables come at the takeover.
        let pml4 = fw;
        let size = (size + 4095) & !4095;
        let Some(stack) = stack_pages() else {
            return;
        };
        let built = x86_64::instructions::interrupts::without_interrupts(|| {
            let cr0 = x86_64::registers::control::Cr0::read_raw();
            x86_64::registers::control::Cr0::write_raw(cr0 & !(1 << 16));
            let ok = (|| {
                direct_map(pml4)?;
                for off in (0..size).step_by(4096) {
                    map(pml4, KERNEL_BASE + off, base + off)?;
                }
                for off in (0..STACK_SIZE).step_by(4096) {
                    map(pml4, STACK_BOTTOM + off, stack + off)?;
                }
                Some(())
            })();
            x86_64::registers::control::Cr0::write_raw(cr0);
            // (new entries only: one reload of CR3 drops whatever the TLB might hold)
            core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags));
            ok
        });
        if built.is_none() {
            // (entries already written point at pages of ours and are never used: nothing runs high)
            crate::arch::crumb::step("go_high: building the higher half failed; staying low");
            return;
        }
        crate::arch::crumb::step_fmt(format_args!("go_high: higher half in the firmware's own table at {:#x} (CR3 unchanged)", pml4));
        let delta = KERNEL_BASE.wrapping_sub(base);
        // Written through the high alias: the firmware may have made the identity pages
        // of read-only sections read-only
        each_reloc(base + rva as u64, len as u64, |r| {
            let p = (KERNEL_BASE + r) as *mut u64;
            core::ptr::write_unaligned(p, core::ptr::read_unaligned(p).wrapping_add(delta));
        });
        crate::arch::crumb::step("go_high: relocations applied; jumping high next");
        crate::memory::frame_allocator::enable_direct_map();
        IMAGE_PHYS.store(base, Ordering::SeqCst);
        IMAGE_SIZE.store(size, Ordering::SeqCst);
        let target = (next as usize as u64).wrapping_add(delta);
        // wave11 GH: the first thing at the high target prints a line through the firmware
        // with nothing but identity addresses (crumb::high_arrived)
        crate::arch::crumb::prepare_arrival();
        STACK_PHYS.store(stack, Ordering::SeqCst);
        // wave11 GH: to the high code, still on the firmware's stack (the kernel's own stack
        // is taken after ExitBootServices: run_on_kernel_stack); 16-byte aligned at the
        // call, 32 bytes of shadow space (the Microsoft x64 convention of the UEFI target)
        core::arch::asm!(
            "and rsp, -16",
            "sub rsp, 32",
            "call {target}",
            "ud2",
            target = in(reg) target,
            options(noreturn)
        );
    }
}

// wave12 GV begin: the higher half after ExitBootServices ("go_high option A")
/// How the kernel keeps out of programs' low 2 GiB (32-bit code, `MAP_32BIT`, Wine's
/// `0x7ffe0000`); the boot log's `[boot] higher half:` line says which one ran.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HighPath {
    /// [`go_high`] at the entry point, before `ExitBootServices`: the image, its stack and
    /// the heap at higher-half addresses from the start (an image the firmware loaded
    /// outside the kept 2-4 GiB slot; boot word `high=early` for any).
    Early,
    /// The default for an image in the kept 2-4 GiB slot (the NUC's firmware loads it there),
    /// and for any with the boot word `high=late`: all of boot services at the load address,
    /// exactly as the firmware gave it (the NUC's firmware stops when kernel code runs high
    /// while it runs, wave 11). Once `ExitBootServices` is done the kernel moves its stack
    /// to the heap ([`run_on_kernel_stack`]) and keeps nothing of the firmware's memory below
    /// 2 GiB in programs' address spaces (`boot_services::kernel_low_ranges`): what it
    /// reaches there afterwards goes through the direct map (frames, the boot log) or its
    /// own tables (runtime services, ACPI), as on the early path. The image stays where it is
    /// (in the kept slot it takes nothing from programs; elsewhere its range stays kept).
    Late,
    /// The path before wave 12 (boot word `high=off`): like [`HighPath::Late`] but on the
    /// firmware's stack, and every region of the firmware's final memory map below 2 GiB
    /// that is not free stays in every address space (a 2.5 GB machine kept GiB slot 1 for
    /// a 2 MiB boot-log block, and programs had a 1 GiB low window).
    Off,
}

/// The path taken (0: not decided yet, then 1 + the [`HighPath`] index).
static PATH: AtomicU8 = AtomicU8::new(0);
/// The late path's stack on the heap (its lowest byte; 0: none).
static LATE_STACK: AtomicU64 = AtomicU64::new(0);

/// The entry point's choice (pure): whether to move to the higher half now ([`go_high`]),
/// from the boot word (`high=late`, `high=early`; `high=off` and none decide as before wave
/// 12) and whether the firmware loaded the image into the kept 2-4 GiB slot.
pub fn move_at_entry(word: Option<HighPath>, in_kept_slot: bool) -> bool {
    match word {
        Some(HighPath::Late) => false,
        Some(HighPath::Early) => true,
        Some(HighPath::Off) | None => !in_kept_slot,
    }
}

/// The path once the firmware is gone (pure): early if the image moved at the entry point,
/// otherwise off with the word `high=off`, else late.
pub fn path_after_firmware(moved: bool, off: bool) -> HighPath {
    if moved {
        HighPath::Early
    } else if off {
        HighPath::Off
    } else {
        HighPath::Late
    }
}

/// The boot word among `high=early`, `high=late`, `high=off` in `text` (whitespace-separated
/// words, any case; the last one counts): pure.
pub fn parse_high_word(text: &[u8]) -> Option<HighPath> {
    let mut found = None;
    for w in text.split(|c| c.is_ascii_whitespace() || *c == 0) {
        if w.len() < 5 || !w[..5].eq_ignore_ascii_case(b"high=") {
            continue;
        }
        let v = &w[5..];
        if v.eq_ignore_ascii_case(b"early") {
            found = Some(HighPath::Early);
        } else if v.eq_ignore_ascii_case(b"late") {
            found = Some(HighPath::Late);
        } else if v.eq_ignore_ascii_case(b"off") {
            found = Some(HighPath::Off);
        }
    }
    found
}

/// Records the path taken.
pub fn set_path(p: HighPath) {
    PATH.store(1 + p as u8, Ordering::SeqCst);
}

/// The path taken: [`HighPath::Early`] once the image runs high, else what was recorded
/// (late before anything was).
pub fn path() -> HighPath {
    if IMAGE_PHYS.load(Ordering::Relaxed) != 0 {
        return HighPath::Early;
    }
    match PATH.load(Ordering::SeqCst) {
        3 => HighPath::Off,
        _ => HighPath::Late,
    }
}

/// The late path's stack on the heap `(start, size)`.
pub fn late_stack() -> Option<(u64, u64)> {
    let p = LATE_STACK.load(Ordering::Relaxed);
    (p != 0).then_some((p, STACK_SIZE))
}

/// The boot word at the entry point (before the heap; one firmware file read): from
/// `\hydra\options.txt`, or in a virtual machine (CPUID's hypervisor bit; never on real
/// hardware) from QEMU's `-fw_cfg name=opt/hydra/high,string=late|early|off`.
#[cfg(target_os = "uefi")]
pub fn entry_word() -> Option<HighPath> {
    let mut buf = [0u8; 2048];
    if in_vm() {
        if let Some(n) = crate::arch::fwcfg::read_file_into("opt/hydra/high", &mut buf[..16]) {
            let mut w = [0u8; 21];
            w[..5].copy_from_slice(b"high=");
            w[5..5 + n].copy_from_slice(&buf[..n]);
            if let Some(p) = parse_high_word(&w[..5 + n]) {
                return Some(p);
            }
        }
    }
    let n = crate::arch::bootopts::early_text(&mut buf);
    parse_high_word(&buf[..n])
}

/// Host build: no boot word.
#[cfg(not(target_os = "uefi"))]
pub fn entry_word() -> Option<HighPath> {
    None
}

/// Whether the word `high=off` was given (after the heap and the boot words exist): in the
/// boot words (`options.txt`, the load options, the start menu's entry) or QEMU's fw_cfg.
pub fn off_word() -> bool {
    if crate::arch::bootopts::say(&[b"high=off", b"HIGH=OFF"]) {
        return true;
    }
    let mut buf = [0u8; 16];
    in_vm() && crate::arch::fwcfg::read_file_into("opt/hydra/high", &mut buf).is_some_and(|n| n >= 3 && buf[..3].eq_ignore_ascii_case(b"off"))
}

/// Whether the CPU runs under a hypervisor (CPUID leaf 1, ECX bit 31): only then are QEMU's
/// fw_cfg ports read this early.
#[cfg(target_os = "uefi")]
fn in_vm() -> bool {
    (core::arch::x86_64::__cpuid(1).ecx >> 31) & 1 == 1
}

/// Host build: never (no fw_cfg ports to read).
#[cfg(not(target_os = "uefi"))]
fn in_vm() -> bool {
    false
}

/// The boot log's line for path `p` (`image` is where the firmware loaded the image).
pub fn path_line(p: HighPath, image: Option<(u64, u64)>) -> alloc::string::String {
    let (start, size) = image.unwrap_or((0, 0));
    match p {
        HighPath::Early => alloc::format!(
            "[boot] higher half: early (moved at the entry point, before ExitBootServices; image at {:#x} -> {:#x})",
            IMAGE_PHYS.load(Ordering::Relaxed),
            KERNEL_BASE
        ),
        HighPath::Late => alloc::format!(
            "[boot] higher half: late (image stays at {:#x}+{:#x}; after ExitBootServices: stack on the heap{}, no firmware memory below 2 GiB kept; boot word high=off for the path before wave 12)",
            start,
            size,
            late_stack().map_or(alloc::string::String::new(), |(s, _)| alloc::format!(" at {:#x}", s))
        ),
        HighPath::Off => alloc::format!(
            "[boot] higher half: off (boot word high=off: image stays at {:#x}+{:#x}, on the firmware's stack, every firmware region below 2 GiB kept)",
            start,
            size
        ),
    }
}
// wave12 GV end
