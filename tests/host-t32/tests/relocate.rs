//! `arch/relocate.rs`: the move to the higher half up to the point of no return. On the
//! host the image is the test program's own PE file (`__ImageBase`), which has the same
//! kind of base relocations as the kernel's; the firmware's pages come from the frame
//! allocator, and the stack allocation fails so `go_high` returns before switching.

mod common;

use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::relocate;
use hydra_hosttests_t32::host;
use hydra_hosttests_t32::memory::frame_allocator::FRAME_ALLOCATOR;
use x86_64::hw;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    common::global_frames();
    g
}

fn never() -> ! {
    panic!("go_high must not jump here on the host")
}

extern "C" {
    static __ImageBase: u8;
}

/// SizeOfImage of the test program, read from its PE header.
fn image_size() -> u64 {
    unsafe {
        let base = &__ImageBase as *const u8 as u64;
        let nt = base + *((base + 0x3c) as *const u32) as u64;
        *((nt + 24 + 56) as *const u32) as u64
    }
}

/// Firmware tables: a PML4 with only low entries.
fn firmware_tables(upper: bool) -> u64 {
    let f = FRAME_ALLOCATOR.lock().allocate_zeroed_frame().unwrap().start_address().as_u64();
    unsafe {
        *(f as *mut u64) = 0x1000 | 3;
        if upper {
            *((f + 300 * 8) as *mut u64) = 0x2000 | 3;
        }
    }
    f
}

#[test]
fn ram_types() {
    use uefi::boot::MemoryType as T;
    for t in [T::CONVENTIONAL, T::LOADER_CODE, T::LOADER_DATA, T::BOOT_SERVICES_CODE, T::BOOT_SERVICES_DATA, T::RUNTIME_SERVICES_CODE, T::RUNTIME_SERVICES_DATA, T::ACPI_RECLAIM, T::ACPI_NON_VOLATILE, T::PERSISTENT_MEMORY] {
        assert!(relocate::is_ram(t), "{t:?}");
    }
    for t in [T::MMIO, T::MMIO_PORT_SPACE, T::RESERVED, T::UNUSABLE, T::PAL_CODE] {
        assert!(!relocate::is_ram(t), "{t:?}");
    }
    assert_eq!(relocate::image_phys(), None, "never moved on the host");
    assert_eq!(relocate::stack_phys(), None);
}

#[test]
fn firmware_using_the_upper_half_keeps_the_identity_addresses() {
    let _g = serial();
    hw::set_cr(3, firmware_tables(true));
    let before = FRAME_ALLOCATOR.lock().allocated_memory();
    relocate::go_high(never);
    assert_eq!(FRAME_ALLOCATOR.lock().allocated_memory(), before, "nothing allocated");
    assert_eq!(relocate::image_phys(), None);
}

#[test]
fn no_memory_for_the_tables() {
    let _g = serial();
    hw::set_cr(3, firmware_tables(false));
    host::RELOC_NO_MEMORY.set(true);
    relocate::go_high(never);
    assert_eq!(relocate::image_phys(), None);
}

#[test]
fn stops_without_a_stack_before_touching_the_firmware_tables() {
    // wave11 GH: the higher half goes into the firmware's own top-level table (CR3 stays);
    // the stack comes first, so without one nothing is allocated or written
    let _g = serial();
    let fw = firmware_tables(false);
    hw::set_cr(3, fw);
    host::RAM_TOP.set(6 << 30);
    let before = FRAME_ALLOCATOR.lock().allocated_memory();
    relocate::go_high(never);
    let pages = (FRAME_ALLOCATOR.lock().allocated_memory() - before) / 4096;
    assert_eq!(pages, 0, "nothing built without a stack");
    assert!((256..512).all(|i| unsafe { *((fw + i * 8) as *const u64) } & 1 == 0), "the firmware's upper half untouched");
    assert_eq!(relocate::image_phys(), None, "returned before the move");
    assert_eq!(hw::cr(3), fw, "still on the firmware's tables");
    // Without NX: the same (the direct map is executable then)
    host::NX.set(false);
    relocate::go_high(never);
    host::NX.set(true);
    assert_eq!(relocate::image_phys(), None);
}
