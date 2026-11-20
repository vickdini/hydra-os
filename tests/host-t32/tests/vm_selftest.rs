//! `memory/vm.rs`'s boot self-tests of PCID and global pages, run against the fake CPU (a
//! page-table walk with no TLB: every invalidation "works", and the control comes out
//! "inconclusive"). Own binary: PCID and global pages stay on.

mod common;

use hydra_hosttests_t32::arch::pcid;
use hydra_hosttests_t32::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests_t32::memory::paging::{self, AddressSpace};
use hydra_hosttests_t32::memory::vm;
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

#[test]
fn boot_self_tests() {
    host::reset();
    stubs::reset();
    host::set_cpu(1);
    common::boot_cr3();
    // Off: skipped
    assert_eq!(vm::tlb_self_test(), Ok("skipped (PCID off)".into()));
    assert_eq!(vm::global_self_test(), Ok("skipped (global pages off)".into()));
    // The kernel's own tables (with the direct map), loaded
    let k = AddressSpace::create_kernel_space(&mut FRAME_ALLOCATOR.lock()).unwrap();
    let kp = k.pml4_physical_address().as_u64();
    *paging::KERNEL_SPACE.lock() = Some(k);
    hw::set_cr(3, kp);
    pcid::init_with(true, true);
    let r = vm::tlb_self_test();
    assert!(r.as_ref().is_ok_and(|s| s.starts_with("passed")), "{r:?}");
    assert!(r.unwrap().contains("inconclusive"), "no TLB on the host");
    assert_eq!(hw::cr(3) & 0x000F_FFFF_FFFF_F000, kp, "back on the kernel's tables");
    pcid::enable_global();
    assert!(pcid::global_enabled());
    let r = vm::global_self_test();
    assert!(r.as_ref().is_ok_and(|s| s.starts_with("passed")), "{r:?}");
    // The test page is gone again
    let k = paging::KERNEL_SPACE.lock();
    assert!(unsafe { k.as_ref().unwrap().leaf_entry(0xFFFF_FFFF_7FE0_0000) }.map_or(true, |e| e.is_unused()));
    drop(k);
    // Without a kernel address space the global test cannot run
    *paging::KERNEL_SPACE.lock() = None;
    assert_eq!(vm::global_self_test(), Err("no kernel address space".into()));
}
