//! `memory/vm.rs` and `memory/frame_allocator.rs` (the parts the lead's `tests/host` does
//! not reach), and `arch/vdso.rs`: the running task's address space (faults, prefaults,
//! shared pages), retiring address spaces, the legacy kernel window, buffer and memory
//! objects, `/proc/<pid>/maps` text, discarding, write-denied mappings, the vDSO mapping.
//!
//! Each test thread plays its own CPU, so its "current address space" (a per-CPU pointer)
//! is its own.

mod common;

use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex, MutexGuard};

use hydra_hosttests_t32::arch::vdso;
use hydra_hosttests_t32::memory::frame_allocator::{self as fa, FRAME_ALLOCATOR};
use hydra_hosttests_t32::memory::vm::{self, Backing, BufferObject, FaultError, MappedObject, MemObject, Mm, PROT_EXEC, PROT_READ, PROT_WRITE};
use hydra_hosttests_t32::{host, stubs};

/// Plays CPU `cpu`, with every other test of this binary waiting (frames freed by one test
/// would otherwise be reused by another while its reference counts are checked).
#[must_use]
fn setup(cpu: usize) -> MutexGuard<'static, ()> {
    let g = global();
    host::reset();
    stubs::reset();
    host::set_cpu(cpu);
    common::boot_cr3();
    g
}

fn global() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn current_address_space_faults() {
    let _g = setup(1);
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    let (private, shared) = {
        let mut m = mm.lock();
        let p = m.mmap(0, 0x3000, PROT_READ | PROT_WRITE, false, false, false, Backing::Anon).unwrap();
        let s = m.mmap(0, 0x1000, PROT_READ | PROT_WRITE, true, false, false, Backing::Anon).unwrap();
        (p, s)
    };
    // No current address space: kernel tasks fault nothing in, and prefault says yes
    vm::set_current_mm(None);
    assert_eq!(vm::handle_current_fault(private, true, false), None);
    assert!(vm::prefault_current(private, 8, true));
    assert_eq!(vm::shared_phys_current(shared), None);
    assert!(vm::uffd_resolve_current(private, true, false));
    // This task's
    vm::set_current_mm(Some(&mm));
    assert_eq!(vm::handle_current_fault(private + 0x10, true, false), Some(Ok(())));
    assert!(mm.lock().translate(private).is_some());
    assert_eq!(vm::handle_current_fault(0xFFFF_8000_0000_0000, false, false), None, "kernel address");
    assert_eq!(vm::handle_current_fault(0x10, false, false), None, "below the user window");
    assert_eq!(vm::handle_current_fault(0x2_0000, false, false), Some(Err(FaultError::Segv)), "nothing mapped there");
    assert_eq!(vm::handle_current_fault(private, false, true), Some(Err(FaultError::Segv)), "not executable");
    assert!(vm::prefault_current(private + 0x1000, 0x2000, true));
    assert!(mm.lock().translate(private + 0x2000).is_some());
    assert!(vm::prefault_current(private, 0, true), "nothing to do");
    assert!(!vm::prefault_current(0xFFFF_8000_0000_0000, 8, false), "not user memory");
    assert!(!vm::prefault_current(0x10, 8, false), "unmapped");
    // Shared pages have a stable physical address; private ones do not count
    vm::handle_current_fault(shared, true, false).unwrap().unwrap();
    let pa = vm::shared_phys_current(shared + 8).unwrap();
    assert_eq!(pa, mm.lock().translate(shared + 8).unwrap().as_u64());
    assert_eq!(vm::shared_phys_current(private), None);
    assert_eq!(vm::shared_phys_current(0x10), None);
    assert!(vm::uffd_resolve_current(private, false, true), "no userfaultfd");
    vm::set_current_mm(None);
}

#[test]
fn a_fault_while_the_mm_is_locked_is_reported() {
    // The kernel's fault path finds the faulting process's lock taken (a fault inside code
    // holding it): a clear panic instead of a deadlock
    let _g = setup(2);
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    let a = mm.lock().mmap(0, 0x1000, PROT_READ, false, false, false, Backing::Anon).unwrap();
    vm::set_current_mm(Some(&mm));
    let guard = mm.lock();
    let r = std::panic::catch_unwind(|| vm::handle_current_fault(a, false, false));
    drop(guard);
    vm::set_current_mm(None);
    let e = r.expect_err("reported");
    let msg = e.downcast_ref::<String>().unwrap();
    assert!(msg.contains("while the faulting process's Mm is locked") && msg.contains("cpu 2"), "{msg}");
}

#[test]
fn retired_address_spaces() {
    let _g = setup(3);
    vm::reap_retired_mms();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    let weak = Arc::downgrade(&mm);
    assert!(vm::retire_mm(mm).is_ok());
    assert!(weak.upgrade().is_some(), "kept until reaped");
    vm::reap_retired_mms();
    assert!(weak.upgrade().is_none(), "freed by the reaper");
    // 64 slots: the 65th comes back
    let mut kept = Vec::new();
    for _ in 0..64 {
        let m = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
        kept.push(Arc::downgrade(&m));
        assert!(vm::retire_mm(m).is_ok());
    }
    let extra = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    assert!(vm::retire_mm(extra).is_err());
    vm::reap_retired_mms();
    assert!(kept.iter().all(|w| w.upgrade().is_none()));
}

#[test]
fn maps_text_names_and_write_denial() {
    let _g = setup(4);
    let mut m = Mm::new().unwrap();
    let obj: Arc<dyn MappedObject> = BufferObject::new(vec![7u8; 0x3000].into_boxed_slice());
    let code = m.mmap(0, 0x2000, PROT_READ | PROT_EXEC, false, false, false, Backing::Object { obj: obj.clone(), pgoff: 1 }).unwrap();
    let data = m.mmap(0, 0x1000, PROT_READ | PROT_WRITE, true, false, false, Backing::Anon).unwrap();
    m.set_name(code, code + 0x2000, Some("/usr/lib/libx.so"));
    let text = m.maps_text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    let code_line = lines.iter().find(|l| l.starts_with(&format!("{code:08x}"))).unwrap();
    assert!(code_line.starts_with(&format!("{:08x}-{:08x} r-xp 00001000 00:00 0", code, code + 0x2000)), "{code_line}");
    assert_eq!(code_line.find("/usr/lib/libx.so"), Some(73), "names start at a fixed column");
    let data_line = lines.iter().find(|l| l.starts_with(&format!("{data:08x}"))).unwrap();
    assert_eq!(*data_line, format!("{:08x}-{:08x} rw-s 00000000 00:00 0", data, data + 0x1000));
    // Naming part of a mapping splits it
    m.set_name(code + 0x1000, code + 0x2000, Some("tail"));
    assert_eq!(m.vmas().count(), 3);
    assert_eq!(m.next_vma_start(code), Some(code + 0x1000));
    // A write-denied mapping cannot be made writable
    m.deny_write(code, code + 0x2000);
    assert_eq!(m.mprotect(code, 0x1000, PROT_READ | PROT_WRITE), Err(-13));
    assert_eq!(m.mprotect(code, 0x1000, PROT_READ), Ok(()));
    // Usage: the object's pages count as file memory once faulted in
    m.handle_fault(code, false, false).unwrap();
    m.handle_fault(data, true, false).unwrap();
    let (size, anon, file) = m.memory_usage();
    assert_eq!((size, anon, file), (0x3000, 1, 1));
    // Discarding drops the pages, keeps the mappings
    m.discard(data, data + 0x1000);
    assert!(m.translate(data).is_none());
    assert!(m.find_vma(data).is_some());
    m.discard(0, u64::MAX);
    assert!(m.translate(code).is_none());
    assert_eq!(m.cr3() & 0xFFF, 0);
}

#[test]
fn present_user_checks_permissions() {
    let _g = setup(5);
    let mut m = Mm::new().unwrap();
    let a = m.mmap(0, 0x2000, PROT_READ | PROT_WRITE, false, false, false, Backing::Anon).unwrap();
    assert_eq!(m.present_user(a, false), None, "not faulted in");
    m.handle_fault(a, false, false).unwrap();
    // A read fault maps the shared zero page read-only (or a fresh page): readable now
    assert!(m.present_user(a + 8, false).is_some());
    m.handle_fault(a, true, false).unwrap();
    let pa = m.present_user(a + 8, true).unwrap();
    assert_eq!(pa, m.translate(a + 8).unwrap());
    m.mprotect(a, 0x1000, PROT_READ).unwrap();
    assert_eq!(m.present_user(a, true), None, "read-only now");
    assert!(m.present_user(a, false).is_some());
    assert_eq!(m.present_user(0x7000_0000_0000, false), None);
}

#[test]
fn buffer_objects() {
    let _g = setup(6);
    let mut data = vec![0u8; 0x1800];
    data[0x1000] = 0xAB;
    let b = BufferObject::new(data.into_boxed_slice());
    assert_eq!(b.len(), 0x1800);
    assert_eq!(b.bytes()[0x1000], 0xAB);
    let f = b.get_page(1).unwrap();
    assert_eq!(unsafe { *(fa::phys_to_virt(f.start_address().as_u64())) }, 0xAB, "copied in");
    assert_eq!(b.get_page(1), Some(f), "kept");
    assert_eq!(b.get_page(2), None, "past the end");
    assert_eq!(fa::frame_refcount(f), 1);
    let f0 = b.get_page(0).unwrap();
    drop(b);
    assert_eq!(fa::frame_refcount(f), 0, "released with the object");
    assert_eq!(fa::frame_refcount(f0), 0);
}

#[test]
fn memory_objects() {
    let _g = setup(7);
    let a = MemObject::anon(3);
    assert_eq!((a.pages(), a.resident(), a.phys_base()), (3, 0, None));
    let f = a.get_page(2).unwrap();
    assert_eq!(a.get_page(2), Some(f));
    assert_eq!(a.resident(), 1);
    assert_eq!(a.get_page(3), None);
    assert!(!a.tracks_writes());
    a.page_written(0);
    a.sync();
    drop(a);
    assert_eq!(fa::frame_refcount(f), 0);
    // Frames given to the object: computed pages, the owner told at the end
    let base = fa::alloc_user_frame().unwrap().start_address().as_u64();
    let told = Arc::new(Mutex::new(None));
    let t = told.clone();
    let o = MemObject::frames(base, 1, true, Some(Box::new(move |b, l| *t.lock().unwrap() = Some((b, l)))));
    assert_eq!((o.pages(), o.resident(), o.phys_base()), (1, 1, Some(base)));
    assert_eq!(o.get_page(0).unwrap().start_address().as_u64(), base);
    assert_eq!(o.get_page(1), None);
    drop(o);
    assert_eq!(*told.lock().unwrap(), Some((base, 4096)));
    assert_eq!(fa::frame_refcount(x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(base))), 0, "owned: released");
    // Not owned: left alone
    let base2 = fa::alloc_user_frame().unwrap();
    let o = MemObject::frames(base2.start_address().as_u64(), 1, false, None);
    drop(o);
    assert_eq!(fa::frame_refcount(base2), 1);
    fa::frame_ref_dec(base2);
}

#[test]
fn legacy_kernel_window() {
    let _g = setup(8);
    let f = fa::alloc_user_frame().unwrap();
    // No kernel address space yet: nothing mapped
    *hydra_hosttests_t32::memory::paging::KERNEL_SPACE.lock() = None;
    assert_eq!(vm::map_into_kernel_space(&[f], true), None);
    // With one: mapped user-accessible in the window, the frame referenced again
    let pml4 = FRAME_ALLOCATOR.lock().allocate_zeroed_frame().unwrap().start_address();
    *hydra_hosttests_t32::memory::paging::KERNEL_SPACE.lock() = Some(hydra_hosttests_t32::memory::paging::AddressSpace::from_pml4(pml4));
    let a = vm::map_into_kernel_space(&[f, f], false).unwrap();
    assert!(a >= 0x0000_1000_0000_0000);
    assert_eq!(fa::frame_refcount(f), 3);
    let k = hydra_hosttests_t32::memory::paging::KERNEL_SPACE.lock();
    let (fr, fl) = unsafe { k.as_ref().unwrap().translate_page(x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(a + 4096))).unwrap() };
    assert_eq!(fr, f);
    use x86_64::structures::paging::PageTableFlags as F;
    assert!(fl.contains(F::USER_ACCESSIBLE) && !fl.contains(F::WRITABLE));
    drop(k);
    let b = vm::map_into_kernel_space(&[f], true).unwrap();
    assert_eq!(b, a + 3 * 4096, "one guard page between windows");
    *hydra_hosttests_t32::memory::paging::KERNEL_SPACE.lock() = None;
}

#[test]
fn nx_follows_efer() {
    let _g = setup(9);
    let mut m = Mm::new().unwrap();
    let a = m.mmap(0, 0x1000, PROT_READ | PROT_WRITE, false, false, false, Backing::Anon).unwrap();
    m.handle_fault(a, true, false).unwrap();
    // (the leaf's NX bit comes from nx_enabled(), i.e. EFER.NXE)
    use x86_64::structures::paging::PageTableFlags as F;
    let s = hydra_hosttests_t32::memory::paging::AddressSpace::from_pml4(x86_64::PhysAddr::new(m.cr3()));
    let (_, fl) = unsafe { s.translate_page(x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(a))).unwrap() };
    assert!(fl.contains(F::NO_EXECUTE));
    host::NX.set(false);
    let b = m.mmap(0, 0x1000, PROT_READ | PROT_WRITE, false, false, false, Backing::Anon).unwrap();
    m.handle_fault(b, true, false).unwrap();
    let (_, fl) = unsafe { s.translate_page(x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(b))).unwrap() };
    assert!(!fl.contains(F::NO_EXECUTE));
    host::NX.set(true);
}

#[test]
fn vdso_mapping_and_clock_page() {
    let _g = setup(10);
    let mut m = Mm::new().unwrap();
    let code = vdso::map(&mut m).unwrap();
    let vvar = code - 4096;
    assert_eq!(m.find_vma(vvar).unwrap().name.as_deref(), Some("[vvar]"));
    assert_eq!(m.find_vma(code).unwrap().name.as_deref(), Some("[vdso]"));
    assert!(m.find_vma(vvar).unwrap().shared && !m.find_vma(vvar).unwrap().may_write);
    assert_eq!(m.mprotect(vvar, 4096, PROT_READ | PROT_WRITE), Err(-13), "the clock page never becomes writable");
    // The code is the image, privately mapped (a breakpoint makes a copy)
    m.handle_fault(code, false, true).unwrap();
    let pa = m.translate(code).unwrap().as_u64();
    let elf = unsafe { core::slice::from_raw_parts(fa::phys_to_virt(pa), 4) };
    assert_eq!(elf, b"\x7fELF");
    assert!(!m.find_vma(code).unwrap().shared);
    // The clock page holds the clock: published at every tick
    m.handle_fault(vvar, false, false).unwrap();
    let v = fa::phys_to_virt(m.translate(vvar).unwrap().as_u64()) as *const u64;
    let seq0 = unsafe { *v };
    assert_eq!(seq0 & 1, 0, "not mid-update");
    vdso::publish();
    let seq1 = unsafe { *v };
    assert_eq!(seq1, seq0 + 2);
    let (base_ns, _, _, mult) = hydra_hosttests_t32::arch::pit::clock_state();
    unsafe {
        assert_eq!(*v.add(1), base_ns);
        assert_eq!(*v.add(4), mult);
        assert_eq!(*v.add(5) as i64, hydra_hosttests_t32::arch::rtc::wall_base_ns());
    }
    // A second process shares the same clock frame; vvar alone for 32-bit programs
    let mut m2 = Mm::new().unwrap();
    let v2 = vdso::map_vvar(&mut m2).unwrap();
    m2.handle_fault(v2, false, false).unwrap();
    assert_eq!(m2.translate(v2), m.translate(vvar));
    assert_eq!(m2.find_vma(v2).unwrap().name.as_deref(), Some("[vvar]"));
    let _ = SeqCst;
}
