//! # The vDSO
//!
//! A small shared object mapped into every Linux process (`[vdso]`, its address in
//! `AT_SYSINFO_EHDR`), with `clock_gettime`, `gettimeofday`, `time` and `clock_getres`
//! running in user mode: no system call, so no kernel lock, for the most frequent calls of
//! graphical programs. The image is built from `userland/vdso` (see its `build.sh`); the
//! page just below it (`[vvar]`, read-only, shared by every process) holds the clock's
//! state, which [`publish`] updates on every timer tick under a sequence counter.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use spin::Once;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::memory::vm::{Backing, MappedObject, Mm, PROT_EXEC, PROT_READ};

/// The vDSO image (a shared object with no relocations, linked at 0).
static IMAGE: &[u8] = include_bytes!("../../userland/vdso/vdso.so");

const PAGE: u64 = 4096;

/// The [vvar] page's layout (shared with `userland/vdso/vdso.c`).
#[repr(C)]
struct Vvar {
    seq: u64,
    base_ns: u64,
    base_frac: u64,
    base_tsc: u64,
    mult: u64,
    wall_ns: i64,
}

/// The [vvar] page and the image's pages, in that order.
struct Pages {
    frames: Vec<PhysFrame<Size4KiB>>,
}

impl MappedObject for Pages {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        self.frames.get(pgoff as usize).copied()
    }
}

static PAGES: Once<Option<Arc<Pages>>> = Once::new();
/// The [vvar] page as the kernel writes it (null until the pages exist).
static VVAR: AtomicPtr<Vvar> = AtomicPtr::new(core::ptr::null_mut());

/// The pages, made on first use: the frames keep their first reference, so they are never
/// freed.
fn pages() -> Option<Arc<Pages>> {
    PAGES
        .call_once(|| {
            let count = 1 + (IMAGE.len() as u64).div_ceil(PAGE) as usize;
            let mut frames = Vec::with_capacity(count);
            for _ in 0..count {
                frames.push(crate::memory::frame_allocator::alloc_user_frame()?);
            }
            for (i, f) in frames.iter().enumerate() {
                let p = crate::memory::frame_allocator::phys_to_virt(f.start_address().as_u64());
                unsafe {
                    core::ptr::write_bytes(p, 0, PAGE as usize);
                    if i > 0 {
                        let off = (i - 1) * PAGE as usize;
                        let len = (IMAGE.len() - off).min(PAGE as usize);
                        core::ptr::copy_nonoverlapping(IMAGE[off..].as_ptr(), p, len);
                    }
                }
            }
            VVAR.store(crate::memory::frame_allocator::phys_to_virt(frames[0].start_address().as_u64()) as *mut Vvar, Ordering::Release);
            publish();
            Some(Arc::new(Pages { frames }))
        })
        .clone()
}

/// Maps [vvar] and [vdso] into the address space `mm` of a new program.
///
/// # Returns
/// The vDSO's address (`AT_SYSINFO_EHDR`), or `None` if it could not be mapped.
pub fn map(mm: &mut Mm) -> Option<u64> {
    let p = pages()?;
    let code = (p.frames.len() as u64 - 1) * PAGE;
    // A place for both, the [vvar] page first
    let base = mm.mmap(0, PAGE + code, PROT_READ, true, false, false, Backing::Object { obj: p.clone(), pgoff: 0 }).ok()?;
    mm.mmap(base + PAGE, code, PROT_READ | PROT_EXEC, true, true, false, Backing::Object { obj: p, pgoff: 1 }).ok()?;
    mm.set_name(base, base + PAGE, Some("[vvar]"));
    mm.set_name(base + PAGE, base + PAGE + code, Some("[vdso]"));
    Some(base + PAGE)
}

/// Writes the clock's state to [vvar] (the timer tick, setting the wall clock): readers
/// retry while the sequence counter is odd or changed.
pub fn publish() {
    let v = VVAR.load(Ordering::Acquire);
    if v.is_null() {
        return;
    }
    let (base_ns, base_frac, base_tsc, mult) = crate::arch::pit::clock_state();
    let wall = crate::arch::rtc::wall_base_ns();
    unsafe {
        let seq = core::ptr::read_volatile(&(*v).seq);
        core::ptr::write_volatile(&mut (*v).seq, seq | 1);
        core::sync::atomic::fence(Ordering::SeqCst);
        core::ptr::write_volatile(&mut (*v).base_ns, base_ns);
        core::ptr::write_volatile(&mut (*v).base_frac, base_frac);
        core::ptr::write_volatile(&mut (*v).base_tsc, base_tsc);
        core::ptr::write_volatile(&mut (*v).mult, mult);
        core::ptr::write_volatile(&mut (*v).wall_ns, wall);
        core::sync::atomic::fence(Ordering::SeqCst);
        core::ptr::write_volatile(&mut (*v).seq, (seq | 1) + 1);
    }
}
