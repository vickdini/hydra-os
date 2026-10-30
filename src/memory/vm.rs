//! # Virtual Memory: Per-Process Address Spaces
//!
//! Implements Linux-compatible user address spaces on top of x86_64 4-level paging.
//!
//! ## Architectural Role & Design Rationale
//!
//! Each Linux process owns an [`Mm`]: a private PML4 plus an ordered set of virtual memory
//! areas ([`Vma`]). Pages are populated lazily by the page-fault handler, private pages are
//! shared copy-on-write, and file or shared-memory pages come from a [`MappedObject`]
//! (an ELF image, a page-cache file, a memfd).
//!
//! ## Address Space Layout
//!
//! ```text
//! 0x0000_0000_0000 .. 0x0080_0000_0000   PML4[0]: kernel identity map (shared, supervisor)
//! 0x0080_0000_0000 .. 0x8000_0000_0000   PML4[1..256]: private user space
//!     0x5555_5555_4000                   PIE executable load base
//!     brk heap                           grows up after the executable
//!     ... mmap area grows down from MMAP_TOP ...
//!     STACK_TOP - STACK_SIZE .. STACK_TOP  main thread stack
//! 0xFFFF_8000_0000_0000 ..               PML4[256..512]: kernel half (shared)
//! ```
//!
//! ## Locking
//!
//! The page-fault handler reaches the running process's `Mm` through [`CURRENT_MM`]
//! without taking the scheduler lock, so kernel code may touch user memory while holding
//! the scheduler or file-descriptor locks. Kernel code must never touch user memory while
//! holding an `Mm` lock or the frame allocator lock.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use spin::Mutex;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::frame_allocator::{alloc_user_frame, frame_ref_dec, frame_ref_inc, frame_refcount, FRAME_ALLOCATOR};

pub const PAGE_SIZE: u64 = 4096;

/// Lowest user virtual address (start of PML4 entry 1).
pub const USER_SPACE_START: u64 = 0x0000_0080_0000_0000;
/// One past the highest user virtual address (end of the canonical lower half).
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
/// Load base for position-independent executables (matches Linux `ELF_ET_DYN_BASE`).
pub const PIE_BASE: u64 = 0x0000_5555_5555_4000;
/// Top of the main thread stack (one guard page below the end of user space).
pub const STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;
/// Size of the main thread stack area (matches the default 8 MiB `RLIMIT_STACK`).
pub const STACK_SIZE: u64 = 8 * 1024 * 1024;
/// Top of the top-down mmap area, leaving a 1 GiB gap below the stack.
pub const MMAP_TOP: u64 = STACK_TOP - STACK_SIZE - 0x4000_0000;

pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;

// Linux errno values returned by memory operations
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;

/// Software PTE bit marking a page that holds a frame but is currently inaccessible
/// (`PROT_NONE`). The PTE keeps its frame address with `PRESENT` cleared.
const PTE_HELD: PageTableFlags = PageTableFlags::BIT_9;

/// Source of pages for file-backed and shared mappings.
///
/// `get_page` returns a frame that the object keeps a reference to; callers that map the
/// frame take their own reference with `frame_ref_inc`.
pub trait MappedObject: Send + Sync {
    /// Returns the frame holding page `pgoff` of the object, or `None` past its end.
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>>;
}

/// What a [`Vma`]'s pages are populated from.
#[derive(Clone)]
pub enum Backing {
    /// Zero-filled anonymous memory.
    Anon,
    /// Pages of a mapped object; `pgoff` is the object page that maps at `Vma::start`.
    Object { obj: Arc<dyn MappedObject>, pgoff: u64 },
}

/// A contiguous range of user virtual memory with uniform protection and backing.
#[derive(Clone)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
    pub shared: bool,
    pub backing: Backing,
}

impl Vma {
    fn split_off(&mut self, at: u64) -> Vma {
        let mut upper = self.clone();
        upper.start = at;
        if let Backing::Object { pgoff, .. } = &mut upper.backing {
            *pgoff += (at - self.start) / PAGE_SIZE;
        }
        self.end = at;
        upper
    }
}

/// Why a page fault could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultError {
    /// No mapping, or the access violates the mapping's protection (`SIGSEGV`).
    Segv,
    /// The backing object has no page at that offset (`SIGBUS`).
    Bus,
    /// Physical memory exhausted.
    OutOfMemory,
}

/// A user address space: page tables plus the areas mapped in them.
pub struct Mm {
    pml4: PhysAddr,
    vmas: BTreeMap<u64, Vma>,
    pub brk_start: u64,
    pub brk: u64,
    /// The process's auxiliary vector as passed at exec (`prctl(PR_GET_AUXV)`, `/proc/self/auxv`).
    pub auxv: Vec<u8>,
}

/// The address space of the task currently running on the CPU (null for kernel tasks).
/// Points into an `Arc<Mutex<Mm>>` kept alive by the running task.
pub static CURRENT_MM: AtomicPtr<Mutex<Mm>> = AtomicPtr::new(core::ptr::null_mut());

/// Address spaces of exited tasks, released later from a context where no locks are held.
/// Fixed-size so the scheduler can park an address space here without allocating.
static RETIRED_MMS: Mutex<[Option<Arc<Mutex<Mm>>>; 64]> = Mutex::new([const { None }; 64]);

/// Returns true if `NX` (execute-disable) is enabled in `IA32_EFER`.
fn nx_enabled() -> bool {
    let efer = unsafe { crate::arch::syscall::rdmsr(0xC000_0080) };
    efer & (1 << 11) != 0
}

#[inline]
fn table_at<'a>(phys: PhysAddr) -> &'a mut PageTable {
    unsafe { &mut *(phys.as_u64() as *mut PageTable) }
}

#[inline]
fn page_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

#[inline]
fn page_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Returns true if `[start, start + len)` lies entirely inside user space.
pub fn is_user_range(start: u64, len: u64) -> bool {
    start >= USER_SPACE_START && start.checked_add(len).map_or(false, |end| end <= USER_SPACE_END)
}

fn pte_flags_for(prot: u32, writable: bool) -> PageTableFlags {
    let mut flags = PageTableFlags::USER_ACCESSIBLE;
    if prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        flags |= PageTableFlags::PRESENT;
    } else {
        flags |= PTE_HELD;
    }
    if writable && prot & PROT_WRITE != 0 {
        flags |= PageTableFlags::WRITABLE;
    }
    if prot & PROT_EXEC == 0 && nx_enabled() {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn pte_holds_frame(entry: &PageTableEntry) -> bool {
    entry.flags().intersects(PageTableFlags::PRESENT | PTE_HELD)
}

fn flush(addr: u64) {
    x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(addr));
}

impl Mm {
    /// Creates an empty address space sharing the kernel mappings.
    pub fn new() -> Result<Self, &'static str> {
        let space = {
            let mut alloc = FRAME_ALLOCATOR.lock();
            super::paging::AddressSpace::create_user_space(&mut alloc)?
        };
        Ok(Self {
            pml4: space.pml4_physical_address(),
            vmas: BTreeMap::new(),
            brk_start: 0,
            brk: 0,
            auxv: Vec::new(),
        })
    }

    /// Physical address of this address space's PML4 (the value loaded into CR3).
    pub fn cr3(&self) -> u64 {
        self.pml4.as_u64()
    }

    /// Returns the area containing `addr`, if any.
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| addr < v.end)
    }

    /// Iterates over all areas in address order.
    pub fn vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        if let Some((_, v)) = self.vmas.range(..end).next_back() {
            return v.end > start;
        }
        false
    }

    /// Finds a free, page-aligned range of `len` bytes, searching down from `MMAP_TOP`.
    fn find_free(&self, len: u64) -> Option<u64> {
        let mut top = MMAP_TOP;
        for (_, v) in self.vmas.range(..MMAP_TOP).rev() {
            if v.end <= top && top - v.end >= len {
                return Some(top - len);
            }
            top = top.min(v.start);
        }
        if top >= USER_SPACE_START + len {
            Some(top - len)
        } else {
            None
        }
    }

    /// Walks the page tables to the leaf entry for `addr`, optionally creating tables.
    fn pte(&mut self, addr: u64, create: bool) -> Option<&'static mut PageTableEntry> {
        let indices = [
            (addr >> 39) & 0x1FF,
            (addr >> 30) & 0x1FF,
            (addr >> 21) & 0x1FF,
        ];
        let mut table = table_at(self.pml4);
        for idx in indices {
            let entry = &mut table[idx as usize];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                if !create {
                    return None;
                }
                let frame = alloc_user_frame()?;
                entry.set_addr(
                    frame.start_address(),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
                );
            }
            table = table_at(entry.addr());
        }
        Some(&mut table[((addr >> 12) & 0x1FF) as usize])
    }

    /// Returns the frame mapped at `addr`, if one is held.
    pub fn translate(&mut self, addr: u64) -> Option<PhysAddr> {
        let entry = self.pte(addr, false)?;
        if pte_holds_frame(entry) {
            Some(entry.addr() + (addr & (PAGE_SIZE - 1)))
        } else {
            None
        }
    }

    /// Unmaps every page in `[start, end)`, dropping frame references. Areas are untouched.
    fn zap_range(&mut self, start: u64, end: u64) {
        let mut addr = start;
        while addr < end {
            // Skip whole missing page tables quickly
            match self.pte(addr, false) {
                Some(entry) => {
                    if pte_holds_frame(entry) {
                        let frame = PhysFrame::containing_address(entry.addr());
                        entry.set_unused();
                        flush(addr);
                        frame_ref_dec(frame);
                    }
                    addr += PAGE_SIZE;
                }
                None => {
                    addr = (addr + 0x20_0000) & !0x1F_FFFF;
                }
            }
        }
    }

    /// Splits areas so that `addr` falls on an area boundary.
    fn split_at(&mut self, addr: u64) {
        let key = match self.vmas.range(..addr).next_back() {
            Some((&k, v)) if v.end > addr => k,
            _ => return,
        };
        let upper = self.vmas.get_mut(&key).unwrap().split_off(addr);
        self.vmas.insert(addr, upper);
    }

    /// Removes all mappings in `[start, end)`.
    pub fn unmap(&mut self, start: u64, end: u64) {
        self.split_at(start);
        self.split_at(end);
        let keys: Vec<u64> = self.vmas.range(start..end).map(|(&k, _)| k).collect();
        for k in keys {
            self.vmas.remove(&k);
        }
        self.zap_range(start, end);
    }

    /// Creates a mapping and returns its address (Linux `mmap` semantics).
    ///
    /// `fixed` replaces existing mappings at `addr`; `noreplace` fails with `EEXIST` instead.
    /// Without either, `addr` is used as a hint.
    pub fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        shared: bool,
        fixed: bool,
        noreplace: bool,
        backing: Backing,
    ) -> Result<u64, i64> {
        if len == 0 {
            return Err(-EINVAL);
        }
        let len = page_up(len);
        let start = if fixed || noreplace {
            if addr & (PAGE_SIZE - 1) != 0 || !is_user_range(addr, len) {
                return Err(-EINVAL);
            }
            if self.overlaps(addr, addr + len) {
                if noreplace {
                    return Err(-EEXIST);
                }
                self.unmap(addr, addr + len);
            }
            addr
        } else {
            let hint = page_down(addr);
            if hint != 0 && is_user_range(hint, len) && !self.overlaps(hint, hint + len) {
                hint
            } else {
                self.find_free(len).ok_or(-ENOMEM)?
            }
        };
        self.vmas.insert(
            start,
            Vma {
                start,
                end: start + len,
                prot,
                shared,
                backing,
            },
        );
        self.merge_around(start);
        Ok(start)
    }

    /// Changes protection on `[start, start + len)` (Linux `mprotect`).
    pub fn mprotect(&mut self, start: u64, len: u64, prot: u32) -> Result<(), i64> {
        if start & (PAGE_SIZE - 1) != 0 {
            return Err(-EINVAL);
        }
        let end = start + page_up(len);
        // Every page of the range must be mapped
        let mut cursor = start;
        while cursor < end {
            match self.find_vma(cursor) {
                Some(v) => cursor = v.end,
                None => return Err(-ENOMEM),
            }
        }
        self.split_at(start);
        self.split_at(end);
        let keys: Vec<u64> = self.vmas.range(start..end).map(|(&k, _)| k).collect();
        for k in keys {
            let shared = {
                let v = self.vmas.get_mut(&k).unwrap();
                v.prot = prot;
                v.shared
            };
            let vend = self.vmas[&k].end;
            let mut addr = k;
            while addr < vend {
                if let Some(entry) = self.pte(addr, false) {
                    if pte_holds_frame(entry) {
                        let frame = PhysFrame::<Size4KiB>::containing_address(entry.addr());
                        // Private pages shared with others stay read-only until a write copies them
                        let exclusive = shared || frame_refcount(frame) == 1;
                        entry.set_addr(frame.start_address(), pte_flags_for(prot, exclusive));
                        flush(addr);
                    }
                }
                addr += PAGE_SIZE;
            }
        }
        self.merge_around(start);
        self.merge_around(end);
        Ok(())
    }

    /// Grows or shrinks the program break (Linux `brk`). Returns the resulting break.
    pub fn set_brk(&mut self, new_brk: u64) -> u64 {
        if new_brk < self.brk_start || new_brk == 0 {
            return self.brk;
        }
        let old_top = page_up(self.brk);
        let new_top = page_up(new_brk);
        if new_top > old_top {
            if self.overlaps(old_top, new_top) {
                return self.brk;
            }
            self.vmas.insert(
                old_top,
                Vma {
                    start: old_top,
                    end: new_top,
                    prot: PROT_READ | PROT_WRITE,
                    shared: false,
                    backing: Backing::Anon,
                },
            );
            self.merge_around(old_top);
        } else if new_top < old_top {
            self.unmap(new_top, old_top);
        }
        self.brk = new_brk;
        self.brk
    }

    /// Returns true if `upper` directly continues `lower` with identical attributes and
    /// backing, so the two can be one area (as Linux's `vma_merge`).
    fn can_merge(lower: &Vma, upper: &Vma) -> bool {
        if lower.end != upper.start || lower.prot != upper.prot || lower.shared != upper.shared {
            return false;
        }
        match (&lower.backing, &upper.backing) {
            (Backing::Anon, Backing::Anon) => true,
            (Backing::Object { obj: a, pgoff: pa }, Backing::Object { obj: b, pgoff: pb }) => {
                core::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b)) && pa + (lower.end - lower.start) / PAGE_SIZE == *pb
            }
            _ => false,
        }
    }

    /// Merges the area starting at `start` with compatible neighbours on either side.
    fn merge_around(&mut self, start: u64) {
        let mut start = start;
        if let Some((&prev_key, prev)) = self.vmas.range(..start).next_back() {
            if let Some(cur) = self.vmas.get(&start) {
                if Self::can_merge(prev, cur) {
                    let cur = self.vmas.remove(&start).unwrap();
                    self.vmas.get_mut(&prev_key).unwrap().end = cur.end;
                    start = prev_key;
                }
            }
        }
        let end = match self.vmas.get(&start) {
            Some(v) => v.end,
            None => return,
        };
        if let Some(next) = self.vmas.get(&end) {
            if Self::can_merge(&self.vmas[&start], next) {
                let next = self.vmas.remove(&end).unwrap();
                self.vmas.get_mut(&start).unwrap().end = next.end;
            }
        }
    }

    /// Resizes or moves a mapping (Linux `mremap`).
    pub fn mremap(&mut self, old: u64, old_len: u64, new_len: u64, may_move: bool, fixed_to: Option<u64>) -> Result<u64, i64> {
        if old & (PAGE_SIZE - 1) != 0 || new_len == 0 {
            return Err(-EINVAL);
        }
        let old_len = page_up(old_len);
        let new_len = page_up(new_len);
        let vma = self.find_vma(old).cloned().ok_or(-EFAULT)?;
        if old + old_len > vma.end {
            return Err(-EFAULT);
        }

        if fixed_to.is_none() {
            if new_len <= old_len {
                self.unmap(old + new_len, old + old_len);
                return Ok(old);
            }
            // Grow in place when the area ends here and the space after it is free
            if old + old_len == vma.end && is_user_range(old, new_len) && !self.overlaps(vma.end, old + new_len) {
                self.vmas.get_mut(&vma.start).unwrap().end = old + new_len;
                return Ok(old);
            }
            if !may_move {
                return Err(-ENOMEM);
            }
        }

        let dest = match fixed_to {
            Some(d) => {
                if d & (PAGE_SIZE - 1) != 0 || !is_user_range(d, new_len) {
                    return Err(-EINVAL);
                }
                self.unmap(d, d + new_len);
                d
            }
            None => self.find_free(new_len).ok_or(-ENOMEM)?,
        };

        // Detach the source range as its own area, then move it with its page table entries
        self.split_at(old);
        self.split_at(old + old_len);
        let mut moved = self.vmas.remove(&old).ok_or(-EFAULT)?;
        let copy_len = old_len.min(new_len);
        let mut offset = 0;
        while offset < copy_len {
            if let Some(src) = self.pte(old + offset, false) {
                if pte_holds_frame(src) {
                    let (addr, flags) = (src.addr(), src.flags());
                    src.set_unused();
                    flush(old + offset);
                    let dst = self.pte(dest + offset, true).ok_or(-ENOMEM)?;
                    dst.set_addr(addr, flags);
                    flush(dest + offset);
                }
            }
            offset += PAGE_SIZE;
        }
        self.zap_range(old + copy_len, old + old_len);
        moved.start = dest;
        moved.end = dest + new_len;
        self.vmas.insert(dest, moved);
        Ok(dest)
    }

    /// Discards the contents of `[start, end)` (Linux `MADV_DONTNEED`): later accesses see
    /// zeroes (anonymous) or the object's contents (file-backed).
    pub fn discard(&mut self, start: u64, end: u64) {
        self.zap_range(page_down(start), page_up(end));
    }

    /// Resolves a page fault at `addr`. `write`/`exec` describe the faulting access.
    pub fn handle_fault(&mut self, addr: u64, write: bool, exec: bool) -> Result<(), FaultError> {
        let vma = self.find_vma(addr).cloned().ok_or(FaultError::Segv)?;
        if (write && vma.prot & PROT_WRITE == 0)
            || (exec && vma.prot & PROT_EXEC == 0)
            || vma.prot == 0
        {
            return Err(FaultError::Segv);
        }
        let page = page_down(addr);
        let entry = self.pte(page, true).ok_or(FaultError::OutOfMemory)?;

        if pte_holds_frame(entry) {
            let frame = PhysFrame::<Size4KiB>::containing_address(entry.addr());
            if !write {
                let writable = entry.flags().contains(PageTableFlags::WRITABLE);
                entry.set_addr(frame.start_address(), pte_flags_for(vma.prot, writable));
            } else if vma.shared || frame_refcount(frame) == 1 {
                entry.set_addr(frame.start_address(), pte_flags_for(vma.prot, true));
            } else {
                // Copy-on-write: take a private copy of a shared page
                let copy = alloc_user_frame().ok_or(FaultError::OutOfMemory)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.start_address().as_u64() as *const u8,
                        copy.start_address().as_u64() as *mut u8,
                        PAGE_SIZE as usize,
                    );
                }
                entry.set_addr(copy.start_address(), pte_flags_for(vma.prot, true));
                frame_ref_dec(frame);
            }
            flush(page);
            return Ok(());
        }

        match &vma.backing {
            Backing::Anon => {
                let frame = alloc_user_frame().ok_or(FaultError::OutOfMemory)?;
                entry.set_addr(frame.start_address(), pte_flags_for(vma.prot, true));
            }
            Backing::Object { obj, pgoff } => {
                let index = pgoff + (page - vma.start) / PAGE_SIZE;
                let source = obj.get_page(index).ok_or(FaultError::Bus)?;
                if vma.shared {
                    frame_ref_inc(source);
                    entry.set_addr(source.start_address(), pte_flags_for(vma.prot, true));
                } else if write {
                    let copy = alloc_user_frame().ok_or(FaultError::OutOfMemory)?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            source.start_address().as_u64() as *const u8,
                            copy.start_address().as_u64() as *mut u8,
                            PAGE_SIZE as usize,
                        );
                    }
                    entry.set_addr(copy.start_address(), pte_flags_for(vma.prot, true));
                } else {
                    // Map the object's page read-only; a later write takes a private copy
                    frame_ref_inc(source);
                    entry.set_addr(source.start_address(), pte_flags_for(vma.prot, false));
                }
            }
        }
        flush(page);
        Ok(())
    }

    /// Copies `data` into this address space at `addr`, faulting pages in as needed.
    /// Works whether or not this address space is active.
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), FaultError> {
        let mut done = 0usize;
        while done < data.len() {
            let va = addr + done as u64;
            let in_page = (PAGE_SIZE - (va & (PAGE_SIZE - 1))) as usize;
            let n = in_page.min(data.len() - done);
            let writable = self
                .pte(va, false)
                .map_or(false, |e| e.flags().contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE));
            if !writable {
                self.handle_fault(va, true, false)?;
            }
            let phys = self.translate(va).ok_or(FaultError::Segv)?;
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), phys.as_u64() as *mut u8, n);
            }
            done += n;
        }
        Ok(())
    }

    /// Faults in every page of `[addr, addr + len)` so kernel code can access it directly
    /// without page faults (used before I/O into user buffers).
    pub fn prefault(&mut self, addr: u64, len: u64, write: bool) -> Result<(), FaultError> {
        if len == 0 {
            return Ok(());
        }
        let mut page = page_down(addr);
        let end = addr.checked_add(len).ok_or(FaultError::Segv)?;
        while page < end {
            let ok = self.pte(page, false).map_or(false, |e| {
                let f = e.flags();
                f.contains(PageTableFlags::PRESENT) && (!write || f.contains(PageTableFlags::WRITABLE))
            });
            if !ok {
                self.handle_fault(page, write, false)?;
            }
            page += PAGE_SIZE;
        }
        Ok(())
    }

    fn free_tables(table_phys: PhysAddr, level: u8) {
        let table = table_at(table_phys);
        for entry in table.iter_mut() {
            if level == 1 {
                if pte_holds_frame(entry) {
                    frame_ref_dec(PhysFrame::containing_address(entry.addr()));
                }
            } else if entry.flags().contains(PageTableFlags::PRESENT) {
                Self::free_tables(entry.addr(), level - 1);
            }
            entry.set_unused();
        }
        frame_ref_dec(PhysFrame::containing_address(table_phys));
    }
}

impl Drop for Mm {
    fn drop(&mut self) {
        // Only the private user half is owned; PML4[0] and the kernel half are shared.
        let pml4 = table_at(self.pml4);
        for i in 1..256 {
            if pml4[i].flags().contains(PageTableFlags::PRESENT) {
                Self::free_tables(pml4[i].addr(), 3);
                pml4[i].set_unused();
            }
        }
        frame_ref_dec(PhysFrame::containing_address(self.pml4));
    }
}

/// Resolves a page fault against the running process's address space.
/// Returns `None` if the current task has no address space.
pub fn handle_current_fault(addr: u64, write: bool, exec: bool) -> Option<Result<(), FaultError>> {
    let ptr = CURRENT_MM.load(Ordering::Acquire);
    if ptr.is_null() || !(USER_SPACE_START..USER_SPACE_END).contains(&addr) {
        return None;
    }
    let mm = unsafe { &*ptr };
    match mm.try_lock() {
        Some(mut guard) => Some(guard.handle_fault(addr, write, exec)),
        None => panic!("page fault at {:#x} while the faulting process's Mm is locked", addr),
    }
}

/// Validates and faults in a user buffer of the running process before kernel I/O into it.
/// Returns false if the range is not mapped with the required access.
pub fn prefault_current(addr: u64, len: u64, write: bool) -> bool {
    let ptr = CURRENT_MM.load(Ordering::Acquire);
    if ptr.is_null() {
        // Legacy tasks share the kernel address space: nothing to fault in
        return true;
    }
    if len == 0 {
        return true;
    }
    if !is_user_range(addr, len) {
        return false;
    }
    let mm = unsafe { &*ptr };
    mm.lock().prefault(addr, len, write).is_ok()
}

/// Makes `mm` the address space the page-fault handler resolves against.
pub fn set_current_mm(mm: Option<&Arc<Mutex<Mm>>>) {
    let ptr = mm.map_or(core::ptr::null_mut(), |m| Arc::as_ptr(m) as *mut Mutex<Mm>);
    CURRENT_MM.store(ptr, Ordering::Release);
}

/// Parks an exited task's address space for later release. Never allocates, so it is
/// safe to call from the scheduler. Returns the address space back if the queue is full
/// or busy, in which case the caller keeps it and retries later.
pub fn retire_mm(mm: Arc<Mutex<Mm>>) -> Result<(), Arc<Mutex<Mm>>> {
    let mut slots = match RETIRED_MMS.try_lock() {
        Some(s) => s,
        None => return Err(mm),
    };
    for slot in slots.iter_mut() {
        if slot.is_none() {
            *slot = Some(mm);
            return Ok(());
        }
    }
    Err(mm)
}

/// Releases parked address spaces. Call only where no frame-allocator or heap locks are
/// held and none of the parked address spaces is active.
pub fn reap_retired_mms() {
    let mut taken: [Option<Arc<Mutex<Mm>>>; 64] = [const { None }; 64];
    if let Some(mut slots) = RETIRED_MMS.try_lock() {
        for (dst, src) in taken.iter_mut().zip(slots.iter_mut()) {
            *dst = src.take();
        }
    }
    drop(taken);
}

/// Next free address in the window used to map shared frames for legacy tasks that run in
/// the kernel address space (PML4 entry 32, never present in private address spaces).
static LEGACY_WINDOW_NEXT: Mutex<u64> = Mutex::new(0x0000_1000_0000_0000);

/// Maps `frames` contiguously and user-accessibly into the kernel address space and
/// returns the start address. Used by legacy (non-`Mm`) tasks for `mmap` of shared memory.
pub fn map_into_kernel_space(frames: &[PhysFrame<Size4KiB>], writable: bool) -> Option<u64> {
    let start = {
        let mut next = LEGACY_WINDOW_NEXT.lock();
        let start = *next;
        *next += (frames.len() as u64 + 1) * PAGE_SIZE;
        start
    };
    let mut guard = super::paging::KERNEL_SPACE.lock();
    let space = guard.as_mut()?;
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    for (i, frame) in frames.iter().enumerate() {
        let page = x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(start + i as u64 * PAGE_SIZE));
        frame_ref_inc(*frame);
        let mut alloc = FRAME_ALLOCATOR.lock();
        unsafe { space.map_page(page, *frame, flags, &mut alloc).ok()? };
    }
    Some(start)
}

/// A mapped object backed by an in-memory byte buffer (an ELF image read into memory).
/// Pages are materialised into frames on first use and kept for the object's lifetime.
pub struct BufferObject {
    data: Box<[u8]>,
    pages: Mutex<BTreeMap<u64, PhysFrame<Size4KiB>>>,
}

impl BufferObject {
    pub fn new(data: Box<[u8]>) -> Arc<Self> {
        Arc::new(Self {
            data,
            pages: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl MappedObject for BufferObject {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        let offset = (pgoff * PAGE_SIZE) as usize;
        if offset >= page_up(self.data.len() as u64) as usize {
            return None;
        }
        let mut pages = self.pages.lock();
        if let Some(&frame) = pages.get(&pgoff) {
            return Some(frame);
        }
        let frame = alloc_user_frame()?;
        let n = (self.data.len() - offset).min(PAGE_SIZE as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data[offset..].as_ptr(),
                frame.start_address().as_u64() as *mut u8,
                n,
            );
        }
        pages.insert(pgoff, frame);
        Some(frame)
    }
}

impl Drop for BufferObject {
    fn drop(&mut self) {
        for (_, frame) in self.pages.lock().iter() {
            frame_ref_dec(*frame);
        }
    }
}
