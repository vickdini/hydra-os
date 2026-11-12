//! # Virtual Memory: Per-Process Address Spaces
//!
//! Implements Linux-compatible user address spaces on top of x86_64 4-level paging.
//!
//! ## Architectural Role & Design Rationale
//!
//! Each Linux process owns an `Mm`: a private PML4 plus an ordered set of virtual memory
//! areas (`Vma`). Pages are populated lazily by the page-fault handler, private pages are
//! shared copy-on-write, and file or shared-memory pages come from a `MappedObject`
//! (an ELF image, a page-cache file, a memfd).
//!
//! ## Key Types & Interfaces
//!
//! - `Mm`: Per-process virtual memory descriptor managing a private `PML4` and `BTreeMap` of `Vma`s.
//! - `Vma` & `Backing`: Contiguous user virtual memory area and its backing store (`Anon` or `Object`).
//! - `MappedObject` & `BufferObject`: Trait and in-memory implementation for file/shared page sources.
//! - `FaultError` & `handle_current_fault`: Demand-paging and copy-on-write page fault resolution.
//!
//! ## Hardware & Dependency Context
//!
//! - **Paging & NX**: Manipulates 4-level x86_64 page tables, checking `IA32_EFER.NXE` (`0xC000_0080`)
//!   before setting `PageTableFlags::NO_EXECUTE`, and uses software bit 9 (`PTE_HELD`) for `PROT_NONE` pages.
//! - **Physical Frames**: Relies on `super::frame_allocator` reference counting for copy-on-write sharing.
//!
//! ## Address Space Layout
//!
//! ```text
//! 0x0000_0000_0000 .. 0x0080_0000_0000   PML4[0]: 1 GiB slots, each the process's or the
//!                                          kernel's (identity map, shared, supervisor):
//!     0x0001_0000 .. 0x4000_0000           slot 0: always the process's (0x400000 executables)
//!     0x4000_0000 .. 0x8000_0000           slot 1: the process's unless kernel memory is there
//!                                          (32-bit code, Wine's 0x7ffe0000, MAP_32BIT)
//!     0x8000_0000 .. 0x1_0000_0000         slots 2-3: the kernel's (its image, firmware, devices)
//!     0x1_0000_0000 ..                     the process's but where the kernel heap, firmware
//!                                          or device memory is (see KERNEL_LOW_SLOTS)
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
//! The page-fault handler reaches the running process's `Mm` through `CURRENT_MM`
//! without taking the scheduler lock, so kernel code may touch user memory while holding
//! the scheduler or file-descriptor locks. Kernel code must never touch user memory while
//! holding an `Mm` lock or the frame allocator lock.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::frame_allocator::{alloc_user_frame, frame_ref_dec, frame_ref_inc, frame_refcount, FRAME_ALLOCATOR};

/// Size of a standard 4 KiB virtual page in bytes.
pub const PAGE_SIZE: u64 = 4096;

/// Lowest user virtual address of the main user area (start of PML4 entry 1).
pub const USER_SPACE_START: u64 = 0x0000_0080_0000_0000;
/// Lowest address of the low user window (Linux's default `mmap_min_addr`).
pub const LOW_USER_START: u64 = 0x1_0000;
/// End of the low user window: the first GiB, where non-PIE executables are linked. Each
/// address space has its own page tables here, so the kernel never uses physical memory
/// below this address (see `frame_allocator::init_memory_from_uefi`).
pub const LOW_USER_END: u64 = 0x4000_0000;
/// One past the highest user virtual address (end of the canonical lower half).
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// The 1 GiB slots of the first 512 GiB (PML4 entry 0) the kernel keeps in every address
/// space (bit `i`: `[i GiB, i+1 GiB)`): where it runs and what it reaches at its physical
/// address (its image, heap and boot stack, firmware and ACPI tables, device memory). The
/// others belong to the process. Slot 0 is always the process's. Until
/// [`init_low_layout`] runs (and in host tests): all slots but 0, the original layout.
static KERNEL_LOW_SLOTS: [core::sync::atomic::AtomicU64; 8] = [
    core::sync::atomic::AtomicU64::new(!1),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
    core::sync::atomic::AtomicU64::new(!0),
];

/// Whether 1 GiB slot `i` of the first 512 GiB is the kernel's in every address space.
pub fn kernel_low_slot(i: usize) -> bool {
    i < 512 && KERNEL_LOW_SLOTS[i / 64].load(Ordering::Relaxed) >> (i % 64) & 1 == 1
}

/// Sets which low slots are the kernel's: those overlapping any of `ranges` (physical =
/// identity-mapped `[start, end)`), never slot 0. Called once at the hardware takeover,
/// before the first process.
pub fn init_low_layout(ranges: &[(u64, u64)]) {
    let mut bits = [0u64; 8];
    for &(start, end) in ranges {
        if end <= start || start >= USER_SPACE_START {
            continue;
        }
        let first = (start >> 30) as usize;
        let last = ((end.min(USER_SPACE_START) - 1) >> 30) as usize;
        for i in first.max(1)..=last {
            bits[i / 64] |= 1 << (i % 64);
        }
    }
    for (slot, b) in KERNEL_LOW_SLOTS.iter().zip(bits) {
        slot.store(b, Ordering::SeqCst);
    }
}

/// End of the low user window: the first slot the kernel keeps, at most 2 GiB (what
/// `MAP_32BIT` and 32-bit code get). 1 GiB in the original layout.
pub fn low_user_end() -> u64 {
    (1..2).find(|&i| kernel_low_slot(i)).unwrap_or(2) as u64 * 0x4000_0000
}
/// Load base for position-independent executables (matches Linux `ELF_ET_DYN_BASE`).
pub const PIE_BASE: u64 = 0x0000_5555_5555_4000;
/// Top of the main thread stack (one guard page below the end of user space).
pub const STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;
/// Size of the main thread stack area (matches the default 8 MiB `RLIMIT_STACK`).
pub const STACK_SIZE: u64 = 8 * 1024 * 1024;
/// Top of the top-down mmap area, leaving a 1 GiB gap below the stack.
pub const MMAP_TOP: u64 = STACK_TOP - STACK_SIZE - 0x4000_0000;

/// Page may be read (`PROT_READ`).
pub const PROT_READ: u32 = 0x1;
/// Page may be written (`PROT_WRITE`).
pub const PROT_WRITE: u32 = 0x2;
/// Page may be executed (`PROT_EXEC`).
pub const PROT_EXEC: u32 = 0x4;

/// Out of memory (`ENOMEM`).
const ENOMEM: i64 = 12;
/// Bad address (`EFAULT`).
const EFAULT: i64 = 14;
/// File or mapping already exists (`EEXIST`).
const EEXIST: i64 = 17;
/// Invalid argument (`EINVAL`).
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
    ///
    /// # Arguments
    ///
    /// * `pgoff` - Page offset within the backing object.
    ///
    /// # Returns
    ///
    /// `Some(PhysFrame)` containing the backing frame; `None` if offset exceeds object length.
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>>;
}

/// What a `Vma`'s pages are populated from.
#[derive(Clone)]
pub enum Backing {
    /// Zero-filled anonymous memory.
    Anon,
    /// Pages of a mapped object; `pgoff` is the object page that maps at `Vma::start`.
    Object {
        /// Shared reference to the underlying backing object.
        obj: Arc<dyn MappedObject>,
        /// Page offset within `obj` corresponding to `Vma::start`.
        pgoff: u64,
    },
}

/// A contiguous range of user virtual memory with uniform protection and backing.
#[derive(Clone)]
pub struct Vma {
    /// Page-aligned inclusive start virtual address of the area.
    pub start: u64,
    /// Page-aligned exclusive end virtual address of the area.
    pub end: u64,
    /// Protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
    pub prot: u32,
    /// True for shared mappings (`MAP_SHARED`), false for private copy-on-write mappings (`MAP_PRIVATE`).
    pub shared: bool,
    /// Backing store from which pages in this area are populated.
    pub backing: Backing,
    /// What `/proc/<pid>/maps` shows for it: a file's path, `[stack]`, `[heap]`, or none.
    pub name: Option<Arc<str>>,
    /// The userfaultfd its missing pages are reported to (0: none).
    pub uffd: u64,
}

impl Vma {
    /// Splits this VMA at page-aligned address `at`, truncating `self` to `[start, at)`
    /// and returning the upper half `[at, end)`.
    ///
    /// # Arguments
    ///
    /// * `at` - Virtual address split boundary.
    ///
    /// # Returns
    ///
    /// The upper half `Vma` covering `[at, end)`.
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
    /// Physical address of this address space's root `PML4` page table.
    pml4: PhysAddr,
    /// Non-overlapping virtual memory areas keyed by their starting virtual address.
    vmas: BTreeMap<u64, Vma>,
    /// Initial program break address at the end of the loaded executable image.
    pub brk_start: u64,
    /// Current program break (`brk`) address.
    pub brk: u64,
    /// The process's auxiliary vector as passed at exec (`prctl(PR_GET_AUXV)`, `/proc/self/auxv`).
    pub auxv: Vec<u8>,
}

/// The address space of the task currently running on the CPU (null for kernel tasks).
/// Points into an `Arc<Mutex<Mm>>` kept alive by the running task.
pub static CURRENT_MM: crate::arch::percpu::PerCpuPtr<Mutex<Mm>> = crate::arch::percpu::PerCpuPtr::new();

/// Address spaces of exited tasks, released later from a context where no locks are held.
/// Fixed-size so the scheduler can park an address space here without allocating.
static RETIRED_MMS: Mutex<[Option<Arc<Mutex<Mm>>>; 64]> = Mutex::new([const { None }; 64]);

/// Returns true if `NX` (execute-disable) is enabled in `IA32_EFER`.
///
/// # Returns
///
/// `true` if CPU execute-disable bit 11 is enabled in EFER; `false` otherwise.
pub(crate) fn nx_enabled() -> bool {
    let efer = unsafe { crate::arch::syscall::rdmsr(0xC000_0080) };
    efer & (1 << 11) != 0
}

/// Returns a mutable reference to the identity-mapped page table at physical address `phys`.
///
/// # Arguments
///
/// * `phys` - Physical address of the page table frame.
///
/// # Returns
///
/// Mutable reference to the `PageTable`.
#[inline]
fn table_at<'a>(phys: PhysAddr) -> &'a mut PageTable {
    unsafe { &mut *(crate::memory::frame_allocator::phys_to_virt(phys.as_u64()) as *mut PageTable) }
}

/// Rounds `addr` down to the nearest 4 KiB page boundary.
///
/// # Arguments
///
/// * `addr` - Virtual address to truncate.
///
/// # Returns
///
/// Page-aligned address truncated to 4096-byte boundary.
#[inline]
fn page_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Rounds `addr` up to the nearest 4 KiB page boundary.
///
/// # Arguments
///
/// * `addr` - Virtual address to round upward.
///
/// # Returns
///
/// Smallest 4096-byte aligned address greater than or equal to `addr`.
#[inline]
fn page_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Returns true if `[start, start + len)` lies entirely inside user space.
///
/// # Arguments
///
/// * `start` - Inclusive start address of the virtual range.
/// * `len` - Length of the range in bytes.
///
/// # Returns
///
/// `true` if the entire range is within unprivileged user space; `false` otherwise.
pub fn is_user_range(start: u64, len: u64) -> bool {
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return false,
    };
    if start < LOW_USER_START || end > USER_SPACE_END {
        return false;
    }
    // Below the main user area: no slot the kernel keeps
    if start < USER_SPACE_START {
        let last = ((end.min(USER_SPACE_START) - 1) >> 30) as usize;
        if ((start >> 30) as usize..=last).any(kernel_low_slot) {
            return false;
        }
    }
    true
}

/// True if `addr` is a user address (low window or main user area).
///
/// # Arguments
///
/// * `addr` - Virtual address to test.
///
/// # Returns
///
/// `true` if `addr` resides within the valid user virtual memory windows.
fn is_user_addr(addr: u64) -> bool {
    (USER_SPACE_START..USER_SPACE_END).contains(&addr)
        || ((LOW_USER_START..USER_SPACE_START).contains(&addr) && !kernel_low_slot((addr >> 30) as usize))
}

/// Computes the hardware [`PageTableFlags`] for a user page with VMA protection `prot`.
///
/// # Arguments
///
/// * `prot` - Protection bitmask (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
/// * `writable` - Whether the PTE should be marked writable (false for CoW pages).
///
/// # Returns
///
/// Formatted `PageTableFlags`.
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

/// Returns true if `entry` owns a physical frame (either `PRESENT` or `PTE_HELD`).
///
/// # Arguments
///
/// * `entry` - Page table entry to query.
///
/// # Returns
///
/// `true` if the entry currently references an active physical memory frame.
fn pte_holds_frame(entry: &PageTableEntry) -> bool {
    entry.flags().intersects(PageTableFlags::PRESENT | PTE_HELD)
}

/// Invalidates the TLB entry for virtual address `addr` of the address space with root
/// `pml4`, on every CPU that has it loaded (threads of a process run on several CPUs).
///
/// # Arguments
///
/// * `pml4` - Physical address of the address space's root table.
/// * `addr` - Virtual address whose cached translation must be flushed.
fn flush(pml4: PhysAddr, addr: u64) {
    crate::arch::smp::shootdown(Some(pml4.as_u64()), Some(addr));
}

impl Mm {
    /// Creates an empty address space sharing the kernel mappings.
    ///
    /// # Returns
    ///
    /// Newly allocated `Mm` structure on success, or an error string on memory exhaustion.
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
    ///
    /// # Returns
    ///
    /// The 64-bit physical address of the root PML4 table for this address space.
    pub fn cr3(&self) -> u64 {
        self.pml4.as_u64()
    }

    /// Duplicates this address space for `fork`. Private pages become shared copy-on-write
    /// (read-only in both, copied on the first write by either); shared mappings stay
    /// shared and writable.
    ///
    /// # Returns
    ///
    /// A new cloned [`Mm`] instance with duplicate VMAs and copy-on-write page table mappings.
    ///
    /// # Errors
    ///
    /// Returns a static string slice describing the failure if page table frame allocation fails.
    pub fn fork(&mut self) -> Result<Mm, &'static str> {
        let mut child = Mm::new()?;
        child.vmas = self.vmas.clone();
        // userfaultfd registrations stay with the parent
        for v in child.vmas.values_mut() {
            v.uffd = 0;
        }
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        child.auxv = self.auxv.clone();
        let areas: Vec<(u64, u64, bool)> = self.vmas.values().map(|v| (v.start, v.end, v.shared)).collect();
        for (start, end, shared) in areas {
            let mut addr = start;
            while addr < end {
                let (frame_addr, flags) = match self.pte(addr, false) {
                    Some(e) if pte_holds_frame(e) => {
                        let flags = if shared { e.flags() } else { e.flags() - PageTableFlags::WRITABLE };
                        let frame_addr = e.addr();
                        e.set_addr(frame_addr, flags);
                        (frame_addr, flags)
                    }
                    Some(_) => {
                        addr += PAGE_SIZE;
                        continue;
                    }
                    None => {
                        addr = (addr + 0x20_0000) & !0x1F_FFFF;
                        continue;
                    }
                };
                frame_ref_inc(PhysFrame::containing_address(frame_addr));
                let entry = child.pte(addr, true).ok_or("Out of memory while forking address space")?;
                entry.set_addr(frame_addr, flags);
                addr += PAGE_SIZE;
            }
        }
        // Parent PTEs lost their write bit: drop stale TLB entries (its other threads'
        // CPUs too)
        crate::arch::smp::shootdown(Some(self.pml4.as_u64()), None);
        Ok(child)
    }

    /// Returns the area containing `addr`, if any.
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual memory address to query.
    ///
    /// # Returns
    ///
    /// `Some(&Vma)` containing the given address, or `None` if `addr` is unmapped.
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| addr < v.end)
    }

    /// Iterates over all areas in address order.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all active [`Vma`] descriptors in increasing order.
    pub fn vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    /// Returns true if any existing VMA overlaps the half-open interval `[start, end)`.
    ///
    /// # Arguments
    ///
    /// * `start` - Inclusive start virtual address.
    /// * `end` - Exclusive end virtual address.
    ///
    /// # Returns
    ///
    /// `true` if an active area intersects `[start, end)`, `false` otherwise.
    pub(crate) fn overlaps(&self, start: u64, end: u64) -> bool {
        if let Some((_, v)) = self.vmas.range(..end).next_back() {
            return v.end > start;
        }
        false
    }

    /// Finds a free, page-aligned range of `len` bytes, searching down from `MMAP_TOP`.
    ///
    /// # Arguments
    ///
    /// * `len` - Length of the requested range in bytes.
    ///
    /// # Returns
    ///
    /// `Some(u64)` base virtual address if an unallocated hole is found, `None` if address space is full.
    /// The highest free, page-aligned range of `len` bytes within `[lo, hi)` (for
    /// `MAP_32BIT`).
    ///
    /// # Returns
    /// Its start, or `None` when no gap that large exists in the window.
    pub fn find_free_in(&self, len: u64, lo: u64, hi: u64) -> Option<u64> {
        let len = page_up(len);
        let mut top = hi;
        for (_, v) in self.vmas.range(..hi).rev() {
            if v.end <= top && top - v.end >= len && top - len >= lo {
                return Some(top - len);
            }
            top = top.min(v.start);
            if top < lo.saturating_add(len) {
                return None;
            }
        }
        if top >= lo.saturating_add(len) {
            Some(top - len)
        } else {
            None
        }
    }

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
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address whose page table entry is looked up.
    /// * `create` - If `true`, missing intermediate page directory levels are allocated.
    ///
    /// # Returns
    ///
    /// `Some(&mut PageTableEntry)` to the leaf PTE if present or created, `None` otherwise.
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
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address to translate.
    ///
    /// # Returns
    ///
    /// `Some(PhysAddr)` if `addr` is mapped to a physical frame, `None` if unmapped or non-frame.
    pub fn translate(&mut self, addr: u64) -> Option<PhysAddr> {
        let entry = self.pte(addr, false)?;
        if pte_holds_frame(entry) {
            Some(entry.addr() + (addr & (PAGE_SIZE - 1)))
        } else {
            None
        }
    }

    /// Unmaps every page in `[start, end)`, dropping frame references. Areas are untouched.
    ///
    /// # Arguments
    ///
    /// * `start` - Inclusive start virtual address.
    /// * `end` - Exclusive end virtual address.
    fn zap_range(&mut self, start: u64, end: u64) {
        let mut addr = start;
        while addr < end {
            // Skip whole missing page tables quickly
            match self.pte(addr, false) {
                Some(entry) => {
                    if pte_holds_frame(entry) {
                        let frame = PhysFrame::containing_address(entry.addr());
                        entry.set_unused();
                        flush(self.pml4, addr);
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
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address boundary to split existing VMAs on.
    fn split_at(&mut self, addr: u64) {
        let key = match self.vmas.range(..addr).next_back() {
            Some((&k, v)) if v.end > addr => k,
            _ => return,
        };
        let upper = self.vmas.get_mut(&key).unwrap().split_off(addr);
        self.vmas.insert(addr, upper);
    }

    /// Removes all mappings in `[start, end)`.
    ///
    /// # Arguments
    ///
    /// * `start` - Inclusive start virtual address.
    /// * `end` - Exclusive end virtual address.
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
    ///
    /// # Arguments
    ///
    /// * `addr` - Requested virtual memory address or placement hint.
    /// * `len` - Size of the mapping in bytes.
    /// * `prot` - Protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
    /// * `shared` - `true` if changes are visible across mappings, `false` for private COW.
    /// * `fixed` - Overwrite any existing mappings at `addr`.
    /// * `noreplace` - Fail if existing mappings overlap with `addr`.
    /// * `backing` - The underlying source of bytes ([`Backing::Anon`] or [`Backing::Object`]).
    ///
    /// # Returns
    ///
    /// The starting virtual address of the allocated mapping.
    ///
    /// # Errors
    ///
    /// - `-EINVAL`: Invalid length, misaligned fixed address, or non-user address.
    /// - `-EEXIST`: Mapping overlaps and `noreplace` was set.
    /// - `-ENOMEM`: No free virtual address range available.
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
            if addr & (PAGE_SIZE - 1) != 0 {
                return Err(-EINVAL);
            }
            if !is_user_range(addr, len) {
                // Within user addresses but over a slot the kernel keeps: to the program
                // that range is occupied (EEXIST, which address-space scanners such as
                // Wine's skip quietly; ENOMEM for MAP_FIXED, which cannot replace it)
                let in_user_span = addr >= LOW_USER_START && addr.checked_add(len).map_or(false, |e| e <= USER_SPACE_END);
                return Err(if !in_user_span {
                    -EINVAL
                } else if noreplace {
                    -EEXIST
                } else {
                    -ENOMEM
                });
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
                name: None,
                uffd: 0,
            },
        );
        self.merge_around(start);
        Ok(start)
    }

    /// Changes protection on `[start, start + len)` (Linux `mprotect`).
    ///
    /// # Arguments
    ///
    /// * `start` - Starting page-aligned virtual address.
    /// * `len` - Length of the region in bytes.
    /// * `prot` - New protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// - `-EINVAL`: `start` is not page-aligned.
    /// - `-ENOMEM`: Part of the specified range is unmapped.
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
                        flush(self.pml4, addr);
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
    ///
    /// # Arguments
    ///
    /// * `new_brk` - Desired new break address.
    ///
    /// # Returns
    ///
    /// The updated program break address (unchanged if the request fails or is invalid).
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
                    name: Some(Arc::from("[heap]")),
                    uffd: 0,
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
    ///
    /// # Arguments
    ///
    /// * `lower` - The earlier VMA descriptor in address order.
    /// * `upper` - The subsequent VMA descriptor immediately following `lower`.
    ///
    /// # Returns
    ///
    /// `true` if both VMAs have identical permissions and contiguous backing and can merge, `false` otherwise.
    fn can_merge(lower: &Vma, upper: &Vma) -> bool {
        if lower.end != upper.start || lower.prot != upper.prot || lower.shared != upper.shared || lower.name != upper.name || lower.uffd != upper.uffd {
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

    /// Names the mappings in `[start, end)` (splitting those that reach outside it), for
    /// `/proc/<pid>/maps`.
    pub fn set_name(&mut self, start: u64, end: u64, name: Option<&str>) {
        let name: Option<Arc<str>> = name.map(Arc::from);
        let keys: Vec<u64> = self.vmas.range(..end).filter(|(_, v)| v.end > start).map(|(k, _)| *k).collect();
        for k in keys {
            let Some(mut v) = self.vmas.remove(&k) else { continue };
            if v.start < start {
                let upper = v.split_off(start);
                self.vmas.insert(v.start, v);
                v = upper;
            }
            if v.end > end {
                let upper = v.split_off(end);
                self.vmas.insert(upper.start, upper);
            }
            v.name = name.clone();
            let at = v.start;
            self.vmas.insert(at, v);
            self.merge_around(at);
        }
    }

    /// Registers `[start, end)` with userfaultfd `id` (or, with `id` 0, unregisters what is
    /// registered with `only`). Registering needs anonymous memory all the way (`EINVAL`) not
    /// registered elsewhere (`EBUSY`).
    pub fn set_uffd(&mut self, start: u64, end: u64, id: u64, only: Option<u64>) -> Result<(), i64> {
        if id != 0 {
            let mut at = start;
            for v in self.vmas.range(..end).map(|(_, v)| v).filter(|v| v.end > start) {
                if v.start > at || !matches!(v.backing, Backing::Anon) {
                    return Err(-EINVAL);
                }
                if v.uffd != 0 && v.uffd != id {
                    return Err(-16);
                }
                at = v.end;
            }
            if at < end {
                return Err(-EINVAL);
            }
        }
        let keys: Vec<u64> = self.vmas.range(..end).filter(|(_, v)| v.end > start).map(|(k, _)| *k).collect();
        for k in keys {
            let Some(mut v) = self.vmas.remove(&k) else { continue };
            if only.is_some_and(|o| v.uffd != o) {
                self.vmas.insert(k, v);
                continue;
            }
            if v.start < start {
                let upper = v.split_off(start);
                self.vmas.insert(v.start, v);
                v = upper;
            }
            if v.end > end {
                let upper = v.split_off(end);
                self.vmas.insert(upper.start, upper);
            }
            v.uffd = id;
            let at = v.start;
            self.vmas.insert(at, v);
            self.merge_around(at);
        }
        Ok(())
    }

    /// The userfaultfd to report a fault at `addr` to: the page is not in memory and its
    /// area is registered.
    pub fn uffd_missing(&mut self, addr: u64) -> Option<u64> {
        let id = self.find_vma(addr)?.uffd;
        if id == 0 {
            return None;
        }
        let present = self.pte(page_down(addr), false).map_or(false, |e| pte_holds_frame(e));
        (!present).then_some(id)
    }

    /// Fills missing page `addr` of an area registered with userfaultfd `id` with `data`
    /// (zeros if none): `UFFDIO_COPY` / `UFFDIO_ZEROPAGE`.
    pub fn fill_page(&mut self, addr: u64, data: Option<&[u8]>, id: u64) -> Result<(), i64> {
        if self.find_vma(addr).map_or(true, |v| v.uffd != id) {
            return Err(-2); // ENOENT: not in a range of this descriptor
        }
        if self.uffd_missing(addr).is_none() {
            return Err(-17); // EEXIST
        }
        self.handle_fault(addr, false, false).map_err(|_| -12)?;
        if let Some(d) = data {
            let phys = self.translate(page_down(addr)).ok_or(-14i64)?;
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), crate::memory::frame_allocator::phys_to_virt(phys.as_u64()), (PAGE_SIZE as usize).min(d.len())) };
        }
        Ok(())
    }

    /// The mappings as `/proc/<pid>/maps` lists them.
    pub fn maps_text(&self) -> alloc::string::String {
        use core::fmt::Write;
        let mut out = alloc::string::String::new();
        for v in self.vmas.values() {
            let off = match &v.backing {
                Backing::Object { pgoff, .. } => pgoff * PAGE_SIZE,
                Backing::Anon => 0,
            };
            let mut line = alloc::format!(
                "{:08x}-{:08x} {}{}{}{} {:08x} 00:00 0",
                v.start,
                v.end,
                if v.prot & PROT_READ != 0 { 'r' } else { '-' },
                if v.prot & PROT_WRITE != 0 { 'w' } else { '-' },
                if v.prot & PROT_EXEC != 0 { 'x' } else { '-' },
                if v.shared { 's' } else { 'p' },
                off
            );
            if let Some(n) = &v.name {
                // The name starts at a fixed column, as on Linux
                while line.len() < 72 {
                    line.push(' ');
                }
                let _ = write!(line, " {}", n);
            }
            line.push('\n');
            out.push_str(&line);
        }
        out
    }

    /// Merges the area starting at `start` with compatible neighbours on either side.
    ///
    /// # Arguments
    ///
    /// * `start` - Virtual address identifying the target VMA.
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
    ///
    /// # Arguments
    ///
    /// * `old` - Current starting address of the mapping.
    /// * `old_len` - Current length in bytes.
    /// * `new_len` - Requested new length in bytes.
    /// * `may_move` - Whether mapping can be relocated if cannot expand in place.
    /// * `fixed_to` - Explicit fixed destination address (if `MREMAP_FIXED` specified).
    ///
    /// # Returns
    ///
    /// The starting virtual address of the resized or relocated mapping.
    ///
    /// # Errors
    ///
    /// - `-EINVAL`: Invalid alignment or zero length.
    /// - `-EFAULT`: Source mapping not found or spans across boundaries.
    /// - `-ENOMEM`: Cannot expand in place and `may_move` is false, or no free space.
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
                    flush(self.pml4, old + offset);
                    let dst = self.pte(dest + offset, true).ok_or(-ENOMEM)?;
                    dst.set_addr(addr, flags);
                    flush(self.pml4, dest + offset);
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
    ///
    /// # Arguments
    ///
    /// * `start` - Inclusive start virtual address.
    /// * `end` - Exclusive end virtual address.
    pub fn discard(&mut self, start: u64, end: u64) {
        self.zap_range(page_down(start), page_up(end));
    }

    /// Resolves a page fault at `addr`. `write`/`exec` describe the faulting access.
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address that caused the fault.
    /// * `write` - Whether the access was a write attempt.
    /// * `exec` - Whether the access was instruction execution.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful fault resolution and mapping installation.
    ///
    /// # Errors
    ///
    /// - [`FaultError::Segv`]: Address not in a valid VMA or violates protection flags.
    /// - [`FaultError::Bus`]: Object page retrieval failed.
    /// - [`FaultError::OutOfMemory`]: Physical frame allocation failed.
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
                        crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()) as *const u8,
                        crate::memory::frame_allocator::phys_to_virt(copy.start_address().as_u64()),
                        PAGE_SIZE as usize,
                    );
                }
                entry.set_addr(copy.start_address(), pte_flags_for(vma.prot, true));
                frame_ref_dec(frame);
            }
            flush(self.pml4, page);
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
                            crate::memory::frame_allocator::phys_to_virt(source.start_address().as_u64()) as *const u8,
                            crate::memory::frame_allocator::phys_to_virt(copy.start_address().as_u64()),
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
        flush(self.pml4, page);
        Ok(())
    }

    /// Copies `data` into this address space at `addr`, faulting pages in as needed.
    /// Works whether or not this address space is active.
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual destination address in this address space.
    /// * `data` - Source byte slice to copy.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful write of all bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FaultError`] if page allocation or access validation fails.
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
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), crate::memory::frame_allocator::phys_to_virt(phys.as_u64()), n);
            }
            done += n;
        }
        Ok(())
    }

    /// Writes `data` at `addr` even where the mapping is read-only (a debugger's breakpoint
    /// in program text): a private page gets a copy of its own first and keeps its
    /// protection. Shared mappings are not written through a read-only view.
    ///
    /// # Errors
    ///
    /// Returns [`FaultError`] if a page is unmapped, shared and read-only, or memory runs out.
    pub fn force_write(&mut self, addr: u64, data: &[u8]) -> Result<(), FaultError> {
        let mut done = 0usize;
        while done < data.len() {
            let va = addr + done as u64;
            let n = ((PAGE_SIZE - (va & (PAGE_SIZE - 1))) as usize).min(data.len() - done);
            let vma = self.find_vma(va).cloned().ok_or(FaultError::Segv)?;
            if vma.prot & PROT_WRITE != 0 {
                self.write_bytes(va, &data[done..done + n])?;
                done += n;
                continue;
            }
            if vma.shared {
                return Err(FaultError::Segv);
            }
            // Present first (a read fault maps file pages shared with the page cache)
            let page = page_down(va);
            if !self.pte(page, false).map_or(false, |e| e.flags().contains(PageTableFlags::PRESENT)) {
                let prot = vma.prot;
                // A PROT_NONE page can still be read by a debugger: fault it in as readable
                if prot == 0 {
                    return Err(FaultError::Segv);
                }
                self.handle_fault(page, false, false)?;
            }
            let entry = self.pte(page, false).ok_or(FaultError::Segv)?;
            let frame = PhysFrame::<Size4KiB>::containing_address(entry.addr());
            let target = if frame_refcount(frame) == 1 {
                frame
            } else {
                let copy = alloc_user_frame().ok_or(FaultError::OutOfMemory)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()) as *const u8, crate::memory::frame_allocator::phys_to_virt(copy.start_address().as_u64()), PAGE_SIZE as usize);
                }
                entry.set_addr(copy.start_address(), pte_flags_for(vma.prot, false));
                frame_ref_dec(frame);
                flush(self.pml4, page);
                copy
            };
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), crate::memory::frame_allocator::phys_to_virt(target.start_address().as_u64() + (va & (PAGE_SIZE - 1))), n);
            }
            done += n;
        }
        Ok(())
    }

    /// Faults in every page of `[addr, addr + len)` so kernel code can access it directly
    /// without page faults (used before I/O into user buffers).
    ///
    /// # Arguments
    ///
    /// * `addr` - Starting virtual address to prefault.
    /// * `len` - Length in bytes of the region to prefault.
    /// * `write` - `true` if write access is required, `false` for read-only.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful fault resolution for the entire span.
    ///
    /// # Errors
    ///
    /// Returns [`FaultError`] if any page in the span fails to fault in.
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

    /// Recursively releases page tables and decrements frame reference counts starting at `level`.
    ///
    /// # Arguments
    ///
    /// * `table_phys` - Physical address of the page table to free.
    /// * `level` - Paging hierarchy level (1 for PT, 2 for PD, 3 for PDPT, 4 for PML4).
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
    /// Tears down the address space, decrementing reference counts on mapped frames and freeing page tables.
    fn drop(&mut self) {
        // Owned: the user half, and in PML4[0] the private PDPT with the low slots that are
        // the process's (the others are the kernel's shared identity map, see
        // KERNEL_LOW_SLOTS). The kernel half is shared.
        let pml4 = table_at(self.pml4);
        if pml4[0].flags().contains(PageTableFlags::PRESENT) {
            let pdpt_phys = pml4[0].addr();
            let pdpt = table_at(pdpt_phys);
            for i in 0..512 {
                if !kernel_low_slot(i) && pdpt[i].flags().contains(PageTableFlags::PRESENT) {
                    Self::free_tables(pdpt[i].addr(), 2);
                    pdpt[i].set_unused();
                }
            }
            pml4[0].set_unused();
            frame_ref_dec(PhysFrame::containing_address(pdpt_phys));
        }
        for i in 1..256 {
            if pml4[i].flags().contains(PageTableFlags::PRESENT) {
                Self::free_tables(pml4[i].addr(), 3);
                pml4[i].set_unused();
            }
        }
        frame_ref_dec(PhysFrame::containing_address(self.pml4));
    }
}

/// Waits while `addr` is a missing page of a range registered with a userfaultfd, until its
/// handler supplies it (`kernel`: an access by a system call). `false` if the descriptor
/// refuses such accesses.
pub fn uffd_resolve_current(addr: u64, write: bool, kernel: bool) -> bool {
    use crate::compat::linux::userfaultfd::{wait_fault, Waited};
    let ptr = CURRENT_MM.load(Ordering::Acquire);
    if ptr.is_null() || !is_user_addr(addr) || !crate::compat::linux::userfaultfd::active() {
        return true;
    }
    let mm = unsafe { &*ptr };
    loop {
        let id = match mm.try_lock() {
            Some(mut g) => g.uffd_missing(addr),
            None => return true,
        };
        let Some(id) = id else { return true };
        match wait_fault(id, page_down(addr), write, kernel) {
            Waited::Again => continue,
            Waited::Proceed => return true,
            Waited::Refuse => return false,
        }
    }
}

/// Resolves a page fault against the running process's address space.
/// Returns `None` if the current task has no address space.
///
/// # Arguments
///
/// * `addr` - Virtual address that faulted.
/// * `write` - `true` if the access was a write.
/// * `exec` - `true` if the access was instruction execution.
///
/// # Returns
///
/// `Some(Ok(()))` on successful resolution, `Some(Err(FaultError))` on fault failure,
/// or `None` if current task has no active address space or `addr` is not user-accessible.
///
/// # Panics
///
/// Panics if the current task's `Mm` mutex is already held when the page fault occurs.
pub fn handle_current_fault(addr: u64, write: bool, exec: bool) -> Option<Result<(), FaultError>> {
    let ptr = CURRENT_MM.load(Ordering::Acquire);
    if ptr.is_null() || !is_user_addr(addr) {
        return None;
    }
    let mm = unsafe { &*ptr };
    match mm.try_lock() {
        Some(mut guard) => Some(guard.handle_fault(addr, write, exec)),
        None => panic!("page fault at {:#x} while the faulting process's Mm is locked", addr),
    }
}

/// Physical address of `addr` in the running process if it lies in a shared mapping
/// (`MAP_SHARED`: memory other processes may map too); `None` for private memory or an
/// unmapped page. Used to key futexes shared between processes.
///
/// # Arguments
///
/// * `addr` - Virtual address to translate.
///
/// # Returns
///
/// `Some(u64)` physical address if `addr` is mapped as shared, `None` otherwise.
pub fn shared_phys_current(addr: u64) -> Option<u64> {
    let ptr = CURRENT_MM.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    let mm = unsafe { &*ptr };
    let mut guard = mm.lock();
    if !guard.find_vma(addr)?.shared {
        return None;
    }
    guard.translate(addr).map(|p| p.as_u64())
}

/// Validates and faults in a user buffer of the running process before kernel I/O into it.
/// Returns false if the range is not mapped with the required access.
///
/// # Arguments
///
/// * `addr` - Virtual address start of user buffer.
/// * `len` - Length of buffer in bytes.
/// * `write` - Whether write access is required.
///
/// # Returns
///
/// `true` if the entire range is valid and faulted in, `false` otherwise.
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
    // Pages a userfaultfd handler must supply first
    if crate::compat::linux::userfaultfd::active() {
        let mut page = page_down(addr);
        while page < addr + len {
            if !uffd_resolve_current(page, write, true) {
                return false;
            }
            page += PAGE_SIZE;
        }
    }
    let mm = unsafe { &*ptr };
    mm.lock().prefault(addr, len, write).is_ok()
}

/// Makes `mm` the address space the page-fault handler resolves against.
///
/// # Arguments
///
/// * `mm` - Optional reference to the new active address space [`Arc<Mutex<Mm>>`].
pub fn set_current_mm(mm: Option<&Arc<Mutex<Mm>>>) {
    let ptr = mm.map_or(core::ptr::null_mut(), |m| Arc::as_ptr(m) as *mut Mutex<Mm>);
    CURRENT_MM.store(ptr, Ordering::Release);
}

/// Parks an exited task's address space for later release. Never allocates, so it is
/// safe to call from the scheduler. Returns the address space back if the queue is full
/// or busy, in which case the caller keeps it and retries later.
///
/// # Arguments
///
/// * `mm` - Address space handle to retire.
///
/// # Returns
///
/// `Ok(())` if parked successfully, or `Err(mm)` returning ownership if slots are full or locked.
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
///
/// # Arguments
///
/// * `frames` - Slice of physical 4 KiB frames to map.
/// * `writable` - Whether the user mapping should be writable.
///
/// # Returns
///
/// `Some(u64)` virtual address of the start of the window, or `None` on allocation failure.
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
    /// Raw byte slice holding the complete backing image in memory.
    data: Box<[u8]>,
    /// Materialised 4 KiB physical frames indexed by page offset (`pgoff`).
    pages: Mutex<BTreeMap<u64, PhysFrame<Size4KiB>>>,
}

impl BufferObject {
    /// Creates a new shared `BufferObject` wrapping `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Boxed slice containing raw object data.
    ///
    /// # Returns
    ///
    /// An [`Arc<BufferObject>`] wrapping the data buffer.
    pub fn new(data: Box<[u8]>) -> Arc<Self> {
        Arc::new(Self {
            data,
            pages: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the total size of the underlying byte buffer in bytes.
    ///
    /// # Returns
    ///
    /// Size in bytes as `usize`.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns a read-only slice of the underlying byte buffer.
    ///
    /// # Returns
    ///
    /// Slice reference `&[u8]` of the data payload.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl MappedObject for BufferObject {
    /// Retrieves or materialises the 4 KiB physical frame corresponding to `pgoff`.
    ///
    /// # Arguments
    ///
    /// * `pgoff` - Page offset index into the backing buffer.
    ///
    /// # Returns
    ///
    /// `Some(PhysFrame)` containing the page data, or `None` if `pgoff` is out of bounds or allocation fails.
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
                crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()),
                n,
            );
        }
        pages.insert(pgoff, frame);
        Some(frame)
    }
}

impl Drop for BufferObject {
    /// Releases physical frames held by this buffer object.
    fn drop(&mut self) {
        for (_, frame) in self.pages.lock().iter() {
            frame_ref_dec(*frame);
        }
    }
}
