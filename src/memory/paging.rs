//! # Memory Subsystem: x86_64 4-Level Page Table Management
//!
//! Provides low-level manipulation of x86_64 4-level hierarchical page tables (`PML4`, `PDPT`,
//! `PD`, `PT`), virtual-to-physical address translation, TLB invalidation, and construction of
//! autonomous kernel and user address spaces.
//!
//! ## Architectural Role & Design Rationale
//!
//! During UEFI boot, the processor executes inside firmware-owned identity-mapped page tables.
//! `AddressSpace` allows the kernel to take ownership of paging by cloning active firmware
//! mappings into conventional RAM (`init_kernel_space`), creating isolated per-process `PML4`
//! roots that share kernel mappings (`AddressSpace::create_user_space`), and mapping or
//! updating protection flags on individual 4 KiB pages with automatic intermediate table allocation.
//!
//! ## Key Types & Interfaces
//!
//! - `AddressSpace`: Handle to a 4-level page table hierarchy rooted at a physical `PML4` frame.
//! - `KERNEL_SPACE`: Global spinlock-protected handle to Hydra's autonomous kernel `AddressSpace`.
//! - `init_kernel_space`: Allocates and populates the kernel's dedicated `PML4` table.
//! - `make_user_accessible`: Grants Ring 3 (`USER_ACCESSIBLE`) permissions across a virtual range.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Registers**: Reads and writes `CR3` (page table root) and temporarily toggles `CR0.WP`
//!   (Write Protect, bit 16) when modifying read-only boot page table structures.
//! - **TLB Management**: Executes `invlpg` (`tlb::flush`) upon mapping, unmapping, or flag changes.
//! - **Physical Memory**: Assumes physical page table frames are identity-mapped and accessible at
//!   their physical addresses.

use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{Page, PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::frame_allocator::PhysicalMemoryManager;

/// Hydra's autonomous kernel address space (allocated in conventional RAM, owned by the OS).
pub static KERNEL_SPACE: Mutex<Option<AddressSpace>> = Mutex::new(None);

/// Initializes Hydra's autonomous kernel address space by allocating a dedicated PML4
/// in conventional memory and copying active boot mappings.
///
/// # Arguments
///
/// * `allocator` - Physical frame allocator used to allocate the new `PML4` root frame.
///
/// # Returns
///
/// The physical address (`PhysAddr`) of the newly created kernel `PML4` table.
///
/// # Errors
///
/// Returns `Err` if the frame allocator is out of physical memory.
pub fn init_kernel_space(allocator: &mut PhysicalMemoryManager) -> Result<PhysAddr, &'static str> {
    let space = AddressSpace::create_kernel_space(allocator)?;
    let pml4 = space.pml4_physical_address();
    *KERNEL_SPACE.lock() = Some(space);
    Ok(pml4)
}

/// Represents an x86_64 4-level (PML4) virtual address space.
pub struct AddressSpace {
    /// Physical address of the 4 KiB-aligned root Page Map Level 4 (`PML4`) table.
    pml4_phys: PhysAddr,
}

impl AddressSpace {
    /// Obtains the currently active address space from the CPU CR3 register.
    ///
    /// # Returns
    ///
    /// An `AddressSpace` wrapping the physical `PML4` address currently loaded in `CR3`.
    pub fn active() -> Self {
        let (cr3_frame, _) = Cr3::read();
        Self {
            pml4_phys: cr3_frame.start_address(),
        }
    }

    /// Creates an AddressSpace handle pointing to a specific PML4 physical address.
    ///
    /// # Arguments
    ///
    /// * `pml4_phys` - Physical address of a valid 4 KiB `PML4` frame.
    pub const fn from_pml4(pml4_phys: PhysAddr) -> Self {
        Self { pml4_phys }
    }

    /// Returns the physical address of this address space's root PML4 table.
    ///
    /// # Returns
    ///
    /// Physical address of the PML4 table loaded into `CR3`.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn pml4_physical_address(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// Switches the CPU CR3 register to make this address space active.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the address space contains valid mappings
    /// for the currently executing kernel code and stack.
    pub unsafe fn switch(&self) {
        let frame = PhysFrame::containing_address(self.pml4_phys);
        Cr3::write(frame, Cr3Flags::empty());
    }

    /// In UEFI x86_64 identity-mapped environments or direct-mapped kernels,
    /// read a page table at a given physical address.
    ///
    /// # Arguments
    ///
    /// * `phys` - Physical address of the page table to inspect.
    ///
    /// # Returns
    ///
    /// Immutable reference to the `PageTable` residing at `phys`.
    ///
    /// # Safety
    ///
    /// `phys` must be a valid, 4 KiB-aligned physical address of an initialized [`PageTable`]
    /// that is identity-mapped in the active address space.
    pub unsafe fn table_at<'a>(&self, phys: PhysAddr) -> &'a PageTable {
        let ptr = super::frame_allocator::phys_to_virt(phys.as_u64()) as *const PageTable;
        &*ptr
    }

    /// In UEFI x86_64 identity-mapped environments or direct-mapped kernels,
    /// get a mutable reference to a page table at a given physical address.
    ///
    /// # Arguments
    ///
    /// * `phys` - Physical address of the page table to mutate.
    ///
    /// # Returns
    ///
    /// Mutable reference to the `PageTable` residing at `phys`.
    ///
    /// # Safety
    ///
    /// `phys` must be a valid, 4 KiB-aligned physical address of an initialized [`PageTable`]
    /// that is identity-mapped and writable in the active address space, with exclusive access.
    pub unsafe fn table_at_mut<'a>(&self, phys: PhysAddr) -> &'a mut PageTable {
        let ptr = super::frame_allocator::phys_to_virt(phys.as_u64()) as *mut PageTable;
        &mut *ptr
    }

    /// Traverses the page table entry to find the next level page table,
    /// allocating a new 4 KiB frame from `allocator` and initializing it if not present.
    ///
    /// # Arguments
    /// * `entry` - Mutable reference to the parent page table entry.
    /// * `allocator` - Physical memory manager used for allocating new page table frames.
    ///
    /// # Returns
    ///
    /// A mutable reference to the next-level [`PageTable`] on success, or an error message on failure.
    ///
    /// # Safety
    ///
    /// The caller must ensure `entry` belongs to a valid page table in identity-mapped memory.
    unsafe fn get_or_create_next_table<'a>(
        &self,
        entry: &mut PageTableEntry,
        allocator: &mut PhysicalMemoryManager,
    ) -> Result<&'a mut PageTable, &'static str> {
        if entry.flags().contains(PageTableFlags::PRESENT) {
            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err("Cannot traverse into huge page");
            }
            let next_phys = entry.addr();
            Ok(self.table_at_mut(next_phys))
        } else {
            let frame = allocator
                .allocate_frame()
                .ok_or("Out of physical memory: failed to allocate page table frame")?;
            let table_phys = frame.start_address();
            let table = self.table_at_mut(table_phys);
            table.zero();
            entry.set_addr(
                table_phys,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
            );
            Ok(table)
        }
    }

    /// Walk the 4-level page table to translate a virtual address to physical address if mapped.
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address to translate.
    ///
    /// # Returns
    ///
    /// `Some(PhysAddr)` with the resolved physical address if mapped; `None` if unmapped or not present.
    ///
    /// # Safety
    ///
    /// All page table frames referenced by this `AddressSpace` must be valid and identity-mapped.
    pub unsafe fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        let p4 = self.table_at(self.pml4_phys);
        let p4_entry = &p4[addr.p4_index()];
        if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }

        let p3 = self.table_at(p4_entry.addr());
        let p3_entry = &p3[addr.p3_index()];
        if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 1 GiB huge page
            let offset = addr.as_u64() & 0x3fff_ffff;
            return Some(p3_entry.addr() + offset);
        }

        let p2 = self.table_at(p3_entry.addr());
        let p2_entry = &p2[addr.p2_index()];
        if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 2 MiB huge page
            let offset = addr.as_u64() & 0x1f_ffff;
            return Some(p2_entry.addr() + offset);
        }

        let p1 = self.table_at(p2_entry.addr());
        let p1_entry = &p1[addr.p1_index()];
        if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }

        let offset = addr.as_u64() & 0xfff;
        Some(p1_entry.addr() + offset)
    }

    /// Queries the mapped physical frame and protection flags for a given 4 KiB virtual page.
    ///
    /// # Arguments
    /// * `page` - The virtual page to translate.
    ///
    /// # Returns
    ///
    /// `Some((frame, flags))` if mapped, or `None` if unmapped or backed by huge pages.
    ///
    /// # Safety
    ///
    /// All page table frames referenced by this `AddressSpace` must be valid and identity-mapped.
    pub unsafe fn translate_page(
        &self,
        page: Page<Size4KiB>,
    ) -> Option<(PhysFrame<Size4KiB>, PageTableFlags)> {
        let p4 = self.table_at(self.pml4_phys);
        let p4_entry = &p4[page.p4_index()];
        if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }

        let p3 = self.table_at(p4_entry.addr());
        let p3_entry = &p3[page.p3_index()];
        if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }

        let p2 = self.table_at(p3_entry.addr());
        let p2_entry = &p2[page.p2_index()];
        if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }

        let p1 = self.table_at(p2_entry.addr());
        let p1_entry = &p1[page.p1_index()];
        if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }

        Some((
            PhysFrame::containing_address(p1_entry.addr()),
            p1_entry.flags(),
        ))
    }

    /// Maps a 4 KiB virtual page to a physical frame with specified protection flags.
    ///
    /// Allocates intermediate page tables (PDPT, PD, PT) as needed from `allocator`.
    /// Flushes the CPU Translation Lookaside Buffer (TLB) for `page`.
    ///
    /// # Arguments
    /// * `page` - The virtual page to map.
    /// * `frame` - The target physical frame.
    /// * `flags` - Protection flags to set on the entry.
    /// * `allocator` - Physical memory manager used for allocating intermediate tables.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error message on allocation failure or existing mapping.
    ///
    /// # Safety
    ///
    /// Mapping an arbitrary virtual page to a physical frame can alias memory or corrupt
    /// active execution state if `page` overlaps live code, stack, or page tables.
    pub unsafe fn map_page(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        allocator: &mut PhysicalMemoryManager,
    ) -> Result<(), &'static str> {
        let p4 = self.table_at_mut(self.pml4_phys);
        let p4_entry = &mut p4[page.p4_index()];
        let p3 = self.get_or_create_next_table(p4_entry, allocator)?;

        let p3_entry = &mut p3[page.p3_index()];
        let p2 = self.get_or_create_next_table(p3_entry, allocator)?;

        let p2_entry = &mut p2[page.p2_index()];
        let p1 = self.get_or_create_next_table(p2_entry, allocator)?;

        let p1_entry = &mut p1[page.p1_index()];
        if p1_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("Page is already mapped");
        }

        p1_entry.set_addr(frame.start_address(), flags | PageTableFlags::PRESENT);
        crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
        Ok(())
    }

    /// Unmaps a 4 KiB virtual page and returns the previously mapped physical frame.
    ///
    /// Flushes the CPU Translation Lookaside Buffer (TLB) for `page`.
    ///
    /// # Arguments
    /// * `page` - The virtual page to unmap.
    ///
    /// # Returns
    ///
    /// The unmapped [`PhysFrame`] on success, or an error message if the page is not present.
    ///
    /// # Safety
    ///
    /// The caller must ensure no active references or execution depend on `page` remaining mapped.
    pub unsafe fn unmap_page(
        &mut self,
        page: Page<Size4KiB>,
    ) -> Result<PhysFrame<Size4KiB>, &'static str> {
        let p4 = self.table_at_mut(self.pml4_phys);
        let p4_entry = &p4[page.p4_index()];
        if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PML4 entry not present");
        }

        let p3 = self.table_at_mut(p4_entry.addr());
        let p3_entry = &p3[page.p3_index()];
        if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PDPT entry not present");
        }
        if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return Err("Cannot unmap 4 KiB page within 1 GiB huge page");
        }

        let p2 = self.table_at_mut(p3_entry.addr());
        let p2_entry = &p2[page.p2_index()];
        if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PD entry not present");
        }
        if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return Err("Cannot unmap 4 KiB page within 2 MiB huge page");
        }

        let p1 = self.table_at_mut(p2_entry.addr());
        let p1_entry = &mut p1[page.p1_index()];
        if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("Page table entry not present");
        }

        let frame = PhysFrame::containing_address(p1_entry.addr());
        p1_entry.set_unused();
        crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
        Ok(frame)
    }

    /// Updates protection flags (e.g. read-write, user-accessible, no-execute) for an existing mapped page.
    ///
    /// # Arguments
    /// * `page` - The virtual page whose flags are to be updated.
    /// * `flags` - New protection flags to apply.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error message if intermediate tables or entry are not present.
    ///
    /// # Safety
    ///
    /// Changing page permissions on active code or data pages can fault or expose kernel memory if
    /// `flags` are misconfigured.
    pub unsafe fn update_flags(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let p4 = self.table_at(self.pml4_phys);
        let p4_entry = &p4[page.p4_index()];
        if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PML4 entry not present");
        }

        let p3 = self.table_at(p4_entry.addr());
        let p3_entry = &p3[page.p3_index()];
        if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PDPT entry not present");
        }

        let p2 = self.table_at(p3_entry.addr());
        let p2_entry = &p2[page.p2_index()];
        if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("PD entry not present");
        }

        let p1 = self.table_at_mut(p2_entry.addr());
        let p1_entry = &mut p1[page.p1_index()];
        if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
            return Err("Page table entry not present");
        }

        let phys = p1_entry.addr();
        p1_entry.set_addr(phys, flags | PageTableFlags::PRESENT);
        crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
        Ok(())
    }

    /// Ensures that the specified virtual address range is marked USER_ACCESSIBLE
    /// across all hierarchical page table levels (PML4, PDPT, PD, and PT / huge page).
    ///
    /// # Arguments
    /// * `virt_start` - The base virtual address of the range.
    /// * `size` - Size in bytes of the address range to mark user-accessible.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error string on failure.
    ///
    /// # Safety
    ///
    /// Marking a virtual range `USER_ACCESSIBLE` exposes those pages (and potentially sharing
    /// huge pages) to unprivileged Ring 3 code.
    pub unsafe fn make_user_accessible(
        &mut self,
        virt_start: VirtAddr,
        size: usize,
    ) -> Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }

        // Temporarily clear CR0.WP (bit 16) so the kernel can modify page table structures
        core::arch::asm!(
            "mov {tmp}, cr0",
            "btr {tmp}, 16",
            "mov cr0, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags),
        );

        let start_page = Page::<Size4KiB>::containing_address(virt_start);
        let end_page = Page::<Size4KiB>::containing_address(virt_start + (size as u64).saturating_sub(1));

        for page in Page::range_inclusive(start_page, end_page) {
            let p4 = self.table_at_mut(self.pml4_phys);
            let p4_entry = &mut p4[page.p4_index()];
            if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p4_entry.set_flags(p4_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);

            let p3 = self.table_at_mut(p4_entry.addr());
            let p3_entry = &mut p3[page.p3_index()];
            if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p3_entry.set_flags(p3_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);
            if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
                continue;
            }

            let p2 = self.table_at_mut(p3_entry.addr());
            let p2_entry = &mut p2[page.p2_index()];
            if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p2_entry.set_flags(p2_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);
            if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
                continue;
            }

            let p1 = self.table_at_mut(p2_entry.addr());
            let p1_entry = &mut p1[page.p1_index()];
            if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p1_entry.set_flags(p1_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);
            crate::arch::smp::shootdown(None, Some(page.start_address().as_u64()));
        }

        // Re-enable CR0.WP (bit 16) to restore supervisor write protection
        core::arch::asm!(
            "mov {tmp}, cr0",
            "bts {tmp}, 16",
            "mov cr0, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags),
        );

        Ok(())
    }

    /// Identity-maps a physical frame 1:1 (`virt_addr = phys_addr`).
    ///
    /// Required for memory-mapped I/O (MMIO), such as the Local APIC,
    /// ACPI tables, and the GOP linear framebuffer.
    ///
    /// # Arguments
    /// * `frame` - The physical frame to identity-map.
    /// * `flags` - Protection flags to set on the mapped page.
    /// * `allocator` - Physical memory manager for intermediate table allocations.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error string on failure.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame` does not collide with an already mapped virtual page
    /// in an unsafe manner.
    pub unsafe fn identity_map(
        &mut self,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        allocator: &mut PhysicalMemoryManager,
    ) -> Result<(), &'static str> {
        let virt = VirtAddr::new(frame.start_address().as_u64());
        let page = Page::containing_address(virt);
        self.map_page(page, frame, flags, allocator)
    }

    /// Maps a contiguous range of physical frames to a contiguous virtual page range.
    ///
    /// # Arguments
    /// * `start_page` - First virtual page of the range.
    /// * `start_frame` - First physical frame of the range.
    /// * `page_count` - Number of contiguous 4 KiB pages to map.
    /// * `flags` - Protection flags applied to all pages in the range.
    /// * `allocator` - Physical memory manager for intermediate table allocations.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error string on failure.
    ///
    /// # Safety
    ///
    /// The caller must ensure the virtual page range and physical frame range are valid
    /// and do not alias active memory unsafely.
    pub unsafe fn map_range(
        &mut self,
        start_page: Page<Size4KiB>,
        start_frame: PhysFrame<Size4KiB>,
        page_count: usize,
        flags: PageTableFlags,
        allocator: &mut PhysicalMemoryManager,
    ) -> Result<(), &'static str> {
        for i in 0..page_count {
            let offset = (i as u64) * 4096;
            let page = Page::containing_address(start_page.start_address() + offset);
            let frame = PhysFrame::containing_address(start_frame.start_address() + offset);
            self.map_page(page, frame, flags, allocator)?;
        }
        Ok(())
    }

    /// Creates Hydra's autonomous kernel address space by allocating a new PML4
    /// frame from conventional RAM and cloning the active firmware mappings.
    ///
    /// # Arguments
    ///
    /// * `allocator` - Mutable physical memory frame allocator.
    ///
    /// # Returns
    ///
    /// A newly initialized autonomous kernel `AddressSpace` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if physical frame allocation for the PML4 table fails.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn create_kernel_space(allocator: &mut PhysicalMemoryManager) -> Result<Self, &'static str> {
        let new_pml4_frame = allocator
            .allocate_frame()
            .ok_or("Out of memory: cannot allocate PML4 frame for kernel address space")?;
        let new_pml4_phys = new_pml4_frame.start_address();

        let active_space = Self::active();
        let active_pml4 = unsafe { active_space.table_at(active_space.pml4_phys) };
        let new_pml4 = unsafe { active_space.table_at_mut(new_pml4_phys) };
        new_pml4.zero();

        // Clone all active entries from the boot table so all existing code, data,
        // stack, heap, and firmware buffers remain identically accessible.
        for i in 0..512 {
            if active_pml4[i].flags().contains(PageTableFlags::PRESENT) {
                new_pml4[i] = active_pml4[i].clone();
            }
        }

        // The direct map of physical memory at DIRECT_MAP_BASE (PML4 entry 256 and up),
        // 2 MiB pages, kernel-only, never executable: all RAM, and at least the first
        // 4 GiB (where firmware and device memory sit). Every address space shares it.
        let top = allocator.max_phys_end().max(4 << 30);
        let gib = ((top + (1 << 30) - 1) >> 30) as usize;
        let base_idx = ((super::frame_allocator::DIRECT_MAP_BASE >> 39) & 511) as usize;
        let nx = if crate::memory::vm::nx_enabled() { PageTableFlags::NO_EXECUTE } else { PageTableFlags::empty() };
        let table_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        for g in 0..gib {
            let (p4i, p3i) = (base_idx + g / 512, g % 512);
            if p4i >= 512 {
                break;
            }
            if !new_pml4[p4i].flags().contains(PageTableFlags::PRESENT) {
                let f = allocator.allocate_zeroed_frame().ok_or("Out of memory: direct map PDPT")?;
                new_pml4[p4i].set_addr(f.start_address(), table_flags);
            }
            let pdpt = unsafe { active_space.table_at_mut(new_pml4[p4i].addr()) };
            let pd_frame = allocator.allocate_zeroed_frame().ok_or("Out of memory: direct map PD")?;
            let pd = unsafe { active_space.table_at_mut(pd_frame.start_address()) };
            for (i, e) in pd.iter_mut().enumerate() {
                let pa = ((g as u64) << 30) + ((i as u64) << 21);
                e.set_addr(PhysAddr::new(pa), table_flags | PageTableFlags::HUGE_PAGE | nx);
            }
            pdpt[p3i].set_addr(pd_frame.start_address(), table_flags);
        }

        Ok(Self {
            pml4_phys: new_pml4_phys,
        })
    }

    /// Creates a new isolated user address space with higher-half kernel mappings shared.
    ///
    /// # Arguments
    ///
    /// * `allocator` - Mutable physical memory frame allocator.
    ///
    /// # Returns
    ///
    /// A newly initialized user `AddressSpace` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if physical frame allocation for page tables fails.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn create_user_space(allocator: &mut PhysicalMemoryManager) -> Result<Self, &'static str> {
        let new_pml4_frame = allocator
            .allocate_frame()
            .ok_or("Out of memory: cannot allocate PML4 frame for user address space")?;
        let new_pml4_phys = new_pml4_frame.start_address();

        let active_space = Self::active();
        let active_pml4 = unsafe { active_space.table_at(active_space.pml4_phys) };
        let new_pml4 = unsafe { active_space.table_at_mut(new_pml4_phys) };
        new_pml4.zero();

        // Share the kernel half (entries 256..512). Entry 0 gets a private PDPT that shares
        // the identity map in the slots the kernel keeps (vm::kernel_low_slot) and leaves
        // the others to the process
        for i in 256..512 {
            new_pml4[i] = active_pml4[i].clone();
        }
        let pdpt_frame = allocator
            .allocate_zeroed_frame()
            .ok_or("Out of memory: cannot allocate the low PDPT of a user address space")?;
        let active_pdpt = unsafe { active_space.table_at(active_pml4[0].addr()) };
        let new_pdpt = unsafe { active_space.table_at_mut(pdpt_frame.start_address()) };
        for i in 1..512 {
            if crate::memory::vm::kernel_low_slot(i) {
                new_pdpt[i] = active_pdpt[i].clone();
            }
        }
        new_pml4[0].set_addr(
            pdpt_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );

        Ok(Self {
            pml4_phys: new_pml4_phys,
        })
    }
}

/// Marks a memory region as user-accessible in the active/kernel PML4 page tables.
///
/// # Arguments
///
/// * `virt_start` - Virtual start address of the memory range to update.
/// * `size` - Size of the range in bytes.
///
/// # Returns
///
/// `Ok(())` on success, or an error string if traversal encounters invalid mappings.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn make_user_accessible(virt_start: VirtAddr, size: usize) -> Result<(), &'static str> {
    if let Some(ref mut space) = *KERNEL_SPACE.lock() {
        unsafe { space.make_user_accessible(virt_start, size) }
    } else {
        let mut active = AddressSpace::active();
        unsafe { active.make_user_accessible(virt_start, size) }
    }
}
