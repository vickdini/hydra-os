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
pub fn init_kernel_space(allocator: &mut PhysicalMemoryManager) -> Result<PhysAddr, &'static str> {
    let space = AddressSpace::create_kernel_space(allocator)?;
    let pml4 = space.pml4_physical_address();
    *KERNEL_SPACE.lock() = Some(space);
    Ok(pml4)
}

/// Represents an x86_64 4-level (PML4) virtual address space.
pub struct AddressSpace {
    pml4_phys: PhysAddr,
}

impl AddressSpace {
    /// Obtains the currently active address space from the CPU CR3 register.
    pub fn active() -> Self {
        let (cr3_frame, _) = Cr3::read();
        Self {
            pml4_phys: cr3_frame.start_address(),
        }
    }

    /// Creates an AddressSpace handle pointing to a specific PML4 physical address.
    pub const fn from_pml4(pml4_phys: PhysAddr) -> Self {
        Self { pml4_phys }
    }

    /// Returns the physical address of this address space's root PML4 table.
    pub fn pml4_physical_address(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// Switches the CPU CR3 register to make this address space active.
    ///
    /// # Safety
    /// The caller must ensure that the address space contains valid mappings
    /// for the currently executing kernel code and stack.
    pub unsafe fn switch(&self) {
        let frame = PhysFrame::containing_address(self.pml4_phys);
        Cr3::write(frame, Cr3Flags::empty());
    }

    /// In UEFI x86_64 identity-mapped environments or direct-mapped kernels,
    /// read a page table at a given physical address.
    pub unsafe fn table_at<'a>(&self, phys: PhysAddr) -> &'a PageTable {
        let ptr = phys.as_u64() as *const PageTable;
        &*ptr
    }

    /// In UEFI x86_64 identity-mapped environments or direct-mapped kernels,
    /// get a mutable reference to a page table at a given physical address.
    pub unsafe fn table_at_mut<'a>(&self, phys: PhysAddr) -> &'a mut PageTable {
        let ptr = phys.as_u64() as *mut PageTable;
        &mut *ptr
    }

    /// Traverses the page table entry to find the next level page table,
    /// allocating a new 4 KiB frame from `allocator` and initializing it if not present.
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
        x86_64::instructions::tlb::flush(page.start_address());
        Ok(())
    }

    /// Unmaps a 4 KiB virtual page and returns the previously mapped physical frame.
    ///
    /// Flushes the CPU Translation Lookaside Buffer (TLB) for `page`.
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
        x86_64::instructions::tlb::flush(page.start_address());
        Ok(frame)
    }

    /// Updates protection flags (e.g. read-write, user-accessible, no-execute) for an existing mapped page.
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
        x86_64::instructions::tlb::flush(page.start_address());
        Ok(())
    }

    /// Ensures that the specified virtual address range is marked USER_ACCESSIBLE
    /// across all hierarchical page table levels (PML4, PDPT, PD, and PT / huge page).
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
                x86_64::instructions::tlb::flush(page.start_address());
                continue;
            }

            let p2 = self.table_at_mut(p3_entry.addr());
            let p2_entry = &mut p2[page.p2_index()];
            if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p2_entry.set_flags(p2_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);
            if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                x86_64::instructions::tlb::flush(page.start_address());
                continue;
            }

            let p1 = self.table_at_mut(p2_entry.addr());
            let p1_entry = &mut p1[page.p1_index()];
            if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            p1_entry.set_flags(p1_entry.flags() | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE);
            x86_64::instructions::tlb::flush(page.start_address());
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

        Ok(Self {
            pml4_phys: new_pml4_phys,
        })
    }

    /// Creates a new isolated user address space with higher-half kernel mappings shared.
    pub fn create_user_space(allocator: &mut PhysicalMemoryManager) -> Result<Self, &'static str> {
        let new_pml4_frame = allocator
            .allocate_frame()
            .ok_or("Out of memory: cannot allocate PML4 frame for user address space")?;
        let new_pml4_phys = new_pml4_frame.start_address();

        let active_space = Self::active();
        let active_pml4 = unsafe { active_space.table_at(active_space.pml4_phys) };
        let new_pml4 = unsafe { active_space.table_at_mut(new_pml4_phys) };
        new_pml4.zero();

        // Share the kernel half (entries 256..512) and active low identity mappings (entry 0)
        for i in 256..512 {
            new_pml4[i] = active_pml4[i].clone();
        }
        new_pml4[0] = active_pml4[0].clone();

        Ok(Self {
            pml4_phys: new_pml4_phys,
        })
    }
}

/// Marks a memory region as user-accessible in the active/kernel PML4 page tables.
pub fn make_user_accessible(virt_start: VirtAddr, size: usize) -> Result<(), &'static str> {
    if let Some(ref mut space) = *KERNEL_SPACE.lock() {
        unsafe { space.make_user_accessible(virt_start, size) }
    } else {
        let mut active = AddressSpace::active();
        unsafe { active.make_user_accessible(virt_start, size) }
    }
}
