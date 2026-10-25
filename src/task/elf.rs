//! # Task Subsystem: ELF64 Userspace Binary Loader
//!
//! Parses 64-bit Executable and Linkable Format (ELF64) binaries, validates machine
//! architecture and segment constraints, maps loadable segments into user virtual address
//! space with appropriate page protection flags, initializes the user stack, and configures
//! hardware CPU registers for unprivileged Ring 3 execution.
//!
//! ## Architectural Role & Design Rationale
//!
//! In the Hydra microkernel architecture, user applications execute as unprivileged tasks
//! in CPU Ring 3, isolated from kernel memory and hardware I/O privileges. Rather than
//! embedding userland binaries directly into the kernel UEFI firmware image (`bootx64.efi`),
//! this module enables dynamic loading of standalone compiled ELF64 binaries from the OpenZFS
//! storage pool or external media at runtime.
//!
//! The loader handles both Position-Independent Executables (PIE, `ET_DYN`) and fixed-address
//! binaries (`ET_EXEC`). For each `PT_LOAD` segment, it:
//! 1. Allocates backing memory pages (heap-allocated buffers or dedicated physical frames).
//! 2. Copies file payload data (`p_filesz`).
//! 3. Zeroes any uninitialized data sections (`.bss`, where `p_memsz > p_filesz`).
//! 4. Configures page table mappings with `USER_ACCESSIBLE` protection flags.
//! 5. Prepares a dedicated user stack and Ring 3 segment selectors (`CS = 0x20 | 3`, `SS = 0x18 | 3`).
//!
//! ## Key Types & Interfaces
//!
//! - [`Elf64Header`]: 64-bit ELF file header definition.
//! - [`Elf64ProgramHeader`]: Describes loadable program segments (`PT_LOAD`).
//! - [`ElfBinary`]: Zero-copy parser validating ELF64 structure and segment layout.
//! - [`ElfProcessImage`]: Allocated process resources (stacks, segment buffers, entry point).
//! - [`load_elf()`]: Primary entry point to parse, validate, allocate, and map an ELF binary.
//!
//! ## Hardware & Dependency Context
//!
//! - CPU Privilege Level: Transitions from Ring 0 (Kernel) to Ring 3 (Userland) via `iretq`.
//! - Segment Selectors: Kernel CS `0x08`, Kernel SS `0x10`, User CS `0x23` (RPL 3), User SS `0x1B` (RPL 3).
//! - Page Tables: 4-Level x86_64 Paging (PML4 -> PDPT -> PD -> PT) with `USER_ACCESSIBLE` bit 2 set.
//! - Concurrency: Thread-safe memory allocation via `FRAME_ALLOCATOR` and `spin::Mutex`.
//!
//! ## Dataflow & Execution Lifecycle
//!
//! ```text
//! +------------------+      +-------------------+      +----------------------+
//! |  ZFS File Server | ---> |   load_elf()      | ---> |  Scheduler Spawn     |
//! | (/bin/hello.elf) |      | (Parse & Map Pgs) |      | (Ring 3 TCB Created) |
//! +------------------+      +-------------------+      +----------------------+
//!                                                                 |
//!                                                                 v
//! +------------------+      +-------------------+      +----------------------+
//! | Terminate Task   | <--- | User Syscalls     | <--- | Hardware iretq       |
//! | (SYS_EXIT / Dead)|      | (SYS_WRITE, etc.) |      | (Unprivileged Ring 3)|
//! +------------------+      +-------------------+      +----------------------+
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::task::scheduler::DEFAULT_STACK_SIZE;

/// Magic bytes identifying a valid ELF binary (`\x7fELF`).
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF File Identification index constants.
pub const EI_MAG0: usize = 0;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_ABIVERSION: usize = 8;

/// ELF architecture class: 64-bit object.
pub const ELFCLASS64: u8 = 2;

/// ELF data encoding: 2's complement, little-endian.
pub const ELFDATA2LSB: u8 = 1;

/// ELF version: Current version (1).
pub const EV_CURRENT: u8 = 1;

/// ELF Object file types.
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

/// Target machine architecture: AMD x86-64.
pub const EM_X86_64: u16 = 0x3E;

/// Program Header segment types.
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;

/// Program Header segment permission flags.
pub const PF_X: u32 = 1; // Executable
pub const PF_W: u32 = 2; // Writable
pub const PF_R: u32 = 4; // Readable

/// Standard 64-bit ELF File Header (64 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    /// ELF identification bytes (magic, class, endianness, version).
    pub e_ident: [u8; 16],
    /// Object file type (`ET_EXEC`, `ET_DYN`, etc.).
    pub e_type: u16,
    /// Target machine architecture (`EM_X86_64`).
    pub e_machine: u16,
    /// Object file version.
    pub e_version: u32,
    /// Virtual memory address of the entry point where execution begins.
    pub e_entry: u64,
    /// Program header table file offset in bytes.
    pub e_phoff: u64,
    /// Section header table file offset in bytes.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes (should be 64 for ELF64).
    pub e_ehsize: u16,
    /// Size of one entry in the program header table in bytes (typically 56).
    pub e_phentsize: u16,
    /// Number of entries in the program header table.
    pub e_phnum: u16,
    /// Size of one entry in the section header table in bytes.
    pub e_shentsize: u16,
    /// Number of entries in the section header table.
    pub e_shnum: u16,
    /// Section header table index of the section name string table.
    pub e_shstrndx: u16,
}

/// Standard 64-bit ELF Program Header entry (56 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    /// Segment type (e.g. `PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP`).
    pub p_type: u32,
    /// Segment permission flags (`PF_X`, `PF_W`, `PF_R`).
    pub p_flags: u32,
    /// Offset of the segment in the binary file image.
    pub p_offset: u64,
    /// Virtual address at which the segment should be placed in process memory.
    pub p_vaddr: u64,
    /// Physical address (reserved for systems with physical addressing; ignored).
    pub p_paddr: u64,
    /// Number of bytes this segment occupies in the file image.
    pub p_filesz: u64,
    /// Number of bytes this segment occupies in process virtual memory.
    pub p_memsz: u64,
    /// Required segment alignment in virtual memory and file.
    pub p_align: u64,
}

/// Errors that can occur during ELF parsing, validation, and segment mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Binary buffer is too small to contain a complete ELF64 header.
    BufferTooSmall,
    /// Magic signature does not match `[0x7f, 'E', 'L', 'F']`.
    InvalidMagic,
    /// Binary is not a 64-bit ELF file (`ELFCLASS64`).
    Not64Bit,
    /// Binary does not use 2's complement little-endian encoding (`ELFDATA2LSB`).
    NotLittleEndian,
    /// Architecture is not AMD x86-64 (`EM_X86_64`).
    UnsupportedMachine,
    /// Binary is neither an executable (`ET_EXEC`) nor a dynamic shared library / PIE (`ET_DYN`).
    UnsupportedType,
    /// Program header table extends beyond the bounds of the provided binary buffer.
    ProgramHeaderOutOfBounds,
    /// Binary contains no loadable (`PT_LOAD`) program segments.
    NoLoadableSegments,
    /// Segment file data extends beyond the bounds of the provided binary buffer.
    SegmentOutOfBounds,
    /// Failed to allocate heap memory or physical frames for program segments.
    AllocationFailed,
    /// Failed to update page table protection flags or map virtual pages.
    PagingError(&'static str),
}

impl ElfError {
    /// Returns a human-readable description of the ELF loading error.
    pub fn as_str(&self) -> &'static str {
        match self {
            ElfError::BufferTooSmall => "ELF buffer too small to hold valid header",
            ElfError::InvalidMagic => "Invalid ELF magic signature (not \\x7fELF)",
            ElfError::Not64Bit => "ELF binary is not 64-bit (ELFCLASS64 required)",
            ElfError::NotLittleEndian => "ELF binary is not Little-Endian (ELFDATA2LSB required)",
            ElfError::UnsupportedMachine => "ELF machine architecture is not x86_64",
            ElfError::UnsupportedType => "Unsupported ELF type (expected ET_EXEC or ET_DYN)",
            ElfError::ProgramHeaderOutOfBounds => "Program header table offset exceeds buffer size",
            ElfError::NoLoadableSegments => "Binary contains no PT_LOAD segments",
            ElfError::SegmentOutOfBounds => "Segment file offset and size exceed buffer bounds",
            ElfError::AllocationFailed => "Memory allocation failed during segment loading",
            ElfError::PagingError(msg) => msg,
        }
    }
}

/// Zero-copy parsed representation of a 64-bit ELF executable.
pub struct ElfBinary<'a> {
    data: &'a [u8],
    header: Elf64Header,
}

impl<'a> ElfBinary<'a> {
    /// Parses and validates an ELF64 binary image from a raw byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw byte slice containing the complete ELF binary image.
    ///
    /// # Returns
    ///
    /// Returns `Ok(ElfBinary)` if the binary contains valid headers, or an [`ElfError`]
    /// indicating why validation failed.
    ///
    /// # Errors
    ///
    /// - [`ElfError::BufferTooSmall`] if `bytes.len()` is less than 64 bytes.
    /// - [`ElfError::InvalidMagic`] if magic bytes differ from `\x7fELF`.
    /// - [`ElfError::Not64Bit`] if target architecture is not 64-bit.
    /// - [`ElfError::UnsupportedMachine`] if architecture is not x86_64.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < core::mem::size_of::<Elf64Header>() {
            return Err(ElfError::BufferTooSmall);
        }

        // Validate ELF Identification magic
        if bytes[..4] != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        // Validate 64-bit class
        if bytes[EI_CLASS] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }

        // Validate Little-Endian encoding
        if bytes[EI_DATA] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        // Read ELF header safely using unaligned read
        let header_ptr = bytes.as_ptr() as *const Elf64Header;
        let header: Elf64Header = unsafe { core::ptr::read_unaligned(header_ptr) };

        // Validate machine architecture
        if header.e_machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }

        // Validate executable or dynamic PIE type
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            return Err(ElfError::UnsupportedType);
        }

        // Validate program header table bounds
        let ph_end = header.e_phoff.saturating_add(
            (header.e_phnum as u64).saturating_mul(header.e_phentsize as u64),
        );
        if ph_end > bytes.len() as u64 {
            return Err(ElfError::ProgramHeaderOutOfBounds);
        }

        Ok(Self { data: bytes, header })
    }

    /// Returns a copy of the parsed ELF64 header.
    pub fn header(&self) -> Elf64Header {
        self.header
    }

    /// Returns the virtual address of the program entry point.
    pub fn entry_point(&self) -> u64 {
        self.header.e_entry
    }

    /// Returns true if this binary is a Position-Independent Executable (`ET_DYN`).
    pub fn is_pie(&self) -> bool {
        self.header.e_type == ET_DYN
    }

    /// Returns an iterator yielding all program headers in the ELF binary.
    pub fn program_headers(&self) -> ProgramHeadersIter<'a> {
        ProgramHeadersIter {
            data: self.data,
            offset: self.header.e_phoff as usize,
            entry_size: self.header.e_phentsize as usize,
            remaining: self.header.e_phnum as usize,
        }
    }

    /// Collects and returns all loadable (`PT_LOAD`) program headers.
    pub fn load_segments(&self) -> Vec<Elf64ProgramHeader> {
        let mut list = Vec::new();
        for ph in self.program_headers() {
            if ph.p_type == PT_LOAD {
                list.push(ph);
            }
        }
        list
    }
}

/// Iterator over ELF program headers.
pub struct ProgramHeadersIter<'a> {
    data: &'a [u8],
    offset: usize,
    entry_size: usize,
    remaining: usize,
}

impl<'a> Iterator for ProgramHeadersIter<'a> {
    type Item = Elf64ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        if self.offset + core::mem::size_of::<Elf64ProgramHeader>() > self.data.len() {
            return None;
        }

        let ph_ptr = unsafe { self.data.as_ptr().add(self.offset) as *const Elf64ProgramHeader };
        let ph = unsafe { core::ptr::read_unaligned(ph_ptr) };

        self.offset += self.entry_size;
        self.remaining -= 1;
        Some(ph)
    }
}

/// Fully prepared and mapped userspace process memory image.
pub struct ElfProcessImage {
    /// Runtime virtual entry point where CPU execution will begin.
    pub entry_point: u64,
    /// Initial user stack pointer (RSP) configured in user space.
    pub initial_user_rsp: u64,
    /// Dedicated 16 KiB unprivileged user stack buffer.
    pub user_stack: Box<[u8]>,
    /// Dedicated 16 KiB privileged kernel stack buffer (for TSS RSP0 and hardware SYSCALL).
    pub kernel_stack: Box<[u8]>,
    /// Backing memory buffer holding segment code/data for Position-Independent Executables.
    pub allocated_image: Option<Box<[u8]>>,
}

/// Parses, allocates, and maps an ELF64 binary into memory for Ring 3 execution.
///
/// # Arguments
///
/// * `elf_data` - Complete raw byte slice of the ELF executable image.
///
/// # Returns
///
/// An [`ElfProcessImage`] containing initialized stacks, entry points, and segment
/// allocations on success, or an [`ElfError`] if parsing or allocation fails.
///
/// # Errors
///
/// Returns [`ElfError`] if the binary is malformed, has invalid headers, or cannot be allocated.
pub fn load_elf(elf_data: &[u8]) -> Result<ElfProcessImage, ElfError> {
    let elf = ElfBinary::parse(elf_data)?;
    let load_segments = elf.load_segments();

    if load_segments.is_empty() {
        return Err(ElfError::NoLoadableSegments);
    }

    // Determine the virtual memory span across all PT_LOAD segments
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;

    for ph in &load_segments {
        if ph.p_vaddr < min_vaddr {
            min_vaddr = ph.p_vaddr;
        }
        let seg_end = ph.p_vaddr.saturating_add(ph.p_memsz);
        if seg_end > max_vaddr {
            max_vaddr = seg_end;
        }

        // Validate file offset bounds
        let file_end = ph.p_offset.saturating_add(ph.p_filesz);
        if file_end > elf_data.len() as u64 {
            return Err(ElfError::SegmentOutOfBounds);
        }
    }

    // Allocate 16 KiB privileged Kernel Stack (used for TSS RSP0 and hardware SYSCALL transitions)
    let kernel_stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();

    // Allocate 16 KiB unprivileged User Stack
    let user_stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();
    let user_stack_bottom = user_stack.as_ptr() as u64;
    let user_stack_top = (user_stack_bottom + user_stack.len() as u64) & !0xF;
    let initial_user_rsp = user_stack_top.saturating_sub(48);

    // Mark the user stack memory region as USER_ACCESSIBLE in the active page tables
    crate::memory::paging::make_user_accessible(
        VirtAddr::new(user_stack_bottom),
        user_stack.len(),
    )
    .map_err(|e| ElfError::PagingError(e))?;

    // Strategy 1: Position-Independent Executable (ET_DYN) or relative segments (min_vaddr == 0)
    if elf.is_pie() || min_vaddr == 0 {
        let total_span = (max_vaddr.saturating_sub(min_vaddr)) as usize;
        let aligned_span = (total_span + 4095) & !4095;

        // Allocate a dedicated zero-initialized backing buffer for all segments
        let mut seg_buffer = alloc::vec![0u8; aligned_span].into_boxed_slice();
        let base_virt = seg_buffer.as_ptr() as u64;

        for ph in &load_segments {
            let seg_offset = (ph.p_vaddr - min_vaddr) as usize;
            let filesz = ph.p_filesz as usize;
            let memsz = ph.p_memsz as usize;

            if filesz > 0 {
                let file_src = &elf_data[ph.p_offset as usize..(ph.p_offset as usize + filesz)];
                seg_buffer[seg_offset..seg_offset + filesz].copy_from_slice(file_src);
            }

            // Zero out trailing BSS if memsz > filesz
            if memsz > filesz {
                let bss_start = seg_offset + filesz;
                let bss_end = seg_offset + memsz;
                if bss_end <= seg_buffer.len() {
                    seg_buffer[bss_start..bss_end].fill(0);
                }
            }
        }

        // Mark the segment buffer memory region as USER_ACCESSIBLE
        crate::memory::paging::make_user_accessible(
            VirtAddr::new(base_virt),
            seg_buffer.len(),
        )
        .map_err(|e| ElfError::PagingError(e))?;

        // Calculate runtime entry point relative to allocated segment base
        let entry_point = base_virt + (elf.header.e_entry - min_vaddr);

        Ok(ElfProcessImage {
            entry_point,
            initial_user_rsp,
            user_stack,
            kernel_stack,
            allocated_image: Some(seg_buffer),
        })
    } else {
        // Strategy 2: Fixed Virtual Address Binary (ET_EXEC with absolute virtual addresses)
        for ph in &load_segments {
            let filesz = ph.p_filesz as usize;
            let memsz = ph.p_memsz as usize;
            let vaddr = ph.p_vaddr;

            // Ensure pages covering [vaddr, vaddr + memsz) are marked USER_ACCESSIBLE
            crate::memory::paging::make_user_accessible(
                VirtAddr::new(vaddr),
                memsz,
            )
            .map_err(|e| ElfError::PagingError(e))?;

            // Copy file payload into target virtual address
            if filesz > 0 {
                let src = &elf_data[ph.p_offset as usize..(ph.p_offset as usize + filesz)];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), vaddr as *mut u8, filesz);
                }
            }

            // Zero out BSS section
            if memsz > filesz {
                let bss_dest = (vaddr + ph.p_filesz) as *mut u8;
                let bss_len = memsz - filesz;
                unsafe {
                    core::ptr::write_bytes(bss_dest, 0, bss_len);
                }
            }
        }

        Ok(ElfProcessImage {
            entry_point: elf.header.e_entry,
            initial_user_rsp,
            user_stack,
            kernel_stack,
            allocated_image: None,
        })
    }
}
