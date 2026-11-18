//! # Task Subsystem: Linux Process Image Loader (`execve`)
//!
//! Builds a complete Linux process image inside a fresh private address space (`Mm`):
//! maps the executable's `PT_LOAD` segments as copy-on-write file mappings, maps the
//! `PT_INTERP` dynamic linker (Ubuntu's own `ld-linux-x86-64.so.2`), sets up the program
//! break and an 8 MiB demand-paged stack, and writes the System V initial stack
//! (`argc`, `argv`, `envp`, auxiliary vector) exactly as Linux's `binfmt_elf` does.
//!
//! ## Architectural Role & Design Rationale
//!
//! Unlike the legacy loader in `super::elf`, which copies segments eagerly into the shared
//! kernel address space, this module constructs a demand-paged virtual memory layout inside
//! an isolated `Mm`. Loadable segments are backed directly by `MappedObject`s (such as
//! page-cached ZFS inodes or `BufferObject`s) so pages are faulted in on demand and shared
//! across processes.
//!
//! Executables linked at fixed addresses must lie in a user area: the low window (the
//! first GiB, where `ET_EXEC` binaries are usually linked) or the main user area; others
//! are rejected by `is_vm_loadable` and the legacy loader in `super::elf` runs them.
//!
//! ## Key Types & Interfaces
//!
//! - `LinuxExecImage`: Loaded user address space (`Mm`), entry point (`RIP`), and stack pointer (`RSP`).
//! - `ExecCreds`: Process UID/GID credentials written into the initial auxiliary vector (`AT_UID`, `AT_GID`, etc.).
//! - `ElfSource`: Header prefix, total file size, and `MappedObject` backing an ELF binary.
//! - `is_vm_loadable`: Checks whether an ELF binary can be mapped into a private user address space.
//! - `load_linux_exec`: Maps main binary and `PT_INTERP` linker, allocates stack, and populates `argv`/`envp`/`auxv`.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Instructions**: Uses `rdtsc` to seed `AT_RANDOM` and `cpuid` (leaf 1) to populate `AT_HWCAP`.
//! - **Virtual Memory**: Relies on [`crate::memory::vm::Mm`] for `mmap`, `write_bytes`, and `brk` setup.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::elf::{ElfBinary, ElfError, Elf64ProgramHeader};
use crate::compat::linux::types::*;
use crate::memory::vm::{
    Backing, BufferObject, Mm, MappedObject, PAGE_SIZE, PIE_BASE, PROT_EXEC, PROT_READ, PROT_WRITE, STACK_SIZE,
    STACK_TOP,
};

/// Program header type describing the location of the program header table itself.
const PT_PHDR: u32 = 6;
/// Segment flag: executable.
const PF_X: u32 = 1;
/// Segment flag: writable.
const PF_W: u32 = 2;
/// Segment flag: readable.
const PF_R: u32 = 4;

/// A loaded Linux process, ready to be scheduled.
pub struct LinuxExecImage {
    /// Populated private virtual address space for the new process.
    pub mm: Mm,
    /// Initial instruction pointer (`RIP`)—either the dynamic linker or main executable entry.
    pub entry: u64,
    /// Initial user stack pointer (`RSP`) pointing to `argc` at the base of the System V stack frame.
    pub rsp: u64,
    /// The personality the program runs with (`crate::personality::choose`).
    pub pers: crate::task::TaskPersonality,
    /// Initial `rdi`: 0 for Linux; FreeBSD passes the address of `argc` there (its `_start`
    /// and `_rtld_start` read it).
    pub rdi: u64,
}

/// Credentials reported to the new process through the auxiliary vector.
#[derive(Clone, Copy)]
pub struct ExecCreds {
    /// Real user ID (`AT_UID`).
    pub uid: u32,
    /// Real group ID (`AT_GID`).
    pub gid: u32,
    /// Effective user ID (`AT_EUID`): the file owner for a set-user-ID program.
    pub euid: u32,
    /// Effective group ID (`AT_EGID`).
    pub egid: u32,
    /// File capabilities raise privileges: secure mode (`AT_SECURE`) as for set-ID.
    pub secure: bool,
}

/// Returns true if the binary can be loaded into a private address space: position
/// independent (`ET_DYN`) or linked entirely above the kernel identity map.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the candidate executable image.
///
/// # Returns
///
/// `true` if binary can be safely mapped in user space, `false` otherwise.
pub fn is_vm_loadable(bytes: &[u8]) -> bool {
    let elf = match ElfBinary::parse(bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if elf.is_pie() {
        return true;
    }
    elf.load_segments().iter().all(|ph| crate::memory::vm::is_user_range(ph.p_vaddr, ph.p_memsz.max(1)))
}

/// Rounds `v` down to the nearest 4 KiB page boundary.
///
/// # Arguments
///
/// * `v` - Input byte address.
///
/// # Returns
///
/// Page-aligned address rounded down.
fn page_down(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

/// Rounds `v` up to the nearest 4 KiB page boundary.
///
/// # Arguments
///
/// * `v` - Input byte address.
///
/// # Returns
///
/// Page-aligned address rounded up.
fn page_up(v: u64) -> u64 {
    (v + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Translates ELF segment flags (`PF_R`, `PF_W`, `PF_X`) into VM protection flags (`PROT_*`).
///
/// # Arguments
///
/// * `ph` - Reference to the ELF64 program header to inspect.
///
/// # Returns
///
/// Bitwise combination of [`PROT_READ`], [`PROT_WRITE`], and [`PROT_EXEC`].
fn segment_prot(ph: &Elf64ProgramHeader) -> u32 {
    let mut prot = 0;
    if ph.p_flags & PF_R != 0 {
        prot |= PROT_READ;
    }
    if ph.p_flags & PF_W != 0 {
        prot |= PROT_WRITE;
    }
    if ph.p_flags & PF_X != 0 {
        prot |= PROT_EXEC;
    }
    prot
}

/// An ELF file to load: its leading bytes (enough for the headers, `PT_INTERP` and
/// program header table), its total length, and the object its pages are mapped from.
pub struct ElfSource {
    /// Leading bytes of the ELF file (at least the header and program header table).
    pub head: Vec<u8>,
    /// Total length of the ELF file in bytes.
    pub len: u64,
    /// Backing object supplying 4 KiB pages for demand-paged segment mappings.
    pub obj: Arc<dyn MappedObject>,
}

impl ElfSource {
    /// A source backed by an in-memory copy of the whole file.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Boxed slice containing complete ELF file contents.
    ///
    /// # Returns
    ///
    /// A initialized [`ElfSource`] ready for segment mapping.
    pub fn from_bytes(bytes: Box<[u8]>) -> Self {
        let head = bytes[..bytes.len().min(64 * 1024)].to_vec();
        let len = bytes.len() as u64;
        let obj: Arc<dyn MappedObject> = BufferObject::new(bytes);
        Self { head, len, obj }
    }
}

/// Result of mapping one ELF object into a user address space.
struct MappedElf {
    /// Load bias added to the ELF object's virtual addresses (`0` for `ET_EXEC`).
    bias: u64,
    /// Relocated virtual entry point address (`bias + e_entry`).
    entry: u64,
    /// Relocated virtual address of the in-memory program header table (`AT_PHDR`).
    phdr: u64,
    /// Highest page-aligned virtual address covered by the mapped segments.
    end: u64,
}

/// Maps all `PT_LOAD` segments of `obj` into `mm`. PIE objects are placed at `pie_base`
/// when given, otherwise wherever the mmap allocator finds room.
///
/// # Arguments
///
/// * `mm` - Mutable reference to the target user address space.
/// * `src` - Source ELF image descriptor.
/// * `pie_base` - Optional fixed base address for position-independent executables.
///
/// # Returns
///
/// [`MappedElf`] layout on success.
///
/// # Errors
///
/// Returns [`ElfError`] if parsing, segment validation, or virtual memory mapping fails.
fn map_elf(mm: &mut Mm, src: &ElfSource, pie_base: Option<u64>, name: &str) -> Result<MappedElf, ElfError> {
    let elf = ElfBinary::parse(&src.head)?;
    let segs = elf.load_segments();
    if segs.is_empty() {
        return Err(ElfError::NoLoadableSegments);
    }
    // Segments must fit the file, and their ends round up to a page without wrapping
    // (where they land is mmap's to check: outside user space, it fails)
    for ph in &segs {
        ph.check_load(src.len)?;
        if ph.p_vaddr + ph.p_memsz > !(PAGE_SIZE - 1) {
            return Err(ElfError::SegmentOutOfBounds);
        }
    }
    let min_vaddr = page_down(segs.iter().map(|p| p.p_vaddr).min().unwrap());
    let max_vaddr = page_up(segs.iter().map(|p| p.p_vaddr + p.p_memsz).max().unwrap());

    // A PIE's bias wraps as on Linux (load_bias = base - vaddr): what counts is where the
    // segments land, which mmap checks
    let bias = if elf.is_pie() {
        match pie_base {
            Some(base) => base.wrapping_sub(min_vaddr),
            None => {
                // Reserve the whole span so segments land contiguously, then map over it
                let span = max_vaddr - min_vaddr;
                let base = mm
                    .mmap(0, span, 0, false, false, false, Backing::Anon)
                    .map_err(|_| ElfError::AllocationFailed)?;
                base.wrapping_sub(min_vaddr)
            }
        }
    } else {
        0
    };

    let object = src.obj.clone();
    let file_len = src.len;
    for ph in &segs {
        if ph.p_offset.saturating_add(ph.p_filesz) > file_len {
            return Err(ElfError::SegmentOutOfBounds);
        }
        let prot = segment_prot(ph);
        let seg_start = bias.wrapping_add(ph.p_vaddr);
        let map_start = page_down(seg_start);
        let file_end = seg_start + ph.p_filesz;
        let mem_end = page_up(seg_start + ph.p_memsz);

        let mut anon_start = map_start;
        if ph.p_filesz > 0 {
            let file_map_end = page_up(file_end);
            mm.mmap(
                map_start,
                file_map_end - map_start,
                prot,
                false,
                true,
                false,
                Backing::Object {
                    obj: object.clone(),
                    pgoff: page_down(ph.p_offset) / PAGE_SIZE,
                },
            )
            .map_err(|_| ElfError::AllocationFailed)?;
            mm.set_name(map_start, file_map_end, Some(name));
            anon_start = file_map_end;

            // The rest of the last file page belongs to .bss and must read as zero
            if ph.p_memsz > ph.p_filesz && file_end & (PAGE_SIZE - 1) != 0 && prot & PROT_WRITE != 0 {
                let zeros = alloc::vec![0u8; (file_map_end - file_end) as usize];
                mm.write_bytes(file_end, &zeros).map_err(|_| ElfError::AllocationFailed)?;
            }
        }
        if mem_end > anon_start {
            mm.mmap(anon_start, mem_end - anon_start, prot, false, true, false, Backing::Anon)
                .map_err(|_| ElfError::AllocationFailed)?;
        }
    }

    // Locate the program headers in memory for AT_PHDR
    let header = elf.header();
    let mut phdr = 0;
    for ph in elf.program_headers() {
        if ph.p_type == PT_PHDR {
            phdr = bias.wrapping_add(ph.p_vaddr);
        }
    }
    if phdr == 0 {
        for ph in &segs {
            if header.e_phoff >= ph.p_offset && header.e_phoff < ph.p_offset + ph.p_filesz {
                phdr = bias.wrapping_add(ph.p_vaddr + (header.e_phoff - ph.p_offset));
            }
        }
    }

    Ok(MappedElf {
        bias,
        entry: bias.wrapping_add(header.e_entry),
        phdr,
        end: bias.wrapping_add(max_vaddr),
    })
}

/// Reads the CPU timestamp counter (`RDTSC`) to seed `AT_RANDOM` bytes on the initial stack.
///
/// # Returns
///
/// 64-bit cycle counter value as `u64`.
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Queries CPUID leaf 1 (`EDX`) hardware capability flags for `AT_HWCAP`.
///
/// # Returns
///
/// 64-bit bitmask of x86_64 CPU features from EDX register.
fn cpuid_edx_leaf1() -> u64 {
    core::arch::x86_64::__cpuid(1).edx as u64
}

/// Loads `exe` (and its dynamic linker, read through `read_file`) into a new address space.
///
/// # Arguments
///
/// * `exe` - Primary ELF executable source descriptor.
/// * `pers` - The personality chosen for it (`crate::personality::choose`); its interpreter
///   must have the same.
/// * `exec_path` - Path string recorded for `AT_EXECFN`.
/// * `argv` - Command-line argument strings.
/// * `envp` - Environment variable strings (`KEY=VALUE`).
/// * `creds` - User and group IDs reported in the auxiliary vector.
/// * `read_file` - Callback used to load the dynamic linker specified by `PT_INTERP`.
///
/// # Returns
///
/// A `LinuxExecImage` containing the populated `Mm`, entry point, and initial stack pointer.
///
/// # Errors
///
/// Returns [`ElfError`] if parsing fails, the dynamic interpreter cannot be found, or VM mapping fails.
pub fn load_linux_exec(
    exe: ElfSource,
    pers: crate::task::TaskPersonality,
    exec_path: &str,
    argv: &[&str],
    envp: &[&str],
    creds: ExecCreds,
    read_file: &dyn Fn(&str) -> Option<ElfSource>,
) -> Result<LinuxExecImage, ElfError> {
    let mut mm = Mm::new().map_err(|e| ElfError::PagingError(e))?;

    let interp_path = ElfBinary::parse(&exe.head)?.interp_path().map(String::from);
    // PT_GNU_STACK with PF_X: the program needs an executable stack (as for GCC nested
    // functions' trampolines), which Linux gives it
    let exec_stack = ElfBinary::parse(&exe.head)?.program_headers().any(|ph| ph.p_type == 0x6474_e551 && ph.p_flags & 1 != 0);
    let main = map_elf(&mut mm, &exe, Some(PIE_BASE), exec_path)?;

    mm.brk_start = page_up(main.end);
    mm.brk = mm.brk_start;

    let (entry, interp_base) = match interp_path {
        Some(path) => {
            let interp_src = read_file(&path).ok_or(ElfError::InterpreterNotFound)?;
            if !crate::personality::interp_agrees(pers, &interp_src.head, &path) {
                return Err(ElfError::UnsupportedType);
            }
            let interp = map_elf(&mut mm, &interp_src, None, &path)?;
            (interp.entry, interp.bias)
        }
        None => (main.entry, 0),
    };

    // Stack: an 8 MiB demand-paged area just below STACK_TOP
    let stack_base = STACK_TOP - STACK_SIZE;
    let stack_prot = PROT_READ | PROT_WRITE | if exec_stack { PROT_EXEC } else { 0 };
    mm.mmap(stack_base, STACK_SIZE, stack_prot, false, true, false, Backing::Anon)
        .map_err(|_| ElfError::AllocationFailed)?;
    mm.set_name(stack_base, stack_base + STACK_SIZE, Some("[stack]"));
    // The personality's layout (design 2.6): FreeBSD gets its auxiliary vector numbers, its
    // entry registers and the signal trampoline page instead of Linux's vDSO
    let freebsd = pers == crate::task::TaskPersonality::FreeBsd;
    // The vDSO (clock_gettime and the like in user mode)
    let vdso = if freebsd { map_freebsd_sigcode(&mut mm)?; None } else { crate::arch::vdso::map(&mut mm) };

    // --- Strings area at the top of the stack ---
    let mut strings: Vec<u8> = Vec::new();
    // FreeBSD: AT_PAGESIZES' array (3 words) and `struct ps_strings` (4 words) first, where
    // they are 8-byte aligned
    const FB_PAGESIZES: usize = 0;
    const FB_PS_STRINGS: usize = 24;
    if freebsd {
        strings.resize(56, 0);
        for (i, v) in [PAGE_SIZE, 0x20_0000, 0x4000_0000].iter().enumerate() {
            strings[FB_PAGESIZES + i * 8..FB_PAGESIZES + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    let push_str = |s: &[u8], strings: &mut Vec<u8>| -> usize {
        let off = strings.len();
        strings.extend_from_slice(s);
        strings.push(0);
        off
    };
    let argv_offs: Vec<usize> = argv.iter().map(|a| push_str(a.as_bytes(), &mut strings)).collect();
    let envp_offs: Vec<usize> = envp.iter().map(|e| push_str(e.as_bytes(), &mut strings)).collect();
    let execfn_off = push_str(exec_path.as_bytes(), &mut strings);
    let platform_off = push_str(b"x86_64", &mut strings);
    let random_off = strings.len();
    let seed = rdtsc();
    for i in 0..16u64 {
        let v = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(i.wrapping_mul(0xBF58_476D_1CE4_E5B9));
        strings.push((v >> 29) as u8 ^ (v >> 7) as u8);
    }

    let strings_base = (STACK_TOP - 16 - strings.len() as u64) & !0xF;
    let addr_of = |off: usize| strings_base + off as u64;
    // The arguments' strings, then the environment's (contiguous: pushed in that order)
    let arg_end = envp_offs.first().copied().unwrap_or(execfn_off);
    mm.args = (strings_base, addr_of(arg_end), addr_of(execfn_off));

    // FreeBSD's vector (`sys/sys/elf_common.h` numbers; its words that point into the
    // argument block are known once the block's size is)
    let fb_auxv = if freebsd {
        use crate::personality::abi::freebsd_at as at;
        let n = 1 + argv.len() + 1 + envp.len() + 1 + 2 * 31;
        let sp = (strings_base - n as u64 * 8) & !0xF;
        let (argv_at, envv_at) = (sp + 8, sp + 8 * (argv.len() as u64 + 2));
        // struct ps_strings { char **ps_argvstr; u_int ps_nargvstr; char **ps_envstr; u_int ps_nenvstr; }
        for (i, v) in [argv_at, argv.len() as u64, envv_at, envp.len() as u64].iter().enumerate() {
            strings[FB_PS_STRINGS + i * 8..FB_PS_STRINGS + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let hdr = ElfBinary::parse(&exe.head)?.header();
        let v: [(u64, u64); 31] = [
            (at::PHDR, main.phdr),
            (at::PHENT, 56),
            (at::PHNUM, hdr.e_phnum as u64),
            (at::PAGESZ, PAGE_SIZE),
            (at::BASE, interp_base),
            (at::FLAGS, 0),
            (at::ENTRY, main.entry),
            (at::UID, creds.uid as u64),
            (at::EUID, creds.euid as u64),
            (at::GID, creds.gid as u64),
            (at::EGID, creds.egid as u64),
            (at::EXECPATH, addr_of(execfn_off)),
            (at::CANARY, addr_of(random_off)),
            (at::CANARYLEN, 16),
            (at::OSRELDATE, crate::personality::abi::FREEBSD_OSRELDATE),
            (at::NCPUS, crate::arch::smp::online() as u64),
            (at::PAGESIZES, addr_of(FB_PAGESIZES)),
            (at::PAGESIZESLEN, 24),
            (at::STACKPROT, stack_prot as u64),
            (at::EHDRFLAGS, hdr.e_flags as u64),
            (at::HWCAP, 0),
            (at::HWCAP2, 0),
            // No ELF_BSDF_SIGFASTBLK: rtld and libthr never use sigfastblock
            (at::BSDFLAGS, 0),
            (at::ARGC, argv.len() as u64),
            (at::ARGV, argv_at),
            (at::ENVC, envp.len() as u64),
            (at::ENVV, envv_at),
            (at::PS_STRINGS, addr_of(FB_PS_STRINGS)),
            (at::USRSTACKBASE, STACK_TOP),
            (at::USRSTACKLIM, STACK_SIZE),
            (at::NULL, 0),
        ];
        Some(v)
    } else {
        None
    };

    // --- argc / argv / envp / auxv words ---
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(argv_offs.iter().map(|&o| addr_of(o)));
    words.push(0);
    words.extend(envp_offs.iter().map(|&o| addr_of(o)));
    words.push(0);
    let auxv = [
        (AT_HWCAP, cpuid_edx_leaf1()),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_CLKTCK, 100),
        (AT_PHDR, main.phdr),
        (AT_PHENT, 56),
        (AT_PHNUM, ElfBinary::parse(&exe.head)?.header().e_phnum as u64),
        (AT_BASE, interp_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, main.entry),
        (AT_UID, creds.uid as u64),
        (AT_EUID, creds.euid as u64),
        (AT_GID, creds.gid as u64),
        (AT_EGID, creds.egid as u64),
        // Secure mode (the C library ignores LD_PRELOAD and the like) for set-ID programs
        (AT_SECURE, (creds.uid != creds.euid || creds.gid != creds.egid || creds.secure) as u64),
        (AT_RANDOM, addr_of(random_off)),
        (AT_HWCAP2, 0),
        (AT_EXECFN, addr_of(execfn_off)),
        (AT_PLATFORM, addr_of(platform_off)),
        // (an AT_IGNORE entry when there is no vDSO)
        if let Some(v) = vdso { (crate::compat::linux::types::AT_SYSINFO_EHDR, v) } else { (1, 0) },
        (AT_NULL, 0),
    ];
    let auxv: &[(u64, u64)] = match &fb_auxv {
        Some(v) => v,
        None => &auxv,
    };
    for &(key, val) in auxv {
        words.push(key);
        words.push(val);
        mm.auxv.extend_from_slice(&key.to_le_bytes());
        mm.auxv.extend_from_slice(&val.to_le_bytes());
    }

    let sp = (strings_base - words.len() as u64 * 8) & !0xF;
    let mut block: Vec<u8> = Vec::with_capacity((STACK_TOP - sp) as usize);
    for w in &words {
        block.extend_from_slice(&w.to_le_bytes());
    }
    block.resize((strings_base - sp) as usize, 0);
    block.extend_from_slice(&strings);
    mm.write_bytes(sp, &block).map_err(|_| ElfError::AllocationFailed)?;

    if freebsd {
        // FreeBSD enters as if `_start` had been called: rsp = ((stack - 8) & ~15) + 8, and
        // rdi = the stack (the address of argc) (`exec_setregs`, sys/amd64/amd64/exec_machdep.c)
        return Ok(LinuxExecImage { mm, entry, rsp: ((sp - 8) & !0xF) + 8, pers, rdi: sp });
    }
    Ok(LinuxExecImage { mm, entry, rsp: sp, pers, rdi: 0 })
}

/// Maps FreeBSD's signal trampoline (`crate::personality::abi::FREEBSD_SIGCODE`) read-only and
/// executable at its fixed address in a FreeBSD process.
fn map_freebsd_sigcode(mm: &mut Mm) -> Result<(), ElfError> {
    use crate::personality::abi::{FREEBSD_SIGCODE as SIGCODE, FREEBSD_SIGCODE_ADDR as SIGCODE_ADDR};
    mm.mmap(SIGCODE_ADDR, PAGE_SIZE, PROT_READ | PROT_WRITE, false, true, false, Backing::Anon)
        .map_err(|_| ElfError::AllocationFailed)?;
    mm.write_bytes(SIGCODE_ADDR, &SIGCODE).map_err(|_| ElfError::AllocationFailed)?;
    mm.mprotect(SIGCODE_ADDR, PAGE_SIZE, PROT_READ | PROT_EXEC).map_err(|_| ElfError::AllocationFailed)?;
    mm.set_name(SIGCODE_ADDR, SIGCODE_ADDR + PAGE_SIZE, Some("[sigcode]"));
    Ok(())
}
