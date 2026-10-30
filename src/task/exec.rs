//! # Task Subsystem: Linux Process Image Loader (`execve`)
//!
//! Builds a complete Linux process image inside a fresh private address space ([`Mm`]):
//! maps the executable's `PT_LOAD` segments as copy-on-write file mappings, maps the
//! `PT_INTERP` dynamic linker (Ubuntu's own `ld-linux-x86-64.so.2`), sets up the program
//! break and an 8 MiB demand-paged stack, and writes the System V initial stack
//! (`argc`, `argv`, `envp`, auxiliary vector) exactly as Linux's `binfmt_elf` does.
//!
//! Executables linked at fixed addresses below `USER_SPACE_START` (inside the kernel's
//! identity map) cannot live in a private address space and are rejected by
//! [`is_vm_loadable`]; the legacy loader in [`super::elf`] still runs those.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::elf::{ElfBinary, ElfError, Elf64ProgramHeader};
use crate::compat::linux::types::*;
use crate::memory::vm::{
    Backing, BufferObject, Mm, MappedObject, PAGE_SIZE, PIE_BASE, PROT_EXEC, PROT_READ, PROT_WRITE, STACK_SIZE,
    STACK_TOP, USER_SPACE_START,
};

const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// A loaded Linux process, ready to be scheduled.
pub struct LinuxExecImage {
    pub mm: Mm,
    pub entry: u64,
    pub rsp: u64,
}

/// Credentials reported to the new process through the auxiliary vector.
#[derive(Clone, Copy)]
pub struct ExecCreds {
    pub uid: u32,
    pub gid: u32,
}

/// Returns true if the binary can be loaded into a private address space: position
/// independent (`ET_DYN`) or linked entirely above the kernel identity map.
pub fn is_vm_loadable(bytes: &[u8]) -> bool {
    let elf = match ElfBinary::parse(bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if elf.is_pie() {
        return true;
    }
    elf.load_segments().iter().all(|ph| ph.p_vaddr >= USER_SPACE_START)
}

fn page_down(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

fn page_up(v: u64) -> u64 {
    (v + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

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

/// Result of mapping one ELF object.
/// An ELF file to load: its leading bytes (enough for the headers, `PT_INTERP` and
/// program header table), its total length, and the object its pages are mapped from.
pub struct ElfSource {
    pub head: Vec<u8>,
    pub len: u64,
    pub obj: Arc<dyn MappedObject>,
}

impl ElfSource {
    /// A source backed by an in-memory copy of the whole file.
    pub fn from_bytes(bytes: Box<[u8]>) -> Self {
        let head = bytes[..bytes.len().min(64 * 1024)].to_vec();
        let len = bytes.len() as u64;
        let obj: Arc<dyn MappedObject> = BufferObject::new(bytes);
        Self { head, len, obj }
    }
}

struct MappedElf {
    bias: u64,
    entry: u64,
    phdr: u64,
    end: u64,
}

/// Maps all `PT_LOAD` segments of `obj` into `mm`. PIE objects are placed at `pie_base`
/// when given, otherwise wherever the mmap allocator finds room.
fn map_elf(mm: &mut Mm, src: &ElfSource, pie_base: Option<u64>) -> Result<MappedElf, ElfError> {
    let elf = ElfBinary::parse(&src.head)?;
    let segs = elf.load_segments();
    if segs.is_empty() {
        return Err(ElfError::NoLoadableSegments);
    }
    let min_vaddr = page_down(segs.iter().map(|p| p.p_vaddr).min().unwrap());
    let max_vaddr = page_up(segs.iter().map(|p| p.p_vaddr + p.p_memsz).max().unwrap());

    let bias = if elf.is_pie() {
        match pie_base {
            Some(base) => base - min_vaddr,
            None => {
                // Reserve the whole span so segments land contiguously, then map over it
                let span = max_vaddr - min_vaddr;
                let base = mm
                    .mmap(0, span, 0, false, false, false, Backing::Anon)
                    .map_err(|_| ElfError::AllocationFailed)?;
                base - min_vaddr
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
        let seg_start = bias + ph.p_vaddr;
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
            phdr = bias + ph.p_vaddr;
        }
    }
    if phdr == 0 {
        for ph in &segs {
            if header.e_phoff >= ph.p_offset && header.e_phoff < ph.p_offset + ph.p_filesz {
                phdr = bias + ph.p_vaddr + (header.e_phoff - ph.p_offset);
            }
        }
    }

    Ok(MappedElf {
        bias,
        entry: bias + header.e_entry,
        phdr,
        end: bias + max_vaddr,
    })
}

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn cpuid_edx_leaf1() -> u64 {
    core::arch::x86_64::__cpuid(1).edx as u64
}

/// Loads `exe` (and its dynamic linker, read through `read_file`) into a new address space.
pub fn load_linux_exec(
    exe: ElfSource,
    exec_path: &str,
    argv: &[&str],
    envp: &[&str],
    creds: ExecCreds,
    read_file: &dyn Fn(&str) -> Option<ElfSource>,
) -> Result<LinuxExecImage, ElfError> {
    let mut mm = Mm::new().map_err(|e| ElfError::PagingError(e))?;

    let interp_path = ElfBinary::parse(&exe.head)?.interp_path().map(String::from);
    let main = map_elf(&mut mm, &exe, Some(PIE_BASE))?;

    mm.brk_start = page_up(main.end);
    mm.brk = mm.brk_start;

    let (entry, interp_base) = match interp_path {
        Some(path) => {
            let interp_src = read_file(&path).ok_or(ElfError::InterpreterNotFound)?;
            let interp = map_elf(&mut mm, &interp_src, None)?;
            (interp.entry, interp.bias)
        }
        None => (main.entry, 0),
    };

    // Stack: an 8 MiB demand-paged area just below STACK_TOP
    let stack_base = STACK_TOP - STACK_SIZE;
    mm.mmap(stack_base, STACK_SIZE, PROT_READ | PROT_WRITE, false, true, false, Backing::Anon)
        .map_err(|_| ElfError::AllocationFailed)?;

    // --- Strings area at the top of the stack ---
    let mut strings: Vec<u8> = Vec::new();
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
        (AT_EUID, creds.uid as u64),
        (AT_GID, creds.gid as u64),
        (AT_EGID, creds.gid as u64),
        (AT_SECURE, 0),
        (AT_RANDOM, addr_of(random_off)),
        (AT_HWCAP2, 0),
        (AT_EXECFN, addr_of(execfn_off)),
        (AT_PLATFORM, addr_of(platform_off)),
        (AT_NULL, 0),
    ];
    for (key, val) in auxv {
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

    Ok(LinuxExecImage { mm, entry, rsp: sp })
}
