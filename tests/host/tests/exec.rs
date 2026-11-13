//! Tests for the Linux `execve` loader in `src/task/exec.rs`: segment
//! mapping into a real `Mm` (protections, .bss zeroing, PIE bias), the
//! dynamic linker, the 8 MiB stack, and the initial stack the C library
//! starts from (argc/argv/envp/auxv).
//!
//! Everything runs on the real address-space code (see tests/vm.rs) backed
//! by the shared frame pool, so the tests read the new process's memory
//! through its own page tables.

mod common;

use common::elf::*;
use hydra_hosttests::compat::linux::types::{
    AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_EXECFN, AT_GID, AT_HWCAP, AT_NULL, AT_PAGESZ, AT_PHDR,
    AT_PHENT, AT_PHNUM, AT_PLATFORM, AT_RANDOM, AT_SECURE, AT_SYSINFO_EHDR, AT_UID,
};
use hydra_hosttests::fake;
use hydra_hosttests::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests::memory::vm::*;
use hydra_hosttests::task::elf::ElfError;
use hydra_hosttests::task::exec::*;

const P: u64 = PAGE_SIZE;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const INTERP: &str = "/lib64/ld-linux-x86-64.so.2";

fn used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

/// Run `f` with exclusive use of the frame pool; check nothing leaks.
fn isolated(f: impl FnOnce()) {
    let _g = common::serial();
    common::global_frames();
    fake::reset();
    warm_vdso();
    let before = used();
    f();
    assert_eq!(used(), before, "frames leaked by this exec");
}

/// The vDSO's pages are made once, on first use, and kept for good (as at
/// boot): make them before measuring, so no test is blamed for them.
fn warm_vdso() {
    let mut mm = Mm::new().unwrap();
    let _ = hydra_hosttests::arch::vdso::map(&mut mm);
}

fn src(bytes: Vec<u8>) -> ElfSource {
    ElfSource::from_bytes(bytes.into_boxed_slice())
}

const USER: ExecCreds = ExecCreds { uid: 1000, gid: 1000, euid: 1000, egid: 1000, secure: false };

fn no_files(_: &str) -> Option<ElfSource> {
    None
}

/// Static PIE: text (R+X) with headers at 0, data (R+W) at 0x2000 whose
/// file part ends mid-page and is followed by .bss. The file bytes after the
/// data segment are non-zero, so .bss zeroing is observable.
fn static_pie() -> Elf {
    Elf::new(
        ET_DYN,
        0x100,
        &[
            load_with(PF_R | PF_X, 0, 0, 0x1000, 0x1000),
            load_with(PF_R | PF_W, 0x1000, 0x2000, 0x80, 0x3000),
            Ph { ty: PT_GNU_STACK, flags: PF_R | PF_W, offset: 0, vaddr: 0, filesz: 0, memsz: 0 },
        ],
        0x2000,
    )
    .put(0x100, b"TEXT")
    .put(0x1000, &[0xDD; 0x80])
    .put(0x1080, &[0xEE; 0xF80]) // file bytes past p_filesz: must not leak into .bss
}

fn dynamic_pie() -> Elf {
    let mut path = INTERP.as_bytes().to_vec();
    path.push(0);
    Elf::new(
        ET_DYN,
        0x200,
        &[
            Ph { ty: PT_PHDR, flags: PF_R, offset: 64, vaddr: 64, filesz: 56 * 3, memsz: 56 * 3 },
            Ph { ty: PT_INTERP, flags: PF_R, offset: 0x800, vaddr: 0x800, filesz: path.len() as u64, memsz: path.len() as u64 },
            load_with(PF_R | PF_X, 0, 0, 0x1000, 0x1000),
        ],
        0x1000,
    )
    .put(0x800, &path)
}

fn ld_so() -> Vec<u8> {
    Elf::new(ET_DYN, 0x400, &[load_with(PF_R | PF_X, 0, 0, 0x800, 0x2000)], 0x800).put(0x400, b"LDSO").bytes
}

// --------------------------------------------------------- stack reading

fn peek(mm: &mut Mm, addr: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let phys = mm.translate(addr + i).expect("stack page not present");
            unsafe { *(phys.as_u64() as *const u8) }
        })
        .collect()
}

fn word(mm: &mut Mm, addr: u64) -> u64 {
    u64::from_le_bytes(peek(mm, addr, 8).try_into().unwrap())
}

fn cstr(mm: &mut Mm, addr: u64) -> String {
    let mut out = Vec::new();
    let mut a = addr;
    loop {
        let b = peek(mm, a, 1)[0];
        if b == 0 {
            break;
        }
        out.push(b);
        a += 1;
    }
    String::from_utf8(out).unwrap()
}

struct Stack {
    argv: Vec<String>,
    envp: Vec<String>,
    auxv: Vec<(u64, u64)>,
}

fn stack(img: &mut LinuxExecImage) -> Stack {
    let mm = &mut img.mm;
    let sp = img.rsp;
    let argc = word(mm, sp);
    let mut at = sp + 8;
    let mut argv = Vec::new();
    for _ in 0..argc {
        let p = word(mm, at);
        argv.push(cstr(mm, p));
        at += 8;
    }
    assert_eq!(word(mm, at), 0, "argv NULL");
    at += 8;
    let mut envp = Vec::new();
    while word(mm, at) != 0 {
        let p = word(mm, at);
        envp.push(cstr(mm, p));
        at += 8;
    }
    at += 8;
    let mut auxv = Vec::new();
    loop {
        let (k, v) = (word(mm, at), word(mm, at + 8));
        auxv.push((k, v));
        at += 16;
        if k == AT_NULL {
            break;
        }
    }
    Stack { argv, envp, auxv }
}

fn aux(s: &Stack, key: u64) -> u64 {
    s.auxv.iter().find(|(k, _)| *k == key).unwrap_or_else(|| panic!("auxv {key} missing")).1
}

fn exec(bytes: Vec<u8>, argv: &[&str], envp: &[&str]) -> LinuxExecImage {
    load_linux_exec(src(bytes), "/usr/bin/app", argv, envp, USER, &no_files).unwrap()
}

// ------------------------------------------------------------- segments

#[test]
fn pie_is_mapped_at_pie_base_with_segment_protections() {
    isolated(|| {
        let img = exec(static_pie().bytes, &["app"], &[]);
        assert_eq!(img.entry, PIE_BASE + 0x100);
        let text = img.mm.find_vma(PIE_BASE).unwrap();
        assert_eq!((text.start, text.end, text.prot), (PIE_BASE, PIE_BASE + P, PROT_READ | PROT_EXEC));
        assert_eq!(text.name.as_deref(), Some("/usr/bin/app"), "/proc/<pid>/maps shows the path");
        assert!(img.mm.find_vma(PIE_BASE + P).is_none(), "gap between segments stays unmapped");
        let data = img.mm.find_vma(PIE_BASE + 0x2000).unwrap();
        assert_eq!(data.prot, PROT_READ | PROT_WRITE);
        assert_eq!(img.mm.find_vma(PIE_BASE + 0x4FFF).unwrap().prot, PROT_READ | PROT_WRITE, ".bss pages");
        assert!(img.mm.find_vma(PIE_BASE + 0x5000).is_none());
    });
}

#[test]
fn text_comes_from_the_file() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        img.mm.handle_fault(PIE_BASE, false, true).unwrap();
        assert_eq!(peek(&mut img.mm, PIE_BASE + 0x100, 4), b"TEXT");
        assert_eq!(peek(&mut img.mm, PIE_BASE, 4), b"\x7fELF");
    });
}

#[test]
fn bss_is_zero_including_the_tail_of_the_last_file_page() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        let data = PIE_BASE + 0x2000;
        img.mm.prefault(data, 0x3000, false).unwrap();
        assert_eq!(peek(&mut img.mm, data, 0x80), vec![0xDD; 0x80], "initialised data");
        let tail = peek(&mut img.mm, data + 0x80, (P - 0x80) as usize);
        assert!(tail.iter().all(|&b| b == 0), "file bytes after p_filesz must read as zero");
        assert!(peek(&mut img.mm, data + P, (2 * P) as usize).iter().all(|&b| b == 0));
    });
}

#[test]
fn brk_starts_after_the_image() {
    isolated(|| {
        let img = exec(static_pie().bytes, &["app"], &[]);
        assert_eq!((img.mm.brk_start, img.mm.brk), (PIE_BASE + 0x5000, PIE_BASE + 0x5000));
    });
}

#[test]
fn fixed_address_executable_in_the_low_window() {
    isolated(|| {
        let exe = Elf::new(ET_EXEC, 0x40_0100, &[load_with(PF_R | PF_X, 0, 0x40_0000, 0x200, 0x200)], 0x200);
        let mut img = exec(exe.bytes, &["app"], &[]);
        assert_eq!(img.entry, 0x40_0100, "no bias for ET_EXEC");
        let s = stack(&mut img);
        assert_eq!(aux(&s, AT_PHDR), 0x40_0040, "program headers found through the segment that maps them");
        assert_eq!(aux(&s, AT_BASE), 0);
    });
}

#[test]
fn kernel_addresses_are_refused() {
    isolated(|| {
        let exe = Elf::new(ET_EXEC, 0xFFFF_8000_0000_0100, &[load(0, 0xFFFF_8000_0000_0000, 0x100, 0x100)], 0x100);
        assert!(!is_vm_loadable(&exe.bytes));
        let r = load_linux_exec(src(exe.bytes), "/x", &[], &[], USER, &no_files);
        assert_eq!(r.err(), Some(ElfError::AllocationFailed));
    });
}

#[test]
fn is_vm_loadable_classification() {
    assert!(is_vm_loadable(&static_pie().bytes));
    let low = Elf::new(ET_EXEC, 0x40_0000, &[load(0, 0x40_0000, 0x100, 0x100)], 0x100);
    assert!(is_vm_loadable(&low.bytes));
    assert!(!is_vm_loadable(b"#!/bin/sh\n"));
}

#[test]
fn malformed_executables() {
    isolated(|| {
        let r = |b: Vec<u8>| load_linux_exec(src(b), "/x", &[], &[], USER, &no_files).err();
        assert_eq!(r(b"\x7fELF".to_vec()), Some(ElfError::BufferTooSmall));
        let no_load = Elf::new(ET_DYN, 0, &[Ph { ty: PT_PHDR, flags: 4, offset: 64, vaddr: 64, filesz: 56, memsz: 56 }], 0x100);
        assert_eq!(r(no_load.bytes), Some(ElfError::NoLoadableSegments));
        let past_eof = Elf::new(ET_DYN, 0, &[load(0x100, 0, 0x1000, 0x1000)], 0x200);
        assert_eq!(r(past_eof.bytes), Some(ElfError::SegmentOutOfBounds));
    });
}

#[test]
#[ignore = "BUG: map_elf computes p_vaddr + p_memsz and PIE_BASE - min_vaddr unchecked; a \
            crafted PT_LOAD near 2^64 overflows. Debug kernels panic; release kernels accept the \
            file and map it at a wrapped bias instead of rejecting it (src/task/exec.rs, map_elf)"]
fn crafted_huge_vaddr_fails_cleanly() {
    isolated(|| {
        let exe = Elf::new(ET_DYN, 0, &[load(0, u64::MAX - 0x100, 0x100, 0x1000)], 0x200);
        let r = std::panic::catch_unwind(|| load_linux_exec(src(exe.bytes), "/x", &[], &[], USER, &no_files).err());
        assert!(matches!(r, Ok(Some(_))), "expected an ElfError, not a panic or success");
    });
}

#[test]
#[ignore = "BUG (low): map_elf accepts p_filesz > p_memsz, which Linux rejects with EINVAL, and \
            maps the extra file pages past the segment's declared size (src/task/exec.rs, map_elf)"]
fn segment_with_filesz_above_memsz_is_rejected() {
    // Linux: p_filesz > p_memsz is -EINVAL.
    isolated(|| {
        let exe = Elf::new(ET_DYN, 0, &[load_with(PF_R | PF_W, 0, 0, 0x2000, 0x1000)], 0x2000);
        let r = std::panic::catch_unwind(|| load_linux_exec(src(exe.bytes), "/x", &[], &[], USER, &no_files).err());
        assert!(matches!(r, Ok(Some(_))), "expected an ElfError");
    });
}

// ------------------------------------------------------------------ stack

#[test]
fn stack_area_is_8_mib_read_write_and_named() {
    isolated(|| {
        let img = exec(static_pie().bytes, &["app"], &[]);
        let v = img.mm.find_vma(STACK_TOP - 1).unwrap();
        assert_eq!((v.start, v.end), (STACK_TOP - STACK_SIZE, STACK_TOP));
        assert_eq!(v.prot, PROT_READ | PROT_WRITE, "PT_GNU_STACK without PF_X: no exec");
        assert_eq!(v.name.as_deref(), Some("[stack]"));
        assert!(img.rsp < STACK_TOP && img.rsp > STACK_TOP - P, "initial frame sits in the top page");
    });
}

#[test]
fn executable_stack_when_requested() {
    isolated(|| {
        let exe = Elf::new(
            ET_DYN,
            0,
            &[load(0, 0, 0x100, 0x100), Ph { ty: PT_GNU_STACK, flags: PF_R | PF_W | PF_X, offset: 0, vaddr: 0, filesz: 0, memsz: 0 }],
            0x100,
        );
        let img = exec(exe.bytes, &[], &[]);
        assert_ne!(img.mm.find_vma(STACK_TOP - 1).unwrap().prot & PROT_EXEC, 0);
    });
}

#[test]
fn initial_stack_layout() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app", "-v", ""], &["HOME=/root", "LANG=C.UTF-8"]);
        assert_eq!(img.rsp % 16, 0, "ABI: rsp 16-byte aligned at entry, argc at rsp");
        let s = stack(&mut img);
        assert_eq!(s.argv, vec!["app", "-v", ""]);
        assert_eq!(s.envp, vec!["HOME=/root", "LANG=C.UTF-8"], "exactly the caller's environment");
        assert_eq!(s.auxv.last(), Some(&(AT_NULL, 0)));
    });
}

#[test]
fn auxiliary_vector() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        let s = stack(&mut img);
        assert_eq!(aux(&s, AT_PAGESZ), 4096);
        assert_eq!(aux(&s, AT_CLKTCK), 100);
        assert_eq!(aux(&s, AT_PHENT), 56);
        assert_eq!(aux(&s, AT_PHNUM), 3);
        assert_eq!(aux(&s, AT_PHDR), PIE_BASE + 64);
        assert_eq!(aux(&s, AT_ENTRY), PIE_BASE + 0x100);
        assert_eq!(aux(&s, AT_BASE), 0, "static: no interpreter");
        assert_eq!((aux(&s, AT_UID), aux(&s, AT_EUID), aux(&s, AT_GID), aux(&s, AT_EGID)), (1000, 1000, 1000, 1000));
        assert_eq!(aux(&s, AT_SECURE), 0);
        assert_ne!(aux(&s, AT_HWCAP) & (1 << 25), 0, "CPUID.1:EDX (SSE) reported");
        let execfn = aux(&s, AT_EXECFN);
        assert_eq!(cstr(&mut img.mm, execfn), "/usr/bin/app");
        let platform = aux(&s, AT_PLATFORM);
        assert_eq!(cstr(&mut img.mm, platform), "x86_64");
        let random = aux(&s, AT_RANDOM);
        assert!(random > img.rsp && random + 16 <= STACK_TOP, "AT_RANDOM bytes live on the stack");
        let bytes = peek(&mut img.mm, random, 16);
        assert!(bytes.iter().any(|&b| b != bytes[0]), "16 random bytes, not a constant fill");
    });
}

#[test]
fn auxv_is_saved_for_proc_self_auxv() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        let s = stack(&mut img);
        let mut expected = Vec::new();
        for (k, v) in &s.auxv {
            expected.extend_from_slice(&k.to_le_bytes());
            expected.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(img.mm.auxv, expected);
    });
}

#[test]
fn secure_mode_for_set_id_programs() {
    isolated(|| {
        let cases = [
            (ExecCreds { euid: 0, ..USER }, 1),
            (ExecCreds { egid: 0, ..USER }, 1),
            (ExecCreds { secure: true, ..USER }, 1),
            (USER, 0),
        ];
        for (creds, want) in cases {
            let mut img = load_linux_exec(src(static_pie().bytes), "/x", &["x"], &[], creds, &no_files).unwrap();
            assert_eq!(aux(&stack(&mut img), AT_SECURE), want);
            assert_eq!(aux(&stack(&mut img), AT_EUID), creds.euid as u64);
        }
    });
}

#[test]
fn stack_alignment_for_any_number_of_strings() {
    isolated(|| {
        for n in 0..7 {
            let args: Vec<String> = (0..n).map(|i| "a".repeat(i * 5 + 1)).collect();
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut img = exec(static_pie().bytes, &refs, &refs[..n / 2]);
            assert_eq!(img.rsp % 16, 0, "{n} arguments");
            assert_eq!(stack(&mut img).argv, args);
        }
    });
}

#[test]
fn large_environment() {
    isolated(|| {
        let env: Vec<String> = (0..500).map(|i| format!("VAR_{i}={}", "x".repeat(i % 40))).collect();
        let refs: Vec<&str> = env.iter().map(String::as_str).collect();
        let mut img = exec(static_pie().bytes, &["app"], &refs);
        assert_eq!(stack(&mut img).envp, env, "spills over several stack pages");
    });
}

// ----------------------------------------------------------- interpreter

#[test]
fn dynamic_executable_starts_in_the_interpreter() {
    isolated(|| {
        let ld = ld_so();
        let read = |p: &str| (p == INTERP).then(|| src(ld.clone()));
        let mut img = load_linux_exec(src(dynamic_pie().bytes), "/usr/bin/app", &["app"], &[], USER, &read).unwrap();
        let s = stack(&mut img);
        let base = aux(&s, AT_BASE);
        assert_ne!(base, 0);
        assert_eq!(base % P, 0);
        assert!(base < MMAP_TOP && base >= USER_SPACE_START, "placed by the mmap allocator");
        assert_eq!(img.entry, base + 0x400, "process starts in ld.so");
        assert_eq!(aux(&s, AT_ENTRY), PIE_BASE + 0x200, "ld.so learns where the program starts");
        assert_eq!(aux(&s, AT_PHDR), PIE_BASE + 64, "from PT_PHDR");
        assert_eq!(aux(&s, AT_PHNUM), 3, "the program's headers, not ld.so's");
        img.mm.handle_fault(base + 0x400, false, true).unwrap();
        assert_eq!(peek(&mut img.mm, base + 0x400, 4), b"LDSO");
        let ld_vma = img.mm.find_vma(base).unwrap();
        assert_eq!(ld_vma.name.as_deref(), Some(INTERP));
        assert_eq!(img.mm.find_vma(base + P).unwrap().prot, PROT_READ | PROT_EXEC, "ld.so .bss part of its span");
    });
}

#[test]
fn interpreter_path_is_looked_up_verbatim() {
    isolated(|| {
        let mut asked = std::cell::RefCell::new(Vec::new());
        let read = |p: &str| {
            asked.borrow_mut().push(p.to_string());
            None
        };
        let r = load_linux_exec(src(dynamic_pie().bytes), "/x", &[], &[], USER, &read);
        assert_eq!(r.err(), Some(ElfError::InterpreterNotFound));
        assert_eq!(asked.get_mut().as_slice(), [INTERP.to_string()]);
    });
}

#[test]
fn broken_interpreter_is_an_error() {
    isolated(|| {
        // Long enough to pass the size check, so the magic is what fails.
        let read = |_: &str| Some(src([&b"#!/bin/sh\n"[..], &[b' '; 100]].concat()));
        let r = load_linux_exec(src(dynamic_pie().bytes), "/x", &[], &[], USER, &read);
        assert_eq!(r.err(), Some(ElfError::InvalidMagic));
    });
}

// ------------------------------------------------------------ ElfSource

#[test]
fn elf_source_keeps_a_64k_head() {
    isolated(|| {
        let big = src(vec![1u8; 100_000]);
        assert_eq!((big.head.len(), big.len), (65_536, 100_000));
        let small = src(vec![2u8; 10]);
        assert_eq!((small.head.len(), small.len), (10, 10));
    });
}

#[test]
fn program_headers_beyond_the_64k_head_are_not_seen() {
    // The loader parses only the first 64 KiB, as Linux reads only the first page or so:
    // a valid file whose program headers sit past the head is reported, not misread.
    isolated(|| {
        let mut exe = static_pie().bytes;
        exe.resize(70_000, 0);
        let headers = exe[64..64 + 3 * 56].to_vec();
        exe[66_000..66_000 + headers.len()].copy_from_slice(&headers);
        exe[32..40].copy_from_slice(&66_000u64.to_le_bytes());
        let r = load_linux_exec(src(exe), "/x", &[], &[], USER, &no_files);
        assert_eq!(r.err(), Some(ElfError::ProgramHeaderOutOfBounds));
    });
}

// ------------------------------------------------------------------ vDSO

#[test]
fn the_vdso_is_mapped_and_announced_in_the_auxiliary_vector() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        let vdso = aux(&stack(&mut img), AT_SYSINFO_EHDR);
        assert!(vdso >= USER_SPACE_START && vdso < MMAP_TOP, "{vdso:#x}");
        let code = img.mm.find_vma(vdso).unwrap();
        assert_eq!((code.prot, code.shared, code.name.as_deref()), (PROT_READ | PROT_EXEC, true, Some("[vdso]")));
        let vvar = img.mm.find_vma(vdso - P).unwrap();
        assert_eq!((vvar.prot, vvar.name.as_deref()), (PROT_READ, Some("[vvar]")), "the data page just below");
        img.mm.prefault(vdso, P, false).unwrap();
        assert_eq!(peek(&mut img.mm, vdso, 4), b"\x7fELF", "AT_SYSINFO_EHDR points at the vDSO's ELF header");
    });
}

#[test]
fn the_vvar_page_carries_the_clock() {
    isolated(|| {
        let mut img = exec(static_pie().bytes, &["app"], &[]);
        let vdso = aux(&stack(&mut img), AT_SYSINFO_EHDR);
        img.mm.prefault(vdso - P, P, false).unwrap();
        let vvar = peek(&mut img.mm, vdso - P, 48);
        let word = |i: usize| u64::from_le_bytes(vvar[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(word(0) % 2, 0, "sequence count even: not in the middle of an update");
        assert_eq!(word(5) as i64, 1_767_225_600 * 1_000_000_000, "wall_ns: the clock's boot time");
    });
}

#[test]
fn every_process_shares_one_copy_of_the_vdso() {
    isolated(|| {
        let mut a = exec(static_pie().bytes, &["a"], &[]);
        let mut b = exec(static_pie().bytes, &["b"], &[]);
        let (va, vb) = (aux(&stack(&mut a), AT_SYSINFO_EHDR), aux(&stack(&mut b), AT_SYSINFO_EHDR));
        a.mm.prefault(va, P, false).unwrap();
        b.mm.prefault(vb, P, false).unwrap();
        assert_eq!(a.mm.translate(va), b.mm.translate(vb), "same physical page");
    });
}

#[test]
#[ignore = "BUG (security): the vDSO is mapped MAP_SHARED, and mprotect may add PROT_WRITE to \
            shared mappings, so one process can rewrite the vDSO code (and the [vvar] clock page) \
            that every process on the system runs, root's included. Linux maps the vDSO \
            privately (a write gets a private copy) and refuses PROT_WRITE on [vvar] \
            (src/arch/vdso.rs, map; src/memory/vm.rs, Mm::mprotect)"]
fn one_process_cannot_change_another_processs_vdso() {
    isolated(|| {
        let mut a = exec(static_pie().bytes, &["attacker"], &[]);
        let mut b = exec(static_pie().bytes, &["victim"], &[]);
        let (va, vb) = (aux(&stack(&mut a), AT_SYSINFO_EHDR), aux(&stack(&mut b), AT_SYSINFO_EHDR));
        b.mm.prefault(vb, P, false).unwrap();
        let original = peek(&mut b.mm, vb + 0x100, 4);
        let patched = a.mm.mprotect(va, P, PROT_READ | PROT_WRITE | PROT_EXEC).is_ok() && a.mm.write_bytes(va + 0x100, &[0xCC; 4]).is_ok();
        let seen = peek(&mut b.mm, vb + 0x100, 4);
        if patched {
            let _ = a.mm.write_bytes(va + 0x100, &original); // undo, for the other tests in this binary
        }
        assert_eq!(seen, original, "the attacker's write reached the victim's vDSO code");
    });
}
