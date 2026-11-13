//! Tests for the ELF64 parser and loaders in `src/task/elf.rs`.
//!
//! Binaries are assembled in memory by `common::elf::Elf`. Position-independent images
//! load into heap buffers and run as-is on the host. Fixed-address (ET_EXEC)
//! images are linked at an address inside a test [`Arena`], so the loader's
//! raw writes land in memory this process owns. Paging calls go to the fake
//! `make_user_accessible`, which records the ranges; the interpreter lookup
//! reads from the fake ZFS and boot volumes.

mod common;

use common::elf::*;
use common::{Arena, GIB};
use hydra_hosttests::compat::linux::types::*;
use hydra_hosttests::fake;
use hydra_hosttests::task::elf::{load_elf, load_linux_elf, ElfBinary, ElfError, ElfProcessImage};

const STACK: usize = 65536;

/// A typical PIE: text (with headers) at 0, data + bss at 0x3000.
fn pie() -> Elf {
    Elf::new(ET_DYN, 0x100, &[load(0, 0, 0x1000, 0x1000), load(0x2000, 0x3000, 0x100, 0x2000)], 0x2100)
        .put(0x100, b"CODE")
        .put(0x2000, b"DATA")
}

const INTERP: &str = "/lib64/ld-linux-x86-64.so.2";

/// PIE that asks for a dynamic linker.
fn dynamic_pie() -> Elf {
    let mut path = INTERP.as_bytes().to_vec();
    path.push(0);
    Elf::new(
        ET_DYN,
        0x200,
        &[
            Ph { flags: 4, ty: PT_PHDR, offset: 64, vaddr: 64, filesz: 56 * 3, memsz: 56 * 3 },
            Ph { flags: 4, ty: PT_INTERP, offset: 0x800, vaddr: 0x800, filesz: path.len() as u64, memsz: path.len() as u64 },
            load(0, 0, 0x1000, 0x1000),
        ],
        0x1000,
    )
    .put(0x800, &path)
}

/// Minimal dynamic linker image: entry at 0x400.
fn ld_so() -> Vec<u8> {
    Elf::new(ET_DYN, 0x400, &[load(0, 0, 0x800, 0x1000)], 0x800).put(0x400, b"LDSO").bytes
}

fn image(img: &ElfProcessImage) -> &[u8] {
    img.allocated_image.as_deref().expect("PIE images are heap-allocated")
}

fn user_ranges() -> Vec<(u64, usize)> {
    fake::USER_RANGES.with_borrow(|v| v.clone())
}

// ---------------------------------------------------------------- parsing

#[test]
fn parse_rejects_malformed_headers() {
    let good = pie().bytes;
    assert_eq!(ElfBinary::parse(&good[..63]).err(), Some(ElfError::BufferTooSmall));

    let cases: [(usize, u8, ElfError); 5] = [
        (0, 0x7E, ElfError::InvalidMagic),
        (4, 1, ElfError::Not64Bit),
        (5, 2, ElfError::NotLittleEndian),
        (18, 183, ElfError::UnsupportedMachine), // AArch64
        (16, 1, ElfError::UnsupportedType),      // ET_REL
    ];
    for (off, v, want) in cases {
        let mut b = good.clone();
        b[off] = v;
        assert_eq!(ElfBinary::parse(&b).err(), Some(want), "byte {off} = {v}");
    }
    let mut core = good.clone();
    core[16] = 4; // ET_CORE
    assert_eq!(ElfBinary::parse(&core).err(), Some(ElfError::UnsupportedType));
}

#[test]
fn parse_checks_program_header_table_bounds() {
    let mut b = pie().bytes;
    b[56..58].copy_from_slice(&1000u16.to_le_bytes());
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::ProgramHeaderOutOfBounds));
    let mut b = pie().bytes;
    b[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::ProgramHeaderOutOfBounds), "no overflow");
}

#[test]
#[ignore = "BUG: parse accepts any e_phentsize; Linux rejects anything but sizeof(Elf64_Phdr)=56. \
            With a smaller value the iterator reads overlapping, misaligned headers (src/task/elf.rs)"]
fn parse_rejects_wrong_phentsize() {
    let b = pie().put(54, &32u16.to_le_bytes()).bytes;
    assert!(ElfBinary::parse(&b).is_err());
}

#[test]
fn accessors() {
    let b = pie().bytes;
    let e = ElfBinary::parse(&b).unwrap();
    assert_eq!(e.entry_point(), 0x100);
    assert!(e.is_pie());
    assert_eq!(e.header().e_phnum, 2);
    let segs = e.load_segments();
    assert_eq!(segs.len(), 2);
    assert_eq!((segs[1].p_offset, segs[1].p_vaddr, segs[1].p_filesz, segs[1].p_memsz), (0x2000, 0x3000, 0x100, 0x2000));
    assert_eq!(e.interp_path(), None);

    let exec = Elf::new(ET_EXEC, 0x401000, &[load(0, 0x400000, 0x100, 0x100)], 0x100).bytes;
    assert!(!ElfBinary::parse(&exec).unwrap().is_pie());
}

#[test]
fn program_header_iteration_filters_and_stops_safely() {
    let b = dynamic_pie().bytes;
    let e = ElfBinary::parse(&b).unwrap();
    let types: Vec<u32> = e.program_headers().map(|p| p.p_type).collect();
    assert_eq!(types, vec![PT_PHDR, PT_INTERP, PT_LOAD]);
    assert_eq!(e.load_segments().len(), 1);
}

#[test]
fn interp_path_is_read_up_to_the_nul() {
    let b = dynamic_pie().bytes;
    assert_eq!(ElfBinary::parse(&b).unwrap().interp_path(), Some(INTERP));
}

#[test]
fn interp_path_out_of_file_is_none() {
    let b = Elf::new(ET_DYN, 0, &[Ph { flags: 4, ty: PT_INTERP, offset: 0x5000, vaddr: 0, filesz: 10, memsz: 10 }], 0x200).bytes;
    assert_eq!(ElfBinary::parse(&b).unwrap().interp_path(), None);
    let clipped = Elf::new(ET_DYN, 0, &[Ph { flags: 4, ty: PT_INTERP, offset: 0x1F0, vaddr: 0, filesz: 100, memsz: 100 }], 0x200)
        .put(0x1F0, b"/lib/ld.so")
        .bytes;
    assert_eq!(ElfBinary::parse(&clipped).unwrap().interp_path(), Some("/lib/ld.so\0\0\0\0\0\0".trim_end_matches('\0')));
}

#[test]
fn interp_path_survives_huge_filesz() {
    let b = Elf::new(ET_DYN, 0, &[Ph { flags: 4, ty: PT_INTERP, offset: 0x100, vaddr: 0, filesz: u64::MAX - 0x80, memsz: 0 }], 0x200)
        .bytes;
    let r = std::panic::catch_unwind(|| ElfBinary::parse(&b).unwrap().interp_path().map(str::len));
    assert!(r.is_ok(), "interp_path panicked");
}

#[test]
fn error_messages_are_distinct() {
    let all = [
        ElfError::BufferTooSmall, ElfError::InvalidMagic, ElfError::Not64Bit, ElfError::NotLittleEndian,
        ElfError::UnsupportedMachine, ElfError::UnsupportedType, ElfError::ProgramHeaderOutOfBounds,
        ElfError::NoLoadableSegments, ElfError::SegmentOutOfBounds, ElfError::AllocationFailed,
        ElfError::InterpreterNotFound,
    ];
    let mut msgs: Vec<&str> = all.iter().map(ElfError::as_str).collect();
    assert!(msgs.iter().all(|m| !m.is_empty()));
    msgs.sort();
    msgs.dedup();
    assert_eq!(msgs.len(), all.len());
    assert_eq!(ElfError::PagingError("boom").as_str(), "boom");
}

// ---------------------------------------------------------- load_elf (PIE)

#[test]
fn load_elf_pie_lays_out_segments() {
    fake::reset();
    let img = load_elf(&pie().bytes).unwrap();
    // The image starts a page-aligned stretch into its buffer: find it from the entry point
    let buf = image(&img);
    let base = img.entry_point - 0x100;
    let start = (base - buf.as_ptr() as u64) as usize;
    assert!(buf.len() >= start + 0x5000, "span of all PT_LOAD segments, page-rounded, fits the buffer");
    let mem = &buf[start..start + 0x5000];
    assert_eq!(&mem[0..4], b"\x7fELF", "headers are part of the first segment");
    assert_eq!(&mem[0x100..0x104], b"CODE");
    assert_eq!(&mem[0x3000..0x3004], b"DATA");
    assert!(mem[0x3100..0x5000].iter().all(|&b| b == 0), "bss is zero");
    assert_eq!(img.entry_point, base + 0x100);
    assert_eq!(img.initial_brk, base + 0x5000);
    assert!(img.interp_image.is_none());
    assert!(user_ranges().contains(&(base, 0x5000)), "image mapped for ring 3");
}

#[test]
fn load_elf_sets_up_aligned_stacks() {
    fake::reset();
    let img = load_elf(&pie().bytes).unwrap();
    assert_eq!((img.user_stack.len(), img.kernel_stack.len()), (STACK, STACK));
    let bottom = img.user_stack.as_ptr() as u64;
    let top = (bottom + STACK as u64) & !0xF;
    assert_eq!(img.initial_user_rsp, top - 48);
    assert_eq!(img.initial_user_rsp % 16, 0);
    assert!(user_ranges().contains(&(bottom, STACK)), "user stack mapped for ring 3");
    assert!(!user_ranges().iter().any(|r| r.0 == img.kernel_stack.as_ptr() as u64), "kernel stack stays private");
}

#[test]
fn load_elf_pie_base_is_page_aligned() {
    fake::reset();
    let img = load_elf(&pie().bytes).unwrap();
    assert_eq!(img.entry_point % 0x1000, 0x100);
}

#[test]
fn load_elf_validates_segments() {
    fake::reset();
    let no_load = Elf::new(ET_DYN, 0, &[Ph { flags: 4, ty: PT_PHDR, offset: 64, vaddr: 64, filesz: 56, memsz: 56 }], 0x200);
    assert_eq!(load_elf(&no_load.bytes).err(), Some(ElfError::NoLoadableSegments));

    let past_eof = Elf::new(ET_DYN, 0, &[load(0x100, 0, 0x1000, 0x1000)], 0x200);
    assert_eq!(load_elf(&past_eof.bytes).err(), Some(ElfError::SegmentOutOfBounds));

    let overflow = Elf::new(ET_DYN, 0, &[load(u64::MAX, 0, 2, 2)], 0x200);
    assert_eq!(load_elf(&overflow.bytes).err(), Some(ElfError::SegmentOutOfBounds));
}

#[test]
fn load_elf_rejects_filesz_larger_than_memsz() {
    fake::reset();
    let bad = Elf::new(ET_DYN, 0, &[load(0, 0, 0x2000, 0x1000)], 0x2000);
    let r = std::panic::catch_unwind(|| load_elf(&bad.bytes).err());
    assert!(matches!(r, Ok(Some(_))), "expected an ElfError, not a panic or success");
}

#[test]
fn load_elf_propagates_paging_errors() {
    fake::reset();
    fake::PAGING_ERROR.set(Some("out of page tables"));
    assert_eq!(load_elf(&pie().bytes).err(), Some(ElfError::PagingError("out of page tables")));
}

// ----------------------------------------------------- load_elf (ET_EXEC)

#[test]
fn load_elf_exec_copies_to_link_address_and_clears_bss() {
    fake::reset();
    let arena = Arena::new(0);
    let base = arena.base;
    unsafe { std::ptr::write_bytes(base as *mut u8, 0xAA, 0x4000) }; // stale memory
    let exe = Elf::new(ET_EXEC, base + 0x100, &[load(0, base, 0x800, 0x3000)], 0x800).put(0x100, b"MAIN");
    let img = load_elf(&exe.bytes).unwrap();
    let mem = unsafe { std::slice::from_raw_parts(base as *const u8, 0x4000) };
    assert_eq!(&mem[0x100..0x104], b"MAIN");
    assert!(mem[0x800..0x3000].iter().all(|&b| b == 0), "bss cleared");
    assert!(mem[0x3000..0x4000].iter().all(|&b| b == 0xAA), "nothing written past memsz");
    assert_eq!(img.entry_point, base + 0x100);
    assert_eq!(img.initial_brk, base + 0x3000);
    assert!(img.allocated_image.is_none());
    assert!(user_ranges().contains(&(base, 0x3000)));
}

// --------------------------------------------------------- load_linux_elf

/// The SysV initial process stack, read back from the loaded image.
struct InitialStack {
    rsp: u64,
    argv: Vec<String>,
    envp: Vec<String>,
    auxv: Vec<(u64, u64)>,
}

unsafe fn cstr(addr: u64) -> String {
    std::ffi::CStr::from_ptr(addr as *const std::ffi::c_char).to_str().unwrap().to_owned()
}

fn read_stack(img: &ElfProcessImage) -> InitialStack {
    let lo = img.user_stack.as_ptr() as u64;
    let hi = lo + img.user_stack.len() as u64;
    let rsp = img.initial_user_rsp;
    assert!(rsp >= lo && rsp < hi, "rsp outside the user stack");
    let word = |i: u64| unsafe { *((rsp + 8 * i) as *const u64) };
    let argc = word(0);
    let mut i = 1;
    let argv: Vec<String> = (0..argc).map(|k| unsafe { cstr(word(1 + k)) }).collect();
    i += argc;
    assert_eq!(word(i), 0, "argv terminator");
    i += 1;
    let mut envp = Vec::new();
    while word(i) != 0 {
        envp.push(unsafe { cstr(word(i)) });
        i += 1;
    }
    i += 1;
    let mut auxv = Vec::new();
    loop {
        let (k, v) = (word(i), word(i + 1));
        auxv.push((k, v));
        i += 2;
        if k == AT_NULL {
            break;
        }
    }
    InitialStack { rsp, argv, envp, auxv }
}

fn aux(s: &InitialStack, key: u64) -> u64 {
    s.auxv.iter().find(|(k, _)| *k == key).unwrap_or_else(|| panic!("auxv {key} missing")).1
}

#[test]
fn linux_stack_has_argv_envp_and_auxv() {
    fake::reset();
    let img = load_linux_elf(&pie().bytes, &["/bin/app", "--flag", ""]).unwrap();
    let s = read_stack(&img);
    assert_eq!(s.rsp % 16, 0, "ABI: rsp is 16-byte aligned at process entry");
    assert_eq!(s.argv, vec!["/bin/app", "--flag", ""]);
    assert!(s.envp.contains(&"PATH=/bin:/usr/bin".to_string()));
    assert!(s.envp.iter().all(|e| e.contains('=')));
    assert_eq!(s.auxv.last(), Some(&(AT_NULL, 0)));
    assert_eq!(aux(&s, AT_PAGESZ), 4096);
    assert_eq!(aux(&s, AT_PHENT), 56);
    assert_eq!(aux(&s, AT_PHNUM), 2);
    assert_eq!(aux(&s, AT_BASE), 0, "no interpreter");
    assert_eq!(aux(&s, AT_ENTRY), img.entry_point);
    assert_eq!((aux(&s, AT_UID), aux(&s, AT_EUID), aux(&s, AT_GID), aux(&s, AT_EGID)), (1000, 1000, 1000, 1000));
    assert_eq!(aux(&s, AT_SECURE), 0);
}

#[test]
fn linux_stack_alignment_holds_for_any_argument_count() {
    for n in 0..6 {
        fake::reset();
        let args: Vec<String> = (0..n).map(|i| "x".repeat(i * 3 + 1)).collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let img = load_linux_elf(&pie().bytes, &refs).unwrap();
        let s = read_stack(&img);
        assert_eq!(s.rsp % 16, 0, "{n} args");
        assert_eq!(s.argv, args);
    }
}

#[test]
fn linux_at_random_points_at_16_bytes_on_the_stack() {
    fake::reset();
    let img = load_linux_elf(&pie().bytes, &["a"]).unwrap();
    let s = read_stack(&img);
    let r = aux(&s, AT_RANDOM);
    let lo = img.user_stack.as_ptr() as u64;
    assert!(r >= s.rsp && r + 16 <= lo + img.user_stack.len() as u64);
}

#[test]
fn linux_pie_image_is_page_aligned_and_at_phdr_points_at_headers() {
    fake::reset();
    let elf = pie();
    let img = load_linux_elf(&elf.bytes, &["a"]).unwrap();
    let s = read_stack(&img);
    assert_eq!(img.entry_point % 0x1000, 0x100, "base is page-aligned");
    let base = img.entry_point - 0x100;
    assert_eq!(img.initial_brk, base + 0x5000);
    let phdr = aux(&s, AT_PHDR);
    assert_eq!(phdr, base + 64);
    let mapped = unsafe { std::slice::from_raw_parts(phdr as *const u8, 2 * 56) };
    assert_eq!(mapped, &elf.bytes[64..64 + 2 * 56], "AT_PHDR addresses the loaded program headers");
}

#[test]
#[ignore = "BUG: for fixed-address (ET_EXEC) binaries load_linux_elf passes the file offset \
            e_phoff as AT_PHDR instead of the headers' virtual address, so libc finds no \
            PT_TLS/PT_DYNAMIC (src/task/elf.rs, load_linux_elf)"]
fn linux_exec_at_phdr_is_a_virtual_address() {
    fake::reset();
    let arena = Arena::new(1);
    let base = arena.base;
    let exe = Elf::new(ET_EXEC, base + 0x100, &[load(0, base, 0x800, 0x1000)], 0x800);
    let img = load_linux_elf(&exe.bytes, &["a"]).unwrap();
    assert_eq!(aux(&read_stack(&img), AT_PHDR), base + 64);
}

#[test]
fn linux_loads_the_interpreter_and_starts_there() {
    fake::reset();
    fake::ZFS_FILES.with_borrow_mut(|m| m.insert(INTERP.into(), ld_so()));
    let img = load_linux_elf(&dynamic_pie().bytes, &["app"]).unwrap();
    let s = read_stack(&img);
    let ld = img.interp_image.as_deref().expect("interpreter loaded");
    let ld_base = aux(&s, AT_BASE);
    assert_eq!(ld_base % 0x1000, 0, "interpreter base is page-aligned");
    assert!(ld_base >= ld.as_ptr() as u64 && ld_base < ld.as_ptr() as u64 + ld.len() as u64);
    assert_eq!(img.entry_point, ld_base + 0x400, "process starts in ld.so");
    let app_base = image(&img).as_ptr() as u64;
    assert_eq!(aux(&s, AT_ENTRY) % 0x1000, 0x200, "ld.so learns the app entry");
    assert!(aux(&s, AT_ENTRY) > app_base);
    assert_eq!(unsafe { std::slice::from_raw_parts((ld_base + 0x400) as *const u8, 4) }, b"LDSO");
    assert_eq!(aux(&s, AT_PHNUM), 3);
}

#[test]
fn linux_interpreter_search_order() {
    // Exact path missing: falls back to /bin, /lib, /lib64 by file name, then
    // Hydra's own linker, then the FAT boot volume.
    let fallbacks = [
        ("zfs", "/lib/ld-linux-x86-64.so.2"),
        ("zfs", "/bin/ld-linux-x86-64.so.2"),
        ("zfs", "/bin/ld-hydra.so"),
        ("boot", "\\lib64\\ld-linux-x86-64.so.2"),
        ("boot", "\\bin\\ld-hydra.so"),
    ];
    for (vol, path) in fallbacks {
        fake::reset();
        let map = if vol == "zfs" { &fake::ZFS_FILES } else { &fake::BOOT_FILES };
        map.with_borrow_mut(|m| m.insert(path.into(), ld_so()));
        let img = load_linux_elf(&dynamic_pie().bytes, &["app"]);
        assert!(img.is_ok(), "interpreter at {vol}:{path} not found");
        assert!(img.unwrap().interp_image.is_some());
    }
}

#[test]
fn linux_missing_or_broken_interpreter() {
    fake::reset();
    assert_eq!(load_linux_elf(&dynamic_pie().bytes, &["app"]).err(), Some(ElfError::InterpreterNotFound));

    fake::ZFS_FILES.with_borrow_mut(|m| m.insert(INTERP.into(), b"#!/bin/sh\n".to_vec()));
    assert_eq!(load_linux_elf(&dynamic_pie().bytes, &["app"]).err(), Some(ElfError::BufferTooSmall));

    let mut not_elf = ld_so();
    not_elf[0] = b'M';
    fake::ZFS_FILES.with_borrow_mut(|m| m.insert(INTERP.into(), not_elf));
    assert_eq!(load_linux_elf(&dynamic_pie().bytes, &["app"]).err(), Some(ElfError::InvalidMagic));
}

#[test]
fn linux_validates_like_load_elf() {
    fake::reset();
    let past_eof = Elf::new(ET_DYN, 0, &[load(0x100, 0, 0x1000, 0x1000)], 0x200);
    assert_eq!(load_linux_elf(&past_eof.bytes, &[]).err(), Some(ElfError::SegmentOutOfBounds));
    fake::PAGING_ERROR.set(Some("no memory"));
    assert_eq!(load_linux_elf(&pie().bytes, &[]).err(), Some(ElfError::PagingError("no memory")));
}

#[test]
fn arena_slots_do_not_collide_with_low_user_window() {
    // Sanity check on the test setup itself: arenas sit above LOW_USER_END.
    assert!(GIB >= hydra_hosttests::memory::vm::LOW_USER_END);
}
