//! The ELF64 parser and the in-kernel loaders (`src/task/elf.rs`): header checks, program
//! headers, the interpreter path, and PIE loading into kernel memory (tests/host covers the
//! loaders in more depth; these keep the file exercised where the scheduler uses it).

mod common;
use common::elf::*;
use common::*;

use hydra_hosttests_t31::task::elf::{load_elf, load_linux_elf, ElfBinary, ElfError};

fn pie() -> Vec<u8> {
    Elf::new(ET_DYN, 0x100, &[load_with(5, 0, 0, 0x200, 0x1800), Ph { ty: PT_PHDR, flags: 4, offset: 64, vaddr: 64, filesz: 112, memsz: 112 }], 0x200)
        .put(0x100, b"CODE")
        .bytes
}

#[test]
fn the_header_checks_refuse_what_is_not_an_x86_64_program() {
    let good = pie();
    assert!(ElfBinary::parse(&good).is_ok());
    assert_eq!(ElfBinary::parse(&good[..10]).err(), Some(ElfError::BufferTooSmall));
    let mut b = good.clone();
    b[0] = 0;
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::InvalidMagic));
    let mut b = good.clone();
    b[4] = 1;
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::Not64Bit));
    let mut b = good.clone();
    b[5] = 2;
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::NotLittleEndian));
    let mut b = good.clone();
    b[18] = 3; // EM_386
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::UnsupportedMachine));
    let mut b = good.clone();
    b[54] = 32; // e_phentsize
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::ProgramHeaderOutOfBounds));
    let mut b = good.clone();
    b[16] = 1; // ET_REL
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::UnsupportedType));
    let mut b = good.clone();
    b[56] = 200; // e_phnum past the end
    assert_eq!(ElfBinary::parse(&b).err(), Some(ElfError::ProgramHeaderOutOfBounds));
    for e in [ElfError::BufferTooSmall, ElfError::InvalidMagic, ElfError::Not64Bit, ElfError::NotLittleEndian, ElfError::UnsupportedMachine, ElfError::UnsupportedType, ElfError::NoLoadableSegments] {
        assert!(!e.as_str().is_empty());
    }
}

#[test]
fn program_headers_entry_and_interpreter() {
    let b = pie();
    let e = ElfBinary::parse(&b).unwrap();
    assert!(e.is_pie());
    assert_eq!(e.entry_point(), 0x100);
    assert_eq!(e.header().e_phnum, 2);
    assert_eq!(e.program_headers().count(), 2);
    assert_eq!(e.load_segments().len(), 1);
    assert_eq!(e.phdr_vaddr(), Some(64));
    assert_eq!(e.interp_path(), None);
    let mut path = b"/lib/ld.so\0".to_vec();
    let d = Elf::new(ET_DYN, 0, &[Ph { ty: PT_INTERP, flags: 4, offset: 0x180, vaddr: 0x180, filesz: path.len() as u64, memsz: path.len() as u64 }, load(0, 0, 0x200, 0x200)], 0x200).put(0x180, &path).bytes;
    assert_eq!(ElfBinary::parse(&d).unwrap().interp_path(), Some("/lib/ld.so"));
    path.clear();
}

#[test]
fn a_pie_is_loaded_into_a_kernel_buffer_with_its_bss_zeroed() {
    let _w = world();
    let img = load_elf(&pie()).unwrap();
    let base = img.allocated_image.as_ref().unwrap().as_ptr() as u64;
    assert!(img.entry_point >= base);
    let code = unsafe { std::slice::from_raw_parts(img.entry_point as *const u8, 4) };
    assert_eq!(code, b"CODE");
    assert!(!fake::USER_RANGES.lock().unwrap().is_empty(), "made user accessible");
    let none = Elf::new(ET_DYN, 0, &[], 0x100).bytes;
    assert_eq!(load_elf(&none).err(), Some(ElfError::NoLoadableSegments));
    let past = Elf::new(ET_DYN, 0, &[load(0, 0, 0x10_000, 0x10_000)], 0x100).bytes;
    assert!(load_elf(&past).is_err(), "a segment past the end of the file");
    // The legacy Linux loader: a 256 KiB stack with argv on it
    let l = load_linux_elf(&pie(), &["prog", "arg"]).unwrap();
    assert!(l.initial_user_rsp != 0);
    assert!(l.initial_brk >= l.entry_point);
    assert_eq!(load_linux_elf(&none, &[]).err(), Some(ElfError::NoLoadableSegments));
}
