//! Tests for the personality hook's pure tables (`src/personality/abi.rs`, wave 5): how a
//! program file's marking picks its system, the errno maps and the signal number maps.

mod common;

use common::elf::*;
use hydra_hosttests::personality::abi::*;

fn elf(osabi: u8) -> Vec<u8> {
    let mut b = Elf::new(ET_EXEC, 0x401000, &[load(0, 0x400000, 0x1000, 0x1000)], 0x1000).bytes;
    b[7] = osabi;
    b
}

/// An ELF with a PT_NOTE at 0x200 holding one note `name` of type `ty`.
fn elf_with_note(osabi: u8, name: &[u8], ty: u32) -> Vec<u8> {
    let mut note = Vec::new();
    note.extend_from_slice(&(name.len() as u32).to_le_bytes());
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&ty.to_le_bytes());
    note.extend_from_slice(name);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note.extend_from_slice(&1501000u32.to_le_bytes());
    let ph = Ph { ty: 4, flags: 4, offset: 0x200, vaddr: 0x400200, filesz: note.len() as u64, memsz: note.len() as u64 };
    let mut b = Elf::new(ET_EXEC, 0x401000, &[load(0, 0x400000, 0x1000, 0x1000), ph], 0x1000).put(0x200, &note).bytes;
    b[7] = osabi;
    b
}

#[test]
fn elf_marking_picks_the_system() {
    assert_eq!(classify(&elf(0)), Kind::Linux, "System V: Linux");
    assert_eq!(classify(&elf(3)), Kind::Linux, "GNU/Linux");
    assert_eq!(classify(&elf(9)), Kind::FreeBsd, "OS/ABI 9");
    assert_eq!(classify(&elf(2)), Kind::OtherOs(2), "NetBSD");
    assert_eq!(classify(&elf(6)), Kind::OtherOs(6), "Solaris");
    assert_eq!(classify(&elf(12)), Kind::OtherOs(12), "OpenBSD");
}

#[test]
fn freebsd_abi_note_without_the_byte() {
    assert_eq!(classify(&elf_with_note(0, b"FreeBSD\0", 1)), Kind::FreeBsd);
    assert_eq!(classify(&elf_with_note(0, b"FreeBSD\0", 4)), Kind::Linux, "another FreeBSD note type");
    assert_eq!(classify(&elf_with_note(0, b"GNU\0", 1)), Kind::Linux, "Linux's ABI note");
    assert_eq!(classify(&elf_with_note(3, b"FreeBSD\0", 1)), Kind::Linux, "only OS/ABI 0 looks at notes");
}

#[test]
fn mach_o_and_other_files() {
    assert_eq!(classify(&[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1]), Kind::MachO, "64-bit Mach-O");
    assert_eq!(classify(&[0xCE, 0xFA, 0xED, 0xFE, 7, 0, 0, 0]), Kind::MachO, "32-bit Mach-O");
    assert_eq!(classify(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]), Kind::MachO, "universal, 2 slices");
    assert_eq!(classify(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]), Kind::Linux, "a Java class file (version 52)");
    assert_eq!(classify(b"#!/bin/sh\n"), Kind::Linux, "scripts are the caller's business");
    assert_eq!(classify(b"MZ\x90\0"), Kind::Linux);
    assert_eq!(classify(&[]), Kind::Linux);
    assert_eq!(classify(b"\x7fELF"), Kind::Linux, "a truncated ELF header: the loader refuses it");
}

#[test]
fn errno_maps() {
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 9), 9, "EBADF is the same");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 11), 35, "EAGAIN");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 35), 11, "EDEADLK");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 38), 78, "ENOSYS");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 95), 45, "EOPNOTSUPP");
    assert_eq!(bsd_errno(&MACOS_ERRNO, 95), 102, "macOS EOPNOTSUPP (sockets)");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 512 + 93), 93, "BSD-only ENOTCAPABLE travels as 512 + n");
    assert_eq!(bsd_errno(&FREEBSD_ERRNO, 4000), 22, "unknown: EINVAL");
    for e in 1..134u64 {
        assert!(FREEBSD_ERRNO[e as usize] != 0 && MACOS_ERRNO[e as usize] != 0, "errno {e} mapped");
    }
}

#[test]
fn signal_maps_round_trip() {
    for s in 1..=64u32 {
        let f = internal_sig_to_freebsd(s);
        assert_eq!(freebsd_sig_to_internal(f as u64), Some(s), "internal {s} -> FreeBSD {f}");
    }
    assert_eq!(freebsd_sig_to_internal(30), Some(10), "SIGUSR1");
    assert_eq!(freebsd_sig_to_internal(31), Some(12), "SIGUSR2");
    assert_eq!(freebsd_sig_to_internal(20), Some(17), "SIGCHLD");
    assert_eq!(freebsd_sig_to_internal(29), Some(30), "SIGINFO arrives as SIGPWR");
    assert_eq!(freebsd_sig_to_internal(12), Some(31), "SIGSYS");
    assert_eq!(freebsd_sig_to_internal(65), Some(34), "SIGRTMIN");
    assert_eq!(freebsd_sig_to_internal(96), None, "FreeBSD's real-time signals past Linux's are refused");
    assert_eq!(freebsd_sig_to_internal(34), None);
    assert_eq!(freebsd_sig_to_internal(0), None);
}
