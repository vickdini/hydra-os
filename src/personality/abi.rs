//! # Personalities: the pure tables (wave 5, the personality hook)
//!
//! What tells programs of different systems apart, and the number maps between them, with
//! no kernel state, so the host unit tests compile this file as it is
//! (`docs/personality-design.md`, sections 2.2, 2.4 and 2.5):
//!
//! - [`classify`]: which system a program file was built for, from its first bytes (the ELF
//!   OS/ABI byte, the "FreeBSD" ABI note, the Mach-O magic).
//! - [`FREEBSD_ERRNO`], [`MACOS_ERRNO`]: internal (Linux) errno to the personality's errno
//!   (generated from `docs/personality-errno.md`).
//! - [`freebsd_sig_to_internal`], [`internal_sig_to_freebsd`]: signal numbers (the kernel
//!   numbers signals as Linux does).

/// What a program file is, as far as choosing a personality goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// An ELF file for Linux (OS/ABI 0 without a FreeBSD note, or 3 "GNU/Linux"), or
    /// anything that is not ELF or Mach-O (scripts, garbage: the caller decides).
    Linux,
    /// An ELF file for FreeBSD (OS/ABI 9, or the "FreeBSD" ABI note).
    FreeBsd,
    /// A Mach-O file (64-bit, 32-bit or universal).
    MachO,
    /// An ELF file whose OS/ABI byte names another system (NetBSD 2, Solaris 6, OpenBSD 12...).
    OtherOs(u8),
}

/// ELF OS/ABI byte: System V (what most Linux programs carry).
pub const ELFOSABI_NONE: u8 = 0;
/// ELF OS/ABI byte: GNU/Linux (programs using GNU extensions such as IFUNC).
pub const ELFOSABI_GNU: u8 = 3;
/// ELF OS/ABI byte: FreeBSD.
pub const ELFOSABI_FREEBSD: u8 = 9;
/// The FreeBSD ABI note's type (`NT_FREEBSD_ABI_TAG`).
const NT_FREEBSD_ABI_TAG: u32 = 1;
/// `PT_NOTE`.
const PT_NOTE: u32 = 4;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Which system the program file starting with `head` was built for (design 2.2, first
/// match wins): Mach-O magic; ELF OS/ABI 9; ELF OS/ABI 0 with a `PT_NOTE` holding the
/// "FreeBSD" ABI tag; ELF OS/ABI 0 or 3; any other ELF OS/ABI. Anything else is
/// [`Kind::Linux`] (the loader refuses what is not a valid ELF file on its own).
///
/// Only notes inside `head` are looked at (FreeBSD's note is in the first page).
pub fn classify(head: &[u8]) -> Kind {
    match head.get(..4) {
        // 0xFEEDFACF / 0xFEEDFACE (little-endian 64/32-bit), and the big-endian universal
        // ("fat") header 0xCAFEBABE / 0xCAFEBABF
        Some([0xCF, 0xFA, 0xED, 0xFE]) | Some([0xCE, 0xFA, 0xED, 0xFE]) => return Kind::MachO,
        Some([0xCA, 0xFE, 0xBA, 0xBE]) | Some([0xCA, 0xFE, 0xBA, 0xBF]) => {
            // Java class files share 0xCAFEBABE: a universal binary's next word is a small
            // slice count (a class file has its version there, 45 or more)
            if u32::from_be_bytes([head.get(4).copied().unwrap_or(0xFF), head.get(5).copied().unwrap_or(0xFF), head.get(6).copied().unwrap_or(0xFF), head.get(7).copied().unwrap_or(0xFF)]) < 30 {
                return Kind::MachO;
            }
            return Kind::Linux;
        }
        Some([0x7F, b'E', b'L', b'F']) => {}
        _ => return Kind::Linux,
    }
    let osabi = head.get(7).copied().unwrap_or(0);
    match osabi {
        ELFOSABI_FREEBSD => Kind::FreeBsd,
        ELFOSABI_NONE if has_freebsd_note(head) => Kind::FreeBsd,
        ELFOSABI_NONE | ELFOSABI_GNU => Kind::Linux,
        other => Kind::OtherOs(other),
    }
}

/// Whether an ELF64 file has a `PT_NOTE` (within `head`) with the note "FreeBSD", type 1.
fn has_freebsd_note(head: &[u8]) -> bool {
    // ELF64 only (EI_CLASS 2, little-endian); the loader refuses the rest anyway
    if head.get(4) != Some(&2) || head.get(5) != Some(&1) {
        return false;
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64_at(head, 32), u16_at(head, 54), u16_at(head, 56)) else {
        return false;
    };
    if phentsize != 56 {
        return false;
    }
    for i in 0..phnum.min(64) as usize {
        let ph = phoff as usize + i * 56;
        if u32_at(head, ph) != Some(PT_NOTE) {
            continue;
        }
        let (Some(off), Some(size)) = (u64_at(head, ph + 8), u64_at(head, ph + 32)) else { continue };
        let (off, size) = (off as usize, size as usize);
        let Some(notes) = head.get(off..off.saturating_add(size)) else { continue };
        let mut p = 0;
        while p + 12 <= notes.len() {
            let namesz = u32_at(notes, p).unwrap_or(0) as usize;
            let descsz = u32_at(notes, p + 4).unwrap_or(0) as usize;
            let ty = u32_at(notes, p + 8).unwrap_or(0);
            let name = notes.get(p + 12..p + 12 + namesz).unwrap_or(&[]);
            if ty == NT_FREEBSD_ABI_TAG && name == b"FreeBSD\0" {
                return true;
            }
            let next = p + 12 + ((namesz + 3) & !3) + ((descsz + 3) & !3);
            if next <= p {
                break;
            }
            p = next;
        }
    }
    false
}

/// Internal (Linux) errno, 0..=133, to FreeBSD's (`docs/personality-errno.md`; 41 and 58,
/// unused by Linux, as `EINVAL`).
pub const FREEBSD_ERRNO: [u8; 134] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 35, 12, 13, 14, 15, //
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, //
    32, 33, 34, 11, 63, 77, 78, 66, 62, 22, 83, 82, 22, 5, 5, 5, //
    22, 6, 5, 5, 22, 22, 28, 2, 22, 22, 22, 22, 22, 87, 60, 55, //
    50, 2, 71, 91, 5, 5, 5, 92, 90, 5, 89, 84, 22, 9, 5, 8, //
    8, 8, 8, 8, 86, 4, 32, 68, 38, 39, 40, 41, 42, 43, 44, 45, //
    46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, //
    64, 65, 37, 36, 70, 5, 22, 22, 22, 5, 69, 6, 6, 85, 2, 13, //
    13, 13, 96, 95, 50, 5,
];

/// Internal (Linux) errno, 0..=133, to macOS's (`docs/personality-errno.md`).
pub const MACOS_ERRNO: [u8; 134] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 35, 12, 13, 14, 15, //
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, //
    32, 33, 34, 11, 63, 77, 78, 66, 62, 22, 91, 90, 22, 5, 5, 5, //
    22, 6, 5, 5, 22, 22, 28, 2, 22, 22, 22, 22, 99, 96, 101, 98, //
    50, 2, 71, 97, 5, 5, 5, 100, 95, 5, 94, 84, 22, 9, 5, 8, //
    8, 8, 8, 8, 92, 4, 32, 68, 38, 39, 40, 41, 42, 43, 44, 102, //
    46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, //
    64, 65, 37, 36, 70, 5, 22, 22, 22, 5, 69, 6, 6, 89, 2, 13, //
    13, 13, 105, 104, 50, 5,
];

/// The positive errno a BSD personality reports for internal errno `e` (1..): through
/// `map`; BSD-only errors carry `512 + n` internally and are `n` there; anything unknown
/// is `EINVAL`.
pub fn bsd_errno(map: &[u8; 134], e: u64) -> u64 {
    if (e as usize) < map.len() {
        map[e as usize] as u64
    } else if (512..1024).contains(&e) {
        e - 512
    } else {
        22
    }
}

/// FreeBSD signal `s` (1..=33, 65..=95) to the internal (Linux) number; `None` for numbers
/// FreeBSD programs cannot send (0 is "no signal": the caller handles it).
pub fn freebsd_sig_to_internal(s: u64) -> Option<u32> {
    Some(match s {
        1..=6 | 8 | 9 | 11 | 13 | 14 | 15 => s as u32,
        7 => 16,  // SIGEMT -> SIGSTKFLT (unused by Linux programs)
        10 => 7,  // SIGBUS
        12 => 31, // SIGSYS
        16 => 23, // SIGURG
        17 => 19, // SIGSTOP
        18 => 20, // SIGTSTP
        19 => 18, // SIGCONT
        20 => 17, // SIGCHLD
        21 | 22 => s as u32, // SIGTTIN, SIGTTOU
        23 => 29, // SIGIO
        24..=28 => s as u32, // SIGXCPU SIGXFSZ SIGVTALRM SIGPROF SIGWINCH
        29 => 30, // SIGINFO -> SIGPWR
        30 => 10, // SIGUSR1
        31 => 12, // SIGUSR2
        32 | 33 => s as u32, // SIGTHR, SIGLIBRT (glibc's two private signals)
        65..=95 => (s - 31) as u32, // SIGRTMIN.. -> 34..64
        _ => return None,
    })
}

/// Internal (Linux) signal `s` (1..=64) to FreeBSD's number (the inverse of
/// [`freebsd_sig_to_internal`]).
pub fn internal_sig_to_freebsd(s: u32) -> u32 {
    match s {
        7 => 10,
        10 => 30,
        12 => 31,
        16 => 7,
        17 => 20,
        18 => 19,
        19 => 17,
        20 => 18,
        23 => 16,
        29 => 23,
        30 => 29,
        31 => 12,
        34..=64 => s + 31,
        _ => s,
    }
}

/// `__FreeBSD_version` reported to FreeBSD programs (`AT_OSRELDATE`): FreeBSD 15.1's, the
/// root Group 11 prepared.
pub const FREEBSD_OSRELDATE: u64 = 1_501_000;

/// Where the signal trampoline is mapped in every FreeBSD process: one page in the gap
/// Hydra leaves between the mmap area and the stack (FreeBSD's own shared page sits just
/// above its stack; programs find the trampoline only through the frame's return).
pub const FREEBSD_SIGCODE_ADDR: u64 = 0x7FFF_EF7F_F000; // STACK_TOP - STACK_SIZE - 256 MiB

/// FreeBSD's `sigcode` (`sys/amd64/amd64/sigtramp.S`): `call *0(%rsp)` (the handler in
/// `sf_ahu`); `lea 16(%rsp), %rdi` (`&sf_uc`); `push $0`; `mov $417, %rax`; `syscall`
/// (`sigreturn`); then `hlt` in a loop.
pub const FREEBSD_SIGCODE: [u8; 22] = [
    0xFF, 0x14, 0x24, // call *(%rsp)
    0x48, 0x8D, 0x7C, 0x24, 0x10, // lea 0x10(%rsp),%rdi
    0x6A, 0x00, // push $0
    0x48, 0xC7, 0xC0, 0xA1, 0x01, 0x00, 0x00, // mov $417,%rax
    0x0F, 0x05, // syscall
    0xF4, 0xEB, 0xFD, // hlt; jmp .-1
];

// ----------------------------------------------------------------------
// The FreeBSD exec layout
// ----------------------------------------------------------------------

/// FreeBSD's auxiliary vector numbers (`sys/sys/elf_common.h`; `AT_` + the name).
#[allow(missing_docs)]
pub mod freebsd_at {
    pub const NULL: u64 = 0;
    pub const PHDR: u64 = 3;
    pub const PHENT: u64 = 4;
    pub const PHNUM: u64 = 5;
    pub const PAGESZ: u64 = 6;
    pub const BASE: u64 = 7;
    pub const FLAGS: u64 = 8;
    pub const ENTRY: u64 = 9;
    pub const UID: u64 = 11;
    pub const EUID: u64 = 12;
    pub const GID: u64 = 13;
    pub const EGID: u64 = 14;
    pub const EXECPATH: u64 = 15;
    pub const CANARY: u64 = 16;
    pub const CANARYLEN: u64 = 17;
    pub const OSRELDATE: u64 = 18;
    pub const NCPUS: u64 = 19;
    pub const PAGESIZES: u64 = 20;
    pub const PAGESIZESLEN: u64 = 21;
    pub const STACKPROT: u64 = 23;
    pub const EHDRFLAGS: u64 = 24;
    pub const HWCAP: u64 = 25;
    pub const HWCAP2: u64 = 26;
    pub const BSDFLAGS: u64 = 27;
    pub const ARGC: u64 = 28;
    pub const ARGV: u64 = 29;
    pub const ENVC: u64 = 30;
    pub const ENVV: u64 = 31;
    pub const PS_STRINGS: u64 = 32;
    pub const USRSTACKBASE: u64 = 35;
    pub const USRSTACKLIM: u64 = 36;
}
