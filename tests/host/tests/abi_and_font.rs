//! Tests for the Linux ABI definitions in `src/compat/linux/types.rs` and the
//! console bitmap font in `src/video/font.rs`.
//!
//! The ABI structs are copied byte-for-byte to and from user memory, so a
//! size or offset that differs from x86_64 glibc silently corrupts data. The
//! expected numbers below come from `<sys/stat.h>`, `<sys/uio.h>`,
//! `<sys/socket.h>` and `<sys/utsname.h>` on x86_64 Linux.

use std::mem::{offset_of, size_of};

use hydra_hosttests::compat::linux::types::*;
use hydra_hosttests::video::font::{get_char_glyph, FONT_HEIGHT, FONT_WIDTH};

// --------------------------------------------------------------- layouts

#[test]
fn struct_stat_layout() {
    assert_eq!(size_of::<LinuxStat>(), 144);
    assert_eq!(offset_of!(LinuxStat, st_dev), 0);
    assert_eq!(offset_of!(LinuxStat, st_ino), 8);
    assert_eq!(offset_of!(LinuxStat, st_nlink), 16);
    assert_eq!(offset_of!(LinuxStat, st_mode), 24);
    assert_eq!(offset_of!(LinuxStat, st_uid), 28);
    assert_eq!(offset_of!(LinuxStat, st_gid), 32);
    assert_eq!(offset_of!(LinuxStat, st_rdev), 40);
    assert_eq!(offset_of!(LinuxStat, st_size), 48);
    assert_eq!(offset_of!(LinuxStat, st_blksize), 56);
    assert_eq!(offset_of!(LinuxStat, st_blocks), 64);
    assert_eq!(offset_of!(LinuxStat, st_atime), 72);
    assert_eq!(offset_of!(LinuxStat, st_mtime), 88);
    assert_eq!(offset_of!(LinuxStat, st_ctime), 104);
}

#[test]
fn time_and_iovec_layouts() {
    assert_eq!(size_of::<LinuxTimeval>(), 16);
    assert_eq!(size_of::<LinuxTimespec>(), 16);
    assert_eq!(offset_of!(LinuxTimespec, tv_nsec), 8);
    assert_eq!(size_of::<LinuxIovec>(), 16);
    assert_eq!(offset_of!(LinuxIovec, iov_len), 8);
    assert_eq!(size_of::<AuxvEntry>(), 16);
}

#[test]
fn msghdr_and_cmsghdr_layouts() {
    assert_eq!(size_of::<LinuxMsghdr>(), 56);
    assert_eq!(offset_of!(LinuxMsghdr, msg_namelen), 8);
    assert_eq!(offset_of!(LinuxMsghdr, msg_iov), 16);
    assert_eq!(offset_of!(LinuxMsghdr, msg_iovlen), 24);
    assert_eq!(offset_of!(LinuxMsghdr, msg_control), 32);
    assert_eq!(offset_of!(LinuxMsghdr, msg_controllen), 40);
    assert_eq!(offset_of!(LinuxMsghdr, msg_flags), 48);
    assert_eq!(size_of::<LinuxCmsghdr>(), 16);
    assert_eq!(offset_of!(LinuxCmsghdr, cmsg_type), 12);
}

#[test]
fn utsname_layout_and_defaults() {
    assert_eq!(size_of::<LinuxUtsname>(), 6 * 65);
    let u = LinuxUtsname::default();
    let field = |f: &[u8; 65]| {
        let end = f.iter().position(|&b| b == 0).expect("NUL-terminated");
        String::from_utf8(f[..end].to_vec()).unwrap()
    };
    assert_eq!(field(&u.sysname), "Linux", "glibc and many programs check this exact value");
    assert_eq!(field(&u.machine), "x86_64");
    let release = field(&u.release);
    let major: u32 = release.split('.').next().unwrap().parse().unwrap();
    assert!(major >= 3, "glibc refuses to run on kernels older than it supports: {release}");
    assert!(!field(&u.nodename).is_empty());
}

// --------------------------------------------------------------- constants

#[test]
fn errno_values_match_linux() {
    let cases = [
        (EPERM, 1), (ENOENT, 2), (ESRCH, 3), (EINTR, 4), (EIO, 5), (ENXIO, 6), (EBADF, 9),
        (EAGAIN, 11), (ENOMEM, 12), (EACCES, 13), (EFAULT, 14), (EEXIST, 17), (ENOTDIR, 20),
        (EISDIR, 21), (EINVAL, 22), (ENFILE, 23), (EMFILE, 24), (ENOTTY, 25), (ENOSPC, 28),
        (ESPIPE, 29), (EROFS, 30), (EPIPE, 32), (ENOSYS, 38), (EPROTONOSUPPORT, 93),
        (EAFNOSUPPORT, 97), (EADDRINUSE, 98), (ECONNREFUSED, 111),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}

#[test]
fn auxv_and_clone_constants_match_linux() {
    assert_eq!((AT_NULL, AT_PHDR, AT_PAGESZ, AT_ENTRY, AT_RANDOM, AT_EXECFN), (0, 3, 6, 9, 25, 31));
    assert_eq!(AT_SYSINFO_EHDR, 33);
    assert_eq!((CLONE_VM, CLONE_FILES, CLONE_THREAD, CLONE_SETTLS), (0x100, 0x400, 0x10000, 0x80000));
    assert_eq!((CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID), (0x100000, 0x200000, 0x1000000));
    assert_eq!((ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS), (0x1001, 0x1002, 0x1003, 0x1004));
    assert_eq!((PROT_READ, PROT_WRITE, PROT_EXEC, MAP_SHARED), (1, 2, 4, 1));
    assert_eq!((SOL_SOCKET, SCM_RIGHTS), (1, 1));
}

// -------------------------------------------------------------------- font

#[test]
fn font_dimensions() {
    assert_eq!((FONT_WIDTH, FONT_HEIGHT), (8, 16));
    assert_eq!(get_char_glyph('A').len(), FONT_HEIGHT);
}

#[test]
fn space_is_blank_and_printables_are_not() {
    assert!(get_char_glyph(' ').iter().all(|&row| row == 0));
    for c in '!'..='~' {
        assert!(get_char_glyph(c).iter().any(|&row| row != 0), "{c:?} has an empty glyph");
    }
}

#[test]
fn printable_glyphs_are_distinct_from_the_fallback() {
    let unknown = get_char_glyph('\u{7F}');
    for c in ' '..='~' {
        assert_ne!(get_char_glyph(c), unknown, "{c:?} renders as the unknown-glyph box");
    }
}

#[test]
fn non_printables_use_the_fallback_glyph() {
    let unknown = get_char_glyph('\u{7F}');
    for c in ['\0', '\n', '\t', '\u{1F}', 'é', '✓', '\u{10FFFF}'] {
        assert_eq!(get_char_glyph(c), unknown, "{c:?}");
    }
}

#[test]
fn common_glyphs_are_unique() {
    let mut glyphs: Vec<&[u8; 16]> = ('!'..='~').map(get_char_glyph).collect();
    let n = glyphs.len();
    glyphs.sort();
    glyphs.dedup();
    assert_eq!(glyphs.len(), n, "two printable characters share a bitmap");
}
