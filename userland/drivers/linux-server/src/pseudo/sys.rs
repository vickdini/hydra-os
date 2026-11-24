//! Which `/sys` file a redirected path names, and the text of the CPU range files (plain
//! Rust, host-tested in `tests/host-w7-40`).
//!
//! wave10 G7b-2: `/proc` moved to lx-proc (`lx-proc/src/procfs/`); linux-server keeps the
//! `/sys` files it served since wave 7 (Group 7-4): the CPU ranges and efivarfs.

use crate::proto::LX_VFS_PSEUDO_SYS;

/// A `/sys` file linux-server serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    /// `/sys/devices/system/cpu/{online,possible,present}`.
    CpuRange,
    /// `/sys/firmware/efi/efivars/<Name>-<GUID>`: a UEFI variable (the file name is the
    /// tail's last component).
    Efivar,
}

/// Whether `name` has the shape of an efivarfs file name: `<Name>-<GUID>` (a GUID of 36
/// characters, hex digits and dashes at 8, 13, 18, 23).
pub fn efivar_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 38 || b[b.len() - 37] != b'-' {
        return false;
    }
    let g = &b[b.len() - 36..];
    g.iter().enumerate().all(|(i, &c)| if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() })
}

/// What `tail` names under the `/sys` mount (object `LX_VFS_PSEUDO_SYS`): `None` = the
/// kernel answers (everything else, `..` in the tail, a trailing `/`).
pub fn classify(obj: u64, tail: &[u8]) -> Option<File> {
    if obj & 0xFFFF_FFFF != LX_VFS_PSEUDO_SYS {
        return None;
    }
    if tail.last() == Some(&b'/') || tail.ends_with(b"/.") || tail == b"." {
        return None;
    }
    let mut c = alloc::vec::Vec::new();
    for part in tail.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return None,
            p => c.push(core::str::from_utf8(p).ok()?),
        }
    }
    match c.as_slice() {
        ["devices", "system", "cpu", "online" | "possible" | "present"] => Some(File::CpuRange),
        ["firmware", "efi", "efivars", name] if efivar_name(name) => Some(File::Efivar),
        _ => None,
    }
}

/// `/sys/devices/system/cpu/online` (and `possible`, `present`) for `n` CPUs.
pub fn cpu_range(n: u64) -> alloc::vec::Vec<u8> {
    if n > 1 {
        alloc::format!("0-{}\n", n - 1).into_bytes()
    } else {
        b"0\n".to_vec()
    }
}

/// An inode number for a pseudo file (FNV-1a of its tail, never 0 or 1; the same function
/// as lx-proc's `/proc` files).
pub fn ino_of(obj: u64, tail: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (obj & 0xFFFF_FFFF);
    for &b in tail {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h >> 1) | 2
}
