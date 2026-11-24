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

// wave11 GF (review 7) begin: Linux efivarfs's rules for changing a variable
/// `EFI_GLOBAL_VARIABLE_GUID`.
pub const GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// `(variable name, GUID)` of efivarfs file name `file` (`<Name>-<GUID>`).
pub fn split_name(file: &str) -> Option<(&str, &str)> {
    if !efivar_name(file) {
        return None;
    }
    let (n, g) = file.split_at(file.len() - 37);
    Some((n, &g[1..]))
}

/// Whether `name` is `<prefix>` and four hex digits (`Boot0001`).
fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|r| r.len() == 4 && r.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Linux's `efivar_validate` for the global variables it knows: whether `data` (without the
/// 4 attribute bytes) is a valid value of variable `name` under `guid`; other variables are
/// not checked.
pub fn validate(name: &str, guid: &str, data: &[u8]) -> bool {
    if !guid.eq_ignore_ascii_case(GLOBAL_GUID) {
        return true;
    }
    let order = |d: &[u8]| d.len() % 2 == 0;
    match name {
        "BootNext" | "Timeout" => data.len() == 2,
        "BootOrder" | "DriverOrder" | "SysPrepOrder" | "BootOptionSupport" => order(data),
        "Lang" | "PlatformLang" | "LangCodes" | "PlatformLangCodes" => data.iter().all(|c| c.is_ascii()),
        n if numbered(n, "Boot") || numbered(n, "Driver") || numbered(n, "SysPrep") => load_option(data),
        _ => true,
    }
}

/// An `EFI_LOAD_OPTION`: attributes (4), file path list length (2), a NUL-ended UCS-2
/// description, then the file path list of that length (as Linux's `validate_load_option`).
pub fn load_option(d: &[u8]) -> bool {
    if d.len() < 6 {
        return false;
    }
    let fpl = u16::from_le_bytes([d[4], d[5]]) as usize;
    let mut i = 6;
    loop {
        if i + 2 > d.len() {
            return false;
        }
        let c = u16::from_le_bytes([d[i], d[i + 1]]);
        i += 2;
        if c == 0 {
            break;
        }
    }
    i + fpl <= d.len()
}

/// Whether variable `name` under `guid` may be deleted (Linux's
/// `efivar_variable_is_removable`: any vendor's; of the global ones only those it validates):
/// the others are immutable until `FS_IOC_SETFLAGS` clears the flag.
pub fn removable(name: &str, guid: &str) -> bool {
    if !guid.eq_ignore_ascii_case(GLOBAL_GUID) {
        return true;
    }
    matches!(name, "BootNext" | "BootOrder" | "DriverOrder" | "SysPrepOrder" | "Timeout" | "Lang" | "PlatformLang")
        || numbered(name, "Boot")
        || numbered(name, "Driver")
        || numbered(name, "SysPrep")
}

/// Whether `name` is a Secure Boot key database (`PK`, `KEK`, `db`, `dbx`, `dbt`, `dbr`):
/// changed only in setup mode.
pub fn secure_boot_key(name: &str) -> bool {
    matches!(name, "PK" | "KEK" | "db" | "dbx" | "dbt" | "dbr")
}
// wave11 GF (review 7) end
