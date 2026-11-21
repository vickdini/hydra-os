//! Permission policy: mode bits, POSIX ACLs and the discretionary capabilities, as the
//! kernel's `vfs::may_access` and `acl::check` decide them today (the ABAC and Landlock
//! checks stay with the kernel until wave 8: a caller they restrict is sent back there).

use crate::ctx::{Ctx, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH};
use crate::fs::fsproto::Attr;

/// Execute, or search a directory.
pub const MAY_EXEC: u32 = 1;
/// Write.
pub const MAY_WRITE: u32 = 2;
/// Read.
pub const MAY_READ: u32 = 4;

/// The extended attribute holding an object's access ACL.
pub const ACL_ACCESS: &[u8] = b"system.posix_acl_access";

const USER_OBJ: u16 = 0x01;
const USER: u16 = 0x02;
const GROUP_OBJ: u16 = 0x04;
const GROUP: u16 = 0x08;
const MASK: u16 = 0x10;
const OTHER: u16 = 0x20;

/// One ACL entry `(tag, perm, id)`.
type Entry = (u16, u16, u32);

/// The entries of an ACL in Linux's xattr encoding (version 2); `None` if malformed.
fn parse(b: &[u8]) -> Option<alloc::vec::Vec<Entry>> {
    if b.len() < 4 || (b.len() - 4) % 8 != 0 || u32::from_le_bytes(b[0..4].try_into().ok()?) != 2 {
        return None;
    }
    Some(b[4..].chunks(8).map(|c| (u16::from_le_bytes([c[0], c[1]]), u16::from_le_bytes([c[2], c[3]]), u32::from_le_bytes([c[4], c[5], c[6], c[7]]))).collect())
}

/// Whether the caller may access `attr` for `want` under ACL `acl` (Linux's
/// `posix_acl_permission`); `None` if `acl` is not a usable ACL (the mode bits decide).
pub fn acl_check(cx: &Ctx, attr: &Attr, acl: &[u8], want: u32) -> Option<bool> {
    let acl = parse(acl)?;
    let want = want as u16;
    let mask = acl.iter().find(|x| x.0 == MASK).map_or(7, |x| x.1);
    if attr.uid == cx.uid {
        return Some(acl.iter().find(|x| x.0 == USER_OBJ).is_some_and(|x| x.1 & want == want));
    }
    if let Some(x) = acl.iter().find(|x| x.0 == USER && x.2 == cx.uid) {
        return Some(x.1 & mask & want == want);
    }
    let mut matched = false;
    for x in acl.iter() {
        let member = match x.0 {
            GROUP_OBJ => cx.in_group(attr.gid),
            GROUP => cx.in_group(x.2),
            _ => false,
        };
        if member {
            if x.1 & mask & want == want {
                return Some(true);
            }
            matched = true;
        }
    }
    if matched {
        return Some(false);
    }
    Some(acl.iter().find(|x| x.0 == OTHER).is_some_and(|x| x.1 & want == want))
}

/// Whether the caller's capabilities alone grant `want` on `attr` (Linux's
/// `generic_permission` after the mode check failed).
fn by_caps(cx: &Ctx, attr: &Attr, want: u32) -> bool {
    if cx.has_cap(CAP_DAC_OVERRIDE) {
        // Read and write anything, search directories, execute what has an x bit
        return want & MAY_EXEC == 0 || attr.is_dir() || attr.mode & 0o111 != 0;
    }
    if cx.has_cap(CAP_DAC_READ_SEARCH) {
        return want & MAY_WRITE == 0 && (want & MAY_EXEC == 0 || attr.is_dir());
    }
    false
}

/// Whether the caller may access the object `attr` describes for `want` (`MAY_*` bits);
/// `acl`: its access ACL if it has one.
pub fn may(cx: &Ctx, attr: &Attr, acl: Option<&[u8]>, want: u32) -> bool {
    let unix = match acl.and_then(|a| acl_check(cx, attr, a, want)) {
        Some(r) => r,
        None => {
            let bits = if attr.uid == cx.uid {
                (attr.mode >> 6) & 7
            } else if cx.in_group(attr.gid) {
                (attr.mode >> 3) & 7
            } else {
                attr.mode & 7
            };
            bits & want == want
        }
    };
    unix || by_caps(cx, attr, want)
}

/// Whether the mode bits alone may decide (no ACL needs to be read): the object has no
/// extended attributes, or the caller passes by its capabilities, or everyone may.
pub fn needs_acl(cx: &Ctx, attr: &Attr, want: u32) -> bool {
    let everyone = (attr.mode & 7) & want == want && ((attr.mode >> 3) & 7) & want == want && ((attr.mode >> 6) & 7) & want == want;
    attr.has_xattr && !everyone && !by_caps(cx, attr, want)
}
