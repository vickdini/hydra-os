//! # POSIX ACL changes (wave 10, Group V1)
//!
//! The kernel's `compat/linux/acl.rs` decisions that change ACLs, on their bytes only (Linux's
//! xattr encoding, version 2: a 4-byte header, then 8-byte entries `{tag u16, perm u16, id
//! u32}`), so they are host-tested (`tests/host-w10-v1`):
//! - **creation** in a directory with a default ACL ([`create_mode`]): no umask, the new
//!   object's access ACL is the default limited by the requested mode, a new directory also
//!   gets the default ACL (`posix_acl_create`);
//! - **chmod** of an object with an access ACL ([`on_chmod`]): the owner, mask (or owning
//!   group) and other entries take the new bits;
//! - **setting** one ([`parse`], [`mode_bits`]): validated as `posix_acl_valid`; an access ACL
//!   sets the mode's permission bits, and one equivalent to the mode (three entries) is not
//!   kept.

use alloc::vec::Vec;

/// The access ACL attribute.
pub const ACCESS: &[u8] = b"system.posix_acl_access";
/// The default ACL attribute (directories).
pub const DEFAULT: &[u8] = b"system.posix_acl_default";
/// The access-control labels attribute (the kernel's `abac::LABELS`): new files and folders
/// get their folder's labels.
pub const LABELS: &[u8] = b"security.hydra.labels";

const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

const USER_OBJ: u16 = 0x01;
const USER: u16 = 0x02;
const GROUP_OBJ: u16 = 0x04;
const GROUP: u16 = 0x08;
const MASK: u16 = 0x10;
const OTHER: u16 = 0x20;

/// One entry `(tag, perm, id)`.
pub type Entry = (u16, u16, u32);

/// Parses and validates an ACL (`EINVAL` if malformed, `EOPNOTSUPP` for another version), as
/// the kernel's `acl::parse`.
pub fn parse(b: &[u8]) -> Result<Vec<Entry>, i64> {
    if b.len() < 4 || (b.len() - 4) % 8 != 0 {
        return Err(EINVAL);
    }
    if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != 2 {
        return Err(EOPNOTSUPP);
    }
    let e: Vec<Entry> = b[4..].chunks(8).map(|c| (u16::from_le_bytes([c[0], c[1]]), u16::from_le_bytes([c[2], c[3]]), u32::from_le_bytes([c[4], c[5], c[6], c[7]]))).collect();
    if valid(&e) {
        Ok(e)
    } else {
        Err(EINVAL)
    }
}

/// Linux's `posix_acl_valid`.
pub fn valid(e: &[Entry]) -> bool {
    // States: 1 expecting owner, 2 named users, 3 named groups, 4 expecting other, 0 done
    let (mut state, mut needs_mask, mut prev) = (1, false, None::<u32>);
    for &(tag, perm, id) in e {
        if perm & !7 != 0 {
            return false;
        }
        match tag {
            USER_OBJ if state == 1 => state = 2,
            USER if state == 2 => {
                if prev.is_some_and(|p| id <= p) {
                    return false;
                }
                prev = Some(id);
                needs_mask = true;
            }
            GROUP_OBJ if state == 2 => {
                state = 3;
                prev = None;
            }
            GROUP if state == 3 => {
                if prev.is_some_and(|p| id <= p) {
                    return false;
                }
                prev = Some(id);
                needs_mask = true;
            }
            MASK if state == 3 => state = 4,
            OTHER if state == 4 || (state == 3 && !needs_mask) => state = 0,
            _ => return false,
        }
    }
    state == 0
}

/// The xattr bytes of `e`.
pub fn encode(e: &[Entry]) -> Vec<u8> {
    let mut b = 2u32.to_le_bytes().to_vec();
    for &(tag, perm, id) in e {
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&perm.to_le_bytes());
        b.extend_from_slice(&id.to_le_bytes());
    }
    b
}

/// The permission bits an access ACL gives the mode: owner, mask (or owning group), other.
pub fn mode_bits(e: &[Entry]) -> u32 {
    let get = |t: u16| e.iter().find(|x| x.0 == t).map(|x| x.1 as u32);
    let owner = get(USER_OBJ).unwrap_or(0);
    let group = get(MASK).or_else(|| get(GROUP_OBJ)).unwrap_or(0);
    owner << 6 | group << 3 | get(OTHER).unwrap_or(0)
}

/// What a new object inherits from its directory (see [`create_mode`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inherit {
    /// Its access ACL (when not equivalent to the mode).
    pub access: Option<Vec<u8>>,
    /// Its default ACL (a directory: its parent's).
    pub default: Option<Vec<u8>>,
    /// Its access-control labels (its directory's).
    pub labels: Option<Vec<u8>>,
}

impl Inherit {
    /// Whether there is nothing to give.
    pub fn is_empty(&self) -> bool {
        self.access.is_none() && self.default.is_none() && self.labels.is_none()
    }
}

/// The permission bits for a new object requested with `perm` in a directory whose default
/// ACL is `default` (its bytes, if it has one; an unreadable one counts as none, as the
/// kernel's): with a default ACL, `perm` limited by it (no umask) and what the object
/// inherits; without one, `perm` minus `umask`.
pub fn create_mode(default: Option<&[u8]>, perm: u32, umask: u32, is_dir: bool) -> (u32, Inherit) {
    let Some(def) = default.and_then(|d| parse(d).ok()) else {
        return (perm & !umask, Inherit::default());
    };
    let mut e = def.clone();
    let mut mode = perm;
    let mut not_equiv = false;
    let (mut group_obj, mut mask) = (None, None);
    for (i, x) in e.iter_mut().enumerate() {
        match x.0 {
            USER_OBJ => {
                x.1 &= ((mode >> 6) & 7) as u16;
                mode = (mode & !0o700) | (x.1 as u32) << 6;
            }
            USER | GROUP => not_equiv = true,
            GROUP_OBJ => group_obj = Some(i),
            OTHER => {
                x.1 &= (mode & 7) as u16;
                mode = (mode & !0o7) | x.1 as u32;
            }
            MASK => {
                mask = Some(i);
                not_equiv = true;
            }
            _ => {}
        }
    }
    if let Some(i) = mask.or(group_obj) {
        e[i].1 &= ((mode >> 3) & 7) as u16;
        mode = (mode & !0o70) | (e[i].1 as u32) << 3;
    }
    let plan = Inherit { access: not_equiv.then(|| encode(&e)), default: is_dir.then(|| encode(&def)), labels: None };
    (mode, plan)
}

/// After a chmod to `mode` of an object whose access ACL is `acl`: the new ACL bytes, if
/// they change (owner, mask or owning group, other take the new bits); `None` also for an
/// ACL that does not parse (the kernel leaves it).
pub fn on_chmod(acl: &[u8], mode: u32) -> Option<Vec<u8>> {
    let old = parse(acl).ok()?;
    let mut e = old.clone();
    let has_mask = e.iter().any(|x| x.0 == MASK);
    for x in e.iter_mut() {
        match x.0 {
            USER_OBJ => x.1 = ((mode >> 6) & 7) as u16,
            MASK => x.1 = ((mode >> 3) & 7) as u16,
            GROUP_OBJ if !has_mask => x.1 = ((mode >> 3) & 7) as u16,
            OTHER => x.1 = (mode & 7) as u16,
            _ => {}
        }
    }
    (e != old).then(|| encode(&e))
}

/// Setting an access ACL from `value` on an object of mode `mode`: `(the ACL to keep (None:
/// equivalent to the mode, removed), the new mode)`; `in_group_or_fsetid`: the caller is in
/// the object's group or holds `CAP_FSETID` (else set-group-ID goes).
pub fn set_access(value: &[u8], mode: u32, in_group_or_fsetid: bool) -> Result<(Option<Vec<u8>>, u32), i64> {
    let e = parse(value)?;
    let mut m = (mode & 0o7000) | mode_bits(&e);
    if !in_group_or_fsetid {
        m &= !0o2000;
    }
    Ok(((e.len() != 3).then(|| encode(&e)), m))
}
