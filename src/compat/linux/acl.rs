//! POSIX access control lists, kept as the `system.posix_acl_access` and
//! `system.posix_acl_default` extended attributes in Linux's format (version 2: a 4-byte
//! header, then 8-byte entries `{tag u16, perm u16, id u32}`).
//!
//! - **Setting** one needs ownership or `CAP_FOWNER`; it is validated as Linux does
//!   (`posix_acl_valid`: one owner, owning group and other entry, a mask when there are
//!   named users or groups, entries in order). An access ACL sets the mode's permission
//!   bits (owner, mask or owning group, other); one equivalent to the mode is not kept.
//!   Default ACLs are for directories (`EACCES` otherwise).
//! - **Checks** ([`check`]) follow `posix_acl_permission`: the owner entry for the owner,
//!   a named user entry, then the owning and named group entries (any that matches and
//!   grants), then other; named users and all groups are limited by the mask.
//! - **chmod** rewrites the owner, mask (or owning group) and other entries ([`on_chmod`]).
//! - **Creation** in a directory with a default ACL ([`create_mode`], [`inherit`]): the
//!   umask is not applied, the new file's ACL is the default ACL limited by the requested
//!   mode, and a new directory also gets the default ACL.
//!
//! Parsed ACLs are cached by inode, generation and change time (which every ACL and mode
//! change updates), so files with no extended attributes cost nothing and others are read
//! once per change.
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::zfs::zpl::{Attr, SetAttr};
use crate::fs::ZfsClient;

const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const ENODATA: i64 = -61;
const EOPNOTSUPP: i64 = -95;

/// The access ACL attribute.
pub const ACCESS: &[u8] = b"system.posix_acl_access";
/// The default ACL attribute (directories).
pub const DEFAULT: &[u8] = b"system.posix_acl_default";

const USER_OBJ: u16 = 0x01;
const USER: u16 = 0x02;
const GROUP_OBJ: u16 = 0x04;
const GROUP: u16 = 0x08;
const MASK: u16 = 0x10;
const OTHER: u16 = 0x20;

/// One ACL entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    tag: u16,
    perm: u16,
    id: u32,
}

/// Parses and validates an ACL (`EINVAL` if malformed, `EOPNOTSUPP` for another version).
fn parse(b: &[u8]) -> Result<Vec<Entry>, i64> {
    if b.len() < 4 || (b.len() - 4) % 8 != 0 {
        return Err(EINVAL);
    }
    if u32::from_le_bytes(b[0..4].try_into().unwrap()) != 2 {
        return Err(EOPNOTSUPP);
    }
    let e: Vec<Entry> = b[4..]
        .chunks(8)
        .map(|c| Entry {
            tag: u16::from_le_bytes([c[0], c[1]]),
            perm: u16::from_le_bytes([c[2], c[3]]),
            id: u32::from_le_bytes(c[4..8].try_into().unwrap()),
        })
        .collect();
    if valid(&e) { Ok(e) } else { Err(EINVAL) }
}

/// Linux's `posix_acl_valid`.
fn valid(e: &[Entry]) -> bool {
    // States: 1 expecting owner, 2 named users, 3 named groups, 4 expecting other, 0 done
    let (mut state, mut needs_mask, mut prev) = (1, false, None::<u32>);
    for x in e {
        if x.perm & !7 != 0 {
            return false;
        }
        match x.tag {
            USER_OBJ if state == 1 => state = 2,
            USER if state == 2 => {
                if prev.is_some_and(|p| x.id <= p) {
                    return false;
                }
                prev = Some(x.id);
                needs_mask = true;
            }
            GROUP_OBJ if state == 2 => {
                state = 3;
                prev = None;
            }
            GROUP if state == 3 => {
                if prev.is_some_and(|p| x.id <= p) {
                    return false;
                }
                prev = Some(x.id);
                needs_mask = true;
            }
            MASK if state == 3 => state = 4,
            OTHER if state == 4 || (state == 3 && !needs_mask) => state = 0,
            _ => return false,
        }
    }
    state == 0
}

fn encode(e: &[Entry]) -> Vec<u8> {
    let mut b = 2u32.to_le_bytes().to_vec();
    for x in e {
        b.extend_from_slice(&x.tag.to_le_bytes());
        b.extend_from_slice(&x.perm.to_le_bytes());
        b.extend_from_slice(&x.id.to_le_bytes());
    }
    b
}

/// The permission bits an access ACL gives the mode: owner, mask (or owning group), other.
fn mode_bits(e: &[Entry]) -> u32 {
    let get = |t: u16| e.iter().find(|x| x.tag == t).map(|x| x.perm as u32);
    let owner = get(USER_OBJ).unwrap_or(0);
    let group = get(MASK).or_else(|| get(GROUP_OBJ)).unwrap_or(0);
    owner << 6 | group << 3 | get(OTHER).unwrap_or(0)
}

/// Parsed ACLs by `(inode, generation, change time, default)`.
type Key = (u64, u64, i64, u32, bool);
static CACHE: Mutex<BTreeMap<Key, Option<Arc<Vec<Entry>>>>> = Mutex::new(BTreeMap::new());

/// `attr`'s access (or default) ACL, if it has one.
fn load(attr: &Attr, default: bool) -> Option<Arc<Vec<Entry>>> {
    if !attr.has_xattr {
        return None;
    }
    let key = (attr.ino, attr.generation, attr.ctime.0, attr.ctime.1, default);
    if let Some(v) = CACHE.lock().get(&key) {
        return v.clone();
    }
    let v = ZfsClient::getxattr(attr.ino, if default { DEFAULT } else { ACCESS })
        .ok()
        .and_then(|b| parse(&b).ok())
        .map(Arc::new);
    let mut c = CACHE.lock();
    if c.len() >= 4096 {
        c.clear();
    }
    c.insert(key, v.clone());
    v
}

fn in_group(gid: u32, egid: u32) -> bool {
    gid == egid || super::proc::in_supplementary_groups(gid)
}

/// Whether `uid`/`gid` may access `attr` for `want` (`r` 4, `w` 2, `x` 1) under its
/// access ACL; `None` if it has none (the mode bits decide).
pub fn check(attr: &Attr, uid: u32, gid: u32, want: u32) -> Option<bool> {
    let acl = load(attr, false)?;
    let want = want as u16;
    let mask = acl.iter().find(|x| x.tag == MASK).map_or(7, |x| x.perm);
    if attr.uid == uid {
        return Some(acl.iter().find(|x| x.tag == USER_OBJ).is_some_and(|x| x.perm & want == want));
    }
    if let Some(x) = acl.iter().find(|x| x.tag == USER && x.id == uid) {
        return Some(x.perm & mask & want == want);
    }
    let mut matched = false;
    for x in acl.iter() {
        let member = match x.tag {
            GROUP_OBJ => in_group(attr.gid, gid),
            GROUP => in_group(x.id, gid),
            _ => false,
        };
        if member {
            if x.perm & mask & want == want {
                return Some(true);
            }
            matched = true;
        }
    }
    if matched {
        return Some(false);
    }
    Some(acl.iter().find(|x| x.tag == OTHER).is_some_and(|x| x.perm & want == want))
}

fn may_change(attr: &Attr) -> bool {
    let euid = super::vfs::creds().euid;
    euid == attr.uid || crate::task::with_current_task_mut(|t| t.caps.has(1 << 3)).unwrap_or(false)
}

/// Sets `attr`'s access ACL or (`default`) its default ACL from `value` (empty: removes
/// it).
pub fn set(attr: &Attr, default: bool, value: &[u8], flags: u32) -> i64 {
    if !may_change(attr) {
        return EPERM;
    }
    if default && !attr.is_dir() {
        return EACCES;
    }
    if value.is_empty() {
        return match remove(attr, default) {
            ENODATA => 0,
            r => r,
        };
    }
    let e = match parse(value) {
        Ok(e) => e,
        Err(err) => return err,
    };
    let name = if default { DEFAULT } else { ACCESS };
    if default {
        return ZfsClient::setxattr(attr.ino, name, &encode(&e), flags).map_or_else(|x| x, |_| 0);
    }
    // The mode follows the ACL; set-group-ID goes for a non-member without CAP_FSETID
    let c = super::vfs::creds();
    let mut mode = (attr.mode & 0o7000) | mode_bits(&e);
    if !in_group(attr.gid, c.egid) && !crate::task::with_current_task_mut(|t| t.caps.has(1 << 4)).unwrap_or(false) {
        mode &= !0o2000;
    }
    let r = if e.len() == 3 {
        // Equivalent to the mode: only the mode is kept
        match ZfsClient::removexattr(attr.ino, name) {
            Err(ENODATA) => Ok(()),
            r => r,
        }
    } else {
        ZfsClient::setxattr(attr.ino, name, &encode(&e), flags)
    };
    if let Err(x) = r {
        return x;
    }
    crate::fs::zfs::with_server(|s| s.setattr(attr.ino, SetAttr { mode: Some(mode), ..SetAttr::default() })).map_or_else(|x| x, |_| 0)
}

/// Removes `attr`'s access or default ACL (the mode stays).
pub fn remove(attr: &Attr, default: bool) -> i64 {
    if !may_change(attr) {
        return EPERM;
    }
    ZfsClient::removexattr(attr.ino, if default { DEFAULT } else { ACCESS }).map_or_else(|x| x, |_| 0)
}

/// After a chmod of `attr` to `mode`: its access ACL takes the new owner, mask (or owning
/// group) and other permissions.
pub fn on_chmod(attr: &Attr, mode: u32) {
    let Some(acl) = load(attr, false) else { return };
    let mut e = (*acl).clone();
    let has_mask = e.iter().any(|x| x.tag == MASK);
    for x in e.iter_mut() {
        match x.tag {
            USER_OBJ => x.perm = ((mode >> 6) & 7) as u16,
            MASK => x.perm = ((mode >> 3) & 7) as u16,
            GROUP_OBJ if !has_mask => x.perm = ((mode >> 3) & 7) as u16,
            OTHER => x.perm = (mode & 7) as u16,
            _ => {}
        }
    }
    if e != *acl {
        let _ = ZfsClient::setxattr(attr.ino, ACCESS, &encode(&e), 0);
    }
}

/// What a new inode inherits from its directory's default ACL.
pub struct Inherit {
    access: Option<Vec<Entry>>,
    default: Option<Vec<u8>>,
}

/// The permission bits for a new inode requested with `perm` in directory `dir`: with a
/// default ACL, `perm` limited by it (no umask) and what the inode inherits
/// (`posix_acl_create`); without one, `perm` minus `umask`.
pub fn create_mode(dir: u64, perm: u32, umask: u32, is_dir: bool) -> (u32, Option<Inherit>) {
    let plain = (perm & !umask, None);
    let Ok(dattr) = ZfsClient::getattr(dir) else { return plain };
    let Some(def) = load(&dattr, true) else { return plain };
    let mut e = (*def).clone();
    let mut mode = perm;
    let mut not_equiv = false;
    let (mut group_obj, mut mask) = (None, None);
    for (i, x) in e.iter_mut().enumerate() {
        match x.tag {
            USER_OBJ => {
                x.perm &= ((mode >> 6) & 7) as u16;
                mode = (mode & !0o700) | (x.perm as u32) << 6;
            }
            USER | GROUP => not_equiv = true,
            GROUP_OBJ => group_obj = Some(i),
            OTHER => {
                x.perm &= (mode & 7) as u16;
                mode = (mode & !0o7) | x.perm as u32;
            }
            MASK => {
                mask = Some(i);
                not_equiv = true;
            }
            _ => {}
        }
    }
    if let Some(i) = mask.or(group_obj) {
        e[i].perm &= ((mode >> 3) & 7) as u16;
        mode = (mode & !0o70) | (e[i].perm as u32) << 3;
    }
    let plan = Inherit { access: not_equiv.then_some(e), default: is_dir.then(|| encode(&def)) };
    (mode, Some(plan))
}

/// Gives new inode `ino` what it inherits (see [`create_mode`]).
pub fn inherit(ino: u64, plan: Option<Inherit>) {
    let Some(p) = plan else { return };
    if let Some(a) = p.access {
        let _ = ZfsClient::setxattr(ino, ACCESS, &encode(&a), 0);
    }
    if let Some(d) = p.default {
        let _ = ZfsClient::setxattr(ino, DEFAULT, &d, 0);
    }
}
