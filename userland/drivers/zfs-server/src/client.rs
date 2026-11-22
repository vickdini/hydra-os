//! Path resolution over the server (the kernel's `fs::client` helpers), used by the
//! requests that walk paths ([`crate::serve`]).

use crate::zfs::fsproto::{ELOOP, ENOENT, ENOTDIR, EEXIST};
use crate::zfs::server::ZfsServer;
use crate::zfs::types::DnodeType;
use alloc::vec::Vec;

/// Symbolic links followed in one path at most (Linux `MAXSYMLINKS`).
const SYMLOOP_MAX: usize = 40;

/// Splits a path into non-empty, non-dot directory components.
///
/// # Arguments
/// * `path` - Byte slice representing the file path.
///
/// # Returns
/// Vector of component byte vectors.
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&c| c == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
}

/// Resolves `path` relative to `base` (the pool root for absolute paths).
///
/// # Arguments
/// * `s` - Active ZFS server.
/// * `base` - Base directory object ID.
/// * `path` - Path byte slice.
/// * `follow_last` - Whether to resolve trailing symlink.
///
/// # Returns
/// Resolved object ID on success.
///
/// # Errors
/// Returns negative Linux error code on resolution failure.
pub fn resolve_at(s: &mut ZfsServer, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    let root = s.root_obj();
    resolve_in(s, root, base, path, follow_last)
}

/// Resolves `path` inside the `root` directory (a `chroot`), expanding symbolic links
/// in every component and, when `follow_last` or with a trailing `/`, in the last.
///
/// # Arguments
/// * `s` - Active ZFS server.
/// * `root` - Root directory object ID.
/// * `base` - Base directory object ID.
/// * `path` - Path byte slice.
/// * `follow_last` - Whether to resolve trailing symlink.
///
/// # Returns
/// Resolved object ID on success.
///
/// # Errors
/// Returns negative Linux error code on resolution failure.
pub fn resolve_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    resolve_in_dirs(s, root, base, path, follow_last, &mut Vec::new())
}

/// Whether directory `dir` is searchable by everyone (all three `x` bits: Linux
/// applies only the owner's bits to the owner, and the group's to members).
fn searchable_by_all(s: &mut ZfsServer, dir: u64) -> bool {
    s.getattr(dir).map_or(false, |a| a.mode & 0o111 == 0o111)
}

/// [`resolve_in`], also collecting in `dirs` each directory looked up into that is
/// not searchable by everyone: the kernel checks the caller's search (`x`)
/// permission on those (it knows the caller, its groups and the ACLs).
pub fn resolve_in_dirs(s: &mut ZfsServer, root: u64, base: u64, path: &[u8], follow_last: bool, dirs: &mut Vec<u64>) -> Result<u64, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let follow_last = follow_last || path.ends_with(b"/");
    let mut cur = if path[0] == b'/' { root } else { base };
    let mut pending: Vec<Vec<u8>> = components(path);
    pending.reverse();
    let mut links = 0;
    let note = |s: &mut ZfsServer, dir: u64, dirs: &mut Vec<u64>| {
        if !dirs.contains(&dir) && !searchable_by_all(s, dir) {
            dirs.push(dir);
        }
    };
    while let Some(comp) = pending.pop() {
        if comp == b".." {
            if cur != root {
                note(s, cur, dirs);
            }
            cur = if cur == root { root } else { s.lookup(cur, b"..")? };
            continue;
        }
        note(s, cur, dirs);
        let next = s.lookup(cur, &comp)?;
        let is_last = pending.is_empty();
        let attr = s.getattr(next)?;
        if attr.kind() == DnodeType::Symlink && (!is_last || follow_last) {
            links += 1;
            if links > SYMLOOP_MAX {
                return Err(ELOOP);
            }
            let target = s.readlink(next)?;
            if target.first() == Some(&b'/') {
                cur = root;
            }
            let mut more = components(&target);
            more.reverse();
            pending.extend(more);
            continue;
        }
        if !is_last && !attr.is_dir() {
            return Err(ENOTDIR);
        }
        cur = next;
    }
    if path.ends_with(b"/") && !s.getattr(cur)?.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(cur)
}

/// Resolves `path` like [`resolve_in`] through a mount table. Mount `i` (1-based) is
/// `(mountpoint, mounted root, parent mount)`: a directory reached inside the parent
/// mount that is its mount point continues in the mounted tree (the topmost mount
/// wins), and `..` from a mounted tree's root leaves the mount. `root_mnt` and
/// `base_mnt` are the mounts the root and the starting directory lie in (0 = none).
///
/// A mounted root with bit 62 set is a FUSE file system's (the kernel serves it): the
/// walk stops on entering it and returns the rest of the path.
///
/// # Returns
/// The object ID and the mount it lies in, and the rest of the path if the walk
/// stopped at a FUSE mount.
#[allow(clippy::too_many_arguments)]
pub fn resolve_mnt(
    s: &mut ZfsServer,
    root: u64,
    root_mnt: usize,
    base: u64,
    base_mnt: usize,
    path: &[u8],
    follow_last: bool,
    mounts: &[(u64, u64, usize)],
) -> Result<(u64, usize, Option<Vec<u8>>), i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let enter = |mut ino: u64, mut mnt: usize| {
        for _ in 0..=mounts.len() {
            match mounts.iter().rposition(|m| m.0 == ino && m.2 == mnt) {
                Some(i) => {
                    ino = mounts[i].1;
                    mnt = i + 1;
                }
                None => break,
            }
        }
        (ino, mnt)
    };
    let follow_last = follow_last || path.ends_with(b"/");
    let (mut cur, mut mnt) = if path[0] == b'/' { (root, root_mnt) } else { (base, base_mnt) };
    let mut pending: Vec<Vec<u8>> = components(path);
    pending.reverse();
    let mut links = 0;
    while let Some(comp) = pending.pop() {
        if comp == b".." {
            for _ in 0..=mounts.len() {
                if (cur, mnt) == (root, root_mnt) || mnt == 0 || mounts[mnt - 1].1 != cur {
                    break;
                }
                let m = mounts[mnt - 1];
                cur = m.0;
                mnt = m.2;
            }
            if (cur, mnt) != (root, root_mnt) {
                cur = s.lookup(cur, b"..")?;
            }
            continue;
        }
        let next = s.lookup(cur, &comp)?;
        let is_last = pending.is_empty();
        let attr = s.getattr(next)?;
        if attr.kind() == DnodeType::Symlink && (!is_last || follow_last) {
            links += 1;
            if links > SYMLOOP_MAX {
                return Err(ELOOP);
            }
            let target = s.readlink(next)?;
            if target.first() == Some(&b'/') {
                cur = root;
                mnt = root_mnt;
            }
            let mut more = components(&target);
            more.reverse();
            pending.extend(more);
            continue;
        }
        if !is_last && !attr.is_dir() {
            return Err(ENOTDIR);
        }
        let (n, m) = enter(next, mnt);
        if n >> 62 == 1 {
            // A FUSE mount: the kernel walks the rest
            let mut rest = Vec::new();
            for c in pending.iter().rev() {
                if !rest.is_empty() {
                    rest.push(b'/');
                }
                rest.extend_from_slice(c);
            }
            return Ok((n, m, Some(rest)));
        }
        cur = n;
        mnt = m;
    }
    if path.ends_with(b"/") && !s.getattr(cur)?.is_dir() {
        return Err(ENOTDIR);
    }
    Ok((cur, mnt, None))
}

/// Resolves the parent directory of `path` and returns it with the last component.
///
/// # Arguments
/// * `s` - Active ZFS server.
/// * `base` - Base directory object ID.
/// * `path` - Path byte slice.
///
/// # Returns
/// Tuple of `(parent_object_id, component_name)` on success.
///
/// # Errors
/// Returns negative Linux error code on resolution failure.
pub fn resolve_parent_at(s: &mut ZfsServer, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
    let root = s.root_obj();
    let trimmed = {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        &path[..end]
    };
    let (dir_part, name) = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(i) => (&trimmed[..i.max(1)], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if name.is_empty() || name == b"/" {
        return Err(EEXIST);
    }
    let dir_path: &[u8] = if dir_part.is_empty() { b"/" } else { dir_part };
    let parent = if dir_path == b"." { base } else { resolve_in(s, root, base, dir_path, true)? };
    Ok((parent, name.to_vec()))
}
