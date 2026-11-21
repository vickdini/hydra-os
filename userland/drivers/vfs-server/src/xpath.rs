//! # The path a program runs under (wave 7, Group 7-5)
//!
//! Linux's `/proc/<pid>/exe` names the file a program was started from with every symbolic
//! link resolved and `.`/`..` removed: `/usr/bin/firefox`, a link to `../lib/firefox/firefox`,
//! runs as `/usr/lib/firefox/firefox` (Firefox's launcher starts its helpers from the
//! directory `/proc/self/exe` names). [`real_path`] is the kernel's `execve.rs` `real_path`
//! over the walk's [`Backend`], for `execve`'s front half (`LX_VFS_OP_EXEC`). Pure: host
//! tests in `tests/host-w7-41`.

use alloc::vec::Vec;

use crate::ctx::Node;
use crate::fs::types::{S_IFLNK, S_IFMT};
use crate::walk::Backend;

/// Most symbolic links followed (as the kernel's copy).
const LINKS_MAX: u32 = 40;

/// Whether `abs` lies in a tree the Linux services serve by name (`/proc`, `/sys`, `/dev`).
pub fn served_by_name(abs: &[u8]) -> bool {
    [&b"/proc"[..], b"/sys", b"/dev"].iter().any(|d| abs.strip_prefix(*d).is_some_and(|r| r.is_empty() || r[0] == b'/'))
}

/// The absolute path `abs` with every symbolic link in it resolved and `.`/`..` removed,
/// walked from `root` without permission checks (the kernel's rule).
///
/// # Returns
/// `None` when `abs` is not absolute, lies in `/proc`, `/sys` or `/dev`, has no symbolic
/// link in it, a step fails, or the walk does not end at object `ino` (the lexical path is
/// kept then).
pub fn real_path(be: &dyn Backend, root: Node, abs: &[u8], ino: u64) -> Option<Vec<u8>> {
    if abs.first() != Some(&b'/') || served_by_name(abs) {
        return None;
    }
    // Components still to walk, the last one on top
    let mut todo: Vec<Vec<u8>> = abs.split(|&b| b == b'/').rev().filter(|c| !c.is_empty()).map(|c| c.to_vec()).collect();
    // The canonical path so far, with the node of each component
    let mut out: Vec<(Vec<u8>, Node)> = Vec::new();
    let mut links = 0;
    while let Some(c) = todo.pop() {
        match c.as_slice() {
            b"." => continue,
            b".." => {
                out.pop();
                continue;
            }
            _ => {}
        }
        let dir = out.last().map_or(root, |&(_, n)| n);
        let next = be.lookup(dir, &c).ok()?;
        if be.getattr(next).ok()?.mode & S_IFMT == S_IFLNK {
            links += 1;
            if links > LINKS_MAX {
                return None;
            }
            let target = be.readlink(next).ok()?;
            if target.first() == Some(&b'/') {
                out.clear();
            }
            todo.extend(target.split(|&b| b == b'/').rev().filter(|c| !c.is_empty()).map(|c| c.to_vec()));
            continue;
        }
        out.push((c, next));
    }
    if links == 0 || out.last().map(|&(_, n)| n.ino) != Some(ino) {
        return None;
    }
    let mut p = Vec::new();
    for (name, _) in &out {
        p.push(b'/');
        p.extend_from_slice(name);
    }
    Some(p)
}
