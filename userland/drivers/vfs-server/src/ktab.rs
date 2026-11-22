//! # The mount changes vfs-server decides (wave 8, Group F)
//!
//! `mount`, `umount2` and `pivot_root` of a program in a mount namespace of its own, on a
//! namespace's whole table as the kernel keeps it ([`MntTable`], `compat/linux/mntrec.rs`):
//! [`crate::mountcalls`] reads the table (`LX_FH_MNTGET`), locates the paths with the walk,
//! calls the functions here and writes the table back (`LX_FH_MNTPUT`, compare and set).
//! The rules are the kernel's (`compat/linux/mount.rs`, kept there as the switch back), so
//! both copies of the code make the same tables: binds (with `MS_REC` the submounts),
//! tmpfs, named file systems (proc, devpts, cgroup2, mqueue, ...: listed, their files served
//! by name), `MS_REMOUNT`, `MS_MOVE`, propagation flags (listed only), `umount2` with
//! `MNT_DETACH`, `pivot_root`.
//!
//! Plain Rust (no system calls): what needs the system (whether an object is a directory, a
//! new tmpfs tree) comes through [`Env`]. Host-tested in `tests/host-w8-f`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::mntrec::{MntRec, MntTable, MK_NAMED, MK_TREE};

pub const EPERM: i64 = -1;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EINVAL: i64 = -22;
/// "The kernel answers this call" (what the calls answer with the redirect to the kernel).
pub const KERNEL: i64 = i64::MIN;

pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_REMOUNT: u64 = 32;
pub const MS_NOSYMFOLLOW: u64 = 256;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
pub const MS_RELATIME: u64 = 1 << 21;
/// The flags kept per mount.
pub const PER_MOUNT: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW | MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
/// The propagation flags.
pub const PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

pub const MNT_FORCE: u64 = 1;
pub const MNT_DETACH: u64 = 2;
pub const MNT_EXPIRE: u64 = 4;
pub const UMOUNT_NOFOLLOW: u64 = 8;

/// A located path: its absolute path in the namespace (lexical, as the kernel's), the
/// object and its mount (0, 0: not found, for the calls that accept a mount point that
/// does not resolve).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Loc {
    pub path: String,
    pub ino: u64,
    pub mnt: u32,
    /// Whether the object is a directory.
    pub is_dir: bool,
}

/// What the changes need from the system.
pub trait Env {
    /// A new tmpfs tree (root mode, owner): `(tmpfs id, root object)`.
    fn make_tmpfs(&mut self, mode: u32, uid: u32, gid: u32) -> Result<(u32, u64), i64>;
}

/// What a change did that the caller completes: after a `pivot_root`, the processes of the
/// namespace rooted (or working) at `old_root` move to `(new_root, new_mnt)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Done {
    pub pivot: Option<(u64, u64, u32)>,
}

/// Whether `fs` is a FUSE type (the kernel's: it is the FUSE client).
pub fn is_fuse_type(fs: &str) -> bool {
    fs == "fuse" || fs.starts_with("fuse.")
}

/// Normalizes an absolute path lexically (`.`, `..`, repeated `/`), as the kernel does.
pub fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        let mut s = String::new();
        for c in parts {
            s.push('/');
            s.push_str(c);
        }
        s
    }
}

/// Paths below `prefix` (or `prefix` itself) rewritten under `to`.
pub fn rebase(path: &str, prefix: &str, to: &str) -> Option<String> {
    let rest = if prefix == "/" {
        path.trim_start_matches('/')
    } else if path == prefix {
        ""
    } else {
        path.strip_prefix(prefix)?.strip_prefix('/')?
    };
    let mut j = String::from(to);
    j.push('/');
    j.push_str(rest);
    Some(normalize(&j))
}

/// Where Hydra serves the files of a named file system type.
pub fn serves_of(fstype: &str) -> Option<&'static str> {
    match fstype {
        "proc" => Some("/proc"),
        "devpts" => Some("/dev/pts"),
        "cgroup2" | "cgroup" => Some("/sys/fs/cgroup"),
        _ => None,
    }
}

/// The named file system types (listed; their files served by name).
fn named_type(fs: &str) -> bool {
    matches!(fs, "proc" | "devpts" | "cgroup2" | "cgroup" | "mqueue" | "binfmt_misc" | "debugfs" | "tracefs" | "securityfs" | "pstore" | "bpf" | "fusectl" | "configfs")
}

/// `mode=`, `uid=`, `gid=` of tmpfs mount data; the root belongs to `(euid, egid)` unless
/// they say otherwise, as on Linux.
pub fn tmpfs_options(data: Option<&str>, euid: u32, egid: u32) -> (u32, u32, u32) {
    let (mut mode, mut uid, mut gid) = (0o1777, euid, egid);
    if let Some(raw) = data {
        for opt in raw.split(',') {
            if let Some(v) = opt.strip_prefix("mode=") {
                mode = u32::from_str_radix(v, 8).unwrap_or(mode) & 0o7777;
            } else if let Some(v) = opt.strip_prefix("uid=") {
                uid = v.parse().unwrap_or(uid);
            } else if let Some(v) = opt.strip_prefix("gid=") {
                gid = v.parse().unwrap_or(gid);
            }
        }
    }
    (mode, uid, gid)
}

/// The mount whose mount point the located `at` is: a tree mount by its root, a named one
/// by its path (the latest).
pub fn mount_at(t: &MntTable, at: &Loc) -> Option<u32> {
    if t.get(at.mnt).is_some_and(|m| m.root == at.ino) {
        return Some(at.mnt);
    }
    t.slots.iter().rposition(|m| m.as_ref().is_some_and(|m| m.kind == MK_NAMED && m.path == at.path)).map(|i| i as u32 + 1)
}

/// Whether a `mount` with `flags` accepts a target that does not resolve (a remount or a
/// propagation change of a named mount point).
pub fn lenient(flags: u64) -> bool {
    flags & (MS_REMOUNT | PROPAGATION) != 0 && flags & (MS_BIND | MS_MOVE) == 0 || flags & MS_REMOUNT != 0
}

/// A new mount (id 0: the kernel gives it the next id when the table is written).
fn new_mount(parent: u32, at: &Loc, root: u64, kind: u32, tmpfs: u32, flags: u64, fstype: &str, source: &str, serves: Option<&str>) -> MntRec {
    MntRec {
        id: 0,
        parent,
        kind,
        tmpfs,
        mountpoint: at.ino,
        root,
        flags,
        propagation: 0,
        fstype: String::from(fstype),
        source: String::from(source),
        path: at.path.clone(),
        serves: serves.map(String::from),
    }
}

/// `mount(2)` on located arguments (the kernel's `mount_core`): `src` the located source of
/// a bind or move (`Err` as located: `EFAULT` when there was none), `target`, file system
/// type `fs`, `source_name` the source string as given, `data` the options, `(euid, egid)`
/// the caller's (tmpfs owner). [`KERNEL`] for what stays the kernel's (sysfs and devtmpfs
/// binds of the system's trees, a bind of something served by name).
#[allow(clippy::too_many_arguments)]
pub fn mount(t: &mut MntTable, src: Result<&Loc, i64>, target: &Loc, fs: Option<&str>, source_name: Option<&str>, flags: u64, data: Option<&str>, ids: (u32, u32), env: &mut dyn Env) -> Result<Done, i64> {
    let per = flags & PER_MOUNT;
    // Propagation changes alone: recorded, never acted on (no propagation between namespaces)
    if flags & PROPAGATION != 0 && flags & (MS_BIND | MS_MOVE | MS_REMOUNT) == 0 {
        let at = mount_at(t, target).unwrap_or(target.mnt);
        let targets = if flags & MS_REC != 0 { t.subtree(at) } else { alloc::vec![at] };
        for i in targets {
            if let Some(m) = t.get_mut(i) {
                m.propagation = flags & PROPAGATION;
            }
        }
        return Ok(Done::default());
    }
    if flags & MS_REMOUNT != 0 {
        let idx = mount_at(t, target).ok_or(EINVAL)?;
        if let Some(m) = t.get_mut(idx) {
            m.flags = per;
        }
        return Ok(Done::default());
    }
    if flags & MS_MOVE != 0 {
        let s = src?;
        if t.get(s.mnt).map_or(true, |m| m.root != s.ino) || s.mnt == t.root {
            return Err(EINVAL);
        }
        let moved = t.subtree(s.mnt);
        if moved.contains(&target.mnt) {
            return Err(EINVAL); // into itself
        }
        for i in moved {
            if let Some(m) = t.get_mut(i) {
                if let Some(p) = rebase(&m.path, &s.path, &target.path) {
                    m.path = p;
                }
            }
        }
        if let Some(m) = t.get_mut(s.mnt) {
            m.mountpoint = target.ino;
            m.parent = target.mnt;
        }
        return Ok(Done::default());
    }
    if flags & MS_BIND != 0 {
        let s = src?;
        if s.is_dir != target.is_dir {
            return Err(ENOTDIR);
        }
        let from = t.get(s.mnt).cloned().ok_or(EINVAL)?;
        let tmpfs = if from.kind == MK_TREE { from.tmpfs } else { 0 };
        let new = t.push(new_mount(target.mnt, target, s.ino, MK_TREE, tmpfs, per, &from.fstype, &from.source, None));
        if flags & MS_REC != 0 {
            // The source's submounts, under the new mount at the same places
            let below: Vec<u32> = t.subtree(s.mnt).into_iter().filter(|i| *i != s.mnt).collect();
            let mut map: Vec<(u32, u32)> = alloc::vec![(s.mnt, new)];
            for i in below {
                let Some(m) = t.get(i).cloned() else { continue };
                let parent = map.iter().find(|(a, _)| *a == m.parent).map(|(_, b)| *b);
                let (Some(parent), Some(path)) = (parent, rebase(&m.path, &s.path, &target.path)) else { continue };
                let copy = t.push(MntRec { id: 0, parent, path, propagation: 0, ..m });
                map.push((i, copy));
            }
        }
        return Ok(Done::default());
    }
    if !target.is_dir {
        return Err(ENOTDIR);
    }
    let fs = fs.ok_or(EFAULT)?;
    let source_name = source_name.unwrap_or(fs);
    match fs {
        "tmpfs" | "ramfs" => {
            let (mode, uid, gid) = tmpfs_options(data, ids.0, ids.1);
            let (n, root) = env.make_tmpfs(mode, uid, gid)?;
            t.push(new_mount(target.mnt, target, root, MK_TREE, n, per, fs, source_name, None));
        }
        // (binds of the system's `/sys` and `/dev`: the kernel's, it walks the system root)
        "sysfs" | "devtmpfs" => return Err(KERNEL),
        f if named_type(f) => {
            t.push(new_mount(target.mnt, target, 0, MK_NAMED, 0, per, fs, source_name, serves_of(fs)));
        }
        _ => return Err(ENODEV),
    }
    Ok(Done::default())
}

/// `umount2(2)` on the located target (flags checked by the caller).
pub fn umount(t: &mut MntTable, target: &Loc, flags: u64) -> Result<Done, i64> {
    let idx = mount_at(t, target).filter(|i| *i != t.root).ok_or(EINVAL)?;
    let gone = t.subtree(idx);
    if gone.len() > 1 && flags & MNT_DETACH == 0 {
        return Err(EBUSY);
    }
    for i in gone {
        if let Some(s) = t.slots.get_mut(i as usize - 1) {
            *s = None;
        }
    }
    Ok(Done::default())
}

/// `pivot_root(2)` on located arguments: `new_root` (a mount) becomes the root, the old root
/// moves to `put_old`.
pub fn pivot_root(t: &mut MntTable, new_root: &Loc, put_old: &Loc) -> Result<Done, i64> {
    let old = t.root;
    let old_root = t.get(old).map(|m| m.root).ok_or(EINVAL)?;
    if t.get(new_root.mnt).map_or(true, |m| m.root != new_root.ino) || new_root.mnt == old {
        return Err(EINVAL); // new_root must be a mount, not the current root
    }
    let put_rel = rebase(&put_old.path, &new_root.path, "/").ok_or(EINVAL)?;
    for (i, slot) in t.slots.iter_mut().enumerate() {
        let Some(m) = slot else { continue };
        if i as u32 + 1 == old {
            continue;
        }
        m.path = match rebase(&m.path, &new_root.path, "/") {
            Some(p) => p,
            None => {
                let mut j = put_rel.clone();
                j.push('/');
                j.push_str(&m.path);
                normalize(&j)
            }
        };
    }
    if let Some(m) = t.get_mut(old) {
        m.mountpoint = put_old.ino;
        m.parent = put_old.mnt;
        m.path = put_rel;
    }
    if let Some(m) = t.get_mut(new_root.mnt) {
        m.mountpoint = 0;
        m.parent = 0;
        m.path = String::from("/");
    }
    t.root = new_root.mnt;
    Ok(Done { pivot: Some((old_root, new_root.ino, new_root.mnt)) })
}
