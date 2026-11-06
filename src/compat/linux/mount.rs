//! # Mounts and mount namespaces
//!
//! The initial mount namespace is Hydra's fixed layout: the pool, with `/proc`, `/dev/pts`
//! and `/sys/fs/cgroup` served by name ([`super::fs::match_pseudo_path`]). A process that
//! creates a new mount namespace (`unshare`/`clone` with `CLONE_NEWNS`) gets a mount table
//! of its own, starting with its root and the standard pseudo file systems, and can change
//! it with `mount`, `umount2` and `pivot_root`:
//!
//! - **Bind mounts** (`MS_BIND`, with `MS_REC` the submounts too) and **tmpfs** (a fresh
//!   hidden directory of the pool, removed when its last mount goes) are trees of the pool:
//!   path lookups go through the mount table in the file server ([`ZfsServer::resolve_mnt`]),
//!   so symbolic links and `..` cross mounts as on Linux.
//! - **proc, devpts, cgroup2, mqueue** mounts are recorded (and listed); their files are
//!   served by name, so they appear where Linux puts them (`/proc`, `/dev/pts`, ...).
//!   **sysfs** and **devtmpfs** are binds of the system's `/sys` and `/dev`.
//! - Per-mount `MS_RDONLY` (`EROFS` for writes), `MS_NOEXEC` and `MS_NOSUID` are enforced;
//!   `MS_REMOUNT` changes them; `MS_MOVE` moves a mount; `pivot_root` swaps the root.
//! - Propagation flags (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`) are accepted
//!   and listed, but mounts never propagate between namespaces (as if all were private).
//!
//! Not yet: overlayfs and other file system types, the new mount API (`fsopen`...).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::fs::ZfsClient;

const EPERM: i64 = -1;
const EBUSY: i64 = -16;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EROFS: i64 = -30;
const ENODEV: i64 = -19;
const EFAULT: i64 = -14;

const MS_RDONLY: u64 = 1;
const MS_NOSUID: u64 = 2;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_REMOUNT: u64 = 32;
const MS_NOSYMFOLLOW: u64 = 256;
const MS_NOATIME: u64 = 1024;
const MS_NODIRATIME: u64 = 2048;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_REC: u64 = 16384;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_RELATIME: u64 = 1 << 21;
/// The flags kept per mount.
const PER_MOUNT: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW | MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
const PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

const MNT_DETACH: u64 = 2;
const UMOUNT_NOFOLLOW: u64 = 8;

/// `CAP_SYS_ADMIN`, needed in the caller's user namespace.
const CAP_SYS_ADMIN: u64 = 1 << 21;
/// Hidden pool directory holding the trees of tmpfs mounts.
const TMPFS_DIR: &[u8] = b".hydra-tmpfs";

/// What a mount is.
#[derive(Clone, PartialEq)]
enum Kind {
    /// A tree of the pool: a bind mount, the namespace root or a tmpfs (with its backing id).
    Tree { tmpfs: Option<u32> },
    /// A file system served by name (proc, devpts, cgroup2, mqueue): listed only.
    Named,
}

/// One mount.
#[derive(Clone)]
struct Mount {
    /// Mount ID (`mountinfo`).
    id: u32,
    /// Index of the parent mount in the table, 1-based (0: none, the root).
    parent: usize,
    /// Directory mounted on (in the parent's tree).
    mountpoint: u64,
    /// Root of the mounted tree.
    root: u64,
    kind: Kind,
    flags: u64,
    propagation: u64,
    fstype: String,
    source: String,
    /// Mount point path in the namespace (from its root).
    path: String,
    /// For a named mount: the path Hydra serves its files at (`/proc` for proc, `/dev/null`
    /// for a bind of that device...); `None` when it is shown where it is.
    serves: Option<String>,
}

/// A mount namespace's table. Slots are never reused (mount indices stay valid).
struct MountNs {
    mounts: Vec<Option<Mount>>,
    /// The root mount (1-based).
    root: usize,
    /// The system root (`/` of the initial namespace as this namespace's first process saw
    /// it), for sysfs and devtmpfs mounts.
    system_root: u64,
}

impl MountNs {
    fn get(&self, i: usize) -> Option<&Mount> {
        self.mounts.get(i.wrapping_sub(1)).and_then(|m| m.as_ref())
    }

    /// `(mountpoint, root, parent)` for every tree mount, by index (named ones are holes).
    fn server_list(&self) -> Vec<(u64, u64, usize)> {
        self.mounts
            .iter()
            .map(|m| match m {
                Some(m) if m.kind != Kind::Named => (m.mountpoint, m.root, m.parent),
                _ => (u64::MAX, u64::MAX, usize::MAX),
            })
            .collect()
    }

    fn push(&mut self, m: Mount) -> usize {
        self.mounts.push(Some(m));
        self.mounts.len()
    }

    /// Indices of `i` and every mount below it.
    fn subtree(&self, i: usize) -> Vec<usize> {
        let mut out = alloc::vec![i];
        let mut k = 0;
        while k < out.len() {
            let p = out[k];
            for (j, m) in self.mounts.iter().enumerate() {
                if m.as_ref().is_some_and(|m| m.parent == p) && !out.contains(&(j + 1)) {
                    out.push(j + 1);
                }
            }
            k += 1;
        }
        out
    }
}

/// Holds (`take`) or lets go of the pool objects at the roots of tree mounts: a mounted
/// file stays alive while mounted even after it is deleted and closed (bubblewrap binds
/// such files), as on Linux. Called outside the table locks (it talks to the file server).
fn hold_roots(roots: &[u64], take: bool) {
    for &r in roots {
        if r != 0 && r != u64::MAX {
            if take {
                ZfsClient::open_ref(r);
            } else {
                ZfsClient::release(r);
            }
        }
    }
}

/// The roots of the tree mounts of a table.
fn tree_roots<'a>(mounts: impl Iterator<Item = &'a Mount>) -> Vec<u64> {
    mounts.filter(|m| matches!(m.kind, Kind::Tree { .. })).map(|m| m.root).collect()
}

/// Mount namespaces by namespace id ([`super::ns::Ns::mnt`]).
static NAMESPACES: Mutex<BTreeMap<u64, Arc<Mutex<MountNs>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(100);
static NEXT_TMPFS: AtomicU32 = AtomicU32::new(1);
/// The tmpfs directory has been emptied of a previous boot's trees.
static TMPFS_CLEAN: AtomicBool = AtomicBool::new(false);
/// Per thread: the mount the next lookup starts in (`base_dir`), and the mount and table
/// of the last one, for the write, exec and statfs checks.
static NOTES: Mutex<BTreeMap<u64, (usize, usize, u64)>> = Mutex::new(BTreeMap::new());

fn new_id() -> u32 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn tid() -> u64 {
    super::proc::current_ids().0
}

/// The calling process's mount namespace id (0: the initial one).
fn current_ns_id() -> u64 {
    let (_, pid) = super::proc::current_ids();
    super::proc::PROCS.lock().get(&pid).map_or(0, |p| p.ns.mnt)
}

fn table(id: u64) -> Option<Arc<Mutex<MountNs>>> {
    NAMESPACES.lock().get(&id).cloned()
}

/// Records the mount a lookup from a directory descriptor (or the working directory)
/// starts in.
pub fn note_base(mnt: usize) {
    NOTES.lock().entry(tid()).or_insert((0, 0, 0)).0 = mnt;
}

/// The mount of the last lookup of the calling thread (for a new descriptor, `chdir`).
pub fn last_mount() -> usize {
    NOTES.lock().get(&tid()).map_or(0, |n| n.1)
}

/// Forgets a thread's notes (it exited).
pub fn forget_thread(tid: u64) {
    NOTES.lock().remove(&tid);
}

/// Resolves `path` from `base` through the caller's mount table, if it has one.
///
/// # Returns
/// `None` in the initial namespace (the caller resolves as before), otherwise the result.
pub fn resolve(base: u64, path: &[u8], follow: bool) -> Option<Result<u64, i64>> {
    let id = current_ns_id();
    if id == 0 {
        return None;
    }
    let ns = table(id)?;
    let (root, root_mnt, cwd, cwd_mnt) = crate::task::with_current_fds_mut(|f| (f.root_ino, f.root_mnt, f.cwd_ino, f.cwd_mnt));
    let (list, ns_root) = {
        let t = ns.lock();
        (t.server_list(), t.get(t.root).map_or(0, |m| m.root))
    };
    let root = if root == 0 { ns_root } else { root };
    let root_mnt = if root_mnt == 0 { ns.lock().root } else { root_mnt };
    let noted = NOTES.lock().get(&tid()).map_or(0, |n| n.0);
    let base_mnt = if base == 0 || base == root {
        root_mnt
    } else if base == cwd && cwd_mnt != 0 {
        cwd_mnt
    } else {
        noted
    };
    let base = if base == 0 { root } else { base };
    let r = crate::fs::zfs::with_server(|s| s.resolve_mnt(root, root_mnt, base, base_mnt, path, follow, &list));
    Some(r.map(|(ino, mnt)| {
        NOTES.lock().insert(tid(), (0, mnt, id));
        ino
    }))
}

/// Resolves the parent directory of `path` through the caller's mount table, if it has one.
///
/// # Returns
/// `None` in the initial namespace, otherwise `(parent, name)` or an errno.
pub fn resolve_parent(base: u64, path: &[u8]) -> Option<Result<(u64, Vec<u8>), i64>> {
    if current_ns_id() == 0 {
        return None;
    }
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    let (dir, name) = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(i) => (&trimmed[..i.max(1)], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if name.is_empty() || name == b"/" || name == b"." || name == b".." {
        return Some(Err(-17)); // EEXIST, as the file server answers
    }
    Some(resolve(base, dir, true)?.map(|ino| (ino, name.to_vec())))
}

/// The flags of the mount the calling thread's last lookup ended in.
fn last_flags() -> u64 {
    let Some((_, mnt, id)) = NOTES.lock().get(&tid()).copied() else { return 0 };
    if id == 0 || id != current_ns_id() {
        return 0;
    }
    table(id).and_then(|t| t.lock().get(mnt).map(|m| m.flags)).unwrap_or(0)
}

/// `0`, or `-EROFS` if the last lookup ended in a read-only mount (call after resolving
/// what a write changes).
pub fn check_write() -> i64 {
    if last_flags() & MS_RDONLY != 0 { EROFS } else { 0 }
}

/// `(noexec, nosuid)` of the mount the last lookup ended in (for `execve`).
pub fn exec_flags() -> (bool, bool) {
    let f = last_flags();
    (f & MS_NOEXEC != 0, f & MS_NOSUID != 0)
}

/// Whether the last lookup ended in a tmpfs (for `statfs`).
pub fn last_is_tmpfs() -> bool {
    let Some((_, mnt, id)) = NOTES.lock().get(&tid()).copied() else { return false };
    id != 0 && table(id).and_then(|t| t.lock().get(mnt).map(|m| matches!(m.kind, Kind::Tree { tmpfs: Some(_) }))).unwrap_or(false)
}

/// Where Hydra serves the files of a named file system type.
fn serves_of(fstype: &str) -> Option<&'static str> {
    match fstype {
        "proc" => Some("/proc"),
        "devpts" => Some("/dev/pts"),
        "cgroup2" | "cgroup" => Some("/sys/fs/cgroup"),
        _ => None,
    }
}

/// The standard table of a new namespace made from the initial one: the caller's root and
/// the file systems Hydra serves, listed where they are.
fn initial_table(root: u64) -> MountNs {
    let lookup = |p: &[u8]| ZfsClient::resolve_in(root, root, p, true).unwrap_or(0);
    let mut ns = MountNs { mounts: Vec::new(), root: 1, system_root: root };
    ns.push(Mount {
        id: new_id(),
        parent: 0,
        mountpoint: 0,
        root,
        kind: Kind::Tree { tmpfs: None },
        flags: MS_RELATIME,
        propagation: MS_SHARED,
        fstype: String::from("zfs"),
        source: String::from("hydrapool/root"),
        path: String::from("/"),
        serves: None,
    });
    for (path, fstype, source, parent) in [
        ("/proc", "proc", "proc", 1),
        ("/sys", "sysfs", "sysfs", 1),
        ("/sys/fs/cgroup", "cgroup2", "cgroup2", 3),
        ("/dev", "devtmpfs", "udev", 1),
        ("/dev/pts", "devpts", "devpts", 5),
        ("/run", "tmpfs", "tmpfs", 1),
    ] {
        ns.push(Mount {
            id: new_id(),
            parent,
            mountpoint: lookup(path.as_bytes()),
            root: 0,
            kind: Kind::Named,
            flags: MS_NOSUID | MS_NOEXEC | MS_RELATIME,
            propagation: MS_SHARED,
            fstype: String::from(fstype),
            source: String::from(source),
            path: String::from(path),
            serves: serves_of(fstype).map(String::from),
        });
    }
    ns
}

/// Gives the calling process's new mount namespace `new_id` a copy of namespace `from`'s
/// table (or the standard table if `from` is the initial namespace), and points the
/// process's root and working directory at its mounts.
///
/// # Arguments
/// * `from` - The namespace being copied.
/// * `ns_id` - The new namespace's id.
/// * `fds` - The descriptor table (root, working directory) of the process moving.
pub fn copy_ns(from: u64, ns_id: u64, fds: &crate::fs::SharedFdTable) {
    let (root, cwd) = {
        let f = fds.lock();
        (f.root_ino, f.cwd_ino)
    };
    let root = if root == 0 { ZfsClient::root_ino() } else { root };
    let copy = match table(from) {
        Some(t) => {
            let t = t.lock();
            MountNs {
                mounts: t.mounts.iter().map(|m| m.clone().map(|mut m| {
                    m.id = new_id();
                    m
                })).collect(),
                root: t.root,
                system_root: t.system_root,
            }
        }
        None => initial_table(root),
    };
    let root_mnt = copy.root;
    let held = tree_roots(copy.mounts.iter().flatten());
    NAMESPACES.lock().insert(ns_id, Arc::new(Mutex::new(copy)));
    hold_roots(&held, true);
    let mut f = fds.lock();
    if from == 0 {
        f.root_mnt = root_mnt;
        if cwd == 0 || cwd == root {
            f.cwd_mnt = root_mnt;
        }
    }
}

/// Drops the tables of namespaces no live process uses, and the tmpfs trees only they held.
fn collect() {
    let live: Vec<u64> = super::proc::PROCS.lock().values().filter(|p| !p.zombie).map(|p| p.ns.mnt).collect();
    let dead: Vec<Arc<Mutex<MountNs>>> = {
        let mut all = NAMESPACES.lock();
        let ids: Vec<u64> = all.keys().copied().filter(|id| !live.contains(id)).collect();
        ids.into_iter().filter_map(|id| all.remove(&id)).collect()
    };
    for ns in dead {
        let held = tree_roots(ns.lock().mounts.iter().flatten());
        hold_roots(&held, false);
        let ids: Vec<u32> = ns.lock().mounts.iter().flatten().filter_map(|m| match m.kind {
            Kind::Tree { tmpfs: Some(t) } => Some(t),
            _ => None,
        }).collect();
        for t in ids {
            release_tmpfs(t);
        }
    }
}

/// Whether any namespace still has a mount of tmpfs `t`.
fn tmpfs_in_use(t: u32) -> bool {
    NAMESPACES.lock().values().any(|ns| ns.lock().mounts.iter().flatten().any(|m| m.kind == Kind::Tree { tmpfs: Some(t) }))
}

/// The pool directory holding tmpfs trees (made, and emptied of a previous boot's, on
/// first use).
fn tmpfs_dir() -> Result<u64, i64> {
    crate::fs::zfs::with_server(|s| {
        let root = s.root_obj();
        let dir = match s.lookup(root, TMPFS_DIR) {
            Ok(d) => d,
            Err(_) => s.mkdir(root, TMPFS_DIR, 0o700, 0, 0)?,
        };
        if !TMPFS_CLEAN.swap(true, Ordering::AcqRel) {
            let _ = remove_contents(s, dir, 0);
        }
        Ok(dir)
    })
}

/// Deletes everything in directory `dir` (depth-limited).
fn remove_contents(s: &mut crate::fs::zfs::ZfsServer, dir: u64, depth: u32) -> Result<(), i64> {
    if depth > 64 {
        return Ok(());
    }
    loop {
        let batch = s.readdir(dir, 2, 64)?;
        let entries: Vec<_> = batch.into_iter().filter(|e| e.name != b"." && e.name != b"..").collect();
        if entries.is_empty() {
            return Ok(());
        }
        for e in entries {
            if e.dtype == 4 {
                remove_contents(s, e.ino, depth + 1)?;
                s.rmdir(dir, &e.name)?;
            } else {
                s.unlink(dir, &e.name)?;
            }
        }
    }
}

/// Removes tmpfs `t`'s tree once no mount uses it.
fn release_tmpfs(t: u32) {
    if tmpfs_in_use(t) {
        return;
    }
    let name = alloc::format!("{}", t);
    let _ = crate::fs::zfs::with_server(|s| {
        let parent = s.lookup(s.root_obj(), TMPFS_DIR)?;
        let dir = s.lookup(parent, name.as_bytes())?;
        remove_contents(s, dir, 0)?;
        s.rmdir(parent, name.as_bytes())
    });
}

/// Parses `mode=`, `uid=` and `gid=` from tmpfs mount data. The root belongs to the
/// mounting process unless they say otherwise, as on Linux.
fn tmpfs_options(data: u64) -> (u32, u32, u32) {
    let (euid, egid) = crate::task::with_current_task_mut(|t| (t.euid, t.egid)).unwrap_or((0, 0));
    let (mut mode, mut uid, mut gid) = (0o1777, euid, egid);
    if data == 0 {
        return (mode, uid, gid);
    }
    if let Ok(raw) = super::vfs::user_path(data) {
        for opt in String::from_utf8_lossy(&raw).split(',') {
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

/// The absolute path (in the caller's view) and resolved `(inode, mount)` of a user path.
/// `/proc/self/fd/N` names what descriptor N is open on.
fn locate(ptr: u64, follow: bool) -> Result<(String, u64, usize), i64> {
    let path = super::vfs::user_path(ptr)?;
    let (base, base_path) = super::vfs::base_dir(-100, &path)?;
    let abs = normalize(&super::vfs::join_path_raw(&base_path, &path));
    if let Some((ino, mnt, p)) = super::vfs::magic_fd_target(&super::vfs::join_path(&base_path, &path)) {
        return Ok((normalize(&p), ino, mnt));
    }
    let ino = super::vfs::resolve(base, &path, follow)?;
    Ok((abs, ino, last_mount()))
}

/// The path Hydra serves a bind mount's source at, when it is a file served by name (such
/// as `/dev/null`, given by path or by an open `/proc/self/fd/N`).
fn served_source(ptr: u64) -> Option<String> {
    let path = super::vfs::user_path(ptr).ok()?;
    let (_, base_path) = super::vfs::base_dir(-100, &path).ok()?;
    let abs = super::vfs::join_path(&base_path, &path);
    let abs = super::vfs::open_file_path(&abs).unwrap_or(abs);
    super::vfs::served_by_name(&abs).then_some(abs)
}

/// Whether `raw` (a path as the caller wrote it) is the mount point of a named mount: the
/// mounted object is there itself, so it is not a link even when it shows a `/proc` link.
pub fn is_named_mountpoint(raw: &str) -> bool {
    let id = current_ns_id();
    if id == 0 {
        return false;
    }
    let Some(t) = table(id) else { return false };
    let t = t.lock();
    t.mounts.iter().flatten().any(|m| m.kind == Kind::Named && m.path == raw)
}

/// [`locate`] for a mount point that may be a named file system's (served by name, with no
/// directory in the pool): when the path does not resolve, inode and mount are 0.
fn locate_mountpoint(ptr: u64, follow: bool) -> Result<(String, u64, usize), i64> {
    match locate(ptr, follow) {
        Ok(v) => Ok(v),
        Err(e) if e == -2 || e == -20 => {
            let path = super::vfs::user_path(ptr)?;
            let (_, base_path) = super::vfs::base_dir(-100, &path)?;
            Ok((normalize(&super::vfs::join_path_raw(&base_path, &path)), 0, 0))
        }
        Err(e) => Err(e),
    }
}

/// The path Hydra serves `abs` by when a named mount of the caller's mount namespace (a
/// proc, devpts or cgroup2 mount, or a bind of a device Hydra serves by name) holds it, or a
/// devtmpfs mount holds one of those devices, somewhere else than where Hydra serves it.
///
/// # Returns
/// `None` when nothing changes (the initial namespace, or no such mount above `abs`).
pub fn canonical(abs: &str) -> Option<String> {
    let id = current_ns_id();
    if id == 0 {
        return None;
    }
    let t = table(id)?;
    let t = t.lock();
    // The deepest mount at or above the path (the latest on the same path): a mount on top
    // hides the named one beneath it
    let m = t
        .mounts
        .iter()
        .enumerate()
        .filter_map(|(i, m)| m.as_ref().map(|m| (i, m)))
        .filter(|(_, m)| rebase(abs, &m.path, "/").is_some())
        .max_by_key(|(i, m)| (m.path.len(), *i))
        .map(|(_, m)| m)?;
    if m.kind != Kind::Named {
        return None;
    }
    match (&m.serves, m.fstype.as_str()) {
        (Some(served), _) if *served != m.path => rebase(abs, &m.path, served),
        (None, "devtmpfs") if m.path != "/dev" => {
            // Only the devices Hydra serves by name; the others are files of the pool
            let candidate = rebase(abs, &m.path, "/dev")?;
            super::vfs::served_by_name(&candidate).then_some(candidate)
        }
        _ => None,
    }
}


/// Normalizes an absolute path lexically (`.`, `..`, repeated `/`).
fn normalize(p: &str) -> String {
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
    if parts.is_empty() { String::from("/") } else { alloc::format!("/{}", parts.join("/")) }
}

/// Paths below `prefix` (or `prefix` itself) rewritten under `to`.
fn rebase(path: &str, prefix: &str, to: &str) -> Option<String> {
    let rest = if prefix == "/" {
        path.trim_start_matches('/')
    } else if path == prefix {
        ""
    } else {
        path.strip_prefix(prefix)?.strip_prefix('/')?
    };
    Some(normalize(&alloc::format!("{}/{}", to, rest)))
}

/// The mount whose mount point `path` (resolved to `ino` in mount `mnt`) is: a tree mount
/// by its root, a named one (proc, devpts...) by its path.
fn mount_at(t: &MountNs, path: &str, ino: u64, mnt: usize) -> Option<usize> {
    if t.get(mnt).is_some_and(|m| m.root == ino) {
        return Some(mnt);
    }
    t.mounts.iter().rposition(|m| m.as_ref().is_some_and(|m| m.kind == Kind::Named && m.path == path)).map(|i| i + 1)
}

/// Whether the caller may change its mount namespace (`CAP_SYS_ADMIN`, in its user
/// namespace), and the namespace.
fn admin_ns() -> Result<Arc<Mutex<MountNs>>, i64> {
    if !crate::task::with_current_task_mut(|t| t.caps.effective & CAP_SYS_ADMIN != 0).unwrap_or(false) {
        return Err(EPERM);
    }
    let id = current_ns_id();
    // The initial namespace's layout is fixed
    if id == 0 {
        return Err(EPERM);
    }
    table(id).ok_or(EINVAL)
}

/// `mount(2)`.
fn mount(source: u64, target: u64, fstype: u64, flags: u64, data: u64) -> i64 {
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    collect();
    let lenient = flags & (MS_REMOUNT | PROPAGATION) != 0 && flags & (MS_BIND | MS_MOVE) == 0 || flags & MS_REMOUNT != 0;
    let found = if lenient { locate_mountpoint(target, true) } else { locate(target, true) };
    let (tpath, tino, tmnt) = match found {
        Ok(v) => v,
        Err(e) => return e,
    };
    let per = flags & PER_MOUNT;
    // Propagation changes (alone): recorded, never acted on (no propagation between
    // namespaces)
    if flags & PROPAGATION != 0 && flags & (MS_BIND | MS_MOVE | MS_REMOUNT) == 0 {
        let mut t = ns.lock();
        let at = mount_at(&t, &tpath, tino, tmnt).unwrap_or(tmnt);
        let targets = if flags & MS_REC != 0 { t.subtree(at) } else { alloc::vec![at] };
        for i in targets {
            if let Some(Some(m)) = t.mounts.get_mut(i.wrapping_sub(1)) {
                m.propagation = flags & PROPAGATION;
            }
        }
        return 0;
    }
    if flags & MS_REMOUNT != 0 {
        let mut t = ns.lock();
        let Some(idx) = mount_at(&t, &tpath, tino, tmnt) else { return EINVAL }; // not a mount point
        if let Some(Some(m)) = t.mounts.get_mut(idx - 1) {
            m.flags = per;
        }
        return 0;
    }
    if flags & MS_MOVE != 0 {
        let (spath, sino, smnt) = match locate(source, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut t = ns.lock();
        if t.get(smnt).map_or(true, |m| m.root != sino) || smnt == t.root {
            return EINVAL;
        }
        let moved = t.subtree(smnt);
        if moved.contains(&tmnt) {
            return EINVAL; // into itself
        }
        for i in moved {
            if let Some(Some(m)) = t.mounts.get_mut(i - 1) {
                if let Some(p) = rebase(&m.path, &spath, &tpath) {
                    m.path = p;
                }
            }
        }
        if let Some(Some(m)) = t.mounts.get_mut(smnt - 1) {
            m.mountpoint = tino;
            m.parent = tmnt;
        }
        return 0;
    }
    let attr = match ZfsClient::getattr(tino) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if flags & MS_BIND != 0 {
        // A device (or other file) Hydra serves by name: the target shows it
        if let Some(served) = served_source(source) {
            ns.lock().push(Mount {
                id: new_id(),
                parent: tmnt,
                mountpoint: tino,
                root: 0,
                kind: Kind::Named,
                flags: per,
                propagation: 0,
                fstype: String::from("devtmpfs"),
                source: String::from("udev"),
                path: tpath,
                serves: Some(served),
            });
            return 0;
        }
        let (spath, sino, smnt) = match locate(source, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if ZfsClient::getattr(sino).map(|a| a.is_dir()).unwrap_or(false) != attr.is_dir() {
            return ENOTDIR;
        }
        let mut t = ns.lock();
        let Some(src) = t.get(smnt).cloned() else { return EINVAL };
        let tmpfs = match src.kind {
            Kind::Tree { tmpfs } => tmpfs,
            Kind::Named => None,
        };
        let new = t.push(Mount {
            id: new_id(),
            parent: tmnt,
            mountpoint: tino,
            root: sino,
            kind: Kind::Tree { tmpfs },
            flags: per,
            propagation: 0,
            fstype: src.fstype.clone(),
            source: src.source.clone(),
            path: tpath.clone(),
            serves: None,
        });
        let mut held = alloc::vec![sino];
        if flags & MS_REC != 0 {
            // The source's submounts, under the new mount at the same places
            let below: Vec<usize> = t.subtree(smnt).into_iter().filter(|i| *i != smnt).collect();
            let mut map: BTreeMap<usize, usize> = BTreeMap::new();
            map.insert(smnt, new);
            for i in below {
                let Some(m) = t.get(i).cloned() else { continue };
                let (Some(&parent), Some(path)) = (map.get(&m.parent), rebase(&m.path, &spath, &tpath)) else { continue };
                if matches!(m.kind, Kind::Tree { .. }) {
                    held.push(m.root);
                }
                let copy = t.push(Mount { id: new_id(), parent, path, propagation: 0, ..m });
                map.insert(i, copy);
            }
        }
        drop(t);
        hold_roots(&held, true);
        return 0;
    }
    if !attr.is_dir() {
        return ENOTDIR;
    }
    let fs = match super::vfs::user_path(fstype) {
        Ok(f) => String::from_utf8_lossy(&f).into_owned(),
        Err(_) => return EFAULT,
    };
    let source_name = super::vfs::user_path(source).map(|s| String::from_utf8_lossy(&s).into_owned()).unwrap_or_else(|_| fs.clone());
    let system_root = ns.lock().system_root;
    let (kind, root) = match fs.as_str() {
        "tmpfs" | "ramfs" => {
            let (mode, uid, gid) = tmpfs_options(data);
            let n = NEXT_TMPFS.fetch_add(1, Ordering::Relaxed);
            let made = tmpfs_dir().and_then(|dir| crate::fs::zfs::with_server(|s| s.mkdir(dir, alloc::format!("{}", n).as_bytes(), mode, uid, gid)));
            match made {
                Ok(ino) => (Kind::Tree { tmpfs: Some(n) }, ino),
                Err(e) => return e,
            }
        }
        "sysfs" | "devtmpfs" => {
            let dir: &[u8] = if fs == "sysfs" { b"/sys" } else { b"/dev" };
            match ZfsClient::resolve_in(system_root, system_root, dir, true) {
                Ok(ino) => (Kind::Tree { tmpfs: None }, ino),
                Err(e) => return e,
            }
        }
        "proc" | "devpts" | "cgroup2" | "cgroup" | "mqueue" | "binfmt_misc" | "debugfs" | "tracefs" | "securityfs" | "pstore" | "bpf" | "fusectl" | "configfs" => {
            (Kind::Named, 0)
        }
        _ => return ENODEV,
    };
    let serves = if kind == Kind::Named { serves_of(&fs).map(String::from) } else { None };
    if matches!(kind, Kind::Tree { .. }) {
        hold_roots(&[root], true);
    }
    ns.lock().push(Mount {
        id: new_id(),
        parent: tmnt,
        mountpoint: tino,
        root,
        kind,
        flags: per,
        propagation: 0,
        fstype: fs,
        source: source_name,
        path: tpath,
        serves,
    });
    0
}

/// `umount2(2)`.
fn umount2(target: u64, flags: u64) -> i64 {
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    if flags & !(1 | MNT_DETACH | 4 | UMOUNT_NOFOLLOW) != 0 {
        return EINVAL;
    }
    let (tpath, tino, tmnt) = match locate_mountpoint(target, flags & UMOUNT_NOFOLLOW == 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut t = ns.lock();
    let Some(idx) = mount_at(&t, &tpath, tino, tmnt).filter(|i| *i != t.root) else { return EINVAL };
    let gone = t.subtree(idx);
    if gone.len() > 1 && flags & MNT_DETACH == 0 {
        return EBUSY;
    }
    let mut tmpfs = Vec::new();
    let mut held = Vec::new();
    for i in gone {
        if let Some(Some(m)) = t.mounts.get(i - 1) {
            if let Kind::Tree { tmpfs: t } = m.kind {
                held.push(m.root);
                if let Some(n) = t {
                    tmpfs.push(n);
                }
            }
        }
        t.mounts[i - 1] = None;
    }
    drop(t);
    hold_roots(&held, false);
    for n in tmpfs {
        release_tmpfs(n);
    }
    0
}

/// `pivot_root(2)`: `new_root` (a mount) becomes the root; the old root moves to `put_old`.
fn pivot_root(new_root: u64, put_old: u64) -> i64 {
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (npath, nino, nmnt) = match locate(new_root, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (ppath, pino, pmnt) = match locate(put_old, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id = current_ns_id();
    let mut t = ns.lock();
    let old = t.root;
    let Some(old_root) = t.get(old).map(|m| m.root) else { return EINVAL };
    if t.get(nmnt).map_or(true, |m| m.root != nino) || nmnt == old {
        return EINVAL; // new_root must be a mount, not the current root
    }
    if rebase(&ppath, &npath, "/").is_none() {
        return EINVAL; // put_old must be at or under new_root
    }
    let put_rel = rebase(&ppath, &npath, "/").unwrap();
    for (i, slot) in t.mounts.iter_mut().enumerate() {
        let Some(m) = slot else { continue };
        if i + 1 == old {
            continue;
        }
        m.path = match rebase(&m.path, &npath, "/") {
            Some(p) => p,
            None => normalize(&alloc::format!("{}/{}", put_rel, m.path)),
        };
    }
    if let Some(Some(m)) = t.mounts.get_mut(old - 1) {
        m.mountpoint = pino;
        m.parent = pmnt;
        m.path = put_rel;
    }
    if let Some(Some(m)) = t.mounts.get_mut(nmnt - 1) {
        m.mountpoint = 0;
        m.parent = 0;
        m.path = String::from("/");
    }
    t.root = nmnt;
    drop(t);
    // Every process of the namespace rooted (or working) at the old root moves
    let pids: Vec<u64> = super::proc::PROCS.lock().values().filter(|p| p.ns.mnt == id && !p.zombie).map(|p| p.pid).collect();
    for pid in pids {
        let Some(fds) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()) else { continue };
        let mut f = fds.lock();
        if f.root_ino == old_root || f.root_ino == 0 {
            f.root_ino = nino;
            f.root_mnt = nmnt;
        }
        if f.cwd_ino == old_root || f.cwd_ino == 0 {
            f.cwd_ino = nino;
            f.cwd_mnt = nmnt;
            f.cwd_path = String::from("/");
        }
    }
    0
}

/// `/proc/<pid>/mountinfo` of a process in a mount namespace of its own (`None` for the
/// initial one).
pub fn mountinfo(pid: u64) -> Option<String> {
    let id = super::proc::PROCS.lock().get(&pid).map(|p| p.ns.mnt)?;
    let t = table(id)?;
    let t = t.lock();
    let mut out = String::new();
    for m in t.mounts.iter().flatten() {
        let parent = t.get(m.parent).map_or(m.id, |p| p.id);
        let mut opts = String::from(if m.flags & MS_RDONLY != 0 { "ro" } else { "rw" });
        for (bit, name) in [(MS_NOSUID, "nosuid"), (MS_NODEV, "nodev"), (MS_NOEXEC, "noexec"), (MS_NOATIME, "noatime"), (MS_RELATIME, "relatime")] {
            if m.flags & bit != 0 {
                opts.push(',');
                opts.push_str(name);
            }
        }
        let prop = if m.propagation & MS_SHARED != 0 { alloc::format!(" shared:{}", m.id) } else { String::new() };
        out.push_str(&alloc::format!("{} {} 0:{} / {} {}{} - {} {} {}\n", m.id, parent, m.id, m.path, opts, prop, m.fstype, m.source, if m.flags & MS_RDONLY != 0 { "ro" } else { "rw" }));
    }
    Some(out)
}

/// `/proc/<pid>/mounts` (fstab format) of a process in a mount namespace of its own.
pub fn mounts(pid: u64) -> Option<String> {
    let id = super::proc::PROCS.lock().get(&pid).map(|p| p.ns.mnt)?;
    let t = table(id)?;
    let t = t.lock();
    let mut out = String::new();
    for m in t.mounts.iter().flatten() {
        out.push_str(&alloc::format!("{} {} {} {} 0 0\n", m.source, m.path, m.fstype, if m.flags & MS_RDONLY != 0 { "ro" } else { "rw" }));
    }
    Some(out)
}

/// Handles `pivot_root` (155), `mount` (165) and `umount2` (166).
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for these calls, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    Some(match num {
        155 => pivot_root(a[0], a[1]),
        165 => mount(a[0], a[1], a[2], a[3], a[4]),
        166 => umount2(a[0], a[1]),
        _ => return None,
    })
}

