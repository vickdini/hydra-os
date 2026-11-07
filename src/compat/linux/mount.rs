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
//! - **The new mount API** (`fsopen`, `fsconfig`, `fsmount`, `open_tree`, `move_mount`,
//!   `fspick`, `mount_setattr`) builds the same mounts through [`mount_core`]: a context
//!   collects the type, source and options, `fsmount` and `open_tree` with
//!   `OPEN_TREE_CLONE` give a detached mount that `move_mount` attaches (it is made then),
//!   and `mount_setattr` changes per-mount flags and propagation (also before attaching).
//!
//! Not yet: overlayfs and other file system types, id-mapped mounts.

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
fn tmpfs_options(data: Option<&str>) -> (u32, u32, u32) {
    let (euid, egid) = crate::task::with_current_task_mut(|t| (t.euid, t.egid)).unwrap_or((0, 0));
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

/// The absolute path (in the caller's view) and resolved `(inode, mount)` of a user path.
/// `/proc/self/fd/N` names what descriptor N is open on.
fn locate(ptr: u64, follow: bool) -> Result<(String, u64, usize), i64> {
    locate_in(-100, &super::vfs::user_path(ptr)?, follow)
}

/// [`locate`] for `path` relative to `dirfd`; an empty path names what `dirfd` is open on.
fn locate_in(dirfd: i64, path: &[u8], follow: bool) -> Result<(String, u64, usize), i64> {
    if path.is_empty() {
        let (ino, p) = super::vfs::base_dir(dirfd, b"x")?;
        return Ok((normalize(&p), ino, last_mount()));
    }
    let path = path.to_vec();
    let (base, base_path) = super::vfs::base_dir(dirfd, &path)?;
    let abs = normalize(&super::vfs::join_path_raw(&base_path, &path));
    if let Some((ino, mnt, p)) = super::vfs::magic_fd_target(&super::vfs::join_path(&base_path, &path)) {
        return Ok((normalize(&p), ino, mnt));
    }
    let ino = super::vfs::resolve(base, &path, follow)?;
    Ok((abs, ino, last_mount()))
}

/// The path Hydra serves a bind mount's source at, when it is a file served by name (such
/// as `/dev/null`, given by path or by an open `/proc/self/fd/N`).
fn served_source_in(dirfd: i64, path: &[u8]) -> Option<String> {
    let (_, base_path) = super::vfs::base_dir(dirfd, path).ok()?;
    let abs = super::vfs::join_path(&base_path, path);
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
    locate_mountpoint_in(-100, &super::vfs::user_path(ptr)?, follow)
}

/// [`locate_mountpoint`] for `path` relative to `dirfd`.
fn locate_mountpoint_in(dirfd: i64, path: &[u8], follow: bool) -> Result<(String, u64, usize), i64> {
    match locate_in(dirfd, path, follow) {
        Ok(v) => Ok(v),
        Err(e) if e == -2 || e == -20 => {
            let (_, base_path) = super::vfs::base_dir(dirfd, path)?;
            Ok((normalize(&super::vfs::join_path_raw(&base_path, path)), 0, 0))
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
    let target = match found {
        Ok(v) => v,
        Err(e) => return e,
    };
    let src = super::vfs::user_path(source).ok().map(|p| (-100i64, p));
    let fs = super::vfs::user_path(fstype).ok().map(|f| String::from_utf8_lossy(&f).into_owned());
    let data = if data != 0 { super::vfs::user_path(data).ok().map(|d| String::from_utf8_lossy(&d).into_owned()) } else { None };
    mount_core(&ns, src, target, fs, flags, data)
}

/// The source of a bind or move, located (`EFAULT` when there is none).
fn locate_src(src: &Option<(i64, Vec<u8>)>) -> Result<(String, u64, usize), i64> {
    match src {
        Some((dirfd, path)) => locate_in(*dirfd, path, true),
        None => Err(EFAULT),
    }
}

/// What `mount` does, on located arguments: `src` is the source `(dirfd, path)`, `target`
/// the located target, `fs` the file system type, `data` its options.
fn mount_core(ns: &Arc<Mutex<MountNs>>, src: Option<(i64, Vec<u8>)>, target: (String, u64, usize), fs: Option<String>, flags: u64, data: Option<String>) -> i64 {
    let (tpath, tino, tmnt) = target;
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
        let (spath, sino, smnt) = match locate_src(&src) {
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
        if let Some(served) = src.as_ref().and_then(|(d, p)| served_source_in(*d, p)) {
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
        let (spath, sino, smnt) = match locate_src(&src) {
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
    let Some(fs) = fs else { return EFAULT };
    let source_name = src.as_ref().map(|(_, s)| String::from_utf8_lossy(s).into_owned()).unwrap_or_else(|| fs.clone());
    let system_root = ns.lock().system_root;
    let (kind, root) = match fs.as_str() {
        "tmpfs" | "ramfs" => {
            let (mode, uid, gid) = tmpfs_options(data.as_deref());
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

// ----------------------------------------------------------------------
// The new mount API: fsopen, fsconfig, fsmount, open_tree, move_mount, fspick,
// mount_setattr
// ----------------------------------------------------------------------

const FSCONFIG_SET_FLAG: u64 = 0;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_SET_BINARY: u64 = 2;
const FSCONFIG_SET_PATH: u64 = 3;
const FSCONFIG_SET_PATH_EMPTY: u64 = 4;
const FSCONFIG_SET_FD: u64 = 5;
const FSCONFIG_CMD_CREATE: u64 = 6;
const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;

const MOUNT_ATTR_RDONLY: u64 = 1;
const MOUNT_ATTR_NOSUID: u64 = 2;
const MOUNT_ATTR_NODEV: u64 = 4;
const MOUNT_ATTR_NOEXEC: u64 = 8;
const MOUNT_ATTR_ATIME: u64 = 0x70;
const MOUNT_ATTR_NOATIME: u64 = 0x10;
const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
const MOUNT_ATTR_IDMAP: u64 = 0x10_0000;
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x20_0000;
const MOUNT_ATTR_ALL: u64 = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSYMFOLLOW;

const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_RECURSIVE: u64 = 0x8000;
const O_CLOEXEC: u64 = 0o2000000;
const E2BIG: i64 = -7;
const EBADF: i64 = -9;
const EMFILE: i64 = -24;

/// File system types `fsopen` knows (those `mount` does).
fn known_fs(fs: &str) -> bool {
    matches!(
        fs,
        "tmpfs" | "ramfs" | "sysfs" | "devtmpfs" | "proc" | "devpts" | "cgroup2" | "cgroup" | "mqueue" | "binfmt_misc" | "debugfs" | "tracefs" | "securityfs" | "pstore" | "bpf" | "fusectl" | "configfs"
    )
}

/// `MOUNT_ATTR_*` as per-mount `MS_*` flags.
fn attr_to_ms(attr: u64) -> u64 {
    let mut f = 0;
    if attr & MOUNT_ATTR_RDONLY != 0 {
        f |= MS_RDONLY;
    }
    if attr & MOUNT_ATTR_NOSUID != 0 {
        f |= MS_NOSUID;
    }
    if attr & MOUNT_ATTR_NODEV != 0 {
        f |= MS_NODEV;
    }
    if attr & MOUNT_ATTR_NOEXEC != 0 {
        f |= MS_NOEXEC;
    }
    if attr & MOUNT_ATTR_NODIRATIME != 0 {
        f |= MS_NODIRATIME;
    }
    if attr & MOUNT_ATTR_NOSYMFOLLOW != 0 {
        f |= MS_NOSYMFOLLOW;
    }
    match attr & MOUNT_ATTR_ATIME {
        MOUNT_ATTR_NOATIME => f |= MS_NOATIME,
        MOUNT_ATTR_STRICTATIME => {}
        _ => f |= MS_RELATIME,
    }
    f
}

/// A file system context (`fsopen`, `fspick`).
pub struct FsCtx {
    fs: String,
    source: Option<String>,
    options: Vec<String>,
    /// `MS_RDONLY` from the "ro" flag.
    ro: bool,
    created: bool,
    mounted: bool,
    /// `fspick`: the mount being reconfigured (its path).
    reconfigure: Option<String>,
}

/// What a detached mount (`fsmount`, `open_tree` with `OPEN_TREE_CLONE`) will be.
#[derive(Clone)]
enum Spec {
    New { fs: String, source: Option<String>, data: String },
    Clone { source: String, recursive: bool },
}

/// A mount object not (yet) attached anywhere.
pub struct Detached {
    spec: Spec,
    /// Per-mount `MS_*` flags and propagation.
    flags: u64,
    propagation: u64,
    /// Where it was attached (then `move_mount` moves it).
    attached: Option<String>,
}

/// The objects behind the new API's descriptors.
pub enum MountObj {
    /// A file system context.
    Ctx(Mutex<FsCtx>),
    /// A mount object (detached until `move_mount`).
    Mnt(Mutex<Detached>),
}

impl super::chardev::CharDevice for MountObj {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut crate::task::wait::WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        match self {
            MountObj::Ctx(_) => String::from("anon_inode:[fscontext]"),
            MountObj::Mnt(m) => m.lock().attached.clone().unwrap_or_else(|| String::from("/")),
        }
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_mount_obj(&self) -> Option<&MountObj> {
        Some(self)
    }
}

fn install(obj: MountObj, cloexec: bool) -> i64 {
    let dev: Arc<dyn super::chardev::CharDevice> = Arc::new(obj);
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, cloexec);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// The new API's object behind descriptor `fd` (`Err(EBADF)` if none, `Err(EINVAL)` if
/// another kind of descriptor).
fn obj_of(fd: u64) -> Result<Arc<dyn super::chardev::CharDevice>, i64> {
    let d = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    match d {
        Some(crate::fs::FileDescriptor::Device(d)) if d.as_mount_obj().is_some() => Ok(d),
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    }
}

/// A path argument that may be empty (the `AT_EMPTY_PATH` style calls check that).
fn path_arg(ptr: u64) -> Result<Vec<u8>, i64> {
    if ptr == 0 {
        Ok(Vec::new())
    } else {
        super::vfs::user_cstr(ptr)
    }
}

/// `fsopen(fsname, flags)`.
fn fsopen(name: u64, flags: u64) -> i64 {
    if flags & !1 != 0 {
        return EINVAL;
    }
    if let Err(e) = admin_ns() {
        return e;
    }
    let fs = match super::vfs::user_path(name) {
        Ok(f) => String::from_utf8_lossy(&f).into_owned(),
        Err(e) => return e,
    };
    if !known_fs(&fs) {
        return ENODEV;
    }
    let ctx = FsCtx { fs, source: None, options: Vec::new(), ro: false, created: false, mounted: false, reconfigure: None };
    install(MountObj::Ctx(Mutex::new(ctx)), flags & 1 != 0)
}

/// `fsconfig(fd, cmd, key, value, aux)`.
fn fsconfig(fd: u64, cmd: u64, key: u64, value: u64, aux: u64) -> i64 {
    let obj = match obj_of(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let MountObj::Ctx(ctx) = obj.as_mount_obj().unwrap() else { return EINVAL };
    let key = if key != 0 {
        match super::vfs::user_path(key) {
            Ok(k) => Some(String::from_utf8_lossy(&k).into_owned()),
            Err(e) => return e,
        }
    } else {
        None
    };
    let mut c = ctx.lock();
    match cmd {
        FSCONFIG_SET_FLAG => {
            let Some(k) = key else { return EINVAL };
            if value != 0 || aux != 0 {
                return EINVAL;
            }
            match k.as_str() {
                "ro" => c.ro = true,
                "rw" => c.ro = false,
                _ => c.options.push(k),
            }
            0
        }
        FSCONFIG_SET_STRING | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            let Some(k) = key else { return EINVAL };
            if value == 0 || (cmd == FSCONFIG_SET_STRING && aux != 0) {
                return EINVAL;
            }
            let v = match super::vfs::user_path(value) {
                Ok(v) => String::from_utf8_lossy(&v).into_owned(),
                Err(e) => return e,
            };
            if k == "source" {
                if c.source.is_some() {
                    return EINVAL;
                }
                c.source = Some(v);
            } else {
                c.options.push(alloc::format!("{}={}", k, v));
            }
            0
        }
        FSCONFIG_SET_BINARY | FSCONFIG_SET_FD => EINVAL,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
            if key.is_some() || value != 0 || aux != 0 {
                return EINVAL;
            }
            if c.created || c.reconfigure.is_some() {
                return EBUSY;
            }
            c.created = true;
            0
        }
        FSCONFIG_CMD_RECONFIGURE => {
            let Some(target) = c.reconfigure.clone() else { return EINVAL };
            let ro = c.ro;
            drop(c);
            set_attrs(&target, if ro { MS_RDONLY } else { 0 }, if ro { 0 } else { MS_RDONLY }, false, 0)
        }
        _ => EOPNOTSUPP,
    }
}

const EOPNOTSUPP: i64 = -95;

/// `fsmount(fs_fd, flags, attr_flags)`.
fn fsmount(fd: u64, flags: u64, attr: u64) -> i64 {
    if flags & !1 != 0 || attr & !MOUNT_ATTR_ALL != 0 || attr & MOUNT_ATTR_IDMAP != 0 {
        return EINVAL;
    }
    if let Err(e) = admin_ns() {
        return e;
    }
    let obj = match obj_of(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let MountObj::Ctx(ctx) = obj.as_mount_obj().unwrap() else { return EINVAL };
    let mut c = ctx.lock();
    if !c.created || c.reconfigure.is_some() {
        return EINVAL;
    }
    if c.mounted {
        return EBUSY;
    }
    c.mounted = true;
    let mut ms = attr_to_ms(attr);
    if c.ro {
        ms |= MS_RDONLY;
    }
    let spec = Spec::New { fs: c.fs.clone(), source: c.source.clone(), data: c.options.join(",") };
    drop(c);
    install(MountObj::Mnt(Mutex::new(Detached { spec, flags: ms, propagation: 0, attached: None })), flags & 1 != 0)
}

/// Where `(dirfd, path)` leads with `AT_EMPTY_PATH`-style `empty` handling.
fn target_of(dirfd: u64, path: &[u8], follow: bool) -> Result<(String, u64, usize), i64> {
    locate_in(dirfd as i32 as i64, path, follow)
}

/// `open_tree(dirfd, path, flags)`.
fn open_tree(dirfd: u64, path: u64, flags: u64) -> i64 {
    const OPEN_TREE_CLONE: u64 = 1;
    if flags & !(OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW) != 0 {
        return EINVAL;
    }
    if flags & AT_RECURSIVE != 0 && flags & OPEN_TREE_CLONE == 0 {
        return EINVAL;
    }
    let p = match path_arg(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if p.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return -2; // ENOENT
    }
    if flags & OPEN_TREE_CLONE == 0 {
        // A plain O_PATH descriptor on the path
        let target = if p.is_empty() { alloc::format!("/proc/self/fd/{}", dirfd as i32).into_bytes() } else { p };
        let dirfd = if target.first() == Some(&b'/') { -100 } else { dirfd as i32 as i64 };
        let fl = 0o10000000 | (flags & O_CLOEXEC) as u32 | if flags & AT_SYMLINK_NOFOLLOW != 0 { 0o400000 } else { 0 };
        return super::vfs::open_path(dirfd, &target, fl, 0).map_or_else(|e| e, |fd| fd as i64);
    }
    if let Err(e) = admin_ns() {
        return e;
    }
    let (abs, _, _) = match target_of(dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let d = Detached { spec: Spec::Clone { source: abs, recursive: flags & AT_RECURSIVE != 0 }, flags: 0, propagation: 0, attached: None };
    install(MountObj::Mnt(Mutex::new(d)), flags & O_CLOEXEC != 0)
}

/// `move_mount(from_dirfd, from_path, to_dirfd, to_path, flags)`.
fn move_mount(from_dfd: u64, from_path: u64, to_dfd: u64, to_path: u64, flags: u64) -> i64 {
    const F_SYMLINKS: u64 = 1;
    const F_EMPTY_PATH: u64 = 4;
    const T_SYMLINKS: u64 = 0x10;
    const T_EMPTY_PATH: u64 = 0x40;
    if flags & !(F_SYMLINKS | 2 | F_EMPTY_PATH | T_SYMLINKS | 0x20 | T_EMPTY_PATH) != 0 {
        return EINVAL; // MOVE_MOUNT_SET_GROUP, _BENEATH: not supported
    }
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    collect();
    let (fp, tp) = match (path_arg(from_path), path_arg(to_path)) {
        (Ok(f), Ok(t)) => (f, t),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if (fp.is_empty() && flags & F_EMPTY_PATH == 0) || (tp.is_empty() && flags & T_EMPTY_PATH == 0) {
        return -2; // ENOENT
    }
    let target = match target_of(to_dfd, &tp, flags & T_SYMLINKS != 0 || !tp.is_empty()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let tpath = target.0.clone();
    // A detached mount's descriptor
    if fp.is_empty() {
        if let Ok(obj) = obj_of(from_dfd) {
            let MountObj::Mnt(m) = obj.as_mount_obj().unwrap() else { return EINVAL };
            let (attached, spec, dflags, prop) = {
                let d = m.lock();
                (d.attached.clone(), d.spec.clone(), d.flags, d.propagation)
            };
            let r = match (attached, spec) {
                (Some(at), _) => mount_core(&ns, Some((-100, at.into_bytes())), target, None, MS_MOVE, None),
                (None, Spec::New { fs, source, data }) => {
                    let src = source.map(|s| (-100, s.into_bytes()));
                    let data = (!data.is_empty()).then_some(data);
                    mount_core(&ns, src, target, Some(fs), dflags, data)
                }
                (None, Spec::Clone { source, recursive }) => {
                    let fl = MS_BIND | if recursive { MS_REC } else { 0 };
                    let r = mount_core(&ns, Some((-100, source.into_bytes())), target, None, fl, None);
                    // The clone's own flags (set with mount_setattr while detached)
                    if r == 0 && dflags != 0 {
                        set_attrs(&tpath, dflags, 0, recursive, 0);
                    }
                    r
                }
            };
            if r == 0 {
                if prop != 0 {
                    set_attrs(&tpath, 0, 0, false, prop);
                }
                m.lock().attached = Some(tpath);
            }
            return r;
        }
    }
    // An attached mount, by path: moved
    mount_core(&ns, Some((from_dfd as i32 as i64, fp)), target, None, MS_MOVE, None)
}

/// `fspick(dirfd, path, flags)`: a context for reconfiguring the mount at `path`.
fn fspick(dirfd: u64, path: u64, flags: u64) -> i64 {
    const FSPICK_CLOEXEC: u64 = 1;
    const FSPICK_SYMLINK_NOFOLLOW: u64 = 2;
    const FSPICK_EMPTY_PATH: u64 = 8;
    if flags & !0xf != 0 {
        return EINVAL;
    }
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    let p = match path_arg(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if p.is_empty() && flags & FSPICK_EMPTY_PATH == 0 {
        return -2;
    }
    let (abs, ino, mnt) = match target_of(dirfd, &p, flags & FSPICK_SYMLINK_NOFOLLOW == 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let t = ns.lock();
    let Some(idx) = mount_at(&t, &abs, ino, mnt) else { return EINVAL };
    let Some(m) = t.get(idx) else { return EINVAL };
    let ctx = FsCtx { fs: m.fstype.clone(), source: Some(m.source.clone()), options: Vec::new(), ro: m.flags & MS_RDONLY != 0, created: true, mounted: false, reconfigure: Some(abs) };
    drop(t);
    install(MountObj::Ctx(Mutex::new(ctx)), flags & FSPICK_CLOEXEC != 0)
}

/// Sets `set` and clears `clear` (per-mount `MS_*` flags) and sets propagation `prop` (if
/// not 0) on the mount at `path` (and those below it with `recursive`).
fn set_attrs(path: &str, set: u64, clear: u64, recursive: bool, prop: u64) -> i64 {
    let ns = match admin_ns() {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (abs, ino, mnt) = match locate_in(-100, path.as_bytes(), true) {
        Ok(v) => v,
        Err(e) if e == -2 || e == -20 => (String::from(path), 0, 0),
        Err(e) => return e,
    };
    let mut t = ns.lock();
    let Some(idx) = mount_at(&t, &abs, ino, mnt) else { return EINVAL };
    let targets = if recursive { t.subtree(idx) } else { alloc::vec![idx] };
    for i in targets {
        if let Some(Some(m)) = t.mounts.get_mut(i - 1) {
            m.flags = (m.flags & !clear) | set;
            if prop != 0 {
                m.propagation = prop;
            }
        }
    }
    0
}

/// `mount_setattr(dirfd, path, flags, attr, size)`.
fn mount_setattr(dirfd: u64, path: u64, flags: u64, uattr: u64, size: u64) -> i64 {
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return EINVAL;
    }
    if size < 32 {
        return EINVAL;
    }
    if size > 4096 {
        return E2BIG;
    }
    let raw = match super::vfs::copy_in(uattr, size as usize) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if raw[32..].iter().any(|&b| b != 0) {
        return E2BIG;
    }
    let field = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (attr_set, attr_clr, prop) = (field(0), field(1), field(2));
    if (attr_set | attr_clr) & !MOUNT_ATTR_ALL != 0 || (attr_set | attr_clr) & MOUNT_ATTR_IDMAP != 0 {
        return EINVAL;
    }
    if prop != 0 && !matches!(prop, MS_PRIVATE | MS_SHARED | MS_SLAVE | MS_UNBINDABLE) {
        return EINVAL;
    }
    // Setting an atime mode replaces the current one
    let mut set = attr_to_ms(attr_set & !MOUNT_ATTR_ATIME) & !MS_RELATIME;
    let mut clear = attr_to_ms(attr_clr & !MOUNT_ATTR_ATIME) & !MS_RELATIME;
    if (attr_set | attr_clr) & MOUNT_ATTR_ATIME != 0 {
        clear |= MS_NOATIME | MS_RELATIME;
        set |= attr_to_ms(attr_set & MOUNT_ATTR_ATIME) & (MS_NOATIME | MS_RELATIME);
    }
    let p = match path_arg(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if p.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return -2;
        }
        // A detached mount: its flags for when it is attached
        if let Ok(obj) = obj_of(dirfd) {
            let MountObj::Mnt(m) = obj.as_mount_obj().unwrap() else { return EINVAL };
            let mut d = m.lock();
            if let Some(at) = d.attached.clone() {
                drop(d);
                return set_attrs(&at, set, clear, flags & AT_RECURSIVE != 0, prop);
            }
            d.flags = (d.flags & !clear) | set;
            if prop != 0 {
                d.propagation = prop;
            }
            return 0;
        }
    }
    if let Err(e) = admin_ns() {
        return e;
    }
    let (abs, _, _) = match target_of(dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    set_attrs(&abs, set, clear, flags & AT_RECURSIVE != 0, prop)
}

/// The new mount API's system calls: open_tree (428), move_mount (429), fsopen (430),
/// fsconfig (431), fsmount (432), fspick (433), mount_setattr (442).
pub fn dispatch_new(num: u64, a: [u64; 6]) -> i64 {
    let _ = EROFS;
    match num {
        428 => open_tree(a[0], a[1], a[2]),
        429 => move_mount(a[0], a[1], a[2], a[3], a[4]),
        430 => fsopen(a[0], a[1]),
        431 => fsconfig(a[0], a[1], a[2], a[3], a[4]),
        432 => fsmount(a[0], a[1], a[2]),
        433 => fspick(a[0], a[1], a[2]),
        _ => mount_setattr(a[0], a[1], a[2], a[3], a[4]),
    }
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

