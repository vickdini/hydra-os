//! # Making objects and names (wave 10, Group V1)
//!
//! The change calls vfs-server sent back to the kernel until wave 10: `mknod`/`mknodat`,
//! `link`/`linkat`, and the making half of `open` ([`create`] for `O_CREAT`, [`tmpfile`]
//! for `O_TMPFILE`). Each walks and checks as the kernel's `with_parent` and `link_at` do
//! (`super::change::parent`: `EEXIST`/`ENOENT`, `EROFS`, search and write permission, ABAC),
//! makes the object through zfs-server, gives it what it inherits from its directory
//! (default ACL, labels: `super::xattr::new_mode`), and tells the caches (vfs-server's, the
//! kernel's names and attributes, and the kernel's in-memory tmpfs files: `crate::tmem`).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::change::{names_changed, parent, parent_checks};
use super::ctxt::{self, Call, KERNEL};
use super::rules;
use crate::cache;
use crate::ctx::Node;
use crate::fs::fsproto::{Attr, FS_CREATE, FS_LINK, FS_MKNOD, FS_UNLINK};
use crate::policy::{self, ll};
use crate::proto::{LxFhDesc, LX_FHC_ATTR, LX_FH_INSTALL, LX_FS_DEVCG, LX_FS_FANOTIFY, LX_FS_INOTIFY};
use crate::walk::{self, Backend, ParentWalked};
use crate::zfs;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EEXIST: i64 = -17;
const EXDEV: i64 = -18;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const EACCES: i64 = -13;

/// What only the kernel has for a change (as `change.rs`).
const NEED: u32 = LX_FS_INOTIFY | LX_FS_FANOTIFY;
const AT_SYMLINK_FOLLOW: u64 = 0x400;

/// The mark of an `O_TMPFILE` object without a name that may get one (not `O_EXCL`): an
/// extended attribute on the object itself, so it survives a vfs-server restart, goes with
/// the object when its last close frees it, and cannot belong to a reused inode number
/// (review 4). `trusted.*`: only `CAP_SYS_ADMIN` could set it on another file; lists hide
/// it (`rules::xattr_list_shown`).
pub const TMPFILE_MARK: &[u8] = b"trusted.hydra.tmpfile";

/// Whether object `ino`, without names, carries the [`TMPFILE_MARK`].
fn linkable_tmpfile(ino: u64) -> bool {
    zfs::getxattr(ino, TMPFILE_MARK).is_ok()
}

/// Tells the kernel that regular file `ino`, new in `dir`, may be an in-memory tmpfs file
/// (only a tmpfs mount's files can be: the initial namespace's `/dev/shm` is walked by the
/// kernel).
fn tmem_created(ino: u64, dir: Node, ns: u32, tmpfs: bool) {
    if tmpfs {
        crate::tmem::created(ino, dir.ino, ns, dir.mnt);
    }
}

/// Whether mount `mnt` of call `k` is a tmpfs.
fn is_tmpfs(k: &Call, mnt: u16) -> bool {
    mnt != 0 && k.w.view.is_tmpfs(mnt)
}

// ----------------------------------------------------------------------
// mknod
// ----------------------------------------------------------------------

/// `mknod(path, mode, dev)`, `mknodat(dirfd, path, mode, dev)`.
pub fn mknod(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let (ptr, mode, dev) = if cx.nr == 133 { (a[0], a[1] as u32, a[2]) } else { (a[1], a[2] as u32, a[3]) };
    let path = ctxt::path(cx, ptr, false)?;
    let k = ctxt::call(c)?;
    let who = &k.who;
    let p = parent(c, who, &path, true)?;
    let ftype = mode & rules::S_IFMT;
    // Device nodes: root only, and the control group's device programs decide (the kernel's)
    let devnode = ftype == 0o020000 || ftype == 0o060000;
    if devnode && c.euid != 0 {
        return Err(EPERM);
    }
    if devnode && c.fs_flags & LX_FS_DEVCG != 0 {
        return Err(KERNEL);
    }
    let (perm, plan) = super::xattr::new_mode(p.dir, &p.dir_attr, mode & 0o7777, c.umask as u32, false)?;
    let mode = ftype | perm;
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, p.dir, ll::make_right(ftype))?;
    }
    let r = zfs::request(FS_MKNOD, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.u64(mode as u64);
        w.u64(dev);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
    crate::notify::changed(&r, who);
    if let Ok(made) = &r {
        // (a regular file made by mknod is a file like any other)
        if ftype == rules::S_IFREG || ftype == 0 {
            tmem_created(made.value, p.dir, c.mnt_ns, is_tmpfs(&k, p.dir.mnt));
        }
        if !plan.is_empty() {
            super::xattr::inherit(made.value, &plan);
        }
    }
    names_changed(&[p.dir], None);
    r.map(|_| 0)
}

// ----------------------------------------------------------------------
// link
// ----------------------------------------------------------------------

/// `link(old, new)`, `linkat(olddir, old, newdir, new, flags)`.
pub fn link(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let (oldp, newp, flags) = if cx.nr == 86 { (a[0], a[1], 0) } else { (a[1], a[3], a[4]) };
    if flags & !(AT_SYMLINK_FOLLOW | ctxt::AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let op = cx.user_cstr(oldp)?;
    rules::check_path(&op, true)?;
    let np = ctxt::path(cx, newp, false)?;
    let who = ctxt::caller(c)?;
    let dom = policy::domain(c)?;
    // The object, and (Landlock) the directory it is reached from
    let (src, attr, sdir) = if op.is_empty() {
        if flags & ctxt::AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        // (the descriptor itself; under Landlock its directory is not known here)
        if dom.is_some() {
            return Err(KERNEL);
        }
        let n = ctxt::handle(c)?;
        (n, ctxt::BE.getattr(n)?, None)
    } else if let Some(n) = proc_fd_link(cx, &op, flags & AT_SYMLINK_FOLLOW != 0)? {
        // `/proc/self/fd/N` followed: the open file itself (an O_TMPFILE file's way to a name)
        if dom.is_some() {
            return Err(KERNEL);
        }
        (n, ctxt::BE.getattr(n)?, None)
    } else {
        let (n, at) = ctxt::find(c, &who, &op, flags & AT_SYMLINK_FOLLOW != 0)?;
        let sdir = if dom.is_some() {
            match walk::walk_parent(&ctxt::walker(c)?, &who, ctxt::start(c, &op)?, &op)? {
                ParentWalked::Found(p) => Some(p.dir),
                ParentWalked::Redirect(_) => return Err(KERNEL),
            }
        } else {
            None
        };
        (n, at, sdir)
    };
    // (a FUSE object: the kernel's, which asks the daemon)
    if crate::fuse::wire::split(src.ino).is_some() {
        return Err(KERNEL);
    }
    // The new name starts at the second directory descriptor
    let mut c2 = *c;
    c2.at_kind = c.at2_kind;
    c2.at_ino = c.at2_ino;
    c2.at_mnt = c.at2_mnt;
    let p = parent(&c2, &who, &np, true)?;
    if attr.is_dir() {
        return Err(EPERM);
    }
    if src.mnt != p.dir.mnt {
        return Err(EXDEV);
    }
    // A file without names: only an O_TMPFILE one (not O_EXCL) may get one
    if attr.nlink == 0 {
        let linkable = linkable_tmpfile(src.ino);
        if !linkable {
            return Err(ENOENT);
        }
    }
    // An in-memory file's data cannot follow a name to another file system
    if crate::tmem::candidate(&attr) && crate::tmem::is_tmem(src.ino) {
        crate::tmem::may_move(src.ino, p.dir.ino)?;
    }
    if let (Some(d), Some(sd)) = (&dom, sdir) {
        policy::check_move(d, sd, p.dir, attr.mode & rules::S_IFMT, 0)?;
        // (check_move of a link: no removal from the source: the kernel's `false`)
    }
    let r = zfs::request(FS_LINK, |w| {
        w.u64(src.ino);
        w.u64(p.dir.ino);
        w.bytes(&p.name);
    });
    crate::notify::changed(&r, &who);
    // (named now: the mark goes)
    if r.is_ok() && attr.nlink == 0 {
        let _ = zfs::request(crate::fs::fsproto::FS_REMOVEXATTR, |w| {
            w.u64(src.ino);
            w.bytes(TMPFILE_MARK);
        });
    }
    cache::CACHE.forget_attr(src);
    names_changed(&[p.dir], None);
    super::change::tell_kernel(src.ino, LX_FHC_ATTR, 0);
    r.map(|_| 0)
}

/// The open file `path` names when it is the caller's own `/proc/self/fd/N` (or
/// `thread-self`, or its process id) followed: its handle (a pool object in the initial
/// namespace), or `None` for any other path. A descriptor that is no such handle: the
/// kernel's.
fn proc_fd_link(cx: &Cx, path: &[u8], follow: bool) -> Result<Option<Node>, i64> {
    let Some(rest) = path.strip_prefix(b"/proc/") else { return Ok(None) };
    if !follow {
        return Ok(None);
    }
    let Some(i) = rest.iter().position(|&b| b == b'/') else { return Ok(None) };
    let (who, tail) = (&rest[..i], &rest[i + 1..]);
    let Some(num) = tail.strip_prefix(b"fd/") else { return Ok(None) };
    let own = who == b"self" || who == b"thread-self" || core::str::from_utf8(who).ok().and_then(|w| w.parse::<u64>().ok()) == Some(cx.c.tgid);
    let Some(fd) = core::str::from_utf8(num).ok().and_then(|n| n.parse::<u32>().ok()) else { return Ok(None) };
    if !own {
        return Ok(None);
    }
    let mut info = crate::proto::LxFhInfo::default();
    sys::lx_obj(crate::proto::LX_FH_INFO, cx.id, fd as u64, &mut info as *mut crate::proto::LxFhInfo as u64)?;
    if !matches!(info.kind, crate::proto::LX_AT_FILE | crate::proto::LX_AT_DIR) || info.mnt != 0 || cx.c.mnt_ns != 0 || info.ino == 0 {
        return Err(KERNEL);
    }
    Ok(Some(Node::new(0, info.ino)))
}

// ----------------------------------------------------------------------
// open's making half
// ----------------------------------------------------------------------

/// What [`create`] did.
pub enum Made {
    /// Made object `.0` (attributes `.1`), named `.3` in directory `.2` (an open that then
    /// fails to install its handle removes it again: [`undo_create`]).
    New(Node, Attr, Node, Vec<u8>),
    /// The name exists after all (another caller made it first; not `O_EXCL`): open it.
    Exists,
}

/// The making half of `open(path, O_CREAT ...)` when the walk found no object: makes a
/// regular file with `mode` (umask or default ACL) owned by the caller.
pub fn create(cx: &Cx, k: &Call, path: &[u8], flags: u32, mode: u32) -> Result<Made, i64> {
    let c = &cx.c;
    // A trailing slash names a directory, which O_CREAT does not make
    if path.last() == Some(&b'/') {
        return Err(EISDIR);
    }
    let mut start = k.start(c, path)?;
    // wave10 GV2: a dangling symbolic link is followed to the name its target makes (as the
    // kernel's `creation_target`, 40 links at most)
    let mut target: Vec<u8>;
    let mut at: &[u8] = path;
    let mut links = 0;
    let p = loop {
        let p = match walk::walk_parent(&k.w, &k.who, start, at)? {
            ParentWalked::Found(p) => p,
            ParentWalked::Redirect(_) => return Err(KERNEL),
        };
        // The name exists, though the walk found nothing: a dangling symbolic link to make
        // the target of, or another caller was faster
        let Some(ch) = p.child else { break p };
        let a = k.w.getattr(ch)?;
        if a.mode & rules::S_IFMT == rules::S_IFLNK && flags & (rules::O_NOFOLLOW | rules::O_EXCL) == 0 {
            links += 1;
            if links > walk::SYMLOOP_MAX {
                return Err(-40); // ELOOP
            }
            target = k.w.readlink(ch)?;
            if target.is_empty() {
                return Err(rules::ENOENT);
            }
            if target.last() == Some(&b'/') {
                return Err(EISDIR);
            }
            start = if target[0] == b'/' { walk::Start::Root } else { walk::Start::At(p.dir) };
            at = &target;
            continue;
        }
        return if flags & rules::O_EXCL != 0 { Err(EEXIST) } else { Ok(Made::Exists) };
    };
    if p.name == b"." || p.name == b".." {
        return Err(EISDIR);
    }
    let who = &k.who;
    let p = parent_checks(c, who, p, path, true)?;
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, p.dir, ll::MAKE_REG)?;
    }
    let (perm, plan) = super::xattr::new_mode(p.dir, &p.dir_attr, mode & 0o7777, c.umask as u32, false)?;
    let r = zfs::request(FS_CREATE, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.u64(perm as u64);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
    crate::notify::changed(&r, who);
    let ino = match r {
        Ok(made) => made.value,
        Err(EEXIST) if flags & rules::O_EXCL == 0 => {
            names_changed(&[p.dir], None);
            return Ok(Made::Exists);
        }
        Err(e) => {
            names_changed(&[p.dir], None);
            return Err(e);
        }
    };
    tmem_created(ino, p.dir, c.mnt_ns, is_tmpfs(k, p.dir.mnt));
    if !plan.is_empty() {
        super::xattr::inherit(ino, &plan);
    }
    names_changed(&[p.dir], None);
    let n = Node::new(p.dir.mnt, ino);
    // (a landlocked caller's open checks the new file through its directory)
    if c.ll_dom != 0 {
        policy::hint(c.id, p.dir, &p.name, n);
    }
    let a = ctxt::BE.getattr(n)?;
    Ok(Made::New(n, a, p.dir, p.name))
}

/// Removes the file [`create`] made as `name` in `dir` (object `ino`) when its open failed
/// afterwards (the handle could not be installed: `EMFILE`): no empty file is left behind,
/// as on Linux, where the descriptor is reserved first. Only if the name still leads to it.
pub fn undo_create(dir: Node, name: &[u8], ino: u64) {
    if zfs::lookup(dir.ino, name) != Ok(ino) {
        return;
    }
    let _ = zfs::request(FS_UNLINK, |w| {
        w.u64(dir.ino);
        w.bytes(name);
    });
    cache::CACHE.forget_object(ino);
    names_changed(&[dir], Some(ino));
}

/// A number for hidden `O_TMPFILE` names.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// `open(dir, O_TMPFILE | O_WRONLY or O_RDWR, mode)`: a regular file without a name in
/// directory `dir`, open: made under a hidden name, opened (the kernel's handle takes
/// zfs-server's open reference), then unlinked; `linkat(fd, "", ..., AT_EMPTY_PATH)` may
/// name it later unless `O_EXCL`.
pub fn tmpfile(cx: &Cx, k: &Call, path: &[u8], flags: u32, mode: u32, dirfd: i32) -> Result<i64, i64> {
    let c = &cx.c;
    let acc = flags & rules::O_ACCMODE;
    if acc != rules::O_WRONLY && acc != 2 {
        return Err(EINVAL);
    }
    let who = &k.who;
    let (dir, dattr) = k.find(c, path, flags & rules::O_NOFOLLOW == 0)?;
    if !dattr.is_dir() {
        return Err(ENOTDIR);
    }
    // (FUSE: the kernel's answer)
    if crate::fuse::wire::split(dir.ino).is_some() {
        return Err(KERNEL);
    }
    k.writable(dir)?;
    let acl = ctxt::acl_of(dir, &dattr)?;
    if !ctxt::allowed(who, &dattr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC, path)? {
        return Err(EACCES);
    }
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, dir, ll::open_rights(flags & !rules::O_TRUNC, false))?;
    }
    let (perm, plan) = super::xattr::new_mode(dir, &dattr, mode & 0o7777, c.umask as u32, false)?;
    // (review 5: made with mode 0 under its hidden name, so nobody else opens it in the
    // moment the name exists; its mode and inherited ACL come after the name is gone)
    let mut name = Vec::from(&b".hydra-tmpfile-"[..]);
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let (s, ns) = sys::clock();
    name.extend_from_slice(alloc::format!("{:x}-{:x}{:x}", seq, s, ns).as_bytes());
    // (no events: the file has no name)
    let ino = zfs::request(FS_CREATE, |w| {
        w.u64(dir.ino);
        w.bytes(&name);
        w.u64(0);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    })?
    .value;
    tmem_created(ino, dir, c.mnt_ns, is_tmpfs(k, dir.mnt));
    let n = Node::new(dir.mnt, ino);
    // The handle: its path shows the directory and the object, as Linux's `#ino (deleted)`
    let mut shown = path.to_vec();
    if shown.last() != Some(&b'/') {
        shown.push(b'/');
    }
    shown.extend_from_slice(alloc::format!("#{} (deleted)", ino).as_bytes());
    let fflags = (flags & !(rules::O_DIRECTORY | super::rules::O_TMPFILE_MASK)) | 0;
    let d = rules::handle_desc(c, n.ino, n.mnt, false, fflags, &shown, dirfd);
    let fd = d.and_then(|d| sys::lx_obj(LX_FH_INSTALL, cx.id, &d as *const LxFhDesc as u64, 0));
    // The hidden name goes whatever happened (an open handle keeps the object); tried twice
    let unlink = || {
        zfs::request(FS_UNLINK, |w| {
            w.u64(dir.ino);
            w.bytes(&name);
        })
    };
    let gone = unlink().is_ok() || unlink().is_ok();
    names_changed(&[dir], None);
    let fd = fd?;
    if !gone {
        // (the descriptor is installed and cannot be taken back: the file keeps its hidden
        // name and mode 0 — a stray name, not a file others can open)
        hydra_rt::println!("[vfs-server] O_TMPFILE: hidden name {} left in directory {}", core::str::from_utf8(&name).unwrap_or("?"), dir.ino);
        return Ok(fd as i64);
    }
    // Its mode and inherited ACL, now that it has no name
    let _ = zfs::request(crate::fs::fsproto::FS_SETATTR, |w| {
        w.u64(ino);
        w.setattr(&crate::fs::fsproto::SetAttr { mode: Some(perm), ..Default::default() });
    });
    if !plan.is_empty() {
        super::xattr::inherit(ino, &plan);
    }
    cache::CACHE.forget_object(ino);
    super::change::tell_kernel(ino, LX_FHC_ATTR, 0);
    if flags & rules::O_EXCL == 0 {
        let _ = zfs::request(crate::fs::fsproto::FS_SETXATTR, |w| {
            w.u64(ino);
            w.bytes(TMPFILE_MARK);
            w.bytes(b"1");
            w.u64(0);
        });
    }
    Ok(fd as i64)
}
