//! # ZFS Client Interface
//!
//! Path-based access to the ZFS file server for kernel code and shell commands, plus the
//! path walker ([`resolve_at`]) that the Linux layer uses. Paths are resolved component
//! by component through the ZPL, following symbolic links (up to 40, as Linux) and `..`.

use alloc::vec::Vec;

use super::zfs::server::{with_server, ZfsServer, ZFS_SERVER};
use super::zfs::types::DnodeType;
use super::zfs::zap::ZapEntry;
use super::zfs::zpl::{self, Attr, ReaddirEntry, SetAttr};
use crate::capability::Capability;
use uefi::proto::media::file::File;

/// Maximum symbolic links followed while resolving one path (Linux `MAXSYMLINKS`).
pub const SYMLOOP_MAX: usize = 40;
const ELOOP: i64 = -40;

/// Detailed file/directory metadata returned by stat
#[derive(Debug, Clone, Copy)]
pub struct FileStat {
    pub obj_id: u64,
    pub obj_type: DnodeType,
    pub size: u64,
    pub birth_txg: u64,
    pub checksum: [u64; 4],
    pub is_allocated: bool,
    pub name: [u8; 32],
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: i64,
}

impl FileStat {
    pub fn name_str(&self) -> &str {
        let mut len = 0;
        while len < self.name.len() && self.name[len] != 0 {
            len += 1;
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("<unknown>")
    }
}

/// Normalizes a path string against a current working directory into `out`.
/// Returns the resulting normalized absolute path string (e.g. "/bin/readme.txt" or "/").
pub fn normalize_path<'a>(cwd: &str, path: &str, out: &'a mut [u8; 128]) -> &'a str {
    let mut parts: [&str; 16] = [""; 16];
    let mut count = 0;

    let is_absolute = path.starts_with('/') || path.starts_with('\\');

    if !is_absolute {
        for token in cwd.split(['/', '\\']) {
            if !token.is_empty() && token != "." {
                if count < parts.len() {
                    parts[count] = token;
                    count += 1;
                }
            }
        }
    }

    for token in path.split(['/', '\\']) {
        if token.is_empty() || token == "." {
            continue;
        } else if token == ".." {
            if count > 0 {
                count -= 1;
            }
        } else if count < parts.len() {
            parts[count] = token;
            count += 1;
        }
    }

    if count == 0 {
        out[0] = b'/';
        return core::str::from_utf8(&out[..1]).unwrap_or("/");
    }

    let mut pos = 0;
    for part in parts.iter().take(count) {
        if pos < out.len() {
            out[pos] = b'/';
            pos += 1;
        }
        let b = part.as_bytes();
        let len = b.len().min(out.len().saturating_sub(pos));
        out[pos..pos + len].copy_from_slice(&b[..len]);
        pos += len;
    }

    core::str::from_utf8(&out[..pos]).unwrap_or("/")
}

fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&c| c == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
}

/// Resolves `path` relative to directory `base` (absolute paths start at the root).
/// Symbolic links are followed in every component, and in the last one if `follow_last`
/// or the path ends in `/`.
pub fn resolve_at(s: &mut ZfsServer, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    let root = s.root_obj();
    resolve_in(s, root, base, path, follow_last)
}

/// Like [`resolve_at`], but with `root` as the root directory (`chroot`): absolute paths
/// and absolute symlink targets start there, and `..` never climbs above it.
pub fn resolve_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    if path.is_empty() {
        return Err(zpl::ENOENT);
    }
    let follow_last = follow_last || path.ends_with(b"/");
    let mut cur = if path[0] == b'/' { root } else { base };
    let mut pending: Vec<Vec<u8>> = components(path);
    pending.reverse();
    let mut links = 0;
    while let Some(comp) = pending.pop() {
        if comp == b".." {
            cur = if cur == root { root } else { s.lookup(cur, b"..")? };
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
            }
            let mut more = components(&target);
            more.reverse();
            pending.extend(more);
            continue;
        }
        if !is_last && !attr.is_dir() {
            return Err(zpl::ENOTDIR);
        }
        cur = next;
    }
    if path.ends_with(b"/") && !s.getattr(cur)?.is_dir() {
        return Err(zpl::ENOTDIR);
    }
    Ok(cur)
}

/// Splits `path` into its parent directory (resolved) and final name.
pub fn resolve_parent_at(s: &mut ZfsServer, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
    let root = s.root_obj();
    resolve_parent_in(s, root, base, path)
}

/// Like [`resolve_parent_at`] within the root directory `root`.
pub fn resolve_parent_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
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
        return Err(zpl::EEXIST);
    }
    let dir_path: &[u8] = if dir_part.is_empty() { b"/" } else { dir_part };
    let parent = if dir_path == b"." { base } else { resolve_in(s, root, base, dir_path, true)? };
    Ok((parent, name.to_vec()))
}

fn errno_str(e: i64) -> &'static str {
    match e {
        zpl::ENOENT => "File or directory not found",
        zpl::EEXIST => "File or directory already exists",
        zpl::ENOTDIR => "Path component is not a directory",
        zpl::EISDIR => "Target is a directory",
        zpl::ENOTEMPTY => "Directory is not empty",
        zpl::ENOSPC => "Storage pool is out of space",
        zpl::EINVAL => "Invalid argument",
        zpl::ENAMETOOLONG => "File name too long",
        ELOOP => "Too many levels of symbolic links",
        _ => "ZFS I/O error",
    }
}

/// Resolves an absolute path, following symlinks, returning (object_id, DnodeType).
pub fn resolve_path(path: &str) -> Result<(u64, DnodeType), &'static str> {
    with_server(|s| {
        let root = s.root_obj();
        let ino = resolve_at(s, root, path.as_bytes(), true)?;
        Ok((ino, s.getattr(ino)?.kind()))
    })
    .map_err(errno_str)
}

/// Resolves the parent directory object ID and child component name for a path.
pub fn resolve_parent_and_name(path: &str) -> Result<(u64, &str), &'static str> {
    let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        return Err("Cannot target root directory as a child");
    }
    let parent = with_server(|s| {
        let root = s.root_obj();
        Ok(resolve_parent_at(s, root, path.as_bytes())?.0)
    })
    .map_err(errno_str)?;
    Ok((parent, name))
}

/// Client interface to the ZFS file server.
pub struct ZfsClient;

impl ZfsClient {
    /// Returns the current committed transaction group.
    pub fn ping() -> Result<u64, &'static str> {
        with_server(|s| Ok(s.dmu.ub.txg)).map_err(errno_str)
    }

    /// Pool status: (total MiB, allocated KiB, free KiB << 32 | txg).
    pub fn pool_status() -> Result<(u64, u64, u64, u64), &'static str> {
        with_server(|s| {
            Ok((
                s.dmu.spa.total_capacity_bytes() / (1024 * 1024),
                s.dmu.spa.allocated_bytes() / 1024,
                s.dmu.spa.free_bytes() / 1024,
                s.dmu.ub.txg,
            ))
        })
        .map_err(errno_str)
    }

    /// Looks up a path, returning (object id, type).
    pub fn lookup(path: &str) -> Result<(u64, DnodeType), &'static str> {
        resolve_path(path)
    }

    /// Reads a file from the start into `out_buf`, returning the bytes read.
    pub fn read_file(obj_id: u64, out_buf: &mut [u8], _cap: Option<Capability>) -> Result<usize, &'static str> {
        with_server(|s| s.read(obj_id, 0, out_buf)).map_err(errno_str)
    }

    /// Replaces a file's contents.
    pub fn write_file(obj_id: u64, data: &[u8], _cap: Option<Capability>) -> Result<u64, &'static str> {
        with_server(|s| {
            s.setattr(obj_id, SetAttr { size: Some(0), ..SetAttr::default() })?;
            s.write(obj_id, 0, data)?;
            Ok(s.dmu.open_txg)
        })
        .map_err(errno_str)
    }

    /// Reads a file by path into `out_buf` (up to its length).
    pub fn read_file_by_path(path: &str, out_buf: &mut [u8]) -> Result<usize, &'static str> {
        let (obj_id, obj_type) = Self::lookup(path)?;
        if obj_type != DnodeType::PlainFile {
            return Err("Target path is not a regular file");
        }
        Self::read_file(obj_id, out_buf, None)
    }

    /// Writes a whole file by path (creating it and parent directories) and commits.
    pub fn write_file_by_path(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        Self::write_file_by_path_batch(path, data)?;
        Self::sync()?;
        Ok(Self::ping()?)
    }

    /// Writes a whole file by path without forcing a commit.
    pub fn write_file_by_path_batch(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let ino = match resolve_at(s, root, path.as_bytes(), true) {
                Ok(ino) => {
                    if s.getattr(ino)?.is_dir() {
                        return Err(zpl::EISDIR);
                    }
                    s.setattr(ino, SetAttr { size: Some(0), ..SetAttr::default() })?;
                    ino
                }
                Err(zpl::ENOENT) => {
                    let parent_path = path.trim_end_matches('/').rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    mkdir_all(s, parent_path)?;
                    let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
                    s.create(parent, &name, 0o644, 0, 0)?
                }
                Err(e) => return Err(e),
            };
            s.write(ino, 0, data)?;
            Ok(s.dmu.open_txg)
        })
        .map_err(errno_str)
    }

    /// Creates an empty file, or updates the timestamps of an existing one.
    pub fn touch_file(path: &str) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            match resolve_at(s, root, path.as_bytes(), true) {
                Ok(ino) => {
                    let t = crate::arch::rtc::now();
                    let t = (t.0 as i64, t.1);
                    s.setattr(ino, SetAttr { atime: Some(t), mtime: Some(t), ..SetAttr::default() })?;
                    Ok(ino)
                }
                Err(zpl::ENOENT) => {
                    let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
                    s.create(parent, &name, 0o644, 0, 0)
                }
                Err(e) => Err(e),
            }
        })
        .map_err(errno_str)
    }

    /// Creates a directory (like `mkdir`).
    pub fn create_dir(path: &str) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.mkdir(parent, &name, 0o755, 0, 0)
        })
        .map_err(errno_str)
    }

    /// Creates a directory and missing parents (like `mkdir -p`).
    pub fn create_dir_all(path: &str) -> Result<u64, &'static str> {
        with_server(|s| mkdir_all(s, path)).map_err(errno_str)
    }

    /// Removes an empty directory.
    pub fn remove_dir(path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.rmdir(parent, &name)
        })
        .map_err(errno_str)
    }

    /// Removes a file or symbolic link.
    pub fn remove_file(path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.unlink(parent, &name)
        })
        .map_err(errno_str)
    }

    /// Commits all pending changes to disk.
    pub fn sync() -> Result<(), &'static str> {
        with_server(|s| s.sync().map(|_| ())).map_err(errno_str)
    }

    /// Commits pending changes if a commit is due (called from idle points).
    pub fn sync_if_dirty() {
        if let Some(mut guard) = ZFS_SERVER.try_lock() {
            if let Some(s) = guard.as_mut() {
                if s.dmu.has_pending_changes() {
                    let _ = s.sync();
                }
            }
        }
    }

    /// Copies a file.
    pub fn copy_file(src_path: &str, dst_path: &str) -> Result<u64, &'static str> {
        let st = Self::file_stat(src_path)?;
        let mut buf = alloc::vec![0u8; st.size as usize];
        let n = Self::read_file_by_path(src_path, &mut buf)?;
        Self::write_file_by_path(dst_path, &buf[..n])
    }

    /// Renames a file or directory.
    pub fn move_entry(src_path: &str, dst_path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (sdir, sname) = resolve_parent_at(s, root, src_path.as_bytes())?;
            let (ddir, dname) = resolve_parent_at(s, root, dst_path.as_bytes())?;
            s.rename(sdir, &sname, ddir, &dname)
        })
        .map_err(errno_str)
    }

    /// File metadata (following symlinks).
    pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let ino = resolve_at(s, root, path.as_bytes(), true)?;
            let a = s.getattr(ino)?;
            let dn = s.dmu.get_dnode(ino).map_err(|_| zpl::EIO)?;
            let bp = dn.blkptr[0];
            let mut name = [0u8; 32];
            let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or("/");
            let n = base.len().min(31);
            name[..n].copy_from_slice(&base.as_bytes()[..n]);
            Ok(FileStat {
                obj_id: ino,
                obj_type: a.kind(),
                size: a.size,
                birth_txg: a.birth_txg,
                checksum: [bp.checksum.a, bp.checksum.b, bp.checksum.c, bp.checksum.d],
                is_allocated: !bp.is_hole(),
                name,
                mode: a.mode,
                uid: a.uid,
                gid: a.gid,
                nlink: a.nlink,
                mtime: a.mtime.0,
            })
        })
        .map_err(errno_str)
    }

    /// Snapshots the dataset with the given index.
    pub fn snapshot(dataset_id: usize) -> Result<u64, &'static str> {
        let name = alloc::format!("snap{}", crate::arch::rtc::now().0);
        with_server(|s| s.snapshot(dataset_id, &name)).map_err(errno_str)
    }

    /// Lists a directory (excluding `.` and `..`). Returns (entries, count, dataset name).
    pub fn list_dir(path: &str) -> Result<(Vec<ZapEntry>, usize, &'static str), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let dir = resolve_at(s, root, path.as_bytes(), true)?;
            let mut out = Vec::new();
            let mut cookie = 2;
            loop {
                let batch = s.readdir(dir, cookie, 256)?;
                if batch.is_empty() {
                    break;
                }
                for e in batch {
                    cookie = e.next_cookie;
                    let kind = s.getattr(e.ino).map(|a| a.kind()).unwrap_or(DnodeType::None);
                    out.push(ZapEntry::new(&e.name, e.ino, kind));
                }
            }
            let n = out.len();
            Ok((out, n, "hydrapool/root"))
        })
        .map_err(errno_str)
    }

    // --------------------------------------------------------------
    // Inode-level access used by the VFS / Linux layer
    // --------------------------------------------------------------

    /// Resolves a path relative to `base` (0 = root).
    pub fn resolve(base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            resolve_at(s, base, path, follow_last)
        })
    }

    /// Resolves a path within root directory `root` (0 = pool root), relative to `base`
    /// (0 = `root`).
    pub fn resolve_in(root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            resolve_in(s, root, base, path, follow_last)
        })
    }

    /// Resolves the parent directory and final name of a path within `root`.
    pub fn resolve_parent_in(root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            resolve_parent_in(s, root, base, path)
        })
    }

    /// Resolves the parent directory and final name of a path relative to `base`.
    pub fn resolve_parent(base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            resolve_parent_at(s, base, path)
        })
    }

    pub fn root_ino() -> u64 {
        with_server(|s| Ok(s.root_obj())).unwrap_or(0)
    }

    pub fn getattr(ino: u64) -> Result<Attr, i64> {
        with_server(|s| s.getattr(ino))
    }

    pub fn setattr(ino: u64, set: SetAttr) -> Result<Attr, i64> {
        with_server(|s| s.setattr(ino, set))
    }

    pub fn read_at(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        with_server(|s| s.read(ino, offset, buf))
    }

    pub fn write_at(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        with_server(|s| s.write(ino, offset, data))
    }

    pub fn readdir(ino: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
        with_server(|s| s.readdir(ino, cookie, max))
    }

    pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
        with_server(|s| s.readlink(ino))
    }

    pub fn open_ref(ino: u64) {
        let _ = with_server(|s| {
            s.open_ref(ino);
            Ok(())
        });
    }

    pub fn release(ino: u64) {
        let _ = with_server(|s| {
            s.release(ino);
            Ok(())
        });
    }

    /// Imports the boot-medium test binaries into the pool (before ExitBootServices).
    pub fn sync_boot_binaries() -> usize {
        if crate::console::is_hardware_mode() {
            return 0;
        }

        let mut root = match crate::shell::fs::open_root_volume() {
            Ok(r) => r,
            Err(_) => return 0,
        };

        let candidate_files = [
            ("\\bin\\hello.elf", "/bin/hello.elf"),
            ("\\bin\\counter.elf", "/bin/counter.elf"),
            ("\\bin\\linuxapp.elf", "/bin/linuxapp.elf"),
            ("\\bin\\linux_app.elf", "/bin/linux_app.elf"),
            ("\\bin\\thread_test.elf", "/bin/thread_test.elf"),
            ("\\bin\\threadtest.elf", "/bin/threadtest.elf"),
            ("\\bin\\roletest.elf", "/bin/roletest.elf"),
            ("\\bin\\socktest.elf", "/bin/socktest.elf"),
            ("\\bin\\epolltest.elf", "/bin/epolltest.elf"),
            ("\\bin\\shmtest.elf", "/bin/shmtest.elf"),
            ("\\bin\\wlclient.elf", "/bin/wlclient.elf"),
            ("\\bin\\wlseat.elf", "/bin/wlseat.elf"),
            ("\\bin\\dynclient.elf", "/bin/dynclient.elf"),
            ("\\bin\\vmtest.elf", "/bin/vmtest.elf"),
            ("\\bin\\fstest.elf", "/bin/fstest.elf"),
            ("\\bin\\plasmashell.elf", "/bin/plasmashell.elf"),
            ("\\bin\\krunner.elf", "/bin/krunner.elf"),
            ("\\bin\\ld-hydra.so", "/lib64/ld-hydra.so"),
            ("\\etc\\passwd", "/etc/passwd"),
            ("\\etc\\group", "/etc/group"),
        ];

        let mut imported_count = 0;
        let mut path_u16 = [0u16; 128];

        for &(fat_path, zfs_path) in &candidate_files {
            let cstr = match crate::shell::fs::path_to_cstr16(fat_path, &mut path_u16) {
                Some(c) => c,
                None => continue,
            };
            let handle = match root.open(cstr, uefi::proto::media::file::FileMode::Read, uefi::proto::media::file::FileAttribute::empty()) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let mut file = match handle.into_regular_file() {
                Some(f) => f,
                None => continue,
            };
            let mut info_buf = [0u8; 256];
            let file_size = file
                .get_info::<uefi::proto::media::file::FileInfo>(&mut info_buf)
                .map(|i| i.file_size() as usize)
                .unwrap_or(0);
            let mut file_buf = alloc::vec![0u8; file_size];
            let mut total_read = 0;
            while total_read < file_buf.len() {
                match file.read(&mut file_buf[total_read..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total_read += n,
                }
            }
            let data = &file_buf[..total_read];

            // Skip files already imported with identical contents
            if let Ok(st) = Self::file_stat(zfs_path) {
                if st.size == data.len() as u64 {
                    let mut existing = alloc::vec![0u8; data.len()];
                    if Self::read_file_by_path(zfs_path, &mut existing).is_ok() && existing == data {
                        continue;
                    }
                }
            }

            let is_elf = data.len() >= 4 && data[..4] == crate::task::elf::ELF_MAGIC;
            let is_config = !data.is_empty() && zfs_path.starts_with("/etc/");
            if (is_elf || is_config) && Self::write_file_by_path_batch(zfs_path, data).is_ok() {
                if is_elf {
                    let _ = with_server(|s| {
                        let root = s.root_obj();
                        let ino = resolve_at(s, root, zfs_path.as_bytes(), true)?;
                        s.setattr(ino, SetAttr { mode: Some(0o755), ..SetAttr::default() })?;
                        Ok(())
                    });
                }
                imported_count += 1;
                crate::console::set_color(uefi::proto::console::text::Color::LightGreen, uefi::proto::console::text::Color::Black);
                crate::println!("[+] Imported '{}' from boot media into ZFS '{}' ({} bytes)", fat_path, zfs_path, total_read);
            }
        }

        if imported_count > 0 {
            let _ = Self::sync();
        }
        imported_count
    }
}

/// Creates `path` and any missing parent directories, returning the final directory.
fn mkdir_all(s: &mut ZfsServer, path: &str) -> Result<u64, i64> {
    let mut cur = s.root_obj();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        cur = match s.lookup(cur, part.as_bytes()) {
            Ok(_) => {
                let ino = resolve_at(s, cur, part.as_bytes(), true)?;
                if !s.getattr(ino)?.is_dir() {
                    return Err(zpl::ENOTDIR);
                }
                ino
            }
            Err(zpl::ENOENT) => s.mkdir(cur, part.as_bytes(), 0o755, 0, 0)?,
            Err(e) => return Err(e),
        };
    }
    Ok(cur)
}
