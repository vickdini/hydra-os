//! *stub* `crate::fs::ZfsClient`: the kernel's inode-level facade over the file server,
//! with the same defaults (root 0 = the pool root, base 0 = the root).

use alloc::vec::Vec;

use crate::fake::zfs_server::{with_server, ZfsServer};
use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

pub struct ZfsClient;

impl ZfsClient {
    pub fn resolve(base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            let root = s.root_obj();
            if path.is_empty() {
                return Err(-2);
            }
            s.resolve_in(root, base, path, follow_last)
        })
    }

    pub fn resolve_in(root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            if path.is_empty() {
                return Err(-2);
            }
            s.resolve_in(root, base, path, follow_last)
        })
    }

    pub fn resolve_in_dirs(root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<(u64, Vec<u64>), i64> {
        if path.is_empty() {
            return Err(-2);
        }
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            s.resolve_in_dirs(root, base, path, follow_last)
        })
    }

    /// *mirror* of `client::resolve_parent_in`.
    pub fn resolve_parent_in(root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            parent_in(s, root, base, path)
        })
    }

    pub fn resolve_parent(base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            let root = s.root_obj();
            parent_in(s, root, base, path)
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

    pub fn getxattr(ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
        with_server(|s| s.getxattr(ino, name))
    }

    pub fn setxattr(ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
        with_server(|s| s.setxattr(ino, name, value, flags))
    }

    pub fn listxattr(ino: u64) -> Result<Vec<u8>, i64> {
        with_server(|s| s.listxattr(ino))
    }

    pub fn removexattr(ino: u64, name: &[u8]) -> Result<(), i64> {
        with_server(|s| s.removexattr(ino, name))
    }

    pub fn open_ref(ino: u64) {
        let _ = with_server(|s| {
            s.open_ref(ino);
            Ok(())
        });
    }

    pub fn release(ino: u64) {
        // Tolerates drops during thread teardown, when the thread's pool is gone
        let _ = crate::fake::memfs::FS.try_with(|_| ());
        if crate::fake::memfs::FS.try_with(|_| ()).is_ok() {
            let _ = with_server(|s| {
                s.release(ino);
                Ok(())
            });
        }
    }

    pub fn notify_close_write(_ino: u64) {}

    pub fn sync() -> Result<(), &'static str> {
        crate::fake::count("sync");
        if crate::fake::memfs::failing("sync").is_err() {
            return Err("EIO");
        }
        Ok(())
    }
}

/// *mirror* of `client::resolve_parent_in`.
fn parent_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
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
        return Err(-17);
    }
    let dir_path: &[u8] = if dir_part.is_empty() { b"/" } else { dir_part };
    let parent = if dir_path == b"." { base } else { s.resolve_in(root, base, dir_path, true)? };
    Ok((parent, name.to_vec()))
}
