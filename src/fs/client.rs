use super::zfs::server::{
    simple_str_hash, ZfsServer, ZFS_IPC_LOOKUP, ZFS_IPC_PING, ZFS_IPC_POOL_STATUS,
    ZFS_IPC_READ, ZFS_IPC_SNAPSHOT, ZFS_IPC_WRITE, ZFS_SERVER, ZFS_STATUS_OK,
};
use super::zfs::types::DnodeType;
use crate::capability::Capability;
use crate::ipc::{Endpoint, Message};
use uefi::proto::media::file::File;

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
        } else {
            if count < parts.len() {
                parts[count] = token;
                count += 1;
            }
        }
    }

    if count == 0 {
        out[0] = b'/';
        return core::str::from_utf8(&out[..1]).unwrap_or("/");
    }

    let mut pos = 0;
    for i in 0..count {
        if pos < out.len() {
            out[pos] = b'/';
            pos += 1;
        }
        let b = parts[i].as_bytes();
        let len = b.len().min(out.len().saturating_sub(pos));
        out[pos..pos + len].copy_from_slice(&b[..len]);
        pos += len;
    }

    core::str::from_utf8(&out[..pos]).unwrap_or("/")
}

/// Resolves an absolute normalized path in ZFS, returning (object_id, DnodeType).
pub fn resolve_path(path: &str) -> Result<(u64, DnodeType), &'static str> {
    let server_lock = ZFS_SERVER.lock();
    let server = match server_lock.as_ref() {
        Some(s) => s,
        None => return Err("ZFS File Server not running"),
    };

    let mut curr_obj = server.root_dir_obj;
    let mut curr_type = DnodeType::Directory;

    let clean = path.trim_matches(['/', '\\']);
    if clean.is_empty() {
        return Ok((curr_obj, curr_type));
    }

    for part in clean.split(['/', '\\']) {
        if part.is_empty() {
            continue;
        }
        if curr_type != DnodeType::Directory {
            return Err("Path component is not a directory");
        }
        let zap = &server.dmu.zap_dirs[curr_obj as usize];
        if let Some(entry) = zap.lookup(part) {
            curr_obj = entry.object_id;
            curr_type = entry.obj_type;
        } else {
            return Err("File or directory not found");
        }
    }

    Ok((curr_obj, curr_type))
}

/// Resolves the parent directory object ID and child component name for a normalized path.
pub fn resolve_parent_and_name<'a>(path: &'a str) -> Result<(u64, &'a str), &'static str> {
    let clean = path.trim_matches(['/', '\\']);
    if clean.is_empty() {
        return Err("Cannot target root directory as a child");
    }

    let server_lock = ZFS_SERVER.lock();
    let server = match server_lock.as_ref() {
        Some(s) => s,
        None => return Err("ZFS File Server not running"),
    };

    let mut curr_obj = server.root_dir_obj;

    let mut parts: [&str; 16] = [""; 16];
    let mut count = 0;
    for token in clean.split(['/', '\\']) {
        if !token.is_empty() && count < parts.len() {
            parts[count] = token;
            count += 1;
        }
    }

    if count == 0 {
        return Err("Invalid path");
    }

    // Traverse up to parent
    for i in 0..(count - 1) {
        let part = parts[i];
        let zap = &server.dmu.zap_dirs[curr_obj as usize];
        if let Some(entry) = zap.lookup(part) {
            if entry.obj_type != DnodeType::Directory {
                return Err("Parent path component is not a directory");
            }
            curr_obj = entry.object_id;
        } else {
            return Err("Parent directory not found");
        }
    }

    let child_name = parts[count - 1];
    Ok((curr_obj, child_name))
}

/// Resolves the parent directory object ID and child component name for a normalized path,
/// automatically creating any intermediate parent directories if they do not exist.
pub fn resolve_parent_and_name_or_create<'a>(server: &mut ZfsServer, path: &'a str) -> Result<(u64, &'a str), &'static str> {
    let clean = path.trim_matches(['/', '\\']);
    if clean.is_empty() {
        return Err("Cannot target root directory as a child");
    }

    let mut curr_obj = server.root_dir_obj;

    let mut parts: [&str; 16] = [""; 16];
    let mut count = 0;
    for token in clean.split(['/', '\\']) {
        if !token.is_empty() && count < parts.len() {
            parts[count] = token;
            count += 1;
        }
    }

    if count == 0 {
        return Err("Invalid path");
    }

    // Traverse up to parent, creating any missing directories
    for i in 0..(count - 1) {
        let part = parts[i];
        let found = {
            let zap = &server.dmu.zap_dirs[curr_obj as usize];
            zap.lookup(part).map(|e| (e.object_id, e.obj_type))
        };
        match found {
            Some((obj_id, DnodeType::Directory)) => {
                curr_obj = obj_id;
            }
            Some((_, _)) => {
                return Err("Parent path component is not a directory");
            }
            None => {
                let new_dir = server.dmu.allocate_object(DnodeType::Directory, part)?;
                server.dmu.add_directory_entry(curr_obj, part, new_dir, DnodeType::Directory)?;
                curr_obj = new_dir;
            }
        }
    }

    let child_name = parts[count - 1];
    Ok((curr_obj, child_name))
}

/// Client interface for interacting with the ZFS File Server via Microkernel IPC
pub struct ZfsClient;

impl ZfsClient {
    /// Pings the ZFS File Server over IPC and returns current active transaction group (TXG).
    pub fn ping() -> Result<u64, &'static str> {
        let req = Message::new(ZFS_IPC_PING);
        let mut reply_ep = Endpoint::new(999);

        let mut server_lock = ZFS_SERVER.lock();
        if let Some(server) = server_lock.as_mut() {
            server.dispatch_request(req, &mut reply_ep);
        } else {
            return Err("ZFS File Server is not initialized");
        }

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                return Ok(resp.args[1]);
            }
        }
        Err("Failed to ping ZFS server")
    }

    /// Queries the ZFS pool status (total MiB, allocated KiB, free KiB, TXG)
    pub fn pool_status() -> Result<(u64, u64, u64, u64), &'static str> {
        let req = Message::new(ZFS_IPC_POOL_STATUS);
        let mut reply_ep = Endpoint::new(999);

        let mut server_lock = ZFS_SERVER.lock();
        if let Some(server) = server_lock.as_mut() {
            server.dispatch_request(req, &mut reply_ep);
        } else {
            return Err("ZFS File Server is not initialized");
        }

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                let total_mb = resp.args[1];
                let alloc_kb = resp.args[2];
                let free_kb = resp.args[3] >> 32;
                let txg = resp.args[3] & 0xFFFF_FFFF;
                return Ok((total_mb, alloc_kb, free_kb, txg));
            }
        }
        Err("Failed to query pool status from ZFS server")
    }

    /// Looks up an object ID by path (e.g. "/bin/hello.efi" or "hello.efi") in the ZFS pool.
    pub fn lookup(path: &str) -> Result<(u64, DnodeType), &'static str> {
        // First attempt standard hierarchical resolution
        if let Ok(res) = resolve_path(path) {
            return Ok(res);
        }

        // Fallback: check in /bin directory for legacy command lookups
        let clean = path.trim_start_matches('/').trim_start_matches('\\');
        let filename = clean.strip_prefix("bin/").unwrap_or_else(|| {
            clean.strip_prefix("bin\\").unwrap_or(clean)
        });

        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let dir_obj = server.bin_dir_obj;
        let hash = simple_str_hash(filename);

        let req = Message::with_args(ZFS_IPC_LOOKUP, [dir_obj, hash, 0, 0]);
        let mut reply_ep = Endpoint::new(999);
        server.dispatch_request(req, &mut reply_ep);

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                let obj_id = resp.args[1];
                let obj_type = match resp.args[2] {
                    1 => DnodeType::PlainFile,
                    2 => DnodeType::Directory,
                    3 => DnodeType::Dataset,
                    _ => DnodeType::None,
                };
                return Ok((obj_id, obj_type));
            }
        }

        Err("File not found in ZFS File Server")
    }

    /// Reads data from a file object via Capability-mediated ZFS IPC.
    pub fn read_file(obj_id: u64, out_buf: &mut [u8], cap: Option<Capability>) -> Result<usize, &'static str> {
        let req = Message::with_args(
            ZFS_IPC_READ,
            [obj_id, out_buf.as_mut_ptr() as u64, out_buf.len() as u64, 0],
        );
        let req = if let Some(c) = cap { req.with_cap(c) } else { req };

        let mut reply_ep = Endpoint::new(999);
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        server.dispatch_request(req, &mut reply_ep);

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                return Ok(resp.args[1] as usize);
            } else if resp.args[0] == 2 {
                return Err("Capability rights violation (READ right required)");
            } else if resp.args[0] == 4 {
                return Err("ZFS Fletcher-4 checksum failure: file corrupted");
            }
        }

        Err("Read error from ZFS server")
    }

    /// Writes data to a file object via Capability-mediated ZFS CoW IPC.
    pub fn write_file(obj_id: u64, data: &[u8], cap: Option<Capability>) -> Result<u64, &'static str> {
        let req = Message::with_args(
            ZFS_IPC_WRITE,
            [obj_id, data.as_ptr() as u64, data.len() as u64, 0],
        );
        let req = if let Some(c) = cap { req.with_cap(c) } else { req };

        let mut reply_ep = Endpoint::new(999);
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        server.dispatch_request(req, &mut reply_ep);

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                return Ok(resp.args[1]); // new TXG
            } else if resp.args[0] == 2 {
                return Err("Capability rights violation (WRITE right required)");
            }
        }

        Err("Write error from ZFS server")
    }

    /// Reads an entire file by path into `out_buf`.
    pub fn read_file_by_path(path: &str, out_buf: &mut [u8]) -> Result<usize, &'static str> {
        let (obj_id, obj_type) = Self::lookup(path)?;
        if obj_type != DnodeType::PlainFile {
            return Err("Target path is not a regular file");
        }
        Self::read_file(obj_id, out_buf, None)
    }

    /// Writes an entire file by path using Copy-on-Write semantics.
    /// Creates the file if it doesn't already exist.
    pub fn write_file_by_path(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        let txg = Self::write_file_by_path_batch(path, data)?;
        Self::sync()?;
        Ok(txg)
    }

    /// Fast batch write that updates DMU structures without flushing metadata on every write.
    pub fn write_file_by_path_batch(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        // If file already exists, overwrite via CoW
        if let Ok((obj_id, obj_type)) = resolve_path(path) {
            if obj_type != DnodeType::PlainFile {
                return Err("Target path is a directory, not a file");
            }
            let mut server_lock = ZFS_SERVER.lock();
            let server = match server_lock.as_mut() {
                Some(s) => s,
                None => return Err("ZFS File Server not running"),
            };
            return server.dmu.cow_write_file(obj_id, data, &mut server.spa);
        }

        // Otherwise create new file in parent directory (auto-creating parent directories if needed)
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };
        let (parent_dir, filename) = resolve_parent_and_name_or_create(server, path)?;

        let file_obj = server.dmu.allocate_object(DnodeType::PlainFile, filename)?;
        let txg = server.dmu.cow_write_file(file_obj, data, &mut server.spa)?;
        server.dmu.add_directory_entry(parent_dir, filename, file_obj, DnodeType::PlainFile)?;
        Ok(txg)
    }

    /// Creates or updates a file (like Unix `touch`).
    pub fn touch_file(path: &str) -> Result<u64, &'static str> {
        if let Ok((obj_id, obj_type)) = resolve_path(path) {
            if obj_type != DnodeType::PlainFile {
                return Err("Target exists and is not a file");
            }
            // Re-commit empty or current data to update timestamp/TXG
            let mut server_lock = ZFS_SERVER.lock();
            let server = match server_lock.as_mut() {
                Some(s) => s,
                None => return Err("ZFS File Server not running"),
            };
            let dnode = &server.dmu.dnodes[obj_id as usize];
            let bp = dnode.direct_blocks[0];
            let txg = server.spa.commit_txg(bp);
            let _ = server.sync_metadata();
            return Ok(txg);
        }

        Self::write_file_by_path(path, &[])
    }

    /// Creates a new directory at the specified path (like Unix `mkdir`).
    pub fn create_dir(path: &str) -> Result<u64, &'static str> {
        if resolve_path(path).is_ok() {
            return Err("File or directory already exists");
        }

        let (parent_dir, dirname) = resolve_parent_and_name(path)?;
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let dir_obj = server.dmu.allocate_object(DnodeType::Directory, dirname)?;
        server.dmu.add_directory_entry(parent_dir, dirname, dir_obj, DnodeType::Directory)?;
        let _ = server.sync_metadata();
        Ok(dir_obj)
    }

    /// Recursively creates a directory and all parent components (like Unix `mkdir -p`).
    pub fn create_dir_all(path: &str) -> Result<u64, &'static str> {
        let clean = path.trim_matches(['/', '\\']);
        if clean.is_empty() {
            let server_lock = ZFS_SERVER.lock();
            let server = match server_lock.as_ref() {
                Some(s) => s,
                None => return Err("ZFS File Server not running"),
            };
            return Ok(server.root_dir_obj);
        }

        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let mut curr_obj = server.root_dir_obj;
        for part in clean.split(['/', '\\']) {
            if part.is_empty() {
                continue;
            }
            let found = {
                let zap = &server.dmu.zap_dirs[curr_obj as usize];
                zap.lookup(part).map(|e| (e.object_id, e.obj_type))
            };
            match found {
                Some((obj_id, DnodeType::Directory)) => {
                    curr_obj = obj_id;
                }
                Some((_, _)) => {
                    return Err("Path component exists and is not a directory");
                }
                None => {
                    let new_dir = server.dmu.allocate_object(DnodeType::Directory, part)?;
                    server.dmu.add_directory_entry(curr_obj, part, new_dir, DnodeType::Directory)?;
                    curr_obj = new_dir;
                }
            }
        }
        let _ = server.sync_metadata();
        Ok(curr_obj)
    }

    /// Removes an empty directory at the specified path (like Unix `rmdir`).
    pub fn remove_dir(path: &str) -> Result<(), &'static str> {
        let (obj_id, obj_type) = resolve_path(path)?;
        if obj_type != DnodeType::Directory {
            return Err("Target path is not a directory");
        }

        let (parent_dir, dirname) = resolve_parent_and_name(path)?;
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let zap = &server.dmu.zap_dirs[obj_id as usize];
        if zap.count > 0 {
            return Err("Directory is not empty");
        }

        let _ = server.dmu.remove_directory_entry(parent_dir, dirname)?;
        server.dmu.free_object(obj_id, &mut server.spa);
        let _ = server.sync_metadata();
        Ok(())
    }

    /// Removes a file from ZFS (like Unix `rm`).
    pub fn remove_file(path: &str) -> Result<(), &'static str> {
        let (obj_id, obj_type) = resolve_path(path)?;
        if obj_type != DnodeType::PlainFile {
            return Err("Target path is a directory (use -r to remove recursively)");
        }

        let (parent_dir, filename) = resolve_parent_and_name(path)?;
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let _ = server.dmu.remove_directory_entry(parent_dir, filename)?;
        server.dmu.free_object(obj_id, &mut server.spa);
        let _ = server.sync_metadata();
        Ok(())
    }

    /// Flushes all cached ZFS file metadata and ATA write buffers to physical media.
    pub fn sync() -> Result<(), &'static str> {
        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };
        server.sync_metadata()?;
        server.spa.flush()
    }

    /// Copies a file in ZFS (like Unix `cp`).
    pub fn copy_file(src_path: &str, dst_path: &str) -> Result<u64, &'static str> {
        let mut buf = [0u8; 4096];
        let bytes_read = Self::read_file_by_path(src_path, &mut buf)?;
        Self::write_file_by_path(dst_path, &buf[..bytes_read])
    }

    /// Moves or renames a file or directory in ZFS (like Unix `mv`).
    pub fn move_entry(src_path: &str, dst_path: &str) -> Result<(), &'static str> {
        let (src_obj, src_type) = resolve_path(src_path)?;
        let (src_parent, src_name) = resolve_parent_and_name(src_path)?;
        let (dst_parent, dst_name) = resolve_parent_and_name(dst_path)?;

        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        // Remove from source directory (without freeing dnode)
        let _ = server.dmu.remove_directory_entry(src_parent, src_name)?;

        // Add into destination directory
        server.dmu.add_directory_entry(dst_parent, dst_name, src_obj, src_type)?;

        // Update dnode name
        server.dmu.dnodes[src_obj as usize].set_name(dst_name);
        let _ = server.sync_metadata();
        Ok(())
    }

    /// Retrieves detailed file metadata (like Unix `stat`).
    pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
        let (obj_id, obj_type) = resolve_path(path)?;
        let server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_ref() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let dnode = &server.dmu.dnodes[obj_id as usize];
        let bp = &dnode.direct_blocks[0];

        Ok(FileStat {
            obj_id,
            obj_type,
            size: dnode.file_size,
            birth_txg: dnode.birth_txg,
            checksum: [bp.checksum.a, bp.checksum.b, bp.checksum.c, bp.checksum.d],
            is_allocated: bp.is_allocated,
            name: dnode.name,
        })
    }

    /// Creates a snapshot of a dataset via ZFS IPC
    pub fn snapshot(dataset_id: usize) -> Result<u64, &'static str> {
        let req = Message::with_args(ZFS_IPC_SNAPSHOT, [dataset_id as u64, 0, 0, 0]);
        let mut reply_ep = Endpoint::new(999);

        let mut server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_mut() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        server.dispatch_request(req, &mut reply_ep);

        if let Some(resp) = reply_ep.receive() {
            if resp.args[0] == ZFS_STATUS_OK {
                return Ok(resp.args[1]);
            }
        }
        Err("Failed to create snapshot")
    }

    /// Queries directory contents from the ZFS File Server.
    pub fn list_dir(
        path: &str,
    ) -> Result<([crate::fs::zfs::zap::ZapEntry; crate::fs::zfs::zap::MAX_ZAP_ENTRIES], usize, &'static str), &'static str> {
        let (dir_obj, dir_type) = resolve_path(path)?;
        if dir_type != DnodeType::Directory {
            return Err("Target path is not a directory");
        }

        let server_lock = ZFS_SERVER.lock();
        let server = match server_lock.as_ref() {
            Some(s) => s,
            None => return Err("ZFS File Server not running"),
        };

        let idx = dir_obj as usize;
        if idx < crate::fs::zfs::dmu::MAX_OBJECTS {
            let zap = &server.dmu.zap_dirs[idx];
            let ds_name = if dir_obj == server.bin_dir_obj {
                "hydrapool/bin"
            } else if dir_obj == server.root_dir_obj {
                "hydrapool/root"
            } else {
                "hydrapool/data"
            };
            return Ok((zap.entries, zap.count, ds_name));
        }

        Err("Directory not found in ZFS")
    }

    /// Discovers standalone executable ELF64 binaries on the UEFI boot medium (FAT volume)
    /// and imports them into the OpenZFS storage pool under `/bin/` before ExitBootServices.
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
            ("\\hello.elf", "/bin/hello.elf"),
            ("\\counter.elf", "/bin/counter.elf"),
            ("\\linuxapp.elf", "/bin/linuxapp.elf"),
            ("\\linux_app.elf", "/bin/linux_app.elf"),
            ("\\thread_test.elf", "/bin/thread_test.elf"),
            ("\\threadtest.elf", "/bin/threadtest.elf"),
        ];

        let mut imported_count = 0;
        let mut path_u16 = [0u16; 128];
        let mut file_buf = alloc::vec![0u8; 65536];

        for &(fat_path, zfs_path) in &candidate_files {
            // Skip only if file already exists in ZFS and can be read successfully
            let mut test_buf = [0u8; 16];
            if Self::read_file_by_path(zfs_path, &mut test_buf).is_ok() {
                continue;
            }

            if let Some(cstr) = crate::shell::fs::path_to_cstr16(fat_path, &mut path_u16) {
                if let Ok(handle) = root.open(cstr, uefi::proto::media::file::FileMode::Read, uefi::proto::media::file::FileAttribute::empty()) {
                    if let Some(mut file) = handle.into_regular_file() {
                        let mut total_read = 0;
                        while total_read < file_buf.len() {
                            match file.read(&mut file_buf[total_read..]) {
                                Ok(0) => break,
                                Ok(n) => total_read += n,
                                Err(_) => break,
                            }
                        }

                        if total_read >= 4 && file_buf[..4] == crate::task::elf::ELF_MAGIC {
                            if let Ok(_txg) = Self::write_file_by_path(zfs_path, &file_buf[..total_read]) {
                                imported_count += 1;
                                crate::console::set_color(uefi::proto::console::text::Color::LightGreen, uefi::proto::console::text::Color::Black);
                                crate::println!("[+] Imported '{}' from boot media into ZFS '{}' ({} bytes, Fletcher-4 verified)",
                                    fat_path, zfs_path, total_read);
                            }
                        }
                    }
                }
            }
        }

        imported_count
    }
}
