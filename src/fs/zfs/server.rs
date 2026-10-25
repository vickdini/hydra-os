use spin::Mutex;

use super::dmu::Dmu;
use super::spa::Spa;
use super::types::DnodeType;
use crate::capability::Rights;
use crate::ipc::{Endpoint, Message, SharedEndpoint};

/// Well-known Endpoint ID for the Hydra ZFS File Server
pub const ENDPOINT_ZFS_SERVER: u32 = 0x20;

// Protocol Message Labels
pub const ZFS_IPC_PING: u32 = 0x3001;
pub const ZFS_IPC_LOOKUP: u32 = 0x3002;
pub const ZFS_IPC_READ: u32 = 0x3003;
pub const ZFS_IPC_WRITE: u32 = 0x3004;
pub const ZFS_IPC_LIST_DIR: u32 = 0x3005;
pub const ZFS_IPC_POOL_STATUS: u32 = 0x3006;
pub const ZFS_IPC_SNAPSHOT: u32 = 0x3007;

// Protocol Response Status Codes
pub const ZFS_STATUS_OK: u64 = 0;
pub const ZFS_STATUS_NOT_FOUND: u64 = 1;
pub const ZFS_STATUS_PERMISSION_DENIED: u64 = 2;
pub const ZFS_STATUS_NO_SPACE: u64 = 3;
pub const ZFS_STATUS_CORRUPTION: u64 = 4;
pub const ZFS_STATUS_ERROR: u64 = 5;

/// Global shared endpoint for the ZFS File Server
pub static ZFS_SERVER_ENDPOINT: SharedEndpoint = SharedEndpoint::new(ENDPOINT_ZFS_SERVER);

/// The Microkernel ZFS File Server
pub struct ZfsServer {
    pub spa: Spa,
    pub dmu: alloc::boxed::Box<Dmu>,
    pub root_dir_obj: u64,
    pub bin_dir_obj: u64,
}

impl ZfsServer {
    /// Attempts to restore an existing OpenZFS pool directly from the persistent storage device.
    pub fn try_restore_from_disk(spa: &mut Spa) -> Option<(alloc::boxed::Box<Dmu>, u64, u64)> {
        let mut block0 = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
        if spa.vdev.read_block(0, &mut block0).is_err() {
            return None;
        }

        let label_ptr = block0.as_ptr() as *const crate::fs::zfs::types::VdevLabel;
        let label = unsafe { core::ptr::read_unaligned(label_ptr) };

        if !label.is_valid() {
            return None;
        }

        // Verify checksum of label
        let label_size_without_checksum = core::mem::size_of::<crate::fs::zfs::types::VdevLabel>()
            - core::mem::size_of::<crate::fs::zfs::types::Fletcher4>();
        let label_raw = unsafe {
            core::slice::from_raw_parts(
                &label as *const crate::fs::zfs::types::VdevLabel as *const u8,
                label_size_without_checksum,
            )
        };
        if crate::fs::zfs::types::Fletcher4::compute(label_raw) != label.checksum {
            crate::console::set_color(
                uefi::proto::console::text::Color::LightRed,
                uefi::proto::console::text::Color::Black,
            );
            crate::println!("[!] Warning: VdevLabel checksum mismatch. Rebuilding pool.");
            return None;
        }

        spa.active_uberblock = label.uberblock;
        spa.allocated_blocks = (label.allocated_blocks as usize).max(crate::fs::zfs::spa::RESERVED_METADATA_BLOCKS);

        let mut dmu = alloc::boxed::Box::new(Dmu::new());
        dmu.next_obj_id = label.next_obj_id;

        // Restore dnodes from Blocks 1..4
        let dnodes_slice = unsafe {
            core::slice::from_raw_parts_mut(
                dmu.dnodes.as_mut_ptr() as *mut u8,
                core::mem::size_of::<[crate::fs::zfs::types::DnodePhys; crate::fs::zfs::dmu::MAX_OBJECTS]>(),
            )
        };
        for (i, chunk) in dnodes_slice.chunks_mut(crate::fs::zfs::types::ZFS_BLOCK_SIZE).enumerate() {
            let mut buf = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
            if spa.vdev.read_block(1 + i, &mut buf).is_ok() {
                chunk.copy_from_slice(&buf[..chunk.len()]);
            }
        }

        // Restore datasets from Block 5
        let ds_slice = unsafe {
            core::slice::from_raw_parts_mut(
                dmu.datasets.as_mut_ptr() as *mut u8,
                core::mem::size_of::<[crate::fs::zfs::dmu::Dataset; crate::fs::zfs::dmu::MAX_DATASETS]>(),
            )
        };
        let mut ds_buf = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
        if spa.vdev.read_block(5, &mut ds_buf).is_ok() {
            ds_slice.copy_from_slice(&ds_buf[..ds_slice.len()]);
        }

        // Restore zap_dirs from Blocks 6..30
        let zap_slice = unsafe {
            core::slice::from_raw_parts_mut(
                dmu.zap_dirs.as_mut_ptr() as *mut u8,
                core::mem::size_of::<crate::fs::zfs::zap::ZapDirectory>() * crate::fs::zfs::dmu::MAX_OBJECTS,
            )
        };
        for (i, chunk) in zap_slice.chunks_mut(crate::fs::zfs::types::ZFS_BLOCK_SIZE).enumerate() {
            let mut buf = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
            if spa.vdev.read_block(6 + i, &mut buf).is_ok() {
                chunk.copy_from_slice(&buf[..chunk.len()]);
            }
        }

        Some((dmu, label.root_dir_obj, label.bin_dir_obj))
    }

    /// Serializes and flushes all active DMU metadata, dnodes, and the VdevLabel to persistent storage.
    pub fn sync_metadata(&mut self) -> Result<(), &'static str> {
        // 1. Write dnodes (64 * 256 bytes = 16 KiB across Blocks 1..4)
        let dnode_bytes = unsafe {
            core::slice::from_raw_parts(
                self.dmu.dnodes.as_ptr() as *const u8,
                core::mem::size_of::<[crate::fs::zfs::types::DnodePhys; crate::fs::zfs::dmu::MAX_OBJECTS]>(),
            )
        };
        for (i, chunk) in dnode_bytes.chunks(crate::fs::zfs::types::ZFS_BLOCK_SIZE).enumerate() {
            self.spa.vdev.write_block(1 + i, chunk)?;
        }

        // 2. Write datasets (Block 5)
        let dataset_bytes = unsafe {
            core::slice::from_raw_parts(
                self.dmu.datasets.as_ptr() as *const u8,
                core::mem::size_of::<[crate::fs::zfs::dmu::Dataset; crate::fs::zfs::dmu::MAX_DATASETS]>(),
            )
        };
        let mut ds_block = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
        let ds_len = dataset_bytes.len().min(crate::fs::zfs::types::ZFS_BLOCK_SIZE);
        ds_block[..ds_len].copy_from_slice(&dataset_bytes[..ds_len]);
        self.spa.vdev.write_block(5, &ds_block)?;

        // 3. Write zap_dirs (Blocks 6..30)
        let zap_bytes = unsafe {
            core::slice::from_raw_parts(
                self.dmu.zap_dirs.as_ptr() as *const u8,
                core::mem::size_of::<crate::fs::zfs::zap::ZapDirectory>() * crate::fs::zfs::dmu::MAX_OBJECTS,
            )
        };
        for (i, chunk) in zap_bytes.chunks(crate::fs::zfs::types::ZFS_BLOCK_SIZE).enumerate() {
            self.spa.vdev.write_block(6 + i, chunk)?;
        }

        // 4. Write VdevLabel (Block 0)
        let mut label = crate::fs::zfs::types::VdevLabel {
            magic: crate::fs::zfs::types::VDEV_LABEL_MAGIC,
            pool_name: self.spa.pool_name,
            uberblock: self.spa.active_uberblock,
            root_dir_obj: self.root_dir_obj,
            bin_dir_obj: self.bin_dir_obj,
            next_obj_id: self.dmu.next_obj_id,
            allocated_blocks: self.spa.allocated_blocks as u64,
            checksum: crate::fs::zfs::types::Fletcher4::default(),
        };

        let label_size_without_checksum = core::mem::size_of::<crate::fs::zfs::types::VdevLabel>()
            - core::mem::size_of::<crate::fs::zfs::types::Fletcher4>();
        let label_raw = unsafe {
            core::slice::from_raw_parts(
                &label as *const crate::fs::zfs::types::VdevLabel as *const u8,
                label_size_without_checksum,
            )
        };
        label.checksum = crate::fs::zfs::types::Fletcher4::compute(label_raw);

        let mut block0 = [0u8; crate::fs::zfs::types::ZFS_BLOCK_SIZE];
        let label_bytes = unsafe {
            core::slice::from_raw_parts(
                &label as *const crate::fs::zfs::types::VdevLabel as *const u8,
                core::mem::size_of::<crate::fs::zfs::types::VdevLabel>(),
            )
        };
        block0[..label_bytes.len()].copy_from_slice(label_bytes);
        self.spa.vdev.write_block(0, &block0)?;

        // 5. Hardware cache flush
        self.spa.vdev.flush()?;

        Ok(())
    }

    pub fn new() -> Self {
        let mut spa = Spa::new("hydrapool");

        // Attempt to mount existing pool from persistent storage media
        if let Some((dmu, root_dir_obj, bin_dir_obj)) = Self::try_restore_from_disk(&mut spa) {
            crate::console::set_color(
                uefi::proto::console::text::Color::LightGreen,
                uefi::proto::console::text::Color::Black,
            );
            crate::println!(
                "[+] OpenZFS: Mounted existing persistent storage pool 'hydrapool' from ATA Hard Disk!"
            );
            crate::println!(
                "    - Active TXG: #{}, Allocated Blocks: {} (Verified via Fletcher-4)",
                spa.active_uberblock.txg,
                spa.allocated_blocks
            );
            return Self {
                spa,
                dmu,
                root_dir_obj,
                bin_dir_obj,
            };
        }

        // Initialize new pool hierarchy
        let mut dmu = alloc::boxed::Box::new(Dmu::new());

        // 1. Create root directory
        let root_dir = dmu.allocate_object(DnodeType::Directory, "root").unwrap();
        let _ = dmu.create_dataset("hydrapool/root", "/");

        // 2. Create /bin directory
        let bin_dir = dmu.allocate_object(DnodeType::Directory, "bin").unwrap();
        let _ = dmu.create_dataset("hydrapool/bin", "/bin");
        let _ = dmu.add_directory_entry(root_dir, "bin", bin_dir, DnodeType::Directory);

        // 3. Create /root and /tmp directories
        let root_home = dmu.allocate_object(DnodeType::Directory, "root").unwrap();
        let _ = dmu.create_dataset("hydrapool/home", "/root");
        let _ = dmu.add_directory_entry(root_dir, "root", root_home, DnodeType::Directory);

        let tmp_dir = dmu.allocate_object(DnodeType::Directory, "tmp").unwrap();
        let _ = dmu.create_dataset("hydrapool/tmp", "/tmp");
        let _ = dmu.add_directory_entry(root_dir, "tmp", tmp_dir, DnodeType::Directory);

        // 4. Pre-populate default files and sample executables in ZFS /bin
        let sample_files: &[(&str, &[u8])] = &[
            (
                "readme.txt",
                b"Hydra OS Default Filesystem: OpenZFS Architecture\nIntegrated as an independent Microkernel File Server.\nAll operations are verified via Fletcher-4 checksums!\n",
            ),
            (
                "hello.efi",
                b"MZ\x90\x00Hydra EFI Application: Hello World from ZFS File Server!\n",
            ),
            (
                "fetch.efi",
                b"MZ\x90\x00Hydra System Fetch: Microkernel CPU/Mem/IPC Telemetry Tool\n",
            ),
            (
                "calc.efi",
                b"MZ\x90\x00Hydra Calculator Utility\n",
            ),
            (
                "demo.sh",
                b"#!/bin/sh\n# Hydra OS Shell Automation Script\necho === Running demo.sh ===\nuname -a\npwd\necho Listing files in /bin:\nls\necho OpenZFS pool status:\ndf -h\necho === Finished demo.sh ===\n",
            ),
        ];

        for &(name, content) in sample_files {
            if let Ok(file_obj) = dmu.allocate_object(DnodeType::PlainFile, name) {
                let _ = dmu.cow_write_file(file_obj, content, &mut spa);
                let _ = dmu.add_directory_entry(bin_dir, name, file_obj, DnodeType::PlainFile);
            }
        }

        let mut server = Self {
            spa,
            dmu,
            root_dir_obj: root_dir,
            bin_dir_obj: bin_dir,
        };

        // Write initial pool metadata to persistent media
        let _ = server.sync_metadata();

        server
    }

    /// Handles a single incoming IPC message sent to the ZFS File Server.
    /// Validates client capability rights and returns a response message.
    pub fn dispatch_request(&mut self, req: Message, reply_ep: &mut Endpoint) {
        // Enforce capability rights
        if let Some(cap) = req.capability {
            if req.label == ZFS_IPC_READ && !cap.rights.contains(Rights::READ) {
                let _ = reply_ep.send(Message::with_args(req.label, [ZFS_STATUS_PERMISSION_DENIED, 0, 0, 0]));
                return;
            }
            if req.label == ZFS_IPC_WRITE && !cap.rights.contains(Rights::WRITE) {
                let _ = reply_ep.send(Message::with_args(req.label, [ZFS_STATUS_PERMISSION_DENIED, 0, 0, 0]));
                return;
            }
        }

        let resp = match req.label {
            ZFS_IPC_PING => {
                Message::with_args(req.label, [ZFS_STATUS_OK, self.spa.active_uberblock.txg, 0, 0])
            }

            ZFS_IPC_POOL_STATUS => {
                let cap_mb = (self.spa.total_capacity_bytes() / (1024 * 1024)) as u64;
                let alloc_kb = (self.spa.allocated_bytes() / 1024) as u64;
                let free_kb = (self.spa.free_bytes() / 1024) as u64;
                let txg = self.spa.active_uberblock.txg;
                Message::with_args(req.label, [ZFS_STATUS_OK, cap_mb, alloc_kb, (free_kb << 32) | (txg & 0xFFFF_FFFF)])
            }

            ZFS_IPC_LOOKUP => {
                let dir_obj = req.args[0];
                let name_hash = req.args[1];
                let mut found_obj = 0;
                let mut found_type = 0;
                let mut status = ZFS_STATUS_NOT_FOUND;

                let dir_idx = dir_obj as usize;
                if dir_idx < super::dmu::MAX_OBJECTS {
                    for entry in self.dmu.zap_dirs[dir_idx].entries.iter() {
                        if entry.is_valid && simple_str_hash(entry.name_str()) == name_hash {
                            found_obj = entry.object_id;
                            found_type = entry.obj_type as u64;
                            status = ZFS_STATUS_OK;
                            break;
                        }
                    }
                }

                Message::with_args(req.label, [status, found_obj, found_type, 0])
            }

            ZFS_IPC_READ => {
                let obj_id = req.args[0];
                let dest_ptr = req.args[1] as *mut u8;
                let max_len = req.args[2] as usize;

                let mut status = ZFS_STATUS_ERROR;
                let mut bytes_read = 0;

                if !dest_ptr.is_null() && max_len > 0 {
                    let out_slice = unsafe { core::slice::from_raw_parts_mut(dest_ptr, max_len) };
                    match self.dmu.read_file(obj_id, out_slice, &self.spa) {
                        Ok(n) => {
                            bytes_read = n as u64;
                            status = ZFS_STATUS_OK;
                        }
                        Err("ZFS Checksum verification failed (silent data corruption detected)") => {
                            status = ZFS_STATUS_CORRUPTION;
                        }
                        Err(_) => {
                            status = ZFS_STATUS_NOT_FOUND;
                        }
                    }
                }

                Message::with_args(req.label, [status, bytes_read, self.spa.active_uberblock.txg, 0])
            }

            ZFS_IPC_WRITE => {
                let obj_id = req.args[0];
                let src_ptr = req.args[1] as *const u8;
                let len = req.args[2] as usize;

                let mut status = ZFS_STATUS_ERROR;
                let mut new_txg = 0;

                if !src_ptr.is_null() && len > 0 {
                    let in_slice = unsafe { core::slice::from_raw_parts(src_ptr, len) };
                    match self.dmu.cow_write_file(obj_id, in_slice, &mut self.spa) {
                        Ok(txg) => {
                            new_txg = txg;
                            status = ZFS_STATUS_OK;
                        }
                        Err("Storage pool is out of space (metaslabs full)") => {
                            status = ZFS_STATUS_NO_SPACE;
                        }
                        Err(_) => {
                            status = ZFS_STATUS_ERROR;
                        }
                    }
                }

                Message::with_args(req.label, [status, new_txg, 0, 0])
            }

            ZFS_IPC_SNAPSHOT => {
                let dataset_id = req.args[0] as usize;
                let mut status = ZFS_STATUS_ERROR;
                let txg = self.spa.active_uberblock.txg;

                if dataset_id < super::dmu::MAX_DATASETS && self.dmu.datasets[dataset_id].is_valid {
                    let mut name_buf = [0u8; 32];
                    name_buf.copy_from_slice(&self.dmu.datasets[dataset_id].name);
                    let len = name_buf.iter().position(|&b| b == 0).unwrap_or(32);
                    let ds_name = core::str::from_utf8(&name_buf[..len]).unwrap_or("");
                    if self.dmu.create_snapshot(ds_name, "auto_snap", txg).is_ok() {
                        status = ZFS_STATUS_OK;
                    }
                }

                Message::with_args(req.label, [status, txg, 0, 0])
            }

            _ => Message::with_args(req.label, [ZFS_STATUS_ERROR, 0, 0, 0]),
        };

        let _ = reply_ep.send(resp);
    }
}

/// Computes a fast 64-bit FNV-1a hash for string lookup in IPC messages.
pub fn simple_str_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in s.as_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Global singleton instance of the ZFS File Server protected by spinlock
pub static ZFS_SERVER: Mutex<Option<ZfsServer>> = Mutex::new(None);

/// Initializes the microkernel ZFS File Server.
pub fn init_server() {
    let mut lock = ZFS_SERVER.lock();
    if lock.is_none() {
        *lock = Some(ZfsServer::new());
    }
}
