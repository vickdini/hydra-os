//! # Hydra ZFS File Server
//!
//! ## Subsystem Role & Architecture
//! This module provides the user-facing microkernel file server coordinating Hydra's
//! OpenZFS storage stack. It integrates the storage pool allocator (SPA), data management
//! unit (DMU), ZFS attribute processor (ZAP), and POSIX layer (ZPL).
//!
//! ## Key Types & Interfaces
//! - [`DatasetRecord`]: In-memory and on-disk representation of a ZFS dataset or snapshot.
//! - [`ZfsServer`]: Main server state managing pool mounts, transaction groups, and caches.
//! - [`ZFS_SERVER`]: Global mutex protecting the active file server instance.
//! - `init_server`, [`with_server`]: Entry points to initialize and access the server safely.
//!
//! ## Concurrency & Hardware Semantics
//! Kernel and user-space threads access the server through the [`ZFS_SERVER`] spinlock.
//! Dirty block counts are tracked to trigger automatic syncs when threshold capacity is
//! reached. Unlinked inodes with open references are retained until the final handle closes.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use spin::Mutex;

use super::dmu::Dmu;
use super::spa::{Spa, Vdev};
use super::types::*;
use super::zap::Zap;

/// Well-known Endpoint ID for the Hydra ZFS File Server
pub const ENDPOINT_ZFS_SERVER: u32 = 0x20;

/// A dataset or snapshot record (stored in the datasets object, 152 bytes each).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DatasetRecord {
    /// Dataset or snapshot name as a null-terminated byte array.
    pub name: [u8; 64],
    /// Filesystem mount point path as a null-terminated byte array.
    pub mountpoint: [u8; 64],
    /// Root directory object identifier for the dataset.
    pub root_obj: u64,
    /// Transaction group number associated with this dataset or snapshot.
    pub txg: u64,
    /// Flag indicating if this record represents a snapshot (1) or dataset (0).
    pub is_snapshot: u8,
    /// Alignment padding bytes to ensure fixed 152-byte record sizing.
    pub _pad: [u8; 7],
}

impl DatasetRecord {
    /// Creates a new dataset or snapshot descriptor.
    ///
    /// # Arguments
    /// * `name` - Dataset or snapshot identifier string.
    /// * `mountpoint` - Mount point path string.
    /// * `root_obj` - Root directory object ID.
    /// * `txg` - Associated transaction group number.
    /// * `is_snapshot` - True if creating a snapshot descriptor.
    pub fn new(name: &str, mountpoint: &str, root_obj: u64, txg: u64, is_snapshot: bool) -> Self {
        let mut r = Self {
            name: [0; 64],
            mountpoint: [0; 64],
            root_obj,
            txg,
            is_snapshot: is_snapshot as u8,
            _pad: [0; 7],
        };
        let n = name.len().min(63);
        r.name[..n].copy_from_slice(&name.as_bytes()[..n]);
        let m = mountpoint.len().min(63);
        r.mountpoint[..m].copy_from_slice(&mountpoint.as_bytes()[..m]);
        r
    }

    fn str_of(bytes: &[u8]) -> &str {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..len]).unwrap_or("")
    }

    /// Returns the dataset or snapshot name as a UTF-8 string slice.
    pub fn name_str(&self) -> &str {
        Self::str_of(&self.name)
    }

    /// Returns the mount point path as a UTF-8 string slice.
    pub fn mountpoint_str(&self) -> &str {
        Self::str_of(&self.mountpoint)
    }
}

/// The ZFS file server state.
pub struct ZfsServer {
    /// Data Management Unit controlling object sets, dnodes, and block transactions.
    pub dmu: Dmu,
    /// ZFS Attribute Processor managing directory namespaces and indexes.
    pub zap: Zap,
    /// List of registered dataset and snapshot records.
    pub datasets: Vec<DatasetRecord>,
    /// Open handles per inode; unlinked inodes stay allocated until their last close.
    pub(super) open_counts: BTreeMap<u64, u32>,
    pub(super) orphans: BTreeSet<u64>,
}

impl ZfsServer {
    /// Mounts the pool on the primary disk, creating a new one only on a blank disk.
    ///
    /// A disk that holds a pool which cannot be imported (or anything else) is never
    /// formatted: the kernel stops with an error instead, leaving the data for repair.
    pub fn new() -> Self {
        let vdev = Vdev::open();
        let contents = super::spa::Spa::probe(&vdev);
        let mut vdev = vdev;
        if contents == Some(super::spa::DiskContents::Pool) {
            // Retry the import: a transient read error must not look like a missing pool
            for _ in 0..3 {
                match Spa::open(vdev) {
                    Ok(pool) => return Self::imported(pool),
                    Err(v) => vdev = v,
                }
            }
            panic!("OpenZFS: the disk holds pool data that cannot be imported; refusing to format it");
        }
        if vdev.is_hardware_backed() && contents != Some(super::spa::DiskContents::Blank) {
            panic!("OpenZFS: the disk is not blank ({:?}); refusing to create a pool on it", contents);
        }
        let vdev = match Spa::open(vdev) {
            Ok(pool) => return Self::imported(pool),
            Err(vdev) => vdev,
        };
        Self::create_on(vdev)
    }

    /// Finishes importing an opened pool.
    fn imported((spa, ub): (Spa, super::types::Uberblock)) -> Self {
        let mut server = Self::with_dmu(Dmu::new(spa, ub));
        server.load_datasets();
        crate::console::set_color(
            uefi::proto::console::text::Color::LightGreen,
            uefi::proto::console::text::Color::Black,
        );
        crate::println!(
            "[+] OpenZFS: Imported pool '{}' ({} MiB, TXG #{}, {} objects)",
            server.dmu.spa.pool_name_str(),
            server.dmu.spa.total_capacity_bytes() / (1024 * 1024),
            server.dmu.ub.txg,
            server.dmu.ub.next_obj - 1
        );
        server
    }

    /// Creates a new pool on a blank device.
    fn create_on(vdev: Vdev) -> Self {
        let spa = Spa::create(vdev, "hydrapool").expect("ZFS: unable to create pool");
        let mut server = Self::with_dmu(Dmu::new(spa, Dmu::initial_uberblock()));
        if let Err(e) = server.populate_new_pool() {
            crate::println!("[!] OpenZFS: failed to initialise new pool: {}", e);
        }
        crate::println!(
            "[+] OpenZFS: Created pool '{}' ({} MiB, format v{})",
            server.dmu.spa.pool_name_str(),
            server.dmu.spa.total_capacity_bytes() / (1024 * 1024),
            POOL_VERSION
        );
        server
    }

    fn with_dmu(dmu: Dmu) -> Self {
        Self {
            dmu,
            zap: Zap::new(),
            datasets: Vec::new(),
            open_counts: BTreeMap::new(),
            orphans: BTreeSet::new(),
        }
    }

    /// Creates the root directory, the base hierarchy and the account database.
    fn populate_new_pool(&mut self) -> Result<(), i64> {
        let root = self.dmu.alloc_object(S_IFDIR | 0o755).map_err(|_| -5i64)?;
        let mut dn = self.dmu.get_dnode(root).map_err(|_| -5i64)?;
        dn.nlink = 2;
        dn.parent = root;
        let (s, ns) = crate::arch::rtc::now();
        dn.atime = s as i64;
        dn.mtime = s as i64;
        dn.ctime = s as i64;
        dn.atime_ns = ns;
        dn.mtime_ns = ns;
        dn.ctime_ns = ns;
        self.dmu.put_dnode(root, dn);
        self.dmu.ub.root_obj = root;

        let bin = self.mkdir(root, b"bin", 0o755, 0, 0)?;
        let etc = self.mkdir(root, b"etc", 0o755, 0, 0)?;
        let home = self.mkdir(root, b"home", 0o755, 0, 0)?;
        self.mkdir(home, b"hydra", 0o755, 1000, 1000)?;
        let root_home = self.mkdir(root, b"root", 0o700, 0, 0)?;
        let tmp = self.mkdir(root, b"tmp", 0o1777, 0, 0)?;

        let passwd: &[u8] = b"root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nhydra:x:1000:1000:Hydra User,,,:/home/hydra:/bin/sh\n";
        let group: &[u8] = b"root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:hydra\nsudo:x:27:hydra\nnogroup:x:65534:\nhydra:x:1000:\n";
        for (name, data) in [(&b"passwd"[..], passwd), (&b"group"[..], group)] {
            let ino = self.create(etc, name, 0o644, 0, 0)?;
            self.write(ino, 0, data)?;
        }
        let readme: &[u8] = b"Hydra OS Default Filesystem: OpenZFS Architecture\nIntegrated as an independent Microkernel File Server.\nAll blocks are verified via Fletcher-4 checksums!\n";
        let ino = self.create(bin, b"readme.txt", 0o644, 0, 0)?;
        self.write(ino, 0, readme)?;
        let demo: &[u8] = b"#!/bin/sh\n# Hydra OS Shell Automation Script\necho === Running demo.sh ===\nuname -a\npwd\necho Listing files in /bin:\nls\necho OpenZFS pool status:\ndf -h\necho === Finished demo.sh ===\n";
        let ino = self.create(bin, b"demo.sh", 0o755, 0, 0)?;
        self.write(ino, 0, demo)?;

        let datasets_obj = self.dmu.alloc_object(S_IFREG | 0o600).map_err(|_| -5i64)?;
        self.dmu.ub.datasets_obj = datasets_obj;
        self.datasets = alloc::vec![
            DatasetRecord::new("hydrapool/root", "/", root, 0, false),
            DatasetRecord::new("hydrapool/bin", "/bin", bin, 0, false),
            DatasetRecord::new("hydrapool/etc", "/etc", etc, 0, false),
            DatasetRecord::new("hydrapool/home", "/home", home, 0, false),
            DatasetRecord::new("hydrapool/root_home", "/root", root_home, 0, false),
            DatasetRecord::new("hydrapool/tmp", "/tmp", tmp, 0, false),
        ];
        self.store_datasets()?;
        self.sync()?;
        Ok(())
    }

    fn load_datasets(&mut self) {
        let obj = self.dmu.ub.datasets_obj;
        if obj == 0 {
            return;
        }
        let size = match self.dmu.get_dnode(obj) {
            Ok(dn) => dn.size as usize,
            Err(_) => return,
        };
        let mut raw = alloc::vec![0u8; size];
        if self.dmu.read(obj, 0, &mut raw).is_err() {
            return;
        }
        let rec = core::mem::size_of::<DatasetRecord>();
        self.datasets = raw
            .chunks_exact(rec)
            .map(|c| unsafe { core::ptr::read_unaligned(c.as_ptr() as *const DatasetRecord) })
            .collect();
    }

    fn store_datasets(&mut self) -> Result<(), i64> {
        let obj = self.dmu.ub.datasets_obj;
        let rec = core::mem::size_of::<DatasetRecord>();
        let mut raw = Vec::with_capacity(self.datasets.len() * rec);
        for d in &self.datasets {
            raw.extend_from_slice(unsafe { core::slice::from_raw_parts(d as *const DatasetRecord as *const u8, rec) });
        }
        self.dmu.truncate(obj, 0).map_err(|_| -5i64)?;
        self.dmu.write(obj, 0, &raw).map_err(|_| -5i64)?;
        Ok(())
    }

    /// Takes a point-in-time snapshot of the pool. Blocks it references are never freed.
    pub fn snapshot(&mut self, dataset_index: usize, snap_name: &str) -> Result<u64, i64> {
        let ds = *self.datasets.iter().filter(|d| d.is_snapshot == 0).nth(dataset_index).ok_or(-22i64)?;
        let txg = self.sync()?;
        self.dmu.ub.snapshot_txg = txg;
        let full = alloc::format!("{}@{}", ds.name_str(), snap_name);
        self.datasets.push(DatasetRecord::new(&full, ds.mountpoint_str(), ds.root_obj, txg, true));
        self.store_datasets()?;
        self.sync()?;
        Ok(txg)
    }

    /// Commits the open transaction group.
    pub fn sync(&mut self) -> Result<u64, i64> {
        self.dmu.sync().map_err(|e| {
            crate::println!("[!] OpenZFS: commit failed: {}", e);
            -5i64
        })
    }

    /// Commits if enough dirty data has accumulated.
    pub fn maybe_sync(&mut self) {
        if self.dmu.dirty_blocks() >= super::dmu::DIRTY_SYNC_THRESHOLD {
            let _ = self.sync();
        }
    }

    /// Returns the root directory object ID of the active dataset.
    pub fn root_obj(&self) -> u64 {
        self.dmu.ub.root_obj
    }
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

/// Runs `f` with the mounted file server, or fails with `-EIO` if none is mounted.
pub fn with_server<R>(f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
    let mut guard = ZFS_SERVER.lock();
    match guard.as_mut() {
        Some(s) => f(s),
        None => Err(-5),
    }
}
