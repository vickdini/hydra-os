//! # Hydra ZFS On-Disk Format (version 2)
//!
//! ## Subsystem Role & Architecture
//! This module defines the core on-disk structures, magic numbers, constants, and
//! serialization helpers for Hydra's OpenZFS filesystem implementation. All on-disk structures
//! are little-endian and operate within uniform 4 KiB physical and logical block frames.
//!
//! ## Architectural Rationale & Layout
//! The layout follows a copy-on-write Merkle tree design rooted in the active uberblock:
//!
//! ```text
//! block 0                     VdevLabel (pool geometry, never rewritten after creation)
//! blocks 1 ..= 32             Uberblock ring (txg N lives in slot N % 32)
//! blocks 33 .. 33+B           Space bitmap (1 bit per block, B = total_blocks / 32768)
//! blocks data_start ..        Copy-on-write data: file data, indirect blocks, dnode array
//! ```
//!
//! Every object (file, directory, symlink, the dnode array itself) is described by a
//! 512-byte [`DnodePhys`] whose three top-level [`BlockPointer`]s root a tree of 64-way
//! indirect blocks. The dnode for object N lives at byte N * 512 of the *meta object*,
//! whose own dnode is embedded in the active [`Uberblock`]. A commit (transaction group)
//! writes changed blocks to fresh locations bottom-up and finishes by writing a new
//! uberblock, so the on-disk state is always a consistent tree.
//!
//! ## Key Types & Interfaces
//! - [`Fletcher4`]: 256-bit checksum accumulator protecting labels, block pointers, and uberblocks.
//! - [`BlockPointer`]: 64-byte block descriptor storing LBA, birth TXG, compression, and checksum.
//! - [`DnodePhys`]: 512-byte inode equivalent holding POSIX attributes, bonus buffer, and block pointers.
//! - [`VdevLabel`]: Persistent geometry descriptor on block 0 storing partition metrics and pool GUID.
//! - [`Uberblock`]: Transactional root tracking active meta-dnode and transaction state.
//!
//! ## Hardware & Privilege Semantics
//! These structures directly represent on-disk byte arrays read from or written to non-volatile
//! storage (ATA drives or RAM backing). Integrity is validated via hardware/software Fletcher-4
//! checksum verification before any block is accepted by higher layers.

/// Standard ZFS Uberblock magic: 0x00bab10c (OO-BA-BLOC)
pub const ZFS_UBERBLOCK_MAGIC: u64 = 0x0000_0000_00ba_b10c;

/// Vdev label magic: "HYDRAZF2"
pub const VDEV_LABEL_MAGIC: u64 = u64::from_le_bytes(*b"HYDRAZF2");

/// On-disk format version.
pub const POOL_VERSION: u64 = 2;

/// Block size (4 KiB) used for every on-disk structure.
pub const ZFS_BLOCK_SIZE: usize = 4096;

/// Number of uberblock slots.
pub const UBERBLOCK_RING: u64 = 32;

/// Block pointers per indirect block.
pub const BP_PER_BLOCK: usize = ZFS_BLOCK_SIZE / core::mem::size_of::<BlockPointer>();

/// Top-level block pointers held directly in a dnode.
pub const DN_TOP_PTRS: usize = 3;

/// Size of a dnode in the dnode array.
pub const DNODE_SIZE: usize = 512;

/// Fletcher-4 Checksum (4 x 64-bit accumulators)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fletcher4 {
    /// First 64-bit accumulator word ($A = \sum X_i$).
    pub a: u64,
    /// Second 64-bit accumulator word ($B = \sum A$).
    pub b: u64,
    /// Third 64-bit accumulator word ($C = \sum B$).
    pub c: u64,
    /// Fourth 64-bit accumulator word ($D = \sum C$).
    pub d: u64,
}

impl Fletcher4 {
    /// Computes standard ZFS Fletcher-4 checksum across 32-bit integers.
    pub fn compute(data: &[u8]) -> Self {
        let mut a: u64 = 0;
        let mut b: u64 = 0;
        let mut c: u64 = 0;
        let mut d: u64 = 0;

        let chunks = data.chunks_exact(4);
        let remainder = chunks.remainder();

        for chunk in chunks {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            a = a.wrapping_add(word);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        if !remainder.is_empty() {
            let mut buf = [0u8; 4];
            buf[..remainder.len()].copy_from_slice(remainder);
            let word = u32::from_le_bytes(buf) as u64;
            a = a.wrapping_add(word);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        Self { a, b, c, d }
    }
}

/// ZFS Block Pointer (`blkptr_t`, 64 bytes): where a block lives, when it was written,
/// and the checksum its contents must match. `block == 0` is a hole (reads as zeroes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockPointer {
    /// Logical block address on the virtual device (0 represents a sparse hole).
    pub block: u64,
    /// Transaction group number in which this block was allocated.
    pub birth_txg: u64,
    /// Fletcher-4 checksum validating the contents of the target block.
    pub checksum: Fletcher4,
    /// Logical size of the data payload in bytes.
    pub lsize: u32,
    /// Indirection level (0 = leaf data block, >0 = indirect block pointer table).
    pub level: u8,
    /// Reserved alignment padding bytes.
    pub _pad: [u8; 3],
    /// Reserved for future expansion.
    pub _reserved: u64,
}

impl BlockPointer {
    /// Constant representation of a zeroed/sparse block hole.
    pub const HOLE: Self = Self {
        block: 0,
        birth_txg: 0,
        checksum: Fletcher4 { a: 0, b: 0, c: 0, d: 0 },
        lsize: 0,
        level: 0,
        _pad: [0; 3],
        _reserved: 0,
    };

    /// Returns a zeroed, unallocated block pointer hole.
    pub const fn empty() -> Self {
        Self::HOLE
    }

    /// Returns true if this block pointer represents an unallocated sparse hole.
    pub fn is_hole(&self) -> bool {
        self.block == 0
    }
}

/// Object kinds. Stored in [`DnodePhys::obj_type`] as a `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnodeType {
    /// Unallocated dnode slot.
    None = 0,
    /// Standard regular file object.
    PlainFile = 1,
    /// Directory namespace object.
    Directory = 2,
    /// Dataset root descriptor object.
    Dataset = 3,
    /// Master node catalog object.
    MasterNode = 4,
    /// Symbolic link object.
    Symlink = 5,
    /// Character/block device, FIFO or socket (see the mode bits).
    Special = 6,
}

impl DnodeType {
    /// Converts a raw `u8` identifier into a [`DnodeType`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::PlainFile,
            2 => Self::Directory,
            3 => Self::Dataset,
            4 => Self::MasterNode,
            5 => Self::Symlink,
            6 => Self::Special,
            _ => Self::None,
        }
    }

    /// Object kind implied by a Linux `st_mode`.
    pub fn from_mode(mode: u32) -> Self {
        match mode & S_IFMT {
            S_IFREG => Self::PlainFile,
            S_IFDIR => Self::Directory,
            S_IFLNK => Self::Symlink,
            0 => Self::None,
            _ => Self::Special,
        }
    }
}

// Linux st_mode file type bits
/// Mask for file type bitfield in mode flags.
pub const S_IFMT: u32 = 0o170000;
/// Socket file type bit.
pub const S_IFSOCK: u32 = 0o140000;
/// Symbolic link file type bit.
pub const S_IFLNK: u32 = 0o120000;
/// Regular file type bit.
pub const S_IFREG: u32 = 0o100000;
/// Block special device file type bit.
pub const S_IFBLK: u32 = 0o060000;
/// Directory file type bit.
pub const S_IFDIR: u32 = 0o040000;
/// Character special device file type bit.
pub const S_IFCHR: u32 = 0o020000;
/// FIFO / named pipe file type bit.
pub const S_IFIFO: u32 = 0o010000;

/// Dnode flag: a symlink target is stored inline in the bonus area.
pub const DNODE_FLAG_INLINE: u8 = 0x01;

/// Bytes available in a dnode's bonus area (inline symlink targets).
pub const DNODE_BONUS_SIZE: usize = 216;

/// Physical dnode (`dnode_phys_t`, 512 bytes): an object's attributes and the root of
/// its block tree.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnodePhys {
    /// File mode and permission bits.
    pub mode: u32,
    /// Hard link reference count.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Logical size of the object in bytes.
    pub size: u64,
    /// Last access time in seconds since Unix epoch.
    pub atime: i64,
    /// Last modification time in seconds since Unix epoch.
    pub mtime: i64,
    /// Last attribute change time in seconds since Unix epoch.
    pub ctime: i64,
    /// Fractional nanosecond component of `atime`.
    pub atime_ns: u32,
    /// Fractional nanosecond component of `mtime`.
    pub mtime_ns: u32,
    /// Fractional nanosecond component of `ctime`.
    pub ctime_ns: u32,
    /// Indirection levels for tree navigation (1 = direct blocks).
    pub nlevels: u8,
    /// Bitwise flags (e.g. [`DNODE_FLAG_INLINE`]).
    pub flags: u8,
    /// Object kind indicator matching [`DnodeType`].
    pub obj_type: u8,
    /// Reserved padding byte.
    pub _pad: u8,
    /// Inode number of the parent directory.
    pub parent: u64,
    /// Inode generation counter.
    pub generation: u64,
    /// Device identifier for character / block special devices.
    pub rdev: u64,
    /// Link pointer to next free dnode slot when unallocated.
    pub next_free: u64,
    /// Transaction group in which this dnode was created.
    pub birth_txg: u64,
    /// Top-level block pointers rooting the object's block tree.
    pub blkptr: [BlockPointer; DN_TOP_PTRS],
    /// Bonus buffer for small symlink targets or extended attributes.
    pub bonus: [u8; DNODE_BONUS_SIZE],
}

const _: () = assert!(core::mem::size_of::<DnodePhys>() == DNODE_SIZE);
const _: () = assert!(core::mem::size_of::<BlockPointer>() == 64);

impl DnodePhys {
    /// Creates a blank, zero-initialized dnode descriptor.
    pub const fn empty() -> Self {
        Self {
            mode: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            nlevels: 1,
            flags: 0,
            obj_type: 0,
            _pad: 0,
            parent: 0,
            generation: 0,
            rdev: 0,
            next_free: 0,
            birth_txg: 0,
            blkptr: [BlockPointer::HOLE; DN_TOP_PTRS],
            bonus: [0; DNODE_BONUS_SIZE],
        }
    }

    /// Returns the high-level [`DnodeType`] of this object.
    pub fn kind(&self) -> DnodeType {
        DnodeType::from_u8(self.obj_type)
    }

    /// Serializes this dnode into a 512-byte raw array.
    pub fn to_bytes(&self) -> [u8; DNODE_SIZE] {
        unsafe { core::mem::transmute_copy(self) }
    }

    /// Deserializes a 512-byte raw array into a [`DnodePhys`] struct.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut raw = [0u8; DNODE_SIZE];
        raw.copy_from_slice(&bytes[..DNODE_SIZE]);
        unsafe { core::mem::transmute(raw) }
    }
}

/// On-disk vdev label (block 0): fixed pool geometry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VdevLabel {
    /// Magic signature verifying pool format ([`VDEV_LABEL_MAGIC`]).
    pub magic: u64,
    /// Pool format version ([`POOL_VERSION`]).
    pub version: u64,
    /// Globally unique pool identifier.
    pub pool_guid: u64,
    /// Total addressable 4 KiB logical blocks on device.
    pub total_blocks: u64,
    /// First block of the space allocation bitmap.
    pub bitmap_start: u64,
    /// Total blocks occupied by the space allocation bitmap.
    pub bitmap_blocks: u64,
    /// First block of the circular uberblock ring.
    pub ub_start: u64,
    /// Number of uberblock slots in the ring ([`UBERBLOCK_RING`]).
    pub ub_count: u64,
    /// Starting block of user and metadata copy-on-write storage.
    pub data_start: u64,
    /// Pool name as a null-padded byte array.
    pub pool_name: [u8; 32],
    /// Fletcher-4 checksum validating label contents.
    pub checksum: Fletcher4,
}

impl VdevLabel {
    fn body(&self) -> &[u8] {
        let len = core::mem::size_of::<Self>() - core::mem::size_of::<Fletcher4>();
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, len) }
    }

    /// Recalculates and updates the Fletcher-4 checksum across the label header.
    pub fn seal(&mut self) {
        self.checksum = Fletcher4::compute(self.body());
    }

    /// Validates the magic signature, version, and Fletcher-4 checksum.
    pub fn is_valid(&self) -> bool {
        self.magic == VDEV_LABEL_MAGIC && self.version == POOL_VERSION && Fletcher4::compute(self.body()) == self.checksum
    }
}

/// ZFS Uberblock: root of the pool's Merkle tree for one transaction group.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Uberblock {
    /// Magic signature verifying uberblock validity ([`ZFS_UBERBLOCK_MAGIC`]).
    pub magic: u64,
    /// On-disk pool format version ([`POOL_VERSION`]).
    pub version: u64,
    /// Monotonically increasing transaction group sequence number.
    pub txg: u64,
    /// Timestamp in seconds since Unix epoch when this transaction group committed.
    pub timestamp: u64,
    /// Dnode of the meta object (the dnode array).
    pub meta_dnode: DnodePhys,
    /// Next never-used object number.
    pub next_obj: u64,
    /// Head of the list of freed object numbers (linked through `DnodePhys::next_free`).
    pub free_obj_head: u64,
    /// Object number of the root directory.
    pub root_obj: u64,
    /// Object holding the dataset and snapshot records.
    pub datasets_obj: u64,
    /// Blocks in use (including metadata).
    pub allocated_blocks: u64,
    /// Highest txg captured by a snapshot; blocks born at or before it are never freed.
    pub snapshot_txg: u64,
    /// Fletcher-4 checksum validating the entire uberblock payload.
    pub checksum: Fletcher4,
}

impl Uberblock {
    fn body(&self) -> &[u8] {
        let len = core::mem::size_of::<Self>() - core::mem::size_of::<Fletcher4>();
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, len) }
    }

    /// Recalculates and updates the Fletcher-4 checksum for this uberblock.
    pub fn seal(&mut self) {
        self.checksum = Fletcher4::compute(self.body());
    }

    /// Verifies the magic signature, format version, and Fletcher-4 checksum.
    pub fn is_valid(&self) -> bool {
        self.magic == ZFS_UBERBLOCK_MAGIC && self.version == POOL_VERSION && Fletcher4::compute(self.body()) == self.checksum
    }
}

/// Linux `d_type` values used in directory entries: unknown entry type.
pub const DT_UNKNOWN: u8 = 0;
/// Linux `d_type` value for a FIFO (named pipe).
pub const DT_FIFO: u8 = 1;
/// Linux `d_type` value for a character device.
pub const DT_CHR: u8 = 2;
/// Linux `d_type` value for a directory.
pub const DT_DIR: u8 = 4;
/// Linux `d_type` value for a block device.
pub const DT_BLK: u8 = 6;
/// Linux `d_type` value for a regular file.
pub const DT_REG: u8 = 8;
/// Linux `d_type` value for a symbolic link.
pub const DT_LNK: u8 = 10;
/// Linux `d_type` value for a UNIX domain socket.
pub const DT_SOCK: u8 = 12;

/// Directory entry type for a Linux `st_mode`.
pub fn dtype_from_mode(mode: u32) -> u8 {
    match mode & S_IFMT {
        S_IFREG => DT_REG,
        S_IFDIR => DT_DIR,
        S_IFLNK => DT_LNK,
        S_IFCHR => DT_CHR,
        S_IFBLK => DT_BLK,
        S_IFIFO => DT_FIFO,
        S_IFSOCK => DT_SOCK,
        _ => DT_UNKNOWN,
    }
}
