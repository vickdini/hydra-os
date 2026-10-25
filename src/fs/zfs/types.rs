/// Core ZFS on-disk data structures and checksum algorithms for Hydra OS.

/// Standard ZFS Uberblock magic: 0x00bab10c (OO-BA-BLOC)
pub const ZFS_UBERBLOCK_MAGIC: u64 = 0x0000_0000_00ba_b10c;

/// Persistent Vdev Label Magic: "HYDRAZFS" (0x4859_4452_415a_4653)
pub const VDEV_LABEL_MAGIC: u64 = 0x4859_4452_415a_4653;

/// Storage Pool Allocator Version
pub const SPA_VERSION_5000: u64 = 5000;

/// Default block size (4 KiB)
pub const ZFS_BLOCK_SIZE: usize = 4096;

/// Fletcher-4 Checksum (4 x 64-bit accumulators)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fletcher4 {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl Fletcher4 {
    /// Computes standard ZFS Fletcher-4 checksum across 32-bit integers.
    pub fn compute(data: &[u8]) -> Self {
        let mut a: u64 = 0;
        let mut b: u64 = 0;
        let mut c: u64 = 0;
        let mut d: u64 = 0;

        // Process in 4-byte (32-bit) words
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
            for (i, &b_byte) in remainder.iter().enumerate() {
                buf[i] = b_byte;
            }
            let word = u32::from_le_bytes(buf) as u64;
            a = a.wrapping_add(word);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        Self { a, b, c, d }
    }
}

/// ZFS Block Pointer (`blkptr_t`)
/// Represents a location on a vdev along with integrity checksum, size, and birth TXG.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockPointer {
    pub vdev_id: u32,
    pub offset: u64,
    pub logical_size: u32,
    pub physical_size: u32,
    pub birth_txg: u64,
    pub checksum: Fletcher4,
    pub is_allocated: bool,
}

impl BlockPointer {
    pub const fn empty() -> Self {
        Self {
            vdev_id: 0,
            offset: 0,
            logical_size: 0,
            physical_size: 0,
            birth_txg: 0,
            checksum: Fletcher4 { a: 0, b: 0, c: 0, d: 0 },
            is_allocated: false,
        }
    }
}

/// ZFS Uberblock (`uberblock_t`)
/// The root of a ZFS pool's Merkle tree. Updated on every transaction group (TXG) commit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub root_bp: BlockPointer,
    pub pool_name: [u8; 16],
}

impl Uberblock {
    pub const fn new(txg: u64, root_bp: BlockPointer, pool_name: [u8; 16]) -> Self {
        Self {
            magic: ZFS_UBERBLOCK_MAGIC,
            version: SPA_VERSION_5000,
            txg,
            guid_sum: 0x4859_4452_415f_5350, // "HYDRA_SP"
            timestamp: 0,
            root_bp,
            pool_name,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == ZFS_UBERBLOCK_MAGIC && self.version == SPA_VERSION_5000
    }
}

/// On-disk Persistent Vdev Label stored in Block 0.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VdevLabel {
    pub magic: u64,
    pub pool_name: [u8; 16],
    pub uberblock: Uberblock,
    pub root_dir_obj: u64,
    pub bin_dir_obj: u64,
    pub next_obj_id: u64,
    pub allocated_blocks: u64,
    pub checksum: Fletcher4,
}

impl VdevLabel {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            pool_name: [0u8; 16],
            uberblock: Uberblock::new(1, BlockPointer::empty(), [0u8; 16]),
            root_dir_obj: 0,
            bin_dir_obj: 0,
            next_obj_id: 0,
            allocated_blocks: 0,
            checksum: Fletcher4 { a: 0, b: 0, c: 0, d: 0 },
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == VDEV_LABEL_MAGIC && self.uberblock.is_valid()
    }
}

/// Dnode object types in DMU
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnodeType {
    None = 0,
    PlainFile = 1,
    Directory = 2,
    Dataset = 3,
    MasterNode = 4,
}

/// Physical Dnode structure (`dnode_phys_t`)
/// Describes an object (file, directory, or dataset) and points to its data blocks.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnodePhys {
    pub obj_type: DnodeType,
    pub nlevels: u8,
    pub block_size: u32,
    pub file_size: u64,
    pub birth_txg: u64,
    pub direct_blocks: [BlockPointer; 4],
    pub name: [u8; 32],
}

impl DnodePhys {
    pub const fn empty() -> Self {
        Self {
            obj_type: DnodeType::None,
            nlevels: 1,
            block_size: ZFS_BLOCK_SIZE as u32,
            file_size: 0,
            birth_txg: 0,
            direct_blocks: [BlockPointer::empty(); 4],
            name: [0u8; 32],
        }
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = if bytes.len() > 31 { 31 } else { bytes.len() };
        for i in 0..len {
            self.name[i] = bytes[i];
        }
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let mut len = 0;
        while len < self.name.len() && self.name[len] != 0 {
            len += 1;
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}
