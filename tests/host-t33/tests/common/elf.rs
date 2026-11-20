//! In-memory ELF64 builder shared by the loader tests.

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PT_GNU_STACK: u32 = 0x6474_E551;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

/// One program header. `flags` is `p_flags` (PF_X=1, PF_W=2, PF_R=4).
#[derive(Clone, Copy)]
pub struct Ph {
    pub ty: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// Read+execute PT_LOAD.
pub fn load(offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
    Ph { ty: PT_LOAD, flags: 5, offset, vaddr, filesz, memsz }
}

/// PT_LOAD with explicit flags.
pub fn load_with(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
    Ph { ty: PT_LOAD, flags, offset, vaddr, filesz, memsz }
}

/// An ELF64 image under construction.
pub struct Elf {
    pub bytes: Vec<u8>,
}

impl Elf {
    /// Header + program headers at offset 64, file padded to `len` bytes.
    pub fn new(e_type: u16, entry: u64, phs: &[Ph], len: usize) -> Elf {
        let mut b = vec![0u8; len.max(64 + 56 * phs.len())];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little-endian
        b[6] = 1; // EV_CURRENT
        b[16..18].copy_from_slice(&e_type.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
        for (i, p) in phs.iter().enumerate() {
            let o = 64 + 56 * i;
            b[o..o + 4].copy_from_slice(&p.ty.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&p.flags.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&p.offset.to_le_bytes());
            b[o + 16..o + 24].copy_from_slice(&p.vaddr.to_le_bytes());
            b[o + 24..o + 32].copy_from_slice(&p.vaddr.to_le_bytes());
            b[o + 32..o + 40].copy_from_slice(&p.filesz.to_le_bytes());
            b[o + 40..o + 48].copy_from_slice(&p.memsz.to_le_bytes());
            b[o + 48..o + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        Elf { bytes: b }
    }

    pub fn put(mut self, offset: usize, data: &[u8]) -> Elf {
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        self
    }
}
