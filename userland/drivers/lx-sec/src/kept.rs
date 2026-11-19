//! lx-sec's kept state: what must outlive a crash of lx-sec (the keyrings; the device
//! programs the kernel was handed), in the kept-state memory object the kernel keeps for the
//! service across restarts (`docs/linux-services-design.md` 5.1).
//!
//! The object holds a small header and a few *blobs*. Each blob has two halves; a new
//! version is written into the half not in use, its length, sequence number and checksum
//! after it, and only then the header's "active half" word flips (the commit). A crash in
//! the middle of a write leaves the previous version active and whole. A restart checks the
//! magic, the version and the active half's checksum before it uses anything; anything that
//! does not check out is dropped (the service starts empty, as on a first start).
//!
//! ```text
//! 0x000  magic u64 | layout version u32 | blobs u32
//! 0x040  per blob (64 bytes each): active u32 | pad u32 | [len u64, seq u64, sum u64] x 2
//! 0x400  the blobs' halves, at the offsets of BLOBS
//! ```

use core::sync::atomic::{fence, Ordering};

/// "LXSECKPT".
const MAGIC: u64 = 0x5450_4B43_4553_584C;
/// Bumped when the layout or a blob's encoding changes (an older kept object is dropped).
const VERSION: u32 = 1;
/// "No half active".
const NONE: u32 = u32::MAX;

/// A blob of the kept object: its two halves start at `off` and `off + cap`.
#[derive(Clone, Copy)]
pub struct Blob {
    /// Index (its header at `0x40 + 64 * index`).
    pub index: usize,
    /// Offset of the first half.
    pub off: usize,
    /// Size of each half.
    pub cap: usize,
}

/// The keyrings (both halves: 2 x 448 KiB).
pub const KEYS: Blob = Blob { index: 0, off: 0x400, cap: 448 * 1024 };
/// The device programs handed to the kernel (2 x 60 KiB).
pub const DEVICES: Blob = Blob { index: 1, off: 0x400 + 2 * 448 * 1024, cap: 60 * 1024 };
/// The size the kept object needs.
pub const SIZE: usize = DEVICES.off + 2 * DEVICES.cap;
const BLOBS: u32 = 2;

/// The kept object, mapped at `base` (`size` bytes).
pub struct Kept {
    base: *mut u8,
    size: usize,
}

// SAFETY: one kept object per process; writers serialize on their own state's lock
unsafe impl Send for Kept {}
unsafe impl Sync for Kept {}

/// FNV-1a, 64 bits.
pub fn checksum(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl Kept {
    /// The kept object at `base`; `fresh`: the kernel just made it (zeroed). An object whose
    /// magic or version does not match is reset (nothing kept).
    ///
    /// # Safety
    /// `base` must be the mapped kept object, `size` bytes, writable, for the process's life.
    pub unsafe fn open(base: *mut u8, size: usize) -> Option<Kept> {
        if base.is_null() || size < SIZE {
            return None;
        }
        let k = Kept { base, size };
        if k.r64(0) != MAGIC || k.r32(8) != VERSION || k.r32(12) != BLOBS {
            // A first start (zeroed), or a layout this build does not know: start empty
            for b in [KEYS, DEVICES] {
                k.w32(Self::hdr(b), NONE);
            }
            fence(Ordering::SeqCst);
            k.w64(0, MAGIC);
            k.w32(8, VERSION);
            k.w32(12, BLOBS);
        }
        Some(k)
    }

    fn hdr(b: Blob) -> usize {
        0x40 + 64 * b.index
    }

    fn r64(&self, off: usize) -> u64 {
        // SAFETY: within the object (offsets are this module's own)
        unsafe { core::ptr::read_volatile(self.base.add(off) as *const u64) }
    }
    fn r32(&self, off: usize) -> u32 {
        // SAFETY: as above
        unsafe { core::ptr::read_volatile(self.base.add(off) as *const u32) }
    }
    fn w64(&self, off: usize, v: u64) {
        // SAFETY: as above
        unsafe { core::ptr::write_volatile(self.base.add(off) as *mut u64, v) }
    }
    fn w32(&self, off: usize, v: u32) {
        // SAFETY: as above
        unsafe { core::ptr::write_volatile(self.base.add(off) as *mut u32, v) }
    }

    /// The committed contents of blob `b`, if any and whole.
    pub fn read(&self, b: Blob) -> Option<&[u8]> {
        let h = Self::hdr(b);
        let active = self.r32(h);
        if active > 1 {
            return None;
        }
        let m = h + 8 + 24 * active as usize;
        let (len, sum) = (self.r64(m) as usize, self.r64(m + 16));
        if len > b.cap || b.off + 2 * b.cap > self.size {
            return None;
        }
        // SAFETY: within the object
        let data = unsafe { core::slice::from_raw_parts(self.base.add(b.off + active as usize * b.cap), len) };
        (checksum(data) == sum).then_some(data)
    }

    /// Commits `data` as blob `b`'s new contents. `false`: it does not fit (the previous
    /// version stays committed).
    pub fn write(&self, b: Blob, data: &[u8]) -> bool {
        if data.len() > b.cap {
            return false;
        }
        let h = Self::hdr(b);
        let active = self.r32(h);
        let (seq, half) = if active > 1 { (0, 0usize) } else { (self.r64(h + 8 + 24 * active as usize + 8), 1 - active as usize) };
        // SAFETY: within the object; the half not in use is ours to overwrite
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(b.off + half * b.cap), data.len()) };
        let m = h + 8 + 24 * half;
        self.w64(m, data.len() as u64);
        self.w64(m + 8, seq.wrapping_add(1));
        self.w64(m + 16, checksum(data));
        fence(Ordering::SeqCst);
        self.w32(h, half as u32);
        true
    }

    /// Forgets blob `b` (a restart then finds nothing).
    pub fn clear(&self, b: Blob) {
        self.w32(Self::hdr(b), NONE);
    }
}

/// A little-endian byte writer for the blobs' encodings.
#[derive(Default)]
pub struct Enc {
    /// The bytes so far.
    pub buf: alloc::vec::Vec<u8>,
}

impl Enc {
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
}

/// The reader matching [`Enc`]: every read fails (`None`) past the end.
pub struct Dec<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

/// The process's kept object (set once at start).
static KEPT: core::sync::atomic::AtomicPtr<Kept> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Makes `k` the process's kept object.
pub fn set(k: Kept) {
    let b = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(k));
    KEPT.store(b, Ordering::Release);
}

/// The process's kept object, if it has one.
pub fn get() -> Option<&'static Kept> {
    let p = KEPT.load(Ordering::Acquire);
    // SAFETY: set once from a leaked box, never freed
    (!p.is_null()).then(|| unsafe { &*p })
}
