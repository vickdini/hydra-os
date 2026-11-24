//! # The boot log's memory: a head and a ring, in a region that can outlive a restart
//!
//! Plain logic over a byte region (no locks, no firmware): [`crate::arch::bootlog`] puts the
//! region at a fixed physical address and the host unit tests on a `Vec`.
//!
//! Layout: a header page, then the head ([`HEAD`] bytes: the first part of the log, kept for
//! good: the boot's start explains most failures), then the ring ([`RING`] bytes: the
//! latest part once the head is full). Line ends are stored as CR LF (Windows' Notepad
//! shows the file as it is). The header says which boot (the log file's number) the text
//! belongs to and how it ended, so the next start can tell a log that the last boot could
//! not write to its file (a crash, a restart forced to save it) from one it wrote.

use alloc::vec::Vec;

/// Size of the header page.
pub const HEADER: usize = 4096;
/// Bytes of the head.
pub const HEAD: usize = 1 << 20;
/// Bytes of the ring.
pub const RING: usize = 1 << 20;
/// The whole region.
pub const REGION: usize = HEADER + HEAD + RING;
/// The log file's size: the longest text [`render`] makes, and room for the end line.
pub const FILE_SIZE: usize = HEAD + RING + 64 * 1024;

/// The header's magic.
const MAGIC: u64 = u64::from_le_bytes(*b"HYDRALG1");

/// Flag: the boot wrote its whole log to its file at the end (power-off, restart).
pub const F_WRITTEN: u32 = 1;
/// Flag: the boot ended in a kernel panic.
pub const F_PANIC: u32 = 2;
/// Flag: the boot restarted only to save its log (it could not write it itself).
pub const F_SAVE_RESTART: u32 = 4;
/// Flag: the log was saved by the next start (nothing left to do).
pub const F_SAVED: u32 = 8;

/// The header (at the start of the region).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    /// [`MAGIC`].
    pub magic: u64,
    /// `!MAGIC ^ seq`: a header of a former boot, not memory that happens to say "HYDRALG1".
    pub check: u64,
    /// The number of the boot's log file (`bootNNN.txt`), 0 when it has none.
    pub seq: u32,
    /// `F_*` flags.
    pub flags: u32,
    /// Bytes in the head.
    pub head_len: u64,
    /// Bytes ever written into the ring.
    pub ring_written: u64,
    /// Unique GUID of the partition whose log directory holds the file (on-disk byte order).
    pub part: [u8; 16],
}

impl Header {
    /// A fresh header for boot `seq`.
    pub fn new(seq: u32) -> Self {
        Header { magic: MAGIC, check: !MAGIC ^ seq as u64, seq, flags: 0, head_len: 0, ring_written: 0, part: [0; 16] }
    }

    /// Whether this is a header [`Header::new`] made, with lengths that fit.
    pub fn valid(&self) -> bool {
        self.magic == MAGIC && self.check == !MAGIC ^ self.seq as u64 && self.head_len <= HEAD as u64 && self.ring_written < (1 << 48)
    }

    /// Whether the log holds text nobody wrote to its file yet.
    pub fn unsaved(&self) -> bool {
        self.valid() && self.seq != 0 && self.flags & (F_WRITTEN | F_SAVED) == 0 && (self.head_len > 0)
    }
}

/// Reads the header of `region`.
pub fn header(region: &[u8]) -> Header {
    assert!(region.len() >= REGION);
    unsafe { core::ptr::read_unaligned(region.as_ptr() as *const Header) }
}

/// Writes the header of `region`.
pub fn set_header(region: &mut [u8], h: &Header) {
    assert!(region.len() >= REGION);
    unsafe { core::ptr::write_unaligned(region.as_mut_ptr() as *mut Header, *h) }
}

/// Adds `text` to the log in `region` (`\n` becomes CR LF, CR and NUL are left out).
pub fn append(region: &mut [u8], text: &[u8]) {
    let mut h = header(region);
    if !h.valid() {
        return;
    }
    let mut put = |b: u8, h: &mut Header| {
        if (h.head_len as usize) < HEAD {
            region[HEADER + h.head_len as usize] = b;
            h.head_len += 1;
        } else {
            region[HEADER + HEAD + (h.ring_written % RING as u64) as usize] = b;
            h.ring_written += 1;
        }
    };
    for &b in text {
        match b {
            b'\r' | 0 => {}
            b'\n' => {
                put(b'\r', &mut h);
                put(b'\n', &mut h);
            }
            _ => put(b, &mut h),
        }
    }
    set_header(region, &h);
}

/// Whether the ring has wrapped (the text after the head no longer only grows).
pub fn wrapped(h: &Header) -> bool {
    h.ring_written > RING as u64
}

/// The log as text: the head, then (if the ring wrapped) a line saying how much was left
/// out, then the ring in order.
pub fn render(region: &[u8]) -> Vec<u8> {
    let h = header(region);
    let mut out = Vec::new();
    if !h.valid() {
        return out;
    }
    out.extend_from_slice(&region[HEADER..HEADER + h.head_len as usize]);
    let ring = &region[HEADER + HEAD..HEADER + HEAD + RING];
    if wrapped(&h) {
        let at = (h.ring_written % RING as u64) as usize;
        let dropped = h.ring_written - RING as u64;
        out.extend_from_slice(alloc::format!("\r\n[... {} bytes of the log left out here ...]\r\n", dropped).as_bytes());
        out.extend_from_slice(&ring[at..]);
        out.extend_from_slice(&ring[..at]);
    } else {
        out.extend_from_slice(&ring[..h.ring_written as usize]);
    }
    out
}

/// What a log file holds before any log is written into it (and what follows the text):
/// empty lines (CR LF).
pub fn filler(len: usize) -> Vec<u8> {
    (0..len).map(|i| if i % 2 == 0 { b'\r' } else { b'\n' }).collect()
}

/// The `bootNNN.txt` number of a directory entry name, if it is one.
pub fn file_number(name: &str) -> Option<u32> {
    let n = name.to_ascii_lowercase();
    let digits = n.strip_prefix("boot")?.strip_suffix(".txt")?;
    if digits.len() != 3 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|&v| v > 0)
}

/// The name of log file `n` (1..=999).
pub fn file_name(n: u32) -> alloc::string::String {
    alloc::format!("boot{:03}.txt", n)
}

/// The next log file number after the existing ones (`have`), wrapping from 999 to 1, and
/// which existing ones to delete so that at most `keep` files stay (the new one included).
pub fn next_number(have: &[u32], keep: usize) -> (u32, Vec<u32>) {
    // The newest is the highest, unless the numbers wrapped (then there is a gap above it)
    let mut sorted: Vec<u32> = have.iter().copied().filter(|&n| (1..=999).contains(&n)).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let newest = if sorted.is_empty() {
        0
    } else {
        // After a wrap the files are 1..k and m..999 with a gap: the newest is just below the
        // biggest gap
        let mut best = (0u32, *sorted.last().unwrap());
        for w in sorted.windows(2) {
            let gap = w[1] - w[0];
            if gap > best.0 {
                best = (gap, w[0]);
            }
        }
        let wrap_gap = 999 - sorted.last().unwrap() + sorted[0];
        if best.0 > wrap_gap { best.1 } else { *sorted.last().unwrap() }
    };
    let next = if newest >= 999 { 1 } else { newest + 1 };
    // Age of file n: how many numbers before `next` it is
    let age = |n: u32| (next + 999 - n) % 999;
    let mut by_age: Vec<u32> = sorted.iter().copied().filter(|&n| n != next).collect();
    by_age.sort_by_key(|&n| age(n));
    let mut delete: Vec<u32> = by_age.iter().copied().skip(keep.saturating_sub(1)).collect();
    if sorted.contains(&next) {
        delete.push(next);
    }
    (next, delete)
}
