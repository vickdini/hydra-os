//! Kernel random number generator backing `/dev/urandom`, `/dev/random` and `getrandom(2)`.
//!
//! - **Generator**: ChaCha20 with fast key erasure: each request draws a fresh keystream
//!   block, takes the first 32 bytes of it as the next key, and hands out the rest, so
//!   output already given away cannot be recomputed from a later state.
//! - **Entropy**: seeded on first use from `RDSEED`/`RDRAND` (when the CPU has them),
//!   the time-stamp counter and the PIT tick count; every request mixes in a fresh
//!   `RDRAND` value and `RDTSC` reading as the nonce.

use spin::Mutex;

/// Generator state: the current ChaCha20 key and a block counter.
struct Rng {
    key: [u32; 8],
    counter: u64,
    seeded: bool,
}

static RNG: Mutex<Rng> = Mutex::new(Rng { key: [0; 8], counter: 0, seeded: false });

/// Applies one ChaCha quarter round to `s` at indices `a`, `b`, `c`, `d`.
#[inline(always)]
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Computes one 64-byte ChaCha20 block.
///
/// # Arguments
/// * `key` - 256-bit key as eight little-endian words.
/// * `counter` - 64-bit block counter.
/// * `nonce` - 64-bit nonce.
///
/// # Returns
/// The 64-byte keystream block.
fn chacha_block(key: &[u32; 8], counter: u64, nonce: u64) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    init[4..12].copy_from_slice(key);
    init[12] = counter as u32;
    init[13] = (counter >> 32) as u32;
    init[14] = nonce as u32;
    init[15] = (nonce >> 32) as u32;
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Reads the time-stamp counter.
fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    ((hi as u64) << 32) | lo as u64
}

/// Returns a hardware random value from `RDSEED` (`seed == true`) or `RDRAND`, if the CPU
/// supports it and it succeeds within a few retries.
fn hw_random(seed: bool) -> Option<u64> {
    let cpuid1 = core::arch::x86_64::__cpuid(1);
    let cpuid7 = core::arch::x86_64::__cpuid_count(7, 0);
    let available = if seed { cpuid7.ebx & (1 << 18) != 0 } else { cpuid1.ecx & (1 << 30) != 0 };
    if !available {
        return None;
    }
    for _ in 0..16 {
        let (value, ok): (u64, u8);
        unsafe {
            if seed {
                core::arch::asm!("rdseed {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok, options(nomem, nostack));
            } else {
                core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok, options(nomem, nostack));
            }
        }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}

/// Fills `buf` with cryptographically strong random bytes.
///
/// # Arguments
/// * `buf` - Destination buffer.
pub fn fill(buf: &mut [u8]) {
    let mut rng = RNG.lock();
    if !rng.seeded {
        // Mix every available source through ChaCha so the key depends on all of them
        let mut material = [0u32; 8];
        for (i, w) in material.iter_mut().enumerate() {
            let hw = hw_random(true).or_else(|| hw_random(false)).unwrap_or(0);
            let t = rdtsc().rotate_left(i as u32 * 7) ^ crate::arch::pit::ticks().rotate_left(32);
            *w = (hw ^ t ^ (hw >> 32)) as u32;
        }
        let block = chacha_block(&material, rdtsc(), crate::arch::pit::ticks());
        for i in 0..8 {
            rng.key[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        rng.seeded = true;
    }
    let nonce = rdtsc() ^ hw_random(false).unwrap_or(0);
    let mut first = true;
    let mut filled = 0;
    while filled < buf.len() || first {
        let counter = rng.counter;
        rng.counter = rng.counter.wrapping_add(1);
        let block = chacha_block(&rng.key, counter, nonce);
        let mut start = 0;
        if first {
            // Fast key erasure: the first 32 bytes become the next key and are never output
            for i in 0..8 {
                rng.key[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
            }
            start = 32;
            first = false;
        }
        let n = (64 - start).min(buf.len() - filled);
        buf[filled..filled + n].copy_from_slice(&block[start..start + n]);
        filled += n;
    }
}
