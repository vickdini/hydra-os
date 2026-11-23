//! wave9 GP2: `memcpy` and `memset` for the services, fast for the small sizes they copy most.
//!
//! The built-in ones (compiler_builtins) run three `rep` string instructions for every copy;
//! their start-up cost dominates the 8..512-byte copies a forwarded call makes (the call
//! record, `Attr`s, `Ctx`, results returned by value): a stat in vfs-server spent about a
//! third of its own time in `memcpy` (100 Hz profile, 2026-11-23). Up to 128 bytes these copy
//! with straight-line overlapping 8-byte moves (every load before any store), larger ones
//! with one `rep movsq` plus an overlapping tail. The built-in symbols are weak, so these
//! take their place in every program linked with hydra-rt.

use core::ffi::c_void;

#[inline(always)]
unsafe fn rd(p: *const u8, o: usize) -> u64 {
    // SAFETY: the caller keeps `o + 8 <= n`
    unsafe { core::ptr::read_unaligned(p.add(o) as *const u64) }
}

#[inline(always)]
unsafe fn wr(p: *mut u8, o: usize, v: u64) {
    // SAFETY: as `rd`
    unsafe { core::ptr::write_unaligned(p.add(o) as *mut u64, v) }
}

/// Copies `n` bytes from `s` to `d` (the ranges do not overlap).
///
/// # Safety
/// As C's `memcpy`.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memcpy(dv: *mut c_void, sv: *const c_void, n: usize) -> *mut c_void {
    let (d, s) = (dv as *mut u8, sv as *const u8);
    // SAFETY: every access below lies within `[0, n)` of both ranges
    unsafe {
        if n <= 16 {
            if n >= 8 {
                let (a, b) = (rd(s, 0), rd(s, n - 8));
                wr(d, 0, a);
                wr(d, n - 8, b);
            } else if n >= 4 {
                let a = core::ptr::read_unaligned(s as *const u32);
                let b = core::ptr::read_unaligned(s.add(n - 4) as *const u32);
                core::ptr::write_unaligned(d as *mut u32, a);
                core::ptr::write_unaligned(d.add(n - 4) as *mut u32, b);
            } else if n > 0 {
                let (a, b, c) = (*s, *s.add(n / 2), *s.add(n - 1));
                *d = a;
                *d.add(n / 2) = b;
                *d.add(n - 1) = c;
            }
        } else if n <= 32 {
            let (a, b, c, e) = (rd(s, 0), rd(s, 8), rd(s, n - 16), rd(s, n - 8));
            wr(d, 0, a);
            wr(d, 8, b);
            wr(d, n - 16, c);
            wr(d, n - 8, e);
        } else if n <= 64 {
            let h = [rd(s, 0), rd(s, 8), rd(s, 16), rd(s, 24)];
            let t = [rd(s, n - 32), rd(s, n - 24), rd(s, n - 16), rd(s, n - 8)];
            wr(d, 0, h[0]);
            wr(d, 8, h[1]);
            wr(d, 16, h[2]);
            wr(d, 24, h[3]);
            wr(d, n - 32, t[0]);
            wr(d, n - 24, t[1]);
            wr(d, n - 16, t[2]);
            wr(d, n - 8, t[3]);
        } else {
            // 8-byte words, then the last 8 bytes again (overlapping the words' end)
            let tail = rd(s, n - 8);
            core::arch::asm!("rep movsq", inout("rcx") n / 8 => _, inout("rdi") d => _, inout("rsi") s => _, options(nostack, preserves_flags));
            wr(d, n - 8, tail);
        }
    }
    dv
}

/// Sets `n` bytes at `d` to `c`.
///
/// # Safety
/// As C's `memset`.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memset(dv: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dv as *mut u8;
    let v = (c as u8 as u64) * 0x0101_0101_0101_0101;
    // SAFETY: every access lies within `[0, n)`
    unsafe {
        if n <= 16 {
            if n >= 8 {
                wr(d, 0, v);
                wr(d, n - 8, v);
            } else {
                for i in 0..n {
                    core::ptr::write_volatile(d.add(i), c as u8);
                }
            }
        } else if n <= 32 {
            wr(d, 0, v);
            wr(d, 8, v);
            wr(d, n - 16, v);
            wr(d, n - 8, v);
        } else {
            core::arch::asm!("rep stosq", inout("rcx") n / 8 => _, inout("rdi") d => _, in("rax") v, options(nostack, preserves_flags));
            wr(d, n - 8, v);
        }
    }
    dv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_every_size() {
        for n in 0..600usize {
            for off in 0..3usize {
                let src: [u8; 640] = core::array::from_fn(|i| (i * 7 + 3) as u8);
                let mut dst = [0xAAu8; 640];
                unsafe { memcpy(dst.as_mut_ptr().add(off).cast(), src.as_ptr().add(1).cast(), n) };
                assert!(dst[..off].iter().all(|&b| b == 0xAA));
                assert_eq!(&dst[off..off + n], &src[1..1 + n], "n={n} off={off}");
                assert!(dst[off + n..].iter().all(|&b| b == 0xAA));
                let mut m = [0x55u8; 640];
                unsafe { memset(m.as_mut_ptr().add(off).cast(), 0x3C, n) };
                assert!(m[..off].iter().all(|&b| b == 0x55));
                assert!(m[off..off + n].iter().all(|&b| b == 0x3C), "set n={n}");
                assert!(m[off + n..].iter().all(|&b| b == 0x55));
            }
        }
    }
}
