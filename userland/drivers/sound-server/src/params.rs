//! Hardware parameters: Linux's `HW_REFINE` negotiation (`snd_pcm_hw_refine`,
//! `snd_pcm_hw_params_choose`) for the one stream format the device takes (16-bit stereo,
//! 44.1 or 48 kHz). Moved from the kernel's `compat/linux/snd.rs` (wave 8, Group S) as
//! plain Rust: the host tests (`tests/host-w8-s`) compile this file.

use alloc::vec::Vec;

const EINVAL: i64 = -22;

/// Bytes of each ring (the largest buffer a program may ask for).
pub const BUF_BYTES: u32 = 128 * 4096;

// Hardware parameter indexes
pub const P_ACCESS: usize = 0;
pub const P_FORMAT: usize = 1;
pub const P_SUBFORMAT: usize = 2;
pub const P_SAMPLE_BITS: usize = 8;
pub const P_FRAME_BITS: usize = 9;
pub const P_CHANNELS: usize = 10;
pub const P_RATE: usize = 11;
pub const P_PERIOD_TIME: usize = 12;
pub const P_PERIOD_SIZE: usize = 13;
pub const P_PERIOD_BYTES: usize = 14;
pub const P_PERIODS: usize = 15;
pub const P_BUFFER_TIME: usize = 16;
pub const P_BUFFER_SIZE: usize = 17;
pub const P_BUFFER_BYTES: usize = 18;

pub const ACCESS_MMAP_INTERLEAVED: u32 = 0;
pub const ACCESS_RW_INTERLEAVED: u32 = 3;
pub const FORMAT_S16_LE: u32 = 2;
/// The rates the device takes.
pub const RATES: [u32; 2] = [44100, 48000];

// snd_pcm_info flags reported in hw_params.info
const INFO_MMAP: u32 = 0x1;
const INFO_MMAP_VALID: u32 = 0x2;
const INFO_BATCH: u32 = 0x10;
const INFO_INTERLEAVED: u32 = 0x100;
const INFO_BLOCK_TRANSFER: u32 = 0x10000;
const INFO_NO_PERIOD_WAKEUP: u32 = 0x0080_0000;
/// (No `INFO_PAUSE`: QEMU's controller restarts a stream from the start of its ring when
/// it runs again, so `PAUSE` works only on real controllers; programs offered no pause
/// stop and restart instead.)
pub const HW_INFO: u32 = INFO_MMAP | INFO_MMAP_VALID | INFO_BATCH | INFO_INTERLEAVED | INFO_BLOCK_TRANSFER | INFO_NO_PERIOD_WAKEUP;

pub fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

pub fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

pub fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// An `snd_interval`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Iv {
    pub min: u32,
    pub max: u32,
    pub openmin: bool,
    pub openmax: bool,
    pub integer: bool,
    pub empty: bool,
}

impl Iv {
    pub fn new(min: u32, max: u32, integer: bool) -> Self {
        Iv { min, max, openmin: false, openmax: false, integer, empty: false }
    }

    pub fn none() -> Self {
        Iv { empty: true, ..Default::default() }
    }

    pub fn single(&self) -> bool {
        !self.empty && (self.min == self.max || (self.min + 1 == self.max && (self.openmin || self.openmax)))
    }

    pub fn value(&self) -> u32 {
        if self.openmin && !self.openmax {
            self.max
        } else {
            self.min
        }
    }

    pub fn checkempty(&self) -> bool {
        self.empty || self.min > self.max || (self.min == self.max && (self.openmin || self.openmax))
    }

    /// Linux's `snd_interval_refine`: narrows to `v`; `Ok(changed)` or `Err` when empty.
    pub fn refine(&mut self, v: &Iv) -> Result<bool, i64> {
        if self.empty || v.empty {
            *self = Iv::none();
            return Err(EINVAL);
        }
        let mut changed = false;
        if self.min < v.min {
            self.min = v.min;
            self.openmin = v.openmin;
            changed = true;
        } else if self.min == v.min && !self.openmin && v.openmin {
            self.openmin = true;
            changed = true;
        }
        if self.max > v.max {
            self.max = v.max;
            self.openmax = v.openmax;
            changed = true;
        } else if self.max == v.max && !self.openmax && v.openmax {
            self.openmax = true;
            changed = true;
        }
        if !self.integer && v.integer {
            self.integer = true;
            changed = true;
        }
        if self.integer {
            if self.openmin {
                self.min = self.min.saturating_add(1);
                self.openmin = false;
            }
            if self.openmax {
                self.max = self.max.saturating_sub(1);
                self.openmax = false;
            }
        } else if !self.openmin && !self.openmax && self.min == self.max {
            self.integer = true;
        }
        if self.checkempty() {
            *self = Iv::none();
            return Err(EINVAL);
        }
        Ok(changed)
    }

    /// Keeps only multiples of `step`.
    pub fn step(&mut self, step: u32) -> Result<bool, i64> {
        let before = *self;
        let mut min = self.min + self.openmin as u32;
        min = min.div_ceil(step) * step;
        let mut max = self.max.saturating_sub(self.openmax as u32);
        max = max / step * step;
        *self = Iv { min, max, openmin: false, openmax: false, integer: true, empty: false };
        if self.checkempty() {
            *self = Iv::none();
            return Err(EINVAL);
        }
        Ok(*self != before)
    }

    /// Keeps only values in `list` (sorted).
    pub fn list(&mut self, list: &[u32]) -> Result<bool, i64> {
        let ok_min = |r: u32| r > self.min || (r == self.min && !self.openmin);
        let ok_max = |r: u32| r < self.max || (r == self.max && !self.openmax);
        let lo = list.iter().copied().find(|&r| ok_min(r) && ok_max(r));
        let hi = list.iter().rev().copied().find(|&r| ok_min(r) && ok_max(r));
        match (lo, hi) {
            (Some(lo), Some(hi)) => {
                let new = Iv { min: lo, max: hi, openmin: false, openmax: false, integer: true, empty: false };
                let changed = new != *self;
                *self = new;
                Ok(changed)
            }
            _ => {
                *self = Iv::none();
                Err(EINVAL)
            }
        }
    }
}

fn muldiv32(a: u32, b: u32, c: u32) -> (u32, bool) {
    if c == 0 {
        return (u32::MAX, false);
    }
    let n = a as u64 * b as u64;
    let q = n / c as u64;
    if q > u32::MAX as u64 {
        return (u32::MAX, false);
    }
    (q as u32, n % c as u64 != 0)
}

fn iv_mul(a: &Iv, b: &Iv) -> Iv {
    if a.empty || b.empty {
        return Iv::none();
    }
    Iv {
        min: a.min.saturating_mul(b.min),
        openmin: a.openmin || b.openmin,
        max: a.max.saturating_mul(b.max),
        openmax: a.openmax || b.openmax,
        integer: a.integer && b.integer,
        empty: false,
    }
}

fn iv_div(a: &Iv, b: &Iv) -> Iv {
    if a.empty || b.empty {
        return Iv::none();
    }
    let mut c = Iv::default();
    let (q, r) = if b.max == 0 { (u32::MAX, false) } else { (a.min / b.max, a.min % b.max != 0) };
    c.min = q;
    c.openmin = r || a.openmin || b.openmax;
    if b.min > 0 {
        let r = a.max % b.min != 0;
        c.max = a.max / b.min;
        if r {
            c.max = c.max.saturating_add(1);
            c.openmax = true;
        } else {
            c.openmax = a.openmax || b.openmin;
        }
    } else {
        c.max = u32::MAX;
        c.openmax = false;
    }
    c
}

/// `a * b / k`.
fn iv_muldivk(a: &Iv, b: &Iv, k: u32) -> Iv {
    if a.empty || b.empty {
        return Iv::none();
    }
    let mut c = Iv::default();
    let (q, r) = muldiv32(a.min, b.min, k);
    c.min = q;
    c.openmin = r || a.openmin || b.openmin;
    let (q, r) = muldiv32(a.max, b.max, k);
    c.max = q;
    if r {
        c.max = c.max.saturating_add(1);
        c.openmax = true;
    } else {
        c.openmax = a.openmax || b.openmax;
    }
    c
}

/// `a * k / b`.
fn iv_mulkdiv(a: &Iv, k: u32, b: &Iv) -> Iv {
    if a.empty || b.empty {
        return Iv::none();
    }
    let mut c = Iv::default();
    let (q, r) = muldiv32(a.min, k, b.max);
    c.min = q;
    c.openmin = r || a.openmin || b.openmax;
    if b.min > 0 {
        let (q, r) = muldiv32(a.max, k, b.min);
        c.max = q;
        if r {
            c.max = c.max.saturating_add(1);
            c.openmax = true;
        } else {
            c.openmax = a.openmax || b.openmin;
        }
    } else {
        c.max = u32::MAX;
        c.openmax = false;
    }
    c
}

/// An `snd_pcm_hw_params` (608 bytes), decoded; `raw` keeps the bytes not modelled.
#[derive(Clone)]
pub struct Params {
    pub raw: Vec<u8>,
    pub masks: [[u32; 8]; 3],
    pub ivs: [Iv; 12],
}

pub const HW_PARAMS_SIZE: usize = 608;
const OFF_MASKS: usize = 4;
const OFF_IVS: usize = 260;
const OFF_RMASK: usize = 512;
const OFF_CMASK: usize = 516;
const OFF_INFO: usize = 520;
const OFF_MSBITS: usize = 524;
const OFF_RATE_NUM: usize = 528;
const OFF_RATE_DEN: usize = 532;
const OFF_FIFO: usize = 536;

impl Params {
    pub fn parse(raw: Vec<u8>) -> Self {
        let mut masks = [[0u32; 8]; 3];
        for (m, mask) in masks.iter_mut().enumerate() {
            for (w, word) in mask.iter_mut().enumerate() {
                *word = get_u32(&raw, OFF_MASKS + m * 32 + w * 4);
            }
        }
        let mut ivs = [Iv::default(); 12];
        for (i, iv) in ivs.iter_mut().enumerate() {
            let o = OFF_IVS + i * 12;
            let bits = get_u32(&raw, o + 8);
            *iv = Iv { min: get_u32(&raw, o), max: get_u32(&raw, o + 4), openmin: bits & 1 != 0, openmax: bits & 2 != 0, integer: bits & 4 != 0, empty: bits & 8 != 0 };
        }
        Params { raw, masks, ivs }
    }

    pub fn encode(&mut self) -> &[u8] {
        for m in 0..3 {
            for w in 0..8 {
                put_u32(&mut self.raw, OFF_MASKS + m * 32 + w * 4, self.masks[m][w]);
            }
        }
        for i in 0..12 {
            let o = OFF_IVS + i * 12;
            let iv = self.ivs[i];
            put_u32(&mut self.raw, o, iv.min);
            put_u32(&mut self.raw, o + 4, iv.max);
            let bits = iv.openmin as u32 | (iv.openmax as u32) << 1 | (iv.integer as u32) << 2 | (iv.empty as u32) << 3;
            put_u32(&mut self.raw, o + 8, bits);
        }
        &self.raw
    }

    pub fn iv(&mut self, p: usize) -> &mut Iv {
        &mut self.ivs[p - P_SAMPLE_BITS]
    }

    pub fn get(&self, p: usize) -> Iv {
        self.ivs[p - P_SAMPLE_BITS]
    }

    /// Narrows interval `p` to `v`, recording a change.
    pub fn set(&mut self, p: usize, v: Iv, changed: &mut bool) -> Result<(), i64> {
        if self.iv(p).refine(&v)? {
            *changed = true;
        }
        Ok(())
    }

    /// Refines the parameter space by the device's limits and Linux's rules.
    pub fn refine(&mut self) -> Result<(), i64> {
        let before = self.clone();
        // Masks
        self.masks[P_ACCESS][0] &= 1 << ACCESS_MMAP_INTERLEAVED | 1 << ACCESS_RW_INTERLEAVED;
        self.masks[P_FORMAT][0] &= 1 << FORMAT_S16_LE;
        self.masks[P_SUBFORMAT][0] &= 1;
        for m in 0..3 {
            for w in 1..8 {
                self.masks[m][w] = 0;
            }
            if self.masks[m][0] == 0 {
                return Err(EINVAL);
            }
        }
        let mut c = false;
        // The device: 16-bit stereo, periods of 128 bytes multiples, 2..=32 of them
        self.set(P_SAMPLE_BITS, Iv::new(16, 16, true), &mut c)?;
        self.set(P_CHANNELS, Iv::new(2, 2, true), &mut c)?;
        self.set(P_RATE, Iv::new(RATES[0], RATES[RATES.len() - 1], true), &mut c)?;
        self.set(P_PERIODS, Iv::new(2, 32, true), &mut c)?;
        self.set(P_PERIOD_BYTES, Iv::new(128, BUF_BYTES / 2, true), &mut c)?;
        // At least 16 KiB: QEMU's codec fetches 8 KiB ahead the moment a stream starts
        self.set(P_BUFFER_BYTES, Iv::new(16384, BUF_BYTES, true), &mut c)?;
        self.set(P_FRAME_BITS, Iv::new(0, u32::MAX, true), &mut c)?;
        self.set(P_PERIOD_SIZE, Iv::new(0, u32::MAX, true), &mut c)?;
        self.set(P_BUFFER_SIZE, Iv::new(0, u32::MAX, true), &mut c)?;
        for _ in 0..64 {
            let mut c = false;
            let g = |s: &Self, p| s.get(p);
            let v = iv_div(&g(self, P_FRAME_BITS), &g(self, P_CHANNELS));
            self.set(P_SAMPLE_BITS, v, &mut c)?;
            let v = iv_mul(&g(self, P_SAMPLE_BITS), &g(self, P_CHANNELS));
            self.set(P_FRAME_BITS, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_PERIOD_BYTES), 8, &g(self, P_PERIOD_SIZE));
            self.set(P_FRAME_BITS, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_BUFFER_BYTES), 8, &g(self, P_BUFFER_SIZE));
            self.set(P_FRAME_BITS, v, &mut c)?;
            let v = iv_div(&g(self, P_FRAME_BITS), &g(self, P_SAMPLE_BITS));
            self.set(P_CHANNELS, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_PERIOD_SIZE), 1_000_000, &g(self, P_PERIOD_TIME));
            self.set(P_RATE, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_BUFFER_SIZE), 1_000_000, &g(self, P_BUFFER_TIME));
            self.set(P_RATE, v, &mut c)?;
            let v = iv_div(&g(self, P_BUFFER_SIZE), &g(self, P_PERIOD_SIZE));
            self.set(P_PERIODS, v, &mut c)?;
            let v = iv_div(&g(self, P_BUFFER_SIZE), &g(self, P_PERIODS));
            self.set(P_PERIOD_SIZE, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_PERIOD_BYTES), 8, &g(self, P_FRAME_BITS));
            self.set(P_PERIOD_SIZE, v, &mut c)?;
            let v = iv_muldivk(&g(self, P_PERIOD_TIME), &g(self, P_RATE), 1_000_000);
            self.set(P_PERIOD_SIZE, v, &mut c)?;
            let v = iv_mul(&g(self, P_PERIOD_SIZE), &g(self, P_PERIODS));
            self.set(P_BUFFER_SIZE, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_BUFFER_BYTES), 8, &g(self, P_FRAME_BITS));
            self.set(P_BUFFER_SIZE, v, &mut c)?;
            let v = iv_muldivk(&g(self, P_BUFFER_TIME), &g(self, P_RATE), 1_000_000);
            self.set(P_BUFFER_SIZE, v, &mut c)?;
            let v = iv_muldivk(&g(self, P_PERIOD_SIZE), &g(self, P_FRAME_BITS), 8);
            self.set(P_PERIOD_BYTES, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_PERIOD_SIZE), 1_000_000, &g(self, P_RATE));
            self.set(P_PERIOD_TIME, v, &mut c)?;
            let v = iv_muldivk(&g(self, P_BUFFER_SIZE), &g(self, P_FRAME_BITS), 8);
            self.set(P_BUFFER_BYTES, v, &mut c)?;
            let v = iv_mulkdiv(&g(self, P_BUFFER_SIZE), 1_000_000, &g(self, P_RATE));
            self.set(P_BUFFER_TIME, v, &mut c)?;
            if self.iv(P_RATE).list(&RATES)? {
                c = true;
            }
            if self.iv(P_PERIOD_BYTES).step(128)? {
                c = true;
            }
            if self.iv(P_BUFFER_BYTES).step(128)? {
                c = true;
            }
            if !c {
                break;
            }
        }
        // Which parameters changed, and the derived fields
        let mut cmask = 0u32;
        for m in 0..3 {
            if self.masks[m] != before.masks[m] {
                cmask |= 1 << m;
            }
        }
        for i in 0..12 {
            if self.ivs[i] != before.ivs[i] {
                cmask |= 1 << (i + P_SAMPLE_BITS);
            }
        }
        put_u32(&mut self.raw, OFF_CMASK, cmask);
        put_u32(&mut self.raw, OFF_RMASK, 0);
        if get_u32(&self.raw, OFF_MSBITS) == 0 && self.get(P_SAMPLE_BITS).single() {
            put_u32(&mut self.raw, OFF_MSBITS, 16);
        }
        if get_u32(&self.raw, OFF_RATE_DEN) == 0 && self.get(P_RATE).single() {
            let rate = self.get(P_RATE).value();
            put_u32(&mut self.raw, OFF_RATE_NUM, rate);
            put_u32(&mut self.raw, OFF_RATE_DEN, 1);
        }
        if get_u32(&self.raw, OFF_INFO) == 0 || get_u32(&self.raw, OFF_INFO) == u32::MAX {
            put_u32(&mut self.raw, OFF_INFO, HW_INFO);
        }
        put_u64(&mut self.raw, OFF_FIFO, 0);
        Ok(())
    }

    /// Linux's `snd_pcm_hw_params_choose`: one value for every parameter.
    pub fn choose(&mut self) -> Result<(), i64> {
        self.refine()?;
        for m in [P_ACCESS, P_FORMAT, P_SUBFORMAT] {
            let w = self.masks[m][0];
            self.masks[m][0] = w & w.wrapping_neg();
        }
        for (p, first) in [(P_CHANNELS, true), (P_RATE, true), (P_PERIOD_TIME, true), (P_BUFFER_SIZE, false), (P_PERIOD_SIZE, true)] {
            let iv = self.get(p);
            if !iv.single() {
                let v = if first { iv.min + iv.openmin as u32 } else { iv.max - iv.openmax as u32 };
                let mut n = Iv::new(v, v, iv.integer);
                if !first && p == P_BUFFER_SIZE {
                    n.integer = true;
                }
                // Rounding into an excluded bound: keep the open interval's inside
                if first && iv.openmin && !iv.integer {
                    n = Iv { min: iv.min, max: iv.min + 1, openmin: true, openmax: true, integer: false, empty: false };
                }
                *self.iv(p) = n;
            }
            self.refine()?;
        }
        Ok(())
    }
}

/// The values chosen by `HW_PARAMS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwSetup {
    pub access: u32,
    pub rate: u32,
    pub period_size: u64,
    pub periods: u64,
    pub buffer_size: u64,
    pub frame_bytes: u64,
}

impl HwSetup {
    /// The HDA stream format word.
    pub fn hda_format(&self) -> u64 {
        let base = if self.rate == 44100 { 1 << 14 } else { 0 };
        base | 1 << 4 | 1 // 16 bits, 2 channels
    }
}

// ------------------------------------------------------------------------------------
