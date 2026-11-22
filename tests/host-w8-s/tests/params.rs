//! sound-server's `params.rs`: Linux's `HW_REFINE` / `HW_PARAMS` negotiation for the one
//! format the device takes.

use hydra_hosttests_w8_s::params::*;

/// An "anything goes" `snd_pcm_hw_params` (what `snd_pcm_hw_params_any` sends).
pub fn any() -> Vec<u8> {
    let mut b = vec![0u8; HW_PARAMS_SIZE];
    for m in 0..3 {
        for w in 0..8 {
            put_u32(&mut b, 4 + m * 32 + w * 4, 0xFFFF_FFFF);
        }
    }
    for i in 0..12 {
        let o = 260 + i * 12;
        put_u32(&mut b, o, 0);
        put_u32(&mut b, o + 4, u32::MAX);
        put_u32(&mut b, o + 8, 0);
    }
    put_u32(&mut b, 512, u32::MAX); // rmask
    put_u32(&mut b, 520, u32::MAX); // info
    b
}

/// Sets interval `p` of record `b` to `[min, max]`.
pub fn set_iv(b: &mut [u8], p: usize, min: u32, max: u32) {
    let o = 260 + (p - P_SAMPLE_BITS) * 12;
    put_u32(b, o, min);
    put_u32(b, o + 4, max);
    put_u32(b, o + 8, 0);
}

#[test]
fn refine_narrows_anything_to_the_device() {
    let mut p = Params::parse(any());
    p.refine().unwrap();
    assert_eq!(p.masks[P_FORMAT][0], 1 << FORMAT_S16_LE);
    assert_eq!(p.masks[P_ACCESS][0], 1 << ACCESS_MMAP_INTERLEAVED | 1 << ACCESS_RW_INTERLEAVED);
    assert_eq!((p.get(P_CHANNELS).min, p.get(P_CHANNELS).max), (2, 2));
    assert_eq!((p.get(P_SAMPLE_BITS).min, p.get(P_SAMPLE_BITS).max), (16, 16));
    assert_eq!((p.get(P_FRAME_BITS).min, p.get(P_FRAME_BITS).max), (32, 32));
    assert_eq!((p.get(P_RATE).min, p.get(P_RATE).max), (44100, 48000));
    assert_eq!((p.get(P_PERIODS).min, p.get(P_PERIODS).max), (2, 32));
    assert!(p.get(P_BUFFER_BYTES).max <= BUF_BYTES && p.get(P_BUFFER_BYTES).min >= 16384);
    let raw = p.encode().to_vec();
    // Every changed parameter is in cmask; rmask is cleared; info is the device's
    assert_ne!(get_u32(&raw, 516), 0);
    assert_eq!(get_u32(&raw, 512), 0);
    assert_eq!(get_u32(&raw, 520), HW_INFO);
}

#[test]
fn pipewires_choice_is_kept() {
    // 48 kHz, period 512 frames, 32 periods (what PipeWire chose on Hydra)
    let mut b = any();
    set_iv(&mut b, P_RATE, 48000, 48000);
    set_iv(&mut b, P_PERIOD_SIZE, 512, 512);
    set_iv(&mut b, P_PERIODS, 32, 32);
    let mut p = Params::parse(b);
    p.choose().unwrap();
    assert_eq!(p.get(P_RATE).value(), 48000);
    assert_eq!(p.get(P_PERIOD_SIZE).value(), 512);
    assert_eq!(p.get(P_PERIODS).value(), 32);
    assert_eq!(p.get(P_BUFFER_SIZE).value(), 16384);
    assert_eq!(p.get(P_BUFFER_BYTES).value(), 65536);
    let raw = p.encode().to_vec();
    assert_eq!((get_u32(&raw, 528), get_u32(&raw, 532)), (48000, 1)); // rate_num / rate_den
    assert_eq!(get_u32(&raw, 524), 16); // msbits
}

#[test]
fn choose_picks_one_value_for_everything() {
    let mut p = Params::parse(any());
    p.choose().unwrap();
    for i in [P_CHANNELS, P_RATE, P_PERIOD_SIZE, P_PERIODS, P_BUFFER_SIZE, P_FRAME_BITS] {
        assert!(p.get(i).single(), "parameter {} not single: {:?}", i, p.get(i));
    }
    assert_eq!(p.masks[P_ACCESS][0].count_ones(), 1);
    let (ps, n, bs) = (p.get(P_PERIOD_SIZE).value(), p.get(P_PERIODS).value(), p.get(P_BUFFER_SIZE).value());
    assert_eq!(ps * n, bs);
    assert_eq!((ps * 4) % 128, 0);
}

#[test]
fn what_the_device_cannot_do_is_refused() {
    let mut b = any();
    set_iv(&mut b, P_CHANNELS, 1, 1);
    assert_eq!(Params::parse(b).refine().err(), Some(-22));
    let mut b = any();
    set_iv(&mut b, P_RATE, 8000, 22050);
    assert_eq!(Params::parse(b).refine().err(), Some(-22));
    // A format mask without S16_LE
    let mut b = any();
    for w in 0..8 {
        put_u32(&mut b, 4 + 32 + w * 4, 0);
    }
    put_u32(&mut b, 4 + 32, 1 << 10);
    assert_eq!(Params::parse(b).refine().err(), Some(-22));
}

#[test]
fn intervals_refine_step_and_list() {
    let mut a = Iv::new(0, 100, false);
    assert_eq!(a.refine(&Iv::new(10, 50, true)), Ok(true));
    assert_eq!((a.min, a.max, a.integer), (10, 50, true));
    assert_eq!(a.refine(&Iv::new(10, 50, true)), Ok(false));
    assert!(a.refine(&Iv::new(60, 70, true)).is_err());
    assert!(a.empty);
    let mut s = Iv::new(100, 1000, true);
    assert_eq!(s.step(128), Ok(true));
    assert_eq!((s.min, s.max), (128, 896));
    let mut l = Iv::new(40000, 50000, true);
    assert_eq!(l.list(&RATES), Ok(true));
    assert_eq!((l.min, l.max), (44100, 48000));
    let mut l = Iv::new(45000, 46000, true);
    assert!(l.list(&RATES).is_err());
    let o = Iv { min: 5, max: 6, openmin: true, openmax: false, integer: false, empty: false };
    assert!(o.single());
    assert_eq!(o.value(), 6);
}

#[test]
fn setup_format_word() {
    let h = HwSetup { access: 0, rate: 44100, period_size: 512, periods: 4, buffer_size: 2048, frame_bytes: 4 };
    assert_eq!(h.hda_format(), 1 << 14 | 1 << 4 | 1);
    let h = HwSetup { rate: 48000, ..h };
    assert_eq!(h.hda_format(), 1 << 4 | 1);
}
