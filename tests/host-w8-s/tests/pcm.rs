//! sound-server's `pcm.rs`: the PCM state machine and the mixer, against a fake controller.

use hydra_hosttests_w8_s::params::*;
use hydra_hosttests_w8_s::pcm::*;

/// A fake controller: a clock, position slots the test moves, rings, and the driver calls
/// it was asked for.
struct Fake {
    now: u64,
    pos: [u64; 4],
    rings: [Vec<u8>; 2],
    setups: Vec<(usize, HwSetup)>,
    triggers: Vec<(usize, bool)>,
    fail_setup: bool,
    fail_trigger: bool,
}

impl Fake {
    fn new() -> Self {
        Fake { now: 1_000_000_000, pos: [0; 4], rings: [vec![0; BUF_BYTES as usize], vec![0; BUF_BYTES as usize]], setups: vec![], triggers: vec![], fail_setup: false, fail_trigger: false }
    }
}

impl Hw for Fake {
    fn now_ns(&self) -> u64 {
        self.now
    }
    fn wall_base_ns(&self) -> i64 {
        1_700_000_000_000_000_000
    }
    fn position(&self, slot: usize) -> u64 {
        self.pos[slot]
    }
    fn reset_position(&mut self, slot: usize) {
        self.pos[slot] = 0;
    }
    fn ring(&mut self, dir: usize) -> Option<&mut [u8]> {
        Some(&mut self.rings[dir])
    }
    fn setup(&mut self, dir: usize, hw: &HwSetup) -> Result<usize, i64> {
        if self.fail_setup {
            return Err(-5);
        }
        self.setups.push((dir, *hw));
        Ok(dir + 1)
    }
    fn trigger(&mut self, dir: usize, run: bool) -> Result<(), i64> {
        if self.fail_trigger {
            return Err(-5);
        }
        self.triggers.push((dir, run));
        Ok(())
    }
}

#[path = "params.rs"]
#[allow(dead_code)]
mod p;

/// A card with both directions and the usual amplifier.
fn engine() -> Engine {
    let mut e = Engine::new();
    e.dirs = 3;
    // 74 steps, 0 dB at 64, 0.25 dB steps, present, can mute
    e.build_controls([74 | 64 << 8 | 0 << 16 | 1 << 24 | 1 << 25, 0]);
    e
}

/// Direction `dir` open with period `period` x `periods`, 48 kHz, `access`.
fn setup(e: &mut Engine, dir: usize, period: u32, periods: u32, access: u32) {
    e.open(dir, 42, 0).unwrap();
    let mut b = p::any();
    p::set_iv(&mut b, P_RATE, 48000, 48000);
    p::set_iv(&mut b, P_PERIOD_SIZE, period, period);
    p::set_iv(&mut b, P_PERIODS, periods, periods);
    for w in 0..8 {
        put_u32(&mut b, 4 + w * 4, 0);
    }
    put_u32(&mut b, 4, 1 << access);
    e.hw_refine(dir, b, true).unwrap();
}

#[test]
fn open_is_exclusive_and_per_direction() {
    let mut e = engine();
    e.open(0, 1, 0).unwrap();
    assert_eq!(e.open(0, 2, 0), Err(-16));
    e.open(1, 2, 0).unwrap();
    let mut only_playback = Engine::new();
    only_playback.dirs = 1;
    assert_eq!(only_playback.open(1, 1, 0), Err(ENODEV));
    let mut hw = Fake::new();
    e.close(0, &mut hw);
    e.open(0, 3, 0).unwrap();
    assert_eq!(e.streams[0].owner, 3);
}

#[test]
fn hw_params_sets_up_the_stream() {
    let mut e = engine();
    setup(&mut e, 0, 512, 32, ACCESS_MMAP_INTERLEAVED);
    let s = e.streams[0];
    assert_eq!(s.state, ST_SETUP);
    let hw = s.hw.unwrap();
    assert_eq!((hw.period_size, hw.periods, hw.buffer_size, hw.frame_bytes, hw.rate), (512, 32, 16384, 4, 48000));
    assert_eq!(s.stop_threshold, 16384);
    assert_eq!(s.avail_min, 512);
    assert_eq!(s.boundary % 16384, 0);
    assert!(s.boundary > 1 << 60);
    // sw_params: thresholds and the boundary written back
    let mut sw = vec![0u8; 136];
    put_u64(&mut sw, 16, 1024);
    put_u64(&mut sw, 32, 2048);
    put_u64(&mut sw, 40, s.boundary);
    assert_eq!(e.sw_params(0, &mut sw), 0);
    assert_eq!(get_u64(&sw, 64), s.boundary);
    assert_eq!((e.streams[0].avail_min, e.streams[0].start_threshold), (1024, 2048));
    put_u32(&mut sw, 0, 2);
    assert_eq!(e.sw_params(0, &mut sw), EINVAL);
    // Not while running
    let mut hwf = Fake::new();
    assert_eq!(e.prepare(0, &mut hwf), 0);
    e.xfer_commit(0, 4096, &mut hwf);
    assert_eq!(e.streams[0].state, ST_RUNNING, "started at the threshold (2048)");
    assert_eq!(e.hw_refine(0, p::any(), true).err(), Some(EBADFD));
    assert_eq!(e.hw_free(0), EBADFD);
}

#[test]
fn prepare_start_and_the_position() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 512, 32, ACCESS_MMAP_INTERLEAVED);
    hw.rings[0].fill(7);
    assert_eq!(e.prepare(0, &mut hw), 0);
    assert_eq!(hw.setups.len(), 1);
    assert!(hw.rings[0][..65536].iter().all(|&b| b == 0), "prepare silences the ring");
    assert_eq!(e.streams[0].state, ST_PREPARED);
    assert_eq!(e.streams[0].slot, 1);
    // Starting an empty playback stream is an underrun at once
    assert_eq!(e.start(0, &mut hw), EPIPE);
    // The program queues a quarter of the buffer (as mmap + SYNC_PTR)
    let mut sp = vec![0u8; 136];
    put_u64(&mut sp, 72, 4096);
    put_u64(&mut sp, 80, 512);
    assert_eq!(e.sync_ptr(0, &mut sp, &mut hw), 0);
    assert_eq!(e.streams[0].appl_ptr, 4096);
    assert_eq!(e.start(0, &mut hw), 0);
    assert_eq!(hw.triggers.last(), Some(&(0, true)));
    assert_eq!(e.streams[0].state, ST_RUNNING);
    // The controller fetched 1024 frames
    hw.pos[1] = 1024 * 4;
    assert!(e.tick(&mut hw));
    assert_eq!(e.streams[0].hw_ptr, 1024);
    assert_eq!(e.streams[0].avail(0), 16384 - 3072);
    assert_eq!(e.streams[0].delay(0), 3072);
    // SYNC_PTR reports it (flag 1: update first; 2: keep appl)
    let mut sp = vec![0u8; 136];
    put_u32(&mut sp, 0, 1 | 2);
    assert_eq!(e.sync_ptr(0, &mut sp, &mut hw), 0);
    assert_eq!(get_u32(&sp, 8), ST_RUNNING);
    assert_eq!(get_u64(&sp, 16), 1024);
    assert_eq!(get_u64(&sp, 72), 4096);
    // The ring wraps: position back near the start counts forward
    e.sync_ptr(0, &mut { let mut b = vec![0u8; 136]; put_u64(&mut b, 72, 16384 + 1024); put_u64(&mut b, 80, 512); b }, &mut hw);
    hw.pos[1] = 15000 * 4;
    e.tick(&mut hw);
    hw.pos[1] = 200 * 4;
    e.tick(&mut hw);
    assert_eq!(e.streams[0].hw_ptr, 16384 + 200);
    assert_eq!(e.streams[0].state, ST_RUNNING);
}

#[test]
fn played_data_is_silenced_and_an_underrun_stops_the_stream() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 512, 32, ACCESS_MMAP_INTERLEAVED);
    e.prepare(0, &mut hw);
    hw.rings[0][..8192].fill(9);
    e.xfer_commit(0, 2048, &mut hw); // start threshold 1: starts
    assert_eq!(e.streams[0].state, ST_RUNNING);
    hw.pos[1] = 1000 * 4;
    e.tick(&mut hw);
    assert!(hw.rings[0][..4000].iter().all(|&b| b == 0));
    assert!(hw.rings[0][4000..8192].iter().all(|&b| b == 9));
    // The controller passes the program's pointer: underrun
    hw.pos[1] = 2048 * 4;
    e.tick(&mut hw);
    assert_eq!(e.streams[0].state, ST_XRUN);
    assert_eq!(e.streams[0].xruns, 1);
    assert_eq!(hw.triggers.last(), Some(&(0, false)));
    assert_eq!(e.hwsync(0, &mut hw), EPIPE);
    assert_eq!(e.delay(0, &mut hw), Err(EPIPE));
    assert_eq!(e.poll_bits(0) & POLLERR, POLLERR);
    // PREPARE recovers
    assert_eq!(e.prepare(0, &mut hw), 0);
    assert_eq!((e.streams[0].hw_ptr, e.streams[0].appl_ptr, e.streams[0].state), (0, 0, ST_PREPARED));
    // Close counts the session
    let (_, xruns) = e.close(0, &mut hw);
    assert_eq!(xruns, 1);
    assert!(!e.streams[0].open);
}

#[test]
fn writei_copies_until_full_then_blocks() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 1024, 4, ACCESS_RW_INTERLEAVED);
    e.prepare(0, &mut hw);
    // Start threshold: the whole buffer (as aplay)
    let mut sw = vec![0u8; 136];
    put_u64(&mut sw, 16, 1024);
    put_u64(&mut sw, 32, 4096);
    put_u64(&mut sw, 40, 4096);
    e.sw_params(0, &mut sw);
    let mut done = 0;
    loop {
        match e.xfer_next(0, 6000, done, false, &mut hw) {
            Xfer::Chunk { lo, frames, frame_bytes } => {
                assert_eq!(frame_bytes, 4);
                assert_eq!(lo as u64, (done % 4096) * 4);
                done += frames;
                assert_eq!(e.xfer_commit(0, frames, &mut hw), 0);
            }
            Xfer::Block => break,
            Xfer::Done(r) => panic!("ended early: {}", r),
        }
    }
    assert_eq!(done, 4096);
    assert_eq!(e.streams[0].state, ST_RUNNING, "started at the threshold");
    assert_eq!(e.xfer_next(0, 6000, done, true, &mut hw), Xfer::Done(4096), "non-blocking: what was done");
    assert_eq!(e.poll_bits(0), 0, "no room");
    // Room comes back
    hw.pos[1] = 2048 * 4;
    match e.xfer_next(0, 6000, done, false, &mut hw) {
        Xfer::Chunk { lo, frames, .. } => assert_eq!((lo, frames), (0, 1904)),
        x => panic!("{:?}", x),
    }
    assert_eq!(e.poll_bits(0), POLLOUT | POLLWRNORM);
    // A stopped stream ends a transfer
    e.drop_stream(0, &mut hw);
    assert_eq!(e.xfer_next(0, 10, 0, false, &mut hw), Xfer::Done(EBADFD));
    // Prepared and full: EAGAIN, not a wait
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 4095, &mut hw);
    e.xfer_commit(0, 1, &mut hw);
    e.drop_stream(0, &mut hw);
}

#[test]
fn capture_starts_on_the_first_read() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 1, 1024, 4, ACCESS_RW_INTERLEAVED);
    e.prepare(1, &mut hw);
    assert_eq!(e.xfer_next(1, 100, 0, false, &mut hw), Xfer::Block);
    assert_eq!(e.streams[1].state, ST_RUNNING);
    assert_eq!(hw.triggers.last(), Some(&(1, true)));
    hw.pos[2] = 300 * 4;
    match e.xfer_next(1, 100, 0, false, &mut hw) {
        Xfer::Chunk { lo, frames, .. } => assert_eq!((lo, frames), (0, 100)),
        x => panic!("{:?}", x),
    }
    e.xfer_commit(1, 100, &mut hw);
    assert_eq!(e.streams[1].avail(1), 200);
    assert_eq!(e.poll_bits(1), 0, "below avail_min");
}

#[test]
fn drain_plays_to_the_end() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 1024, 4, ACCESS_RW_INTERLEAVED);
    assert_eq!(e.drain_begin(0, false, &mut hw), Some(0), "nothing prepared: done");
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 1500, &mut hw);
    assert_eq!(e.drain_begin(0, false, &mut hw), None);
    assert_eq!(e.streams[0].state, ST_DRAINING);
    assert_eq!(e.xfer_next(0, 10, 0, false, &mut hw), Xfer::Done(EBADFD));
    hw.pos[1] = 1000 * 4;
    assert!(!e.drained(0, &mut hw));
    hw.pos[1] = 1500 * 4;
    assert!(e.drained(0, &mut hw));
    assert_eq!(e.streams[0].state, ST_SETUP);
    assert_eq!(hw.triggers.last(), Some(&(0, false)));
    // Non-blocking drain answers EAGAIN and drains on
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 100, &mut hw);
    assert_eq!(e.drain_begin(0, true, &mut hw), Some(EAGAIN));
    assert_eq!(e.streams[0].state, ST_DRAINING);
    // Capture: a drain is a drop
    setup(&mut e, 1, 1024, 4, ACCESS_RW_INTERLEAVED);
    e.prepare(1, &mut hw);
    assert_eq!(e.drain_begin(1, false, &mut hw), Some(0));
    assert_eq!(e.streams[1].state, ST_SETUP);
}

#[test]
fn status_rewind_forward_reset() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 1024, 4, ACCESS_MMAP_INTERLEAVED);
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 3000, &mut hw);
    hw.pos[1] = 1000 * 4;
    hw.now += 5_000_000;
    let st = e.status(0, &mut hw);
    assert_eq!(get_u32(&st, 0), ST_RUNNING);
    assert_eq!(get_u64(&st, 40), 3000);
    assert_eq!(get_u64(&st, 48), 1000);
    assert_eq!(get_u64(&st, 56), 2000); // delay
    assert_eq!(get_u64(&st, 64), 2096); // avail
    // Wall-clock timestamps by default (tstamp_type 0)
    assert!(get_u64(&st, 112) > 1_600_000_000);
    assert_eq!(e.move_appl(0, 5000, true, &mut hw), Ok(2000));
    assert_eq!(e.streams[0].appl_ptr, 1000);
    assert_eq!(e.move_appl(0, 100, false, &mut hw), Ok(100));
    assert_eq!(e.reset(0, &mut hw), 0);
    assert_eq!(e.streams[0].appl_ptr, e.streams[0].hw_ptr);
    assert_eq!(e.force_xrun(0, &mut hw), 0);
    assert_eq!(e.streams[0].state, ST_XRUN);
}

#[test]
fn driver_failures_are_eio() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 1024, 4, ACCESS_MMAP_INTERLEAVED);
    hw.fail_setup = true;
    assert_eq!(e.prepare(0, &mut hw), EIO);
    hw.fail_setup = false;
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 0, &mut hw);
    hw.fail_trigger = true;
    let mut sp = vec![0u8; 136];
    put_u64(&mut sp, 72, 100);
    put_u64(&mut sp, 80, 1);
    e.sync_ptr(0, &mut sp, &mut hw);
    assert_eq!(e.start(0, &mut hw), EIO);
    assert_eq!(e.streams[0].state, ST_PREPARED);
}

#[test]
fn kept_streams_come_back_as_underruns() {
    let mut e = engine();
    let mut hw = Fake::new();
    setup(&mut e, 0, 512, 32, ACCESS_MMAP_INTERLEAVED);
    e.prepare(0, &mut hw);
    e.xfer_commit(0, 4096, &mut hw);
    let s = e.streams[0];
    assert_eq!(s.state, ST_RUNNING);
    let b = s.encode();
    let d = Stream::decode(&b, 77).unwrap();
    assert_eq!(d.state, ST_XRUN);
    assert_eq!(d.xruns, s.xruns + 1);
    assert_eq!(d.hw, s.hw);
    assert_eq!((d.boundary, d.appl_ptr, d.avail_min, d.owner, d.opened_ns), (s.boundary, s.appl_ptr, s.avail_min, 42, 77));
    // A stream in SETUP stays set up; a closed one stays closed
    let mut e2 = engine();
    setup(&mut e2, 0, 512, 32, ACCESS_RW_INTERLEAVED);
    assert_eq!(Stream::decode(&e2.streams[0].encode(), 0).unwrap().state, ST_SETUP);
    assert!(!Stream::decode(&Stream::new().encode(), 0).unwrap().open);
    // Open without parameters: OPEN
    let mut o = Stream::new();
    o.open = true;
    o.state = ST_PREPARED;
    assert_eq!(Stream::decode(&o.encode(), 0).unwrap().state, ST_OPEN);
    // Garbage is refused
    assert!(Stream::decode(&[0u8; KEPT_STREAM], 0).is_none());
    let mut bad = b;
    put_u64(&mut bad, 8 * 8, 1 << 40); // buffer size beyond the ring
    assert!(Stream::decode(&bad, 0).is_none());
    assert!(Stream::decode(&b[..100], 0).is_none());
}

#[test]
fn mixer_controls() {
    let mut e = engine();
    assert_eq!(e.controls.len(), 2, "playback volume and switch (no capture amplifier)");
    assert_eq!(e.controls[0].values, [64, 64]);
    assert_eq!(e.volume_of(0), Some((64, 64, 0)));
    assert_eq!(e.volume_of(1), None);
    // By number and by name
    let id = e.elem_id(2);
    assert_eq!(e.find_control(&id), Some(2));
    let mut byname = [0u8; 64];
    byname[4] = 2;
    byname[16..16 + 22].copy_from_slice(b"Master Playback Volume");
    assert_eq!(e.find_control(&byname), Some(1));
    byname[60] = 1;
    assert_eq!(e.find_control(&byname), None);
    // Write: a change reports the control and direction; out of range is EINVAL
    let mut w = vec![0u8; 1224];
    w[..64].copy_from_slice(&e.elem_id(1));
    put_u64(&mut w, 72, 30);
    put_u64(&mut w, 80, 31);
    assert_eq!(e.elem_write(&w), Ok(Some((1, 0))));
    assert_eq!(e.elem_write(&w), Ok(None));
    put_u64(&mut w, 72, 75);
    assert_eq!(e.elem_write(&w), Err(EINVAL));
    let mut m = vec![0u8; 1224];
    m[..64].copy_from_slice(&e.elem_id(2));
    put_u64(&mut m, 72, 0);
    put_u64(&mut m, 80, 1);
    assert_eq!(e.elem_write(&m), Ok(Some((2, 0))));
    assert_eq!(e.volume_of(0), Some((30, 31, 1)));
    // Read and info
    let mut r = vec![0u8; 1224];
    r[..64].copy_from_slice(&e.elem_id(1));
    assert_eq!(e.elem_read(&mut r), 0);
    assert_eq!((get_u64(&r, 72), get_u64(&r, 80)), (30, 31));
    let mut i = vec![0u8; 272];
    i[..64].copy_from_slice(&e.elem_id(1));
    assert_eq!(e.elem_info(&mut i), 0);
    assert_eq!((get_u32(&i, 64), get_u64(&i, 88)), (2, 74));
    // The dB scale: -16 dB minimum, 0.25 dB steps
    let t = e.tlv(1, 64).unwrap();
    assert_eq!((get_u32(&t, 8) as i32, get_u32(&t, 12)), (-1600, 25));
    assert_eq!(e.tlv(2, 64).err(), Some(ENXIO));
    assert_eq!(e.tlv(1, 8).err(), Some(ENOMEM));
    // Kept across a restart
    let kept = e.mixer_encode();
    let mut e2 = engine();
    assert!(e2.mixer_decode(&kept));
    assert_eq!(e2.volume_of(0), Some((30, 31, 1)));
    assert!(!e2.mixer_decode(&[0u8; 72]));
    let mut bad = kept;
    put_u64(&mut bad, 8, 500);
    let mut e3 = engine();
    e3.mixer_decode(&bad);
    assert_eq!(e3.controls[0].values, [64, 64], "out of range: kept default");
}

#[test]
fn records_for_the_control_device() {
    let b = card_info(0x1AF4_0022, 0xFEB0_0000);
    assert_eq!(&b[8..13], b"Intel");
    assert!(core::str::from_utf8(&b[72..152]).unwrap().starts_with("HDA Intel at 0xfeb00000"));
    assert!(core::str::from_utf8(&b[168..176]).unwrap().starts_with("QEMU HDA"));
    let p = pcm_info(1, 0x10EC_0269, true);
    assert_eq!(get_u32(&p, 8), 1);
    assert!(core::str::from_utf8(&p[16..32]).unwrap().starts_with("ALC269 Analog"));
    assert_eq!(get_u32(&p, 204), 0);
    assert_eq!(chip_name(0x8086_2805), "Intel HDMI");
    assert_eq!(boundary_for(16384) % 16384, 0);
}
