//! The PCM streams and the mixer: the state machine of `pcmC0D0p`/`pcmC0D0c` and the
//! controls of `controlC0`, moved from the kernel's `compat/linux/snd.rs` (wave 8, Group S).
//!
//! Plain Rust on byte buffers and a [`Hw`] (the controller: its ring, its position page, the
//! sound driver's calls), so the host tests (`tests/host-w8-s`) run it against a fake
//! controller. The service (`main.rs`) copies the program's records in and out, makes
//! blocking calls wait, and gives this module the real [`Hw`].
//!
//! The hardware position comes from the controller's DMA position page: reading it needs
//! no call to the driver. The service looks at running streams every timer tick
//! ([`Engine::tick`]): it advances their hardware pointer, silences what was played (so an
//! underrun repeats silence, not old sound), stops a stream that ran dry (an "xrun") or
//! finished draining.

use alloc::vec::Vec;

use crate::params::*;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const ENODEV: i64 = -19;
pub const EINVAL: i64 = -22;
pub const ENOTTY: i64 = -25;
pub const EPIPE: i64 = -32;
pub const ENOSYS: i64 = -38;
pub const EBADFD: i64 = -77;

// PCM states
pub const ST_OPEN: u32 = 0;
pub const ST_SETUP: u32 = 1;
pub const ST_PREPARED: u32 = 2;
pub const ST_RUNNING: u32 = 3;
pub const ST_XRUN: u32 = 4;
pub const ST_DRAINING: u32 = 5;
pub const ST_PAUSED: u32 = 6;

pub const POLLIN: u32 = 0x1;
pub const POLLOUT: u32 = 0x4;
pub const POLLERR: u32 = 0x8;
pub const POLLRDNORM: u32 = 0x40;
pub const POLLWRNORM: u32 = 0x100;

/// The controller, as the streams use it.
pub trait Hw {
    /// The monotonic clock, ns.
    fn now_ns(&self) -> u64;
    /// The wall clock's offset from the monotonic clock, ns.
    fn wall_base_ns(&self) -> i64;
    /// Position slot `slot`'s byte position in its ring, as the controller last wrote it.
    fn position(&self, slot: usize) -> u64;
    /// Clears position slot `slot`.
    fn reset_position(&mut self, slot: usize);
    /// Direction `dir`'s ring.
    fn ring(&mut self, dir: usize) -> Option<&mut [u8]>;
    /// Points direction `dir`'s stream at its ring with `hw`'s layout (`MSG_SND_SETUP`);
    /// the stream's position slot.
    fn setup(&mut self, dir: usize, hw: &HwSetup) -> Result<usize, i64>;
    /// Starts or stops direction `dir`'s DMA (`MSG_SND_TRIGGER`).
    fn trigger(&mut self, dir: usize, run: bool) -> Result<(), i64>;
}

/// One direction's stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    pub open: bool,
    pub state: u32,
    pub hw: Option<HwSetup>,
    pub avail_min: u64,
    pub start_threshold: u64,
    pub stop_threshold: u64,
    pub silence_threshold: u64,
    pub silence_size: u64,
    pub boundary: u64,
    pub tstamp_mode: u32,
    /// Clock of the timestamps (0 wall clock, 1 monotonic, 2 monotonic raw).
    pub tstamp_type: u32,
    pub hw_ptr: u64,
    pub appl_ptr: u64,
    /// Position in the ring (frames) at the last update.
    pub last_pos: u64,
    /// Frames the controller has fetched since the start (from its position).
    pub dma_frames: u64,
    /// `hw_ptr` at the start.
    pub start_hw: u64,
    pub avail_max: u64,
    pub trigger_ns: u64,
    pub tstamp_ns: u64,
    /// Slot of the stream in the position page.
    pub slot: usize,
    /// The ring was programmed for the current parameters.
    pub programmed: bool,
    /// Underruns (overruns) since the device was opened.
    pub xruns: u64,
    /// When it was opened (ns) and by which process.
    pub opened_ns: u64,
    pub owner: u32,
}

impl Stream {
    pub const fn new() -> Self {
        Stream {
            open: false,
            state: ST_OPEN,
            hw: None,
            avail_min: 1,
            start_threshold: 1,
            stop_threshold: 0,
            silence_threshold: 0,
            silence_size: 0,
            boundary: 0,
            tstamp_mode: 0,
            tstamp_type: 0,
            hw_ptr: 0,
            appl_ptr: 0,
            last_pos: 0,
            dma_frames: 0,
            start_hw: 0,
            avail_max: 0,
            trigger_ns: 0,
            tstamp_ns: 0,
            slot: 0,
            programmed: false,
            xruns: 0,
            opened_ns: 0,
            owner: 0,
        }
    }

    pub fn active(&self) -> bool {
        self.state == ST_RUNNING || self.state == ST_DRAINING
    }

    /// The hardware streams: running, draining or paused.
    pub fn moving(&self) -> bool {
        matches!(self.state, ST_RUNNING | ST_DRAINING | ST_PAUSED)
    }

    /// Frames the program may write (playback) or read (capture).
    pub fn avail(&self, dir: usize) -> u64 {
        let Some(hw) = self.hw else { return 0 };
        let b = self.boundary.max(1);
        if dir == 0 {
            (self.hw_ptr + hw.buffer_size + b - self.appl_ptr) % b
        } else {
            (self.hw_ptr + b - self.appl_ptr) % b
        }
    }

    /// Frames queued between the program and the hardware.
    pub fn delay(&self, dir: usize) -> i64 {
        let Some(hw) = self.hw else { return 0 };
        if dir == 0 {
            hw.buffer_size as i64 - self.avail(0) as i64
        } else {
            self.avail(1) as i64
        }
    }

    /// `(seconds, nanoseconds)` of a timestamp `ns` (monotonic) in the stream's clock.
    fn timespec(&self, ns: u64, wall_base: i64) -> (u64, u64) {
        let t = if self.tstamp_type == 0 { (wall_base as i128 + ns as i128).max(0) as u64 } else { ns };
        (t / 1_000_000_000, t % 1_000_000_000)
    }

    /// The record kept across a restart of the service (`KEPT_STREAM` bytes).
    pub fn encode(&self) -> [u8; KEPT_STREAM] {
        let mut b = [0u8; KEPT_STREAM];
        let hw = self.hw.unwrap_or(HwSetup { access: 0, rate: 0, period_size: 0, periods: 0, buffer_size: 0, frame_bytes: 0 });
        let words: [u64; 22] = [
            1, // version
            self.open as u64,
            self.state as u64,
            self.hw.is_some() as u64,
            hw.access as u64,
            hw.rate as u64,
            hw.period_size,
            hw.periods,
            hw.buffer_size,
            hw.frame_bytes,
            self.avail_min,
            self.start_threshold,
            self.stop_threshold,
            self.silence_threshold,
            self.silence_size,
            self.boundary,
            self.tstamp_mode as u64 | (self.tstamp_type as u64) << 32,
            self.hw_ptr,
            self.appl_ptr,
            self.slot as u64,
            self.xruns,
            self.owner as u64,
        ];
        for (i, w) in words.iter().enumerate() {
            put_u64(&mut b, i * 8, *w);
        }
        b
    }

    /// The stream a previous instance kept (`None`: not a record of ours). A stream that
    /// was prepared or moving comes back as an underrun: the hardware was stopped and the
    /// program sets it up again (`PREPARE`), as after any underrun.
    pub fn decode(b: &[u8], now_ns: u64) -> Option<Stream> {
        if b.len() < 22 * 8 || get_u64(b, 0) != 1 {
            return None;
        }
        let w = |i: usize| get_u64(b, i * 8);
        let mut s = Stream::new();
        s.open = w(1) != 0;
        if !s.open {
            return Some(s);
        }
        let state = w(2) as u32;
        if w(3) != 0 {
            let hw = HwSetup { access: w(4) as u32, rate: w(5) as u32, period_size: w(6), periods: w(7), buffer_size: w(8), frame_bytes: w(9) };
            // (checked products: the record may be garbage)
            let fits = hw.buffer_size.checked_mul(hw.frame_bytes).is_some_and(|b| b <= BUF_BYTES as u64);
            let periods_ok = hw.period_size.checked_mul(hw.periods) == Some(hw.buffer_size);
            if hw.buffer_size == 0 || hw.frame_bytes == 0 || !fits || !periods_ok || hw.rate == 0 || w(19) >= 512 {
                return None;
            }
            s.hw = Some(hw);
        }
        s.avail_min = w(10).max(1);
        s.start_threshold = w(11);
        s.stop_threshold = w(12);
        s.silence_threshold = w(13);
        s.silence_size = w(14);
        s.boundary = w(15);
        s.tstamp_mode = w(16) as u32;
        s.tstamp_type = (w(16) >> 32) as u32;
        s.hw_ptr = w(17);
        s.appl_ptr = w(18);
        s.slot = w(19) as usize;
        s.xruns = w(20);
        s.owner = w(21) as u32;
        s.opened_ns = now_ns;
        s.state = match state {
            ST_OPEN | ST_SETUP if s.hw.is_some() => ST_SETUP,
            ST_OPEN | ST_SETUP => ST_OPEN,
            _ if s.hw.is_none() => ST_OPEN,
            _ => {
                s.xruns += 1;
                ST_XRUN
            }
        };
        if s.boundary == 0 && s.hw.is_some() {
            return None;
        }
        Some(s)
    }
}

/// Bytes of a stream's kept record.
pub const KEPT_STREAM: usize = 176;

/// What an update asks the caller to do with the hardware.
#[derive(PartialEq, Eq, Debug)]
pub enum Action {
    None,
    Stop,
}

/// The next step of a `WRITEI`/`READI` transfer ([`Engine::xfer_next`]).
#[derive(PartialEq, Eq, Debug)]
pub enum Xfer {
    /// Copy `frames` frames at byte `lo` of the ring, then [`Engine::xfer_commit`].
    Chunk { lo: usize, frames: u64, frame_bytes: u64 },
    /// No room (data) yet: wait for the position to move.
    Block,
    /// The transfer ends with this result.
    Done(i64),
}

/// A mixer control.
#[derive(Clone, Debug)]
pub struct Control {
    pub name: &'static str,
    /// Direction it acts on.
    pub dir: usize,
    /// Volume (integer) or switch (boolean).
    pub volume: bool,
    /// Steps of the amplifier (volume maximum).
    pub max: i64,
    /// Amplifier description (for the dB scale).
    pub amp: u32,
    pub values: [i64; 2],
}

/// The card's streams and mixer.
pub struct Engine {
    pub streams: [Stream; 2],
    /// Directions the card has (bit 0 playback, bit 1 capture).
    pub dirs: u32,
    pub controls: Vec<Control>,
}

/// Linux's boundary for a buffer of `buffer_size` frames: the largest power-of-two
/// multiple that fits.
pub fn boundary_for(buffer_size: u64) -> u64 {
    let mut b = buffer_size.max(1);
    while b * 2 <= (i64::MAX as u64) - buffer_size {
        b *= 2;
    }
    b
}

impl Engine {
    pub const fn new() -> Self {
        Engine { streams: [Stream::new(), Stream::new()], dirs: 0, controls: Vec::new() }
    }

    /// Opens direction `dir` for process `owner`.
    pub fn open(&mut self, dir: usize, owner: u32, now_ns: u64) -> Result<(), i64> {
        if dir > 1 || self.dirs & (1 << dir) == 0 {
            return Err(ENODEV);
        }
        let s = &mut self.streams[dir];
        if s.open {
            return Err(-16); // EBUSY
        }
        *s = Stream::new();
        s.open = true;
        s.opened_ns = now_ns;
        s.owner = owner;
        Ok(())
    }

    /// The last descriptor of direction `dir` closed: the hardware stops; the session's
    /// `(seconds open, xruns)`.
    pub fn close(&mut self, dir: usize, hw: &mut dyn Hw) -> (u64, u64) {
        let s = self.streams[dir];
        if s.moving() {
            let _ = hw.trigger(dir, false);
        }
        self.streams[dir] = Stream::new();
        (hw.now_ns().saturating_sub(s.opened_ns) / 1_000_000_000, s.xruns)
    }

    /// Advances the hardware pointer of a running stream; silences played playback data;
    /// detects underruns and the end of draining.
    pub fn update(&mut self, dir: usize, hw: &mut dyn Hw) -> Action {
        let now = hw.now_ns();
        let s = &mut self.streams[dir];
        if !s.active() {
            // Timestamps say when the status was taken, running or not
            s.tstamp_ns = now;
            return Action::None;
        }
        let Some(setup) = s.hw else { return Action::None };
        let pos = (hw.position(s.slot) / setup.frame_bytes) % setup.buffer_size;
        let delta = (pos + setup.buffer_size - s.last_pos) % setup.buffer_size;
        if delta > 0 {
            if dir == 0 {
                if let Some(bytes) = hw.ring(0) {
                    // Silence what was played: an underrun then loops silence
                    let (a, b) = ((s.last_pos * setup.frame_bytes) as usize, (pos * setup.frame_bytes) as usize);
                    let end = ((setup.buffer_size * setup.frame_bytes) as usize).min(bytes.len());
                    if a < b {
                        bytes[a.min(end)..b.min(end)].fill(0);
                    } else {
                        bytes[a.min(end)..end].fill(0);
                        bytes[..b.min(end)].fill(0);
                    }
                }
            }
            s.dma_frames += delta;
            s.last_pos = pos;
        }
        // What the controller fetched counts as played. (QEMU's codec fetches 8 KiB, 2048
        // frames, the moment a stream starts and stays about that far ahead; holding the
        // pointer back to the clock instead made PipeWire's writes land behind the
        // controller: gaps of silence. With the true position it keeps enough queued.)
        s.hw_ptr = (s.start_hw + s.dma_frames) % s.boundary.max(1);
        s.tstamp_ns = now;
        let avail = s.avail(dir);
        s.avail_max = s.avail_max.max(avail);
        if s.state == ST_DRAINING && dir == 0 && avail >= setup.buffer_size {
            s.state = ST_SETUP;
            return Action::Stop;
        }
        if s.state == ST_RUNNING && s.stop_threshold < s.boundary && avail >= s.stop_threshold {
            s.state = ST_XRUN;
            s.xruns += 1;
            return Action::Stop;
        }
        Action::None
    }

    /// [`Engine::update`], stopping the hardware when it says so.
    pub fn sync(&mut self, dir: usize, hw: &mut dyn Hw) {
        if self.update(dir, hw) == Action::Stop {
            let _ = hw.trigger(dir, false);
        }
    }

    /// Updates every running stream; whether any runs.
    pub fn tick(&mut self, hw: &mut dyn Hw) -> bool {
        let mut any = false;
        for dir in 0..2 {
            any |= self.streams[dir].active();
            self.sync(dir, hw);
        }
        any
    }

    /// `HW_REFINE` (`set` = false) or `HW_PARAMS`: the record narrowed (written back).
    pub fn hw_refine(&mut self, dir: usize, raw: Vec<u8>, set: bool) -> Result<Vec<u8>, i64> {
        if raw.len() < HW_PARAMS_SIZE {
            return Err(EINVAL);
        }
        let mut p = Params::parse(raw);
        if set {
            if !matches!(self.streams[dir].state, ST_OPEN | ST_SETUP | ST_PREPARED) {
                return Err(EBADFD);
            }
            p.choose()?;
            let v = |p: &Params, i| p.get(i).value() as u64;
            let access = p.masks[P_ACCESS][0].trailing_zeros();
            let hw = HwSetup {
                access,
                rate: p.get(P_RATE).value(),
                period_size: v(&p, P_PERIOD_SIZE),
                periods: v(&p, P_PERIODS),
                buffer_size: v(&p, P_BUFFER_SIZE),
                frame_bytes: v(&p, P_FRAME_BITS) / 8,
            };
            if hw.period_size == 0
                || hw.frame_bytes != 4
                || hw.buffer_size != hw.period_size * hw.periods
                || hw.buffer_size * hw.frame_bytes > BUF_BYTES as u64
                || (hw.period_size * hw.frame_bytes) % 128 != 0
            {
                return Err(EINVAL);
            }
            let s = &mut self.streams[dir];
            s.hw = Some(hw);
            s.state = ST_SETUP;
            s.programmed = false;
            s.avail_min = hw.period_size;
            s.start_threshold = 1;
            s.stop_threshold = hw.buffer_size;
            s.silence_threshold = 0;
            s.silence_size = 0;
            s.boundary = boundary_for(hw.buffer_size);
            s.hw_ptr = 0;
            s.appl_ptr = 0;
        } else {
            p.refine()?;
        }
        Ok(p.encode().to_vec())
    }

    /// `HW_FREE`.
    pub fn hw_free(&mut self, dir: usize) -> i64 {
        let s = &mut self.streams[dir];
        if s.moving() {
            return EBADFD;
        }
        s.hw = None;
        s.programmed = false;
        s.state = ST_OPEN;
        0
    }

    /// `SW_PARAMS` on the 136-byte record `b` (the boundary written back).
    pub fn sw_params(&mut self, dir: usize, b: &mut [u8]) -> i64 {
        let s = &mut self.streams[dir];
        if s.hw.is_none() {
            return EBADFD;
        }
        let tstamp_mode = get_u32(b, 0);
        if tstamp_mode > 1 {
            return EINVAL;
        }
        s.tstamp_mode = tstamp_mode;
        s.avail_min = get_u64(b, 16).max(1);
        s.start_threshold = get_u64(b, 32);
        s.stop_threshold = get_u64(b, 40);
        s.silence_threshold = get_u64(b, 48);
        s.silence_size = get_u64(b, 56);
        if get_u32(b, 72) >= 0x0002_000C {
            s.tstamp_type = get_u32(b, 76).min(2);
        }
        put_u64(b, 64, s.boundary);
        0
    }

    /// `STATUS` / `STATUS_EXT`: the 152-byte `snd_pcm_status`.
    pub fn status(&mut self, dir: usize, hw: &mut dyn Hw) -> [u8; 152] {
        self.sync(dir, hw);
        let (now, wall) = (hw.now_ns(), hw.wall_base_ns());
        let s = &mut self.streams[dir];
        let mut b = [0u8; 152];
        put_u32(&mut b, 0, s.state);
        let (sec, nsec) = s.timespec(s.trigger_ns, wall);
        put_u64(&mut b, 8, sec);
        put_u64(&mut b, 16, nsec);
        let (sec, nsec) = s.timespec(now, wall);
        put_u64(&mut b, 24, sec);
        put_u64(&mut b, 32, nsec);
        put_u64(&mut b, 40, s.appl_ptr);
        put_u64(&mut b, 48, s.hw_ptr);
        put_u64(&mut b, 56, s.delay(dir) as u64);
        put_u64(&mut b, 64, s.avail(dir));
        put_u64(&mut b, 72, s.avail_max);
        s.avail_max = 0;
        if let Some(h) = s.hw {
            let at = s.hw_ptr as u128 * 1_000_000_000 / h.rate.max(1) as u128;
            put_u64(&mut b, 96, (at / 1_000_000_000) as u64);
            put_u64(&mut b, 104, (at % 1_000_000_000) as u64);
        }
        let (sec, nsec) = s.timespec(s.tstamp_ns, wall);
        put_u64(&mut b, 112, sec);
        put_u64(&mut b, 120, nsec);
        b
    }

    /// `SYNC_PTR` on the 136-byte record `b`: takes the program's pointer and minimum,
    /// writes the status back.
    pub fn sync_ptr(&mut self, dir: usize, b: &mut [u8], hw: &mut dyn Hw) -> i64 {
        let flags = get_u32(b, 0);
        if flags & 1 != 0 {
            self.sync(dir, hw);
        }
        let wall = hw.wall_base_ns();
        let s = &mut self.streams[dir];
        if flags & 2 == 0 {
            let appl = get_u64(b, 72);
            if s.boundary > 0 {
                s.appl_ptr = appl % s.boundary;
            }
        }
        if flags & 4 == 0 {
            s.avail_min = get_u64(b, 80).max(1);
        }
        put_u32(b, 8, s.state);
        put_u64(b, 16, s.hw_ptr);
        let (sec, nsec) = s.timespec(s.tstamp_ns, wall);
        put_u64(b, 24, sec);
        put_u64(b, 32, nsec);
        put_u32(b, 40, 0);
        if let Some(h) = s.hw {
            let at = s.hw_ptr as u128 * 1_000_000_000 / h.rate.max(1) as u128;
            put_u64(b, 48, (at / 1_000_000_000) as u64);
            put_u64(b, 56, (at % 1_000_000_000) as u64);
        }
        put_u64(b, 72, s.appl_ptr);
        put_u64(b, 80, s.avail_min);
        0
    }

    /// `PREPARE`.
    pub fn prepare(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        let s = self.streams[dir];
        let Some(setup) = s.hw else { return EBADFD };
        if s.moving() {
            let _ = hw.trigger(dir, false);
        }
        let slot = match hw.setup(dir, &setup) {
            Ok(slot) => slot,
            Err(_) => return EIO,
        };
        if let Some(r) = hw.ring(dir) {
            let n = ((setup.buffer_size * setup.frame_bytes) as usize).min(r.len());
            r[..n].fill(0);
        }
        hw.reset_position(slot);
        let s = &mut self.streams[dir];
        s.slot = slot;
        s.programmed = true;
        s.hw_ptr = 0;
        s.appl_ptr = 0;
        s.last_pos = 0;
        s.avail_max = 0;
        s.state = ST_PREPARED;
        0
    }

    /// `START` (the state must be PREPARED).
    pub fn start(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        let s = self.streams[dir];
        if s.state != ST_PREPARED {
            return EBADFD;
        }
        if dir == 0 && s.stop_threshold < s.boundary && s.avail(0) >= s.hw.map_or(0, |h| h.buffer_size) {
            return EPIPE;
        }
        hw.reset_position(s.slot);
        if hw.trigger(dir, true).is_err() {
            return EIO;
        }
        let now = hw.now_ns();
        let s = &mut self.streams[dir];
        s.state = ST_RUNNING;
        s.last_pos = 0;
        s.dma_frames = 0;
        s.start_hw = s.hw_ptr;
        s.trigger_ns = now;
        s.tstamp_ns = now;
        0
    }

    /// `DROP`.
    pub fn drop_stream(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        let s = &mut self.streams[dir];
        if s.state == ST_OPEN {
            return EBADFD;
        }
        let was = s.moving();
        s.state = ST_SETUP;
        if was {
            let _ = hw.trigger(dir, false);
        }
        0
    }

    /// `DRAIN`, first step: `Some(result)` when it is over at once, `None` while the
    /// stream drains (the caller waits for [`Engine::drained`]).
    pub fn drain_begin(&mut self, dir: usize, nonblock: bool, hw: &mut dyn Hw) -> Option<i64> {
        let state = self.streams[dir].state;
        match state {
            ST_OPEN => return Some(EBADFD),
            ST_SETUP | ST_XRUN => {
                self.streams[dir].state = ST_SETUP;
                return Some(0);
            }
            _ => {}
        }
        if dir == 1 {
            return Some(self.drop_stream(dir, hw));
        }
        if state == ST_PREPARED {
            let s = &self.streams[dir];
            if s.avail(0) >= s.hw.map_or(0, |h| h.buffer_size) {
                self.streams[dir].state = ST_SETUP;
                return Some(0);
            }
            let r = self.start(dir, hw);
            if r < 0 {
                return Some(r);
            }
        }
        if state == ST_PAUSED {
            let _ = hw.trigger(dir, true);
        }
        let s = &mut self.streams[dir];
        if s.state == ST_RUNNING || s.state == ST_PAUSED {
            s.state = ST_DRAINING;
        }
        if nonblock {
            return Some(EAGAIN);
        }
        None
    }

    /// Whether direction `dir` finished draining (updates it first).
    pub fn drained(&mut self, dir: usize, hw: &mut dyn Hw) -> bool {
        self.sync(dir, hw);
        self.streams[dir].state != ST_DRAINING
    }

    /// `REWIND` (`back`) or `FORWARD` by up to `frames`: how far it moved.
    pub fn move_appl(&mut self, dir: usize, frames: u64, back: bool, hw: &mut dyn Hw) -> Result<u64, i64> {
        self.sync(dir, hw);
        let s = &mut self.streams[dir];
        let Some(setup) = s.hw else { return Err(EBADFD) };
        let b = s.boundary.max(1);
        let room = if back { setup.buffer_size - s.avail(dir).min(setup.buffer_size) } else { s.avail(dir) };
        let n = frames.min(room);
        s.appl_ptr = if back { (s.appl_ptr + b - n) % b } else { (s.appl_ptr + n) % b };
        Ok(n)
    }

    /// `DELAY`.
    pub fn delay(&mut self, dir: usize, hw: &mut dyn Hw) -> Result<i64, i64> {
        self.sync(dir, hw);
        let s = &self.streams[dir];
        if s.state == ST_XRUN {
            return Err(EPIPE);
        }
        Ok(s.delay(dir))
    }

    /// `HWSYNC`.
    pub fn hwsync(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        self.sync(dir, hw);
        if self.streams[dir].state == ST_XRUN {
            EPIPE
        } else {
            0
        }
    }

    /// `RESET`.
    pub fn reset(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        self.sync(dir, hw);
        let s = &mut self.streams[dir];
        if s.hw.is_none() {
            return EBADFD;
        }
        s.appl_ptr = s.hw_ptr;
        0
    }

    /// `XRUN` (the program asks for one).
    pub fn force_xrun(&mut self, dir: usize, hw: &mut dyn Hw) -> i64 {
        let s = &mut self.streams[dir];
        let was = s.active();
        if s.state != ST_OPEN {
            s.state = ST_XRUN;
        }
        if was {
            let _ = hw.trigger(dir, false);
        }
        0
    }

    /// The next step of a `WRITEI_FRAMES`/`READI_FRAMES` transfer of `frames` frames of
    /// which `done` are done.
    pub fn xfer_next(&mut self, dir: usize, frames: u64, done: u64, nonblock: bool, hw: &mut dyn Hw) -> Xfer {
        loop {
            self.sync(dir, hw);
            let s = self.streams[dir];
            let Some(setup) = s.hw else { return Xfer::Done(EBADFD) };
            let partial = |e: i64| Xfer::Done(if done > 0 { done as i64 } else { e });
            match s.state {
                ST_OPEN | ST_SETUP => return Xfer::Done(EBADFD),
                ST_XRUN => return partial(EPIPE),
                ST_DRAINING if dir == 0 => return Xfer::Done(EBADFD),
                _ => {}
            }
            if done >= frames {
                return Xfer::Done(done as i64);
            }
            if dir == 1 && s.state == ST_PREPARED {
                // Capture starts on the first read
                let r = self.start(dir, hw);
                if r < 0 {
                    return Xfer::Done(r);
                }
                continue;
            }
            let avail = s.avail(dir).min(setup.buffer_size);
            if avail == 0 {
                if s.state == ST_PREPARED || s.state == ST_PAUSED || nonblock {
                    return partial(EAGAIN);
                }
                return Xfer::Block;
            }
            let ofs = s.appl_ptr % setup.buffer_size;
            let n = (frames - done).min(avail).min(setup.buffer_size - ofs);
            return Xfer::Chunk { lo: (ofs * setup.frame_bytes) as usize, frames: n, frame_bytes: setup.frame_bytes };
        }
    }

    /// `n` frames of a transfer were copied: the application pointer moves, and playback
    /// starts at its threshold.
    pub fn xfer_commit(&mut self, dir: usize, n: u64, hw: &mut dyn Hw) -> i64 {
        let s = &mut self.streams[dir];
        let Some(setup) = s.hw else { return EBADFD };
        s.appl_ptr = (s.appl_ptr + n) % s.boundary.max(1);
        let start = dir == 0 && s.state == ST_PREPARED && (setup.buffer_size - s.avail(0).min(setup.buffer_size)) >= s.start_threshold;
        if start {
            let r = self.start(dir, hw);
            if r < 0 {
                return r;
            }
        }
        0
    }

    /// The poll bits of direction `dir` (after an update).
    pub fn poll_bits(&self, dir: usize) -> u32 {
        let s = &self.streams[dir];
        let ok = if dir == 0 { POLLOUT | POLLWRNORM } else { POLLIN | POLLRDNORM };
        match s.state {
            ST_RUNNING | ST_PREPARED | ST_PAUSED => {
                if s.avail(dir) >= s.avail_min {
                    ok
                } else {
                    0
                }
            }
            ST_DRAINING if dir == 0 => 0,
            _ => ok | POLLERR,
        }
    }

    // --------------------------------------------------------------------------------
    // Mixer
    // --------------------------------------------------------------------------------

    /// Builds the controls from the amplifiers the driver reported, at 0 dB and unmuted.
    pub fn build_controls(&mut self, amps: [u32; 2]) {
        self.controls.clear();
        for (dir, vol, sw) in [(0usize, "Master Playback Volume", "Master Playback Switch"), (1, "Capture Volume", "Capture Switch")] {
            let amp = amps[dir];
            if self.dirs & (1 << dir) == 0 || amp & (1 << 24) == 0 || amp & 0x7F == 0 {
                continue;
            }
            let steps = (amp & 0x7F) as i64;
            let zero_db = (((amp >> 8) & 0x7F) as i64).min(steps);
            self.controls.push(Control { name: vol, dir, volume: true, max: steps, amp, values: [zero_db; 2] });
            self.controls.push(Control { name: sw, dir, volume: false, max: 1, amp, values: [1; 2] });
        }
    }

    /// The volume of direction `dir` from its controls: `(left, right, mute bits)`.
    pub fn volume_of(&self, dir: usize) -> Option<(u64, u64, u64)> {
        let gain = self.controls.iter().find(|k| k.dir == dir && k.volume).map(|k| k.values)?;
        let on = self.controls.iter().find(|k| k.dir == dir && !k.volume).map(|k| k.values).unwrap_or([1, 1]);
        let mute = (on[0] == 0) as u64 | ((on[1] == 0) as u64) << 1;
        Some((gain[0] as u64, gain[1] as u64, mute))
    }

    /// The mixer values, for kept state (`[volume, switch] x [left, right]` per direction).
    pub fn mixer_encode(&self) -> [u8; 72] {
        let mut b = [0u8; 72];
        put_u64(&mut b, 0, 1);
        for (i, k) in self.controls.iter().take(4).enumerate() {
            put_u64(&mut b, 8 + i * 16, k.values[0] as u64);
            put_u64(&mut b, 16 + i * 16, k.values[1] as u64);
        }
        b
    }

    /// Takes kept mixer values back (values out of range are ignored).
    pub fn mixer_decode(&mut self, b: &[u8]) -> bool {
        if b.len() < 72 || get_u64(b, 0) != 1 {
            return false;
        }
        for (i, k) in self.controls.iter_mut().take(4).enumerate() {
            let v = [get_u64(b, 8 + i * 16) as i64, get_u64(b, 16 + i * 16) as i64];
            if v.iter().all(|&x| x >= 0 && x <= k.max) {
                k.values = v;
            }
        }
        true
    }

    /// The `snd_ctl_elem_id` of control `numid` (1-based).
    pub fn elem_id(&self, numid: u32) -> [u8; 64] {
        let mut id = [0u8; 64];
        if let Some(k) = self.controls.get((numid as usize).wrapping_sub(1)) {
            id[0..4].copy_from_slice(&numid.to_le_bytes());
            id[4..8].copy_from_slice(&2u32.to_le_bytes()); // SNDRV_CTL_ELEM_IFACE_MIXER
            id[16..16 + k.name.len()].copy_from_slice(k.name.as_bytes());
        }
        id
    }

    /// Finds the control an `snd_ctl_elem_id` names (by number, else by interface and name);
    /// its 1-based number.
    pub fn find_control(&self, id: &[u8]) -> Option<u32> {
        let numid = get_u32(id, 0);
        if numid != 0 {
            return (numid as usize <= self.controls.len()).then_some(numid);
        }
        let iface = get_u32(id, 4);
        let name = &id[16..60];
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let index = get_u32(id, 60);
        if iface != 2 || index != 0 {
            return None;
        }
        self.controls.iter().position(|k| k.name.as_bytes() == &name[..len]).map(|i| i as u32 + 1)
    }

    /// `ELEM_INFO` on the 272-byte record `b`.
    pub fn elem_info(&self, b: &mut [u8]) -> i64 {
        let Some(numid) = self.find_control(&b[0..64]) else { return ENOENT };
        b[0..64].copy_from_slice(&self.elem_id(numid));
        let k = &self.controls[numid as usize - 1];
        put_u32(b, 64, if k.volume { 2 } else { 1 }); // INTEGER / BOOLEAN
        put_u32(b, 68, 0x3 | if k.volume { 0x10 } else { 0 }); // READWRITE, TLV_READ
        put_u32(b, 72, 2); // count
        put_u32(b, 76, 0xFFFF_FFFF); // owner: none (-1)
        b[80..208].fill(0);
        put_u64(b, 80, 0);
        put_u64(b, 88, k.max as u64);
        put_u64(b, 96, if k.volume { 1 } else { 0 });
        0
    }

    /// `ELEM_READ` on the 1224-byte record `b`.
    pub fn elem_read(&self, b: &mut [u8]) -> i64 {
        let Some(numid) = self.find_control(&b[0..64]) else { return ENOENT };
        b[0..64].copy_from_slice(&self.elem_id(numid));
        let v = self.controls[numid as usize - 1].values;
        b[72..1096].fill(0);
        put_u64(b, 72, v[0] as u64);
        put_u64(b, 80, v[1] as u64);
        0
    }

    /// `ELEM_WRITE` of the 1224-byte record `b`: `Ok(Some((numid, dir)))` when a value
    /// changed (the volume goes to the driver, subscribers get an event).
    pub fn elem_write(&mut self, b: &[u8]) -> Result<Option<(u32, usize)>, i64> {
        let Some(numid) = self.find_control(&b[0..64]) else { return Err(ENOENT) };
        let new = [get_u64(b, 72) as i64, get_u64(b, 80) as i64];
        let k = &mut self.controls[numid as usize - 1];
        if new.iter().any(|&v| v < 0 || v > k.max) {
            return Err(EINVAL);
        }
        let changed = k.values != new;
        k.values = new;
        Ok(changed.then_some((numid, k.dir)))
    }

    /// `TLV_READ`: the 16-byte dB scale of control `numid` (buffer of `len` bytes).
    pub fn tlv(&self, numid: u32, len: u32) -> Result<[u8; 16], i64> {
        let amp = match self.controls.get((numid as usize).wrapping_sub(1)) {
            Some(k) if k.volume => k.amp,
            _ => return Err(ENXIO),
        };
        if len < 16 {
            return Err(ENOMEM);
        }
        // SNDRV_CTL_TLVT_DB_SCALE: minimum and step in hundredths of a dB
        let offset = ((amp >> 8) & 0x7F) as i32;
        let step = (((amp >> 16) & 0x7F) as i32 + 1) * 25;
        let mut t = [0u8; 16];
        put_u32(&mut t, 0, 1);
        put_u32(&mut t, 4, 8);
        put_u32(&mut t, 8, (-offset * step) as u32);
        put_u32(&mut t, 12, step as u32);
        Ok(t)
    }
}

/// The codec's chip name as Linux's HDA driver shows it.
pub fn chip_name(vendor: u32) -> alloc::string::String {
    use alloc::string::String;
    let (v, d) = (vendor >> 16, vendor & 0xFFFF);
    match v {
        0x10EC => alloc::format!("ALC{:x}", d),
        0x1AF4 => String::from("QEMU HDA"),
        0x8086 => String::from("Intel HDMI"),
        0x14F1 => alloc::format!("CX{:x}", d),
        0x111D | 0x8384 => alloc::format!("IDT {:x}", d),
        _ => String::from("Generic"),
    }
}

/// Writes `s` NUL-padded into `b`.
pub fn put_str(b: &mut [u8], s: &str) {
    let n = s.len().min(b.len() - 1);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// The `snd_pcm_info` record of direction `dir` (`busy`: someone has it open).
pub fn pcm_info(dir: usize, vendor: u32, busy: bool) -> [u8; 288] {
    let mut b = [0u8; 288];
    b[8..12].copy_from_slice(&(dir as u32).to_le_bytes());
    let name = alloc::format!("{} Analog", chip_name(vendor));
    let n = name.len().min(63);
    b[16..16 + n].copy_from_slice(&name.as_bytes()[..n]);
    let n = name.len().min(79);
    b[80..80 + n].copy_from_slice(&name.as_bytes()[..n]);
    b[160..172].copy_from_slice(b"subdevice #0");
    b[200..204].copy_from_slice(&1u32.to_le_bytes()); // subdevices_count
    b[204..208].copy_from_slice(&(!busy as u32).to_le_bytes()); // subdevices_avail
    b
}

/// Card information: `snd_ctl_card_info`.
pub fn card_info(vendor: u32, mmio: u64) -> [u8; 376] {
    let mut b = [0u8; 376];
    put_str(&mut b[8..24], "Intel");
    put_str(&mut b[24..40], "HDA-Intel");
    put_str(&mut b[40..72], "HDA Intel");
    put_str(&mut b[72..152], &alloc::format!("HDA Intel at {:#x} irq 0", mmio));
    put_str(&mut b[168..248], &chip_name(vendor));
    put_str(&mut b[248..376], &alloc::format!("HDA:{:08x},{:08x},00100000", vendor, vendor));
    b
}
