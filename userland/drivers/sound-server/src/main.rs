//! # Hydra's sound service (sound-server, wave 8, Group S)
//!
//! The Linux sound devices (`/dev/snd`, ALSA, character major 116) out of the kernel: what
//! libasound, PipeWire and Wine's ALSA driver open. A Linux service on the service runtime
//! (`hydra_rt::svcrt`), endpoint [`ENDPOINT_LX_SOUND`], service id `LXS_SOUND`; the kernel
//! sends it the `open` of every device of major 116 and every call on the objects it made
//! (`docs/display-input-design.md`, sections 3.2, 3.6 and 5).
//!
//! - `/dev/snd/controlC0` (116:0): the card, its PCM devices, the mixer controls ("Master
//!   Playback Volume/Switch", "Capture Volume/Switch") and their change events.
//! - `/dev/snd/pcmC0D0p` (116:16), `pcmC0D0c` (116:24): playback and capture, the state
//!   machine of [`pcm`] with the parameter negotiation of [`params`]. Their rings are
//!   kernel memory the controller reads by DMA (`src/ipc/sound.rs`), handed to this service
//!   as memory objects: a program's `mmap` at offset 0 maps the same pages; `WRITEI`/
//!   `READI` copy between the program and the ring here.
//! - The hardware position comes from the controller's DMA position page (mapped here):
//!   the audio hot path (`SYNC_PTR`) never reaches the driver. The main thread looks at
//!   running streams every timer tick (the old kernel task `snd-position`): xruns, the end
//!   of draining, waiting writers and readers, the readiness words.
//! - **The sound driver** (`hda-driver`, unchanged) is called directly with its
//!   `MSG_SND_SETUP/TRIGGER/VOLUME` on its window. When it restarts (its process id, the
//!   kernel's `LX_SND_DRVGEN`, changes) the streams it was playing come back as underruns
//!   (the program prepares them again, as after any underrun) and the volume is set again.
//! - **A restart of this service** (Transparent): the new instance adopts the old one's
//!   objects; the mixer, the streams' parameters and the control files' subscriptions are
//!   in kept state. The kernel silenced the rings when the old instance died (a gap in the
//!   sound); a stream that was playing comes back as an underrun.
//! - `/proc/asound` stays in the kernel; this service writes each stream's state into the
//!   kernel's status page (`SndStatus`), which the kernel's files read.

#![no_std]
#![no_main]

extern crate alloc;

mod lock;
mod params;
mod pcm;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, objs, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

use lock::YLock;
use params::{get_u32, get_u64, put_u32, HwSetup, ACCESS_MMAP_INTERLEAVED};
use pcm::*;

hydra_rt::entry!(main);

const ERESTARTSYS: i64 = -512;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;

/// The ALSA character major.
const MAJOR: u64 = 116;
/// Minors: the control device, playback (`+ 8`: capture).
const MINOR_CONTROL: u64 = 0;
const MINOR_PLAYBACK: u64 = 16;

fn makedev(major: u64, minor: u64) -> u64 {
    (major & 0xFFF) << 8 | (minor & 0xFF) | (minor & !0xFF) << 12
}

// ------------------------------------------------------------------------------------
// The controller (the real `Hw`)
// ------------------------------------------------------------------------------------

/// What the kernel handed over (`LX_SND_GET`), mapped into this process.
struct Hda {
    /// The position page (read-only).
    pos: *const u32,
    /// The rings, per direction (null: none).
    rings: [*mut u8; 2],
    ring_bytes: usize,
    ring_phys: [u64; 2],
    pos_phys: u64,
    /// The sound driver's window (`MSG_SND_SETUP`'s words).
    window: *mut u8,
}

// SAFETY: the pointers name mappings that live as long as the process; every use of the
// rings, the window and the driver happens under ENGINE's lock
unsafe impl Send for Hda {}
unsafe impl Sync for Hda {}

static HDA: spin::Once<Hda> = spin::Once::new();

/// The `Hw` the engine drives (a view of [`HDA`]; used under ENGINE's lock only).
struct Real;

fn hda() -> &'static Hda {
    HDA.get().expect("sound memory mapped before going online")
}

fn snd_call(label: u32, args: [u64; 4]) -> Result<Message, i64> {
    match sys::svc_call(ENDPOINT_SOUND_DEV, Message::new(label as u64, args), 0) {
        Ok(m) if m.label == MSG_SND_REPLY as u64 && m.args[0] == 0 => Ok(m),
        Ok(m) => Err(if (m.args[0] as i64) < 0 { m.args[0] as i64 } else { EIO }),
        Err(e) => Err(e),
    }
}

/// The monotonic clock (ns) from the kernel.
fn now_ns() -> u64 {
    sys::lx_obj(LX_OBJ_SND, LX_SND_NOW, 0, 0).unwrap_or(0)
}

impl Hw for Real {
    fn now_ns(&self) -> u64 {
        now_ns()
    }

    fn wall_base_ns(&self) -> i64 {
        sys::lx_obj(LX_OBJ_SND, LX_SND_NOW, 1, 0).map_or(0, |v| v as i64)
    }

    fn position(&self, slot: usize) -> u64 {
        if slot >= 512 {
            return 0;
        }
        // SAFETY: the position page is mapped for the process's life; the slot is in it
        unsafe { core::ptr::read_volatile(hda().pos.add(slot * 2)) as u64 }
    }

    fn reset_position(&mut self, _slot: usize) {
        // (the page is the kernel's and mapped read-only here: the controller rewrites the
        // slot when the stream starts; `update` only uses differences)
    }

    fn ring(&mut self, dir: usize) -> Option<&mut [u8]> {
        let h = hda();
        let p = *h.rings.get(dir)?;
        // SAFETY: the ring is mapped read-write for the process's life; ENGINE's lock
        // serializes this service's uses of it
        (!p.is_null()).then(|| unsafe { core::slice::from_raw_parts_mut(p, h.ring_bytes) })
    }

    fn setup(&mut self, dir: usize, hw: &HwSetup) -> Result<usize, i64> {
        let h = hda();
        if h.ring_phys[dir] == 0 {
            return Err(ENODEV);
        }
        let words = [dir as u64, h.ring_phys[dir], hw.buffer_size * hw.frame_bytes, hw.period_size * hw.frame_bytes, hw.hda_format(), h.pos_phys];
        for (i, v) in words.iter().enumerate() {
            // SAFETY: the driver's window is mapped (64 pages); only this service uses it
            unsafe { core::ptr::write_volatile(h.window.add(i * 8) as *mut u64, *v) };
        }
        let r = snd_call(MSG_SND_SETUP, [0; 4]).map(|m| m.args[1] as usize);
        if let Err(e) = r {
            println!("[sound-server] the driver could not set up the stream: {}", e);
        }
        r
    }

    fn trigger(&mut self, dir: usize, run: bool) -> Result<(), i64> {
        let r = snd_call(MSG_SND_TRIGGER, [dir as u64, run as u64, 0, 0]).map(|_| ());
        if run {
            if let Err(e) = r {
                println!("[sound-server] the driver could not start the stream: {}", e);
            }
        }
        r
    }
}

// ------------------------------------------------------------------------------------
// State
// ------------------------------------------------------------------------------------

/// The streams and the mixer.
static ENGINE: YLock<Engine> = YLock::new(Engine::new());
/// The card the kernel found: codec vendor, register address.
static VENDOR: AtomicU64 = AtomicU64::new(0);
static MMIO: AtomicU64 = AtomicU64::new(0);

/// An open device.
enum Obj {
    Ctl { events: VecDeque<[u8; 72]>, subscribed: bool },
    Pcm { dir: usize },
}

/// The objects, by slot.
static OBJECTS: YLock<BTreeMap<u32, Obj>> = YLock::new(BTreeMap::new());

/// A call answered later.
#[derive(Clone, Copy)]
enum Wait {
    /// `WRITEI`/`READI`: the transfer record at `arg`, `frames` at `buf`, `done` so far;
    /// the hardware pointer last seen and since when (a stalled stream ends it after 10 s).
    Xfer { dir: usize, arg: u64, buf: u64, frames: u64, done: u64, last_hw: u64, since: u64 },
    /// `DRAIN` until the stream stops draining or `deadline` (ticks).
    Drain { dir: usize, deadline: u64 },
    /// `read` of a control file: `len` bytes at `buf`.
    CtlRead { slot: u32, buf: u64, len: usize },
}

static WAITERS: YLock<Vec<(u64, Wait)>> = YLock::new(Vec::new());
/// Something waits, or a stream runs: the main thread ticks every 10 ms.
static BUSY: AtomicBool = AtomicBool::new(false);

/// The thread raised for each direction (0: none).
static BOOSTED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// The sound driver's process when the streams were last set up.
static DRVGEN: AtomicU64 = AtomicU64::new(0);
/// The status page.
static STATUS: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------------------------------
// Kept state: the mixer, the streams, the subscribed control files
// ------------------------------------------------------------------------------------

static KEPT: spin::Mutex<Option<hydra_rt::kept::Kept>> = spin::Mutex::new(None);
const KEPT_LAYOUT: u32 = 1;
const KEPT_REC: usize = 256;
const REC_MIXER: usize = 0;
const REC_STREAM: usize = 1; // + dir
const REC_SUBS: usize = 3;

fn kept_put(i: usize, data: &[u8]) {
    if let Some(k) = KEPT.lock().as_mut() {
        k.put(i, data);
    }
}

fn kept_get(i: usize) -> Option<Vec<u8>> {
    KEPT.lock().as_ref().and_then(|k| k.get(i).map(|b| b.to_vec()))
}

/// Keeps direction `dir`'s stream.
fn keep_stream(e: &Engine, dir: usize) {
    kept_put(REC_STREAM + dir, &e.streams[dir].encode());
}

/// Keeps the slots of the subscribed control files.
fn keep_subs(objects: &BTreeMap<u32, Obj>) {
    let mut b = [0u8; KEPT_REC];
    let mut n = 0;
    for (slot, o) in objects.iter() {
        if let Obj::Ctl { subscribed: true, .. } = o {
            if n < KEPT_REC / 4 - 1 {
                put_u32(&mut b, 4 + n * 4, *slot);
                n += 1;
            }
        }
    }
    put_u32(&mut b, 0, n as u32);
    kept_put(REC_SUBS, &b);
}

// ------------------------------------------------------------------------------------
// Start
// ------------------------------------------------------------------------------------

fn main(args: &[&str]) {
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[sound-server] no service id names endpoint {:#x}: not started", ENDPOINT_LX_SOUND);
        sys::exit(0);
    }
    let cfg = svcrt::Config { name: "sound-server", endpoint: ENDPOINT_LX_SOUND, workers: svcrt::workers_arg(args, 3), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[sound-server] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    objs::init(svc.area, ENDPOINT_LX_SOUND);
    if let Err(e) = map_card() {
        println!("[sound-server] no sound card memory: {}", e);
        sys::exit_group(1);
    }
    kept_init();
    adopt_objects();
    if let Err(e) = svc.online() {
        println!("[sound-server] cannot go online: {}", e);
        sys::exit_group(1);
    }
    if let Err(e) = sys::lx_svc(LX_SVC_CLAIM_MAJOR, MAJOR, 0, 0) {
        println!("[sound-server] cannot claim major {}: {}", MAJOR, e);
    }
    let mut last_check = 0u64;
    loop {
        let timeout = if BUSY.load(Ordering::Acquire) { 1 } else { 100 };
        match svc.recv(timeout) {
            Event::Request(id, _) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        let now = sys::uptime_ticks();
        if now != last_check {
            last_check = now;
            tick();
        }
        objs::flush();
    }
}

/// Maps what the kernel hands over and builds the mixer.
fn map_card() -> Result<(), i64> {
    let mut info = LxSndInfo::ZERO;
    sys::lx_obj(LX_OBJ_SND, LX_SND_GET, &mut info as *mut LxSndInfo as u64, 0)?;
    let map = |h: u32, len: u64, prot: u32| -> Result<*mut u8, i64> {
        if h == 0 {
            return Ok(core::ptr::null_mut());
        }
        let o = hydra_rt::mem::MemObj::from_raw(h);
        let r = o.map(0, len, prot);
        let _ = o.into_raw();
        r
    };
    // (the handles stay open: a program's `mmap` answer names the ring's)
    let pos = map(info.pos_handle, 4096, hydra_rt::mem::PROT_READ)?;
    let status = map(info.status_handle, 4096, hydra_rt::mem::PROT_RW)?;
    let rings = [map(info.ring_handle[0], info.ring_bytes, hydra_rt::mem::PROT_RW)?, map(info.ring_handle[1], info.ring_bytes, hydra_rt::mem::PROT_RW)?];
    let window = sys::svc_attach(ENDPOINT_SOUND_DEV)? as *mut u8;
    RING_HANDLE[0].store(info.ring_handle[0] as u64, Ordering::Release);
    RING_HANDLE[1].store(info.ring_handle[1] as u64, Ordering::Release);
    STATUS.store(status as usize, Ordering::Release);
    HDA.call_once(|| Hda { pos: pos as *const u32, rings, ring_bytes: info.ring_bytes as usize, ring_phys: info.ring_phys, pos_phys: info.pos_phys, window });
    VENDOR.store(info.vendor as u64, Ordering::Relaxed);
    MMIO.store(info.mmio, Ordering::Relaxed);
    let mut e = ENGINE.lock();
    e.dirs = info.dirs;
    e.build_controls(info.amps);
    let desc = core::str::from_utf8(&info.desc[..(info.desc_len as usize).min(SND_DESC_MAX)]).unwrap_or("");
    println!("[sound-server] sound card: {} ({}), directions {:#x}", chip_name(info.vendor), desc, info.dirs);
    DRVGEN.store(sys::lx_obj(LX_OBJ_SND, LX_SND_DRVGEN, 0, 0).unwrap_or(0), Ordering::Release);
    Ok(())
}

/// The ring handles (for `mmap` answers).
static RING_HANDLE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Maps the kept state; takes the mixer back (and sets the driver's volume from it).
fn kept_init() {
    let size = hydra_rt::kept::Kept::size_for(4, KEPT_REC);
    match sys::lx_svc_kept(size) {
        Ok(p) => {
            // SAFETY: the kernel mapped `size` bytes at `p` for this process alone
            let (k, a) = unsafe { hydra_rt::kept::Kept::open(p, size, KEPT_LAYOUT, KEPT_REC) };
            println!("[sound-server] kept state: {} ({} bad records)", if a.fresh { "new" } else { "adopted" }, a.bad_records);
            *KEPT.lock() = Some(k);
        }
        Err(e) => println!("[sound-server] no kept state: {}", e),
    }
    let mut e = ENGINE.lock();
    if let Some(b) = kept_get(REC_MIXER) {
        e.mixer_decode(&b);
    }
    for dir in 0..2 {
        apply_volume(&e, dir);
    }
}

/// Sends direction `dir`'s volume (from its controls) to the driver.
fn apply_volume(e: &Engine, dir: usize) {
    if let Some((l, r, mute)) = e.volume_of(dir) {
        let _ = snd_call(MSG_SND_VOLUME, [dir as u64, l, r, mute]);
    }
}

/// A Transparent restart: the old instance's devices are taken again, with their streams
/// from kept state (a stream that was playing comes back as an underrun).
fn adopt_objects() {
    let mut found: Vec<LxSvcObj> = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut start = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, start) {
        if n == 0 {
            break;
        }
        found.extend_from_slice(&buf[..n]);
        start = buf[n - 1].slot + 1;
    }
    let mut e = ENGINE.lock();
    let mut hw = Real;
    // The old instance's streams: the hardware stops (the kernel silenced the rings)
    for dir in 0..2 {
        let _ = hw.trigger(dir, false);
    }
    if found.is_empty() {
        return;
    }
    for o in &found {
        if o.kind != LX_OBJ_KIND_SND_CTL && o.kind != LX_OBJ_KIND_SND_PCM {
            let _ = sys::lx_svc_dead(o.slot);
        }
    }
    if sys::lx_svc_adopt().is_err() {
        return; // not a Transparent restart: the kernel makes them stale
    }
    let subs: Vec<u32> = kept_get(REC_SUBS).map_or_else(Vec::new, |b| (0..(get_u32(&b, 0) as usize).min(KEPT_REC / 4 - 1)).map(|i| get_u32(&b, 4 + i * 4)).collect());
    let mut objects = OBJECTS.lock();
    let mut have = [false; 2];
    let now = now_ns();
    for o in found.iter().filter(|o| o.kind == LX_OBJ_KIND_SND_CTL || o.kind == LX_OBJ_KIND_SND_PCM) {
        if !objs::reserve(o.slot) {
            continue;
        }
        let minor = (o.key & 0xFF) | (o.key >> 12) & !0xFF;
        let obj = if o.kind == LX_OBJ_KIND_SND_CTL {
            Obj::Ctl { events: VecDeque::new(), subscribed: subs.contains(&o.slot) }
        } else {
            let dir = (minor.saturating_sub(MINOR_PLAYBACK) / 8).min(1) as usize;
            have[dir] = true;
            Obj::Pcm { dir }
        };
        objects.insert(o.slot, obj);
    }
    for dir in 0..2 {
        let kept = kept_get(REC_STREAM + dir).and_then(|b| Stream::decode(&b, now));
        e.streams[dir] = match kept {
            Some(s) if have[dir] && s.open => s,
            // A device open without a kept stream: open, no parameters (the program's next
            // call gets EBADFD and sets it up again)
            _ if have[dir] => {
                let mut s = Stream::new();
                s.open = true;
                s.opened_ns = now;
                s
            }
            _ => Stream::new(),
        };
        keep_stream(&e, dir);
        write_status(&e, dir);
    }
    println!("[sound-server] adopted {} devices of the previous instance (streams: {} {})", objects.len(), state_name(e.streams[0].state), state_name(e.streams[1].state));
}

fn state_name(s: u32) -> &'static str {
    ["OPEN", "SETUP", "PREPARED", "RUNNING", "XRUN", "DRAINING", "PAUSED"].get(s as usize).copied().unwrap_or("?")
}

// ------------------------------------------------------------------------------------
// The status page and readiness
// ------------------------------------------------------------------------------------

/// Writes direction `dir`'s record of the status page.
fn write_status(e: &Engine, dir: usize) {
    let base = STATUS.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let s = &e.streams[dir];
    let p = (base + dir * SND_STATUS_STRIDE) as *mut SndStatus;
    // SAFETY: the status page is mapped read-write; only this service writes it
    unsafe {
        let seq = core::ptr::read_volatile(&(*p).seq);
        core::ptr::write_volatile(&mut (*p).seq, seq | 1);
        core::sync::atomic::fence(Ordering::Release);
        let hw = s.hw;
        let rec = SndStatus {
            seq: seq | 1,
            open: s.open as u32,
            state: s.state,
            has_hw: hw.is_some() as u32,
            access: hw.map_or(ACCESS_MMAP_INTERLEAVED, |h| h.access),
            rate: hw.map_or(0, |h| h.rate),
            tstamp_mode: s.tstamp_mode,
            owner: s.owner,
            period_size: hw.map_or(0, |h| h.period_size),
            buffer_size: hw.map_or(0, |h| h.buffer_size),
            hw_ptr: s.hw_ptr,
            appl_ptr: s.appl_ptr,
            avail_min: s.avail_min,
            start_threshold: s.start_threshold,
            stop_threshold: s.stop_threshold,
            silence_threshold: s.silence_threshold,
            silence_size: s.silence_size,
            boundary: s.boundary,
            xruns: s.xruns,
        };
        core::ptr::write_volatile(p, rec);
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(&mut (*p).seq, (seq | 1).wrapping_add(1));
    }
}

/// The readiness words of every open device.
fn update_ready(e: &Engine) {
    let objects = OBJECTS.lock();
    for (slot, o) in objects.iter() {
        let bits = match o {
            Obj::Pcm { dir } => e.poll_bits(*dir),
            Obj::Ctl { events, .. } => {
                if events.is_empty() {
                    0
                } else {
                    POLLIN | POLLRDNORM
                }
            }
        };
        if objs::ready(*slot) != bits {
            objs::set(*slot, bits, 0);
        }
    }
}

// ------------------------------------------------------------------------------------
// The timer tick (the old kernel task `snd-position`)
// ------------------------------------------------------------------------------------

/// Calls per direction since the last report (`SYNC_PTR`, `PREPARE`), and when it was.
static SYNCS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static PREPS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static REPORTED: AtomicU64 = AtomicU64::new(0);

/// Every 10 s while a stream is open: its call rate and underruns (section 2.5's measure).
fn report(e: &Engine) {
    let now = sys::uptime_ticks();
    if now < REPORTED.load(Ordering::Relaxed) + 1000 {
        return;
    }
    REPORTED.store(now, Ordering::Relaxed);
    for dir in 0..2 {
        let s = &e.streams[dir];
        let (n, p) = (SYNCS[dir].swap(0, Ordering::Relaxed), PREPS[dir].swap(0, Ordering::Relaxed));
        if s.open && (n > 0 || p > 0) {
            println!("[sound-server] pcm{} 10 s: {} SYNC_PTR, {} PREPARE, {} xruns since open, state {}", dir, n, p, s.xruns, state_name(s.state));
        }
    }
}

fn tick() {
    let mut hw = Real;
    let mut e = ENGINE.lock();
    report(&e);
    let before = [e.streams[0].state, e.streams[1].state];
    let running = e.tick(&mut hw);
    // The sound driver restarted: its streams are gone (the controller was reset)
    let programmed = e.streams.iter().any(|s| s.programmed);
    if programmed || running {
        check_driver(&mut e);
    }
    for dir in 0..2 {
        if e.streams[dir].open {
            write_status(&e, dir);
        }
        if e.streams[dir].state != before[dir] {
            keep_stream(&e, dir);
        }
    }
    let waiting = run_waiters(&mut e, &mut hw);
    update_ready(&e);
    BUSY.store(running || waiting, Ordering::Release);
}

/// Sets the streams up again if the sound driver restarted since they were.
fn check_driver(e: &mut Engine) {
    let gen = sys::lx_obj(LX_OBJ_SND, LX_SND_DRVGEN, 0, 0).unwrap_or(0);
    let old = DRVGEN.load(Ordering::Acquire);
    if gen == old || gen == 0 {
        return;
    }
    DRVGEN.store(gen, Ordering::Release);
    println!("[sound-server] the sound driver restarted (process {} -> {}): streams set up again", old, gen);
    for dir in 0..2 {
        let s = &mut e.streams[dir];
        s.programmed = false;
        if matches!(s.state, ST_PREPARED | ST_RUNNING | ST_DRAINING | ST_PAUSED) {
            // The program prepares it again, as after an underrun
            s.state = ST_XRUN;
            s.xruns += 1;
        }
        keep_stream(e, dir);
        apply_volume(e, dir);
    }
}

/// Serves the calls that wait; whether any still waits.
fn run_waiters(e: &mut Engine, hw: &mut Real) -> bool {
    let list: Vec<(u64, Wait)> = core::mem::take(&mut *WAITERS.lock());
    if list.is_empty() {
        return false;
    }
    let mut keep = Vec::new();
    for (id, w) in list {
        match step_wait(e, hw, id, w) {
            Some(w) => keep.push((id, w)),
            None => {}
        }
    }
    let mut ws = WAITERS.lock();
    keep.extend(ws.drain(..));
    *ws = keep;
    !ws.is_empty()
}

/// One waiting call: `None` when it was answered.
fn step_wait(e: &mut Engine, hw: &mut Real, id: u64, w: Wait) -> Option<Wait> {
    match w {
        Wait::Xfer { dir, arg, buf, frames, mut done, mut last_hw, mut since } => {
            match xfer_run(e, hw, id, dir, buf, frames, &mut done, false) {
                Some(r) => {
                    finish_xfer(id, arg, r);
                    None
                }
                None => {
                    // Blocked: a stream that stopped moving ends it after 10 s, as on Linux
                    let now = sys::uptime_ticks();
                    let h = e.streams[dir].hw_ptr;
                    if h != last_hw {
                        last_hw = h;
                        since = now;
                    } else if now > since + 1000 {
                        finish_xfer(id, arg, if done > 0 { done as i64 } else { EIO });
                        return None;
                    }
                    Some(Wait::Xfer { dir, arg, buf, frames, done, last_hw, since })
                }
            }
        }
        Wait::Drain { dir, deadline } => {
            if e.drained(dir, hw) {
                keep_stream(e, dir);
                let _ = sys::lx_complete(id, 0);
                None
            } else if sys::uptime_ticks() >= deadline {
                e.drop_stream(dir, hw);
                let _ = sys::lx_complete(id, EIO);
                None
            } else {
                Some(w)
            }
        }
        Wait::CtlRead { slot, buf, len } => {
            let r = ctl_read_now(slot, buf, len, id, true);
            if r == EAGAIN {
                Some(w)
            } else {
                let _ = sys::lx_complete(id, r);
                None
            }
        }
    }
}

/// The end of a waiting transfer: the result into the record, the call answered.
fn finish_xfer(id: u64, arg: u64, r: i64) {
    if sys::lx_write(id, arg, &r.to_le_bytes()).is_err() {
        let _ = sys::lx_complete(id, EFAULT);
        return;
    }
    let _ = sys::lx_complete(id, r.min(0));
}

/// A signal for a waiting call: it ends (with what it transferred, or `ERESTARTSYS`).
fn interrupted(id: u64) {
    let w = {
        let mut ws = WAITERS.lock();
        let i = ws.iter().position(|(x, _)| *x == id);
        i.map(|i| ws.remove(i).1)
    };
    match w {
        Some(Wait::Xfer { arg, done, .. }) if done > 0 => finish_xfer(id, arg, done as i64),
        Some(_) => {
            let _ = sys::lx_complete(id, ERESTARTSYS);
        }
        None => {}
    }
}

// ------------------------------------------------------------------------------------
// Notifications
// ------------------------------------------------------------------------------------

fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_CLOSE if b == LX_OBJ_KIND_SND_CTL as u64 || b == LX_OBJ_KIND_SND_PCM as u64 => closed(a as u32),
        LX_NOTE_INTERRUPT => interrupted(a),
        _ => {}
    }
}

/// The last descriptor of object `slot` went.
fn closed(slot: u32) {
    let o = OBJECTS.lock().remove(&slot);
    if let Some(Obj::Pcm { dir }) = o {
        let mut e = ENGINE.lock();
        let (secs, xruns) = e.close(dir, &mut Real);
        if xruns > 0 || secs >= 5 {
            println!("[sound-server] pcm{} closed after {} s: {} xruns", dir, secs, xruns);
        }
        if BOOSTED[dir].swap(0, Ordering::AcqRel) != 0 {
            let _ = sys::lx_obj(LX_OBJ_SND, LX_SND_UNBOOST, dir as u64, 0);
        }
        keep_stream(&e, dir);
        write_status(&e, dir);
    }
    if let Some(Obj::Ctl { subscribed: true, .. }) = o {
        keep_subs(&OBJECTS.lock());
    }
    objs::set(slot, 0, 0);
    objs::free(slot);
}

// ------------------------------------------------------------------------------------
// Calls
// ------------------------------------------------------------------------------------

fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        LX_KCALL_DEVOPEN => (open(&cx, c.dev, c.args[1]), 0),
        16 if c.obj != LX_OBJ_NONE => ioctl(&cx),
        0 if c.obj != LX_OBJ_NONE => read(&cx),
        1 if c.obj != LX_OBJ_NONE => (EINVAL, 0),
        9 if c.obj != LX_OBJ_NONE => (mmap(&cx), 0),
        _ => (ENOSYS, 0),
    };
    objs::flush();
    r
}

/// `open` of device `rdev`: a new object, its descriptor.
fn open(cx: &Cx, rdev: u64, flags: u64) -> i64 {
    let minor = (rdev & 0xFF) | (rdev >> 12) & !0xFF;
    let (obj, kind, name): (Obj, u32, &[u8]) = match minor {
        MINOR_CONTROL => (Obj::Ctl { events: VecDeque::new(), subscribed: false }, LX_OBJ_KIND_SND_CTL, b"/dev/snd/controlC0"),
        16 | 24 => {
            let dir = ((minor - 16) / 8) as usize;
            let mut e = ENGINE.lock();
            if let Err(err) = e.open(dir, cx.c.tgid as u32, now_ns()) {
                return err;
            }
            keep_stream(&e, dir);
            write_status(&e, dir);
            (Obj::Pcm { dir }, LX_OBJ_KIND_SND_PCM, if dir == 0 { b"/dev/snd/pcmC0D0p" } else { b"/dev/snd/pcmC0D0c" })
        }
        _ => return ENXIO,
    };
    let undo = |obj: &Obj| {
        if let Obj::Pcm { dir } = obj {
            let mut e = ENGINE.lock();
            e.close(*dir, &mut Real);
            keep_stream(&e, *dir);
            write_status(&e, *dir);
        }
    };
    let slot = match objs::alloc() {
        Ok(s) => s,
        Err(err) => {
            undo(&obj);
            return err;
        }
    };
    let dev = makedev(MAJOR, minor);
    match objs::install_keyed(cx, slot, kind, flags as u32 & 0o2004000, 0o020660, name, 0, dev) {
        Ok(fd) => {
            let ready = match &obj {
                Obj::Pcm { dir } => ENGINE.lock().poll_bits(*dir),
                Obj::Ctl { .. } => 0,
            };
            OBJECTS.lock().insert(slot, obj);
            objs::set(slot, ready, 0);
            fd
        }
        Err(err) => {
            undo(&obj);
            objs::free(slot);
            err
        }
    }
}

/// `mmap` of a PCM device: its ring at offset 0 (the status and control records at
/// 0x80000000 and 0x81000000 are not mappable: libasound then uses `SYNC_PTR`).
fn mmap(cx: &Cx) -> i64 {
    let Some(dir) = pcm_dir(cx.c.obj as u32) else { return ENODEV };
    let (len, offset) = (cx.args[1], cx.args[5]);
    if offset != 0 {
        return ENXIO;
    }
    if ENGINE.lock().streams[dir].hw.is_none() {
        return EBADFD;
    }
    let h = RING_HANDLE[dir].load(Ordering::Acquire) as u32;
    if h == 0 || len == 0 || len > SND_RING_BYTES {
        return if h == 0 { ENODEV } else { EINVAL };
    }
    hydra_rt::mem::lx_mmap_answer(h, 0, false)
}

fn pcm_dir(slot: u32) -> Option<usize> {
    match OBJECTS.lock().get(&slot) {
        Some(Obj::Pcm { dir }) => Some(*dir),
        _ => None,
    }
}

fn is_ctl(slot: u32) -> bool {
    matches!(OBJECTS.lock().get(&slot), Some(Obj::Ctl { .. }))
}

/// `read`: control events (72 bytes each).
fn read(cx: &Cx) -> Answer {
    let slot = cx.c.obj as u32;
    if !is_ctl(slot) {
        return (if pcm_dir(slot).is_some() { EINVAL } else { EBADF }, 0);
    }
    let (buf, len) = (cx.args[1], cx.args[2] as usize);
    if len < 72 {
        return (EINVAL, 0);
    }
    let r = ctl_read_now(slot, buf, len, cx.id, false);
    if r == EAGAIN && !cx.nonblock() {
        WAITERS.lock().push((cx.id, Wait::CtlRead { slot, buf, len }));
        BUSY.store(true, Ordering::Release);
        let _ = sys::lx_ctl(LX_CTL_WAKE);
        return (0, LX_REPLY_PENDING);
    }
    (r, 0)
}

/// Takes queued events of control file `slot` into `buf` of request `id`: bytes, or
/// `-EAGAIN` (none), `-EBADFD` (not subscribed).
fn ctl_read_now(slot: u32, buf: u64, len: usize, id: u64, _later: bool) -> i64 {
    let mut out = Vec::new();
    {
        let mut objects = OBJECTS.lock();
        let Some(Obj::Ctl { events, subscribed }) = objects.get_mut(&slot) else { return EBADF };
        while out.len() + 72 <= len {
            match events.pop_front() {
                Some(e) => out.extend_from_slice(&e),
                None => break,
            }
        }
        if out.is_empty() {
            return if *subscribed { EAGAIN } else { EBADFD };
        }
    }
    match sys::lx_write(id, buf, &out) {
        Ok(()) => out.len() as i64,
        Err(e) => e,
    }
}

/// Queues a value-change event for control `numid` on every subscribed control file.
fn notify(e: &Engine, numid: u32) {
    let id = e.elem_id(numid);
    let mut objects = OBJECTS.lock();
    for o in objects.values_mut() {
        if let Obj::Ctl { events, subscribed: true } = o {
            let mut ev = [0u8; 72];
            ev[4..8].copy_from_slice(&1u32.to_le_bytes()); // SNDRV_CTL_EVENT_MASK_VALUE
            ev[8..72].copy_from_slice(&id);
            if events.len() < 256 {
                events.push_back(ev);
            }
        }
    }
}

fn write_int(cx: &Cx, arg: u64, v: i32) -> i64 {
    match cx.copy_out(arg, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn read_int(cx: &Cx, arg: u64) -> Result<i32, i64> {
    let v = cx.copy_in(arg, 4)?;
    Ok(i32::from_le_bytes(v[..4].try_into().unwrap_or([0; 4])))
}

/// Copies `n` bytes in at `arg`, lets `f` change them and gives its result; copies them
/// back out when it succeeded.
fn inout(cx: &Cx, arg: u64, n: usize, f: impl FnOnce(&mut [u8]) -> i64) -> i64 {
    let mut b = match cx.copy_in(arg, n) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let r = f(&mut b);
    if r < 0 {
        return r;
    }
    match cx.copy_out(arg, &b) {
        Ok(()) => r,
        Err(e) => e,
    }
}

fn out(cx: &Cx, arg: u64, b: &[u8]) -> i64 {
    match cx.copy_out(arg, b) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn ioctl(cx: &Cx) -> Answer {
    let slot = cx.c.obj as u32;
    if let Some(dir) = pcm_dir(slot) {
        return pcm_ioctl(cx, dir);
    }
    if is_ctl(slot) {
        return (ctl_ioctl(cx, slot), 0);
    }
    (EBADF, 0)
}

/// `ioctl` on `controlC0`.
fn ctl_ioctl(cx: &Cx, slot: u32) -> i64 {
    let (cmd, arg) = (cx.args[1] as u32, cx.args[2]);
    let vendor = VENDOR.load(Ordering::Relaxed) as u32;
    match cmd {
        0x8004_5500 => write_int(cx, arg, 0x0002_0009), // PVERSION 2.0.9
        0x8178_5501 => out(cx, arg, &card_info(vendor, MMIO.load(Ordering::Relaxed))), // CARD_INFO
        0xC050_5510 => {
            // ELEM_LIST
            let mut b = match cx.copy_in(arg, 80) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let (offset, space, pids) = (get_u32(&b, 0), get_u32(&b, 4), get_u64(&b, 16));
            let ids: Vec<[u8; 64]> = {
                let e = ENGINE.lock();
                let count = e.controls.len() as u32;
                put_u32(&mut b, 12, count);
                (offset..count).take(space as usize).map(|i| e.elem_id(i + 1)).collect()
            };
            if !ids.is_empty() {
                let flat: Vec<u8> = ids.iter().flat_map(|i| i.iter().copied()).collect();
                if cx.copy_out(pids, &flat).is_err() {
                    return EFAULT;
                }
            }
            put_u32(&mut b, 8, ids.len() as u32);
            out(cx, arg, &b)
        }
        0xC110_5511 => inout(cx, arg, 272, |b| ENGINE.lock().elem_info(b)),
        0xC4C8_5512 => inout(cx, arg, 1224, |b| ENGINE.lock().elem_read(b)),
        0xC4C8_5513 => {
            let b = match cx.copy_in(arg, 1224) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let mut e = ENGINE.lock();
            match e.elem_write(&b) {
                Ok(Some((numid, dir))) => {
                    let (l, r, m) = e.volume_of(dir).unwrap_or((0, 0, 0));
                    println!("[sound-server] {} volume {}/{}{}", if dir == 0 { "playback" } else { "capture" }, l, r, if m != 0 { " muted" } else { "" });
                    apply_volume(&e, dir);
                    kept_put(REC_MIXER, &e.mixer_encode());
                    notify(&e, numid);
                    drop(e);
                    update_ready(&ENGINE.lock());
                    0
                }
                Ok(None) => 0,
                Err(err) => err,
            }
        }
        0x4040_5514 | 0x4040_5515 => 0, // ELEM_LOCK / UNLOCK
        0xC004_5516 => {
            // SUBSCRIBE_EVENTS: 1 on, 0 off, -1 query
            let v = match read_int(cx, arg) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let mut objects = OBJECTS.lock();
            let Some(Obj::Ctl { subscribed, .. }) = objects.get_mut(&slot) else { return EBADF };
            if v == -1 {
                let cur = *subscribed as i32;
                drop(objects);
                return write_int(cx, arg, cur);
            }
            let new = v != 0;
            let changed = *subscribed != new;
            *subscribed = new;
            if changed {
                keep_subs(&objects);
            }
            0
        }
        0xC110_5517 | 0xC110_5518 | 0xC040_5519 => EPERM, // ELEM_ADD/REPLACE/REMOVE
        0xC008_551A => {
            // TLV_READ
            let hdr = match cx.copy_in(arg, 8) {
                Ok(b) => b,
                Err(e) => return e,
            };
            match ENGINE.lock().tlv(get_u32(&hdr, 0), get_u32(&hdr, 4)) {
                Ok(t) => out(cx, arg + 8, &t),
                Err(e) => e,
            }
        }
        0xC008_551B | 0xC008_551C => ENXIO, // TLV_WRITE / TLV_COMMAND
        0xC004_5520 | 0xC004_5540 | 0xC004_5543 | 0xC004_5544 => write_int(cx, arg, -1), // HWDEP/RAWMIDI/UMP_NEXT_DEVICE
        0x8004_5530 | 0xC004_5530 => {
            // PCM_NEXT_DEVICE: device 0 only
            let d = match read_int(cx, arg) {
                Ok(v) => v,
                Err(e) => return e,
            };
            write_int(cx, arg, if d < 0 { 0 } else { -1 })
        }
        0xC120_5531 => {
            // PCM_INFO
            let b = match cx.copy_in(arg, 288) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let (device, sub, stream) = (get_u32(&b, 0), get_u32(&b, 4), get_u32(&b, 8) as usize);
            if device != 0 || sub != 0 || stream > 1 {
                return ENXIO;
            }
            let (dirs, busy) = {
                let e = ENGINE.lock();
                (e.dirs, e.streams[stream].open)
            };
            if dirs & (1 << stream) == 0 {
                return ENOENT;
            }
            out(cx, arg, &pcm_info(stream, vendor, busy))
        }
        0x4004_5532 | 0x4004_5542 => 0,      // PCM/RAWMIDI_PREFER_SUBDEVICE
        0xC004_55D0 => 0,                    // POWER
        0x8004_55D1 => write_int(cx, arg, 0), // POWER_STATE: D0
        _ => ENOTTY,
    }
}

/// The calling thread drives direction `dir`'s stream: high priority (the kernel's
/// `LX_SND_BOOST`, once per thread).
fn boost(cx: &Cx, dir: usize) {
    let tid = cx.c.tid;
    if tid != 0 && BOOSTED[dir].swap(tid, Ordering::AcqRel) != tid {
        let _ = sys::lx_obj(LX_OBJ_SND, LX_SND_BOOST, dir as u64, tid);
    }
}

/// `ioctl` on a PCM device.
fn pcm_ioctl(cx: &Cx, dir: usize) -> Answer {
    let (cmd, arg) = (cx.args[1] as u32, cx.args[2]);
    let mut hw = Real;
    let vendor = VENDOR.load(Ordering::Relaxed) as u32;
    let frequent = matches!(cmd, 0xC088_4123 | 0x0000_4122 | 0x8008_4121 | 0x8098_4120 | 0xC098_4124);
    let r = match cmd {
        0x8004_4100 => write_int(cx, arg, 0x0002_000F), // PVERSION 2.0.15
        0x8120_4101 => {
            let busy = ENGINE.lock().streams[dir].open;
            out(cx, arg, &pcm_info(dir, vendor, busy))
        }
        0x4004_4102 => match read_int(cx, arg) {
            // TSTAMP (old): 0 none, 1 enabled
            Ok(v) => {
                ENGINE.lock().streams[dir].tstamp_mode = (v != 0) as u32;
                0
            }
            Err(e) => e,
        },
        0x4004_4103 => match read_int(cx, arg) {
            // TTSTAMP: the timestamp clock
            Ok(v) if (0..=2).contains(&v) => {
                ENGINE.lock().streams[dir].tstamp_type = v as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(e) => e,
        },
        0x4004_4104 => 0, // USER_PVERSION
        0xC260_4110 | 0xC260_4111 => {
            let raw = match cx.copy_in(arg, params::HW_PARAMS_SIZE) {
                Ok(b) => b,
                Err(e) => return (e, 0),
            };
            let set = cmd == 0xC260_4111;
            let r = ENGINE.lock().hw_refine(dir, raw, set);
            match r {
                Ok(b) => out(cx, arg, &b),
                Err(e) => {
                    if set {
                        println!("[sound-server] HW_PARAMS refused: {}", e);
                    }
                    e
                }
            }
        }
        0x0000_4112 => ENGINE.lock().hw_free(dir), // HW_FREE
        0xC088_4113 => inout(cx, arg, 136, |b| ENGINE.lock().sw_params(dir, b)),
        0x8098_4120 | 0xC098_4124 => {
            let b = ENGINE.lock().status(dir, &mut hw);
            out(cx, arg, &b)
        }
        0x8008_4121 => {
            // DELAY
            let d = ENGINE.lock().delay(dir, &mut hw);
            match d {
                Ok(d) => out(cx, arg, &d.to_le_bytes()),
                Err(e) => e,
            }
        }
        0x0000_4122 => ENGINE.lock().hwsync(dir, &mut hw), // HWSYNC
        0xC088_4123 => {
            boost(cx, dir);
            SYNCS[dir].fetch_add(1, Ordering::Relaxed);
            inout(cx, arg, 136, |b| ENGINE.lock().sync_ptr(dir, b, &mut hw))
        }
        0x8018_4132 | 0xC018_4132 => {
            // CHANNEL_INFO
            let has = ENGINE.lock().streams[dir].hw.is_some();
            inout(cx, arg, 24, |b| {
                let ch = get_u32(b, 0);
                if ch >= 2 || !has {
                    return EINVAL;
                }
                params::put_u64(b, 8, 0);
                put_u32(b, 16, ch * 16);
                put_u32(b, 20, 32);
                0
            })
        }
        0x0000_4140 => {
            PREPS[dir].fetch_add(1, Ordering::Relaxed);
            ENGINE.lock().prepare(dir, &mut hw)
        }
        0x0000_4141 => ENGINE.lock().reset(dir, &mut hw),
        0x0000_4142 => {
            let r = ENGINE.lock().start(dir, &mut hw);
            if r == 0 {
                boost(cx, dir);
            }
            r
        }
        0x0000_4143 => ENGINE.lock().drop_stream(dir, &mut hw),
        0x0000_4144 => {
            // DRAIN
            let r = ENGINE.lock().drain_begin(dir, cx.nonblock(), &mut hw);
            match r {
                Some(r) => r,
                None => {
                    WAITERS.lock().push((cx.id, Wait::Drain { dir, deadline: sys::uptime_ticks() + 1000 }));
                    BUSY.store(true, Ordering::Release);
                    let _ = sys::lx_ctl(LX_CTL_WAKE);
                    after_pcm(dir, false);
                    return (0, LX_REPLY_PENDING);
                }
            }
        }
        // PAUSE (the flag is the argument itself): not offered (see HW_INFO), as Linux
        // answers for a device without pause
        0x4004_4145 => ENOSYS,
        0x4008_4146 | 0x4008_4149 => {
            // REWIND / FORWARD
            let frames = match cx.copy_in(arg, 8) {
                Ok(b) => get_u64(&b, 0),
                Err(e) => return (e, 0),
            };
            let m = ENGINE.lock().move_appl(dir, frames, cmd == 0x4008_4146, &mut hw);
            match m {
                Ok(n) => out(cx, arg, &n.to_le_bytes()),
                Err(e) => e,
            }
        }
        0x0000_4147 => EINVAL, // RESUME: never suspended
        0x0000_4148 => ENGINE.lock().force_xrun(dir, &mut hw),
        0x4018_4150 if dir == 0 => return transfer(cx, dir, arg),
        0x8018_4151 if dir == 1 => return transfer(cx, dir, arg),
        0x4018_4150 | 0x8018_4151 => EINVAL,
        0x4018_4152 | 0x8018_4153 => EINVAL, // non-interleaved: not offered
        0x4004_4160 | 0x0000_4161 => ENOTTY, // LINK / UNLINK
        _ => ENOTTY,
    };
    after_pcm(dir, !frequent);
    (r, 0)
}

/// After a PCM call: the status page, the readiness words, the kept stream (`keep`: a
/// call that may have changed more than the pointers), the main thread's ticking.
fn after_pcm(dir: usize, keep: bool) {
    let e = ENGINE.lock();
    write_status(&e, dir);
    if keep {
        keep_stream(&e, dir);
    }
    let active = e.streams.iter().any(|s| s.active());
    update_ready(&e);
    drop(e);
    if active && !BUSY.swap(true, Ordering::AcqRel) {
        let _ = sys::lx_ctl(LX_CTL_WAKE);
    }
}

/// Runs a transfer as far as it goes now: `Some(result)` when it ended, `None` when it
/// must wait for the position to move (`done` frames are done).
#[allow(clippy::too_many_arguments)]
fn xfer_run(e: &mut Engine, hw: &mut Real, id: u64, dir: usize, buf: u64, frames: u64, done: &mut u64, nonblock: bool) -> Option<i64> {
    loop {
        match e.xfer_next(dir, frames, *done, nonblock, hw) {
            Xfer::Done(r) => return Some(r),
            Xfer::Block => return None,
            Xfer::Chunk { lo, frames: n, frame_bytes } => {
                let len = (n * frame_bytes) as usize;
                let user = buf + *done * frame_bytes;
                let Some(ring) = hw.ring(dir) else { return Some(ENODEV) };
                let r = if dir == 0 { sys::lx_read(id, user, &mut ring[lo..lo + len]) } else { sys::lx_write(id, user, &ring[lo..lo + len]) };
                if let Err(err) = r {
                    return Some(if *done > 0 { *done as i64 } else { err });
                }
                *done += n;
                let r = e.xfer_commit(dir, n, hw);
                if r < 0 {
                    return Some(if *done > 0 { *done as i64 } else { r });
                }
            }
        }
    }
}

/// `WRITEI_FRAMES` / `READI_FRAMES`: copies frames between the program and the ring
/// (waiting for room or data unless the descriptor is non-blocking).
fn transfer(cx: &Cx, dir: usize, arg: u64) -> Answer {
    let x = match cx.copy_in(arg, 24) {
        Ok(b) => b,
        Err(e) => return (e, 0),
    };
    let (buf, frames) = (get_u64(&x, 8), get_u64(&x, 16));
    let mut done = 0u64;
    let r = {
        let mut e = ENGINE.lock();
        xfer_run(&mut e, &mut Real, cx.id, dir, buf, frames, &mut done, cx.nonblock())
    };
    match r {
        Some(r) => {
            after_pcm(dir, true);
            if cx.copy_out(arg, &r.to_le_bytes()).is_err() {
                return (EFAULT, 0);
            }
            (r.min(0), 0)
        }
        None => {
            let hw_ptr = ENGINE.lock().streams[dir].hw_ptr;
            WAITERS.lock().push((cx.id, Wait::Xfer { dir, arg, buf, frames, done, last_hw: hw_ptr, since: sys::uptime_ticks() }));
            BUSY.store(true, Ordering::Release);
            let _ = sys::lx_ctl(LX_CTL_WAKE);
            after_pcm(dir, true);
            (0, LX_REPLY_PENDING)
        }
    }
}
