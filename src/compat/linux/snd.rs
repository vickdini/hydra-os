//! # ALSA sound devices (`/dev/snd`)
//!
//! The Linux sound API on top of Hydra's sound driver (`hda-driver`, a Ring 3 program for
//! Intel High Definition Audio, on [`ENDPOINT_SOUND_DEV`]): what libasound, PipeWire and
//! Wine's ALSA driver open.
//!
//! - `/dev/snd/controlC0` (116:0): the card's identity, its PCM devices, and the mixer
//!   controls "Master Playback Volume/Switch" and "Capture Volume/Switch" (element list,
//!   info, read, write, dB scale, change events).
//! - `/dev/snd/pcmC0D0p` (116:16) and `pcmC0D0c` (116:24): playback and capture. Their
//!   ring buffer is kernel memory the controller reads (or writes) by DMA; programs write
//!   it with `SNDRV_PCM_IOCTL_WRITEI_FRAMES` or map it (`mmap` at offset 0). The status
//!   and control records are not mappable, so libasound exchanges them through
//!   `SNDRV_PCM_IOCTL_SYNC_PTR`.
//!
//! The hardware position comes from the controller's DMA position buffer, a page the
//! controller writes each stream's byte position into: reading it needs no call to the
//! driver. A kernel task looks at running streams every timer tick: it advances their
//! hardware pointer, silences what was played (so an underrun repeats silence, not old
//! sound), stops a stream that ran dry (an "xrun") or finished draining, and wakes the
//! programs waiting for room or data.
//!
//! Hardware parameters are negotiated as Linux does (`HW_REFINE`): masks and intervals
//! narrowed by the device's limits and by the rules relating sizes, times and rates,
//! until nothing changes. The device takes 16-bit stereo at 44.1 or 48 kHz; PipeWire
//! converts everything else.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::ipc::protocol::{ENDPOINT_SOUND_DEV, MSG_SND_INFO, MSG_SND_REPLY, MSG_SND_SETUP, MSG_SND_TRIGGER, MSG_SND_VOLUME};
use crate::ipc::service::{self, ContiguousFrames};
use crate::ipc::Message;
use crate::memory::vm::MappedObject;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

use super::chardev::{makedev, CharDevice};
use super::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EIO: i64 = -5;
const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const EBADFD: i64 = -77;

/// Character device major of ALSA.
pub const MAJOR: u64 = 116;
/// Minor of `controlC0`.
pub const MINOR_CONTROL: u64 = 0;
/// Minor of `pcmC0D0p` (`+ 8`: `pcmC0D0c`).
pub const MINOR_PLAYBACK: u64 = 16;

/// Ring buffer of each stream (the largest buffer a program may ask for).
const BUF_PAGES: u64 = 128;
const BUF_BYTES: u32 = (BUF_PAGES * 4096) as u32;

// PCM states
const ST_OPEN: u32 = 0;
const ST_SETUP: u32 = 1;
const ST_PREPARED: u32 = 2;
const ST_RUNNING: u32 = 3;
const ST_XRUN: u32 = 4;
const ST_DRAINING: u32 = 5;
const ST_PAUSED: u32 = 6;

// Hardware parameter indexes
const P_ACCESS: usize = 0;
const P_FORMAT: usize = 1;
const P_SUBFORMAT: usize = 2;
const P_SAMPLE_BITS: usize = 8;
const P_FRAME_BITS: usize = 9;
const P_CHANNELS: usize = 10;
const P_RATE: usize = 11;
const P_PERIOD_TIME: usize = 12;
const P_PERIOD_SIZE: usize = 13;
const P_PERIOD_BYTES: usize = 14;
const P_PERIODS: usize = 15;
const P_BUFFER_TIME: usize = 16;
const P_BUFFER_SIZE: usize = 17;
const P_BUFFER_BYTES: usize = 18;

const ACCESS_MMAP_INTERLEAVED: u32 = 0;
const ACCESS_RW_INTERLEAVED: u32 = 3;
const FORMAT_S16_LE: u32 = 2;
/// The rates the device takes.
const RATES: [u32; 2] = [44100, 48000];

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
const HW_INFO: u32 = INFO_MMAP | INFO_MMAP_VALID | INFO_BATCH | INFO_INTERLEAVED | INFO_BLOCK_TRANSFER | INFO_NO_PERIOD_WAKEUP;

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const POLLERR: u32 = 0x8;
const POLLRDNORM: u32 = 0x40;
const POLLWRNORM: u32 = 0x100;

/// Woken whenever the stream positions advance or a stream changes state.
static SND_WQ: WaitQueue = WaitQueue::new();
/// Logs PCM ioctls (other than the frequent position ones) and failures.
static TRACE: AtomicBool = AtomicBool::new(false);
static SYNC_TRACED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Wakes the position task when a stream starts.
static TASK_WQ: WaitQueue = WaitQueue::new();

/// The thread that drives each direction's stream (`SYNC_PTR`, `START`), raised to the
/// scheduler's high priority while it holds the device open (0: none). PipeWire runs the
/// card from a timer in its data thread, which must run within a few milliseconds of it:
/// at normal priority, behind Firefox's threads, it ran 50-250 ms late and the card ran
/// dry 1-3 times a second (wave 6, G25). On Ubuntu RTKit makes that thread real-time;
/// PipeWire asks RTKit through the desktop portal, which Hydra does not serve, so the
/// device does it for the thread that drives it.
static DRIVER: [core::sync::atomic::AtomicU64; 2] = [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)];

/// Makes the calling thread direction `dir`'s driver: high priority (a Linux thread at
/// normal priority only), the previous driver back to its own priority.
fn boost_caller(dir: usize) {
    let me = crate::task::CURRENT_TID.load(Ordering::Relaxed);
    let old = DRIVER[dir].load(Ordering::Relaxed);
    if me == 0 || old == me {
        return;
    }
    DRIVER[dir].store(me, Ordering::Relaxed);
    if old != 0 {
        super::extra::reapply_priority(old);
    }
    crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(me), |t| {
        if t.personality.is_posix() && t.priority == crate::task::TaskPriority::Normal {
            t.priority = crate::task::TaskPriority::High;
        }
    });
}

/// The device of direction `dir` was closed: its driver thread gets its own priority back.
fn unboost(dir: usize) {
    let old = DRIVER[dir].swap(0, Ordering::Relaxed);
    if old != 0 {
        super::extra::reapply_priority(old);
    }
}

/// What the driver reported about the card.
#[derive(Clone)]
struct Card {
    vendor: u32,
    /// Bit 0 playback, bit 1 capture.
    dirs: u32,
    /// Volume amplifier per direction (see `MSG_SND_INFO`; 0: none).
    amps: [u32; 2],
    /// The driver's description of the codec.
    desc: String,
    /// The controller's register address (for the long name).
    mmio: u64,
}

static CARD: Mutex<Option<Card>> = Mutex::new(None);
/// The DMA position buffer (one page, the controller writes positions into it).
static POSBUF: spin::Once<Arc<ContiguousFrames>> = spin::Once::new();
/// Ring buffers, per direction.
static BUFFERS: [spin::Once<Option<Arc<ContiguousFrames>>>; 2] = [spin::Once::new(), spin::Once::new()];

/// The controller's register address, recorded by the supervisor when it starts the driver.
static MMIO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// PCI slot of the controller (`0000:00:1b.0`), for sysfs.
static SLOT: Mutex<Option<(String, u16, u16, u32)>> = Mutex::new(None);

/// Records the controller the supervisor found (`slot`, vendor, device, subsystem IDs).
pub fn set_controller(mmio: u64, slot: String, vendor: u16, device: u16, subsys: u32) {
    MMIO.store(mmio, Ordering::Relaxed);
    *SLOT.lock() = Some((slot, vendor, device, subsys));
}

/// The controller's PCI identity, if there is a sound card: `(slot, vendor, device,
/// subsystem)`.
pub fn controller() -> Option<(String, u16, u16, u32)> {
    if CARD.lock().is_none() {
        return None;
    }
    SLOT.lock().clone()
}

/// Whether a card is present.
pub fn present() -> bool {
    CARD.lock().is_some()
}

/// Whether direction `dir` exists.
pub fn has_dir(dir: usize) -> bool {
    CARD.lock().as_ref().map_or(false, |c| c.dirs & (1 << dir) != 0)
}

/// Called after the supervisor started the drivers: asks the sound driver about the card,
/// allocates the buffers, and starts the position task.
pub fn start() {
    if !service::is_online(ENDPOINT_SOUND_DEV) {
        return;
    }
    let reply = {
        let _w = service::hold_window(ENDPOINT_SOUND_DEV);
        let r = service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_INFO, [0; 4]), service::CALL_TIMEOUT_TICKS);
        r.map(|m| {
            let desc = service::window(ENDPOINT_SOUND_DEV)
                .map(|w| {
                    let n = w.iter().take(1024).position(|&b| b == 0).unwrap_or(0);
                    String::from_utf8_lossy(&w[..n]).into_owned()
                })
                .unwrap_or_default();
            (m, desc)
        })
    };
    let (m, desc) = match reply {
        Ok((m, d)) if m.label == MSG_SND_REPLY && m.args[0] == 0 => (m, d),
        _ => {
            crate::kprintln!("[snd] the sound driver did not describe the card");
            return;
        }
    };
    let Some(pos) = ContiguousFrames::allocate(1) else { return };
    POSBUF.call_once(|| pos);
    for dir in 0..2 {
        BUFFERS[dir].call_once(|| if m.args[2] & (1 << dir) != 0 { ContiguousFrames::allocate(BUF_PAGES) } else { None });
    }
    let mut dirs = m.args[2] as u32;
    for dir in 0..2 {
        if BUFFERS[dir].get().map_or(true, |b| b.is_none()) {
            dirs &= !(1 << dir);
        }
    }
    // IOMMU (Group 1): the controller reaches these kernel buffers by DMA; they live as
    // long as the kernel, across driver restarts
    let shared = POSBUF.get().into_iter().chain(BUFFERS.iter().filter_map(|b| b.get().and_then(|b| b.as_ref())));
    for b in shared {
        if crate::arch::iommu::map_dma(ENDPOINT_SOUND_DEV, b.base, b.pages * 4096).is_err() {
            crate::kprintln!("[snd] the sound controller's IOMMU domain could not map a buffer");
        }
    }
    if dirs & 1 == 0 {
        crate::kprintln!("[snd] no playback buffer");
        return;
    }
    let card = Card { vendor: m.args[1] as u32, dirs, amps: [m.args[3] as u32, (m.args[3] >> 32) as u32], desc, mmio: MMIO.load(Ordering::Relaxed) };
    build_controls(&card);
    crate::kprintln!("[snd] sound card: {} ({})", chip_name(card.vendor), card.desc);
    *CARD.lock() = Some(card);
    crate::task::spawn("snd-position", position_task, crate::task::TaskPriority::Normal);
}

/// The codec's chip name as Linux's HDA driver shows it.
fn chip_name(vendor: u32) -> String {
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

// ------------------------------------------------------------------------------------
// Mixer controls
// ------------------------------------------------------------------------------------

/// A mixer control.
struct Control {
    name: &'static str,
    /// Direction it acts on.
    dir: usize,
    /// Volume (integer) or switch (boolean).
    volume: bool,
    /// Steps of the amplifier (volume maximum).
    max: i64,
    /// Amplifier description (for the dB scale).
    amp: u32,
    values: [i64; 2],
}

static CONTROLS: Mutex<Vec<Control>> = Mutex::new(Vec::new());

/// Builds the controls from the amplifiers the driver reported, at 0 dB and unmuted.
fn build_controls(card: &Card) {
    let mut c = CONTROLS.lock();
    c.clear();
    for (dir, vol, sw) in [(0usize, "Master Playback Volume", "Master Playback Switch"), (1, "Capture Volume", "Capture Switch")] {
        let amp = card.amps[dir];
        if card.dirs & (1 << dir) == 0 || amp & (1 << 24) == 0 || amp & 0x7F == 0 {
            continue;
        }
        let steps = (amp & 0x7F) as i64;
        let zero_db = (((amp >> 8) & 0x7F) as i64).min(steps);
        c.push(Control { name: vol, dir, volume: true, max: steps, amp, values: [zero_db; 2] });
        c.push(Control { name: sw, dir, volume: false, max: 1, amp, values: [1; 2] });
    }
}

/// Sends the volume of direction `dir` (from its controls) to the driver.
fn apply_volume(dir: usize) {
    let (gain, on) = {
        let c = CONTROLS.lock();
        let gain = c.iter().find(|k| k.dir == dir && k.volume).map(|k| k.values);
        let on = c.iter().find(|k| k.dir == dir && !k.volume).map(|k| k.values).unwrap_or([1, 1]);
        (gain, on)
    };
    let Some(gain) = gain else { return };
    let mute = (on[0] == 0) as u64 | ((on[1] == 0) as u64) << 1;
    crate::kprintln!("[snd] {} volume {}/{}{}", if dir == 0 { "playback" } else { "capture" }, gain[0], gain[1], if mute != 0 { " muted" } else { "" });
    let _ = service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_VOLUME, [dir as u64, gain[0] as u64, gain[1] as u64, mute]), service::CALL_TIMEOUT_TICKS);
}

/// Open control files that subscribed to events.
static SUBSCRIBERS: Mutex<Vec<Weak<CtlFile>>> = Mutex::new(Vec::new());

/// Queues a value-change event for control `numid` on every subscribed control file.
fn notify(numid: u32) {
    let id = elem_id(numid);
    let mut subs = SUBSCRIBERS.lock();
    subs.retain(|w| w.strong_count() > 0);
    for f in subs.iter().filter_map(|w| w.upgrade()) {
        let mut ev = [0u8; 72];
        ev[4..8].copy_from_slice(&1u32.to_le_bytes()); // SNDRV_CTL_EVENT_MASK_VALUE
        ev[8..72].copy_from_slice(&id);
        let mut q = f.events.lock();
        if q.len() < 256 {
            q.push_back(ev);
        }
    }
    drop(subs);
    SND_WQ.wake_all();
}

/// The `snd_ctl_elem_id` of control `numid` (1-based).
fn elem_id(numid: u32) -> [u8; 64] {
    let mut id = [0u8; 64];
    let c = CONTROLS.lock();
    if let Some(k) = c.get(numid as usize - 1) {
        id[0..4].copy_from_slice(&numid.to_le_bytes());
        id[4..8].copy_from_slice(&2u32.to_le_bytes()); // SNDRV_CTL_ELEM_IFACE_MIXER
        id[16..16 + k.name.len()].copy_from_slice(k.name.as_bytes());
    }
    id
}

/// Finds the control an `snd_ctl_elem_id` names (by number, else by interface and name);
/// its 1-based number.
fn find_control(id: &[u8]) -> Option<u32> {
    let numid = u32::from_le_bytes(id[0..4].try_into().ok()?);
    let c = CONTROLS.lock();
    if numid != 0 {
        return (numid as usize <= c.len()).then_some(numid);
    }
    let iface = u32::from_le_bytes(id[4..8].try_into().ok()?);
    let name = &id[16..60];
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let index = u32::from_le_bytes(id[60..64].try_into().ok()?);
    if iface != 2 || index != 0 {
        return None;
    }
    c.iter().position(|k| k.name.as_bytes() == &name[..len]).map(|i| i as u32 + 1)
}

// ------------------------------------------------------------------------------------
// Control device
// ------------------------------------------------------------------------------------

/// An open `/dev/snd/controlC0`.
pub struct CtlFile {
    events: Mutex<VecDeque<[u8; 72]>>,
    subscribed: AtomicBool,
    nonblock: AtomicBool,
}

/// The `snd_pcm_info` record of direction `dir`.
fn pcm_info(dir: usize, card: &Card) -> [u8; 288] {
    let mut b = [0u8; 288];
    b[8..12].copy_from_slice(&(dir as u32).to_le_bytes());
    let name = alloc::format!("{} Analog", chip_name(card.vendor));
    let n = name.len().min(63);
    b[16..16 + n].copy_from_slice(&name.as_bytes()[..n]);
    let n = name.len().min(79);
    b[80..80 + n].copy_from_slice(&name.as_bytes()[..n]);
    b[160..172].copy_from_slice(b"subdevice #0");
    b[200..204].copy_from_slice(&1u32.to_le_bytes()); // subdevices_count
    let busy = STREAMS[dir].lock().open;
    b[204..208].copy_from_slice(&(!busy as u32).to_le_bytes()); // subdevices_avail
    b
}

/// Writes `s` NUL-padded into `b`.
fn put_str(b: &mut [u8], s: &str) {
    let n = s.len().min(b.len() - 1);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
}

fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Reads an `int` argument.
fn read_int(arg: u64) -> Result<i32, i64> {
    let v = copy_in(arg, 4)?;
    Ok(i32::from_le_bytes(v[..4].try_into().unwrap()))
}

fn write_int(arg: u64, v: i32) -> i64 {
    match copy_out(arg, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Card information: `snd_ctl_card_info`.
fn card_info(card: &Card) -> [u8; 376] {
    let mut b = [0u8; 376];
    put_str(&mut b[8..24], "Intel");
    put_str(&mut b[24..40], "HDA-Intel");
    put_str(&mut b[40..72], "HDA Intel");
    put_str(&mut b[72..152], &alloc::format!("HDA Intel at {:#x} irq 0", card.mmio));
    put_str(&mut b[168..248], &chip_name(card.vendor));
    put_str(&mut b[248..376], &alloc::format!("HDA:{:08x},{:08x},00100000", card.vendor, card.vendor));
    b
}

impl CtlFile {
    fn elem_info(&self, arg: u64) -> i64 {
        let mut b = match copy_in(arg, 272) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let Some(numid) = find_control(&b[0..64]) else { return ENOENT };
        let id = elem_id(numid);
        b[0..64].copy_from_slice(&id);
        let c = CONTROLS.lock();
        let k = &c[numid as usize - 1];
        put_u32(&mut b, 64, if k.volume { 2 } else { 1 }); // INTEGER / BOOLEAN
        let access = 0x3 | if k.volume { 0x10 } else { 0 }; // READWRITE, TLV_READ
        put_u32(&mut b, 68, access);
        put_u32(&mut b, 72, 2); // count
        put_u32(&mut b, 76, 0xFFFF_FFFF); // owner: none (-1)
        b[80..208].fill(0);
        put_u64(&mut b, 80, 0);
        put_u64(&mut b, 88, k.max as u64);
        put_u64(&mut b, 96, if k.volume { 1 } else { 0 });
        drop(c);
        match copy_out(arg, &b) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn elem_read(&self, arg: u64) -> i64 {
        let mut b = match copy_in(arg, 1224) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let Some(numid) = find_control(&b[0..64]) else { return ENOENT };
        b[0..64].copy_from_slice(&elem_id(numid));
        let v = CONTROLS.lock()[numid as usize - 1].values;
        b[72..1096].fill(0);
        put_u64(&mut b, 72, v[0] as u64);
        put_u64(&mut b, 80, v[1] as u64);
        match copy_out(arg, &b) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn elem_write(&self, arg: u64) -> i64 {
        let b = match copy_in(arg, 1224) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let Some(numid) = find_control(&b[0..64]) else { return ENOENT };
        let new = [get_u64(&b, 72) as i64, get_u64(&b, 80) as i64];
        let (changed, dir) = {
            let mut c = CONTROLS.lock();
            let k = &mut c[numid as usize - 1];
            if new.iter().any(|&v| v < 0 || v > k.max) {
                return EINVAL;
            }
            let changed = k.values != new;
            k.values = new;
            (changed, k.dir)
        };
        if changed {
            apply_volume(dir);
            notify(numid);
        }
        0
    }

    fn tlv_read(&self, arg: u64) -> i64 {
        let hdr = match copy_in(arg, 8) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let (numid, len) = (get_u32(&hdr, 0), get_u32(&hdr, 4));
        let amp = {
            let c = CONTROLS.lock();
            match c.get((numid as usize).wrapping_sub(1)) {
                Some(k) if k.volume => k.amp,
                _ => return ENXIO,
            }
        };
        if len < 16 {
            return ENOMEM;
        }
        // SNDRV_CTL_TLVT_DB_SCALE: minimum and step in hundredths of a dB
        let offset = ((amp >> 8) & 0x7F) as i32;
        let step = (((amp >> 16) & 0x7F) as i32 + 1) * 25;
        let mut t = [0u8; 16];
        put_u32(&mut t, 0, 1);
        put_u32(&mut t, 4, 8);
        put_u32(&mut t, 8, (-offset * step) as u32);
        put_u32(&mut t, 12, step as u32);
        match copy_out(arg + 8, &t) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }
}

impl CharDevice for CtlFile {
    fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.len() < 72 {
            return EINVAL;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&SND_WQ));
        loop {
            waits.register();
            {
                let mut q = self.events.lock();
                let mut n = 0;
                while n + 72 <= buf.len() {
                    match q.pop_front() {
                        Some(e) => {
                            buf[n..n + 72].copy_from_slice(&e);
                            n += 72;
                        }
                        None => break,
                    }
                }
                if n > 0 {
                    return n as i64;
                }
            }
            if !self.subscribed.load(Ordering::Relaxed) {
                return EBADFD;
            }
            if self.nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        let Some(card) = CARD.lock().clone() else { return ENODEV };
        match cmd as u32 {
            0x8004_5500 => write_int(arg, 0x0002_0009), // PVERSION 2.0.9
            0x8178_5501 => match copy_out(arg, &card_info(&card)) {
                // CARD_INFO
                Ok(()) => 0,
                Err(e) => e,
            },
            0xC050_5510 => {
                // ELEM_LIST
                let mut b = match copy_in(arg, 80) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                let (offset, space, pids) = (get_u32(&b, 0), get_u32(&b, 4), get_u64(&b, 16));
                let count = CONTROLS.lock().len() as u32;
                let mut used = 0;
                let mut i = offset;
                while i < count && used < space {
                    if copy_out(pids + used as u64 * 64, &elem_id(i + 1)).is_err() {
                        return EFAULT;
                    }
                    used += 1;
                    i += 1;
                }
                put_u32(&mut b, 8, used);
                put_u32(&mut b, 12, count);
                match copy_out(arg, &b) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            0xC110_5511 => self.elem_info(arg),
            0xC4C8_5512 => self.elem_read(arg),
            0xC4C8_5513 => self.elem_write(arg),
            0x4040_5514 | 0x4040_5515 => 0, // ELEM_LOCK / UNLOCK
            0xC004_5516 => {
                // SUBSCRIBE_EVENTS: 1 on, 0 off, -1 query
                let v = match read_int(arg) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match v {
                    -1 => write_int(arg, self.subscribed.load(Ordering::Relaxed) as i32),
                    0 => {
                        self.subscribed.store(false, Ordering::Relaxed);
                        0
                    }
                    _ => {
                        self.subscribed.store(true, Ordering::Relaxed);
                        0
                    }
                }
            }
            0xC110_5517 | 0xC110_5518 | 0xC040_5519 => EPERM, // ELEM_ADD/REPLACE/REMOVE
            0xC008_551A => self.tlv_read(arg),
            0xC008_551B | 0xC008_551C => ENXIO, // TLV_WRITE / TLV_COMMAND
            0xC004_5520 | 0xC004_5540 | 0xC004_5543 | 0xC004_5544 => write_int(arg, -1), // HWDEP/RAWMIDI/UMP_NEXT_DEVICE
            0x8004_5530 | 0xC004_5530 => {
                // PCM_NEXT_DEVICE: device 0 only
                let d = match read_int(arg) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                write_int(arg, if d < 0 { 0 } else { -1 })
            }
            0xC120_5531 => {
                // PCM_INFO
                let b = match copy_in(arg, 288) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                let (device, sub, stream) = (get_u32(&b, 0), get_u32(&b, 4), get_u32(&b, 8) as usize);
                if device != 0 || sub != 0 || stream > 1 {
                    return ENXIO;
                }
                if card.dirs & (1 << stream) == 0 {
                    return ENOENT;
                }
                match copy_out(arg, &pcm_info(stream, &card)) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            0x4004_5532 | 0x4004_5542 => 0, // PCM/RAWMIDI_PREFER_SUBDEVICE
            0xC004_55D0 => 0,               // POWER
            0x8004_55D1 => write_int(arg, 0), // POWER_STATE: D0
            _ => ENOTTY,
        }
    }

    fn poll_events(&self) -> u32 {
        if self.events.lock().is_empty() {
            0
        } else {
            POLLIN | POLLRDNORM
        }
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Static(&SND_WQ));
    }

    fn rdev(&self) -> u64 {
        makedev(MAJOR, MINOR_CONTROL)
    }

    fn path(&self) -> String {
        String::from("/dev/snd/controlC0")
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}

// ------------------------------------------------------------------------------------
// Hardware parameters
// ------------------------------------------------------------------------------------

/// An `snd_interval`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
struct Iv {
    min: u32,
    max: u32,
    openmin: bool,
    openmax: bool,
    integer: bool,
    empty: bool,
}

impl Iv {
    fn new(min: u32, max: u32, integer: bool) -> Self {
        Iv { min, max, openmin: false, openmax: false, integer, empty: false }
    }

    fn none() -> Self {
        Iv { empty: true, ..Default::default() }
    }

    fn single(&self) -> bool {
        !self.empty && (self.min == self.max || (self.min + 1 == self.max && (self.openmin || self.openmax)))
    }

    fn value(&self) -> u32 {
        if self.openmin && !self.openmax {
            self.max
        } else {
            self.min
        }
    }

    fn checkempty(&self) -> bool {
        self.empty || self.min > self.max || (self.min == self.max && (self.openmin || self.openmax))
    }

    /// Linux's `snd_interval_refine`: narrows to `v`; `Ok(changed)` or `Err` when empty.
    fn refine(&mut self, v: &Iv) -> Result<bool, i64> {
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
    fn step(&mut self, step: u32) -> Result<bool, i64> {
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
    fn list(&mut self, list: &[u32]) -> Result<bool, i64> {
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
struct Params {
    raw: Vec<u8>,
    masks: [[u32; 8]; 3],
    ivs: [Iv; 12],
}

const HW_PARAMS_SIZE: usize = 608;
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
    fn parse(raw: Vec<u8>) -> Self {
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

    fn encode(&mut self) -> &[u8] {
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

    fn iv(&mut self, p: usize) -> &mut Iv {
        &mut self.ivs[p - P_SAMPLE_BITS]
    }

    fn get(&self, p: usize) -> Iv {
        self.ivs[p - P_SAMPLE_BITS]
    }

    /// Narrows interval `p` to `v`, recording a change.
    fn set(&mut self, p: usize, v: Iv, changed: &mut bool) -> Result<(), i64> {
        if self.iv(p).refine(&v)? {
            *changed = true;
        }
        Ok(())
    }

    /// Refines the parameter space by the device's limits and Linux's rules.
    fn refine(&mut self) -> Result<(), i64> {
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
    fn choose(&mut self) -> Result<(), i64> {
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
#[derive(Clone, Copy)]
struct HwSetup {
    access: u32,
    rate: u32,
    period_size: u64,
    periods: u64,
    buffer_size: u64,
    frame_bytes: u64,
}

impl HwSetup {
    /// The HDA stream format word.
    fn hda_format(&self) -> u64 {
        let base = if self.rate == 44100 { 1 << 14 } else { 0 };
        base | 1 << 4 | 1 // 16 bits, 2 channels
    }
}

// ------------------------------------------------------------------------------------
// Streams
// ------------------------------------------------------------------------------------

struct Stream {
    open: bool,
    state: u32,
    hw: Option<HwSetup>,
    avail_min: u64,
    start_threshold: u64,
    stop_threshold: u64,
    silence_threshold: u64,
    silence_size: u64,
    boundary: u64,
    tstamp_mode: u32,
    /// Clock of the timestamps (0 wall clock, 1 monotonic, 2 monotonic raw).
    tstamp_type: u32,
    hw_ptr: u64,
    appl_ptr: u64,
    /// Position in the ring (frames) at the last update.
    last_pos: u64,
    /// Frames the controller has fetched since the start (from its position).
    dma_frames: u64,
    /// Frames counted as played since the start (what `hw_ptr` advanced by).
    played: u64,
    /// `hw_ptr` at the start.
    start_hw: u64,
    avail_max: u64,
    trigger_ns: u64,
    tstamp_ns: u64,
    /// Slot of the stream in the position buffer.
    slot: usize,
    /// The ring was programmed for the current parameters.
    programmed: bool,
}

impl Stream {
    const fn new() -> Self {
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
            played: 0,
            start_hw: 0,
            avail_max: 0,
            trigger_ns: 0,
            tstamp_ns: 0,
            slot: 0,
            programmed: false,
        }
    }

    fn active(&self) -> bool {
        self.state == ST_RUNNING || self.state == ST_DRAINING
    }

    /// Frames the program may write (playback) or read (capture).
    fn avail(&self, dir: usize) -> u64 {
        let Some(hw) = self.hw else { return 0 };
        let b = self.boundary.max(1);
        if dir == 0 {
            (self.hw_ptr + hw.buffer_size + b - self.appl_ptr) % b
        } else {
            (self.hw_ptr + b - self.appl_ptr) % b
        }
    }

    /// Frames queued between the program and the hardware.
    fn delay(&self, dir: usize) -> i64 {
        let Some(hw) = self.hw else { return 0 };
        if dir == 0 {
            hw.buffer_size as i64 - self.avail(0) as i64
        } else {
            self.avail(1) as i64
        }
    }
}

static STREAMS: [Mutex<Stream>; 2] = [Mutex::new(Stream::new()), Mutex::new(Stream::new())];

/// What an update asks the caller to do with the hardware (outside the stream lock).
#[derive(PartialEq, Eq)]
enum Action {
    None,
    Stop,
}

fn ring(dir: usize) -> Option<&'static Arc<ContiguousFrames>> {
    BUFFERS[dir].get().and_then(|b| b.as_ref())
}

/// The stream's position in its ring (bytes), as the controller last wrote it.
fn hw_position(slot: usize) -> u64 {
    let Some(pb) = POSBUF.get() else { return 0 };
    let p = crate::memory::frame_allocator::phys_to_virt(pb.base) as *const u32;
    unsafe { p.add(slot * 2).read_volatile() as u64 }
}

fn reset_position(slot: usize) {
    if let Some(pb) = POSBUF.get() {
        let p = crate::memory::frame_allocator::phys_to_virt(pb.base) as *mut u32;
        unsafe { p.add(slot * 2).write_volatile(0) };
    }
}

/// Advances the hardware pointer of a running stream; silences played playback data;
/// detects underruns and the end of draining.
fn update(dir: usize, s: &mut Stream) -> Action {
    if !s.active() {
        // Timestamps say when the status was taken, running or not
        s.tstamp_ns = crate::arch::pit::now_ns();
        return Action::None;
    }
    let Some(hw) = s.hw else { return Action::None };
    let pos = (hw_position(s.slot) / hw.frame_bytes) % hw.buffer_size;
    let delta = (pos + hw.buffer_size - s.last_pos) % hw.buffer_size;
    if delta > 0 {
        if dir == 0 {
            if let Some(r) = ring(0) {
                // Silence what was played: an underrun then loops silence
                let bytes = unsafe { r.bytes() };
                let (a, b) = ((s.last_pos * hw.frame_bytes) as usize, (pos * hw.frame_bytes) as usize);
                if a < b {
                    bytes[a..b].fill(0);
                } else {
                    let end = (hw.buffer_size * hw.frame_bytes) as usize;
                    bytes[a..end].fill(0);
                    bytes[..b].fill(0);
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
    let now = crate::arch::pit::now_ns();
    if s.state == ST_RUNNING || s.state == ST_DRAINING {
        s.played = s.dma_frames;
        s.hw_ptr = (s.start_hw + s.played) % s.boundary.max(1);
    }
    s.tstamp_ns = now;
    let avail = s.avail(dir);
    s.avail_max = s.avail_max.max(avail);
    if s.state == ST_DRAINING && dir == 0 && avail >= hw.buffer_size {
        s.state = ST_SETUP;
        return Action::Stop;
    }
    if s.state == ST_RUNNING && s.stop_threshold < s.boundary && avail >= s.stop_threshold {
        s.state = ST_XRUN;
        return Action::Stop;
    }
    Action::None
}

/// Starts or stops direction `dir`'s DMA.
fn trigger(dir: usize, run: bool) -> Result<(), i64> {
    match service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_TRIGGER, [dir as u64, run as u64, 0, 0]), service::CALL_TIMEOUT_TICKS) {
        Ok(m) if m.label == MSG_SND_REPLY && m.args[0] == 0 => Ok(()),
        Ok(m) => Err(m.args[0] as i64),
        Err(e) => Err(e),
    }
}

/// Points direction `dir`'s stream at its ring with `hw`'s layout; the position slot.
fn program(dir: usize, hw: &HwSetup) -> Result<usize, i64> {
    let buf = ring(dir).ok_or(ENODEV)?;
    let pos = POSBUF.get().ok_or(ENODEV)?;
    let _w = service::hold_window(ENDPOINT_SOUND_DEV);
    let w = service::window(ENDPOINT_SOUND_DEV).ok_or(ENODEV)?;
    let words = [dir as u64, buf.base, hw.buffer_size * hw.frame_bytes, hw.period_size * hw.frame_bytes, hw.hda_format(), pos.base];
    for (i, v) in words.iter().enumerate() {
        w[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    match service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_SETUP, [0; 4]), service::CALL_TIMEOUT_TICKS) {
        Ok(m) if m.label == MSG_SND_REPLY && m.args[0] == 0 => Ok(m.args[1] as usize),
        Ok(m) => Err(m.args[0] as i64),
        Err(e) => Err(e),
    }
}

/// The position task: updates running streams every tick and wakes their waiters.
fn position_task() {
    loop {
        let mut any = false;
        for dir in 0..2 {
            let act = {
                let mut s = STREAMS[dir].lock();
                any |= s.active();
                update(dir, &mut s)
            };
            if act == Action::Stop {
                let _ = trigger(dir, false);
            }
        }
        SND_WQ.wake_all();
        if any {
            crate::task::wait::wait(Some(crate::arch::pit::ticks() + 1));
        } else {
            TASK_WQ.register();
            if STREAMS.iter().any(|s| s.lock().active()) {
                TASK_WQ.unregister();
                continue;
            }
            crate::task::wait::wait(Some(crate::arch::pit::ticks() + 100));
        }
    }
}

/// An open `pcmC0D0p` or `pcmC0D0c`.
pub struct PcmFile {
    dir: usize,
    nonblock: AtomicBool,
}

/// The ring mapped at offset 0.
struct RingPages(Arc<ContiguousFrames>);

impl MappedObject for RingPages {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        (pgoff < self.0.pages).then(|| PhysFrame::containing_address(PhysAddr::new(self.0.base + pgoff * 4096)))
    }
}

/// `(seconds, nanoseconds)` of a timestamp `ns` (monotonic) in the stream's clock.
fn timespec(s: &Stream, ns: u64) -> (u64, u64) {
    let t = if s.tstamp_type == 0 { (crate::arch::rtc::wall_base_ns() as i128 + ns as i128).max(0) as u64 } else { ns };
    (t / 1_000_000_000, t % 1_000_000_000)
}

impl PcmFile {
    fn stream(&self) -> spin::MutexGuard<'static, Stream> {
        STREAMS[self.dir].lock()
    }

    /// Updates the stream; stops the hardware if the update says so.
    fn sync(&self) {
        let act = {
            let mut s = self.stream();
            update(self.dir, &mut s)
        };
        if act == Action::Stop {
            let _ = trigger(self.dir, false);
        }
    }

    fn hw_refine(&self, arg: u64, set: bool) -> i64 {
        let raw = match copy_in(arg, HW_PARAMS_SIZE) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut p = Params::parse(raw);
        if set {
            {
                let s = self.stream();
                if !matches!(s.state, ST_OPEN | ST_SETUP | ST_PREPARED) {
                    return EBADFD;
                }
            }
            if let Err(e) = p.choose() {
                return e;
            }
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
                crate::kprintln!("[snd] HW_PARAMS chose an unusable setup: period {} x {}, buffer {}", hw.period_size, hw.periods, hw.buffer_size);
                return EINVAL;
            }
            let mut s = self.stream();
            s.hw = Some(hw);
            s.state = ST_SETUP;
            s.programmed = false;
            s.avail_min = hw.period_size;
            s.start_threshold = 1;
            s.stop_threshold = hw.buffer_size;
            s.silence_threshold = 0;
            s.silence_size = 0;
            let mut b = hw.buffer_size;
            while b * 2 <= (i64::MAX as u64) - hw.buffer_size {
                b *= 2;
            }
            s.boundary = b;
            s.hw_ptr = 0;
            s.appl_ptr = 0;
        } else if let Err(e) = p.refine() {
            return e;
        }
        match copy_out(arg, p.encode()) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn sw_params(&self, arg: u64) -> i64 {
        let mut b = match copy_in(arg, 136) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut s = self.stream();
        if s.hw.is_none() {
            return EBADFD;
        }
        let tstamp_mode = get_u32(&b, 0);
        let avail_min = get_u64(&b, 16);
        let start = get_u64(&b, 32);
        let stop = get_u64(&b, 40);
        let sil_thr = get_u64(&b, 48);
        let sil_size = get_u64(&b, 56);
        if tstamp_mode > 1 {
            return EINVAL;
        }
        s.tstamp_mode = tstamp_mode;
        s.avail_min = avail_min.max(1);
        s.start_threshold = start;
        s.stop_threshold = stop;
        s.silence_threshold = sil_thr;
        s.silence_size = sil_size;
        if get_u32(&b, 72) >= 0x0002_000C {
            s.tstamp_type = get_u32(&b, 76).min(2);
        }
        put_u64(&mut b, 64, s.boundary);
        drop(s);
        match copy_out(arg, &b) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    /// `snd_pcm_status` (152 bytes).
    fn status(&self, arg: u64) -> i64 {
        self.sync();
        let mut b = [0u8; 152];
        {
            let mut s = self.stream();
            let now = crate::arch::pit::now_ns();
            put_u32(&mut b, 0, s.state);
            let (sec, nsec) = timespec(&s, s.trigger_ns);
            put_u64(&mut b, 8, sec);
            put_u64(&mut b, 16, nsec);
            let (sec, nsec) = timespec(&s, now);
            put_u64(&mut b, 24, sec);
            put_u64(&mut b, 32, nsec);
            put_u64(&mut b, 40, s.appl_ptr);
            put_u64(&mut b, 48, s.hw_ptr);
            put_u64(&mut b, 56, s.delay(self.dir) as u64);
            put_u64(&mut b, 64, s.avail(self.dir));
            put_u64(&mut b, 72, s.avail_max);
            s.avail_max = 0;
            if let Some(hw) = s.hw {
                let at = s.hw_ptr as u128 * 1_000_000_000 / hw.rate as u128;
                put_u64(&mut b, 96, (at / 1_000_000_000) as u64);
                put_u64(&mut b, 104, (at % 1_000_000_000) as u64);
            }
            let (sec, nsec) = timespec(&s, s.tstamp_ns);
            put_u64(&mut b, 112, sec);
            put_u64(&mut b, 120, nsec);
        }
        match copy_out(arg, &b) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    /// `SNDRV_PCM_IOCTL_SYNC_PTR`: takes the program's pointer and minimum, returns the
    /// status.
    fn sync_ptr(&self, arg: u64) -> i64 {
        let mut b = match copy_in(arg, 136) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let flags = get_u32(&b, 0);
        if flags & 1 != 0 {
            self.sync();
        }
        boost_caller(self.dir);
        {
            let mut s = self.stream();
            if flags & 2 == 0 {
                let appl = get_u64(&b, 72);
                if s.boundary > 0 {
                    s.appl_ptr = appl % s.boundary;
                }
            }
            if flags & 4 == 0 {
                s.avail_min = get_u64(&b, 80).max(1);
            }
            put_u32(&mut b, 8, s.state);
            put_u64(&mut b, 16, s.hw_ptr);
            let (sec, nsec) = timespec(&s, s.tstamp_ns);
            put_u64(&mut b, 24, sec);
            put_u64(&mut b, 32, nsec);
            put_u32(&mut b, 40, 0);
            if let Some(hw) = s.hw {
                let at = s.hw_ptr as u128 * 1_000_000_000 / hw.rate as u128;
                put_u64(&mut b, 48, (at / 1_000_000_000) as u64);
                put_u64(&mut b, 56, (at % 1_000_000_000) as u64);
            }
            put_u64(&mut b, 72, s.appl_ptr);
            put_u64(&mut b, 80, s.avail_min);
        }
        if TRACE.load(Ordering::Relaxed) && SYNC_TRACED.fetch_add(1, Ordering::Relaxed) < 40 {
            let (dma, t) = {
                let st = self.stream();
                (st.dma_frames, (crate::arch::pit::now_ns().saturating_sub(st.trigger_ns)) / 1000)
            };
            crate::kprintln!("[snd] pcm{} sync_ptr flags {} -> state {} hw {} appl {} dma {} t {} us", self.dir, flags, get_u32(&b, 8), get_u64(&b, 16), get_u64(&b, 72), dma, t);
        }
        // An underrun found by this update is reported by the state
        SND_WQ.wake_all();
        match copy_out(arg, &b) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn prepare(&self) -> i64 {
        let (hw, running) = {
            let s = self.stream();
            let Some(hw) = s.hw else { return EBADFD };
            (hw, matches!(s.state, ST_RUNNING | ST_DRAINING | ST_PAUSED))
        };
        if running {
            let _ = trigger(self.dir, false);
        }
        let slot = match program(self.dir, &hw) {
            Ok(slot) => slot,
            Err(e) => {
                crate::kprintln!("[snd] the driver could not set up the stream: {}", e);
                return EIO;
            }
        };
        if let Some(r) = ring(self.dir) {
            unsafe { r.bytes()[..(hw.buffer_size * hw.frame_bytes) as usize].fill(0) };
        }
        reset_position(slot);
        SYNC_TRACED.store(0, Ordering::Relaxed);
        let mut s = self.stream();
        s.slot = slot;
        s.programmed = true;
        s.hw_ptr = 0;
        s.appl_ptr = 0;
        s.last_pos = 0;
        s.avail_max = 0;
        s.state = ST_PREPARED;
        0
    }

    /// Starts the stream (state must be PREPARED).
    fn start(&self) -> i64 {
        {
            let s = self.stream();
            if s.state != ST_PREPARED {
                return EBADFD;
            }
            if self.dir == 0 && s.stop_threshold < s.boundary && s.avail(0) >= s.hw.map_or(0, |h| h.buffer_size) {
                return EPIPE;
            }
            reset_position(s.slot);
        }
        if let Err(e) = trigger(self.dir, true) {
            crate::kprintln!("[snd] the driver could not start the stream: {}", e);
            return EIO;
        }
        boost_caller(self.dir);
        let mut s = self.stream();
        s.state = ST_RUNNING;
        s.last_pos = 0;
        s.dma_frames = 0;
        s.played = 0;
        s.start_hw = s.hw_ptr;
        s.trigger_ns = crate::arch::pit::now_ns();
        s.tstamp_ns = s.trigger_ns;
        drop(s);
        TASK_WQ.wake_all();
        0
    }

    fn drop_stream(&self) -> i64 {
        let was = {
            let mut s = self.stream();
            if s.state == ST_OPEN {
                return EBADFD;
            }
            let was = matches!(s.state, ST_RUNNING | ST_DRAINING | ST_PAUSED);
            if s.state != ST_SETUP {
                s.state = ST_SETUP;
            }
            was
        };
        if was {
            let _ = trigger(self.dir, false);
        }
        SND_WQ.wake_all();
        0
    }

    fn drain(&self) -> i64 {
        let state = self.stream().state;
        match state {
            ST_OPEN => return EBADFD,
            ST_SETUP | ST_XRUN => {
                self.stream().state = ST_SETUP;
                return 0;
            }
            _ => {}
        }
        if self.dir == 1 {
            return self.drop_stream();
        }
        if state == ST_PREPARED {
            let empty = { self.stream().avail(0) >= self.stream().hw.map_or(0, |h| h.buffer_size) };
            if empty {
                self.stream().state = ST_SETUP;
                return 0;
            }
            let r = self.start();
            if r < 0 {
                return r;
            }
        }
        if state == ST_PAUSED {
            let _ = trigger(self.dir, true);
        }
        {
            let mut s = self.stream();
            if s.state == ST_RUNNING || s.state == ST_PAUSED {
                s.state = ST_DRAINING;
            }
        }
        if self.nonblock() {
            return EAGAIN;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&SND_WQ));
        let deadline = crate::arch::pit::ticks() + 1000;
        loop {
            waits.register();
            self.sync();
            if self.stream().state != ST_DRAINING {
                return 0;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            if crate::arch::pit::ticks() >= deadline {
                self.drop_stream();
                return EIO;
            }
            waits.wait(Some(crate::arch::pit::ticks() + 2));
        }
    }

    /// `REWIND` (`back`) or `FORWARD` the application pointer by up to `*arg` frames.
    fn move_appl(&self, arg: u64, back: bool) -> i64 {
        let frames = match copy_in(arg, 8) {
            Ok(b) => get_u64(&b, 0),
            Err(e) => return e,
        };
        self.sync();
        let moved = {
            let mut s = self.stream();
            let Some(hw) = s.hw else { return EBADFD };
            let b = s.boundary.max(1);
            let room = if back { hw.buffer_size - s.avail(self.dir).min(hw.buffer_size) } else { s.avail(self.dir) };
            let n = frames.min(room);
            s.appl_ptr = if back { (s.appl_ptr + b - n) % b } else { (s.appl_ptr + n) % b };
            n
        };
        match copy_out(arg, &moved.to_le_bytes()) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    /// `WRITEI_FRAMES` / `READI_FRAMES`: copies frames between the program and the ring.
    fn transfer(&self, arg: u64) -> i64 {
        let x = match copy_in(arg, 24) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let (buf, frames) = (get_u64(&x, 8), get_u64(&x, 16));
        let result = self.transfer_frames(buf, frames);
        if copy_out(arg, &result.to_le_bytes()).is_err() {
            return EFAULT;
        }
        result.min(0)
    }

    fn transfer_frames(&self, buf: u64, frames: u64) -> i64 {
        let Some(r) = ring(self.dir) else { return ENODEV };
        let ringbytes = unsafe { r.bytes() };
        let mut done = 0u64;
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&SND_WQ));
        // A stream that stops moving (no input reaching the controller) ends a blocking
        // transfer after 10 s, as on Linux
        let mut stalled_since = crate::arch::pit::ticks();
        let mut last_hw = u64::MAX;
        while done < frames {
            waits.register();
            self.sync();
            let mut s = self.stream();
            let Some(hw) = s.hw else { return EBADFD };
            match s.state {
                ST_OPEN | ST_SETUP => return EBADFD,
                ST_XRUN => return if done > 0 { done as i64 } else { EPIPE },
                ST_DRAINING if self.dir == 0 => return EBADFD,
                _ => {}
            }
            if self.dir == 1 && s.state == ST_PREPARED {
                // Capture starts on the first read
                drop(s);
                let r = self.start();
                if r < 0 {
                    return r;
                }
                continue;
            }
            let avail = s.avail(self.dir).min(hw.buffer_size);
            if avail == 0 {
                if s.state == ST_PREPARED || s.state == ST_PAUSED {
                    return if done > 0 { done as i64 } else { EAGAIN };
                }
                drop(s);
                if self.nonblock() {
                    return if done > 0 { done as i64 } else { EAGAIN };
                }
                if super::proc::signal_pending() {
                    return if done > 0 { done as i64 } else { super::proc::ERESTARTSYS };
                }
                let hw_now = self.stream().hw_ptr;
                if hw_now != last_hw {
                    last_hw = hw_now;
                    stalled_since = crate::arch::pit::ticks();
                } else if crate::arch::pit::ticks() > stalled_since + 1000 {
                    return if done > 0 { done as i64 } else { EIO };
                }
                waits.wait(Some(crate::arch::pit::ticks() + 2));
                continue;
            }
            let fb = hw.frame_bytes;
            let ofs = s.appl_ptr % hw.buffer_size;
            let n = (frames - done).min(avail).min(hw.buffer_size - ofs);
            let (lo, len) = ((ofs * fb) as usize, (n * fb) as usize);
            let user = buf + done * fb;
            if self.dir == 0 {
                match copy_in(user, len) {
                    Ok(data) => ringbytes[lo..lo + len].copy_from_slice(&data),
                    Err(e) => return if done > 0 { done as i64 } else { e },
                }
            } else if let Err(e) = copy_out(user, &ringbytes[lo..lo + len]) {
                return if done > 0 { done as i64 } else { e };
            }
            s.appl_ptr = (s.appl_ptr + n) % s.boundary.max(1);
            done += n;
            let start = self.dir == 0 && s.state == ST_PREPARED && (hw.buffer_size - s.avail(0).min(hw.buffer_size)) >= s.start_threshold;
            drop(s);
            if start {
                let r = self.start();
                if r < 0 {
                    return if done > 0 { done as i64 } else { r };
                }
            }
        }
        done as i64
    }
}

impl Drop for PcmFile {
    fn drop(&mut self) {
        let was = {
            let mut s = STREAMS[self.dir].lock();
            let was = matches!(s.state, ST_RUNNING | ST_DRAINING | ST_PAUSED);
            *s = Stream::new();
            was
        };
        if was {
            let _ = trigger(self.dir, false);
        }
        unboost(self.dir);
        SND_WQ.wake_all();
    }
}

impl CharDevice for PcmFile {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        let r = (|| -> i64 {
        let Some(card) = CARD.lock().clone() else { return ENODEV };
        match cmd as u32 {
            0x8004_4100 => write_int(arg, 0x0002_000F), // PVERSION 2.0.15
            0x8120_4101 => match copy_out(arg, &pcm_info(self.dir, &card)) {
                Ok(()) => 0,
                Err(e) => e,
            },
            0x4004_4102 => match read_int(arg) {
                // TSTAMP (old): 0 none, 1 enabled
                Ok(v) => {
                    self.stream().tstamp_mode = (v != 0) as u32;
                    0
                }
                Err(e) => e,
            },
            0x4004_4103 => match read_int(arg) {
                // TTSTAMP: the timestamp clock
                Ok(v) if (0..=2).contains(&v) => {
                    self.stream().tstamp_type = v as u32;
                    0
                }
                Ok(_) => EINVAL,
                Err(e) => e,
            },
            0x4004_4104 => 0, // USER_PVERSION
            0xC260_4110 => self.hw_refine(arg, false),
            0xC260_4111 => self.hw_refine(arg, true),
            0x0000_4112 => {
                // HW_FREE
                let mut s = self.stream();
                if matches!(s.state, ST_RUNNING | ST_DRAINING | ST_PAUSED) {
                    return EBADFD;
                }
                s.hw = None;
                s.programmed = false;
                s.state = ST_OPEN;
                0
            }
            0xC088_4113 => self.sw_params(arg),
            0x8098_4120 | 0xC098_4124 => self.status(arg),
            0x8008_4121 => {
                // DELAY
                self.sync();
                let (state, delay) = {
                    let s = self.stream();
                    (s.state, s.delay(self.dir))
                };
                if state == ST_XRUN {
                    return EPIPE;
                }
                match copy_out(arg, &delay.to_le_bytes()) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            0x0000_4122 => {
                // HWSYNC
                self.sync();
                if self.stream().state == ST_XRUN {
                    EPIPE
                } else {
                    0
                }
            }
            0xC088_4123 => self.sync_ptr(arg),
            0x8018_4132 | 0xC018_4132 => {
                // CHANNEL_INFO
                let mut b = match copy_in(arg, 24) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                let ch = get_u32(&b, 0);
                if ch >= 2 || self.stream().hw.is_none() {
                    return EINVAL;
                }
                put_u64(&mut b, 8, 0);
                put_u32(&mut b, 16, ch * 16);
                put_u32(&mut b, 20, 32);
                match copy_out(arg, &b) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            0x0000_4140 => self.prepare(),
            0x0000_4141 => {
                // RESET
                self.sync();
                let mut s = self.stream();
                if s.hw.is_none() {
                    return EBADFD;
                }
                s.appl_ptr = s.hw_ptr;
                0
            }
            0x0000_4142 => self.start(),
            0x0000_4143 => self.drop_stream(),
            0x0000_4144 => self.drain(),
            // PAUSE (the flag is the argument itself): not offered (see HW_INFO), as Linux
            // answers for a device without pause
            0x4004_4145 => -38,
            0x4008_4146 => self.move_appl(arg, true),
            0x4008_4149 => self.move_appl(arg, false),
            0x0000_4147 => EINVAL, // RESUME: never suspended
            0x0000_4148 => {
                // XRUN
                let was = {
                    let mut s = self.stream();
                    let was = s.active();
                    if s.state != ST_OPEN {
                        s.state = ST_XRUN;
                    }
                    was
                };
                if was {
                    let _ = trigger(self.dir, false);
                }
                0
            }
            0x4018_4150 if self.dir == 0 => self.transfer(arg),
            0x8018_4151 if self.dir == 1 => self.transfer(arg),
            0x4018_4150 | 0x8018_4151 => EINVAL,
            0x4018_4152 | 0x8018_4153 => EINVAL, // non-interleaved: not offered
            0x4004_4160 | 0x0000_4161 => ENOTTY,  // LINK / UNLINK
            _ => ENOTTY,
        }
        })();
        if TRACE.load(Ordering::Relaxed) && (r < 0 && r != EAGAIN || !matches!(cmd as u32, 0xC088_4123 | 0x0000_4122 | 0x8008_4121 | 0x4018_4150 | 0x8018_4151 | 0x8098_4120 | 0xC098_4124)) {
            let st = self.stream().state;
            crate::kprintln!("[snd] pcm{} ioctl {:#x} -> {} (state {})", self.dir, cmd, r, st);
        }
        r
    }

    fn poll_events(&self) -> u32 {
        self.sync();
        let s = self.stream();
        let ok = if self.dir == 0 { POLLOUT | POLLWRNORM } else { POLLIN | POLLRDNORM };
        match s.state {
            ST_RUNNING | ST_PREPARED | ST_PAUSED => {
                if s.avail(self.dir) >= s.avail_min {
                    ok
                } else {
                    0
                }
            }
            ST_DRAINING if self.dir == 0 => 0,
            _ => ok | POLLERR,
        }
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Static(&SND_WQ));
    }

    fn rdev(&self) -> u64 {
        makedev(MAJOR, MINOR_PLAYBACK + 8 * self.dir as u64)
    }

    fn path(&self) -> String {
        String::from(if self.dir == 0 { "/dev/snd/pcmC0D0p" } else { "/dev/snd/pcmC0D0c" })
    }

    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        self.mmap_object_at(0)
    }

    fn mmap_object_at(&self, pgoff: u64) -> Result<Arc<dyn MappedObject>, i64> {
        // The status and control records (offsets 0x80000000, 0x81000000) are not
        // mappable: libasound then uses SYNC_PTR
        if pgoff != 0 {
            return Err(ENXIO);
        }
        let r = ring(self.dir).ok_or(ENODEV)?;
        if self.stream().hw.is_none() {
            return Err(EBADFD);
        }
        Ok(Arc::new(RingPages(r.clone())))
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}

/// Opens minor `minor` of the ALSA major.
pub fn open(minor: u64, nonblock: bool) -> Result<Arc<dyn CharDevice>, i64> {
    if !present() {
        return Err(ENODEV);
    }
    match minor {
        MINOR_CONTROL => {
            let f = Arc::new(CtlFile { events: Mutex::new(VecDeque::new()), subscribed: AtomicBool::new(false), nonblock: AtomicBool::new(nonblock) });
            SUBSCRIBERS.lock().push(Arc::downgrade(&f));
            Ok(f)
        }
        16 | 24 => {
            let dir = ((minor - 16) / 8) as usize;
            if !has_dir(dir) {
                return Err(ENODEV);
            }
            let mut s = STREAMS[dir].lock();
            if s.open {
                return Err(EBUSY);
            }
            *s = Stream::new();
            s.open = true;
            drop(s);
            Ok(Arc::new(PcmFile { dir, nonblock: AtomicBool::new(nonblock) }))
        }
        _ => Err(ENXIO),
    }
}

// ------------------------------------------------------------------------------------
// /proc/asound
// ------------------------------------------------------------------------------------

/// The text of a dynamic `/proc/asound` file (`path` after `/proc/asound/`), or `None`.
pub fn proc_text(path: &str) -> Option<String> {
    let card = CARD.lock().clone()?;
    let chip = chip_name(card.vendor);
    match path {
        "cards" => Some(alloc::format!(
            " 0 [Intel          ]: HDA-Intel - HDA Intel\n                      HDA Intel at {:#x} irq 0\n",
            card.mmio
        )),
        "version" => Some(String::from("Advanced Linux Sound Architecture Driver Version k6.8.0-hydra.\n")),
        "devices" => {
            let mut t = String::from("  0: [ 0]   : control\n 16: [ 0- 0]: digital audio playback\n");
            if card.dirs & 2 != 0 {
                t.push_str(" 24: [ 0- 0]: digital audio capture\n");
            }
            Some(t)
        }
        "pcm" => Some(alloc::format!(
            "00-00: {} Analog : {} Analog : playback 1{}\n",
            chip,
            chip,
            if card.dirs & 2 != 0 { " : capture 1" } else { "" }
        )),
        "card0/id" => Some(String::from("Intel\n")),
        "card0/codec#0" => Some(alloc::format!("Codec: {}\nAddress: 0\nVendor Id: {:#010x}\n{}\n", chip, card.vendor, card.desc)),
        _ => {
            let rest = path.strip_prefix("card0/pcm0")?;
            let dir = match rest.as_bytes().first()? {
                b'p' => 0,
                b'c' => 1,
                _ => return None,
            };
            let file = &rest[1..];
            let s = STREAMS[dir].lock();
            match file {
                "/info" | "/sub0/info" => Some(alloc::format!(
                    "card: 0\ndevice: 0\nsubdevice: 0\nstream: {}\nid: {} Analog\nname: {} Analog\nsubname: subdevice #0\nclass: 0\nsubclass: 0\nsubdevices_count: 1\nsubdevices_avail: {}\n",
                    if dir == 0 { "PLAYBACK" } else { "CAPTURE" },
                    chip,
                    chip,
                    !s.open as u32
                )),
                "/sub0/status" => Some(if !s.open {
                    String::from("closed\n")
                } else {
                    let name = ["OPEN", "SETUP", "PREPARED", "RUNNING", "XRUN", "DRAINING", "PAUSED"].get(s.state as usize).copied().unwrap_or("?");
                    alloc::format!("state: {}\nowner_pid   : 0\nhw_ptr      : {}\nappl_ptr    : {}\n", name, s.hw_ptr, s.appl_ptr)
                }),
                "/sub0/hw_params" => Some(match (s.open, s.hw) {
                    (true, Some(hw)) => alloc::format!(
                        "access: {}\nformat: S16_LE\nsubformat: STD\nchannels: 2\nrate: {} ({}/1)\nperiod_size: {}\nbuffer_size: {}\n",
                        if hw.access == ACCESS_MMAP_INTERLEAVED { "MMAP_INTERLEAVED" } else { "RW_INTERLEAVED" },
                        hw.rate,
                        hw.rate,
                        hw.period_size,
                        hw.buffer_size
                    ),
                    _ => String::from("closed\n"),
                }),
                "/sub0/sw_params" => Some(match (s.open, s.hw) {
                    (true, Some(_)) => alloc::format!(
                        "tstamp_mode: {}\nperiod_step: 1\navail_min: {}\nstart_threshold: {}\nstop_threshold: {}\nsilence_threshold: {}\nsilence_size: {}\nboundary: {}\n",
                        if s.tstamp_mode == 1 { "ENABLE" } else { "NONE" },
                        s.avail_min,
                        s.start_threshold,
                        s.stop_threshold,
                        s.silence_threshold,
                        s.silence_size,
                        s.boundary
                    ),
                    _ => String::from("closed\n"),
                }),
                _ => None,
            }
        }
    }
}

/// Whether `path` (absolute) is a `/proc/asound` file served by [`proc_text`].
pub fn is_proc_file(path: &str) -> bool {
    path.strip_prefix("/proc/asound/").map_or(false, |p| proc_text(p).is_some())
}
