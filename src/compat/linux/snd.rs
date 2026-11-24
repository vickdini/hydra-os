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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::ipc::protocol::{ENDPOINT_SOUND_DEV, MSG_SND_INFO, MSG_SND_REPLY, MSG_SND_SETUP, MSG_SND_TRIGGER};
use crate::ipc::service::{self, ContiguousFrames};
use crate::ipc::Message;


const EIO: i64 = -5;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;

// PCM states

// Hardware parameter indexes

// snd_pcm_info flags reported in hw_params.info

/// The thread that drives each direction's stream (`SYNC_PTR`, `START`), raised to the
/// scheduler's high priority while it holds the device open (0: none). PipeWire runs the
/// card from a timer in its data thread, which must run within a few milliseconds of it:
/// at normal priority, behind Firefox's threads, it ran 50-250 ms late and the card ran
/// dry 1-3 times a second (wave 6, G25). On Ubuntu RTKit makes that thread real-time;
/// PipeWire asks RTKit through the desktop portal, which Hydra does not serve, so the
/// device does it for the thread that drives it.
static DRIVER: [core::sync::atomic::AtomicU64; 2] = [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)];

/// wave8 GS: thread `me` becomes direction `dir`'s driver (the calling thread here, the
/// thread a forwarded call names for the sound service, `ipc::sound`).
pub fn boost_thread(dir: usize, me: u64) {
    let _g = BOOSTING.lock();
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

/// Serializes changes of [`DRIVER`] with the priority changes they make (wave8 GS).
static BOOSTING: Mutex<()> = Mutex::new(());

/// wave8 GS: the wall clock's offset from the monotonic clock (the sound service's
/// timestamps).
pub fn wall_base_ns() -> i64 {
    crate::arch::rtc::wall_base_ns()
}

/// The device of direction `dir` was closed: its driver thread gets its own priority back.
pub fn unboost(dir: usize) {
    let _g = BOOSTING.lock();
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
// (wave8 GS: the DMA position page and the rings are `ipc::sound`'s, shared with the sound
// service: allocated once, in the sound driver's IOMMU domain, alive as long as the kernel)

/// The DMA position buffer (one page, the controller writes positions into it).
fn posbuf() -> Option<&'static Arc<ContiguousFrames>> {
    crate::ipc::sound::buffers().map(|b| &b.pos)
}

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

/// wave8 GS: the card the driver described, for the sound service: `(codec vendor and
/// device, directions, amplifiers, description, register address)`.
pub fn card() -> Option<(u32, u32, [u32; 2], String, u64)> {
    CARD.lock().as_ref().map(|c| (c.vendor, c.dirs, c.amps, c.desc.clone(), c.mmio))
}

/// Whether a card is present.
pub fn present() -> bool {
    CARD.lock().is_some()
}

/// Whether direction `dir` exists.
pub fn has_dir(dir: usize) -> bool {
    CARD.lock().as_ref().map_or(false, |c| c.dirs & (1 << dir) != 0)
}

/// Called after the supervisor started the drivers: asks the sound driver about the card
/// ([`probe`]); the sound service drives it from there.
pub fn start() {
    probe();
}

/// Asks the sound driver about the card once and allocates the buffers (wave8 GS: also
/// called by the supervisor before it starts the sound service, which takes the card from
/// here).
pub fn probe() {
    if CARD.lock().is_some() || !service::is_online(ENDPOINT_SOUND_DEV) {
        return;
    }
    // (one prober: the supervisor's and `start`'s calls must not both ask the driver)
    if PROBING.swap(true, Ordering::AcqRel) {
        return;
    }
    probe_once();
    PROBING.store(false, Ordering::Release);
}

/// A probe is in progress.
static PROBING: AtomicBool = AtomicBool::new(false);

fn probe_once() {
    if CARD.lock().is_some() {
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
    // (wave8 GS: `ipc::sound` allocates the buffers and maps them into the controller's
    // IOMMU domain, once; they live as long as the kernel, across driver restarts)
    if crate::ipc::sound::buffers().is_none() {
        crate::kprintln!("[snd] no memory for the sound buffers");
        return;
    }
    let mut dirs = m.args[2] as u32;
    for dir in 0..2 {
        if ring(dir).is_none() {
            dirs &= !(1 << dir);
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
#[allow(dead_code)] // (wave10 G10-C: fields the deleted bpf()/ALSA copy read; kept as the records' shape)
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


// ------------------------------------------------------------------------------------
// Control device
// ------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------
// Hardware parameters
// ------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------
// Streams
// ------------------------------------------------------------------------------------


fn ring(dir: usize) -> Option<&'static Arc<ContiguousFrames>> {
    crate::ipc::sound::ring(dir)
}

/// Starts or stops direction `dir`'s DMA.
/// wave8 GS: stops both directions' DMA (the sound service died and is not back: its stream
/// must not run on for ever).
pub fn stop_streams() {
    for dir in 0..2 {
        let _ = trigger(dir, false);
    }
}

fn trigger(dir: usize, run: bool) -> Result<(), i64> {
    match service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_TRIGGER, [dir as u64, run as u64, 0, 0]), service::CALL_TIMEOUT_TICKS) {
        Ok(m) if m.label == MSG_SND_REPLY && m.args[0] == 0 => Ok(()),
        Ok(m) => Err(m.args[0] as i64),
        Err(e) => Err(e),
    }
}

/// wave8 GS: `MSG_SND_SETUP` for direction `dir` with `bytes` of its ring, periods of
/// `period` bytes and format word `fmt`, always on the kernel's own ring and position page
/// (the sound service asks for it through `LX_SND_SETUP`: it never names a physical
/// address, so the controller's DMA stays on the kernel's buffers with or without an IOMMU).
pub fn program_stream(dir: usize, bytes: u64, period: u64, fmt: u64) -> Result<usize, i64> {
    let buf = ring(dir).ok_or(ENODEV)?;
    let pos = posbuf().ok_or(ENODEV)?;
    if !crate::ipc::sound_page::setup_ok(dir as u64, bytes, period, fmt, buf.pages * 4096) {
        return Err(EINVAL);
    }
    let _w = service::hold_window(ENDPOINT_SOUND_DEV);
    let w = service::window(ENDPOINT_SOUND_DEV).ok_or(ENODEV)?;
    let words = [dir as u64, buf.base, bytes, period, fmt, pos.base];
    for (i, v) in words.iter().enumerate() {
        w[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    match service::call(ENDPOINT_SOUND_DEV, Message::with_args(MSG_SND_SETUP, [0; 4]), service::CALL_TIMEOUT_TICKS) {
        // (wave8 GS: the slot indexes the one-page position buffer: never trust a larger one)
        Ok(m) if m.label == MSG_SND_REPLY && m.args[0] == 0 && m.args[1] < 512 => Ok(m.args[1] as usize),
        Ok(m) if m.label == MSG_SND_REPLY && m.args[0] == 0 => Err(EIO),
        Ok(m) => Err(m.args[0] as i64),
        Err(e) => Err(e),
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
            // wave8 GS: the sound service's streams, from the status page it writes
            let st = crate::ipc::sound::status(dir).unwrap_or_default();
            crate::ipc::sound_page::proc_stream_text(file, dir, &chip, &st)
        }
    }
}


/// Whether `path` (absolute) is a `/proc/asound` file served by [`proc_text`].
pub fn is_proc_file(path: &str) -> bool {
    path.strip_prefix("/proc/asound/").map_or(false, |p| proc_text(p).is_some())
}
