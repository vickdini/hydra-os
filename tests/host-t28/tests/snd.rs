//! `snd.rs` with a (fake) HDA card: the card description, mixer controls and their
//! events, `/proc/asound`, hardware parameter refinement and choice, the PCM state
//! machine (prepare, start, write/read, xrun, drain, drop, rewind/forward), SYNC_PTR,
//! status, the position updates and the driver-thread priority boost.
//!
//! The card, its buffers and the two streams are globals: every test holds
//! `common::serial()`, finds the card set up once (`setup`) and closes its streams.

mod common;

use std::sync::{Arc, Mutex, Once};

use hydra_hosttests_t28::compat::linux::chardev::{makedev, CharDevice};
use hydra_hosttests_t28::compat::linux::snd;
use hydra_hosttests_t28::fake;
use hydra_hosttests_t28::ipc::protocol::{MSG_SND_INFO, MSG_SND_REPLY, MSG_SND_SETUP, MSG_SND_TRIGGER, MSG_SND_VOLUME};
use hydra_hosttests_t28::ipc::Message;
use hydra_hosttests_t28::task::{TaskPersonality, TaskPriority};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EIO: i64 = -5;
const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const EBADFD: i64 = -77;
const ERESTARTSYS: i64 = -512;

const VENDOR: u32 = 0x10ec_0269; // ALC269
/// Playback amplifier: 64 steps of 1.5 dB, 0 dB at step 48; capture: 32 steps.
const AMP_PLAY: u64 = (1 << 24) | (5 << 16) | (48 << 8) | 64;
const AMP_CAP: u64 = (1 << 24) | (3 << 16) | (10 << 8) | 32;

// ioctls
const HW_REFINE: u64 = 0xC260_4110;
const HW_PARAMS: u64 = 0xC260_4111;
const HW_FREE: u64 = 0x4112;
const SW_PARAMS: u64 = 0xC088_4113;
const STATUS: u64 = 0x8098_4120;
const DELAY: u64 = 0x8008_4121;
const HWSYNC: u64 = 0x4122;
const SYNC_PTR: u64 = 0xC088_4123;
const PREPARE: u64 = 0x4140;
const RESET: u64 = 0x4141;
const START: u64 = 0x4142;
const DROP: u64 = 0x4143;
const DRAIN: u64 = 0x4144;
const REWIND: u64 = 0x4008_4146;
const FORWARD: u64 = 0x4008_4149;
const XRUN: u64 = 0x4148;
const WRITEI: u64 = 0x4018_4150;
const READI: u64 = 0x8018_4151;

// states
const OPEN: u32 = 0;
const SETUP: u32 = 1;
const PREPARED: u32 = 2;
const RUNNING: u32 = 3;
const XRUN_ST: u32 = 4;
const DRAINING: u32 = 5;

type Dev = Arc<dyn CharDevice>;

/// The driver's last MSG_SND_SETUP and triggers, as the responder saw them.
static TRIGGERS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
static VOLUMES: Mutex<Vec<[u64; 4]>> = Mutex::new(Vec::new());
/// Make the next SETUP / TRIGGER fail with this status.
static FAIL_SETUP: Mutex<Option<u64>> = Mutex::new(None);
static FAIL_TRIGGER: Mutex<Option<u64>> = Mutex::new(None);

fn responder(_ep: u32, m: &Message) -> Result<Message, i64> {
    let ok = |a1: u64| Ok(Message::with_args(MSG_SND_REPLY, [0, a1, 0, 0]));
    match m.label {
        MSG_SND_INFO => Ok(Message::with_args(MSG_SND_REPLY, [0, VENDOR as u64, 0b11, AMP_PLAY | AMP_CAP << 32])),
        MSG_SND_SETUP => match FAIL_SETUP.lock().unwrap().take() {
            Some(e) => Ok(Message::with_args(MSG_SND_REPLY, [e, 0, 0, 0])),
            None => ok(3),
        },
        MSG_SND_TRIGGER => {
            TRIGGERS.lock().unwrap().push((m.args[0], m.args[1]));
            match FAIL_TRIGGER.lock().unwrap().take() {
                Some(e) => Ok(Message::with_args(MSG_SND_REPLY, [e, 0, 0, 0])),
                None => ok(0),
            }
        }
        MSG_SND_VOLUME => {
            VOLUMES.lock().unwrap().push(m.args);
            ok(0)
        }
        _ => Err(-38),
    }
}

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = common::serial();
    static START: Once = Once::new();
    START.call_once(|| {
        let window: &'static mut [u8] = Box::leak(vec![0u8; 4096].into_boxed_slice());
        window[..11].copy_from_slice(b"Realtek ALC");
        fake::sound(|s| {
            s.online = true;
            s.window = Some(window);
            s.responder = Some(Box::new(responder));
        });
        snd::set_controller(0xfebf_0000, "0000:00:1b.0".into(), 0x8086, 0x293e, 0x1af4_1100);
        snd::start();
    });
    TRIGGERS.lock().unwrap().clear();
    VOLUMES.lock().unwrap().clear();
    fake::SIGNAL_PENDING.set(false);
    fake::clear_on_wait();
    g
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn p(b: &mut [u8]) -> u64 {
    b.as_mut_ptr() as u64
}

// ------------------------------------------------------- hw_params encoding

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

/// A `snd_pcm_hw_params` allowing everything.
fn any_params() -> Vec<u8> {
    let mut b = vec![0u8; 608];
    for i in 4..100 {
        b[i] = 0xFF;
    }
    for i in 0..12 {
        let o = 260 + i * 12;
        put32(&mut b, o, 0);
        put32(&mut b, o + 4, u32::MAX);
    }
    b
}
/// Interval `p` of `b`: (min, max, flags: openmin 1, openmax 2, integer 4, empty 8).
fn iv(b: &[u8], p: usize) -> (u32, u32, u32) {
    let o = 260 + (p - P_SAMPLE_BITS) * 12;
    (get32(b, o), get32(b, o + 4), get32(b, o + 8))
}
fn set_iv(b: &mut [u8], p: usize, min: u32, max: u32, flags: u32) {
    let o = 260 + (p - P_SAMPLE_BITS) * 12;
    put32(b, o, min);
    put32(b, o + 4, max);
    put32(b, o + 8, flags);
}
fn mask(b: &[u8], m: usize) -> u32 {
    get32(b, 4 + m * 32)
}
fn set_mask(b: &mut [u8], m: usize, v: u32) {
    for w in 0..8 {
        put32(b, 4 + m * 32 + w * 4, if w == 0 { v } else { 0 });
    }
}

/// 48 kHz, periods of `period` frames, `periods` of them.
fn params(period: u32, periods: u32) -> Vec<u8> {
    let mut b = any_params();
    set_iv(&mut b, P_RATE, 48000, 48000, 0);
    set_iv(&mut b, P_PERIOD_SIZE, period, period, 0);
    set_iv(&mut b, P_PERIODS, periods, periods, 0);
    b
}

fn pcm(dir: usize) -> Dev {
    snd::open(16 + 8 * dir as u64, true).unwrap()
}

/// Opens direction `dir`, sets 48 kHz x `period` x `periods` and prepares it.
fn prepared(dir: usize, period: u32, periods: u32) -> Dev {
    let f = pcm(dir);
    let mut b = params(period, periods);
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), 0);
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    f
}

/// The position buffer the driver was told about, and the slot (3, see `responder`).
fn set_position(bytes: u32) {
    let pos = fake::sound(|s| get64(s.window.as_ref().unwrap(), 40));
    unsafe { ((pos + 3 * 8) as *mut u32).write_volatile(bytes) };
}
/// The ring the driver was told about for the last SETUP.
fn ring() -> *mut u8 {
    fake::sound(|s| get64(s.window.as_ref().unwrap(), 8)) as *mut u8
}

/// SYNC_PTR: (state, hw_ptr, appl_ptr, avail_min) after giving `appl` (None: keep).
fn sync_ptr(f: &Dev, appl: Option<u64>) -> (u32, u64, u64, u64) {
    let mut b = vec![0u8; 136];
    let mut flags = 1u32 | 4; // HWSYNC, keep avail_min
    match appl {
        Some(a) => put64(&mut b, 72, a),
        None => flags |= 2,
    }
    put32(&mut b, 0, flags);
    assert_eq!(f.ioctl(SYNC_PTR, p(&mut b)), 0);
    (get32(&b, 8), get64(&b, 16), get64(&b, 72), get64(&b, 80))
}
fn state(f: &Dev) -> u32 {
    sync_ptr(f, None).0
}

fn write_frames(f: &Dev, frames: &mut [u32]) -> (i64, i64) {
    let mut x = [0u8; 24];
    put64(&mut x, 8, frames.as_mut_ptr() as u64);
    put64(&mut x, 16, frames.len() as u64);
    let r = f.ioctl(WRITEI, p(&mut x));
    (r, get64(&x, 0) as i64)
}
fn read_frames(f: &Dev, frames: &mut [u32]) -> (i64, i64) {
    let mut x = [0u8; 24];
    put64(&mut x, 8, frames.as_mut_ptr() as u64);
    put64(&mut x, 16, frames.len() as u64);
    let r = f.ioctl(READI, p(&mut x));
    (r, get64(&x, 0) as i64)
}

// =================================================================== card

#[test]
fn card_presence_and_controller() {
    let _g = setup();
    assert!(snd::present());
    assert!(snd::has_dir(0) && snd::has_dir(1) && !snd::has_dir(2));
    assert_eq!(snd::controller(), Some(("0000:00:1b.0".to_string(), 0x8086, 0x293e, 0x1af4_1100)));
    assert_eq!(fake::spawned("snd-position"), 1);
    // Two controls per direction at 0 dB, unmuted
    assert_eq!(snd::open(5, false).err(), Some(ENXIO));
}

#[test]
fn proc_asound_files() {
    let _g = setup();
    assert!(snd::proc_text("cards").unwrap().contains("HDA Intel at 0xfebf0000 irq 0"));
    assert!(snd::proc_text("version").unwrap().starts_with("Advanced Linux Sound Architecture"));
    assert!(snd::proc_text("devices").unwrap().contains("24: [ 0- 0]: digital audio capture"));
    assert_eq!(snd::proc_text("pcm").unwrap(), "00-00: ALC269 Analog : ALC269 Analog : playback 1 : capture 1\n");
    assert_eq!(snd::proc_text("card0/id").unwrap(), "Intel\n");
    let codec = snd::proc_text("card0/codec#0").unwrap();
    assert!(codec.contains("Vendor Id: 0x10ec0269") && codec.contains("Realtek ALC"), "{codec}");
    assert!(snd::proc_text("card0/pcm0p/info").unwrap().contains("stream: PLAYBACK\n"));
    assert!(snd::proc_text("card0/pcm0c/sub0/info").unwrap().contains("subdevices_avail: 1\n"));
    assert_eq!(snd::proc_text("card0/pcm0p/sub0/status").unwrap(), "closed\n");
    assert_eq!(snd::proc_text("card0/pcm0p/sub0/hw_params").unwrap(), "closed\n");
    assert_eq!(snd::proc_text("card0/pcm0p/sub0/sw_params").unwrap(), "closed\n");
    assert!(snd::proc_text("card0/pcm0x/info").is_none());
    assert!(snd::proc_text("card0/pcm0p/bogus").is_none());
    assert!(snd::proc_text("card0/pcm0").is_none());
    assert!(snd::proc_text("nothing").is_none());
    assert!(snd::is_proc_file("/proc/asound/cards"));
    assert!(!snd::is_proc_file("/proc/asound/nothing"));
    // An open stream shows its state and parameters
    let f = prepared(0, 1024, 4);
    assert!(snd::proc_text("card0/pcm0p/info").unwrap().contains("subdevices_avail: 0\n"));
    let st = snd::proc_text("card0/pcm0p/sub0/status").unwrap();
    assert!(st.starts_with("state: PREPARED\n"), "{st}");
    let hw = snd::proc_text("card0/pcm0p/sub0/hw_params").unwrap();
    assert!(hw.contains("access: MMAP_INTERLEAVED\n") && hw.contains("rate: 48000 (48000/1)\n") && hw.contains("period_size: 1024\n") && hw.contains("buffer_size: 4096\n"), "{hw}");
    let sw = snd::proc_text("card0/pcm0p/sub0/sw_params").unwrap();
    assert!(sw.contains("tstamp_mode: NONE\n") && sw.contains("avail_min: 1024\n") && sw.contains("stop_threshold: 4096\n"), "{sw}");
    drop(f);
}

// =============================================================== controls

fn ctl() -> Dev {
    snd::open(0, true).unwrap()
}

/// An elem id naming control `numid`, or by `name` (numid 0).
fn elem_id(numid: u32, name: &str) -> Vec<u8> {
    let mut id = vec![0u8; 64];
    put32(&mut id, 0, numid);
    put32(&mut id, 4, 2);
    id[16..16 + name.len()].copy_from_slice(name.as_bytes());
    id
}

fn elem_read(c: &Dev, id: &[u8]) -> Result<[i64; 2], i64> {
    let mut b = vec![0u8; 1224];
    b[..64].copy_from_slice(id);
    match c.ioctl(0xC4C8_5512, p(&mut b)) {
        0 => Ok([get64(&b, 72) as i64, get64(&b, 80) as i64]),
        e => Err(e),
    }
}
fn elem_write(c: &Dev, id: &[u8], v: [i64; 2]) -> i64 {
    let mut b = vec![0u8; 1224];
    b[..64].copy_from_slice(id);
    put64(&mut b, 72, v[0] as u64);
    put64(&mut b, 80, v[1] as u64);
    c.ioctl(0xC4C8_5513, p(&mut b))
}

#[test]
fn control_identity() {
    let _g = setup();
    let c = ctl();
    assert_eq!(c.rdev(), makedev(116, 0));
    assert_eq!(c.path(), "/dev/snd/controlC0");
    assert!(c.nonblock());
    c.set_nonblock(false);
    assert!(!c.nonblock());
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    c.add_wait_queues(&mut ws);
    assert_eq!(ws.queues.len(), 1);
    let mut v = [0u8; 4];
    assert_eq!(c.ioctl(0x8004_5500, p(&mut v)), 0);
    assert_eq!(get32(&v, 0), 0x0002_0009);
    assert_eq!(c.ioctl(0x8004_5500, fake::BAD_PTR), EFAULT);
    let mut info = vec![0u8; 376];
    assert_eq!(c.ioctl(0x8178_5501, p(&mut info)), 0);
    assert_eq!(&info[8..13], b"Intel");
    assert_eq!(&info[24..33], b"HDA-Intel");
    assert!(String::from_utf8_lossy(&info[72..152]).starts_with("HDA Intel at 0xfebf0000 irq 0"));
    assert_eq!(&info[168..174], b"ALC269");
    assert!(String::from_utf8_lossy(&info[248..]).starts_with("HDA:10ec0269,10ec0269,00100000"));
    assert_eq!(c.ioctl(0x8178_5501, fake::BAD_PTR), EFAULT);
    // Device enumeration: one PCM device, no hwdep/rawmidi/ump
    let mut d = [0u8; 4];
    put32(&mut d, 0, u32::MAX);
    assert_eq!(c.ioctl(0xC004_5530, p(&mut d)), 0);
    assert_eq!(get32(&d, 0), 0);
    assert_eq!(c.ioctl(0xC004_5530, p(&mut d)), 0);
    assert_eq!(get32(&d, 0) as i32, -1);
    assert_eq!(c.ioctl(0x8004_5530, fake::BAD_PTR), EFAULT);
    for cmd in [0xC004_5520u64, 0xC004_5540, 0xC004_5543, 0xC004_5544] {
        put32(&mut d, 0, 0);
        assert_eq!(c.ioctl(cmd, p(&mut d)), 0);
        assert_eq!(get32(&d, 0) as i32, -1);
    }
    // PCM_INFO of each stream
    let mut pi = vec![0u8; 288];
    put32(&mut pi, 8, 1);
    assert_eq!(c.ioctl(0xC120_5531, p(&mut pi)), 0);
    assert_eq!(get32(&pi, 8), 1);
    assert_eq!(&pi[16..29], b"ALC269 Analog");
    assert_eq!((get32(&pi, 200), get32(&pi, 204)), (1, 1));
    put32(&mut pi, 0, 1);
    assert_eq!(c.ioctl(0xC120_5531, p(&mut pi)), ENXIO);
    put32(&mut pi, 0, 0);
    put32(&mut pi, 8, 2);
    assert_eq!(c.ioctl(0xC120_5531, p(&mut pi)), ENXIO);
    assert_eq!(c.ioctl(0xC120_5531, fake::BAD_PTR), EFAULT);
    // Accepted no-ops, refusals, unknown
    for cmd in [0x4040_5514u64, 0x4040_5515, 0x4004_5532, 0x4004_5542, 0xC004_55D0] {
        assert_eq!(c.ioctl(cmd, 0), 0);
    }
    assert_eq!(c.ioctl(0x8004_55D1, p(&mut d)), 0);
    for cmd in [0xC110_5517u64, 0xC110_5518, 0xC040_5519] {
        assert_eq!(c.ioctl(cmd, 0), EPERM);
    }
    assert_eq!(c.ioctl(0xC008_551B, 0), ENXIO);
    assert_eq!(c.ioctl(0xC008_551C, 0), ENXIO);
    assert_eq!(c.ioctl(0x1234, 0), ENOTTY);
    assert_eq!(c.poll_events(), 0);
}

#[test]
fn element_list_info_and_tlv() {
    let _g = setup();
    let c = ctl();
    let mut ids = vec![0u8; 64 * 8];
    let mut l = vec![0u8; 80];
    put32(&mut l, 4, 8);
    put64(&mut l, 16, p(&mut ids));
    assert_eq!(c.ioctl(0xC050_5510, p(&mut l)), 0);
    assert_eq!((get32(&l, 8), get32(&l, 12)), (4, 4));
    let names: Vec<String> = (0..4).map(|i| String::from_utf8_lossy(&ids[i * 64 + 16..i * 64 + 60]).trim_end_matches('\0').to_string()).collect();
    assert_eq!(names, ["Master Playback Volume", "Master Playback Switch", "Capture Volume", "Capture Switch"]);
    assert_eq!(get32(&ids, 64 * 3), 4);
    // From offset 3, room for 1
    put32(&mut l, 0, 3);
    put32(&mut l, 4, 1);
    assert_eq!(c.ioctl(0xC050_5510, p(&mut l)), 0);
    assert_eq!(get32(&l, 8), 1);
    put64(&mut l, 16, fake::BAD_PTR);
    assert_eq!(c.ioctl(0xC050_5510, p(&mut l)), EFAULT);
    assert_eq!(c.ioctl(0xC050_5510, fake::BAD_PTR), EFAULT);
    // ELEM_INFO by name: integer volume with TLV; by number: boolean switch
    let mut b = vec![0u8; 272];
    b[..64].copy_from_slice(&elem_id(0, "Master Playback Volume"));
    assert_eq!(c.ioctl(0xC110_5511, p(&mut b)), 0);
    assert_eq!((get32(&b, 0), get32(&b, 64), get32(&b, 68), get32(&b, 72)), (1, 2, 0x13, 2));
    assert_eq!((get64(&b, 80), get64(&b, 88), get64(&b, 96)), (0, 64, 1));
    let mut b = vec![0u8; 272];
    b[..64].copy_from_slice(&elem_id(2, ""));
    assert_eq!(c.ioctl(0xC110_5511, p(&mut b)), 0);
    assert_eq!((get32(&b, 64), get32(&b, 68), get64(&b, 88)), (1, 0x3, 1));
    // Unknown names, numbers, interfaces, indexes
    for id in [elem_id(0, "PCM Playback Volume"), elem_id(9, ""), { let mut i = elem_id(0, "Capture Switch"); put32(&mut i, 4, 3); i }, { let mut i = elem_id(0, "Capture Switch"); put32(&mut i, 60, 1); i }] {
        let mut b = vec![0u8; 272];
        b[..64].copy_from_slice(&id);
        assert_eq!(c.ioctl(0xC110_5511, p(&mut b)), ENOENT);
    }
    assert_eq!(c.ioctl(0xC110_5511, fake::BAD_PTR), EFAULT);
    // TLV dB scale: min = -offset * step, step = (bits 16..22 + 1) * 25
    let mut t = vec![0u8; 8 + 16];
    put32(&mut t, 0, 1);
    put32(&mut t, 4, 16);
    assert_eq!(c.ioctl(0xC008_551A, p(&mut t)), 0);
    let step = 6 * 25;
    assert_eq!((get32(&t, 8), get32(&t, 12), get32(&t, 16) as i32, get32(&t, 20)), (1, 8, -48 * step, step as u32));
    put32(&mut t, 4, 8);
    assert_eq!(c.ioctl(0xC008_551A, p(&mut t)), ENOMEM);
    put32(&mut t, 0, 2); // a switch: no TLV
    assert_eq!(c.ioctl(0xC008_551A, p(&mut t)), ENXIO);
    put32(&mut t, 0, 0);
    assert_eq!(c.ioctl(0xC008_551A, p(&mut t)), ENXIO);
    assert_eq!(c.ioctl(0xC008_551A, fake::BAD_PTR), EFAULT);
}

#[test]
fn volume_changes_reach_the_driver_and_subscribers() {
    let _g = setup();
    let c = ctl();
    let quiet = ctl();
    // SUBSCRIBE_EVENTS: query, on
    let mut v = [0u8; 4];
    put32(&mut v, 0, u32::MAX);
    assert_eq!(c.ioctl(0xC004_5516, p(&mut v)), 0);
    assert_eq!(get32(&v, 0), 0);
    put32(&mut v, 0, 1);
    assert_eq!(c.ioctl(0xC004_5516, p(&mut v)), 0);
    put32(&mut v, 0, u32::MAX);
    c.ioctl(0xC004_5516, p(&mut v));
    assert_eq!(get32(&v, 0), 1);
    assert_eq!(c.ioctl(0xC004_5516, fake::BAD_PTR), EFAULT);
    let vol = elem_id(1, "");
    let start = elem_read(&c, &vol).unwrap();
    assert_eq!(start, [48, 48]);
    // A change: sent to the driver, an event for subscribers only (bug fixed, wave TW,
    // Group 28: every open control file got it, and polled readable for ever)
    assert_eq!(elem_write(&c, &vol, [10, 20]), 0);
    assert_eq!(elem_read(&c, &vol).unwrap(), [10, 20]);
    assert_eq!(VOLUMES.lock().unwrap().last().copied(), Some([0, 10, 20, 0]));
    assert_eq!(c.poll_events(), 0x1 | 0x40);
    assert_eq!(quiet.poll_events(), 0);
    let mut small = [0u8; 71];
    assert_eq!(c.read(&mut small), EINVAL);
    let mut ev = [0u8; 72 * 2];
    assert_eq!(c.read(&mut ev), 72);
    assert_eq!(get32(&ev, 4), 1);
    assert_eq!(get32(&ev, 8), 1);
    assert_eq!(&ev[24..46], b"Master Playback Volume");
    // Nothing more: non-blocking EAGAIN; the unsubscribed file: EBADFD
    assert_eq!(c.read(&mut ev), EAGAIN);
    assert_eq!(quiet.read(&mut ev), EBADFD);
    // The same value again: no event, nothing sent
    let n = VOLUMES.lock().unwrap().len();
    assert_eq!(elem_write(&c, &vol, [10, 20]), 0);
    assert_eq!(VOLUMES.lock().unwrap().len(), n);
    // Out of range
    assert_eq!(elem_write(&c, &vol, [65, 0]), EINVAL);
    assert_eq!(elem_write(&c, &vol, [-1, 0]), EINVAL);
    assert_eq!(elem_write(&c, &elem_id(7, ""), [0, 0]), ENOENT);
    assert_eq!(elem_read(&c, &elem_id(7, "")).err(), Some(ENOENT));
    assert_eq!(c.ioctl(0xC4C8_5512, fake::BAD_PTR), EFAULT);
    assert_eq!(c.ioctl(0xC4C8_5513, fake::BAD_PTR), EFAULT);
    // Muting one channel of capture: the mute bits
    assert_eq!(elem_write(&c, &elem_id(4, ""), [1, 0]), 0);
    assert_eq!(VOLUMES.lock().unwrap().last().copied(), Some([1, 10, 10, 2]));
    let _ = c.read(&mut ev);
    // A blocking subscriber waits for the next event; a signal ends the wait
    c.set_nonblock(false);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(c.read(&mut ev), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    let c2 = ctl();
    fake::on_wait(move || {
        elem_write(&c2, &elem_id(4, ""), [1, 1]);
    });
    assert_eq!(c.read(&mut ev), 72);
    fake::clear_on_wait();
    // Unsubscribe: back to EBADFD when empty
    put32(&mut v, 0, 0);
    assert_eq!(c.ioctl(0xC004_5516, p(&mut v)), 0);
    c.set_nonblock(true);
    while c.read(&mut ev) > 0 {}
    assert_eq!(c.read(&mut ev), EBADFD);
    // Restore 0 dB
    assert_eq!(elem_write(&c, &vol, [48, 48]), 0);
    assert_eq!(elem_write(&c, &elem_id(3, ""), [10, 10]), 0);
}

// =========================================================== hw params

#[test]
fn hw_refine_narrows_to_the_device() {
    let _g = setup();
    let f = pcm(0);
    let mut b = any_params();
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), 0);
    // Access: mmap and rw interleaved; format S16_LE; 16-bit stereo; 44.1-48 kHz
    assert_eq!(mask(&b, 0), 1 | 1 << 3);
    assert_eq!(mask(&b, 1), 1 << 2);
    assert_eq!(mask(&b, 2), 1);
    assert_eq!(iv(&b, P_SAMPLE_BITS), (16, 16, 4));
    assert_eq!(iv(&b, P_FRAME_BITS), (32, 32, 4));
    assert_eq!(iv(&b, P_CHANNELS), (2, 2, 4));
    assert_eq!(iv(&b, P_RATE), (44100, 48000, 4));
    assert_eq!(iv(&b, P_PERIODS).0, 2);
    assert_eq!(iv(&b, P_PERIODS).1, 32);
    // (at least 16 KiB in at most 32 periods: periods of 512 bytes or more)
    assert_eq!(iv(&b, P_PERIOD_BYTES), (512, 256 * 1024, 4));
    assert_eq!(iv(&b, P_BUFFER_BYTES), (16384, 512 * 1024, 4));
    assert_eq!(iv(&b, P_BUFFER_SIZE), (4096, 128 * 1024, 4));
    assert_eq!(get32(&b, 524), 16); // msbits
    assert_eq!(get32(&b, 520), 0x81_0113); // info
    assert_eq!(get32(&b, 512), 0); // rmask
    assert_ne!(get32(&b, 516), 0); // cmask
    assert_eq!(get32(&b, 532), 0, "rate not single yet");
    // One rate: rate_num/den filled in
    let mut b = any_params();
    set_iv(&mut b, P_RATE, 44100, 44100, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), 0);
    assert_eq!((get32(&b, 528), get32(&b, 532)), (44100, 1));
    // A rate between the two: rounded to a listed one
    let mut b = any_params();
    set_iv(&mut b, P_RATE, 45000, 47000, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    let mut b = any_params();
    set_iv(&mut b, P_RATE, 44100, 44100, 1); // open minimum: excludes 44100
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    // Impossible requests: mono, 8-bit format only, no access, empty interval
    let mut b = any_params();
    set_iv(&mut b, P_CHANNELS, 1, 1, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    let mut b = any_params();
    set_mask(&mut b, 1, 1 << 1);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    let mut b = any_params();
    set_mask(&mut b, 0, 1 << 1);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    let mut b = any_params();
    set_iv(&mut b, P_PERIODS, 4, 4, 8);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    let mut b = any_params();
    set_iv(&mut b, P_BUFFER_BYTES, 1000, 2000, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), EINVAL);
    // Open bounds on non-integer intervals (times) and rounding by the period step
    let mut b = any_params();
    set_iv(&mut b, P_PERIOD_TIME, 10000, 20000, 1 | 2);
    set_iv(&mut b, P_PERIOD_BYTES, 1000, 3000, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), 0);
    let (lo, hi, _) = iv(&b, P_PERIOD_BYTES);
    assert!(lo % 128 == 0 && hi % 128 == 0 && lo >= 1000 && hi <= 3000, "{lo}..{hi}");
    // Buffer time pins the buffer size
    let mut b = any_params();
    set_iv(&mut b, P_RATE, 48000, 48000, 0);
    set_iv(&mut b, P_BUFFER_TIME, 100_000, 100_000, 0);
    assert_eq!(f.ioctl(HW_REFINE, p(&mut b)), 0);
    assert_eq!(iv(&b, P_BUFFER_SIZE).0, 4800);
    assert_eq!(f.ioctl(HW_REFINE, fake::BAD_PTR), EFAULT);
    drop(f);
}

#[test]
fn hw_params_chooses_one_setup() {
    let _g = setup();
    let f = pcm(0);
    // Everything allowed: the first access (mmap), the lowest rate, the smallest period,
    // the largest buffer that fits
    let mut b = any_params();
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), 0);
    assert_eq!(mask(&b, 0), 1);
    assert_eq!(iv(&b, P_RATE).0, 44100);
    let (period, periods, buffer) = (iv(&b, P_PERIOD_SIZE).0 as u64, iv(&b, P_PERIODS).0 as u64, iv(&b, P_BUFFER_SIZE).0 as u64);
    assert_eq!(buffer, period * periods);
    assert!(buffer * 4 <= 512 * 1024 && (period * 4) % 128 == 0, "{period} x {periods}");
    // A specific request
    let mut b = params(1024, 4);
    set_mask(&mut b, 0, 1 << 3);
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), 0);
    assert_eq!(mask(&b, 0), 1 << 3);
    assert_eq!((iv(&b, P_PERIOD_SIZE).0, iv(&b, P_BUFFER_SIZE).0, iv(&b, P_BUFFER_BYTES).0), (1024, 4096, 16384));
    assert_eq!(iv(&b, P_PERIOD_TIME).0, 21333);
    let hw = snd::proc_text("card0/pcm0p/sub0/hw_params").unwrap();
    assert!(hw.contains("access: RW_INTERLEAVED"), "{hw}");
    // A setup the device cannot ring: periods that do not divide evenly into 128 bytes
    let mut b = params(1000, 4);
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), EINVAL);
    // Only in OPEN/SETUP/PREPARED
    let mut b = params(1024, 4);
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), 0);
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    assert_eq!(f.ioctl(START, 0), EPIPE); // nothing written yet
    let mut fr = vec![0u32; 1024];
    assert_eq!(write_frames(&f, &mut fr), (0, 1024));
    assert_eq!(state(&f), RUNNING);
    let mut b = params(1024, 4);
    assert_eq!(f.ioctl(HW_PARAMS, p(&mut b)), EBADFD);
    assert_eq!(f.ioctl(HW_FREE, 0), EBADFD);
    assert_eq!(f.ioctl(DROP, 0), 0);
    assert_eq!(f.ioctl(HW_FREE, 0), 0);
    assert_eq!(state(&f), OPEN);
    assert_eq!(f.ioctl(PREPARE, 0), EBADFD);
    drop(f);
}

// ================================================================ streams

#[test]
fn pcm_open_rules_and_identity() {
    let _g = setup();
    let f = pcm(0);
    assert_eq!(snd::open(16, false).err(), Some(EBUSY));
    assert_eq!(f.rdev(), makedev(116, 16));
    assert_eq!(f.path(), "/dev/snd/pcmC0D0p");
    let c = pcm(1);
    assert_eq!(c.path(), "/dev/snd/pcmC0D0c");
    assert_eq!(c.rdev(), makedev(116, 24));
    assert_eq!(f.read(&mut [0u8; 4]), EINVAL);
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    f.add_wait_queues(&mut ws);
    assert_eq!(ws.queues.len(), 1);
    f.set_nonblock(false);
    assert!(!f.nonblock());
    let mut v = [0u8; 4];
    assert_eq!(f.ioctl(0x8004_4100, p(&mut v)), 0);
    assert_eq!(get32(&v, 0), 0x0002_000F);
    let mut info = vec![0u8; 288];
    assert_eq!(c.ioctl(0x8120_4101, p(&mut info)), 0);
    assert_eq!(get32(&info, 8), 1);
    assert_eq!(c.ioctl(0x8120_4101, fake::BAD_PTR), EFAULT);
    // Timestamp settings
    put32(&mut v, 0, 1);
    assert_eq!(f.ioctl(0x4004_4102, p(&mut v)), 0);
    assert_eq!(f.ioctl(0x4004_4102, fake::BAD_PTR), EFAULT);
    put32(&mut v, 0, 2);
    assert_eq!(f.ioctl(0x4004_4103, p(&mut v)), 0);
    put32(&mut v, 0, 3);
    assert_eq!(f.ioctl(0x4004_4103, p(&mut v)), EINVAL);
    assert_eq!(f.ioctl(0x4004_4103, fake::BAD_PTR), EFAULT);
    assert_eq!(f.ioctl(0x4004_4104, 0), 0);
    // Not offered / not supported
    assert_eq!(f.ioctl(0x4004_4145, 1), -38);
    assert_eq!(f.ioctl(0x4147, 0), EINVAL);
    assert_eq!(f.ioctl(0x4018_4152, 0), EINVAL);
    assert_eq!(f.ioctl(0x4004_4160, 0), ENOTTY);
    assert_eq!(f.ioctl(0x9999, 0), ENOTTY);
    // The wrong transfer direction
    assert_eq!(f.ioctl(READI, 0), EINVAL);
    assert_eq!(c.ioctl(WRITEI, 0), EINVAL);
    // Without hw params: nothing to do
    assert_eq!(f.ioctl(PREPARE, 0), EBADFD);
    assert_eq!(f.ioctl(RESET, 0), EBADFD);
    assert_eq!(f.ioctl(DROP, 0), EBADFD);
    assert_eq!(f.ioctl(DRAIN, 0), EBADFD);
    assert_eq!(f.ioctl(START, 0), EBADFD);
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut vec![0u8; 136])), EBADFD);
    let mut x = [0u8; 8];
    assert_eq!(f.ioctl(REWIND, p(&mut x)), EBADFD);
    assert_eq!(f.ioctl(0x8018_4132, p(&mut [0u8; 24])), EINVAL);
    assert_eq!(f.mmap_object().err(), Some(EBADFD));
    assert_eq!(f.mmap_object_at(0x80000).err(), Some(ENXIO));
    let mut fr = vec![0u32; 4];
    assert_eq!(write_frames(&f, &mut fr).0, EBADFD);
    assert_eq!(f.poll_events(), 0x4 | 0x100 | 0x8);
    drop((f, c));
}

#[test]
fn sw_params_status_and_channel_info() {
    let _g = setup();
    let f = prepared(0, 1024, 4);
    let mut sw = vec![0u8; 136];
    put32(&mut sw, 0, 1);
    put64(&mut sw, 16, 0); // avail_min 0 -> 1
    put64(&mut sw, 32, 2048);
    put64(&mut sw, 40, 4096);
    put32(&mut sw, 72, 0x0002_000C);
    put32(&mut sw, 76, 7); // tstamp type, capped at 2
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut sw)), 0);
    let boundary = get64(&sw, 64);
    assert!(boundary >= 4096 && boundary % 4096 == 0 && boundary.is_power_of_two() == (4096u64.is_power_of_two()));
    assert!(boundary > (i64::MAX as u64) / 4);
    let text = snd::proc_text("card0/pcm0p/sub0/sw_params").unwrap();
    assert!(text.contains("tstamp_mode: ENABLE") && text.contains("avail_min: 1\n") && text.contains("start_threshold: 2048\n"), "{text}");
    put32(&mut sw, 0, 2);
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut sw)), EINVAL);
    assert_eq!(f.ioctl(SW_PARAMS, fake::BAD_PTR), EFAULT);
    // STATUS of a prepared stream: everything available, no delay
    fake::TICKS.set(2_000);
    let mut st = vec![0u8; 152];
    assert_eq!(f.ioctl(STATUS, p(&mut st)), 0);
    assert_eq!(get32(&st, 0), PREPARED);
    assert_eq!((get64(&st, 40), get64(&st, 48), get64(&st, 56), get64(&st, 64)), (0, 0, 0, 4096));
    // Monotonic raw clock (type 2): the tick clock as is
    assert_eq!((get64(&st, 24), get64(&st, 32)), (2, 0));
    assert_eq!(f.ioctl(0xC098_4124, p(&mut st)), 0);
    assert_eq!(f.ioctl(STATUS, fake::BAD_PTR), EFAULT);
    // Wall clock type: boot wall time added
    let mut v = [0u8; 4];
    put32(&mut v, 0, 0);
    assert_eq!(f.ioctl(0x4004_4103, p(&mut v)), 0);
    assert_eq!(f.ioctl(STATUS, p(&mut st)), 0);
    assert_eq!(get64(&st, 24), 1_767_225_600 + 2);
    // DELAY
    let mut d = [0u8; 8];
    assert_eq!(f.ioctl(DELAY, p(&mut d)), 0);
    assert_eq!(get64(&d, 0), 0);
    assert_eq!(f.ioctl(DELAY, fake::BAD_PTR), EFAULT);
    // CHANNEL_INFO: interleaved, 16 bits apart, a 32-bit step
    let mut ci = [0u8; 24];
    put32(&mut ci, 0, 1);
    assert_eq!(f.ioctl(0xC018_4132, p(&mut ci)), 0);
    assert_eq!((get64(&ci, 8), get32(&ci, 16), get32(&ci, 20)), (0, 16, 32));
    put32(&mut ci, 0, 2);
    assert_eq!(f.ioctl(0x8018_4132, p(&mut ci)), EINVAL);
    assert_eq!(f.ioctl(0x8018_4132, fake::BAD_PTR), EFAULT);
    // The ring maps at offset 0, page by page
    let obj = f.mmap_object().unwrap();
    let pg0 = obj.get_page(0).unwrap();
    assert_eq!(pg0.start_address().as_u64(), ring() as u64);
    assert!(obj.get_page(127).is_some() && obj.get_page(128).is_none());
    drop(f);
}

#[test]
fn playback_runs_underruns_and_recovers() {
    let _g = setup();
    let f = prepared(0, 1024, 4); // buffer 4096 frames = 16 KiB
    assert_eq!(state(&f), PREPARED);
    // poll: room for a period
    assert_eq!(f.poll_events(), 0x4 | 0x100);
    // Write 3000 frames: the stream starts with the first (start threshold 1)
    let mut fr: Vec<u32> = (0..3000).map(|i| 0x0001_0001 * (i % 100 + 1)).collect();
    assert_eq!(write_frames(&f, &mut fr), (0, 3000));
    assert_eq!(TRIGGERS.lock().unwrap().last().copied(), Some((0, 1)));
    let (st, hw, appl, _) = sync_ptr(&f, None);
    assert_eq!((st, hw, appl), (RUNNING, 0, 3000));
    // The frames landed in the ring
    let r = ring() as *const u32;
    assert_eq!(unsafe { *r.add(5) }, 0x0001_0001 * 6);
    // The controller fetched 1000 frames: hw_ptr follows, the played part is silenced
    set_position(1000 * 4);
    let (st, hw, _, _) = sync_ptr(&f, None);
    assert_eq!((st, hw), (RUNNING, 1000));
    assert_eq!(unsafe { *r.add(5) }, 0);
    assert_ne!(unsafe { *r.add(1000) }, 0);
    let mut d = [0u8; 8];
    assert_eq!(f.ioctl(DELAY, p(&mut d)), 0);
    assert_eq!(get64(&d, 0), 2000);
    // Fill to the end of the ring and wrap
    let mut fr2 = vec![7u32; 2096];
    assert_eq!(write_frames(&f, &mut fr2), (0, 2096));
    assert_eq!(unsafe { *r.add(4095) }, 7);
    assert_eq!(unsafe { *r.add(999) }, 7);
    assert_ne!(unsafe { *r.add(1000) }, 7); // not played yet: the first write's
    // Full: non-blocking write gives EAGAIN
    let mut one = vec![1u32; 1];
    assert_eq!(write_frames(&f, &mut one), (EAGAIN, EAGAIN));
    assert_eq!(f.poll_events(), 0);
    // The controller wraps past the end: silenced across the wrap
    set_position(500 * 4);
    let (_, hw, _, _) = sync_ptr(&f, None);
    assert_eq!(hw, 4096 + 500);
    assert_eq!(unsafe { *r.add(4095) }, 0);
    assert_eq!(unsafe { *r.add(100) }, 0);
    // The controller passes the program: underrun, the DMA is stopped
    set_position(1001 * 4); // past appl (5096 % 4096 = 1000)
    let (st, ..) = sync_ptr(&f, None);
    assert_eq!(st, XRUN_ST);
    assert_eq!(TRIGGERS.lock().unwrap().last().copied(), Some((0, 0)));
    assert_eq!(write_frames(&f, &mut one).0, EPIPE);
    assert_eq!(f.ioctl(DELAY, p(&mut d)), EPIPE);
    assert_eq!(f.ioctl(HWSYNC, 0), EPIPE);
    assert_eq!(f.poll_events() & 0x8, 0x8);
    // Recover: prepare again, start explicitly after writing
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    assert_eq!(f.ioctl(HWSYNC, 0), 0);
    let mut fr3 = vec![3u32; 100];
    let mut sw = vec![0u8; 136];
    put64(&mut sw, 32, 1 << 40); // start threshold: never by itself
    put64(&mut sw, 40, 4096);
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut sw)), 0);
    assert_eq!(write_frames(&f, &mut fr3), (0, 100));
    assert_eq!(state(&f), PREPARED);
    assert_eq!(f.ioctl(START, 0), 0);
    assert_eq!(state(&f), RUNNING);
    assert_eq!(f.ioctl(START, 0), EBADFD);
    // XRUN by request
    assert_eq!(f.ioctl(XRUN, 0), 0);
    assert_eq!(state(&f), XRUN_ST);
    // DRAIN of an xrun stream: back to SETUP
    assert_eq!(f.ioctl(DRAIN, 0), 0);
    assert_eq!(state(&f), SETUP);
    let mut fr4 = vec![0u32; 1];
    assert_eq!(write_frames(&f, &mut fr4).0, EBADFD);
    drop(f);
    // Closing a running stream stops the DMA
    let f = prepared(0, 1024, 4);
    let mut fr = vec![1u32; 100];
    write_frames(&f, &mut fr);
    TRIGGERS.lock().unwrap().clear();
    drop(f);
    assert_eq!(TRIGGERS.lock().unwrap().as_slice(), &[(0, 0)]);
}

#[test]
fn stop_threshold_at_the_boundary_never_xruns() {
    let _g = setup();
    let f = prepared(0, 1024, 4);
    let mut sw = vec![0u8; 136];
    put64(&mut sw, 32, 1);
    put64(&mut sw, 40, u64::MAX);
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut sw)), 0);
    let mut fr = vec![1u32; 10];
    write_frames(&f, &mut fr);
    set_position(2000 * 4);
    assert_eq!(state(&f), RUNNING);
    drop(f);
}

#[test]
fn blocking_writes_wait_for_room() {
    let _g = setup();
    let f = prepared(0, 1024, 4);
    f.set_nonblock(false);
    let mut fr = vec![1u32; 4096];
    assert_eq!(write_frames(&f, &mut fr), (0, 4096));
    // Full; a signal interrupts the wait (nothing written)
    fake::SIGNAL_PENDING.set(true);
    let mut more = vec![2u32; 512];
    assert_eq!(write_frames(&f, &mut more).0, ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    // The controller moves on while the writer sleeps
    fake::on_wait(|| set_position(1024 * 4));
    assert_eq!(write_frames(&f, &mut more), (0, 512));
    fake::clear_on_wait();
    // A stalled controller: after 10 s of no progress, EIO (or what was written)
    let mut lots = vec![3u32; 1024];
    let (r, _) = write_frames(&f, &mut lots);
    assert_eq!(r, 0, "512 frames of room");
    let mut again = vec![3u32; 600];
    let before = fake::TICKS.get();
    assert_eq!(write_frames(&f, &mut again).0, EIO);
    assert!(fake::TICKS.get() > before + 1000);
    drop(f);
}

#[test]
fn faulting_transfers() {
    let _g = setup();
    let f = prepared(0, 1024, 4);
    assert_eq!(f.ioctl(WRITEI, fake::BAD_PTR), EFAULT);
    let mut x = [0u8; 24];
    put64(&mut x, 8, fake::BAD_PTR);
    put64(&mut x, 16, 10);
    assert_eq!(f.ioctl(WRITEI, p(&mut x)), EFAULT);
    drop(f);
    let c = prepared(1, 1024, 4);
    let mut x = [0u8; 24];
    put64(&mut x, 8, fake::BAD_PTR);
    put64(&mut x, 16, 10);
    set_position(0);
    // starts on the first read, then data appears
    fake::on_wait(|| set_position(64 * 4));
    c.set_nonblock(false);
    assert_eq!(c.ioctl(READI, p(&mut x)), EFAULT);
    fake::clear_on_wait();
    drop(c);
}

#[test]
fn capture_starts_on_the_first_read() {
    let _g = setup();
    let c = prepared(1, 1024, 4);
    assert_eq!(c.poll_events(), 0); // nothing captured yet
    let mut fr = vec![0u32; 256];
    // Prepared: the read starts the stream; nothing there yet
    assert_eq!(read_frames(&c, &mut fr), (EAGAIN, EAGAIN));
    assert_eq!(TRIGGERS.lock().unwrap().last().copied(), Some((1, 1)));
    assert_eq!(state(&c), RUNNING);
    // The controller wrote 300 frames
    let r = ring() as *mut u32;
    for i in 0..300 {
        unsafe { *r.add(i) = i as u32 + 1 };
    }
    set_position(300 * 4);
    assert_eq!(c.poll_events(), 0); // below avail_min (a period)
    assert_eq!(read_frames(&c, &mut fr), (0, 256));
    assert_eq!(fr[0], 1);
    assert_eq!(fr[255], 256);
    let mut d = [0u8; 8];
    assert_eq!(c.ioctl(DELAY, p(&mut d)), 0);
    assert_eq!(get64(&d, 0), 44);
    // REWIND/FORWARD of the application pointer
    let mut x = [0u8; 8];
    put64(&mut x, 0, 100);
    assert_eq!(c.ioctl(FORWARD, p(&mut x)), 0);
    assert_eq!(get64(&x, 0), 44);
    put64(&mut x, 0, 10);
    assert_eq!(c.ioctl(REWIND, p(&mut x)), 0);
    assert_eq!(get64(&x, 0), 10);
    assert_eq!(c.ioctl(REWIND, fake::BAD_PTR), EFAULT);
    // RESET: the program catches up with the hardware
    assert_eq!(c.ioctl(RESET, 0), 0);
    let (_, hw, appl, _) = sync_ptr(&c, None);
    assert_eq!(hw, appl);
    // DRAIN of capture drops the stream
    assert_eq!(c.ioctl(DRAIN, 0), 0);
    assert_eq!(state(&c), SETUP);
    assert_eq!(c.ioctl(DRAIN, 0), 0);
    assert_eq!(read_frames(&c, &mut fr).0, EBADFD);
    drop(c);
}

#[test]
fn draining_playback() {
    let _g = setup();
    // Prepared and empty: drain is immediate. (Bug fixed, wave TW, Group 28: this hung for
    // ever, the kernel spinning on the stream lock it already held)
    let f = prepared(0, 1024, 4);
    assert_eq!(f.ioctl(DRAIN, 0), 0);
    assert_eq!(state(&f), SETUP);
    // Prepared with data: drain starts it; non-blocking: EAGAIN while it drains
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    let mut sw = vec![0u8; 136];
    put64(&mut sw, 32, 1 << 40);
    put64(&mut sw, 40, 4096);
    assert_eq!(f.ioctl(SW_PARAMS, p(&mut sw)), 0);
    let mut fr = vec![1u32; 2048];
    assert_eq!(write_frames(&f, &mut fr), (0, 2048));
    assert_eq!(state(&f), PREPARED);
    assert_eq!(f.ioctl(DRAIN, 0), EAGAIN);
    assert_eq!(state(&f), DRAINING);
    assert_eq!(f.poll_events(), 0);
    assert_eq!(write_frames(&f, &mut fr).0, EBADFD);
    // Blocking: done when the controller played everything
    f.set_nonblock(false);
    fake::on_wait(|| set_position(2048 * 4));
    assert_eq!(f.ioctl(DRAIN, 0), 0);
    fake::clear_on_wait();
    assert_eq!(state(&f), SETUP);
    // A signal interrupts a drain; a drain that never ends gives up after 10 s
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    let mut fr = vec![1u32; 100];
    write_frames(&f, &mut fr);
    assert_eq!(f.ioctl(START, 0), 0);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(f.ioctl(DRAIN, 0), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    assert_eq!(f.ioctl(DRAIN, 0), EIO);
    assert_eq!(state(&f), SETUP);
    // Starting fails at the driver: EIO
    assert_eq!(f.ioctl(PREPARE, 0), 0);
    write_frames(&f, &mut fr);
    *FAIL_TRIGGER.lock().unwrap() = Some(5);
    assert_eq!(f.ioctl(START, 0), EIO);
    assert_eq!(f.ioctl(DRAIN, 0), EIO);
    // The driver cannot set the stream up: EIO
    *FAIL_SETUP.lock().unwrap() = Some(5);
    assert_eq!(f.ioctl(PREPARE, 0), EIO);
    drop(f);
}

#[test]
fn sync_ptr_exchanges_pointers_and_boosts_the_driver_thread() {
    let _g = setup();
    use std::sync::atomic::Ordering;
    let tid = 4242;
    fake::IDS.set((tid, tid));
    fake::TASK_SCHED.set((TaskPersonality::Linux, TaskPriority::Normal));
    hydra_hosttests_t28::task::CURRENT_TID.store(tid, Ordering::Relaxed);
    let f = prepared(0, 1024, 4);
    // The program's pointer and minimum go in; the status comes out
    let mut b = vec![0u8; 136];
    put64(&mut b, 72, 1500);
    put64(&mut b, 80, 0);
    assert_eq!(f.ioctl(SYNC_PTR, p(&mut b)), 0);
    assert_eq!((get32(&b, 8), get64(&b, 72), get64(&b, 80)), (PREPARED, 1500, 1));
    assert_eq!(fake::TASK_SCHED.get().1, TaskPriority::High);
    // The appl pointer wraps at the boundary
    let (.., appl, _) = sync_ptr(&f, Some(u64::MAX));
    assert!(appl < u64::MAX);
    assert_eq!(f.ioctl(SYNC_PTR, fake::BAD_PTR), EFAULT);
    // Another thread takes over: the first gets its own priority back
    hydra_hosttests_t28::task::CURRENT_TID.store(tid + 1, Ordering::Relaxed);
    fake::REAPPLIED.lock().unwrap().clear();
    sync_ptr(&f, None);
    assert_eq!(fake::REAPPLIED.lock().unwrap().as_slice(), &[tid]);
    // Closing gives the driver thread its priority back
    drop(f);
    assert_eq!(fake::REAPPLIED.lock().unwrap().as_slice(), &[tid, tid + 1]);
    // A native Hydra thread is not boosted
    hydra_hosttests_t28::task::CURRENT_TID.store(tid, Ordering::Relaxed);
    fake::TASK_SCHED.set((TaskPersonality::Hydra, TaskPriority::Normal));
    let f = prepared(0, 1024, 4);
    sync_ptr(&f, None);
    assert_eq!(fake::TASK_SCHED.get().1, TaskPriority::Normal);
    drop(f);
    hydra_hosttests_t28::task::CURRENT_TID.store(0, Ordering::Relaxed);
}

#[test]
fn the_position_task_updates_running_streams() {
    let _g = setup();
    let f = prepared(0, 1024, 4);
    let mut fr = vec![1u32; 4096];
    write_frames(&f, &mut fr);
    set_position(512 * 4);
    let task = fake::spawned_entry("snd-position").unwrap();
    // It loops for ever: stop it at its second sleep
    let mut n = 0;
    fake::on_wait(move || {
        n += 1;
        if n == 2 {
            panic!("stop the position task");
        }
    });
    assert!(std::panic::catch_unwind(task).is_err());
    fake::clear_on_wait();
    let (st, hw, ..) = sync_ptr(&f, None);
    assert_eq!((st, hw), (RUNNING, 512));
    // An underrun found by the task stops the DMA
    set_position(0); // wrapped round: 4096 - 512 + ... past appl
    TRIGGERS.lock().unwrap().clear();
    let mut n = 0;
    fake::on_wait(move || {
        n += 1;
        if n == 1 {
            set_position(4095 * 4);
        }
        if n == 2 {
            panic!("stop");
        }
    });
    assert!(std::panic::catch_unwind(task).is_err());
    fake::clear_on_wait();
    drop(f);
    // Nothing running: it sleeps long
    fake::on_wait(|| panic!("stop"));
    assert!(std::panic::catch_unwind(task).is_err());
    fake::clear_on_wait();
}

#[test]
fn traced_ioctls() {
    let _g = setup();
    // TRACE is private; the ioctl paths with tracing off are covered elsewhere. Here a
    // closed stream's status is "closed" and hw_free twice is fine.
    let f = pcm(0);
    assert_eq!(f.ioctl(HW_FREE, 0), 0);
    assert_eq!(f.ioctl(HW_FREE, 0), 0);
    let st = snd::proc_text("card0/pcm0p/sub0/status").unwrap();
    assert!(st.starts_with("state: OPEN"), "{st}");
    drop(f);
}
