//! # evdev input devices (`/dev/input/event0`, `/dev/input/event1`)
//!
//! The PS/2 keyboard (minor 64) and mouse (minor 65) as Linux event devices, the interface
//! libinput reads. Each open file has its own queue of `struct input_event` records
//! (24 bytes: monotonic `timeval`, type, code, value), filled while a DRM client shows a
//! picture ([`set_routing`]); otherwise the keyboard belongs to the console or Hydra's
//! compositor.
//!
//! The interrupt handlers only append raw scancodes and mouse packets to a fixed ring
//! ([`push_scancode`], [`push_mouse`]) and wake [`INPUT_WQ`]; the conversion to events and
//! the fan-out to open files happen in process context when a reader reads or polls, so
//! no interrupt handler allocates.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

use super::chardev::{makedev, CharDevice};
use super::vfs::copy_out;

const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_MSC: u16 = 0x04;
const EV_LED: u16 = 0x11;
const EV_REP: u16 = 0x14;
const SYN_REPORT: u16 = 0;
const SYN_DROPPED: u16 = 3;
const MSC_SCAN: u16 = 4;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

/// Events a file may hold before older ones are dropped (and `SYN_DROPPED` reported).
const QUEUE_LIMIT: usize = 2048;

/// Woken whenever raw input arrives.
pub static INPUT_WQ: WaitQueue = WaitQueue::new();

static ROUTING: AtomicBool = AtomicBool::new(false);

/// Sends the keyboard and mouse to the event devices (`true`) or back to Hydra (`false`).
pub fn set_routing(on: bool) {
    ROUTING.store(on, Ordering::Release);
}

/// True while input goes to the event devices.
pub fn routing() -> bool {
    ROUTING.load(Ordering::Acquire)
}

#[derive(Clone, Copy)]
enum Raw {
    Scancode(u8),
    /// Relative motion (x right, y down) and button bits (left, right, middle).
    Mouse(i16, i16, u8),
}

/// Raw input from the interrupt handlers: a fixed ring, locked only with interrupts off.
struct Ring {
    buf: [(Raw, u64); 512],
    head: usize,
    len: usize,
}

static RING: Mutex<Ring> = Mutex::new(Ring { buf: [(Raw::Scancode(0), 0); 512], head: 0, len: 0 });

fn push_raw(r: Raw) {
    if !routing() {
        return;
    }
    let t = crate::arch::pit::ticks();
    {
        let mut ring = RING.lock();
        if ring.len == ring.buf.len() {
            return; // nobody reads: drop
        }
        let i = (ring.head + ring.len) % ring.buf.len();
        ring.buf[i] = (r, t);
        ring.len += 1;
    }
    INPUT_WQ.wake_all();
}

/// Keyboard interrupt: one set-1 scancode byte.
pub fn push_scancode(code: u8) {
    push_raw(Raw::Scancode(code));
}

/// Mouse interrupt: one decoded packet (`dy` positive = down).
pub fn push_mouse(dx: i32, dy: i32, buttons: u8) {
    push_raw(Raw::Mouse(dx as i16, dy as i16, buttons));
}

fn ring_pending() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| RING.lock().len > 0)
}

/// Translation state of the two devices.
struct Translator {
    e0: bool,
    keys: [u8; 96],
    buttons: u8,
}

static STATE: Mutex<Translator> = Mutex::new(Translator { e0: false, keys: [0; 96], buttons: 0 });

/// Open files of the keyboard (`[0]`) and mouse (`[1]`).
static CLIENTS: Mutex<[Vec<Weak<EvdevFile>>; 2]> = Mutex::new([Vec::new(), Vec::new()]);

fn event(t: u64, ty: u16, code: u16, value: i32) -> [u8; 24] {
    let us = t * 10_000;
    let mut e = [0u8; 24];
    e[0..8].copy_from_slice(&(us / 1_000_000).to_le_bytes());
    e[8..16].copy_from_slice(&(us % 1_000_000).to_le_bytes());
    e[16..18].copy_from_slice(&ty.to_le_bytes());
    e[18..20].copy_from_slice(&code.to_le_bytes());
    e[20..24].copy_from_slice(&value.to_le_bytes());
    e
}

/// Moves raw input into the queues of every open file.
fn pump() {
    if !ring_pending() {
        return;
    }
    let raw: Vec<(Raw, u64)> = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut ring = RING.lock();
        let mut out = Vec::with_capacity(ring.len);
        while ring.len > 0 {
            out.push(ring.buf[ring.head]);
            ring.head = (ring.head + 1) % ring.buf.len();
            ring.len -= 1;
        }
        out
    });
    let mut per_dev: [Vec<[u8; 24]>; 2] = [Vec::new(), Vec::new()];
    {
        let mut st = STATE.lock();
        for (r, t) in raw {
            match r {
                Raw::Scancode(0xE0) => st.e0 = true,
                Raw::Scancode(sc) => {
                    let make = sc & 0x7F;
                    let code = if st.e0 { crate::wayland::e0_keycode(make) } else { make as u32 };
                    let scan = if st.e0 { 0xE000 | make as i32 } else { make as i32 };
                    st.e0 = false;
                    if code == 0 || code >= 768 {
                        continue;
                    }
                    let (byte, bit) = (code as usize / 8, 1u8 << (code % 8));
                    let was_down = st.keys[byte] & bit != 0;
                    let value = if sc & 0x80 != 0 {
                        if !was_down {
                            continue;
                        }
                        st.keys[byte] &= !bit;
                        0
                    } else if was_down {
                        2 // typematic repeat
                    } else {
                        st.keys[byte] |= bit;
                        1
                    };
                    let q = &mut per_dev[0];
                    q.push(event(t, EV_MSC, MSC_SCAN, scan));
                    q.push(event(t, EV_KEY, code as u16, value));
                    q.push(event(t, EV_SYN, SYN_REPORT, 0));
                }
                Raw::Mouse(dx, dy, buttons) => {
                    let q = &mut per_dev[1];
                    for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
                        let bit = 1u8 << i;
                        if (buttons ^ st.buttons) & bit != 0 {
                            q.push(event(t, EV_KEY, *code, (buttons & bit != 0) as i32));
                        }
                    }
                    st.buttons = buttons;
                    if dx != 0 {
                        q.push(event(t, EV_REL, REL_X, dx as i32));
                    }
                    if dy != 0 {
                        q.push(event(t, EV_REL, REL_Y, dy as i32));
                    }
                    if !q.is_empty() && q.last().map_or(false, |e| e[16..18] != [0, 0]) {
                        q.push(event(t, EV_SYN, SYN_REPORT, 0));
                    }
                }
            }
        }
    }
    let mut clients = CLIENTS.lock();
    for (dev, events) in per_dev.iter().enumerate() {
        clients[dev].retain(|w| w.strong_count() > 0);
        if events.is_empty() {
            continue;
        }
        for f in clients[dev].iter().filter_map(|w| w.upgrade()) {
            if f.revoked.load(Ordering::Relaxed) {
                continue;
            }
            let mut q = f.queue.lock();
            if q.len() + events.len() > QUEUE_LIMIT {
                q.clear();
                q.push_back(event(crate::arch::pit::ticks(), EV_SYN, SYN_DROPPED, 0));
            }
            q.extend(events.iter().copied());
        }
    }
}

/// One open event device.
pub struct EvdevFile {
    dev: usize,
    queue: Mutex<VecDeque<[u8; 24]>>,
    nonblock: AtomicBool,
    revoked: AtomicBool,
}

/// Opens `event0` (minor 64, keyboard) or `event1` (minor 65, mouse).
pub fn open(minor: u64, nonblock: bool) -> Result<Arc<dyn CharDevice>, i64> {
    let dev = match minor {
        64 => 0,
        65 => 1,
        _ => return Err(ENXIO),
    };
    pump(); // input from before the open is not this file's
    let f = Arc::new(EvdevFile { dev, queue: Mutex::new(VecDeque::new()), nonblock: AtomicBool::new(nonblock), revoked: AtomicBool::new(false) });
    CLIENTS.lock()[dev].push(Arc::downgrade(&f));
    Ok(f)
}

/// Static description of a device.
struct Info {
    name: &'static str,
    phys: &'static str,
    id: [u16; 4],
}

const INFO: [Info; 2] = [
    Info { name: "AT Translated Set 2 keyboard", phys: "isa0060/serio0/input0", id: [0x11, 0x1, 0x1, 0xab41] },
    Info { name: "ImPS/2 Generic Wheel Mouse", phys: "isa0060/serio1/input0", id: [0x11, 0x2, 0x1, 0] },
];

/// Device names and identities for sysfs ([`super::devices`]).
pub fn device_info(dev: usize) -> (&'static str, &'static str, [u16; 4]) {
    let i = &INFO[dev];
    (i.name, i.phys, i.id)
}

fn set_bit(map: &mut [u8], bit: usize) {
    if bit / 8 < map.len() {
        map[bit / 8] |= 1 << (bit % 8);
    }
}

/// Capability bitmap of event type `ty` (0 = the event types themselves), in bytes.
pub fn capabilities(dev: usize, ty: u16) -> Vec<u8> {
    let bytes = match ty {
        0 => 8,
        EV_KEY => 96,
        EV_REL | EV_MSC | EV_LED | EV_REP => 8,
        0x03 | 0x05 | 0x12 => 8, // ABS, SW, SND
        0x15 => 16,              // FF
        _ => 8,
    };
    let mut m = alloc::vec![0u8; bytes];
    match (dev, ty) {
        (0, 0) => [EV_SYN, EV_KEY, EV_MSC, EV_LED, EV_REP].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (1, 0) => [EV_SYN, EV_KEY, EV_REL].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (0, EV_KEY) => {
            (1..=88).chain(96..=111).chain(125..=127).for_each(|k| set_bit(&mut m, k));
        }
        (1, EV_KEY) => [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().for_each(|&k| set_bit(&mut m, k as usize)),
        (1, EV_REL) => {
            set_bit(&mut m, REL_X as usize);
            set_bit(&mut m, REL_Y as usize);
        }
        (0, EV_MSC) => set_bit(&mut m, MSC_SCAN as usize),
        (0, EV_LED) => (0..3).for_each(|l| set_bit(&mut m, l)),
        _ => {}
    }
    m
}

impl EvdevFile {
    fn put(&self, arg: u64, size: usize, data: &[u8]) -> i64 {
        let n = size.min(data.len());
        if n > 0 && copy_out(arg, &data[..n]).is_err() {
            return EFAULT;
        }
        n as i64
    }
}

impl CharDevice for EvdevFile {
    fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.len() < 24 {
            return EINVAL;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&INPUT_WQ));
        loop {
            waits.register();
            if self.revoked.load(Ordering::Relaxed) {
                return ENODEV;
            }
            pump();
            {
                let mut q = self.queue.lock();
                let mut n = 0;
                while n + 24 <= buf.len() {
                    match q.pop_front() {
                        Some(e) => {
                            buf[n..n + 24].copy_from_slice(&e);
                            n += 24;
                        }
                        None => break,
                    }
                }
                if n > 0 {
                    return n as i64;
                }
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

    fn write(&self, data: &[u8]) -> i64 {
        // Writes inject events (LED state and the like): accepted and ignored
        (data.len() / 24 * 24) as i64
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        if (cmd >> 8) & 0xFF != 0x45 {
            return ENOTTY;
        }
        let nr = (cmd & 0xFF) as u16;
        let size = ((cmd >> 16) & 0x3FFF) as usize;
        let info = &INFO[self.dev];
        let cstr = |s: &str| {
            let mut v = Vec::from(s.as_bytes());
            v.push(0);
            v
        };
        match nr {
            0x01 => self.put(arg, 4, &0x0001_0001u32.to_le_bytes()).min(0), // EVIOCGVERSION
            0x02 => {
                // EVIOCGID
                let mut b = [0u8; 8];
                for (i, v) in info.id.iter().enumerate() {
                    b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
                }
                self.put(arg, 8, &b).min(0)
            }
            0x03 if cmd >> 30 == 2 => {
                // EVIOCGREP: delay 250 ms, period 33 ms
                if self.dev != 0 {
                    return ENOSYS;
                }
                let mut b = [0u8; 8];
                b[0..4].copy_from_slice(&250u32.to_le_bytes());
                b[4..8].copy_from_slice(&33u32.to_le_bytes());
                self.put(arg, 8, &b).min(0)
            }
            0x03 => 0, // EVIOCSREP
            0x06 => self.put(arg, size, &cstr(info.name)),
            0x07 => self.put(arg, size, &cstr(info.phys)),
            0x08 => self.put(arg, size, &[0]), // EVIOCGUNIQ: empty
            0x09 => self.put(arg, size, &[0u8; 8]), // EVIOCGPROP: no properties
            0x0a => EINVAL, // EVIOCGMTSLOTS: not multitouch
            0x18 => {
                // EVIOCGKEY: keys held down
                let st = STATE.lock();
                let mut keys = [0u8; 96];
                if self.dev == 0 {
                    keys = st.keys;
                } else {
                    for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
                        if st.buttons & (1 << i) != 0 {
                            set_bit(&mut keys, *code as usize);
                        }
                    }
                }
                drop(st);
                self.put(arg, size, &keys)
            }
            0x19 | 0x1a | 0x1b => self.put(arg, size, &[0u8; 8]), // LED / sound / switch state
            0x20..=0x3f => self.put(arg, size, &capabilities(self.dev, nr - 0x20)),
            0x40..=0x7f => EINVAL, // EVIOCGABS: no absolute axes
            0x80 | 0x81 => EINVAL, // force feedback upload / erase
            0x84 => self.put(arg, 4, &0u32.to_le_bytes()).min(0), // EVIOCGEFFECTS
            0x90 => 0, // EVIOCGRAB
            0x91 => {
                // EVIOCREVOKE: the file stops working for good (logind on session switch)
                self.revoked.store(true, Ordering::Relaxed);
                self.queue.lock().clear();
                INPUT_WQ.wake_all();
                0
            }
            0x92 | 0x93 => 0, // EVIOCGMASK / EVIOCSMASK
            0xa0 => 0,        // EVIOCSCLOCKID: timestamps are always monotonic
            _ => EINVAL,
        }
    }

    fn poll_events(&self) -> u32 {
        if self.revoked.load(Ordering::Relaxed) {
            return 0x0008 | 0x0010;
        }
        // Raw input not yet translated may hold events for this file
        if !self.queue.lock().is_empty() || (routing() && ring_pending()) {
            0x0001
        } else {
            0
        }
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Static(&INPUT_WQ));
    }

    fn rdev(&self) -> u64 {
        makedev(13, 64 + self.dev as u64)
    }

    fn path(&self) -> String {
        alloc::format!("/dev/input/event{}", self.dev)
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}
