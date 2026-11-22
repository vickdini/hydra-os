//! # Raw records to Linux input events, and the event devices' answers
//!
//! The pure part of the input service (host-tested in `tests/host-w8-i`): the translation
//! of the kernel's raw input records ([`InputRec`]) into Linux `struct input_event`s per
//! device, the per-file event queue, and what each `EVIOC*` `ioctl` answers. Moved from the
//! kernel's `compat/linux/evdev.rs` (which stays as the switch back, `lx.input=kernel`);
//! the device names, identities and capabilities are the same, so programs and udev see
//! the same devices whichever side serves them, and after a restart of the service.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::protocol::{InputRec, INPUT_REC_ABS, INPUT_REC_KEY, INPUT_REC_REL, INPUT_REC_RELEASE};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_LED: u16 = 0x11;
pub const EV_REP: u16 = 0x14;
pub const SYN_REPORT: u16 = 0;
pub const SYN_DROPPED: u16 = 3;
pub const MSC_SCAN: u16 = 4;
pub const ABS_X: u16 = 0;
pub const ABS_Y: u16 = 1;
pub const REL_X: u16 = 0;
pub const REL_Y: u16 = 1;
pub const REL_WHEEL: u16 = 8;
pub const REL_WHEEL_HI_RES: u16 = 11;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

const ENOSYS: i64 = -38;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;

/// Event devices: keyboard (minor 64), relative mouse (65), absolute pointer (66).
pub const DEVICES: usize = 3;
/// Largest absolute coordinate.
pub const ABS_MAX: i32 = 0xFFFF;
/// Events a file may hold before older ones are dropped (and `SYN_DROPPED` reported).
pub const QUEUE_LIMIT: usize = 2048;

/// One Linux `struct input_event` (24 bytes: `timeval`, type, code, value).
pub type Event = [u8; 24];

/// Events per device produced by one batch of records.
pub type PerDev = [Vec<Event>; DEVICES];

/// An empty [`PerDev`].
pub fn per_dev() -> PerDev {
    [Vec::new(), Vec::new(), Vec::new()]
}

/// The device index of minor `minor` (`None`: not an event device of ours).
pub fn dev_of_minor(minor: u64) -> Option<usize> {
    match minor {
        64..=66 => Some((minor - 64) as usize),
        _ => None,
    }
}

/// Formats an event at `t` ns of the monotonic clock.
pub fn event(t: u64, ty: u16, code: u16, value: i32) -> Event {
    let us = t / 1_000;
    let mut e = [0u8; 24];
    e[0..8].copy_from_slice(&(us / 1_000_000).to_le_bytes());
    e[8..16].copy_from_slice(&(us % 1_000_000).to_le_bytes());
    e[16..18].copy_from_slice(&ty.to_le_bytes());
    e[18..20].copy_from_slice(&code.to_le_bytes());
    e[20..24].copy_from_slice(&value.to_le_bytes());
    e
}

/// An event's type.
pub fn ev_type(e: &Event) -> u16 {
    u16::from_le_bytes([e[16], e[17]])
}

/// The Linux key code of an `0xE0`-prefixed set-1 scancode (0: none).
pub fn e0_keycode(make: u8) -> u32 {
    match make {
        0x1C => 96,  // KP Enter
        0x1D => 97,  // Right Ctrl
        0x35 => 98,  // KP /
        0x38 => 100, // Right Alt
        0x47 => 102, // Home
        0x48 => 103, // Up
        0x49 => 104, // Page Up
        0x4B => 105, // Left
        0x4D => 106, // Right
        0x4F => 107, // End
        0x50 => 108, // Down
        0x51 => 109, // Page Down
        0x52 => 110, // Insert
        0x53 => 111, // Delete
        0x5B => 125, // Left Meta
        0x5C => 126, // Right Meta
        0x5D => 127, // Menu
        _ => 0,
    }
}

/// The translation state shared by the devices.
pub struct Translator {
    /// An `0xE0` prefix was seen.
    pub e0: bool,
    /// Keys held (bit per Linux key code).
    pub keys: [u8; 96],
    /// The relative mouse's buttons.
    pub buttons: u8,
    /// The absolute pointer's buttons and last position.
    pub abs_buttons: u8,
    pub abs_pos: (u16, u16),
}

impl Translator {
    /// Nothing held, the pointer in the middle.
    pub const fn new() -> Self {
        Self { e0: false, keys: [0; 96], buttons: 0, abs_buttons: 0, abs_pos: (0x8000, 0x8000) }
    }

    /// Queues a release for every held key and button and forgets them.
    pub fn release_all(&mut self, out: &mut PerDev, t: u64) {
        let mut q = per_dev();
        for code in 0..self.keys.len() * 8 {
            if self.keys[code / 8] & (1 << (code % 8)) != 0 {
                q[0].push(event(t, EV_KEY, code as u16, 0));
            }
        }
        self.keys = [0; 96];
        for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
            if self.buttons & (1 << i) != 0 {
                q[1].push(event(t, EV_KEY, *code, 0));
            }
            if self.abs_buttons & (1 << i) != 0 {
                q[2].push(event(t, EV_KEY, *code, 0));
            }
        }
        self.buttons = 0;
        self.abs_buttons = 0;
        self.e0 = false;
        for (d, mut q) in q.into_iter().enumerate() {
            if !q.is_empty() {
                q.push(event(t, EV_SYN, SYN_REPORT, 0));
                out[d].extend(q);
            }
        }
    }

    /// Translates one raw record into events, appended to `out`.
    pub fn feed(&mut self, r: &InputRec, out: &mut PerDev) {
        let t = r.time;
        match r.kind {
            INPUT_REC_RELEASE => self.release_all(out, t),
            INPUT_REC_KEY if r.code == 0xE0 => self.e0 = true,
            INPUT_REC_KEY => {
                let sc = r.code;
                let make = sc & 0x7F;
                let code = if self.e0 { e0_keycode(make) } else { make as u32 };
                let scan = if self.e0 { 0xE000 | make as i32 } else { make as i32 };
                self.e0 = false;
                if code == 0 || code >= 768 {
                    return;
                }
                let (byte, bit) = (code as usize / 8, 1u8 << (code % 8));
                let was_down = self.keys[byte] & bit != 0;
                let value = if sc & 0x80 != 0 {
                    if !was_down {
                        return;
                    }
                    self.keys[byte] &= !bit;
                    0
                } else if was_down {
                    2 // typematic repeat
                } else {
                    self.keys[byte] |= bit;
                    1
                };
                let q = &mut out[0];
                q.push(event(t, EV_MSC, MSC_SCAN, scan));
                q.push(event(t, EV_KEY, code as u16, value));
                q.push(event(t, EV_SYN, SYN_REPORT, 0));
            }
            INPUT_REC_REL => {
                let (dx, dy) = (r.x as i16, r.y as i16);
                let q = &mut out[1];
                let start = q.len();
                for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
                    let bit = 1u8 << i;
                    if (r.buttons ^ self.buttons) & bit != 0 {
                        q.push(event(t, EV_KEY, *code, (r.buttons & bit != 0) as i32));
                    }
                }
                self.buttons = r.buttons;
                if dx != 0 {
                    q.push(event(t, EV_REL, REL_X, dx as i32));
                }
                if dy != 0 {
                    q.push(event(t, EV_REL, REL_Y, dy as i32));
                }
                if r.wheel != 0 {
                    q.push(event(t, EV_REL, REL_WHEEL, r.wheel as i32));
                    q.push(event(t, EV_REL, REL_WHEEL_HI_RES, r.wheel as i32 * 120));
                }
                if q.len() > start {
                    q.push(event(t, EV_SYN, SYN_REPORT, 0));
                }
            }
            INPUT_REC_ABS => {
                let q = &mut out[2];
                let start = q.len();
                if (r.x, r.y) != self.abs_pos {
                    q.push(event(t, EV_ABS, ABS_X, r.x as i32));
                    q.push(event(t, EV_ABS, ABS_Y, r.y as i32));
                    self.abs_pos = (r.x, r.y);
                }
                for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
                    let bit = 1u8 << i;
                    if (r.buttons ^ self.abs_buttons) & bit != 0 {
                        q.push(event(t, EV_KEY, *code, (r.buttons & bit != 0) as i32));
                    }
                }
                self.abs_buttons = r.buttons;
                if r.wheel != 0 {
                    q.push(event(t, EV_REL, REL_WHEEL, r.wheel as i32));
                    q.push(event(t, EV_REL, REL_WHEEL_HI_RES, r.wheel as i32 * 120));
                }
                if q.len() > start {
                    q.push(event(t, EV_SYN, SYN_REPORT, 0));
                }
            }
            _ => {}
        }
    }

    /// The state worth keeping across a restart of the service (what is held, where the
    /// absolute pointer is), as [`SAVED_LEN`] bytes: version, keys, buttons, position.
    pub fn save(&self) -> [u8; SAVED_LEN] {
        let mut b = [0u8; SAVED_LEN];
        b[0] = SAVED_VERSION;
        b[1..97].copy_from_slice(&self.keys);
        b[97] = self.buttons;
        b[98] = self.abs_buttons;
        b[99..101].copy_from_slice(&self.abs_pos.0.to_le_bytes());
        b[101..103].copy_from_slice(&self.abs_pos.1.to_le_bytes());
        b
    }

    /// A translator in the state [`Translator::save`] wrote (`None`: not a saved state).
    pub fn restore(b: &[u8]) -> Option<Self> {
        if b.len() < SAVED_LEN || b[0] != SAVED_VERSION {
            return None;
        }
        let mut t = Self::new();
        t.keys.copy_from_slice(&b[1..97]);
        t.buttons = b[97] & 7;
        t.abs_buttons = b[98] & 7;
        t.abs_pos = (u16::from_le_bytes([b[99], b[100]]), u16::from_le_bytes([b[101], b[102]]));
        Some(t)
    }

    /// Whether anything is held (a key or a button).
    pub fn any_held(&self) -> bool {
        self.buttons != 0 || self.abs_buttons != 0 || self.keys.iter().any(|&k| k != 0)
    }

    /// `EVIOCGKEY` of device `dev`: the keys (or buttons) held.
    pub fn held(&self, dev: usize) -> [u8; 96] {
        if dev == 0 {
            return self.keys;
        }
        let mut keys = [0u8; 96];
        let held = if dev == 2 { self.abs_buttons } else { self.buttons };
        for (i, code) in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().enumerate() {
            if held & (1 << i) != 0 {
                set_bit(&mut keys, *code as usize);
            }
        }
        keys
    }
}

impl Default for Translator {
    fn default() -> Self {
        Self::new()
    }
}

/// Length of [`Translator::save`]'s record.
pub const SAVED_LEN: usize = 103;
/// Its version byte.
pub const SAVED_VERSION: u8 = 1;

/// Prepends `SYN_DROPPED` (at `t` ns) to every device's batch: records were lost in the
/// kernel's ring, so clients resynchronize (`EVIOCGKEY`), as after a Linux buffer overrun.
pub fn mark_dropped(out: &mut PerDev, t: u64) {
    for q in out.iter_mut() {
        q.insert(0, event(t, EV_SYN, SYN_DROPPED, 0));
    }
}

/// One open file's queue of events.
pub struct Queue {
    q: VecDeque<Event>,
}

impl Queue {
    /// Empty.
    pub const fn new() -> Self {
        Self { q: VecDeque::new() }
    }

    /// Appends `events` (at `now` ns); a file that would hold more than [`QUEUE_LIMIT`] loses
    /// what it holds and gets `SYN_DROPPED` first, as Linux does.
    pub fn extend(&mut self, events: &[Event], now: u64) {
        if events.is_empty() {
            return;
        }
        if self.q.len() + events.len() > QUEUE_LIMIT {
            self.q.clear();
            self.q.push_back(event(now, EV_SYN, SYN_DROPPED, 0));
        }
        self.q.extend(events.iter().copied());
    }

    /// Takes whole events into `buf` (a multiple of 24 bytes); returns the bytes filled.
    pub fn take(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n + 24 <= buf.len() {
            match self.q.pop_front() {
                Some(e) => {
                    buf[n..n + 24].copy_from_slice(&e);
                    n += 24;
                }
                None => break,
            }
        }
        n
    }

    /// Events waiting.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Whether none wait.
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// Drops every event.
    pub fn clear(&mut self) {
        self.q.clear();
    }
}

impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}

/// Static description of a device.
pub struct Info {
    pub name: &'static str,
    pub phys: &'static str,
    pub id: [u16; 4],
}

/// The devices, as the kernel's `evdev.rs` (and Linux's drivers) name them.
pub const INFO: [Info; DEVICES] = [
    Info { name: "AT Translated Set 2 keyboard", phys: "isa0060/serio0/input0", id: [0x11, 0x1, 0x1, 0xab41] },
    Info { name: "ImPS/2 Generic Wheel Mouse", phys: "isa0060/serio1/input0", id: [0x11, 0x2, 0x1, 0] },
    Info { name: "VirtualPS/2 VMware VMMouse", phys: "isa0060/serio1/input1", id: [0x11, 0x2, 0x13, 0] },
];

/// Sets bit `bit` of `map`.
pub fn set_bit(map: &mut [u8], bit: usize) {
    if bit / 8 < map.len() {
        map[bit / 8] |= 1 << (bit % 8);
    }
}

/// Capability bitmap of event type `ty` (0: the event types themselves) of device `dev`.
pub fn capabilities(dev: usize, ty: u16) -> Vec<u8> {
    let bytes = match ty {
        EV_KEY => 96,
        0x15 => 16, // FF
        _ => 8,
    };
    let mut m = alloc::vec![0u8; bytes];
    match (dev, ty) {
        (0, 0) => [EV_SYN, EV_KEY, EV_MSC, EV_LED, EV_REP].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (1, 0) => [EV_SYN, EV_KEY, EV_REL].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (2, 0) => [EV_SYN, EV_KEY, EV_REL, EV_ABS].iter().for_each(|&t| set_bit(&mut m, t as usize)),
        (2, EV_KEY) | (1, EV_KEY) => [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].iter().for_each(|&k| set_bit(&mut m, k as usize)),
        (2, EV_REL) => [REL_WHEEL, REL_WHEEL_HI_RES].iter().for_each(|&c| set_bit(&mut m, c as usize)),
        (2, EV_ABS) => [ABS_X, ABS_Y].iter().for_each(|&c| set_bit(&mut m, c as usize)),
        (0, EV_KEY) => (1..=88).chain(96..=111).chain(125..=127).for_each(|k| set_bit(&mut m, k)),
        (1, EV_REL) => [REL_X, REL_Y, REL_WHEEL, REL_WHEEL_HI_RES].iter().for_each(|&c| set_bit(&mut m, c as usize)),
        (0, EV_MSC) => set_bit(&mut m, MSC_SCAN as usize),
        (0, EV_LED) => (0..3).for_each(|l| set_bit(&mut m, l)),
        _ => {}
    }
    m
}

/// What an `ioctl` on an event device answers.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// Copy at most `cap` bytes of `data` to the argument; return the bytes copied
    /// (`len` true) or 0.
    Out { data: Vec<u8>, cap: usize, len: bool },
    /// Return this at once.
    Val(i64),
    /// `EVIOCREVOKE`: the file stops working for good; return 0.
    Revoke,
    /// `EVIOCGRAB`: the argument (non-zero: grab, 0: let go) makes the file the device's
    /// only receiver, or ends that.
    Grab,
}

/// The answer to `ioctl(cmd)` on device `dev` (translation state `st`).
pub fn ioctl(dev: usize, cmd: u64, st: &Translator) -> Answer {
    use Answer::*;
    if (cmd >> 8) & 0xFF != 0x45 || dev >= DEVICES {
        return Val(ENOTTY);
    }
    let nr = (cmd & 0xFF) as u16;
    let size = ((cmd >> 16) & 0x3FFF) as usize;
    let info = &INFO[dev];
    let cstr = |s: &str| {
        let mut v = Vec::from(s.as_bytes());
        v.push(0);
        v
    };
    match nr {
        0x01 => Out { data: 0x0001_0001u32.to_le_bytes().to_vec(), cap: 4, len: false }, // EVIOCGVERSION
        0x02 => {
            // EVIOCGID
            let mut b = alloc::vec![0u8; 8];
            for (i, v) in info.id.iter().enumerate() {
                b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
            Out { data: b, cap: 8, len: false }
        }
        0x03 if cmd >> 30 == 2 => {
            // EVIOCGREP: delay 250 ms, period 33 ms
            if dev != 0 {
                return Val(ENOSYS);
            }
            let mut b = alloc::vec![0u8; 8];
            b[0..4].copy_from_slice(&250u32.to_le_bytes());
            b[4..8].copy_from_slice(&33u32.to_le_bytes());
            Out { data: b, cap: 8, len: false }
        }
        0x03 => Val(0), // EVIOCSREP
        0x06 => Out { data: cstr(info.name), cap: size, len: true },
        0x07 => Out { data: cstr(info.phys), cap: size, len: true },
        0x08 => Out { data: alloc::vec![0], cap: size, len: true },     // EVIOCGUNIQ: empty
        0x09 => Out { data: alloc::vec![0; 8], cap: size, len: true },  // EVIOCGPROP: none
        0x0a => Val(EINVAL),                                             // EVIOCGMTSLOTS
        0x18 => Out { data: st.held(dev).to_vec(), cap: size, len: true }, // EVIOCGKEY
        0x19..=0x1b => Out { data: alloc::vec![0; 8], cap: size, len: true }, // LED / sound / switch
        0x20..=0x3f => Out { data: capabilities(dev, nr - 0x20), cap: size, len: true },
        0x40 | 0x41 if dev == 2 => {
            // EVIOCGABS(ABS_X / ABS_Y): struct input_absinfo
            let value = if nr == 0x40 { st.abs_pos.0 } else { st.abs_pos.1 } as i32;
            let mut b = alloc::vec![0u8; 24];
            b[0..4].copy_from_slice(&value.to_le_bytes());
            b[8..12].copy_from_slice(&ABS_MAX.to_le_bytes());
            Out { data: b, cap: size, len: false }
        }
        0x40..=0x7f => Val(EINVAL),
        0x80 | 0x81 => Val(EINVAL),
        0x84 => Out { data: alloc::vec![0; 4], cap: 4, len: false }, // EVIOCGEFFECTS
        0x90 => Grab, // EVIOCGRAB: the caller decides with the argument
        0x91 => Revoke,
        0x92 | 0x93 => Val(0), // EVIOCGMASK / EVIOCSMASK
        0xa0 => Val(0),        // EVIOCSCLOCKID
        _ => Val(EINVAL),
    }
}

/// `EVIOCGRAB` on the file in slot `slot` of a device grabbed by `current`: `on` grabs
/// (`EBUSY` when another file holds it), off lets go (`EINVAL` when this file does not
/// hold it), as Linux's evdev. The device's grabber afterwards.
pub fn grab(current: Option<u32>, slot: u32, on: bool) -> Result<Option<u32>, i64> {
    match (current, on) {
        (Some(g), true) if g != slot => Err(-16),
        (_, true) => Ok(Some(slot)),
        (Some(g), false) if g == slot => Ok(None),
        (_, false) => Err(EINVAL),
    }
}

/// Whether the file in slot `slot` gets events of a device grabbed by `grabber`.
pub fn receives(grabber: Option<u32>, slot: u32) -> bool {
    grabber.map_or(true, |g| g == slot)
}
