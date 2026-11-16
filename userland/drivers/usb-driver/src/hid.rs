//! HID class pieces: finding HID interfaces in a configuration descriptor, translating
//! boot-protocol keyboard reports to set-1 scancodes, and reading pointer reports through
//! a (minimal) report descriptor parser.

use alloc::vec::Vec;

/// A HID interface with an interrupt IN endpoint.
pub struct HidFunction {
    pub number: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub ep_addr: u8,
    pub max_packet: u16,
    pub interval: u8,
    pub report_desc_len: u16,
}

/// The HID interfaces (alternate setting 0) of a configuration descriptor, each with its
/// first interrupt IN endpoint.
pub fn interfaces(conf: &[u8]) -> Vec<HidFunction> {
    let mut found: Vec<HidFunction> = Vec::new();
    let mut current: Option<HidFunction> = None;
    let mut at = 0;
    while at + 2 <= conf.len() {
        let (len, ty) = (conf[at] as usize, conf[at + 1]);
        if len < 2 || at + len > conf.len() {
            break;
        }
        let d = &conf[at..at + len];
        match ty {
            4 if len >= 9 => {
                // A new interface: the previous one ends here
                if let Some(f) = current.take().filter(|f| f.ep_addr != 0) {
                    found.push(f);
                }
                if d[5] == 3 && d[3] == 0 {
                    current = Some(HidFunction {
                        number: d[2],
                        subclass: d[6],
                        protocol: d[7],
                        ep_addr: 0,
                        max_packet: 0,
                        interval: 0,
                        report_desc_len: 0,
                    });
                }
            }
            0x21 if len >= 9 => {
                if let Some(f) = current.as_mut() {
                    f.report_desc_len = u16::from_le_bytes([d[7], d[8]]);
                }
            }
            5 if len >= 7 => {
                if let Some(f) = current.as_mut() {
                    if f.ep_addr == 0 && d[2] & 0x80 != 0 && d[3] & 3 == 3 {
                        f.ep_addr = d[2];
                        f.max_packet = u16::from_le_bytes([d[4], d[5]]);
                        f.interval = d[6];
                    }
                }
            }
            _ => {}
        }
        at += len;
    }
    if let Some(f) = current.filter(|f| f.ep_addr != 0) {
        found.push(f);
    }
    found
}

/// Set-1 scancode of each HID keyboard usage (0x00..0x65); `0x100` marks an `E0`
/// prefixed (extended) code, 0 no key.
const SET1: [u16; 0x66] = [
    0, 0, 0, 0, // 0x00..0x03: no event, rollover, POST fail, undefined
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, // a..l
    0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, // m..x
    0x15, 0x2C, // y, z
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // 1..0
    0x1C, 0x01, 0x0E, 0x0F, 0x39, // enter, escape, backspace, tab, space
    0x0C, 0x0D, 0x1A, 0x1B, 0x2B, 0x2B, 0x27, 0x28, 0x29, 0x33, 0x34, 0x35, // - = [ ] \ #~ ; ' ` , . /
    0x3A, // caps lock
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58, // F1..F12
    0x137, 0x46, 0, // print screen, scroll lock, pause (a sequence of its own: not sent)
    0x152, 0x147, 0x149, 0x153, 0x14F, 0x151, // insert, home, page up, delete, end, page down
    0x14D, 0x14B, 0x150, 0x148, // right, left, down, up
    0x45, 0x135, 0x37, 0x4A, 0x4E, 0x11C, // num lock, keypad / * - + enter
    0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49, 0x52, 0x53, // keypad 1..9, 0, .
    0x56, 0x15D, // non-US \|, application (menu)
];

/// Set-1 codes of the modifier keys, bits 0..7 of the report's first byte: left Ctrl,
/// Shift, Alt, GUI, then the right ones.
const MODIFIERS: [u16; 8] = [0x1D, 0x2A, 0x38, 0x15B, 0x11D, 0x36, 0x138, 0x15C];

/// Emits the scancode bytes of one key press or release.
fn emit_key(code: u16, release: bool, emit: &mut impl FnMut(u8)) {
    if code == 0 {
        return;
    }
    if code & 0x100 != 0 {
        emit(0xE0);
    }
    emit(code as u8 | if release { 0x80 } else { 0 });
}

/// Compares two boot-protocol keyboard reports (modifier bits, reserved byte, six key
/// usages) and emits the set-1 scancodes of what changed: releases first, then presses.
pub fn keyboard_changes(prev: &[u8; 8], cur: &[u8; 8], mut emit: impl FnMut(u8)) {
    for (bit, &code) in MODIFIERS.iter().enumerate() {
        let (was, is) = (prev[0] & (1 << bit) != 0, cur[0] & (1 << bit) != 0);
        if was && !is {
            emit_key(code, true, &mut emit);
        }
    }
    for &k in &prev[2..8] {
        if k >= 4 && (k as usize) < SET1.len() && !cur[2..8].contains(&k) {
            emit_key(SET1[k as usize], true, &mut emit);
        }
    }
    for (bit, &code) in MODIFIERS.iter().enumerate() {
        let (was, is) = (prev[0] & (1 << bit) != 0, cur[0] & (1 << bit) != 0);
        if is && !was {
            emit_key(code, false, &mut emit);
        }
    }
    for &k in &cur[2..8] {
        if k >= 4 && (k as usize) < SET1.len() && !prev[2..8].contains(&k) {
            emit_key(SET1[k as usize], false, &mut emit);
        }
    }
}

/// A value in a report: bit offset (after the report ID), size, logical range.
#[derive(Clone, Copy)]
pub struct Field {
    off: u32,
    size: u32,
    min: i32,
    max: i32,
}

impl Field {
    /// The field's value in `data` (sign-extended when the range is signed).
    fn get(&self, data: &[u8]) -> Option<i32> {
        if self.size == 0 || self.size > 32 || (self.off + self.size).div_ceil(8) as usize > data.len() {
            return None;
        }
        let mut v: u64 = 0;
        for i in 0..self.size {
            let bit = self.off + i;
            if data[(bit / 8) as usize] & (1 << (bit % 8)) != 0 {
                v |= 1 << i;
            }
        }
        if self.min < 0 && self.size < 64 && v & (1 << (self.size - 1)) != 0 {
            v |= !0u64 << self.size;
        }
        Some(v as i64 as i32)
    }
}

/// Where a pointer's values are in its reports.
pub struct Layout {
    report_id: Option<u8>,
    x: Field,
    y: Field,
    wheel: Option<Field>,
    buttons: [Option<Field>; 3],
    /// Absolute positions (a tablet or touch screen) rather than motion.
    pub absolute: bool,
}

impl Layout {
    /// Turns one report into an input record (see the protocol), or `None` if the report
    /// is another one (a different report ID) or too short.
    pub fn decode(&self, report: &[u8]) -> Option<[u8; 8]> {
        let data = match self.report_id {
            Some(id) => {
                if report.first() != Some(&id) {
                    return None;
                }
                &report[1..]
            }
            None => report,
        };
        let mut buttons = 0u8;
        for (i, b) in self.buttons.iter().enumerate() {
            if let Some(f) = b {
                if f.get(data).unwrap_or(0) != 0 {
                    buttons |= 1 << i;
                }
            }
        }
        let wheel = self.wheel.and_then(|w| w.get(data)).unwrap_or(0).clamp(-127, 127) as i8 as u8;
        let (x, y) = (self.x.get(data)?, self.y.get(data)?);
        if self.absolute {
            let scale = |v: i32, f: &Field| {
                let span = (f.max as i64 - f.min as i64).max(1);
                ((v as i64 - f.min as i64).clamp(0, span) * 0xFFFF / span) as u16
            };
            let (x, y) = (scale(x, &self.x).to_le_bytes(), scale(y, &self.y).to_le_bytes());
            Some([3, buttons, x[0], x[1], y[0], y[1], wheel, 0])
        } else {
            let (x, y) = ((x.clamp(-32768, 32767) as i16).to_le_bytes(), (y.clamp(-32768, 32767) as i16).to_le_bytes());
            Some([2, buttons, x[0], x[1], y[0], y[1], wheel, 0])
        }
    }
}

/// Global item state (pushed and popped as a whole).
#[derive(Clone, Copy, Default)]
struct Globals {
    page: u32,
    min: i32,
    max: i32,
    size: u32,
    count: u32,
    id: u8,
}

/// Reads a report descriptor and finds a pointer in it: X and Y on the generic desktop
/// page, with buttons and a wheel if present. Only input reports are considered, and only
/// the first report ID that has X.
pub fn parse(desc: &[u8]) -> Option<Layout> {
    let mut g = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    let mut usages: Vec<u32> = Vec::new();
    let (mut umin, mut umax) = (None::<u32>, None::<u32>);
    let mut uses_ids = false;
    // Bit offsets per report ID
    let mut offsets: Vec<(u8, u32)> = Vec::new();
    // (report id, usage (page << 16 | id), field, relative)
    let mut fields: Vec<(u8, u32, Field, bool)> = Vec::new();
    let mut at = 0;
    while at < desc.len() {
        let prefix = desc[at];
        if prefix == 0xFE {
            // A long item: skipped
            let len = *desc.get(at + 1)? as usize;
            at += 3 + len;
            continue;
        }
        let size = [0, 1, 2, 4][(prefix & 3) as usize];
        if at + 1 + size > desc.len() {
            break;
        }
        let raw = desc[at + 1..at + 1 + size].iter().rev().fold(0u32, |v, &b| v << 8 | b as u32);
        let signed = match size {
            1 => raw as u8 as i8 as i32,
            2 => raw as u16 as i16 as i32,
            _ => raw as i32,
        };
        let (ty, tag) = ((prefix >> 2) & 3, prefix >> 4);
        at += 1 + size;
        match (ty, tag) {
            // Main items
            (0, 8) => {
                let constant = raw & 1 != 0;
                let variable = raw & 2 != 0;
                let relative = raw & 4 != 0;
                let id = g.id;
                let pos = match offsets.iter().position(|o| o.0 == id) {
                    Some(p) => p,
                    None => {
                        offsets.push((id, 0));
                        offsets.len() - 1
                    }
                };
                for i in 0..g.count {
                    let usage = if let Some(lo) = umin {
                        let u = lo + i;
                        if umax.map_or(false, |hi| u > hi) { 0 } else { u }
                    } else {
                        usages.get(i as usize).or(usages.last()).copied().unwrap_or(0)
                    };
                    let usage = if usage >> 16 == 0 { g.page << 16 | usage } else { usage };
                    if !constant && variable {
                        fields.push((id, usage, Field { off: offsets[pos].1, size: g.size, min: g.min, max: g.max }, relative));
                    }
                    offsets[pos].1 += g.size;
                }
                usages.clear();
                umin = None;
                umax = None;
            }
            (0, _) => {
                usages.clear();
                umin = None;
                umax = None;
            }
            // Global items
            (1, 0) => g.page = raw,
            (1, 1) => g.min = signed,
            (1, 2) => g.max = if g.min >= 0 && size < 4 { raw as i32 } else { signed },
            (1, 7) => g.size = raw,
            (1, 8) => {
                g.id = raw as u8;
                uses_ids = true;
            }
            (1, 9) => g.count = raw,
            (1, 10) => stack.push(g),
            (1, 11) => g = stack.pop().unwrap_or(g),
            // Local items
            (2, 0) => usages.push(raw),
            (2, 1) => umin = Some(raw),
            (2, 2) => umax = Some(raw),
            _ => {}
        }
    }
    const X: u32 = 0x0001_0030;
    const Y: u32 = 0x0001_0031;
    const WHEEL: u32 = 0x0001_0038;
    let (id, _, x, rel) = *fields.iter().find(|f| f.1 == X)?;
    let y = fields.iter().find(|f| f.0 == id && f.1 == Y)?.2;
    let wheel = fields.iter().find(|f| f.0 == id && f.1 == WHEEL).map(|f| f.2);
    let button = |n: u32| fields.iter().find(|f| f.0 == id && f.1 == (0x0009_0000 | n)).map(|f| f.2);
    Some(Layout {
        report_id: uses_ids.then_some(id),
        x,
        y,
        wheel,
        buttons: [button(1), button(2), button(3)],
        absolute: !rel,
    })
}
