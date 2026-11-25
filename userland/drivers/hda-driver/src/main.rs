//! # Hydra sound driver: Intel High Definition Audio
//!
//! Drives an Intel High Definition Audio controller (PCI class 04:03; QEMU's `intel-hda`,
//! and the audio controller of nearly every PC since 2004) and its codecs from Ring 3. The
//! kernel enumerates PCI (enabling bus mastering) and starts it with `mmio=<phys>`; the
//! controller's registers are the device memory the supervisor granted, its command rings
//! (CORB/RIRB) and buffer descriptor lists DMA memory it allocates.
//!
//! At start the driver resets the controller, finds the codecs, and in the first audio
//! function group that has one picks
//! - a playback path: an analog output pin (line out, speaker, headphone) and the audio
//!   output converter (DAC) it reaches through selectors and mixers;
//! - a capture path: an audio input converter (ADC) and an analog input pin (microphone,
//!   line in) it reaches.
//! It powers the widgets on the paths, selects their connections, unmutes them at 0 dB,
//! and enables the pins. The volume of each direction is the first amplifier with steps
//! on its path, counted from the converter.
//!
//! The audio itself never passes through the driver: the kernel owns the ring buffers
//! (`/dev/snd/pcmC0D0p` and `pcmC0D0c` map them into programs) and asks the driver to
//! point a stream descriptor at one ([`MSG_SND_SETUP`]); the controller then moves the
//! samples by DMA and writes each stream's position into a buffer the kernel reads
//! (`DPLBASE`). So the driver needs no interrupts: it only answers requests.
//!
//! Requests on [`ENDPOINT_SOUND_DEV`]: see the `MSG_SND_*` codes in `ipc/protocol.rs`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use hydra_rt::protocol::{
    ENDPOINT_SOUND_DEV, MSG_SND_INFO, MSG_SND_POSITION, MSG_SND_REPLY, MSG_SND_SETUP, MSG_SND_TRIGGER, MSG_SND_VOLUME,
};
use hydra_rt::{println, sys, Message, Server};

hydra_rt::entry!(main);

// ---- Controller registers ----
const GCAP: usize = 0x00;
const GCTL: usize = 0x08;
const STATESTS: usize = 0x0E;
const INTCTL: usize = 0x20;
const CORBLBASE: usize = 0x40;
const CORBUBASE: usize = 0x44;
const CORBWP: usize = 0x48;
const CORBRP: usize = 0x4A;
const CORBCTL: usize = 0x4C;
const CORBSIZE: usize = 0x4E;
const RIRBLBASE: usize = 0x50;
const RIRBUBASE: usize = 0x54;
const RIRBWP: usize = 0x58;
const RINTCNT: usize = 0x5A;
const RIRBCTL: usize = 0x5C;
const RIRBSTS: usize = 0x5D;
const RIRBSIZE: usize = 0x5E;
const DPLBASE: usize = 0x70;
const DPUBASE: usize = 0x74;
// wave11 GG: the immediate command interface (a fallback when the rings get no answer)
const ICOI: usize = 0x60;
const ICII: usize = 0x64;
const ICIS: usize = 0x68;
const ICIS_BUSY: u16 = 1 << 0;
const ICIS_VALID: u16 = 1 << 1;

// Stream descriptor registers (offsets in a descriptor)
const SD_CTL: usize = 0x00;
const SD_STS: usize = 0x03;
const SD_LPIB: usize = 0x04;
const SD_CBL: usize = 0x08;
const SD_LVI: usize = 0x0C;
const SD_FMT: usize = 0x12;
const SD_BDPL: usize = 0x18;
const SD_BDPU: usize = 0x1C;
const SD_CTL_SRST: u32 = 1 << 0;
const SD_CTL_RUN: u32 = 1 << 1;

// ---- Codec verbs and parameters ----
const VERB_GET_PARAM: u32 = 0xF00;
const VERB_GET_CONN_LIST: u32 = 0xF02;
const VERB_SET_CONN_SELECT: u32 = 0x701;
const VERB_SET_POWER_STATE: u32 = 0x705;
const VERB_SET_STREAM_CHANNEL: u32 = 0x706;
const VERB_SET_PIN_CTL: u32 = 0x707;
const VERB_SET_EAPD: u32 = 0x70C;
// wave11 GG: Realtek's processing coefficients (on the vendor widget 0x20)
const VERB_SET_COEF_INDEX: u32 = 0x5;
const VERB_GET_PROC_COEF: u32 = 0xC;
const VERB_SET_PROC_COEF: u32 = 0x4;
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C;
/// 4-bit verbs (16-bit payload).
const VERB4_SET_FORMAT: u32 = 0x2;
const VERB4_SET_AMP: u32 = 0x3;

const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_NODE_COUNT: u32 = 0x04;
const PARAM_FUNCTION_TYPE: u32 = 0x05;
const PARAM_WIDGET_CAPS: u32 = 0x09;
const PARAM_PIN_CAPS: u32 = 0x0C;
const PARAM_AMP_IN_CAPS: u32 = 0x0D;
const PARAM_CONN_LIST_LEN: u32 = 0x0E;
const PARAM_AMP_OUT_CAPS: u32 = 0x12;

// Widget types (widget capabilities bits 23:20)
const WT_OUTPUT: u8 = 0;
const WT_INPUT: u8 = 1;
const WT_MIXER: u8 = 2;
const WT_SELECTOR: u8 = 3;
const WT_PIN: u8 = 4;

const WCAP_IN_AMP: u32 = 1 << 1;
const WCAP_OUT_AMP: u32 = 1 << 2;
const WCAP_AMP_OVERRIDE: u32 = 1 << 3;
const WCAP_CONN_LIST: u32 = 1 << 8;
const WCAP_DIGITAL: u32 = 1 << 9;
const WCAP_POWER: u32 = 1 << 10;

const PINCAP_OUT: u32 = 1 << 4;
const PINCAP_IN: u32 = 1 << 5;
const PINCAP_EAPD: u32 = 1 << 16;

const PIN_OUT_EN: u32 = 0x40;
const PIN_HP_EN: u32 = 0x80;
const PIN_IN_EN: u32 = 0x20;

// Default device types (configuration default bits 23:20)
const DEV_LINE_OUT: u32 = 0x0;
const DEV_SPEAKER: u32 = 0x1;
const DEV_HP_OUT: u32 = 0x2;
const DEV_LINE_IN: u32 = 0x8;
const DEV_MIC_IN: u32 = 0xA;

// ---- DMA memory layout ----
const DMA_LEN: usize = 4 * 4096;
const CORB_OFF: usize = 0x0000;
const RIRB_OFF: usize = 0x0800;
/// One buffer descriptor list per direction (256 entries of 16 bytes).
const BDL_OFF: [usize; 2] = [0x1000, 0x2000];
const BDL_MAX: usize = 256;

/// Stream tags given to the two streams.
const TAG: [u32; 2] = [1, 2];

const EIO: i64 = -5;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;

/// Value of a `key=<number>` argument (decimal or `0x` hex).
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Spins until `cond` holds or about `ms` milliseconds passed; whether it holds.
fn wait_for(ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let end = sys::uptime_ticks() + ms.div_ceil(10) + 1;
    loop {
        if cond() {
            return true;
        }
        if sys::uptime_ticks() >= end {
            return cond();
        }
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    }
}

/// The controller's register window.
#[derive(Clone, Copy)]
struct Regs(*mut u8);

impl Regs {
    fn r8(self, off: usize) -> u8 {
        unsafe { self.0.add(off).read_volatile() }
    }
    fn r16(self, off: usize) -> u16 {
        unsafe { (self.0.add(off) as *const u16).read_volatile() }
    }
    fn r32(self, off: usize) -> u32 {
        unsafe { (self.0.add(off) as *const u32).read_volatile() }
    }
    fn w8(self, off: usize, v: u8) {
        unsafe { self.0.add(off).write_volatile(v) }
    }
    fn w16(self, off: usize, v: u16) {
        unsafe { (self.0.add(off) as *mut u16).write_volatile(v) }
    }
    fn w32(self, off: usize, v: u32) {
        unsafe { (self.0.add(off) as *mut u32).write_volatile(v) }
    }
}

// wave11 GG begin
/// Writes the cache line holding `p` back to memory and drops it (`clflush`), so the
/// controller sees what the CPU wrote and the CPU then reads what the controller wrote,
/// even when the controller's DMA does not snoop the caches (an Intel PCH whose firmware
/// left "no snoop" on; the kernel also turns that off, see `hda_args`).
fn flush_line(p: *const u8) {
    // SAFETY: `clflush` of a mapped address; `mfence` orders it with the accesses around it
    unsafe { core::arch::asm!("mfence", "clflush [{0}]", "mfence", in(reg) p, options(nostack, preserves_flags)) };
}

/// How the driver talks to the codecs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Transport {
    /// The command and response rings (CORB/RIRB), as normal.
    Rings,
    /// The immediate command registers (`ICOI`/`ICII`/`ICIS`), one verb at a time: Linux's
    /// `single_cmd` fallback for controllers whose rings stay silent.
    Immediate,
}
// wave11 GG end

/// One widget of an audio function group.
#[derive(Clone, Default)]
struct Widget {
    nid: u8,
    ty: u8,
    caps: u32,
    conns: Vec<u8>,
    pincap: u32,
    config: u32,
    amp_in: u32,
    amp_out: u32,
}

/// An amplifier: the widget, its direction (output amp, or input amp `index`) and its
/// capabilities.
#[derive(Clone, Copy)]
struct Amp {
    nid: u8,
    out: bool,
    index: u8,
    caps: u32,
}

impl Amp {
    fn offset(&self) -> u32 {
        self.caps & 0x7F
    }
    fn steps(&self) -> u32 {
        (self.caps >> 8) & 0x7F
    }
    /// The capabilities as [`MSG_SND_INFO`] reports them.
    fn describe(&self) -> u64 {
        let c = self.caps;
        ((c >> 8) & 0x7F) as u64 | ((c & 0x7F) as u64) << 8 | (((c >> 16) & 0x7F) as u64) << 16 | 1 << 24 | ((c >> 31) as u64) << 25
    }
}

/// A configured direction: the converter, the paths to its pins, its volume.
struct Route {
    /// Converter widget (DAC or ADC).
    conv: u8,
    /// Pins it plays to (or the one it records from).
    pins: Vec<u8>,
    /// Volume amplifier.
    volume: Option<Amp>,
    /// Stream descriptor register offset.
    sd: usize,
    /// Slot of the stream in the position buffer.
    slot: usize,
    /// Whether the stream was set up.
    ready: bool,
}

struct Hda {
    regs: Regs,
    mem: *mut u8,
    mem_phys: u64,
    corb_entries: usize,
    rirb_entries: usize,
    corb_wp: usize,
    rirb_rp: usize,
    codec: u32,
    vendor: u32,
    afg: u8,
    widgets: Vec<Widget>,
    routes: [Option<Route>; 2],
    timeouts: u32,
    /// wave11 GG: rings or immediate commands.
    transport: Transport,
    /// wave11 GG: how long a verb may take (ms): long for the first verbs of a codec.
    verb_ms: u64,
}

impl Hda {
    // ---- Command transport (CORB/RIRB) ----

    /// Sends `cmd` and returns the codec's response (`None` if it gave none).
    fn command(&mut self, cmd: u32) -> Option<u32> {
        if self.transport == Transport::Immediate {
            return self.command_immediate(cmd);
        }
        let r = self.regs;
        let wp = (self.corb_wp + 1) % self.corb_entries;
        let slot = unsafe { self.mem.add(CORB_OFF + wp * 4) };
        unsafe { (slot as *mut u32).write_volatile(cmd) };
        // wave11 GG: in memory before the controller is told
        flush_line(slot);
        self.corb_wp = wp;
        r.w16(CORBWP, wp as u16);
        let mut resp = None;
        let rirb_entries = self.rirb_entries;
        let got = wait_for(self.verb_ms, || {
            loop {
                let hw = (r.r16(RIRBWP) & 0xFF) as usize % rirb_entries;
                if hw == self.rirb_rp {
                    return false;
                }
                self.rirb_rp = (self.rirb_rp + 1) % rirb_entries;
                let e = unsafe { self.mem.add(RIRB_OFF + self.rirb_rp * 8) as *const u32 };
                // wave11 GG: what the controller wrote, not a stale cached copy
                flush_line(e as *const u8);
                let (value, ex) = unsafe { (e.read_volatile(), e.add(1).read_volatile()) };
                // An interrupt cause the controller counts responses with: acknowledge it,
                // or it stops at RINTCNT responses
                r.w8(RIRBSTS, 0x05);
                if ex & 0x10 == 0 {
                    resp = Some(value);
                    return true;
                }
                // Unsolicited response (a jack event): not ours
            }
        });
        if !got {
            self.timeouts += 1;
            if self.timeouts <= 4 {
                println!("[hda-driver] no response to verb {:#010x} ({})", cmd, self.ring_state());
            }
        }
        resp
    }

    // wave11 GG begin
    /// The command path's registers, for the log when a codec stays silent.
    fn ring_state(&self) -> String {
        let r = self.regs;
        alloc::format!(
            "GCTL {:#x} STATESTS {:#x} CORBWP {} CORBRP {:#x} CORBCTL {:#x} CORBSIZE {:#x} RIRBWP {} RIRBCTL {:#x} RIRBSTS {:#x} RINTCNT {} ICIS {:#x}",
            r.r32(GCTL),
            r.r16(STATESTS),
            r.r16(CORBWP),
            r.r16(CORBRP),
            r.r8(CORBCTL),
            r.r8(CORBSIZE),
            r.r16(RIRBWP),
            r.r8(RIRBCTL),
            r.r8(RIRBSTS),
            r.r16(RINTCNT),
            r.r16(ICIS)
        )
    }

    /// Sends `cmd` through the immediate command registers.
    fn command_immediate(&mut self, cmd: u32) -> Option<u32> {
        let r = self.regs;
        if !wait_for(self.verb_ms, || r.r16(ICIS) & ICIS_BUSY == 0) {
            self.timeouts += 1;
            return None;
        }
        // Clear "result valid" (write 1), the verb, then "busy" starts it
        r.w16(ICIS, r.r16(ICIS) | ICIS_VALID);
        r.w32(ICOI, cmd);
        r.w16(ICIS, (r.r16(ICIS) & !ICIS_VALID) | ICIS_BUSY);
        if wait_for(self.verb_ms, || r.r16(ICIS) & (ICIS_VALID | ICIS_BUSY) == ICIS_VALID) {
            return Some(r.r32(ICII));
        }
        self.timeouts += 1;
        if self.timeouts <= 4 {
            println!("[hda-driver] no immediate response to verb {:#010x} ({})", cmd, self.ring_state());
        }
        None
    }

    /// Stops the command rings and talks to the codecs through the immediate command
    /// registers from now on (the rings must not run while they are used).
    fn use_immediate(&mut self) {
        let r = self.regs;
        r.w8(CORBCTL, 0);
        r.w8(RIRBCTL, 0);
        wait_for(10, || r.r8(CORBCTL) & 2 == 0 && r.r8(RIRBCTL) & 2 == 0);
        self.transport = Transport::Immediate;
    }

    /// The codec's vendor id, asked patiently: up to three tries on the rings with a long
    /// timeout, then the immediate command registers. 0 if it never answers.
    fn wake_codec(&mut self, codec: u32) -> u32 {
        self.codec = codec;
        self.verb_ms = 200;
        let mut id = 0;
        for _ in 0..3 {
            id = self.param(0, PARAM_VENDOR_ID);
            if id != 0 && id != 0xFFFF_FFFF {
                break;
            }
        }
        if (id == 0 || id == 0xFFFF_FFFF) && self.transport == Transport::Rings {
            println!("[hda-driver] codec {}: the command rings got no answer; trying the immediate command registers", codec);
            self.use_immediate();
            id = self.param(0, PARAM_VENDOR_ID);
        }
        self.verb_ms = 50;
        id
    }

    /// A Realtek processing coefficient: read, then `(old & !mask) | set`.
    fn realtek_coef(&mut self, index: u32, mask: u32, set: u32) {
        const VENDOR_NID: u8 = 0x20;
        self.verb4(VENDOR_NID, VERB_SET_COEF_INDEX, index);
        let old = self.verb4(VENDOR_NID, VERB_GET_PROC_COEF, 0) & 0xFFFF;
        self.verb4(VENDOR_NID, VERB_SET_COEF_INDEX, index);
        self.verb4(VENDOR_NID, VERB_SET_PROC_COEF, (old & !mask) | set);
    }

    /// Codec-specific set-up Linux's `patch_realtek.c` does for the codecs of the machines
    /// Hydra runs on: the ALC283 (the user's NUC) needs its headphone amplifier out of
    /// the "capless" low-power mode and the combo jack's 3k pull-down off, or the front
    /// headphone jack stays silent.
    fn codec_fixups(&mut self) {
        match self.vendor {
            0x10EC_0283 => {
                // Index 0x43: direct-drive headphone amplifier, normal mode
                self.realtek_coef(0x43, 0xFFFF, 0x9614);
                // Index 0x46 bits 13:12: the headset jack's 3k pull-down off
                self.realtek_coef(0x46, 3 << 12, 0);
                println!("[hda-driver] Realtek ALC283: headphone amplifier and combo jack set up");
            }
            _ => {}
        }
    }
    // wave11 GG end

    /// A 12-bit verb with an 8-bit payload to widget `nid`.
    fn verb(&mut self, nid: u8, verb: u32, payload: u32) -> u32 {
        self.command(self.codec << 28 | (nid as u32) << 20 | verb << 8 | (payload & 0xFF)).unwrap_or(0)
    }

    /// A 4-bit verb with a 16-bit payload to widget `nid`.
    fn verb4(&mut self, nid: u8, verb: u32, payload: u32) -> u32 {
        self.command(self.codec << 28 | (nid as u32) << 20 | verb << 16 | (payload & 0xFFFF)).unwrap_or(0)
    }

    fn param(&mut self, nid: u8, p: u32) -> u32 {
        self.verb(nid, VERB_GET_PARAM, p)
    }

    // ---- Controller ----

    /// Resets the controller and starts the command rings; the codecs present (bit mask).
    fn reset(&mut self) -> u16 {
        let r = self.regs;
        // Stop the command rings and every stream the firmware may have left running
        r.w8(CORBCTL, 0);
        r.w8(RIRBCTL, 0);
        wait_for(10, || r.r8(CORBCTL) & 2 == 0 && r.r8(RIRBCTL) & 2 == 0);
        let gcap = r.r16(GCAP);
        let streams = ((gcap >> 8) & 0xF) + ((gcap >> 12) & 0xF) + ((gcap >> 3) & 0x1F);
        for i in 0..streams as usize {
            let sd = 0x80 + i * 0x20;
            r.w32(sd + SD_CTL, r.r32(sd + SD_CTL) & !(SD_CTL_RUN | 0xFF00_0000));
        }
        r.w32(DPLBASE, 0);
        r.w32(INTCTL, 0);
        r.w16(STATESTS, 0x7FFF);
        // Controller reset: CRST low, then high; the codecs then announce themselves
        // (wave11 GG: the waits as Linux's `azx_reset`: >= 100 us in reset for the codecs'
        // clocks, >= 521 us after it before they ask for an address)
        r.w32(GCTL, r.r32(GCTL) & !1);
        if !wait_for(100, || r.r32(GCTL) & 1 == 0) {
            println!("[hda-driver] the controller did not enter reset (GCTL {:#x})", r.r32(GCTL));
        }
        sys::sleep_ms(1);
        r.w32(GCTL, r.r32(GCTL) | 1);
        if !wait_for(100, || r.r32(GCTL) & 1 == 1) {
            println!("[hda-driver] the controller did not leave reset");
        }
        sys::sleep_ms(2);
        let mut codecs = 0;
        wait_for(100, || {
            codecs = r.r16(STATESTS) & 0x7FFF;
            codecs != 0
        });
        r.w16(STATESTS, 0x7FFF);

        // CORB: the largest size the controller offers
        let size = |caps: u8| -> (u8, usize) {
            if caps & 0x40 != 0 {
                (2, 256)
            } else if caps & 0x20 != 0 {
                (1, 16)
            } else {
                (0, 2)
            }
        };
        // (no size capability bits: a fixed 256-entry ring)
        let caps = r.r8(CORBSIZE);
        let (code, n) = if caps & 0xF0 == 0 { (2, 256) } else { size(caps) };
        r.w8(CORBSIZE, (r.r8(CORBSIZE) & !3) | code);
        self.corb_entries = n;
        let corb = self.mem_phys + CORB_OFF as u64;
        r.w32(CORBLBASE, corb as u32);
        r.w32(CORBUBASE, (corb >> 32) as u32);
        // wave11 GG: the rings' memory clean and in memory (not only in this CPU's cache)
        unsafe { core::ptr::write_bytes(self.mem.add(CORB_OFF), 0, 0x1000) };
        for off in (0..0x1000).step_by(64) {
            flush_line(unsafe { self.mem.add(CORB_OFF + off) });
        }
        // Write pointer first, then the read pointer reset (as Linux's `azx_init_cmd_io`;
        // the bit reads back set on real controllers; QEMU clears it at once)
        r.w16(CORBWP, 0);
        r.w16(CORBRP, 0x8000);
        wait_for(10, || r.r16(CORBRP) & 0x8000 != 0);
        r.w16(CORBRP, 0);
        wait_for(10, || r.r16(CORBRP) & 0x8000 == 0);
        r.w16(CORBWP, 0);
        self.corb_wp = 0;

        let caps = r.r8(RIRBSIZE);
        let (code, n) = if caps & 0xF0 == 0 { (2, 256) } else { size(caps) };
        r.w8(RIRBSIZE, (r.r8(RIRBSIZE) & !3) | code);
        self.rirb_entries = n;
        let rirb = self.mem_phys + RIRB_OFF as u64;
        r.w32(RIRBLBASE, rirb as u32);
        r.w32(RIRBUBASE, (rirb >> 32) as u32);
        r.w16(RIRBWP, 0x8000);
        self.rirb_rp = 0;
        // One response per "interrupt" (with interrupts off at INTCTL, a status bit the
        // command loop acknowledges)
        r.w16(RINTCNT, 1);
        r.w8(RIRBSTS, 0x05);
        r.w8(CORBCTL, 0x02);
        r.w8(RIRBCTL, 0x03);
        wait_for(10, || r.r8(CORBCTL) & 2 != 0);
        // wave11 GG: the rings again after a fallback to immediate commands
        self.transport = Transport::Rings;
        codecs
    }

    // ---- Codec discovery ----

    /// Reads the connection list of widget `nid` (`len` = its list length parameter).
    fn connections(&mut self, nid: u8) -> Vec<u8> {
        let len_param = self.param(nid, PARAM_CONN_LIST_LEN);
        let long = len_param & 0x80 != 0;
        let count = (len_param & 0x7F) as usize;
        let per = if long { 2 } else { 4 };
        let mut out: Vec<u8> = Vec::new();
        let mut i = 0;
        while i < count {
            let v = self.verb(nid, VERB_GET_CONN_LIST, i as u32);
            for k in 0..per {
                if i + k >= count {
                    break;
                }
                let (range, id) = if long {
                    let e = (v >> (16 * k)) & 0xFFFF;
                    (e & 0x8000 != 0, (e & 0x7FFF) as u8)
                } else {
                    let e = (v >> (8 * k)) & 0xFF;
                    (e & 0x80 != 0, (e & 0x7F) as u8)
                };
                match (range, out.last().copied()) {
                    (true, Some(prev)) if id > prev => {
                        for n in prev + 1..=id {
                            out.push(n);
                        }
                    }
                    _ => out.push(id),
                }
            }
            i += per;
        }
        out
    }

    /// Finds the first audio function group of codec `codec` and reads its widgets.
    fn probe_codec(&mut self, codec: u32) -> bool {
        // wave11 GG: patient for the first answer, with the immediate registers as fallback
        self.vendor = self.wake_codec(codec);
        if self.vendor == 0 || self.vendor == 0xFFFF_FFFF {
            println!("[hda-driver] codec {} does not answer", codec);
            return false;
        }
        let nodes = self.param(0, PARAM_NODE_COUNT);
        let (start, count) = (((nodes >> 16) & 0xFF) as u8, (nodes & 0xFF) as u8);
        for fg in start..start.saturating_add(count) {
            if self.param(fg, PARAM_FUNCTION_TYPE) & 0xFF != 0x01 {
                continue; // a modem or vendor function group
            }
            self.afg = fg;
            self.verb(fg, VERB_SET_POWER_STATE, 0);
            let afg_in = self.param(fg, PARAM_AMP_IN_CAPS);
            let afg_out = self.param(fg, PARAM_AMP_OUT_CAPS);
            let nodes = self.param(fg, PARAM_NODE_COUNT);
            let (wstart, wcount) = (((nodes >> 16) & 0xFF) as u8, (nodes & 0xFF) as u8);
            self.widgets.clear();
            for nid in wstart..wstart.saturating_add(wcount) {
                let caps = self.param(nid, PARAM_WIDGET_CAPS);
                let mut w = Widget { nid, ty: ((caps >> 20) & 0xF) as u8, caps, ..Default::default() };
                if caps & WCAP_CONN_LIST != 0 {
                    w.conns = self.connections(nid);
                }
                if w.ty == WT_PIN {
                    w.pincap = self.param(nid, PARAM_PIN_CAPS);
                    w.config = self.verb(nid, VERB_GET_CONFIG_DEFAULT, 0);
                }
                let own = caps & WCAP_AMP_OVERRIDE != 0;
                if caps & WCAP_IN_AMP != 0 {
                    w.amp_in = if own { self.param(nid, PARAM_AMP_IN_CAPS) } else { afg_in };
                }
                if caps & WCAP_OUT_AMP != 0 {
                    w.amp_out = if own { self.param(nid, PARAM_AMP_OUT_CAPS) } else { afg_out };
                }
                self.widgets.push(w);
            }
            return true;
        }
        false
    }

    fn widget(&self, nid: u8) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.nid == nid)
    }

    /// A path from widget `from` through connection lists to a widget of type `goal`
    /// (`from` first), at most `depth` hops, avoiding digital converters.
    fn search(&self, from: u8, goal: u8, depth: u32, seen: &mut Vec<u8>) -> Option<Vec<u8>> {
        let w = self.widget(from)?;
        if w.ty == goal && !seen.is_empty() {
            return (w.caps & WCAP_DIGITAL == 0).then(|| alloc::vec![from]);
        }
        if depth == 0 || seen.contains(&from) {
            return None;
        }
        seen.push(from);
        for &c in &w.conns {
            let Some(cw) = self.widget(c) else { continue };
            // Only through mixers and selectors to the goal (no other pins or converters)
            if cw.ty != goal && cw.ty != WT_MIXER && cw.ty != WT_SELECTOR {
                continue;
            }
            if let Some(mut rest) = self.search(c, goal, depth - 1, seen) {
                rest.insert(0, from);
                return Some(rest);
            }
        }
        None
    }

    /// Sets an amplifier to `gain` (both channels), muted or not.
    fn set_amp(&mut self, amp: Amp, left: u32, right: u32, mute_l: bool, mute_r: bool) {
        let dir = if amp.out { 1 << 15 } else { 1 << 14 };
        let max = amp.steps();
        let base = dir | (amp.index as u32) << 8;
        self.verb4(amp.nid, VERB4_SET_AMP, base | 1 << 13 | (mute_l as u32) << 7 | left.min(max));
        self.verb4(amp.nid, VERB4_SET_AMP, base | 1 << 12 | (mute_r as u32) << 7 | right.min(max));
    }

    /// Powers the widgets of `path` (pin first, converter last), selects its connections
    /// and opens its amplifiers at 0 dB. Returns the amplifiers on it, converter side first.
    fn open_path(&mut self, path: &[u8]) -> Vec<Amp> {
        let mut amps = Vec::new();
        for (i, &nid) in path.iter().enumerate() {
            let Some(w) = self.widget(nid).cloned() else { continue };
            if w.caps & WCAP_POWER != 0 {
                self.verb(nid, VERB_SET_POWER_STATE, 0);
            }
            // The connection toward the next widget of the path
            if let Some(&next) = path.get(i + 1) {
                if let Some(idx) = w.conns.iter().position(|&c| c == next) {
                    if w.conns.len() > 1 && (w.ty == WT_SELECTOR || w.ty == WT_PIN || w.ty == WT_INPUT) {
                        self.verb(nid, VERB_SET_CONN_SELECT, idx as u32);
                    }
                    if w.caps & WCAP_IN_AMP != 0 && (w.ty == WT_MIXER || w.ty == WT_INPUT || w.ty == WT_SELECTOR) {
                        amps.push(Amp { nid, out: false, index: idx as u8, caps: w.amp_in });
                    }
                }
            }
            if w.caps & WCAP_OUT_AMP != 0 {
                amps.push(Amp { nid, out: true, index: 0, caps: w.amp_out });
            }
        }
        for a in &amps {
            let g = a.offset().min(a.steps());
            self.set_amp(*a, g, g, false, false);
        }
        amps.reverse();
        amps
    }

    /// Chooses and opens the playback route.
    fn setup_output(&mut self, sd: usize, slot: usize) -> Option<Route> {
        let rank = |w: &Widget| -> Option<u32> {
            let connectivity = w.config >> 30;
            let dev = (w.config >> 20) & 0xF;
            if w.ty != WT_PIN || w.pincap & PINCAP_OUT == 0 || connectivity == 1 || w.caps & WCAP_DIGITAL != 0 {
                return None;
            }
            match dev {
                DEV_LINE_OUT => Some(0),
                DEV_SPEAKER => Some(1),
                DEV_HP_OUT => Some(2),
                _ => None,
            }
        };
        let mut pins: Vec<(u32, u8)> = self.widgets.iter().filter_map(|w| rank(w).map(|r| (r, w.nid))).collect();
        pins.sort();
        let mut paths: Vec<Vec<u8>> = Vec::new();
        let mut dac = None;
        for &(_, pin) in &pins {
            let Some(p) = self.search(pin, WT_OUTPUT, 5, &mut Vec::new()) else { continue };
            let conv = *p.last()?;
            match dac {
                None => dac = Some(conv),
                // Other pins are used when they reach the same converter
                Some(d) if d != conv => {
                    let mut alt = None;
                    if let Some(w) = self.widget(pin) {
                        for &c in &w.conns.clone() {
                            if let Some(mut q) = self.search(c, WT_OUTPUT, 4, &mut alloc::vec![pin]) {
                                if q.last() == Some(&d) {
                                    q.insert(0, pin);
                                    alt = Some(q);
                                    break;
                                }
                            }
                        }
                    }
                    match alt {
                        Some(q) => paths.push(q),
                        None => continue,
                    }
                    continue;
                }
                _ => {}
            }
            paths.push(p);
        }
        let conv = dac?;
        let mut volume = None;
        let mut pin_ids = Vec::new();
        for p in &paths {
            let amps = self.open_path(p);
            if volume.is_none() {
                volume = amps.iter().copied().find(|a| a.steps() > 0);
            }
            let pin = p[0];
            let w = self.widget(pin).cloned().unwrap_or_default();
            let hp = (w.config >> 20) & 0xF == DEV_HP_OUT;
            self.verb(pin, VERB_SET_PIN_CTL, PIN_OUT_EN | if hp { PIN_HP_EN } else { 0 });
            if w.pincap & PINCAP_EAPD != 0 {
                self.verb(pin, VERB_SET_EAPD, 0x02);
            }
            pin_ids.push(pin);
        }
        self.verb(conv, VERB_SET_POWER_STATE, 0);
        Some(Route { conv, pins: pin_ids, volume, sd, slot, ready: false })
    }

    /// Chooses and opens the capture route.
    fn setup_input(&mut self, sd: usize, slot: usize) -> Option<Route> {
        let adcs: Vec<u8> = self.widgets.iter().filter(|w| w.ty == WT_INPUT && w.caps & WCAP_DIGITAL == 0).map(|w| w.nid).collect();
        let rank = |w: &Widget| -> u32 {
            match (w.config >> 20) & 0xF {
                DEV_MIC_IN => 0,
                DEV_LINE_IN => 1,
                _ => 2,
            }
        };
        let mut best: Option<(u32, Vec<u8>)> = None;
        for adc in adcs {
            let mut seen = Vec::new();
            let Some(w) = self.widget(adc).cloned() else { continue };
            for &c in &w.conns {
                let Some(cw) = self.widget(c) else { continue };
                let path = if cw.ty == WT_PIN {
                    Some(alloc::vec![adc, c])
                } else if cw.ty == WT_MIXER || cw.ty == WT_SELECTOR {
                    seen.clear();
                    seen.push(adc);
                    self.search(c, WT_PIN, 4, &mut seen).map(|mut p| {
                        p.insert(0, adc);
                        p
                    })
                } else {
                    None
                };
                let Some(path) = path else { continue };
                let pin = self.widget(*path.last()?)?;
                if pin.pincap & PINCAP_IN == 0 || pin.config >> 30 == 1 {
                    continue;
                }
                let r = rank(pin);
                if best.as_ref().map_or(true, |(b, _)| r < *b) {
                    best = Some((r, path));
                }
            }
        }
        let (_, path) = best?;
        // open_path wants the far end first: the pin
        let mut rev = path.clone();
        rev.reverse();
        let amps = self.open_path(&rev);
        let volume = amps.iter().copied().find(|a| a.steps() > 0);
        let conv = path[0];
        let pin = *path.last()?;
        self.verb(pin, VERB_SET_PIN_CTL, PIN_IN_EN);
        Some(Route { conv, pins: alloc::vec![pin], volume, sd, slot, ready: false })
    }

    // ---- Streams ----

    /// Stops a stream descriptor's DMA.
    fn stop(&mut self, sd: usize) {
        let r = self.regs;
        r.w32(sd + SD_CTL, r.r32(sd + SD_CTL) & !(SD_CTL_RUN | 0xFF00_0000));
        wait_for(20, || r.r32(sd + SD_CTL) & SD_CTL_RUN == 0);
    }

    /// Programs direction `dir`'s stream (see [`MSG_SND_SETUP`]).
    fn setup_stream(&mut self, dir: usize, buf: u64, bytes: u64, period: u64, fmt: u32, posbuf: u64) -> Result<usize, i64> {
        let (sd, slot, conv) = match &self.routes[dir] {
            Some(rt) => (rt.sd, rt.slot, rt.conv),
            None => return Err(ENODEV),
        };
        if period == 0 || bytes % period != 0 || period % 128 != 0 || bytes / period > BDL_MAX as u64 || bytes / period < 2 || buf & 127 != 0 {
            return Err(EINVAL);
        }
        let r = self.regs;
        self.stop(sd);
        // Stream reset
        r.w32(sd + SD_CTL, (r.r32(sd + SD_CTL) & !0xFF00_0000) | SD_CTL_SRST);
        wait_for(20, || r.r32(sd + SD_CTL) & SD_CTL_SRST != 0);
        r.w32(sd + SD_CTL, r.r32(sd + SD_CTL) & !(SD_CTL_SRST | 0xFF00_0000));
        wait_for(20, || r.r32(sd + SD_CTL) & SD_CTL_SRST == 0);
        r.w8(sd + SD_STS, 0x1C);
        // Buffer descriptor list: one entry per period, no interrupts
        let n = (bytes / period) as usize;
        let bdl = unsafe { self.mem.add(BDL_OFF[dir]) as *mut u32 };
        for i in 0..n {
            let a = buf + i as u64 * period;
            unsafe {
                bdl.add(i * 4).write_volatile(a as u32);
                bdl.add(i * 4 + 1).write_volatile((a >> 32) as u32);
                bdl.add(i * 4 + 2).write_volatile(period as u32);
                bdl.add(i * 4 + 3).write_volatile(0);
            }
        }
        let bdl_phys = self.mem_phys + BDL_OFF[dir] as u64;
        r.w32(sd + SD_BDPL, bdl_phys as u32);
        r.w32(sd + SD_BDPU, (bdl_phys >> 32) as u32);
        r.w32(sd + SD_CBL, bytes as u32);
        r.w16(sd + SD_LVI, (n - 1) as u16);
        r.w16(sd + SD_FMT, fmt as u16);
        let ctl = r.r32(sd + SD_CTL) & !(0xFF00_0000 | 0x00F0_0000);
        r.w32(sd + SD_CTL, ctl | TAG[dir] << 20);
        // Position buffer
        r.w32(DPUBASE, (posbuf >> 32) as u32);
        r.w32(DPLBASE, (posbuf as u32 & !0x7F) | 1);
        // The converter: stream tag, channel 0, and the same format
        self.verb4(conv, VERB4_SET_FORMAT, fmt);
        self.verb(conv, VERB_SET_STREAM_CHANNEL, TAG[dir] << 4);
        if let Some(rt) = self.routes[dir].as_mut() {
            rt.ready = true;
        }
        Ok(slot)
    }

    fn trigger(&mut self, dir: usize, run: bool) -> Result<u64, i64> {
        let rt = self.routes[dir].as_ref().ok_or(ENODEV)?;
        if !rt.ready {
            return Err(EINVAL);
        }
        let sd = rt.sd;
        let r = self.regs;
        if run {
            r.w32(sd + SD_CTL, (r.r32(sd + SD_CTL) & !0xFF00_0000) | SD_CTL_RUN);
            if !wait_for(20, || r.r32(sd + SD_CTL) & SD_CTL_RUN != 0) {
                return Err(EIO);
            }
        } else {
            self.stop(sd);
        }
        Ok(r.r32(sd + SD_LPIB) as u64)
    }

    fn position(&self, dir: usize) -> Result<u64, i64> {
        let rt = self.routes[dir].as_ref().ok_or(ENODEV)?;
        Ok(self.regs.r32(rt.sd + SD_LPIB) as u64)
    }

    fn volume(&mut self, dir: usize, left: u32, right: u32, mute: u32) -> Result<(), i64> {
        let amp = self.routes[dir].as_ref().ok_or(ENODEV)?.volume.ok_or(EINVAL)?;
        self.set_amp(amp, left, right, mute & 1 != 0, mute & 2 != 0);
        Ok(())
    }

    /// A line describing the codec and the routes.
    fn describe(&self) -> String {
        let mut s = String::new();
        let _ = write!(s, "codec {} vendor {:04x}:{:04x}", self.codec, self.vendor >> 16, self.vendor & 0xFFFF);
        for (dir, name) in [(0usize, "playback"), (1, "capture")] {
            if let Some(rt) = &self.routes[dir] {
                let _ = write!(s, ", {}: converter {} pins {:?}", name, rt.conv, rt.pins);
                if let Some(a) = rt.volume {
                    let _ = write!(s, " volume at {}{} ({} steps)", a.nid, if a.out { "out" } else { "in" }, a.steps());
                }
            }
        }
        s
    }
}

fn reply(args: [u64; 4]) -> Message {
    Message::new(MSG_SND_REPLY as u64, args)
}

fn err(e: i64) -> Message {
    reply([e as u64, 0, 0, 0])
}

/// Driver entry point: sets up the controller and codec, then serves requests.
fn main(args: &[&str]) {
    let Some(mmio) = arg(args, "mmio") else {
        println!("[hda-driver] no controller given (mmio=...)");
        return;
    };
    let regs = match sys::physmap(mmio, 0x4000) {
        Ok(r) => Regs(r),
        Err(e) => {
            println!("[hda-driver] cannot map the registers at {:#x}: error {}", mmio, e);
            return;
        }
    };
    let (mem, mem_phys) = match sys::dma_alloc(DMA_LEN) {
        Ok(m) => m,
        Err(e) => {
            println!("[hda-driver] no DMA memory: error {}", e);
            return;
        }
    };
    let mut hda = Hda {
        regs,
        mem,
        mem_phys,
        corb_entries: 256,
        rirb_entries: 256,
        corb_wp: 0,
        rirb_rp: 0,
        codec: 0,
        vendor: 0,
        afg: 0,
        widgets: Vec::new(),
        routes: [None, None],
        timeouts: 0,
        transport: Transport::Rings,
        verb_ms: 50,
    };
    let gcap = regs.r16(GCAP);
    let (iss, oss) = (((gcap >> 8) & 0xF) as usize, ((gcap >> 12) & 0xF) as usize);
    let mut codecs = hda.reset();
    if codecs == 0 {
        // wave11 GG: one more reset before giving up
        sys::sleep_ms(10);
        codecs = hda.reset();
    }
    if codecs == 0 {
        println!("[hda-driver] controller at {:#x}: no codec ({})", mmio, hda.ring_state());
        return;
    }
    // wave11 GG: `cmd=immediate` (a test or a diagnosis): no command rings at all
    if args.contains(&"cmd=immediate") {
        hda.use_immediate();
        println!("[hda-driver] immediate commands only (cmd=immediate)");
    }
    // wave11 GG: a codec that does not answer gets a second controller reset
    if !(0..15).any(|c| codecs & (1 << c) != 0 && { let v = hda.wake_codec(c); v != 0 && v != u32::MAX }) {
        println!("[hda-driver] no codec answered; resetting the controller once more");
        sys::sleep_ms(10);
        let again = hda.reset();
        if again != 0 {
            codecs = again;
        }
    }
    // The first codec with an audio function group and a playback route
    for c in 0..15 {
        if codecs & (1 << c) == 0 || !hda.probe_codec(c) {
            continue;
        }
        hda.codec_fixups(); // wave11 GG
        if oss > 0 {
            hda.routes[0] = hda.setup_output(0x80 + iss * 0x20, iss);
        }
        if iss > 0 {
            hda.routes[1] = hda.setup_input(0x80, 0);
        }
        if hda.routes[0].is_some() {
            break;
        }
        hda.routes = [None, None];
    }
    if hda.routes[0].is_none() {
        println!("[hda-driver] controller at {:#x}: no codec with an analog output (codecs {:#x})", mmio, codecs);
        return;
    }
    let mut server = match Server::register(ENDPOINT_SOUND_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[hda-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_SOUND_DEV, e);
            return;
        }
    };
    let text = hda.describe();
    println!("[hda-driver] {}", text);
    server.serve(|srv, msg| {
        let dir = msg.args[0] as usize;
        if msg.label as u32 != MSG_SND_INFO && dir > 1 {
            return err(EINVAL);
        }
        match msg.label as u32 {
            MSG_SND_INFO => {
                let text = hda.describe();
                let w = srv.window();
                let n = text.len().min(w.len() - 1);
                w[..n].copy_from_slice(&text.as_bytes()[..n]);
                w[n] = 0;
                let dirs = hda.routes[0].is_some() as u64 | (hda.routes[1].is_some() as u64) << 1;
                let amp = |d: usize| hda.routes[d].as_ref().and_then(|r| r.volume).map_or(0, |a| a.describe());
                reply([0, hda.vendor as u64, dirs, amp(0) | amp(1) << 32])
            }
            MSG_SND_SETUP => {
                let w = srv.window();
                let word = |i: usize| u64::from_le_bytes(w[i * 8..i * 8 + 8].try_into().unwrap());
                let (d, buf, bytes, period, fmt, posbuf) = (word(0) as usize, word(1), word(2), word(3), word(4) as u32, word(5));
                if d > 1 {
                    return err(EINVAL);
                }
                match hda.setup_stream(d, buf, bytes, period, fmt, posbuf) {
                    Ok(slot) => reply([0, slot as u64, 0, 0]),
                    Err(e) => err(e),
                }
            }
            MSG_SND_TRIGGER => match hda.trigger(dir, msg.args[1] != 0) {
                Ok(pos) => reply([0, pos, 0, 0]),
                Err(e) => err(e),
            },
            MSG_SND_POSITION => match hda.position(dir) {
                Ok(pos) => reply([0, pos, 0, 0]),
                Err(e) => err(e),
            },
            MSG_SND_VOLUME => match hda.volume(dir, msg.args[1] as u32, msg.args[2] as u32, msg.args[3] as u32) {
                Ok(()) => reply([0; 4]),
                Err(e) => err(e),
            },
            _ => err(EINVAL),
        }
    })
}
