//! # Hydra USB driver (xHCI host controller, HID input devices, hubs, USB disks)
//!
//! Drives one xHCI USB host controller from Ring 3, in an address space of its own: its
//! registers are the device memory the supervisor granted (PCI `BAR0`), its rings and
//! contexts DMA memory this driver allocates. It enumerates the devices on the root ports
//! and behind USB hubs ([`hub`]) and runs:
//! - HID devices: keyboards (boot protocol), mice (boot protocol) and pointers described by
//!   their report descriptor (tablets such as QEMU's `usb-tablet`, which report absolute
//!   positions);
//! - USB mass storage (sticks, card readers, USB disks): Bulk-Only Transport with SCSI
//!   commands ([`storage`]).
//!
//! The supervisor starts it with `mmio=<phys> len=<bytes>` and, when the kernel routed the
//! controller's message-signalled interrupt (MSI) to it, `irq=<line>`.
//!
//! One process owns the controller, so it serves two endpoints that share one call slot
//! (the kernel lets one request at a time reach this driver):
//! - [`ENDPOINT_INPUT_DEV`]: `MSG_INPUT_READ` services the controller's event ring
//!   (finished interrupt transfers carry HID reports and hub status changes; port changes
//!   plug devices in and out) and returns the input since the last request as 8-byte
//!   records in that endpoint's window (see the protocol). The kernel's USB input task asks
//!   whenever the controller interrupts, and a few times a second regardless.
//! - [`ENDPOINT_USB_DISK`]: the block protocol of the disk drivers (`MSG_BLOCK_*`, 4 KiB
//!   blocks, data in that endpoint's window), with `args[3]` naming the USB disk (0, 1,
//!   ...); `MSG_BLOCK_LIST` describes the disks present (see the protocol).
//!
//! Limits: keyboard LEDs are not driven; keys do not auto-repeat in the Hydra console
//! (desktops repeat keys themselves); USB Attached SCSI (UAS) is not used (UAS disks also
//! offer Bulk-Only Transport, which is); LUN 0 only.

#![no_std]
#![no_main]

extern crate alloc;

mod hid;
mod hub;
mod storage;

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use hydra_rt::protocol::{ENDPOINT_INPUT_DEV, ENDPOINT_USB_DISK, MSG_BLOCK_REPLY, MSG_INPUT_READ, MSG_INPUT_REPLY};
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

hydra_rt::entry!(main);

// Capability registers
const CAP_CAPLENGTH: usize = 0x00;
const CAP_HCSPARAMS1: usize = 0x04;
const CAP_HCSPARAMS2: usize = 0x08;
const CAP_HCCPARAMS1: usize = 0x10;
const CAP_DBOFF: usize = 0x14;
const CAP_RTSOFF: usize = 0x18;

// Operational registers
const OP_USBCMD: usize = 0x00;
const OP_USBSTS: usize = 0x04;
const OP_CRCR: usize = 0x18;
const OP_DCBAAP: usize = 0x30;
const OP_CONFIG: usize = 0x38;
const OP_PORTSC: usize = 0x400;

const CMD_RS: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HCH: u32 = 1 << 0;
const STS_HSE: u32 = 1 << 2;
const STS_EINT: u32 = 1 << 3;
const STS_CNR: u32 = 1 << 11;

const PORT_CCS: u32 = 1 << 0;
const PORT_PED: u32 = 1 << 1;
const PORT_PR: u32 = 1 << 4;
const PORT_PP: u32 = 1 << 9;
const PORT_PRC: u32 = 1 << 21;
/// The status-change bits (write 1 to clear): CSC, PEC, WRC, OCC, PRC, PLC, CEC.
const PORT_CHANGES: u32 = 0x00FE_0000;
/// Bits that must be written as 0 to leave a port as it is: PED (writing 1 disables the
/// port), PR, LWS, the change bits and WPR.
const PORT_WRITE_ZERO: u32 = PORT_PED | PORT_PR | (1 << 16) | PORT_CHANGES | (1 << 31);

// Interrupter 0 (runtime registers + 0x20)
const IR_IMAN: usize = 0x20;
const IR_IMOD: usize = 0x24;
const IR_ERSTSZ: usize = 0x28;
const IR_ERSTBA: usize = 0x30;
const IR_ERDP: usize = 0x38;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;

// TRB types
const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_EP: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_RESET_EP: u32 = 14;
const TRB_STOP_EP: u32 = 15;
const TRB_SET_TR_DEQUEUE: u32 = 16;
const TRB_EV_TRANSFER: u32 = 32;
const TRB_EV_COMMAND: u32 = 33;
const TRB_EV_PORT: u32 = 34;

const TRB_CH: u32 = 1 << 4;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_ISP: u32 = 1 << 2;

const CC_SUCCESS: u32 = 1;
const CC_SHORT_PACKET: u32 = 13;
const CC_STALL: u32 = 6;

/// TRBs per ring: one page of 16-byte TRBs, the last a link back to the start.
const RING_TRBS: usize = 256;
/// Interrupt transfers kept queued per HID endpoint.
const REPORTS_QUEUED: usize = 8;
/// Bytes per report buffer.
const REPORT_BUF: usize = 512;
/// Most devices handled (hubs and the devices behind them included).
const MAX_DEVICES: usize = 32;

const PAGE: usize = 4096;

/// A time limit in milliseconds, measured with the 100 Hz uptime clock.
struct Deadline(u64);

impl Deadline {
    fn after_ms(ms: u64) -> Self {
        Self(sys::uptime_ticks() + ms.div_ceil(10) + 1)
    }
    fn expired(&self) -> bool {
        sys::uptime_ticks() >= self.0
    }
}

/// Physically contiguous DMA memory.
#[derive(Clone, Copy)]
struct Dma {
    virt: *mut u8,
    phys: u64,
}

impl Dma {
    /// `pages` zeroed pages.
    fn alloc(pages: usize) -> Result<Self, &'static str> {
        let (virt, phys) = sys::dma_alloc(pages * PAGE).map_err(|_| "no DMA memory")?;
        unsafe { core::ptr::write_bytes(virt, 0, pages * PAGE) };
        Ok(Self { virt, phys })
    }

    /// The memory `off` bytes in.
    fn at(&self, off: usize) -> Dma {
        Dma { virt: unsafe { self.virt.add(off) }, phys: self.phys + off as u64 }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { (self.virt.add(off) as *mut u32).write_volatile(v) }
    }

    fn r32(&self, off: usize) -> u32 {
        unsafe { (self.virt.add(off) as *const u32).read_volatile() }
    }

    fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }

    fn bytes(&self, off: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt.add(off), len) }
    }

    #[allow(clippy::mut_from_ref)]
    fn bytes_mut(&self, off: usize, len: usize) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt.add(off), len) }
    }
}

/// A producer ring of TRBs (command ring or transfer ring) in one page.
struct Ring {
    mem: Dma,
    enq: usize,
    cycle: bool,
}

impl Ring {
    fn new(mem: Dma) -> Self {
        Self { mem, enq: 0, cycle: true }
    }

    /// Appends a TRB (its cycle bit written last, so the controller never sees half of
    /// it); returns its physical address, which the completion event names.
    fn push(&mut self, param: u64, status: u32, control: u32) -> u64 {
        let off = self.enq * 16;
        self.mem.w64(off, param);
        self.mem.w32(off + 8, status);
        fence(Ordering::SeqCst);
        self.mem.w32(off + 12, (control & !1) | self.cycle as u32);
        let at = self.mem.phys + off as u64;
        self.enq += 1;
        if self.enq == RING_TRBS - 1 {
            // Link back to the start, toggling the cycle state (TC); a TD that goes on
            // past the link keeps its chain through it (CH)
            let off = self.enq * 16;
            self.mem.w64(off, self.mem.phys);
            self.mem.w32(off + 8, 0);
            fence(Ordering::SeqCst);
            self.mem.w32(off + 12, TRB_LINK << 10 | (control & TRB_CH) | 1 << 1 | self.cycle as u32);
            self.cycle = !self.cycle;
            self.enq = 0;
        }
        at
    }

    /// Where the next TRB goes, with the cycle state (for Set TR Dequeue Pointer).
    fn dequeue_pointer(&self) -> u64 {
        self.mem.phys + (self.enq * 16) as u64 | self.cycle as u64
    }
}

/// What an interrupt IN endpoint is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HidKind {
    Keyboard,
    BootMouse,
    /// A pointer described by its report descriptor.
    Pointer,
    /// A hub's status change endpoint (a bitmap of the ports that changed).
    HubStatus,
}

/// One interrupt IN endpoint (a HID interface's, or a hub's) and its state.
struct HidIf {
    kind: HidKind,
    dci: u32,
    ring: Ring,
    /// Report buffers, [`REPORTS_QUEUED`] of [`REPORT_BUF`] bytes.
    bufs: Dma,
    /// The TRB address queued for each buffer.
    queued: [u64; REPORTS_QUEUED],
    report_len: usize,
    layout: Option<hid::Layout>,
    prev_keys: [u8; 8],
    failed: bool,
}

/// A device in a slot.
struct Device {
    slot: u32,
    /// Root port it is reached through (1-based).
    port: u32,
    /// Route string: the hub port at each tier below the root port, 4 bits each (0 for a
    /// device on a root port).
    route: u32,
    /// Hubs between it and the root port.
    depth: u32,
    speed: u32,
    /// Slot of the hub it is attached to (0: a root port) and the hub's port.
    parent: u32,
    parent_port: u32,
    /// Transaction translator for a low or full speed device behind a high speed hub:
    /// the hub's slot and port (0: none).
    tt_slot: u32,
    tt_port: u32,
    /// Output device context, input context, EP0 ring, control buffer (one page each).
    mem: Dma,
    ep0: Ring,
    hids: Vec<HidIf>,
    /// Hub state, if it is a hub.
    hub: Option<hub::Hub>,
    /// Mass storage state, if it is a USB disk.
    msd: Option<storage::Msd>,
    /// Vendor and product IDs.
    vendor: u16,
    product: u16,
}

const DEV_OUT_CTX: usize = 0;
const DEV_IN_CTX: usize = PAGE;
const DEV_EP0_RING: usize = 2 * PAGE;
const DEV_CTL_BUF: usize = 3 * PAGE;
const DEV_PAGES: usize = 4;

/// A completed command: its TRB, completion code, slot.
#[derive(Clone, Copy)]
struct CmdDone {
    trb: u64,
    code: u32,
    slot: u32,
}

/// A completed transfer: slot, endpoint, TRB, completion code, bytes not transferred.
#[derive(Clone, Copy)]
struct XferDone {
    slot: u32,
    dci: u32,
    trb: u64,
    code: u32,
    residual: u32,
}

/// The controller.
struct Xhci {
    cap: *mut u8,
    op: *mut u8,
    rt: *mut u8,
    db: *mut u8,
    irq: Option<u8>,
    max_slots: u32,
    max_ports: u32,
    /// Context size: 32 or 64 bytes (HCCPARAMS1.CSZ).
    ctx: usize,
    /// DCBAA, command ring, event ring, event ring segment table (a page each).
    mem: Dma,
    cmd: Ring,
    ev_deq: usize,
    ev_cycle: bool,
    devices: Vec<Device>,
    cmd_done: Option<CmdDone>,
    xfer_done: Option<XferDone>,
    /// Finished bulk transfers (USB disks) not yet looked at.
    bulk_done: Vec<XferDone>,
    /// Root ports with a status change to look at.
    port_changes: Vec<u32>,
    /// Hubs (by slot) whose status change endpoint reported something.
    hub_changes: Vec<u32>,
    /// Input records not yet collected.
    out: Vec<[u8; 8]>,
    /// USB disks by number: the slot of the device (0: none).
    disks: [u32; storage::MAX_DISKS],
    /// Counts disk attachments (each disk records the value it got).
    disk_generation: u32,
    /// Where the pool is, if on a USB disk (`hydra_rt::blockunits`).
    units: hydra_rt::blockunits::Units,
    /// Generation of the pool's disk when it was chosen.
    pool_generation: u32,
}

const MEM_DCBAA: usize = 0;
const MEM_CMD_RING: usize = PAGE;
const MEM_EVENT_RING: usize = 2 * PAGE;
const MEM_ERST: usize = 3 * PAGE;
const MEM_PAGES: usize = 4;

/// Reads a 32-bit register.
fn rd(base: *mut u8, off: usize) -> u32 {
    unsafe { (base.add(off) as *const u32).read_volatile() }
}

/// Writes a 32-bit register.
fn wr(base: *mut u8, off: usize, v: u32) {
    unsafe { (base.add(off) as *mut u32).write_volatile(v) }
}

/// Writes a 64-bit register as two 32-bit halves, low first (allowed by the spec, and
/// what controllers without 64-bit register access need).
fn wr64(base: *mut u8, off: usize, v: u64) {
    wr(base, off, v as u32);
    wr(base, off + 4, (v >> 32) as u32);
}

/// Where a device sits, for the log: `port 3` or `port 3.2.1` (root port, then hub ports).
struct Location(u32, u32, u32);

impl core::fmt::Display for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "port {}", self.0)?;
        for tier in 0..self.2 {
            write!(f, ".{}", (self.1 >> (4 * tier)) & 0xF)?;
        }
        Ok(())
    }
}

impl Xhci {
    fn portsc(&self, port: u32) -> u32 {
        rd(self.op, OP_PORTSC + (port as usize - 1) * 0x10)
    }

    fn set_portsc(&self, port: u32, v: u32) {
        wr(self.op, OP_PORTSC + (port as usize - 1) * 0x10, v)
    }

    /// Device `di`'s location, for the log.
    fn loc(&self, di: usize) -> Location {
        let d = &self.devices[di];
        Location(d.port, d.route, d.depth)
    }

    /// The device in `slot`.
    fn dev_of_slot(&self, slot: u32) -> Option<usize> {
        self.devices.iter().position(|d| d.slot == slot)
    }

    /// Takes the controller from the firmware (USB Legacy Support capability): the
    /// firmware may be emulating a PS/2 keyboard with it through SMIs.
    fn bios_handoff(&self) {
        let hcc = rd(self.cap, CAP_HCCPARAMS1);
        let mut off = ((hcc >> 16) as usize) * 4;
        for _ in 0..64 {
            if off == 0 {
                return;
            }
            let v = rd(self.cap, off);
            if v & 0xFF == 1 {
                if v & (1 << 16) != 0 {
                    wr(self.cap, off, v | 1 << 24); // OS owned semaphore
                    let d = Deadline::after_ms(1000);
                    while rd(self.cap, off) & (1 << 16) != 0 && !d.expired() {
                        sys::sleep_ms(5);
                    }
                    if rd(self.cap, off) & (1 << 16) != 0 {
                        println!("[usb-driver] the firmware did not release the controller; taking it anyway");
                        wr(self.cap, off, (rd(self.cap, off) & !(1 << 16)) | 1 << 24);
                    }
                } else {
                    wr(self.cap, off, v | 1 << 24);
                }
                // No more SMIs on USB events; clear the ones pending (write 1 to clear)
                let ctl = rd(self.cap, off + 4);
                wr(self.cap, off + 4, (ctl & !0x0000_E011) | 0xE000_0000);
                return;
            }
            let next = ((v >> 8) & 0xFF) as usize;
            off = if next == 0 { 0 } else { off + next * 4 };
        }
    }

    /// Stops and resets the controller.
    fn reset(&self) -> Result<(), &'static str> {
        wr(self.op, OP_USBCMD, rd(self.op, OP_USBCMD) & !(CMD_RS | CMD_INTE));
        let d = Deadline::after_ms(100);
        while rd(self.op, OP_USBSTS) & STS_HCH == 0 {
            if d.expired() {
                return Err("the controller does not halt");
            }
            sys::sleep_ms(1);
        }
        wr(self.op, OP_USBCMD, CMD_HCRST);
        // Some Intel controllers must not be read for a moment after the reset starts
        sys::sleep_ms(10);
        let d = Deadline::after_ms(1000);
        while rd(self.op, OP_USBCMD) & CMD_HCRST != 0 || rd(self.op, OP_USBSTS) & STS_CNR != 0 {
            if d.expired() {
                return Err("the controller reset does not finish");
            }
            sys::sleep_ms(1);
        }
        Ok(())
    }

    /// Sets up the data structures and starts the controller.
    fn start(&mut self) -> Result<(), &'static str> {
        let slots = self.max_slots.min(MAX_DEVICES as u32 + 1);
        wr(self.op, OP_CONFIG, (rd(self.op, OP_CONFIG) & !0xFF) | slots);
        // Scratchpad buffers: memory the controller keeps its own state in (none in QEMU;
        // real controllers ask for some and fail without them)
        let p2 = rd(self.cap, CAP_HCSPARAMS2);
        let scratch = ((p2 >> 21) & 0x1F) << 5 | (p2 >> 27) & 0x1F;
        if scratch > 0 {
            let arr = Dma::alloc(1)?;
            let pages = Dma::alloc(scratch as usize)?;
            for i in 0..scratch as usize {
                arr.w64(i * 8, pages.phys + (i * PAGE) as u64);
            }
            self.mem.w64(MEM_DCBAA, arr.phys);
        }
        wr64(self.op, OP_DCBAAP, self.mem.phys + MEM_DCBAA as u64);
        wr64(self.op, OP_CRCR, self.cmd.mem.phys | 1);
        // One event ring segment
        let erst = self.mem.at(MEM_ERST);
        erst.w64(0, self.mem.phys + MEM_EVENT_RING as u64);
        erst.w32(8, RING_TRBS as u32);
        wr(self.rt, IR_ERSTSZ, 1);
        wr64(self.rt, IR_ERDP, self.mem.phys + MEM_EVENT_RING as u64);
        wr64(self.rt, IR_ERSTBA, erst.phys);
        // At most one interrupt per 40 us (in 250 ns units), as Linux
        wr(self.rt, IR_IMOD, 160);
        wr(self.rt, IR_IMAN, IMAN_IP | if self.irq.is_some() { IMAN_IE } else { 0 });
        wr(self.op, OP_USBSTS, STS_EINT | STS_HSE);
        wr(self.op, OP_USBCMD, CMD_RS | if self.irq.is_some() { CMD_INTE } else { 0 });
        let d = Deadline::after_ms(100);
        while rd(self.op, OP_USBSTS) & STS_HCH != 0 {
            if d.expired() {
                return Err("the controller does not start");
            }
            sys::sleep_ms(1);
        }
        // Port power, where software controls it (HCCPARAMS1.PPC)
        if rd(self.cap, CAP_HCCPARAMS1) & (1 << 3) != 0 {
            for port in 1..=self.max_ports {
                let sc = self.portsc(port);
                if sc & PORT_PP == 0 {
                    self.set_portsc(port, (sc & !PORT_WRITE_ZERO) | PORT_PP);
                }
            }
            sys::sleep_ms(20);
        }
        Ok(())
    }

    fn ring_doorbell(&self, slot: u32, target: u32) {
        fence(Ordering::SeqCst);
        wr(self.db, slot as usize * 4, target);
    }

    /// Takes every event the controller posted; transfer events of HID endpoints become
    /// input records at once.
    fn drain_events(&mut self) {
        let ring = self.mem.at(MEM_EVENT_RING);
        let mut any = false;
        loop {
            let off = self.ev_deq * 16;
            let control = ring.r32(off + 12);
            if (control & 1 != 0) != self.ev_cycle {
                break;
            }
            let param = ring.r32(off) as u64 | (ring.r32(off + 4) as u64) << 32;
            let status = ring.r32(off + 8);
            self.ev_deq += 1;
            if self.ev_deq == RING_TRBS {
                self.ev_deq = 0;
                self.ev_cycle = !self.ev_cycle;
            }
            any = true;
            let code = status >> 24;
            let slot = control >> 24;
            match (control >> 10) & 0x3F {
                TRB_EV_COMMAND => self.cmd_done = Some(CmdDone { trb: param, code, slot }),
                TRB_EV_TRANSFER => {
                    let dci = (control >> 16) & 0x1F;
                    let x = XferDone { slot, dci, trb: param, code, residual: status & 0xFF_FFFF };
                    if dci == 1 {
                        self.xfer_done = Some(x);
                    } else if self.is_bulk(slot, dci) {
                        // Kept short: a disk waits for one transfer at a time
                        if self.bulk_done.len() >= 64 {
                            self.bulk_done.remove(0);
                        }
                        self.bulk_done.push(x);
                    } else {
                        self.hid_report(slot, dci, param, code, status & 0xFF_FFFF);
                    }
                }
                TRB_EV_PORT => {
                    let port = (param >> 24) as u32 & 0xFF;
                    if !self.port_changes.contains(&port) {
                        self.port_changes.push(port);
                    }
                }
                _ => {}
            }
        }
        // Acknowledge: the dequeue pointer (clearing Event Handler Busy), then the
        // interrupt pending flags (write 1 to clear)
        if any {
            wr64(self.rt, IR_ERDP, (ring.phys + (self.ev_deq * 16) as u64) | ERDP_EHB);
        }
        wr(self.rt, IR_IMAN, rd(self.rt, IR_IMAN) | IMAN_IP);
        wr(self.op, OP_USBSTS, STS_EINT);
    }

    /// Whether endpoint `dci` of `slot` is a USB disk's bulk endpoint.
    fn is_bulk(&self, slot: u32, dci: u32) -> bool {
        self.devices.iter().any(|d| d.slot == slot && d.msd.as_ref().is_some_and(|m| m.dci_in == dci || m.dci_out == dci))
    }

    /// Waits for the next event or 10 ms: the interrupt if there is one, else a sleep.
    fn pause(&self) {
        match self.irq {
            Some(irq) => {
                let _ = sys::irq_wait(irq, 1);
            }
            None => sys::sleep_ms(1),
        }
    }

    /// Issues a command and waits for its completion; returns the slot it reports.
    fn command(&mut self, param: u64, control: u32, ms: u64) -> Result<u32, &'static str> {
        self.command_code(param, control, ms).and_then(|(code, slot)| {
            if code == CC_SUCCESS {
                Ok(slot)
            } else {
                println!("[usb-driver] command {} failed: completion code {}", (control >> 10) & 0x3F, code);
                Err("command failed")
            }
        })
    }

    /// Issues a command and waits for its completion; returns its completion code and slot.
    fn command_code(&mut self, param: u64, control: u32, ms: u64) -> Result<(u32, u32), &'static str> {
        let trb = self.cmd.push(param, 0, control);
        self.cmd_done = None;
        self.ring_doorbell(0, 0);
        let d = Deadline::after_ms(ms);
        loop {
            self.drain_events();
            if let Some(c) = self.cmd_done.filter(|c| c.trb == trb) {
                return Ok((c.code, c.slot));
            }
            if rd(self.op, OP_USBSTS) & STS_HSE != 0 {
                return Err("host system error");
            }
            if d.expired() {
                return Err("command timed out");
            }
            self.pause();
        }
    }

    /// A control transfer on device `di`'s default endpoint; returns the bytes moved. The
    /// data is in the device's control buffer.
    fn control(&mut self, di: usize, req_type: u8, req: u8, value: u16, index: u16, len: u16) -> Result<usize, &'static str> {
        let setup = req_type as u64 | (req as u64) << 8 | (value as u64) << 16 | (index as u64) << 32 | (len as u64) << 48;
        let input = req_type & 0x80 != 0;
        let (slot, buf) = (self.devices[di].slot, self.devices[di].mem.phys + DEV_CTL_BUF as u64);
        let ep0 = &mut self.devices[di].ep0;
        // Transfer type: 3 IN data stage, 2 OUT data stage, 0 none
        let trt = if len == 0 { 0 } else if input { 3 } else { 2 };
        ep0.push(setup, 8, TRB_SETUP << 10 | TRB_IDT | trt << 16);
        if len > 0 {
            // ISP: a short data stage reports its length (an event of its own)
            ep0.push(buf, len as u32, TRB_DATA << 10 | TRB_ISP | (input as u32) << 16);
        }
        // The status stage goes the other way (IN when there is no data stage)
        let status_in = len == 0 || !input;
        let trb = ep0.push(0, 0, TRB_STATUS << 10 | TRB_IOC | (status_in as u32) << 16);
        self.xfer_done = None;
        self.ring_doorbell(slot, 1);
        let d = Deadline::after_ms(2000);
        let mut residual = 0;
        loop {
            self.drain_events();
            if let Some(x) = self.xfer_done.filter(|x| x.slot == slot) {
                self.xfer_done = None;
                match x.code {
                    CC_SUCCESS if x.trb == trb => return Ok(len as usize - residual as usize),
                    // A short data stage: the status stage completes after it
                    CC_SHORT_PACKET => residual = x.residual,
                    CC_SUCCESS => {}
                    code => {
                        // A stall halts the endpoint: reset it before the next request
                        self.recover_endpoint(di, 1);
                        return Err(if code == CC_STALL { "the device refused the request (stall)" } else { "control transfer error" });
                    }
                }
            }
            if d.expired() {
                self.stop_endpoint(di, 1);
                self.recover_endpoint(di, 1);
                return Err("control transfer timed out");
            }
            self.pause();
        }
    }

    /// The ring of endpoint `dci` of device `di`.
    fn ring_of(&self, di: usize, dci: u32) -> Option<&Ring> {
        let d = &self.devices[di];
        if dci == 1 {
            return Some(&d.ep0);
        }
        if let Some(m) = d.msd.as_ref() {
            if m.dci_in == dci {
                return Some(&m.ring_in);
            }
            if m.dci_out == dci {
                return Some(&m.ring_out);
            }
        }
        d.hids.iter().find(|h| h.dci == dci).map(|h| &h.ring)
    }

    /// Stops an endpoint with a transfer still pending (one that timed out), so its
    /// dequeue pointer can be moved.
    fn stop_endpoint(&mut self, di: usize, dci: u32) {
        let slot = self.devices[di].slot;
        let _ = self.command_code(0, TRB_STOP_EP << 10 | dci << 16 | slot << 24, 1000);
    }

    /// Brings a halted (or stopped) endpoint back: Reset Endpoint, then its dequeue
    /// pointer moved past whatever was left on the ring. Returns whether the endpoint was
    /// halted (Reset Endpoint succeeded).
    fn recover_endpoint(&mut self, di: usize, dci: u32) -> bool {
        let slot = self.devices[di].slot;
        let halted = matches!(self.command_code(0, TRB_RESET_EP << 10 | dci << 16 | slot << 24, 1000), Ok((CC_SUCCESS, _)));
        let Some(deq) = self.ring_of(di, dci).map(|r| r.dequeue_pointer()) else { return halted };
        let _ = self.command_code(deq, TRB_SET_TR_DEQUEUE << 10 | dci << 16 | slot << 24, 1000);
        halted
    }

    /// Resets root port `port` (USB 2 ports need it to be enabled; USB 3 ones enable
    /// themselves when the link trains, and a reset does no harm).
    fn reset_port(&self, port: u32) -> bool {
        let sc = self.portsc(port);
        self.set_portsc(port, (sc & !PORT_WRITE_ZERO) | PORT_PR);
        let d = Deadline::after_ms(500);
        while self.portsc(port) & PORT_PRC == 0 {
            if d.expired() {
                return false;
            }
            sys::sleep_ms(1);
        }
        let sc = self.portsc(port);
        self.set_portsc(port, (sc & !PORT_WRITE_ZERO) | (sc & PORT_CHANGES));
        // Reset recovery time (USB 2.0 7.1.7.5: 10 ms) before the first request
        sys::sleep_ms(10);
        self.portsc(port) & PORT_PED != 0
    }

    /// Sets up the device on root port `port`.
    fn attach(&mut self, port: u32) -> Result<(), &'static str> {
        if self.devices.iter().any(|d| d.port == port && d.depth == 0) {
            return Ok(());
        }
        // Debounce: the connection must last 100 ms (USB 2.0 7.1.7.3)
        sys::sleep_ms(100);
        if self.portsc(port) & PORT_CCS == 0 {
            return Err("disconnected again");
        }
        if !self.reset_port(port) {
            return Err("the port does not enable after a reset");
        }
        let speed = (self.portsc(port) >> 10) & 0xF;
        self.attach_device(port, 0, 0, speed, 0, 0, (0, 0))
    }

    /// Gives a device (its port already reset and enabled) a slot and sets it up: on root
    /// port `port`, at `route`/`depth` below it, behind hub slot `parent` port
    /// `parent_port` (0, 0 on a root port), with transaction translator `tt`.
    #[allow(clippy::too_many_arguments)]
    fn attach_device(&mut self, port: u32, route: u32, depth: u32, speed: u32, parent: u32, parent_port: u32, tt: (u32, u32)) -> Result<(), &'static str> {
        if self.devices.len() >= MAX_DEVICES {
            return Err("too many devices");
        }
        let slot = self.command(0, TRB_ENABLE_SLOT << 10, 1000)?;
        let mem = match Dma::alloc(DEV_PAGES) {
            Ok(m) => m,
            Err(e) => {
                let _ = self.command(0, TRB_DISABLE_SLOT << 10 | slot << 24, 1000);
                return Err(e);
            }
        };
        let ep0 = Ring::new(mem.at(DEV_EP0_RING));
        self.mem.w64(MEM_DCBAA + slot as usize * 8, mem.phys + DEV_OUT_CTX as u64);
        self.devices.push(Device {
            slot,
            port,
            route,
            depth,
            speed,
            parent,
            parent_port,
            tt_slot: tt.0,
            tt_port: tt.1,
            mem,
            ep0,
            hids: Vec::new(),
            hub: None,
            msd: None,
            vendor: 0,
            product: 0,
        });
        let di = self.devices.len() - 1;
        if let Err(e) = self.setup_device(di) {
            self.detach(di);
            return Err(e);
        }
        Ok(())
    }

    /// Input context entry `i` (0: input control, 1: slot, 1 + DCI: endpoints).
    fn in_ctx(&self, di: usize, i: usize) -> Dma {
        self.devices[di].mem.at(DEV_IN_CTX + i * self.ctx)
    }

    /// Clears device `di`'s input context.
    fn clear_in_ctx(&self, di: usize) {
        unsafe { core::ptr::write_bytes(self.devices[di].mem.virt.add(DEV_IN_CTX), 0, PAGE) };
    }

    /// Writes device `di`'s slot context into its input context, with `entries` endpoint
    /// contexts (the highest DCI in use).
    fn write_slot_ctx(&self, di: usize, entries: u32) {
        let d = &self.devices[di];
        let mut dw0 = (d.route & 0xF_FFFF) | d.speed << 20 | entries << 27;
        let mut dw1 = d.port << 16;
        let mut dw2 = d.tt_slot | d.tt_port << 8;
        if let Some(h) = d.hub.as_ref() {
            dw0 |= 1 << 26 | (h.mtt as u32) << 25;
            dw1 |= h.ports << 24;
            dw2 |= h.think_time << 16;
        }
        let sl = self.in_ctx(di, 1);
        sl.w32(0, dw0);
        sl.w32(4, dw1);
        sl.w32(8, dw2);
        sl.w32(12, 0);
    }

    /// The device's configured endpoint contexts, highest DCI (for the slot context).
    fn max_dci(&self, di: usize) -> u32 {
        let d = &self.devices[di];
        let mut m = 1;
        for h in &d.hids {
            m = m.max(h.dci);
        }
        if let Some(s) = d.msd.as_ref() {
            m = m.max(s.dci_in).max(s.dci_out);
        }
        m
    }

    /// Reads a string descriptor (English) as ASCII into `out`; returns its length.
    fn string_descriptor(&mut self, di: usize, index: u8, out: &mut [u8]) -> usize {
        if index == 0 {
            return 0;
        }
        let Ok(n) = self.control(di, 0x80, 6, 0x0300 | index as u16, 0x0409, 255) else { return 0 };
        let s = self.devices[di].mem.bytes(DEV_CTL_BUF, n);
        let end = n.min(s.first().copied().unwrap_or(0) as usize);
        let mut len = 0;
        for ch in s.get(2..end).unwrap_or(&[]).chunks_exact(2) {
            if len == out.len() {
                break;
            }
            let c = u16::from_le_bytes([ch[0], ch[1]]);
            out[len] = if (0x20..0x7F).contains(&c) { c as u8 } else { b'?' };
            len += 1;
        }
        len
    }

    /// Addresses the device, reads its descriptors and starts what it offers: a hub, a
    /// USB disk or HID interfaces.
    fn setup_device(&mut self, di: usize) -> Result<(), &'static str> {
        let (slot, speed) = (self.devices[di].slot, self.devices[di].speed);
        // The first packet size for the default endpoint, by speed (full speed devices
        // say theirs in the device descriptor's first 8 bytes)
        let mps0: u32 = match speed {
            2 => 8,   // low speed
            1 => 8,   // full speed: 8 until known
            3 => 64,  // high speed
            _ => 512, // SuperSpeed
        };
        self.clear_in_ctx(di);
        let ctrl = self.in_ctx(di, 0);
        ctrl.w32(4, 0b11); // add the slot and EP0
        self.write_slot_ctx(di, 1);
        let ep0 = self.in_ctx(di, 2);
        ep0.w32(4, 3 << 1 | 4 << 3 | mps0 << 16); // 3 retries, control endpoint
        ep0.w64(8, self.devices[di].ep0.mem.phys | 1);
        ep0.w32(16, 8); // average TRB length
        let input = self.devices[di].mem.phys + DEV_IN_CTX as u64;
        self.command(input, TRB_ADDRESS_DEVICE << 10 | slot << 24, 3000)?;
        // The default endpoint's real packet size
        self.control(di, 0x80, 6, 0x0100, 0, 8)?;
        let b7 = self.devices[di].mem.bytes(DEV_CTL_BUF, 8)[7] as u32;
        let real = if speed >= 4 { 1u32 << b7.min(9) } else { b7 };
        if real != mps0 && real != 0 {
            ctrl.w32(0, 0);
            ctrl.w32(4, 0b10); // evaluate EP0
            ep0.w32(4, 3 << 1 | 4 << 3 | real << 16);
            self.command(input, TRB_EVALUATE_CONTEXT << 10 | slot << 24, 1000)?;
        }
        self.control(di, 0x80, 6, 0x0100, 0, 18)?;
        let dd: [u8; 18] = self.devices[di].mem.bytes(DEV_CTL_BUF, 18).try_into().unwrap();
        let (vendor, product) = (u16::from_le_bytes([dd[8], dd[9]]), u16::from_le_bytes([dd[10], dd[11]]));
        self.devices[di].vendor = vendor;
        self.devices[di].product = product;
        let class = dd[4];
        // The first configuration
        self.control(di, 0x80, 6, 0x0200, 0, 9)?;
        let head = self.devices[di].mem.bytes(DEV_CTL_BUF, 4);
        let total = (u16::from_le_bytes([head[2], head[3]]) as usize).min(PAGE);
        let got = self.control(di, 0x80, 6, 0x0200, 0, total as u16)?;
        let conf: Vec<u8> = self.devices[di].mem.bytes(DEV_CTL_BUF, got).to_vec();
        let found = hid::interfaces(&conf);
        let msd = storage::find_interface(&conf);
        println!(
            "[usb-driver] {}: device {:04x}:{:04x} (class {:#x}, speed {}), slot {}{}",
            self.loc(di),
            vendor,
            product,
            class,
            speed,
            slot,
            if class == 9 {
                ", hub"
            } else if msd.is_some() {
                ", mass storage"
            } else if !found.is_empty() {
                ", HID"
            } else {
                ""
            }
        );
        let config_value = conf.get(5).copied().unwrap_or(1);
        if class == 9 {
            return self.setup_hub(di, &dd, &conf, config_value);
        }
        if let Some(m) = msd {
            return self.setup_storage(di, &dd, m, config_value);
        }
        if found.is_empty() {
            // wave11 GH: say so (the log then names the device, e.g. a Wi-Fi adapter Hydra
            // has no driver for yet)
            println!("[usb-driver] {}: device {:04x}:{:04x}: no Hydra driver for it; ignored", self.loc(di), vendor, product);
            return Ok(());
        }
        self.control(di, 0x00, 9, config_value as u16, 0, 0)?;
        // Each HID interface's interrupt IN endpoint
        self.clear_in_ctx(di);
        let mut add = 1u32;
        for f in found.iter().take(4) {
            let dci = (f.ep_addr as u32 & 0xF) * 2 + 1;
            let mem = Dma::alloc(2)?;
            let ring = Ring::new(mem);
            self.write_interrupt_ep(di, dci, f.interval, f.max_packet, ring.mem.phys);
            add |= 1 << dci;
            let kind = match (f.subclass, f.protocol) {
                (1, 1) => HidKind::Keyboard,
                (1, 2) => HidKind::BootMouse,
                _ => HidKind::Pointer,
            };
            self.devices[di].hids.push(HidIf {
                kind,
                dci,
                ring,
                bufs: mem.at(PAGE),
                queued: [0; REPORTS_QUEUED],
                report_len: (f.max_packet as usize & 0x7FF).clamp(8, REPORT_BUF),
                layout: None,
                prev_keys: [0; 8],
                failed: false,
            });
        }
        let ctrl = self.in_ctx(di, 0);
        ctrl.w32(4, add);
        self.write_slot_ctx(di, self.max_dci(di));
        let input = self.devices[di].mem.phys + DEV_IN_CTX as u64;
        self.command(input, TRB_CONFIGURE_EP << 10 | slot << 24, 1000)?;
        // Class set-up: boot protocol for boot keyboards and mice, no idle repeats; a
        // report descriptor for the others
        for (i, f) in found.iter().take(4).enumerate() {
            let iface = f.number as u16;
            let kind = self.devices[di].hids[i].kind;
            if kind != HidKind::Pointer {
                // SET_PROTOCOL(boot); a device that refuses is already in it
                let _ = self.control(di, 0x21, 0x0B, 0, iface, 0);
            }
            // SET_IDLE(0): reports only on change (mice often refuse: harmless)
            let _ = self.control(di, 0x21, 0x0A, 0, iface, 0);
            if kind == HidKind::Pointer {
                let len = (f.report_desc_len as usize).clamp(1, PAGE);
                match self.control(di, 0x81, 6, 0x2200, iface, len as u16) {
                    Ok(n) => {
                        let layout = hid::parse(self.devices[di].mem.bytes(DEV_CTL_BUF, n));
                        if layout.is_none() {
                            println!("[usb-driver] {}: interface {}: not a pointer; ignored", self.loc(di), iface);
                            self.devices[di].hids[i].failed = true;
                        }
                        self.devices[di].hids[i].layout = layout;
                    }
                    Err(e) => {
                        println!("[usb-driver] {}: interface {}: no report descriptor: {}", self.loc(di), iface, e);
                        self.devices[di].hids[i].failed = true;
                    }
                }
            }
            let h = &self.devices[di].hids[i];
            println!(
                "[usb-driver] {}: interface {}: {}",
                self.loc(di),
                iface,
                match (h.kind, &h.layout) {
                    (HidKind::Keyboard, _) => "keyboard",
                    (HidKind::BootMouse, _) => "mouse",
                    (_, Some(l)) if l.absolute => "absolute pointer (tablet)",
                    (_, Some(_)) => "mouse (report protocol)",
                    _ => "unsupported",
                }
            );
        }
        self.start_interrupt_eps(di);
        Ok(())
    }

    /// Writes the input context of an interrupt IN endpoint (`interval` as the endpoint
    /// descriptor says it).
    fn write_interrupt_ep(&self, di: usize, dci: u32, interval: u8, max_packet: u16, ring: u64) {
        let speed = self.devices[di].speed;
        // Interval in 2^n * 125 us: full and low speed give milliseconds, high and
        // SuperSpeed an exponent
        let interval = if speed <= 2 {
            (31 - (interval.max(1) as u32 * 8).leading_zeros()).clamp(3, 10)
        } else {
            (interval.clamp(1, 16) as u32) - 1
        };
        let mps = max_packet as u32 & 0x7FF;
        let ep = self.in_ctx(di, 1 + dci as usize);
        ep.w32(0, interval << 16);
        ep.w32(4, 3 << 1 | 7 << 3 | mps << 16); // interrupt IN
        ep.w64(8, ring | 1);
        ep.w32(16, mps | mps << 16); // average TRB length, max ESIT payload
    }

    /// Queues the report transfers of device `di`'s interrupt endpoints.
    fn start_interrupt_eps(&mut self, di: usize) {
        let slot = self.devices[di].slot;
        for i in 0..self.devices[di].hids.len() {
            if !self.devices[di].hids[i].failed {
                for b in 0..REPORTS_QUEUED {
                    self.queue_report(di, i, b);
                }
                let dci = self.devices[di].hids[i].dci;
                self.ring_doorbell(slot, dci);
            }
        }
    }

    /// Queues a transfer for report buffer `b` of HID interface `hi` (the doorbell is rung
    /// by the caller).
    fn queue_report(&mut self, di: usize, hi: usize, b: usize) {
        let h = &mut self.devices[di].hids[hi];
        let buf = h.bufs.phys + (b * REPORT_BUF) as u64;
        let trb = h.ring.push(buf, h.report_len as u32, TRB_NORMAL << 10 | TRB_IOC | TRB_ISP);
        h.queued[b] = trb;
    }

    /// A finished interrupt transfer: its report becomes input records (or, from a hub, a
    /// note to look at its ports), and the buffer is queued again.
    fn hid_report(&mut self, slot: u32, dci: u32, trb: u64, code: u32, residual: u32) {
        let Some(di) = self.dev_of_slot(slot) else { return };
        let Some(hi) = self.devices[di].hids.iter().position(|h| h.dci == dci) else { return };
        let Some(b) = self.devices[di].hids[hi].queued.iter().position(|&t| t == trb) else { return };
        if code != CC_SUCCESS && code != CC_SHORT_PACKET {
            let h = &mut self.devices[di].hids[hi];
            if !h.failed {
                println!("[usb-driver] slot {} endpoint {}: transfer error {}; resetting the endpoint", slot, dci, code);
                h.failed = true;
                // Recovering issues commands, which drain events: done outside this
                // event (see `recover_failed`)
            }
            return;
        }
        let h = &self.devices[di].hids[hi];
        let len = h.report_len.saturating_sub(residual as usize);
        let mut report = [0u8; 64];
        let n = len.min(report.len());
        report[..n].copy_from_slice(h.bufs.bytes(b * REPORT_BUF, n));
        let report = &report[..n];
        match h.kind {
            HidKind::Keyboard => {
                let prev = h.prev_keys;
                let mut cur = [0u8; 8];
                cur[..n.min(8)].copy_from_slice(&report[..n.min(8)]);
                // Keyboard rollover error (all keys 0x01): no information
                if cur[2] != 1 {
                    hid::keyboard_changes(&prev, &cur, |code| self.out.push([1, code, 0, 0, 0, 0, 0, 0]));
                    self.devices[di].hids[hi].prev_keys = cur;
                }
            }
            HidKind::BootMouse => {
                if n >= 3 {
                    let dx = report[1] as i8 as i16;
                    let dy = report[2] as i8 as i16;
                    let wheel = if n >= 4 { report[3] } else { 0 };
                    let (x, y) = (dx.to_le_bytes(), dy.to_le_bytes());
                    self.out.push([2, report[0] & 7, x[0], x[1], y[0], y[1], wheel, 0]);
                }
            }
            HidKind::Pointer => {
                if let Some(rec) = h.layout.as_ref().and_then(|l| l.decode(report)) {
                    self.out.push(rec);
                }
            }
            HidKind::HubStatus => {
                if report.iter().any(|&b| b != 0) && !self.hub_changes.contains(&slot) {
                    self.hub_changes.push(slot);
                }
            }
        }
        if self.out.len() > WINDOW_SIZE / 8 {
            self.out.drain(..self.out.len() - WINDOW_SIZE / 8);
        }
        self.queue_report(di, hi, b);
        self.ring_doorbell(slot, dci);
    }

    /// Resets the endpoints whose transfers failed and queues their reports again.
    fn recover_failed(&mut self) {
        for di in 0..self.devices.len() {
            for hi in 0..self.devices[di].hids.len() {
                let h = &self.devices[di].hids[hi];
                if !h.failed || (h.kind == HidKind::Pointer && h.layout.is_none()) {
                    continue;
                }
                let dci = h.dci;
                self.recover_endpoint(di, dci);
                self.devices[di].hids[hi].failed = false;
                for b in 0..REPORTS_QUEUED {
                    self.queue_report(di, hi, b);
                }
                self.ring_doorbell(self.devices[di].slot, dci);
            }
        }
    }

    /// Forgets device `di` and frees its slot.
    fn detach(&mut self, di: usize) {
        let d = self.devices.remove(di);
        if d.msd.is_some() {
            self.disk_generation = self.disk_generation.wrapping_add(1);
        }
        for disk in self.disks.iter_mut() {
            if *disk == d.slot {
                *disk = 0;
            }
        }
        self.bulk_done.retain(|x| x.slot != d.slot);
        self.hub_changes.retain(|&s| s != d.slot);
        let _ = self.command(0, TRB_DISABLE_SLOT << 10 | d.slot << 24, 1000);
        self.mem.w64(MEM_DCBAA + d.slot as usize * 8, 0);
        // Its DMA memory stays allocated (there is no call to free it); a few pages
        // per unplug
    }

    /// Forgets the device at root port `port`, `route`/`depth`, and everything behind it
    /// (devices on a hub that went away), the farthest first.
    fn detach_tree(&mut self, port: u32, route: u32, depth: u32) {
        let mask = if depth == 0 { 0 } else { (1u32 << (4 * depth)) - 1 };
        loop {
            let found = self
                .devices
                .iter()
                .enumerate()
                .filter(|(_, d)| d.port == port && d.depth >= depth && d.route & mask == route & mask)
                .max_by_key(|(_, d)| d.depth)
                .map(|(i, _)| i);
            let Some(di) = found else { break };
            println!("[usb-driver] {}: device removed", self.loc(di));
            self.detach(di);
        }
    }

    /// Looks at the ports whose status changed: new devices are set up, removed ones
    /// forgotten; then the same for hub ports.
    fn handle_port_changes(&mut self) {
        while let Some(port) = self.port_changes.pop() {
            if port == 0 || port > self.max_ports {
                continue;
            }
            let sc = self.portsc(port);
            self.set_portsc(port, (sc & !PORT_WRITE_ZERO) | (sc & PORT_CHANGES));
            let present = sc & PORT_CCS != 0;
            let known = self.devices.iter().any(|d| d.port == port && d.depth == 0);
            // A connect change with the port disabled while a device is known: it was
            // replaced; forget the old one first
            let replaced = known && sc & (1 << 17) != 0 && sc & PORT_PED == 0;
            if known && (!present || replaced) {
                self.detach_tree(port, 0, 0);
            }
            if present && !self.devices.iter().any(|d| d.port == port && d.depth == 0) {
                if let Err(e) = self.attach(port) {
                    println!("[usb-driver] port {}: {}", port, e);
                }
            }
        }
        while let Some(slot) = self.hub_changes.pop() {
            if let Some(di) = self.dev_of_slot(slot) {
                self.hub_service(di);
            }
        }
    }

    /// Everything a request from the kernel starts with: events taken, plugged and
    /// unplugged devices handled, failed interrupt endpoints restarted.
    fn housekeeping(&mut self) {
        self.drain_events();
        if !self.port_changes.is_empty() || !self.hub_changes.is_empty() {
            self.handle_port_changes();
        }
        self.recover_failed();
    }
}

/// Value of a `key=<number>` argument (decimal or `0x` hex).
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Driver entry point: takes over the controller, sets up the devices on its ports and
/// serves input and disk requests.
fn main(args: &[&str]) {
    let (Some(mmio), Some(len)) = (arg(args, "mmio"), arg(args, "len")) else {
        println!("[usb-driver] no controller given (mmio=... len=...)");
        return;
    };
    let cap = match sys::physmap(mmio, len as usize) {
        Ok(r) => r,
        Err(e) => {
            println!("[usb-driver] cannot map the registers at {:#x}: error {}", mmio, e);
            return;
        }
    };
    let caplen = rd(cap, CAP_CAPLENGTH) & 0xFF;
    let version = rd(cap, CAP_CAPLENGTH) >> 16;
    let p1 = rd(cap, CAP_HCSPARAMS1);
    let hcc = rd(cap, CAP_HCCPARAMS1);
    let mem = match Dma::alloc(MEM_PAGES) {
        Ok(m) => m,
        Err(e) => {
            println!("[usb-driver] {}", e);
            return;
        }
    };
    if hcc & 1 == 0 && mem.phys >= 0x1_0000_0000 {
        println!("[usb-driver] the controller reaches only 32-bit addresses and the DMA memory is above 4 GiB");
        return;
    }
    // MSI-X: the kernel enabled it with vector 0 masked; the table is in the register
    // window, so this driver writes the vector's message and unmasks it
    if let Some(spec) = args.iter().find_map(|a| a.strip_prefix("msix=")) {
        let parts: Vec<u64> = spec.split(':').filter_map(|p| u64::from_str_radix(p.trim_start_matches("0x"), 16).ok()).collect();
        match parts[..] {
            [table, addr, data] if table >= mmio && table + 16 <= mmio + len => {
                let entry = unsafe { cap.add((table - mmio) as usize) };
                wr(entry, 0, addr as u32);
                wr(entry, 4, 0);
                wr(entry, 8, data as u32);
                wr(entry, 12, 0); // unmasked
            }
            _ => println!("[usb-driver] MSI-X table outside the register window: interrupts unavailable"),
        }
    }
    let irq = arg(args, "irq").map(|i| i as u8).filter(|&i| sys::irq_register(i).is_ok());
    let mut hc = Xhci {
        cap,
        op: unsafe { cap.add(caplen as usize) },
        rt: unsafe { cap.add((rd(cap, CAP_RTSOFF) & !0x1F) as usize) },
        db: unsafe { cap.add((rd(cap, CAP_DBOFF) & !0x3) as usize) },
        irq,
        max_slots: p1 & 0xFF,
        max_ports: p1 >> 24,
        ctx: if hcc & (1 << 2) != 0 { 64 } else { 32 },
        mem,
        cmd: Ring::new(mem.at(MEM_CMD_RING)),
        ev_deq: 0,
        ev_cycle: true,
        devices: Vec::new(),
        cmd_done: None,
        xfer_done: None,
        bulk_done: Vec::new(),
        port_changes: Vec::new(),
        hub_changes: Vec::new(),
        out: Vec::new(),
        disks: [0; storage::MAX_DISKS],
        disk_generation: 0,
        units: hydra_rt::blockunits::Units { pool: None },
        pool_generation: 0,
    };
    println!(
        "[usb-driver] xHCI {}.{:02x} at {:#x}: {} ports, {} slots, {}-byte contexts, {}",
        version >> 8,
        version & 0xFF,
        mmio,
        hc.max_ports,
        hc.max_slots,
        hc.ctx,
        if irq.is_some() { "MSI interrupt" } else { "polled" }
    );
    hc.bios_handoff();
    if let Err(e) = hc.reset().and_then(|_| hc.start()) {
        println!("[usb-driver] {}", e);
        return;
    }
    // USB 3 links train on their own after the reset; give them a moment, then look at
    // every port with something connected
    sys::sleep_ms(50);
    for port in 1..=hc.max_ports {
        if hc.portsc(port) & PORT_CCS != 0 && !hc.port_changes.contains(&port) {
            hc.port_changes.push(port);
        }
    }
    hc.drain_events();
    hc.handle_port_changes();
    // Devices behind hubs that reported their ports while the others were set up
    hc.housekeeping();
    hc.choose_pool(args);
    // The disk endpoint first: once the input endpoint is registered the supervisor
    // starts the services that may use the disks
    let disk_window = match sys::svc_register(ENDPOINT_USB_DISK) {
        Ok(w) => Some(w as *mut u8),
        Err(e) => {
            println!("[usb-driver] cannot register on endpoint {:#x}: error {}; no USB disks", ENDPOINT_USB_DISK, e);
            None
        }
    };
    let mut server = match Server::register(ENDPOINT_INPUT_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[usb-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_INPUT_DEV, e);
            return;
        }
    };
    println!("[usb-driver] ready: {} device(s), {} disk(s)", hc.devices.len(), hc.disks.iter().filter(|&&s| s != 0).count());
    server.serve(|srv, msg| {
        let label = msg.label as u32;
        if label == MSG_INPUT_READ {
            hc.housekeeping();
            if let Some(irq) = hc.irq {
                let _ = sys::irq_ack(irq);
            }
            let n = hc.out.len().min(WINDOW_SIZE / 8);
            let w = srv.window();
            for (i, r) in hc.out.drain(..n).enumerate() {
                w[i * 8..i * 8 + 8].copy_from_slice(&r);
            }
            return Message::new(MSG_INPUT_REPLY as u64, [0, n as u64, hc.devices.len() as u64, 0]);
        }
        if (0x2000..0x2010).contains(&label) {
            let Some(w) = disk_window else {
                return Message::new(MSG_BLOCK_REPLY as u64, [(-19i64) as u64, 0, 0, 0]);
            };
            let window = unsafe { core::slice::from_raw_parts_mut(w, WINDOW_SIZE) };
            let reply = hc.block_request(msg, window);
            if let Some(irq) = hc.irq {
                let _ = sys::irq_ack(irq);
            }
            return reply;
        }
        Message::new(MSG_INPUT_REPLY as u64, [(-38i64) as u64, 0, 0, 0])
    })
}
