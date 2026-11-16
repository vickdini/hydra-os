//! # Hydra USB driver (xHCI host controller, HID input devices)
//!
//! Drives one xHCI USB host controller from Ring 3, in an address space of its own: its
//! registers are the device memory the supervisor granted (PCI `BAR0`), its rings and
//! contexts DMA memory this driver allocates. It enumerates the devices on the root ports
//! and runs the HID ones: keyboards (boot protocol), mice (boot protocol) and pointers
//! described by their report descriptor (tablets such as QEMU's `usb-tablet`, which
//! report absolute positions).
//!
//! The supervisor starts it with `mmio=<phys> len=<bytes>` and, when the kernel routed the
//! controller's message-signalled interrupt (MSI) to it, `irq=<line>`.
//!
//! Requests on [`ENDPOINT_INPUT_DEV`]: `MSG_INPUT_READ` services the controller's event
//! ring (finished interrupt transfers carry HID reports; port changes plug devices in and
//! out) and returns the input since the last request as 8-byte records in the service
//! window (see the protocol). The kernel's USB input task asks whenever the controller
//! interrupts, and a few times a second regardless.
//!
//! Limits: devices behind a USB hub are not enumerated (keyboards and mice must be on the
//! computer's own ports); keyboard LEDs are not driven; keys do not auto-repeat in the
//! Hydra console (desktops repeat keys themselves).

#![no_std]
#![no_main]

extern crate alloc;

mod hid;

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use hydra_rt::protocol::{ENDPOINT_INPUT_DEV, MSG_INPUT_READ, MSG_INPUT_REPLY};
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
const TRB_SET_TR_DEQUEUE: u32 = 16;
const TRB_EV_TRANSFER: u32 = 32;
const TRB_EV_COMMAND: u32 = 33;
const TRB_EV_PORT: u32 = 34;

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
/// Most devices handled.
const MAX_DEVICES: usize = 16;

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
            // Link back to the start, toggling the cycle state (TC)
            let off = self.enq * 16;
            self.mem.w64(off, self.mem.phys);
            self.mem.w32(off + 8, 0);
            fence(Ordering::SeqCst);
            self.mem.w32(off + 12, TRB_LINK << 10 | 1 << 1 | self.cycle as u32);
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

/// What a HID interface is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HidKind {
    Keyboard,
    BootMouse,
    /// A pointer described by its report descriptor.
    Pointer,
}

/// One HID interface's interrupt IN endpoint and its state.
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
    port: u32,
    speed: u32,
    /// Output device context, input context, EP0 ring, control buffer (one page each).
    mem: Dma,
    ep0: Ring,
    hids: Vec<HidIf>,
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

/// A completed control transfer: slot, completion code, bytes not transferred.
#[derive(Clone, Copy)]
struct XferDone {
    slot: u32,
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
    /// Root ports with a status change to look at.
    port_changes: Vec<u32>,
    /// Input records not yet collected.
    out: Vec<[u8; 8]>,
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

impl Xhci {
    fn portsc(&self, port: u32) -> u32 {
        rd(self.op, OP_PORTSC + (port as usize - 1) * 0x10)
    }

    fn set_portsc(&self, port: u32, v: u32) {
        wr(self.op, OP_PORTSC + (port as usize - 1) * 0x10, v)
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
                    if dci == 1 {
                        self.xfer_done = Some(XferDone { slot, trb: param, code, residual: status & 0xFF_FFFF });
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
        let trb = self.cmd.push(param, 0, control);
        self.cmd_done = None;
        self.ring_doorbell(0, 0);
        let d = Deadline::after_ms(ms);
        loop {
            self.drain_events();
            if let Some(c) = self.cmd_done.filter(|c| c.trb == trb) {
                return if c.code == CC_SUCCESS {
                    Ok(c.slot)
                } else {
                    println!("[usb-driver] command {} failed: completion code {}", (control >> 10) & 0x3F, c.code);
                    Err("command failed")
                };
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
                self.recover_endpoint(di, 1);
                return Err("control transfer timed out");
            }
            self.pause();
        }
    }

    /// Brings a halted endpoint back: Reset Endpoint, then its dequeue pointer moved past
    /// whatever was left on the ring.
    fn recover_endpoint(&mut self, di: usize, dci: u32) {
        let slot = self.devices[di].slot;
        let _ = self.command(0, TRB_RESET_EP << 10 | dci << 16 | slot << 24, 1000);
        let deq = if dci == 1 {
            self.devices[di].ep0.dequeue_pointer()
        } else {
            match self.devices[di].hids.iter().find(|h| h.dci == dci) {
                Some(h) => h.ring.dequeue_pointer(),
                None => return,
            }
        };
        let _ = self.command(deq, TRB_SET_TR_DEQUEUE << 10 | dci << 16 | slot << 24, 1000);
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

    /// Sets up the device on root port `port`; returns a description for the log.
    fn attach(&mut self, port: u32) -> Result<(), &'static str> {
        if self.devices.iter().any(|d| d.port == port) {
            return Ok(());
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err("too many devices");
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
        let slot = self.command(0, TRB_ENABLE_SLOT << 10, 1000)?;
        let mem = Dma::alloc(DEV_PAGES)?;
        let ep0 = Ring::new(mem.at(DEV_EP0_RING));
        self.mem.w64(MEM_DCBAA + slot as usize * 8, mem.phys + DEV_OUT_CTX as u64);
        self.devices.push(Device { slot, port, speed, mem, ep0, hids: Vec::new() });
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

    /// Addresses the device, reads its descriptors and starts its HID interfaces.
    fn setup_device(&mut self, di: usize) -> Result<(), &'static str> {
        let (slot, port, speed) = (self.devices[di].slot, self.devices[di].port, self.devices[di].speed);
        // The first packet size for the default endpoint, by speed (full speed devices
        // say theirs in the device descriptor's first 8 bytes)
        let mps0: u32 = match speed {
            2 => 8,   // low speed
            1 => 8,   // full speed: 8 until known
            3 => 64,  // high speed
            _ => 512, // SuperSpeed
        };
        unsafe { core::ptr::write_bytes(self.devices[di].mem.virt.add(DEV_IN_CTX), 0, PAGE) };
        let ctrl = self.in_ctx(di, 0);
        ctrl.w32(4, 0b11); // add the slot and EP0
        let sl = self.in_ctx(di, 1);
        sl.w32(0, speed << 20 | 1 << 27);
        sl.w32(4, port << 16);
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
        let dd = self.devices[di].mem.bytes(DEV_CTL_BUF, 18);
        let (vendor, product) = (u16::from_le_bytes([dd[8], dd[9]]), u16::from_le_bytes([dd[10], dd[11]]));
        let class = dd[4];
        // The first configuration
        self.control(di, 0x80, 6, 0x0200, 0, 9)?;
        let total = (u16::from_le_bytes([self.devices[di].mem.bytes(DEV_CTL_BUF, 4)[2], self.devices[di].mem.bytes(DEV_CTL_BUF, 4)[3]]) as usize).min(PAGE);
        let got = self.control(di, 0x80, 6, 0x0200, 0, total as u16)?;
        let conf: Vec<u8> = self.devices[di].mem.bytes(DEV_CTL_BUF, got).to_vec();
        let found = hid::interfaces(&conf);
        println!(
            "[usb-driver] port {}: device {:04x}:{:04x} (class {:#x}, speed {}), slot {}, {} HID interface(s)",
            port, vendor, product, class, speed, slot, found.len()
        );
        if class == 9 {
            println!("[usb-driver] port {}: a USB hub; devices behind hubs are not supported yet", port);
            return Ok(());
        }
        if found.is_empty() {
            return Ok(());
        }
        let config_value = conf.get(5).copied().unwrap_or(1);
        self.control(di, 0x00, 9, config_value as u16, 0, 0)?;
        // Each HID interface's interrupt IN endpoint
        unsafe { core::ptr::write_bytes(self.devices[di].mem.virt.add(DEV_IN_CTX), 0, PAGE) };
        let mut add = 1u32;
        let mut max_dci = 1;
        for f in found.iter().take(4) {
            let dci = (f.ep_addr as u32 & 0xF) * 2 + 1;
            let mem = Dma::alloc(2)?;
            let ring = Ring::new(mem);
            // Interval in 2^n * 125 us: full and low speed give milliseconds, high and
            // SuperSpeed an exponent
            let interval = if speed <= 2 {
                (31 - (f.interval.max(1) as u32 * 8).leading_zeros()).clamp(3, 10)
            } else {
                (f.interval.clamp(1, 16) as u32) - 1
            };
            let mps = f.max_packet as u32 & 0x7FF;
            let ep = self.in_ctx(di, 1 + dci as usize);
            ep.w32(0, interval << 16);
            ep.w32(4, 3 << 1 | 7 << 3 | mps << 16); // interrupt IN
            ep.w64(8, ring.mem.phys | 1);
            ep.w32(16, mps | mps << 16); // average TRB length, max ESIT payload
            add |= 1 << dci;
            max_dci = max_dci.max(dci);
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
                report_len: (mps as usize).clamp(8, REPORT_BUF),
                layout: None,
                prev_keys: [0; 8],
                failed: false,
            });
        }
        let ctrl = self.in_ctx(di, 0);
        ctrl.w32(4, add);
        let sl = self.in_ctx(di, 1);
        sl.w32(0, speed << 20 | max_dci << 27);
        sl.w32(4, port << 16);
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
                            println!("[usb-driver] port {}: interface {}: not a pointer; ignored", port, iface);
                            self.devices[di].hids[i].failed = true;
                        }
                        self.devices[di].hids[i].layout = layout;
                    }
                    Err(e) => {
                        println!("[usb-driver] port {}: interface {}: no report descriptor: {}", port, iface, e);
                        self.devices[di].hids[i].failed = true;
                    }
                }
            }
            let h = &self.devices[di].hids[i];
            println!(
                "[usb-driver] port {}: interface {}: {}",
                port,
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
        for i in 0..self.devices[di].hids.len() {
            if !self.devices[di].hids[i].failed {
                for b in 0..REPORTS_QUEUED {
                    self.queue_report(di, i, b);
                }
                let dci = self.devices[di].hids[i].dci;
                self.ring_doorbell(slot, dci);
            }
        }
        Ok(())
    }

    /// Queues a transfer for report buffer `b` of HID interface `hi` (the doorbell is rung
    /// by the caller).
    fn queue_report(&mut self, di: usize, hi: usize, b: usize) {
        let h = &mut self.devices[di].hids[hi];
        let buf = h.bufs.phys + (b * REPORT_BUF) as u64;
        let trb = h.ring.push(buf, h.report_len as u32, TRB_NORMAL << 10 | TRB_IOC | TRB_ISP);
        h.queued[b] = trb;
    }

    /// A finished interrupt transfer: its report becomes input records, and the buffer
    /// is queued again.
    fn hid_report(&mut self, slot: u32, dci: u32, trb: u64, code: u32, residual: u32) {
        let Some(di) = self.devices.iter().position(|d| d.slot == slot) else { return };
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
        let _ = self.command(0, TRB_DISABLE_SLOT << 10 | d.slot << 24, 1000);
        self.mem.w64(MEM_DCBAA + d.slot as usize * 8, 0);
        // Its DMA memory stays allocated (there is no call to free it); a few pages
        // per unplug
    }

    /// Looks at the ports whose status changed: new devices are set up, removed ones
    /// forgotten.
    fn handle_port_changes(&mut self) {
        while let Some(port) = self.port_changes.pop() {
            if port == 0 || port > self.max_ports {
                continue;
            }
            let sc = self.portsc(port);
            self.set_portsc(port, (sc & !PORT_WRITE_ZERO) | (sc & PORT_CHANGES));
            let present = sc & PORT_CCS != 0;
            let known = self.devices.iter().position(|d| d.port == port);
            match (present, known) {
                (true, None) => {
                    if let Err(e) = self.attach(port) {
                        println!("[usb-driver] port {}: {}", port, e);
                    }
                }
                (false, Some(di)) => {
                    println!("[usb-driver] port {}: device removed", port);
                    self.detach(di);
                }
                _ => {}
            }
        }
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
/// serves input requests.
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
        port_changes: Vec::new(),
        out: Vec::new(),
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
    let mut server = match Server::register(ENDPOINT_INPUT_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[usb-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_INPUT_DEV, e);
            return;
        }
    };
    println!("[usb-driver] ready: {} device(s)", hc.devices.len());
    server.serve(|srv, msg| match msg.label as u32 {
        MSG_INPUT_READ => {
            hc.drain_events();
            if !hc.port_changes.is_empty() {
                hc.handle_port_changes();
            }
            hc.recover_failed();
            if let Some(irq) = hc.irq {
                let _ = sys::irq_ack(irq);
            }
            let n = hc.out.len().min(WINDOW_SIZE / 8);
            let w = srv.window();
            for (i, r) in hc.out.drain(..n).enumerate() {
                w[i * 8..i * 8 + 8].copy_from_slice(&r);
            }
            Message::new(MSG_INPUT_REPLY as u64, [0, n as u64, hc.devices.len() as u64, 0])
        }
        _ => Message::new(MSG_INPUT_REPLY as u64, [(-38i64) as u64, 0, 0, 0]),
    })
}
