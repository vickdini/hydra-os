//! USB mass storage: Bulk-Only Transport (BOT, class 08, subclass 06 SCSI, protocol 50)
//! with SCSI commands, and the block requests the kernel and the file server send for the
//! USB disks.
//!
//! Each SCSI command is a Command Block Wrapper (CBW, 31 bytes) on the bulk OUT endpoint,
//! an optional data stage on the bulk IN or OUT endpoint, and a Command Status Wrapper
//! (CSW, 13 bytes) on the bulk IN endpoint. Error handling follows the BOT specification
//! (section 5.3 and 6.6): a stalled data stage is cleared and the CSW read anyway; a
//! stalled CSW is read once more; an invalid CSW, a phase error or a transfer that fails
//! or times out gets a reset recovery (Bulk-Only Mass Storage Reset, then both bulk
//! endpoints cleared). A failed command (CSW status 1) is followed by REQUEST SENSE.
//!
//! Disks are served in 4 KiB blocks whatever their sector size (512 or 4096 bytes; 1024
//! and 2048 work too). A request is split into SCSI commands of at most
//! [`MAX_XFER_BLOCKS`] blocks (120 KiB, what Linux's usb-storage sends: some sticks fail
//! larger ones), through a DMA bounce buffer.

use alloc::vec::Vec;

use hydra_rt::protocol::{
    BLOCK_LIST_RECORD, BLOCK_READV_MAX, BLOCK_READV_TABLE, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_LIST, MSG_BLOCK_READ, MSG_BLOCK_READV,
    MSG_BLOCK_REPLY, MSG_BLOCK_WRITE,
};
use hydra_rt::Message;

use crate::{println, sys, Deadline, Dma, Ring, Xhci, CC_SHORT_PACKET, CC_STALL, CC_SUCCESS, DEV_IN_CTX, PAGE, TRB_CH, TRB_CONFIGURE_EP, TRB_IOC, TRB_ISP, TRB_NORMAL};

/// Most USB disks served at once.
pub const MAX_DISKS: usize = 8;
/// Bytes of a block request's unit.
const BLOCK: usize = 4096;
/// Most 4 KiB blocks per SCSI command (120 KiB).
const MAX_XFER_BLOCKS: usize = 30;
/// Pages of the bounce buffer (128 KiB).
const DATA_PAGES: usize = 32;

/// Offsets in the command page: CBW, CSW.
const CBW_OFF: usize = 0;
const CSW_OFF: usize = 64;

const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;

// Error numbers of the replies
const EIO: i64 = -5;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EROFS: i64 = -30;
const ENOSYS: i64 = -38;
const ENOMEDIUM: i64 = -123;

// SCSI sense keys
const NOT_READY: u8 = 2;
const MEDIUM_ERROR: u8 = 3;
const ILLEGAL_REQUEST: u8 = 5;
const UNIT_ATTENTION: u8 = 6;

/// A mass storage interface found in a configuration descriptor.
pub struct MsdIf {
    iface: u8,
    ep_in: u8,
    ep_out: u8,
    mps_in: u16,
    mps_out: u16,
    burst_in: u8,
    burst_out: u8,
}

/// The first Bulk-Only SCSI interface (alternate setting 0) with both bulk endpoints.
pub fn find_interface(conf: &[u8]) -> Option<MsdIf> {
    let mut cur: Option<MsdIf> = None;
    // The endpoint the next SuperSpeed companion descriptor belongs to (true: IN)
    let mut last_in: Option<bool> = None;
    let mut at = 0;
    while at + 2 <= conf.len() {
        let (len, ty) = (conf[at] as usize, conf[at + 1]);
        if len < 2 || at + len > conf.len() {
            break;
        }
        let d = &conf[at..at + len];
        match ty {
            4 if len >= 9 => {
                if let Some(m) = cur.take() {
                    if m.ep_in != 0 && m.ep_out != 0 {
                        return Some(m);
                    }
                }
                last_in = None;
                // Class 8 (mass storage), subclass 6 (SCSI transparent), protocol 0x50 (BOT)
                if d[3] == 0 && d[5] == 8 && d[6] == 6 && d[7] == 0x50 {
                    cur = Some(MsdIf { iface: d[2], ep_in: 0, ep_out: 0, mps_in: 0, mps_out: 0, burst_in: 0, burst_out: 0 });
                }
            }
            5 if len >= 7 => {
                last_in = None;
                if let Some(m) = cur.as_mut() {
                    if d[3] & 3 == 2 {
                        let mps = u16::from_le_bytes([d[4], d[5]]) & 0x7FF;
                        if d[2] & 0x80 != 0 && m.ep_in == 0 {
                            m.ep_in = d[2];
                            m.mps_in = mps;
                            last_in = Some(true);
                        } else if d[2] & 0x80 == 0 && m.ep_out == 0 {
                            m.ep_out = d[2];
                            m.mps_out = mps;
                            last_in = Some(false);
                        }
                    }
                }
            }
            0x30 if len >= 6 => {
                if let (Some(m), Some(is_in)) = (cur.as_mut(), last_in) {
                    if is_in {
                        m.burst_in = d[2].min(15);
                    } else {
                        m.burst_out = d[2].min(15);
                    }
                }
            }
            _ => {}
        }
        at += len;
    }
    cur.filter(|m| m.ep_in != 0 && m.ep_out != 0)
}

/// A USB disk's state.
pub struct Msd {
    iface: u8,
    ep_in: u8,
    ep_out: u8,
    pub dci_in: u32,
    pub dci_out: u32,
    pub ring_in: Ring,
    pub ring_out: Ring,
    /// Endpoint context dword 1 of each (type, packet size, burst), to set them up again.
    ctx_in: u32,
    ctx_out: u32,
    /// CBW and CSW.
    cmd: Dma,
    /// Bounce buffer for the data.
    buf: Dma,
    tag: u32,
    /// Its disk number and the generation it got.
    disk: usize,
    generation: u32,
    sector_size: u32,
    sectors: u64,
    /// Whether the medium answered TEST UNIT READY and READ CAPACITY.
    ready: bool,
    removable: bool,
    write_protected: bool,
    /// Vendor, product and revision from INQUIRY, space padded.
    model: [u8; 40],
    /// Serial number string, space padded.
    serial: [u8; 32],
}

/// Why a SCSI command failed.
#[derive(Clone, Copy)]
enum ScsiError {
    /// The device answered with this sense key, ASC and ASCQ.
    Sense(u8, u8, u8),
    /// The transport failed (after a reset recovery).
    Transport(&'static str),
}

impl core::fmt::Display for ScsiError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ScsiError::Sense(k, a, q) => write!(f, "sense key {:#x}, ASC {:#04x}, ASCQ {:#04x}", k, a, q),
            ScsiError::Transport(e) => write!(f, "{}", e),
        }
    }
}

/// A big-endian SCSI field.
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

impl Xhci {
    fn msd(&self, di: usize) -> &Msd {
        self.devices[di].msd.as_ref().unwrap()
    }

    fn msd_mut(&mut self, di: usize) -> &mut Msd {
        self.devices[di].msd.as_mut().unwrap()
    }

    /// Sets up USB disk `di`: its bulk endpoints, its configuration, then the SCSI
    /// identification and capacity.
    pub(crate) fn setup_storage(&mut self, di: usize, dd: &[u8; 18], m: MsdIf, config_value: u8) -> Result<(), &'static str> {
        let slot = self.devices[di].slot;
        let Some(disk) = self.disks.iter().position(|&s| s == 0) else { return Err("too many USB disks") };
        let rings = Dma::alloc(2)?;
        let cmd = Dma::alloc(1)?;
        let buf = Dma::alloc(DATA_PAGES)?;
        let (dci_in, dci_out) = ((m.ep_in as u32 & 0xF) * 2 + 1, (m.ep_out as u32 & 0xF) * 2);
        // Bulk endpoints: 3 retries, type 6 (bulk IN) or 2 (bulk OUT), burst, packet size
        let ctx_in = 3 << 1 | 6 << 3 | (m.burst_in as u32) << 8 | (m.mps_in as u32) << 16;
        let ctx_out = 3 << 1 | 2 << 3 | (m.burst_out as u32) << 8 | (m.mps_out as u32) << 16;
        self.devices[di].msd = Some(Msd {
            iface: m.iface,
            ep_in: m.ep_in,
            ep_out: m.ep_out,
            dci_in,
            dci_out,
            ring_in: Ring::new(rings),
            ring_out: Ring::new(rings.at(PAGE)),
            ctx_in,
            ctx_out,
            cmd,
            buf,
            tag: 0,
            disk,
            generation: 0,
            sector_size: 512,
            sectors: 0,
            ready: false,
            removable: false,
            write_protected: false,
            model: [b' '; 40],
            serial: [b' '; 32],
        });
        self.clear_in_ctx(di);
        self.in_ctx(di, 0).w32(4, 1 | 1 << dci_in | 1 << dci_out);
        self.write_slot_ctx(di, self.max_dci(di));
        self.write_bulk_ctx(di, dci_in);
        self.write_bulk_ctx(di, dci_out);
        let input = self.devices[di].mem.phys + DEV_IN_CTX as u64;
        if let Err(e) = self.command(input, TRB_CONFIGURE_EP << 10 | slot << 24, 1000) {
            self.devices[di].msd = None;
            return Err(e);
        }
        self.control(di, 0x00, 9, config_value as u16, 0, 0)?;
        // GET MAX LUN (devices with one LUN may stall it); LUN 0 is used either way
        let luns = match self.control(di, 0xA1, 0xFE, 0, m.iface as u16, 1) {
            Ok(1) => self.devices[di].mem.bytes(crate::DEV_CTL_BUF, 1)[0] as u32 + 1,
            _ => 1,
        };
        let mut serial = [b' '; 32];
        self.string_descriptor(di, dd[16], &mut serial);
        self.disk_generation = self.disk_generation.wrapping_add(1);
        let generation = self.disk_generation;
        {
            let s = self.msd_mut(di);
            s.serial = serial;
            s.disk = disk;
            s.generation = generation;
        }
        self.disks[disk] = slot;
        self.identify(di)?;
        self.probe_medium(di, 3000);
        let s = self.msd(di);
        println!(
            "[usb-driver] {}: USB disk {}: '{}', {} MiB, {}-byte sectors{}{}{}, {} LUN(s), serial '{}'",
            self.loc(di),
            disk,
            core::str::from_utf8(&s.model).unwrap_or("?").trim_end(),
            s.sectors * s.sector_size as u64 / (1024 * 1024),
            s.sector_size,
            if s.ready { "" } else { ", no medium" },
            if s.removable { ", removable" } else { "" },
            if s.write_protected { ", write-protected" } else { "" },
            luns,
            core::str::from_utf8(&s.serial).unwrap_or("?").trim_end()
        );
        Ok(())
    }

    /// Writes bulk endpoint `dci`'s context into device `di`'s input context, its ring
    /// starting where the next transfer goes.
    fn write_bulk_ctx(&self, di: usize, dci: u32) {
        let s = self.msd(di);
        let (dw1, deq) = if dci == s.dci_in { (s.ctx_in, s.ring_in.dequeue_pointer()) } else { (s.ctx_out, s.ring_out.dequeue_pointer()) };
        let ep = self.in_ctx(di, 1 + dci as usize);
        ep.w32(0, 0);
        ep.w32(4, dw1);
        ep.w64(8, deq);
        ep.w32(16, 3072); // average TRB length (xHCI 4.14.1.1: bulk)
    }

    /// Resets the host side of bulk endpoint `dci` (its data toggle or sequence number)
    /// when it is not halted: the endpoint is dropped and added again (Linux
    /// `xhci_endpoint_reset`).
    fn reinit_bulk(&mut self, di: usize, dci: u32) {
        self.stop_endpoint(di, dci);
        self.clear_in_ctx(di);
        let ctrl = self.in_ctx(di, 0);
        ctrl.w32(0, 1 << dci);
        ctrl.w32(4, 1 | 1 << dci);
        self.write_slot_ctx(di, self.max_dci(di));
        self.write_bulk_ctx(di, dci);
        let slot = self.devices[di].slot;
        let input = self.devices[di].mem.phys + DEV_IN_CTX as u64;
        let _ = self.command(input, TRB_CONFIGURE_EP << 10 | slot << 24, 1000);
    }

    /// Clears a halted (or stuck) bulk endpoint on both sides: the controller's endpoint
    /// reset (or set up again) and the device's CLEAR_FEATURE(ENDPOINT_HALT).
    fn clear_halt(&mut self, di: usize, dci: u32) {
        if !self.recover_endpoint(di, dci) {
            self.reinit_bulk(di, dci);
        }
        let addr = if dci == self.msd(di).dci_in { self.msd(di).ep_in } else { self.msd(di).ep_out };
        let _ = self.control(di, 0x02, 1, 0, addr as u16, 0);
    }

    /// Reset recovery (BOT 5.3.4): Bulk-Only Mass Storage Reset, then both bulk
    /// endpoints cleared.
    fn reset_recovery(&mut self, di: usize) {
        let iface = self.msd(di).iface as u16;
        let _ = self.control(di, 0x21, 0xFF, 0, iface, 0);
        let (i, o) = (self.msd(di).dci_in, self.msd(di).dci_out);
        self.clear_halt(di, i);
        self.clear_halt(di, o);
    }

    /// Queues a transfer of `len` bytes at `phys` on bulk endpoint `dci` as one TD (TRBs
    /// of at most 64 KiB that do not cross a 64 KiB boundary) and rings the doorbell;
    /// returns the TRBs `(address, length)`.
    fn bulk_queue(&mut self, di: usize, dci: u32, phys: u64, len: usize) -> Vec<(u64, u32)> {
        let slot = self.devices[di].slot;
        self.bulk_done.retain(|x| !(x.slot == slot && x.dci == dci));
        let s = self.msd_mut(di);
        let mps = ((if dci == s.dci_in { s.ctx_in } else { s.ctx_out }) >> 16).max(8) as u64;
        let ring = if dci == s.dci_in { &mut s.ring_in } else { &mut s.ring_out };
        let mut trbs = Vec::new();
        let (mut at, end) = (phys, phys + len as u64);
        loop {
            let chunk = ((at | 0xFFFF) + 1).min(end) - at;
            let last = at + chunk == end;
            // TD size (bits 17..21): packets still to come after this TRB, capped at 31
            // (xHCI 4.11.2.4; QEMU ignores it, Intel controllers use it)
            let remaining = end - at - chunk;
            let td_size = remaining.div_ceil(mps).min(31) as u32;
            let control = TRB_NORMAL << 10 | TRB_ISP | if last { TRB_IOC } else { TRB_CH };
            let trb = ring.push(at, chunk as u32 | td_size << 17, control);
            trbs.push((trb, chunk as u32));
            at += chunk;
            if last {
                break;
            }
        }
        self.ring_doorbell(slot, dci);
        trbs
    }

    /// Waits for the TD of `trbs` on bulk endpoint `dci` to finish; returns the bytes
    /// moved, or the completion code (0: timed out, or the device is gone).
    fn bulk_wait(&mut self, di: usize, dci: u32, trbs: &[(u64, u32)], ms: u64) -> Result<usize, u32> {
        let slot = self.devices[di].slot;
        let total: usize = trbs.iter().map(|t| t.1 as usize).sum();
        let d = Deadline::after_ms(ms);
        loop {
            self.drain_events();
            while let Some(pos) = self.bulk_done.iter().position(|x| x.slot == slot && x.dci == dci && trbs.iter().any(|t| t.0 == x.trb)) {
                let x = self.bulk_done.remove(pos);
                let idx = trbs.iter().position(|t| t.0 == x.trb).unwrap();
                let before: usize = trbs[..idx].iter().map(|t| t.1 as usize).sum();
                match x.code {
                    CC_SUCCESS if idx == trbs.len() - 1 => return Ok(total),
                    CC_SUCCESS => {}
                    CC_SHORT_PACKET => return Ok(before + (trbs[idx].1 as usize).saturating_sub(x.residual as usize)),
                    code => return Err(code),
                }
            }
            if self.device_gone(di) {
                return Err(0);
            }
            if d.expired() {
                return Err(0);
            }
            self.pause();
        }
    }

    /// One command through Bulk-Only Transport: CBW, data stage (`len` bytes in the
    /// bounce buffer, `dir_in` from the device), CSW. Returns the bytes moved and the
    /// CSW status (0 passed, 1 failed).
    fn bot(&mut self, di: usize, cdb: &[u8], dir_in: bool, len: usize, ms: u64) -> Result<(usize, u8), &'static str> {
        let (dci_in, dci_out) = (self.msd(di).dci_in, self.msd(di).dci_out);
        let s = self.msd_mut(di);
        s.tag = s.tag.wrapping_add(1);
        let tag = s.tag;
        let cbw = s.cmd.bytes_mut(CBW_OFF, 31);
        cbw.fill(0);
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        cbw[12] = if dir_in { 0x80 } else { 0 };
        cbw[13] = 0; // LUN
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        let (cmd_phys, buf_phys) = (s.cmd.phys, s.buf.phys);
        // Command
        let trbs = self.bulk_queue(di, dci_out, cmd_phys + CBW_OFF as u64, 31);
        match self.bulk_wait(di, dci_out, &trbs, 5000) {
            Ok(_) => {}
            Err(CC_STALL) => {
                self.clear_halt(di, dci_out);
                self.reset_recovery(di);
                return Err("the device refused the command block");
            }
            Err(code) => return Err(self.transport_failed(di, dci_out, code)),
        }
        // Data
        let mut moved = 0;
        if len > 0 {
            let dci = if dir_in { dci_in } else { dci_out };
            let trbs = self.bulk_queue(di, dci, buf_phys, len);
            match self.bulk_wait(di, dci, &trbs, ms) {
                Ok(n) => moved = n,
                // A stalled data stage: clear it, the CSW says what happened
                Err(CC_STALL) => self.clear_halt(di, dci),
                Err(code) => return Err(self.transport_failed(di, dci, code)),
            }
        }
        // Status (a stalled one is read once more)
        let mut csw_ok = false;
        for attempt in 0..2 {
            let trbs = self.bulk_queue(di, dci_in, cmd_phys + CSW_OFF as u64, 13);
            match self.bulk_wait(di, dci_in, &trbs, 5000) {
                Ok(13) => {
                    csw_ok = true;
                    break;
                }
                Ok(_) => break,
                Err(CC_STALL) if attempt == 0 => self.clear_halt(di, dci_in),
                Err(code) => return Err(self.transport_failed(di, dci_in, code)),
            }
        }
        let csw: [u8; 13] = self.msd(di).cmd.bytes(CSW_OFF, 13).try_into().unwrap();
        let valid = csw_ok && u32::from_le_bytes(csw[0..4].try_into().unwrap()) == CSW_SIGNATURE && u32::from_le_bytes(csw[4..8].try_into().unwrap()) == tag;
        if !valid {
            self.reset_recovery(di);
            return Err("invalid command status");
        }
        match csw[12] {
            0 | 1 => Ok((moved, csw[12])),
            _ => {
                self.reset_recovery(di);
                Err("phase error")
            }
        }
    }

    /// A transfer that failed with completion `code` (0: timed out or device gone):
    /// the endpoint is stopped and reset, then a reset recovery.
    fn transport_failed(&mut self, di: usize, dci: u32, code: u32) -> &'static str {
        if self.device_gone(di) {
            return "the device is gone";
        }
        if code == 0 {
            self.stop_endpoint(di, dci);
        }
        self.clear_halt(di, dci);
        self.reset_recovery(di);
        if code == 0 {
            "the transfer timed out"
        } else {
            "transfer error"
        }
    }

    /// A SCSI command; a failed one gets its sense data.
    fn scsi(&mut self, di: usize, cdb: &[u8], dir_in: bool, len: usize, ms: u64) -> Result<usize, ScsiError> {
        match self.bot(di, cdb, dir_in, len, ms) {
            Ok((n, 0)) => Ok(n),
            Ok(_) => Err(self.request_sense(di)),
            Err(e) => Err(ScsiError::Transport(e)),
        }
    }

    /// REQUEST SENSE: why the last command failed.
    fn request_sense(&mut self, di: usize) -> ScsiError {
        match self.bot(di, &[0x03, 0, 0, 0, 18, 0], true, 18, 5000) {
            Ok((n, 0)) if n >= 8 => {
                let b = self.msd(di).buf.bytes(0, 18);
                if b[0] & 0x7F >= 0x72 {
                    ScsiError::Sense(b[1] & 0xF, b[2], b[3])
                } else if n >= 14 {
                    ScsiError::Sense(b[2] & 0xF, b[12], b[13])
                } else {
                    ScsiError::Sense(b[2] & 0xF, 0, 0)
                }
            }
            Ok(_) => ScsiError::Sense(0, 0, 0),
            Err(e) => ScsiError::Transport(e),
        }
    }

    /// INQUIRY: a direct-access device; its names and whether the medium is removable.
    fn identify(&mut self, di: usize) -> Result<(), &'static str> {
        let mut n = 0;
        for _ in 0..3 {
            match self.scsi(di, &[0x12, 0, 0, 0, 36, 0], true, 36, 5000) {
                Ok(got) => {
                    n = got;
                    break;
                }
                Err(e) => println!("[usb-driver] {}: INQUIRY failed: {}", self.loc(di), e),
            }
        }
        if n < 32 {
            return Err("no answer to INQUIRY");
        }
        let b: [u8; 36] = {
            let mut a = [b' '; 36];
            a[..n.min(36)].copy_from_slice(self.msd(di).buf.bytes(0, n.min(36)));
            a
        };
        let kind = b[0] & 0x1F;
        if b[0] >> 5 != 0 || !matches!(kind, 0x00 | 0x0E) {
            return Err("not a disk (an optical drive or another SCSI device type)");
        }
        let mut model = [b' '; 40];
        let clean = |c: u8| if (0x20..0x7F).contains(&c) { c } else { b' ' };
        for (i, &c) in b[8..16].iter().enumerate() {
            model[i] = clean(c);
        }
        for (i, &c) in b[16..32].iter().enumerate() {
            model[9 + i] = clean(c);
        }
        for (i, &c) in b[32..36].iter().enumerate() {
            model[26 + i] = clean(c);
        }
        let s = self.msd_mut(di);
        s.model = model;
        s.removable = b[1] & 0x80 != 0;
        Ok(())
    }

    /// TEST UNIT READY until the medium is ready (up to `ms`), then its capacity and
    /// write protection. Sets `ready`.
    fn probe_medium(&mut self, di: usize, ms: u64) {
        self.msd_mut(di).ready = false;
        let d = Deadline::after_ms(ms);
        loop {
            match self.scsi(di, &[0x00, 0, 0, 0, 0, 0], false, 0, 5000) {
                Ok(_) => break,
                // No medium (a card reader without a card): no use waiting
                Err(ScsiError::Sense(NOT_READY, 0x3A, _)) => return,
                Err(ScsiError::Transport(e)) => {
                    println!("[usb-driver] {}: TEST UNIT READY: {}", self.loc(di), e);
                    return;
                }
                Err(_) => {}
            }
            if d.expired() {
                println!("[usb-driver] {}: the medium does not become ready", self.loc(di));
                return;
            }
            sys::sleep_ms(100);
        }
        let mut cap = None;
        for _ in 0..3 {
            match self.read_capacity(di) {
                Ok(c) => {
                    cap = Some(c);
                    break;
                }
                Err(e) => println!("[usb-driver] {}: READ CAPACITY: {}", self.loc(di), e),
            }
            sys::sleep_ms(50);
        }
        let Some((sectors, sector_size)) = cap else { return };
        if sector_size < 512 || sector_size > 4096 || 4096 % sector_size != 0 {
            println!("[usb-driver] {}: {}-byte sectors are not supported", self.loc(di), sector_size);
            return;
        }
        // MODE SENSE(6), all pages, 192 bytes (what Linux asks first: some devices fail
        // other lengths): byte 2 bit 7 is write protection
        let wp = matches!(self.scsi(di, &[0x1A, 0, 0x3F, 0, 192, 0], true, 192, 5000), Ok(n) if n >= 4 && self.msd(di).buf.bytes(0, 4)[2] & 0x80 != 0);
        let s = self.msd_mut(di);
        s.sectors = sectors;
        s.sector_size = sector_size;
        s.write_protected = wp;
        s.ready = sectors > 0;
    }

    /// READ CAPACITY (10), or (16) for disks over 2 TiB: sectors and sector size.
    fn read_capacity(&mut self, di: usize) -> Result<(u64, u32), ScsiError> {
        self.scsi(di, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], true, 8, 5000)?;
        let b = self.msd(di).buf.bytes(0, 8);
        let (last, size) = (be32(&b[0..4]), be32(&b[4..8]));
        if last != 0xFFFF_FFFF {
            return Ok((last as u64 + 1, size));
        }
        let mut cdb = [0u8; 16];
        cdb[0] = 0x9E; // SERVICE ACTION IN(16)
        cdb[1] = 0x10; // READ CAPACITY(16)
        cdb[13] = 32;
        self.scsi(di, &cdb, true, 32, 5000)?;
        let b = self.msd(di).buf.bytes(0, 12);
        let last = u64::from_be_bytes(b[0..8].try_into().unwrap());
        Ok((last + 1, be32(&b[8..12])))
    }

    /// READ or WRITE of `count` sectors at `lba` through the bounce buffer, retried on
    /// unit attentions, a medium becoming ready and transport errors.
    fn rw(&mut self, di: usize, lba: u64, count: u32, write: bool) -> Result<(), ScsiError> {
        let len = count as usize * self.msd(di).sector_size as usize;
        let mut cdb = [0u8; 16];
        let cdb_len = if lba + count as u64 <= 0xFFFF_FFFF && count <= 0xFFFF {
            cdb[0] = if write { 0x2A } else { 0x28 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            10
        } else {
            cdb[0] = if write { 0x8A } else { 0x88 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&count.to_be_bytes());
            16
        };
        let mut tries = 0;
        loop {
            tries += 1;
            let r = self.scsi(di, &cdb[..cdb_len], !write, len, 30_000);
            match r {
                Ok(n) if n == len => return Ok(()),
                Ok(_) => {
                    if tries >= 3 {
                        return Err(ScsiError::Transport("short transfer"));
                    }
                }
                Err(ScsiError::Sense(UNIT_ATTENTION, ..)) if tries < 5 => {}
                Err(ScsiError::Sense(NOT_READY, asc, _)) if asc != 0x3A && tries < 20 => sys::sleep_ms(100),
                Err(ScsiError::Transport(e)) if tries < 3 && e != "the device is gone" => {}
                Err(ScsiError::Sense(MEDIUM_ERROR, ..)) if tries < 2 => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// The device of USB disk `disk`.
    fn disk_dev(&self, disk: usize) -> Option<usize> {
        let slot = *self.disks.get(disk)?;
        if slot == 0 {
            return None;
        }
        self.dev_of_slot(slot).filter(|&di| self.devices[di].msd.is_some())
    }

    /// Blocks `count` (4 KiB) at `block` of disk device `di` to or from `data`.
    fn disk_blocks(&mut self, di: usize, block: u64, count: usize, data: &mut [u8], write: bool) -> Result<(), ScsiError> {
        let spb = (BLOCK / self.msd(di).sector_size as usize) as u64;
        let mut done = 0;
        while done < count {
            let n = (count - done).min(MAX_XFER_BLOCKS);
            let bytes = &mut data[done * BLOCK..(done + n) * BLOCK];
            if write {
                self.msd(di).buf.bytes_mut(0, bytes.len()).copy_from_slice(bytes);
            }
            self.rw(di, (block + done as u64) * spb, (n as u64 * spb) as u32, write)?;
            if !write {
                bytes.copy_from_slice(self.msd(di).buf.bytes(0, n * BLOCK));
            }
            done += n;
        }
        Ok(())
    }

    /// Fills `window` with a [`BLOCK_LIST_RECORD`]-byte record per USB disk; returns how
    /// many.
    fn list_disks(&self, window: &mut [u8]) -> usize {
        let mut n = 0;
        for disk in 0..MAX_DISKS {
            let Some(di) = self.disk_dev(disk) else { continue };
            let (d, s) = (&self.devices[di], self.msd(di));
            let r = &mut window[n * BLOCK_LIST_RECORD..(n + 1) * BLOCK_LIST_RECORD];
            r.fill(0);
            r[0..4].copy_from_slice(&(disk as u32).to_le_bytes());
            r[4..8].copy_from_slice(&s.generation.to_le_bytes());
            let blocks = if s.ready { s.sectors * s.sector_size as u64 / BLOCK as u64 } else { 0 };
            r[8..16].copy_from_slice(&blocks.to_le_bytes());
            r[16..20].copy_from_slice(&s.sector_size.to_le_bytes());
            r[20] = d.port as u8;
            r[21] = d.depth as u8;
            r[22] = d.speed as u8;
            r[23] = s.removable as u8 | (s.write_protected as u8) << 1 | (s.ready as u8) << 2;
            r[24..28].copy_from_slice(&d.route.to_le_bytes());
            r[28..30].copy_from_slice(&d.vendor.to_le_bytes());
            r[30..32].copy_from_slice(&d.product.to_le_bytes());
            r[32..72].copy_from_slice(&s.model);
            r[72..104].copy_from_slice(&s.serial);
            r[104] = s.iface;
            r[105] = 0; // LUN
            n += 1;
        }
        n
    }

    /// Serves a block request (`MSG_BLOCK_*`, `args[3]` the disk number) with its data in
    /// `window`.
    pub(crate) fn block_request(&mut self, msg: &Message, window: &mut [u8]) -> Message {
        let reply = |status: i64, value: u64| Message::new(MSG_BLOCK_REPLY as u64, [status as u64, value, 0, 0]);
        // Unplugged and new disks first
        self.housekeeping();
        let label = msg.label as u32;
        if label == MSG_BLOCK_LIST {
            let n = self.list_disks(window);
            return Message::new(MSG_BLOCK_REPLY as u64, [0, n as u64, self.disk_generation as u64, 0]);
        }
        let Some(di) = self.disk_dev(msg.args[3] as usize) else { return reply(ENODEV, 0) };
        if !self.msd(di).ready && matches!(label, MSG_BLOCK_GET_SIZE | MSG_BLOCK_READ | MSG_BLOCK_WRITE | MSG_BLOCK_READV) {
            // A card put in since, or a disk slow to start
            self.probe_medium(di, 1000);
            if !self.msd(di).ready {
                return reply(ENOMEDIUM, 0);
            }
        }
        let blocks = self.msd(di).sectors * self.msd(di).sector_size as u64 / BLOCK as u64;
        match label {
            MSG_BLOCK_GET_SIZE => {
                window[..40].copy_from_slice(&self.msd(di).model);
                Message::new(MSG_BLOCK_REPLY as u64, [0, blocks, 1, 1])
            }
            MSG_BLOCK_READ | MSG_BLOCK_WRITE => {
                let (block, count, offset) = (msg.args[0], msg.args[1] as usize, msg.args[2] as usize);
                if count == 0 || offset % BLOCK != 0 || offset + count * BLOCK > window.len() || block + count as u64 > blocks {
                    return reply(EINVAL, 0);
                }
                let write = label == MSG_BLOCK_WRITE;
                if write && self.msd(di).write_protected {
                    return reply(EROFS, 0);
                }
                match self.disk_blocks(di, block, count, &mut window[offset..offset + count * BLOCK], write) {
                    Ok(()) => reply(0, count as u64),
                    Err(e) => {
                        println!("[usb-driver] {}: {} of {} blocks at {} failed: {}", self.loc(di), if write { "write" } else { "read" }, count, block, e);
                        reply(EIO, 0)
                    }
                }
            }
            MSG_BLOCK_READV => {
                let n = msg.args[0] as usize;
                if n == 0 || n > BLOCK_READV_MAX {
                    return reply(EINVAL, 0);
                }
                let mut runs = [[0u64; 3]; BLOCK_READV_MAX];
                let mut total = 0u64;
                for (i, r) in runs[..n].iter_mut().enumerate() {
                    for (k, v) in r.iter_mut().enumerate() {
                        let at = BLOCK_READV_TABLE + (i * 3 + k) * 8;
                        *v = u64::from_le_bytes(window[at..at + 8].try_into().unwrap());
                    }
                    let (block, count, offset) = (r[0], r[1] as usize, r[2] as usize);
                    if count == 0 || offset % BLOCK != 0 || offset + count * BLOCK > BLOCK_READV_TABLE || block + count as u64 > blocks {
                        return reply(EINVAL, 0);
                    }
                    total += count as u64;
                }
                for r in &runs[..n] {
                    let (block, count, offset) = (r[0], r[1] as usize, r[2] as usize);
                    if let Err(e) = self.disk_blocks(di, block, count, &mut window[offset..offset + count * BLOCK], false) {
                        println!("[usb-driver] {}: read of {} blocks at {} failed: {}", self.loc(di), count, block, e);
                        return reply(EIO, 0);
                    }
                }
                reply(0, total)
            }
            MSG_BLOCK_FLUSH => match self.scsi(di, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], false, 0, 60_000) {
                // Devices without a write cache may not know the command
                Ok(_) | Err(ScsiError::Sense(ILLEGAL_REQUEST, ..)) => reply(0, 0),
                Err(e) => {
                    println!("[usb-driver] {}: cache flush failed: {}", self.loc(di), e);
                    reply(EIO, 0)
                }
            },
            _ => reply(ENOSYS, 0),
        }
    }
}
