//! # Hydra AHCI disk driver
//!
//! Drives one SATA disk behind an AHCI host bus adapter (PCI class 01:06) from Ring 3, in
//! an address space of its own. The adapter's registers (`ABAR`, PCI `BAR5`) are device
//! memory the supervisor granted; the command list, the received-FIS area, the command
//! tables and a bounce buffer are DMA memory this driver allocates. Requests are served
//! one at a time; a vectored read (`MSG_BLOCK_READV`) puts all its runs in flight at once
//! with native command queueing (NCQ, one command slot each) when the adapter and the
//! disk have it, so the disk (or the emulator behind it) works on them together.
//! Everything else uses slot 0.
//!
//! The supervisor starts it with `abar=<phys>` and, when the kernel routed the adapter's
//! message-signalled interrupt (MSI) to this driver, `irq=<line>`; without it completion
//! is polled. `port=<n>` picks a port instead of the first one with a disk.
//!
//! Requests on [`ENDPOINT_BLOCK_DEV`] are those of `ata-driver` (blocks are 4 KiB; data is
//! in the service window at byte offset `args[2]`):
//! - `MSG_BLOCK_READ [block, count, offset]`, `MSG_BLOCK_WRITE [block, count, offset]`;
//! - `MSG_BLOCK_READV [runs]`: up to 32 runs `[block, count, offset]` from the table at
//!   `BLOCK_READV_TABLE` in the window (see the kernel's `ipc/protocol.rs`);
//! - `MSG_BLOCK_FLUSH`: flush the disk's write cache (FLUSH CACHE EXT);
//! - `MSG_BLOCK_GET_SIZE`: reply `[0, blocks, lba48, dma]`, the model (40 bytes) in the window.
//!
//! Replies are `MSG_BLOCK_REPLY [status (0 or -errno), blocks transferred]`.
//!
//! Real hardware notes: firmware may still own the adapter (BIOS/OS handoff below), may
//! have left ports running (they are stopped before being reprogrammed), and a port can
//! need a COMRESET before its link comes up. The adapter is deliberately not reset as a
//! whole (`GHC.HR`): on Intel PCH adapters that also clears the port-enable bits in PCI
//! configuration space (PCS, offset 0x92), which this driver cannot reach.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{fence, Ordering};

use hydra_rt::protocol::{
    BLOCK_READV_MAX, BLOCK_READV_TABLE, ENDPOINT_BLOCK_DEV, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_READ, MSG_BLOCK_READV,
    MSG_BLOCK_REPLY, MSG_BLOCK_WRITE,
};
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

mod iostat;

hydra_rt::entry!(main);

const BLOCK: usize = 4096;
/// Size of the register window mapped: the generic registers and 32 ports.
const ABAR_LEN: u64 = 0x1100;

// Generic host control registers
const HBA_CAP: usize = 0x00;
const HBA_GHC: usize = 0x04;
const HBA_IS: usize = 0x08;
const HBA_PI: usize = 0x0C;
const HBA_VS: usize = 0x10;
const HBA_CAP2: usize = 0x24;
const HBA_BOHC: usize = 0x28;

const CAP_S64A: u32 = 1 << 31;
const CAP_SNCQ: u32 = 1 << 30;
const CAP_SSS: u32 = 1 << 27;
const CAP_SCLO: u32 = 1 << 24;
const GHC_AE: u32 = 1 << 31;
const GHC_IE: u32 = 1 << 1;
const CAP2_BOH: u32 = 1 << 0;
const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;

// Port registers (offsets within a port's 0x80 bytes)
const PX_CLB: usize = 0x00;
const PX_CLBU: usize = 0x04;
const PX_FB: usize = 0x08;
const PX_FBU: usize = 0x0C;
const PX_IS: usize = 0x10;
const PX_IE: usize = 0x14;
const PX_CMD: usize = 0x18;
const PX_TFD: usize = 0x20;
const PX_SIG: usize = 0x24;
const PX_SSTS: usize = 0x28;
const PX_SCTL: usize = 0x2C;
const PX_SERR: usize = 0x30;
const PX_SACT: usize = 0x34;
const PX_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_CLO: u32 = 1 << 3;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

/// Port interrupt causes this driver enables: D2H register FIS, PIO setup FIS, set device
/// bits, and the error causes (task file, host bus data/fatal, interface fatal/non-fatal,
/// overflow).
const IS_DHRS: u32 = 1 << 0;
const IS_PSS: u32 = 1 << 1;
const IS_SDBS: u32 = 1 << 3;
const IS_ERRORS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27) | (1 << 26) | (1 << 24);
const IS_TFES: u32 = 1 << 30;

const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

/// Signature of an ATA disk (ATAPI devices, port multipliers and enclosures differ).
const SIG_ATA: u32 = 0x0000_0101;

const FIS_TYPE_REG_H2D: u8 = 0x27;

const ATA_READ_DMA: u8 = 0xC8;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA: u8 = 0xCA;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE: u8 = 0xE7;
const ATA_FLUSH_CACHE_EXT: u8 = 0xEA;
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;

// DMA memory layout: the command list (32 headers of 32 bytes, 1 KiB aligned), the
// received-FIS area (256 bytes, 256-byte aligned), the command tables of the 32 slots
// (each 0x100 bytes, 128-byte aligned: the command FIS, then the PRD table at 0x80), then
// the bounce buffer
const CLB_OFF: usize = 0x0000;
const FB_OFF: usize = 0x0400;
const CT_OFF: usize = 0x1000;
/// Bytes per slot's command table.
const CT_SLOT: usize = 0x100;
const PRDT_OFF: usize = CT_OFF + 0x80;
const BUF_OFF: usize = CT_OFF + 32 * CT_SLOT;
/// The bounce buffer: one full service window.
const BUF_LEN: usize = WINDOW_SIZE;
/// The command table of a command on lent pages (slot 0 only): its PRD table has one entry
/// per physically contiguous piece of the lent memory, more than fit in a `CT_SLOT`.
const LENT_CT_OFF: usize = BUF_OFF + BUF_LEN;
const LENT_CT_LEN: usize = 0x1000;
/// PRD entries in the lent command table.
const LENT_MAX_PRDS: usize = (LENT_CT_LEN - 0x80) / 16;
const DMA_LEN: usize = LENT_CT_OFF + LENT_CT_LEN;
/// Bytes per PRD entry. AHCI allows up to 4 MiB; 64 KiB entries are what the older
/// bus-master IDE engines could do and every AHCI implementation handles them.
const PRD_BYTES: usize = 64 * 1024;
/// PRD entries in the command table (they fit in its page after the command FIS).
const MAX_PRDS: usize = BUF_LEN / PRD_BYTES;
const _: () = assert!(PRDT_OFF + MAX_PRDS * 16 <= CT_OFF + CT_SLOT);

/// Command time limit. Flushing a large write cache on a real disk can take seconds.
const COMMAND_TIMEOUT_MS: u64 = 30_000;

const EIO: i64 = -5;
const EINVAL: i64 = -22;
/// A lent request this driver cannot do on the lent pages themselves (pages out of a
/// 32-bit adapter's reach, odd addresses): the caller sends it again through the window.
const EOPNOTSUPP: i64 = -95;

/// `args[2]` (the window offset) of a read or write whose data is in pages the caller lent
/// with the request (`hydra_rt::sys::svc_grant`) instead of in the window.
const OFFSET_LENT: u64 = u64::MAX;

/// Where a command's data is.
#[derive(Clone, Copy)]
enum Data<'a> {
    /// The bounce buffer, at this byte offset.
    Bounce(usize),
    /// Lent memory: its physical segments `(address, length)`, from this byte on.
    Lent(&'a [(u64, u64)], usize),
}

/// A time limit in milliseconds, measured with the 100 Hz uptime clock.
struct Deadline {
    end: u64,
}

impl Deadline {
    /// A deadline `ms` milliseconds from now (at least one clock tick away).
    fn after_ms(ms: u64) -> Self {
        Self { end: sys::uptime_ticks() + ms.div_ceil(10) + 1 }
    }

    /// Whether the deadline has passed.
    fn expired(&self) -> bool {
        sys::uptime_ticks() >= self.end
    }
}

/// The adapter's register window.
#[derive(Clone, Copy)]
struct Hba {
    regs: *mut u8,
}

impl Hba {
    /// Reads a 32-bit register at byte offset `reg`.
    fn read(&self, reg: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.regs.add(reg) as *const u32) }
    }

    /// Writes a 32-bit register at byte offset `reg`.
    fn write(&self, reg: usize, v: u32) {
        unsafe { core::ptr::write_volatile(self.regs.add(reg) as *mut u32, v) }
    }

    /// Reads register `reg` of port `port`.
    fn port_read(&self, port: usize, reg: usize) -> u32 {
        self.read(0x100 + port * 0x80 + reg)
    }

    /// Writes register `reg` of port `port`.
    fn port_write(&self, port: usize, reg: usize, v: u32) {
        self.write(0x100 + port * 0x80 + reg, v)
    }

    /// Polls until `(read(reg) & mask) == want` or `ms` milliseconds pass.
    fn wait_port(&self, port: usize, reg: usize, mask: u32, want: u32, ms: u64) -> bool {
        let d = Deadline::after_ms(ms);
        loop {
            if self.port_read(port, reg) & mask == want {
                return true;
            }
            if d.expired() {
                return false;
            }
            sys::sleep_ms(1);
        }
    }

    /// Takes the adapter over from the firmware (BIOS/OS handoff, AHCI 1.2 section 10.6)
    /// and switches it to AHCI mode.
    fn take_ownership(&self) {
        self.write(HBA_GHC, self.read(HBA_GHC) | GHC_AE);
        if self.read(HBA_CAP2) & CAP2_BOH == 0 {
            return;
        }
        self.write(HBA_BOHC, self.read(HBA_BOHC) | BOHC_OOS);
        // The firmware has 25 ms to release it; if it says it is busy, up to 2 s more
        let d = Deadline::after_ms(25);
        while self.read(HBA_BOHC) & BOHC_BOS != 0 && !d.expired() {
            sys::sleep_ms(1);
        }
        if self.read(HBA_BOHC) & BOHC_BB != 0 {
            let d = Deadline::after_ms(2000);
            while self.read(HBA_BOHC) & BOHC_BOS != 0 && !d.expired() {
                sys::sleep_ms(5);
            }
        }
        if self.read(HBA_BOHC) & BOHC_BOS != 0 {
            println!("[ahci-driver] the firmware did not release the adapter; going on regardless");
        }
    }
}

/// A command's data direction and buffer use.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    None,
    Read,
    Write,
}

/// The disk on one port, with the port's DMA structures.
struct Disk {
    hba: Hba,
    port: usize,
    irq: Option<u8>,
    can_clo: bool,
    mem: *mut u8,
    mem_phys: u64,
    model: [u8; 40],
    /// Logical sectors on the disk.
    sectors: u64,
    /// Bytes per logical sector (512 on almost every disk; 4096 on "4Kn" ones).
    sector_size: usize,
    lba48: bool,
    /// Whether the disk has a write cache that is on (FLUSH CACHE is then needed).
    write_cache: bool,
    /// Commands that failed and were retried after a port reset (diagnostics).
    recoveries: u32,
    /// The adapter reaches 64-bit addresses (lent pages may be anywhere).
    s64a: bool,
    /// Command slots usable for queued (NCQ) reads at once; 0 without NCQ.
    ncq_slots: usize,
}

impl Disk {
    /// A pointer into the DMA memory.
    fn at(&self, off: usize) -> *mut u8 {
        unsafe { self.mem.add(off) }
    }

    /// Stops the port's command engine and FIS receive (AHCI 1.2 section 10.1.2): needed
    /// before its list addresses may change, and to recover from errors.
    fn stop(&self) -> Result<(), &'static str> {
        let (h, p) = (&self.hba, self.port);
        let cmd = h.port_read(p, PX_CMD);
        if cmd & CMD_ST != 0 {
            h.port_write(p, PX_CMD, cmd & !CMD_ST);
        }
        if !h.wait_port(p, PX_CMD, CMD_CR, 0, 500) {
            return Err("command list engine did not stop");
        }
        let cmd = h.port_read(p, PX_CMD);
        if cmd & CMD_FRE != 0 {
            h.port_write(p, PX_CMD, cmd & !CMD_FRE);
        }
        if !h.wait_port(p, PX_CMD, CMD_FR, 0, 500) {
            return Err("FIS receive did not stop");
        }
        Ok(())
    }

    /// Resets the link (COMRESET) and waits for the device to come back.
    fn comreset(&self) -> bool {
        let (h, p) = (&self.hba, self.port);
        let sctl = h.port_read(p, PX_SCTL) & !0xF;
        h.port_write(p, PX_SCTL, sctl | 1);
        // DET=1 must be held at least 1 ms for the COMRESET to go out
        sys::sleep_ms(10);
        h.port_write(p, PX_SCTL, sctl);
        let up = h.wait_port(p, PX_SSTS, 0xF, 3, 1000);
        h.port_write(p, PX_SERR, 0xFFFF_FFFF);
        up
    }

    /// Points the port at this driver's structures, brings the link up and starts the
    /// command engine once the device is ready.
    fn start(&mut self) -> Result<(), &'static str> {
        self.stop()?;
        let (h, p) = (&self.hba, self.port);
        let clb = self.mem_phys + CLB_OFF as u64;
        let fb = self.mem_phys + FB_OFF as u64;
        h.port_write(p, PX_CLB, clb as u32);
        h.port_write(p, PX_CLBU, (clb >> 32) as u32);
        h.port_write(p, PX_FB, fb as u32);
        h.port_write(p, PX_FBU, (fb >> 32) as u32);
        h.port_write(p, PX_SERR, 0xFFFF_FFFF);
        h.port_write(p, PX_IS, 0xFFFF_FFFF);
        let mut cmd = h.port_read(p, PX_CMD) | CMD_FRE | CMD_POD;
        if h.read(HBA_CAP) & CAP_SSS != 0 {
            cmd |= CMD_SUD; // staggered spin-up: the port waits for this
        }
        h.port_write(p, PX_CMD, cmd);
        if !h.wait_port(p, PX_SSTS, 0xF, 3, 100) && !self.comreset() {
            return Err("no SATA link");
        }
        // The device must not be busy when the engine starts (a spinning disk may still
        // be spinning up after a COMRESET; an SSD answers at once)
        if !h.wait_port(p, PX_TFD, TFD_BSY | TFD_DRQ, 0, 10_000) {
            if self.can_clo {
                h.port_write(p, PX_CMD, h.port_read(p, PX_CMD) | CMD_CLO);
                h.wait_port(p, PX_CMD, CMD_CLO, 0, 500);
            } else if !self.comreset() || !h.wait_port(p, PX_TFD, TFD_BSY | TFD_DRQ, 0, 10_000) {
                return Err("device stays busy");
            }
        }
        h.port_write(p, PX_SERR, 0xFFFF_FFFF);
        h.port_write(p, PX_IS, 0xFFFF_FFFF);
        h.write(HBA_IS, 1 << p);
        h.port_write(p, PX_IE, if self.irq.is_some() { IS_DHRS | IS_PSS | IS_SDBS | IS_ERRORS } else { 0 });
        h.port_write(p, PX_CMD, h.port_read(p, PX_CMD) | CMD_ST);
        Ok(())
    }

    /// Recovers the port after a failed or timed-out command: stops it, clears the
    /// errors, resets the link if the device is stuck, and starts it again.
    fn recover(&mut self) {
        self.recoveries += 1;
        if self.stop().is_err() {
            // An engine that will not stop needs the link reset
            self.comreset();
        }
        let tfd = self.hba.port_read(self.port, PX_TFD);
        if tfd & (TFD_BSY | TFD_DRQ) != 0 && !self.can_clo {
            self.comreset();
        }
        if let Err(e) = self.start() {
            println!("[ahci-driver] port {} did not come back after an error: {}", self.port, e);
        }
    }

    /// Fills the command header of slot 0, the command FIS and the PRD table for one
    /// command moving `bytes` bytes of the bounce buffer.
    fn build(&self, command: u8, lba: u64, count: u16, bytes: usize, data: Data, dir: Dir) {
        self.build_slot(0, command, lba, count, bytes, data, dir);
    }

    /// Fills slot `tag`'s command header, command FIS and PRD table for one command
    /// moving `bytes` bytes of `data` (lent memory: slot 0 only). A queued read
    /// (READ FPDMA QUEUED) carries its sector count in the features field and its tag in
    /// the count field.
    #[allow(clippy::too_many_arguments)]
    fn build_slot(&self, tag: usize, command: u8, lba: u64, count: u16, bytes: usize, data: Data, dir: Dir) {
        let ct_off = match data {
            Data::Bounce(_) => CT_OFF + tag * CT_SLOT,
            Data::Lent(..) => LENT_CT_OFF,
        };
        unsafe {
            // The command FIS: a host-to-device register FIS (20 bytes, 5 dwords)
            let fis = self.at(ct_off);
            core::ptr::write_bytes(fis, 0, 0x80);
            let f = core::slice::from_raw_parts_mut(fis, 20);
            f[0] = FIS_TYPE_REG_H2D;
            f[1] = 0x80; // C: a command
            f[2] = command;
            f[4] = lba as u8;
            f[5] = (lba >> 8) as u8;
            f[6] = (lba >> 16) as u8;
            f[7] = if matches!(command, ATA_IDENTIFY | ATA_FLUSH_CACHE | ATA_FLUSH_CACHE_EXT) {
                0
            } else if self.lba48 {
                0x40 // LBA mode
            } else {
                0x40 | ((lba >> 24) & 0x0F) as u8
            };
            f[8] = (lba >> 24) as u8;
            f[9] = (lba >> 32) as u8;
            f[10] = (lba >> 40) as u8;
            if command == ATA_READ_FPDMA_QUEUED {
                f[3] = count as u8;
                f[11] = (count >> 8) as u8;
                f[12] = (tag as u8) << 3;
            } else {
                f[12] = count as u8;
                f[13] = (count >> 8) as u8;
            }
            // The PRD table: the data in pieces of at most PRD_BYTES
            let prdt = self.at(ct_off + 0x80) as *mut u32;
            let mut prds = 0usize;
            let mut put = |addr: u64, len: usize| {
                prdt.add(prds * 4).write_volatile(addr as u32);
                prdt.add(prds * 4 + 1).write_volatile((addr >> 32) as u32);
                prdt.add(prds * 4 + 2).write_volatile(0);
                // Byte count minus one (bit 0 set: counts are even); no per-entry interrupt
                prdt.add(prds * 4 + 3).write_volatile((len - 1) as u32);
                prds += 1;
            };
            match data {
                Data::Bounce(buf_off) => {
                    for off in (0..bytes).step_by(PRD_BYTES) {
                        put(self.mem_phys + (BUF_OFF + buf_off + off) as u64, (bytes - off).min(PRD_BYTES));
                    }
                }
                Data::Lent(segs, from) => {
                    // The segments' bytes from `from` on, `bytes` of them (`blocks_lent`
                    // checked that they fit in the table)
                    let (mut skip, mut left) = (from as u64, bytes as u64);
                    for &(a, l) in segs {
                        if left == 0 {
                            break;
                        }
                        if skip >= l {
                            skip -= l;
                            continue;
                        }
                        let (mut a, mut l) = (a + skip, (l - skip).min(left));
                        skip = 0;
                        left -= l;
                        while l > 0 {
                            let n = l.min(PRD_BYTES as u64);
                            put(a, n as usize);
                            a += n;
                            l -= n;
                        }
                    }
                }
            }
            // The slot's header: FIS length 5 dwords, W for writes, the PRD count, the table
            let hdr = self.at(CLB_OFF + tag * 32) as *mut u32;
            let w = if dir == Dir::Write { 1 << 6 } else { 0 };
            hdr.write_volatile(5 | w | ((prds as u32) << 16));
            hdr.add(1).write_volatile(0); // PRDBC: bytes transferred, set by the adapter
            let ct = self.mem_phys + ct_off as u64;
            hdr.add(2).write_volatile(ct as u32);
            hdr.add(3).write_volatile((ct >> 32) as u32);
        }
    }

    /// Issues slot 0 and waits for it to complete.
    fn issue(&mut self) -> Result<(), &'static str> {
        let (h, p) = (&self.hba, self.port);
        // The descriptors in memory before the adapter is told to fetch them
        fence(Ordering::SeqCst);
        h.port_write(p, PX_CI, 1);
        let d = Deadline::after_ms(COMMAND_TIMEOUT_MS);
        let mut spins = 0u32;
        let result = loop {
            let is = h.port_read(p, PX_IS);
            if is & IS_ERRORS != 0 {
                break Err(if is & IS_TFES != 0 { "the disk reported an error" } else { "adapter or link error" });
            }
            if h.port_read(p, PX_CI) & 1 == 0 {
                // The task file may still report an error without TFES on some adapters
                break if h.port_read(p, PX_TFD) & TFD_ERR != 0 { Err("the disk reported an error") } else { Ok(()) };
            }
            if d.expired() {
                break Err("command timed out");
            }
            match self.irq {
                // Up to 20 ms, then the registers are checked again (a lost or early
                // interrupt costs at most that)
                Some(irq) => {
                    let _ = sys::irq_wait(irq, 2);
                }
                // A short command (a 4 KiB read from an SSD) completes within tens of
                // microseconds: spin a little before giving the CPU away
                None => {
                    spins += 1;
                    if spins < 64 {
                        core::hint::spin_loop();
                    } else {
                        sys::yield_now();
                    }
                }
            }
        };
        // Clear the causes (write 1 to clear), the port's then the adapter's
        let is = h.port_read(p, PX_IS);
        h.port_write(p, PX_IS, is);
        h.write(HBA_IS, 1 << p);
        if result.is_err() {
            let (tfd, serr) = (h.port_read(p, PX_TFD), h.port_read(p, PX_SERR));
            println!("[ahci-driver] port {}: PxIS={:#x} PxTFD={:#x} PxSERR={:#x}", p, is, tfd, serr);
        }
        result
    }

    /// Runs one command, retrying it once after recovering the port.
    fn command(&mut self, command: u8, lba: u64, count: u16, bytes: usize, data: Data, dir: Dir) -> Result<(), &'static str> {
        self.build(command, lba, count, bytes, data, dir);
        match self.issue() {
            Ok(()) => Ok(()),
            Err(e) => {
                println!("[ahci-driver] command {:#x} at sector {} failed ({}); resetting the port and retrying", command, lba, e);
                self.recover();
                self.build(command, lba, count, bytes, data, dir);
                self.issue()
            }
        }
    }

    /// Reads the disk's IDENTIFY DEVICE data and learns its size and features.
    fn identify(&mut self) -> Result<(), &'static str> {
        self.command(ATA_IDENTIFY, 0, 0, 512, Data::Bounce(0), Dir::Read)?;
        let mut id = [0u16; 256];
        for (i, w) in id.iter_mut().enumerate() {
            *w = unsafe { (self.at(BUF_OFF + i * 2) as *const u16).read_volatile() };
        }
        for (i, w) in id[27..47].iter().enumerate() {
            self.model[i * 2] = (*w >> 8) as u8;
            self.model[i * 2 + 1] = *w as u8;
        }
        self.lba48 = id[83] & (1 << 10) != 0;
        self.sectors = if self.lba48 {
            id[100] as u64 | (id[101] as u64) << 16 | (id[102] as u64) << 32 | (id[103] as u64) << 48
        } else {
            id[60] as u64 | (id[61] as u64) << 16
        };
        // Word 106: valid (bit 14 set, 15 clear) and "logical sector longer than 256
        // words" (bit 12): the size in words is in words 117-118
        self.sector_size = 512;
        if id[106] & 0xC000 == 0x4000 && id[106] & (1 << 12) != 0 {
            self.sector_size = ((id[117] as usize) | (id[118] as usize) << 16) * 2;
        }
        // Word 85 bit 5: write cache enabled (82 bit 5: supported)
        self.write_cache = id[82] & (1 << 5) != 0 && id[85] & (1 << 5) != 0;
        // Word 76 bit 8: native command queueing; word 75: the queue depth minus one.
        // Queued commands are 48-bit; the adapter must have NCQ and as many slots
        let cap = self.hba.read(HBA_CAP);
        if id[76] & (1 << 8) != 0 && self.lba48 && cap & CAP_SNCQ != 0 {
            let depth = (id[75] & 0x1F) as usize + 1;
            let slots = ((cap >> 8) & 0x1F) as usize + 1;
            self.ncq_slots = depth.min(slots).min(BLOCK_READV_MAX);
        }
        if self.sectors == 0 {
            return Err("the disk reports no sectors");
        }
        if self.sector_size == 0 || self.sector_size > BLOCK || BLOCK % self.sector_size != 0 {
            return Err("unsupported logical sector size");
        }
        Ok(())
    }

    /// Returns the drive model string trimmed of trailing spaces.
    fn model_str(&self) -> &str {
        let len = self.model.iter().rposition(|&b| b != b' ' && b != 0).map_or(0, |i| i + 1);
        core::str::from_utf8(&self.model[..len]).unwrap_or("SATA disk")
    }

    /// Sectors per 4 KiB block.
    fn sectors_per_block(&self) -> u64 {
        (BLOCK / self.sector_size) as u64
    }

    /// Reads or writes `count` 4 KiB blocks at `block` to or from `data`, as few commands
    /// as the sector count field allows (65535 sectors for the 48-bit commands, 256 for
    /// the 28-bit ones: a count of 0 means 256 there).
    fn blocks(&mut self, block: u64, count: usize, data: &mut [u8], write: bool) -> Result<(), &'static str> {
        let spb = self.sectors_per_block();
        let max_sectors: u64 = if self.lba48 { 65535 } else { 256 };
        let run = ((max_sectors / spb) as usize).min(BUF_LEN / BLOCK).max(1);
        for (i, chunk) in data[..count * BLOCK].chunks_mut(run * BLOCK).enumerate() {
            let lba = (block + (i * run) as u64) * spb;
            let sectors = (chunk.len() / self.sector_size) as u64;
            if lba + sectors > self.sectors {
                return Err("past the end of the disk");
            }
            // 28-bit commands address only the first 2^28 sectors
            if !self.lba48 && lba + sectors > 0x1000_0000 {
                return Err("beyond the 28-bit address range");
            }
            if write {
                unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), self.at(BUF_OFF), chunk.len()) };
            }
            let cmd = match (write, self.lba48) {
                (false, false) => ATA_READ_DMA,
                (false, true) => ATA_READ_DMA_EXT,
                (true, false) => ATA_WRITE_DMA,
                (true, true) => ATA_WRITE_DMA_EXT,
            };
            // 256 sectors are encoded as 0 in the 28-bit commands' 8-bit count
            self.command(cmd, lba, sectors as u16, chunk.len(), Data::Bounce(0), if write { Dir::Write } else { Dir::Read })?;
            if !write {
                unsafe { core::ptr::copy_nonoverlapping(self.at(BUF_OFF), chunk.as_mut_ptr(), chunk.len()) };
            }
        }
        Ok(())
    }

    /// Reads or writes `count` 4 KiB blocks at `block` straight to or from memory the
    /// caller lent (`segs`: its physical segments, in order), with no copy through the
    /// bounce buffer.
    ///
    /// # Errors
    /// `Err(None)`: the lent memory cannot be used as it is (see [`EOPNOTSUPP`]);
    /// `Err(Some(e))`: the disk failed.
    fn blocks_lent(&mut self, block: u64, count: usize, segs: &[(u64, u64)], write: bool) -> Result<(), Option<&'static str>> {
        let total: u64 = segs.iter().map(|s| s.1).sum();
        if total < (count * BLOCK) as u64
            || segs.iter().any(|&(a, l)| a % 2 != 0 || l % 2 != 0 || (!self.s64a && a + l > 0x1_0000_0000))
            || segs.iter().map(|s| s.1.div_ceil(PRD_BYTES as u64) as usize).sum::<usize>() + segs.len() > LENT_MAX_PRDS
        {
            return Err(None);
        }
        let spb = self.sectors_per_block();
        let max_sectors: u64 = if self.lba48 { 65535 } else { 256 };
        let run = ((max_sectors / spb) as usize).max(1);
        let mut done = 0;
        while done < count {
            let n = run.min(count - done);
            let lba = (block + done as u64) * spb;
            let sectors = n as u64 * spb;
            if lba + sectors > self.sectors {
                return Err(Some("past the end of the disk"));
            }
            if !self.lba48 && lba + sectors > 0x1000_0000 {
                return Err(Some("beyond the 28-bit address range"));
            }
            let cmd = match (write, self.lba48) {
                (false, false) => ATA_READ_DMA,
                (false, true) => ATA_READ_DMA_EXT,
                (true, false) => ATA_WRITE_DMA,
                (true, true) => ATA_WRITE_DMA_EXT,
            };
            let data = Data::Lent(segs, done * BLOCK);
            self.command(cmd, lba, sectors as u16, n * BLOCK, data, if write { Dir::Write } else { Dir::Read }).map_err(Some)?;
            done += n;
        }
        Ok(())
    }

    /// Flushes the disk's write cache to the media.
    fn flush(&mut self) -> Result<(), &'static str> {
        let cmd = if self.lba48 { ATA_FLUSH_CACHE_EXT } else { ATA_FLUSH_CACHE };
        self.command(cmd, 0, 0, 0, Data::Bounce(0), Dir::None)
    }

    /// Reads the runs `[block, count, window offset]` into `window`: all in flight at
    /// once as queued commands when the disk has NCQ (each run in the bounce buffer at its
    /// window offset), otherwise one after the other. A queued read that fails is redone
    /// without queueing after the port is recovered.
    fn readv(&mut self, runs: &[[u64; 3]], window: &mut [u8]) -> Result<(), &'static str> {
        let spb = self.sectors_per_block();
        if self.ncq_slots >= runs.len() && runs.len() > 1 {
            let mut mask = 0u32;
            for (tag, r) in runs.iter().enumerate() {
                let (block, count, off) = (r[0], r[1] as usize, r[2] as usize);
                let sectors = count as u64 * spb;
                self.build_slot(tag, ATA_READ_FPDMA_QUEUED, block * spb, sectors as u16, count * BLOCK, Data::Bounce(off), Dir::Read);
                mask |= 1 << tag;
            }
            if self.issue_queued(mask).is_ok() {
                for r in runs {
                    let (off, len) = (r[2] as usize, r[1] as usize * BLOCK);
                    unsafe { core::ptr::copy_nonoverlapping(self.at(BUF_OFF + off), window[off..].as_mut_ptr(), len) };
                }
                return Ok(());
            }
            println!("[ahci-driver] a queued read failed; resetting the port and reading without queueing");
            self.recover();
        }
        for r in runs {
            let (block, count, off) = (r[0], r[1] as usize, r[2] as usize);
            self.blocks(block, count, &mut window[off..], false)?;
        }
        Ok(())
    }

    /// Issues the queued commands of the slots in `mask` and waits for all of them.
    fn issue_queued(&mut self, mask: u32) -> Result<(), &'static str> {
        let (h, p) = (&self.hba, self.port);
        fence(Ordering::SeqCst);
        // A queued command's PxSACT bit is set before its PxCI bit
        h.port_write(p, PX_SACT, mask);
        h.port_write(p, PX_CI, mask);
        let d = Deadline::after_ms(COMMAND_TIMEOUT_MS);
        let mut spins = 0u32;
        let result = loop {
            let is = h.port_read(p, PX_IS);
            if is & IS_ERRORS != 0 {
                break Err(if is & IS_TFES != 0 { "the disk reported an error" } else { "adapter or link error" });
            }
            if (h.port_read(p, PX_SACT) | h.port_read(p, PX_CI)) & mask == 0 {
                break Ok(());
            }
            if d.expired() {
                break Err("command timed out");
            }
            match self.irq {
                Some(irq) => {
                    // Each completion interrupts (set device bits): its cause is cleared
                    // before the next wait
                    let _ = sys::irq_wait(irq, 2);
                    let is = h.port_read(p, PX_IS);
                    h.port_write(p, PX_IS, is & !IS_ERRORS);
                    h.write(HBA_IS, 1 << p);
                }
                None => {
                    spins += 1;
                    if spins < 64 {
                        core::hint::spin_loop();
                    } else {
                        sys::yield_now();
                    }
                }
            }
        };
        let is = h.port_read(p, PX_IS);
        h.port_write(p, PX_IS, is);
        h.write(HBA_IS, 1 << p);
        if result.is_err() {
            let (tfd, serr, sact) = (h.port_read(p, PX_TFD), h.port_read(p, PX_SERR), h.port_read(p, PX_SACT));
            println!("[ahci-driver] port {}: queued PxIS={:#x} PxTFD={:#x} PxSERR={:#x} PxSACT={:#x}", p, is, tfd, serr, sact);
        }
        result
    }
}

/// Constructs a block service reply message.
fn reply(status: i64, value: u64) -> Message {
    Message::new(MSG_BLOCK_REPLY as u64, [status as u64, value, 0, 0])
}

/// Value of a `key=<number>` argument (decimal or `0x` hex).
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// The implemented ports (or only `wanted`) with an ATA disk on an established link.
fn find_disk_ports(hba: &Hba, wanted: Option<usize>) -> alloc::vec::Vec<usize> {
    let pi = hba.read(HBA_PI);
    (0..32)
        .filter(|&p| pi & (1 << p) != 0 && wanted.map_or(true, |w| w == p))
        .filter(|&p| {
            let ssts = hba.port_read(p, PX_SSTS);
            let (det, ipm) = (ssts & 0xF, (ssts >> 8) & 0xF);
            let sig = hba.port_read(p, PX_SIG);
            println!("[ahci-driver] port {}: SSTS={:#x} SIG={:#x}", p, ssts, sig);
            // DET 3: device present and communicating; IPM 1: active (2 and 6 are partial
            // and slumber power states, which a command wakes up)
            det == 3 && matches!(ipm, 1 | 2 | 6) && sig == SIG_ATA
        })
        .collect()
}

// wave11 GH begin
/// Ports with a device on an established link but no device signature (`PxSIG` all ones:
/// the firmware reset or stopped the port it booted from, and the signature arrives only in
/// a received FIS): receives FISes into a scratch page, resets the link (COMRESET) and waits
/// up to 1 s for the signature, then stops receiving again. Seen in QEMU (q35, the firmware
/// had used the disk); real firmware may leave ports the same way.
fn refresh_signatures(hba: &Hba, wanted: Option<usize>, cap: u32) {
    let pi = hba.read(HBA_PI);
    let todo: alloc::vec::Vec<usize> = (0..32)
        .filter(|&p| pi & (1 << p) != 0 && wanted.map_or(true, |w| w == p))
        .filter(|&p| hba.port_read(p, PX_SSTS) & 0xF != 0 && hba.port_read(p, PX_SIG) == 0xFFFF_FFFF)
        .collect();
    if todo.is_empty() {
        return;
    }
    let Ok((_, fb)) = sys::dma_alloc(4096) else { return };
    if cap & CAP_S64A == 0 && fb >= 0x1_0000_0000 {
        return;
    }
    for p in todo {
        // The engine and FIS receive off (they may still run from the firmware)
        hba.port_write(p, PX_CMD, hba.port_read(p, PX_CMD) & !CMD_ST);
        hba.wait_port(p, PX_CMD, CMD_CR, 0, 500);
        hba.port_write(p, PX_CMD, hba.port_read(p, PX_CMD) & !CMD_FRE);
        hba.wait_port(p, PX_CMD, CMD_FR, 0, 500);
        hba.port_write(p, PX_FB, fb as u32);
        hba.port_write(p, PX_FBU, (fb >> 32) as u32);
        hba.port_write(p, PX_SERR, 0xFFFF_FFFF);
        hba.port_write(p, PX_CMD, hba.port_read(p, PX_CMD) | CMD_FRE | CMD_POD | CMD_SUD);
        let sctl = hba.port_read(p, PX_SCTL) & !0xF;
        hba.port_write(p, PX_SCTL, sctl | 1);
        sys::sleep_ms(2);
        hba.port_write(p, PX_SCTL, sctl);
        hba.wait_port(p, PX_SSTS, 0xF, 3, 1000);
        let got = hba.wait_port(p, PX_SIG, 0xFFFF_FFFF, SIG_ATA, 1000);
        hba.port_write(p, PX_SERR, 0xFFFF_FFFF);
        hba.port_write(p, PX_CMD, hba.port_read(p, PX_CMD) & !CMD_FRE);
        hba.wait_port(p, PX_CMD, CMD_FR, 0, 500);
        println!("[ahci-driver] port {}: no signature from the firmware's use; after a link reset {:#x}{}", p, hba.port_read(p, PX_SIG), if got { "" } else { " (still none)" });
    }
}
// wave11 GH end

/// The driver's disks, for the unit logic shared with the other block drivers.
struct Set(alloc::vec::Vec<Disk>);

impl hydra_rt::blockunits::DiskSet for Set {
    fn count(&self) -> usize {
        self.0.len()
    }
    fn blocks(&self, disk: usize) -> u64 {
        self.0[disk].sectors / self.0[disk].sectors_per_block()
    }
    fn read(&mut self, disk: usize, block: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        let count = buf.len() / BLOCK;
        self.0[disk].blocks(block, count, buf, false)
    }
}

/// Driver entry point: takes over the adapter, finds the disks, and serves block requests
/// (units: see `hydra_rt::blockunits`).
fn main(args: &[&str]) {
    let Some(abar) = arg(args, "abar") else {
        println!("[ahci-driver] no adapter given (abar=...)");
        return;
    };
    // The register window need not start on a page (Intel's is 2 KiB aligned): map the
    // pages that hold it
    let page = abar & !0xFFF;
    let span = ((abar + ABAR_LEN + 0xFFF) & !0xFFF) - page;
    let regs = match sys::physmap(page, span as usize) {
        Ok(r) => unsafe { r.add((abar - page) as usize) },
        Err(e) => {
            println!("[ahci-driver] cannot map the registers at {:#x}: error {}", abar, e);
            return;
        }
    };
    let hba = Hba { regs };
    hba.take_ownership();
    let cap = hba.read(HBA_CAP);
    let vs = hba.read(HBA_VS);
    println!(
        "[ahci-driver] AHCI {}.{} at {:#x}: {} ports (implemented {:#x}), {}-bit DMA",
        vs >> 16,
        (vs >> 8) & 0xFF,
        abar,
        (cap & 0x1F) + 1,
        hba.read(HBA_PI),
        if cap & CAP_S64A != 0 { 64 } else { 32 }
    );
    // Firmware may leave a port's link still negotiating: give the links a moment
    let wanted = arg(args, "port").map(|p| p as usize);
    let mut ports = find_disk_ports(&hba, wanted);
    if ports.is_empty() {
        sys::sleep_ms(200);
        // wave11 GH: a device on the link without a signature (the firmware stopped the
        // port it used): a fresh one, as Linux's probe does with its hard reset
        refresh_signatures(&hba, wanted, cap);
        ports = find_disk_ports(&hba, wanted);
    }
    if ports.is_empty() {
        println!("[ahci-driver] no SATA disk on the adapter");
        return;
    }
    let irq = arg(args, "irq").map(|i| i as u8).filter(|&i| sys::irq_register(i).is_ok());
    let mut disks = alloc::vec::Vec::new();
    for port in ports {
        let (mem, mem_phys) = match sys::dma_alloc(DMA_LEN) {
            Ok(m) => m,
            Err(e) => {
                println!("[ahci-driver] no DMA memory: error {}", e);
                break;
            }
        };
        if cap & CAP_S64A == 0 && mem_phys + DMA_LEN as u64 > 0x1_0000_0000 {
            println!("[ahci-driver] the adapter reaches only 32-bit addresses and the DMA memory is above 4 GiB");
            break;
        }
        let mut disk = Disk {
            hba,
            port,
            irq,
            can_clo: cap & CAP_SCLO != 0,
            mem,
            mem_phys,
            model: [b' '; 40],
            sectors: 0,
            sector_size: 512,
            lba48: false,
            write_cache: false,
            recoveries: 0,
            s64a: cap & CAP_S64A != 0,
            ncq_slots: 0,
        };
        if let Err(e) = disk.start() {
            println!("[ahci-driver] port {}: {}", port, e);
            continue;
        }
        if disk.irq.is_some() {
            disk.hba.write(HBA_GHC, disk.hba.read(HBA_GHC) | GHC_IE);
        }
        if let Err(e) = disk.identify() {
            println!("[ahci-driver] port {}: IDENTIFY failed: {}", port, e);
            continue;
        }
        println!(
            "[ahci-driver] port {} (disk {}): '{}': {} MiB, {}-byte sectors, LBA{}, write cache {}, NCQ {}, {}",
            port,
            disks.len(),
            disk.model_str(),
            disk.sectors * disk.sector_size as u64 / (1024 * 1024),
            disk.sector_size,
            if disk.lba48 { 48 } else { 28 },
            if disk.write_cache { "on" } else { "off" },
            disk.ncq_slots,
            if disk.irq.is_some() { "MSI interrupt" } else { "polled" }
        );
        disks.push(disk);
    }
    if disks.is_empty() {
        return;
    }
    let mut set = Set(disks);
    let units = hydra_rt::blockunits::Units::choose(args, &mut set, "ahci-driver");
    let mut server = match Server::register(ENDPOINT_BLOCK_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[ahci-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_BLOCK_DEV, e);
            return;
        }
    };
    let mut stats = iostat::IoStats::new("ahci-driver");
    server.serve_ids(|srv, id, msg| match msg.label as u32 {
        MSG_BLOCK_READ | MSG_BLOCK_WRITE if msg.args[2] == OFFSET_LENT => {
            // The data is in pages the caller lent with the request: the disk reads or
            // writes them directly
            let (block, count) = (msg.args[0], msg.args[1] as usize);
            let write = msg.label as u32 == MSG_BLOCK_WRITE;
            let mut segs = [(0u64, 0u64); sys::GRANT_SEGMENTS_MAX];
            let nsegs = match sys::svc_grant(ENDPOINT_BLOCK_DEV, id, &mut segs) {
                Ok(n) => n.min(segs.len()),
                Err(_) => return reply(EINVAL, 0),
            };
            if count == 0 {
                return reply(EINVAL, 0);
            }
            let (d, at) = match units.map(msg.args[3], block, count as u64, write, &set) {
                Ok(m) => m,
                Err(e) => return reply(e, 0),
            };
            let t = stats.start();
            let result = set.0[d].blocks_lent(at, count, &segs[..nsegs], write);
            stats.done(t, (count * BLOCK) as u64, write);
            match result {
                Ok(()) => reply(0, count as u64),
                Err(None) => reply(EOPNOTSUPP, 0),
                Err(Some(e)) => {
                    println!("[ahci-driver] {} of {} lent blocks at {} (disk {}) failed: {}", if write { "write" } else { "read" }, count, at, d, e);
                    reply(EIO, 0)
                }
            }
        }
        MSG_BLOCK_READ | MSG_BLOCK_WRITE => {
            let (block, count, offset) = (msg.args[0], msg.args[1] as usize, msg.args[2] as usize);
            let write = msg.label as u32 == MSG_BLOCK_WRITE;
            if count == 0 || offset % BLOCK != 0 || offset + count * BLOCK > WINDOW_SIZE {
                return reply(EINVAL, 0);
            }
            let (d, at) = match units.map(msg.args[3], block, count as u64, write, &set) {
                Ok(m) => m,
                Err(e) => return reply(e, 0),
            };
            let t = stats.start();
            let result = set.0[d].blocks(at, count, &mut srv.window()[offset..], write);
            stats.done(t, (count * BLOCK) as u64, write);
            match result {
                Ok(()) => reply(0, count as u64),
                Err(e) => {
                    println!("[ahci-driver] {} of {} blocks at {} (disk {}) failed: {}", if write { "write" } else { "read" }, count, at, d, e);
                    reply(EIO, 0)
                }
            }
        }
        MSG_BLOCK_READV => {
            let n = msg.args[0] as usize;
            if n == 0 || n > BLOCK_READV_MAX {
                return reply(EINVAL, 0);
            }
            let window = srv.window();
            let mut runs = [[0u64; 3]; BLOCK_READV_MAX];
            let mut total = 0u64;
            let mut disk = 0;
            for (i, r) in runs[..n].iter_mut().enumerate() {
                for (k, v) in r.iter_mut().enumerate() {
                    let at = BLOCK_READV_TABLE + (i * 3 + k) * 8;
                    *v = u64::from_le_bytes(window[at..at + 8].try_into().unwrap());
                }
                let (block, count, offset) = (r[0], r[1] as usize, r[2] as usize);
                if count == 0 || offset % BLOCK != 0 || offset + count * BLOCK > BLOCK_READV_TABLE {
                    return reply(EINVAL, 0);
                }
                match units.map(msg.args[1], block, count as u64, false, &set) {
                    Ok((d, at)) => {
                        disk = d;
                        r[0] = at;
                    }
                    Err(e) => return reply(e, 0),
                }
                total += count as u64;
            }
            let t = stats.start();
            let result = set.0[disk].readv(&runs[..n], window);
            stats.done(t, total * BLOCK as u64, false);
            match result {
                Ok(()) => reply(0, total),
                Err(e) => {
                    println!("[ahci-driver] vectored read of {} runs failed: {}", n, e);
                    reply(EIO, 0)
                }
            }
        }
        MSG_BLOCK_FLUSH => {
            let d = match units.disk_of(msg.args[3], &set) {
                Ok(d) => d,
                Err(e) => return reply(e, 0),
            };
            match set.0[d].flush() {
                Ok(()) => reply(0, 0),
                Err(e) => {
                    println!("[ahci-driver] cache flush failed: {}", e);
                    reply(EIO, 0)
                }
            }
        }
        MSG_BLOCK_GET_SIZE => {
            let unit = msg.args[3];
            let d = match units.disk_of(unit, &set) {
                Ok(d) => d,
                Err(e) => return reply(e, 0),
            };
            let blocks = units.blocks_of(unit, &set);
            let w = srv.window();
            w[..40].copy_from_slice(&set.0[d].model);
            units.describe(unit, w, set.0[d].sector_size as u32, false);
            Message::new(MSG_BLOCK_REPLY as u64, [0, blocks, set.0[d].lba48 as u64, 1])
        }
        _ => reply(-38, 0),
    })
}
