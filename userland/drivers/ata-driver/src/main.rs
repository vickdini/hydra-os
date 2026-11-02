//! # Hydra ATA disk driver
//!
//! Drives the primary master IDE/ATA disk from Ring 3, in an address space of its own:
//! port I/O for commands and polled PIO transfers, bus-master DMA through a bounce buffer
//! when the controller supports it. Interrupts stay off (nIEN): completion is polled.
//!
//! The supervisor starts it with the controller's ports: `io=<base> ctrl=<port>` and,
//! when the PCI IDE controller can bus-master, `bm=<base>` (the kernel enumerates PCI and
//! enables bus mastering).
//!
//! Requests on [`ENDPOINT_BLOCK_DEV`] (blocks are 4 KiB; data is in the service window at
//! byte offset `args[2]`):
//! - `MSG_BLOCK_READ [block, count, offset]`, `MSG_BLOCK_WRITE [block, count, offset]`;
//! - `MSG_BLOCK_FLUSH`: flush the disk's write cache;
//! - `MSG_BLOCK_GET_SIZE`: reply `[0, blocks, lba48, dma]`, the model (40 bytes) in the window.
//!
//! Replies are `MSG_BLOCK_REPLY [status (0 or -errno), blocks transferred]`.

#![no_std]
#![no_main]

extern crate alloc;

use hydra_rt::port::{inb, inw, outb, outl, outw};
use hydra_rt::protocol::{
    ENDPOINT_BLOCK_DEV, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_READ, MSG_BLOCK_REPLY, MSG_BLOCK_WRITE,
};
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

hydra_rt::entry!(main);

const SECTOR: usize = 512;
const BLOCK: usize = 4096;
const SECTORS_PER_BLOCK: u64 = (BLOCK / SECTOR) as u64;
/// Blocks per ATA command (the sector count register holds up to 255 sectors).
const MAX_RUN: usize = 31;

const CMD_READ_SECTORS: u8 = 0x20;
const CMD_READ_SECTORS_EXT: u8 = 0x24;
const CMD_WRITE_SECTORS: u8 = 0x30;
const CMD_WRITE_SECTORS_EXT: u8 = 0x34;
const CMD_READ_DMA: u8 = 0xC8;
const CMD_READ_DMA_EXT: u8 = 0x25;
const CMD_WRITE_DMA: u8 = 0xCA;
const CMD_WRITE_DMA_EXT: u8 = 0x35;
const CMD_CACHE_FLUSH: u8 = 0xE7;
const CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
const CMD_IDENTIFY: u8 = 0xEC;

const STATUS_ERR: u8 = 0x01;
const STATUS_DRQ: u8 = 0x08;
const STATUS_DF: u8 = 0x20;
const STATUS_BSY: u8 = 0x80;

const BM_COMMAND: u16 = 0;
const BM_STATUS: u16 = 2;
const BM_PRDT: u16 = 4;
const BM_CMD_START: u8 = 0x01;
const BM_CMD_TO_MEMORY: u8 = 0x08;
const BM_STATUS_ACTIVE: u8 = 0x01;
const BM_STATUS_ERROR: u8 = 0x02;
const BM_STATUS_IRQ: u8 = 0x04;

/// Pages in the DMA bounce buffer: one command of up to 255 sectors fits.
const DMA_PAGES: usize = 32;

const EIO: i64 = -5;
const EINVAL: i64 = -22;

/// Polls a condition with a time limit (30 s), checking the clock only now and then.
struct Deadline {
    polls: u64,
    end: u64,
}

impl Deadline {
    /// Creates a new deadline timer instance.
    ///
    /// # Returns
    /// Newly initialized [`Deadline`] structure.
    fn new() -> Self {
        Self { polls: 0, end: 0 }
    }

    /// Checks whether the deadline timeout (30 seconds) has expired.
    ///
    /// # Returns
    /// `true` if deadline has passed, `false` otherwise.
    fn expired(&mut self) -> bool {
        self.polls += 1;
        if self.polls % 4096 != 0 {
            return false;
        }
        let now = sys::uptime_ticks();
        if self.end == 0 {
            self.end = now + 3000;
        }
        now >= self.end
    }
}

/// Task-file registers of one channel.
struct Ports {
    io: u16,
    ctrl: u16,
}

impl Ports {
    /// Delays execution by at least 400 nanoseconds by reading the control port 4 times.
    fn delay_400ns(&self) {
        for _ in 0..4 {
            inb(self.ctrl);
        }
    }

    /// Issues an ATA software reset to the channel and waits for BSY to clear.
    fn soft_reset(&self) {
        outb(self.ctrl, 0x04 | 0x02); // SRST, interrupts off
        self.delay_400ns();
        outb(self.ctrl, 0x02);
        for _ in 0..10 {
            self.delay_400ns();
        }
        let _ = self.wait_not_busy();
    }

    /// Polls the status register until the BSY bit clears or deadline expires.
    ///
    /// # Returns
    /// Final status register byte on success.
    ///
    /// # Errors
    /// Static error string if timeout occurs.
    fn wait_not_busy(&self) -> Result<u8, &'static str> {
        let mut d = Deadline::new();
        while !d.expired() {
            let s = inb(self.ctrl);
            if s & STATUS_BSY == 0 {
                return Ok(s);
            }
            core::hint::spin_loop();
        }
        Err("timeout waiting for BSY to clear")
    }

    /// Polls the status register until DRQ is set and BSY is clear.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string if timeout or device fault occurs.
    fn wait_data_ready(&self) -> Result<(), &'static str> {
        let mut d = Deadline::new();
        while !d.expired() {
            let s = inb(self.ctrl);
            if s & STATUS_ERR != 0 {
                return Err("device error");
            }
            if s & STATUS_DF != 0 {
                return Err("device fault");
            }
            if s & STATUS_BSY == 0 && s & STATUS_DRQ != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("timeout waiting for DRQ")
    }

    /// Selects the drive and loads the address and count registers for a command.
    ///
    /// # Arguments
    /// * `lba` - Logical block address.
    /// * `count` - Sector count.
    /// * `lba48` - Whether to issue 48-bit LBA command registers.
    fn setup(&self, lba: u64, count: u8, lba48: bool) {
        outb(self.io + 6, if lba48 { 0x40 } else { 0xE0 | ((lba >> 24) & 0x0F) as u8 });
        self.delay_400ns();
        if lba48 {
            outb(self.io + 2, 0);
            outb(self.io + 3, (lba >> 24) as u8);
            outb(self.io + 4, (lba >> 32) as u8);
            outb(self.io + 5, (lba >> 40) as u8);
        } else {
            outb(self.io + 1, 0);
        }
        outb(self.io + 2, count);
        outb(self.io + 3, lba as u8);
        outb(self.io + 4, (lba >> 8) as u8);
        outb(self.io + 5, (lba >> 16) as u8);
    }
}

/// Bus-master DMA engine of the channel, with its PRD table and bounce buffer.
struct BusMaster {
    base: u16,
    prdt: *mut u32,
    prdt_phys: u64,
    buf: *mut u8,
    buf_phys: u64,
}

impl BusMaster {
    /// Initializes the bus-master DMA controller and allocates PRDT/buffer memory.
    ///
    /// # Arguments
    /// * `base` - Bus-master I/O base port.
    ///
    /// # Returns
    /// `Some(BusMaster)` on success, `None` if allocation fails or exceeds 32-bit physical limit.
    fn new(base: u16) -> Option<Self> {
        let (mem, phys) = sys::dma_alloc((DMA_PAGES + 1) * 4096).ok()?;
        if phys + ((DMA_PAGES as u64 + 1) * 4096) > 0x1_0000_0000 {
            return None; // PRD entries hold 32-bit addresses
        }
        Some(Self { base, prdt: mem as *mut u32, prdt_phys: phys, buf: unsafe { mem.add(4096) }, buf_phys: phys + 4096 })
    }

    /// Describes `bytes` of the bounce buffer, one entry per page (none crosses 64 KiB).
    ///
    /// # Arguments
    /// * `bytes` - Total transfer size in bytes.
    fn build_prdt(&self, bytes: usize) {
        let pages = (bytes + 4095) / 4096;
        for i in 0..pages {
            let len = (bytes - i * 4096).min(4096) as u32;
            let last = if i + 1 == pages { 0x8000_0000u32 } else { 0 };
            unsafe {
                core::ptr::write_volatile(self.prdt.add(i * 2), (self.buf_phys + (i * 4096) as u64) as u32);
                core::ptr::write_volatile(self.prdt.add(i * 2 + 1), len | last);
            }
        }
    }
}

/// The disk.
struct Disk {
    ports: Ports,
    model: [u8; 40],
    sectors: u64,
    lba48: bool,
    dma: Option<BusMaster>,
    dma_failures: u32,
}

impl Disk {
    /// Identifies the primary master; `None` if there is no ATA disk there.
    ///
    /// # Arguments
    /// * `ports` - Channel task-file port registers.
    ///
    /// # Returns
    /// `Some(Disk)` if an ATA hard drive is detected, or `None`.
    fn probe(ports: Ports) -> Option<Self> {
        outb(ports.ctrl, 0x02); // interrupts off
        outb(ports.io + 6, 0xA0);
        ports.delay_400ns();
        for r in 2..6 {
            outb(ports.io + r, 0);
        }
        outb(ports.io + 7, CMD_IDENTIFY);
        ports.delay_400ns();
        let status = inb(ports.io + 7);
        if status == 0 || status == 0xFF || ports.wait_not_busy().is_err() {
            return None;
        }
        let (mid, high) = (inb(ports.io + 4), inb(ports.io + 5));
        if (mid == 0x14 && high == 0xEB) || (mid == 0x69 && high == 0x96) {
            return None; // ATAPI (optical) device
        }
        ports.wait_data_ready().ok()?;
        let mut id = [0u16; 256];
        for w in id.iter_mut() {
            *w = inw(ports.io);
        }
        let mut model = [b' '; 40];
        for (i, w) in id[27..47].iter().enumerate() {
            model[i * 2] = (*w >> 8) as u8;
            model[i * 2 + 1] = *w as u8;
        }
        let lba48 = id[83] & (1 << 10) != 0;
        let sectors = if lba48 {
            id[100] as u64 | (id[101] as u64) << 16 | (id[102] as u64) << 32 | (id[103] as u64) << 48
        } else {
            id[60] as u64 | (id[61] as u64) << 16
        };
        (sectors != 0).then_some(Self { ports, model, sectors, lba48, dma: None, dma_failures: 0 })
    }

    /// Returns the drive model string trimmed of trailing spaces.
    ///
    /// # Returns
    /// Drive model name as a string slice.
    fn model_str(&self) -> &str {
        let len = self.model.iter().rposition(|&b| b != b' ' && b != 0).map_or(0, |i| i + 1);
        core::str::from_utf8(&self.model[..len]).unwrap_or("ATA disk")
    }

    /// Determines whether 48-bit LBA addressing must be used for `lba`.
    ///
    /// # Arguments
    /// * `lba` - Logical block address.
    ///
    /// # Returns
    /// `true` if 48-bit commands should be issued, `false` for 28-bit.
    fn use_lba48(&self, lba: u64) -> bool {
        !(lba < 0x1000_0000 && !self.lba48)
    }

    /// Moves `count` sectors at `lba` by DMA.
    ///
    /// # Arguments
    /// * `lba` - Logical block address.
    /// * `count` - Number of sectors to transfer.
    /// * `data` - Sector data buffer.
    /// * `write` - `true` for write, `false` for read.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string on DMA or device fault.
    fn dma_transfer(&mut self, lba: u64, count: u8, data: &mut [u8], write: bool) -> Result<(), &'static str> {
        let bm = self.dma.as_ref().ok_or("no DMA")?;
        let bytes = count as usize * SECTOR;
        if write {
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), bm.buf, bytes) };
        }
        bm.build_prdt(bytes);
        outb(bm.base + BM_COMMAND, 0);
        outb(bm.base + BM_STATUS, BM_STATUS_ERROR | BM_STATUS_IRQ);
        outl(bm.base + BM_PRDT, bm.prdt_phys as u32);
        let direction = if write { 0 } else { BM_CMD_TO_MEMORY };
        outb(bm.base + BM_COMMAND, direction);
        self.ports.wait_not_busy()?;
        let lba48 = self.use_lba48(lba);
        self.ports.setup(lba, count, lba48);
        let cmd = match (write, lba48) {
            (false, false) => CMD_READ_DMA,
            (false, true) => CMD_READ_DMA_EXT,
            (true, false) => CMD_WRITE_DMA,
            (true, true) => CMD_WRITE_DMA_EXT,
        };
        outb(self.ports.io + 7, cmd);
        outb(bm.base + BM_COMMAND, direction | BM_CMD_START);
        let mut d = Deadline::new();
        let result = loop {
            let st = inb(bm.base + BM_STATUS);
            if st & BM_STATUS_ERROR != 0 {
                break Err("DMA transfer error");
            }
            if st & BM_STATUS_ACTIVE == 0 || st & BM_STATUS_IRQ != 0 {
                break Ok(());
            }
            if d.expired() {
                break Err("DMA transfer timed out");
            }
            core::hint::spin_loop();
        };
        outb(bm.base + BM_COMMAND, 0);
        let status = self.ports.wait_not_busy()?;
        outb(bm.base + BM_STATUS, BM_STATUS_ERROR | BM_STATUS_IRQ);
        result?;
        if status & (STATUS_ERR | STATUS_DF) != 0 {
            return Err("device error after DMA");
        }
        if !write {
            unsafe { core::ptr::copy_nonoverlapping(bm.buf, data.as_mut_ptr(), bytes) };
        }
        Ok(())
    }

    /// Moves `count` sectors at `lba` with port I/O.
    ///
    /// # Arguments
    /// * `lba` - Logical block address.
    /// * `count` - Number of sectors to transfer.
    /// * `data` - Sector data buffer.
    /// * `write` - `true` for write, `false` for read.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string on timeout or device fault.
    fn pio_transfer(&mut self, lba: u64, count: u8, data: &mut [u8], write: bool) -> Result<(), &'static str> {
        self.ports.wait_not_busy()?;
        let lba48 = self.use_lba48(lba);
        self.ports.setup(lba, count, lba48);
        let cmd = match (write, lba48) {
            (false, false) => CMD_READ_SECTORS,
            (false, true) => CMD_READ_SECTORS_EXT,
            (true, false) => CMD_WRITE_SECTORS,
            (true, true) => CMD_WRITE_SECTORS_EXT,
        };
        outb(self.ports.io + 7, cmd);
        for sector in data[..count as usize * SECTOR].chunks_mut(SECTOR) {
            self.ports.wait_data_ready()?;
            for word in sector.chunks_mut(2) {
                if write {
                    outw(self.ports.io, word[0] as u16 | (word[1] as u16) << 8);
                } else {
                    let w = inw(self.ports.io);
                    word[0] = w as u8;
                    word[1] = (w >> 8) as u8;
                }
            }
            self.ports.delay_400ns();
        }
        if write {
            self.ports.wait_not_busy()?;
        }
        Ok(())
    }

    /// One command: DMA if available (port I/O after a DMA failure, and from then on
    /// after repeated ones), retried once after a reset.
    ///
    /// # Arguments
    /// * `lba` - Logical block address.
    /// * `count` - Number of sectors to transfer.
    /// * `data` - Sector data buffer.
    /// * `write` - `true` for write, `false` for read.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string on persistent failure.
    fn transfer(&mut self, lba: u64, count: u8, data: &mut [u8], write: bool) -> Result<(), &'static str> {
        if lba + count as u64 > self.sectors {
            return Err("past the end of the disk");
        }
        if self.dma.is_some() {
            match self.dma_transfer(lba, count, data, write) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.ports.soft_reset();
                    self.dma_failures += 1;
                    println!("[ata-driver] DMA failed ({}); retrying with port I/O", e);
                    if self.dma_failures >= 3 {
                        println!("[ata-driver] DMA failing repeatedly; using port I/O");
                        self.dma = None;
                    }
                }
            }
        }
        self.pio_transfer(lba, count, data, write).or_else(|_| {
            self.ports.soft_reset();
            self.pio_transfer(lba, count, data, write)
        })
    }

    /// Flushes write cache to disk media.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string on flush failure.
    fn flush(&mut self) -> Result<(), &'static str> {
        let once = |p: &Ports, ext: bool| -> Result<(), &'static str> {
            p.wait_not_busy()?;
            outb(p.io + 7, if ext { CMD_CACHE_FLUSH_EXT } else { CMD_CACHE_FLUSH });
            p.delay_400ns();
            p.wait_not_busy().map(|_| ())
        };
        once(&self.ports, self.lba48).or_else(|_| {
            self.ports.soft_reset();
            once(&self.ports, self.lba48)
        })
    }

    /// Reads or writes `count` 4 KiB blocks at `block` to or from `data`.
    ///
    /// # Arguments
    /// * `block` - 4 KiB block index.
    /// * `count` - Number of 4 KiB blocks.
    /// * `data` - Block data buffer.
    /// * `write` - `true` for write, `false` for read.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string on transfer failure.
    fn blocks(&mut self, block: u64, count: usize, data: &mut [u8], write: bool) -> Result<(), &'static str> {
        for (i, chunk) in data[..count * BLOCK].chunks_mut(MAX_RUN * BLOCK).enumerate() {
            let lba = (block + (i * MAX_RUN) as u64) * SECTORS_PER_BLOCK;
            self.transfer(lba, (chunk.len() / SECTOR) as u8, chunk, write)?;
        }
        Ok(())
    }
}

/// Constructs a block service reply message.
///
/// # Arguments
/// * `status` - Status code (0 for success or negative error code).
/// * `value` - Return value (e.g. transferred count).
///
/// # Returns
/// Constructed [`Message`].
fn reply(status: i64, value: u64) -> Message {
    Message::new(MSG_BLOCK_REPLY as u64, [status as u64, value, 0, 0])
}

/// Value of a `key=<number>` argument (decimal or `0x` hex).
///
/// # Arguments
/// * `args` - Program argument list.
/// * `key` - Argument key name.
///
/// # Returns
/// Parsed integer value if found, or `None`.
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Driver entry point that probes the ATA controller, registers service, and dispatches requests.
///
/// # Arguments
/// * `args` - Command-line argument strings.
fn main(args: &[&str]) {
    if let Err(e) = sys::iopl() {
        println!("[ata-driver] no I/O port access: error {}", e);
        return;
    }
    let io = arg(args, "io").unwrap_or(0x1F0) as u16;
    let ctrl = arg(args, "ctrl").unwrap_or(0x3F6) as u16;
    let Some(mut disk) = Disk::probe(Ports { io, ctrl }) else {
        println!("[ata-driver] no ATA disk at {:#x}", io);
        return;
    };
    disk.dma = arg(args, "bm").and_then(|bm| BusMaster::new(bm as u16));
    let mut server = match Server::register(ENDPOINT_BLOCK_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[ata-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_BLOCK_DEV, e);
            return;
        }
    };
    println!(
        "[ata-driver] '{}': {} MiB, LBA{}, {}",
        disk.model_str(),
        disk.sectors * SECTOR as u64 / (1024 * 1024),
        if disk.lba48 { 48 } else { 28 },
        if disk.dma.is_some() { "bus-master DMA" } else { "port I/O" }
    );
    let blocks = disk.sectors / SECTORS_PER_BLOCK;
    server.serve(|srv, msg| match msg.label as u32 {
        MSG_BLOCK_READ | MSG_BLOCK_WRITE => {
            let (block, count, offset) = (msg.args[0], msg.args[1] as usize, msg.args[2] as usize);
            if count == 0 || offset % BLOCK != 0 || offset + count * BLOCK > WINDOW_SIZE || block + count as u64 > blocks {
                return reply(EINVAL, 0);
            }
            let write = msg.label as u32 == MSG_BLOCK_WRITE;
            match disk.blocks(block, count, &mut srv.window()[offset..], write) {
                Ok(()) => reply(0, count as u64),
                Err(e) => {
                    println!("[ata-driver] {} of {} blocks at {} failed: {}", if write { "write" } else { "read" }, count, block, e);
                    reply(EIO, 0)
                }
            }
        }
        MSG_BLOCK_FLUSH => match disk.flush() {
            Ok(()) => reply(0, 0),
            Err(e) => {
                println!("[ata-driver] cache flush failed: {}", e);
                reply(EIO, 0)
            }
        },
        MSG_BLOCK_GET_SIZE => {
            srv.window()[..40].copy_from_slice(&disk.model);
            Message::new(MSG_BLOCK_REPLY as u64, [0, blocks, disk.lba48 as u64, disk.dma.is_some() as u64])
        }
        _ => reply(-38, 0),
    })
}
