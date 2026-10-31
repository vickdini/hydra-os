//! # Architecture Layer: ATA / IDE PIO Block Device Driver
//!
//! Provides bare-metal programmed I/O (PIO) access to legacy and virtualized ATA/IDE hard disks.
//!
//! ## Architectural Role & Design Rationale
//!
//! To achieve true operating system persistence across hardware reboots, Hydra OS requires an
//! autonomous block device driver that operates directly on physical/virtual hardware without
//! relying on terminated UEFI firmware boot services.
//!
//! The ATA driver communicates over the legacy standard x86 I/O port ranges:
//! - **Primary Bus**: Command block `0x1F0..0x1F7`, Control block `0x3F6`.
//! - **Secondary Bus**: Command block `0x170..0x177`, Control block `0x376`.
//!
//! By operating in polled PIO mode with device interrupts disabled (`nIEN = 1`), the driver
//! executes synchronously with zero interrupt latency and complete fault isolation, providing
//! reliable sector read, write, and cache flush operations to back the OpenZFS storage pool.
//!
//! ## Key Types & Interfaces
//!
//! - `AtaDevice`: Represents an identified physical or virtual ATA/IDE disk drive supporting PIO and Bus-Master DMA.
//! - `DriveRole`: Distinguishes Master (`0xA0`/`0xE0`) and Slave (`0xB0`/`0xF0`) drives on an ATA channel.
//! - `PRIMARY_ATA`: Global mutex-protected singleton holding the primary master ATA disk instance.
//! - `init`: Probes the primary master ATA channel and registers the block device.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Executes exclusively in Ring 0 (Microkernel core).
//! - **Hardware Interaction**: Standard Intel PIIX3/PIIX4 IDE Controller or compatible SATA in IDE mode; 16-bit data port (`0x1F0`), 8-bit command/status registers (`0x1F1..0x1F7`), device control (`0x3F6`), and PCI Bus-Master DMA BAR4 registers.
//! - **Concurrency**: Synchronized globally via `PRIMARY_ATA` (`spin::Mutex`) with polled completion deadlines.
//! - **Filesystem Integration**: Directly backs [`crate::fs::zfs::spa::Vdev`] in the OpenZFS SPA.

use spin::Mutex;
use x86_64::instructions::port::Port;

/// Standard sector size in bytes for ATA/IDE hard drives.
pub const ATA_SECTOR_SIZE: usize = 512;

/// Primary ATA channel command block base I/O port (`0x1F0`).
pub const ATA_PRIMARY_IO_BASE: u16 = 0x1F0;
/// Primary ATA channel control/alternate-status port (`0x3F6`).
pub const ATA_PRIMARY_CTRL_BASE: u16 = 0x3F6;
/// Secondary ATA channel command block base I/O port (`0x170`).
pub const ATA_SECONDARY_IO_BASE: u16 = 0x170;
/// Secondary ATA channel control/alternate-status port (`0x376`).
pub const ATA_SECONDARY_CTRL_BASE: u16 = 0x376;

// ATA Commands
/// ATA PIO 28-bit LBA Read Sectors command (`0x20`).
pub const ATA_CMD_READ_SECTORS: u8 = 0x20;
/// ATA PIO 48-bit LBA Read Sectors Ext command (`0x24`).
pub const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
/// ATA PIO 28-bit LBA Write Sectors command (`0x30`).
pub const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
/// ATA PIO 48-bit LBA Write Sectors Ext command (`0x34`).
pub const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;
/// ATA 28-bit Flush Volatile Write Cache command (`0xE7`).
pub const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
/// ATA 48-bit Flush Volatile Write Cache Ext command (`0xEA`).
pub const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
/// ATA Identify Device command (`0xEC`).
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;

// ATA Status Register Bits
/// ATA Status bit 0: Error (`ERR`) occurred during the previous command.
pub const ATA_STATUS_ERR: u8 = 0x01;  // Error
/// ATA Status bit 3: Data Request (`DRQ`) — drive is ready to transfer a word/sector of data.
pub const ATA_STATUS_DRQ: u8 = 0x08;  // Data Request Ready
/// ATA Status bit 4: Overlapped Mode Service Request (`SRV`).
pub const ATA_STATUS_SRV: u8 = 0x10;  // Overlapped Mode Service Request
/// ATA Status bit 5: Drive Fault (`DF`) — internal hardware fault detected.
pub const ATA_STATUS_DF: u8 = 0x20;   // Drive Fault / Device Fault
/// ATA Status bit 6: Drive Ready (`DRDY`) — drive is spun up and ready to accept commands.
pub const ATA_STATUS_DRDY: u8 = 0x40; // Device Ready
/// ATA Status bit 7: Busy (`BSY`) — drive controller is busy; no other status bits are valid.
pub const ATA_STATUS_BSY: u8 = 0x80;  // Busy executing command

/// Maximum polling iterations before timing out on ATA hardware response.
const ATA_POLL_TIMEOUT: usize = 1_000_000;

/// Global autonomous primary ATA hard disk drive instance.
pub static PRIMARY_ATA: Mutex<Option<AtaDevice>> = Mutex::new(None);

/// Identifies the drive role on an ATA bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveRole {
    /// Master drive (selector `0xA0` / `0xE0`).
    Master = 0x00,
    /// Slave drive (selector `0xB0` / `0xF0`).
    Slave = 0x10,
}

/// Hardware register interface for an ATA PIO channel.
struct AtaPorts {
    /// 16-bit PIO data read/write register (`base + 0`).
    data: Port<u16>,
    /// Error register on read / Features register on write (`base + 1`).
    error_features: Port<u8>,
    /// Number of sectors to transfer (`base + 2`).
    sector_count: Port<u8>,
    /// LBA bits `0..=7` (and `24..=31` in LBA48 high byte write) (`base + 3`).
    lba_low: Port<u8>,
    /// LBA bits `8..=15` (and `32..=39` in LBA48 high byte write) (`base + 4`).
    lba_mid: Port<u8>,
    /// LBA bits `16..=23` (and `40..=47` in LBA48 high byte write) (`base + 5`).
    lba_high: Port<u8>,
    /// Drive select (`Master`/`Slave`), LBA mode bit, and LBA28 bits `24..=27` (`base + 6`).
    drive_head: Port<u8>,
    /// Primary Status register on read / Command register on write (`base + 7`).
    status_command: Port<u8>,
    /// Alternate Status register on read / Device Control (`nIEN`, `SRST`) on write (`ctrl_base`).
    control_alt_status: Port<u8>,
}

impl AtaPorts {
    /// Constructs an [`AtaPorts`] register set for the given command block and control port bases.
    fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self {
            data: Port::new(io_base),
            error_features: Port::new(io_base + 1),
            sector_count: Port::new(io_base + 2),
            lba_low: Port::new(io_base + 3),
            lba_mid: Port::new(io_base + 4),
            lba_high: Port::new(io_base + 5),
            drive_head: Port::new(io_base + 6),
            status_command: Port::new(io_base + 7),
            control_alt_status: Port::new(ctrl_base),
        }
    }

    /// Delays for at least 400 nanoseconds by reading the Alternate Status register 4 times.
    #[inline(always)]
    fn delay_400ns(&mut self) {
        unsafe {
            let _ = self.control_alt_status.read();
            let _ = self.control_alt_status.read();
            let _ = self.control_alt_status.read();
            let _ = self.control_alt_status.read();
        }
    }

    /// Reads the alternate status register without clearing pending interrupts.
    #[inline(always)]
    fn read_alt_status(&mut self) -> u8 {
        unsafe { self.control_alt_status.read() }
    }

    /// Reads the main status register (which clears pending hardware interrupts).
    #[inline(always)]
    fn read_status(&mut self) -> u8 {
        unsafe { self.status_command.read() }
    }

    /// Software reset of the channel (SRST): returns a drive stuck busy after a failed or
    /// timed-out command to a state where it accepts commands again.
    fn soft_reset(&mut self) {
        unsafe {
            self.control_alt_status.write(0x04 | 0x02); // SRST, interrupts off
        }
        self.delay_400ns();
        unsafe {
            self.control_alt_status.write(0x02);
        }
        for _ in 0..10 {
            self.delay_400ns();
        }
        let _ = self.wait_not_busy();
    }

    /// Polls until the BSY bit is cleared or a timeout occurs.
    fn wait_not_busy(&mut self) -> Result<u8, &'static str> {
        let mut wait = PollDeadline::new();
        while !wait.expired() {
            let status = self.read_alt_status();
            if (status & ATA_STATUS_BSY) == 0 {
                return Ok(status);
            }
            core::hint::spin_loop();
        }
        Err("ATA device timeout waiting for BSY to clear")
    }

    /// Polls until the drive indicates DRQ (data request ready) and is not busy.
    fn wait_data_ready(&mut self) -> Result<(), &'static str> {
        let mut wait = PollDeadline::new();
        while !wait.expired() {
            let status = self.read_alt_status();
            if (status & ATA_STATUS_ERR) != 0 {
                return Err("ATA device reported error status (ERR bit asserted)");
            }
            if (status & ATA_STATUS_DF) != 0 {
                return Err("ATA device fault detected (DF bit asserted)");
            }
            if (status & ATA_STATUS_BSY) == 0 && (status & ATA_STATUS_DRQ) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("ATA device timeout waiting for DRQ data ready")
    }
}

/// Timeout for status polling: at least `ATA_POLL_TIMEOUT` polls, and while the timer
/// runs, at least 30 seconds. A virtual disk can stall for seconds while the host flushes
/// its image file; a fixed poll count alone gave up on writes that were still in progress.
struct PollDeadline {
    /// Number of status register poll iterations performed so far.
    polls: u64,
    /// PIT tick count recorded when the poll operation started.
    start: u64,
    /// PIT tick count at which the 30-second wall-clock timeout expires.
    deadline: u64,
}

impl PollDeadline {
    /// Starts a new polling deadline anchored to the current PIT tick counter.
    fn new() -> Self {
        let hz = crate::arch::pit::frequency_hz().max(1);
        let start = crate::arch::pit::ticks();
        Self { polls: 0, start, deadline: start + 30 * hz }
    }

    /// Increments the poll counter and returns `true` if both the minimum poll budget and
    /// the 30-second timer deadline have expired.
    fn expired(&mut self) -> bool {
        self.polls += 1;
        if self.polls <= ATA_POLL_TIMEOUT as u64 {
            return false;
        }
        // Past the poll budget: keep waiting only while the timer shows time passing
        let now = crate::arch::pit::ticks();
        now == self.start || now >= self.deadline
    }
}

/// Represents an active physical or virtual ATA/IDE hard disk drive.
///
/// # Concurrency & Thread Safety
/// Wrapped inside `PRIMARY_ATA` (`spin::Mutex<Option<AtaDevice>>`) so all PIO and DMA
/// commands execute sequentially without overlapping port accesses.
pub struct AtaDevice {
    /// I/O port register set for the drive's ATA channel.
    ports: AtaPorts,
    /// Master or Slave role on the channel.
    _role: DriveRole,
    /// 40-byte ASCII model string extracted from `IDENTIFY` words `27..=46`.
    model: [u8; 40],
    /// Total addressable 512-byte sectors reported by the drive.
    total_sectors: u64,
    /// Whether 48-bit LBA addressing (`EXT` commands) is supported.
    lba48_supported: bool,
    /// Bus-master DMA engine, when the controller has one.
    dma: Option<BusMaster>,
    /// Consecutive DMA transfer error count before falling back permanently to PIO.
    dma_failures: u32,
}

impl AtaDevice {
    /// Probes and initializes the primary master ATA hard disk drive.
    ///
    /// # Returns
    /// - `Some(AtaDevice)` if an ATA drive is present and successfully identified.
    /// - `None` if no drive is connected or the device is ATAPI/unsupported.
    pub fn probe_primary_master() -> Option<Self> {
        let mut ports = AtaPorts::new(ATA_PRIMARY_IO_BASE, ATA_PRIMARY_CTRL_BASE);

        // 1. Disable hardware interrupts by setting nIEN bit in Device Control Register
        unsafe {
            ports.control_alt_status.write(0x02);
        }

        // 2. Select Primary Master drive
        unsafe {
            ports.drive_head.write(0xA0);
        }
        ports.delay_400ns();

        // 3. Clear parameter registers
        unsafe {
            ports.sector_count.write(0);
            ports.lba_low.write(0);
            ports.lba_mid.write(0);
            ports.lba_high.write(0);
        }

        // 4. Send IDENTIFY command
        unsafe {
            ports.status_command.write(ATA_CMD_IDENTIFY);
        }
        ports.delay_400ns();

        // 5. Read status: 0 or 0xFF indicates no drive connected on this port
        let status = ports.read_status();
        if status == 0 || status == 0xFF {
            return None;
        }

        // 6. Wait for drive to become ready
        if ports.wait_not_busy().is_err() {
            return None;
        }

        // 7. Check for ATAPI signature (LBA mid = 0x14, LBA high = 0xEB)
        let lba_mid = unsafe { ports.lba_mid.read() };
        let lba_high = unsafe { ports.lba_high.read() };
        if (lba_mid == 0x14 && lba_high == 0xEB) || (lba_mid == 0x69 && lba_high == 0x96) {
            // ATAPI optical drive; not an ATA hard drive
            return None;
        }

        // 8. Wait for DRQ to transfer 512-byte identification frame
        if ports.wait_data_ready().is_err() {
            return None;
        }

        // 9. Read 256 words (512 bytes) of identify data
        let mut identify_buf = [0u16; 256];
        for word in identify_buf.iter_mut() {
            *word = unsafe { ports.data.read() };
        }

        // Words 27..46: Model string (40 ASCII characters, byte-swapped)
        let mut model = [b' '; 40];
        for (i, word) in identify_buf[27..47].iter().enumerate() {
            model[i * 2] = (*word >> 8) as u8;
            model[i * 2 + 1] = (*word & 0xFF) as u8;
        }

        // Word 83 bit 10: 48-bit LBA support flag
        let lba48_supported = (identify_buf[83] & (1 << 10)) != 0;

        // Total sectors calculation
        let total_sectors = if lba48_supported {
            let s0 = identify_buf[100] as u64;
            let s1 = (identify_buf[101] as u64) << 16;
            let s2 = (identify_buf[102] as u64) << 32;
            let s3 = (identify_buf[103] as u64) << 48;
            s0 | s1 | s2 | s3
        } else {
            let low = identify_buf[60] as u64;
            let high = (identify_buf[61] as u64) << 16;
            low | high
        };

        if total_sectors == 0 {
            return None;
        }

        Some(Self {
            ports,
            _role: DriveRole::Master,
            model,
            total_sectors,
            lba48_supported,
            dma: BusMaster::probe(),
            dma_failures: 0,
        })
    }

    /// Returns the human-readable model string of the drive.
    pub fn model_str(&self) -> &str {
        let mut len = self.model.len();
        while len > 0 && (self.model[len - 1] == b' ' || self.model[len - 1] == 0) {
            len -= 1;
        }
        core::str::from_utf8(&self.model[..len]).unwrap_or("Generic ATA Disk")
    }

    /// Returns total addressable 512-byte sectors on the drive.
    pub fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    /// Returns the storage capacity of the drive in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(ATA_SECTOR_SIZE as u64)
    }

    /// Returns true if the drive supports 48-bit Logical Block Addressing.
    pub fn is_lba48(&self) -> bool {
        self.lba48_supported
    }

    /// Reads contiguous 512-byte sectors into the provided buffer using PIO mode.
    ///
    /// # Arguments
    /// - `lba`: Starting Logical Block Address.
    /// - `count`: Number of 512-byte sectors to read (1 to 255).
    /// - `buf`: Destination byte slice. Must be at least `count * 512` bytes long.
    ///
    /// # Errors
    /// Returns `Err` if the target LBA exceeds disk boundaries, the buffer is undersized,
    /// or a hardware communication error/timeout occurs.
    pub fn read_sectors(&mut self, lba: u64, count: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        // A failed command leaves the drive in an unknown state: reset it, then retry once
        self.read_sectors_once(lba, count, buf).or_else(|_| {
            self.ports.soft_reset();
            self.read_sectors_once(lba, count, buf)
        })
    }

    fn read_sectors_once(&mut self, lba: u64, count: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        let required_len = (count as usize).saturating_mul(ATA_SECTOR_SIZE);
        if buf.len() < required_len {
            return Err("Destination buffer too small for requested sector count");
        }
        if lba.saturating_add(count as u64) > self.total_sectors {
            return Err("LBA address out of disk bounds");
        }
        if count == 0 {
            return Ok(());
        }
        if let Some(r) = self.dma_or(lba, count, buf.as_mut_ptr(), false) {
            return r;
        }

        self.ports.wait_not_busy()?;

        // Configure LBA28 or LBA48 registers
        if lba < 0x1000_0000 && !self.lba48_supported {
            // LBA28 Addressing
            unsafe {
                self.ports.drive_head.write(0xE0 | (((lba >> 24) & 0x0F) as u8));
            }
            self.ports.delay_400ns();
            unsafe {
                self.ports.error_features.write(0);
                self.ports.sector_count.write(count);
                self.ports.lba_low.write(lba as u8);
                self.ports.lba_mid.write((lba >> 8) as u8);
                self.ports.lba_high.write((lba >> 16) as u8);
                self.ports.status_command.write(ATA_CMD_READ_SECTORS);
            }
        } else {
            // LBA48 Addressing
            unsafe {
                self.ports.drive_head.write(0x40); // LBA bit set
            }
            self.ports.delay_400ns();
            unsafe {
                // High bytes first
                self.ports.sector_count.write(0);
                self.ports.lba_low.write((lba >> 24) as u8);
                self.ports.lba_mid.write((lba >> 32) as u8);
                self.ports.lba_high.write((lba >> 40) as u8);
                // Low bytes second
                self.ports.sector_count.write(count);
                self.ports.lba_low.write(lba as u8);
                self.ports.lba_mid.write((lba >> 8) as u8);
                self.ports.lba_high.write((lba >> 16) as u8);
                self.ports.status_command.write(ATA_CMD_READ_SECTORS_EXT);
            }
        }

        // Transfer sector data
        let mut buf_offset = 0;
        for _ in 0..count {
            self.ports.wait_data_ready()?;

            let words = ATA_SECTOR_SIZE / 2; // 256 words
            for _ in 0..words {
                let word = unsafe { self.ports.data.read() };
                buf[buf_offset] = (word & 0xFF) as u8;
                buf[buf_offset + 1] = (word >> 8) as u8;
                buf_offset += 2;
            }
            self.ports.delay_400ns();
        }

        Ok(())
    }

    /// Writes contiguous 512-byte sectors from the provided buffer using PIO mode.
    ///
    /// # Arguments
    /// - `lba`: Starting Logical Block Address.
    /// - `count`: Number of 512-byte sectors to write (1 to 255).
    /// - `buf`: Source byte slice containing at least `count * 512` bytes.
    ///
    /// # Errors
    /// Returns `Err` if the target LBA exceeds disk boundaries or a write timeout occurs.
    pub fn write_sectors(&mut self, lba: u64, count: u8, buf: &[u8]) -> Result<(), &'static str> {
        // Rewriting the same sectors is safe: reset after a failure and retry once
        self.write_sectors_once(lba, count, buf).or_else(|_| {
            self.ports.soft_reset();
            self.write_sectors_once(lba, count, buf)
        })
    }

    fn write_sectors_once(&mut self, lba: u64, count: u8, buf: &[u8]) -> Result<(), &'static str> {
        let required_len = (count as usize).saturating_mul(ATA_SECTOR_SIZE);
        if buf.len() < required_len {
            return Err("Source buffer too small for requested sector count");
        }
        if lba.saturating_add(count as u64) > self.total_sectors {
            return Err("LBA address out of disk bounds");
        }
        if count == 0 {
            return Ok(());
        }
        if let Some(r) = self.dma_or(lba, count, buf.as_ptr() as *mut u8, true) {
            return r;
        }

        self.ports.wait_not_busy()?;

        if lba < 0x1000_0000 && !self.lba48_supported {
            // LBA28 Addressing
            unsafe {
                self.ports.drive_head.write(0xE0 | (((lba >> 24) & 0x0F) as u8));
            }
            self.ports.delay_400ns();
            unsafe {
                self.ports.error_features.write(0);
                self.ports.sector_count.write(count);
                self.ports.lba_low.write(lba as u8);
                self.ports.lba_mid.write((lba >> 8) as u8);
                self.ports.lba_high.write((lba >> 16) as u8);
                self.ports.status_command.write(ATA_CMD_WRITE_SECTORS);
            }
        } else {
            // LBA48 Addressing
            unsafe {
                self.ports.drive_head.write(0x40);
            }
            self.ports.delay_400ns();
            unsafe {
                // High bytes
                self.ports.sector_count.write(0);
                self.ports.lba_low.write((lba >> 24) as u8);
                self.ports.lba_mid.write((lba >> 32) as u8);
                self.ports.lba_high.write((lba >> 40) as u8);
                // Low bytes
                self.ports.sector_count.write(count);
                self.ports.lba_low.write(lba as u8);
                self.ports.lba_mid.write((lba >> 8) as u8);
                self.ports.lba_high.write((lba >> 16) as u8);
                self.ports.status_command.write(ATA_CMD_WRITE_SECTORS_EXT);
            }
        }

        // Write sector payload
        let mut buf_offset = 0;
        for _ in 0..count {
            self.ports.wait_data_ready()?;

            let words = ATA_SECTOR_SIZE / 2;
            for _ in 0..words {
                let low = buf[buf_offset] as u16;
                let high = (buf[buf_offset + 1] as u16) << 8;
                let word = low | high;
                unsafe {
                    self.ports.data.write(word);
                }
                buf_offset += 2;
            }
            self.ports.delay_400ns();
        }

        // Sector write complete; wait for drive to finish internal transfer
        self.ports.delay_400ns();
        self.ports.wait_not_busy()?;
        Ok(())
    }

    /// Flushes the drive's volatile write cache to persistent magnetic or flash media.
    pub fn flush(&mut self) -> Result<(), &'static str> {
        self.flush_once().or_else(|_| {
            self.ports.soft_reset();
            self.flush_once()
        })
    }

    fn flush_once(&mut self) -> Result<(), &'static str> {
        self.ports.wait_not_busy()?;
        let cmd = if self.lba48_supported {
            ATA_CMD_CACHE_FLUSH_EXT
        } else {
            ATA_CMD_CACHE_FLUSH
        };
        unsafe {
            self.ports.status_command.write(cmd);
        }
        self.ports.delay_400ns();
        self.ports.wait_not_busy()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bus-master DMA (PCI IDE controller, e.g. PIIX)
// ---------------------------------------------------------------------------

/// ATA 28-bit Read DMA command (`0xC8`).
const ATA_CMD_READ_DMA: u8 = 0xC8;
/// ATA 48-bit Read DMA Ext command (`0x25`).
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// ATA 28-bit Write DMA command (`0xCA`).
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
/// ATA 48-bit Write DMA Ext command (`0x35`).
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

// Bus-master register offsets and bits (primary channel)
/// Primary channel Bus-Master Command register offset (`0x00`).
const BM_COMMAND: u16 = 0;
/// Primary channel Bus-Master Status register offset (`0x02`).
const BM_STATUS: u16 = 2;
/// Primary channel Bus-Master Physical Region Descriptor Table (PRDT) address register offset (`0x04`).
const BM_PRDT: u16 = 4;
/// Bus-Master Command bit 0: Start/Stop DMA engine (`1` = Start, `0` = Stop).
const BM_CMD_START: u8 = 0x01;
/// Bus-Master Command bit 3: Transfer direction (`1` = Device to Memory / disk read, `0` = Memory to Device / disk write).
const BM_CMD_TO_MEMORY: u8 = 0x08; // device -> memory (a disk read)
/// Bus-Master Status bit 0: Bus-Master DMA active flag.
const BM_STATUS_ACTIVE: u8 = 0x01;
/// Bus-Master Status bit 1: DMA transfer error flag (write-1-to-clear).
const BM_STATUS_ERROR: u8 = 0x02;
/// Bus-Master Status bit 2: IDE interrupt asserted flag (write-1-to-clear).
const BM_STATUS_IRQ: u8 = 0x04;

/// Pages in the DMA bounce buffer: one transfer of up to 255 sectors fits.
const DMA_PAGES: usize = 32;

/// Bus-master DMA engine of the primary IDE channel.
///
/// Transfers go through a physically contiguous bounce buffer below 4 GiB (PRD entries
/// carry 32-bit addresses), described by one PRD entry per page so that no entry crosses
/// a 64 KiB boundary. One command moves a whole run of sectors: under virtualization this
/// replaces hundreds of thousands of emulated port accesses per megabyte with a single
/// transfer, and on hardware it frees the CPU during the transfer.
struct BusMaster {
    /// Base I/O port address of the primary channel Bus-Master registers (from PCI `BAR4`).
    base: u16,
    /// Physical (identity-mapped) address of the PRD table page.
    prdt: u64,
    /// Physical (identity-mapped) address of the bounce buffer.
    buf: u64,
}

impl BusMaster {
    /// Finds the IDE controller's bus-master registers and allocates the DMA memory.
    fn probe() -> Option<Self> {
        let dev = crate::arch::pci::find_class(0x01, 0x01)?;
        // Programming interface bit 7: the controller supports bus mastering
        let prog_if = crate::arch::pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09);
        if prog_if & 0x80 == 0 {
            return None;
        }
        let bar4 = crate::arch::pci::pci_read_u32(dev.bus, dev.device, dev.function, 0x20);
        if bar4 & 1 == 0 || bar4 & !3 == 0 {
            return None; // not an I/O BAR
        }
        crate::arch::pci::enable_bus_mastering(&dev);
        let frames = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock().allocate_contiguous_frames(DMA_PAGES + 1)?;
        let base_phys = frames.start_address().as_u64();
        if base_phys + ((DMA_PAGES as u64 + 1) * 4096) > 0x1_0000_0000 {
            return None; // PRDs address only the first 4 GiB
        }
        crate::console::serial_write("[ata] bus-master DMA enabled\n");
        Some(Self { base: (bar4 & 0xFFFC) as u16, prdt: base_phys, buf: base_phys + 4096 })
    }

    /// Writes an 8-bit value to the specified Bus-Master register offset.
    fn outb(&self, reg: u16, v: u8) {
        unsafe { Port::<u8>::new(self.base + reg).write(v) };
    }

    /// Reads an 8-bit value from the specified Bus-Master register offset.
    fn inb(&self, reg: u16) -> u8 {
        unsafe { Port::<u8>::new(self.base + reg).read() }
    }

    /// Describes `bytes` of the bounce buffer in the PRD table.
    fn build_prdt(&self, bytes: usize) {
        let table = self.prdt as *mut u32;
        let pages = (bytes + 4095) / 4096;
        for i in 0..pages {
            let len = (bytes - i * 4096).min(4096) as u32;
            let last = if i + 1 == pages { 0x8000_0000u32 } else { 0 };
            unsafe {
                core::ptr::write_volatile(table.add(i * 2), (self.buf + (i * 4096) as u64) as u32);
                core::ptr::write_volatile(table.add(i * 2 + 1), len | last);
            }
        }
    }
}

impl AtaDevice {
    /// Moves `count` sectors at `lba` by DMA (`write`: from `data` to the disk).
    fn dma_transfer(&mut self, lba: u64, count: u8, data: *mut u8, write: bool) -> Result<(), &'static str> {
        let bm = match self.dma.as_ref() {
            Some(b) => b,
            None => return Err("no DMA"),
        };
        let bytes = count as usize * ATA_SECTOR_SIZE;
        if write {
            unsafe { core::ptr::copy_nonoverlapping(data as *const u8, bm.buf as *mut u8, bytes) };
        }
        bm.build_prdt(bytes);
        bm.outb(BM_COMMAND, 0);
        bm.outb(BM_STATUS, BM_STATUS_ERROR | BM_STATUS_IRQ); // write-1-to-clear
        unsafe { Port::<u32>::new(bm.base + BM_PRDT).write(bm.prdt as u32) };
        let direction = if write { 0 } else { BM_CMD_TO_MEMORY };
        bm.outb(BM_COMMAND, direction);

        self.ports.wait_not_busy()?;
        let lba48 = !(lba < 0x1000_0000 && !self.lba48_supported);
        unsafe {
            if !lba48 {
                self.ports.drive_head.write(0xE0 | (((lba >> 24) & 0x0F) as u8));
            } else {
                self.ports.drive_head.write(0x40);
            }
        }
        self.ports.delay_400ns();
        unsafe {
            if lba48 {
                self.ports.sector_count.write(0);
                self.ports.lba_low.write((lba >> 24) as u8);
                self.ports.lba_mid.write((lba >> 32) as u8);
                self.ports.lba_high.write((lba >> 40) as u8);
            } else {
                self.ports.error_features.write(0);
            }
            self.ports.sector_count.write(count);
            self.ports.lba_low.write(lba as u8);
            self.ports.lba_mid.write((lba >> 8) as u8);
            self.ports.lba_high.write((lba >> 16) as u8);
            let cmd = match (write, lba48) {
                (false, false) => ATA_CMD_READ_DMA,
                (false, true) => ATA_CMD_READ_DMA_EXT,
                (true, false) => ATA_CMD_WRITE_DMA,
                (true, true) => ATA_CMD_WRITE_DMA_EXT,
            };
            self.ports.status_command.write(cmd);
        }
        bm.outb(BM_COMMAND, direction | BM_CMD_START);

        // Completion: the engine stops (or reports an error) and the drive is no longer busy
        let mut wait = PollDeadline::new();
        let result = loop {
            let st = bm.inb(BM_STATUS);
            if st & BM_STATUS_ERROR != 0 {
                break Err("ATA DMA transfer error");
            }
            if st & BM_STATUS_ACTIVE == 0 || st & BM_STATUS_IRQ != 0 {
                break Ok(());
            }
            if wait.expired() {
                break Err("ATA DMA transfer timed out");
            }
            core::hint::spin_loop();
        };
        bm.outb(BM_COMMAND, 0);
        let status = self.ports.wait_not_busy()?;
        bm.outb(BM_STATUS, BM_STATUS_ERROR | BM_STATUS_IRQ);
        result?;
        if status & (ATA_STATUS_ERR | ATA_STATUS_DF) != 0 {
            return Err("ATA device reported an error after DMA");
        }
        if !write {
            unsafe { core::ptr::copy_nonoverlapping(bm.buf as *const u8, data, bytes) };
        }
        Ok(())
    }

    /// Uses DMA when the controller supports it; on a DMA failure the drive is reset and
    /// the transfer is repeated with port I/O (and DMA is turned off after repeated
    /// failures).
    fn dma_or(&mut self, lba: u64, count: u8, data: *mut u8, write: bool) -> Option<Result<(), &'static str>> {
        if self.dma.is_none() || count == 0 {
            return None;
        }
        match self.dma_transfer(lba, count, data, write) {
            Ok(()) => Some(Ok(())),
            Err(e) => {
                self.ports.soft_reset();
                self.dma_failures += 1;
                if self.dma_failures >= 3 {
                    crate::console::serial_write("[ata] DMA failing repeatedly; using port I/O\n");
                    self.dma = None;
                }
                let _ = e;
                None
            }
        }
    }
}

/// Whether disk transfers use bus-master DMA.
pub fn dma_enabled() -> bool {
    PRIMARY_ATA.lock().as_ref().map_or(false, |d| d.dma.is_some())
}

/// Initializes the primary ATA hard disk drive subsystem.
/// Probes for Primary Master drive, disables hardware IRQs, and registers the singleton.
pub fn init() {
    let mut primary = PRIMARY_ATA.lock();
    if primary.is_some() {
        return;
    }

    if let Some(dev) = AtaDevice::probe_primary_master() {
        let cap_mb = dev.capacity_bytes() / (1024 * 1024);
        crate::console::set_color(
            uefi::proto::console::text::Color::LightGreen,
            uefi::proto::console::text::Color::Black,
        );
        crate::println!(
            "[+] ATA Storage: Detected Primary Master '{}' ({} MiB, {} sectors, LBA{})",
            dev.model_str(),
            cap_mb,
            dev.total_sectors(),
            if dev.is_lba48() { 48 } else { 28 }
        );
        *primary = Some(dev);
    } else {
        crate::console::set_color(
            uefi::proto::console::text::Color::Yellow,
            uefi::proto::console::text::Color::Black,
        );
        crate::println!("[*] ATA Storage: No physical IDE hard disk detected on Primary Master (falling back to RAM pool).");
    }
}

/// Returns true if an ATA physical/virtual hard disk is detected and active.
pub fn is_drive_present() -> bool {
    PRIMARY_ATA.lock().is_some()
}

/// Returns drive capacity in bytes, total sectors, and whether LBA48 is supported.
///
/// # Returns
/// `Some((capacity_bytes, total_sectors, is_lba48))` if an ATA hard drive is present, or `None`.
pub fn drive_info() -> Option<(u64, u64, bool)> {
    let guard = PRIMARY_ATA.lock();
    guard.as_ref().map(|d| (d.capacity_bytes(), d.total_sectors(), d.is_lba48()))
}

/// Copies the drive model string into the provided destination buffer and returns the string slice.
///
/// # Arguments
/// - `buf`: Destination byte slice to hold the ASCII model name.
///
/// # Returns
/// `Some(&str)` containing the drive model, or `None` if no drive is present.
pub fn get_drive_model<'a>(buf: &'a mut [u8]) -> Option<&'a str> {
    let guard = PRIMARY_ATA.lock();
    guard.as_ref().and_then(|d| {
        let s = d.model_str().as_bytes();
        let len = s.len().min(buf.len());
        buf[..len].copy_from_slice(&s[..len]);
        core::str::from_utf8(&buf[..len]).ok()
    })
}

