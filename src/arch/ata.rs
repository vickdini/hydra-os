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
//! ## Hardware & Interface Context
//!
//! - Hardware Controller: Standard Intel PIIX3/PIIX4 IDE Controller or compatible SATA in IDE mode.
//! - I/O Ports: 16-bit data port (`0x1F0`), 8-bit registers (`0x1F1..0x1F7`), and device control (`0x3F6`).
//! - Addressing Modes: Logical Block Addressing (LBA28 up to 128 GiB, LBA48 up to 128 PiB).
//! - Sector Size: Fixed 512 bytes per physical sector.
//!
//! ## System Call & Privilege Context
//!
//! - Privilege Level: Executes exclusively in Ring 0 (Microkernel core).
//! - Filesystem Integration: Directly backs [`crate::fs::zfs::spa::VdevStorage`] in the OpenZFS SPA.

use spin::Mutex;
use x86_64::instructions::port::Port;

/// Standard sector size in bytes for ATA/IDE hard drives.
pub const ATA_SECTOR_SIZE: usize = 512;

/// Standard ATA I/O port base addresses.
pub const ATA_PRIMARY_IO_BASE: u16 = 0x1F0;
pub const ATA_PRIMARY_CTRL_BASE: u16 = 0x3F6;
pub const ATA_SECONDARY_IO_BASE: u16 = 0x170;
pub const ATA_SECONDARY_CTRL_BASE: u16 = 0x376;

// ATA Commands
pub const ATA_CMD_READ_SECTORS: u8 = 0x20;
pub const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
pub const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
pub const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;
pub const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
pub const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;

// ATA Status Register Bits
pub const ATA_STATUS_ERR: u8 = 0x01;  // Error
pub const ATA_STATUS_DRQ: u8 = 0x08;  // Data Request Ready
pub const ATA_STATUS_SRV: u8 = 0x10;  // Overlapped Mode Service Request
pub const ATA_STATUS_DF: u8 = 0x20;   // Drive Fault / Device Fault
pub const ATA_STATUS_DRDY: u8 = 0x40; // Device Ready
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
    data: Port<u16>,
    error_features: Port<u8>,
    sector_count: Port<u8>,
    lba_low: Port<u8>,
    lba_mid: Port<u8>,
    lba_high: Port<u8>,
    drive_head: Port<u8>,
    status_command: Port<u8>,
    control_alt_status: Port<u8>,
}

impl AtaPorts {
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

    /// Polls until the BSY bit is cleared or a timeout occurs.
    fn wait_not_busy(&mut self) -> Result<u8, &'static str> {
        for _ in 0..ATA_POLL_TIMEOUT {
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
        for _ in 0..ATA_POLL_TIMEOUT {
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

/// Represents an active physical or virtual ATA/IDE hard disk drive.
pub struct AtaDevice {
    ports: AtaPorts,
    _role: DriveRole,
    model: [u8; 40],
    total_sectors: u64,
    lba48_supported: bool,
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

        // Flush write cache immediately for ACID durability
        self.flush()
    }

    /// Flushes the drive's volatile write cache to persistent magnetic or flash media.
    pub fn flush(&mut self) -> Result<(), &'static str> {
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

