//! # Network Subsystem: Intel 82540EM (E1000) Gigabit Ethernet Controller Driver
//!
//! Provides bare-metal DMA programmed I/O and interrupt-safe packet transport for the Intel E1000 NIC.
//!
//! ## Architectural Role & Design Rationale
//!
//! Connecting Hydra OS to local networks and the Internet requires a high-performance network interface card.
//! The **Intel 82540EM (E1000)** is the de facto standard Gigabit Ethernet controller virtualized across
//! VirtualBox, QEMU, KVM, and VMware, as well as being deployed on vast numbers of physical x86 motherboards.
//!
//! The driver utilizes circular direct memory access (DMA) descriptor rings for transmission and reception:
//! - **Transmit Ring (TX)**: 32 descriptors of 16 bytes each. Packets are written into identity-mapped host
//!   memory buffers and transmitted autonomously by the hardware DMA engine upon updating the Tail pointer.
//! - **Receive Ring (RX)**: 32 descriptors of 16 bytes each. Incoming Ethernet frames are written by the NIC
//!   directly into pre-allocated 2048-byte host buffers with hardware CRC validation.
//!
//! ## Hardware Registers (MMIO via BAR0)
//!
//! - `0x0000` (`CTRL`): Device Control (Reset, Set Link Up)
//! - `0x0008` (`STATUS`): Device Status (Link Up, Speed, Duplex)
//! - `0x00D8` (`IMC`): Interrupt Mask Clear (Writing `0xFFFFFFFF` masks all hardware interrupts)
//! - `0x0100` (`RCTL`): Receive Control (Broadcast enable, Multicast enable, Buffer size)
//! - `0x0400` (`TCTL`): Transmit Control (Enable, Pad Short Packets, Collision settings)
//! - `0x2800` (`RDBAL`) / `0x2818` (`RDT`): Receive Descriptor Base and Tail pointers
//! - `0x3800` (`TDBAL`) / `0x3818` (`TDT`): Transmit Descriptor Base and Tail pointers
//! - `0x5400` (`RAL0`) / `0x5404` (`RAH0`): Receive Address Low/High (Hardware MAC Address)

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;
use crate::arch::pci::{self, PciDevice};

pub const E1000_VENDOR_ID: u16 = 0x8086; // Intel
pub const E1000_DEVICE_ID: u16 = 0x100E; // 82540EM (VirtualBox / QEMU)

// E1000 Register Offsets
const REG_CTRL: usize = 0x0000;
const REG_STATUS: usize = 0x0008;
const REG_IMC: usize = 0x00D8;
const REG_RCTL: usize = 0x0100;
const REG_TCTL: usize = 0x0400;
const REG_TIPG: usize = 0x0410;
const REG_RDBAL: usize = 0x2800;
const REG_RDBAH: usize = 0x2804;
const REG_RDLEN: usize = 0x2808;
const REG_RDH: usize = 0x2810;
const REG_RDT: usize = 0x2818;
const REG_TDBAL: usize = 0x3800;
const REG_TDBAH: usize = 0x3804;
const REG_TDLEN: usize = 0x3808;
const REG_TDH: usize = 0x3810;
const REG_TDT: usize = 0x3818;
const REG_RAL0: usize = 0x5400;
const REG_RAH0: usize = 0x5404;

// Control Register Bits
const CTRL_SLU: u32 = 1 << 6;  // Set Link Up
const CTRL_RST: u32 = 1 << 26; // Device Reset

// Status Register Bits
const STATUS_LU: u32 = 1 << 1; // Link Up indication

// Receive Control Bits
const RCTL_EN: u32 = 1 << 1;      // Receiver Enable
const RCTL_SBP: u32 = 1 << 2;     // Store Bad Packets
const RCTL_UPE: u32 = 1 << 3;     // Unicast Promiscuous
const RCTL_MPE: u32 = 1 << 4;     // Multicast Promiscuous
const RCTL_BAM: u32 = 1 << 15;    // Broadcast Accept Mode
const RCTL_BSIZE_2048: u32 = 0;   // Buffer Size 2048 Bytes
const RCTL_SECRC: u32 = 1 << 26;  // Strip Ethernet CRC

// Transmit Control Bits
const TCTL_EN: u32 = 1 << 1;       // Transmitter Enable
const TCTL_PSP: u32 = 1 << 3;      // Pad Short Packets
const TCTL_CT_SHIFT: u32 = 4;      // Collision Threshold
const TCTL_COLD_SHIFT: u32 = 12;   // Collision Distance

// Descriptors Configuration
const NUM_TX_DESC: usize = 32;
const NUM_RX_DESC: usize = 32;
const BUFFER_SIZE: usize = 2048;

/// Hardware 16-byte Transmit Descriptor consumed by the E1000 DMA engine.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct E1000TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

/// Hardware 16-byte Receive Descriptor produced by the E1000 DMA engine.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct E1000RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

/// Active Intel E1000 Gigabit Ethernet network adapter instance.
pub struct E1000Device {
    mmio_base: u64,
    mac_address: [u8; 6],
    tx_descriptors: Box<[E1000TxDesc]>,
    rx_descriptors: Box<[E1000RxDesc]>,
    tx_buffers: Vec<Box<[u8; BUFFER_SIZE]>>,
    rx_buffers: Vec<Box<[u8; BUFFER_SIZE]>>,
    tx_cur: usize,
    rx_cur: usize,
    packets_rx: u64,
    packets_tx: u64,
    bytes_rx: u64,
    bytes_tx: u64,
}

impl E1000Device {
    /// Reads a 32-bit register from the controller's MMIO address space.
    #[inline(always)]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe {
            let ptr = (self.mmio_base + offset as u64) as *const u32;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Writes a 32-bit register into the controller's MMIO address space.
    #[inline(always)]
    fn write_reg(&self, offset: usize, value: u32) {
        unsafe {
            let ptr = (self.mmio_base + offset as u64) as *mut u32;
            core::ptr::write_volatile(ptr, value);
        }
    }

    /// Returns the hardware 48-bit MAC address.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Returns true if the physical Ethernet link is active (carrier detected).
    pub fn is_link_up(&self) -> bool {
        (self.read_reg(REG_STATUS) & STATUS_LU) != 0
    }

    /// Returns cumulative telemetry metrics: `(packets_rx, packets_tx, bytes_rx, bytes_tx)`.
    pub fn metrics(&self) -> (u64, u64, u64, u64) {
        (self.packets_rx, self.packets_tx, self.bytes_rx, self.bytes_tx)
    }

    /// Transmits an Ethernet frame over the physical link via DMA.
    ///
    /// # Arguments
    /// - `packet`: Raw Ethernet frame slice (including header and payload).
    ///
    /// # Errors
    /// Returns `Err` if the packet exceeds the hardware MTU (`BUFFER_SIZE`) or timeout occurs.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() > BUFFER_SIZE {
            return Err("Packet exceeds max transmission buffer size (2048 bytes)");
        }

        let cur = self.tx_cur;
        let buf_addr = {
            let buf = &mut self.tx_buffers[cur];
            buf[..packet.len()].copy_from_slice(packet);
            buf.as_ptr() as u64
        };

        {
            let desc = &mut self.tx_descriptors[cur];
            desc.addr = buf_addr;
            desc.length = packet.len() as u16;
            // CMD: EOP (bit 0) | IFCS (bit 1) | RS (bit 3) = 0x0B
            desc.cmd = (1 << 0) | (1 << 1) | (1 << 3);
            desc.status = 0;
        }

        self.tx_cur = (cur + 1) % NUM_TX_DESC;
        self.write_reg(REG_TDT, self.tx_cur as u32);

        // Wait until the hardware marks the descriptor as transmitted (STATUS_DD)
        for _ in 0..100_000 {
            if self.tx_descriptors[cur].status & 0x01 != 0 {
                self.packets_tx += 1;
                self.bytes_tx += packet.len() as u64;
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err("E1000 transmit descriptor timed out waiting for DD bit")
    }

    /// Receives a pending Ethernet frame from the RX DMA ring, if available.
    ///
    /// # Arguments
    /// - `out_buf`: Destination byte slice. Must be at least 1518 bytes long.
    ///
    /// # Returns
    /// `Some(bytes_read)` if a complete frame was received, or `None` if the RX ring is empty.
    pub fn receive_packet(&mut self, out_buf: &mut [u8]) -> Option<usize> {
        let cur = self.rx_cur;
        let desc = &mut self.rx_descriptors[cur];

        // Check if Descriptor Done (DD bit 0) is asserted
        if desc.status & 0x01 == 0 {
            return None;
        }

        let len = (desc.length as usize).min(out_buf.len());
        let buf = &self.rx_buffers[cur];
        out_buf[..len].copy_from_slice(&buf[..len]);

        desc.status = 0;
        self.write_reg(REG_RDT, cur as u32);
        self.rx_cur = (cur + 1) % NUM_RX_DESC;

        self.packets_rx += 1;
        self.bytes_rx += len as u64;

        Some(len)
    }
}

/// Global singleton handle to the initialized Intel E1000 network device.
pub static E1000_NIC: Mutex<Option<E1000Device>> = Mutex::new(None);

/// Initializes the Intel 82540EM E1000 Gigabit Ethernet network adapter.
pub fn init() -> Result<(), &'static str> {
    let mut nic_lock = E1000_NIC.lock();
    if nic_lock.is_some() {
        return Ok(());
    }

    // 1. Locate device on PCI bus
    let dev: PciDevice = pci::find_device(E1000_VENDOR_ID, E1000_DEVICE_ID)
        .ok_or("Intel E1000 (82540EM) NIC not found on PCI bus")?;

    // 2. Enable Bus Master & Memory Space in PCI command register
    pci::enable_bus_mastering(&dev);

    let mmio_base = dev.bar0_address();
    if mmio_base == 0 {
        return Err("Intel E1000 BAR0 is invalid (0x0)");
    }

    // 3. Allocate TX and RX descriptors and memory buffers
    let mut tx_descriptors = vec![E1000TxDesc::default(); NUM_TX_DESC].into_boxed_slice();
    let mut rx_descriptors = vec![E1000RxDesc::default(); NUM_RX_DESC].into_boxed_slice();

    let mut tx_buffers = Vec::with_capacity(NUM_TX_DESC);
    for desc in tx_descriptors.iter_mut() {
        let buf = Box::new([0u8; BUFFER_SIZE]);
        desc.addr = buf.as_ptr() as u64;
        desc.status = 1; // Mark initially available
        tx_buffers.push(buf);
    }

    let mut rx_buffers = Vec::with_capacity(NUM_RX_DESC);
    for desc in rx_descriptors.iter_mut() {
        let buf = Box::new([0u8; BUFFER_SIZE]);
        desc.addr = buf.as_ptr() as u64;
        desc.status = 0;
        rx_buffers.push(buf);
    }

    let mut device = E1000Device {
        mmio_base,
        mac_address: [0; 6],
        tx_descriptors,
        rx_descriptors,
        tx_buffers,
        rx_buffers,
        tx_cur: 0,
        rx_cur: 0,
        packets_rx: 0,
        packets_tx: 0,
        bytes_rx: 0,
        bytes_tx: 0,
    };

    // 4. Disable interrupts (operating in polled microkernel mode)
    device.write_reg(REG_IMC, 0xFFFF_FFFF);

    // 5. Software Reset
    device.write_reg(REG_CTRL, device.read_reg(REG_CTRL) | CTRL_RST);
    for _ in 0..10_000 {
        core::hint::spin_loop();
    }
    // Re-disable interrupts after reset
    device.write_reg(REG_IMC, 0xFFFF_FFFF);

    // 6. Read Hardware MAC Address from RAL0 and RAH0
    let ral = device.read_reg(REG_RAL0);
    let rah = device.read_reg(REG_RAH0);
    device.mac_address[0] = (ral & 0xFF) as u8;
    device.mac_address[1] = ((ral >> 8) & 0xFF) as u8;
    device.mac_address[2] = ((ral >> 16) & 0xFF) as u8;
    device.mac_address[3] = ((ral >> 24) & 0xFF) as u8;
    device.mac_address[4] = (rah & 0xFF) as u8;
    device.mac_address[5] = ((rah >> 8) & 0xFF) as u8;

    // 7. Setup Transmit (TX) Ring
    let tx_base_addr = device.tx_descriptors.as_ptr() as u64;
    device.write_reg(REG_TDBAL, (tx_base_addr & 0xFFFF_FFFF) as u32);
    device.write_reg(REG_TDBAH, (tx_base_addr >> 32) as u32);
    device.write_reg(REG_TDLEN, (NUM_TX_DESC * core::mem::size_of::<E1000TxDesc>()) as u32);
    device.write_reg(REG_TDH, 0);
    device.write_reg(REG_TDT, 0);

    // Configure Transmit Control: Enable, Pad Short Packets, Standard Collisions
    let tctl_val = TCTL_EN
        | TCTL_PSP
        | (15 << TCTL_CT_SHIFT)
        | (0x40 << TCTL_COLD_SHIFT);
    device.write_reg(REG_TCTL, tctl_val);
    device.write_reg(REG_TIPG, 0x0060_200A); // Standard IEEE 802.3 IPG spacing

    // 8. Setup Receive (RX) Ring
    let rx_base_addr = device.rx_descriptors.as_ptr() as u64;
    device.write_reg(REG_RDBAL, (rx_base_addr & 0xFFFF_FFFF) as u32);
    device.write_reg(REG_RDBAH, (rx_base_addr >> 32) as u32);
    device.write_reg(REG_RDLEN, (NUM_RX_DESC * core::mem::size_of::<E1000RxDesc>()) as u32);
    device.write_reg(REG_RDH, 0);
    device.write_reg(REG_RDT, (NUM_RX_DESC - 1) as u32);

    // Configure Receive Control: Enable, Broadcast accept, Multicast/Unicast promiscuous, Strip CRC
    let rctl_val = RCTL_EN
        | RCTL_SBP
        | RCTL_UPE
        | RCTL_MPE
        | RCTL_BAM
        | RCTL_BSIZE_2048
        | RCTL_SECRC;
    device.write_reg(REG_RCTL, rctl_val);

    // 9. Set Link Up (SLU bit 6)
    device.write_reg(REG_CTRL, device.read_reg(REG_CTRL) | CTRL_SLU);

    // Allow virtual PHY autonegotiation to establish carrier link
    for _ in 0..500 {
        if (device.read_reg(REG_STATUS) & STATUS_LU) != 0 {
            break;
        }
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }

    *nic_lock = Some(device);
    Ok(())
}

/// Returns true if the Intel E1000 device is initialized and active.
pub fn is_present() -> bool {
    E1000_NIC.lock().is_some()
}

/// Transmits a raw Ethernet frame through the global E1000 singleton.
pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    let mut guard = E1000_NIC.lock();
    let nic = guard.as_mut().ok_or("E1000 NIC not initialized")?;
    nic.send_packet(frame)
}

/// Reads a pending raw Ethernet frame from the global E1000 singleton.
pub fn receive_frame(out_buf: &mut [u8]) -> Option<usize> {
    let mut guard = E1000_NIC.lock();
    let nic = guard.as_mut()?;
    nic.receive_packet(out_buf)
}

/// Returns the MAC address of the active E1000 adapter, or all zeros if not present.
pub fn mac_address() -> [u8; 6] {
    let guard = E1000_NIC.lock();
    guard.as_ref().map(|d| d.mac_address()).unwrap_or([0; 6])
}

/// Returns true if carrier link is detected on the active E1000 adapter.
pub fn is_link_up() -> bool {
    let guard = E1000_NIC.lock();
    guard.as_ref().map(|d| d.is_link_up()).unwrap_or(false)
}
