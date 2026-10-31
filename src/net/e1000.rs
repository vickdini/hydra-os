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
//! - **Receive Ring (RX)**: 256 descriptors of 16 bytes each. Incoming Ethernet frames are written by the NIC
//!   directly into pre-allocated 2048-byte host buffers with hardware CRC validation. The ring holds 512 KiB,
//!   several full TCP receive windows.
//!
//! Receive is interrupt-driven once the scheduler runs ([`enable_interrupts`]): the handler acknowledges the
//! interrupt and wakes the network task (`netd`), which drains the ring. Early boot code (DHCP) polls.
//!
//! ## Key Types & Interfaces
//!
//! - [`E1000Device`]: Represents the initialized Intel 82540EM NIC, owning the TX/RX DMA descriptor rings and packet buffers.
//! - [`E1000_NIC`]: Global spinlock-protected singleton holding the active [`E1000Device`].
//! - `init`: Discovers the PCI adapter, enables bus mastering, allocates DMA rings, and brings the link up.
//! - [`enable_interrupts()`] / [`on_interrupt()`]: Configures and acknowledges hardware receive interrupts.
//! - [`send_frame()`] / [`receive_frame()`]: Global convenience functions for transmitting and polling Ethernet frames.
//!
//! ## Hardware & Dependency Context
//!
//! - **PCI ID**: Vendor `0x8086` (Intel), Device `0x100E` (82540EM).
//! - **MMIO Registers (via BAR0)**:
//!   - `0x0000` (`CTRL`): Device Control (Reset, Set Link Up)
//!   - `0x0008` (`STATUS`): Device Status (Link Up, Speed, Duplex)
//!   - `0x00C0` (`ICR`) / `0x00D0` (`IMS`) / `0x00D8` (`IMC`): Interrupt Cause Read, Mask Set, and Mask Clear
//!   - `0x0100` (`RCTL`): Receive Control (Broadcast enable, Multicast enable, Buffer size)
//!   - `0x0400` (`TCTL`): Transmit Control (Enable, Pad Short Packets, Collision settings)
//!   - `0x2800` (`RDBAL`) / `0x2818` (`RDT`): Receive Descriptor Base and Tail pointers
//!   - `0x3800` (`TDBAL`) / `0x3818` (`TDT`): Transmit Descriptor Base and Tail pointers
//!   - `0x5400` (`RAL0`) / `0x5404` (`RAH0`): Receive Address Low/High (Hardware MAC Address)

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use spin::Mutex;
use crate::arch::pci::{self, PciDevice};

/// PCI Vendor ID for Intel Corporation (`0x8086`).
pub const E1000_VENDOR_ID: u16 = 0x8086; // Intel
/// PCI Device ID for the Intel 82540EM Gigabit Ethernet Controller (`0x100E`).
pub const E1000_DEVICE_ID: u16 = 0x100E; // 82540EM (VirtualBox / QEMU)

// E1000 Register Offsets
/// Device Control Register offset (`0x0000`).
const REG_CTRL: usize = 0x0000;
/// Device Status Register offset (`0x0008`).
const REG_STATUS: usize = 0x0008;
/// Interrupt Cause Read Register offset (`0x00C0`).
const REG_ICR: usize = 0x00C0;
/// Interrupt Mask Set/Read Register offset (`0x00D0`).
const REG_IMS: usize = 0x00D0;
/// Interrupt Mask Clear Register offset (`0x00D8`).
const REG_IMC: usize = 0x00D8;
/// Receive Delay Timer Register offset (`0x2820`).
const REG_RDTR: usize = 0x2820;
/// Receive Control Register offset (`0x0100`).
const REG_RCTL: usize = 0x0100;
/// Transmit Control Register offset (`0x0400`).
const REG_TCTL: usize = 0x0400;
/// Transmit Inter-Packet Gap Register offset (`0x0410`).
const REG_TIPG: usize = 0x0410;
/// Receive Descriptor Base Address Low offset (`0x2800`).
const REG_RDBAL: usize = 0x2800;
/// Receive Descriptor Base Address High offset (`0x2804`).
const REG_RDBAH: usize = 0x2804;
/// Receive Descriptor Length offset (`0x2808`).
const REG_RDLEN: usize = 0x2808;
/// Receive Descriptor Head offset (`0x2810`).
const REG_RDH: usize = 0x2810;
/// Receive Descriptor Tail offset (`0x2818`).
const REG_RDT: usize = 0x2818;
/// Transmit Descriptor Base Address Low offset (`0x3800`).
const REG_TDBAL: usize = 0x3800;
/// Transmit Descriptor Base Address High offset (`0x3804`).
const REG_TDBAH: usize = 0x3804;
/// Transmit Descriptor Length offset (`0x3808`).
const REG_TDLEN: usize = 0x3808;
/// Transmit Descriptor Head offset (`0x3810`).
const REG_TDH: usize = 0x3810;
/// Transmit Descriptor Tail offset (`0x3818`).
const REG_TDT: usize = 0x3818;
/// Receive Address Low (MAC bytes 0..=3) offset (`0x5400`).
const REG_RAL0: usize = 0x5400;
/// Receive Address High (MAC bytes 4..=5) offset (`0x5404`).
const REG_RAH0: usize = 0x5404;

// Control Register Bits
/// Control Register: Set Link Up (`bit 6`).
const CTRL_SLU: u32 = 1 << 6;  // Set Link Up
/// Control Register: Device Reset (`bit 26`).
const CTRL_RST: u32 = 1 << 26; // Device Reset

// Status Register Bits
/// Status Register: Link Up indication (`bit 1`).
const STATUS_LU: u32 = 1 << 1; // Link Up indication

// Receive Control Bits
/// Receive Control: Receiver Enable (`bit 1`).
const RCTL_EN: u32 = 1 << 1;      // Receiver Enable
/// Receive Control: Store Bad Packets (`bit 2`).
const RCTL_SBP: u32 = 1 << 2;     // Store Bad Packets
/// Receive Control: Unicast Promiscuous Enable (`bit 3`).
const RCTL_UPE: u32 = 1 << 3;     // Unicast Promiscuous
/// Receive Control: Multicast Promiscuous Enable (`bit 4`).
const RCTL_MPE: u32 = 1 << 4;     // Multicast Promiscuous
/// Receive Control: Broadcast Accept Mode (`bit 15`).
const RCTL_BAM: u32 = 1 << 15;    // Broadcast Accept Mode
/// Receive Control: 2048-Byte Receive Buffer Size (`0`).
const RCTL_BSIZE_2048: u32 = 0;   // Buffer Size 2048 Bytes
/// Receive Control: Strip Ethernet CRC from incoming frames (`bit 26`).
const RCTL_SECRC: u32 = 1 << 26;  // Strip Ethernet CRC

// Transmit Control Bits
/// Transmit Control: Transmitter Enable (`bit 1`).
const TCTL_EN: u32 = 1 << 1;       // Transmitter Enable
/// Transmit Control: Pad Short Packets (`bit 3`).
const TCTL_PSP: u32 = 1 << 3;      // Pad Short Packets
/// Transmit Control: Collision Threshold bit shift (`4`).
const TCTL_CT_SHIFT: u32 = 4;      // Collision Threshold
/// Transmit Control: Collision Distance bit shift (`12`).
const TCTL_COLD_SHIFT: u32 = 12;   // Collision Distance

// Descriptors Configuration
/// Number of descriptors in the TX DMA circular ring (`32`).
const NUM_TX_DESC: usize = 32;
/// Number of descriptors in the RX DMA circular ring (`256`).
const NUM_RX_DESC: usize = 256;

// Interrupt causes (ICR/IMS bits)
/// Interrupt Cause: Link Status Change (`bit 2`).
const INT_LSC: u32 = 1 << 2; // Link status change
/// Interrupt Cause: Receive Descriptor Minimum Threshold hit (`bit 4`).
const INT_RXDMT0: u32 = 1 << 4; // Receive descriptors running low
/// Interrupt Cause: Receiver Overrun (`bit 6`).
const INT_RXO: u32 = 1 << 6; // Receiver overrun
/// Interrupt Cause: Receiver Timer Interrupt (`bit 7`).
const INT_RXT0: u32 = 1 << 7; // Receive timer (a frame arrived)

/// MMIO base of the active device, for the interrupt handler (which must not take
/// [`E1000_NIC`]: the interrupted code may hold it).
static MMIO_BASE: AtomicU64 = AtomicU64::new(0);
/// Legacy IRQ line of the device once interrupts are enabled (0xFF = polled).
static IRQ_LINE: AtomicU8 = AtomicU8::new(0xFF);
/// PCI interrupt line reported by the firmware.
static PCI_IRQ_LINE: AtomicU8 = AtomicU8::new(0xFF);
/// Size in bytes of each pre-allocated TX and RX DMA packet buffer (`2048`).
const BUFFER_SIZE: usize = 2048;

/// Hardware 16-byte Transmit Descriptor consumed by the E1000 DMA engine.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct E1000TxDesc {
    /// Physical address of the transmit packet buffer.
    addr: u64,
    /// Length of the frame in bytes.
    length: u16,
    /// Checksum Offset.
    cso: u8,
    /// Command byte (`EOP | IFCS | RS`).
    cmd: u8,
    /// Descriptor status byte (`DD` bit 0 set by hardware when transmission completes).
    status: u8,
    /// Checksum Start field.
    css: u8,
    /// Special VLAN tag field.
    special: u16,
}

/// Hardware 16-byte Receive Descriptor produced by the E1000 DMA engine.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct E1000RxDesc {
    /// Physical address of the receive packet buffer.
    addr: u64,
    /// Length of the received frame in bytes written by hardware.
    length: u16,
    /// Hardware-computed packet checksum.
    checksum: u16,
    /// Descriptor status byte (`DD` bit 0 and `EOP` bit 1).
    status: u8,
    /// Hardware reception error flags.
    errors: u8,
    /// Special VLAN tag field.
    special: u16,
}

/// Active Intel E1000 Gigabit Ethernet network adapter instance.
///
/// Owns the DMA descriptor rings and pre-allocated packet buffers in identity-mapped memory.
/// Synchronized via the global [`E1000_NIC`] spinlock.
pub struct E1000Device {
    /// Base virtual/physical address of the BAR0 MMIO register aperture.
    mmio_base: u64,
    /// Hardware 48-bit Ethernet MAC address read from `RAL0`/`RAH0`.
    mac_address: [u8; 6],
    /// Heap-allocated 16-byte aligned TX descriptor ring.
    tx_descriptors: Box<[E1000TxDesc]>,
    /// Heap-allocated 16-byte aligned RX descriptor ring.
    rx_descriptors: Box<[E1000RxDesc]>,
    /// Pre-allocated 2048-byte DMA buffers corresponding to each TX descriptor.
    tx_buffers: Vec<Box<[u8; BUFFER_SIZE]>>,
    /// Pre-allocated 2048-byte DMA buffers corresponding to each RX descriptor.
    rx_buffers: Vec<Box<[u8; BUFFER_SIZE]>>,
    /// Current software producer index into `tx_descriptors`.
    tx_cur: usize,
    /// Current software consumer index into `rx_descriptors`.
    rx_cur: usize,
    /// Cumulative count of received frames.
    packets_rx: u64,
    /// Cumulative count of transmitted frames.
    packets_tx: u64,
    /// Cumulative count of received bytes.
    bytes_rx: u64,
    /// Cumulative count of transmitted bytes.
    bytes_tx: u64,
}

impl E1000Device {
    /// Reads a 32-bit register from the controller's MMIO address space.
    ///
    /// # Arguments
    /// - `offset`: Byte offset of the register relative to `BAR0`.
    ///
    /// # Returns
    /// 32-bit value read via volatile MMIO access.
    #[inline(always)]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe {
            let ptr = (self.mmio_base + offset as u64) as *const u32;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Writes a 32-bit register into the controller's MMIO address space.
    ///
    /// # Arguments
    /// - `offset`: Byte offset of the register relative to `BAR0`.
    /// - `value`: 32-bit value to write via volatile MMIO access.
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

    /// Returns `true` if the physical Ethernet link is active (carrier detected).
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
///
/// Discovers the PCI device, enables bus mastering, allocates TX and RX DMA descriptor rings
/// and 2048-byte packet buffers, resets the controller, reads the factory MAC address, and
/// brings the physical link up.
///
/// # Returns
/// `Ok(())` when the E1000 adapter is initialized (or already active).
///
/// # Errors
/// Returns `Err` if no Intel 82540EM PCI device is present or `BAR0` is invalid.
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

    MMIO_BASE.store(device.mmio_base, Ordering::Release);
    PCI_IRQ_LINE.store(dev.irq_line, Ordering::Release);
    *nic_lock = Some(device);
    Ok(())
}

/// Switches receive to interrupts: unmasks the device's receive causes and its PIC line.
///
/// # Returns
/// `true` if legacy IRQ interrupts were enabled, or `false` (the stack keeps polling) if the firmware assigned no valid legacy IRQ.
pub fn enable_interrupts() -> bool {
    let base = MMIO_BASE.load(Ordering::Acquire);
    let irq = PCI_IRQ_LINE.load(Ordering::Acquire);
    if base == 0 || irq == 0 || irq >= 16 || irq == 2 {
        return false;
    }
    IRQ_LINE.store(irq, Ordering::Release);
    unsafe {
        // Interrupt for every frame (no receive delay timer), then unmask the causes
        core::ptr::write_volatile((base + REG_RDTR as u64) as *mut u32, 0);
        core::ptr::read_volatile((base + REG_ICR as u64) as *const u32);
        core::ptr::write_volatile((base + REG_IMS as u64) as *mut u32, INT_RXT0 | INT_RXO | INT_RXDMT0 | INT_LSC);
    }
    crate::arch::pic::unmask_irq(irq);
    if irq >= 8 {
        crate::arch::pic::unmask_irq(2);
    }
    true
}

/// Returns the device's legacy PIC IRQ line when interrupt-driven, or `None` if polling.
pub fn irq_line() -> Option<u8> {
    match IRQ_LINE.load(Ordering::Acquire) {
        0xFF => None,
        l => Some(l),
    }
}

/// Interrupt handler body: acknowledges the causes (reading `ICR` clears them and lowers the line).
///
/// # Returns
/// `true` if the interrupt was raised by the E1000 controller, or `false` otherwise.
pub fn on_interrupt() -> bool {
    let base = MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    let icr = unsafe { core::ptr::read_volatile((base + REG_ICR as u64) as *const u32) };
    icr != 0
}

/// Returns `true` if the Intel E1000 device is initialized and active.
pub fn is_present() -> bool {
    E1000_NIC.lock().is_some()
}

/// Transmits a raw Ethernet frame through the global E1000 singleton.
///
/// # Arguments
/// - `frame`: Raw Ethernet II frame byte slice.
///
/// # Returns
/// `Ok(())` upon successful DMA transmission.
///
/// # Errors
/// Returns `Err` if the E1000 NIC is not initialized, the frame exceeds `BUFFER_SIZE`, or DMA times out.
pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    let mut guard = E1000_NIC.lock();
    let nic = guard.as_mut().ok_or("E1000 NIC not initialized")?;
    nic.send_packet(frame)
}

/// Reads a pending raw Ethernet frame from the global E1000 singleton.
///
/// # Arguments
/// - `out_buf`: Destination buffer for the received frame.
///
/// # Returns
/// `Some(bytes_read)` if a frame was received, or `None` if the NIC is uninitialized or the RX ring is empty.
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

/// Returns `true` if carrier link is detected on the active E1000 adapter.
pub fn is_link_up() -> bool {
    let guard = E1000_NIC.lock();
    guard.as_ref().map(|d| d.is_link_up()).unwrap_or(false)
}
