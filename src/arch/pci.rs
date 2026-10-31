//! # Architecture Layer: Peripheral Component Interconnect (PCI) Subsystem
//!
//! Provides bare-metal hardware discovery, enumeration, and configuration of PCI devices.
//!
//! ## Architectural Role & Design Rationale
//!
//! Rather than relying on static hardware port assumptions, modern x86 architectures multiplex
//! expansion cards (Ethernet controllers, graphics adapters, storage host controllers) on the PCI bus.
//!
//! The PCI subsystem communicates over the legacy standard x86 I/O port pair:
//! - **CONFIG_ADDRESS (`0xCF8`)**: Specifies the 32-bit target Bus (0..255), Device (0..31), Function (0..7), and Register Offset.
//! - **CONFIG_DATA (`0xCFC`)**: 32-bit bidirection data transfer port.
//!
//! The driver scans all buses to discover connected devices, parses Base Address Registers (BARs),
//! and enables Bus Mastering (DMA) so network cards like the Intel E1000 can initiate autonomous DMA transfers.
//!
//! ## Key Types & Interfaces
//!
//! - [`PciDevice`]: Discovered device descriptor containing bus location, vendor/device IDs, and BARs.
//! - [`pci_read_u32()`] / [`pci_write_u32()`]: Low-level PCI configuration space accessors.
//! - [`find_device()`]: Scans the PCI hierarchy for a specific `(vendor_id, device_id)` pair.
//! - [`enable_bus_mastering()`]: Grants the PCI device permission to perform autonomous memory DMA.
//!
//! ## Privilege Level & Hardware Context
//!
//! - Privilege Level: Ring 0 microkernel core.
//! - I/O Ports: `0xCF8` and `0xCFC`.

use x86_64::instructions::port::Port;

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// PCI Configuration Register Offsets
pub const PCI_REG_VENDOR_ID: u8 = 0x00;
pub const PCI_REG_DEVICE_ID: u8 = 0x02;
pub const PCI_REG_COMMAND: u8 = 0x04;
pub const PCI_REG_STATUS: u8 = 0x06;
pub const PCI_REG_REVISION: u8 = 0x08;
pub const PCI_REG_CLASS: u8 = 0x0B;
pub const PCI_REG_SUBCLASS: u8 = 0x0A;
pub const PCI_REG_HEADER_TYPE: u8 = 0x0E;
pub const PCI_REG_BAR0: u8 = 0x10;
pub const PCI_REG_BAR1: u8 = 0x14;
pub const PCI_REG_INTERRUPT_LINE: u8 = 0x3C;

// PCI Command Bits
pub const PCI_CMD_IO_SPACE: u16 = 0x0001;
pub const PCI_CMD_MEMORY_SPACE: u16 = 0x0002;
pub const PCI_CMD_BUS_MASTER: u16 = 0x0004;

/// Encapsulates a discovered PCI peripheral on the hardware bus.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_id: u8,
    pub subclass_id: u8,
    pub bar0: u32,
    pub irq_line: u8,
}

impl PciDevice {
    /// Returns true if BAR0 specifies a memory-mapped I/O (MMIO) window.
    pub fn is_mmio_bar0(&self) -> bool {
        (self.bar0 & 0x01) == 0
    }

    /// Returns the physical base address of BAR0 with flags stripped.
    pub fn bar0_address(&self) -> u64 {
        if self.is_mmio_bar0() {
            (self.bar0 & !0x0F) as u64
        } else {
            (self.bar0 & !0x03) as u64
        }
    }
}

/// Constructs a 32-bit PCI configuration address word.
#[inline(always)]
fn pci_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

/// Reads a 32-bit dword from PCI configuration space.
pub fn pci_read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let mut addr_port = Port::<u32>::new(PCI_CONFIG_ADDRESS);
    let mut data_port = Port::<u32>::new(PCI_CONFIG_DATA);

    let address = pci_config_address(bus, device, function, offset);
    unsafe {
        addr_port.write(address);
        data_port.read()
    }
}

/// Reads a 16-bit word from PCI configuration space.
pub fn pci_read_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let dword = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 2) * 8) as u32;
    ((dword >> shift) & 0xFFFF) as u16
}

/// Reads an 8-bit byte from PCI configuration space.
pub fn pci_read_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let dword = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 3) * 8) as u32;
    ((dword >> shift) & 0xFF) as u8
}

/// Writes a 32-bit dword into PCI configuration space.
pub fn pci_write_u32(bus: u8, device: u8, function: u8, offset: u8, val: u32) {
    let mut addr_port = Port::<u32>::new(PCI_CONFIG_ADDRESS);
    let mut data_port = Port::<u32>::new(PCI_CONFIG_DATA);

    let address = pci_config_address(bus, device, function, offset);
    unsafe {
        addr_port.write(address);
        data_port.write(val);
    }
}

/// Writes a 16-bit word into PCI configuration space.
pub fn pci_write_u16(bus: u8, device: u8, function: u8, offset: u8, val: u16) {
    let current = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 2) * 8) as u32;
    let mask = !(0xFFFFu32 << shift);
    let new_val = (current & mask) | ((val as u32) << shift);
    pci_write_u32(bus, device, function, offset, new_val);
}

/// Enables PCI Bus Mastering, Memory Space, and I/O Space on the specified device.
pub fn enable_bus_mastering(dev: &PciDevice) {
    let cmd = pci_read_u16(dev.bus, dev.device, dev.function, PCI_REG_COMMAND);
    let updated = cmd | PCI_CMD_BUS_MASTER | PCI_CMD_MEMORY_SPACE | PCI_CMD_IO_SPACE;
    pci_write_u16(dev.bus, dev.device, dev.function, PCI_REG_COMMAND, updated);
}

/// Finds the first device of a class/subclass (e.g. 0x01/0x01, an IDE controller).
pub fn find_class(class: u8, subclass: u8) -> Option<PciDevice> {
    for bus in 0..=31 {
        for device in 0..32 {
            if matches!(pci_read_u16(bus, device, 0, PCI_REG_VENDOR_ID), 0xFFFF | 0x0000) {
                continue;
            }
            let functions = if pci_read_u8(bus, device, 0, PCI_REG_HEADER_TYPE) & 0x80 != 0 { 8 } else { 1 };
            for function in 0..functions {
                let v = pci_read_u16(bus, device, function, PCI_REG_VENDOR_ID);
                if v == 0xFFFF || v == 0x0000 {
                    continue;
                }
                if pci_read_u8(bus, device, function, PCI_REG_CLASS) == class
                    && pci_read_u8(bus, device, function, PCI_REG_SUBCLASS) == subclass
                {
                    return Some(PciDevice {
                        bus,
                        device,
                        function,
                        vendor_id: v,
                        device_id: pci_read_u16(bus, device, function, PCI_REG_DEVICE_ID),
                        class_id: class,
                        subclass_id: subclass,
                        bar0: pci_read_u32(bus, device, function, PCI_REG_BAR0),
                        irq_line: pci_read_u8(bus, device, function, PCI_REG_INTERRUPT_LINE),
                    });
                }
            }
        }
    }
    None
}

/// Scans the PCI bus topology for a device matching the target vendor and device IDs.
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    for bus in 0..=31 {
        for device in 0..32 {
            // Function 0 is always probed first
            let dev_vendor = pci_read_u16(bus, device, 0, PCI_REG_VENDOR_ID);
            if dev_vendor == 0xFFFF || dev_vendor == 0x0000 {
                continue;
            }

            let header_type = pci_read_u8(bus, device, 0, PCI_REG_HEADER_TYPE);
            let num_functions = if (header_type & 0x80) != 0 { 8 } else { 1 };

            for function in 0..num_functions {
                let v = pci_read_u16(bus, device, function, PCI_REG_VENDOR_ID);
                if v == 0xFFFF || v == 0x0000 {
                    continue;
                }
                let d = pci_read_u16(bus, device, function, PCI_REG_DEVICE_ID);

                if v == vendor_id && d == device_id {
                    let class_id = pci_read_u8(bus, device, function, PCI_REG_CLASS);
                    let subclass_id = pci_read_u8(bus, device, function, PCI_REG_SUBCLASS);
                    let bar0 = pci_read_u32(bus, device, function, PCI_REG_BAR0);
                    let irq_line = pci_read_u8(bus, device, function, PCI_REG_INTERRUPT_LINE);

                    return Some(PciDevice {
                        bus,
                        device,
                        function,
                        vendor_id: v,
                        device_id: d,
                        class_id,
                        subclass_id,
                        bar0,
                        irq_line,
                    });
                }
            }
        }
    }
    None
}
