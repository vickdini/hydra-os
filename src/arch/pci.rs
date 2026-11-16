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
//! - `PciDevice`: Discovered device descriptor containing bus location, vendor/device IDs, and BARs.
//! - `pci_read_u32` / `pci_write_u32`: Low-level PCI configuration space accessors.
//! - `find_device`: Scans the PCI hierarchy for a specific `(vendor_id, device_id)` pair.
//! - `enable_bus_mastering`: Grants the PCI device permission to perform autonomous memory DMA.
//!
//! ## Privilege Level & Hardware Context
//!
//! - Privilege Level: Ring 0 microkernel core.
//! - I/O Ports: `0xCF8` and `0xCFC`.

use x86_64::instructions::port::Port;

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI Configuration Space: Vendor ID register offset (16-bit).
pub const PCI_REG_VENDOR_ID: u8 = 0x00;
/// PCI Configuration Space: Device ID register offset (16-bit).
pub const PCI_REG_DEVICE_ID: u8 = 0x02;
/// PCI Configuration Space: Command register offset (16-bit).
pub const PCI_REG_COMMAND: u8 = 0x04;
/// PCI Configuration Space: Status register offset (16-bit).
pub const PCI_REG_STATUS: u8 = 0x06;
/// PCI Configuration Space: Revision ID register offset (8-bit).
pub const PCI_REG_REVISION: u8 = 0x08;
/// PCI Configuration Space: Base Class Code register offset (8-bit).
pub const PCI_REG_CLASS: u8 = 0x0B;
/// PCI Configuration Space: Subclass Code register offset (8-bit).
pub const PCI_REG_SUBCLASS: u8 = 0x0A;
/// PCI Configuration Space: Header Type register offset (8-bit).
pub const PCI_REG_HEADER_TYPE: u8 = 0x0E;
/// PCI Configuration Space: Base Address Register 0 offset (32-bit).
pub const PCI_REG_BAR0: u8 = 0x10;
/// PCI Configuration Space: Base Address Register 1 offset (32-bit).
pub const PCI_REG_BAR1: u8 = 0x14;
/// PCI Configuration Space: Interrupt Line register offset (8-bit).
pub const PCI_REG_INTERRUPT_LINE: u8 = 0x3C;

/// PCI Command Register bit 0: Response in I/O Space.
pub const PCI_CMD_IO_SPACE: u16 = 0x0001;
/// PCI Command Register bit 1: Response in Memory Space.
pub const PCI_CMD_MEMORY_SPACE: u16 = 0x0002;
/// PCI Command Register bit 2: Enable Bus Mastering (DMA).
pub const PCI_CMD_BUS_MASTER: u16 = 0x0004;

/// Encapsulates a discovered PCI peripheral on the hardware bus.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// Target PCI bus number (0..255).
    pub bus: u8,
    /// Target PCI device/slot number (0..31).
    pub device: u8,
    /// Target PCI function index (0..7).
    pub function: u8,
    /// 16-bit Vendor Identifier assigned by the PCI-SIG.
    pub vendor_id: u16,
    /// 16-bit Device Identifier assigned by the device vendor.
    pub device_id: u16,
    /// PCI base class code identifying the device category (e.g. 0x02 for Network).
    pub class_id: u8,
    /// PCI subclass code further refining device functionality.
    pub subclass_id: u8,
    /// Raw Base Address Register 0 (specifies memory or I/O window).
    pub bar0: u32,
    /// Programmable interrupt line (IRQ vector) assigned to the device.
    pub irq_line: u8,
}

impl PciDevice {
    /// Checks whether BAR0 specifies a memory-mapped I/O (MMIO) window.
    ///
    /// Inspects bit 0 of Base Address Register 0. If cleared (0), the BAR represents
    /// memory-mapped physical registers; if set (1), it represents legacy I/O ports.
    ///
    /// # Returns
    ///
    /// `true` if BAR0 targets MMIO physical memory; `false` if it targets legacy I/O ports.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn is_mmio_bar0(&self) -> bool {
        (self.bar0 & 0x01) == 0
    }

    /// Returns the physical base address encoded in BAR0 with metadata flags stripped.
    ///
    /// Masks off the lower 4 bits for MMIO windows (type, prefetch, and memory indicator bits)
    /// or the lower 2 bits for port I/O windows.
    ///
    /// # Returns
    ///
    /// The sanitized 64-bit physical address or base port of BAR0.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    pub fn bar0_address(&self) -> u64 {
        if self.is_mmio_bar0() {
            (self.bar0 & !0x0F) as u64
        } else {
            (self.bar0 & !0x03) as u64
        }
    }
}

/// Constructs a 32-bit PCI configuration address word for Mechanism #1.
///
/// Sets bit 31 (Enable Configuration Space Mapping), the 8-bit bus number (bits 16..23),
/// 5-bit device number (bits 11..15), 3-bit function number (bits 8..10), and the
/// doubleword-aligned register offset (bits 2..7).
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index on the bus (0..31).
/// * `function` - Function index within the device (0..7).
/// * `offset` - Byte register offset within the 256-byte configuration header (0..255).
///
/// # Returns
///
/// A 32-bit address word formatted for write to I/O port `0xCF8`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
#[inline(always)]
fn pci_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

/// Reads a 32-bit doubleword from PCI configuration space.
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index (0..31).
/// * `function` - Function index (0..7).
/// * `offset` - Register offset (must be 4-byte aligned).
///
/// # Returns
///
/// The 32-bit register value read from configuration data port `0xCFC`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index (0..31).
/// * `function` - Function index (0..7).
/// * `offset` - Register offset (must be 2-byte aligned).
///
/// # Returns
///
/// The 16-bit word at the specified offset.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn pci_read_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let dword = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 2) * 8) as u32;
    ((dword >> shift) & 0xFFFF) as u16
}

/// Reads an 8-bit byte from PCI configuration space.
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index (0..31).
/// * `function` - Function index (0..7).
/// * `offset` - Byte register offset (0..255).
///
/// # Returns
///
/// The 8-bit value at the specified offset.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn pci_read_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let dword = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 3) * 8) as u32;
    ((dword >> shift) & 0xFF) as u8
}

/// Writes a 32-bit doubleword into PCI configuration space.
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index (0..31).
/// * `function` - Function index (0..7).
/// * `offset` - 4-byte aligned register offset.
/// * `val` - 32-bit value to store.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn pci_write_u32(bus: u8, device: u8, function: u8, offset: u8, val: u32) {
    let mut addr_port = Port::<u32>::new(PCI_CONFIG_ADDRESS);
    let mut data_port = Port::<u32>::new(PCI_CONFIG_DATA);

    let address = pci_config_address(bus, device, function, offset);
    unsafe {
        addr_port.write(address);
        data_port.write(val);
    }
}

/// Writes a 16-bit word into PCI configuration space via read-modify-write.
///
/// # Arguments
///
/// * `bus` - PCI bus number (0..255).
/// * `device` - Device slot index (0..31).
/// * `function` - Function index (0..7).
/// * `offset` - 2-byte aligned register offset.
/// * `val` - 16-bit word to write.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn pci_write_u16(bus: u8, device: u8, function: u8, offset: u8, val: u16) {
    let current = pci_read_u32(bus, device, function, offset);
    let shift = ((offset & 2) * 8) as u32;
    let mask = !(0xFFFFu32 << shift);
    let new_val = (current & mask) | ((val as u32) << shift);
    pci_write_u32(bus, device, function, offset, new_val);
}

/// Enables PCI Bus Mastering, Memory Space, and I/O Space on the specified device.
///
/// Reads the Command register (offset `0x04`), sets bits 0 (I/O Space), 1 (Memory Space),
/// and 2 (Bus Master), and writes the updated command word back.
///
/// # Arguments
///
/// * `dev` - Target PCI device descriptor whose bus mastering is to be enabled.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn enable_bus_mastering(dev: &PciDevice) {
    let cmd = pci_read_u16(dev.bus, dev.device, dev.function, PCI_REG_COMMAND);
    let updated = cmd | PCI_CMD_BUS_MASTER | PCI_CMD_MEMORY_SPACE | PCI_CMD_IO_SPACE;
    pci_write_u16(dev.bus, dev.device, dev.function, PCI_REG_COMMAND, updated);
}

/// Finds the first device on the PCI bus matching a specified class and subclass code.
///
/// Iterates over buses 0..=31, devices 0..31, and all functions, reading class/subclass
/// registers to locate matching controllers (e.g. IDE controllers, network interfaces).
///
/// # Arguments
///
/// * `class` - Target PCI base class code (e.g. `0x01` for Mass Storage).
/// * `subclass` - Target PCI subclass code (e.g. `0x01` for IDE).
///
/// # Returns
///
/// `Some(PciDevice)` containing device parameters and BAR0 if found; `None` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
///
/// Iterates across buses 0..=31, devices 0..31, and all multifunction device sub-functions.
/// Reads vendor and device ID registers, extracts class, subclass, BAR0, and interrupt line
/// configuration if a match is found.
///
/// # Arguments
///
/// * `vendor_id` - 16-bit PCI vendor identifier (e.g. `0x8086` for Intel).
/// * `device_id` - 16-bit PCI device identifier (e.g. `0x100E` for Intel 82540EM).
///
/// # Returns
///
/// `Some(PciDevice)` containing full topological coordinates and BAR0 if found; `None` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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

/// Physical address of memory BAR `index` (0..=5), with the upper half of a 64-bit BAR
/// (UEFI firmware may place those above 4 GiB, as on an xHCI controller); 0 for an I/O
/// BAR or one the firmware left unassigned.
///
/// # Arguments
///
/// * `dev` - The device.
/// * `index` - BAR number.
///
/// # Returns
///
/// The BAR's physical base address, or 0.
pub fn bar_address(dev: &PciDevice, index: u8) -> u64 {
    if index > 5 {
        return 0;
    }
    let off = PCI_REG_BAR0 + index * 4;
    let lo = pci_read_u32(dev.bus, dev.device, dev.function, off);
    if lo & 1 != 0 {
        return 0;
    }
    let mut addr = (lo & !0xF) as u64;
    // Type 2 (bits 1..2): 64-bit, the next BAR holds the upper half
    if (lo >> 1) & 3 == 2 && index < 5 {
        addr |= (pci_read_u32(dev.bus, dev.device, dev.function, off + 4) as u64) << 32;
    }
    addr
}

/// Size of memory BAR `index` in bytes (0 for an I/O or unassigned BAR), found the
/// standard way: all ones written to it, the address bits that stay zero give the size.
/// Memory decoding is off meanwhile, so call it before the device's driver runs.
///
/// # Arguments
///
/// * `dev` - The device.
/// * `index` - BAR number.
///
/// # Returns
///
/// The size in bytes, or 0.
pub fn bar_size(dev: &PciDevice, index: u8) -> u64 {
    if index > 5 || bar_address(dev, index) == 0 {
        return 0;
    }
    let (b, d, f) = (dev.bus, dev.device, dev.function);
    let off = PCI_REG_BAR0 + index * 4;
    let lo = pci_read_u32(b, d, f, off);
    let is64 = (lo >> 1) & 3 == 2 && index < 5;
    let cmd = pci_read_u16(b, d, f, PCI_REG_COMMAND);
    pci_write_u16(b, d, f, PCI_REG_COMMAND, cmd & !PCI_CMD_MEMORY_SPACE);
    pci_write_u32(b, d, f, off, 0xFFFF_FFFF);
    let mut mask = (pci_read_u32(b, d, f, off) & !0xF) as u64;
    pci_write_u32(b, d, f, off, lo);
    if is64 {
        let hi = pci_read_u32(b, d, f, off + 4);
        pci_write_u32(b, d, f, off + 4, 0xFFFF_FFFF);
        mask |= (pci_read_u32(b, d, f, off + 4) as u64) << 32;
        pci_write_u32(b, d, f, off + 4, hi);
    } else {
        mask |= 0xFFFF_FFFF_0000_0000;
    }
    pci_write_u16(b, d, f, PCI_REG_COMMAND, cmd);
    if mask == 0xFFFF_FFFF_0000_0000 {
        return 0;
    }
    (!mask).wrapping_add(1)
}

/// Offset of the device's capability `id` in configuration space (0x05: MSI, 0x11:
/// MSI-X, 0x10: PCI Express, 0x01: power management).
///
/// # Arguments
///
/// * `dev` - The device.
/// * `id` - Capability ID.
///
/// # Returns
///
/// `Some(offset)` if the device lists the capability.
pub fn find_capability(dev: &PciDevice, id: u8) -> Option<u8> {
    // Status bit 4: the device has a capability list
    if pci_read_u16(dev.bus, dev.device, dev.function, PCI_REG_STATUS) & 0x10 == 0 {
        return None;
    }
    let mut ptr = pci_read_u8(dev.bus, dev.device, dev.function, 0x34) & 0xFC;
    // Bounded: a broken list must not loop forever
    for _ in 0..48 {
        if ptr < 0x40 {
            return None;
        }
        if pci_read_u8(dev.bus, dev.device, dev.function, ptr) == id {
            return Some(ptr);
        }
        ptr = pci_read_u8(dev.bus, dev.device, dev.function, ptr + 1) & 0xFC;
    }
    None
}

/// Makes the device signal its interrupt as a message (MSI) carrying `vector` to the
/// local APIC `apic_id`, and turns its legacy INTx line off. Messages need no routing
/// through the PIC or an I/O APIC (which Hydra does not program), are never shared with
/// another device, and work the same on every chipset.
///
/// # Arguments
///
/// * `dev` - The device.
/// * `apic_id` - Local APIC ID of the CPU that takes the interrupt.
/// * `vector` - IDT vector of the interrupt.
///
/// # Returns
///
/// `true` if the device has the MSI capability and it is now enabled.
pub fn enable_msi(dev: &PciDevice, apic_id: u32, vector: u8) -> bool {
    let Some(cap) = find_capability(dev, 0x05) else { return false };
    let (b, d, f) = (dev.bus, dev.device, dev.function);
    // A device with MSI-X too uses MSI-X when that is enabled (firmware may have left it so)
    if let Some(x) = find_capability(dev, 0x11) {
        let ctrl = pci_read_u16(b, d, f, x + 2);
        pci_write_u16(b, d, f, x + 2, ctrl & !0x8000);
    }
    let ctrl = pci_read_u16(b, d, f, cap + 2);
    let is64 = ctrl & (1 << 7) != 0;
    let per_vector_mask = ctrl & (1 << 8) != 0;
    // Off while it is reprogrammed
    pci_write_u16(b, d, f, cap + 2, ctrl & !1);
    // Address: the local APIC message range, physical destination mode
    pci_write_u32(b, d, f, cap + 4, 0xFEE0_0000 | ((apic_id & 0xFF) << 12));
    let data = if is64 {
        pci_write_u32(b, d, f, cap + 8, 0);
        cap + 12
    } else {
        cap + 8
    };
    // Data: fixed delivery, edge triggered
    pci_write_u16(b, d, f, data, vector as u16);
    if per_vector_mask {
        pci_write_u32(b, d, f, if is64 { cap + 16 } else { cap + 12 }, 0);
    }
    // One message (multiple message enable 0), enabled
    pci_write_u16(b, d, f, cap + 2, (ctrl & !(7 << 4)) | 1);
    // INTx disable (command bit 10): the line must not fire too
    let cmd = pci_read_u16(b, d, f, PCI_REG_COMMAND);
    pci_write_u16(b, d, f, PCI_REG_COMMAND, cmd | 0x400);
    true
}

/// Every function on the PCI bus whose class and subclass match (all of them, where
/// [`find_class`] returns the first).
///
/// # Arguments
///
/// * `class` - Base class code.
/// * `subclass` - Subclass code.
///
/// # Returns
///
/// The matching devices in bus order.
pub fn find_all_class(class: u8, subclass: u8) -> alloc::vec::Vec<PciDevice> {
    let mut found = alloc::vec::Vec::new();
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
                    found.push(PciDevice {
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
    found
}
