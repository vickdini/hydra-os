//! # Network: finding the Intel e1000-family adapter
//!
//! The adapter is driven by `e1000-driver`, a Ring 3 program the supervisor starts with
//! the adapter's registers granted to it (`userland/drivers/e1000-driver`); its only client
//! is net-server (`userland/drivers/net-server`), which takes frames from it directly. The
//! kernel only finds the adapter on the PCI bus for the supervisor ([`find_adapter`]).

use crate::arch::pci;

/// PCI Vendor ID for Intel Corporation.
pub const E1000_VENDOR_ID: u16 = 0x8086;
/// PCI Device ID for the Intel 82540EM (VirtualBox / QEMU default).
pub const E1000_DEVICE_ID: u16 = 0x100E;

/// Intel adapters the driver runs, with their family (its `model=` argument): the 8254x,
/// the 82574 (QEMU's `e1000e`), and the chipset-integrated I217/I218 ("PCH LAN", as in
/// Haswell and Broadwell machines). The I219 (Skylake on) needs more workarounds than the
/// driver has and is not listed.
const ADAPTERS: &[(u16, &str)] = &[
    (E1000_DEVICE_ID, "82540"),
    (0x100F, "82540"), // 82545EM (VMware's)
    (0x10D3, "82574"),
    (0x10F6, "82574"), // 82574LA
    (0x153A, "pch"),   // I217-LM
    (0x153B, "pch"),   // I217-V
    (0x155A, "pch"),   // I218-LM
    (0x1559, "pch"),   // I218-V
    (0x15A0, "pch"),   // I218-LM (2)
    (0x15A1, "pch"),   // I218-V (2)
    (0x15A2, "pch"),   // I218-LM (3)
    (0x15A3, "pch"),   // I218-V (3)
];

/// A network adapter for the driver.
pub struct Adapter {
    /// Its PCI function.
    pub dev: pci::PciDevice,
    /// Physical address of its register window (`BAR0`, 128 KiB).
    pub bar0: u64,
    /// Its family, the driver's `model=` argument.
    pub model: &'static str,
}

/// Finds the adapter on the PCI bus and lets it bus-master; the supervisor gives its
/// register window (`BAR0`) and interrupt to the driver.
///
/// # Returns
///
/// `Some(Adapter)` if one is found, or `None`.
pub fn find_adapter() -> Option<Adapter> {
    ADAPTERS.iter().find_map(|&(id, model)| {
        let dev = pci::find_device(E1000_VENDOR_ID, id)?;
        pci::enable_bus_mastering(&dev);
        let bar0 = pci::bar_address(&dev, 0);
        (bar0 != 0).then_some(Adapter { dev, bar0, model })
    })
}
