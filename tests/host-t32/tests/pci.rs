//! `arch/pci.rs`: configuration access, enumeration, BARs, capabilities, MSI and MSI-X,
//! against a modelled configuration space (`common::pci`).

mod common;

use common::pci::{install, Pci};
use hydra_hosttests_t32::arch::pci::{self, PciDevice};
use hydra_hosttests_t32::host;

fn dev(b: u8, d: u8, f: u8) -> PciDevice {
    PciDevice { bus: b, device: d, function: f, vendor_id: 0, device_id: 0, class_id: 0, subclass_id: 0, bar0: 0, irq_line: 0 }
}

/// Host bridge at 00:00.0, a multi-function device at 00:1f (ISA + SATA + SMBus), a NIC on
/// bus 2, a USB controller on bus 31 (the last scanned).
fn machine() -> Pci {
    let mut p = Pci::default();
    p.add(0, 0, 0, 0x8086, 0x29C0, 0x06, 0x00, 0);
    p.add(0, 0x1F, 0, 0x8086, 0x2918, 0x06, 0x01, 0x80);
    let sata = p.add(0, 0x1F, 2, 0x8086, 0x2922, 0x01, 0x06, 0);
    sata.regs[4] = 0xC001; // BAR0: I/O
    sata.regs[15] = 0x0B | 1 << 8;
    p.add(0, 0x1F, 3, 0x8086, 0x2930, 0x0C, 0x05, 0);
    let nic = p.add(2, 0, 0, 0x8086, 0x10D3, 0x02, 0x00, 0);
    nic.regs[4] = 0xFEB0_0000; // BAR0: 32-bit memory
    nic.regs[15] = 0x0A;
    p.add(31, 3, 0, 0x1B36, 0x000D, 0x0C, 0x03, 0);
    // A second SATA controller, on a single-function device: function 2 there is never probed
    p.add(5, 1, 0, 0x1234, 0x0001, 0x01, 0x06, 0);
    p.add(5, 1, 2, 0x1234, 0x0002, 0x01, 0x06, 0);
    p
}

#[test]
fn config_reads_pick_the_right_bytes() {
    host::reset();
    let mut p = Pci::default();
    p.add(1, 2, 3, 0xABCD, 0x1234, 0, 0, 0).regs[1] = 0x8765_4321;
    let _p = install(p);
    assert_eq!(pci::pci_read_u32(1, 2, 3, 0), 0x1234_ABCD);
    assert_eq!(pci::pci_read_u16(1, 2, 3, 0), 0xABCD);
    assert_eq!(pci::pci_read_u16(1, 2, 3, 2), 0x1234);
    assert_eq!(pci::pci_read_u16(1, 2, 3, 6), 0x8765);
    assert_eq!(pci::pci_read_u8(1, 2, 3, 4), 0x21);
    assert_eq!(pci::pci_read_u8(1, 2, 3, 5), 0x43);
    assert_eq!(pci::pci_read_u8(1, 2, 3, 7), 0x87);
    // The address: enable bit, bus, device, function, dword offset
    let w = x86_64::hw::port_writes();
    assert_eq!(w[0], (0xCF8, 0x8000_0000 | 1 << 16 | 2 << 11 | 3 << 8));
    assert_eq!(w[3], (0xCF8, 0x8000_0000 | 1 << 16 | 2 << 11 | 3 << 8 | 4), "offset 6 reads dword 4");
    // Absent functions read all ones
    assert_eq!(pci::pci_read_u32(9, 9, 1, 0), 0xFFFF_FFFF);
}

#[test]
fn config_writes_merge_16_bits() {
    host::reset();
    let mut p = Pci::default();
    p.add(0, 3, 0, 0x1AF4, 0x1000, 2, 0, 0).regs[1] = 0x0010_0000;
    let p = install(p);
    pci::pci_write_u16(0, 3, 0, 4, 0x0007);
    assert_eq!(p.borrow().reg(0, 3, 0, 4), 0x0010_0007, "status kept, command written");
    pci::pci_write_u16(0, 3, 0, 6, 0xBEEF);
    assert_eq!(p.borrow().reg(0, 3, 0, 4), 0xBEEF_0007);
    pci::pci_write_u32(0, 3, 0, 0x3C, 0x0000_010B);
    assert_eq!(p.borrow().reg(0, 3, 0, 0x3C), 0x10B);
    // Bus mastering: memory, I/O and master on, other command bits kept
    p.borrow_mut().funcs.get_mut(&(0, 3, 0)).unwrap().regs[1] = 0x0000_0400;
    pci::enable_bus_mastering(&dev(0, 3, 0));
    assert_eq!(p.borrow().reg(0, 3, 0, 4) & 0xFFFF, 0x0407);
}

#[test]
fn enumeration_finds_classes_and_ids() {
    host::reset();
    let _p = install(machine());
    let sata = pci::find_class(0x01, 0x06).unwrap();
    assert_eq!((sata.bus, sata.device, sata.function), (0, 0x1F, 2), "function 2 of a multi-function device");
    assert_eq!((sata.vendor_id, sata.device_id, sata.bar0, sata.irq_line), (0x8086, 0x2922, 0xC001, 0x0B));
    assert!(!sata.is_mmio_bar0());
    assert_eq!(sata.bar0_address(), 0xC000);
    let nic = pci::find_device(0x8086, 0x10D3).unwrap();
    assert_eq!((nic.bus, nic.class_id, nic.subclass_id, nic.irq_line), (2, 2, 0, 0x0A));
    assert!(nic.is_mmio_bar0());
    assert_eq!(nic.bar0_address(), 0xFEB0_0000);
    assert_eq!(pci::find_class(0x0C, 0x03).map(|d| d.bus), Some(31), "bus 31 is scanned");
    assert!(pci::find_class(0x03, 0x00).is_none());
    assert!(pci::find_device(0x8086, 0xFFFF).is_none());
    assert!(pci::find_device(0x1234, 0x0002).is_none(), "function 2 of a single-function device");
    let all = pci::find_all_class(0x01, 0x06);
    assert_eq!(all.iter().map(|d| (d.bus, d.device, d.function)).collect::<Vec<_>>(), vec![(0, 0x1F, 2), (5, 1, 0)]);
    assert_eq!(all[1].vendor_id, 0x1234);
    assert!(pci::find_all_class(0x0C, 0x05).len() == 1);
}

#[test]
fn bar_addresses_and_sizes() {
    host::reset();
    let mut p = Pci::default();
    let f = p.add(0, 4, 0, 0x1AF4, 0x1041, 1, 0, 0);
    f.regs[1] = 0x0000_0006; // memory + master on
    f.regs[4] = 0xFEA0_0000; // BAR0: 32-bit, 16 KiB
    f.bar_sizes.insert(0, 16 << 10);
    f.regs[5] = 0xE001; // BAR1: I/O
    f.regs[6] = 0x0000_000C; // BAR2: 64-bit prefetchable, 8 GiB, at 0x8_0000_0000
    f.regs[7] = 0x8;
    f.bar_sizes.insert(2, 8 << 30);
    f.regs[8] = 0xFE80_0000; // BAR4: 32-bit, size reads back 0 (broken)
    f.regs[9] = 0x0000_0004; // BAR5: 64-bit type but the last BAR: no upper half
    let p = install(p);
    let d = dev(0, 4, 0);
    assert_eq!(pci::bar_address(&d, 0), 0xFEA0_0000);
    assert_eq!(pci::bar_address(&d, 1), 0, "I/O BAR");
    assert_eq!(pci::bar_address(&d, 2), 0x8_0000_0000);
    assert_eq!(pci::bar_address(&d, 6), 0);
    assert_eq!(pci::bar_size(&d, 0), 16 << 10);
    assert_eq!(pci::bar_size(&d, 2), 8 << 30);
    assert_eq!(pci::bar_size(&d, 1), 0);
    assert_eq!(pci::bar_size(&d, 3), 0, "upper half of BAR2 / empty");
    assert_eq!(pci::bar_size(&d, 4), 0, "no writable bits");
    assert_eq!(pci::bar_size(&d, 7), 0);
    let s = p.borrow();
    // The BARs and the command register are as before
    assert_eq!(s.reg(0, 4, 0, 0x10), 0xFEA0_0000);
    assert_eq!(s.reg(0, 4, 0, 0x18), 0xC);
    assert_eq!(s.reg(0, 4, 0, 0x1C), 0x8);
    assert_eq!(s.reg(0, 4, 0, 4) & 0xFFFF, 0x6);
    // Memory decoding was off while the BAR read all ones
    let w = &s.writes;
    let i = w.iter().position(|e| e.3 == 0x10 && e.4 == 0xFFFF_FFFF).unwrap();
    assert_eq!(w[i - 1].3, 4);
    assert_eq!(w[i - 1].4 & 2, 0);
}

#[test]
fn capability_list_walk() {
    host::reset();
    let mut p = Pci::default();
    p.add(0, 5, 0, 1, 1, 2, 0, 0).caps(&[(0x01, 0), (0x05, 0), (0x10, 0), (0x11, 0)]);
    let f = p.add(0, 6, 0, 1, 2, 2, 0, 0);
    f.caps(&[(0x09, 0)]);
    f.regs[0x40 / 4] |= 0x40 << 8; // points at itself: a loop
    p.add(0, 7, 0, 1, 3, 2, 0, 0); // no capability list
    let f = p.add(0, 8, 0, 1, 4, 2, 0, 0);
    f.regs[1] |= 0x10 << 16;
    f.set8(0x34, 0x20); // a pointer into the header
    let _p = install(p);
    assert_eq!(pci::find_capability(&dev(0, 5, 0), 0x05), Some(0x60));
    assert_eq!(pci::find_capability(&dev(0, 5, 0), 0x11), Some(0xA0));
    assert_eq!(pci::find_capability(&dev(0, 5, 0), 0x12), None);
    assert_eq!(pci::find_capability(&dev(0, 6, 0), 0x05), None, "a looping list ends");
    assert_eq!(pci::find_capability(&dev(0, 7, 0), 0x05), None);
    assert_eq!(pci::find_capability(&dev(0, 8, 0), 0x05), None);
}

#[test]
fn msi_programming() {
    host::reset();
    let mut p = Pci::default();
    // 64-bit MSI with per-vector masking (control bits 7, 8), and MSI-X left on by firmware
    p.add(0, 9, 0, 1, 1, 2, 0, 0).caps(&[(0x05, 1 << 7 | 1 << 8 | 2 << 4), (0x11, 0x8000 | 3)]);
    // 32-bit MSI only
    p.add(0, 10, 0, 1, 2, 2, 0, 0).caps(&[(0x05, 0)]);
    p.add(0, 11, 0, 1, 3, 2, 0, 0);
    let p = install(p);
    assert!(pci::enable_msi(&dev(0, 9, 0), 0x3, 0x51));
    {
        let s = p.borrow();
        assert_eq!(s.reg(0, 9, 0, 0x40) >> 16, (1 << 7 | 1 << 8) | 1, "one message, enabled");
        assert_eq!(s.reg(0, 9, 0, 0x44), 0xFEE0_3000, "destination APIC 3");
        assert_eq!(s.reg(0, 9, 0, 0x48), 0, "upper address");
        assert_eq!(s.reg(0, 9, 0, 0x4C) & 0xFFFF, 0x51, "vector");
        assert_eq!(s.reg(0, 9, 0, 0x60) >> 16, 3, "MSI-X turned off");
        assert_eq!(s.reg(0, 9, 0, 0x50), 0, "vector unmasked");
        assert_eq!(s.reg(0, 9, 0, 4) & 0x400, 0x400, "INTx disabled");
        // It was off while reprogrammed
        let w: Vec<_> = s.writes.iter().filter(|e| (e.0, e.1, e.3) == (0, 9, 0x40)).collect();
        assert_eq!(w[0].4 >> 16 & 1, 0);
    }
    assert!(pci::enable_msi(&dev(0, 10, 0), 0x1FF, 0x50));
    {
        let s = p.borrow();
        assert_eq!(s.reg(0, 10, 0, 0x44), 0xFEEF_F000, "APIC id masked to 8 bits");
        assert_eq!(s.reg(0, 10, 0, 0x48) & 0xFFFF, 0x50);
    }
    assert!(!pci::enable_msi(&dev(0, 11, 0), 0, 0x50), "no MSI capability");
}

#[test]
fn msix_programming() {
    host::reset();
    let mut p = Pci::default();
    let f = p.add(0, 12, 0, 1, 1, 2, 0, 0);
    f.caps(&[(0x05, 1), (0x11, 0x4000 | 7)]);
    f.regs[0x64 / 4] = 0x2000 | 2; // table at BAR2 + 0x2000
    f.regs[6] = 0xFE00_0000;
    let f = p.add(0, 13, 0, 1, 2, 2, 0, 0);
    f.caps(&[(0x11, 0)]);
    f.regs[0x44 / 4] = 1; // BAR1: I/O: no table address
    f.regs[5] = 0xD001;
    let p = install(p);
    assert_eq!(pci::enable_msix(&dev(0, 12, 0)), Some(0xFE00_2000));
    let s = p.borrow();
    assert_eq!(s.reg(0, 12, 0, 0x60) >> 16, 0x8000 | 7, "enabled, function mask cleared");
    assert_eq!(s.reg(0, 12, 0, 0x40) >> 16 & 1, 0, "MSI off");
    assert_eq!(s.reg(0, 12, 0, 4) & 0x400, 0x400);
    drop(s);
    assert_eq!(pci::enable_msix(&dev(0, 13, 0)), None);
    assert_eq!(pci::enable_msix(&dev(0, 12, 1)), None, "absent function");
}
