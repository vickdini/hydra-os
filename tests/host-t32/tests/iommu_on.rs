//! `arch/iommu.rs` with DMA remapping on: the ACPI DMAR table found, two modelled VT-d
//! units started, a reserved region kept for its device, drivers' devices attached to
//! their own domains, DMA mapped and unmapped, faults polled.
//!
//! The IOMMU state is global and starts once: one test drives the whole life.

mod common;

use common::{acpi, pci, vtd};
use hydra_hosttests_t32::arch::{dmar, iommu};
use hydra_hosttests_t32::arch::pci::PciDevice;
use hydra_hosttests_t32::{host, stubs};

const UNIT_A: u64 = 0xFED9_0000; // everything else (INCLUDE_PCI_ALL)
const UNIT_B: u64 = 0xFED9_1000; // the NIC on bus 2 behind the bridge 00:1c.0

fn dev(b: u8, d: u8, f: u8) -> PciDevice {
    PciDevice { bus: b, device: d, function: f, vendor_id: 0, device_id: 0, class_id: 0, subclass_id: 0, bar0: 0, irq_line: 0 }
}

/// The context entry of `id` in a unit's tables: (low, high).
fn context(u: &vtd::Unit, id: u16) -> (u64, u64) {
    let root = u.r(0x20) as u64 | (u.r(0x24) as u64) << 32;
    let re = unsafe { *((root + (id as u64 >> 8) * 16) as *const u64) };
    assert_eq!(re & 1, 1, "root entry present for bus {}", id >> 8);
    let ct = re & !0xFFF;
    let p = (ct + (id as u64 & 0xFF) * 16) as *const u64;
    unsafe { (*p, *p.add(1)) }
}

#[test]
fn dma_remapping_life() {
    host::reset();
    stubs::reset();
    common::global_frames();

    // PCI: a bridge 00:1c.0 to buses 2-3, a NIC 02:00.0, USB 00:1d.0, graphics 00:02.0
    let mut p = pci::Pci::default();
    let br = p.add(0, 0x1C, 0, 0x8086, 0x2940, 0x06, 0x04, 1);
    br.set8(0x19, 2);
    br.set8(0x1A, 3);
    p.add(2, 0, 0, 0x8086, 0x10D3, 0x02, 0x00, 0);
    p.add(0, 0x1D, 0, 0x8086, 0x2934, 0x0C, 0x03, 0);
    p.add(0, 2, 0, 0x8086, 0x0102, 0x03, 0x00, 0);
    let _pci = pci::install(p);

    // The DMAR: unit B for the bridge's buses, unit A for the rest, an RMRR for USB
    let usb = acpi::scope(1, 0, &[(0x1D, 0)]);
    let table = acpi::dmar(&[
        acpi::drhd(0, 0, UNIT_B, &[acpi::scope(2, 0, &[(0x1C, 0)]), acpi::scope(3, 0, &[(0x1F, 0)])]),
        acpi::drhd(1, 0, UNIT_A, &[]),
        acpi::rmrr(0x7E00_0000, 0x7E00_FFFF, &[usb]),
    ]);
    host::RSDP.set(Some(acpi::rsdp(vec![acpi::table(b"FACP", &[0; 8]), table], true)));
    iommu::discover();
    assert!(!iommu::active());
    assert_eq!(iommu::status(), vec!["DMA remapping: off (no usable Intel VT-d unit; see the boot log)"]);

    // Unit A left translation and queued invalidation on (firmware), and a protected region
    let mut a = vtd::Unit::new(UNIT_A, vtd::CAP4 | 1 << 4 | 1 << 7, vtd::ECAP);
    a.regs.insert(0x1C, 1 << 31 | 1 << 26 | 1 << 25);
    a.regs.insert(0x64, 1 << 31 | 1);
    let b = vtd::Unit::new(UNIT_B, vtd::CAP4, vtd::ECAP);
    let units = vtd::install(vec![a, b]);
    iommu::init();
    let log = stubs::take_log();
    assert!(iommu::active(), "{log:#?}");
    assert!(log.iter().any(|l| l.contains("firmware region 0x7e000000-0x7e00ffff kept reachable for 1 device(s)")), "{log:#?}");
    assert!(log.iter().any(|l| l.contains("[iommu] unit 0xfed90000 (VT-d 1.0, 256 domains, caching mode): translating all other devices")));
    assert!(log.iter().any(|l| l.contains("[iommu] unit 0xfed91000 (VT-d 1.0, 256 domains): translating its listed devices")));
    assert!(log.iter().any(|l| l.contains("DMA remapping on: 2 unit(s), 4-level I/O page tables")));
    {
        let u = units.borrow();
        for unit in u.iter() {
            assert_eq!(unit.gsts() & (1 << 31 | 1 << 30), 1 << 31 | 1 << 30, "translating, root table set");
            assert_eq!(unit.gsts() & (1 << 26 | 1 << 25), 0, "queued invalidation and IR off");
            assert_eq!(unit.r(0x38), 1 << 31, "fault interrupts masked");
        }
        assert_eq!(u[0].r(0x64) & 1, 0, "protected region off");
        // USB (00:1d.0) is in the firmware domain on unit A, which maps the RMRR 1:1
        let (lo, hi) = context(&u[0], dmar::bdf(0, 0x1D, 0));
        assert_eq!(lo & 1, 1);
        assert_eq!(hi & 7, 2, "4-level");
        assert_eq!(hi >> 8 & 0xFFFF, 1, "domain 1");
    }
    assert_eq!(iommu::lookup(0, 0x7E00_1234).map(|t| t.0), Some(0x7E00_1234));

    // The NIC's driver (endpoint 0x30) gets a domain on unit B
    iommu::attach(0x30, "e1000e", &dev(2, 0, 0));
    assert_eq!(stubs::take_log(), vec!["[iommu] 02:00.0 (e1000e): DMA domain 2"]);
    {
        let u = units.borrow();
        let (lo, hi) = context(&u[1], dmar::bdf(2, 0, 0));
        assert_eq!((lo & 1, hi >> 8 & 0xFFFF), (1, 2));
        // The unit was told: context and IOTLB invalidated after the change
        assert!(u[1].log.iter().any(|&(o, v)| o == 0x2C && v >> 31 == 1));
    }
    assert_eq!(iommu::device_of(0x30), Some(dmar::bdf(2, 0, 0)));
    assert_eq!(iommu::device_of(0x99), None);
    // A restart of the driver: nothing new
    iommu::attach(0x30, "e1000e", &dev(2, 0, 0));
    assert!(stubs::take_log().is_empty());

    // Its DMA memory
    assert_eq!(iommu::map_dma(0x30, 0x1234_5000, 0x2001), Ok(()));
    assert_eq!(iommu::lookup(0x30, 0x1234_6010), Some((0x1234_6010, dmar::PTE_R | dmar::PTE_W)));
    assert_eq!(iommu::lookup(0x30, 0x1234_7000).map(|t| t.0), Some(0x1234_7000), "the partial last page");
    assert_eq!(iommu::lookup(0x30, 0x1234_8000), None);
    assert_eq!(iommu::lookup(0x99, 0x1234_5000), None, "no such domain");
    assert_eq!(iommu::map_dma(0x30, 0, 0), Ok(()), "empty");
    iommu::unmap_dma(0x30, 0x1234_5000, 0x1000);
    assert_eq!(iommu::lookup(0x30, 0x1234_5000), None);
    assert_eq!(iommu::lookup(0x30, 0x1234_6000).map(|t| t.0), Some(0x1234_6000));
    iommu::unmap_dma(0x77, 0x1000, 0x1000); // no such domain: nothing
    let st = iommu::status();
    assert!(st[0].starts_with("DMA remapping: on (4-level tables"), "{st:?}");
    assert!(st.iter().any(|l| l.contains("domain 2 (endpoint 0x30): 2 page(s) mapped; devices: 02:00.0 e1000e")), "{st:#?}");
    assert!(st.iter().any(|l| l.contains("domain 1 (firmware regions): 16 page(s) mapped; devices: 00:1d.0 firmware")), "{st:#?}");

    // USB's own driver takes it out of the firmware domain, keeping the RMRR mapped
    iommu::attach(0x40, "xhci", &dev(0, 0x1D, 0));
    assert_eq!(stubs::take_log(), vec!["[iommu] 00:1d.0 (xhci): DMA domain 3"]);
    assert_eq!(iommu::lookup(0x40, 0x7E00_F000).map(|t| t.0), Some(0x7E00_F000));
    {
        let u = units.borrow();
        let (_, hi) = context(&u[0], dmar::bdf(0, 0x1D, 0));
        assert_eq!(hi >> 8 & 0xFFFF, 3, "moved to its driver's domain");
    }
    assert!(iommu::status().iter().any(|l| l.contains("devices: none")), "firmware domain now empty");

    // Graphics: unit A covers it (include-all)
    iommu::attach(0x50, "gpu", &dev(0, 2, 0));
    assert_eq!(stubs::take_log(), vec!["[iommu] 00:02.0 (gpu): DMA domain 4"]);

    // Faults: two recorded on unit B, one lost
    {
        let mut u = units.borrow_mut();
        u[1].fault(0, 0x1234_5000, dmar::bdf(2, 0, 0), 5, false);
        u[1].fault(1, 0x9999_9000, dmar::bdf(3, 1, 0), 6, true);
        let f = u[1].r(0x34) | 1;
        u[1].regs.insert(0x34, f);
    }
    assert_eq!(iommu::poll_faults(), 2);
    let log = stubs::take_log();
    assert!(log[0].starts_with("[iommu] blocked DMA: device 02:00.0 (e1000e) tried to write 0x12345000"), "{log:#?}");
    assert!(log[1].starts_with("[iommu] blocked DMA: device 03:01.0 (no driver) tried to read 0x99999000"));
    assert!(log[2].contains("more faults came than the unit could record"));
    assert_eq!(units.borrow()[1].r(0x34) & 3, 0, "status cleared");
    let recent = iommu::recent_faults();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].fault.source, dmar::bdf(2, 0, 0));
    assert_eq!(iommu::poll_faults(), 0, "nothing new");
    assert!(iommu::status()[0].contains("2 fault(s) since boot, 1 lost"));

    // Many faults: eight shown, the rest counted; the recent list keeps 64
    for round in 0..17 {
        {
            let mut u = units.borrow_mut();
            for i in 0..4 {
                u[0].fault(i, 0x1000 * (round * 4 + i + 1), dmar::bdf(0, 0x1D, 0), 5, true);
            }
        }
        assert_eq!(iommu::poll_faults(), 4);
    }
    assert_eq!(iommu::recent_faults().len(), 64);
    stubs::take_log();
}
