//! `arch/iommu.rs` when DMA remapping cannot start: no table, a broken one, units that do
//! not answer or do not follow their commands, unusable units. Each failure undoes what
//! was turned on and leaves the IOMMU off. The table is global: tests hold [`serial`].

mod common;

use std::sync::{Mutex, MutexGuard};

use common::{acpi, pci, vtd};
use hydra_hosttests_t32::arch::iommu;
use hydra_hosttests_t32::{host, stubs};

const BASE: u64 = 0xFED9_0000;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    common::global_frames();
    g
}

/// Discovers a DMAR made of `structs` and runs init; returns the log.
fn start(structs: &[Vec<u8>], units: Vec<vtd::Unit>) -> (Vec<String>, std::rc::Rc<std::cell::RefCell<Vec<vtd::Unit>>>) {
    host::RSDP.set(Some(acpi::rsdp(vec![acpi::dmar(structs)], true)));
    iommu::discover();
    let u = vtd::install(units);
    iommu::init();
    (stubs::take_log(), u)
}

fn has(log: &[String], s: &str) -> bool {
    log.iter().any(|l| l.contains(s))
}

#[test]
fn no_table() {
    let _g = serial();
    host::RSDP.set(None);
    iommu::discover();
    iommu::init();
    assert!(has(&stubs::take_log(), "no DMAR table"));
    // ACPI tables without a DMAR, through an RSDT (ACPI 1)
    host::RSDP.set(Some(acpi::rsdp(vec![acpi::table(b"FACP", &[1, 2, 3])], false)));
    iommu::discover();
    iommu::init();
    assert!(has(&stubs::take_log(), "no DMAR table"));
    // A bad RSDP signature
    let mut r = vec![0u8; 36];
    r[..8].copy_from_slice(b"RSD PTX ");
    host::RSDP.set(Some(acpi::leak(r)));
    iommu::discover();
    iommu::init();
    assert!(has(&stubs::take_log(), "no DMAR table"));
    // A DMAR shorter than its fixed part is not taken
    let mut short = acpi::table(b"DMAR", &[38, 0]);
    short.truncate(40);
    host::RSDP.set(Some(acpi::rsdp(vec![short], true)));
    iommu::discover();
    iommu::init();
    assert!(has(&stubs::take_log(), "no DMAR table"));
    assert!(!iommu::active());
    assert!(!iommu::dma_test_enabled());
}

#[test]
fn broken_table() {
    let _g = serial();
    let mut t = acpi::dmar(&[acpi::drhd(1, 0, BASE, &[])]);
    t[9] = t[9].wrapping_add(1); // checksum
    host::RSDP.set(Some(acpi::rsdp(vec![t], false)));
    iommu::discover();
    iommu::init();
    assert!(has(&stubs::take_log(), "the firmware's DMAR table is broken (the table's checksum is wrong)"));
    // A bad RMRR is only a warning; then no unit answers at the address
    let mut dead = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    dead.regs.insert(0, 0);
    let (log, _) = start(&[acpi::drhd(1, 0, BASE, &[]), acpi::rmrr(0x1000, 0x1000, &[])], vec![dead]);
    assert!(has(&log, "firmware table: a reserved memory region (RMRR) has a bad address range; ignored"), "{log:#?}");
    assert!(has(&log, "could not start the IOMMU (no remapping unit answers at 0xfed90000)"), "{log:#?}");
    assert!(!iommu::active());
}

#[test]
fn unusable_units() {
    let _g = serial();
    // Another PCI segment, registers above 4 GiB, no page-table format, graphics only
    let mut p = pci::Pci::default();
    p.add(0, 2, 0, 0x8086, 0x0102, 0x03, 0x00, 0);
    let _pci = pci::install(p);
    let gfx = acpi::scope(1, 0, &[(2, 0)]);
    let units = vec![
        vtd::Unit::new(BASE, 0, vtd::ECAP), // SAGAW 0
        vtd::Unit::new(BASE + 0x1000, vtd::CAP4, vtd::ECAP),
    ];
    let (log, _) = start(
        &[
            acpi::drhd(1, 1, BASE + 0x8000, &[]),
            acpi::drhd(0, 0, 0x1_0000_0000, &[gfx.clone()]),
            acpi::drhd(0, 0, BASE + 0x1000, &[gfx]),
            acpi::drhd(1, 0, BASE, &[]),
        ],
        units,
    );
    assert!(has(&log, "could not start the IOMMU (no usable remapping unit)"), "{log:#?}");
    assert!(!iommu::active());
}

#[test]
fn firmware_translation_that_will_not_stop() {
    let _g = serial();
    let mut u = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    u.regs.insert(0x1C, 1 << 31);
    u.stuck = 1 << 31;
    let (log, _) = start(&[acpi::drhd(1, 0, BASE, &[])], vec![u]);
    assert!(has(&log, "unit 0xfed90000 did not stop the firmware's translation"), "{log:#?}");
}

#[test]
fn queued_invalidation_that_will_not_stop() {
    let _g = serial();
    let mut u = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    u.regs.insert(0x1C, 1 << 26);
    u.stuck = 1 << 26;
    let (log, _) = start(&[acpi::drhd(1, 0, BASE, &[])], vec![u]);
    assert!(has(&log, "did not leave queued invalidation"), "{log:#?}");
}

#[test]
fn root_table_not_taken() {
    let _g = serial();
    let mut u = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    u.stuck = 1 << 30;
    let (log, _) = start(&[acpi::drhd(1, 0, BASE, &[])], vec![u]);
    assert!(has(&log, "did not take the root table"), "{log:#?}");
}

#[test]
fn invalidation_never_completes() {
    let _g = serial();
    let mut u = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    u.hang_inval = true;
    let (log, _) = start(&[acpi::drhd(1, 0, BASE, &[])], vec![u]);
    assert!(has(&log, "did not finish an invalidation"), "{log:#?}");
}

#[test]
fn second_unit_fails_first_is_undone() {
    let _g = serial();
    // Unit 1 (3-level only, non-coherent, scoped to 00:03.0) starts; unit 2 never turns
    // translation on: unit 1 is turned off again
    let mut p = pci::Pci::default();
    p.add(0, 3, 0, 0x8086, 0x10D3, 0x02, 0x00, 0);
    let _pci = pci::install(p);
    let one = vtd::Unit::new(BASE, (vtd::CAP4 & !(0x1F << 8)) | 2 << 8, 0 | (vtd::IRO / 16) << 8);
    let mut two = vtd::Unit::new(BASE + 0x1000, (vtd::CAP4 & !(0x1F << 8)) | 6 << 8, vtd::ECAP);
    two.stuck = 1 << 31;
    let (log, units) = start(&[acpi::drhd(0, 0, BASE, &[acpi::scope(1, 0, &[(3, 0)])]), acpi::drhd(1, 0, BASE + 0x1000, &[])], vec![one, two]);
    assert!(has(&log, "unit 0xfed91000 did not turn translation on"), "{log:#?}");
    let u = units.borrow();
    assert_eq!(u[0].gsts() & (1 << 31), 0, "unit 1 turned off again");
    assert!(u[0].log.iter().any(|&(o, v)| o == 0x18 && v & (1 << 31) != 0), "it was on");
    assert!(!iommu::active());
    assert_eq!(iommu::poll_faults(), 0);
    iommu::attach(1, "x", &hydra_hosttests_t32::arch::pci::PciDevice { bus: 0, device: 3, function: 0, vendor_id: 0, device_id: 0, class_id: 0, subclass_id: 0, bar0: 0, irq_line: 0 });
    assert_eq!(iommu::map_dma(1, 0x1000, 0x1000), Ok(()), "nothing to map while off");
    iommu::unmap_dma(1, 0x1000, 0x1000);
}

#[test]
fn mixed_page_table_formats() {
    let _g = serial();
    // Unit A takes 4 levels only, unit B 3 only: 3-level tables, A left off; then the
    // memory note (RAM beyond 512 GiB is not reachable with 3 levels... not here: little
    // RAM). B's invalidation hangs so init fails after the decisions are logged.
    let a = vtd::Unit::new(BASE, vtd::CAP4, vtd::ECAP);
    let mut b = vtd::Unit::new(BASE + 0x1000, (vtd::CAP4 & !(0x1F << 8)) | 2 << 8, vtd::ECAP);
    b.hang_inval = true;
    let (log, units) = start(&[acpi::drhd(0, 0, BASE, &[acpi::scope(1, 0, &[(5, 0)])]), acpi::drhd(1, 0, BASE + 0x1000, &[])], vec![a, b]);
    assert!(has(&log, "unit 0xfed91000 did not finish an invalidation"), "{log:#?}");
    assert_eq!(units.borrow()[0].r(0x20), 0, "A never got a root table");
}

#[test]
fn test_mode_from_fw_cfg() {
    let _g = serial();
    // fw_cfg opt/hydra/iommu=test: DMA test mode on
    let mut items = std::collections::BTreeMap::new();
    items.insert(0u16, b"QEMU".to_vec());
    let mut dir = 1u32.to_be_bytes().to_vec();
    let mut e = [0u8; 64];
    e[0..4].copy_from_slice(&4u32.to_be_bytes());
    e[4..6].copy_from_slice(&0x20u16.to_be_bytes());
    e[8..23].copy_from_slice(b"opt/hydra/iommu");
    dir.extend_from_slice(&e);
    items.insert(0x19, dir);
    items.insert(0x20, b"test".to_vec());
    let mut cur = (0u16, 0usize);
    x86_64::hw::set_port_handler(move |op| match (op.port, op.write) {
        (0x510, Some(v)) => {
            cur = (v as u16, 0);
            0
        }
        (0x511, None) => {
            let b = items.get(&cur.0).and_then(|d| d.get(cur.1)).copied().unwrap_or(0);
            cur.1 += 1;
            b as u32
        }
        _ => 0,
    });
    host::RSDP.set(None);
    iommu::discover();
    assert!(iommu::dma_test_enabled());
}
