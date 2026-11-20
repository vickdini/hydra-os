//! `arch/iommu.rs` and `arch/pcid.rs` off switches: QEMU fw_cfg, UEFI load options and a
//! file on the EFI partition (own binary: once off, the switch stays).

use hydra_hosttests_t32::arch::{iommu, pcid};
use hydra_hosttests_t32::{host, stubs};

/// fw_cfg with one file.
fn fw_cfg(name: &str, data: &'static [u8]) {
    let mut items = std::collections::BTreeMap::new();
    items.insert(0u16, b"QEMU".to_vec());
    let mut dir = 1u32.to_be_bytes().to_vec();
    let mut e = [0u8; 64];
    e[0..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
    e[4..6].copy_from_slice(&0x20u16.to_be_bytes());
    e[8..8 + name.len()].copy_from_slice(name.as_bytes());
    dir.extend_from_slice(&e);
    items.insert(0x19, dir);
    items.insert(0x20, data.to_vec());
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
}

#[test]
fn iommu_off_switches() {
    host::reset();
    stubs::reset();
    host::RSDP.set(None);
    let off = || {
        iommu::init();
        let log = stubs::take_log();
        assert_eq!(log.len(), 1);
        log[0].clone()
    };
    fw_cfg("opt/hydra/iommu", b"off");
    iommu::discover();
    assert!(off().contains("turned off by QEMU fw_cfg opt/hydra/iommu=off"));
    x86_64::hw::clear_ports();
    // The load options are UCS-2, compared without case
    host::set_load_options("\\EFI\\hydra.efi quiet IOMMU=OFF");
    iommu::discover();
    assert!(off().contains("turned off by boot option iommu=off"));
    host::set_load_options("noiommu");
    iommu::discover();
    assert!(off().contains("boot option"));
    host::LOAD_OPTIONS.with_borrow_mut(|o| *o = None);
    stubs::fs::bootfs::FILES.with_borrow_mut(|f| f.insert("\\hydra\\noiommu".into(), vec![]));
    iommu::discover();
    assert!(off().contains("file \\hydra\\noiommu on the EFI partition"));
    assert_eq!(iommu::status(), vec!["DMA remapping: off (turned off by a boot option)"]);
    assert!(!iommu::active());
}

#[test]
fn pcid_and_global_pages_off_switches() {
    host::reset();
    stubs::reset();
    // PCID: fw_cfg first
    fw_cfg("opt/hydra/pcid", b"off");
    pcid::discover();
    x86_64::hw::clear_ports();
    pcid::init_with(true, true);
    assert!(!pcid::enabled());
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("PCID off: turned off by QEMU fw_cfg opt/hydra/pcid=off")), "{log:?}");
    // A load option, then a file; non-ASCII UCS-2 characters never match
    host::LOAD_OPTIONS.with_borrow_mut(|o| *o = Some(vec![b'n', 1, b'o', 0, b'p', 0, b'c', 0, b'i', 0, b'd', 0]));
    pcid::discover();
    pcid::init_with(true, false);
    assert!(stubs::take_log().iter().any(|l| l.contains("turned off by QEMU fw_cfg")), "the earlier reason stays");
    host::set_load_options("nopcid noglobal");
    pcid::discover();
    pcid::init_with(true, false);
    assert!(stubs::take_log().iter().any(|l| l.contains("turned off by boot option nopcid")));
    pcid::enable_global();
    assert!(!pcid::global_enabled());
    assert!(stubs::take_log().iter().any(|l| l.contains("global kernel pages off: turned off by boot option noglobal")));
    host::LOAD_OPTIONS.with_borrow_mut(|o| *o = None);
    stubs::fs::bootfs::FILES.with_borrow_mut(|f| {
        f.insert("\\hydra\\nopcid".into(), vec![]);
        f.insert("\\hydra\\noglobal".into(), vec![]);
    });
    pcid::discover();
    pcid::init_with(true, true);
    pcid::enable_global();
    let log = stubs::take_log();
    assert!(log.iter().any(|l| l.contains("file \\hydra\\nopcid")), "{log:?}");
    assert!(log.iter().any(|l| l.contains("file \\hydra\\noglobal")), "{log:?}");
    fw_cfg("opt/hydra/pge", b"off");
    pcid::discover();
    x86_64::hw::clear_ports();
    pcid::enable_global();
    assert!(stubs::take_log().iter().any(|l| l.contains("QEMU fw_cfg opt/hydra/pge=off")));
    assert_eq!(pcid::summary(), "PCID off (file \\hydra\\nopcid on the EFI partition), global kernel pages off");
}
