//! The supervisor's USB (xHCI) and sound (HD Audio) drivers. The controllers are looked up
//! once per boot (`spin::Once`), so this binary has a single test that sets both up first.

mod common;
use common::*;

use hydra_hosttests_t31::ipc::protocol::*;
use hydra_hosttests_t31::task::supervisor::{self, SUPERVISOR};

#[test]
fn usb_and_sound_drivers_get_their_controllers() {
    let _w = booted();
    common::global_frames();
    // An EHCI function (skipped), then an Intel xHCI that still routes its ports to EHCI
    let ehci = fake::pci_add(0, 0x1a, 0, 0x8086, 0x8C2D, 0x0C, 0x03, 0x20);
    fake::pci_set_bar(ehci, 0, 0xF7E0_0000, 0x400);
    let xhci = fake::pci_add(0, 0x14, 0, 0x8086, 0x8C31, 0x0C, 0x03, 0x30);
    fake::pci_set_bar(xhci, 0, 0xF7F0_0000, 0x10000);
    fake::pci_poke32(xhci, 0xDC, 0x0F); // USB3PRM
    fake::pci_poke32(xhci, 0xD4, 0x7FFF); // XUSB2PRM
    fake::MSIX.lock().unwrap().insert((0, 0x14, 0), (44, 0xF7F0_3000, 0xFEE0_0000, 0x4021));
    // An HDMI-only Intel audio function (skipped), then the codec controller
    let hdmi = fake::pci_add(0, 3, 0, 0x8086, 0x0C0C, 0x04, 0x03, 0);
    fake::pci_set_bar(hdmi, 0, 0xF7A0_0000, 0x4000);
    let hda = fake::pci_add(0, 0x1b, 0, 0x8086, 0x8C20, 0x04, 0x03, 0);
    fake::pci_set_bar(hda, 0, 0xF7B1_0000, 0x4000);
    fake::pci_poke32(hda, 0x78, 1 << 11); // no-snoop enabled
    fake::pci_poke32(hda, 0x2C, 0x2222_1111);

    supervisor::supervisor_init();
    let usb = SUPERVISOR.lock().start_service("usb_driver").unwrap();
    assert_eq!(
        &with(usb.0, |t| t.cmdline.clone()).unwrap()[..],
        b"/drivers/usb_driver\0mmio=0xf7f00000\0len=0x10000\0pool=usb\0irq=44\0msix=0xf7f03000:0xfee00000:0x4021\0"
    );
    assert_eq!(fake::pci_peek32(xhci, 0xD8), 0x0F, "SuperSpeed enabled from its mask");
    assert_eq!(fake::pci_peek32(xhci, 0xD0), 0x7FFF, "USB 2 ports routed to xHCI");
    assert!(fake::klog_has("Intel xHCI: USB ports switched from EHCI"));
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("set_grants", ENDPOINT_INPUT_DEV, 0xF7F0_0000, 0x10000)));
    assert!(fake::IOMMU_ATTACH.lock().unwrap().contains(&(ENDPOINT_INPUT_DEV, "usb_driver")));

    let snd = SUPERVISOR.lock().start_service("sound_driver").unwrap();
    assert_eq!(&with(snd.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/sound_driver\0mmio=0xf7b10000\0");
    assert_eq!(fake::pci_peek32(hda, 0x78) & (1 << 11), 0, "no-snoop cleared");
    assert_eq!(*fake::SND.lock().unwrap(), vec![String::from("0000:00:1b.0")]);
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("set_grants", ENDPOINT_SOUND_DEV, 0xF7B1_0000, 0x4000)));

    // With a disk driver and the boot disk known, the USB driver is told where the pool is
    hydra_hosttests_t31::task::kill(usb);
    *fake::BOOTDISK_ARG.lock().unwrap() = Some("boot=usb0p2".into());
    fake::MSIX.lock().unwrap().clear();
    fake::MSI.lock().unwrap().insert((0, 0x14, 0), 45);
    let usb = SUPERVISOR.lock().start_service("usb_driver").unwrap();
    assert!(with(usb.0, |t| t.cmdline.clone()).unwrap().ends_with(b"boot=usb0p2\0irq=45\0"));
    hydra_hosttests_t31::task::kill(usb);
    *fake::BOOTDISK_ARG.lock().unwrap() = None;
    fake::MSI.lock().unwrap().clear();
    let disk = hydra_hosttests_t31::task::spawn("disk", noop, hydra_hosttests_t31::task::TaskPriority::High).0;
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_BLOCK_DEV, disk);
    let usb = SUPERVISOR.lock().start_service("usb_driver").unwrap();
    assert!(with(usb.0, |t| t.cmdline.clone()).unwrap().ends_with(b"len=0x10000\0"), "no pool argument, polling");
    assert!(fake::klog_has("xHCI controller: no MSI; its driver polls"));
}
