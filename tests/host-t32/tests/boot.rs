//! Boot glue: `arch/bootdisk.rs` (where the kernel came from, the boot volume's flag
//! files), `arch/boot_services.rs` (the takeover's checks and the kernel's low ranges) and
//! `arch/usb_input.rs` (the USB input task's polling loop and report decoding).

use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::{boot_services, bootdisk, usb_input};
use hydra_hosttests_t32::ipc::Message;
use hydra_hosttests_t32::stubs::ipc::service;
use hydra_hosttests_t32::{host, stubs};
use uefi::boot::MemoryType as T;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

#[test]
fn gpt_device_path_nodes() {
    let mut d = vec![0u8; 42];
    d[20..36].copy_from_slice(&[0xAA; 16]);
    d[36] = 2;
    d[37] = 2;
    assert_eq!(bootdisk::gpt_partition(4, 1, &d), Some([0xAA; 16]));
    assert_eq!(bootdisk::gpt_partition(4, 2, &d), None, "not a hard-drive node");
    assert_eq!(bootdisk::gpt_partition(3, 1, &d), None);
    d[36] = 1; // MBR
    assert_eq!(bootdisk::gpt_partition(4, 1, &d), None);
    assert_eq!(bootdisk::gpt_partition(4, 1, &d[..30]), None, "cut short");
}

#[test]
fn boot_info() {
    let _g = serial();
    // Before detection: nothing known
    assert!(bootdisk::info().boot_part.is_none());
    assert_eq!(bootdisk::driver_arg(), None);
    // From a CD: no partition, no flag files
    bootdisk::detect();
    let log = stubs::take_log();
    assert!(log[0].contains("loaded from a device without a GPT partition (CD/ISO); live session: no; first-boot settings: none"), "{log:?}");
    assert_eq!(bootdisk::new_guid_id(), None);
    // From a GPT partition with a live flag (read or merely present) and settings
    let g = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 1, 2, 3, 4, 5, 6, 7, 8];
    host::BOOT_PART.set(Some(g));
    stubs::fs::bootfs::FILES.with_borrow_mut(|f| {
        f.insert("\\hydra\\live".into(), vec![]);
        f.insert("\\hydra\\setup.conf".into(), b"hostname=nuc\n".to_vec());
    });
    bootdisk::detect();
    let log = stubs::take_log();
    assert!(log[0].contains("loaded from GPT partition 76543210-ba98-fedc-0102-030405060708; live session: yes; first-boot settings: 13 bytes"), "{log:?}");
    let info = bootdisk::info();
    assert!(info.live);
    assert_eq!(info.setup_conf.as_deref(), Some(&b"hostname=nuc\n"[..]));
    assert_eq!(bootdisk::driver_arg().as_deref(), Some("boot_part=76543210-ba98-fedc-0102-030405060708"));
    // The new install's GUID seed: FNV-1a of the settings, never 0
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in b"hostname=nuc\n" {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    assert_eq!(bootdisk::new_guid_id(), Some(h));
}

#[test]
fn kernel_low_ranges() {
    let map = [(T::CONVENTIONAL, 0x10_0000, 100), (T::LOADER_CODE, 0x20_0000, 16), (T::ACPI_RECLAIM, 0x7FF0_0000, 4), (T::MMIO, 0xFEC0_0000, 1), (T::RESERVED, 0x1_0000_0000, 8)];
    let r = boot_services::kernel_low_ranges(map.iter().copied(), false, Some((0x4000_0000, 0x8000_0000)), 0x12_3456, Some(0xC000_0000), None);
    assert_eq!(
        r,
        vec![
            (0x20_0000, 0x21_0000),
            (0x7FF0_0000, 0x7FF0_4000),
            (0xFEC0_0000, 0xFEC0_1000),
            (0x1_0000_0000, 0x1_0000_8000),
            (0x4000_0000, 0x8000_0000),
            (2 << 30, 4 << 30),
            (0x12_0000, 0x13_0000),
            (0xC000_0000, 0xC000_0001),
        ]
    );
    // In the higher half: below 2 GiB only device memory counts; the heap is in the direct map
    let r = boot_services::kernel_low_ranges(map.iter().copied(), true, None, 0xFFFF_FFFF_C000_8000, None, None);
    assert_eq!(r, vec![(0xFEC0_0000, 0xFEC0_1000), (0x1_0000_0000, 0x1_0000_8000), (2 << 30, 4 << 30), (0xFFFF_FFFF_C000_0000, 0xFFFF_FFFF_C001_0000)]);
    // wave12 GV: the late path (the image stayed where the firmware loaded it): as in the
    // higher half, below 2 GiB only device memory; the image's range, the heap and the heap
    // stack's 64 KiB are passed on. The 2.5 GB machine: a 2 MiB boot-log block of loader
    // data at 0x7000_0000 kept GiB slot 1 before (programs had a 1 GiB low window)
    let map = [
        (T::CONVENTIONAL, 0x10_0000, 0x6FF00),
        (T::LOADER_DATA, 0x7000_0000, 0x201),
        (T::BOOT_SERVICES_DATA, 0x7100_0000, 16),
        (T::LOADER_CODE, 0x9A00_0000, 0x800),
        (T::ACPI_NON_VOLATILE, 0x9FF0_0000, 4),
        (T::MMIO, 0xFEC0_0000, 1),
    ];
    let heap = Some((0x8BF5_D000, 0x8BF5_D000 + (208 << 20)));
    let r = boot_services::kernel_low_ranges(map.iter().copied(), true, heap, 0x8C00_1234, None, Some((0x9A00_0000, 0x80_0000)));
    assert_eq!(
        r,
        vec![
            (0x9A00_0000, 0x9A80_0000),
            (0x9FF0_0000, 0x9FF0_4000),
            (0xFEC0_0000, 0xFEC0_1000),
            (0x8BF5_D000, 0x8BF5_D000 + (208 << 20)),
            (2 << 30, 4 << 30),
            (0x8C00_0000, 0x8C01_0000),
            (0x9A00_0000, 0x9A80_0000),
        ]
    );
    assert!(r.iter().all(|&(s, e)| s >= 2 << 30 || e <= 1 << 30), "nothing in GiB slot 1: {r:x?}");
    // An image loaded below 2 GiB that stays there (high=late, nohigh) stays reachable
    let r = boot_services::kernel_low_ranges(map.iter().copied(), true, None, 0x9000_0000, None, Some((0x5000_0000, 0x80_0000)));
    assert!(r.contains(&(0x5000_0000, 0x5080_0000)), "{r:x?}");
    assert!(!r.iter().any(|&(s, _)| s == 0x7000_0000), "the boot-log block is reached through the direct map");
    // high=off (the path before wave 12): every region below 2 GiB that is not free is kept
    let r = boot_services::kernel_low_ranges(map.iter().copied(), false, heap, 0x8C00_1234, None, None);
    assert!(r.contains(&(0x7000_0000, 0x7020_1000)) && r.contains(&(0x7100_0000, 0x7101_0000)), "{r:x?}");
}

#[test]
fn takeover_needs_the_framebuffer() {
    let _g = serial();
    assert!(!boot_services::is_hardware_takeover_complete());
    match boot_services::take_hardware_ownership() {
        Err(e) => assert_eq!(e, "Hardware GOP framebuffer driver not available."),
        Ok(_) => panic!(),
    }
    assert!(!boot_services::is_hardware_takeover_complete());
    assert!(stubs::take_calls().is_empty(), "nothing done");
}

#[test]
fn usb_input_task() {
    let _g = serial();
    // No USB input driver online: nothing started
    usb_input::start();
    assert!(stubs::take_calls().is_empty());
    stubs::answer("svc::online", 1);
    usb_input::start();
    let ep = hydra_hosttests_t32::ipc::protocol::ENDPOINT_INPUT_DEV;
    assert_eq!(stubs::take_calls(), vec![format!("svc::notify_on_irq {ep}"), "task::spawn usb-input".to_string()]);
    let task = stubs::task::SPAWNED.with_borrow(|s| s[0]);
    // The window: a key (scancode 0x1E), a relative motion, an absolute position, junk
    let mut w = vec![0u8; 64];
    w[0..8].copy_from_slice(&[1, 0x1E, 0, 0, 0, 0, 0, 0]);
    w[8..16].copy_from_slice(&[2, 1, 0xFD, 0xFF, 0x05, 0x00, 0xFF, 0]); // dx -3, dy 5, wheel -1, left
    w[16..24].copy_from_slice(&[3, 2, 0xFF, 0x7F, 0x00, 0x80, 1, 0]); // x 0x7FFF, y 0x8000, wheel 1, right
    w[24..32].copy_from_slice(&[9, 0, 0, 0, 0, 0, 0, 0]);
    service::WINDOW.with_borrow_mut(|s| *s = Some(Box::leak(w.into_boxed_slice())));
    use hydra_hosttests_t32::ipc::protocol::MSG_INPUT_REPLY;
    service::QUEUED.with_borrow_mut(|q| {
        q.push_back(Ok(Message::with_args(MSG_INPUT_REPLY, [0, 4, 0, 0]))); // 4 records
        q.push_back(Ok(Message::with_args(MSG_INPUT_REPLY, [-5i64 as u64, 0, 0, 0]))); // an error
        q.push_back(Err(-110)); // the driver is gone
        q.push_back(Ok(Message::with_args(MSG_INPUT_REPLY, [0, 1000, 0, 0]))); // more than fits
    });
    stubs::answer("wait::limit", 3);
    let r = std::panic::catch_unwind(task);
    assert!(r.is_err(), "the loop runs until the wait limit");
    let k = stubs::take_calls();
    // The key went to the console buffer (no evdev routing), the pointer reports to evdev
    assert!(k.contains(&"evdev::mouse -3 5 -1 1".to_string()), "{k:#?}");
    assert!(k.contains(&"evdev::abs 32767 32768 1 2".to_string()), "{k:#?}");
    assert_eq!(hydra_hosttests_t32::arch::keyboard::read_key(), Some(uefi::proto::console::text::Key::Printable(uefi::Char16::try_from('a').unwrap())));
    // After a failed call: unregistered, a long wait; after a good one: registered, a poll
    let waits: Vec<_> = k.iter().filter(|c| c.starts_with("wait::wait") || c.starts_with("wq::")).cloned().collect();
    assert_eq!(&waits[..2], &["wq::register", "wait::wait true"], "{waits:?}");
    assert_eq!(&waits[2..4], &["wq::unregister", "wait::wait true"]);
}
