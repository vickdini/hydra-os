//! Boot-volume files (`src/fs/bootfs.rs`) and the installer's first-boot settings
//! (`src/fs/firstboot.rs`). The UEFI file protocol is not there on the host (boot services
//! are gone, as in the kernel after the hardware takeover): what runs is the path
//! conversion, the hardware-mode answers, and the import of staged settings into the pool.

use std::sync::Mutex;

use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs};
use hydra_hosttests_t33::fs::bootfs::{self, path_to_cstr16, MAX_LOAD_SIZE};
use hydra_hosttests_t33::fs::client::ZfsClient;
use hydra_hosttests_t33::fs::firstboot::{self, POOL_PATH};

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

#[test]
fn paths_become_volume_relative_utf16() {
    let mut buf = [0u16; 32];
    let c = path_to_cstr16("/bin/hello.elf", &mut buf).unwrap();
    assert_eq!(c.to_string(), r"bin\hello.elf");
    let c = path_to_cstr16(r"\\efi\boot/x", &mut buf).unwrap();
    assert_eq!(c.to_string(), r"efi\boot\x");
    assert_eq!(path_to_cstr16("", &mut buf).unwrap().to_string(), "");
    // Exactly fitting (with the NUL) and one too long
    let mut small = [0u16; 4];
    assert!(path_to_cstr16("abc", &mut small).is_some());
    assert!(path_to_cstr16("abcd", &mut small).is_none());
    // Not UCS-2: a NUL inside makes CStr16 refuse it
    assert!(path_to_cstr16("a\0b", &mut buf).is_none());
}

#[test]
fn without_boot_services_nothing_is_read() {
    let _g = serial();
    fake::HARDWARE_MODE.set(true);
    assert!(bootfs::open_root_volume().is_err());
    assert_eq!(bootfs::read_boot_file(r"\etc\passwd"), Err("Boot media reading unavailable in hardware mode"));
    assert_eq!(bootfs::read_media_file(r"\rootfs.tar.gz"), Err("Boot media reading unavailable in hardware mode"));
    assert!(!bootfs::file_exists(r"\bin\hello.elf"));
    assert_eq!(MAX_LOAD_SIZE, 16 << 20);
}

#[test]
fn settings_size_limits() {
    assert!(!firstboot::usable_size(0));
    assert!(firstboot::usable_size(1));
    assert!(firstboot::usable_size(64 * 1024));
    assert!(!firstboot::usable_size(64 * 1024 + 1));
}

#[test]
fn staged_settings_reach_the_linux_root() {
    let _g = serial();
    fakefs::pool();
    // Nothing staged: nothing happens
    firstboot::import_into_pool();
    assert!(fake::klog_take().is_empty());
    // Staged, but the pool has no Linux root
    let _ = with_fs(|fs| fs.detach(fakefs::ROOT_INO, b"ubuntu"));
    firstboot::stage(b"user=alice\n".to_vec());
    assert!(firstboot::setup_pending());
    firstboot::import_into_pool();
    assert!(fake::klog_take().contains("no Linux root (/ubuntu/etc) in the pool: settings not applied"));
    // With a Linux root: written as root, mode 600, and committed
    with_fs(|fs| fs.mkdir_p(fakefs::ROOT_INO, "ubuntu/etc"));
    firstboot::stage(b"user=bob\n".to_vec());
    let txg = with_fs(|fs| fs.txg);
    firstboot::import_into_pool();
    assert!(fake::klog_take().contains(&format!("settings written to {POOL_PATH}")));
    let mut buf = [0u8; 64];
    assert_eq!(ZfsClient::read_file_by_path(POOL_PATH, &mut buf), Ok(9));
    assert_eq!(&buf[..9], b"user=bob\n");
    let st = ZfsClient::file_stat(POOL_PATH).unwrap();
    assert_eq!((st.mode & 0o777, st.uid, st.gid), (0o600, 0, 0));
    assert!(with_fs(|fs| fs.txg) > txg, "committed");
    // Taken: a second import does nothing
    firstboot::import_into_pool();
    assert!(fake::klog_take().is_empty());
    // A failing write is reported
    firstboot::stage(b"x".to_vec());
    fakefs::fail(0x3107, -28, 1);
    firstboot::import_into_pool();
    assert!(fake::klog_take().contains("failed: the new user is NOT created"));
}
