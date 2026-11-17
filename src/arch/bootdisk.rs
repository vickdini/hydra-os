//! # The boot disk and the boot volume's Hydra files
//!
//! Learned from the firmware before `ExitBootServices` ([`detect`]):
//!
//! - **Where the kernel was loaded from.** The `LoadedImage` protocol names the device the
//!   kernel came from; on an installed system (or a live USB stick) its device path ends in
//!   a hard-drive node: a GPT partition (the EFI system partition) with a unique GUID. The
//!   disk drivers get that GUID (`boot_part=<GUID>`) and serve as the pool the Hydra pool
//!   partition of the disk that has that partition (`hydra_rt::blockunits`). Booted from a
//!   CD (the ISO) there is no such node and the drivers keep the old choice: the first disk.
//! - **`\hydra\live`** on the boot volume: the live session of the installation stick.
//! - **`\hydra\setup.conf`** on the boot volume: the first-boot settings the installer
//!   left. Its presence also gives the pool a new GUID, once per distinct file
//!   ([`new_guid_id`], passed to the ZFS file server).
//!
//! Userland sees them as files in the Linux root (written with the device files):
//! `/run/hydra/live`, `/run/hydra/setup.conf`, `/run/hydra/boot-disk`.

use alloc::vec::Vec;
use spin::Mutex;

/// What [`detect`] found.
#[derive(Clone, Default)]
pub struct BootInfo {
    /// Unique GUID of the GPT partition the kernel was loaded from (on-disk byte order).
    pub boot_part: Option<[u8; 16]>,
    /// `\hydra\live` exists on the boot volume.
    pub live: bool,
    /// Contents of `\hydra\setup.conf` on the boot volume.
    pub setup_conf: Option<Vec<u8>>,
}

static INFO: Mutex<Option<BootInfo>> = Mutex::new(None);

/// What was found at boot.
pub fn info() -> BootInfo {
    INFO.lock().clone().unwrap_or_default()
}

/// Asks the firmware where the kernel came from and reads the Hydra flag files of the boot
/// volume. Only before `ExitBootServices`.
pub fn detect() {
    let mut info = BootInfo::default();
    if let Ok(img) = uefi::boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(uefi::boot::image_handle()) {
        if let Some(dev) = img.device() {
            let path = unsafe {
                uefi::boot::open_protocol::<uefi::proto::device_path::DevicePath>(
                    uefi::boot::OpenProtocolParams { handle: dev, agent: uefi::boot::image_handle(), controller: None },
                    uefi::boot::OpenProtocolAttributes::GetProtocol,
                )
            };
            if let Ok(path) = path {
                for node in path.node_iter() {
                    let (ty, sub) = node.full_type();
                    // MEDIA_DEVICE_PATH (4), MEDIA_HARDDRIVE_DP (1): partition number,
                    // start, size, signature[16], MBR type (2: GPT), signature type (2: GUID)
                    let d = node.data();
                    if ty.0 == 4 && sub.0 == 1 && d.len() >= 38 && d[36] == 2 && d[37] == 2 {
                        let mut g = [0u8; 16];
                        g.copy_from_slice(&d[20..36]);
                        info.boot_part = Some(g);
                    }
                }
            }
        }
    }
    info.live = crate::fs::bootfs::read_boot_file("\\hydra\\live").is_ok() || crate::fs::bootfs::file_exists("\\hydra\\live");
    info.setup_conf = crate::fs::bootfs::read_boot_file("\\hydra\\setup.conf").ok();
    crate::kprintln!(
        "[boot] loaded from {}; live session: {}; first-boot settings: {}",
        match &info.boot_part {
            Some(g) => alloc::format!("GPT partition {}", crate::fs::gpt::guid_string(g)),
            None => alloc::string::String::from("a device without a GPT partition (CD/ISO)"),
        },
        if info.live { "yes" } else { "no" },
        match &info.setup_conf {
            Some(c) => alloc::format!("{} bytes", c.len()),
            None => alloc::string::String::from("none"),
        }
    );
    *INFO.lock() = Some(info);
}

/// The disk driver argument naming the boot partition, if the kernel came from one.
pub fn driver_arg() -> Option<alloc::string::String> {
    info().boot_part.map(|g| alloc::format!("boot_part={}", crate::fs::gpt::guid_string(&g)))
}

/// The id for a new pool GUID: a hash (FNV-1a, never 0) of the first-boot settings file,
/// if there is one.
pub fn new_guid_id() -> Option<u64> {
    let conf = info().setup_conf?;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &conf {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    Some(h.max(1))
}
