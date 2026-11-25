//! Group G (installer): the first-boot settings the installer leaves on the ESP.
//!
//! `hydra-install` writes `\hydra\setup.conf` (user account with a password hash, computer
//! name, time zone, keyboard, language) onto the new computer's EFI system partition; the
//! installer never mounts the new pool. At the first boot of the installed system:
//!
//! 1. [`read_from_boot_volume`] (with the other boot files, while UEFI Boot Services still
//!    run) reads the file and deletes it from the ESP. This is the only moment the kernel
//!    can write the ESP, and the file holds a password hash, so it must not stay there.
//! 2. [`import_into_pool`] (right after the pool is up) writes it to the Linux root as
//!    `/ubuntu/etc/hydra/setup.conf` (mode 600) and commits the pool.
//! 3. `/usr/libexec/hydra-firstboot` (started by `hydra-session --display-manager` before the
//!    login screen) applies it and deletes it.
//!
//! [`setup_pending`] tells other parts of the kernel (Group E: a new pool GUID for a freshly
//! installed computer) that this is the first boot after an installation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Path of the settings on the ESP.
const ESP_PATH: &str = r"\hydra\setup.conf";
/// Where [`import_into_pool`] writes them (pool path of the Linux root's `/etc/hydra/setup.conf`).
pub const POOL_PATH: &str = "/ubuntu/etc/hydra/setup.conf";
/// Largest settings file accepted (it is a few hundred bytes).
const MAX_SIZE: usize = 64 * 1024;

/// The settings read from the ESP this boot, until [`import_into_pool`] writes them.
static STAGED: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// True for the whole boot in which `\hydra\setup.conf` was found on the ESP.
static PENDING: AtomicBool = AtomicBool::new(false);

/// True when this is the first boot after an installation: `\hydra\setup.conf` was on the
/// ESP. Valid from the boot-file reading on (before the pool is imported).
pub fn setup_pending() -> bool {
    PENDING.load(Ordering::Acquire)
}

/// Reads `\hydra\setup.conf` from the boot volume `root` and deletes it there. Must run while
/// UEFI Boot Services are active (from [`super::client::ZfsClient::read_boot_files`]).
pub fn read_from_boot_volume(root: &mut uefi::proto::media::file::Directory) {
    use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
    let mut path_u16 = [0u16; 64];
    let Some(cstr) = crate::fs::bootfs::path_to_cstr16(ESP_PATH, &mut path_u16) else { return };
    // Read-write, so it can be deleted; a read-only medium (CD) falls back to reading only
    let (handle, writable) = match root.open(cstr, FileMode::ReadWrite, FileAttribute::empty()) {
        Ok(h) => (h, true),
        Err(_) => match root.open(cstr, FileMode::Read, FileAttribute::empty()) {
            Ok(h) => (h, false),
            Err(_) => return,
        },
    };
    let Some(mut file) = handle.into_regular_file() else { return };
    let mut info_buf = crate::fs::bootfs::InfoBuf::new();
    let size = file.get_info::<FileInfo>(info_buf.bytes()).map(|i| i.file_size() as usize).unwrap_or(0);
    if !usable_size(size) {
        crate::kprintln!("[firstboot] {} has an unusable size ({} bytes): ignored", ESP_PATH, size);
        return;
    }
    let mut data = alloc::vec![0u8; size];
    let mut got = 0;
    while got < size {
        match crate::fs::bootfs::fw_read(&mut file, &mut data[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    if got != size {
        crate::kprintln!("[firstboot] reading {} failed ({} of {} bytes): left on the ESP", ESP_PATH, got, size);
        return;
    }
    let deleted = writable && file.delete().is_ok();
    crate::kprintln!(
        "[firstboot] first boot after installation: {} read ({} bytes){}",
        ESP_PATH,
        size,
        if deleted { ", deleted from the ESP" } else { "; could not delete it from the ESP" }
    );
    stage(data);
}

/// Whether a settings file of `size` bytes is worth reading (empty or huge ones are not).
pub fn usable_size(size: usize) -> bool {
    size != 0 && size <= MAX_SIZE
}

/// Keeps settings read from the ESP until [`import_into_pool`] writes them, and marks this
/// boot as the first after an installation ([`setup_pending`]).
pub fn stage(data: Vec<u8>) {
    *STAGED.lock() = Some(data);
    PENDING.store(true, Ordering::Release);
}

/// Writes the settings read by [`read_from_boot_volume`] to [`POOL_PATH`] (mode 600) and
/// commits the pool, so they survive even if this boot ends early. Called once the pool is up.
pub fn import_into_pool() {
    let Some(data) = STAGED.lock().take() else { return };
    use super::client::ZfsClient;
    if ZfsClient::resolve(0, b"/ubuntu/etc", true).is_err() {
        crate::kprintln!("[firstboot] no Linux root (/ubuntu/etc) in the pool: settings not applied");
        return;
    }
    let ok = ZfsClient::write_file_by_path_batch(POOL_PATH, &data).is_ok()
        && super::zfs::with_server(|s| {
            let root = s.root_obj();
            let ino = super::client::resolve_at(s, root, POOL_PATH.as_bytes(), true)?;
            s.setattr(ino, super::zfs::zpl::SetAttr { mode: Some(0o600), uid: Some(0), gid: Some(0), ..Default::default() })?;
            Ok(())
        })
        .is_ok()
        && ZfsClient::sync().is_ok();
    if ok {
        crate::kprintln!("[firstboot] settings written to {} for hydra-firstboot", POOL_PATH);
    } else {
        crate::kprintln!("[firstboot] writing {} failed: the new user is NOT created", POOL_PATH);
    }
}
