//! # Live session (Group F)
//!
//! Hydra started from its USB stick ("try Hydra"): the stick's EFI system partition holds the
//! file `\hydra\live` (see the installer's LAYOUT.md). The kernel then
//! - logs the console in without a password (there is nothing on the stick to protect, and
//!   nobody has an account yet),
//! - and writes the live session's files into the system (`super::devices`, the Group F
//!   block): `/run/hydra/live` for programs (the installer, the desktop), the user `live` with
//!   automatic login on the login screen, "Install Hydra" on the desktop and in the start
//!   menu, and the "You are trying Hydra" notice.
//!
//! The flag is read from the boot volume while the firmware's boot services still run (it is
//! unreachable after the hardware takeover), with the other boot files.

use core::sync::atomic::{AtomicBool, Ordering};
use uefi::proto::media::file::File;

/// Whether this boot is a live session.
static LIVE: AtomicBool = AtomicBool::new(false);

/// The boot volume's live flag file.
pub const FLAG_PATH: &str = r"\hydra\live";

/// Looks for [`FLAG_PATH`] on the boot volume `root` (before the hardware takeover).
///
/// # Arguments
/// * `root` - The boot volume's root directory.
pub fn detect(root: &mut uefi::proto::media::file::Directory) {
    let mut buf = [0u16; 32];
    let Some(path) = crate::shell::fs::path_to_cstr16(FLAG_PATH, &mut buf) else { return };
    if root.open(path, uefi::proto::media::file::FileMode::Read, uefi::proto::media::file::FileAttribute::empty()).is_ok() {
        LIVE.store(true, Ordering::Relaxed);
        crate::kprintln!("[live] {} found on the boot volume: live session", FLAG_PATH);
    }
}

/// Whether Hydra runs as a live session (from the USB stick).
///
/// # Returns
/// `true` if the boot volume had the live flag.
pub fn is_live() -> bool {
    LIVE.load(Ordering::Relaxed)
}
