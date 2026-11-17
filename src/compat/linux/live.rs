//! # Live session (Group F)
//!
//! Hydra started from its USB stick ("try Hydra"): the stick's EFI system partition holds the
//! file `\hydra\live` (see the installer's LAYOUT.md), found at boot by
//! [`crate::arch::bootdisk`], which also writes `/run/hydra/live` for programs. Then
//! - the console logs in without a password (there is nothing on the stick to protect, and
//!   nobody has an account yet),
//! - and the live session's files are written into the system (`super::devices`, the Group F
//!   block): the user `live` with automatic login on the login screen, "Install Hydra" on the
//!   desktop, the "You are trying Hydra" notice.

/// Whether Hydra runs as a live session (from the USB stick).
///
/// # Returns
/// `true` if the boot volume had the live flag.
pub fn is_live() -> bool {
    crate::arch::bootdisk::info().live
}
