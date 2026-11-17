//! # Video Subsystem: the Emergency Text Console and the Boot Splash
//!
//! The kernel keeps only what it needs to show text without any user-space program: the
//! UEFI Graphics Output Protocol (GOP) linear framebuffer, a text console with an embedded
//! 8x16 font, and the boot logo.
//!
//! ## Architectural Role & Design Rationale
//!
//! The desktop is KDE Plasma: KWin draws through the Linux DRM device
//! ([`crate::compat::linux::drm`]), which borrows the framebuffer from this console while a
//! session shows and gives it back on Ctrl+Alt+F1, at logout, and on a kernel panic. The
//! console is what remains when no desktop runs: early boot messages, the Hydra shell and
//! its login, and panic messages. There is no compositor or window drawing in the kernel.
//!
//! ## Key Modules
//!
//! - `gop`: Discovers and maps the UEFI GOP linear framebuffer before ExitBootServices.
//! - `framebuffer`: Pixel, rectangle, glyph and scroll primitives on that framebuffer.
//! - `font`: Embedded 8x16 VGA font glyphs.
//! - [`console`]: Scrolling text terminal (with the ANSI sequences the shell uses) on the framebuffer.
//! - `splash`: The Hydra logo shown during boot instead of the messages.

/// Graphical text console emulation backed by the GOP framebuffer.
pub mod console;
/// Embedded 8x16 bitmap font glyph table and character blitting.
pub mod font;
/// Linear framebuffer memory abstraction and pixel manipulation primitives.
pub mod framebuffer;
/// UEFI Graphics Output Protocol (GOP) discovery and hardware mode query.
pub mod gop;
/// The Hydra logo shown during boot instead of the boot messages.
pub mod splash;

pub use gop::{get_video_info, init_gop, VideoModeInfo};
