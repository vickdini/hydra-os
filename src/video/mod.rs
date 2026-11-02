//! # Video Subsystem: Framebuffer, Text Console, and Display Client
//!
//! Provides the UEFI Graphics Output Protocol (GOP) linear framebuffer, the kernel's
//! bitmap text console, and the client side of the display server.
//!
//! ## Architectural Role & Design Rationale
//!
//! Modern graphical displays in UEFI systems provide a linear frame buffer configured via GOP.
//! The kernel keeps only what it needs to print: the framebuffer and a text console with an
//! embedded 8x16 font. The graphical desktop (compositor, window management, the
//! Plasma-style shell) is the display server, a Ring 3 program (`userland/drivers/display-server`)
//! that the supervisor starts with the framebuffer granted to it; `display` talks to it.
//!
//! ## Key Modules
//!
//! - `gop`: Discovers and maps the UEFI GOP linear framebuffer before ExitBootServices.
//! - `framebuffer`: 32-bit ARGB/BGR canvas abstraction and drawing primitives.
//! - `font`: Embedded 8x16 VGA font glyphs (shared with the display server).
//! - [`console`]: Terminal emulation layer rendering scrolling text onto the graphical framebuffer.
//! - `display`: Requests to the display server (input events, frames).

/// Graphical text console emulation backed by the GOP framebuffer.
pub mod console;
/// Client of the Ring 3 display server.
pub mod display;
/// Embedded 8x16 bitmap font glyph table and character blitting.
pub mod font;
/// Linear framebuffer memory abstraction and pixel manipulation primitives.
pub mod framebuffer;
/// UEFI Graphics Output Protocol (GOP) discovery and hardware mode query.
pub mod gop;

pub use console::{clear_screen, is_active, set_colors, write_str, VideoConsole, VIDEO_CONSOLE};
pub use framebuffer::Framebuffer;
pub use gop::{get_video_info, init_gop, VideoModeInfo};

/// Executes a closure with mutable access to the global display Framebuffer.
pub fn with_framebuffer<R>(f: impl FnOnce(&mut Framebuffer) -> R) -> Option<R> {
    VIDEO_CONSOLE.lock().as_mut().map(|vc| f(vc.framebuffer_mut()))
}
