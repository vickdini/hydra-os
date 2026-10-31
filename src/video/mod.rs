//! # Video Subsystem: Graphics, Framebuffer, and Wayland Compositor
//!
//! Provides the UEFI Graphics Output Protocol (GOP) linear framebuffer driver, bitmap text console,
//! 32-bit alpha compositor, and Wayland window server.
//!
//! ## Architectural Role & Design Rationale
//!
//! Modern graphical displays in UEFI systems provide a linear frame buffer configured via GOP.
//! This subsystem encapsulates raw Video RAM into a safe 32-bit pixel canvas (`Framebuffer`),
//! renders ASCII text through an embedded 8x16 bitmap font, and runs a double-buffered compositor
//! (`Compositor`) driving both an interactive desktop shell (`render_plasma_desktop`) and
//! native Wayland client windows (`WaylandCompositor`).
//!
//! ## Key Modules
//!
//! - `gop`: Discovers and maps the UEFI GOP linear framebuffer before ExitBootServices.
//! - `framebuffer`: Double-buffered 32-bit ARGB/BGR canvas abstractions and drawing primitives.
//! - `font`: Embedded 8x16 VGA font glyphs and character blitting routines.
//! - [`console`]: Terminal emulation layer rendering scrolling text onto the graphical framebuffer.
//! - `compositor`: Window surface blending, title bars, and Breeze-style desktop controls.
//! - [`wayland`]: Wayland surface registry, focus routing, and window geometry management.
//! - `plasma`: KDE Plasma 6.8 desktop shell rendering (panel, system tray, app launcher, widgets).

/// 32-bit software alpha compositor and window surface rendering.
pub mod compositor;
/// Graphical text console emulation backed by the GOP framebuffer.
pub mod console;
/// Embedded 8x16 bitmap font glyph table and character blitting.
pub mod font;
/// Linear framebuffer memory abstraction and pixel manipulation primitives.
pub mod framebuffer;
/// UEFI Graphics Output Protocol (GOP) discovery and hardware mode query.
pub mod gop;
/// KDE Plasma-styled desktop shell widgets, panel, and wallpaper rendering.
pub mod plasma;
/// Wayland window surfaces, client buffer attachments, and input focus.
pub mod wayland;

pub use compositor::{Color, Compositor};
pub use console::{clear_screen, is_active, set_colors, write_str, VideoConsole, VIDEO_CONSOLE};
pub use framebuffer::Framebuffer;
pub use gop::{get_video_info, init_gop, VideoModeInfo};
pub use plasma::render_plasma_desktop;
pub use wayland::WaylandCompositor;

/// Executes a closure with mutable access to the global display Framebuffer.
pub fn with_framebuffer<R>(f: impl FnOnce(&mut Framebuffer) -> R) -> Option<R> {
    VIDEO_CONSOLE.lock().as_mut().map(|vc| f(vc.framebuffer_mut()))
}
