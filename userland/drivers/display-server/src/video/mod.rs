//! The desktop: an off-screen canvas ([`compositor`]), window bookkeeping ([`wayland`]),
//! the Plasma-style shell drawn on it ([`plasma`]), and the screen it is copied to
//! ([`framebuffer`]).

/// 32-bit software alpha compositor and window surface rendering.
#[allow(dead_code)] // the full drawing API, not all of which the desktop uses
pub mod compositor;
/// The 8x16 console font, shared with the kernel's text console.
#[path = "../../../../../src/video/font.rs"]
pub mod font;
/// The linear framebuffer, mapped into this process.
pub mod framebuffer;
/// KDE Plasma-style desktop shell rendering (panel, launcher, widgets).
pub mod plasma;
/// Window surfaces, focus, and input routing.
#[allow(dead_code)]
pub mod wayland;
