pub mod compositor;
pub mod console;
pub mod font;
pub mod framebuffer;
pub mod gop;
pub mod plasma;
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
