//! # Video Subsystem: Ring 3 Display & Wayland Compositor Server
//!
//! Provides the unprivileged microkernel display server daemon, event routing,
//! and linear framebuffer blitter.
//!
//! ## Architectural Role & Design Rationale
//!
//! In monolithic operating systems, the graphical display server and window compositor
//! execute either within kernel space (e.g. legacy Windows GDI/DirectX drivers) or require
//! elevated root privileges to access raw `/dev/fb0` or `/dev/dri/card0`.
//!
//! Under Hydra's microkernel architecture, graphical rendering is completely evicted from
//! Ring 0 into an unprivileged Ring 3 service daemon:
//! 1. The microkernel reserves [`crate::ipc::ENDPOINT_DISPLAY_DEV`] (`0x23`) as a rendezvous channel.
//! 2. The display server requests hardware display properties via [`crate::ipc::protocol::MSG_FB_GET_INFO`].
//! 3. Video RAM is mapped into the display daemon's private address space using `sys_physmap`.
//! 4. Input devices (mouse motion, clicks, and keystrokes) are reflected across the endpoint as
//!    [`crate::ipc::protocol::MSG_FB_INPUT_EVENT`].
//! 5. Off-screen surfaces and the KDE Plasma desktop shell are composited off-screen and blitted
//!    directly to user-mapped VRAM with zero kernel mode transitions in the render loop.
//!
//! ## Key Types & Interfaces
//!
//! - [`DisplayServer`]: The display controller and Wayland surface manager instance.
//! - [`USE_DISPLAY_ENDPOINT`]: Global routing flag for microkernel display redirection.
//! - [`set_use_display_endpoint`]: Controls whether display events route through IPC.
//! - [`run_user_display_daemon`]: Entry point for the user-space display server process.
//! - [`forward_mouse_event`]: Marshals pointer updates across [`crate::ipc::ENDPOINT_DISPLAY_DEV`].
//! - [`forward_key_char`]: Marshals keystrokes across [`crate::ipc::ENDPOINT_DISPLAY_DEV`].
//!
//! ## Concurrency & Safety
//!
//! All inter-task communications flow through bounded lock-free circular queues. Direct Video
//! RAM writes in user space are confined to the page frames mapped via `sys_physmap`.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ipc::endpoint::get_system_endpoint;
use crate::ipc::protocol::{
    MSG_FB_FLUSH, MSG_FB_GET_INFO, MSG_FB_INPUT_EVENT, MSG_FB_REPLY,
    MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG,
};
use crate::ipc::{Message, ENDPOINT_DISPLAY_DEV};
use crate::video::compositor::Compositor;
use crate::video::gop::{get_video_info, VideoModeInfo};
use crate::video::plasma::render_plasma_desktop;
use crate::video::wayland::WaylandCompositor;
use crate::video::with_framebuffer;

/// Flag indicating whether display and input events should route across the IPC endpoint.
pub static USE_DISPLAY_ENDPOINT: AtomicBool = AtomicBool::new(false);

/// Enables or disables microkernel IPC routing for the display and compositor subsystem.
///
/// # Arguments
///
/// * `enable` - True to route graphical events across [`ENDPOINT_DISPLAY_DEV`]; false for direct kernel rendering.
pub fn set_use_display_endpoint(enable: bool) {
    USE_DISPLAY_ENDPOINT.store(enable, Ordering::Release);
}

/// Unprivileged user-space display server and Wayland compositor instance.
pub struct DisplayServer {
    info: VideoModeInfo,
    user_fb_ptr: Option<*mut u8>,
    canvas: Compositor,
    wayland_comp: WaylandCompositor,
    cursor_x: usize,
    cursor_y: usize,
    frame_counter: u64,
}

impl DisplayServer {
    /// Constructs a new display server managing the given video mode.
    ///
    /// # Arguments
    ///
    /// * `info` - Video mode parameters (resolution, stride, pixel format).
    /// * `user_fb_ptr` - Optional user-space mapped pointer to the linear framebuffer.
    pub fn new(info: VideoModeInfo, user_fb_ptr: Option<*mut u8>) -> Self {
        let width = info.width;
        let height = info.height;
        Self {
            info,
            user_fb_ptr,
            canvas: Compositor::new(width, height),
            wayland_comp: WaylandCompositor::new(width, height),
            cursor_x: width / 2,
            cursor_y: height / 2,
            frame_counter: 0,
        }
    }

    /// Returns a reference to the active video mode information.
    pub fn info(&self) -> &VideoModeInfo {
        &self.info
    }

    /// Returns a mutable reference to the internal Wayland compositor.
    pub fn wayland_mut(&mut self) -> &mut WaylandCompositor {
        &mut self.wayland_comp
    }

    /// Returns an immutable reference to the off-screen compositor canvas.
    pub fn canvas(&self) -> &Compositor {
        &self.canvas
    }

    /// Dispatches an incoming IPC message and produces a protocol reply.
    ///
    /// # Arguments
    ///
    /// * `msg` - The received IPC message envelope.
    ///
    /// # Returns
    ///
    /// A formatted [`Message`] containing the reply status and operation payload.
    pub fn handle_ipc_message(&mut self, msg: &Message) -> Message {
        match msg.label {
            MSG_FB_GET_INFO => {
                let packed_dims = (self.info.width as u64) | ((self.info.height as u64) << 32);
                let packed_stride = (self.info.stride as u64)
                    | ((if self.info.is_bgr { 1u64 } else { 0u64 }) << 32);
                Message::with_args(
                    MSG_FB_REPLY,
                    [
                        self.info.base_ptr as u64,
                        packed_dims,
                        packed_stride,
                        self.info.size as u64,
                    ],
                )
            }
            MSG_FB_FLUSH => {
                self.render_and_flip(self.cursor_x, self.cursor_y);
                Message::with_args(MSG_FB_REPLY, [0, 0, 0, 0])
            }
            MSG_FB_INPUT_EVENT => {
                let event_type = msg.args[0];
                match event_type {
                    // Mouse motion
                    1 => {
                        let px = (msg.args[1] & 0xFFFF_FFFF) as usize;
                        let py = ((msg.args[1] >> 32) & 0xFFFF_FFFF) as usize;
                        self.cursor_x = px;
                        self.cursor_y = py;
                        self.wayland_comp.handle_mouse_move(
                            px,
                            py,
                            self.info.width,
                            self.info.height,
                        );
                    }
                    // Mouse button
                    2 => {
                        let px = (msg.args[1] & 0xFFFF_FFFF) as usize;
                        let py = ((msg.args[1] >> 32) & 0xFFFF_FFFF) as usize;
                        self.cursor_x = px;
                        self.cursor_y = py;
                        let left_pressed = (msg.args[2] & 1) != 0;
                        let left_held = (msg.args[2] & 2) != 0;

                        if left_pressed {
                            self.wayland_comp.handle_mouse_down(
                                px,
                                py,
                                self.info.width,
                                self.info.height,
                            );
                        } else if !left_held {
                            self.wayland_comp.handle_mouse_up();
                        }
                    }
                    // Keyboard input
                    3 => {
                        let char_code = msg.args[1] as u32;
                        if let Some(ch) = core::char::from_u32(char_code) {
                            self.wayland_comp.handle_key_char(ch);
                        }
                    }
                    _ => {}
                }
                Message::with_args(MSG_FB_REPLY, [0, 0, 0, 0])
            }
            MSG_SUPERVISOR_PING => {
                Message::with_args(MSG_SUPERVISOR_PONG, [msg.args[0], 1, 0, 0])
            }
            _ => Message::with_args(MSG_FB_REPLY, [(-38i64) as u64, 0, 0, 0]),
        }
    }

    /// Renders the complete KDE Plasma desktop shell and blits it to video RAM.
    ///
    /// # Arguments
    ///
    /// * `cursor_x` - Current horizontal mouse pointer coordinate.
    /// * `cursor_y` - Current vertical mouse pointer coordinate.
    pub fn render_and_flip(&mut self, cursor_x: usize, cursor_y: usize) {
        self.cursor_x = cursor_x;
        self.cursor_y = cursor_y;
        render_plasma_desktop(
            &mut self.canvas,
            &self.wayland_comp,
            cursor_x,
            cursor_y,
            self.frame_counter,
        );
        self.flip();
        self.frame_counter = self.frame_counter.wrapping_add(1);
    }

    /// Transfers the off-screen canvas to linear video memory.
    ///
    /// Uses unprivileged direct memory copies when user VRAM mapping is present; falls back
    /// to kernel framebuffer routines when running in early initialization mode.
    pub fn flip(&self) {
        if let Some(user_ptr) = self.user_fb_ptr {
            unsafe {
                self.canvas.flip_raw(
                    user_ptr,
                    self.info.width,
                    self.info.height,
                    self.info.stride,
                    self.info.is_bgr,
                );
            }
        } else {
            let _ = with_framebuffer(|fb| {
                self.canvas.flip(fb);
            });
        }
    }
}

/// Forwards a hardware mouse update to the display server over [`ENDPOINT_DISPLAY_DEV`].
///
/// Returns `Ok(())` immediately if [`USE_DISPLAY_ENDPOINT`] is disabled.
///
/// # Arguments
///
/// * `event` - The mouse event structure emitted by the PS/2 pointing device driver.
///
/// # Returns
///
/// * `Ok(())` on successful queue delivery.
/// * `Err(&str)` if the display endpoint is missing or congested.
pub fn forward_mouse_event(event: &crate::arch::mouse::MouseEvent) -> Result<(), &'static str> {
    if !USE_DISPLAY_ENDPOINT.load(Ordering::Relaxed) {
        return Ok(());
    }
    let ep = get_system_endpoint(ENDPOINT_DISPLAY_DEV).ok_or("Display endpoint unavailable")?;

    let packed_pos = (event.state.x as u64) | ((event.state.y as u64) << 32);
    let mut btn_mask: u64 = 0;
    if event.left_pressed {
        btn_mask |= 1;
    }
    if event.state.left_button {
        btn_mask |= 2;
    }
    if event.right_pressed {
        btn_mask |= 4;
    }
    if event.state.right_button {
        btn_mask |= 8;
    }

    let msg = Message::with_args(MSG_FB_INPUT_EVENT, [2, packed_pos, btn_mask, 0]);
    ep.send(msg).map_err(|_| "Display endpoint queue full")
}

/// Forwards a typed keyboard character to the display server over [`ENDPOINT_DISPLAY_DEV`].
///
/// Returns `Ok(())` immediately if [`USE_DISPLAY_ENDPOINT`] is disabled.
///
/// # Arguments
///
/// * `c` - The typed Unicode character to dispatch.
///
/// # Returns
///
/// * `Ok(())` on successful queue delivery.
/// * `Err(&str)` if the display endpoint is missing or congested.
pub fn forward_key_char(c: char) -> Result<(), &'static str> {
    if !USE_DISPLAY_ENDPOINT.load(Ordering::Relaxed) {
        return Ok(());
    }
    let ep = get_system_endpoint(ENDPOINT_DISPLAY_DEV).ok_or("Display endpoint unavailable")?;

    let msg = Message::with_args(MSG_FB_INPUT_EVENT, [3, c as u64, 0, 0]);
    ep.send(msg).map_err(|_| "Display endpoint queue full")
}

/// Unprivileged Ring 3 entry point executing the Wayland display compositor server daemon.
///
/// Discovers video configuration, maps physical Video RAM into unprivileged user memory via
/// `sys_physmap`, and services display requests and reflected input events.
///
/// # Arguments
///
/// * `endpoint_id` - Numeric ID of the rendezvous IPC endpoint to listen on (typically [`ENDPOINT_DISPLAY_DEV`]).
pub fn run_user_display_daemon(endpoint_id: u32) -> ! {
    let info = match get_video_info() {
        Some(i) => i,
        None => loop {
            let _ = crate::syscall::user::sys_sleep(1000);
        },
    };

    // Map physical linear framebuffer into user space address range (0x0000_6000_...)
    let user_ptr = match crate::syscall::user::sys_physmap(info.base_ptr as u64, info.size, 0) {
        Ok(mapped_addr) => Some(mapped_addr as *mut u8),
        Err(_) => None,
    };

    let mut server = DisplayServer::new(info, user_ptr);
    set_use_display_endpoint(true);

    let mut msg = Message::new(0);
    loop {
        // Process any pending IPC requests (input events, flushes, metadata queries)
        while crate::syscall::user::sys_ipc_recv(endpoint_id, &mut msg).is_ok() {
            let reply = server.handle_ipc_message(&msg);
            let _ = crate::syscall::user::sys_ipc_send(endpoint_id, &reply);
        }

        // Render desktop frame and flip directly to user-mapped Video RAM
        server.render_and_flip(server.cursor_x, server.cursor_y);

        // Throttle frame rate to ~60 FPS
        let _ = crate::syscall::user::sys_sleep(16);
    }
}
