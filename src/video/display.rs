//! # Video Subsystem: Display Server Client
//!
//! The graphical desktop belongs to the display server, a Ring 3 program the supervisor
//! starts with the framebuffer granted to it. The kernel forwards input to it and asks it
//! for frames over [`crate::ipc::protocol::ENDPOINT_DISPLAY_DEV`] (see [`crate::ipc::service`]).

use crate::ipc::protocol::{ENDPOINT_DISPLAY_DEV, MSG_FB_FLUSH, MSG_FB_INPUT_EVENT};
use crate::ipc::service::{self, CALL_TIMEOUT_TICKS};
use crate::ipc::Message;

/// Whether the display server is running.
pub fn is_online() -> bool {
    service::is_online(ENDPOINT_DISPLAY_DEV)
}

/// Sends a request and returns the server's status word.
fn request(label: u32, args: [u64; 4]) -> Result<u64, i64> {
    let reply = service::call(ENDPOINT_DISPLAY_DEV, Message::with_args(label, args), CALL_TIMEOUT_TICKS)?;
    match reply.args[0] as i64 {
        e if e < 0 => Err(e),
        v => Ok(v as u64),
    }
}

/// Passes a mouse update (position and buttons) to the desktop.
pub fn mouse_event(event: &crate::arch::mouse::MouseEvent) -> Result<(), i64> {
    let pos = event.state.x as u64 | (event.state.y as u64) << 32;
    let buttons = event.left_pressed as u64
        | (event.state.left_button as u64) << 1
        | (event.right_pressed as u64) << 2
        | (event.state.right_button as u64) << 3;
    request(MSG_FB_INPUT_EVENT, [2, pos, buttons, 0]).map(|_| ())
}

/// Passes a typed character to the focused window.
pub fn key_char(c: char) -> Result<(), i64> {
    request(MSG_FB_INPUT_EVENT, [3, c as u64, 0, 0]).map(|_| ())
}

/// Has the desktop drawn and shown.
pub fn flush() -> Result<(), i64> {
    request(MSG_FB_FLUSH, [0; 4]).map(|_| ())
}
