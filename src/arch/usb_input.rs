//! # USB keyboards and pointers
//!
//! The xHCI host controller and its HID devices are driven by `usb-driver`, a Ring 3
//! program (`userland/drivers/usb-driver`). This module is the kernel's side: a task that
//! asks the driver for input whenever the controller interrupts (and twice a second, so a
//! lost interrupt costs little) and hands each record to the same code the PS/2 keyboard
//! and mouse interrupts use, so USB input reaches the console, Hydra's compositor and the
//! Linux event devices (`/dev/input/event*`, read by KDE) exactly as PS/2 input does.

use crate::ipc::protocol::{ENDPOINT_INPUT_DEV, MSG_INPUT_READ, MSG_INPUT_REPLY};
use crate::ipc::service;
use crate::ipc::Message;
use crate::task::wait::WaitQueue;

/// Woken by the controller's interrupt (see [`service::notify_on_irq`]).
static USB_WQ: WaitQueue = WaitQueue::new();

/// Longest wait between two requests (ticks of 10 ms).
const POLL_TICKS: u64 = 50;

/// Starts the input task if the USB driver runs. Called after the supervisor started the
/// drivers.
pub fn start() {
    if service::is_online(ENDPOINT_INPUT_DEV) {
        service::notify_on_irq(ENDPOINT_INPUT_DEV, &USB_WQ);
        crate::task::spawn("usb-input", input_task, crate::task::TaskPriority::Normal);
    }
}

/// Hands one 8-byte record from the driver to the input code (with interrupts off, as in
/// the PS/2 interrupt handlers whose state it shares).
fn deliver(r: &[u8]) {
    let word = |i: usize| i16::from_le_bytes([r[i], r[i + 1]]);
    x86_64::instructions::interrupts::without_interrupts(|| match r[0] {
        1 => crate::arch::keyboard::handle_scancode(r[1]),
        2 => crate::arch::mouse::inject_relative(word(2) as i32, word(4) as i32, r[6] as i8 as i32, r[1]),
        3 => {
            let (x, y) = (u16::from_le_bytes([r[2], r[3]]) as u32, u16::from_le_bytes([r[4], r[5]]) as u32);
            crate::arch::mouse::inject_absolute(x, y, 0xFFFF, r[6] as i8, r[1]);
        }
        _ => {}
    });
}

/// The input task: one request per interrupt (or per [`POLL_TICKS`]).
fn input_task() {
    let mut records = alloc::vec::Vec::new();
    loop {
        // Interrupts counted before the request: one arriving while it is in progress
        // (whose wakeup the request's own wait consumes) makes the next request follow at once
        let irqs = USB_WQ.wakes();
        records.clear();
        let got = {
            // A queued call: this task holds no kernel locks, so everything else keeps
            // running while the driver works (a hand-off here stalled every CPU's kernel
            // entries for each poll)
            let _window = service::hold_window_queued(ENDPOINT_INPUT_DEV);
            match service::call_queued(ENDPOINT_INPUT_DEV, Message::with_args(MSG_INPUT_READ, [0; 4]), service::CALL_TIMEOUT_TICKS) {
                Ok(r) if r.label == MSG_INPUT_REPLY && (r.args[0] as i64) >= 0 => {
                    if let Some(w) = service::window(ENDPOINT_INPUT_DEV) {
                        let n = (r.args[1] as usize).min(w.len() / 8);
                        records.extend_from_slice(&w[..n * 8]);
                    }
                    true
                }
                _ => false,
            }
        };
        for r in records.chunks_exact(8) {
            deliver(r);
        }
        if !got {
            // The driver died or is restarting: the supervisor revives it; try again later
            USB_WQ.unregister();
            crate::task::wait::wait(Some(crate::arch::pit::ticks() + 100));
            continue;
        }
        USB_WQ.register();
        if USB_WQ.wakes() != irqs {
            USB_WQ.unregister();
            continue;
        }
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + POLL_TICKS));
    }
}
