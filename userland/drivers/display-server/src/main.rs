//! # Hydra display server
//!
//! Owns the framebuffer and draws the built-in Plasma-style desktop, in Ring 3 in an
//! address space of its own. The supervisor starts it with the framebuffer's geometry,
//! `fb=<phys>:<width>:<height>:<stride>:<bgr>`, and whether a disk is attached, `disk=ata`
//! (for the system monitor widget); it may map only that framebuffer.
//!
//! Requests on [`ENDPOINT_DISPLAY_DEV`]:
//! - `MSG_FB_GET_INFO`: framebuffer address, `width | height << 32`, `stride | bgr << 32`, size;
//! - `MSG_FB_INPUT_EVENT`: pointer motion (1), button (2) or typed character (3);
//! - `MSG_FB_FLUSH`: draw a frame and show it.

#![no_std]
#![no_main]

extern crate alloc;

mod video;

use core::sync::atomic::{AtomicBool, Ordering};
use hydra_rt::protocol::{ENDPOINT_DISPLAY_DEV, MSG_FB_FLUSH, MSG_FB_GET_INFO, MSG_FB_INPUT_EVENT, MSG_FB_REPLY};
use hydra_rt::{println, Message, Server};
use video::compositor::Compositor;
use video::framebuffer::Framebuffer;
use video::wayland::WaylandCompositor;

/// What the desktop's widgets report about this process's memory.
mod memory {
    pub mod heap {
        /// Heap totals in bytes.
        pub struct HeapStats {
            pub total_bytes: usize,
            pub free_bytes: usize,
        }

        /// This server's heap.
        pub fn stats() -> HeapStats {
            let (used, free) = hydra_rt::heap_usage();
            HeapStats { total_bytes: used + free, free_bytes: free }
        }
    }
}

/// What the desktop's widgets report about the disk.
mod arch {
    pub mod ata {
        /// Whether the supervisor reported a disk.
        pub fn is_drive_present() -> bool {
            crate::DISK_PRESENT.load(core::sync::atomic::Ordering::Relaxed)
        }
    }
}

/// Set from the `disk=` argument.
static DISK_PRESENT: AtomicBool = AtomicBool::new(false);

hydra_rt::entry!(main);

/// The desktop and the screen it is shown on.
struct Display {
    fb: Framebuffer,
    phys: u64,
    canvas: Compositor,
    windows: WaylandCompositor,
    cursor: (usize, usize),
    frame: u64,
}

impl Display {
    fn reply(args: [u64; 4]) -> Message {
        Message::new(MSG_FB_REPLY as u64, args)
    }

    fn handle(&mut self, msg: &Message) -> Message {
        let (w, h) = (self.fb.width(), self.fb.height());
        match msg.label as u32 {
            MSG_FB_GET_INFO => Self::reply([
                self.phys,
                w as u64 | (h as u64) << 32,
                self.fb.stride() as u64 | (self.fb.is_bgr() as u64) << 32,
                (self.fb.stride() * h * 4) as u64,
            ]),
            MSG_FB_FLUSH => {
                video::plasma::render_plasma_desktop(&mut self.canvas, &self.windows, self.cursor.0, self.cursor.1, self.frame);
                self.canvas.flip(&mut self.fb);
                self.frame = self.frame.wrapping_add(1);
                Self::reply([0; 4])
            }
            MSG_FB_INPUT_EVENT => {
                let (x, y) = ((msg.args[1] & 0xFFFF_FFFF) as usize, (msg.args[1] >> 32) as usize);
                match msg.args[0] {
                    1 => {
                        self.cursor = (x, y);
                        self.windows.handle_mouse_move(x, y, w, h);
                    }
                    2 => {
                        self.cursor = (x, y);
                        self.windows.handle_mouse_move(x, y, w, h);
                        let (pressed, held) = (msg.args[2] & 1 != 0, msg.args[2] & 2 != 0);
                        if pressed {
                            self.windows.handle_mouse_down(x, y, w, h);
                        } else if !held {
                            self.windows.handle_mouse_up();
                        }
                    }
                    3 => {
                        if let Some(c) = char::from_u32(msg.args[1] as u32) {
                            self.windows.handle_key_char(c);
                        }
                    }
                    _ => return Self::reply([(-22i64) as u64, 0, 0, 0]),
                }
                Self::reply([0; 4])
            }
            _ => Self::reply([(-38i64) as u64, 0, 0, 0]),
        }
    }
}

/// Parses `fb=<phys>:<width>:<height>:<stride>:<bgr>` (numbers in decimal or `0x` hex).
fn parse_fb(arg: &str) -> Option<(u64, usize, usize, usize, bool)> {
    let num = |s: &str| match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    };
    let mut it = arg.strip_prefix("fb=")?.split(':');
    let phys = num(it.next()?)?;
    let w = num(it.next()?)? as usize;
    let h = num(it.next()?)? as usize;
    let stride = num(it.next()?)? as usize;
    let bgr = num(it.next()?)? != 0;
    Some((phys, w, h, stride, bgr))
}

fn main(args: &[&str]) {
    let Some((phys, w, h, stride, bgr)) = args.iter().find_map(|a| parse_fb(a)) else {
        println!("[display-server] no framebuffer given (fb=...)");
        return;
    };
    DISK_PRESENT.store(args.iter().any(|a| *a == "disk=ata"), Ordering::Relaxed);
    let fb = match Framebuffer::map(phys, w, h, stride, bgr) {
        Ok(fb) => fb,
        Err(e) => {
            println!("[display-server] cannot map the framebuffer at {:#x}: error {}", phys, e);
            return;
        }
    };
    let mut server = match Server::register(ENDPOINT_DISPLAY_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[display-server] cannot register on endpoint {:#x}: error {}", ENDPOINT_DISPLAY_DEV, e);
            return;
        }
    };
    let mut display = Display {
        fb,
        phys,
        canvas: Compositor::new(w, h),
        windows: WaylandCompositor::new(w, h),
        cursor: (w / 2, h / 2),
        frame: 0,
    };
    server.serve(|_, msg| display.handle(msg))
}
