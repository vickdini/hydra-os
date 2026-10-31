//! # Shell Command: Video Framebuffer Mode & Diagnostics (`video`, `gop`, `fb`)
//!
//! Provides the `video` command reporting linear framebuffer dimensions, stride, and video RAM address.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;
use crate::video;

/// Shell command inspecting GOP framebuffer hardware mode parameters.
pub struct VideoCommand;

impl Command for VideoCommand {
    fn name(&self) -> &'static str {
        "video"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["gop", "fb"]
    }

    fn description(&self) -> &'static str {
        "Inspect hardware display resolution or run visual framebuffer test patterns"
    }

    fn usage(&self) -> &'static str {
        "video [info | test | clear]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let subcmd = args.first().copied().unwrap_or("info");

        match subcmd {
            "test" => {
                let mut guard = video::VIDEO_CONSOLE.lock();
                if let Some(ref mut console) = *guard {
                    let fb = console.framebuffer_mut();
                    let w = fb.width();
                    let h = fb.height();

                    // Draw 8 standard color bars across top third of screen
                    // Colors: White, Yellow, Cyan, Green, Magenta, Red, Blue, Black
                    let colors = [
                        (255, 255, 255), // White
                        (255, 255, 0),   // Yellow
                        (0, 255, 255),   // Cyan
                        (0, 255, 0),     // Green
                        (255, 0, 255),   // Magenta
                        (255, 0, 0),     // Red
                        (0, 0, 255),     // Blue
                        (32, 32, 32),    // Dark Gray/Black
                    ];

                    let bar_w = w / colors.len();
                    let bar_h = h / 4;
                    for (i, &(r, g, b)) in colors.iter().enumerate() {
                        fb.fill_rect(i * bar_w, 0, bar_w, bar_h, r, g, b);
                    }

                    // Draw a sample centered desktop GUI window frame (Wayland preview)
                    let win_w = 400.min(w - 40);
                    let win_h = 200.min(h - bar_h - 40);
                    let win_x = (w - win_w) / 2;
                    let win_y = bar_h + 20;

                    // Window shadow & body
                    fb.fill_rect(win_x + 4, win_y + 4, win_w, win_h, 16, 16, 16);
                    fb.fill_rect(win_x, win_y, win_w, win_h, 38, 42, 54);

                    // Window title bar
                    fb.fill_rect(win_x, win_y, win_w, 28, 24, 110, 185);

                    // Window control buttons (close, minimize, maximize)
                    fb.fill_rect(win_x + 8, win_y + 8, 12, 12, 235, 75, 75);
                    fb.fill_rect(win_x + 26, win_y + 8, 12, 12, 235, 185, 75);
                    fb.fill_rect(win_x + 44, win_y + 8, 12, 12, 75, 215, 115);

                    // Window title text
                    fb.draw_string(
                        win_x + 68,
                        win_y + 6,
                        "Hydra OS - Wayland Compositor Preview",
                        (255, 255, 255),
                        (24, 110, 185),
                    );

                    // Window interior text
                    fb.draw_string(
                        win_x + 16,
                        win_y + 48,
                        "Hardware Framebuffer Direct Render",
                        (220, 220, 220),
                        (38, 42, 54),
                    );
                    fb.draw_string(
                        win_x + 16,
                        win_y + 72,
                        "Resolution: Linear 32 bpp ARGB/ABGR",
                        (140, 200, 255),
                        (38, 42, 54),
                    );
                    fb.draw_string(
                        win_x + 16,
                        win_y + 96,
                        "Autonomous Kernel Display Driver Active",
                        (120, 235, 140),
                        (38, 42, 54),
                    );

                    set_color(Color::LightGreen, Color::Black);
                    println!("[+] Graphical test pattern & Wayland preview window rendered to screen.");
                    state.last_status = 0;
                } else {
                    set_color(Color::LightRed, Color::Black);
                    println!("[!] Error: GOP video console is not active");
                    state.last_status = 1;
                }
            }
            "clear" => {
                video::clear_screen();
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Framebuffer display cleared.");
                state.last_status = 0;
            }
            "info" | _ => {
                match video::get_video_info() {
                    Some(info) => {
                        set_color(Color::LightCyan, Color::Black);
                        println!("\nHardware Video Subsystem & Framebuffer Statistics:");
                        set_color(Color::White, Color::Black);
                        println!("  Driver Status:      ONLINE (Direct GOP Linear Framebuffer)");
                        println!("  Resolution:         {} x {} pixels (32 bpp)", info.width, info.height);
                        println!("  Pixel Stride:       {} pixels/scanline ({} bytes)",
                            info.stride, info.stride * 4);
                        println!("  Pixel Encoding:     {}",
                            if info.is_bgr { "BGR888 (Little-Endian)" } else { "RGB888" });
                        println!("  Video Memory Base:  {:#x}", info.base_ptr as u64);
                        println!("  Framebuffer Size:   {} bytes ({} MiB)",
                            info.size, info.size / (1024 * 1024));
                        println!("  Text Terminal Grid: {} columns x {} rows (8x16 font)",
                            info.text_cols, info.text_rows);
                        println!("  Kernel VMM Status:  Identity-mapped in Hydra Autonomous PML4\n");
                        state.last_status = 0;
                    }
                    None => {
                        set_color(Color::Yellow, Color::Black);
                        println!("\n[!] GOP Video Driver is offline (running in UEFI text mode)\n");
                        state.last_status = 1;
                    }
                }
            }
        }
    }
}
