//! # Shell Command: KDE Plasma Wayland Desktop Shell
//!
//! Launches the interactive KDE Plasma desktop environment running on the Wayland compositor.
//!
//! ## Architectural Role & Design Rationale
//!
//! Provides a seamless transition between the Ring 0 / Ring 3 text command shell and
//! the double-buffered Wayland graphical desktop shell. When launched, the command
//! activates the double-buffered compositor, routes PS/2 mouse motion and button events,
//! and renders interactive Breeze-themed application windows (Konsole and KSysGuard).
//!
//! Pressing the `Escape` key or selecting "Leave" terminates the graphical session and
//! cleanly restores the interactive microkernel text console.

use uefi::proto::console::text::{Color, Key, ScanCode};
use crate::console::{read_key, set_color};
use crate::shell::command::Command;
use crate::shell::state::ShellState;
use crate::video::{render_plasma_desktop, with_framebuffer, Compositor, WaylandCompositor};

/// Shell command to launch the KDE Plasma Wayland desktop environment.
pub struct PlasmaCommand;

impl Command for PlasmaCommand {
    fn name(&self) -> &'static str {
        "plasma"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["startplasma", "wayland", "gui", "desktop"]
    }

    fn description(&self) -> &'static str {
        "Launch the KDE Plasma Wayland desktop shell (Breeze theme, Konsole, KSysGuard)"
    }

    fn usage(&self) -> &'static str {
        "plasma"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let force_builtin = args.iter().any(|&a| a == "--builtin" || a == "-b");

        // By default, launch the genuine upstream KDE Plasma 6.8 Linux ELF64 binary (/bin/plasmashell.elf)
        // directly in Ring 3 userspace via the Linux ABI & Wayland compositor bridge.
        if !force_builtin {
            let target_elf = if args.iter().any(|&a| a == "--krunner" || a == "krunner") {
                "/bin/krunner.elf"
            } else {
                "/bin/plasmashell.elf"
            };

            let mut elf_buf = alloc::vec![0u8; 2 * 1024 * 1024];
            let mut bytes_read = 0;
            if let Ok(n) = crate::fs::ZfsClient::read_file_by_path(target_elf, &mut elf_buf) {
                bytes_read = n;
            } else if !crate::arch::boot_services::is_hardware_takeover_complete() {
                let fat_path = if target_elf.contains("krunner") {
                    "\\bin\\krunner.elf"
                } else {
                    "\\bin\\plasmashell.elf"
                };
                if let Ok(data) = crate::shell::fs::read_boot_file(fat_path) {
                    let copy_n = data.len().min(elf_buf.len());
                    elf_buf[..copy_n].copy_from_slice(&data[..copy_n]);
                    bytes_read = copy_n;
                }
            }

            if bytes_read > 0 {
                if !crate::arch::boot_services::is_hardware_takeover_complete() {
                    set_color(Color::Yellow, Color::Black);
                    println!(
                        "[*] Auto-transitioning to bare-metal hardware mode to launch Ring 3 KDE Plasma 6.8 binary '{}'...",
                        target_elf
                    );
                    let _ = crate::arch::boot_services::take_hardware_ownership();
                }

                set_color(Color::LightCyan, Color::Black);
                println!(
                    "[*] Launching genuine KDE Plasma 6.8 Linux ELF64 binary '{}' ({} bytes) in Ring 3...",
                    target_elf, bytes_read
                );
                let proc_args = [target_elf];
                match crate::task::spawn_linux_elf(
                    target_elf,
                    &elf_buf[..bytes_read],
                    &proc_args,
                    crate::task::TaskPriority::Normal,
                    state.current_uid,
                    state.current_gid,
                ) {
                    Ok(tid) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!(
                            "[+] KDE Plasma 6.8 process '{}' spawned (Task ID #{}, UID {}, GID {}).",
                            target_elf, tid.0, state.current_uid, state.current_gid
                        );
                        set_color(Color::White, Color::Black);
                        crate::task::wait_task(tid);
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] KDE Plasma 6.8 process '{}' (Task #{}) completed cleanly.", target_elf, tid.0);
                        set_color(Color::White, Color::Black);
                        return;
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("[!] Failed to spawn '{}': {}", target_elf, e);
                        set_color(Color::White, Color::Black);
                    }
                }
            }
        }

        // Verify that hardware GOP video linear framebuffer is active
        let fb_dims = with_framebuffer(|fb| (fb.width(), fb.height()));
        let (width, height) = match fb_dims {
            Some((w, h)) => (w, h),
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error: UEFI GOP Framebuffer not available. Cannot launch Plasma Wayland desktop.");
                return;
            }
        };

        set_color(Color::LightCyan, Color::Black);
        println!("[*] Initializing KDE Plasma Wayland Desktop ({}x{})...", width, height);

        // Ensure PS/2 mouse reporting is active and center the cursor
        crate::arch::mouse::init();
        crate::arch::mouse::set_position(width / 2, height / 2);

        let mut canvas = Compositor::new(width, height);
        let mut wayland_comp = WaylandCompositor::new(width, height);
        let mut frame_counter: u64 = 0;

        // Desktop Interactive Event Loop
        loop {
            // 1. Process Hardware PS/2 Mouse Input
            if let Some(mouse_event) = crate::arch::mouse::poll_mouse(width, height) {
                wayland_comp.handle_mouse_move(
                    mouse_event.state.x,
                    mouse_event.state.y,
                    width,
                    height,
                );

                if mouse_event.left_pressed {
                    wayland_comp.handle_mouse_down(
                        mouse_event.state.x,
                        mouse_event.state.y,
                        width,
                        height,
                    );
                } else if !mouse_event.state.left_button {
                    wayland_comp.handle_mouse_up();
                }
            }

            // 2. Process Keyboard Input
            if let Some(key) = read_key() {
                match key {
                    // Escape key exits back to CLI
                    Key::Special(ScanCode(0x17)) | Key::Special(ScanCode(0x01)) => {
                        break;
                    }
                    Key::Printable(ch) => {
                        let c = (u16::from(ch) as u8) as char;
                        if c == '\x1b' {
                            // Escape character
                            break;
                        }
                        wayland_comp.handle_key_char(c);
                    }

                    _ => {}
                }
            }

            // 3. Render Complete Plasma Breeze Desktop to Off-Screen Canvas
            let mouse_state = crate::arch::mouse::current_state();
            render_plasma_desktop(
                &mut canvas,
                &wayland_comp,
                mouse_state.x,
                mouse_state.y,
                frame_counter,
            );

            // 4. Flip Double Buffer to Physical Framebuffer
            with_framebuffer(|fb| {
                canvas.flip(fb);
            });

            frame_counter = frame_counter.wrapping_add(1);

            // Bounded pause to throttle frame rate to ~60 FPS and avoid hogging CPU
            for _ in 0..12_000 {
                core::hint::spin_loop();
            }
        }

        // Clean exit: Clear screen and restore text console
        crate::video::clear_screen();
        set_color(Color::LightGreen, Color::Black);
        println!("[+] Exited KDE Plasma Wayland session. Returned to Hydra shell.");
    }
}
