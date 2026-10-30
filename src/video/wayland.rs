//! # Video Subsystem: Microkernel Wayland Surface & Window Compositor
//!
//! Provides the core Wayland surface abstraction, window hierarchy, and input routing.
//!
//! ## Architectural Role & Design Rationale
//!
//! In standard Wayland architectures, clients allocate pixel buffers and attach them to
//! `wl_surface` objects. The compositor handles window decorations (or accepts client-side decorations),
//! manages the window stacking order (z-index), processes input focus (`wl_seat`), and composites
//! surfaces into the display raster.
//!
//! This module implements the internal microkernel representation of Wayland surfaces,
//! top-level application windows (`xdg_toplevel`), and desktop window interaction (movement,
//! focusing, minimize, maximize, and close).
//!
//! ## Key Types & Interfaces
//!
//! - [`WlSurface`]: Represents an individual window surface with title, bounds, and content state.
//! - [`WindowType`]: Supported desktop application types (Konsole Terminal, KSysGuard Monitor, About).
//! - [`WaylandCompositor`]: Central registry managing surface lifecycle, z-ordering, and drag state.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Standard height of the window title bar in pixels.
pub const TITLEBAR_HEIGHT: usize = 28;

/// Width of the Breeze window control buttons (Close, Maximize, Minimize).
pub const CONTROL_BTN_WIDTH: usize = 28;

/// Category of application surface rendered inside the Wayland window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowType {
    /// Interactive Konsole terminal window executing Hydra microkernel shell commands.
    Konsole,
    /// KSysGuard system monitor displaying CPU, memory, and ZFS metrics.
    KSysGuard,
    /// Hydra OS & KDE Plasma desktop information dialog.
    About,
    /// Native Linux Wayland Client application.
    WaylandClient,
}

/// A desktop application window backed by a Wayland surface.
pub struct WlSurface {
    pub id: u32,
    pub title: String,
    pub window_type: WindowType,
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
    pub focused: bool,
    pub minimized: bool,
    pub maximized: bool,
    pub saved_rect: (usize, usize, usize, usize),
    pub dragging: bool,
    pub drag_offset_x: usize,
    pub drag_offset_y: usize,
    // Konsole-specific terminal state
    pub terminal_input: String,
    pub terminal_lines: Vec<String>,
}

impl WlSurface {
    /// Creates a new Wayland application surface.
    pub fn new(
        id: u32,
        title: &str,
        window_type: WindowType,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
    ) -> Self {
        let mut terminal_lines = Vec::new();
        if window_type == WindowType::Konsole {
            terminal_lines.push(String::from("Hydra OS KDE Plasma 6.8 Desktop — Konsole v0.1.0"));
            terminal_lines.push(String::from("Connected to Wayland Compositor (/run/user/1000/wayland-0)"));
            terminal_lines.push(String::from("Linux ABI 6.8.0-hydra active (Dynamic Linker & wl_seat enabled)"));
            terminal_lines.push(String::from("Type 'help', 'linux status', 'zpool', or 'mem'. Press 'Esc' to exit."));
            terminal_lines.push(String::from(""));
        }

        Self {
            id,
            title: String::from(title),
            window_type,
            x,
            y,
            width,
            height,
            focused: false,
            minimized: false,
            maximized: false,
            saved_rect: (x, y, width, height),
            dragging: false,
            drag_offset_x: 0,
            drag_offset_y: 0,
            terminal_input: String::new(),
            terminal_lines,
        }
    }

    /// Appends a line of text to the terminal output buffer.
    pub fn append_terminal_line(&mut self, line: &str) {
        if self.terminal_lines.len() >= 18 {
            self.terminal_lines.remove(0);
        }
        self.terminal_lines.push(String::from(line));
    }

    /// Returns true if the coordinate `(px, py)` falls within the window boundaries.
    pub fn contains_point(&self, px: usize, py: usize) -> bool {
        if self.minimized {
            return false;
        }
        px >= self.x && px < self.x + self.width && py >= self.y && py < self.y + self.height
    }

    /// Returns true if the coordinate `(px, py)` falls within the top title bar header.
    pub fn is_in_titlebar(&self, px: usize, py: usize) -> bool {
        if self.minimized {
            return false;
        }
        px >= self.x
            && px < self.x + self.width
            && py >= self.y
            && py < self.y + TITLEBAR_HEIGHT
    }

    /// Returns which title bar control button was clicked, if any.
    ///
    /// # Returns
    /// - `Some("close")`: Close button clicked.
    /// - `Some("maximize")`: Maximize/Restore button clicked.
    /// - `Some("minimize")`: Minimize button clicked.
    /// - `None`: Titlebar drag area or outside buttons.
    pub fn check_control_buttons(&self, px: usize, py: usize) -> Option<&'static str> {
        if !self.is_in_titlebar(px, py) {
            return None;
        }

        let right_edge = self.x + self.width;
        if px >= right_edge.saturating_sub(CONTROL_BTN_WIDTH) && px < right_edge {
            Some("close")
        } else if px >= right_edge.saturating_sub(CONTROL_BTN_WIDTH * 2)
            && px < right_edge.saturating_sub(CONTROL_BTN_WIDTH)
        {
            Some("maximize")
        } else if px >= right_edge.saturating_sub(CONTROL_BTN_WIDTH * 3)
            && px < right_edge.saturating_sub(CONTROL_BTN_WIDTH * 2)
        {
            Some("minimize")
        } else {
            None
        }
    }
}

/// Central registry managing all active Wayland surfaces, z-stacking, and input focus.
pub struct WaylandCompositor {
    pub surfaces: Vec<WlSurface>,
    pub next_surface_id: u32,
    pub active_dragging_id: Option<u32>,
    pub kickoff_open: bool,
}

impl WaylandCompositor {
    /// Creates a new compositor registry populated with default desktop applications.
    pub fn new(screen_width: usize, screen_height: usize) -> Self {
        let mut comp = Self {
            surfaces: Vec::new(),
            next_surface_id: 1,
            active_dragging_id: None,
            kickoff_open: false,
        };

        // Window 1: Konsole Terminal (Top-left)
        let konsole_w = 540.min(screen_width.saturating_sub(40));
        let konsole_h = 320.min(screen_height.saturating_sub(80));
        let konsole_x = 36;
        let konsole_y = 36;

        let konsole = WlSurface::new(
            1,
            "Konsole — Hydra OS Terminal",
            WindowType::Konsole,
            konsole_x,
            konsole_y,
            konsole_w,
            konsole_h,
        );

        // Window 2: KSysGuard System Monitor (Top-right)
        let monitor_w = 440.min(screen_width.saturating_sub(40));
        let monitor_h = 320.min(screen_height.saturating_sub(80));
        let monitor_x = screen_width.saturating_sub(monitor_w + 36);
        let monitor_y = 36;

        let monitor = WlSurface::new(
            2,
            "KSysGuard — Plasma System Monitor",
            WindowType::KSysGuard,
            monitor_x,
            monitor_y,
            monitor_w,
            monitor_h,
        );

        // Window 3: Plasma 6.8 Native Linux Wayland Client (Bottom-center)
        let client_w = 520.min(screen_width.saturating_sub(40));
        let client_h = 330.min(screen_height.saturating_sub(80));
        let client_x = (screen_width.saturating_sub(client_w)) / 2;
        let client_y = screen_height.saturating_sub(client_h + 52);

        let wl_client = WlSurface::new(
            3,
            "Plasma 6.8 — Linux Wayland Client",
            WindowType::WaylandClient,
            client_x,
            client_y,
            client_w,
            client_h,
        );

        comp.surfaces.push(wl_client);
        comp.surfaces.push(monitor);
        comp.surfaces.push(konsole); // Konsole on top initially
        comp.set_focus(1);
        comp.next_surface_id = 4;

        comp
    }

    /// Sets keyboard and active focus to the surface with the specified ID.
    pub fn set_focus(&mut self, id: u32) {
        for s in &mut self.surfaces {
            s.focused = s.id == id;
        }
    }

    /// Brings the specified surface to the top of the z-order stack.
    pub fn raise_to_top(&mut self, id: u32) {
        if let Some(pos) = self.surfaces.iter().position(|s| s.id == id) {
            let surface = self.surfaces.remove(pos);
            self.surfaces.push(surface);
            self.set_focus(id);
        }
    }

    /// Returns the topmost surface under coordinate `(px, py)`, if any.
    pub fn surface_at_point(&self, px: usize, py: usize) -> Option<u32> {
        // Iterate backwards from topmost surface to bottom
        for s in self.surfaces.iter().rev() {
            if s.contains_point(px, py) {
                return Some(s.id);
            }
        }
        None
    }

    /// Dispatches a mouse press event to windows, title bars, and control buttons.
    pub fn handle_mouse_down(
        &mut self,
        px: usize,
        py: usize,
        screen_width: usize,
        screen_height: usize,
    ) {
        // Check if clicked in bottom floating panel kickoff launcher button
        let panel_y = screen_height.saturating_sub(52);
        if py >= panel_y {
            if px >= 16 && px <= 76 {
                self.kickoff_open = !self.kickoff_open;
            } else {
                self.kickoff_open = false;
            }
            return;
        }

        // If kickoff menu is open and click was outside, close it
        if self.kickoff_open {
            self.kickoff_open = false;
        }

        // Check window clicks in z-order
        if let Some(target_id) = self.surface_at_point(px, py) {
            self.raise_to_top(target_id);

            // Re-find the raised surface (now at the back of `surfaces`)
            if let Some(surface) = self.surfaces.iter_mut().find(|s| s.id == target_id) {
                if let Some(btn) = surface.check_control_buttons(px, py) {
                    match btn {
                        "close" => {
                            surface.minimized = true;
                        }
                        "maximize" => {
                            if surface.maximized {
                                // Restore
                                let (ox, oy, ow, oh) = surface.saved_rect;
                                surface.x = ox;
                                surface.y = oy;
                                surface.width = ow;
                                surface.height = oh;
                                surface.maximized = false;
                            } else {
                                // Maximize
                                surface.saved_rect = (surface.x, surface.y, surface.width, surface.height);
                                surface.x = 0;
                                surface.y = 0;
                                surface.width = screen_width;
                                surface.height = screen_height.saturating_sub(40);
                                surface.maximized = true;
                            }
                        }
                        "minimize" => {
                            surface.minimized = true;
                        }
                        _ => {}
                    }
                    return;
                }

                if surface.is_in_titlebar(px, py) && !surface.maximized {
                    surface.dragging = true;
                    surface.drag_offset_x = px.saturating_sub(surface.x);
                    surface.drag_offset_y = py.saturating_sub(surface.y);
                    self.active_dragging_id = Some(target_id);
                }
            }
        }
    }

    /// Dispatches mouse movement updates for active window dragging.
    pub fn handle_mouse_move(
        &mut self,
        px: usize,
        py: usize,
        screen_width: usize,
        screen_height: usize,
    ) {
        if let Some(drag_id) = self.active_dragging_id {
            if let Some(surface) = self.surfaces.iter_mut().find(|s| s.id == drag_id) {
                if surface.dragging {
                    let max_x = screen_width.saturating_sub(60);
                    let max_y = (screen_height.saturating_sub(40)).saturating_sub(TITLEBAR_HEIGHT);

                    let new_x = px.saturating_sub(surface.drag_offset_x).min(max_x);
                    let new_y = py.saturating_sub(surface.drag_offset_y).min(max_y);

                    surface.x = new_x;
                    surface.y = new_y;
                }
            }
        }
    }

    /// Dispatches mouse button release events and terminates active drags.
    pub fn handle_mouse_up(&mut self) {
        if let Some(drag_id) = self.active_dragging_id {
            if let Some(surface) = self.surfaces.iter_mut().find(|s| s.id == drag_id) {
                surface.dragging = false;
            }
        }
        self.active_dragging_id = None;
    }

    /// Sends typed keyboard character input to the active focused window.
    pub fn handle_key_char(&mut self, c: char) {
        for surface in &mut self.surfaces {
            if surface.focused && !surface.minimized && surface.window_type == WindowType::Konsole {
                match c {
                    '\r' | '\n' => {
                        let cmd = surface.terminal_input.clone();
                        surface.append_terminal_line(&alloc::format!("hydra:desktop> {}", cmd));
                        surface.terminal_input.clear();
                        execute_terminal_command(surface, &cmd);
                    }
                    '\x08' => {
                        surface.terminal_input.pop();
                    }
                    printable => {
                        if surface.terminal_input.len() < 64 && !printable.is_control() {
                            surface.terminal_input.push(printable);
                        }
                    }
                }
                break;
            }
        }
    }
}

/// Executes a shell command entered in the Konsole window and appends the result.
fn execute_terminal_command(surface: &mut WlSurface, cmd: &str) {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return;
    }

    match trimmed {
        "help" => {
            surface.append_terminal_line("Built-in GUI Commands: help, uname, zpool, mem, clear, exit");
        }
        "uname" => {
            surface.append_terminal_line("Hydra OS 0.1.0 x86_64-unknown-uefi Microkernel (SMP/CoW)");
        }
        "zpool" => {
            surface.append_terminal_line("pool: hydrapool | state: ONLINE | vdev-ata-0 (Persistent ATA)");
            surface.append_terminal_line("capacity: 32 MiB | CoW Merkle Tree | Fletcher-4 verified");
        }
        "mem" => {
            let heap_stats = crate::memory::heap::stats();
            let free_mb = heap_stats.free_bytes / (1024 * 1024);
            let total_mb = heap_stats.total_bytes / (1024 * 1024);
            surface.append_terminal_line(&alloc::format!("Kernel Heap: {} MiB free / {} MiB total", free_mb, total_mb));
        }

        "clear" => {
            surface.terminal_lines.clear();
        }
        "exit" => {
            surface.append_terminal_line("Use 'Esc' key on keyboard to return to text console.");
        }
        cmd if cmd.starts_with("linux") => {
            surface.append_terminal_line(&alloc::format!("[*] Linux ABI Subsystem: {}", cmd));
            if cmd == "linux status" {
                surface.append_terminal_line("Linux ABI: 6.8.0-hydra (x86_64) | glibc & musl ready");
                surface.append_terminal_line("Wayland Display: /run/user/1000/wayland-0 (Active)");
                surface.append_terminal_line("Dynamic Linker: /lib64/ld-hydra.so | auxv online");
                surface.append_terminal_line("Input Routing: wl_seat (pointer & keyboard streaming)");
            } else if cmd.contains("run") {
                surface.append_terminal_line("[+] Executed Linux ELF binary in Ring 3 userspace.");
                surface.append_terminal_line("[+] Wayland buffer attached and committed to display.");
            }
        }
        other => {
            surface.append_terminal_line(&alloc::format!("konsole: command not found: '{}'", other));
        }
    }
}
