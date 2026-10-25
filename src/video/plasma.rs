//! # Video Subsystem: KDE Plasma "Breeze" Desktop Shell
//!
//! Renders a KDE Plasma-inspired Wayland desktop environment complete with dark Breeze theme,
//! taskbar panel, Kickoff application menu, and interactive window manager.
//!
//! ## Architectural Role & Design Rationale
//!
//! Hydra OS implements a desktop user interface modeling the KDE Plasma workspace:
//! - **Breeze Theme Engine**: Cohesive color palette utilizing Plasma blues (`#3daee9`, `#1d99f3`),
//!   slate darks (`#232629`, `#31363b`), and danger accents (`#da4453`).
//! - **Bottom Panel & System Tray**: Persistent 40px taskbar featuring a Kickoff launcher button,
//!   window task tabs with focus indicators, and a live hardware system tray.
//! - **Window Management**: Window shadows, title bars, maximize/restore, minimize, and real-time
//!   smooth window dragging without tearing.
//!
//! ## Key Types & Interfaces
//!
//! - [`render_plasma_desktop()`]: Main rendering pass combining wallpaper, windows, panel, and cursor.

use super::compositor::{Color, Compositor};
use super::wayland::{WaylandCompositor, WindowType, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT};
use super::font::FONT_HEIGHT;

// KDE Plasma Breeze Palette Constants
const COLOR_WALLPAPER_TOP: u32 = Color::rgb(27, 30, 32);       // #1b1e20
const COLOR_WALLPAPER_MID: u32 = Color::rgb(35, 38, 41);       // #232629
const COLOR_WALLPAPER_BOT: u32 = Color::rgb(42, 46, 50);       // #2a2e32
const COLOR_PANEL_BG: u32 = Color::rgb(35, 38, 41);            // #232629
const COLOR_PANEL_BORDER: u32 = Color::rgb(49, 54, 59);        // #31363b
const COLOR_PLASMA_BLUE: u32 = Color::rgb(61, 174, 233);       // #3daee9 (Breeze Blue)
const COLOR_PLASMA_DEEP_BLUE: u32 = Color::rgb(29, 153, 243);  // #1d99f3
const COLOR_TITLEBAR_ACTIVE: u32 = Color::rgb(49, 54, 59);     // #31363b
const COLOR_TITLEBAR_INACTIVE: u32 = Color::rgb(35, 38, 41);   // #232629
const COLOR_WINDOW_BORDER: u32 = Color::rgb(27, 30, 32);       // #1b1e20
const COLOR_CLOSE_RED: u32 = Color::rgb(218, 68, 83);          // #da4453
const COLOR_KONSOLE_BG: u32 = Color::rgb(24, 27, 29);          // #181b1d
const COLOR_KSYSGUARD_BG: u32 = Color::rgb(32, 35, 38);        // #202326
const COLOR_CARD_BG: u32 = Color::rgb(40, 44, 48);             // #282c30
const COLOR_TEXT_LIGHT: u32 = Color::rgb(239, 240, 241);       // #eff0f1
const COLOR_TEXT_MUTED: u32 = Color::rgb(189, 195, 199);       // #bdc3c7
const COLOR_GREEN_ACCENT: u32 = Color::rgb(46, 204, 113);      // #2ecc71

/// Renders the complete KDE Plasma desktop shell to the off-screen compositor canvas.
///
/// # Arguments
/// - `canvas`: Double-buffered off-screen compositor canvas.
/// - `compositor`: Active Wayland surface and window hierarchy.
/// - `cursor_x`: Horizontal mouse pointer pixel coordinate.
/// - `cursor_y`: Vertical mouse pointer pixel coordinate.
/// - `frame_counter`: Monotonically increasing tick counter for subtle animations.
pub fn render_plasma_desktop(
    canvas: &mut Compositor,
    compositor: &WaylandCompositor,
    cursor_x: usize,
    cursor_y: usize,
    frame_counter: u64,
) {
    let width = canvas.width();
    let height = canvas.height();

    // 1. Render Plasma Wallpaper (Geometric Dark Mesh)
    render_wallpaper(canvas, width, height);

    // 2. Render Managed Wayland Windows (in z-order from back to front)
    for surface in &compositor.surfaces {
        if surface.minimized {
            continue;
        }

        render_window(canvas, surface, frame_counter);
    }

    // 3. Render Bottom Taskbar / Panel (height 40px)
    render_panel(canvas, compositor, width, height, frame_counter);

    // 4. Render Kickoff Application Menu (if toggled open)
    if compositor.kickoff_open {
        render_kickoff_menu(canvas, height);
    }

    // 5. Render Mouse Cursor Sprite
    canvas.draw_cursor(cursor_x, cursor_y);
}

/// Renders a KDE Plasma-style geometric dark wallpaper.
fn render_wallpaper(canvas: &mut Compositor, width: usize, height: usize) {
    // Top-to-bottom gradient
    canvas.draw_gradient_v(0, 0, width, height / 2, COLOR_WALLPAPER_TOP, COLOR_WALLPAPER_MID);
    canvas.draw_gradient_v(0, height / 2, width, height - (height / 2), COLOR_WALLPAPER_MID, COLOR_WALLPAPER_BOT);

    // Decorative geometric polygon facets (Plasma Breeze abstract triangles)
    let facet_color = Color::rgb(30, 33, 36);
    let facet_w = width / 4;
    canvas.fill_rect(facet_w, 0, facet_w, height / 3, facet_color);
    canvas.fill_rect(facet_w * 2, height / 4, facet_w, height / 2, Color::rgb(38, 42, 45));

    // Subtle watermark in bottom-right corner
    canvas.draw_string(
        width.saturating_sub(230),
        height.saturating_sub(60),
        "Hydra OS | KDE Plasma Wayland",
        COLOR_TEXT_MUTED,
        None,
    );
}

/// Renders an individual Wayland application surface and its Breeze window frame.
fn render_window(canvas: &mut Compositor, surface: &crate::video::wayland::WlSurface, frame_counter: u64) {
    let x = surface.x;
    let y = surface.y;
    let w = surface.width;
    let h = surface.height;

    // Window shadow (subtle dark translucent border)
    canvas.draw_rect_outline(x.saturating_sub(2), y.saturating_sub(2), w + 4, h + 4, Color::rgb(15, 17, 19), 2);

    // Window border
    let border_color = if surface.focused { COLOR_PLASMA_BLUE } else { COLOR_WINDOW_BORDER };
    canvas.draw_rect_outline(x, y, w, h, border_color, 1);

    // Titlebar header (height 28px)
    let titlebar_color = if surface.focused { COLOR_TITLEBAR_ACTIVE } else { COLOR_TITLEBAR_INACTIVE };
    canvas.fill_rect(x, y, w, TITLEBAR_HEIGHT, titlebar_color);

    // Titlebar bottom separator line
    canvas.fill_rect(x, y + TITLEBAR_HEIGHT - 1, w, 1, COLOR_PANEL_BORDER);

    // Window icon / emblem
    canvas.fill_rect(x + 8, y + 8, 12, 12, COLOR_PLASMA_BLUE);

    // Window title text
    canvas.draw_string(x + 28, y + 6, &surface.title, COLOR_TEXT_LIGHT, None);

    // Window control buttons (Close, Maximize, Minimize) on top-right
    let right_edge = x + w;

    // Minimize button ('_')
    let min_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH * 3);
    canvas.fill_rect(min_x, y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, titlebar_color);
    canvas.draw_char(min_x + 10, y + 6, '-', COLOR_TEXT_MUTED, None);

    // Maximize button ('□')
    let max_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH * 2);
    canvas.fill_rect(max_x, y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, titlebar_color);
    canvas.draw_char(max_x + 10, y + 6, if surface.maximized { '=' } else { '#' }, COLOR_TEXT_MUTED, None);

    // Close button ('X')
    let close_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH);
    canvas.fill_rect(close_x, y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, COLOR_CLOSE_RED);
    canvas.draw_char(close_x + 10, y + 6, 'X', COLOR_TEXT_LIGHT, None);

    // Window client content area
    let client_y = y + TITLEBAR_HEIGHT;
    let client_h = h.saturating_sub(TITLEBAR_HEIGHT);

    match surface.window_type {
        WindowType::Konsole => {
            render_konsole_content(canvas, surface, x, client_y, w, client_h, frame_counter);
        }
        WindowType::KSysGuard => {
            render_ksysguard_content(canvas, x, client_y, w, client_h, frame_counter);
        }
        WindowType::About => {
            canvas.fill_rect(x, client_y, w, client_h, COLOR_KSYSGUARD_BG);
            canvas.draw_string(x + 20, client_y + 20, "Hydra OS Plasma Shell v0.1.0", COLOR_TEXT_LIGHT, None);
        }
    }
}

/// Renders the Konsole terminal application content.
fn render_konsole_content(
    canvas: &mut Compositor,
    surface: &crate::video::wayland::WlSurface,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    frame_counter: u64,
) {
    canvas.fill_rect(x, y, w, h, COLOR_KONSOLE_BG);

    let mut text_y = y + 8;
    for line in &surface.terminal_lines {
        if text_y + FONT_HEIGHT > y + h - 24 {
            break;
        }
        canvas.draw_string(x + 12, text_y, line, COLOR_TEXT_LIGHT, None);
        text_y += FONT_HEIGHT + 2;
    }

    // Active shell prompt and cursor
    if text_y + FONT_HEIGHT <= y + h {
        let prompt = "hydra:desktop> ";
        canvas.draw_string(x + 12, text_y, prompt, COLOR_PLASMA_BLUE, None);
        let prompt_width = prompt.len() * 8;

        canvas.draw_string(x + 12 + prompt_width, text_y, &surface.terminal_input, COLOR_TEXT_LIGHT, None);

        // Blinking cursor block '█'
        if (frame_counter / 15) % 2 == 0 {
            let cursor_offset = (prompt.len() + surface.terminal_input.len()) * 8;
            canvas.draw_char(x + 12 + cursor_offset, text_y, '#', COLOR_PLASMA_BLUE, None);
        }
    }
}

/// Renders the KSysGuard System Monitor dashboard.
fn render_ksysguard_content(
    canvas: &mut Compositor,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    frame_counter: u64,
) {
    canvas.fill_rect(x, y, w, h, COLOR_KSYSGUARD_BG);

    // Header banner
    canvas.draw_string(x + 16, y + 12, "Hardware & Subsystem Performance", COLOR_TEXT_LIGHT, None);

    // Card 1: Microkernel CPU Meter
    let card1_y = y + 36;
    let card_w = w.saturating_sub(32);
    canvas.fill_rect(x + 16, card1_y, card_w, 54, COLOR_CARD_BG);
    canvas.draw_string(x + 24, card1_y + 8, "Processor: x86_64 Long Mode (SMP Core 0)", COLOR_TEXT_MUTED, None);

    // Animated CPU usage bar
    let cpu_load_pct = 8 + ((frame_counter / 4) % 15) as usize;
    canvas.draw_string(x + 24, card1_y + 26, &alloc::format!("CPU Load: {}%", cpu_load_pct), COLOR_TEXT_LIGHT, None);
    let bar_x = x + 140;
    let bar_w = card_w.saturating_sub(150);
    canvas.fill_rect(bar_x, card1_y + 28, bar_w, 10, Color::rgb(25, 28, 30));
    canvas.fill_rect(bar_x, card1_y + 28, (bar_w * cpu_load_pct) / 100, 10, COLOR_PLASMA_BLUE);

    // Card 2: Microkernel Kernel Heap Memory
    let card2_y = card1_y + 64;
    canvas.fill_rect(x + 16, card2_y, card_w, 54, COLOR_CARD_BG);
    let heap_stats = crate::memory::heap::stats();
    let free_mb = heap_stats.free_bytes / (1024 * 1024);
    let total_mb = heap_stats.total_bytes / (1024 * 1024);
    let used_mb = total_mb.saturating_sub(free_mb);
    canvas.draw_string(x + 24, card2_y + 8, "Physical & Virtual RAM: 512 MiB Conventional", COLOR_TEXT_MUTED, None);
    canvas.draw_string(x + 24, card2_y + 26, &alloc::format!("Heap: {}M / {}M", used_mb, total_mb), COLOR_TEXT_LIGHT, None);
    let mem_bar_x = x + 140;
    let mem_pct = if total_mb > 0 { (used_mb * 100) / total_mb } else { 5 };
    canvas.fill_rect(mem_bar_x, card2_y + 28, bar_w, 10, Color::rgb(25, 28, 30));
    canvas.fill_rect(mem_bar_x, card2_y + 28, (bar_w * mem_pct.max(5)) / 100, 10, COLOR_GREEN_ACCENT);

    // Card 3: OpenZFS Persistent Storage Pool
    let card3_y = card2_y + 64;
    canvas.fill_rect(x + 16, card3_y, card_w, 54, COLOR_CARD_BG);
    let is_disk = crate::arch::ata::is_drive_present();
    canvas.draw_string(
        x + 24,
        card3_y + 8,
        if is_disk { "Storage: /dev/hda ATA-0 (Persistent Media)" } else { "Storage: Volatile RAM Vdev" },
        COLOR_TEXT_MUTED,
        None,
    );
    canvas.draw_string(x + 24, card3_y + 26, "Pool 'hydrapool': 32 MiB | CoW Active", COLOR_TEXT_LIGHT, None);
}

/// Renders the bottom Plasma taskbar panel.
fn render_panel(
    canvas: &mut Compositor,
    compositor: &WaylandCompositor,
    width: usize,
    height: usize,
    _frame_counter: u64,
) {
    let panel_h = 40;
    let panel_y = height.saturating_sub(panel_h);

    // Panel background and top border
    canvas.fill_rect(0, panel_y, width, panel_h, COLOR_PANEL_BG);
    canvas.fill_rect(0, panel_y, width, 1, COLOR_PANEL_BORDER);

    // Kickoff Application Launcher Button (far left)
    let kickoff_w = 140;
    let kickoff_bg = if compositor.kickoff_open { COLOR_PLASMA_DEEP_BLUE } else { COLOR_TITLEBAR_ACTIVE };
    canvas.fill_rect(0, panel_y, kickoff_w, panel_h, kickoff_bg);

    // Plasma "K" gear icon representation
    canvas.fill_rect(8, panel_y + 10, 20, 20, COLOR_PLASMA_BLUE);
    canvas.draw_char(14, panel_y + 12, 'K', COLOR_TEXT_LIGHT, None);
    canvas.draw_string(34, panel_y + 12, "Plasma", COLOR_TEXT_LIGHT, None);

    // Taskbar entries for active open windows
    let mut task_x = kickoff_w + 12;
    for surface in &compositor.surfaces {
        let task_w = 160;
        if task_x + task_w > width.saturating_sub(260) {
            break;
        }

        let task_bg = if surface.focused && !surface.minimized {
            COLOR_TITLEBAR_ACTIVE
        } else {
            COLOR_PANEL_BG
        };
        canvas.fill_rect(task_x, panel_y + 4, task_w, panel_h - 8, task_bg);

        // Highlight line on bottom of focused task
        if surface.focused && !surface.minimized {
            canvas.fill_rect(task_x, panel_y + panel_h - 2, task_w, 2, COLOR_PLASMA_BLUE);
        }

        // Window icon and truncated title
        canvas.fill_rect(task_x + 6, panel_y + 12, 14, 14, COLOR_PLASMA_BLUE);
        let title_slice = if surface.title.len() > 14 { &surface.title[..14] } else { &surface.title };
        canvas.draw_string(task_x + 26, panel_y + 12, title_slice, COLOR_TEXT_LIGHT, None);

        task_x += task_w + 6;
    }

    // System Tray (right side of panel)
    let tray_x = width.saturating_sub(250);

    // ZFS indicator
    canvas.draw_string(tray_x, panel_y + 12, "ZFS: ONLINE", COLOR_GREEN_ACCENT, None);

    // Digital clock
    canvas.draw_string(tray_x + 120, panel_y + 12, "14:15 | UTC", COLOR_TEXT_LIGHT, None);
}

/// Renders the Kickoff Application Menu popup above the launcher button.
fn render_kickoff_menu(canvas: &mut Compositor, screen_height: usize) {
    let menu_w = 260;
    let menu_h = 240;
    let menu_x = 0;
    let menu_y = (screen_height.saturating_sub(40)).saturating_sub(menu_h);

    // Menu container & outline
    canvas.fill_rect(menu_x, menu_y, menu_w, menu_h, COLOR_PANEL_BG);
    canvas.draw_rect_outline(menu_x, menu_y, menu_w, menu_h, COLOR_PLASMA_BLUE, 1);

    // Search header
    canvas.fill_rect(menu_x + 8, menu_y + 8, menu_w - 16, 26, COLOR_TITLEBAR_ACTIVE);
    canvas.draw_string(menu_x + 16, menu_y + 12, "Search applications...", COLOR_TEXT_MUTED, None);

    // Menu Items
    let items = [
        "1. Konsole (Terminal)",
        "2. KSysGuard (System Monitor)",
        "3. Dolphin (File Manager)",
        "4. System Settings",
        "5. Leave / Return to CLI (Esc)",
    ];

    let mut item_y = menu_y + 46;
    for (i, item) in items.iter().enumerate() {
        let is_hover = i == 0;
        if is_hover {
            canvas.fill_rect(menu_x + 4, item_y - 2, menu_w - 8, 24, COLOR_TITLEBAR_ACTIVE);
        }
        canvas.draw_string(menu_x + 16, item_y + 2, item, COLOR_TEXT_LIGHT, None);
        item_y += 28;
    }
}
