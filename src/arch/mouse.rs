//! # Architecture Layer: PS/2 Auxiliary Mouse Device Driver
//!
//! Provides bare-metal driver support for standard PS/2 mice and pointing devices.
//!
//! ## Architectural Role & Design Rationale
//!
//! To support modern graphical desktop environments (such as the KDE Plasma-style Wayland
//! compositor shell) without relying on firmware boot services, Hydra OS requires an autonomous
//! pointer input driver operating directly on hardware I/O ports `0x60` (data) and `0x64` (status/command).
//!
//! The 8042 Keyboard and Auxiliary Controller multiplexes input from both the keyboard (Port 1, IRQ 1)
//! and the mouse (Port 2 / Auxiliary, IRQ 12). By inspecting bit 5 (`AUX`) of the controller status register,
//! the driver cleanly routes mouse packet bytes without interfering with keyboard scancode processing.
//!
//! ## Key Types & Interfaces
//!
//! - [`MouseState`]: Tracks absolute pointer coordinates `(x, y)` and button press states.
//! - [`MouseEvent`]: Represents a discrete pointing motion or button transition event.
//! - [`init()`]: Initializes the 8042 auxiliary port and enables streaming packet reporting.
//! - [`poll_mouse()`]: Dispatches pending hardware packets and updates the pointer state.
//!
//! ## Hardware Context
//!
//! - I/O Ports: `0x60` (Data), `0x64` (Command / Status)
//! - Packet Format: Standard 3-byte PS/2 motion packet with 9-bit relative coordinates
//! - Privilege Level: Ring 0 microkernel core

use spin::Mutex;
use x86_64::instructions::port::Port;

const PS2_DATA_PORT: u16 = 0x60;
const PS2_STATUS_CMD_PORT: u16 = 0x64;

// 8042 Controller Commands
const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_WRITE_AUX: u8 = 0xD4;

// Mouse Device Commands
const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_CMD_ENABLE_REPORTING: u8 = 0xF4;
const MOUSE_ACK: u8 = 0xFA;

// Status Register Bits
const STATUS_OUTPUT_BUFFER_FULL: u8 = 0x01;
const STATUS_INPUT_BUFFER_FULL: u8 = 0x02;
const STATUS_AUX_OUTPUT: u8 = 0x20;

/// State of the mouse pointing device across the active display canvas.
#[derive(Debug, Clone, Copy)]
pub struct MouseState {
    /// Horizontal screen coordinate (clamped to display width).
    pub x: usize,
    /// Vertical screen coordinate (clamped to display height).
    pub y: usize,
    /// Primary (left) mouse button state.
    pub left_button: bool,
    /// Secondary (right) mouse button state.
    pub right_button: bool,
    /// Tertiary (middle/wheel) mouse button state.
    pub middle_button: bool,
}

impl MouseState {
    /// Creates a default mouse state centered at the given screen coordinates.
    pub const fn new(initial_x: usize, initial_y: usize) -> Self {
        Self {
            x: initial_x,
            y: initial_y,
            left_button: false,
            right_button: false,
            middle_button: false,
        }
    }
}

/// Represents a mouse update event emitted by the hardware driver.
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    pub state: MouseState,
    pub delta_x: i32,
    pub delta_y: i32,
    pub left_pressed: bool,
    pub right_pressed: bool,
}

struct Ps2Mouse {
    data_port: Port<u8>,
    cmd_port: Port<u8>,
    packet_buf: [u8; 3],
    packet_idx: usize,
    state: MouseState,
    initialized: bool,
}

impl Ps2Mouse {
    const fn new() -> Self {
        Self {
            data_port: Port::new(PS2_DATA_PORT),
            cmd_port: Port::new(PS2_STATUS_CMD_PORT),
            packet_buf: [0; 3],
            packet_idx: 0,
            state: MouseState::new(400, 300),
            initialized: false,
        }
    }

    /// Waits until the 8042 input buffer is empty and ready to accept a command/data byte.
    fn wait_write(&mut self) -> Result<(), &'static str> {
        for _ in 0..100_000 {
            if unsafe { self.cmd_port.read() } & STATUS_INPUT_BUFFER_FULL == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("PS/2 controller timeout waiting for input buffer ready")
    }

    /// Waits until the 8042 output buffer contains data to be read.
    fn wait_read(&mut self) -> Result<(), &'static str> {
        for _ in 0..100_000 {
            if unsafe { self.cmd_port.read() } & STATUS_OUTPUT_BUFFER_FULL != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("PS/2 controller timeout waiting for output data")
    }

    /// Sends a command byte specifically targeted at the auxiliary mouse device.
    fn write_mouse_cmd(&mut self, cmd: u8) -> Result<(), &'static str> {
        self.wait_write()?;
        unsafe {
            self.cmd_port.write(CMD_WRITE_AUX);
        }
        self.wait_write()?;
        unsafe {
            self.data_port.write(cmd);
        }

        // Wait for device ACK (0xFA)
        self.wait_read()?;
        let ack = unsafe { self.data_port.read() };
        if ack == MOUSE_ACK {
            Ok(())
        } else {
            Err("Mouse did not return 0xFA ACK to command")
        }
    }

    /// Initializes the 8042 auxiliary port and enables continuous PS/2 packet streaming.
    fn init(&mut self) -> Result<(), &'static str> {
        // 1. Enable Auxiliary Device (Command 0xA8)
        self.wait_write()?;
        unsafe {
            self.cmd_port.write(CMD_ENABLE_AUX);
        }

        // 2. Read Controller Configuration Byte (Command 0x20)
        self.wait_write()?;
        unsafe {
            self.cmd_port.write(CMD_READ_CONFIG);
        }
        self.wait_read()?;
        let mut config = unsafe { self.data_port.read() };

        // 3. Configure flags:
        //    Bit 1 = 1: Enable IRQ 12 (Auxiliary interrupt)
        //    Bit 5 = 0: Enable Auxiliary device clock line
        config |= 0x02;
        config &= !0x20;

        // 4. Write back Controller Configuration Byte (Command 0x60)
        self.wait_write()?;
        unsafe {
            self.cmd_port.write(CMD_WRITE_CONFIG);
        }
        self.wait_write()?;
        unsafe {
            self.data_port.write(config);
        }

        // 5. Tell mouse to use default settings (Command 0xF6)
        let _ = self.write_mouse_cmd(MOUSE_CMD_SET_DEFAULTS);

        // 6. Enable Data Reporting (Command 0xF4)
        self.write_mouse_cmd(MOUSE_CMD_ENABLE_REPORTING)?;

        self.initialized = true;
        Ok(())
    }

    /// Polls for incoming mouse packet bytes and updates coordinates.
    fn poll(&mut self, screen_width: usize, screen_height: usize) -> Option<MouseEvent> {
        if !self.initialized {
            let _ = self.init();
        }

        // Check if data is pending in the 8042 output buffer
        let status = unsafe { self.cmd_port.read() };
        if (status & STATUS_OUTPUT_BUFFER_FULL) == 0 {
            return None;
        }

        // Verify that the byte originated from the auxiliary device (mouse)
        if (status & STATUS_AUX_OUTPUT) == 0 {
            return None;
        }

        let byte = unsafe { self.data_port.read() };

        // Byte 0 must have bit 3 set (always 1 in standard PS/2 packet)
        if self.packet_idx == 0 && (byte & 0x08) == 0 {
            // Out of sync; discard byte and await valid packet header
            return None;
        }

        self.packet_buf[self.packet_idx] = byte;
        self.packet_idx += 1;

        if self.packet_idx < 3 {
            return None;
        }

        // Full 3-byte packet received!
        self.packet_idx = 0;
        let b0 = self.packet_buf[0];
        let b1 = self.packet_buf[1];
        let b2 = self.packet_buf[2];

        // Parse button flags
        let left_button = (b0 & 0x01) != 0;
        let right_button = (b0 & 0x02) != 0;
        let middle_button = (b0 & 0x04) != 0;

        // Parse relative motion with 9-bit sign extension
        let mut dx = b1 as i32;
        if (b0 & 0x10) != 0 {
            dx |= !0xFF; // Sign extend negative delta
        }

        let mut dy = b2 as i32;
        if (b0 & 0x20) != 0 {
            dy |= !0xFF; // Sign extend negative delta
        }

        // Invert dy: PS/2 upward movement is positive, but screen Y increases downward
        let screen_dy = -dy;

        // Apply clamped coordinate updates
        let new_x = ((self.state.x as i32) + dx).clamp(0, (screen_width.saturating_sub(1)) as i32) as usize;
        let new_y = ((self.state.y as i32) + screen_dy).clamp(0, (screen_height.saturating_sub(1)) as i32) as usize;

        let left_pressed = left_button && !self.state.left_button;
        let right_pressed = right_button && !self.state.right_button;

        self.state.x = new_x;
        self.state.y = new_y;
        self.state.left_button = left_button;
        self.state.right_button = right_button;
        self.state.middle_button = middle_button;

        Some(MouseEvent {
            state: self.state,
            delta_x: dx,
            delta_y: screen_dy,
            left_pressed,
            right_pressed,
        })
    }
}

static MOUSE_DRIVER: Mutex<Ps2Mouse> = Mutex::new(Ps2Mouse::new());

/// Initializes the PS/2 auxiliary mouse driver subsystem.
pub fn init() {
    let mut mouse = MOUSE_DRIVER.lock();
    if !mouse.initialized {
        match mouse.init() {
            Ok(()) => {
                crate::console::set_color(
                    uefi::proto::console::text::Color::LightGreen,
                    uefi::proto::console::text::Color::Black,
                );
                crate::println!("[+] PS/2 Mouse: Initialized auxiliary pointing device with 3-byte packet streaming.");
            }
            Err(e) => {
                crate::console::set_color(
                    uefi::proto::console::text::Color::Yellow,
                    uefi::proto::console::text::Color::Black,
                );
                crate::println!("[*] PS/2 Mouse: Pointer device reporting disabled or not present: {}", e);
            }
        }
    }
}

/// Polls for incoming mouse events and returns an updated pointer event if movement occurred.
///
/// # Arguments
/// - `screen_width`: Display width in pixels (used for coordinate clamping).
/// - `screen_height`: Display height in pixels (used for coordinate clamping).
pub fn poll_mouse(screen_width: usize, screen_height: usize) -> Option<MouseEvent> {
    MOUSE_DRIVER.lock().poll(screen_width, screen_height)
}

/// Sets the current pointer coordinates (e.g. upon resolution change or center reset).
pub fn set_position(x: usize, y: usize) {
    let mut mouse = MOUSE_DRIVER.lock();
    mouse.state.x = x;
    mouse.state.y = y;
}

/// Returns the current snapshot of pointer coordinates and button states.
pub fn current_state() -> MouseState {
    MOUSE_DRIVER.lock().state
}
