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
//! - `MouseState`: Tracks absolute pointer coordinates `(x, y)` and button press states.
//! - `MouseEvent`: Represents a discrete pointing motion or button transition event.
//! - `init`: Initializes the 8042 auxiliary port and enables streaming packet reporting.
//! - `poll_mouse`: Dispatches pending hardware packets and updates the pointer state.
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
    /// Absolute cursor position and current button press states.
    pub state: MouseState,
    /// Relative horizontal motion delta since the previous packet.
    pub delta_x: i32,
    /// Relative vertical motion delta since the previous packet.
    pub delta_y: i32,
    /// Whether the left mouse button transitioned from unpressed to pressed.
    pub left_pressed: bool,
    /// Whether the right mouse button transitioned from unpressed to pressed.
    pub right_pressed: bool,
    /// Wheel clicks since the previous packet (positive = away from the user).
    pub wheel: i32,
}

struct Ps2Mouse {
    data_port: Port<u8>,
    cmd_port: Port<u8>,
    packet_buf: [u8; 4],
    packet_idx: usize,
    /// Bytes per packet: 3, or 4 once the IntelliMouse wheel protocol is enabled.
    packet_len: usize,
    state: MouseState,
    initialized: bool,
    /// Bytes arrive through IRQ 12 (after hardware takeover) instead of polling.
    irq_mode: bool,
    /// Latest event decoded by the interrupt handler, not yet polled.
    pending: Option<MouseEvent>,
    /// Screen size the position is clamped to (from the last poll).
    screen: (usize, usize),
}

impl Ps2Mouse {
    const fn new() -> Self {
        Self {
            data_port: Port::new(PS2_DATA_PORT),
            cmd_port: Port::new(PS2_STATUS_CMD_PORT),
            packet_buf: [0; 4],
            packet_idx: 0,
            packet_len: 3,
            state: MouseState::new(400, 300),
            initialized: false,
            irq_mode: false,
            pending: None,
            screen: (1024, 768),
        }
    }

    /// Waits until the 8042 input buffer is empty and ready to accept a command/data byte.
    ///
    /// Polls the status register port `0x64` until bit 1 (`STATUS_INPUT_BUFFER_FULL`) clears.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the input buffer is ready for write; `Err(&'static str)` on timeout.
    ///
    /// # Errors
    ///
    /// Returns an error string if the controller fails to drain its buffer within 100,000 spin cycles.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
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
    ///
    /// Polls the status register port `0x64` until bit 0 (`STATUS_OUTPUT_BUFFER_FULL`) is set.
    ///
    /// # Returns
    ///
    /// `Ok(())` when data is ready to be read from port `0x60`; `Err(&'static str)` on timeout.
    ///
    /// # Errors
    ///
    /// Returns an error string if no data byte appears within 100,000 spin cycles.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
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
    ///
    /// Dispatches command `0xD4` to tell the 8042 controller that the subsequent byte
    /// written to data port `0x60` should be routed to the auxiliary PS/2 mouse port,
    /// and waits for the standard device acknowledge byte (`0xFA`).
    ///
    /// # Arguments
    ///
    /// * `cmd` - The mouse command byte (e.g. `0xF4` for enable reporting, `0xF6` for defaults).
    ///
    /// # Returns
    ///
    /// `Ok(())` if the mouse acknowledged the command with `0xFA`; `Err(&'static str)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error string if writing times out or the mouse returns a non-ACK response.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
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
    ///
    /// Enables the auxiliary device clock line, configures IRQ 12 interrupt generation
    /// in the 8042 controller configuration byte, attempts IntelliMouse wheel detection,
    /// and issues the enable data reporting command (`0xF4`).
    ///
    /// # Returns
    ///
    /// `Ok(())` if the mouse was successfully initialized; `Err(&'static str)` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error string if any phase of the 8042 auxiliary handshake fails.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
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

        // 6. IntelliMouse wheel: sample rates 200, 100, 80 in a row switch a wheel mouse to
        //    4-byte packets, after which it reports device id 3
        if self.enable_wheel() {
            self.packet_len = 4;
        }

        // 7. Enable Data Reporting (Command 0xF4)
        self.write_mouse_cmd(MOUSE_CMD_ENABLE_REPORTING)?;

        self.initialized = true;
        Ok(())
    }

    /// Attempts the Microsoft IntelliMouse 4-byte packet wheel handshake sequence.
    ///
    /// Transmits sample rates 200, 100, 80 sequentially, queries the device ID (`0xF2`),
    /// and checks if ID `3` (wheel mouse) is returned.
    ///
    /// # Returns
    ///
    /// `true` if the device supports scroll wheel 4-byte packets; `false` otherwise.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    fn enable_wheel(&mut self) -> bool {
        for rate in [200u8, 100, 80] {
            if self.write_mouse_cmd(0xF3).is_err() || self.write_mouse_cmd(rate).is_err() {
                return false;
            }
        }
        // Get Device ID (0xF2): ACK, then the id byte
        if self.write_mouse_cmd(0xF2).is_err() || self.wait_read().is_err() {
            return false;
        }
        let id = unsafe { self.data_port.read() };
        // Back to the usual 100 samples/s
        let _ = self.write_mouse_cmd(0xF3).and_then(|_| self.write_mouse_cmd(100));
        id == 3
    }

    /// Polls for incoming mouse packet bytes and updates coordinates.
    ///
    /// In polled mode (before IRQ 12 is enabled), inspects status port `0x64` for pending
    /// auxiliary data bytes and feeds them into the packet assembler. In IRQ mode, returns
    /// any pending event decoded by the interrupt handler.
    ///
    /// # Arguments
    ///
    /// * `screen_width` - Current display width in pixels for boundary clamping.
    /// * `screen_height` - Current display height in pixels for boundary clamping.
    ///
    /// # Returns
    ///
    /// `Some(MouseEvent)` if a complete mouse packet was assembled; `None` otherwise.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    fn poll(&mut self, screen_width: usize, screen_height: usize) -> Option<MouseEvent> {
        self.screen = (screen_width, screen_height);
        if self.irq_mode {
            return self.pending.take();
        }
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
        self.feed(byte, screen_width, screen_height)
    }

    /// Appends one byte to the active packet buffer and decodes complete mouse packets.
    ///
    /// Assembles standard 3-byte PS/2 packets (or 4-byte IntelliMouse wheel packets),
    /// performs 9-bit sign extension on X and Y movement deltas, inverts screen Y coordinates,
    /// updates internal position clamping against screen boundaries, and detects button transitions.
    ///
    /// # Arguments
    ///
    /// * `byte` - Incoming byte from the 8042 auxiliary port.
    /// * `screen_width` - Maximum horizontal boundary in pixels.
    /// * `screen_height` - Maximum vertical boundary in pixels.
    ///
    /// # Returns
    ///
    /// `Some(MouseEvent)` when a full packet is assembled; `None` while receiving partial bytes.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    fn feed(&mut self, byte: u8, screen_width: usize, screen_height: usize) -> Option<MouseEvent> {

        // Byte 0 must have bit 3 set (always 1 in standard PS/2 packet)
        // A header with both overflow bits set is a stray reply (ACK 0xFA, resend 0xFE)
        if self.packet_idx == 0 && ((byte & 0x08) == 0 || byte & 0xC0 == 0xC0) {
            // Out of sync; discard byte and await valid packet header
            return None;
        }

        self.packet_buf[self.packet_idx] = byte;
        self.packet_idx += 1;

        if self.packet_idx < self.packet_len {
            return None;
        }

        // Full packet received
        self.packet_idx = 0;
        // 4th byte: signed wheel movement (negative = away from the user)
        let wheel = if self.packet_len == 4 { -(self.packet_buf[3] as i8 as i32) } else { 0 };
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
            wheel,
        })
    }
}

static MOUSE_DRIVER: Mutex<Ps2Mouse> = Mutex::new(Ps2Mouse::new());

/// Initializes the PS/2 auxiliary mouse driver subsystem.
///
/// Sends initialization commands to the 8042 controller, sets up default sample rates,
/// attempts IntelliMouse wheel probing, and enables data packet streaming.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
///
/// * `screen_width` - Display width in pixels (used for coordinate clamping).
/// * `screen_height` - Display height in pixels (used for coordinate clamping).
///
/// # Returns
///
/// `Some(MouseEvent)` if a movement or button state change was decoded; `None` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn poll_mouse(screen_width: usize, screen_height: usize) -> Option<MouseEvent> {
    MOUSE_DRIVER.lock().poll(screen_width, screen_height)
}

/// Sets the current pointer coordinates (e.g. upon resolution change or center reset).
///
/// # Arguments
///
/// * `x` - Target horizontal coordinate in pixels.
/// * `y` - Target vertical coordinate in pixels.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn set_position(x: usize, y: usize) {
    let mut mouse = MOUSE_DRIVER.lock();
    mouse.state.x = x;
    mouse.state.y = y;
}

/// Returns the current snapshot of pointer coordinates and button states.
///
/// # Returns
///
/// A copy of the current `MouseState` containing coordinates and button press flags.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn current_state() -> MouseState {
    MOUSE_DRIVER.lock().state
}

/// Switches the mouse to interrupt-driven input (IRQ 12), once Hydra owns the PIC and IDT.
///
/// Unmasks IRQ 2 (cascade line) and IRQ 12 on the Slave PIC, activates interrupt mode in
/// the driver state, and performs the wheel handshake without firmware interference.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn enable_irq() {
    {
        let mut mouse = MOUSE_DRIVER.lock();
        if !mouse.initialized {
            return;
        }
        // The firmware's own PS/2 driver may have reset the mouse since `init`: redo the
        // wheel handshake now that it is gone (interrupts off, so the keyboard handler
        // cannot take the mouse's replies)
        let wheel = x86_64::instructions::interrupts::without_interrupts(|| {
            let _ = mouse.write_mouse_cmd(0xF5); // disable reporting during the handshake
            let wheel = mouse.enable_wheel();
            let _ = mouse.write_mouse_cmd(MOUSE_CMD_ENABLE_REPORTING);
            // Drop replies still queued (a late ACK has bit 3 set and would be taken for
            // the first byte of a packet)
            for _ in 0..16 {
                if unsafe { mouse.cmd_port.read() } & STATUS_OUTPUT_BUFFER_FULL == 0 {
                    break;
                }
                let _ = unsafe { mouse.data_port.read() };
            }
            wheel
        });
        mouse.packet_len = if wheel { 4 } else { 3 };
        mouse.irq_mode = true;
        mouse.packet_idx = 0;
        crate::kprintln!("[mouse] {} packets{}", mouse.packet_len, if wheel { " (wheel enabled)" } else { "" });
    }
    crate::arch::pic::unmask_irq(2);
    crate::arch::pic::unmask_irq(12);
}

/// Handles incoming bytes from the auxiliary PS/2 port on IRQ 12 (IDT Vector 44).
///
/// Reads the byte from data port `0x60`, feeds it into the packet decoder, merges any
/// unconsumed pending motion events, dispatches events to Linux evdev, and wakes
/// waiting graphical tasks via the Wayland input wait queue.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn on_mouse_irq() {
    let mut data_port: Port<u8> = Port::new(PS2_DATA_PORT);
    let byte = unsafe { data_port.read() };
    let mut mouse = match MOUSE_DRIVER.try_lock() {
        Some(m) => m,
        None => return,
    };
    let (w, h) = mouse.screen;
    if let Some(ev) = mouse.feed(byte, w, h) {
        // Merge with an event not yet polled so presses are not lost
        let merged = match mouse.pending.take() {
            Some(prev) => MouseEvent {
                left_pressed: prev.left_pressed || ev.left_pressed,
                right_pressed: prev.right_pressed || ev.right_pressed,
                delta_x: prev.delta_x + ev.delta_x,
                delta_y: prev.delta_y + ev.delta_y,
                wheel: prev.wheel + ev.wheel,
                ..ev
            },
            None => ev,
        };
        mouse.pending = Some(merged);
        drop(mouse);
        let buttons = ev.state.left_button as u8 | (ev.state.right_button as u8) << 1 | (ev.state.middle_button as u8) << 2;
        crate::compat::linux::evdev::push_mouse(ev.delta_x, ev.delta_y, ev.wheel, buttons);
        crate::wayland::INPUT_WQ.wake_all();
    }
}
