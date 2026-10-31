use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::Char16;
use x86_64::instructions::port::Port;

const KEY_BUFFER_CAPACITY: usize = 128;

struct KeyRingBuffer {
    buffer: [Option<Key>; KEY_BUFFER_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}

impl KeyRingBuffer {
    pub const fn new() -> Self {
        Self {
            buffer: [None; KEY_BUFFER_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, key: Key) {
        if self.count < KEY_BUFFER_CAPACITY {
            self.buffer[self.tail] = Some(key);
            self.tail = (self.tail + 1) % KEY_BUFFER_CAPACITY;
            self.count += 1;
        }
    }

    pub fn pop(&mut self) -> Option<Key> {
        if self.count == 0 {
            None
        } else {
            let key = self.buffer[self.head].take();
            self.head = (self.head + 1) % KEY_BUFFER_CAPACITY;
            self.count -= 1;
            key
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

static SHIFT_HELD: AtomicBool = AtomicBool::new(false);
static CTRL_HELD: AtomicBool = AtomicBool::new(false);
static EXTENDED_PREFIX: AtomicBool = AtomicBool::new(false);
static KEYBOARD_LOCK: Mutex<()> = Mutex::new(());
static KEY_BUFFER: Mutex<KeyRingBuffer> = Mutex::new(KeyRingBuffer::new());

/// Processes a single raw Scancode Set 1 byte and updates modifier states.
/// Returns Some(Key) if a printable or special key event completed.
pub fn process_scancode(scancode: u8) -> Option<Key> {
    if scancode == 0xE0 {
        EXTENDED_PREFIX.store(true, Ordering::SeqCst);
        return None;
    }

    let is_extended = EXTENDED_PREFIX.swap(false, Ordering::SeqCst);
    let is_break = (scancode & 0x80) != 0;
    let make_code = scancode & 0x7F;

    if is_break {
        // Key release
        match make_code {
            0x2A | 0x36 => SHIFT_HELD.store(false, Ordering::SeqCst),
            0x1D => CTRL_HELD.store(false, Ordering::SeqCst),
            _ => {}
        }
        return None;
    }

    // Key press (Make)
    match make_code {
        0x2A | 0x36 => {
            SHIFT_HELD.store(true, Ordering::SeqCst);
            return None;
        }
        0x1D => {
            CTRL_HELD.store(true, Ordering::SeqCst);
            return None;
        }
        _ => {}
    }

    let shift = SHIFT_HELD.load(Ordering::SeqCst);
    let ctrl = CTRL_HELD.load(Ordering::SeqCst);

    if is_extended {
        // Extended keys (arrows, navigation)
        return match make_code {
            0x48 => Some(Key::Special(ScanCode(1))),  // Up
            0x50 => Some(Key::Special(ScanCode(2))),  // Down
            0x4D => Some(Key::Special(ScanCode(3))),  // Right
            0x4B => Some(Key::Special(ScanCode(4))),  // Left
            0x47 => Some(Key::Special(ScanCode(5))),  // Home
            0x4F => Some(Key::Special(ScanCode(6))),  // End
            0x53 => Some(Key::Special(ScanCode(8))),  // Delete
            0x49 => Some(Key::Special(ScanCode(9))),  // PageUp
            0x51 => Some(Key::Special(ScanCode(10))), // PageDown
            _ => None,
        };
    }

    // Standard Scancode Set 1 decoding
    let ch: Option<char> = match make_code {
        0x01 => Some('\x1B'), // Escape
        0x02 => Some(if shift { '!' } else { '1' }),
        0x03 => Some(if shift { '@' } else { '2' }),
        0x04 => Some(if shift { '#' } else { '3' }),
        0x05 => Some(if shift { '$' } else { '4' }),
        0x06 => Some(if shift { '%' } else { '5' }),
        0x07 => Some(if shift { '^' } else { '6' }),
        0x08 => Some(if shift { '&' } else { '7' }),
        0x09 => Some(if shift { '*' } else { '8' }),
        0x0A => Some(if shift { '(' } else { '9' }),
        0x0B => Some(if shift { ')' } else { '0' }),
        0x0C => Some(if shift { '_' } else { '-' }),
        0x0D => Some(if shift { '+' } else { '=' }),
        0x0E => Some('\x08'), // Backspace
        0x0F => Some('\t'),   // Tab
        0x10 => Some(if shift { 'Q' } else { 'q' }),
        0x11 => Some(if shift { 'W' } else { 'w' }),
        0x12 => Some(if shift { 'E' } else { 'e' }),
        0x13 => Some(if shift { 'R' } else { 'r' }),
        0x14 => Some(if shift { 'T' } else { 't' }),
        0x15 => Some(if shift { 'Y' } else { 'y' }),
        0x16 => Some(if shift { 'U' } else { 'u' }),
        0x17 => Some(if shift { 'I' } else { 'i' }),
        0x18 => Some(if shift { 'O' } else { 'o' }),
        0x19 => Some(if shift { 'P' } else { 'p' }),
        0x1A => Some(if shift { '{' } else { '[' }),
        0x1B => Some(if shift { '}' } else { ']' }),
        0x1C => Some('\r'), // Enter
        0x1E => Some(if shift { 'A' } else { 'a' }),
        0x1F => Some(if shift { 'S' } else { 's' }),
        0x20 => Some(if shift { 'D' } else { 'd' }),
        0x21 => Some(if shift { 'F' } else { 'f' }),
        0x22 => Some(if shift { 'G' } else { 'g' }),
        0x23 => Some(if shift { 'H' } else { 'h' }),
        0x24 => Some(if shift { 'J' } else { 'j' }),
        0x25 => Some(if shift { 'K' } else { 'k' }),
        0x26 => Some(if shift { 'L' } else { 'l' }),
        0x27 => Some(if shift { ':' } else { ';' }),
        0x28 => Some(if shift { '"' } else { '\'' }),
        0x29 => Some(if shift { '~' } else { '`' }),
        0x2B => Some(if shift { '|' } else { '\\' }),
        0x2C => Some(if shift { 'Z' } else { 'z' }),
        0x2D => Some(if shift { 'X' } else { 'x' }),
        0x2E => Some(if shift { 'C' } else { 'c' }),
        0x2F => Some(if shift { 'V' } else { 'v' }),
        0x30 => Some(if shift { 'B' } else { 'b' }),
        0x31 => Some(if shift { 'N' } else { 'n' }),
        0x32 => Some(if shift { 'M' } else { 'm' }),
        0x33 => Some(if shift { '<' } else { ',' }),
        0x34 => Some(if shift { '>' } else { '.' }),
        0x35 => Some(if shift { '?' } else { '/' }),
        0x39 => Some(' '), // Space
        _ => None,
    };

    if let Some(mut c) = ch {
        if ctrl && c.is_ascii_alphabetic() {
            // ASCII Control Code 1..26 for Ctrl+A .. Ctrl+Z
            let ascii_val = (c.to_ascii_uppercase() as u8) - b'@';
            c = ascii_val as char;
        }
        if let Ok(c16) = Char16::try_from(c) {
            return Some(Key::Printable(c16));
        }
    }

    None
}

/// Ctrl and Alt held on the console (for the Ctrl+Alt+F2 display switch).
static CONSOLE_CTRL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static CONSOLE_ALT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set by F12; the timer interrupt prints the task list (see `Scheduler::dump_tasks`).
pub static TASK_DUMP_REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Called exclusively by the IRQ 1 (Vector 33) interrupt service routine.
pub fn on_keyboard_irq() {
    let mut data_port: Port<u8> = Port::new(0x60);
    let scancode = unsafe { data_port.read() };
    if scancode == 0x58 {
        // F12: dump the task list on the serial port (handled by the timer interrupt)
        TASK_DUMP_REQUESTED.store(true, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    if crate::wayland::RAW_KEYBOARD.load(core::sync::atomic::Ordering::Acquire) {
        // The Wayland compositor shows: it receives the keyboard as raw scancodes
        crate::wayland::push_scancode(scancode);
        return;
    }
    // Ctrl+Alt+F2 on the console switches to the compositor's screen
    use core::sync::atomic::Ordering::Relaxed;
    match scancode {
        0x1D => CONSOLE_CTRL.store(true, Relaxed),
        0x9D => CONSOLE_CTRL.store(false, Relaxed),
        0x38 => CONSOLE_ALT.store(true, Relaxed),
        0xB8 => CONSOLE_ALT.store(false, Relaxed),
        0x3C if CONSOLE_CTRL.load(Relaxed) && CONSOLE_ALT.load(Relaxed) && crate::wayland::is_running() => {
            crate::wayland::SWITCH_TO_COMPOSITOR.store(true, core::sync::atomic::Ordering::Release);
            crate::wayland::INPUT_WQ.wake_all();
            return;
        }
        _ => {}
    }
    if let Some(key) = process_scancode(scancode) {
        let mut buffer = KEY_BUFFER.lock();
        buffer.push(key);
        drop(buffer);
        crate::compat::linux::tty::INPUT_WQ.wake_all();
    }
}

/// Reads a key non-blockingly (first from the interrupt ring buffer, then fallback polling if interrupts disabled).
pub fn read_key() -> Option<Key> {
    // 1. Check if a key was captured asynchronously by the IRQ 1 handler
    if let Some(key) = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut buffer = KEY_BUFFER.lock();
        buffer.pop()
    }) {
        return Some(key);
    }

    // 2. Fallback polling before the IRQ 1 handler is set up (early init). Once it is,
    // polling would race with it and read the same scancode twice.
    if !crate::arch::pit::is_active() && !x86_64::instructions::interrupts::are_enabled() {
        let _guard = KEYBOARD_LOCK.lock();
        let mut status_port: Port<u8> = Port::new(0x64);
        let status = unsafe { status_port.read() };

        if (status & 0x01) != 0 {
            let mut data_port: Port<u8> = Port::new(0x60);
            let scancode = unsafe { data_port.read() };
            return process_scancode(scancode);
        }
    }

    None
}

/// Blocking wait for the next key from the PS/2 keyboard.
/// Halts the CPU efficiently using `hlt` when interrupts are enabled.
pub fn get_key() -> Key {
    loop {
        if let Some(key) = read_key() {
            return key;
        }
        if x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Configures the 8042 PS/2 keyboard controller to enable scanning and IRQ 1 interrupt generation.
pub fn init() {
    unsafe {
        let mut status_port: Port<u8> = Port::new(0x64);
        let mut data_port: Port<u8> = Port::new(0x60);

        // 1. Drain any pending bytes in output buffer
        for _ in 0..100 {
            if (status_port.read() & 0x01) != 0 {
                let _ = data_port.read();
            } else {
                break;
            }
        }

        // 2. Enable first PS/2 port (Keyboard)
        for _ in 0..100 {
            if (status_port.read() & 0x02) == 0 {
                status_port.write(0xAE);
                break;
            }
        }

        // 3. Read 8042 Controller Configuration Byte (Command 0x20)
        for _ in 0..100 {
            if (status_port.read() & 0x02) == 0 {
                status_port.write(0x20);
                break;
            }
        }
        let mut config = 0u8;
        for _ in 0..100 {
            if (status_port.read() & 0x01) != 0 {
                config = data_port.read();
                break;
            }
        }

        // 4. Enable IRQ 1 (bit 0 = 1) and enable first port clock (bit 4 = 0)
        config |= 0x01; // Enable port 1 interrupt
        config &= !0x10; // Enable port 1 clock

        // 5. Write 8042 Controller Configuration Byte (Command 0x60)
        for _ in 0..100 {
            if (status_port.read() & 0x02) == 0 {
                status_port.write(0x60);
                break;
            }
        }
        for _ in 0..100 {
            if (status_port.read() & 0x02) == 0 {
                data_port.write(config);
                break;
            }
        }

        // 6. Send 'Enable Scanning' command (0xF4) to the keyboard device
        for _ in 0..100 {
            if (status_port.read() & 0x02) == 0 {
                data_port.write(0xF4);
                break;
            }
        }
        for _ in 0..100 {
            if (status_port.read() & 0x01) != 0 {
                let _ = data_port.read();
                break;
            }
        }
    }
}

