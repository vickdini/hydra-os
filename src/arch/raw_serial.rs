//! # Lock-free COM1 output
//!
//! Writes bytes to the first serial port by polling the UART directly, without the
//! console's locks or any allocation. For the panic handler: the panic may be an
//! allocation failure, or happen while the console is locked.

use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;

/// `core::fmt::Write` sink for COM1.
pub struct RawSerial;

impl core::fmt::Write for RawSerial {
    /// Formats and emits a string slice directly to COM1 without allocating or locking.
    ///
    /// Intercepts newline characters (`\n`) and emits a carriage return (`\r`) first
    /// to ensure standard terminal line discipline.
    ///
    /// # Arguments
    ///
    /// * `s` - String slice to transmit over the UART serial line.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())`.
    ///
    /// # Panics
    ///
    /// *Guaranteed to never panic under normal execution.*
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                put(b'\r');
            }
            put(b);
        }
        Ok(())
    }
}

/// Transmits a single raw byte over COM1 by polling the Line Status Register (LSR).
///
/// Bounded poll up to 100,000 spin iterations for the Transmit Holding Register Empty
/// flag (bit 5) before writing the byte to port `0x3F8`.
///
/// # Arguments
///
/// * `b` - Byte to transmit.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn put(b: u8) {
    let mut lsr: Port<u8> = Port::new(COM1 + 5);
    let mut data: Port<u8> = Port::new(COM1);
    unsafe {
        // Wait (bounded) for the transmit holding register to empty
        for _ in 0..100_000 {
            if lsr.read() & 0x20 != 0 {
                break;
            }
        }
        data.write(b);
    }
}
