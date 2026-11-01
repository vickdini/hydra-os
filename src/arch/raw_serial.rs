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
