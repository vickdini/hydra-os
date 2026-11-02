//! I/O port access (after [`crate::sys::iopl`]).

/// Reads a byte from `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
///
/// # Returns
/// Byte read from the port.
#[inline]
pub fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

/// Writes a byte to `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
/// * `v` - Byte value to write.
#[inline]
pub fn outb(port: u16, v: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}

/// Reads a 16-bit word from `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
///
/// # Returns
/// 16-bit word read from the port.
#[inline]
pub fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe { core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

/// Writes a 16-bit word to `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
/// * `v` - 16-bit word value to write.
#[inline]
pub fn outw(port: u16, v: u16) {
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) };
}

/// Reads a 32-bit word from `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
///
/// # Returns
/// 32-bit double word read from the port.
#[inline]
pub fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

/// Writes a 32-bit word to `port`.
///
/// # Arguments
/// * `port` - 16-bit I/O port address.
/// * `v` - 32-bit double word value to write.
#[inline]
pub fn outl(port: u16, v: u32) {
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) };
}
