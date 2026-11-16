//! VMware's absolute pointer ("vmmouse"), which QEMU's PC machine provides by default
//! (`vmport`): the PS/2 mouse keeps raising IRQ 12, but in absolute mode each of its packets
//! only says that pointer data is queued behind the VMware backdoor port (0x5658), where
//! the position (0..=0xFFFF on both axes), the buttons and the wheel are read. With it the
//! guest pointer sits exactly under the host's: QEMU's window stops converting host pointer
//! motion into PS/2 movements (which drift and scale wrong, worst under Wayland/WSLg).
//!
//! The protocol is Linux's `drivers/input/mouse/vmmouse.c`. The port is only probed under a
//! hypervisor (CPUID leaf 1, ECX bit 31): on real hardware 0x5658 may belong to anything.

use core::sync::atomic::{AtomicBool, Ordering};

const MAGIC: u32 = 0x564D_5868;
const PORT: u16 = 0x5658;
const CMD_GETVERSION: u32 = 10;
const CMD_ABSPOINTER_DATA: u32 = 39;
const CMD_ABSPOINTER_STATUS: u32 = 40;
const CMD_ABSPOINTER_COMMAND: u32 = 41;
const ENABLE: u32 = 0x4541_4552;
const REQUEST_ABSOLUTE: u32 = 0x5342_4152;
const VERSION_ID: u32 = 0x3442_554a;
const STATUS_ERROR: u32 = 0xffff_0000;
const RELATIVE_PACKET: u32 = 0x0001_0000;
const LEFT_BUTTON: u32 = 0x20;
const RIGHT_BUTTON: u32 = 0x10;
const MIDDLE_BUTTON: u32 = 0x08;

/// Largest coordinate on either axis.
pub const MAX: u32 = 0xFFFF;

/// Absolute mode is on: PS/2 packets are only notifications.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The hypervisor offered the device (it stays listed as an input device even if a later
/// enable fails).
static PRESENT: AtomicBool = AtomicBool::new(false);

/// One pointer report.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    /// Position, 0..=[`MAX`] across the screen.
    pub x: u16,
    /// Position, 0..=[`MAX`] down the screen.
    pub y: u16,
    /// Buttons: bit 0 left, 1 right, 2 middle (as the PS/2 driver reports them).
    pub buttons: u8,
    /// Wheel clicks (positive = away from the user).
    pub wheel: i8,
}

/// One backdoor call: `(eax, ebx, ecx, edx)` after `in eax, dx` with the magic in EAX,
/// `arg` in EBX and `cmd` in ECX. RBX is reserved by the compiler, so it is swapped in.
fn call(cmd: u32, arg: u32) -> (u32, u32, u32, u32) {
    let (eax, ecx, edx): (u32, u32, u32);
    let mut rbx = arg as u64;
    unsafe {
        core::arch::asm!(
            "xchg {b}, rbx",
            "in eax, dx",
            "xchg {b}, rbx",
            b = inout(reg) rbx,
            inout("eax") MAGIC => eax,
            inout("ecx") cmd => ecx,
            inout("edx") PORT as u32 => edx,
            // QEMU's vmmouse writes all six backdoor registers back (as 32-bit values, so
            // the upper halves of RSI and RDI are lost too)
            out("rsi") _,
            out("rdi") _,
            options(nostack),
        );
    }
    (eax, rbx as u32, ecx, edx)
}

/// Whether Hydra runs under a hypervisor (CPUID leaf 1, ECX bit 31).
fn under_hypervisor() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0
}

/// Switches the device to absolute mode. `false` if there is none or it refuses.
fn try_enable() -> bool {
    call(CMD_ABSPOINTER_COMMAND, ENABLE);
    let (status, ..) = call(CMD_ABSPOINTER_STATUS, 0);
    if status & STATUS_ERROR == STATUS_ERROR || status & 0xffff == 0 {
        return false;
    }
    let (version, ..) = call(CMD_ABSPOINTER_DATA, 1);
    if version != VERSION_ID {
        return false;
    }
    call(CMD_ABSPOINTER_COMMAND, REQUEST_ABSOLUTE);
    true
}

/// Probes for the device and turns absolute mode on (after the PS/2 mouse is set up and
/// reporting). Returns whether it is active.
pub fn enable() -> bool {
    if !under_hypervisor() {
        return false;
    }
    let (_, ebx, ..) = call(CMD_GETVERSION, 0);
    if ebx != MAGIC {
        return false;
    }
    PRESENT.store(true, Ordering::Relaxed);
    let on = try_enable();
    ACTIVE.store(on, Ordering::Release);
    on
}

/// Whether absolute mode is on.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Whether the hypervisor offers the device (for listing it as an input device).
pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// Takes the queued reports, oldest first, calling `f` for each (from the IRQ 12 handler,
/// after a PS/2 packet). A device error re-enables absolute mode, as Linux does.
pub fn drain(mut f: impl FnMut(Report)) {
    for _ in 0..64 {
        let (status, ..) = call(CMD_ABSPOINTER_STATUS, 0);
        if status & STATUS_ERROR == STATUS_ERROR {
            let on = try_enable();
            ACTIVE.store(on, Ordering::Release);
            return;
        }
        if status & 0xffff < 4 {
            return;
        }
        let (flags, x, y, z) = call(CMD_ABSPOINTER_DATA, 4);
        if flags & RELATIVE_PACKET != 0 {
            // Absolute mode was asked for: a relative packet is stale
            continue;
        }
        let buttons = (flags & LEFT_BUTTON != 0) as u8 | ((flags & RIGHT_BUTTON != 0) as u8) << 1 | ((flags & MIDDLE_BUTTON != 0) as u8) << 2;
        f(Report { x: x.min(MAX) as u16, y: y.min(MAX) as u16, buttons, wheel: -(z as u8 as i8) });
    }
}
