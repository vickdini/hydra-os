//! # EHCI controllers left running by the firmware (wave 11, Group G)
//!
//! Intel chipsets of the 7 to 9 series (the NUC's Lynx Point) have EHCI USB 2 controllers
//! next to the xHCI one. Hydra drives only xHCI (the supervisor switches the ports to it),
//! but the firmware's EHCI driver may still be running: its schedules keep the controller
//! reading memory, which the IOMMU then blocks (`[iommu] blocked DMA: device 00:1d.0
//! (firmware)` on the NUC), and its legacy-support SMIs may fire at any time.
//!
//! So before DMA remapping is turned on, every EHCI controller (PCI class 0C/03, interface
//! 20) is taken from the firmware and stopped, as Linux's `quirk_usb_disable_ehci` does:
//! 1. **BIOS handoff:** in the controller's extended capabilities (PCI configuration space,
//!    `HCCPARAMS.EECP`), the legacy support capability (`USBLEGSUP`, id 1) gets the "OS
//!    owned" semaphore; the firmware is given up to a second to drop "BIOS owned" (else it
//!    is cleared by force); the SMI enables (`USBLEGCTLSTS`) are turned off.
//! 2. **Halt:** `USBCMD.RS` (and the schedule enables) cleared, then up to 20 ms for
//!    `USBSTS.HCHalted`; interrupts off, status cleared.
//! 3. **No more DMA:** bus mastering off in the PCI command register.
//!
//! The steps are plain logic over [`Hw`] (configuration space, registers, a delay), so the
//! host tests drive them on a simulated controller.

/// What the steps need from the machine.
pub trait Hw {
    /// A dword of the controller's PCI configuration space.
    fn cfg_r32(&mut self, off: u8) -> u32;
    /// Writes a dword of its configuration space.
    fn cfg_w32(&mut self, off: u8, v: u32);
    /// A register of its memory window (BAR 0).
    fn mmio_r32(&mut self, off: usize) -> u32;
    /// Writes a register of its memory window.
    fn mmio_w32(&mut self, off: usize, v: u32);
    /// Waits about `us` microseconds.
    fn delay_us(&mut self, us: u64);
}

/// PCI command register and its bits.
const PCI_COMMAND: u8 = 0x04;
const CMD_MEMORY: u32 = 1 << 1;
const CMD_MASTER: u32 = 1 << 2;

/// Capability registers.
const CAPLENGTH: usize = 0x00;
const HCCPARAMS: usize = 0x08;
/// Operational registers (at `CAPLENGTH`).
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const USBINTR: usize = 0x08;
const CMD_RUN: u32 = 1 << 0;
const CMD_PSE: u32 = 1 << 4;
const CMD_ASE: u32 = 1 << 5;
const STS_HALTED: u32 = 1 << 12;

/// Legacy support capability.
const CAP_LEGSUP: u32 = 1;
const LEGSUP_BIOS_OWNED: u32 = 1 << 16;
const LEGSUP_OS_OWNED: u32 = 1 << 24;
/// `USBLEGCTLSTS`: only "SMI on OS ownership change" stays enabled (as Linux).
const LEGCTLSTS_SOOE: u32 = 1 << 13;

/// What happened to one controller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Its memory window answered (decoding on, registers readable).
    pub reachable: bool,
    /// The firmware owned it (legacy support said "BIOS owned").
    pub bios_owned: bool,
    /// The firmware did not let go in time: ownership was taken by force.
    pub forced: bool,
    /// It was running (`USBCMD.RS`).
    pub was_running: bool,
    /// It is halted now (or was).
    pub halted: bool,
}

/// Takes one EHCI controller from the firmware, halts it and turns its bus mastering off.
pub fn quiesce(hw: &mut impl Hw) -> Outcome {
    let mut out = Outcome::default();
    let cmd = hw.cfg_r32(PCI_COMMAND);
    if cmd & CMD_MEMORY != 0 {
        let cap = hw.mmio_r32(CAPLENGTH);
        if cap != u32::MAX {
            out.reachable = true;
            let caplen = (cap & 0xFF) as usize;
            let eecp = ((hw.mmio_r32(HCCPARAMS) >> 8) & 0xFF) as u8;
            handoff(hw, eecp, &mut out);
            halt(hw, caplen, &mut out);
        }
    }
    // No DMA from here on, whatever state it is in
    let cmd = hw.cfg_r32(PCI_COMMAND);
    hw.cfg_w32(PCI_COMMAND, cmd & 0xFFFF & !CMD_MASTER);
    out
}

/// Step 1: the legacy support capability's handoff.
fn handoff(hw: &mut impl Hw, mut eecp: u8, out: &mut Outcome) {
    // Capabilities start at 0x40 in configuration space; at most a few of them
    for _ in 0..16 {
        if eecp < 0x40 {
            return;
        }
        let cap = hw.cfg_r32(eecp);
        if cap & 0xFF == CAP_LEGSUP {
            if cap & LEGSUP_BIOS_OWNED != 0 {
                out.bios_owned = true;
                hw.cfg_w32(eecp, cap | LEGSUP_OS_OWNED);
                // Up to a second for the firmware's SMI handler to let go
                let mut left = 1000;
                while hw.cfg_r32(eecp) & LEGSUP_BIOS_OWNED != 0 && left > 0 {
                    hw.delay_us(1000);
                    left -= 1;
                }
                if hw.cfg_r32(eecp) & LEGSUP_BIOS_OWNED != 0 {
                    out.forced = true;
                    let now = hw.cfg_r32(eecp);
                    hw.cfg_w32(eecp, (now & !LEGSUP_BIOS_OWNED) | LEGSUP_OS_OWNED);
                }
            }
            // SMIs off (only the one on an ownership change stays, as Linux leaves it)
            hw.cfg_w32(eecp.wrapping_add(4), LEGCTLSTS_SOOE);
            return;
        }
        eecp = ((cap >> 8) & 0xFF) as u8;
    }
}

/// Step 2: stop the controller and its interrupts.
fn halt(hw: &mut impl Hw, caplen: usize, out: &mut Outcome) {
    let sts = hw.mmio_r32(caplen + USBSTS);
    let cmd = hw.mmio_r32(caplen + USBCMD);
    out.was_running = cmd & CMD_RUN != 0;
    if sts & STS_HALTED == 0 || out.was_running {
        hw.mmio_w32(caplen + USBCMD, cmd & !(CMD_RUN | CMD_PSE | CMD_ASE));
        let mut left = 200;
        loop {
            hw.mmio_w32(caplen + USBSTS, 0x3F);
            hw.delay_us(100);
            let s = hw.mmio_r32(caplen + USBSTS);
            if s == u32::MAX || s & STS_HALTED != 0 {
                break;
            }
            left -= 1;
            if left == 0 {
                break;
            }
        }
    }
    out.halted = hw.mmio_r32(caplen + USBSTS) & STS_HALTED != 0;
    hw.mmio_w32(caplen + USBINTR, 0);
    hw.mmio_w32(caplen + USBSTS, 0x3F);
}

/// One controller on the machine: configuration space by port I/O, registers through the
/// direct map.
struct Machine {
    dev: super::pci::PciDevice,
    regs: *mut u32,
}

impl Hw for Machine {
    fn cfg_r32(&mut self, off: u8) -> u32 {
        super::pci::pci_read_u32(self.dev.bus, self.dev.device, self.dev.function, off)
    }
    fn cfg_w32(&mut self, off: u8, v: u32) {
        super::pci::pci_write_u32(self.dev.bus, self.dev.device, self.dev.function, off, v)
    }
    fn mmio_r32(&mut self, off: usize) -> u32 {
        // SAFETY: inside the controller's register window (BAR 0 is at least 256 bytes)
        unsafe { self.regs.add(off / 4).read_volatile() }
    }
    fn mmio_w32(&mut self, off: usize, v: u32) {
        // SAFETY: as above
        unsafe { self.regs.add(off / 4).write_volatile(v) }
    }
    fn delay_us(&mut self, us: u64) {
        // The kernel's clock (the timer runs at this point of the takeover); a bound on the
        // spins in case it does not move
        let end = super::pit::now_ns().saturating_add(us * 1000);
        let mut spins = us.saturating_mul(10_000);
        while super::pit::now_ns() < end && spins > 0 {
            core::hint::spin_loop();
            spins -= 1;
        }
    }
}

/// Takes every EHCI controller from the firmware and stops it. Called at takeover, before
/// the IOMMU starts translating (and whether or not it does).
pub fn quiesce_all() {
    for dev in super::pci::find_all_class(0x0C, 0x03) {
        if super::pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09) != 0x20 {
            continue; // UHCI, OHCI or xHCI
        }
        let bar = super::pci::bar_address(&dev, 0);
        let name = alloc::format!("{:02x}:{:02x}.{}", dev.bus, dev.device, dev.function);
        let o = if bar == 0 || bar >= 4 << 30 {
            // No window to reach it through: at least no DMA
            let mut m = Machine { dev, regs: core::ptr::null_mut() };
            let cmd = m.cfg_r32(PCI_COMMAND);
            m.cfg_w32(PCI_COMMAND, cmd & 0xFFFF & !(CMD_MASTER | CMD_MEMORY));
            Outcome::default()
        } else {
            let regs = crate::memory::frame_allocator::phys_to_virt(bar) as *mut u32;
            quiesce(&mut Machine { dev, regs })
        };
        crate::kprintln!("{}", describe(&name, &o));
    }
}

/// The log line for one controller.
pub fn describe(name: &str, o: &Outcome) -> alloc::string::String {
    let owner = match (o.bios_owned, o.forced) {
        (false, _) => "",
        (true, false) => "; the firmware handed it over",
        (true, true) => "; the firmware did not let go: taken by force",
    };
    if !o.reachable {
        return alloc::format!("[ehci] {}: registers not reachable; bus mastering off", name);
    }
    alloc::format!(
        "[ehci] {}: {}{}; bus mastering off (the ports are xHCI's)",
        name,
        match (o.was_running, o.halted) {
            (true, true) => "was running: halted",
            (true, false) => "was running: DID NOT HALT",
            (false, true) => "halted",
            (false, false) => "not halted",
        },
        owner
    )
}
