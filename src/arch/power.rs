//! # Power: Power Off and Reset
//!
//! Turns the machine off or restarts it, for the shell's `shutdown`/`reboot` and the Linux
//! `reboot(2)` system call (how a login manager shuts the system down). The pool's pending
//! changes are committed first: the `txgd` task only does so every few seconds.

use uefi::runtime::ResetType;
use uefi::Status;

/// Commits the pool's pending changes before the power goes.
fn sync_pool() {
    crate::kprintln!("[power] Committing the pool...");
    if let Err(e) = crate::fs::ZfsClient::sync() {
        crate::kprintln!("[power] pool commit failed: {}", e);
    }
}

/// Commits the pool and powers the machine off (ACPI S5 on the usual virtual machines,
/// then the firmware's shutdown).
pub fn power_off() -> ! {
    sync_pool();
    crate::kprintln!("[power] Powering off.");
    unsafe {
        use x86_64::instructions::port::Port;

        // 1. VirtualBox PIIX3/4 ACPI PM1a_CNT (Port 0x4004)
        let mut p4004: Port<u16> = Port::new(0x4004);
        p4004.write(0x3400); // SLP_EN | (5 << 10)
        p4004.write(0x2000); // SLP_EN | (0 << 10)

        // 2. QEMU PIIX4 ACPI PM1a_CNT (Port 0x604)
        let mut p604: Port<u16> = Port::new(0x604);
        p604.write(0x2000);
        p604.write(0x3400);

        // 3. Bochs / Cloud / Q35 ACPI PM1a_CNT (Port 0xb004)
        let mut pb004: Port<u16> = Port::new(0xb004);
        pb004.write(0x2000);
        pb004.write(0x3400);

        // 4. QEMU debug exit (Port 0x501)
        let mut p501: Port<u8> = Port::new(0x501);
        p501.write(0x00);

        // 5. APM Power Off (Port 0xb2)
        let mut pb2: Port<u8> = Port::new(0xb2);
        pb2.write(0x00);
    }

    // 6. UEFI Runtime Services Shutdown
    uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
}

/// Commits the pool and restarts the machine.
pub fn reboot() -> ! {
    sync_pool();
    crate::kprintln!("[power] Restarting.");
    unsafe {
        use x86_64::instructions::port::Port;

        // 1. Standard x86 8042 Keyboard Controller pulse reset line (Port 0x64, 0xFE)
        let mut p64: Port<u8> = Port::new(0x64);
        p64.write(0xFE);

        // 2. Standard x86 PCI Reset Control Register (Port 0xCF9, 0x06)
        let mut pcf9: Port<u8> = Port::new(0xCF9);
        pcf9.write(0x06);
    }

    // 3. Fallback to UEFI cold reset
    uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None);
}
