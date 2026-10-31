//! # Shell Commands: System Power Management (`shutdown`, `reboot`, `halt`)
//!
//! Provides commands to shut down the machine, perform hardware resets, or enter low-power halt state.

use uefi::proto::console::text::Color;
use uefi::runtime::ResetType;
use uefi::Status;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command powering off the hardware system via UEFI runtime services or ACPI.
pub struct ShutdownCommand;

impl Command for ShutdownCommand {
    fn name(&self) -> &'static str {
        "shutdown"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["poweroff", "exit", "logout"]
    }

    fn description(&self) -> &'static str {
        "Power off system using ACPI S5 and UEFI runtime shutdown"
    }

    fn usage(&self) -> &'static str {
        "shutdown"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Powering down system...");

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
}

/// Shell command resetting and rebooting the hardware system.
pub struct RebootCommand;

impl Command for RebootCommand {
    fn name(&self) -> &'static str {
        "reboot"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["restart"]
    }

    fn description(&self) -> &'static str {
        "Reboot system via 8042 keyboard pulse, PCI reset, and UEFI cold reset"
    }

    fn usage(&self) -> &'static str {
        "reboot"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Rebooting system...");

        // 1. Standard x86 8042 Keyboard Controller pulse reset line (Port 0x64, 0xFE)
        unsafe {
            use x86_64::instructions::port::Port;
            let mut p64: Port<u8> = Port::new(0x64);
            p64.write(0xFE);

            // 2. Standard x86 PCI Reset Control Register (Port 0xCF9, 0x06)
            let mut pcf9: Port<u8> = Port::new(0xCF9);
            pcf9.write(0x06);
        }

        // 3. Fallback to UEFI cold reset
        uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None);
    }
}

/// Shell command halting the CPU into an infinite low-power loop (`HLT`).
pub struct HaltCommand;

impl Command for HaltCommand {
    fn name(&self) -> &'static str {
        "halt"
    }

    fn description(&self) -> &'static str {
        "Disable interrupts and halt the CPU"
    }

    fn usage(&self) -> &'static str {
        "halt"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Halting CPU. Hardware interrupts disabled.");
        x86_64::instructions::interrupts::disable();
        loop {
            x86_64::instructions::hlt();
        }
    }
}
