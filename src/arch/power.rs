//! # Power: Power Off and Reset
//!
//! Turns the machine off or restarts it, for the shell's `shutdown`/`reboot` and the Linux
//! `reboot(2)` system call (how a login manager shuts the system down). The pool's pending
//! changes are committed first: the `txgd` task only does so every few seconds.

use core::sync::atomic::{AtomicBool, Ordering};
use uefi::runtime::ResetType;
use uefi::Status;

/// Commits the pool's pending changes before the power goes.
///
/// With the scheduler running, the commit runs in a task of its own and the power goes after
/// at most [`COMMIT_LIMIT_MS`] even if it has not finished (wave 7, Group B: with the live
/// stick pulled, the pool's disk is gone and a commit may never end; the restart must still
/// happen). Before the scheduler runs (the emergency shell), it is made here.
fn sync_pool() {
    crate::kprintln!("[power] Committing the pool...");
    // wave7 GB begin
    if !crate::task::is_active() {
        commit_now();
        return;
    }
    // (one commit task for every caller: a second shutdown request waits for the same one)
    if !COMMIT_STARTED.swap(true, Ordering::SeqCst) {
        COMMIT_DONE.store(false, Ordering::SeqCst);
        crate::task::spawn("pool-commit", commit_task, crate::task::TaskPriority::High);
    }
    let mut waited = 0;
    while !COMMIT_DONE.load(Ordering::SeqCst) {
        if waited >= COMMIT_LIMIT_MS {
            crate::kprintln!("[power] the pool commit did not finish within {} s (its disk gone?): going on without it", COMMIT_LIMIT_MS / 1000);
            return;
        }
        crate::task::sleep_ms(COMMIT_STEP_MS);
        waited += COMMIT_STEP_MS;
    }
    // wave7 GB end
}

// wave7 GB begin
/// The longest wait for the pool commit before the power goes (an ordinary commit takes a
/// second or two).
const COMMIT_LIMIT_MS: u64 = 30_000;
/// How often [`sync_pool`] looks whether the commit has finished.
const COMMIT_STEP_MS: u64 = 100;
/// The commit task has finished (well or not).
static COMMIT_DONE: AtomicBool = AtomicBool::new(false);
/// The commit task was started (the power goes after it; never started twice).
static COMMIT_STARTED: AtomicBool = AtomicBool::new(false);

/// The pool commit, reporting a failure.
fn commit_now() {
    if let Err(e) = crate::fs::ZfsClient::sync() {
        crate::kprintln!("[power] pool commit failed: {}", e);
    }
}

/// The task [`sync_pool`] starts: commits, says so, ends.
fn commit_task() {
    commit_now();
    COMMIT_DONE.store(true, Ordering::SeqCst);
    crate::task::exit();
}
// wave7 GB end

// wave8 GB begin
/// The live session's last shutdown step (the user's decision, wave 8): the pool is
/// committed and nothing needs the stick any more, so only now the console asks for it to be
/// removed, and the power goes when Enter is pressed (as Ubuntu's live system does). Pulling
/// the stick earlier crashes programs whose files are on it. Outside a live session, before
/// the scheduler runs, or when Hydra did not start from a disk partition (the image build's
/// live ISO, a CD: nothing to pull), nothing waits.
fn remove_stick_prompt() {
    if !crate::compat::linux::live::is_live() || !crate::task::is_active() || crate::arch::bootdisk::info().boot_part.is_none() {
        return;
    }
    // The console on the screen (the desktop has ended by now)
    crate::compat::linux::drm::request_vt_switch(false);
    crate::task::sleep_ms(500);
    let seen = crate::arch::keyboard::ENTER_PRESSES.load(Ordering::Relaxed);
    crate::kprintln!("");
    crate::kprintln!("    Hydra has stopped. Remove the installation stick (USB), then press Enter.");
    crate::kprintln!("");
    while crate::arch::keyboard::ENTER_PRESSES.load(Ordering::Relaxed) == seen {
        crate::task::sleep_ms(50);
    }
}
// wave8 GB end

/// Commits the pool and powers the machine off (ACPI S5 on the usual virtual machines,
/// then the firmware's shutdown).
pub fn power_off() -> ! {
    sync_pool();
    remove_stick_prompt(); // wave8 GB
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

    // 6. UEFI Runtime Services Shutdown (with the kernel's tables: the firmware's memory
    // is not mapped in a program's address space)
    crate::memory::paging::load_kernel_tables_for_good();
    uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
}

/// Commits the pool and restarts the machine.
pub fn reboot() -> ! {
    sync_pool();
    remove_stick_prompt(); // wave8 GB
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

    // 3. Fallback to UEFI cold reset (see power_off)
    crate::memory::paging::load_kernel_tables_for_good();
    uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None);
}
