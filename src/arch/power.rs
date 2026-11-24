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
///
/// wave11 GH: the stick being gone also ends the wait: pulled before (the restart then goes
/// on at once: nothing to ask for any more) or while the prompt shows (the user did what it
/// says; Enter is not needed then). A task watches the stick ([`watch_stick`]) so that a
/// disk call that hangs never holds the prompt up.
fn remove_stick_prompt() {
    if !crate::compat::linux::live::is_live() || !crate::task::is_active() || crate::arch::bootdisk::info().boot_part.is_none() {
        return;
    }
    // wave11 GH begin
    let watched = match crate::arch::bootlog::boot_disk() {
        Some(idx) => {
            STICK_DISK.store(idx, Ordering::SeqCst);
            STICK_STATE.store(STICK_UNKNOWN, Ordering::SeqCst);
            crate::task::spawn("stick-watch", watch_stick, crate::task::TaskPriority::High);
            // The first look (a stick already gone answers at once)
            for _ in 0..30 {
                if STICK_STATE.load(Ordering::SeqCst) != STICK_UNKNOWN {
                    break;
                }
                crate::task::sleep_ms(50);
            }
            true
        }
        None => false,
    };
    if STICK_STATE.load(Ordering::SeqCst) == STICK_GONE {
        crate::kprintln!("[power] the installation stick is already removed: no prompt");
        return;
    }
    // wave11 GH end
    // The console on the screen (the desktop has ended by now)
    crate::compat::linux::drm::request_vt_switch(false);
    crate::task::sleep_ms(500);
    let seen = crate::arch::keyboard::ENTER_PRESSES.load(Ordering::Relaxed);
    crate::kprintln!("");
    crate::kprintln!("    Hydra has stopped. Remove the installation stick (USB), then press Enter.");
    crate::kprintln!("");
    while crate::arch::keyboard::ENTER_PRESSES.load(Ordering::Relaxed) == seen {
        // wave11 GH: removing the stick is the answer too
        if watched && STICK_STATE.load(Ordering::SeqCst) == STICK_GONE {
            crate::kprintln!("[power] the installation stick was removed");
            break;
        }
        crate::task::sleep_ms(50);
    }
    STICK_STATE.store(STICK_DONE, Ordering::SeqCst);
}
// wave8 GB end

// wave11 GH begin
/// [`watch_stick`]'s findings: not looked yet, there, gone; done: the watch ends.
const STICK_UNKNOWN: u8 = 0;
const STICK_THERE: u8 = 1;
const STICK_GONE: u8 = 2;
const STICK_DONE: u8 = 3;
static STICK_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(STICK_UNKNOWN);
/// The stick's disk index (`fs::blockdev`).
static STICK_DISK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Reads the stick's first sector twice a second until it fails (the stick is gone) or the
/// prompt has ended.
fn watch_stick() {
    let idx = STICK_DISK.load(Ordering::SeqCst);
    let mut sector = [0u8; 512];
    loop {
        if STICK_STATE.load(Ordering::SeqCst) == STICK_DONE {
            break;
        }
        if !crate::arch::bootlog::disk_present(idx, &mut sector) {
            // (never over STICK_DONE: the prompt has ended)
            let mut s = STICK_STATE.load(Ordering::SeqCst);
            while s != STICK_DONE {
                match STICK_STATE.compare_exchange(s, STICK_GONE, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(now) => s = now,
                }
            }
            break;
        }
        let _ = STICK_STATE.compare_exchange(STICK_UNKNOWN, STICK_THERE, Ordering::SeqCst, Ordering::SeqCst);
        crate::task::sleep_ms(500);
    }
    crate::task::exit();
}
// wave11 GH end

// wave11 GH begin
/// The FADT's power-off and reset values and the DSDT's `\_S5` sleep types, read before
/// `ExitBootServices` ([`discover`]).
static ACPI: spin::Mutex<Option<(super::acpi_s5::Fadt, Option<(u8, u8)>)>> = spin::Mutex::new(None);

/// Reads the FADT and the DSDT's `\_S5` (while the firmware's identity map still reaches
/// the ACPI tables) and says what power-off and reset will use.
pub fn discover() {
    let Some(fadt) = find_table(b"FACP") else {
        crate::kprintln!("[power] no FADT: power-off and restart use the firmware and the usual ports");
        return;
    };
    let Some(f) = super::acpi_s5::parse_fadt(&fadt) else { return };
    let s5 = if f.dsdt == 0 {
        None
    } else {
        unsafe {
            let len = core::ptr::read_unaligned((f.dsdt + 4) as *const u32) as usize;
            let t = core::slice::from_raw_parts(f.dsdt as *const u8, len.clamp(36, 4 << 20));
            if &t[..4] == b"DSDT" { super::acpi_s5::s5_sleep_types(t) } else { None }
        }
    };
    crate::kprintln!(
        "[power] ACPI: PM1a control {:#x}, PM1b {:#x}, soft-off sleep type {}, SMI command {:#x}/{:#x}, reset register {}",
        f.pm1a_cnt,
        f.pm1b_cnt,
        s5.map_or(alloc::string::String::from("not found"), |(a, b)| alloc::format!("{}/{}", a, b)),
        f.smi_cmd,
        f.acpi_enable,
        f.reset.map_or(alloc::string::String::from("none"), |(sp, a, v)| alloc::format!("space {} {:#x} value {:#x}", sp, a, v))
    );
    *ACPI.lock() = Some((f, s5));
}

/// A copy of the ACPI table with signature `sig` (from the RSDT/XSDT), if there is one.
fn find_table(sig: &[u8; 4]) -> Option<alloc::vec::Vec<u8>> {
    let rsdp = crate::arch::iommu::acpi_rsdp()?;
    unsafe {
        let rd32 = |p: u64| core::ptr::read_unaligned(p as *const u32);
        let rd64 = |p: u64| core::ptr::read_unaligned(p as *const u64);
        if core::slice::from_raw_parts(rsdp as *const u8, 8) != b"RSD PTR " {
            return None;
        }
        let revision = *((rsdp + 15) as *const u8);
        let (sdt, entry) = if revision >= 2 && rd64(rsdp + 24) != 0 { (rd64(rsdp + 24), 8) } else { (rd32(rsdp + 16) as u64, 4) };
        if sdt == 0 {
            return None;
        }
        let len = rd32(sdt + 4) as u64;
        let mut at = sdt + 36;
        while at + entry <= sdt + len {
            let t = if entry == 8 { rd64(at) } else { rd32(at) as u64 };
            at += entry;
            if t != 0 && core::slice::from_raw_parts(t as *const u8, 4) == sig {
                let n = (rd32(t + 4) as usize).min(64 * 1024);
                return Some(core::slice::from_raw_parts(t as *const u8, n).to_vec());
            }
        }
    }
    None
}

/// Whether Hydra runs in a virtual machine (CPUID's hypervisor bit).
#[cfg(target_os = "uefi")]
fn in_vm() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0
}

/// Host builds (unit tests): as in a virtual machine (the ports are recorded).
#[cfg(not(target_os = "uefi"))]
fn in_vm() -> bool {
    true
}

/// Busy-waits about `ms` milliseconds.
fn spin_ms(ms: u64) {
    let end = crate::arch::pit::now_ns() + ms * 1_000_000;
    while crate::arch::pit::now_ns() < end {
        core::hint::spin_loop();
    }
}

/// ACPI soft-off (S5) through the FADT's PM1 control registers, switching the firmware to
/// ACPI mode first if it is not. Returns if the machine is still on.
fn acpi_power_off() {
    use x86_64::instructions::port::Port;
    let Some((f, Some((a, b)))) = *ACPI.lock() else { return };
    if f.pm1a_cnt == 0 {
        return;
    }
    unsafe {
        let mut cnt: Port<u16> = Port::new(f.pm1a_cnt);
        if cnt.read() & 1 == 0 && f.smi_cmd != 0 && f.acpi_enable != 0 {
            // SCI_EN clear: the firmware is in legacy mode; ask it for ACPI mode (up to 1 s)
            Port::<u8>::new(f.smi_cmd).write(f.acpi_enable);
            for _ in 0..100 {
                if cnt.read() & 1 != 0 {
                    break;
                }
                spin_ms(10);
            }
        }
        let v = super::acpi_s5::pm1_sleep_value(cnt.read(), a);
        if f.pm1b_cnt != 0 {
            let mut cntb: Port<u16> = Port::new(f.pm1b_cnt);
            let vb = super::acpi_s5::pm1_sleep_value(cntb.read(), b);
            cntb.write(vb);
        }
        cnt.write(v);
    }
    spin_ms(1000);
}

/// The FADT's reset register, if it has an I/O or memory one.
fn acpi_reset() {
    let Some((f, _)) = *ACPI.lock() else { return };
    let Some((space, addr, value)) = f.reset else { return };
    unsafe {
        match space {
            1 => x86_64::instructions::port::Port::<u8>::new(addr as u16).write(value),
            0 => core::ptr::write_volatile(crate::memory::frame_allocator::phys_to_virt(addr), value),
            _ => return,
        }
    }
    spin_ms(500);
}

/// Restarts the machine at once (no pool commit, no prompt): the panic and boot-log paths.
/// A warm restart (the memory, and the boot log in it, stays).
pub fn hard_reset() -> ! {
    x86_64::instructions::interrupts::disable();
    acpi_reset();
    unsafe {
        use x86_64::instructions::port::Port;
        Port::<u8>::new(0xCF9).write(0x02);
        spin_ms(1);
        Port::<u8>::new(0xCF9).write(0x06);
        spin_ms(500);
        Port::<u8>::new(0x64).write(0xFE);
        spin_ms(500);
    }
    crate::memory::paging::load_kernel_tables_for_good();
    uefi::runtime::reset(ResetType::WARM, Status::SUCCESS, None);
}
// wave11 GH end

/// Commits the pool, writes the boot log and powers the machine off: ACPI S5 from the
/// firmware's tables, then the firmware's shutdown, then (in a virtual machine only) the
/// usual virtual machines' ports.
pub fn power_off() -> ! {
    sync_pool();
    crate::arch::bootlog::at_power("powered off"); // wave11 GH
    remove_stick_prompt(); // wave8 GB
    crate::kprintln!("[power] Powering off.");
    acpi_power_off(); // wave11 GH
    // The firmware's shutdown (with the kernel's tables: the firmware's memory is not
    // mapped in a program's address space). On real hardware before the ports below: they
    // are QEMU's and VirtualBox's (on a real chipset 0xB2 is the SMI command port)
    if !in_vm() {
        crate::memory::paging::load_kernel_tables_for_good();
        uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
    }
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
    }

    // 5. UEFI Runtime Services Shutdown
    crate::memory::paging::load_kernel_tables_for_good();
    uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
}

/// Commits the pool, writes the boot log and restarts the machine: the FADT's reset
/// register, the keyboard controller, the chipset's reset port 0xCF9, then the firmware.
pub fn reboot() -> ! {
    sync_pool();
    crate::arch::bootlog::at_power("restarted"); // wave11 GH
    remove_stick_prompt(); // wave8 GB
    crate::kprintln!("[power] Restarting.");
    acpi_reset(); // wave11 GH
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
