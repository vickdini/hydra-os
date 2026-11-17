//! # The console after boot: the desktop, then `hydra-shell`, watched
//!
//! At the end of boot the kernel's main thread (task 0) comes here. It starts the KDE
//! desktop (unless asked not to), then runs the console shell `hydra-shell` (ring 3) on the
//! text console and watches it: when it ends it is started again (a fresh session, login
//! first).
//!
//! ## The emergency prompt
//! The tiny in-kernel prompt (`crate::shell`) takes the console instead when user space is
//! broken or when asked for:
//! - `hydra-shell` cannot be started (a broken image, no memory);
//! - `hydra-shell` ended 3 times in a row, each within 30 seconds of its start (QEMU's
//!   `opt/hydra/console` fw_cfg value `crash` makes it end at once, to test this);
//! - asked for at boot: QEMU's `opt/hydra/boot` fw_cfg value `emergency`, the boot entry's
//!   option word `emergency`, or a file `\hydra\emergency` on the EFI partition.
//!
//! The prompt asks for the same login as `hydra-shell` (the rules are the kernel's,
//! `session`), when the installed system can check passwords. Its `ushell` command goes back
//! to `hydra-shell`.

use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};
use uefi::proto::console::text::Color;

use crate::console::set_color;

/// The emergency prompt was asked for at boot.
static EMERGENCY_AT_BOOT: AtomicBool = AtomicBool::new(false);
/// What asked for it.
static EMERGENCY_BY: spin::Mutex<&'static str> = spin::Mutex::new("");

/// A run of `hydra-shell` shorter than this many ticks counts as a failure (30 s).
const QUICK_EXIT_TICKS: u64 = 30 * 100;
/// Failed runs in a row before the emergency prompt takes over.
const MAX_QUICK_EXITS: u32 = 3;

/// Reads the console's boot options. Called while the firmware's boot services still run
/// (the boot entry's options and the EFI partition are reachable only then).
pub fn discover() {
    let mut cfg = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/boot", &mut cfg).map(|n| &cfg[..n]);
    let by = if fw.is_some_and(|v| v.starts_with(b"emergency")) {
        Some("QEMU fw_cfg opt/hydra/boot=emergency")
    } else if load_options_say(b"emergency") {
        Some("boot option 'emergency'")
    } else if crate::fs::bootfs::file_exists("\\hydra\\emergency") {
        Some("file \\hydra\\emergency on the EFI partition")
    } else {
        None
    };
    // The Linux calls moved to linux-server go back to the in-kernel code (`crate::lx`)
    if load_options_say(b"lx=kernel") {
        crate::lx::KERNEL_BY_BOOT_OPTION.store(true, Ordering::Release);
    }
    if let Some(by) = by {
        *EMERGENCY_BY.lock() = by;
        EMERGENCY_AT_BOOT.store(true, Ordering::Release);
    }
}

/// Whether the boot entry's load options contain `word` (lower case).
fn load_options_say(word: &[u8]) -> bool {
    let Ok(img) = uefi::boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(uefi::boot::image_handle()) else {
        return false;
    };
    let Some(opts) = img.load_options_as_bytes() else { return false };
    let mut text = [0u8; 512];
    let mut n = 0;
    for c in opts.chunks_exact(2).take(text.len()) {
        text[n] = if c[1] == 0 { c[0].to_ascii_lowercase() } else { b'?' };
        n += 1;
    }
    text[..n].windows(word.len()).any(|w| w == word)
}

/// After the bare-metal transition, starts the KDE desktop (`linux plasma`) at once, unless
/// a key is already waiting (pressed during boot) or QEMU's `opt/hydra/boot` fw_cfg value
/// asks for the console (`shell`, test harnesses; `emergency`): then the console stays.
/// The console is also reachable from the desktop on the first virtual terminal
/// (Ctrl+Alt+F1).
fn start_desktop(emergency: bool) {
    let key = crate::console::read_key().is_some();
    let asked = crate::arch::fwcfg::read_file("opt/hydra/boot").is_some_and(|v| v.starts_with(b"shell") || v.starts_with(b"emergency"));
    if key || asked || emergency {
        crate::video::splash::end();
        set_color(Color::LightCyan, Color::Black);
        crate::println!("[*] Hydra shell (the desktop was not started; type 'linux plasma' to start it)");
        set_color(Color::White, Color::Black);
    } else {
        set_color(Color::LightCyan, Color::Black);
        crate::println!("[*] Starting KDE Plasma (the Hydra shell is on Ctrl+Alt+F1)");
        set_color(Color::White, Color::Black);
        super::linux::plasma("/ubuntu", false);
        if !crate::video::splash::is_desktop_starting() {
            // No desktop to wait for: the boot logo makes way for the console
            crate::video::splash::end();
        }
    }
}

/// Runs the console for good: the desktop, then `hydra-shell` (started again whenever it
/// ends), or the emergency prompt when it cannot run.
pub fn run() -> ! {
    let at_boot = EMERGENCY_AT_BOOT.load(Ordering::Acquire);
    start_desktop(at_boot);
    let mut emergency: Option<String> = if at_boot { Some(format!("asked for at boot ({})", *EMERGENCY_BY.lock())) } else { None };
    let mut quick_exits = 0u32;
    loop {
        if let Some(reason) = emergency.take() {
            crate::shell::run(&reason);
            quick_exits = 0;
        }
        super::session::begin();
        // QEMU's opt/hydra/console=crash: a hydra-shell that ends at once (tests this fallback)
        let crash = crate::arch::fwcfg::read_file("opt/hydra/console").is_some_and(|v| v.starts_with(b"crash"));
        let args: &[&str] = if crash { &["hydra-shell", "--test-crash"] } else { &["hydra-shell"] };
        let id = match super::launch_shell(args, 1000, 1000) {
            Ok(id) => id,
            Err(e) => {
                emergency = Some(format!("hydra-shell cannot start: {}", e));
                continue;
            }
        };
        let started = crate::arch::pit::ticks();
        // The keys belong to hydra-shell: only check now and then whether it still runs
        while crate::task::is_task_alive(id) {
            crate::task::sleep_ms(50);
        }
        super::revoke_console(id);
        set_color(Color::White, Color::Black);
        if crate::arch::pit::ticks().saturating_sub(started) < QUICK_EXIT_TICKS {
            quick_exits += 1;
        } else {
            quick_exits = 0;
        }
        if quick_exits >= MAX_QUICK_EXITS {
            emergency = Some(format!("hydra-shell ended {} times in a row, each within {} s of its start", quick_exits, QUICK_EXIT_TICKS / 100));
        } else {
            set_color(Color::Yellow, Color::Black);
            crate::println!("[!] The console shell (process {}) ended; starting it again.", id.0);
            set_color(Color::White, Color::Black);
        }
    }
}
