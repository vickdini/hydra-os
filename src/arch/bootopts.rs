//! # Boot options: one place for the boot words, and the start menu
//!
//! The words come from, in this order:
//! 1. the boot entry's load options (a UEFI boot entry's optional data; QEMU test harnesses
//!    pass them so);
//! 2. the file `\hydra\options.txt` on the boot volume, if there is one: words on lines,
//!    `#` starts a comment (anyone can edit it on another computer: the stick's EFI
//!    partition is the drive Windows shows);
//! 3. the start menu's choice, when the boot volume has a `\hydra\menu` file (the
//!    installation stick has one): before anything else the firmware's text screen offers
//!    "1 Start Hydra, 2 Safe mode, 3 Safe mode with the text console only", and starts
//!    entry 1 after the wait the file names (`timeout=N`, 5 s without one; any other key
//!    stops the countdown).
//!
//! Safe mode ([`bootwords::SAFE`]): one processor (`cpus=1`), no IOMMU (`iommu=off`), no
//! PCID (`pcid=off`), the boot messages on screen (`verbose`); the display is the
//! firmware's framebuffer in every mode (Hydra has no graphics driver).
//!
//! [`init`] runs first thing at boot, before the heap exists (it allocates nothing);
//! the other modules ask [`say`] (or read [`ucs2`], the old form of the options).

use super::bootwords::{self, Words};
use spin::Once;

/// The words, decided once by [`init`].
static WORDS: Once<Words> = Once::new();

/// The words (none before [`init`]).
pub fn words() -> &'static Words {
    static NONE: Words = Words::new();
    WORDS.get().unwrap_or(&NONE)
}

/// Whether the boot words contain one of `words` (lower case).
pub fn say(words: &[&[u8]]) -> bool {
    words.iter().any(|w| self::words().has(w))
}

/// The boot words as UCS-2 bytes (what the load options looked like), for the modules that
/// parse those.
pub fn ucs2() -> alloc::vec::Vec<u8> {
    words().ucs2()
}

/// The `cpus=N` boot word: the most processors to start (at least 1).
pub fn max_cpus() -> Option<usize> {
    words().number(b"cpus=").map(|n| n.max(1) as usize)
}

/// Host builds (unit tests): no boot words.
#[cfg(not(target_os = "uefi"))]
pub fn init() {}

// wave11 GH begin
/// Host builds: no boot words.
#[cfg(not(target_os = "uefi"))]
pub fn early_word(_word: &[u8]) -> bool {
    false
}

/// Whether `\hydra\options.txt` has `word`, read before anything else (before [`init`]
/// and the start menu: for what must be decided first, the debug words of the
/// execute-disable test). Firmware file reads only, no heap.
#[cfg(target_os = "uefi")]
pub fn early_word(word: &[u8]) -> bool {
    let mut buf = [0u8; 2048];
    let Some(n) = read_small("\\hydra\\options.txt", &mut buf) else { return false };
    buf[..n].split(|c| c.is_ascii_whitespace()).any(|w| w == word)
}
// wave11 GH end

/// Reads the boot words and shows the start menu. Called first at boot, while the
/// firmware's services run and before the kernel's heap exists.
#[cfg(target_os = "uefi")]
pub fn init() {
    WORDS.call_once(|| {
        let mut w = Words::new();
        if let Ok(img) = uefi::boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(uefi::boot::image_handle()) {
            if let Some(opts) = img.load_options_as_bytes() {
                w.add_ucs2(opts);
            }
        }
        let mut buf = [0u8; 2048];
        if let Some(n) = read_small("\\hydra\\options.txt", &mut buf) {
            w.add_file(&buf[..n]);
        }
        if let Some(n) = read_small("\\hydra\\menu", &mut buf) {
            let wait = bootwords::menu_timeout(&buf[..n], 5);
            if let Some(extra) = menu(wait) {
                w.add_text(extra);
            }
        }
        w
    });
}

#[cfg(target_os = "uefi")]
/// Reads a small file of the boot volume into `buf` (no heap): its length, `None` if it
/// is missing or unreadable (a longer file is cut at `buf`'s size).
fn read_small(path: &str, buf: &mut [u8]) -> Option<usize> {
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    let mut root = crate::fs::bootfs::open_root_volume().ok()?;
    let mut name = [0u16; 64];
    let cpath = crate::fs::bootfs::path_to_cstr16(path, &mut name)?;
    let mut file = root.open(cpath, FileMode::Read, FileAttribute::empty()).ok()?.into_regular_file()?;
    let mut n = 0;
    while n < buf.len() {
        match crate::fs::bootfs::fw_read(&mut file, &mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    let _ = file.close();
    Some(n)
}

#[cfg(target_os = "uefi")]
/// Writes `s` on the firmware's text screen.
fn out(s: &str) {
    use core::fmt::Write;
    uefi::system::with_stdout(|o| {
        let _ = o.write_str(s);
    });
}

#[cfg(target_os = "uefi")]
/// The start menu on the firmware's text screen: the words the chosen entry adds (`None`
/// for entry 1, or when there is no keyboard to ask).
fn menu(wait: u32) -> Option<&'static str> {
    use bootwords::{Menu, MenuKey};
    use uefi::proto::console::text::Key;
    out("\r\n  Hydra - how to start\r\n\r\n");
    out("    1  Start Hydra\r\n");
    out("    2  Safe mode: one processor, no IOMMU, no PCID, messages on screen\r\n");
    out("    3  Safe mode, text console only (no desktop)\r\n");
    // wave11 GG: one safe-mode change at a time (to find which one matters)
    out("    4  One processor only (cpus=1)\r\n");
    out("    5  No PCID only (pcid=off)\r\n");
    out("    6  No IOMMU only (iommu=off)\r\n");
    // wave11 GH: the start's memory and interrupt changes one at a time (NUC run 11)
    out("    7  Test: no firmware interrupt gates (fwidt=off)\r\n");
    out("    8  Test: memory as in run 10 (fwmem=old)\r\n");
    out("    9  Test: 7 and 8\r\n\r\n");
    if wait == 0 {
        return None;
    }
    // Keys pressed before the menu (the one held for the firmware's boot menu) do not count
    for _ in 0..64 {
        if uefi::system::with_stdin(|i| i.read_key().ok().flatten()).is_none() {
            break;
        }
    }
    let mut m = Menu::new(wait);
    let mut shown = u32::MAX;
    let mut was_counting = true;
    loop {
        if m.counting && m.left / 10 != shown {
            shown = m.left / 10;
            let mut line = crate::console::FixedBuf::new();
            let _ = core::fmt::Write::write_fmt(&mut line, format_args!("\r  Press 1 to 9. Starting entry 1 in {} s ", shown));
            out(line.as_str());
        }
        let key = uefi::system::with_stdin(|i| i.read_key().ok().flatten()).map(|k| match k {
            Key::Printable(c) => MenuKey::Char(char::from(c)),
            Key::Special(_) => MenuKey::Special,
        });
        if let Some(words) = m.step(key) {
            out("\r\n\r\n");
            if !words.is_empty() {
                out("  Starting with: ");
                out(words);
                out("\r\n");
            }
            return (!words.is_empty()).then_some(words);
        }
        if was_counting && !m.counting {
            was_counting = false;
            // (the firmware restarts the machine after 5 minutes in a boot program otherwise)
            let _ = uefi::boot::set_watchdog_timer(0, 0x10000, None);
            out("\r  Press 1 to 9 (entry 1 starts after 30 s without a key).   ");
        }
        uefi::boot::stall(core::time::Duration::from_millis(100));
    }
}
