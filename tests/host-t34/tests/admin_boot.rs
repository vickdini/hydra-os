//! `src/admin/boot.rs`: the console after boot (the desktop, then `hydra-shell`, watched)
//! and the boot options. The emergency prompt asked for at boot is in
//! `admin_boot_emergency.rs` (it stays set for the whole test binary).

mod common;
use common::*;
use k::admin::boot;

/// UCS-2 bytes of `s`.
fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

#[test]
fn load_options_become_lower_case_ascii() {
    // Characters beyond Latin-1 become '?' (Latin-1 bytes pass as they are)
    let (t, n) = boot::options_text(&ucs2("Debug LX=Kernel \u{416}\u{e9}"));
    assert_eq!(&t[..n], b"debug lx=kernel ?\xe9");
    // An odd byte at the end is dropped; at most 512 characters
    let (_, n) = boot::options_text(&[b'a', 0, b'b']);
    assert_eq!(n, 1);
    let (t, n) = boot::options_text(&ucs2(&"X".repeat(600)));
    assert_eq!(n, 512);
    assert!(t.iter().all(|&b| b == b'x'));
    let (_, n) = boot::options_text(&[]);
    assert_eq!(n, 0);
}

#[test]
fn boot_options_set_the_switches() {
    use core::sync::atomic::Ordering::Acquire;
    let _g = setup();
    boot::discover_with(None, Some(b"quiet lx=kernel lx.net=linux persona=fbsd-stub"));
    assert!(k::lx::KERNEL_BY_BOOT_OPTION.load(Acquire));
    assert!(k::personality::STUB_BY_BOOT_OPTION.load(Acquire));
    assert_eq!(fake::take_log(), vec!["boot_words quiet lx=kernel lx.net=linux persona=fbsd-stub", "personality_init"]);
    // No options: no boot words, the personality hook still starts
    boot::discover_with(Some(b"shell"), None);
    assert_eq!(fake::take_log(), vec!["personality_init"]);
}

#[test]
fn discover_reads_fw_cfg_and_survives_without_load_options() {
    let _g = setup();
    // On the host the firmware has no loaded-image protocol: no options
    fake::with(|s| {
        s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec());
    });
    boot::discover();
    assert_eq!(fake::take_log(), vec!["personality_init"]);
}

/// Ends `boot::run` (which never returns) when `stop` says so, from the fake clock.
fn stop_when(stop: impl Fn(&fake::State) -> bool + 'static) {
    fake::with(|s| {
        s.on_sleep = Some(Box::new(move |st: &mut fake::State| {
            if stop(st) {
                panic!("stop the console");
            }
            // A test that never reaches its end stops here instead of spinning forever
            assert!(st.clock_ns < 3_600_000_000_000, "runaway console loop");
        }))
    });
}

fn shell_starts(st: &fake::State) -> usize {
    st.log.iter().filter(|l| l.starts_with("spawn_native hydra-shell")).count()
}

#[test]
fn the_desktop_starts_unless_asked_not_to() {
    let _g = setup();
    stop_when(|st| shell_starts(st) >= 1);
    expect_panic("stop the console", || boot::run());
    let out = fake::take_out();
    assert!(out.starts_with("[*] Starting KDE Plasma (the Hydra shell is on Ctrl+Alt+F1)\n"), "{}", out);
    // No KDE installed: the console takes the screen
    assert!(out.contains("[!] linux plasma: no KDE in /ubuntu"));
    assert!(!k::video::splash::is_active());
}

#[test]
fn the_console_stays_when_asked_or_a_key_waits() {
    let _g = setup();
    fake::with(|s| s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec()));
    stop_when(|st| shell_starts(st) >= 1);
    expect_panic("stop the console", || boot::run());
    assert!(fake::take_out().starts_with("[*] Hydra shell (the desktop was not started; type 'linux plasma' to start it)\n"));
    // A key pressed during boot
    fake::with(|s| {
        s.fwcfg.clear();
        s.uefi_keys.push_back(fake::key('q'));
    });
    stop_when(|st| shell_starts(st) >= 1);
    expect_panic("stop the console", || boot::run());
    assert!(fake::take_out().starts_with("[*] Hydra shell"));
}

#[test]
fn the_shell_is_started_again_when_it_ends() {
    let _g = setup();
    fake::with(|s| s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec()));
    // Each run lasts 40 s (800 checks 50 ms apart): not a failure
    for tid in 100..110 {
        fake::task(tid, 800, Some(0));
    }
    stop_when(|st| shell_starts(st) >= 4);
    expect_panic("stop the console", || boot::run());
    let out = fake::take_out();
    for tid in 100..103 {
        assert!(out.contains(&format!("[!] The console shell (process {}) ended; starting it again.", tid)), "{}", out);
    }
    assert!(!out.contains("EMERGENCY"));
    // Every run is a fresh session with the console authorized, then revoked
    assert_eq!(k::admin::console_task(), Some(k::task::TaskId(103)));
    assert!(fake::logged("abac None"));
}

#[test]
fn three_quick_exits_bring_the_emergency_prompt() {
    let _g = setup();
    fake::with(|s| {
        s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec());
        s.fwcfg.insert("opt/hydra/console".into(), b"crash".to_vec());
    });
    // In the emergency prompt: 'ushell' goes back to hydra-shell (typed once it shows)
    stop_when(|st| shell_starts(st) >= 4);
    let stop = std::cell::RefCell::new(fake::with(|s| s.on_sleep.take()).unwrap());
    fake::with(|s| {
        s.on_sleep = Some(Box::new(move |st: &mut fake::State| {
            if st.out.contains("EMERGENCY PROMPT") && !st.log.iter().any(|l| l == "typed") {
                st.uefi_keys.extend("ushell\r".chars().map(fake::key));
                st.log.push("typed".into());
            }
            (stop.borrow_mut())(st)
        }))
    });
    expect_panic("stop the console", || boot::run());
    let out = fake::take_out();
    assert_eq!(out.matches("ended; starting it again").count(), 2, "{}", out);
    assert!(out.contains("[!] EMERGENCY PROMPT: hydra-shell ended 3 times in a row, each within 30 s of its start"));
    // The crash switch reaches hydra-shell
    assert!(fake::logged("spawn_native hydra-shell hydra-shell [\"hydra-shell\", \"--test-crash\"] 1000 1000"));
}

#[test]
fn a_shell_that_cannot_start_brings_the_emergency_prompt() {
    let _g = setup();
    fake::with(|s| {
        s.fwcfg.insert("opt/hydra/boot".into(), b"shell".to_vec());
        s.spawn_fail = Some("out of memory");
    });
    stop_when(|st| st.clock_ns > 1_000_000_000);
    expect_panic("stop the console", || boot::run());
    let out = fake::take_out();
    assert!(out.contains("[!] EMERGENCY PROMPT: hydra-shell cannot start: out of memory"), "{}", out);
    assert!(out.contains("emergency:/# "));
}
