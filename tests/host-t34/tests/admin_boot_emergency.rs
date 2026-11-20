//! `src/admin/boot.rs`: the emergency prompt asked for at boot (a global switch that stays
//! set, hence its own test binary).

mod common;
use common::*;
use k::admin::boot;

fn run_until_prompt() -> String {
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns > 500_000_000 {
                panic!("stop the console");
            }
        }))
    });
    expect_panic("stop the console", || boot::run());
    fake::take_out()
}

#[test]
fn the_reasons_for_the_emergency_prompt() {
    let _g = setup();
    // A file on the EFI partition (the weakest reason)
    fake::with(|s| {
        s.boot_files.insert("\\hydra\\emergency".into());
    });
    boot::discover_with(None, None);
    let out = run_until_prompt();
    // The desktop is not started; the prompt comes at once
    assert!(out.starts_with("[*] Hydra shell (the desktop was not started"), "{}", out);
    assert!(out.contains("[!] EMERGENCY PROMPT: asked for at boot (file \\hydra\\emergency on the EFI partition)"));
    // The boot entry's option beats the file
    boot::discover_with(None, Some(b"ro emergency"));
    assert!(run_until_prompt().contains("asked for at boot (boot option 'emergency')"));
    // QEMU's fw_cfg value beats both
    boot::discover_with(Some(b"emergency"), Some(b"emergency"));
    assert!(run_until_prompt().contains("asked for at boot (QEMU fw_cfg opt/hydra/boot=emergency)"));
    // Nothing asks: the reason stays what it was (it is set once per boot)
    fake::with(|s| s.boot_files.clear());
    boot::discover_with(None, Some(b"quiet"));
    assert!(run_until_prompt().contains("QEMU fw_cfg"));
}
