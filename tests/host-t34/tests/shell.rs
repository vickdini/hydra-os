//! `src/shell/mod.rs`: the emergency prompt (its login, line input, word splitting and
//! commands).

mod common;
use common::*;
use k::task::supervisor::{ServiceSnapshot, ServiceState};
use k::task::*;

/// Types `lines` (each ended with Enter) into the firmware console and runs the prompt
/// until it returns; its output.
fn session(lines: &[&str]) -> String {
    let mut keys = Vec::new();
    for l in lines {
        keys.extend(l.chars().map(fake::key));
        keys.push(fake::key('\r'));
    }
    fake::with(|s| s.uefi_keys.extend(keys));
    k::shell::run("testing");
    fake::take_out()
}

#[test]
fn the_prompt_runs_until_ushell() {
    let _g = setup();
    let out = session(&["", "help", "exit"]);
    assert!(out.starts_with("\n[!] EMERGENCY PROMPT: testing\n"), "{}", out);
    assert!(out.contains("'help' lists its commands, 'ushell' starts hydra-shell again."));
    assert!(out.contains("emergency:/# \nemergency:/# help\n"));
    assert!(out.contains("  help                                   this list\n"));
    assert!(out.contains("  shutdown | reboot | halt               power\n"));
    // The prompt is light red, what is typed and printed white
    assert_eq!(k::console::CONSOLE.lock().current_attr, 0x0F);
    let out = session(&["?", "ushell"]);
    assert!(out.contains("  ushell                                 leave this prompt, start hydra-shell again\n"));
}

#[test]
fn unknown_commands_and_quotes() {
    let _g = setup();
    let out = session(&["frobnicate now", "cat", "  'two words'  ", "ushell"]);
    assert!(out.contains("'frobnicate': not an emergency command, or arguments missing; type 'help'"));
    assert!(out.contains("'cat': not an emergency command"));
    // Quotes group words (and the quote marks go)
    assert!(out.contains("'two words': not an emergency command"));
    let out = session(&["\"a b\"c 'd'", "ushell"]);
    assert!(out.contains("'a bc': not an emergency command"));
    // An empty quoted word is a word
    let out = session(&["'' x", "ushell"]);
    assert!(out.contains("'': not an emergency command"));
}

#[test]
fn line_editing() {
    let _g = setup();
    let keys = vec![
        fake::key('h'),
        fake::key('x'),
        fake::key('\u{8}'),
        fake::key('e'),
        fake::key('\u{7f}'),
        fake::key('e'),
        fake::special(1), // an arrow: ignored
        fake::key('\u{1}'), // a control character: ignored
        fake::key('l'),
        fake::key('p'),
        fake::key('\u{3}'), // Ctrl+C clears the line
        fake::key('h'),
        fake::key('e'),
        fake::key('l'),
        fake::key('p'),
        fake::key('\n'),
        fake::key('\u{8}'), // backspace on an empty line: nothing
    ];
    fake::with(|s| s.uefi_keys.extend(keys));
    let out = session(&["ushell"]);
    assert!(out.contains("emergency:/# hx\u{8} \u{8}e\u{8} \u{8}elp^C\nemergency:/# help\n"), "{:?}", out);
    assert!(out.contains("this list"));
}

#[test]
fn a_line_has_at_most_512_characters() {
    let _g = setup();
    let long = "y".repeat(600);
    let out = session(&[&long, "ushell"]);
    assert!(out.contains(&format!("'{}': not an emergency command", "y".repeat(512))));
    assert!(!out.contains(&"y".repeat(513)));
}

#[test]
fn the_prompt_waits_for_keys() {
    let _g = setup();
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 100_000_000 && st.uefi_keys.is_empty() && !st.log.contains(&"typed".to_string()) {
                st.uefi_keys.extend("ushell\r".chars().map(fake::key));
                st.log.push("typed".into());
            }
        }))
    });
    k::shell::run("waiting");
    assert_eq!(fake::with(|s| s.clock_ns), 100_000_000);
}

#[test]
fn files_of_the_pool() {
    let _g = setup();
    fake::file("/etc/motd", b"Welcome to Hydra\n");
    fake::file("/etc/apt/sources.list", b"deb x\n");
    fake::file("/etc/~gone", b"");
    let out = session(&["ls /etc", "cd /etc", "ls", "cat motd", "cat nothing", "cp motd motd.bak", "cp nothing x", "cd apt", "cd ..", "cd /etc/motd", "cd", "ls nowhere", "ushell"]);
    assert!(out.contains("emergency:/# ls /etc\n  motd\n  apt/\n"), "{}", out);
    assert!(!out.contains("~gone"));
    assert!(out.contains("emergency:/etc# ls\n  motd\n  apt/\n"));
    assert!(out.contains("Welcome to Hydra\n"));
    assert!(out.contains("cat: No such file"));
    assert!(out.contains("[+] Copied 'motd' -> '/etc/motd.bak' (Committed TXG #12)"));
    assert_eq!(fake::with(|s| s.files.get("/etc/motd.bak").cloned()).unwrap(), b"Welcome to Hydra\n".to_vec());
    assert!(out.contains("cp: failed to copy 'nothing' to 'x': source not found"));
    assert!(out.contains("emergency:/etc/apt# "));
    assert!(out.contains("cd: not a directory: /etc/motd"));
    // cd without a directory goes to the root
    assert!(out.contains("emergency:/etc# cd\nemergency:/# "));
    assert!(out.contains("ls: not a directory"));
}

#[test]
fn tasks_memory_services_and_the_pool() {
    let _g = setup();
    fake::with(|s| {
        s.snapshots = vec![TaskSnapshot { id: TaskId(3), uid: 0, mode: PrivilegeMode::User, state: TaskState::Blocked, priority: TaskPriority::Normal, ticks_run: 1, rsp: 0, name: "net-server" }];
        s.services = vec![
            ServiceSnapshot { task_id: Some(3), endpoint_id: 40, state: ServiceState::Running, restart_count: 1, unanswered_pings: 0, name: "net-server" },
            ServiceSnapshot { task_id: None, endpoint_id: 41, state: ServiceState::Faulted, restart_count: 5, unanswered_pings: 2, name: "usb" },
        ];
        s.pool = Some((2048, 1000, 3000, 42));
    });
    fake::task(50, 1, None);
    let out = session(&["ps", "kill 50", "kill 50", "kill 1", "kill x", "mem", "service", "service restart usb", "service start usb", "zpool", "ushell"]);
    assert!(out.contains("  3     0     net-server       Blocked\n"), "{}", out);
    assert!(out.contains("[+] Task #50 terminated."));
    assert_eq!(out.matches("kill: no such task (or not allowed)").count(), 3);
    assert!(out.contains("  RAM 512 MiB, free 448 MiB; kernel heap 1024 KiB used of 8192 KiB"));
    assert!(out.contains("  net-server       pid 3      Running, 1 restarts\n"));
    assert!(out.contains("  usb              pid -1     Faulted, 5 restarts\n"));
    assert!(out.contains("Ok(41)\n"));
    assert!(out.contains("Ok(43)\n"));
    assert!(out.contains("  hydrapool RAM fallback: 2048 MiB, 1000 KiB used, 3000 KiB free, TXG #42"));
    fake::with(|s| {
        s.pool = None;
        s.disk = Some((1, true, true, "disk".into()));
        s.service_fail = Some("unknown service");
    });
    let out = session(&["zpool", "service restart x", "ushell"]);
    assert!(out.contains("zpool: the file server did not answer"));
    assert!(out.contains("Err(\"unknown service\")"));
}

#[test]
fn a_root_shell_of_the_installed_system() {
    let _g = setup();
    let out = session(&["linux chroot /ubuntu /bin/bash -l", "linux chroot /ubuntu", "ushell"]);
    // As the console's user, in the foreground
    assert!(fake::logged("spawn_chroot /ubuntu /bin/bash [\"/bin/bash\", \"-l\"] 1000 1000"));
    assert!(fake::logged("attach"));
    assert!(out.contains("[+] Linux process "));
    // No program: not the command
    assert!(out.contains("'linux': not an emergency command"));
}

#[test]
fn power_commands() {
    let _g = setup();
    expect_panic("power_off", || {
        session(&["shutdown"]);
    });
    assert!(fake::take_out().contains("[*] Powering down system..."));
    expect_panic("power_off", || {
        session(&["poweroff"]);
    });
    expect_panic("reboot", || {
        session(&["reboot"]);
    });
    assert!(fake::take_out().contains("[*] Rebooting system..."));
    expect_panic("hlt", || {
        session(&["halt"]);
    });
    assert!(!x86_64::instructions::interrupts::are_enabled());
    x86_64::instructions::interrupts::enable();
}

#[test]
fn the_prompt_asks_for_a_login_when_passwords_are_checked() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "a1"), ("bob", "b1")]);
    let out = session(&["alice", "wrong", "bob", "b1", "alice", "a1", "ushell"]);
    // The password is not echoed
    assert!(out.contains("login: alice\nPassword: \nLogin incorrect\n"), "{}", out);
    assert!(!out.contains("wrong"));
    assert!(out.contains("'bob' is not an administrator (not in 'sudo')."));
    assert!(out.contains("[+] Logged in as 'alice'."));
    assert!(out.contains("emergency:/# ushell"));
    // A wrong password costs 2 s
    assert!(fake::with(|s| s.clock_ns) >= 2_000_000_000);
}
