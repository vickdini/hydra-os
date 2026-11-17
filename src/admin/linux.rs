//! # Admin operations of the Linux root (op group `0x8_`)
//!
//! What the console asks of the Linux compatibility layer: start a program in the
//! installed system (`linux chroot`), or a static Linux program of the pool (`linux run`),
//! with the console as its terminal, and wait for it; the layer's statistics, self-test,
//! tracing and profiler; and the KDE desktop.
//!
//! These operations are kept apart from the rest of the admin interface on purpose: the
//! Linux layer will leave the kernel (wave 2, group 6 designs it), and then this group
//! becomes requests to the Linux server, with the same records. Nothing here is needed by
//! the kernel's own parts of the interface.
//!
//! The password check of the console login (`session.rs`) also runs a program in the
//! installed system (PAM's `unix_chkpwd`), through [`wait_exit`].

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::proto::console::text::Color;

use super::proto::*;
use crate::console::set_color;

/// The Linux process that owns the console now (started with `RUN_FOREGROUND`), plus one.
static FOREGROUND: AtomicU64 = AtomicU64::new(0);

/// Sleeps until task `tid` has exited (the deadline covers the gap between the process
/// becoming a zombie and its task being gone).
pub fn wait_exit(tid: crate::task::TaskId) {
    let mut waits = crate::task::wait::WaitSet::new();
    waits.add(crate::task::wait::QueueRef::Static(&crate::compat::linux::pidfd::EXIT_WQ));
    loop {
        waits.register();
        if !crate::task::is_task_alive(tid) {
            break;
        }
        let deadline = crate::arch::pit::ticks() + 25;
        crate::task::preemptible(|| waits.wait(Some(deadline)));
    }
}

/// `ADMIN_LINUX_STATUS`.
pub fn status() -> LinuxStats {
    let s = crate::compat::linux::LINUX_STATS.lock();
    LinuxStats { calls: [s.total_calls, s.io_calls, s.memory_calls, s.process_calls, s.arch_prctl_calls, s.time_calls, s.unknown_calls] }
}

/// Prepares `root` (devices, network files, the user's runtime directory) and starts
/// `argv` there as `uid`/`gid`.
///
/// # Errors
/// The reason it could not start.
pub fn spawn_in_root(root: &str, argv: &[&str], uid: u32, gid: u32) -> Result<crate::task::TaskId, String> {
    prepare_network_files(root);
    prepare_runtime_dir(root, uid, gid);
    if let Err(e) = crate::compat::linux::devices::populate(root) {
        crate::println!("[!] linux chroot: device files: {}", e);
    }
    crate::task::spawn_linux_chroot(root, argv[0], argv, uid, gid)
}

/// Gives the console to Linux process `tid` (it leads its own session: keyboard, Ctrl+C).
fn attach(tid: crate::task::TaskId) {
    crate::compat::linux::tty::attach_session(tid.0, tid.0);
    FOREGROUND.store(tid.0 + 1, Ordering::Release);
}

/// Waits for the foreground process `tid`, gives the console back, and answers its status.
pub fn wait_foreground(tid: crate::task::TaskId) -> WaitResult {
    wait_exit(tid);
    crate::compat::linux::tty::detach_session();
    let _ = FOREGROUND.compare_exchange(tid.0 + 1, 0, Ordering::AcqRel, Ordering::Acquire);
    match crate::compat::linux::proc::take_status(tid.0) {
        Some(s) => WaitResult { known: 1, status: s as u64 },
        None => WaitResult { known: 0, status: 0 },
    }
}

/// Prints how a foreground Linux process ended, as the console shells always have.
pub fn print_exit(pid: u64, w: &WaitResult) {
    if w.known == 0 {
        crate::println!("[+] Linux process {} exited.", pid);
    } else if w.status & 0x7f != 0 {
        crate::println!("[+] Linux process {} killed by signal {}.", pid, w.status & 0x7f);
    } else {
        crate::println!("[+] Linux process {} exited with status {}.", pid, (w.status >> 8) & 0xff);
    }
}

/// Runs `argv` in `root` as `uid`/`gid` in the foreground and reports its end (the
/// emergency prompt's `linux chroot`, and the desktop session without a login screen).
pub fn run_chroot(root: &str, argv: &[&str], uid: u32, gid: u32) {
    match spawn_in_root(root, argv, uid, gid) {
        Ok(tid) => {
            attach(tid);
            let w = wait_foreground(tid);
            print_exit(tid.0, &w);
        }
        Err(e) => {
            set_color(Color::LightRed, Color::Black);
            crate::println!("[!] linux chroot: {}", e);
            set_color(Color::White, Color::Black);
        }
    }
}

/// Splits NUL-separated input into words.
pub fn words(input: &[u8]) -> Vec<&str> {
    input.split(|&b| b == 0).map(|w| core::str::from_utf8(w).unwrap_or("")).collect()
}

/// Reads a static Linux program from the pool: `path`, then `/bin/path`, then
/// `/bin/path.elf`. Answers the bytes and the path found.
fn read_program(raw: &str) -> Option<(Vec<u8>, String)> {
    let mut candidates = alloc::vec![String::from(raw)];
    if !raw.starts_with('/') {
        candidates.push(alloc::format!("/bin/{}", raw));
        if !raw.ends_with(".elf") {
            candidates.push(alloc::format!("/bin/{}.elf", raw));
        }
    }
    for path in candidates {
        if let Ok(st) = crate::fs::ZfsClient::file_stat(&path) {
            let mut buf = alloc::vec![0u8; st.size as usize];
            if let Ok(n) = crate::fs::ZfsClient::read_file_by_path(&path, &mut buf) {
                if n > 0 {
                    buf.truncate(n);
                    return Some((buf, path));
                }
            }
        }
    }
    None
}

/// `ADMIN_LINUX_RUN`, as the console's user `uid`/`gid`.
///
/// # Errors
/// A message for the user.
pub fn run(flags: u64, input: &[u8], uid: u32, gid: u32) -> Result<RunResult, String> {
    let w = words(input);
    let foreground = flags & RUN_FOREGROUND != 0;
    if foreground && FOREGROUND.load(Ordering::Acquire) != 0 {
        return Err(String::from("another Linux program owns the console"));
    }
    let mut res = RunResult { uid, gid, ..Default::default() };
    let tid = match flags & 0xff {
        RUN_CHROOT => {
            if w.len() < 2 || w[0].is_empty() || w[1].is_empty() {
                return Err(String::from("usage: root directory and program"));
            }
            spawn_in_root(w[0], &w[1..], uid, gid)?
        }
        RUN_FILE => {
            let raw = *w.first().filter(|p| !p.is_empty()).ok_or(String::from("no program given"))?;
            let (data, path) = read_program(raw).ok_or(String::from("cannot read the program from the pool"))?;
            res.size = data.len() as u64;
            res.path = name_field(&path);
            let mut argv: Vec<&str> = alloc::vec![path.as_str()];
            argv.extend_from_slice(&w[1..]);
            crate::task::spawn_linux_elf("linux_app", &data, &argv, crate::task::TaskPriority::Normal, uid, gid).map_err(String::from)?
        }
        _ => return Err(String::from("unknown kind of program")),
    };
    if foreground {
        attach(tid);
    }
    res.pid = tid.0;
    Ok(res)
}

/// `ADMIN_LINUX_WAIT`: only for the console's own foreground process.
pub fn wait(pid: u64) -> Option<WaitResult> {
    if FOREGROUND.load(Ordering::Acquire) != pid + 1 {
        return None;
    }
    Some(wait_foreground(crate::task::TaskId(pid)))
}

/// `ADMIN_LINUX_TEST` (report): the Linux layer's self-test.
pub fn self_test() {
    set_color(Color::Yellow, Color::Black);
    crate::println!("[*] Running Linux ABI compatibility self-tests...");
    let uts = crate::compat::linux::LinuxUtsname::default();
    let sysname = core::str::from_utf8(&uts.sysname).unwrap_or("").trim_matches('\0');
    let release = core::str::from_utf8(&uts.release).unwrap_or("").trim_matches('\0');
    set_color(Color::LightGreen, Color::Black);
    crate::println!("  [+] sys_uname: {} {}", sysname, release);
    let mut buf = [0u8; 128];
    let n = crate::compat::linux::fs::PseudoFile::ProcVersion.read(0, &mut buf);
    if n > 0 {
        crate::println!("  [+] /proc/version: {}", core::str::from_utf8(&buf[..n]).unwrap_or("").trim());
    }
    let mut rand_bytes = [0u8; 8];
    crate::compat::linux::fs::PseudoFile::DevUrandom.read(0, &mut rand_bytes);
    crate::println!("  [+] /dev/urandom: {:02x?}", rand_bytes);
    // The FS base MSR (arch_prctl): the caller's own value is put back afterwards
    unsafe {
        let saved = crate::arch::syscall::rdmsr(0xC000_0100);
        let test_tls_addr: u64 = 0x7FFF_0000_1000;
        crate::arch::syscall::wrmsr(0xC000_0100, test_tls_addr);
        let read_back = crate::arch::syscall::rdmsr(0xC000_0100);
        crate::arch::syscall::wrmsr(0xC000_0100, saved);
        if read_back == test_tls_addr {
            crate::println!("  [+] arch_prctl(ARCH_SET_FS): MSR 0xC0000100 read/write verified");
        } else {
            set_color(Color::LightRed, Color::Black);
            crate::println!("  [!] arch_prctl MSR test failed (mismatch: {:#x})", read_back);
        }
    }
    set_color(Color::LightCyan, Color::Black);
    crate::println!("[+] Linux ABI self-tests completed successfully.");
    set_color(Color::White, Color::Black);
}

/// `ADMIN_LINUX_TRACE`.
pub fn trace(on: bool, filter: &str) {
    *crate::compat::linux::TRACE_FILTER.lock() = String::from(filter);
    crate::compat::linux::TRACE_SYSCALLS.store(on, Ordering::Relaxed);
}

/// `ADMIN_LINUX_PROF` (report).
///
/// # Returns
/// `false` for an unknown code, or a sample of a task that does not exist.
pub fn prof(args: &[u64; 4], name: &str) -> bool {
    use crate::compat::linux::prof;
    use core::sync::atomic::Ordering::Relaxed;
    match args[0] {
        PROF_ON => {
            prof::reset();
            prof::ON.store(true, Relaxed);
            crate::println!("[+] Linux profile reset and started");
        }
        PROF_OFF => {
            prof::ON.store(false, Relaxed);
            crate::println!("[+] Linux profile stopped");
        }
        PROF_RESET => prof::reset(),
        PROF_SHOW => prof::show(args[1] as usize),
        PROF_TUNE => {
            match args[1] {
                0 => crate::arch::smp::DEFER_KICKS.store(args[2] != 0, Relaxed),
                1 => crate::arch::smp::IDLE_POLL_NS.store(args[2] * 1000, Relaxed),
                _ => {}
            }
            crate::println!(
                "[+] kick deferral {}, idle poll {} us",
                if crate::arch::smp::DEFER_KICKS.load(Relaxed) { "on" } else { "off" },
                crate::arch::smp::IDLE_POLL_NS.load(Relaxed) / 1000
            );
        }
        PROF_WAITS => {
            prof::SLOW_MS.store(args[1], Relaxed);
            crate::println!("[+] logging calls of {} ms or more", args[1]);
        }
        PROF_WAITS_SHOW => prof::slow_show(),
        PROF_SAMPLE => {
            // *: every task
            let id = if name == "*" { Some(u64::MAX) } else { crate::task::SCHEDULER.lock().task_named(name).map(|t| t.0) };
            match id {
                Some(id) => {
                    prof::sample_start(id, args[1] != 0);
                    crate::println!("[+] sampling task {} ({})", id, name);
                }
                None => {
                    crate::println!("[!] no task named {}", name);
                    return false;
                }
            }
        }
        PROF_SAMPLE_STOP => prof::sample_start(0, false),
        PROF_SAMPLE_SHOW => prof::sample_show(args[1] as usize),
        _ => return false,
    }
    true
}

/// `ADMIN_LINUX_PLASMA` (report), and the desktop start at boot: the graphical KDE
/// desktop on the DRM display from `root`. The login screen (SDDM) if installed (a
/// service: the console stays free for its own login), otherwise (or with `nologin`) the
/// session of the desktop user, uid 1000, started as root (the login manager needs it),
/// which owns the console until it ends.
pub fn plasma(root: &str, nologin: bool) {
    let has = |p: &str| crate::fs::ZfsClient::resolve(0, alloc::format!("{}{}", root.trim_end_matches('/'), p).as_bytes(), true).is_ok();
    if !has("/usr/libexec/hydra-session") && !has("/usr/bin/kwin_wayland") {
        crate::println!("[!] linux plasma: no KDE in {} (apt-get install kwin-wayland konsole)", root);
        return;
    }
    if has("/usr/bin/sddm") && !nologin {
        crate::println!("[*] Starting the login screen (SDDM)...");
        crate::video::splash::desktop_starting();
        let argv = ["/bin/sh", "/usr/libexec/hydra-session", "--display-manager"];
        match spawn_in_root(root, &argv, 0, 0) {
            Ok(tid) => crate::println!("[+] Started {} (process {}).", argv.join(" "), tid.0),
            Err(e) => crate::println!("[!] linux chroot: {}", e),
        }
        return;
    }
    let mut argv: Vec<&str> = alloc::vec!["/bin/sh", "/usr/libexec/hydra-session", "env", "KWIN_COMPOSE=Q", "XCURSOR_THEME=breeze_cursors", "dbus-run-session"];
    if has("/usr/bin/startplasma-wayland") {
        crate::println!("[*] Starting KDE Plasma...");
        argv.push("startplasma-wayland");
    } else {
        // plasma-workspace is not installed yet: the compositor with a terminal
        crate::println!("[*] Plasma (plasma-workspace) is not installed in {}; starting KWin with Konsole...", root);
        argv.extend_from_slice(&["kwin_wayland", "--drm", "konsole"]);
    }
    crate::video::splash::desktop_starting();
    run_chroot(root, &argv, 0, 0);
    // The session ended (or never showed): the console comes back
    crate::video::splash::end();
}

/// Creates `/run/user/<uid>` in the target root (mode 0700, owned by the user), the
/// per-user runtime directory (`XDG_RUNTIME_DIR`) that logind provides on a real system
/// and D-Bus, Wayland and KDE expect.
fn prepare_runtime_dir(root: &str, uid: u32, gid: u32) {
    // /run/user itself must stay searchable by every user
    let parent = alloc::format!("{}/run/user", root.trim_end_matches('/'));
    if let Ok(ino) = crate::fs::ZfsClient::create_dir_all(&parent) {
        let _ = crate::fs::ZfsClient::setattr(ino, crate::fs::zfs::zpl::SetAttr { mode: Some(0o755), ..Default::default() });
    }
    let path = alloc::format!("{}/run/user/{}", root.trim_end_matches('/'), uid);
    if let Ok(ino) = crate::fs::ZfsClient::create_dir_all(&path) {
        let _ = crate::fs::ZfsClient::setattr(
            ino,
            crate::fs::zfs::zpl::SetAttr { mode: Some(0o700), uid: Some(uid), gid: Some(gid), ..Default::default() },
        );
    }
}

/// Fills in a Linux root's empty `/etc/resolv.conf` and `/etc/hosts` (as WSL does), so the
/// C library resolves names through the DNS server from the DHCP lease. Files that already
/// have content, or are symbolic links, are left alone.
fn prepare_network_files(root: &str) {
    let dns = crate::net::iface().dns;
    let resolv = if dns != [0, 0, 0, 0] {
        alloc::format!("# Generated by Hydra from the DHCP lease\nnameserver {}.{}.{}.{}\n", dns[0], dns[1], dns[2], dns[3])
    } else {
        String::new()
    };
    let hosts = String::from("127.0.0.1\tlocalhost\n127.0.1.1\thydra\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    for (name, content) in [("etc/resolv.conf", resolv), ("etc/hosts", hosts)] {
        if content.is_empty() {
            continue;
        }
        let path = alloc::format!("{}/{}", root.trim_end_matches('/'), name);
        let is_empty_file = match crate::fs::ZfsClient::resolve(0, path.as_bytes(), false).and_then(crate::fs::ZfsClient::getattr) {
            Ok(attr) => attr.mode & 0o170000 == 0o100000 && attr.size == 0,
            Err(_) => true,
        };
        if is_empty_file {
            let _ = crate::fs::ZfsClient::write_file_by_path(&path, content.as_bytes());
        }
    }
}
