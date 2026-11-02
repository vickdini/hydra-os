//! # Shell: Console Login
//!
//! The kernel shell is an administrator's console: its commands act below any permission
//! check (the pool, the drivers), so only `root` and members of the `sudo` (or `admin`)
//! group may use it, after logging in with their password.
//!
//! Accounts and passwords are those of the installed system (`/ubuntu/etc/passwd`,
//! `/etc/group`, `/etc/shadow`). The kernel never sees a password hash: a password is
//! checked by PAM's helper, `unix_chkpwd`, run as root inside that system with the
//! password on its standard input; its exit status is the answer.

use alloc::string::String;
use alloc::vec::Vec;
use uefi::proto::console::text::{Color, Key};

use crate::console::set_color;
use crate::shell::state::ShellState;

/// The installed system whose accounts the console uses.
const SYSTEM_ROOT: &str = "/ubuntu";
/// PAM's password checking helper.
const CHKPWD: &str = "/usr/sbin/unix_chkpwd";
/// Groups whose members administer the system (Ubuntu's, and Debian's older name).
const ADMIN_GROUPS: [&str; 2] = ["sudo", "admin"];

/// An account of the installed system.
pub struct Account {
    /// Login name.
    pub name: String,
    /// User ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    /// Whether it may administer the system (root, or a member of an admin group).
    pub admin: bool,
}

/// Contents of a file of the installed system.
///
/// # Arguments
/// * `path` - Relative file path under `SYSTEM_ROOT`.
///
/// # Returns
///
/// File contents as a [`String`], or `None` on read failure.
fn system_file(path: &str) -> Option<String> {
    let full = alloc::format!("{}{}", SYSTEM_ROOT, path);
    let size = crate::fs::ZfsClient::file_stat(&full).ok()?.size as usize;
    let mut buf = alloc::vec![0u8; size];
    let n = crate::fs::ZfsClient::read_file_by_path(&full, &mut buf).ok()?;
    buf.truncate(n);
    String::from_utf8(buf).ok()
}

/// Whether the installed system can check passwords (it has accounts and PAM's helper).
///
/// # Returns
///
/// `true` if authentication helper and `/etc/passwd` are accessible, `false` otherwise.
pub fn available() -> bool {
    crate::fs::ZfsClient::file_stat(&alloc::format!("{}{}", SYSTEM_ROOT, CHKPWD)).is_ok() && system_file("/etc/passwd").is_some()
}

/// Looks up account `name`.
///
/// # Arguments
/// * `name` - Username string slice to find.
///
/// # Returns
///
/// `Some(Account)` if found in `/etc/passwd`, or `None`.
pub fn account(name: &str) -> Option<Account> {
    let passwd = system_file("/etc/passwd")?;
    let fields: Vec<&str> = passwd.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f| f.len() >= 4 && f[0] == name)?;
    let uid: u32 = fields[2].parse().ok()?;
    let gid: u32 = fields[3].parse().ok()?;
    let group = system_file("/etc/group").unwrap_or_default();
    let admin = uid == 0
        || group.lines().any(|l| {
            let g: Vec<&str> = l.split(':').collect();
            g.len() >= 4
                && ADMIN_GROUPS.contains(&g[0])
                && (g[3].split(',').any(|m| m == name) || g[2].parse::<u32>().ok() == Some(gid))
        });
    Some(Account { name: String::from(name), uid, gid, admin })
}

/// Checks `password` for account `name` with PAM's helper. Returns whether it matches.
///
/// # Arguments
/// * `name` - Username string slice.
/// * `password` - Plaintext password to verify.
///
/// # Returns
///
/// `true` if password matched via PAM helper, `false` otherwise.
pub fn verify_password(name: &str, password: &str) -> bool {
    use crate::fs::{FileDescriptor, PipeBuffer};
    let argv = [CHKPWD, name, "nonull"];
    let tid = match crate::task::spawn_linux_chroot(SYSTEM_ROOT, CHKPWD, &argv, 0, 0) {
        Ok(t) => t,
        Err(e) => {
            crate::println!("[!] login: cannot check passwords: {}", e);
            return false;
        }
    };
    // Its standard input: the password, NUL-terminated (it refuses a terminal). The task
    // has not run yet: the shell is not preempted until it waits below
    let pipe = PipeBuffer::new();
    let fds = crate::task::SCHEDULER.lock().with_task_mut(tid, |t| t.fds.clone());
    if let Some(fds) = fds {
        let mut table = fds.lock();
        let _ = table.close(0);
        let _ = table.set_fd(0, Some(FileDescriptor::PipeRead(pipe.clone())));
    }
    {
        let mut p = pipe.lock();
        let mut secret = password.as_bytes().to_vec();
        secret.push(0);
        let _ = p.write(&secret);
        secret.fill(0);
        p.drop_writer();
    }
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
    // Exit status 0 (PAM_SUCCESS) means the password matched
    crate::compat::linux::proc::take_status(tid.0) == Some(0)
}

/// Reads a line from the keyboard, echoing it unless `secret`.
///
/// # Arguments
/// * `prompt` - Interactive prompt message displayed before input.
/// * `secret` - Whether to suppress echoing typed characters (for passwords).
///
/// # Returns
///
/// The entered text line as a [`String`].
pub fn read_input(prompt: &str, secret: bool) -> String {
    crate::print!("{}", prompt);
    let mut line = String::new();
    loop {
        match crate::console::read_key() {
            Some(Key::Printable(ch)) => {
                let c = u16::from(ch);
                match c {
                    13 | 10 => {
                        crate::println!();
                        return line;
                    }
                    8 | 127 => {
                        if line.pop().is_some() && !secret {
                            crate::print!("\x08 \x08");
                        }
                    }
                    c if c >= 32 && line.len() < 128 => {
                        if let Some(ch) = char::from_u32(c as u32) {
                            line.push(ch);
                            if !secret {
                                crate::print!("{}", ch);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Some(_) => {}
            None => crate::task::preemptible(|| crate::console::stall(core::time::Duration::from_millis(10))),
        }
    }
}

/// Tick of the last `sudo` password check (0: none since the last login).
static SUDO_TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How long a `sudo` password check holds (5 minutes at 100 Hz).
const SUDO_TIMEOUT_TICKS: u64 = 5 * 60 * 100;

/// Whether `sudo` was given a password recently.
///
/// # Returns
///
/// `true` if a successful `sudo` check occurred within the timeout period, `false` otherwise.
pub fn sudo_fresh() -> bool {
    let t = SUDO_TICK.load(core::sync::atomic::Ordering::Relaxed);
    t != 0 && crate::arch::pit::ticks().saturating_sub(t) < SUDO_TIMEOUT_TICKS
}

/// Records a successful `sudo` password check.
pub fn sudo_remember() {
    SUDO_TICK.store(crate::arch::pit::ticks().max(1), core::sync::atomic::Ordering::Relaxed);
}

/// Asks for a login until an administrator logs in, and makes them the shell's user.
///
/// # Arguments
/// * `state` - Mutable reference to the shell session state.
pub fn login(state: &mut ShellState) {
    SUDO_TICK.store(0, core::sync::atomic::Ordering::Relaxed);
    if !available() {
        set_color(Color::Yellow, Color::Black);
        crate::println!("[!] No installed system with accounts in {}: the console is not protected.", SYSTEM_ROOT);
        set_color(Color::White, Color::Black);
        return;
    }
    set_color(Color::LightCyan, Color::Black);
    crate::println!("Hydra administration console. Log in as root or as a member of 'sudo'.");
    let mut failures = 0u32;
    loop {
        set_color(Color::White, Color::Black);
        let name = read_input("login: ", false);
        let password = read_input("Password: ", true);
        let ok = !name.is_empty() && verify_password(&name, &password);
        match account(&name) {
            Some(acct) if ok && acct.admin => {
                state.set_user(&acct.name, acct.uid, acct.gid);
                set_color(Color::LightGreen, Color::Black);
                crate::println!("[+] Logged in as '{}' (UID {}).\n", acct.name, acct.uid);
                set_color(Color::White, Color::Black);
                return;
            }
            Some(_) if ok => {
                set_color(Color::LightRed, Color::Black);
                crate::println!("'{}' is not an administrator (not in 'sudo'); use the login screen.\n", name);
            }
            _ => {
                set_color(Color::LightRed, Color::Black);
                crate::println!("Login incorrect\n");
                failures += 1;
                if failures % 3 == 0 {
                    crate::task::sleep_ms(3000);
                }
            }
        }
    }
}
