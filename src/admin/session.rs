//! # The console session: who is logged in on the admin console
//!
//! The admin console acts below every permission check (the pool, the drivers), so only
//! `root` and members of the `sudo` (or `admin`) group may use it, after logging in with
//! their password. This module holds the console's user and applies those rules; the
//! console program (`hydra-shell`, or the emergency prompt) only draws the prompts and
//! passes what was typed (`ADMIN_SESSION_LOGIN`). The kernel never takes the console's word
//! for who it is.
//!
//! Accounts and passwords are those of the installed system (`/ubuntu/etc/passwd`,
//! `/etc/group`, `/etc/shadow`). The kernel never sees a password hash: a password is
//! checked by PAM's helper, `unix_chkpwd`, run as root inside that system with the
//! password on its standard input; its exit status is the answer. (When the Linux layer
//! leaves the kernel, that check becomes a request to the Linux server.)
//!
//! Before anybody logs in, the admin interface refuses every operation except the
//! console's own and the login (see `crate::admin::syscall`).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::proto::*;

/// The installed system whose accounts the console uses.
pub const SYSTEM_ROOT: &str = "/ubuntu";
/// PAM's password checking helper.
const CHKPWD: &str = "/usr/sbin/unix_chkpwd";
/// Groups whose members administer the system (Ubuntu's, and Debian's older name).
const ADMIN_GROUPS: [&str; 2] = ["sudo", "admin"];

/// The console's user.
struct Session {
    uid: u32,
    gid: u32,
    name: String,
    logged_in: bool,
}

static SESSION: spin::Mutex<Session> = spin::Mutex::new(Session { uid: 1000, gid: 1000, name: String::new(), logged_in: false });

/// Tick of the last `sudo` password check (0: none since the last login).
static SUDO_TICK: AtomicU64 = AtomicU64::new(0);
/// How long a `sudo` password check holds (5 minutes at 100 Hz).
const SUDO_TIMEOUT_TICKS: u64 = 5 * 60 * 100;

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
/// * `path` - File path under [`SYSTEM_ROOT`].
fn system_file(path: &str) -> Option<String> {
    let full = alloc::format!("{}{}", SYSTEM_ROOT, path);
    let size = crate::fs::ZfsClient::file_stat(&full).ok()?.size as usize;
    let mut buf = alloc::vec![0u8; size];
    let n = crate::fs::ZfsClient::read_file_by_path(&full, &mut buf).ok()?;
    buf.truncate(n);
    String::from_utf8(buf).ok()
}

/// Whether the installed system can check passwords (it has accounts and PAM's helper).
pub fn protected() -> bool {
    crate::fs::ZfsClient::file_stat(&alloc::format!("{}{}", SYSTEM_ROOT, CHKPWD)).is_ok() && system_file("/etc/passwd").is_some()
}

/// Looks up account `name`.
pub fn account(name: &str) -> Option<Account> {
    let passwd = system_file("/etc/passwd")?;
    let fields: Vec<&str> = passwd.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f| f.len() >= 4 && f[0] == name)?;
    let uid: u32 = fields[2].parse().ok()?;
    let gid: u32 = fields[3].parse().ok()?;
    let group = system_file("/etc/group").unwrap_or_default();
    let admin = uid == 0
        || group.lines().any(|l| {
            let g: Vec<&str> = l.split(':').collect();
            g.len() >= 4 && ADMIN_GROUPS.contains(&g[0]) && (g[3].split(',').any(|m| m == name) || g[2].parse::<u32>().ok() == Some(gid))
        });
    Some(Account { name: String::from(name), uid, gid, admin })
}

/// Checks `password` for account `name` with PAM's helper. Returns whether it matches.
pub fn verify_password(name: &str, password: &str) -> bool {
    use crate::fs::{FileDescriptor, PipeBuffer};
    if name.is_empty() {
        return false;
    }
    let argv = [CHKPWD, name, "nonull"];
    let tid = match crate::task::spawn_linux_chroot(SYSTEM_ROOT, CHKPWD, &argv, 0, 0) {
        Ok(t) => t,
        Err(e) => {
            crate::kprintln!("[!] login: cannot check passwords: {}", e);
            return false;
        }
    };
    // Its standard input: the password, NUL-terminated (it refuses a terminal)
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
    super::linux::wait_exit(tid);
    // Exit status 0 (PAM_SUCCESS) means the password matched
    crate::compat::linux::proc::take_status(tid.0) == Some(0)
}

/// Makes `name` the console's user (and the console task's credentials).
fn set_user(name: &str, uid: u32, gid: u32) {
    {
        let mut s = SESSION.lock();
        s.uid = uid;
        s.gid = gid;
        s.name = String::from(name);
        s.logged_in = true;
    }
    if let Some(id) = super::console_task() {
        crate::task::SCHEDULER.lock().with_task_mut(id, |t| {
            t.uid = uid;
            t.gid = gid;
            t.euid = uid;
            t.egid = gid;
            t.suid = uid;
            t.sgid = gid;
        });
    }
}

/// A new console session (the console program starts): nobody is logged in yet, unless
/// nothing can be protected (no installed system with accounts) or this is the live
/// session (root at once).
pub fn begin() {
    SUDO_TICK.store(0, Ordering::Relaxed);
    crate::compat::linux::abac::console_login(None);
    if crate::compat::linux::live::is_live() {
        set_user("root", 0, 0);
    } else if !protected() {
        set_user("hydra", 1000, 1000);
    } else {
        let mut s = SESSION.lock();
        s.logged_in = false;
        s.uid = 1000;
        s.gid = 1000;
        s.name = String::from("hydra");
    }
}

/// Whether somebody is logged in on the console.
pub fn logged_in() -> bool {
    SESSION.lock().logged_in
}

/// The console's user: `(uid, gid, name)`.
pub fn user() -> (u32, u32, String) {
    let s = SESSION.lock();
    (s.uid, s.gid, s.name.clone())
}

/// Whether `sudo` was given a password recently.
fn sudo_fresh() -> bool {
    let t = SUDO_TICK.load(Ordering::Relaxed);
    t != 0 && crate::arch::pit::ticks().saturating_sub(t) < SUDO_TIMEOUT_TICKS
}

/// `ADMIN_SESSION_INFO`.
pub fn info() -> SessionInfo {
    let s = SESSION.lock();
    SessionInfo {
        uid: s.uid,
        gid: s.gid,
        logged_in: s.logged_in as u32,
        protected: protected() as u32,
        live: crate::compat::linux::live::is_live() as u32,
        sudo_fresh: sudo_fresh() as u32,
        name: name_field(&s.name),
    }
}

/// Logs `name` in with `password` (the console's login rules).
///
/// # Returns
/// A `LOGIN_*` status.
pub fn login(name: &str, password: &str) -> u32 {
    if !protected() {
        set_user("hydra", 1000, 1000);
        return LOGIN_UNPROTECTED;
    }
    let ok = verify_password(name, password);
    match account(name) {
        Some(acct) if ok && acct.admin => {
            set_user(&acct.name, acct.uid, acct.gid);
            SUDO_TICK.store(0, Ordering::Relaxed);
            // The user's access-control attributes go with the programs the console starts
            let attrs = system_file(&alloc::format!("/etc/hydra/access/subjects/{}", acct.name));
            crate::compat::linux::abac::console_login(attrs.as_deref());
            LOGIN_OK
        }
        Some(_) if ok => LOGIN_NOT_ADMIN,
        _ => LOGIN_INCORRECT,
    }
}

/// `ADMIN_SESSION_LOGIN`.
///
/// # Arguments
/// * `mode` - `LOGIN_*`.
/// * `name` - Account name (login, su, restore).
/// * `password` - Password typed.
pub fn login_op(mode: u64, name: &str, password: &str) -> LoginResult {
    let status = match mode {
        LOGIN_LOGIN => login(name, password),
        LOGIN_LOGOUT => {
            begin();
            LOGIN_OK
        }
        // The rest needs a logged-in console
        _ if !logged_in() => LOGIN_INCORRECT,
        LOGIN_SU => match account(name) {
            None => LOGIN_NO_USER,
            // root switches freely; anyone else gives the target account's password
            Some(acct) => {
                if user().0 == 0 || verify_password(&acct.name, password) {
                    set_user(&acct.name, acct.uid, acct.gid);
                    LOGIN_OK
                } else {
                    LOGIN_INCORRECT
                }
            }
        },
        LOGIN_SUDO => {
            let (uid, _, me) = user();
            if uid == 0 {
                LOGIN_OK
            } else if !protected() {
                set_user("root", 0, 0);
                LOGIN_OK
            } else if !account(&me).is_some_and(|a| a.admin) {
                LOGIN_NOT_ADMIN
            } else if sudo_fresh() {
                set_user("root", 0, 0);
                LOGIN_OK
            } else if password.is_empty() {
                LOGIN_NEED_PASSWORD
            } else if verify_password(&me, password) {
                // An administrator proves who they are (again after 5 minutes), as with Ubuntu's sudo
                SUDO_TICK.store(crate::arch::pit::ticks().max(1), Ordering::Relaxed);
                set_user("root", 0, 0);
                LOGIN_OK
            } else {
                LOGIN_INCORRECT
            }
        }
        LOGIN_RESTORE => {
            if user().0 != 0 {
                LOGIN_INCORRECT
            } else {
                match account(name) {
                    Some(acct) => {
                        set_user(&acct.name, acct.uid, acct.gid);
                        LOGIN_OK
                    }
                    // Without accounts: the default console user
                    None if name == "hydra" => {
                        set_user("hydra", 1000, 1000);
                        LOGIN_OK
                    }
                    None => LOGIN_NO_USER,
                }
            }
        }
        _ => LOGIN_INCORRECT,
    };
    let (uid, gid, name) = user();
    LoginResult { status, uid, gid, _pad: 0, name: name_field(&name) }
}
