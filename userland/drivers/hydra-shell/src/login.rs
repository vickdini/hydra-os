//! The console login, `su`, `sudo`, `whoami`. The kernel checks passwords and the admin
//! group and records the console's user (`ADMIN_SESSION_LOGIN`); this module only asks.

use alloc::string::String;
use alloc::vec::Vec;

use crate::editor::read_input;
use crate::proto::*;
use crate::sys::*;
use crate::Shell;
use hydra_rt::println;

/// Asks the kernel to change the console's user.
fn session(mode: u64, name: &str, password: &str) -> LoginResult {
    let mut input = two(name, password.as_bytes());
    let r = admin_rec::<LoginResult>(ADMIN_SESSION_LOGIN, [mode, 0, 0, 0], &input).unwrap_or(LoginResult { status: LOGIN_INCORRECT, ..Default::default() });
    // The password does not linger in this program's memory
    input.fill(0);
    r
}

/// Asks for a login until an administrator logs in (as the kernel shell's login).
pub fn login(sh: &mut Shell) {
    let info: SessionInfo = admin_rec(ADMIN_SESSION_INFO, [0; 4], &[]).unwrap_or_default();
    if info.logged_in != 0 {
        if info.live != 0 {
            color(LIGHT_GREEN);
            println!("[+] Live session (Hydra from its USB stick): logged in as 'root' without a password.\n");
        } else if info.protected == 0 {
            color(YELLOW);
            println!("[!] No installed system with accounts in /ubuntu: the console is not protected.");
        }
        color(WHITE);
        sh.refresh_user();
        return;
    }
    color(LIGHT_CYAN);
    println!("Hydra administration console. Log in as root or as a member of 'sudo'.");
    let mut failures = 0u32;
    loop {
        color(WHITE);
        let name = read_input("login: ", false);
        let mut password = read_input("Password: ", true);
        let r = session(LOGIN_LOGIN, &name, &password);
        unsafe { password.as_bytes_mut().fill(0) };
        match r.status {
            LOGIN_OK | LOGIN_UNPROTECTED => {
                sh.refresh_user();
                color(LIGHT_GREEN);
                println!("[+] Logged in as '{}' (UID {}).\n", sh.user, sh.uid);
                color(WHITE);
                return;
            }
            LOGIN_NOT_ADMIN => {
                color(LIGHT_RED);
                println!("'{}' is not an administrator (not in 'sudo'); use the login screen.\n", name);
            }
            _ => {
                color(LIGHT_RED);
                println!("Login incorrect\n");
                failures += 1;
                if failures % 3 == 0 {
                    hydra_rt::sys::sleep_ms(3000);
                }
            }
        }
    }
}

/// Ends the session (the kernel forgets the user until the next login).
pub fn logout(sh: &mut Shell) {
    session(LOGIN_LOGOUT, "", "");
    sh.refresh_user();
    sh.history = crate::history::History::new();
}

pub fn whoami(sh: &mut Shell, args: &[&str]) {
    sh.refresh_user();
    color(WHITE);
    if args.contains(&"-u") {
        println!("{}", sh.uid);
    } else if args.contains(&"-g") {
        println!("{}", sh.gid);
    } else if args.is_empty() {
        println!("{}", sh.user);
    } else {
        println!("uid={}({}) gid={}", sh.uid, sh.user, sh.gid);
    }
}

pub fn su(sh: &mut Shell, args: &[&str]) {
    let target = args.first().copied().unwrap_or("root");
    // root switches freely; anyone else gives the target account's password
    let r = if sh.uid == 0 {
        session(LOGIN_SU, target, "")
    } else {
        let mut password = read_input("Password: ", true);
        let r = session(LOGIN_SU, target, &password);
        unsafe { password.as_bytes_mut().fill(0) };
        r
    };
    sh.refresh_user();
    match r.status {
        LOGIN_OK => {
            color(LIGHT_GREEN);
            println!("[+] Switched to '{}' (UID {}, GID {})", sh.user, sh.uid, sh.gid);
        }
        LOGIN_NO_USER => {
            color(LIGHT_RED);
            println!("su: user '{}' does not exist", target);
            sh.status = 1;
        }
        _ => {
            color(LIGHT_RED);
            println!("su: Authentication failure");
            sh.status = 1;
        }
    }
}

pub fn sudo(sh: &mut Shell, args: &[&str]) {
    if args.is_empty() {
        return crate::usage("sudo <command> [args...]");
    }
    let (old_uid, old_user) = (sh.uid, sh.user.clone());
    // An administrator proves who they are (again after 5 minutes), as with Ubuntu's sudo
    let mut r = session(LOGIN_SUDO, "", "");
    if r.status == LOGIN_NEED_PASSWORD {
        let mut password = read_input(&alloc::format!("[sudo] password for {}: ", old_user), true);
        r = session(LOGIN_SUDO, "", &password);
        unsafe { password.as_bytes_mut().fill(0) };
    }
    match r.status {
        LOGIN_OK => {}
        LOGIN_NOT_ADMIN => {
            color(LIGHT_RED);
            println!("{} is not in the sudoers file.", old_user);
            sh.status = 1;
            return;
        }
        _ => {
            color(LIGHT_RED);
            println!("sudo: 1 incorrect password attempt");
            sh.status = 1;
            return;
        }
    }
    sh.refresh_user();
    // sudo -s / -i: a root console
    if args[0] == "-s" || args[0] == "-i" {
        color(LIGHT_GREEN);
        println!("[+] Switched to superuser 'root' (UID 0, GID 0)");
        return;
    }
    let line: Vec<String> = args.iter().map(|a| quote(a)).collect();
    if crate::find(args[0]).is_none() && !crate::system::program_exists(sh, args[0]) {
        color(LIGHT_RED);
        println!("sudo: command not found: '{}'", args[0]);
        sh.status = 127;
    } else {
        crate::execute_single(sh, &line.join(" "));
    }
    // Back to the previous user
    if old_uid != 0 {
        session(LOGIN_RESTORE, &old_user, "");
    }
    sh.refresh_user();
}

/// Quotes a word for [`crate::split_words`].
fn quote(w: &str) -> String {
    if !w.is_empty() && !w.contains([' ', '\t', '\'', '"', '\\']) {
        return String::from(w);
    }
    let mut s = String::from("'");
    for c in w.chars() {
        if c == '\'' {
            s.push_str("'\\''");
        } else {
            s.push(c);
        }
    }
    s.push('\'');
    s
}
