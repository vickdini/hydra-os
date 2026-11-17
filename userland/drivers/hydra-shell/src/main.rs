//! # hydra-shell: Hydra's console shell, in Ring 3
//!
//! The kernel starts this program as the console after boot (`src/admin/boot.rs`) and
//! starts it again whenever it ends. It asks the kernel for what it needs through the admin
//! interface (`src/admin`, the native system call `SYS_ADMIN`; design in
//! `docs/shell-admin-interface.md`) and reads files through the native `open`/`read` calls.
//! The kernel keeps only a tiny emergency prompt (`src/shell`) for when this program cannot
//! run.
//!
//! What it does, as the old kernel shell did, with the same output: the console login
//! (administrators only; the kernel applies the rules), the prompt `hydra:<cwd>$ ` (`#` for
//! root), the line editor (history, cursor keys, Tab), pipes (`|`), redirects (`>`, `>>`),
//! `!!`, scripts (`sh`), programs of the pool, and every command (see [`COMMANDS`]).
//!
//! `exit`, `logout` and Ctrl+D on an empty line end the session: the login prompt comes
//! back. Power is `shutdown`/`poweroff`, `reboot` and `halt`.
//!
//! Modules: [`editor`] the line editor, [`login`] login/su/sudo, [`fs`] files, [`text`]
//! text tools, [`system`] tasks, memory, services, power, [`storage`] ZFS and disks,
//! [`net`] the network commands (the one place that talks to the network), [`linux`] the
//! Linux root.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../../../src/admin/proto.rs"]
#[allow(dead_code)]
mod proto;

mod editor;
mod fs;
mod history;
#[allow(dead_code)] // parse_u32, parse_usize: host-tested, used by the kernel shell before
mod parse;
mod linux;
mod login;
mod net;
mod storage;
mod sys;
mod system;
mod text;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use hydra_rt::{print, println};
use proto::*;
use sys::*;

hydra_rt::entry!(main);

/// The session.
pub struct Shell {
    /// Working directory.
    pub cwd: String,
    /// The console's user (as the kernel recorded it).
    pub uid: u32,
    /// Its group.
    pub gid: u32,
    /// Its name.
    pub user: String,
    /// Recent command lines.
    pub history: history::History,
    /// Status of the last command (`$?`).
    pub status: i32,
    /// Standard input of the command running in a pipeline (the previous stage's output).
    pub stdin: Option<Vec<u8>>,
    /// The session ends (exit, logout).
    pub logout: bool,
}

impl Shell {
    /// The prompt, as the kernel shell's `format_prompt`.
    pub fn prompt(&self) -> String {
        let scroll = ctl(CTL_SCROLL_LOCK, 3, 0, 0, &[])[0] != 0;
        format!("hydra:{}{}{}", self.cwd, if scroll { " [SCROLL]" } else { "" }, if self.uid == 0 { "# " } else { "$ " })
    }

    /// The prompt colour: light cyan for root, light green for others.
    pub fn prompt_color(&self) -> u64 {
        if self.uid == 0 {
            LIGHT_CYAN
        } else {
            LIGHT_GREEN
        }
    }

    /// Adds a line to the history.
    pub fn remember(&mut self, line: &str) {
        self.history.add(line);
    }

    /// Takes the user the kernel now records (after login, su, sudo).
    pub fn refresh_user(&mut self) {
        if let Ok(i) = admin_rec::<SessionInfo>(ADMIN_SESSION_INFO, [0; 4], &[]) {
            self.uid = i.uid;
            self.gid = i.gid;
            self.user = String::from(name_str(&i.name));
        }
    }

    /// The pipeline's input for this command, if any.
    pub fn take_stdin(&mut self) -> Option<Vec<u8>> {
        self.stdin.take()
    }
}

/// Depth of output redirection (fd 1 is a pipe while > 0): no console colours then.
static REDIRECT_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Whether the output goes to a pipe or a file now.
pub fn redirected() -> bool {
    REDIRECT_DEPTH.load(Ordering::Relaxed) > 0
}

/// Splits a command line into words (the kernel shell's `split_words`: POSIX quoting).
pub fn split_words(line: &str) -> Vec<String> {
    const SQ: char = '\'';
    const BS: char = '\\';
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == SQ {
            in_word = true;
            for q in chars.by_ref() {
                if q == SQ {
                    break;
                }
                cur.push(q);
            }
        } else if c == '"' {
            in_word = true;
            while let Some(q) = chars.next() {
                if q == '"' {
                    break;
                }
                if q == BS {
                    if let Some(n) = chars.next() {
                        if !(n == '"' || n == BS || n == '$' || n == '`') {
                            cur.push(BS);
                        }
                        cur.push(n);
                    }
                } else {
                    cur.push(q);
                }
            }
        } else if c == BS {
            in_word = true;
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c.is_whitespace() {
            if in_word {
                words.push(core::mem::take(&mut cur));
                in_word = false;
            }
        } else {
            in_word = true;
            cur.push(c);
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Normalizes `path` against `cwd` (the kernel's `fs::client::normalize_path`: `.` and `..`,
/// backslashes, at most 16 components).
pub fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let absolute = path.starts_with('/') || path.starts_with('\\');
    if !absolute {
        for t in cwd.split(['/', '\\']) {
            if !t.is_empty() && t != "." && parts.len() < 16 {
                parts.push(t);
            }
        }
    }
    for t in path.split(['/', '\\']) {
        if t.is_empty() || t == "." {
            continue;
        } else if t == ".." {
            parts.pop();
        } else if parts.len() < 16 {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        return String::from("/");
    }
    let mut out = String::new();
    for p in parts {
        out.push('/');
        out.push_str(p);
    }
    // As the kernel's 128-byte buffer
    out.truncate(128);
    out
}

/// Prints an admin failure as the kernel shell would print the condition.
pub fn report(e: &AdminError, what: &str) {
    if e.errno == EIO && !e.message.is_empty() {
        color(YELLOW);
        println!("[-] {}", e.message);
    } else {
        color(LIGHT_RED);
        println!("[!] {}: {}", what, e.text());
    }
}

/// Prints a usage line in red.
pub fn usage(text: &str) {
    color(LIGHT_RED);
    println!("Usage: {}", text);
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

/// A command: name, aliases, usage, one-line description, handler.
pub struct Command {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub usage: &'static str,
    pub about: &'static str,
    pub run: fn(&mut Shell, &[&str]),
}

/// Shorthand for the table.
const fn cmd(name: &'static str, aliases: &'static [&'static str], usage: &'static str, about: &'static str, run: fn(&mut Shell, &[&str])) -> Command {
    Command { name, aliases, usage, about, run }
}

/// Every command of the console.
pub static COMMANDS: &[Command] = &[
    // The shell itself
    cmd("help", &["?"], "help [command]", "List the commands, or show one command's usage", cmd_help),
    cmd("info", &["version", "about"], "info", "Display Hydra OS version, kernel architecture, and features", system::info),
    cmd("status", &[], "status", "Inspect operational health of the microkernel subsystems", system::status),
    cmd("history", &["hist"], "history [-c]", "Show (or clear) the command history", cmd_history),
    cmd("clear", &["cls"], "clear", "Clear the screen and the scrollback", system::clear),
    cmd("color", &[], "color <cyan|green|yellow|red|white|magenta|blue>", "Change the console text colour", system::color_cmd),
    cmd("echo", &[], "echo <text...>", "Print the arguments", text::echo),
    cmd("cursor", &[], "cursor [on|off|underline|block|bar]", "Configure the console cursor", system::cursor),
    cmd("scroll", &["scrolllock", "slock"], "scroll [on|off]", "Scroll lock: browse the scrollback (PgUp, PgDn, arrows)", system::scroll),
    cmd("sh", &["source", "."], "sh <script.sh> [args...]", "Run a script of shell commands", cmd_sh),
    cmd("exit", &["logout"], "exit", "End the session (back to the login prompt)", cmd_exit),
    // Files
    cmd("pwd", &[], "pwd", "Print the working directory", fs::pwd),
    cmd("cd", &["chdir"], "cd [dir]", "Change the working directory", fs::cd),
    cmd("ls", &["dir"], "ls [-l] [-a] [dir]", "List a ZFS directory", fs::ls),
    cmd("cat", &["type"], "cat <file>", "Print a file (or the standard input)", fs::cat),
    cmd("write", &["append"], "write <file> [content...]", "Create or replace a file with the given text", fs::write),
    cmd("touch", &[], "touch <file...>", "Create files (or update them)", fs::touch),
    cmd("mkdir", &[], "mkdir [-p] <dir...>", "Create directories", fs::mkdir),
    cmd("rmdir", &[], "rmdir <dir...>", "Remove empty directories", fs::rmdir),
    cmd("rm", &["unlink"], "rm [-r] [-f] <path...>", "Remove files (and directories with -r)", fs::rm),
    cmd("cp", &["copy"], "cp [-r] <source> <dest>", "Copy files in ZFS", fs::cp),
    cmd("mv", &["rename"], "mv <source> <dest>", "Move or rename files/directories in ZFS", fs::mv),
    cmd("stat", &[], "stat <path>", "Show a file's ZFS metadata", fs::stat),
    cmd("df", &[], "df [-h]", "Show the pool's space", fs::df),
    cmd("du", &[], "du [-h] [-s] [path]", "Show space used under a path", fs::du),
    cmd("sync", &["locks", "waiters"], "sync [--all]", "Commit the pool; --all also shows endpoints and task states", system::sync),
    // Text
    cmd("head", &[], "head [-n lines] <file...>", "Print the first lines", text::head),
    cmd("tail", &[], "tail [-n lines] <file...>", "Print the last lines", text::tail),
    cmd("wc", &[], "wc [-l] [-w] [-c] <file...>", "Count lines, words and bytes", text::wc),
    cmd("grep", &[], "grep [-i] [-n] [-v] [-c] <pattern> [file...]", "Print lines that contain a pattern", text::grep),
    cmd("more", &["less", "page"], "more <file>", "Show a file page by page", text::more),
    cmd("basename", &[], "basename <path> [suffix]", "Strip the directory (and a suffix)", text::basename),
    cmd("dirname", &[], "dirname <path>", "Strip the last component", text::dirname),
    cmd("seq", &[], "seq [FIRST [INCREMENT]] LAST", "Print a sequence of numbers", text::seq),
    cmd("yes", &[], "yes [string]", "Print a string until Ctrl+C", text::yes),
    cmd("true", &[], "true", "Succeed", text::true_cmd),
    cmd("false", &[], "false", "Fail", text::false_cmd),
    cmd("sleep", &[], "sleep <seconds>", "Wait (Ctrl+C stops)", text::sleep),
    // Users
    cmd("uname", &[], "uname [-a] [-s] [-n] [-r] [-v] [-m]", "Print system information", system::uname),
    cmd("whoami", &["id"], "whoami [-u] [-g]", "Print the console's user", login::whoami),
    cmd("su", &[], "su [user]", "Switch the console's user (e.g. 'su root')", login::su),
    cmd("sudo", &[], "sudo <command> [args...] | sudo -s", "Run a command as root (or become root)", login::sudo),
    cmd("uptime", &[], "uptime", "Time since boot", system::uptime),
    // Tasks and programs
    cmd("ps", &["tasks", "threads"], "ps", "List tasks", system::ps),
    cmd("kill", &[], "kill <pid>", "End a task", system::kill),
    cmd("syscalls", &["sys", "syscall"], "syscalls", "System call MSRs and counters", system::syscalls),
    cmd("elf", &["elf64", "runelf"], "elf [-i|--info] <file.elf> [--bg]", "Inspect or run an ELF program of the pool", system::elf),
    // Memory and the CPU
    cmd("mem", &["memory"], "mem", "Physical memory and kernel heap statistics", system::mem),
    cmd("heap", &[], "heap [stats | test]", "Kernel heap statistics, or its self-test", system::heap),
    cmd("cpu", &[], "cpu", "CPU control registers (CR0, CR2, CR3, CR4)", system::cpu),
    cmd("translate", &["v2p"], "translate <virtual_address_hex>", "Walk the page tables for an address (this shell's address space)", system::translate),
    cmd("time", &["date"], "time", "The hardware clock (UTC)", system::time),
    // Services
    cmd("service", &["rs", "daemon", "daemons"], "service [status|list|restart <name>|kill <name>|start <name>|tick]", "Supervised drivers and servers", system::service),
    cmd("iommu", &[], "iommu [status|faults|dmatest]", "The IOMMU (Intel VT-d)", system::iommu),
    // Storage
    cmd("zpool", &[], "zpool <status|list>", "Pool status", storage::zpool),
    cmd("zfs", &[], "zfs <list | snap <id> | cat <path> | write <name> <text...> | selftest | verify | fsck [dir] [repair]>", "Datasets, snapshots and file server checks", storage::zfs),
    cmd("disks", &["storage", "lsblk", "fdisk"], "disks", "The pool's disk", storage::disks),
    cmd("usbdisk", &[], "usbdisk [list | test <n> [blocks] | speed <n|ahci> [MiB] [write]]", "List and test USB disks", storage::usbdisk),
    // Network
    cmd("ifconfig", &["ip", "netstat"], "ifconfig", "The network interface", net::ifconfig),
    cmd("dhcp", &["dhclient", "renew"], "dhcp", "Ask DHCP for an address", net::dhcp),
    cmd("dns", &["nslookup", "host", "resolve"], "dns <domain_or_url>", "Resolve a name", net::dns),
    cmd("ping", &[], "ping <ip_or_url>", "Ping a host", net::ping),
    cmd("wget", &["fetch", "curl"], "wget <server_ip_or_url> <port> <remote_path> <dest_zfs_path>", "Download a file over HTTP into the pool", net::wget),
    // The Linux root
    cmd("linux", &["linux64", "lx"], "linux [status|test|run <path> [args]|chroot <dir> <program> [args]|plasma [dir] [nologin]|trace on [name]|off|prof ...]", "The Linux layer: programs, diagnostics, the desktop", linux::linux),
    // Power and fault tests
    cmd("shutdown", &["poweroff"], "shutdown", "Power off", system::shutdown),
    cmd("reboot", &["restart"], "reboot", "Restart the computer", system::reboot),
    cmd("halt", &[], "halt", "Stop the CPU", system::halt),
    cmd("panic", &[], "panic [seconds]", "Kernel panic on purpose (after N seconds: from a kernel task)", system::panic),
    cmd("trap", &["int3", "breakpoint"], "trap", "A breakpoint exception in the kernel (it resumes)", system::trap),
];

/// Finds a command by name or alias.
pub fn find(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.name == name || c.aliases.contains(&name))
}

fn cmd_help(_sh: &mut Shell, args: &[&str]) {
    if let Some(&target) = args.first() {
        match find(target) {
            Some(c) => {
                color(LIGHT_CYAN);
                println!("\nCommand: {}", c.name);
                if !c.aliases.is_empty() {
                    println!("Aliases: {}", c.aliases.join(", "));
                }
                println!("Description: {}", c.about);
                println!("Usage:       {}\n", c.usage);
            }
            None => {
                color(LIGHT_RED);
                println!("No help entry found for '{}'.", target);
            }
        }
        return;
    }
    color(YELLOW);
    println!("\nHydra Shell Available Commands:");
    for c in COMMANDS {
        color(LIGHT_GREEN);
        print!("  {:14}", c.name);
        color(WHITE);
        println!("- {}", c.about);
    }
    color(LIGHT_CYAN);
    println!("\nPipes (|), redirects (>, >>), !! and programs of the pool work as before.");
    println!("Type 'help <command>' for specific syntax, flags, and options.\n");
    color(WHITE);
}

fn cmd_history(sh: &mut Shell, args: &[&str]) {
    if args.first() == Some(&"-c") {
        sh.history = history::History::new();
        return;
    }
    color(WHITE);
    let first = sh.history.start_session_index().max(1);
    for i in first..=sh.history.total_count() {
        if let Some(h) = sh.history.get_by_index(i) {
            println!("  {:>4}  {}", i, h);
        }
    }
}

fn cmd_exit(sh: &mut Shell, _args: &[&str]) {
    sh.logout = true;
}

/// `sh`: runs a script's lines (`#` comments; `$1`.. are its arguments).
fn cmd_sh(sh: &mut Shell, args: &[&str]) {
    let Some(&script) = args.first() else { return usage("sh <script.sh> [args...]") };
    let path = normalize_path(&sh.cwd, script);
    let data = match read_file(&path, 1 << 20) {
        Ok(d) => d,
        Err(e) => {
            color(LIGHT_RED);
            println!("sh: {}: {}", script, e);
            sh.status = 127;
            return;
        }
    };
    let text = String::from_utf8_lossy(&data).into_owned();
    for raw in text.lines() {
        let mut line = String::from(raw.trim());
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for (i, a) in args.iter().enumerate().rev() {
            line = line.replace(&format!("${}", i), a);
        }
        execute(sh, &line);
        if sh.logout || interrupted() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Running command lines
// ---------------------------------------------------------------------------

/// Whether `c` occurs in `s` outside quotes.
fn has_unquoted(s: &str, c: char) -> bool {
    split_unquoted(s, c).len() > 1
}

/// Splits `s` at `c` outside quotes.
fn split_unquoted(s: &str, c: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut quote, mut start) = (None, 0);
    for (i, ch) in s.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == c => {
                parts.push(&s[start..i]);
                start = i + ch.len_utf8();
            }
            None => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Runs `line` with its output captured (fd 1 on a pipe: this program's output and the
/// kernel's report output both land there; at most 64 KiB, the pipe's size).
fn capture(sh: &mut Shell, line: &str) -> Vec<u8> {
    /// Where fd 1 is kept meanwhile (one more per nesting level).
    const SAVED_FD: u64 = 40;
    let Some((r, w)) = pipe() else { return Vec::new() };
    let depth = REDIRECT_DEPTH.fetch_add(1, Ordering::Relaxed);
    let saved = SAVED_FD + depth as u64;
    dup2(1, saved);
    dup2(w, 1);
    close(w);
    execute_single(sh, line);
    dup2(saved, 1);
    close(saved);
    REDIRECT_DEPTH.fetch_sub(1, Ordering::Relaxed);
    let mut out = Vec::new();
    let mut chunk = alloc::vec![0u8; 16384];
    loop {
        let n = read(r, &mut chunk);
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
    }
    close(r);
    out
}

/// Splits `cmd > file` / `cmd >> file`: `(command, file, append)`.
fn parse_redirect(s: &str) -> (&str, &str, bool) {
    let parts = split_unquoted(s, '>');
    if parts.len() == 3 && parts[1].is_empty() {
        (parts[0].trim(), parts[2].trim(), true)
    } else if parts.len() >= 2 {
        (parts[0].trim(), parts[parts.len() - 1].trim(), false)
    } else {
        (s.trim(), "", false)
    }
}

/// Writes the output of a redirect to a pool file.
fn commit_output(sh: &Shell, file: &str, data: &[u8], append: bool) {
    let path = normalize_path(&sh.cwd, file);
    let code = if append { FS_APPEND } else { FS_WRITE };
    if let Err(e) = admin(ADMIN_FS_OP, [code, 0, 0, 0], &two(&path, data)) {
        color(LIGHT_RED);
        println!("failed to {} '{}': {}", if append { "append to" } else { "write to" }, path, e.text());
    }
}

/// Runs a command line: `!!`, pipes, redirects, or one command.
pub fn execute(sh: &mut Shell, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    if line == "!!" {
        let prev = (0..sh.history.len()).filter_map(|i| sh.history.get_from_latest(i)).find(|h| *h != "!!").map(String::from);
        match prev {
            Some(p) => {
                color(LIGHT_CYAN);
                println!("{}", p);
                color(WHITE);
                execute(sh, &p);
            }
            None => {
                color(LIGHT_RED);
                println!("!!: event not found");
                sh.status = 1;
            }
        }
        return;
    }
    if has_unquoted(line, '|') {
        let stages = split_unquoted(line, '|');
        let mut data: Option<Vec<u8>> = None;
        for (i, stage) in stages.iter().enumerate() {
            let last = i == stages.len() - 1;
            let (cmd, file, append) = if last && has_unquoted(stage, '>') { parse_redirect(stage) } else { (stage.trim(), "", false) };
            sh.stdin = data.take();
            if last && file.is_empty() {
                execute_single(sh, cmd);
            } else {
                let out = capture(sh, cmd);
                if last {
                    commit_output(sh, file, &out, append);
                } else {
                    data = Some(out);
                }
            }
            sh.stdin = None;
        }
    } else if has_unquoted(line, '>') {
        let (cmd, file, append) = parse_redirect(line);
        if file.is_empty() {
            color(LIGHT_RED);
            println!("syntax error: missing redirection target file");
            sh.status = 2;
            return;
        }
        let out = capture(sh, cmd);
        commit_output(sh, file, &out, append);
    } else {
        execute_single(sh, line);
    }
}

/// Runs one command (no pipes or redirects): a built-in, a program of the pool, a script.
pub fn execute_single(sh: &mut Shell, line: &str) {
    let words = split_words(line.trim());
    let Some(first) = words.first() else { return };
    let args: Vec<&str> = words[1..].iter().map(|s| s.as_str()).collect();
    color(WHITE);
    sh.status = 0;
    if let Some(c) = find(first) {
        (c.run)(sh, &args);
    } else if system::run_program(sh, first, &args) {
        // A program of the pool ran
    } else if first.starts_with("./") || first.ends_with(".sh") {
        let mut all: Vec<&str> = alloc::vec![first.as_str()];
        all.extend_from_slice(&args);
        cmd_sh(sh, &all);
    } else {
        color(LIGHT_RED);
        println!("Unknown command: '{}'. Type 'help' for built-ins or 'path' for executable search dirs.", first);
        sh.status = 127;
    }
}

/// The kernel shell's welcome banner.
fn banner() {
    color(LIGHT_CYAN);
    println!("\n+--------------------------------------------------------------+");
    println!("|             HYDRA MICROKERNEL INTERACTIVE SHELL              |");
    println!("|  Type 'help' for available commands, or 'info' for details.  |");
    println!("+--------------------------------------------------------------+\n");
    color(WHITE);
}

fn main(args: &[&str]) {
    // A deliberately broken start, to test the kernel's emergency prompt (QEMU fw_cfg
    // opt/hydra/console=crash makes the kernel pass this)
    if args.contains(&"--test-crash") {
        println!("hydra-shell: --test-crash: ending at once");
        hydra_rt::sys::exit(101);
    }
    // The interface must be there and ours (the kernel authorizes only its console)
    match admin(ADMIN_VERSION, [0; 4], &[]) {
        Ok(a) if a.len() >= 4 && u32::from_le_bytes([a[0], a[1], a[2], a[3]]) == ADMIN_ABI_VERSION => {}
        Ok(_) => {
            println!("hydra-shell: admin interface version mismatch");
            hydra_rt::sys::exit(2);
        }
        Err(e) => {
            println!("hydra-shell: no admin interface: {}", errno_name(e.errno));
            hydra_rt::sys::exit(2);
        }
    }
    banner();
    let mut sh = Shell { cwd: String::from("/bin"), uid: 1000, gid: 1000, user: String::from("hydra"), history: history::History::new(), status: 0, stdin: None, logout: false };
    loop {
        login::login(&mut sh);
        sh.cwd = String::from("/bin");
        sh.logout = false;
        while !sh.logout {
            let Some(line) = editor::read_line(&mut sh) else { break };
            color(WHITE);
            if !line.trim().is_empty() {
                execute(&mut sh, &line);
            }
        }
        // End of the session (exit, logout, Ctrl+D): the next user logs in again
        color(LIGHT_CYAN);
        println!("logout\n");
        color(WHITE);
        login::logout(&mut sh);
    }
}
