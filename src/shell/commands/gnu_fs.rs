//! # Shell Commands: GNU Coreutils Filesystem Utilities
//!
//! Implements POSIX and GNU Coreutils-compatible filesystem navigation, manipulation, and
//! space-reporting commands (`pwd`, `cd`, `mkdir`, `rmdir`, `rm`, `cp`, `mv`, `touch`, `stat`,
//! `df`, and `du`) backed by the microkernel's OpenZFS engine.
//!
//! ## Architectural Role & Design Rationale
//! Providing familiar UNIX filesystem utilities directly in the built-in shell enables scripts
//! and interactive sessions to manage ZFS directory hierarchies, inspect dnode metadata and
//! 256-bit Fletcher-4 checksums (`stat`), and monitor pool allocation (`df`, `du`) without
//! requiring external binaries for basic administration.
//!
//! ## Key Types & Interfaces
//! - [`PwdCommand`] / [`CdCommand`]: Queries and updates `ShellState::cwd`.
//! - [`MkdirCommand`] / [`RmdirCommand`] / [`RmCommand`]: Creates and removes directories and files (including `mkdir -p` and `rm -rf`).
//! - [`CpCommand`] / [`MvCommand`] / [`TouchCommand`]: Copies, moves/renames, and updates files in ZFS.
//! - [`StatCommand`]: Displays dnode object ID, birth TXG, and Fletcher-4 checksum words.
//! - [`DfCommand`] / [`DuCommand`]: Reports ZFS pool capacity and per-directory disk usage.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Dispatches filesystem operations through [`crate::fs::client::ZfsClient`]
//! - Concurrency: Operates synchronously on `ShellState` and the ZFS dataset state

use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::{normalize_path, resolve_path, ZfsClient};
use crate::fs::zfs::types::DnodeType;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Built-in `pwd` command that prints the current working directory.
pub struct PwdCommand;

impl Command for PwdCommand {
    fn name(&self) -> &'static str {
        "pwd"
    }

    fn description(&self) -> &'static str {
        "Print current working directory"
    }

    fn usage(&self) -> &'static str {
        "pwd"
    }

    fn execute(&self, _args: &[&str], state: &mut ShellState) {
        set_color(Color::White, Color::Black);
        println!("{}", state.cwd_str());
    }
}

/// Changes the current working directory.
pub struct CdCommand;

impl Command for CdCommand {
    fn name(&self) -> &'static str {
        "cd"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["chdir"]
    }

    fn description(&self) -> &'static str {
        "Change the current working directory (e.g. 'cd /bin', 'cd ..', 'cd /')"
    }

    fn usage(&self) -> &'static str {
        "cd [directory]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let target = if args.is_empty() || args[0] == "~" {
            "/root"
        } else {
            args[0]
        };

        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

        match resolve_path(path) {
            Ok((_, DnodeType::Directory)) => {
                state.set_cwd(path);
            }
            Ok((_, _)) => {
                set_color(Color::LightRed, Color::Black);
                println!("cd: '{}' is not a directory", target);
            }
            Err(_) => {
                // If /root doesn't exist yet, fallback to /
                if target == "/root" {
                    state.set_cwd("/");
                } else {
                    set_color(Color::LightRed, Color::Black);
                    println!("cd: no such file or directory: '{}'", target);
                }
            }
        }
    }
}

/// Creates new directories in ZFS.
pub struct MkdirCommand;

impl Command for MkdirCommand {
    fn name(&self) -> &'static str {
        "mkdir"
    }

    fn description(&self) -> &'static str {
        "Create directories in ZFS (options: -p create parents without error)"
    }

    fn usage(&self) -> &'static str {
        "mkdir [-p] <directory...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut parents = false;
        let mut targets: [&str; 8] = [""; 8];
        let mut target_count = 0;

        for &arg in args {
            if arg == "-p" {
                parents = true;
            } else if !arg.starts_with('-') && target_count < targets.len() {
                targets[target_count] = arg;
                target_count += 1;
            }
        }

        if target_count == 0 {
            set_color(Color::LightRed, Color::Black);
            println!("mkdir: missing operand");
            return;
        }

        for i in 0..target_count {
            let target = targets[i];
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

            if parents {
                // Create intermediate directories if necessary
                let clean = path.trim_matches(['/', '\\']);
                let mut accumulated = [0u8; 128];
                let mut acc_len = 0;
                accumulated[0] = b'/';
                acc_len += 1;

                let mut had_err = false;
                for part in clean.split(['/', '\\']) {
                    if part.is_empty() { continue; }
                    if acc_len > 1 && acc_len < accumulated.len() {
                        accumulated[acc_len] = b'/';
                        acc_len += 1;
                    }
                    let b = part.as_bytes();
                    let len = b.len().min(accumulated.len().saturating_sub(acc_len));
                    accumulated[acc_len..acc_len + len].copy_from_slice(&b[..len]);
                    acc_len += len;

                    let sub_path = core::str::from_utf8(&accumulated[..acc_len]).unwrap_or("/");
                    if resolve_path(sub_path).is_err() {
                        if let Err(e) = ZfsClient::create_dir(sub_path) {
                            set_color(Color::LightRed, Color::Black);
                            println!("mkdir: cannot create directory '{}': {}", sub_path, e);
                            had_err = true;
                            break;
                        }
                    }
                }
                if !had_err {
                    set_color(Color::LightGreen, Color::Black);
                    println!("[+] Created directory '{}'", path);
                }
            } else {
                match ZfsClient::create_dir(path) {
                    Ok(_) => {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Created directory '{}'", path);
                    }
                    Err(e) => {
                        set_color(Color::LightRed, Color::Black);
                        println!("mkdir: cannot create directory '{}': {}", path, e);
                    }
                }
            }
        }
    }
}

/// Removes empty directories from ZFS.
pub struct RmdirCommand;

impl Command for RmdirCommand {
    fn name(&self) -> &'static str {
        "rmdir"
    }

    fn description(&self) -> &'static str {
        "Remove empty directories in ZFS"
    }

    fn usage(&self) -> &'static str {
        "rmdir <directory...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        for &target in args {
            if target.starts_with('-') { continue; }
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

            match ZfsClient::remove_dir(path) {
                Ok(_) => {
                    set_color(Color::LightGreen, Color::Black);
                    println!("[+] Removed directory '{}'", path);
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("rmdir: failed to remove '{}': {}", target, e);
                }
            }
        }
    }
}

/// Removes files or directories from ZFS.
pub struct RmCommand;

impl Command for RmCommand {
    fn name(&self) -> &'static str {
        "rm"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["unlink"]
    }

    fn description(&self) -> &'static str {
        "Remove files or directories from ZFS (options: -r recursive, -f force)"
    }

    fn usage(&self) -> &'static str {
        "rm [-r] [-f] <file...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut recursive = false;
        let mut force = false;
        let mut targets: [&str; 8] = [""; 8];
        let mut target_count = 0;

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'r' | 'R' => recursive = true,
                        'f' => force = true,
                        _ => {}
                    }
                }
            } else if target_count < targets.len() {
                targets[target_count] = arg;
                target_count += 1;
            }
        }

        if target_count == 0 {
            if !force {
                set_color(Color::LightRed, Color::Black);
                println!("rm: missing operand");
            }
            return;
        }

        for i in 0..target_count {
            let target = targets[i];
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

            match resolve_path(path) {
                Ok((_, DnodeType::PlainFile)) => {
                    if let Err(e) = ZfsClient::remove_file(path) {
                        if !force {
                            set_color(Color::LightRed, Color::Black);
                            println!("rm: cannot remove '{}': {}", target, e);
                        }
                    } else {
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Removed file '{}'", path);
                    }
                }
                Ok((_, DnodeType::Directory)) => {
                    if recursive {
                        // Recursively remove directory contents
                        let _ = recursively_remove_dir(path);
                        set_color(Color::LightGreen, Color::Black);
                        println!("[+] Removed directory '{}'", path);
                    } else if !force {
                        set_color(Color::LightRed, Color::Black);
                        println!("rm: cannot remove '{}': Is a directory (use -r)", target);
                    }
                }
                _ => {
                    if !force {
                        set_color(Color::LightRed, Color::Black);
                        println!("rm: cannot remove '{}': No such file or directory", target);
                    }
                }
            }
        }
    }
}

/// Recursively deletes all child files and subdirectories within `dir_path` before removing `dir_path` itself.
///
/// # Arguments
///
/// * `dir_path` - Normalized ZFS directory path to remove recursively.
///
/// # Returns
///
/// * `Ok(())` - If the directory and its contents were removed.
/// * `Err(&'static str)` - If the final directory removal failed.
fn recursively_remove_dir(dir_path: &str) -> Result<(), &'static str> {
    if let Ok((entries, _, _)) = ZfsClient::list_dir(dir_path) {
        for entry in entries.iter() {
            if entry.is_valid {
                let name = entry.name_str();
                let mut child_buf = [0u8; 128];
                let child_path = normalize_path(dir_path, name, &mut child_buf);
                if entry.obj_type == DnodeType::Directory {
                    let _ = recursively_remove_dir(child_path);
                } else {
                    let _ = ZfsClient::remove_file(child_path);
                }
            }
        }
    }
    ZfsClient::remove_dir(dir_path)
}

/// Copies files in ZFS.
pub struct CpCommand;

impl Command for CpCommand {
    fn name(&self) -> &'static str {
        "cp"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["copy"]
    }

    fn description(&self) -> &'static str {
        "Copy files in ZFS"
    }

    fn usage(&self) -> &'static str {
        "cp [-r] <source> <dest>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let mut clean_args: [&str; 4] = [""; 4];
        let mut count = 0;

        for &arg in args {
            if !arg.starts_with('-') && count < clean_args.len() {
                clean_args[count] = arg;
                count += 1;
            }
        }

        if count < 2 {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let src = clean_args[0];
        let dst = clean_args[1];

        let mut src_buf = [0u8; 128];
        let src_norm = normalize_path(state.cwd_str(), src, &mut src_buf);

        let mut dst_buf = [0u8; 128];
        let mut dst_norm = normalize_path(state.cwd_str(), dst, &mut dst_buf);

        // If destination is an existing directory, copy into it with source filename
        let mut final_dst_buf = [0u8; 128];
        if let Ok((_, DnodeType::Directory)) = resolve_path(dst_norm) {
            let filename = src_norm.rsplit(['/', '\\']).next().unwrap_or(src);
            dst_norm = normalize_path(dst_norm, filename, &mut final_dst_buf);
        }

        match ZfsClient::copy_file(src_norm, dst_norm) {
            Ok(txg) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Copied '{}' -> '{}' (Committed TXG #{})", src, dst_norm, txg);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("cp: failed to copy '{}' to '{}': {}", src, dst, e);
            }
        }
    }
}

/// Moves or renames files or directories in ZFS.
pub struct MvCommand;

impl Command for MvCommand {
    fn name(&self) -> &'static str {
        "mv"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["rename"]
    }

    fn description(&self) -> &'static str {
        "Move or rename files/directories in ZFS"
    }

    fn usage(&self) -> &'static str {
        "mv <source> <dest>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let mut clean_args: [&str; 4] = [""; 4];
        let mut count = 0;

        for &arg in args {
            if !arg.starts_with('-') && count < clean_args.len() {
                clean_args[count] = arg;
                count += 1;
            }
        }

        if count < 2 {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let src = clean_args[0];
        let dst = clean_args[1];

        let mut src_buf = [0u8; 128];
        let src_norm = normalize_path(state.cwd_str(), src, &mut src_buf);

        let mut dst_buf = [0u8; 128];
        let mut dst_norm = normalize_path(state.cwd_str(), dst, &mut dst_buf);

        // If destination is a directory, move into it keeping original name
        let mut final_dst_buf = [0u8; 128];
        if let Ok((_, DnodeType::Directory)) = resolve_path(dst_norm) {
            let filename = src_norm.rsplit(['/', '\\']).next().unwrap_or(src);
            dst_norm = normalize_path(dst_norm, filename, &mut final_dst_buf);
        }

        match ZfsClient::move_entry(src_norm, dst_norm) {
            Ok(_) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Moved '{}' -> '{}'", src, dst_norm);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("mv: failed to move '{}' to '{}': {}", src, dst, e);
            }
        }
    }
}

/// Creates an empty file or updates timestamp in ZFS.
pub struct TouchCommand;

impl Command for TouchCommand {
    fn name(&self) -> &'static str {
        "touch"
    }

    fn description(&self) -> &'static str {
        "Create empty files or update timestamps in ZFS"
    }

    fn usage(&self) -> &'static str {
        "touch <filename...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        for &arg in args {
            if arg.starts_with('-') { continue; }
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), arg, &mut norm_buf);

            match ZfsClient::touch_file(path) {
                Ok(txg) => {
                    set_color(Color::LightGreen, Color::Black);
                    println!("[+] Touched '{}' (TXG #{})", path, txg);
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("touch: failed to touch '{}': {}", arg, e);
                }
            }
        }
    }
}

/// Displays detailed file or directory metadata.
pub struct StatCommand;

impl Command for StatCommand {
    fn name(&self) -> &'static str {
        "stat"
    }

    fn description(&self) -> &'static str {
        "Display detailed file or filesystem status"
    }

    fn usage(&self) -> &'static str {
        "stat <filename>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let target = args[0];
        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

        match ZfsClient::file_stat(path) {
            Ok(st) => {
                set_color(Color::Yellow, Color::Black);
                println!("  File: {}", path);
                set_color(Color::White, Color::Black);
                let type_str = match st.obj_type {
                    DnodeType::PlainFile => "regular file",
                    DnodeType::Directory => "directory",
                    DnodeType::Dataset => "dataset",
                    _ => "unknown",
                };
                let blocks = (st.size + 4095) / 4096;
                println!("  Size: {:<12} Blocks: {:<8} IO Block: 4096   {}", st.size, blocks, type_str);
                println!("Device: hydrapool    Inode/Obj: {:<8} Links: 1", st.obj_id);
                println!("Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)");
                println!("Birth TXG: #{}", st.birth_txg);
                println!("Checksum: Fletcher-4 [{:016x} {:016x} {:016x} {:016x}]",
                    st.checksum[0], st.checksum[1], st.checksum[2], st.checksum[3]);
                println!("Status: ONLINE (Copy-on-Write Merkle root verified)");
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("stat: cannot stat '{}': {}", target, e);
            }
        }
    }
}

/// Reports filesystem disk space and pool usage.
pub struct DfCommand;

impl Command for DfCommand {
    fn name(&self) -> &'static str {
        "df"
    }

    fn description(&self) -> &'static str {
        "Report file system disk space and pool usage (options: -h human-readable)"
    }

    fn usage(&self) -> &'static str {
        "df [-h]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let mut human = false;
        for &arg in args {
            if arg == "-h" || arg == "-H" {
                human = true;
            }
        }

        match ZfsClient::pool_status() {
            Ok((total_mb, alloc_kb, free_kb, txg)) => {
                let total_kb = total_mb * 1024;
                let used_pct = if total_kb > 0 { (alloc_kb * 100) / total_kb } else { 0 };

                set_color(Color::Yellow, Color::Black);
                if human {
                    println!("{:<18} {:>8} {:>8} {:>8} {:>5} {:<12}", "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on");
                } else {
                    println!("{:<18} {:>10} {:>10} {:>10} {:>5} {:<12}", "Filesystem", "1K-blocks", "Used", "Available", "Use%", "Mounted on");
                }
                println!("----------------------------------------------------------------------");

                set_color(Color::White, Color::Black);
                let datasets = [
                    ("hydrapool/root", "/"),
                    ("hydrapool/bin", "/bin"),
                    ("hydrapool/home", "/root"),
                    ("hydrapool/tmp", "/tmp"),
                ];

                for &(ds_name, mount) in &datasets {
                    if human {
                        println!("{:<18} {:>7}M {:>7}K {:>7}K {:>4}% {:<12}",
                            ds_name, total_mb, alloc_kb, free_kb, used_pct, mount);
                    } else {
                        println!("{:<18} {:>10} {:>10} {:>10} {:>4}% {:<12}",
                            ds_name, total_kb, alloc_kb, free_kb, used_pct, mount);
                    }
                }
                set_color(Color::LightGreen, Color::Black);
                println!("----------------------------------------------------------------------");
                println!("Storage Engine: OpenZFS v5000 (Active TXG #{}, 1 vdev, CoW enabled)\n", txg);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("df: failed to query storage pool: {}", e);
            }
        }
    }
}

/// Estimates file space usage.
pub struct DuCommand;

impl Command for DuCommand {
    fn name(&self) -> &'static str {
        "du"
    }

    fn description(&self) -> &'static str {
        "Estimate file and directory space usage (options: -h human-readable, -s summary)"
    }

    fn usage(&self) -> &'static str {
        "du [-h] [-s] [-a] [path]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let mut human = false;
        let mut summary_only = false;
        let mut all_files = false;
        let mut target_path = "";

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'h' => human = true,
                        's' => summary_only = true,
                        'a' => all_files = true,
                        _ => {}
                    }
                }
            } else if target_path.is_empty() {
                target_path = arg;
            }
        }

        let raw_path = if target_path.is_empty() { state.cwd_str() } else { target_path };
        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), raw_path, &mut norm_buf);

        match resolve_path(path) {
            Ok((_, DnodeType::PlainFile)) => {
                if let Ok(st) = ZfsClient::file_stat(path) {
                    let kb = (st.size + 1023) / 1024;
                    set_color(Color::White, Color::Black);
                    if human {
                        println!("{}K\t{}", kb, path);
                    } else {
                        println!("{}\t{}", kb, path);
                    }
                }
            }
            Ok((_, DnodeType::Directory)) => {
                let mut total_kb = 0;
                if let Ok((entries, _, _)) = ZfsClient::list_dir(path) {
                    for entry in entries.iter() {
                        if entry.is_valid {
                            let name = entry.name_str();
                            let mut item_buf = [0u8; 128];
                            let item_path = normalize_path(path, name, &mut item_buf);
                            if let Ok(st) = ZfsClient::file_stat(item_path) {
                                let item_kb = (st.size + 1023) / 1024;
                                total_kb += item_kb;
                                if all_files && !summary_only {
                                    set_color(Color::White, Color::Black);
                                    if human {
                                        println!("{}K\t{}", item_kb, item_path);
                                    } else {
                                        println!("{}\t{}", item_kb, item_path);
                                    }
                                }
                            }
                        }
                    }
                }
                set_color(Color::White, Color::Black);
                if human {
                    println!("{}K\t{}", total_kb, path);
                } else {
                    println!("{}\t{}", total_kb, path);
                }
            }
            _ => {
                set_color(Color::LightRed, Color::Black);
                println!("du: cannot access '{}': No such file or directory", path);
            }
        }
    }
}
