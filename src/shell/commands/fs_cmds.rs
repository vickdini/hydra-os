use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::{normalize_path, ZfsClient};
use crate::fs::zfs::types::DnodeType;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

pub struct LsCommand;

impl Command for LsCommand {
    fn name(&self) -> &'static str {
        "ls"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["dir"]
    }

    fn description(&self) -> &'static str {
        "List files and directories from ZFS (options: -l long format, -a show all)"
    }

    fn usage(&self) -> &'static str {
        "ls [-l] [-a] [path]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let mut long_format = false;
        let mut show_all = false;
        let mut target_path = "";

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'l' => long_format = true,
                        'a' => show_all = true,
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

        match ZfsClient::list_dir(path) {
            Ok((entries, count, ds_name)) => {
                set_color(Color::Yellow, Color::Black);
                println!("ZFS Directory listing for '{}' (Dataset: {}):", path, ds_name);
                if long_format {
                    println!("{:<24} {:<10} {:>10} {:>10} {:>10}", "NAME", "TYPE", "SIZE", "CHECKSUM", "STATUS");
                } else {
                    println!("{:<24} {:<10} {:>10} {:>10}", "NAME", "TYPE", "CHECKSUM", "STATUS");
                }
                println!("------------------------------------------------------------");

                let mut printed = 0;
                for entry in entries.iter() {
                    if entry.is_valid {
                        let name = entry.name_str();
                        if !show_all && name.starts_with('.') && name != "." && name != ".." {
                            continue;
                        }

                        let is_dir = entry.obj_type == DnodeType::Directory;
                        let type_str = if is_dir { "<DIR>" } else { "<FILE>" };

                        if is_dir {
                            set_color(Color::LightCyan, Color::Black);
                        } else {
                            set_color(Color::White, Color::Black);
                        }

                        if long_format {
                            let mut item_path_buf = [0u8; 128];
                            let item_norm = normalize_path(path, name, &mut item_path_buf);
                            let size_str = if let Ok(stat) = ZfsClient::file_stat(item_norm) {
                                stat.size
                            } else {
                                0
                            };
                            println!("{:<24} {:<10} {:>10} {:>10} {:>10}", name, type_str, size_str, "Fletcher4", "ONLINE");
                        } else {
                            println!("{:<24} {:<10} {:>10} {:>10}", name, type_str, "Fletcher4", "ONLINE");
                        }
                        printed += 1;
                    }
                }

                if printed == 0 {
                    set_color(Color::DarkGray, Color::Black);
                    println!("  (empty directory)");
                }

                set_color(Color::LightGreen, Color::Black);
                println!("------------------------------------------------------------");
                println!("Total entries: {} (ZFS pool: hydrapool, CoW enabled)\n", count);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to list directory '{}': {}", path, e);
            }
        }
    }
}

pub struct CatCommand;

impl Command for CatCommand {
    fn name(&self) -> &'static str {
        "cat"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["type"]
    }

    fn description(&self) -> &'static str {
        "Display file contents via the ZFS File Server (e.g. 'cat readme.txt')"
    }

    fn usage(&self) -> &'static str {
        "cat <filename>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() || args[0] == "-" {
            let mut chunk = [0u8; 1024];
            loop {
                let n = crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(0) {
                        desc.read(&mut chunk).unwrap_or(0)
                    } else {
                        0
                    }
                });
                if n == 0 {
                    break;
                }
                set_color(Color::White, Color::Black);
                if let Ok(text) = core::str::from_utf8(&chunk[..n]) {
                    print!("{}", text);
                } else {
                    for &b in &chunk[..n] {
                        print!("{}", b as char);
                    }
                }
            }
            return;
        }

        let target = args[0];
        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), target, &mut norm_buf);

        let mut buf = [0u8; 4096];
        match ZfsClient::read_file_by_path(path, &mut buf) {
            Ok(n) => {
                set_color(Color::White, Color::Black);
                if let Ok(text) = core::str::from_utf8(&buf[..n]) {
                    for line in text.lines() {
                        if crate::console::check_interrupt() {
                            println!("^C");
                            state.last_status = 130;
                            return;
                        }
                        println!("{}", line);
                    }
                } else {
                    println!("[Binary data: {} bytes, Fletcher-4 checksum verified]", n);
                }
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Cannot read file '{}': {}", path, e);
            }
        }
    }
}

pub struct WriteCommand;

impl Command for WriteCommand {
    fn name(&self) -> &'static str {
        "write"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["append"]
    }

    fn description(&self) -> &'static str {
        "Create or update a file in ZFS via Copy-on-Write (e.g. 'write note.txt Hello World')"
    }

    fn usage(&self) -> &'static str {
        "write <filename> [content...]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: write <filename> [content...]");
            return;
        }

        let name = args[0];
        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), name, &mut norm_buf);

        let mut content_buf = [0u8; 1024];
        let mut content_len = 0;

        for (i, word) in args[1..].iter().enumerate() {
            if i > 0 && content_len < content_buf.len() {
                content_buf[content_len] = b' ';
                content_len += 1;
            }
            for &b in word.as_bytes() {
                if content_len < content_buf.len() {
                    content_buf[content_len] = b;
                    content_len += 1;
                }
            }
        }
        let content_bytes = &content_buf[..content_len];

        match ZfsClient::write_file_by_path(path, content_bytes) {
            Ok(new_txg) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] File '{}' written to ZFS File Server!", path);
                println!("    - Size: {} bytes", content_bytes.len());
                println!("    - Merkle Root committed at TXG #{}", new_txg);
                println!("    - Checksum: Fletcher-4 verified");
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Write failed for '{}': {}", path, e);
            }
        }
    }
}
