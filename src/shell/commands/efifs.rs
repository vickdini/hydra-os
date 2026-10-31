//! # Shell Command: UEFI Boot Partition Diagnostics (`efifs`)
//!
//! Provides low-level inspection (`efifs ls`, `efifs cat`) and PE32+ image execution
//! (`efifs run`) on the underlying UEFI firmware FAT boot volume while UEFI Boot Services
//! remain active.
//!
//! ## Architectural Role & Design Rationale
//! Because standard shell filesystem commands (`ls`, `cat`, `cp`, `rm`) operate against the
//! microkernel's OpenZFS storage pool (`hydrapool`), [`EfifsCommand`] gives engineers a dedicated
//! tool to inspect and execute files residing directly on the EFI System Partition (ESP) prior
//! to calling `exitboot`.
//!
//! ## Key Types & Interfaces
//! - [`EfifsCommand`]: Implements the `efifs` command and its `ls`, `cat`, and `run` subcommands.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (UEFI Boot Services context only; disabled after `exitboot`)
//! - Hardware Interaction: Invokes UEFI `SimpleFileSystem` and `LoadedImage` protocols via [`crate::shell::fs`]
//! - Concurrency: Single-threaded synchronous UEFI protocol calls

use uefi::proto::console::text::Color;
use uefi::proto::media::file::{File, FileAttribute, FileMode};

use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::fs::{open_root_volume, path_to_cstr16, print_file, execute_file};
use crate::shell::state::ShellState;

/// Built-in `efifs` command for inspecting and running files on the UEFI FAT boot partition.
pub struct EfifsCommand;

impl Command for EfifsCommand {
    fn name(&self) -> &'static str {
        "efifs"
    }

    fn description(&self) -> &'static str {
        "Low-level UEFI firmware boot partition diagnostics (e.g. 'efifs ls', 'efifs cat')"
    }

    fn usage(&self) -> &'static str {
        "efifs <ls|cat|run> [path]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if crate::console::is_hardware_mode() {
            set_color(Color::Yellow, Color::Black);
            println!("[-] 'efifs' is unavailable in hardware mode: UEFI Boot Services have been terminated.");
            println!("    Use native ZFS file commands ('ls', 'cat', 'write') instead.");
            return;
        }

        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: efifs <ls [path] | cat <path> | run <path>>");
            return;
        }

        match args[0] {
            "ls" | "dir" => {
                let dir_path = if args.len() > 1 { args[1] } else { "\\" };
                list_uefi_directory(dir_path);
            }

            "cat" | "type" => {
                if args.len() < 2 {
                    set_color(Color::LightRed, Color::Black);
                    println!("Usage: efifs cat <path>");
                    return;
                }
                print_file(args[1]);
            }

            "run" | "exec" => {
                if args.len() < 2 {
                    set_color(Color::LightRed, Color::Black);
                    println!("Usage: efifs run <path> [args...]");
                    return;
                }
                let path = args[1];
                let app_args = &args[2..];
                if let Err(e) = execute_file(path, app_args) {
                    set_color(Color::LightRed, Color::Black);
                    println!("[!] UEFI execution failed: {}", e);
                }
            }

            _ => {
                set_color(Color::LightRed, Color::Black);
                println!("Unknown sub-command: '{}'. Usage: efifs <ls|cat|run>", args[0]);
            }
        }
    }
}

/// Lists directory contents on the raw UEFI firmware boot partition with proper string decoding.
fn list_uefi_directory(dir_path: &str) {
    let mut root = match open_root_volume() {
        Ok(r) => r,
        Err(e) => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Cannot open UEFI boot filesystem: {}", e);
            return;
        }
    };

    let target_dir_res = if dir_path.is_empty() || dir_path == "\\" || dir_path == "/" {
        Ok(root)
    } else {
        let mut path_u16 = [0u16; 128];
        match path_to_cstr16(dir_path, &mut path_u16) {
            Some(cstr) => match root.open(cstr, FileMode::Read, FileAttribute::empty()) {
                Ok(fh) => fh.into_directory().ok_or("Not a directory"),
                Err(_) => Err("Directory not found"),
            },
            None => Err("Invalid directory path"),
        }
    };

    let mut target_dir = match target_dir_res {
        Ok(d) => d,
        Err(err) => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Error opening UEFI directory '{}': {}", dir_path, err);
            return;
        }
    };

    set_color(Color::Yellow, Color::Black);
    println!("UEFI Firmware Boot Partition ('{}'):", if dir_path.is_empty() { "\\" } else { dir_path });
    println!("{:<24} {:<10} {:>10}", "NAME", "TYPE", "SIZE");
    println!("--------------------------------------------------");

    let mut entry_buf = [0u8; 512];
    let mut count = 0;

    loop {
        match target_dir.read_entry(&mut entry_buf) {
            Ok(Some(info)) => {
                let is_dir = info.attribute().contains(FileAttribute::DIRECTORY);
                let type_str = if is_dir { "<DIR>" } else { "<FILE>" };
                let size = info.file_size();

                // Decode UTF-16 to ASCII to avoid formatter column misalignment
                let mut name_buf = [0u8; 64];
                let mut len = 0;
                for c in info.file_name().iter() {
                    let val = u16::from(*c);
                    if val == 0 || len >= name_buf.len() { break; }
                    name_buf[len] = if val < 128 { val as u8 } else { b'?' };
                    len += 1;
                }
                let name_str = core::str::from_utf8(&name_buf[..len]).unwrap_or("<invalid>");

                if is_dir {
                    set_color(Color::LightCyan, Color::Black);
                } else {
                    set_color(Color::White, Color::Black);
                }

                println!("{:<24} {:<10} {:>10}", name_str, type_str, size);
                count += 1;
            }
            Ok(None) => break,
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Error reading directory entry: {:?}", e);
                break;
            }
        }
    }

    set_color(Color::LightGreen, Color::Black);
    println!("--------------------------------------------------");
    println!("Total entries: {}\n", count);
}
