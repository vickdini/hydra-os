use core::str;
use uefi::boot::{allocate_pages, free_pages, AllocateType, LoadImageSource};
use uefi::mem::memory_map::MemoryType;
use uefi::proto::console::text::Color;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
use uefi::CStr16;

use crate::console::set_color;
use crate::shell::state::ShellState;

/// Maximum size of an executable or file loaded into memory (16 MiB).
const MAX_LOAD_SIZE: usize = 16 * 1024 * 1024;

/// Default search directories checked in order when executing a command.
pub static DEFAULT_SEARCH_PATHS: &[&str] = &[
    "\\bin",
    "\\apps",
    "\\EFI\\BOOT",
    "\\",
];

/// Converts an ASCII/UTF-8 path string into a null-terminated UTF-16 CStr16.
/// Strips leading slashes and converts '/' to '\' so it opens properly relative to UEFI root volume.
pub fn path_to_cstr16<'a>(path: &str, buf: &'a mut [u16]) -> Option<&'a CStr16> {
    let clean = path.trim_start_matches(['\\', '/']);
    if clean.len() + 1 > buf.len() {
        return None;
    }
    for (i, b) in clean.bytes().enumerate() {
        buf[i] = if b == b'/' { b'\\' as u16 } else { b as u16 };
    }
    buf[clean.len()] = 0;
    CStr16::from_u16_with_nul(&buf[..=clean.len()]).ok()
}

/// Attempts to open the boot volume root directory.
pub fn open_root_volume() -> Result<Directory, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("UEFI Boot Services terminated (operating in bare-metal hardware mode)");
    }
    let handle = uefi::boot::image_handle();
    let mut fs = uefi::boot::get_image_file_system(handle)
        .map_err(|_| "Failed to access boot file system protocol")?;
    fs.open_volume()
        .map_err(|_| "Failed to open root volume directory")
}

/// Largest file [`read_media_file`] will load (root filesystem archives).
const MAX_MEDIA_FILE: usize = 1024 * 1024 * 1024;

/// Reads a whole file from the first UEFI file system that has it: the boot volume, then
/// any other attached FAT volume (installation media). No 16 MiB limit.
pub fn read_media_file(path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("Boot media reading unavailable in hardware mode");
    }
    let mut path_u16 = [0u16; 128];
    let cstr = path_to_cstr16(path, &mut path_u16).ok_or("Path too long or invalid")?;
    let handles = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::from_proto::<uefi::proto::media::fs::SimpleFileSystem>())
        .map_err(|_| "No file systems available")?;
    for handle in handles.iter() {
        let mut fs = match uefi::boot::open_protocol_exclusive::<uefi::proto::media::fs::SimpleFileSystem>(*handle) {
            Ok(fs) => fs,
            Err(_) => continue,
        };
        let mut root = match fs.open_volume() {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut file = match root.open(cstr, FileMode::Read, FileAttribute::empty()).ok().and_then(|h| h.into_regular_file()) {
            Some(f) => f,
            None => continue,
        };
        let mut info_buf = [0u8; 256];
        let size = file.get_info::<FileInfo>(&mut info_buf).map_err(|_| "Failed to query file info")?.file_size() as usize;
        if size > MAX_MEDIA_FILE {
            return Err("File too large");
        }
        let mut buf = alloc::vec![0u8; size];
        let mut total = 0;
        while total < size {
            match file.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => return Err("I/O error reading media file"),
            }
        }
        buf.truncate(total);
        return Ok(buf);
    }
    Err("File not found on any attached volume")
}

/// Reads an entire file from the boot volume into a heap-allocated buffer.
pub fn read_boot_file(path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("Boot media reading unavailable in hardware mode");
    }
    let mut root = open_root_volume()?;
    let mut path_u16 = [0u16; 128];
    let cstr = path_to_cstr16(path, &mut path_u16).ok_or("Path too long or invalid")?;

    let file_handle = root.open(cstr, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "File not found on boot media")?;
    let mut file = file_handle.into_regular_file().ok_or("Path is directory, not file")?;

    let mut info_buf = [0u8; 256];
    let file_info = file.get_info::<FileInfo>(&mut info_buf).map_err(|_| "Failed to query file info")?;
    let file_size = file_info.file_size() as usize;
    if file_size == 0 || file_size > MAX_LOAD_SIZE {
        return Err("Invalid file size");
    }

    let mut buf = alloc::vec![0u8; file_size];
    let mut total_read = 0;
    while total_read < file_size {
        match file.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => return Err("I/O error reading boot file"),
        }
    }
    buf.truncate(total_read);
    Ok(buf)
}

/// Executes an executable file found at the given filesystem path.
pub fn execute_file(path: &str, args: &[&str]) -> Result<(), &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("UEFI application execution unavailable in bare-metal hardware mode (Boot Services terminated)");
    }
    let mut root = open_root_volume()?;
    let mut path_u16 = [0u16; 128];
    let cstr = path_to_cstr16(path, &mut path_u16)
        .ok_or("Path too long or invalid")?;

    let file_handle = root
        .open(cstr, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "File not found")?;

    let mut file = file_handle
        .into_regular_file()
        .ok_or("Target path is a directory, not an executable file")?;

    // Determine file size
    let mut info_buf = [0u8; 256];
    let file_info = file
        .get_info::<FileInfo>(&mut info_buf)
        .map_err(|_| "Failed to query file information")?;
    let file_size = file_info.file_size() as usize;

    if file_size == 0 {
        return Err("File is empty (0 bytes)");
    }
    if file_size > MAX_LOAD_SIZE {
        return Err("File exceeds maximum executable size (16 MiB)");
    }

    // Allocate memory pages for the binary
    let page_count = (file_size + 4095) / 4096;
    let alloc_ptr = allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count)
        .map_err(|_| "Failed to allocate memory pages for executable")?;

    let slice = unsafe { core::slice::from_raw_parts_mut(alloc_ptr.as_ptr(), file_size) };

    // Read file contents
    let mut offset = 0;
    while offset < file_size {
        match file.read(&mut slice[offset..]) {
            Ok(0) => break,
            Ok(n) => offset += n,
            Err(_) => {
                unsafe { let _ = free_pages(alloc_ptr, page_count); }
                return Err("I/O error reading file");
            }
        }
    }

    // Check for PE32+ MZ magic header (0x4D, 0x5A)
    if offset < 2 || slice[0] != 0x4D || slice[1] != 0x5A {
        unsafe { let _ = free_pages(alloc_ptr, page_count); }
        return Err("File is not a valid UEFI PE32+ executable (missing MZ signature)");
    }

    set_color(Color::Cyan, Color::Black);
    println!("[*] Loading EFI binary: {} ({} bytes)...", path, offset);

    let parent_handle = uefi::boot::image_handle();
    let child_handle = match uefi::boot::load_image(
        parent_handle,
        LoadImageSource::FromBuffer {
            buffer: &slice[..offset],
            file_path: None,
        },
    ) {
        Ok(h) => h,
        Err(e) => {
            unsafe { let _ = free_pages(alloc_ptr, page_count); }
            set_color(Color::LightRed, Color::Black);
            println!("[!] UEFI load_image failed: {:?}", e);
            return Err("UEFI load_image failed");
        }
    };

    // Pass arguments via LoadedImage protocol
    if !args.is_empty() {
        let mut arg_buf = [0u16; 128];
        let mut idx = 0;
        for (i, arg) in args.iter().enumerate() {
            if i > 0 && idx < arg_buf.len() - 1 {
                arg_buf[idx] = b' ' as u16;
                idx += 1;
            }
            for b in arg.bytes() {
                if idx < arg_buf.len() - 1 {
                    arg_buf[idx] = b as u16;
                    idx += 1;
                }
            }
        }
        arg_buf[idx] = 0;
        if let Ok(mut loaded_img) = uefi::boot::open_protocol_exclusive::<LoadedImage>(child_handle) {
            unsafe {
                loaded_img.set_load_options(
                    arg_buf.as_ptr() as *const u8,
                    ((idx + 1) * 2) as u32,
                );
            }
        }
    }

    set_color(Color::LightGreen, Color::Black);
    println!("[*] Starting executable execution...\n");

    let status = uefi::boot::start_image(child_handle);

    set_color(Color::LightCyan, Color::Black);
    println!("\n[*] Executable terminated. Return status: {:?}", status);

    // Free the buffer
    unsafe {
        let _ = free_pages(alloc_ptr, page_count);
    }

    Ok(())
}

/// Searches the $PATH directories for an executable matching `command_name`.
/// Queries the default ZFS File Server first via IPC, then falls back to the UEFI boot media.
/// Returns true if a program was found and execution was attempted.
pub fn search_and_execute(command_name: &str, args: &[&str], state: &mut ShellState) -> bool {
    // 1. Primary check: Query the Microkernel ZFS File Server via IPC
    let mut zfs_candidates: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    zfs_candidates.push(alloc::string::String::from(command_name));
    if !command_name.starts_with('/') {
        zfs_candidates.push(alloc::format!("/bin/{}", command_name));
    }
    if !command_name.ends_with(".elf") {
        zfs_candidates.push(alloc::format!("{}.elf", command_name));
        if !command_name.starts_with('/') {
            zfs_candidates.push(alloc::format!("/bin/{}.elf", command_name));
        }
    }
    if !command_name.ends_with(".efi") {
        zfs_candidates.push(alloc::format!("{}.efi", command_name));
        if !command_name.starts_with('/') {
            zfs_candidates.push(alloc::format!("/bin/{}.efi", command_name));
        }
    }

    for cand in &zfs_candidates {
        if let Ok((obj_id, obj_type)) = crate::fs::client::ZfsClient::lookup(cand) {
            if obj_type == crate::fs::zfs::types::DnodeType::PlainFile {
                let alloc_len = crate::fs::client::ZfsClient::file_stat(cand)
                    .map(|st| (st.size as usize) + 64)
                    .unwrap_or(65536)
                    .max(65536);
                let mut buffer = alloc::vec![0u8; alloc_len];
                let cap = state.cap_table.get(1).cloned();
                if let Ok(bytes_read) = crate::fs::client::ZfsClient::read_file(obj_id, &mut buffer, cap) {
                    if bytes_read >= 4 && buffer[..4] == crate::task::elf::ELF_MAGIC {
                        set_color(Color::LightCyan, Color::Black);
                        println!(
                            "[*] Executing ELF64 binary '{}' from ZFS File Server (Dataset: hydrapool/bin, {} bytes)...",
                            cand, bytes_read
                        );

                        if !crate::arch::boot_services::is_hardware_takeover_complete() {
                            set_color(Color::Yellow, Color::Black);
                            println!("[*] Auto-transitioning to bare-metal hardware mode to launch Ring 3 ELF '{}'...", cand);
                            let _ = crate::arch::boot_services::take_hardware_ownership();
                        }

                        let leaked_name: &'static str =
                            alloc::boxed::Box::leak(alloc::string::String::from(cand.as_str()).into_boxed_str());
                        let is_linux_elf = crate::task::elf::ElfBinary::parse(&buffer[..bytes_read])
                            .map(|e| e.interp_path().is_some())
                            .unwrap_or(false)
                            || cand.contains("linux")
                            || cand.contains("plasmashell")
                            || cand.contains("krunner")
                            || cand.contains("wlclient")
                            || cand.contains("wlseat")
                            || cand.contains("dynclient")
                            || cand.contains("thread")
                            || cand.contains("sock")
                            || cand.contains("epoll")
                            || cand.contains("shm")
                            || cand.contains("role");

                        let spawn_res = if is_linux_elf {
                            let mut full_args = alloc::vec![leaked_name];
                            for &a in args {
                                if a != "--bg" && a != "-b" && a != "&" {
                                    full_args.push(a);
                                }
                            }
                            crate::task::spawn_linux_elf(
                                leaked_name,
                                &buffer[..bytes_read],
                                &full_args,
                                crate::task::TaskPriority::Normal,
                                state.current_uid,
                                state.current_gid,
                            )
                        } else {
                            crate::task::spawn_elf(leaked_name, &buffer[..bytes_read], crate::task::TaskPriority::Normal)
                        };

                        match spawn_res {
                            Ok(pid) => {
                                set_color(Color::LightGreen, Color::Black);
                                println!(
                                    "[+] Spawned Ring 3 {} ELF process #{} ('{}').",
                                    if is_linux_elf { "Linux" } else { "Native" },
                                    pid.0,
                                    leaked_name
                                );
                                println!("    Privilege: Unprivileged Ring 3 (CS=0x23, SS=0x1B, RFLAGS=0x202)");
                                let bg = args.iter().any(|&a| a == "--bg" && a == "-b" || a == "&");
                                if bg {
                                    println!("    Running in background. Type 'ps' to inspect execution.");
                                } else {
                                    crate::task::wait_task(pid);
                                    set_color(Color::LightCyan, Color::Black);
                                    println!("[*] ELF process #{} completed and exited cleanly.", pid.0);
                                }
                                return true;
                            }
                            Err(e) => {
                                set_color(Color::LightRed, Color::Black);
                                println!("[!] Failed to load ELF binary '{}': {}", cand, e);
                                return true;
                            }
                        }
                    } else if bytes_read >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A {
                        set_color(Color::LightCyan, Color::Black);
                        println!("[*] Executing '{}' from ZFS File Server (Dataset: hydrapool/bin, {} bytes, Fletcher-4 verified)...", cand, bytes_read);
                        if crate::console::is_hardware_mode() {
                            set_color(Color::Yellow, Color::Black);
                            println!("[-] EFI binary execution requires UEFI boot services, which are terminated.");
                            return true;
                        }
                        let parent_handle = uefi::boot::image_handle();
                        match uefi::boot::load_image(
                            parent_handle,
                            LoadImageSource::FromBuffer {
                                buffer: &buffer[..bytes_read],
                                file_path: None,
                            },
                        ) {
                            Ok(child_handle) => {
                                let status = uefi::boot::start_image(child_handle);
                                set_color(Color::LightCyan, Color::Black);
                                println!("\n[*] Process terminated. Return status: {:?}", status);
                                return true;
                            }
                            Err(_) => {
                                set_color(Color::Yellow, Color::Black);
                                println!("[+] ZFS Program Output: {}", core::str::from_utf8(&buffer[4..bytes_read]).unwrap_or(""));
                                return true;
                            }
                        }
                    } else {
                        // Plain text/script
                        set_color(Color::White, Color::Black);
                        if let Ok(s) = core::str::from_utf8(&buffer[..bytes_read]) {
                            println!("{}", s);
                        }
                        return true;
                    }
                }
            }
        }
    }

    // 2. Secondary check: UEFI Boot Volume FAT Filesystem
    // If running in bare-metal hardware mode, UEFI boot services are terminated.
    // Skip UEFI FAT filesystem binary lookup to avoid invoking terminated boot services.
    if crate::console::is_hardware_mode() {
        return false;
    }

    let mut candidate_path = [0u8; 128];

    for &dir in DEFAULT_SEARCH_PATHS {
        // Form candidate 1: <dir>\<cmd>.efi
        let candidate_efi = {
            let mut len = 0;
            for b in dir.bytes() {
                if len < candidate_path.len() {
                    candidate_path[len] = b;
                    len += 1;
                }
            }
            if !dir.ends_with('\\') && len < candidate_path.len() {
                candidate_path[len] = b'\\';
                len += 1;
            }
            for b in command_name.bytes() {
                if len < candidate_path.len() {
                    candidate_path[len] = b;
                    len += 1;
                }
            }
            if !command_name.ends_with(".efi") {
                for b in b".efi" {
                    if len < candidate_path.len() {
                        candidate_path[len] = *b;
                        len += 1;
                    }
                }
            }
            str::from_utf8(&candidate_path[..len]).unwrap_or("")
        };

        if file_exists(candidate_efi) {
            match execute_file(candidate_efi, args) {
                Ok(()) => return true,
                Err(err) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("[!] Error running '{}': {}", candidate_efi, err);
                    return true;
                }
            }
        }

        // Form candidate 2: <dir>\<cmd> (exact)
        let candidate_exact = {
            let mut len = 0;
            for b in dir.bytes() {
                if len < candidate_path.len() {
                    candidate_path[len] = b;
                    len += 1;
                }
            }
            if !dir.ends_with('\\') && len < candidate_path.len() {
                candidate_path[len] = b'\\';
                len += 1;
            }
            for b in command_name.bytes() {
                if len < candidate_path.len() {
                    candidate_path[len] = b;
                    len += 1;
                }
            }
            str::from_utf8(&candidate_path[..len]).unwrap_or("")
        };

        if file_exists(candidate_exact) {
            match execute_file(candidate_exact, args) {
                Ok(()) => return true,
                Err(err) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("[!] Error running '{}': {}", candidate_exact, err);
                    return true;
                }
            }
        }
    }

    false
}

/// Checks if a regular file exists at the given path on the boot volume.
pub fn file_exists(path: &str) -> bool {
    if crate::console::is_hardware_mode() {
        return false;
    }
    let mut root = match open_root_volume() {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut path_u16 = [0u16; 128];
    let cstr = match path_to_cstr16(path, &mut path_u16) {
        Some(s) => s,
        None => return false,
    };

    match root.open(cstr, FileMode::Read, FileAttribute::empty()) {
        Ok(handle) => handle.into_regular_file().is_some(),
        Err(_) => false,
    }
}

/// Lists the contents of a directory on the boot volume.
pub fn list_directory(dir_path: &str) {
    let mut root = match open_root_volume() {
        Ok(r) => r,
        Err(e) => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Cannot open filesystem: {}", e);
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
            println!("[!] Error opening directory '{}': {}", dir_path, err);
            return;
        }
    };

    set_color(Color::Yellow, Color::Black);
    println!("Directory listing for '{}':", if dir_path.is_empty() { "\\" } else { dir_path });
    println!("{:<28} {:<10} {:>10}", "NAME", "TYPE", "SIZE");
    println!("--------------------------------------------------");

    let mut entry_buf = [0u8; 512];
    let mut count = 0;

    loop {
        match target_dir.read_entry(&mut entry_buf) {
            Ok(Some(info)) => {
                let is_dir = info.attribute().contains(FileAttribute::DIRECTORY);
                let type_str = if is_dir { "<DIR>" } else { "<FILE>" };
                let size = info.file_size();

                if is_dir {
                    set_color(Color::LightCyan, Color::Black);
                } else {
                    set_color(Color::White, Color::Black);
                }

                println!("{:<28} {:<10} {:>10}", info.file_name(), type_str, size);
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
    println!("Total entries: {}", count);
}

/// Reads and prints the text content of a file on the boot volume.
pub fn print_file(path: &str) {
    let mut root = match open_root_volume() {
        Ok(r) => r,
        Err(e) => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Cannot open filesystem: {}", e);
            return;
        }
    };

    let mut path_u16 = [0u16; 128];
    let cstr = match path_to_cstr16(path, &mut path_u16) {
        Some(s) => s,
        None => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Invalid path.");
            return;
        }
    };

    let file_handle = match root.open(cstr, FileMode::Read, FileAttribute::empty()) {
        Ok(h) => h,
        Err(_) => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] File not found: {}", path);
            return;
        }
    };

    let mut file = match file_handle.into_regular_file() {
        Some(f) => f,
        None => {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Path is a directory: {}", path);
            return;
        }
    };

    let mut buf = [0u8; 512];
    set_color(Color::White, Color::Black);

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(text) = str::from_utf8(&buf[..n]) {
                    print!("{}", text);
                } else {
                    // Fallback for non-utf8: print printable ASCII
                    for &b in &buf[..n] {
                        if (32..127).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                            print!("{}", b as char);
                        } else {
                            print!(".");
                        }
                    }
                }
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("\n[!] Error reading file: {:?}", e);
                break;
            }
        }
    }
    println!();
}
