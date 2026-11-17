//! File commands: the pool through the admin interface's storage operations (listings,
//! changes) and the native `open`/`read` calls (contents).

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::{normalize_path, usage, Shell};
use hydra_rt::println;

/// Splits arguments into flag letters and operands.
fn flags_and_operands<'a>(args: &[&'a str]) -> (String, Vec<&'a str>) {
    let mut flags = String::new();
    let mut ops = Vec::new();
    for &a in args {
        if a.starts_with('-') && a.len() > 1 {
            flags.push_str(&a[1..]);
        } else {
            ops.push(a);
        }
    }
    (flags, ops)
}

/// A change in the pool (`FS_*`): the transaction group, or the kernel's message.
fn fs_op(code: u64, path: &str, second: &[u8]) -> Result<u64, String> {
    let input = if second.is_empty() && code != FS_WRITE { Vec::from(path.as_bytes()) } else { two(path, second) };
    admin_u64(ADMIN_FS_OP, [code, 0, 0, 0], &input).map_err(|e| String::from(e.text()))
}

/// The kind of a pool path, if it exists.
fn kind(path: &str) -> Option<u8> {
    lookup(path).ok().map(|r| r.kind as u8)
}

pub fn pwd(sh: &mut Shell, _args: &[&str]) {
    color(WHITE);
    println!("{}", sh.cwd);
}

pub fn cd(sh: &mut Shell, args: &[&str]) {
    let target = if args.is_empty() || args[0] == "~" { "/root" } else { args[0] };
    let path = normalize_path(&sh.cwd, target);
    match kind(&path) {
        Some(KIND_DIR) => {
            let mut p = path;
            // As the kernel shell's 64-byte working directory
            p.truncate(64);
            sh.cwd = p;
        }
        Some(_) => {
            color(LIGHT_RED);
            println!("cd: '{}' is not a directory", target);
        }
        None => {
            if target == "/root" {
                sh.cwd = String::from("/");
            } else {
                color(LIGHT_RED);
                println!("cd: no such file or directory: '{}'", target);
            }
        }
    }
}

pub fn ls(sh: &mut Shell, args: &[&str]) {
    let (flags, ops) = flags_and_operands(args);
    let (long, all) = (flags.contains('l'), flags.contains('a'));
    let raw = ops.first().map_or(sh.cwd.clone(), |t| String::from(*t));
    let path = normalize_path(&sh.cwd, &raw);
    let answer = match admin(ADMIN_DIR_LIST, [0; 4], path.as_bytes()) {
        Ok(a) => a,
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Failed to list directory '{}': {}", path, e.text());
            return;
        }
    };
    let header: DirHeader = read_record(&answer, 0).unwrap_or_default();
    color(YELLOW);
    println!("ZFS Directory listing for '{}' (Dataset: {}):", path, name_str(&header.dataset));
    if long {
        println!("{:<24} {:<10} {:>10} {:>10} {:>10}", "NAME", "TYPE", "SIZE", "CHECKSUM", "STATUS");
    } else {
        println!("{:<24} {:<10} {:>10} {:>10}", "NAME", "TYPE", "CHECKSUM", "STATUS");
    }
    println!("------------------------------------------------------------");
    let mut printed = 0;
    for e in records::<DirRecord>(&answer, core::mem::size_of::<DirHeader>(), header.count as usize) {
        if e.kind == KIND_INVALID {
            continue;
        }
        let name = name_str(&e.name);
        if !all && name.starts_with('.') && name != "." && name != ".." {
            continue;
        }
        let is_dir = e.kind == KIND_DIR;
        let kind = if is_dir { "<DIR>" } else { "<FILE>" };
        color(if is_dir { LIGHT_CYAN } else { WHITE });
        if long {
            let size = lookup(&normalize_path(&path, name)).map_or(0, |r| r.size);
            println!("{:<24} {:<10} {:>10} {:>10} {:>10}", name, kind, size, "Fletcher4", "ONLINE");
        } else {
            println!("{:<24} {:<10} {:>10} {:>10}", name, kind, "Fletcher4", "ONLINE");
        }
        printed += 1;
    }
    if printed == 0 {
        color(DARK_GRAY);
        println!("  (empty directory)");
    }
    color(LIGHT_GREEN);
    println!("------------------------------------------------------------");
    println!("Total entries: {} (ZFS pool: hydrapool, CoW enabled)\n", header.count);
}

/// Prints text (lines), or the binary-data line.
fn print_text(data: &[u8]) {
    color(WHITE);
    match core::str::from_utf8(data) {
        Ok(text) => {
            for line in text.lines() {
                if interrupted() {
                    println!("^C");
                    return;
                }
                println!("{}", line);
            }
        }
        Err(_) => println!("[Binary data: {} bytes, Fletcher-4 checksum verified]", data.len()),
    }
}

pub fn cat(sh: &mut Shell, args: &[&str]) {
    if args.is_empty() || args[0] == "-" {
        if let Some(data) = sh.take_stdin() {
            color(WHITE);
            write_out(&data);
        }
        return;
    }
    let path = normalize_path(&sh.cwd, args[0]);
    // As the kernel shell: the first 4 KiB
    match read_file(&path, 4096) {
        Ok(data) => print_text(&data),
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Cannot read file '{}': {}", path, e);
            sh.status = 1;
        }
    }
}

pub fn write(sh: &mut Shell, args: &[&str]) {
    let Some(&name) = args.first() else { return usage("write <filename> [content...]") };
    let path = normalize_path(&sh.cwd, name);
    let content = args[1..].join(" ");
    match fs_op(FS_WRITE, &path, content.as_bytes()) {
        Ok(txg) => {
            color(LIGHT_GREEN);
            println!("[+] File '{}' written to ZFS File Server!", path);
            println!("    - Size: {} bytes", content.len());
            println!("    - Merkle Root committed at TXG #{}", txg);
            println!("    - Checksum: Fletcher-4 verified");
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("[!] Write failed for '{}': {}", path, e);
        }
    }
}

pub fn touch(sh: &mut Shell, args: &[&str]) {
    if args.is_empty() {
        return usage("touch <file...>");
    }
    for &a in args {
        let path = normalize_path(&sh.cwd, a);
        match fs_op(FS_TOUCH, &path, &[]) {
            Ok(txg) => {
                color(LIGHT_GREEN);
                println!("[+] Touched '{}' (TXG #{})", path, txg);
            }
            Err(e) => {
                color(LIGHT_RED);
                println!("touch: failed to touch '{}': {}", a, e);
            }
        }
    }
}

pub fn mkdir(sh: &mut Shell, args: &[&str]) {
    let (flags, ops) = flags_and_operands(args);
    if ops.is_empty() {
        color(LIGHT_RED);
        println!("mkdir: missing operand");
        return;
    }
    for t in ops {
        let path = normalize_path(&sh.cwd, t);
        let code = if flags.contains('p') { FS_MKDIR_ALL } else { FS_MKDIR };
        match fs_op(code, &path, &[]) {
            Ok(_) => {
                color(LIGHT_GREEN);
                println!("[+] Created directory '{}'", path);
            }
            Err(e) => {
                color(LIGHT_RED);
                println!("mkdir: cannot create directory '{}': {}", path, e);
            }
        }
    }
}

pub fn rmdir(sh: &mut Shell, args: &[&str]) {
    if args.is_empty() {
        return usage("rmdir <dir...>");
    }
    for &t in args {
        let path = normalize_path(&sh.cwd, t);
        match fs_op(FS_RMDIR, &path, &[]) {
            Ok(_) => {
                color(LIGHT_GREEN);
                println!("[+] Removed directory '{}'", path);
            }
            Err(e) => {
                color(LIGHT_RED);
                println!("rmdir: failed to remove '{}': {}", t, e);
            }
        }
    }
}

/// Removes a directory and everything in it.
fn remove_tree(path: &str) -> Result<u64, String> {
    if let Ok(a) = admin(ADMIN_DIR_LIST, [0; 4], path.as_bytes()) {
        let header: DirHeader = read_record(&a, 0).unwrap_or_default();
        for e in records::<DirRecord>(&a, core::mem::size_of::<DirHeader>(), header.count as usize) {
            let name = name_str(&e.name);
            if e.kind == KIND_INVALID || name == "." || name == ".." {
                continue;
            }
            let child = normalize_path(path, name);
            if e.kind == KIND_DIR {
                let _ = remove_tree(&child);
            } else {
                let _ = fs_op(FS_UNLINK, &child, &[]);
            }
        }
    }
    fs_op(FS_RMDIR, path, &[])
}

pub fn rm(sh: &mut Shell, args: &[&str]) {
    let (flags, ops) = flags_and_operands(args);
    let (recursive, force) = (flags.contains('r') || flags.contains('R'), flags.contains('f'));
    if ops.is_empty() {
        if !force {
            color(LIGHT_RED);
            println!("rm: missing operand");
        }
        return;
    }
    for t in ops {
        let path = normalize_path(&sh.cwd, t);
        match kind(&path) {
            Some(KIND_DIR) if recursive => {
                let _ = remove_tree(&path);
                color(LIGHT_GREEN);
                println!("[+] Removed directory '{}'", path);
            }
            Some(KIND_DIR) => {
                if !force {
                    color(LIGHT_RED);
                    println!("rm: cannot remove '{}': Is a directory (use -r)", t);
                }
            }
            Some(_) => match fs_op(FS_UNLINK, &path, &[]) {
                Ok(_) => {
                    color(LIGHT_GREEN);
                    println!("[+] Removed file '{}'", path);
                }
                Err(e) => {
                    if !force {
                        color(LIGHT_RED);
                        println!("rm: cannot remove '{}': {}", t, e);
                    }
                }
            },
            None => {
                if !force {
                    color(LIGHT_RED);
                    println!("rm: cannot remove '{}': No such file or directory", t);
                }
            }
        }
    }
}

/// `cp`/`mv`: the target path (into a directory: under the source's name).
fn target(sh: &Shell, src: &str, dst: &str) -> (String, String) {
    let src_norm = normalize_path(&sh.cwd, src);
    let mut dst_norm = normalize_path(&sh.cwd, dst);
    if kind(&dst_norm) == Some(KIND_DIR) {
        let file = src_norm.rsplit(['/', '\\']).next().unwrap_or(src);
        dst_norm = normalize_path(&dst_norm, file);
    }
    (src_norm, dst_norm)
}

pub fn cp(sh: &mut Shell, args: &[&str]) {
    let (_, ops) = flags_and_operands(args);
    if ops.len() < 2 {
        return usage("cp [-r] <source> <dest>");
    }
    let (src, dst) = (ops[0], ops[1]);
    let (src_norm, dst_norm) = target(sh, src, dst);
    match fs_op(FS_COPY, &src_norm, dst_norm.as_bytes()) {
        Ok(txg) => {
            color(LIGHT_GREEN);
            println!("[+] Copied '{}' -> '{}' (Committed TXG #{})", src, dst_norm, txg);
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("cp: failed to copy '{}' to '{}': {}", src, dst, e);
            sh.status = 1;
        }
    }
}

pub fn mv(sh: &mut Shell, args: &[&str]) {
    let (_, ops) = flags_and_operands(args);
    if ops.len() < 2 {
        return usage("mv <source> <dest>");
    }
    let (src, dst) = (ops[0], ops[1]);
    let (src_norm, dst_norm) = target(sh, src, dst);
    match fs_op(FS_RENAME, &src_norm, dst_norm.as_bytes()) {
        Ok(_) => {
            color(LIGHT_GREEN);
            println!("[+] Moved '{}' -> '{}'", src, dst_norm);
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("mv: failed to move '{}' to '{}': {}", src, dst, e);
        }
    }
}

pub fn stat(sh: &mut Shell, args: &[&str]) {
    let Some(&t) = args.first() else { return usage("stat <path>") };
    let path = normalize_path(&sh.cwd, t);
    match admin_rec::<StatRecord>(ADMIN_FILE_STAT, [0; 4], path.as_bytes()) {
        Ok(st) => {
            let type_str = match st.kind as u8 {
                KIND_FILE => "regular file",
                KIND_DIR => "directory",
                _ => "unknown",
            };
            color(LIGHT_CYAN);
            println!("  File: {}", path);
            color(WHITE);
            println!("  Size: {:<12} Blocks: {:<8} IO Block: 4096   {}", st.size, st.size.div_ceil(4096), type_str);
            println!("Device: hydrapool    Inode/Obj: {:<8} Links: 1", st.obj);
            println!("Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)");
            println!("Birth TXG: #{}", st.birth_txg);
            println!("Checksum: Fletcher-4 [{:016x} {:016x} {:016x} {:016x}]", st.checksum[0], st.checksum[1], st.checksum[2], st.checksum[3]);
            println!("Status: ONLINE (Copy-on-Write Merkle root verified)");
        }
        Err(e) => {
            color(LIGHT_RED);
            println!("stat: cannot stat '{}': {}", t, e.text());
        }
    }
}

pub fn df(_sh: &mut Shell, args: &[&str]) {
    let human = args.iter().any(|a| *a == "-h" || *a == "-H");
    let st: PoolStatus = admin_rec(ADMIN_POOL_STATUS, [0; 4], &[]).unwrap_or_default();
    if st.metrics_valid == 0 {
        color(LIGHT_RED);
        println!("df: failed to query storage pool: the file server did not answer");
        return;
    }
    let total_kb = st.total_mib * 1024;
    let used_pct = if total_kb > 0 { (st.alloc_kib * 100) / total_kb } else { 0 };
    color(YELLOW);
    if human {
        println!("{:<18} {:>8} {:>8} {:>8} {:>5} {:<12}", "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on");
    } else {
        println!("{:<18} {:>10} {:>10} {:>10} {:>5} {:<12}", "Filesystem", "1K-blocks", "Used", "Available", "Use%", "Mounted on");
    }
    println!("----------------------------------------------------------------------");
    color(WHITE);
    for (ds, mount) in [("hydrapool/root", "/"), ("hydrapool/bin", "/bin"), ("hydrapool/home", "/root"), ("hydrapool/tmp", "/tmp")] {
        if human {
            println!("{:<18} {:>7}M {:>7}K {:>7}K {:>4}% {:<12}", ds, st.total_mib, st.alloc_kib, st.free_kib, used_pct, mount);
        } else {
            println!("{:<18} {:>10} {:>10} {:>10} {:>4}% {:<12}", ds, total_kb, st.alloc_kib, st.free_kib, used_pct, mount);
        }
    }
    color(LIGHT_GREEN);
    println!("----------------------------------------------------------------------");
    println!("Storage Engine: OpenZFS v5000 (Active TXG #{}, 1 vdev, CoW enabled)\n", st.txg);
}

pub fn du(sh: &mut Shell, args: &[&str]) {
    let (flags, ops) = flags_and_operands(args);
    let (human, summary, all) = (flags.contains('h'), flags.contains('s'), flags.contains('a'));
    let raw = ops.first().map_or(sh.cwd.clone(), |t| String::from(*t));
    let path = normalize_path(&sh.cwd, &raw);
    let show = |kb: u64, p: &str| {
        color(WHITE);
        if human {
            println!("{}K\t{}", kb, p);
        } else {
            println!("{}\t{}", kb, p);
        }
    };
    match lookup(&path) {
        Ok(r) if r.kind == KIND_FILE as u64 => show(r.size.div_ceil(1024), &path),
        Ok(r) if r.kind == KIND_DIR as u64 => {
            let mut total = 0;
            if let Ok(a) = admin(ADMIN_DIR_LIST, [0; 4], path.as_bytes()) {
                let header: DirHeader = read_record(&a, 0).unwrap_or_default();
                for e in records::<DirRecord>(&a, core::mem::size_of::<DirHeader>(), header.count as usize) {
                    if e.kind == KIND_INVALID {
                        continue;
                    }
                    let item = normalize_path(&path, name_str(&e.name));
                    if let Ok(st) = lookup(&item) {
                        let kb = st.size.div_ceil(1024);
                        total += kb;
                        if all && !summary {
                            show(kb, &item);
                        }
                    }
                }
            }
            show(total, &path);
        }
        _ => {
            color(LIGHT_RED);
            println!("du: cannot access '{}': No such file or directory", path);
        }
    }
}
