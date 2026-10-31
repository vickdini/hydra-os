//! # Linux Compatibility: Program Execution (`execve` / `execveat`)
//!
//! Replaces the calling process's program image with a new ELF binary or `#!` interpreter
//! script while preserving process identity, credentials, and open non-`CLOEXEC` descriptors.
//!
//! ## Architectural Role & Design Rationale
//! The new image (executable, dynamic linker `PT_INTERP`, and initial user stack populated
//! with `argv`, `envp`, and the ELF auxiliary vector) is constructed inside a fresh virtual
//! address space ([`Mm`](crate::memory::vm::Mm)) while the caller's existing address space is
//! still active. Consequently, any failure prior to the commit point (missing file, bad ELF
//! header, out of memory, `E2BIG`) cleanly returns an error code to the calling process just
//! like Linux. Once committed, peer threads in the thread group are terminated, `O_CLOEXEC`
//! files are closed, `CR3` is switched to the new page table, and the [`SyscallFrame`] is
//! rewritten to enter the new program's entry point in Ring 3.
//!
//! ## Key Types & Interfaces
//! - [`sys_execve()`]: Unified system call handler for both `execve(2)` and `execveat(2)`.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel syscall context preparing Ring 3 transition)
//! - Hardware Interaction: Reloads `CR3` (Page Directory Base Register), clears `IA32_FS_BASE`
//!   MSR (`0xC000_0100`), and resets x87/SSE [`FpuState`].
//! - Concurrency: Acquires [`SCHEDULER`](crate::task::SCHEDULER) lock during the commit phase
//!   to atomically terminate sibling threads and swap the task's `Mm`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::vfs::{base_dir, creds, join_path, may_access, proc_root, resolve, user_cstr};
use crate::arch::idt::FpuState;
use crate::arch::syscall::SyscallFrame;
use crate::fs::zfs::types::{S_IFMT, S_IFREG};
use crate::fs::ZfsClient;

/// Negative errno for file or interpreter not found.
const ENOENT: i64 = -2;
/// Negative errno for argument and environment list exceeding [`ARG_MAX`].
const E2BIG: i64 = -7;
/// Negative errno for invalid ELF format or unsupported binary architecture.
const ENOEXEC: i64 = -8;
/// Negative errno for insufficient memory when building the new address space.
const ENOMEM: i64 = -12;
/// Negative errno for permission denied or non-regular file target.
const EACCES: i64 = -13;
/// Negative errno for invalid userland pointer in path, `argv`, or `envp`.
const EFAULT: i64 = -14;
/// Negative errno for too many nested `#!` interpreter scripts or symbolic links.
const ELOOP: i64 = -40;

/// `execveat` flag: execute the file descriptor `dirfd` itself when `pathname` is empty.
const AT_EMPTY_PATH: u64 = 0x1000;
/// `execveat` flag: do not dereference the terminal symbolic link component.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

/// Maximum combined byte length of argument and environment strings accepted (Linux's `ARG_MAX` default: 2 MiB).
const ARG_MAX: usize = 2 * 1024 * 1024;

/// Reads a `NULL`-terminated array of `NUL`-terminated C string pointers (`argv` or `envp`)
/// from the calling process's user memory.
///
/// # Arguments
/// * `ptr` - User virtual address of the `const char *const *` array (0 is treated as empty).
/// * `total` - Running byte counter across `argv` and `envp`; checked against [`ARG_MAX`].
///
/// # Returns
/// * `Ok(Vec<Vec<u8>>)` containing each copied byte string (excluding trailing `NUL`).
/// * `Err(EFAULT)` if any pointer slot or string resides in unmapped user memory.
/// * `Err(E2BIG)` if `*total` exceeds [`ARG_MAX`].
fn read_string_array(ptr: u64, total: &mut usize) -> Result<Vec<Vec<u8>>, i64> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    for i in 0.. {
        let slot = ptr + i * 8;
        if !crate::memory::vm::prefault_current(slot, 8, false) {
            return Err(EFAULT);
        }
        let p = unsafe { *(slot as *const u64) };
        if p == 0 {
            break;
        }
        let s = user_cstr(p)?;
        *total += s.len() + 1;
        if *total > ARG_MAX {
            return Err(E2BIG);
        }
        out.push(s);
    }
    Ok(out)
}

/// Parses a `#!interpreter [optional-arg]` shebang line from the beginning of an executable file.
///
/// # Arguments
/// * `data` - Initial bytes of the executable file.
///
/// # Returns
/// * `Some((interpreter_path, optional_single_arg))` if `data` begins with `#!` followed by a non-empty path.
/// * `None` if `data` does not start with `#!` or the interpreter path is empty.
fn parse_shebang(data: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    if !data.starts_with(b"#!") {
        return None;
    }
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len()).min(256);
    let line = &data[2..end];
    let line: Vec<u8> = line.iter().copied().skip_while(|b| *b == b' ' || *b == b'\t').collect();
    let line = {
        let mut l = line;
        while matches!(l.last(), Some(b' ' | b'\t' | b'\r')) {
            l.pop();
        }
        l
    };
    if line.is_empty() {
        return None;
    }
    match line.iter().position(|&b| b == b' ' || b == b'\t') {
        Some(i) => {
            let arg: Vec<u8> = line[i..].iter().copied().skip_while(|b| *b == b' ' || *b == b'\t').collect();
            Some((line[..i].to_vec(), if arg.is_empty() { None } else { Some(arg) }))
        }
        None => Some((line, None)),
    }
}

/// Converts a raw byte slice into a UTF-8 [`String`], replacing invalid sequences with U+FFFD.
fn lossy(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// Executes a new program image in the current process (`execve(2)` and `execveat(2)`).
///
/// Resolves `path_ptr` relative to `dirfd`, expands up to 4 levels of `#!` shebang scripts,
/// maps the target ELF binary and optional dynamic linker into a new [`Mm`](crate::memory::vm::Mm),
/// and—once past the point of no return—switches `CR3`, resets signal handlers and `CLOEXEC`
/// descriptors, and updates `frame` so `SYSRET` jumps directly to the new entry point.
///
/// # Arguments
/// * `frame` - Mutable reference to the saved [`SyscallFrame`] on the kernel stack.
/// * `fpu` - Pointer to the saved [`FpuState`] to reinitialize on commit (may be null).
/// * `dirfd` - Directory file descriptor for relative paths (`-100` / `AT_FDCWD` for `execve`).
/// * `path_ptr` - User virtual address of the `NUL`-terminated path string.
/// * `argv_ptr` - User virtual address of the `NULL`-terminated argument string array.
/// * `envp_ptr` - User virtual address of the `NULL`-terminated environment string array.
/// * `flags` - `execveat` flags (`AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW`).
///
/// # Returns
/// * `0` on success (with `frame.rip` and `frame.rsp` updated to the new image's entry and stack).
/// * Negative errno (`-ENOENT`, `-EACCES`, `-ENOEXEC`, `-ENOMEM`, `-E2BIG`, `-EFAULT`, `-ELOOP`) on failure.
pub fn sys_execve(frame: &mut SyscallFrame, fpu: *mut FpuState, dirfd: i64, path_ptr: u64, argv_ptr: u64, envp_ptr: u64, flags: u64) -> i64 {
    let mut path = match user_cstr(path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut total = 0;
    let mut argv = match read_string_array(argv_ptr, &mut total) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let envp = match read_string_array(envp_ptr, &mut total) {
        Ok(e) => e,
        Err(e) => return e,
    };

    let c = creds();
    let mut abs_path;
    let mut follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let mut dirfd = dirfd;
    let mut depth = 0;
    let image = loop {
        let ino = if path.is_empty() {
            if flags & AT_EMPTY_PATH == 0 {
                return ENOENT;
            }
            let (ino, p) = match base_dir(dirfd, b"x") {
                Ok(b) => b,
                Err(e) => return e,
            };
            abs_path = p;
            ino
        } else {
            let (base, base_path) = match base_dir(dirfd, &path) {
                Ok(b) => b,
                Err(e) => return e,
            };
            abs_path = join_path(&base_path, &path);
            // /proc/self/exe and friends name the file they link to
            if let Some(target) = super::fs::proc_link(&abs_path) {
                abs_path = target.clone();
                path = target.into_bytes();
            }
            match resolve(base, &path, follow) {
                Ok(i) => i,
                Err(e) => return e,
            }
        };
        let attr = match ZfsClient::getattr(ino) {
            Ok(a) => a,
            Err(e) => return e,
        };
        if attr.mode & S_IFMT != S_IFREG || !may_access(&attr, c.euid, c.egid, 1) || attr.mode & 0o111 == 0 {
            return EACCES;
        }
        let source = match super::mm::inode_source(ino) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let data = &source.head;

        if let Some((interp, arg)) = parse_shebang(data) {
            depth += 1;
            if depth > 4 {
                return ELOOP;
            }
            // argv becomes: interpreter [arg] script original-argv[1..]
            let script = if path.is_empty() { abs_path.clone().into_bytes() } else { path.clone() };
            let mut new_argv = alloc::vec![interp.clone()];
            if let Some(a) = arg {
                new_argv.push(a);
            }
            new_argv.push(script);
            new_argv.extend(argv.iter().skip(1).cloned());
            argv = new_argv;
            path = interp;
            dirfd = -100; // AT_FDCWD: interpreters are resolved normally
            follow = true;
            continue;
        }

        if crate::task::elf::ElfBinary::parse(data).is_err() {
            return ENOEXEC;
        }
        if !crate::task::exec::is_vm_loadable(data) {
            return ENOEXEC;
        }

        let root = proc_root();
        let read_in_root = |p: &str| -> Option<crate::task::exec::ElfSource> {
            let ino = ZfsClient::resolve_in(root, 0, p.as_bytes(), true).ok()?;
            super::mm::inode_source(ino).ok()
        };
        let argv_s: Vec<String> = argv.iter().map(|a| lossy(a)).collect();
        let envp_s: Vec<String> = envp.iter().map(|e| lossy(e)).collect();
        let argv_r: Vec<&str> = argv_s.iter().map(|s| s.as_str()).collect();
        let envp_r: Vec<&str> = envp_s.iter().map(|s| s.as_str()).collect();
        match crate::task::exec::load_linux_exec(
            source,
            &abs_path,
            &argv_r,
            &envp_r,
            crate::task::exec::ExecCreds { uid: c.euid, gid: c.egid },
            &read_in_root,
        ) {
            Ok(img) => break img,
            Err(crate::task::elf::ElfError::InterpreterNotFound) => return ENOENT,
            Err(crate::task::elf::ElfError::AllocationFailed) => return ENOMEM,
            Err(_) => return ENOEXEC,
        }
    };

    // ---- Point of no return ----
    let (_, pid) = super::proc::current_ids();
    let new_mm = Arc::new(Mutex::new(image.mm));
    let cr3 = new_mm.lock().cr3();
    let exe: Arc<str> = Arc::from(abs_path.as_str());
    let old_mm = {
        let mut sched = crate::task::SCHEDULER.lock();
        sched.terminate_current_group();
        sched.current_task_mut(|t| {
            t.regs.cr3 = cr3;
            t.exe = Some(exe);
            t.fs_base = 0;
            t.clear_child_tid = 0;
            // The new image gets a descriptor table of its own (as Linux's unshare_files)
            if alloc::sync::Arc::strong_count(&t.fds) > 1 {
                let copy = t.fds.lock().fork_copy();
                t.fds = copy.into_shared();
            }
            t.fds.lock().close_on_exec();
            core::mem::replace(&mut t.mm, Some(new_mm.clone()))
        })
        .flatten()
    };
    unsafe {
        x86_64::registers::control::Cr3::write(
            x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(cr3)),
            x86_64::registers::control::Cr3Flags::empty(),
        );
        crate::arch::syscall::wrmsr(0xC000_0100, 0);
    }
    crate::memory::vm::set_current_mm(Some(&new_mm));
    // The old address space is no longer loaded; release it (unless a vfork parent shares it)
    drop(old_mm);
    super::proc::exec_reset(pid);

    if !fpu.is_null() {
        unsafe { *fpu = FpuState::new() };
    }
    frame.rip = image.entry;
    frame.rsp = image.rsp;
    frame.rflags = 0x202;
    frame.rdi = 0;
    frame.rsi = 0;
    frame.rdx = 0;
    frame.r8 = 0;
    frame.r9 = 0;
    frame.r10 = 0;
    frame.r12 = 0;
    frame.r13 = 0;
    frame.r14 = 0;
    frame.r15 = 0;
    frame.rbp = 0;
    frame.rbx = 0;
    0
}
