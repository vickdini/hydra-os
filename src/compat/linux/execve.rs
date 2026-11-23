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

/// The absolute path `abs` with every symlink in it resolved and `.`/`..` removed, as
/// Linux shows a program's path in `/proc/<pid>/exe` (`/usr/bin/firefox`, a link to
/// `../lib/firefox/firefox`, runs as `/usr/lib/firefox/firefox`).
///
/// # Returns
/// `None` when `abs` has no symlink in it, or when the walk does not end at `ino` (the file
/// being run): the lexical path is kept then.
fn real_path(abs: &str, ino: u64) -> Option<String> {
    if !abs.starts_with('/') || super::vfs::served_by_name(abs) {
        return None;
    }
    let root = resolve(0, b"/", true).ok()?;
    // Components still to walk, the last one on top
    let mut todo: Vec<Vec<u8>> = abs.split('/').rev().filter(|c| !c.is_empty()).map(|c| c.as_bytes().to_vec()).collect();
    // The canonical path so far, with the inode of each component
    let mut out: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut links = 0;
    while let Some(c) = todo.pop() {
        match c.as_slice() {
            b"." => continue,
            b".." => {
                out.pop();
                continue;
            }
            _ => {}
        }
        let dir = out.last().map_or(root, |&(_, i)| i);
        let next = resolve(dir, &c, false).ok()?;
        if ZfsClient::getattr(next).ok()?.mode & S_IFMT == super::types::S_IFLNK {
            links += 1;
            if links > 40 {
                return None;
            }
            let target = ZfsClient::readlink(next).ok()?;
            if target.first() == Some(&b'/') {
                out.clear();
            }
            todo.extend(target.split(|&b| b == b'/').rev().filter(|c| !c.is_empty()).map(|c| c.to_vec()));
            continue;
        }
        out.push((c, next));
    }
    if links == 0 || out.last().map(|&(_, i)| i) != Some(ino) {
        return None;
    }
    let mut p = String::new();
    for (name, _) in &out {
        p.push('/');
        p.push_str(&String::from_utf8_lossy(name));
    }
    Some(p)
}

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
///
/// # Arguments
///
/// * `v` - Byte slice to convert.
///
/// # Returns
///
/// An owned UTF-8 string with lossy replacements for invalid sequences.
fn lossy(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// One file of the chain `execve` runs (the program, or a `#!` script on the way): its
/// attributes and bytes, and what running it would grant.
struct Level {
    /// Its head and object.
    source: crate::task::exec::ElfSource,
    /// Set-user-ID / set-group-ID owner (never applied for a script).
    set_uid: Option<u32>,
    /// See [`Level::set_uid`].
    set_gid: Option<u32>,
    /// File capabilities `(permitted, effective)`.
    file_caps: Option<(u64, bool)>,
    /// The effective bit of the file capabilities (secure mode even if not granted).
    caps_secure: bool,
}

/// The checks and the bytes of file `ino`, run as `abs_path` (`follow`: how its last
/// component was looked up, for Landlock): regular, executable for the caller, allowed by
/// app control, Landlock and fanotify, then the set-ID bits and file capabilities as
/// `nosuid`, tracing, `no_new_privs` and user namespaces leave them.
fn level(ino: u64, abs_path: &str, follow: bool) -> Result<Level, i64> {
    let c = creds();
    let attr = ZfsClient::getattr(ino)?;
    if attr.mode & S_IFMT != S_IFREG || !may_access(&attr, c.euid, c.egid, 1) || attr.mode & 0o111 == 0 {
        super::abac::note_path(ino, abs_path);
        return Err(EACCES);
    }
    // App control (access policies): may this user run this program?
    {
        let dir = abs_path.rsplit_once('/').map(|(d, _)| if d.is_empty() { String::from("/") } else { String::from(d) });
        let mut parent = || dir.as_ref().and_then(|d| resolve(0, d.as_bytes(), true).ok()).and_then(|i| ZfsClient::getattr(i).ok());
        if !super::abac::exec_check(abs_path, &attr, &mut parent) {
            return Err(EACCES);
        }
    }
    if super::landlock::check_at(abs_path, ino, false, follow, super::landlock::EXECUTE).is_err() {
        return Err(EACCES);
    }
    // fanotify: FAN_OPEN_EXEC_PERM (a listener may refuse), FAN_OPEN_EXEC
    if super::fanotify::active() {
        let dir = super::fanotify::parent_of_path(abs_path);
        super::fanotify::on_open(ino, dir, abs_path, false, true)?;
    }
    let source = super::mm::inode_source(ino)?;
    let mut set_uid = (attr.mode & 0o4000 != 0).then_some(attr.uid);
    // File capabilities (security.capability) of the program that will run; with the
    // effective bit the program runs in secure mode even if they are not granted
    let mut file_caps = super::vfs::file_caps(ino);
    let caps_secure = file_caps.is_some_and(|(_, e)| e);
    let mut set_gid = (attr.mode & 0o2010 == 0o2010).then_some(attr.gid);
    // A noexec mount refuses to run anything; a nosuid one ignores the set-ID bits
    let (noexec, nosuid) = super::mount::exec_flags();
    if noexec {
        return Err(EACCES);
    }
    let traced = super::ptrace::is_traced(super::proc::current_ids().0);
    if nosuid || traced || crate::task::with_current_task_mut(|t| t.seccomp.no_new_privs || t.caps.in_userns).unwrap_or(false) {
        // no_new_privs, or a user namespace (the owner, root, is not mapped in it):
        // set-user/group-ID bits are ignored
        set_uid = None;
        set_gid = None;
        file_caps = None;
    }
    Ok(Level { source, set_uid, set_gid, file_caps, caps_secure })
}

/// A new image, built and not yet committed.
struct Ready {
    image: crate::task::exec::LinuxExecImage,
    abs_path: String,
    argv: Vec<Vec<u8>>,
    set_uid: Option<u32>,
    set_gid: Option<u32>,
    file_caps: Option<(u64, bool)>,
    via_script: bool,
}

/// Loads the program of `lv` (shown as `abs_path`) into a new address space (`task_exec`'s
/// loading part). `interp`: the ELF interpreter linux-server looked up (`(path, ino)`, ino 0:
/// not found); any other interpreter path is looked up here.
fn load(lv: Level, abs_path: String, argv: Vec<Vec<u8>>, envp: &[Vec<u8>], via_script: bool, interp: Option<(String, u64)>) -> Result<Ready, i64> {
    let c = creds();
    let data = &lv.source.head;
    // The personality the program runs with: FreeBSD and Mach-O programs, and ELF files
    // of other systems, are refused until a front end exists (crate::personality)
    let pers = crate::personality::choose(data, &abs_path)?;
    // A seccomp filter judges Linux system call numbers: it cannot follow a program
    // into another personality
    if pers != crate::task::TaskPersonality::Linux && crate::task::with_current_task_mut(|t| t.seccomp.mode != 0).unwrap_or(false) {
        crate::kprintln!("[exec] {}: a seccomp filter is installed: refused, ENOEXEC", abs_path);
        return Err(ENOEXEC);
    }
    if crate::task::elf::ElfBinary::parse(data).is_err() {
        return Err(ENOEXEC);
    }
    if !crate::task::exec::is_vm_loadable(data) {
        return Err(ENOEXEC);
    }

    let root = proc_root();
    // Landlock refusing EXECUTE on the dynamic loader fails the exec with EACCES
    let interp_refused = core::cell::Cell::new(false);
    let read_in_root = |p: &str| -> Option<crate::task::exec::ElfSource> {
        if root == super::vfs::EMPTY_ROOT {
            return None;
        }
        // wave7 G7-5: the interpreter linux-server found (vfs-server's walk); 0: not found
        let ino = match interp.as_ref().filter(|(ip, _)| ip == p) {
            Some(&(_, 0)) => return None,
            Some(&(_, i)) => i,
            // Through the mount table in a mount namespace of its own (a sandbox's /usr)
            None => match super::mount::resolve(0, p.as_bytes(), true) {
                Some(r) => r.ok()?,
                None => ZfsClient::resolve_in(root, 0, p.as_bytes(), true).ok()?,
            },
        };
        if super::landlock::check_at(p, ino, false, true, super::landlock::EXECUTE).is_err() {
            interp_refused.set(true);
            return None;
        }
        // wave7 G7-5: the interpreter must be a regular file the caller may execute (Linux's
        // open_exec): EACCES otherwise
        let a = ZfsClient::getattr(ino).ok()?;
        if a.mode & S_IFMT != S_IFREG || !may_access(&a, c.euid, c.egid, 1) || a.mode & 0o111 == 0 {
            interp_refused.set(true);
            return None;
        }
        super::mm::inode_source(ino).ok()
    };
    let argv_s: Vec<String> = argv.iter().map(|a| lossy(a)).collect();
    let envp_s: Vec<String> = envp.iter().map(|e| lossy(e)).collect();
    let argv_r: Vec<&str> = argv_s.iter().map(|s| s.as_str()).collect();
    let envp_r: Vec<&str> = envp_s.iter().map(|s| s.as_str()).collect();
    let image = match crate::task::exec::load_linux_exec(
        lv.source,
        pers,
        &abs_path,
        &argv_r,
        &envp_r,
        crate::task::exec::ExecCreds {
            uid: c.uid,
            gid: c.gid,
            euid: if via_script { c.euid } else { lv.set_uid.unwrap_or(c.euid) },
            egid: if via_script { c.egid } else { lv.set_gid.unwrap_or(c.egid) },
            secure: (lv.caps_secure || lv.file_caps.is_some_and(|(p, _)| p != 0)) && c.euid != 0,
        },
        &read_in_root,
    ) {
        Ok(img) => img,
        Err(crate::task::elf::ElfError::InterpreterNotFound) => return Err(if interp_refused.get() { EACCES } else { ENOENT }),
        Err(crate::task::elf::ElfError::AllocationFailed) => return Err(ENOMEM),
        Err(_) => return Err(ENOEXEC),
    };
    Ok(Ready { image, abs_path, argv, set_uid: lv.set_uid, set_gid: lv.set_gid, file_caps: lv.file_caps, via_script })
}

/// wave7 G7-5: plans of programs that would gain privileges, handed to the kernel's own
/// front half ([`from_plan`]).
pub static PRIVILEGED_TO_KERNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// wave7 G7-5: the front half by the services (`crate::lx::xexec`): linux-server and
/// vfs-server looked up the program, its `#!` interpreters and its ELF interpreter; here the
/// same checks as for the kernel's own lookup, then the load. `None`: the kernel's own front
/// half runs instead (the file turned into a script meanwhile).
fn from_plan(plan: crate::lx::xexec::ExecPlan, argv: &[Vec<u8>], envp: &[Vec<u8>], flags: u64) -> Option<Result<Ready, i64>> {
    // (checks only the kernel's own lookup makes at every `#!` level: Landlock, fanotify, app
    // control; such callers get no plan, but the rules may have come meanwhile)
    // (wave9 G6b-3: and app rules alone: a policy without file rules still controls apps)
    if super::landlock::active() || super::fanotify::active() || super::abac::active() || super::abac::apps_active() {
        return None;
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0 || !plan.prefix.is_empty();
    let lv = match level(plan.ino, &plan.shown, follow) {
        Ok(l) => l,
        Err(e) => return Some(Err(e)),
    };
    if parse_shebang(&lv.source.head).is_some() {
        return None;
    }
    // A program that would gain privileges (set-user/group-ID, file capabilities): the kernel
    // looks it up itself, so the services' plan never decides which file or interpreter runs
    // with them (rare: su, sudo, passwd, ping; the plan costs the same lookup again)
    if lv.set_uid.is_some() || lv.set_gid.is_some() || lv.file_caps.is_some() {
        PRIVILEGED_TO_KERNEL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return None;
    }
    let via_script = !plan.prefix.is_empty();
    let argv: Vec<Vec<u8>> = if via_script { plan.prefix.iter().cloned().chain(argv.iter().skip(1).cloned()).collect() } else { argv.to_vec() };
    Some(load(lv, plan.shown, argv, envp, via_script, plan.interp))
}

/// Executes a new program image in the current process (`execve(2)` and `execveat(2)`).
///
/// Resolves `path_ptr` relative to `dirfd`, expands up to 4 levels of `#!` shebang scripts,
/// maps the target ELF binary and optional dynamic linker into a new [`Mm`](crate::memory::vm::Mm),
/// and—once past the point of no return—switches `CR3`, resets signal handlers and `CLOEXEC`
/// descriptors, and updates `frame` so `SYSRET` jumps directly to the new entry point.
///
/// wave7 G7-5: the lookup of the files (the front half) is linux-server's and vfs-server's
/// when they can do it for this caller ([`crate::lx::xexec::front`]); otherwise, and with
/// `lx=kernel` / `lx.vfs=kernel`, the kernel's own ([`front_kernel`]).
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
    let path = match user_cstr(path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut total = 0;
    let argv = match read_string_array(argv_ptr, &mut total) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let envp = match read_string_array(envp_ptr, &mut total) {
        Ok(e) => e,
        Err(e) => return e,
    };
    // wave7 G7-5 begin: the front half by the services
    if !path.is_empty() {
        if let Some(plan) = crate::lx::xexec::front(dirfd, &path, flags) {
            let r = match plan {
                Ok(p) => from_plan(p, &argv, &envp, flags),
                Err(e) => Some(Err(e)),
            };
            match r {
                Some(Ok(ready)) => return commit(frame, fpu, ready),
                Some(Err(e)) => return e,
                None => {}
            }
        }
    }
    // wave7 G7-5 end
    match front_kernel(dirfd, path, argv, &envp, flags) {
        Ok(ready) => commit(frame, fpu, ready),
        Err(e) => e,
    }
}

/// The kernel's own front half: resolves the program (and `#!` interpreters) itself, then
/// [`level`] and [`load`].
fn front_kernel(dirfd: i64, mut path: Vec<u8>, mut argv: Vec<Vec<u8>>, envp: &[Vec<u8>], flags: u64) -> Result<Ready, i64> {
    let mut abs_path;
    let mut follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let mut via_script = false;
    let mut dirfd = dirfd;
    let mut depth = 0;
    loop {
        let ino = if path.is_empty() {
            if flags & AT_EMPTY_PATH == 0 {
                return Err(ENOENT);
            }
            let (ino, p) = base_dir(dirfd, b"x")?;
            abs_path = p;
            ino
        } else {
            let (base, base_path) = base_dir(dirfd, &path)?;
            abs_path = join_path(&base_path, &path);
            // /proc/self/exe and friends name the file they link to
            if let Some(target) = super::fs::proc_link(&abs_path) {
                // (a link: AT_SYMLINK_NOFOLLOW does not follow it, wave7 G7-5)
                if !follow {
                    return Err(ELOOP);
                }
                abs_path = target.clone();
                path = target.into_bytes();
            }
            let ino = resolve(base, &path, follow)?;
            // wave7 G7-5: execveat(AT_SYMLINK_NOFOLLOW) of a symbolic link is ELOOP (Linux's
            // open_exec; it was EACCES, from the type check in `level`)
            if !follow && ZfsClient::getattr(ino)?.mode & S_IFMT == super::types::S_IFLNK {
                return Err(ELOOP);
            }
            // Linux's /proc/self/exe names the file itself, every symlink resolved: Firefox's
            // launcher execs firefox-bin from the directory /proc/self/exe names
            if let Some(real) = real_path(&abs_path, ino) {
                abs_path = real;
            }
            ino
        };
        let lv = level(ino, &abs_path, follow)?;
        if let Some((interp, arg)) = parse_shebang(&lv.source.head) {
            via_script = true;
            depth += 1;
            if depth > 4 {
                return Err(ELOOP);
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
        return load(lv, abs_path, argv, envp, via_script, None);
    }
}

/// The point of no return: the new image `r` replaces the caller's (`task_exec`'s commit).
fn commit(frame: &mut SyscallFrame, fpu: *mut FpuState, r: Ready) -> i64 {
    let Ready { image, abs_path, argv, set_uid, set_gid, file_caps, via_script } = r;
    // ---- Point of no return ----
    // Robust mutexes the old image holds are released as at exit (Linux's
    // futex_exec_release), while it is still mapped
    super::futex::exit_robust_list_current();
    let (_, pid) = super::proc::current_ids();
    let new_mm = Arc::new(Mutex::new(image.mm));
    let cr3 = new_mm.lock().cr3();
    let exe: Arc<str> = Arc::from(abs_path.as_str());
    let cmdline = crate::task::Task::join_cmdline(argv.iter().map(|a| a.as_slice()));
    // The old program's LDT, dropped once the scheduler lock is released
    let mut old_ldt = None;
    let old_mm = {
        let mut sched = crate::task::SCHEDULER.lock();
        sched.terminate_current_group();
        sched.current_task_mut(|t| {
            t.regs.cr3 = cr3;
            // The new program's personality (a FreeBSD program may exec a Linux one, and back)
            t.personality = image.pers;
            crate::personality::set_current(image.pers);
            t.exe = Some(exe);
            t.cmdline = Some(cmdline);
            t.fs_base = 0;
            t.segs = Default::default();
            // In the CPU too: null selectors and bases, no TLS descriptors, no LDT
            x86_64::instructions::interrupts::without_interrupts(crate::arch::segments::reset_current);
            old_ldt = t.ldt.take();
            // A set-ID program runs with the file's owner (group) as its effective and
            // saved id; capabilities follow the new effective user
            if !via_script {
                if let Some(u) = set_uid {
                    t.euid = u;
                    t.suid = u;
                }
                if let Some(g) = set_gid {
                    t.egid = g;
                    t.sgid = g;
                }
            }
            let (uid, euid) = (t.uid, t.euid);
            t.caps.on_exec(uid, euid);
            // File capabilities: permitted = the file's permitted set (every capability is
            // in the bounding set); effective = all of them if the file's effective bit is
            // set. Root already holds everything.
            if let Some((fp, fe)) = file_caps {
                if euid != 0 {
                    t.caps.permitted |= fp & crate::task::tcb::Caps::FULL;
                    if fe {
                        t.caps.effective = t.caps.permitted;
                    }
                }
            }
            t.clear_child_tid = 0;
            t.robust_list = 0;
            // The new image gets a descriptor table of its own (as Linux's unshare_files)
            if alloc::sync::Arc::strong_count(&t.fds) > 1 {
                let copy = t.fds.lock().fork_copy();
                t.fds = copy.into_shared();
            }
            core::mem::replace(&mut t.mm, Some(new_mm.clone()))
        })
        .flatten()
    };
    unsafe {
        crate::arch::syscall::wrmsr(0xC000_0100, 0);
    }
    crate::arch::pcid::load_cr3(cr3);
    // This CPU has the new address space loaded (no other CPU may run it meanwhile)
    crate::task::SCHEDULER.lock().note_loaded_cr3(cr3);
    crate::memory::vm::set_current_mm(Some(&new_mm));
    // Close-on-exec descriptors close outside the scheduler lock: releasing a file is a
    // request to the file server
    crate::task::with_current_fds_mut(|fds| fds.close_on_exec());
    // The thread and process keyrings do not survive exec
    let (tid, tgid) = super::proc::current_ids();
    super::keys::on_exec(tid, tgid);
    crate::lx::note(crate::ipc::protocol::LX_NOTE_EXEC, tid, tgid, 0);
    super::limits::on_exec(tgid);
    super::ptrace::on_exec(tgid, tid);
    super::perf::on_exec(tgid);
    super::admin::note_exec(tgid);
    // Hardware breakpoints do not survive exec
    if crate::task::with_current_task_mut(|t| core::mem::take(&mut t.debugregs)[7] != 0).unwrap_or(false) {
        crate::arch::debugregs::switch_to(&[0; 8]);
    }
    // The old address space is no longer loaded; release it (unless a vfork parent shares it)
    drop(old_mm);
    super::proc::exec_reset(pid);

    if !fpu.is_null() {
        unsafe { *fpu = FpuState::new() };
    }
    frame.rip = image.entry;
    frame.rsp = image.rsp;
    frame.rflags = 0x202;
    // (FreeBSD: the address of argc)
    frame.rdi = image.rdi;
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
