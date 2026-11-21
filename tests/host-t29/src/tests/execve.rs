//! `src/compat/linux/execve.rs`: path and argument handling, permission checks, `#!`
//! scripts, set-user/group-ID and file capabilities, the personality and loader checks, the
//! commit to the new image, and `/proc/self/exe`'s resolved path.

use super::common::elf::*;
use super::common::*;
use crate::arch::idt::FpuState;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::execve::sys_execve;
use crate::fs::{FileDescriptor, OpenFile};
use std::sync::Arc;

const ENOENT: i64 = -2;
const E2BIG: i64 = -7;
const ENOEXEC: i64 = -8;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const ELOOP: i64 = -40;
const AT_FDCWD: i64 = -100;
const AT_EMPTY_PATH: u64 = 0x1000;

/// A static executable: one read+execute segment at 0x400000, entry 0x400100.
fn program() -> Vec<u8> {
    Elf::new(ET_EXEC, 0x40_0100, &[load_with(5, 0, 0x40_0000, 0x200, 0x200)], 0x200).bytes
}

/// Puts a file at `path` (inode `ino`, `mode`, contents).
fn file(path: &str, ino: u64, mode: u32, data: Vec<u8>) {
    fake::INODES.with_borrow_mut(|m| m.insert(ino, (mode, data)));
    fake::INODE_PATHS.with_borrow_mut(|m| m.insert(path.to_string(), ino));
}

fn owner(ino: u64, uid: u32, gid: u32) {
    fake::INODE_OWNERS.with_borrow_mut(|m| m.insert(ino, (uid, gid)));
}

/// A NUL-terminated copy of `s` and pointer arrays for `argv`/`envp` (kept alive by the
/// returned holder).
struct Args {
    _strings: Vec<Vec<u8>>,
    ptrs: Vec<u64>,
}

fn args(list: &[&str]) -> Args {
    let strings: Vec<Vec<u8>> = list.iter().map(|s| format!("{s}\0").into_bytes()).collect();
    let mut ptrs: Vec<u64> = strings.iter().map(|s| s.as_ptr() as u64).collect();
    ptrs.push(0);
    Args { _strings: strings, ptrs }
}

impl Args {
    fn ptr(&self) -> u64 {
        self.ptrs.as_ptr() as u64
    }
}

fn cstr(s: &str) -> Vec<u8> {
    format!("{s}\0").into_bytes()
}

/// Runs execve as the current task; afterwards no address space stays loaded (the new one
/// is the task's).
fn exec(path: &str, argv: &[&str], envp: &[&str]) -> (i64, SyscallFrame) {
    let p = cstr(path);
    let a = args(argv);
    let e = args(envp);
    let mut f = SyscallFrame { rax: 59, rip: 0x1234, rsp: 0x5678, rbx: 9, ..Default::default() };
    let mut fpu = FpuState::new();
    fpu.0[0] = 0;
    let r = sys_execve(&mut f, &mut fpu, AT_FDCWD, p.as_ptr() as u64, a.ptr(), e.ptr(), 0);
    crate::memory::vm::set_current_mm(None);
    (r, f)
}

fn proc_(pid: u64, uid: u32) {
    global_frames();
    spawn_as(pid, 1, uid, uid);
    run(pid);
}

fn cmdline(pid: u64) -> Vec<u8> {
    fake::task(pid, |t| t.cmdline.as_deref().map(|c| c.to_vec())).flatten().unwrap_or_default()
}

#[test]
fn a_successful_exec_replaces_the_image() {
    let _g = setup();
    proc_(1100, 1000);
    file("/bin/prog", 50, 0o100755, program());
    // State the old image had
    fake::task(1100, |t| {
        t.fs_base = 0x1234;
        t.robust_list = 0;
        t.debugregs[7] = 1;
        t.caps.effective = 0xff;
        t.caps.permitted = 0xff;
    });
    crate::task::with_current_fds_mut(|f| {
        f.install(3, FileDescriptor::ConsoleOut);
        f.install(4, FileDescriptor::ConsoleOut);
        f.set_cloexec(4, true);
    });
    let old_fds = fake::task(1100, |t| Arc::as_ptr(&t.fds) as usize).unwrap();
    add_thread(1100, 1101); // de-threaded by the exec
    let (r, f) = exec("/bin/prog", &["prog", "a"], &["X=1"]);
    assert_eq!(r, 0);
    assert_eq!((f.rip, f.rflags, f.rbx), (0x40_0100, 0x202, 0));
    assert!(f.rsp > 0x40_0000 && f.rsp < crate::memory::vm::USER_SPACE_END && f.rsp % 16 == 0);
    let (exe, fs_base, dr7, caps, mm) = fake::task(1100, |t| (t.exe.clone(), t.fs_base, t.debugregs[7], t.caps, t.mm.is_some())).unwrap();
    assert_eq!(exe.as_deref(), Some("/bin/prog"));
    assert_eq!(cmdline(1100), b"prog\0a\0");
    assert_eq!((fs_base, dr7), (0, 0));
    assert_eq!((caps.effective, caps.permitted), (0, 0), "a non-root program loses its capabilities");
    assert!(mm, "a new address space");
    assert_eq!(fake::task(1101, |t| t.state), Some(TaskState::Dead), "other threads are gone");
    // Close-on-exec descriptors closed, others kept; the table is now the process's own
    crate::task::with_current_fds_mut(|f| {
        assert!(f.get(3).is_some() && f.get(4).is_none());
    });
    assert_eq!(old_fds, fake::task(1100, |t| Arc::as_ptr(&t.fds) as usize).unwrap(), "an unshared table is kept");
    for c in [
        "terminate_current_group()",
        "segments::reset_current()",
        "personality::set_current(Linux)",
        "wrmsr(0xc0000100,0x0)",
        "load_cr3(",
        "note_loaded_cr3(",
        "keys::on_exec(1100,1100,)",
        "lx::note(",
        "perf::on_exec(1100,)",
        "admin::note_exec(1100,)",
        "debugregs::switch_to(0x0)",
    ] {
        assert!(fake::called(c), "{c}");
    }
}

#[test]
fn shared_descriptor_tables_are_copied() {
    let _g = setup();
    proc_(1105, 0);
    file("/bin/prog", 50, 0o100755, program());
    let shared = fake::task(1105, |t| t.fds.clone()).unwrap();
    let (r, _) = exec("/bin/prog", &["prog"], &[]);
    assert_eq!(r, 0);
    assert!(!Arc::ptr_eq(&shared, &fake::task(1105, |t| t.fds.clone()).unwrap()));
    assert_eq!(fake::task(1105, |t| t.caps.effective), Some((1 << 41) - 1), "root keeps everything");
}

#[test]
fn errors_before_the_point_of_no_return() {
    let _g = setup();
    proc_(1110, 1000);
    let mut f = SyscallFrame::default();
    assert_eq!(sys_execve(&mut f, std::ptr::null_mut(), AT_FDCWD, 0, 0, 0, 0), EFAULT);
    assert_eq!(exec("/bin/none", &["x"], &[]).0, ENOENT);
    // A directory, a file without execute permission, one the caller may not execute
    file("/bin", 51, 0o040755, vec![]);
    assert_eq!(exec("/bin", &[], &[]).0, EACCES);
    assert!(fake::called("abac::note_path(51,/bin)"));
    file("/bin/data", 52, 0o100644, program());
    assert_eq!(exec("/bin/data", &[], &[]).0, EACCES);
    file("/bin/rootonly", 53, 0o100700, program());
    assert_eq!(exec("/bin/rootonly", &[], &[]).0, EACCES);
    // Not an ELF file nor a script; an ELF the loader cannot place
    file("/bin/garbage", 54, 0o100755, b"MZ\x90\x00 not a program".to_vec());
    assert_eq!(exec("/bin/garbage", &[], &[]).0, ENOEXEC);
    let kernel = Elf::new(ET_EXEC, 0xFFFF_8000_0000_0100, &[load(0, 0xFFFF_8000_0000_0000, 0x100, 0x100)], 0x100).bytes;
    file("/bin/kernel", 55, 0o100755, kernel);
    assert_eq!(exec("/bin/kernel", &[], &[]).0, ENOEXEC);
    let mut broken = program();
    broken[18] = 3; // EM_386
    file("/bin/i386", 56, 0o100755, broken);
    assert_eq!(exec("/bin/i386", &[], &[]).0, ENOEXEC);
    // Access control and noexec mounts
    file("/bin/prog", 57, 0o100755, program());
    fake::set_ret("abac::exec_check", 1);
    assert_eq!(exec("/bin/prog", &[], &[]).0, EACCES);
    fake::set_ret("abac::exec_check", 0);
    fake::MOUNT_EXEC_FLAGS.set((true, false));
    assert_eq!(exec("/bin/prog", &[], &[]).0, EACCES, "noexec mount");
    fake::MOUNT_EXEC_FLAGS.set((false, false));
    // execveat with an empty path but no AT_EMPTY_PATH; a bad dirfd
    let empty = cstr("");
    assert_eq!(sys_execve(&mut f, std::ptr::null_mut(), AT_FDCWD, empty.as_ptr() as u64, 0, 0, 0), ENOENT);
    let rel = cstr("prog");
    assert_eq!(sys_execve(&mut f, std::ptr::null_mut(), 9, rel.as_ptr() as u64, 0, 0, 0), -9);
    assert_eq!(sys_execve(&mut f, std::ptr::null_mut(), 9, empty.as_ptr() as u64, 0, 0, AT_EMPTY_PATH), -9);
    // Arguments too long (ARG_MAX, 2 MiB)
    let long = "x".repeat(4000);
    let many: Vec<&str> = (0..600).map(|_| long.as_str()).collect();
    assert_eq!(exec("/bin/prog", &many, &[]).0, E2BIG);
    assert_eq!(exec("/bin/prog", &[], &many).0, E2BIG, "argv and envp count together");
    // A FreeBSD program under a seccomp filter
    let mut bsd = program();
    bsd[7] = 9; // ELFOSABI_FREEBSD
    file("/bin/bsd", 58, 0o100755, bsd);
    fake::task(1110, |t| t.seccomp.mode = 2);
    assert_eq!(exec("/bin/bsd", &[], &[]).0, ENOEXEC);
    assert!(fake::called("log:[exec] /bin/bsd: a seccomp filter is installed"));
    // A dynamic program whose interpreter is missing
    let dynamic = Elf::new(ET_DYN, 0x100, &[load_with(5, 0, 0, 0x200, 0x200), Ph { ty: PT_INTERP, flags: 4, offset: 0x180, vaddr: 0x180, filesz: 9, memsz: 9 }], 0x200)
        .put(0x180, b"/lib/ld\0\0")
        .bytes;
    file("/bin/dyn", 59, 0o100755, dynamic);
    fake::task(1110, |t| t.seccomp.mode = 0);
    assert_eq!(exec("/bin/dyn", &[], &[]).0, ENOENT);
}

#[test]
fn execveat_with_an_open_file() {
    let _g = setup();
    proc_(1115, 0);
    file("/bin/prog", 60, 0o100755, program());
    crate::task::with_current_fds_mut(|f| {
        f.install(5, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 60, path: "/bin/prog".into(), readable: true, ..Default::default() }))))
    });
    let empty = cstr("");
    let a = args(&["prog"]);
    let mut f = SyscallFrame::default();
    let r = sys_execve(&mut f, std::ptr::null_mut(), 5, empty.as_ptr() as u64, a.ptr(), 0, AT_EMPTY_PATH);
    crate::memory::vm::set_current_mm(None);
    assert_eq!(r, 0);
    assert_eq!(fake::task(1115, |t| t.exe.clone()).flatten().as_deref(), Some("/bin/prog"));
    // Relative to the working directory
    file("tool", 61, 0o100755, program());
    crate::task::with_current_fds_mut(|f| f.cwd_path = "/usr/bin".into());
    assert_eq!(exec("tool", &["tool"], &[]).0, 0);
    assert_eq!(fake::task(1115, |t| t.exe.clone()).flatten().as_deref(), Some("/usr/bin/tool"));
}

#[test]
fn scripts_run_through_their_interpreter() {
    let _g = setup();
    proc_(1120, 1000);
    file("/bin/sh", 70, 0o100755, program());
    file("/bin/script", 71, 0o100755, b"#!  /bin/sh   -e  \r\necho hi\n".to_vec());
    assert_eq!(exec("/bin/script", &["script", "a1"], &[]).0, 0);
    assert_eq!(cmdline(1120), b"/bin/sh\0-e\0/bin/script\0a1\0");
    assert_eq!(fake::task(1120, |t| t.exe.clone()).flatten().as_deref(), Some("/bin/sh"));
    // Without an argument
    file("/bin/plain", 72, 0o100755, b"#!/bin/sh".to_vec());
    assert_eq!(exec("/bin/plain", &["plain"], &[]).0, 0);
    assert_eq!(cmdline(1120), b"/bin/sh\0/bin/plain\0");
    // An empty interpreter line is no script: not an executable either
    file("/bin/empty", 73, 0o100755, b"#!   \n".to_vec());
    assert_eq!(exec("/bin/empty", &[], &[]).0, ENOEXEC);
    // A script whose interpreter is a script... more than 4 levels: ELOOP
    file("/bin/loop", 74, 0o100755, b"#!/bin/loop\n".to_vec());
    assert_eq!(exec("/bin/loop", &["loop"], &[]).0, ELOOP);
    // A missing interpreter
    file("/bin/lost", 75, 0o100755, b"#!/bin/nowhere\n".to_vec());
    assert_eq!(exec("/bin/lost", &[], &[]).0, ENOENT);
}

#[test]
fn set_user_and_group_id_programs() {
    let _g = setup();
    proc_(1130, 1000);
    file("/bin/su", 80, 0o104755, program());
    assert_eq!(exec("/bin/su", &["su"], &[]).0, 0);
    let ids = |pid| fake::task(pid, |t| (t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid, t.caps.effective)).unwrap();
    assert_eq!(ids(1130), (1000, 0, 0, 1000, 1000, 1000, (1 << 41) - 1), "runs as root, with root's capabilities");
    // set-group-ID (needs group execute too)
    proc_(1131, 1000);
    file("/bin/sg", 81, 0o102755, program());
    owner(81, 5, 50);
    assert_eq!(exec("/bin/sg", &["sg"], &[]).0, 0);
    assert_eq!(ids(1131).4, 50);
    file("/bin/sgnox", 82, 0o102745, program());
    owner(82, 5, 51);
    proc_(1132, 1000);
    assert_eq!(exec("/bin/sgnox", &["x"], &[]).0, 0);
    assert_eq!(ids(1132).4, 1000, "no group execute: no set-group-ID");
    // Ignored: under no_new_privs, a nosuid mount, a tracer, a user namespace, via a script
    proc_(1133, 1000);
    fake::task(1133, |t| t.seccomp.no_new_privs = true);
    assert_eq!(exec("/bin/su", &["su"], &[]).0, 0);
    assert_eq!(ids(1133).1, 1000);
    proc_(1134, 1000);
    fake::MOUNT_EXEC_FLAGS.set((false, true));
    assert_eq!(exec("/bin/su", &["su"], &[]).0, 0);
    assert_eq!(ids(1134).1, 1000);
    fake::MOUNT_EXEC_FLAGS.set((false, false));
    proc_(1135, 1000);
    spawn(1136, 1);
    run(1135);
    linux::ptrace::sys_ptrace(0, 0, 0, 0); // TRACEME: parent 1 traces it
    assert_eq!(exec("/bin/su", &["su"], &[]).0, 0);
    assert_eq!(ids(1135).1, 1000);
    proc_(1137, 1000);
    file("/bin/suscript", 83, 0o104755, b"#!/bin/sh\n".to_vec());
    file("/bin/sh", 84, 0o100755, program());
    assert_eq!(exec("/bin/suscript", &["s"], &[]).0, 0);
    assert_eq!(ids(1137).1, 1000, "a set-user-ID script runs as the caller");
}

#[test]
fn file_capabilities() {
    let _g = setup();
    proc_(1140, 1000);
    file("/bin/ping", 90, 0o100755, program());
    fake::FILE_CAPS.with_borrow_mut(|m| m.insert(90, (1 << 13, true)));
    assert_eq!(exec("/bin/ping", &["ping"], &[]).0, 0);
    assert_eq!(fake::task(1140, |t| (t.caps.permitted, t.caps.effective)), Some((1 << 13, 1 << 13)));
    // Without the effective bit: permitted only
    proc_(1141, 1000);
    fake::FILE_CAPS.with_borrow_mut(|m| m.insert(90, (1 << 12, false)));
    assert_eq!(exec("/bin/ping", &["ping"], &[]).0, 0);
    assert_eq!(fake::task(1141, |t| (t.caps.permitted, t.caps.effective)), Some((1 << 12, 0)));
}

#[test]
fn proc_self_exe_and_resolved_paths() {
    let _g = setup();
    proc_(1150, 0);
    // /usr/bin/firefox -> ../lib/ff/firefox: runs as /usr/lib/ff/firefox
    file("/", 1, 0o040755, vec![]);
    fake::INODE_PATHS.with_borrow_mut(|m| {
        for (k, v) in [("1:usr", 2u64), ("2:bin", 3), ("3:firefox", 4), ("2:lib", 5), ("5:ff", 6), ("6:firefox", 7)] {
            m.insert(k.to_string(), v);
        }
    });
    fake::INODES.with_borrow_mut(|m| {
        for d in [2u64, 3, 5, 6] {
            m.insert(d, (0o040755, vec![]));
        }
        m.insert(4, (0o120777, b"../lib/./ff/firefox".to_vec()));
    });
    file("/usr/bin/firefox", 7, 0o100755, program());
    assert_eq!(exec("/usr/bin/firefox", &["firefox"], &[]).0, 0);
    assert_eq!(fake::task(1150, |t| t.exe.clone()).flatten().as_deref(), Some("/usr/lib/ff/firefox"));
    // An absolute link target restarts at the root
    fake::INODES.with_borrow_mut(|m| m.insert(4, (0o120777, b"/usr/lib/ff/firefox".to_vec())));
    assert_eq!(exec("/usr/bin/firefox", &["firefox"], &[]).0, 0);
    assert_eq!(fake::task(1150, |t| t.exe.clone()).flatten().as_deref(), Some("/usr/lib/ff/firefox"));
    // A link loop: the lexical path is kept
    fake::INODES.with_borrow_mut(|m| m.insert(4, (0o120777, b"firefox".to_vec())));
    assert_eq!(exec("/usr/bin/firefox", &["firefox"], &[]).0, 0);
    assert_eq!(fake::task(1150, |t| t.exe.clone()).flatten().as_deref(), Some("/usr/bin/firefox"));
    // /proc/self/exe names the program it links to
    file("/bin/prog", 8, 0o100755, program());
    fake::PROC_LINKS.with_borrow_mut(|m| m.insert("/proc/self/exe".into(), "/bin/prog".into()));
    assert_eq!(exec("/proc/self/exe", &["again"], &[]).0, 0);
    assert_eq!(fake::task(1150, |t| t.exe.clone()).flatten().as_deref(), Some("/bin/prog"));
}

// ---------------------------------------------------------------- wave7 G7-5

fn plan(ino: u64, shown: &str, prefix: &[&str], interp: Option<(&str, u64)>) -> crate::lx::xexec::ExecPlan {
    crate::lx::xexec::ExecPlan { ino, shown: shown.into(), prefix: prefix.iter().map(|s| s.as_bytes().to_vec()).collect(), interp: interp.map(|(p, i)| (p.to_string(), i)) }
}

#[test]
fn the_services_front_half_is_used() {
    let _g = setup();
    proc_(1160, 1000);
    file("/bin/sh", 70, 0o100755, program());
    // linux-server resolved a script (that the kernel does not even know by path): its
    // interpreter runs with the argv it made
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(70, "/bin/sh", &["/bin/sh", "-e", "./script"], None))));
    assert_eq!(exec("./script", &["script", "a1"], &[]).0, 0);
    assert!(fake::called("xexec::front(-100,./script,0)"));
    assert_eq!(cmdline(1160), b"/bin/sh\0-e\0./script\0a1\0");
    assert_eq!(fake::task(1160, |t| t.exe.clone()).flatten().as_deref(), Some("/bin/sh"));
    // A program, argv unchanged, shown under the path it gave
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(70, "/usr/lib/real/sh", &[], None))));
    assert_eq!(exec("/usr/bin/sh-link", &["x", "y"], &[]).0, 0);
    assert_eq!(cmdline(1160), b"x\0y\0");
    assert_eq!(fake::task(1160, |t| t.exe.clone()).flatten().as_deref(), Some("/usr/lib/real/sh"));
    // Its error is the exec's
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Err(EACCES)));
    assert_eq!(exec("/bin/whatever", &[], &[]).0, EACCES);
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Err(ELOOP)));
    assert_eq!(exec("/bin/whatever", &[], &[]).0, ELOOP);
}

#[test]
fn the_kernel_checks_the_planned_program_again() {
    let _g = setup();
    proc_(1161, 1000);
    // Not executable (changed after the lookup): EACCES
    file("/bin/nox", 76, 0o100644, program());
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(76, "/bin/nox", &[], None))));
    assert_eq!(exec("/bin/nox", &[], &[]).0, EACCES);
    // Junk: ENOEXEC
    file("/bin/junk", 77, 0o100755, b"not a program at all".to_vec());
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(77, "/bin/junk", &[], None))));
    assert_eq!(exec("/bin/junk", &[], &[]).0, ENOEXEC);
    // Set-user-ID applies to the planned program as to the kernel's own
    file("/bin/su", 78, 0o104755, program());
    owner(78, 0, 0);
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(78, "/bin/su", &[], None))));
    assert_eq!(exec("/bin/su", &["su"], &[]).0, 0);
    assert_eq!(fake::task(1161, |t| (t.uid, t.euid, t.suid)), Some((1000, 0, 0)));
}

#[test]
fn a_planned_program_that_became_a_script_goes_to_the_kernel() {
    let _g = setup();
    proc_(1162, 1000);
    file("/bin/sh", 70, 0o100755, program());
    file("/bin/script", 71, 0o100755, b"#!/bin/sh\n".to_vec());
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(71, "/bin/script", &[], None))));
    assert_eq!(exec("/bin/script", &["s"], &[]).0, 0);
    // (the kernel's own front half: the script ran through its interpreter)
    assert_eq!(cmdline(1162), b"/bin/sh\0/bin/script\0");
}

#[test]
fn the_planned_elf_interpreter_is_used() {
    let _g = setup();
    proc_(1163, 1000);
    let dynamic = Elf::new(ET_DYN, 0x100, &[load_with(5, 0, 0, 0x200, 0x200), Ph { ty: PT_INTERP, flags: 4, offset: 0x180, vaddr: 0x180, filesz: 9, memsz: 9 }], 0x200)
        .put(0x180, b"/lib/ld\0\0")
        .bytes;
    file("/bin/dyn", 59, 0o100755, dynamic);
    // linux-server did not find it: ENOENT, even though the kernel knows a /lib/ld
    file("/lib/ld", 60, 0o100755, program());
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(59, "/bin/dyn", &[], Some(("/lib/ld", 0))))));
    assert_eq!(exec("/bin/dyn", &[], &[]).0, ENOENT);
    // Found: loaded
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(59, "/bin/dyn", &[], Some(("/lib/ld", 60))))));
    assert_eq!(exec("/bin/dyn", &[], &[]).0, 0);
    // Another path than the one planned: the kernel looks it up itself
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(59, "/bin/dyn", &[], Some(("/lib/other", 0))))));
    assert_eq!(exec("/bin/dyn", &[], &[]).0, 0);
}

#[test]
fn a_plan_is_not_used_once_kernel_only_rules_exist() {
    let _g = setup();
    proc_(1164, 1000);
    file("/bin/sh", 70, 0o100755, program());
    file("/bin/prog", 50, 0o100755, program());
    // (app control loaded after the front half was asked: the kernel looks up /bin/prog itself)
    fake::set_ret("abac::active", 1);
    fake::EXEC_FRONT.with_borrow_mut(|m| *m = Some(Ok(plan(70, "/bin/sh", &[], None))));
    assert_eq!(exec("/bin/prog", &["prog"], &[]).0, 0);
    assert_eq!(fake::task(1164, |t| t.exe.clone()).flatten().as_deref(), Some("/bin/prog"));
}
