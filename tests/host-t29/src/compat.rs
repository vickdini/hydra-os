//! `crate::compat::linux`: the kernel's `mod.rs` (the system call table) itself. On the
//! host its submodules come from [`linux_host`] (`pub use crate::compat::linux_host::*` in
//! mod.rs): Group 29's files (real), the real files they lean on, and stubs for the rest of
//! the Linux layer.

#[path = "../../../src/compat/linux/mod.rs"]
pub mod linux;

pub mod linux_host {
    use crate::stub;

    // ---- Group 29's files (the kernel's own code)
    #[path = "../../../../../src/compat/linux/execve.rs"]
    pub mod execve;
    #[path = "../../../../../src/compat/linux/extra.rs"]
    pub mod extra;
    #[path = "../../../../../src/compat/linux/futex.rs"]
    pub mod futex;
    #[path = "../../../../../src/compat/linux/ldt.rs"]
    pub mod ldt;
    #[path = "../../../../../src/compat/linux/limits.rs"]
    pub mod limits;
    #[path = "../../../../../src/compat/linux/mm.rs"]
    pub mod mm;
    #[path = "../../../../../src/compat/linux/ns.rs"]
    pub mod ns;
    #[path = "../../../../../src/compat/linux/proc.rs"]
    pub mod proc;
    #[path = "../../../../../src/compat/linux/process.rs"]
    pub mod process;
    #[path = "../../../../../src/compat/linux/ptrace.rs"]
    pub mod ptrace;
    #[path = "../../../../../src/compat/linux/seccomp.rs"]
    pub mod seccomp;
    #[path = "../../../../../src/compat/linux/syscalls.rs"]
    pub mod syscalls;
    #[path = "../../../../../src/compat/linux/types.rs"]
    pub mod types;
    #[path = "../../../../../src/compat/linux/userfaultfd.rs"]
    pub mod userfaultfd;

    // ---- Other groups' files compiled unchanged (pure enough for the host)
    #[path = "../../../../../src/compat/linux/memfd.rs"]
    pub mod memfd;
    #[path = "../../../../../src/compat/linux/prof.rs"]
    pub mod prof;
    #[path = "../../../../../src/compat/linux/landlock.rs"]
    pub mod landlock;
    #[path = "../../../../../src/compat/linux/socket.rs"]
    pub mod socket;
    #[path = "../../../../../src/compat/linux/epoll.rs"]
    pub mod epoll;

    pub use syscalls::*;
    pub use types::*;

    /// mod.rs's own items that its submodules reach through `super::`.
    pub use super::linux::{dispatch_linux_syscall, ident_changed, TRACE_SYSCALLS};

    // ---- Stubs of the rest of the Linux layer

    /// *stub* Pseudo-files (`/proc`, `/dev`): the paths in `fake::PSEUDO`.
    pub mod fs {
        pub struct PseudoFile(pub alloc::string::String);
        impl PseudoFile {
            pub fn stat(&self, st: &mut crate::compat::linux::types::LinuxStat) {
                st.st_mode = 0o100444;
                st.st_size = 1;
            }
        }
        pub fn match_pseudo_path(path: &str) -> Option<PseudoFile> {
            crate::fake::PSEUDO.with_borrow(|v| v.iter().any(|p| p == path)).then(|| PseudoFile(path.into()))
        }
        pub fn proc_link(path: &str) -> Option<alloc::string::String> {
            crate::fake::PROC_LINKS.with_borrow(|m| m.get(path).cloned())
        }
    }
    pub mod bpf {
        crate::stub!(pub fn sys_bpf(cmd: u64, attr: u64, size: u64) -> i64 as "bpf::sys_bpf");
    }
    pub mod io_uring {
        pub fn dispatch(_frame: &crate::arch::syscall::SyscallFrame, num: u64, a: [u64; 6]) -> i64 {
            crate::fake::rec(alloc::format!("io_uring::dispatch({num})"));
            crate::fake::ret("io_uring::dispatch")
        }
    }
    pub mod xfer {
        pub fn dispatch(_frame: &mut crate::arch::syscall::SyscallFrame, num: u64) -> i64 {
            crate::fake::rec(alloc::format!("xfer::dispatch({num})"));
            crate::fake::ret("xfer::dispatch")
        }
    }
    pub mod recent {
        pub fn dispatch(_frame: &mut crate::arch::syscall::SyscallFrame, num: u64) -> i64 {
            crate::fake::rec(alloc::format!("recent::dispatch({num})"));
            crate::fake::ret("recent::dispatch")
        }
    }
    pub mod mqueue {
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("mqueue::dispatch", num)
        }
    }
    pub mod rtnetlink {
        pub fn interface_ioctl(cmd: u64, arg: u64) -> Option<i64> {
            crate::fake::opt("rtnetlink::interface_ioctl", cmd)
        }
    }
    pub mod unix {
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("unix::dispatch", num)
        }
    }
    pub mod inet {
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("inet::dispatch", num)
        }
    }
    pub mod tty {
        pub fn pump() {}
    }
    pub mod abac {
        pub const PR_HYDRA_ACCESS: u64 = 0x4859_4401;
        /// wave7 G7-5: no access policies loaded (a test sets fake ret "abac::active").
        pub fn active() -> bool {
            crate::fake::ret("abac::active") != 0
        }
        /// wave9 G6b-3: app rules loaded (a test sets fake ret "abac::apps_active").
        pub fn apps_active() -> bool {
            crate::fake::ret("abac::apps_active") != 0
        }
        pub fn console_subject() -> u32 {
            0
        }
        pub fn exec_check(path: &str, _attr: &crate::fs::zfs::zpl::Attr, _parent: &mut dyn FnMut() -> Option<crate::fs::zfs::zpl::Attr>) -> bool {
            crate::fake::rec(alloc::format!("abac::exec_check({path})"));
            crate::fake::ret("abac::exec_check") == 0
        }
        pub fn note_path(ino: u64, path: &str) {
            crate::fake::rec(alloc::format!("abac::note_path({ino},{path})"));
        }
        crate::stub!(pub fn prctl(a: [u64; 6]) -> i64 as "abac::prctl");
    }
    pub mod admin {
        pub fn acct_on() -> bool {
            false
        }
        crate::stub!(pub fn on_exit(pid: u64, ppid: u64, start: u64, status: i32, cpu_ticks: u64, faults: u64) as "admin::on_exit");
        crate::stub!(pub fn note_exec(pid: u64) as "admin::note_exec");
        pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
            crate::fake::rec(alloc::format!("admin::dispatch({num})"));
            crate::fake::ret("admin::dispatch")
        }
    }
    pub mod aio {
        crate::stub!(pub fn forget_process(pid: u64) as "aio::forget_process");
        pub fn dispatch(_frame: &mut crate::arch::syscall::SyscallFrame, num: u64) -> i64 {
            crate::fake::rec(alloc::format!("aio::dispatch({num})"));
            crate::fake::ret("aio::dispatch")
        }
    }
    pub mod eventfd {
        crate::stub!(pub fn sys_eventfd2(initval: u64, flags: u64) -> i64 as "eventfd::sys_eventfd2");
    }
    pub mod fanotify {
        pub fn active() -> bool {
            false
        }
        crate::stub!(pub fn name_to_handle_at(dirfd: u64, path: u64, handle: u64, mount_id: u64, flags: u64) -> i64 as "fanotify::name_to_handle_at");
        pub fn on_open(ino: u64, dir: u64, path: &str, is_dir: bool, exec: bool) -> Result<(), i64> {
            crate::fake::rec(alloc::format!("fanotify::on_open({ino},{path},{exec})"));
            Ok(())
        }
        pub fn parent_of_path(_path: &str) -> u64 {
            0
        }
        pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
            crate::fake::rec(alloc::format!("fanotify::dispatch({num})"));
            crate::fake::ret("fanotify::dispatch")
        }
        crate::stub!(pub fn open_by_handle_at(mount_fd: u64, handle: u64, flags: u64) -> i64 as "fanotify::open_by_handle_at");
    }

    pub mod inotify {
        crate::stub!(pub fn sys_add_watch(fd: u64, path_ptr: u64, mask: u64) -> i64 as "inotify::sys_add_watch");
        crate::stub!(pub fn sys_init1(flags: u64) -> i64 as "inotify::sys_init1");
        crate::stub!(pub fn sys_rm_watch(fd: u64, wd: u64) -> i64 as "inotify::sys_rm_watch");
    }
    pub mod itimer {
        crate::stub!(pub fn sys_alarm(seconds: u64) -> i64 as "itimer::sys_alarm");
        crate::stub!(pub fn sys_getitimer(which: u64, ptr: u64) -> i64 as "itimer::sys_getitimer");
        crate::stub!(pub fn sys_setitimer(which: u64, new_ptr: u64, old_ptr: u64) -> i64 as "itimer::sys_setitimer");
    }
    pub mod keys {
        crate::stub!(pub fn on_exec(tid: u64, tgid: u64) as "keys::on_exec");
        crate::stub!(pub fn on_fork(parent_tgid: u64, child_tgid: u64) as "keys::on_fork");
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("keys::dispatch", num)
        }
    }
    pub mod locks {
        crate::stub!(pub fn flock(fd: u64, op: u64) -> i64 as "locks::flock");
        crate::stub!(pub fn process_exited(pid: u64) as "locks::process_exited");
    }
    pub mod misc {
        crate::stub!(pub fn forget_process(pid: u64) as "misc::forget_process");
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("misc::dispatch", num)
        }
    }
    pub mod mount {
        pub fn copy_ns(from: u64, ns_id: u64, _fds: &crate::fs::SharedFdTable) {
            crate::fake::rec(alloc::format!("mount::copy_ns({from},{ns_id})"));
        }
        pub fn exec_flags() -> (bool, bool) {
            crate::fake::MOUNT_EXEC_FLAGS.get()
        }
        pub fn resolve(_base: u64, _path: &[u8], _follow: bool) -> Option<Result<u64, i64>> {
            None
        }
        crate::stub!(pub fn forget_thread(tid: u64) as "mount::forget_thread");
        pub fn dispatch_new(num: u64, a: [u64; 6]) -> i64 {
            crate::fake::rec(alloc::format!("mount::dispatch_new({num})"));
            crate::fake::ret("mount::dispatch_new")
        }
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("mount::dispatch", num)
        }
    }
    pub mod perf {
        pub fn own_ticks(_tgid: u64) -> (u64, u64) {
            (0, 0)
        }
        pub fn active() -> bool {
            false
        }
        pub fn exited(pid: u64, ancestors: &[u64]) {
            crate::fake::rec(alloc::format!("perf::exited({pid},{:?})", ancestors));
        }
        crate::stub!(pub fn on_exec(tgid: u64) as "perf::on_exec");
        crate::stub!(pub fn sys_perf_event_open(attr: u64, pid: u64, cpu: u64, group_fd: u64, flags: u64) -> i64 as "perf::sys_perf_event_open");
    }
    pub mod pidfd {
        /// Woken when a process exits.
        pub static EXIT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
        pub fn pid_of(fd: u64) -> Result<u64, i64> {
            crate::task::with_current_fds_mut(|f| match f.get(fd as usize) {
                Some(crate::fs::FileDescriptor::PidFd(p)) => Ok(**p),
                Some(_) => Err(-22),
                None => Err(-9),
            })
        }
        crate::stub!(pub fn sys_pidfd_open(pid: u64, flags: u64) -> i64 as "pidfd::sys_pidfd_open");
        crate::stub!(pub fn sys_pidfd_send_signal(fd: u64, sig: u64, info: u64, flags: u64) -> i64 as "pidfd::sys_pidfd_send_signal");
        pub fn install(pid: u64, _nonblock: bool) -> i64 {
            crate::task::with_current_fds_mut(|f| f.alloc_fd(crate::fs::FileDescriptor::PidFd(alloc::sync::Arc::new(pid))).map_or(-24, |fd| fd as i64))
        }
    }
    pub mod ptimer {
        pub const SI_TIMER: i32 = -2;
        crate::stub!(pub fn forget_process(pid: u64) as "ptimer::forget_process");
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("ptimer::dispatch", num)
        }
    }
    pub mod select {
        crate::stub!(pub fn sys_pselect6(a: [u64; 6]) -> i64 as "select::sys_pselect6");
        crate::stub!(pub fn sys_select(a: [u64; 6]) -> i64 as "select::sys_select");
    }
    pub mod signalfd {
        crate::stub!(pub fn sys_signalfd4(fd: i64, mask_ptr: u64, size: u64, flags: u64) -> i64 as "signalfd::sys_signalfd4");
    }
    pub mod sysv {
        crate::stub!(pub fn forget_process(pid: u64, exiting: bool) as "sysv::forget_process");
        crate::stub!(pub fn on_fork(parent: u64, child: u64) as "sysv::on_fork");
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("sysv::dispatch", num)
        }
    }
    pub mod timerfd {
        crate::stub!(pub fn sys_create(clock: u64, flags: u64) -> i64 as "timerfd::sys_create");
        crate::stub!(pub fn sys_gettime(fd: u64, cur_ptr: u64) -> i64 as "timerfd::sys_gettime");
        crate::stub!(pub fn sys_settime(fd: u64, flags: u64, new_ptr: u64, old_ptr: u64) -> i64 as "timerfd::sys_settime");
    }

    /// *stub* The kernel's `CharDevice` trait, cut down to what the code here calls.
    pub mod chardev {
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("chardev::dispatch", num)
        }
        use alloc::string::String;
        use alloc::sync::Arc;

        use crate::memory::vm::MappedObject;
        use crate::task::wait::WaitSet;

        pub trait CharDevice: Send + Sync {
            fn read(&self, buf: &mut [u8]) -> i64;
            fn write(&self, _data: &[u8]) -> i64 {
                -22
            }
            fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
                -25
            }
            fn pread(&self, _buf: &mut [u8], _off: u64) -> Option<i64> {
                None
            }
            fn pwrite(&self, _data: &[u8], _off: u64) -> Option<i64> {
                None
            }
            fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
                None
            }
            fn poll_events(&self) -> u32 {
                0
            }
            fn add_wait_queues(&self, _waits: &mut WaitSet) {}
            fn rdev(&self) -> u64 {
                0
            }
            fn path(&self) -> String {
                String::new()
            }
            fn edges(&self) -> Option<u64> {
                None
            }
            fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
                Err(-19)
            }
            fn mmap_object_at(&self, _pgoff: u64) -> Result<Arc<dyn MappedObject>, i64> {
                self.mmap_object()
            }
            fn set_nonblock(&self, _on: bool) {}
            fn nonblock(&self) -> bool {
                false
            }
            fn stat(&self) -> crate::compat::linux::types::LinuxStat {
                crate::compat::linux::types::LinuxStat::default()
            }
            fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
                None
            }
            fn as_landlock(&self) -> Option<&crate::compat::linux::landlock::Ruleset> {
                None
            }
            /// *stub* A process's memory (`/proc/<pid>/mem`): the pid.
            fn mem_pid(&self) -> Option<u64> {
                None
            }
        }
    }

    /// *stub* The VFS: user-memory copies (as the kernel's), credentials, and path lookup
    /// through `fake::INODE_PATHS`.
    pub mod vfs {
        use alloc::string::String;
        use alloc::vec::Vec;

        const EFAULT: i64 = -14;
        pub(crate) const EMPTY_ROOT: u64 = u64::MAX;

        pub(crate) struct Creds {
            pub uid: u32,
            pub gid: u32,
            pub euid: u32,
            pub egid: u32,
        }
        pub(crate) fn creds() -> Creds {
            crate::task::with_current_task_mut(|t| Creds { uid: t.uid, gid: t.gid, euid: t.euid, egid: t.egid })
                .unwrap_or(Creds { uid: 0, gid: 0, euid: 0, egid: 0 })
        }
        pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
            if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
                return Err(EFAULT);
            }
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
            Ok(())
        }
        pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
            if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
                return Err(EFAULT);
            }
            let mut v = alloc::vec![0u8; len];
            unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
            Ok(v)
        }
        /// Verbatim from the kernel.
        pub(crate) fn user_cstr(ptr: u64) -> Result<Vec<u8>, i64> {
            if ptr == 0 {
                return Err(EFAULT);
            }
            let mut out = Vec::new();
            let mut addr = ptr;
            loop {
                let page_end = (addr | 0xFFF) + 1;
                if !crate::memory::vm::prefault_current(addr, page_end - addr, false) {
                    return Err(EFAULT);
                }
                while addr < page_end {
                    let b = unsafe { *(addr as *const u8) };
                    if b == 0 {
                        return Ok(out);
                    }
                    out.push(b);
                    if out.len() >= 4096 {
                        return Err(-36); // ENAMETOOLONG
                    }
                    addr += 1;
                }
            }
        }
        pub(crate) fn user_path(ptr: u64) -> Result<Vec<u8>, i64> {
            let p = user_cstr(ptr)?;
            if p.is_empty() {
                return Err(-2);
            }
            Ok(p)
        }
        /// *mirror* of the kernel's: `/` for absolute paths, the working directory for
        /// `AT_FDCWD`, an open file's inode and path for a `Vnode` descriptor.
        pub(crate) fn base_dir(dirfd: i64, path: &[u8]) -> Result<(u64, String), i64> {
            if path.first() == Some(&b'/') {
                return Ok((0, String::from("/")));
            }
            if dirfd as i32 == -100 {
                return Ok(crate::task::with_current_fds_mut(|f| (f.cwd_ino, f.cwd_path.clone())));
            }
            let fd = dirfd as i32;
            let found = crate::task::with_current_fds_mut(|f| {
                if fd < 0 {
                    return Err(-9);
                }
                match f.get(fd as usize) {
                    Some(crate::fs::FileDescriptor::Vnode(v)) => {
                        let v = v.lock();
                        Ok((v.ino, v.path.clone()))
                    }
                    Some(_) => Err(-20), // ENOTDIR
                    None => Err(-9),     // EBADF
                }
            });
            found
        }
        /// Plain path join.
        pub(crate) fn join_path(base: &str, path: &[u8]) -> String {
            let p = String::from_utf8_lossy(path);
            if p.starts_with('/') {
                p.into_owned()
            } else {
                alloc::format!("{}/{}", base.trim_end_matches('/'), p)
            }
        }
        /// *mirror* of the kernel's permission bits check (owner, group, other; root
        /// passes all but execute without any x bit).
        pub(crate) fn may_access(attr: &crate::fs::zfs::zpl::Attr, uid: u32, gid: u32, want: u32) -> bool {
            if uid == 0 {
                return want & 1 == 0 || attr.mode & 0o111 != 0;
            }
            let bits = if attr.uid == uid {
                (attr.mode >> 6) & 7
            } else if attr.gid == gid {
                (attr.mode >> 3) & 7
            } else {
                attr.mode & 7
            };
            bits & want == want
        }
        pub(crate) fn proc_root() -> u64 {
            0
        }
        /// Lookup in `fake::INODE_PATHS`: "<base>:<name>" first (one component below a
        /// directory inode), then the path as given.
        pub(crate) fn resolve(base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
            let p = String::from_utf8_lossy(path).into_owned();
            crate::fake::INODE_PATHS.with_borrow(|m| m.get(&alloc::format!("{base}:{p}")).or_else(|| m.get(&p)).copied().ok_or(-2))
        }
        pub(crate) fn served_by_name(_abs: &str) -> bool {
            false
        }
        pub(crate) fn file_caps(ino: u64) -> Option<(u64, bool)> {
            crate::fake::FILE_CAPS.with_borrow(|m| m.get(&ino).copied())
        }
        pub(crate) fn fd_link(abs: &str) -> Option<String> {
            Some(String::from(abs))
        }
        pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
            crate::fake::opt("vfs::dispatch", num)
        }
    }
}
