//! # Linux ABI Compatibility Subsystem
//!
//! Provides in-kernel translation and execution of Linux x86_64 system calls
//! allowing unmodified standard binaries (e.g. musl, BusyBox, Qt6/KDE runtimes)
//! to execute natively on Hydra Microkernel.

pub mod fs;
pub mod futex;
pub mod syscalls;
pub mod types;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::VirtAddr;

use crate::arch::syscall::SyscallFrame;
pub use syscalls::*;
pub use types::*;

/// Linux ABI subsystem diagnostic counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxSyscallStats {
    pub total_calls: u64,
    pub io_calls: u64,
    pub memory_calls: u64,
    pub process_calls: u64,
    pub arch_prctl_calls: u64,
    pub time_calls: u64,
    pub unknown_calls: u64,
}

pub static LINUX_STATS: Mutex<LinuxSyscallStats> = Mutex::new(LinuxSyscallStats {
    total_calls: 0,
    io_calls: 0,
    memory_calls: 0,
    process_calls: 0,
    arch_prctl_calls: 0,
    time_calls: 0,
    unknown_calls: 0,
});

/// High-level Linux system call dispatcher called by the hardware SYSCALL trampoline
/// when the active task personality is set to Linux.
pub fn dispatch_linux_syscall(frame: &mut SyscallFrame) -> i64 {
    let num = frame.rax;
    let arg0 = frame.rdi;
    let arg1 = frame.rsi;
    let arg2 = frame.rdx;
    let arg3 = frame.r10;
    let arg4 = frame.r8;
    let arg5 = frame.r9;

    {
        let mut stats = LINUX_STATS.lock();
        stats.total_calls += 1;
    }

    match num {
        SYS_READ => {
            // sys_read(fd: int, buf: void*, count: size_t)
            let fd = arg0 as usize;
            let ptr = arg1 as *mut u8;
            let count = (arg2 as usize).min(1024 * 1024);
            if ptr.is_null() && count > 0 {
                return -EFAULT;
            }
            if count == 0 {
                return 0;
            }

            let slice = unsafe { core::slice::from_raw_parts_mut(ptr, count) };
            crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(fd) {
                    match desc.read(slice) {
                        Ok(n) => n as i64,
                        Err(_) => -EIO,
                    }
                } else {
                    -EBADF
                }
            })
        }

        SYS_WRITE => {
            // sys_write(fd: int, buf: const void*, count: size_t)
            let fd = arg0 as usize;
            let ptr = arg1 as *const u8;
            let count = arg2 as usize;
            if ptr.is_null() && count > 0 {
                return -EFAULT;
            }
            if count == 0 {
                return 0;
            }

            let slice = unsafe { core::slice::from_raw_parts(ptr, count) };
            crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(fd) {
                    match desc.write(slice) {
                        Ok(n) => n as i64,
                        Err(_) => -EIO,
                    }
                } else {
                    -EBADF
                }
            })
        }

        SYS_OPEN => {
            // sys_open(filename: const char*, flags: int, mode: mode_t)
            let path_ptr = arg0 as *const u8;
            let flags = arg1 as u64;
            let path = match read_user_string(path_ptr) {
                Some(p) => p,
                None => return -EFAULT,
            };

            open_path(&path, flags)
        }

        SYS_CLOSE => {
            // sys_close(fd: int)
            let fd = arg0 as usize;
            crate::task::with_current_fds_mut(|fds| {
                match fds.close(fd) {
                    Ok(_) => 0,
                    Err(_) => -EBADF,
                }
            })
        }

        SYS_STAT | SYS_LSTAT => {
            // sys_stat(filename: const char*, statbuf: struct stat*)
            let path_ptr = arg0 as *const u8;
            let stat_ptr = arg1 as *mut LinuxStat;
            if stat_ptr.is_null() {
                return -EFAULT;
            }
            let path = match read_user_string(path_ptr) {
                Some(p) => p,
                None => return -EFAULT,
            };

            let mut statbuf = LinuxStat::default();
            if let Some(pseudo) = fs::match_pseudo_path(&path) {
                pseudo.stat(&mut statbuf);
                unsafe { *stat_ptr = statbuf; }
                0
            } else {
                match crate::fs::ZfsClient::file_stat(&path) {
                    Ok(st) => {
                        let is_dir = st.obj_type == crate::fs::zfs::DnodeType::Directory;
                        statbuf.st_dev = 2;
                        statbuf.st_ino = st.obj_id;
                        statbuf.st_nlink = 1;
                        statbuf.st_size = st.size as i64;
                        statbuf.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
                        statbuf.st_blksize = 4096;
                        unsafe { *stat_ptr = statbuf; }
                        0
                    }
                    Err(_) => -ENOENT,
                }
            }
        }

        SYS_FSTAT => {
            // sys_fstat(fd: int, statbuf: struct stat*)
            let fd = arg0 as usize;
            let stat_ptr = arg1 as *mut LinuxStat;
            if stat_ptr.is_null() {
                return -EFAULT;
            }

            let mut statbuf = LinuxStat::default();
            if fd <= 2 {
                // stdin, stdout, stderr are character devices (tty)
                statbuf.st_mode = S_IFCHR | 0o666;
                statbuf.st_rdev = 5;
                unsafe { *stat_ptr = statbuf; }
                0
            } else {
                crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get(fd) {
                        match desc {
                            crate::fs::FileDescriptor::File { path, .. } => {
                                if let Ok(st) = crate::fs::ZfsClient::file_stat(path) {
                                    let is_dir = st.obj_type == crate::fs::zfs::DnodeType::Directory;
                                    statbuf.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
                                    statbuf.st_size = st.size as i64;
                                    statbuf.st_blksize = 4096;
                                    unsafe { *stat_ptr = statbuf; }
                                    0
                                } else {
                                    -ENOENT
                                }
                            }
                            crate::fs::FileDescriptor::PipeRead(_) | crate::fs::FileDescriptor::PipeWrite(_) => {
                                statbuf.st_mode = S_IFIFO | 0o600;
                                unsafe { *stat_ptr = statbuf; }
                                0
                            }
                            _ => {
                                statbuf.st_mode = S_IFREG | 0o644;
                                unsafe { *stat_ptr = statbuf; }
                                0
                            }
                        }
                    } else {
                        -EBADF
                    }
                })
            }
        }

        SYS_LSEEK => {
            // sys_lseek(fd: int, offset: off_t, whence: int)
            // whence: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END
            let fd = arg0 as usize;
            let offset = arg1 as i64;
            let whence = arg2 as u32;

            crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(fd) {
                    match desc {
                        crate::fs::FileDescriptor::File { path, cursor, .. } => {
                            let file_size = crate::fs::ZfsClient::file_stat(path).map(|st| st.size).unwrap_or(0) as i64;
                            let new_cursor = match whence {
                                0 => offset,
                                1 => (*cursor as i64) + offset,
                                2 => file_size + offset,
                                _ => return -EINVAL,
                            };
                            if new_cursor < 0 {
                                return -EINVAL;
                            }
                            *cursor = new_cursor as usize;
                            new_cursor
                        }
                        _ => -ESPIPE,
                    }
                } else {
                    -EBADF
                }
            })
        }

        SYS_MMAP => {
            // sys_mmap(addr: void*, length: size_t, prot: int, flags: int, fd: int, offset: off_t)
            let _hint_addr = arg0;
            let length = arg1 as usize;
            let _prot = arg2;
            let flags = arg3;
            let fd = arg4 as i64;

            if length == 0 {
                return -EINVAL;
            }

            let aligned_len = (length + 4095) & !4095;

            // Strategy: Anonymous memory allocation via kernel heap/frame allocator
            if (flags & MAP_ANONYMOUS) != 0 || fd == -1 {
                let buffer = alloc::vec![0u8; aligned_len].into_boxed_slice();
                let vaddr = buffer.as_ptr() as u64;

                // Mark pages USER_ACCESSIBLE
                if let Err(_) = crate::memory::paging::make_user_accessible(VirtAddr::new(vaddr), aligned_len) {
                    return -ENOMEM;
                }

                // Prevent Rust from deallocating the buffer when it goes out of scope
                core::mem::forget(buffer);
                vaddr as i64
            } else {
                // File-backed mapping
                let fd = fd as usize;
                let mut data = alloc::vec![0u8; aligned_len];
                let _bytes_read = crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(fd) {
                        desc.read(&mut data).unwrap_or(0)
                    } else {
                        0
                    }
                });

                let buffer = data.into_boxed_slice();
                let vaddr = buffer.as_ptr() as u64;
                if let Err(_) = crate::memory::paging::make_user_accessible(VirtAddr::new(vaddr), aligned_len) {
                    return -ENOMEM;
                }
                core::mem::forget(buffer);
                vaddr as i64
            }
        }

        SYS_MPROTECT => {
            // sys_mprotect(addr: void*, len: size_t, prot: int)
            // Memory is already user-accessible in our flat identity mapping; return success
            0
        }

        SYS_MUNMAP => {
            // sys_munmap(addr: void*, length: size_t)
            // In microkernel environment, memory cleanup is reclaimed on task exit
            0
        }

        SYS_BRK => {
            // sys_brk(new_brk: void*)
            let new_brk = arg0;
            crate::task::with_current_task_mut(|task| {
                if new_brk == 0 || new_brk == task.brk {
                    task.brk as i64
                } else if new_brk > task.brk {
                    let diff = (new_brk - task.brk) as usize;
                    let aligned_diff = (diff + 4095) & !4095;
                    // Allocate new backing pages
                    let buf = alloc::vec![0u8; aligned_diff].into_boxed_slice();
                    let vaddr = buf.as_ptr() as u64;
                    let _ = crate::memory::paging::make_user_accessible(VirtAddr::new(vaddr), aligned_diff);
                    core::mem::forget(buf);
                    task.brk = new_brk;
                    task.brk as i64
                } else {
                    task.brk as i64
                }
            }).unwrap_or(0)
        }

        SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK => {
            // Signal management stubs (successful no-op for musl/glibc startup)
            0
        }

        SYS_IOCTL => {
            // sys_ioctl(fd: int, request: unsigned long, arg: void*)
            let fd = arg0 as usize;
            let request = arg1;
            // TIOCGWINSZ (0x5413): Terminal Window Size query
            if request == 0x5413 && arg2 != 0 {
                let winsize_ptr = arg2 as *mut u16;
                unsafe {
                    *winsize_ptr = 25;       // rows
                    *winsize_ptr.add(1) = 80; // cols
                    *winsize_ptr.add(2) = 0;  // xpixel
                    *winsize_ptr.add(3) = 0;  // ypixel
                }
                0
            } else if fd <= 2 {
                0 // Success for terminal FDs
            } else {
                -ENOTTY
            }
        }

        SYS_WRITEV => {
            // sys_writev(fd: int, iov: const struct iovec*, iovcnt: int)
            let fd = arg0 as usize;
            let iov_ptr = arg1 as *const LinuxIovec;
            let iovcnt = arg2 as usize;
            if iov_ptr.is_null() && iovcnt > 0 {
                return -EFAULT;
            }

            let mut total_written = 0i64;
            for i in 0..iovcnt {
                let iov = unsafe { *iov_ptr.add(i) };
                if iov.iov_len > 0 && iov.iov_base != 0 {
                    let slice = unsafe { core::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len as usize) };
                    let res = crate::task::with_current_fds_mut(|fds| {
                        if let Some(desc) = fds.get_mut(fd) {
                            desc.write(slice).map(|n| n as i64).unwrap_or(-EIO)
                        } else {
                            -EBADF
                        }
                    });
                    if res < 0 {
                        return if total_written > 0 { total_written } else { res };
                    }
                    total_written += res;
                }
            }
            total_written
        }

        SYS_ACCESS => {
            // sys_access(pathname: const char*, mode: int)
            let path_ptr = arg0 as *const u8;
            let path = match read_user_string(path_ptr) {
                Some(p) => p,
                None => return -EFAULT,
            };

            if fs::match_pseudo_path(&path).is_some() || crate::fs::ZfsClient::file_stat(&path).is_ok() {
                0
            } else {
                -ENOENT
            }
        }

        SYS_PIPE | SYS_PIPE2 => {
            // sys_pipe(pipefd: int[2])
            let pipefd_ptr = arg0 as *mut [i32; 2];
            if pipefd_ptr.is_null() {
                return -EFAULT;
            }

            let pipe = crate::fs::PipeBuffer::new();
            let read_desc = crate::fs::FileDescriptor::PipeRead(pipe.clone());
            let write_desc = crate::fs::FileDescriptor::PipeWrite(pipe);

            crate::task::with_current_fds_mut(|fds| {
                match fds.alloc_fd(read_desc) {
                    Ok(rfd) => match fds.alloc_fd(write_desc) {
                        Ok(wfd) => {
                            unsafe {
                                (*pipefd_ptr)[0] = rfd as i32;
                                (*pipefd_ptr)[1] = wfd as i32;
                            }
                            0
                        }
                        Err(_) => {
                            let _ = fds.close(rfd);
                            -EMFILE
                        }
                    },
                    Err(_) => -EMFILE,
                }
            })
        }

        SYS_SCHED_YIELD => {
            crate::task::yield_now();
            0
        }

        SYS_DUP => {
            let oldfd = arg0 as usize;
            crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get(oldfd).cloned() {
                    match fds.alloc_fd(desc) {
                        Ok(newfd) => newfd as i64,
                        Err(_) => -EMFILE,
                    }
                } else {
                    -EBADF
                }
            })
        }

        SYS_DUP2 | SYS_DUP3 => {
            let oldfd = arg0 as usize;
            let newfd = arg1 as usize;
            crate::task::with_current_fds_mut(|fds| {
                match fds.dup2(oldfd, newfd) {
                    Ok(fd) => fd as i64,
                    Err(_) => -EBADF,
                }
            })
        }

        SYS_NANOSLEEP => {
            // sys_nanosleep(req: const struct timespec*, rem: struct timespec*)
            let req_ptr = arg0 as *const LinuxTimespec;
            if req_ptr.is_null() {
                return -EFAULT;
            }
            let req = unsafe { *req_ptr };
            let ms = (req.tv_sec as u64 * 1000) + (req.tv_nsec as u64 / 1_000_000);
            crate::task::sleep_ms(ms);
            0
        }

        SYS_GETPID => {
            crate::task::with_current_task_mut(|t| t.tgid as i64).unwrap_or(0)
        }

        SYS_GETTID => {
            crate::task::SCHEDULER.lock().current_task_id().0 as i64
        }

        SYS_CLONE => {
            // sys_clone(flags: unsigned long, child_stack: void*, ptid: int*, ctid: int*, newtls: unsigned long)
            {
                let mut stats = LINUX_STATS.lock();
                stats.process_calls += 1;
            }
            match crate::task::SCHEDULER.lock().spawn_clone(frame) {
                Ok(child_id) => child_id.0 as i64,
                Err(_) => -ENOMEM,
            }
        }

        SYS_EXIT | SYS_EXIT_GROUP => {
            crate::task::exit();
        }

        SYS_UNAME => {
            // sys_uname(buf: struct utsname*)
            let buf_ptr = arg0 as *mut LinuxUtsname;
            if buf_ptr.is_null() {
                return -EFAULT;
            }
            unsafe {
                *buf_ptr = LinuxUtsname::default();
            }
            0
        }

        SYS_FCNTL => {
            // sys_fcntl(fd: int, cmd: int, arg: unsigned long)
            // F_GETFD (1), F_SETFD (2), F_GETFL (3), F_SETFL (4)
            let _fd = arg0 as usize;
            let cmd = arg1 as u32;
            match cmd {
                1 => 0, // FD_CLOEXEC is 0
                2 => 0,
                3 => 2, // O_RDWR
                4 => 0,
                _ => 0,
            }
        }

        SYS_GETCWD => {
            // sys_getcwd(buf: char*, size: size_t)
            let buf_ptr = arg0 as *mut u8;
            let size = arg1 as usize;
            if buf_ptr.is_null() || size == 0 {
                return -EFAULT;
            }
            let cwd = b"/\0";
            if size < cwd.len() {
                return -ERANGE;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf_ptr, cwd.len());
            }
            buf_ptr as i64
        }

        SYS_CHDIR => {
            0 // Support root chdir
        }

        SYS_GETTIMEOFDAY => {
            // sys_gettimeofday(tv: struct timeval*, tz: struct timezone*)
            let tv_ptr = arg0 as *mut LinuxTimeval;
            if !tv_ptr.is_null() {
                let ticks = crate::arch::pit::ticks();
                let secs = (ticks / 100) as i64;
                let usecs = ((ticks % 100) * 10_000) as i64;
                unsafe {
                    (*tv_ptr).tv_sec = secs;
                    (*tv_ptr).tv_usec = usecs;
                }
            }
            0
        }

        SYS_GETUID | SYS_GETEUID => 1000,
        SYS_GETGID | SYS_GETEGID => 1000,

        SYS_ARCH_PRCTL => {
            // sys_arch_prctl(code: int, addr: unsigned long)
            let code = arg0;
            let addr = arg1;

            {
                let mut stats = LINUX_STATS.lock();
                stats.arch_prctl_calls += 1;
            }

            match code {
                ARCH_SET_FS => {
                    // Update current task control block and hardware MSR
                    crate::task::with_current_task_mut(|t| {
                        t.fs_base = addr;
                    });
                    unsafe {
                        crate::arch::syscall::wrmsr(0xC000_0100, addr);
                    }
                    0
                }
                ARCH_GET_FS => {
                    let fs_base = unsafe { crate::arch::syscall::rdmsr(0xC000_0100) };
                    if arg1 != 0 {
                        unsafe {
                            *(arg1 as *mut u64) = fs_base;
                        }
                        0
                    } else {
                        -EFAULT
                    }
                }
                _ => -EINVAL,
            }
        }

        SYS_FUTEX => {
            // sys_futex(uaddr: int*, op: int, val: int, timeout: const struct timespec*, uaddr2: int*, val3: int)
            {
                let mut stats = LINUX_STATS.lock();
                stats.process_calls += 1;
            }
            futex::dispatch_futex(arg0, arg1 as i32, arg2 as u32, arg3, arg4, arg5 as u32)
        }

        SYS_SET_TID_ADDRESS => {
            // sys_set_tid_address(tidptr: int*)
            let tidptr = arg0;
            crate::task::with_current_task_mut(|t| {
                t.clear_child_tid = tidptr;
            });
            crate::task::SCHEDULER.lock().current_task_id().0 as i64
        }

        SYS_CLOCK_GETTIME => {
            // sys_clock_gettime(clk_id: clockid_t, tp: struct timespec*)
            let tp_ptr = arg1 as *mut LinuxTimespec;
            if tp_ptr.is_null() {
                return -EFAULT;
            }
            let ticks = crate::arch::pit::ticks();
            let secs = (ticks / 100) as i64;
            let nsecs = ((ticks % 100) * 10_000_000) as i64;
            unsafe {
                (*tp_ptr).tv_sec = secs;
                (*tp_ptr).tv_nsec = nsecs;
            }
            0
        }

        SYS_OPENAT => {
            // sys_openat(dirfd: int, pathname: const char*, flags: int, mode: mode_t)
            let path_ptr = arg1 as *const u8;
            let flags = arg2 as u64;
            let path = match read_user_string(path_ptr) {
                Some(p) => p,
                None => return -EFAULT,
            };

            open_path(&path, flags)
        }

        SYS_NEWFSTATAT => {
            // sys_newfstatat(dirfd: int, pathname: const char*, statbuf: struct stat*, flags: int)
            let path_ptr = arg1 as *const u8;
            let stat_ptr = arg2 as *mut LinuxStat;
            if stat_ptr.is_null() {
                return -EFAULT;
            }
            let path = match read_user_string(path_ptr) {
                Some(p) => p,
                None => return -EFAULT,
            };

            let mut statbuf = LinuxStat::default();
            if let Some(pseudo) = fs::match_pseudo_path(&path) {
                pseudo.stat(&mut statbuf);
                unsafe { *stat_ptr = statbuf; }
                0
            } else {
                match crate::fs::ZfsClient::file_stat(&path) {
                    Ok(st) => {
                        let is_dir = st.obj_type == crate::fs::zfs::DnodeType::Directory;
                        statbuf.st_dev = 2;
                        statbuf.st_ino = st.obj_id;
                        statbuf.st_nlink = 1;
                        statbuf.st_size = st.size as i64;
                        statbuf.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
                        statbuf.st_blksize = 4096;
                        unsafe { *stat_ptr = statbuf; }
                        0
                    }
                    Err(_) => -ENOENT,
                }
            }
        }

        SYS_GETRANDOM => {
            // sys_getrandom(buf: void*, buflen: size_t, flags: unsigned int)
            let buf_ptr = arg0 as *mut u8;
            let buflen = arg1 as usize;
            if buf_ptr.is_null() && buflen > 0 {
                return -EFAULT;
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buflen) };
            let pseudo = fs::PseudoFile::DevUrandom;
            pseudo.read(0, slice);
            buflen as i64
        }

        _ => {
            let mut stats = LINUX_STATS.lock();
            stats.unknown_calls += 1;
            -ENOSYS
        }
    }
}

const ERANGE: i64 = 34;

fn read_user_string(ptr: *const u8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    let mut offset = 0;
    while offset < 4096 {
        let b = unsafe { *ptr.add(offset) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        offset += 1;
    }
    String::from_utf8(bytes).ok()
}

fn open_path(path: &str, flags: u64) -> i64 {
    // Check if opening pseudo-file
    if let Some(_) = fs::match_pseudo_path(path) {
        let desc = crate::fs::FileDescriptor::File {
            path: String::from(path),
            cursor: 0,
            readable: true,
            writable: true,
            append: false,
        };
        return crate::task::with_current_fds_mut(|fds| {
            fds.alloc_fd(desc).map(|fd| fd as i64).unwrap_or(-EMFILE)
        });
    }

    let readable = (flags & 3) == 0 || (flags & 3) == 2;
    let writable = (flags & 3) == 1 || (flags & 3) == 2;
    let append = (flags & 0o2000) != 0;

    if writable {
        let _ = crate::fs::ZfsClient::touch_file(path);
    } else {
        // Readonly check
        if crate::fs::ZfsClient::file_stat(path).is_err() {
            return -ENOENT;
        }
    }

    let desc = crate::fs::FileDescriptor::File {
        path: String::from(path),
        cursor: 0,
        readable,
        writable,
        append,
    };

    crate::task::with_current_fds_mut(|fds| {
        fds.alloc_fd(desc).map(|fd| fd as i64).unwrap_or(-EMFILE)
    })
}
