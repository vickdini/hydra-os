//! # Linux ABI Compatibility Subsystem
//!
//! Provides in-kernel translation and execution of Linux x86_64 system calls
//! allowing unmodified standard binaries (e.g. musl, BusyBox, Qt6/KDE runtimes)
//! to execute natively on Hydra Microkernel.

pub mod chardev;
pub mod devices;
pub mod drm;
pub mod epoll;
pub mod evdev;
pub mod netlink;
pub mod eventfd;
pub mod fs;
pub mod itimer;
pub mod inotify;
pub mod futex;
pub mod inet;
pub mod memfd;
pub mod execve;
pub mod mm;
pub mod proc;
pub mod pidfd;
pub mod pty;
pub mod process;
pub mod select;
pub mod signalfd;
pub mod socket;
pub mod syscalls;
pub mod timerfd;
pub mod tty;
pub mod types;
pub mod unix;
pub mod vfs;
pub mod wayland_bridge;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::VirtAddr;

use crate::arch::syscall::SyscallFrame;
pub use epoll::*;
pub use eventfd::*;
pub use memfd::*;
pub use socket::*;
pub use syscalls::*;
pub use types::*;
pub use wayland_bridge::*;

/// Linux ABI subsystem diagnostic counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxSyscallStats {
    /// Total number of Linux system calls intercepted.
    pub total_calls: u64,
    /// Number of file and I/O system calls dispatched (`read`, `write`, `openat`, etc.).
    pub io_calls: u64,
    /// Number of virtual memory management calls dispatched (`mmap`, `brk`, `mprotect`).
    pub memory_calls: u64,
    /// Number of process lifecycle calls dispatched (`clone`, `exit`, `wait4`).
    pub process_calls: u64,
    /// Number of architecture-specific control calls dispatched (`arch_prctl`).
    pub arch_prctl_calls: u64,
    /// Number of time/clock system calls dispatched (`clock_gettime`, `nanosleep`).
    pub time_calls: u64,
    /// Number of unhandled or unimplemented Linux system call numbers.
    pub unknown_calls: u64,
}

/// Global diagnostic counter singleton tracking Linux ABI system call activity.
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

    if let Some(r) = dispatch_process_calls(frame, num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        LINUX_STATS.lock().process_calls += 1;
        return r;
    }

    if let Some(r) = process::dispatch(num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        LINUX_STATS.lock().process_calls += 1;
        return r;
    }

    if let Some(r) = chardev::dispatch(num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        return r;
    }
    if let Some(r) = unix::dispatch(num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        return r;
    }
    if let Some(r) = inet::dispatch(num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        LINUX_STATS.lock().io_calls += 1;
        return r;
    }

    if let Some(r) = vfs::dispatch(num, [arg0, arg1, arg2, arg3, arg4, arg5]) {
        LINUX_STATS.lock().io_calls += 1;
        return r;
    }

    if matches!(num, SYS_MMAP | SYS_MUNMAP | SYS_MPROTECT | SYS_BRK | SYS_MREMAP | SYS_MADVISE | SYS_MINCORE | SYS_MSYNC) {
        if let Some(mm) = mm::current_mm() {
            LINUX_STATS.lock().memory_calls += 1;
            return match num {
                SYS_MMAP => mm::sys_mmap(&mm, arg0, arg1, arg2, arg3, arg4 as i64, arg5),
                SYS_MUNMAP => mm::sys_munmap(&mm, arg0, arg1),
                SYS_MPROTECT => mm::sys_mprotect(&mm, arg0, arg1, arg2),
                SYS_BRK => mm::sys_brk(&mm, arg0),
                SYS_MREMAP => mm::sys_mremap(&mm, arg0, arg1, arg2, arg3, arg4),
                SYS_MADVISE => mm::sys_madvise(&mm, arg0, arg1, arg2),
                SYS_MINCORE => mm::sys_mincore(&mm, arg0, arg1, arg2),
                _ => 0, // msync: no write-back of shared file mappings yet
            };
        }
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

            if !crate::memory::vm::prefault_current(ptr as u64, count as u64, true) {
                return -EFAULT;
            }
            dispatch_wayland_events();

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
            if !crate::memory::vm::prefault_current(ptr as u64, count as u64, false) {
                return -EFAULT;
            }

            let slice = unsafe { core::slice::from_raw_parts(ptr, count) };
            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(fd) {
                    match desc.write(slice) {
                        Ok(n) => n as i64,
                        Err(_) => -EIO,
                    }
                } else {
                    -EBADF
                }
            });
            if res > 0 {
                dispatch_wayland_events();
            }
            res
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

            // Check if fd is a shared memory descriptor (memfd)
            if fd >= 0 {
                let is_memfd = crate::task::with_current_fds_mut(|fds| {
                    if let Some(crate::fs::FileDescriptor::MemFd(m)) = fds.get(fd as usize) {
                        Some(m.clone())
                    } else {
                        None
                    }
                });

                if let Some(memfd) = is_memfd {
                    let frames = match memfd.lock().frames_for(aligned_len) {
                        Some(f) => f,
                        None => return -ENOMEM,
                    };
                    return match crate::memory::vm::map_into_kernel_space(&frames, true) {
                        Some(vaddr) => vaddr as i64,
                        None => -ENOMEM,
                    };
                }
            }

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

        SYS_READV => {
            // sys_readv(fd: int, iov: const struct iovec*, iovcnt: int)
            let fd = arg0 as usize;
            let iov_ptr = arg1 as *const LinuxIovec;
            let iovcnt = arg2 as usize;
            if !crate::memory::vm::prefault_current(iov_ptr as u64, (iovcnt * core::mem::size_of::<LinuxIovec>()) as u64, false) {
                return -EFAULT;
            }
            let mut total = 0i64;
            for i in 0..iovcnt {
                let iov = unsafe { *iov_ptr.add(i) };
                if iov.iov_len == 0 {
                    continue;
                }
                if !crate::memory::vm::prefault_current(iov.iov_base, iov.iov_len, true) {
                    return if total > 0 { total } else { -EFAULT };
                }
                let slice = unsafe { core::slice::from_raw_parts_mut(iov.iov_base as *mut u8, iov.iov_len as usize) };
                let res = crate::task::with_current_fds_mut(|fds| match fds.get_mut(fd) {
                    Some(desc) => desc.read(slice).map(|n| n as i64).unwrap_or(-EIO),
                    None => -EBADF,
                });
                if res < 0 {
                    return if total > 0 { total } else { res };
                }
                total += res;
                if (res as u64) < iov.iov_len {
                    break;
                }
            }
            total
        }

        SYS_PREAD64 | SYS_PWRITE64 => {
            // sys_pread64/pwrite64(fd: int, buf: void*, count: size_t, offset: loff_t)
            let fd = arg0 as usize;
            let count = arg2 as usize;
            let offset = arg3 as usize;
            let is_read = num == SYS_PREAD64;
            if count == 0 {
                return 0;
            }
            if !crate::memory::vm::prefault_current(arg1, count as u64, is_read) {
                return -EFAULT;
            }
            crate::task::with_current_fds_mut(|fds| match fds.get_mut(fd) {
                Some(desc) => {
                    let res = if is_read {
                        desc.pread(unsafe { core::slice::from_raw_parts_mut(arg1 as *mut u8, count) }, offset)
                    } else {
                        desc.pwrite(unsafe { core::slice::from_raw_parts(arg1 as *const u8, count) }, offset)
                    };
                    match res {
                        Ok(n) => n as i64,
                        Err(_) => -ESPIPE,
                    }
                }
                None => -EBADF,
            })
        }

        SYS_WRITEV => {
            // sys_writev(fd: int, iov: const struct iovec*, iovcnt: int)
            let fd = arg0 as usize;
            let iov_ptr = arg1 as *const LinuxIovec;
            let iovcnt = arg2 as usize;
            if iov_ptr.is_null() && iovcnt > 0 {
                return -EFAULT;
            }

            if !crate::memory::vm::prefault_current(iov_ptr as u64, (iovcnt * core::mem::size_of::<LinuxIovec>()) as u64, false) {
                return -EFAULT;
            }
            let mut total_written = 0i64;
            for i in 0..iovcnt {
                let iov = unsafe { *iov_ptr.add(i) };
                if !crate::memory::vm::prefault_current(iov.iov_base, iov.iov_len, false) {
                    return if total_written > 0 { total_written } else { -EFAULT };
                }
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

            // pipe2 flags: O_NONBLOCK (0o4000), O_CLOEXEC (0o2000000)
            let flags = if num == SYS_PIPE2 { arg1 } else { 0 };
            let pipe = crate::fs::PipeBuffer::new();
            {
                let mut p = pipe.lock();
                p.read_nonblock = flags & 0o4000 != 0;
                p.write_nonblock = flags & 0o4000 != 0;
            }
            let read_desc = crate::fs::FileDescriptor::PipeRead(pipe.clone());
            let write_desc = crate::fs::FileDescriptor::PipeWrite(pipe);

            crate::task::with_current_fds_mut(|fds| {
                match fds.alloc_fd(read_desc) {
                    Ok(rfd) => match fds.alloc_fd(write_desc) {
                        Ok(wfd) => {
                            if flags & 0o2000000 != 0 {
                                fds.set_cloexec(rfd, true);
                                fds.set_cloexec(wfd, true);
                            }
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

        SYS_SOCKET => {
            // sys_socket(domain: int, type: int, protocol: int)
            let domain = arg0 as u32;
            let sock_type = arg1 as u32;
            let _protocol = arg2 as u32;

            if domain != AF_UNIX && domain != AF_LOCAL {
                return -EAFNOSUPPORT;
            }

            let nonblock = (sock_type & SOCK_NONBLOCK) != 0;
            let sock = UnixSocket::new(domain, sock_type, nonblock);
            let desc = crate::fs::FileDescriptor::Socket(sock);

            crate::task::with_current_fds_mut(|fds| {
                fds.alloc_fd(desc).map(|fd| fd as i64).unwrap_or(-EMFILE)
            })
        }

        SYS_BIND => {
            // sys_bind(sockfd: int, addr: const struct sockaddr*, addrlen: socklen_t)
            let fd = arg0 as usize;
            let addr_ptr = arg1 as *const LinuxSockaddrUn;
            let addrlen = arg2 as usize;

            if addr_ptr.is_null() || addrlen < 2 {
                return -EFAULT;
            }

            let addr: LinuxSockaddrUn = unsafe { core::ptr::read_unaligned(addr_ptr) };
            if addr.sun_family as u32 != AF_UNIX && addr.sun_family as u32 != AF_LOCAL {
                return -EAFNOSUPPORT;
            }

            let path = match read_sockaddr_path(&addr.sun_path) {
                Some(p) => p,
                None => return -EINVAL,
            };

            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                    let sock_clone = sock.clone();
                    UnixSocket::bind(&sock_clone, &path)
                } else {
                    Err(-EBADF)
                }
            });
            match res {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        SYS_LISTEN => {
            // sys_listen(sockfd: int, backlog: int)
            let fd = arg0 as usize;
            let backlog = arg1 as usize;

            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                    sock.lock().listen(backlog)
                } else {
                    Err(-EBADF)
                }
            });
            match res {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        SYS_ACCEPT | SYS_ACCEPT4 => {
            // sys_accept(sockfd: int, addr: struct sockaddr*, addrlen: socklen_t*)
            // sys_accept4(sockfd: int, addr: struct sockaddr*, addrlen: socklen_t*, flags: int)
            let fd = arg0 as usize;
            let addr_ptr = arg1 as *mut LinuxSockaddrUn;
            let addrlen_ptr = arg2 as *mut u32;
            let flags = if num == SYS_ACCEPT4 { arg3 as u32 } else { 0 };
            let nonblock = (flags & SOCK_NONBLOCK) != 0;

            let sock = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(s)) = fds.get(fd) {
                    Some(s.clone())
                } else {
                    None
                }
            });

            let sock = match sock {
                Some(s) => s,
                None => return -EBADF,
            };

            let client_sock = match sock.lock().accept(nonblock) {
                Ok(c) => c,
                Err(err) => return err,
            };

            if !addr_ptr.is_null() {
                unsafe {
                    let mut un = LinuxSockaddrUn::default();
                    un.sun_family = AF_UNIX as u16;
                    *addr_ptr = un;
                    if !addrlen_ptr.is_null() {
                        *addrlen_ptr = 2; // sizeof(sun_family)
                    }
                }
            }

            let desc = crate::fs::FileDescriptor::Socket(client_sock);
            crate::task::with_current_fds_mut(|fds| {
                fds.alloc_fd(desc).map(|newfd| newfd as i64).unwrap_or(-EMFILE)
            })
        }

        SYS_CONNECT => {
            // sys_connect(sockfd: int, addr: const struct sockaddr*, addrlen: socklen_t)
            let fd = arg0 as usize;
            let addr_ptr = arg1 as *const LinuxSockaddrUn;
            let addrlen = arg2 as usize;

            if addr_ptr.is_null() || addrlen < 2 {
                return -EFAULT;
            }

            let addr: LinuxSockaddrUn = unsafe { core::ptr::read_unaligned(addr_ptr) };
            if addr.sun_family as u32 != AF_UNIX && addr.sun_family as u32 != AF_LOCAL {
                return -EAFNOSUPPORT;
            }

            let path = match read_sockaddr_path(&addr.sun_path) {
                Some(p) => p,
                None => return -EINVAL,
            };

            if path == "/run/user/1000/wayland-0" || path == "wayland-0" {
                ensure_wayland_bridge();
            }

            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                    sock.lock().connect(&path)
                } else {
                    Err(-EBADF)
                }
            });
            if res.is_ok() && (path == "/run/user/1000/wayland-0" || path == "wayland-0") {
                dispatch_wayland_events();
            }
            match res {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        SYS_SOCKETPAIR => {
            // sys_socketpair(domain: int, type: int, protocol: int, sv: int[2])
            let domain = arg0 as u32;
            let sock_type = arg1 as u32;
            let _protocol = arg2 as u32;
            let sv_ptr = arg3 as *mut [i32; 2];

            if sv_ptr.is_null() {
                return -EFAULT;
            }

            if domain != AF_UNIX && domain != AF_LOCAL {
                return -EAFNOSUPPORT;
            }

            let nonblock = (sock_type & SOCK_NONBLOCK) != 0;
            let (sock_a, sock_b) = UnixSocket::pair(sock_type, nonblock);

            let desc_a = crate::fs::FileDescriptor::Socket(sock_a);
            let desc_b = crate::fs::FileDescriptor::Socket(sock_b);

            crate::task::with_current_fds_mut(|fds| {
                match fds.alloc_fd(desc_a) {
                    Ok(fd_a) => match fds.alloc_fd(desc_b) {
                        Ok(fd_b) => {
                            unsafe {
                                (*sv_ptr)[0] = fd_a as i32;
                                (*sv_ptr)[1] = fd_b as i32;
                            }
                            0
                        }
                        Err(_) => {
                            let _ = fds.close(fd_a);
                            -EMFILE
                        }
                    },
                    Err(_) => -EMFILE,
                }
            })
        }

        SYS_SENDTO => {
            // sys_sendto(sockfd: int, buf: const void*, len: size_t, flags: int, dest_addr: const struct sockaddr*, addrlen: socklen_t)
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
            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(fd) {
                    match desc.write(slice) {
                        Ok(n) => n as i64,
                        Err(_) => -EIO,
                    }
                } else {
                    -EBADF
                }
            });
            if res > 0 {
                dispatch_wayland_events();
            }
            res
        }

        SYS_RECVFROM => {
            // sys_recvfrom(sockfd: int, buf: void*, len: size_t, flags: int, src_addr: struct sockaddr*, addrlen: socklen_t*)
            let fd = arg0 as usize;
            let ptr = arg1 as *mut u8;
            let count = arg2 as usize;
            if ptr.is_null() && count > 0 {
                return -EFAULT;
            }
            if count == 0 {
                return 0;
            }
            dispatch_wayland_events();
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

        SYS_SENDMSG => {
            // sys_sendmsg(sockfd: int, msg: const struct msghdr*, flags: int)
            let fd = arg0 as usize;
            let msg_ptr = arg1 as *const LinuxMsghdr;
            if msg_ptr.is_null() {
                return -EFAULT;
            }
            let msg = unsafe { *msg_ptr };

            // 1. Process SCM_RIGHTS ancillary data if present
            if !msg.msg_control.is_null() && msg.msg_controllen >= 16 {
                let cmsg = unsafe { *(msg.msg_control as *const LinuxCmsghdr) };
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
                    let num_fds = cmsg.cmsg_len.saturating_sub(16) / 4;
                    let fd_array = unsafe { msg.msg_control.add(16) as *const i32 };
                    for i in 0..num_fds {
                        let target_fd = unsafe { *fd_array.add(i) } as usize;
                        let desc_clone = crate::task::with_current_fds_mut(|fds| {
                            fds.get(target_fd).cloned()
                        });
                        if let Some(desc) = desc_clone {
                            let _ = crate::task::with_current_fds_mut(|fds| {
                                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                                    sock.lock().push_ancillary_fd(desc)
                                } else {
                                    Err("Not a socket")
                                }
                            });
                        }
                    }
                }
            }

            // 2. Transmit payload data buffers from msg_iov
            let mut total_sent = 0;
            if !msg.msg_iov.is_null() && msg.msg_iovlen > 0 {
                for i in 0..msg.msg_iovlen {
                    let iov = unsafe { *msg.msg_iov.add(i) };
                    if iov.iov_base != 0 && iov.iov_len > 0 {
                        let slice = unsafe { core::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len as usize) };
                        let sent = crate::task::with_current_fds_mut(|fds| {
                            if let Some(desc) = fds.get_mut(fd) {
                                desc.write(slice).map(|n| n as i64).unwrap_or(-EIO)
                            } else {
                                -EBADF
                            }
                        });
                        if sent < 0 {
                            return sent;
                        }
                        total_sent += sent;
                    }
                }
            }
            if total_sent > 0 {
                dispatch_wayland_events();
            }
            total_sent
        }

        SYS_RECVMSG => {
            // sys_recvmsg(sockfd: int, msg: struct msghdr*, flags: int)
            let fd = arg0 as usize;
            let msg_ptr = arg1 as *mut LinuxMsghdr;
            if msg_ptr.is_null() {
                return -EFAULT;
            }
            let msg = unsafe { *msg_ptr };
            dispatch_wayland_events();

            // 1. Receive incoming ancillary data (SCM_RIGHTS) if requested
            if !msg.msg_control.is_null() && msg.msg_controllen >= 20 {
                let incoming_desc = crate::task::with_current_fds_mut(|fds| {
                    if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                        sock.lock().pop_ancillary_fd()
                    } else {
                        None
                    }
                });

                if let Some(desc) = incoming_desc {
                    let new_fd = crate::task::with_current_fds_mut(|fds| {
                        fds.alloc_fd(desc).map(|f| f as i32).unwrap_or(-1)
                    });
                    if new_fd >= 0 {
                        unsafe {
                            let cmsg_ptr = msg.msg_control as *mut LinuxCmsghdr;
                            *cmsg_ptr = LinuxCmsghdr {
                                cmsg_len: 20,
                                cmsg_level: SOL_SOCKET,
                                cmsg_type: SCM_RIGHTS,
                            };
                            let fd_dest = msg.msg_control.add(16) as *mut i32;
                            *fd_dest = new_fd;
                            (*msg_ptr).msg_controllen = 20;
                        }
                    }
                } else {
                    unsafe {
                        (*msg_ptr).msg_controllen = 0;
                    }
                }
            }

            // 2. Read incoming payload data into msg_iov
            let mut total_recv = 0;
            if !msg.msg_iov.is_null() && msg.msg_iovlen > 0 {
                for i in 0..msg.msg_iovlen {
                    let iov = unsafe { *msg.msg_iov.add(i) };
                    if iov.iov_base != 0 && iov.iov_len > 0 {
                        let slice = unsafe { core::slice::from_raw_parts_mut(iov.iov_base as *mut u8, iov.iov_len as usize) };
                        let recvd = crate::task::with_current_fds_mut(|fds| {
                            if let Some(desc) = fds.get_mut(fd) {
                                desc.read(slice).map(|n| n as i64).unwrap_or(-EIO)
                            } else {
                                -EBADF
                            }
                        });
                        if recvd < 0 {
                            return recvd;
                        }
                        total_recv += recvd;
                    }
                }
            }
            total_recv
        }

        SYS_SHUTDOWN => {
            // sys_shutdown(sockfd: int, how: int)
            let fd = arg0 as usize;
            let how = arg1 as u32;

            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                    sock.lock().shutdown(how)
                } else {
                    Err(-EBADF)
                }
            });
            match res {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        SYS_GETSOCKNAME | SYS_GETPEERNAME => {
            // sys_getsockname(sockfd: int, addr: struct sockaddr*, addrlen: socklen_t*)
            // sys_getpeername(sockfd: int, addr: struct sockaddr*, addrlen: socklen_t*)
            let fd = arg0 as usize;
            let addr_ptr = arg1 as *mut LinuxSockaddrUn;
            let addrlen_ptr = arg2 as *mut u32;

            if addr_ptr.is_null() || addrlen_ptr.is_null() {
                return -EFAULT;
            }

            crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Socket(sock)) = fds.get(fd) {
                    let s = sock.lock();
                    let mut un = LinuxSockaddrUn::default();
                    un.sun_family = AF_UNIX as u16;
                    let path_str = match &s.role {
                        UnixSocketRole::Bound(p) => p.as_str(),
                        UnixSocketRole::Listening { path, .. } => path.as_str(),
                        UnixSocketRole::Connected { peer_path, .. } => peer_path.as_str(),
                        _ => "",
                    };
                    let bytes = path_str.as_bytes();
                    let copy_len = bytes.len().min(107);
                    un.sun_path[..copy_len].copy_from_slice(&bytes[..copy_len]);
                    un.sun_path[copy_len] = 0;
                    unsafe {
                        *addr_ptr = un;
                        *addrlen_ptr = (2 + copy_len + 1) as u32;
                    }
                    0
                } else {
                    -EBADF
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
            match crate::task::SCHEDULER.lock().spawn_clone(frame, [arg0, arg1, arg2, arg3, arg4]) {
                Ok(child_id) => child_id.0 as i64,
                Err(_) => -ENOMEM,
            }
        }

        SYS_EXIT => {
            crate::task::exit();
        }

        SYS_EXIT_GROUP => {
            crate::task::exit_group();
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

        SYS_FTRUNCATE => {
            // sys_ftruncate(fd: int, length: off_t)
            let fd = arg0 as usize;
            let length = arg1 as usize;
            let res = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::MemFd(m)) = fds.get(fd) {
                    m.lock().truncate(length);
                    Ok(0)
                } else if let Some(crate::fs::FileDescriptor::File { .. }) = fds.get(fd) {
                    Ok(0)
                } else {
                    Err(-EBADF)
                }
            });
            match res {
                Ok(v) => v,
                Err(e) => e,
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
                if !crate::memory::vm::prefault_current(arg0, 16, true) {
                    return -EFAULT;
                }
                let (s, ns) = crate::arch::rtc::now();
                let (secs, usecs) = (s as i64, (ns / 1000) as i64);
                unsafe {
                    (*tv_ptr).tv_sec = secs;
                    (*tv_ptr).tv_usec = usecs;
                }
            }
            0
        }

        SYS_GETUID => {
            crate::task::with_current_task_mut(|t| t.uid as i64).unwrap_or(0)
        }
        SYS_GETGID => {
            crate::task::with_current_task_mut(|t| t.gid as i64).unwrap_or(0)
        }
        SYS_GETEUID => {
            crate::task::with_current_task_mut(|t| t.euid as i64).unwrap_or(0)
        }
        SYS_GETEGID => {
            crate::task::with_current_task_mut(|t| t.egid as i64).unwrap_or(0)
        }

        SYS_SETUID => {
            // sys_setuid(uid: uid_t)
            let new_uid = arg0 as u32;
            crate::task::with_current_task_mut(|t| {
                let old = (t.uid, t.euid, t.suid);
                if t.caps.has(crate::task::tcb::Caps::SETUID) {
                    // Privileged: set real, effective, and saved-set UID
                    t.uid = new_uid;
                    t.euid = new_uid;
                    t.suid = new_uid;
                } else if new_uid == t.uid || new_uid == t.suid {
                    // Unprivileged: can only switch effective UID to real or saved UID
                    t.euid = new_uid;
                } else {
                    return -EPERM;
                }
                let new = (t.uid, t.euid, t.suid);
                t.caps.on_uid_change(old, new);
                0
            }).unwrap_or(-EPERM)
        }

        SYS_SETGID => {
            // sys_setgid(gid: gid_t)
            let new_gid = arg0 as u32;
            crate::task::with_current_task_mut(|t| {
                if t.caps.has(crate::task::tcb::Caps::SETGID) {
                    // Privileged: set real, effective, and saved-set GID
                    t.gid = new_gid;
                    t.egid = new_gid;
                    t.sgid = new_gid;
                    0
                } else if new_gid == t.gid || new_gid == t.sgid {
                    // Unprivileged: can only switch effective GID to real or saved GID
                    t.egid = new_gid;
                    0
                } else {
                    -EPERM
                }
            }).unwrap_or(-EPERM)
        }

        SYS_SETREUID => {
            // sys_setreuid(ruid: uid_t, euid: uid_t)
            let ruid = arg0 as u32;
            let euid = arg1 as u32;
            crate::task::with_current_task_mut(|t| {
                let is_root = t.caps.has(crate::task::tcb::Caps::SETUID);
                let old = (t.uid, t.euid, t.suid);
                let ok_r = ruid == u32::MAX || is_root || ruid == t.uid || ruid == t.euid;
                let ok_e = euid == u32::MAX || is_root || euid == t.uid || euid == t.euid || euid == t.suid;
                if !ok_r || !ok_e {
                    return -EPERM;
                }
                if ruid != u32::MAX {
                    t.uid = ruid;
                }
                if euid != u32::MAX {
                    t.euid = euid;
                }
                if ruid != u32::MAX || (euid != u32::MAX && euid != t.uid) {
                    t.suid = t.euid;
                }
                let new = (t.uid, t.euid, t.suid);
                t.caps.on_uid_change(old, new);
                0
            }).unwrap_or(-EPERM)
        }

        SYS_SETREGID => {
            // sys_setregid(rgid: gid_t, egid: gid_t)
            let rgid = arg0 as u32;
            let egid = arg1 as u32;
            crate::task::with_current_task_mut(|t| {
                let is_root = t.caps.has(crate::task::tcb::Caps::SETGID);
                let ok_r = rgid == u32::MAX || is_root || rgid == t.gid || rgid == t.egid;
                let ok_e = egid == u32::MAX || is_root || egid == t.gid || egid == t.egid || egid == t.sgid;
                if !ok_r || !ok_e {
                    return -EPERM;
                }
                if rgid != u32::MAX {
                    t.gid = rgid;
                }
                if egid != u32::MAX {
                    t.egid = egid;
                }
                if rgid != u32::MAX || (egid != u32::MAX && egid != t.gid) {
                    t.sgid = t.egid;
                }
                0
            }).unwrap_or(-EPERM)
        }

        SYS_SETRESUID => {
            // sys_setresuid(ruid: uid_t, euid: uid_t, suid: uid_t)
            let ruid = arg0 as u32;
            let euid = arg1 as u32;
            let suid = arg2 as u32;
            crate::task::with_current_task_mut(|t| {
                let is_root = t.caps.has(crate::task::tcb::Caps::SETUID);
                let old = (t.uid, t.euid, t.suid);
                let ok_r = ruid == u32::MAX || is_root || ruid == t.uid || ruid == t.euid || ruid == t.suid;
                let ok_e = euid == u32::MAX || is_root || euid == t.uid || euid == t.euid || euid == t.suid;
                let ok_s = suid == u32::MAX || is_root || suid == t.uid || suid == t.euid || suid == t.suid;
                if !ok_r || !ok_e || !ok_s {
                    return -EPERM;
                }
                if ruid != u32::MAX { t.uid = ruid; }
                if euid != u32::MAX { t.euid = euid; }
                if suid != u32::MAX { t.suid = suid; }
                let new = (t.uid, t.euid, t.suid);
                t.caps.on_uid_change(old, new);
                0
            }).unwrap_or(-EPERM)
        }

        SYS_GETRESUID => {
            // sys_getresuid(ruid: uid_t*, euid: uid_t*, suid: uid_t*)
            let ruid_p = arg0 as *mut u32;
            let euid_p = arg1 as *mut u32;
            let suid_p = arg2 as *mut u32;
            crate::task::with_current_task_mut(|t| {
                unsafe {
                    if !ruid_p.is_null() { *ruid_p = t.uid; }
                    if !euid_p.is_null() { *euid_p = t.euid; }
                    if !suid_p.is_null() { *suid_p = t.suid; }
                }
                0
            }).unwrap_or(-EFAULT)
        }

        SYS_SETRESGID => {
            // sys_setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t)
            let rgid = arg0 as u32;
            let egid = arg1 as u32;
            let sgid = arg2 as u32;
            crate::task::with_current_task_mut(|t| {
                let is_root = t.caps.has(crate::task::tcb::Caps::SETGID);
                let ok_r = rgid == u32::MAX || is_root || rgid == t.gid || rgid == t.egid || rgid == t.sgid;
                let ok_e = egid == u32::MAX || is_root || egid == t.gid || egid == t.egid || egid == t.sgid;
                let ok_s = sgid == u32::MAX || is_root || sgid == t.gid || sgid == t.egid || sgid == t.sgid;
                if !ok_r || !ok_e || !ok_s {
                    return -EPERM;
                }
                if rgid != u32::MAX { t.gid = rgid; }
                if egid != u32::MAX { t.egid = egid; }
                if sgid != u32::MAX { t.sgid = sgid; }
                0
            }).unwrap_or(-EPERM)
        }

        SYS_GETRESGID => {
            // sys_getresgid(rgid: gid_t*, egid: gid_t*, sgid: gid_t*)
            let rgid_p = arg0 as *mut u32;
            let egid_p = arg1 as *mut u32;
            let sgid_p = arg2 as *mut u32;
            crate::task::with_current_task_mut(|t| {
                unsafe {
                    if !rgid_p.is_null() { *rgid_p = t.gid; }
                    if !egid_p.is_null() { *egid_p = t.egid; }
                    if !sgid_p.is_null() { *sgid_p = t.sgid; }
                }
                0
            }).unwrap_or(-EFAULT)
        }

        SYS_CAPGET => {
            // sys_capget(hdrp: cap_user_header_t, datap: cap_user_data_t)
            let datap = arg1 as *mut u32;
            crate::task::with_current_task_mut(|t| {
                let is_root = t.euid == 0;
                let cap_mask = if is_root { 0xFFFF_FFFFu32 } else { 0u32 };
                if !datap.is_null() {
                    unsafe {
                        *datap = cap_mask;
                        *datap.add(1) = cap_mask;
                        *datap.add(2) = 0;
                    }
                }
                0
            }).unwrap_or(0)
        }

        SYS_CAPSET => {
            crate::task::with_current_task_mut(|t| {
                if t.euid == 0 {
                    0
                } else {
                    -EPERM
                }
            }).unwrap_or(-EPERM)
        }

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
            if tp_ptr.is_null() || !crate::memory::vm::prefault_current(arg1, 16, true) {
                return -EFAULT;
            }
            // CLOCK_REALTIME(_COARSE/_ALARM) is wall-clock time; the others count from boot
            let (secs, nsecs) = match arg0 {
                0 | 5 | 8 | 11 => {
                    let (s, ns) = crate::arch::rtc::now();
                    (s as i64, ns as i64)
                }
                _ => {
                    let ticks = crate::arch::pit::ticks();
                    ((ticks / 100) as i64, ((ticks % 100) * 10_000_000) as i64)
                }
            };
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

        SYS_POLL | SYS_PPOLL => {
            // sys_poll(fds: struct pollfd*, nfds: nfds_t, timeout_msecs: int)
            // sys_ppoll(fds: struct pollfd*, nfds: nfds_t, tmo_p: const struct timespec*, sigmask: const sigset_t*)
            let fds_ptr = arg0 as *mut LinuxPollFd;
            let nfds = arg1 as usize;
            let timeout_ms = if num == SYS_PPOLL {
                let ts_ptr = arg2 as *const LinuxTimespec;
                if ts_ptr.is_null() {
                    -1
                } else {
                    let ts = unsafe { *ts_ptr };
                    (ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000) as i32
                }
            } else {
                arg2 as i32
            };

            if fds_ptr.is_null() && nfds > 0 {
                return -EFAULT;
            }
            if nfds == 0 {
                if timeout_ms > 0 {
                    crate::task::sleep_ms(timeout_ms as u64);
                }
                return 0;
            }

            let start_tick = crate::arch::pit::ticks();
            let timeout_ticks = if timeout_ms < 0 {
                u64::MAX
            } else {
                (timeout_ms as u64 + 9) / 10
            };

            let deadline = if timeout_ms < 0 { None } else { Some(start_tick + timeout_ticks) };
            let mut waits = crate::task::wait::WaitSet::new();
            crate::task::with_current_fds_mut(|fds| {
                for i in 0..nfds {
                    let fd = unsafe { (*fds_ptr.add(i)).fd };
                    if fd >= 0 {
                        if let Some(desc) = fds.get(fd as usize) {
                            fds.add_wait_queues_for(desc, &mut waits);
                        }
                    }
                }
            });

            loop {
                waits.register();
                tty::pump();
                crate::net::stack::kick();
                let mut ready_count = 0;
                crate::task::with_current_fds_mut(|fds| {
                    for i in 0..nfds {
                        unsafe {
                            let pfd = &mut *fds_ptr.add(i);
                            pfd.revents = 0;
                            if pfd.fd < 0 {
                                continue;
                            }
                            if let Some(desc) = fds.get(pfd.fd as usize) {
                                let ev = fds.readiness(desc) as i16;
                                let matched = ev & (pfd.events | (EPOLLERR as i16) | (EPOLLHUP as i16));
                                if matched != 0 {
                                    pfd.revents = matched;
                                    ready_count += 1;
                                }
                            } else {
                                pfd.revents = EPOLLNVAL as i16;
                                ready_count += 1;
                            }
                        }
                    }
                });

                if ready_count > 0 || timeout_ms == 0 {
                    return ready_count as i64;
                }

                let elapsed = crate::arch::pit::ticks().saturating_sub(start_tick);
                if elapsed >= timeout_ticks {
                    return 0;
                }
                if proc::signal_pending() {
                    return proc::ERESTARTSYS;
                }
                waits.wait(deadline);
            }
        }

        SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 => {
            // sys_epoll_create(size: int)
            // sys_epoll_create1(flags: int)
            let cloexec = num == SYS_EPOLL_CREATE1 && arg0 as u32 & EPOLL_CLOEXEC != 0;
            let ep = EpollInstance::new();
            let desc = crate::fs::FileDescriptor::Epoll(ep);
            crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(desc) {
                Ok(fd) => {
                    fds.set_cloexec(fd, cloexec);
                    fd as i64
                }
                Err(_) => -EMFILE,
            })
        }

        SYS_EPOLL_CTL => {
            // sys_epoll_ctl(epfd: int, op: int, fd: int, event: struct epoll_event*)
            let epfd = arg0 as usize;
            let op = arg1 as i32;
            let target_fd = arg2 as i32;
            let ev_ptr = arg3 as *const LinuxEpollEvent;

            let ev = if !ev_ptr.is_null() && op != EPOLL_CTL_DEL {
                Some(unsafe { core::ptr::read_unaligned(ev_ptr) })
            } else {
                None
            };

            let epoll_arc = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Epoll(ep)) = fds.get(epfd) {
                    Some(ep.clone())
                } else {
                    None
                }
            });

            let epoll_arc = match epoll_arc {
                Some(ep) => ep,
                None => return -EBADF,
            };

            let res = epoll_arc.lock().ctl(op, target_fd, ev);
            match res {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => {
            // sys_epoll_wait(epfd: int, events: struct epoll_event*, maxevents: int, timeout: int)
            let epfd = arg0 as usize;
            let events_ptr = arg1 as *mut LinuxEpollEvent;
            let maxevents = arg2 as i32;
            let timeout_ms = arg3 as i32;

            if events_ptr.is_null() || maxevents <= 0 {
                return -EINVAL;
            }

            let epoll_arc = crate::task::with_current_fds_mut(|fds| {
                if let Some(crate::fs::FileDescriptor::Epoll(ep)) = fds.get(epfd) {
                    Some(ep.clone())
                } else {
                    None
                }
            });

            let epoll_arc = match epoll_arc {
                Some(ep) => ep,
                None => return -EBADF,
            };

            let start_tick = crate::arch::pit::ticks();
            let timeout_ticks = if timeout_ms < 0 {
                u64::MAX
            } else {
                (timeout_ms as u64 + 9) / 10
            };

            let deadline = if timeout_ms < 0 { None } else { Some(start_tick + timeout_ticks) };
            let waits = epoll_wait_set(&epoll_arc);

            loop {
                waits.register();
                let ready = epoll_collect_ready(&epoll_arc, maxevents as usize);
                if !ready.is_empty() {
                    let count = ready.len();
                    for (i, ev) in ready.into_iter().enumerate() {
                        unsafe {
                            core::ptr::write_unaligned(events_ptr.add(i), ev);
                        }
                    }
                    return count as i64;
                }

                if timeout_ms == 0 {
                    return 0;
                }

                let elapsed = crate::arch::pit::ticks().saturating_sub(start_tick);
                if elapsed >= timeout_ticks {
                    return 0;
                }
                if proc::signal_pending() {
                    return proc::ERESTARTSYS;
                }
                waits.wait(deadline);
            }
        }

        SYS_MEMFD_CREATE => {
            // sys_memfd_create(name: const char*, flags: unsigned int)
            let name_ptr = arg0 as *const u8;
            let _flags = arg1 as u32;
            let name = read_user_string(name_ptr).unwrap_or_else(|| String::from("memfd"));
            let memfd = MemFd::new(&name);
            let desc = crate::fs::FileDescriptor::MemFd(memfd);
            crate::task::with_current_fds_mut(|fds| {
                fds.alloc_fd(desc).map(|fd| fd as i64).unwrap_or(-EMFILE)
            })
        }

        _ => {
            let mut stats = LINUX_STATS.lock();
            stats.unknown_calls += 1;
            drop(stats);
            report_unimplemented(num, [arg0, arg1, arg2]);
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

fn read_sockaddr_path(sun_path: &[u8; 108]) -> Option<String> {
    let mut len = 0;
    while len < sun_path.len() && sun_path[len] != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    core::str::from_utf8(&sun_path[..len]).map(String::from).ok()
}

/// When set, every Linux system call is logged with its arguments and result
/// (`linux trace on|off`).
pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Only trace processes whose executable path contains this text (empty = all).
pub static TRACE_FILTER: Mutex<String> = Mutex::new(String::new());

/// True if the running process passes the trace filter.
pub fn trace_matches_current() -> bool {
    let filter = TRACE_FILTER.lock();
    filter.is_empty() || crate::task::with_current_task_mut(|t| t.exe_path().contains(filter.as_str())).unwrap_or(false)
}

/// Bitmap of syscall numbers already reported as unimplemented (each is logged once).
static REPORTED_ENOSYS: Mutex<[u64; 8]> = Mutex::new([0; 8]);

/// Logs the first use of an unimplemented system call to the console and serial port.
fn report_unimplemented(num: u64, args: [u64; 3]) {
    if num >= 512 {
        crate::kprintln!("[linux] unimplemented syscall {} ({:#x}, {:#x}, {:#x})", num, args[0], args[1], args[2]);
        return;
    }
    let mut seen = REPORTED_ENOSYS.lock();
    let (w, b) = ((num / 64) as usize, num % 64);
    if seen[w] & (1 << b) == 0 {
        seen[w] |= 1 << b;
        drop(seen);
        let pid = crate::task::SCHEDULER.lock().current_task_id().0;
        crate::kprintln!("[linux] pid {}: unimplemented syscall {} ({:#x}, {:#x}, {:#x}) -> ENOSYS", pid, num, args[0], args[1], args[2]);
    }
}

/// Process lifecycle and signal system calls that need the syscall frame.
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Creates a thread or process for `clone`/`clone3` (`args` as `clone` takes them:
/// flags with the exit signal, stack, parent_tid, child_tid, tls) and stores a pidfd for
/// the child at `pidfd_ptr` when asked to.
fn do_clone(frame: &mut SyscallFrame, mut args: [u64; 5], pidfd_ptr: Option<u64>) -> i64 {
    const CLONE_VFORK: u64 = 0x4000;
    args[0] &= !CLONE_PIDFD;
    let child = match crate::task::SCHEDULER.lock().spawn_clone(frame, args) {
        Ok(id) => id.0,
        Err(_) => return -ENOMEM,
    };
    if let Some(ptr) = pidfd_ptr {
        let fd = pidfd::install(child, false) as i32;
        if !crate::memory::vm::prefault_current(ptr, 4, true) {
            return -EFAULT;
        }
        unsafe { core::ptr::write_unaligned(ptr as *mut i32, fd) };
    }
    if args[0] & CLONE_VFORK != 0 {
        // The parent sleeps until the child execs or exits (it borrows our memory)
        while !proc::vfork_released(child) {
            crate::task::sleep_ticks(1);
        }
    }
    child as i64
}

/// `clone3(struct clone_args *, size)`.
fn sys_clone3(frame: &mut SyscallFrame, args_ptr: u64, size: u64) -> i64 {
    // CLONE_ARGS_SIZE_VER0 is 64 bytes; later fields (set_tid, cgroup) must be unused
    if size < 64 || size > 4096 || !crate::memory::vm::prefault_current(args_ptr, size, false) {
        return if size < 64 || size > 4096 { -EINVAL } else { -EFAULT };
    }
    let field = |i: u64| -> u64 {
        if (i + 1) * 8 <= size {
            unsafe { core::ptr::read_unaligned((args_ptr + i * 8) as *const u64) }
        } else {
            0
        }
    };
    let (flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls) =
        (field(0), field(1), field(2), field(3), field(4), field(5), field(6), field(7));
    let (set_tid_size, cgroup) = (field(9), field(10));
    if exit_signal > 64 || set_tid_size != 0 || (flags & CLONE_INTO_CGROUP != 0 && cgroup != 0) {
        return -EINVAL;
    }
    if (stack == 0) != (stack_size == 0) {
        return -EINVAL;
    }
    // The child starts with the top of the given stack
    let sp = if stack != 0 { stack + stack_size } else { 0 };
    let clone_flags = (flags & !(CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) & 0xFFFF_FF00) | exit_signal;
    let pidfd_ptr = if flags & CLONE_PIDFD != 0 { Some(pidfd) } else { None };
    let child = do_clone(frame, [clone_flags, sp, parent_tid, child_tid, tls], pidfd_ptr);
    if child > 0 && flags & CLONE_CLEAR_SIGHAND != 0 {
        proc::reset_handlers(child as u64);
    }
    child
}

fn dispatch_process_calls(frame: &mut SyscallFrame, num: u64, a: [u64; 6]) -> Option<i64> {
    const CLONE_VM: u64 = 0x100;
    const CLONE_VFORK: u64 = 0x4000;
    let fpu = crate::arch::syscall::SYSCALL_FPU.load(core::sync::atomic::Ordering::Acquire);
    Some(match num {
        15 => proc::sys_rt_sigreturn(frame),
        13 => proc::sys_rt_sigaction(a[0], a[1], a[2], a[3]),
        14 => proc::sys_rt_sigprocmask(a[0], a[1], a[2], a[3]),
        127 => proc::sys_rt_sigpending(a[0], a[1]),
        130 => proc::sys_rt_sigsuspend(a[0], a[1]),
        131 => proc::sys_sigaltstack(a[0], a[1]),
        61 => proc::sys_wait4(a[0] as i32 as i64, a[1], a[2], a[3]),
        247 => proc::sys_waitid(a[0], a[1], a[2], a[3]),
        59 => execve::sys_execve(frame, fpu, -100, a[0], a[1], a[2], 0),
        322 => execve::sys_execve(frame, fpu, a[0] as i32 as i64, a[1], a[2], a[3], a[4]),
        56 | 57 | 58 => {
            let args = match num {
                56 => [a[0], a[1], a[2], a[3], a[4]],
                57 => [17, 0, 0, 0, 0],                           // fork: SIGCHLD
                _ => [CLONE_VM | CLONE_VFORK | 17, 0, 0, 0, 0],   // vfork
            };
            // clone(CLONE_PIDFD) stores the pidfd where parent_tid points
            let pidfd_ptr = if num == 56 && args[0] & CLONE_PIDFD != 0 { Some(a[2]) } else { None };
            if pidfd_ptr.is_some() && args[0] & CLONE_PARENT_SETTID != 0 {
                return Some(-EINVAL);
            }
            do_clone(frame, args, pidfd_ptr)
        }
        435 => sys_clone3(frame, a[0], a[1]),
        60 => {
            let (_, pid) = proc::current_ids();
            if proc::PROCS.lock().get(&pid).map_or(false, |p| p.threads_alive() <= 1) {
                proc::set_exit_status(pid, proc::wait_status_exit(a[0] as i32));
            }
            crate::task::exit();
        }
        231 => {
            let (_, pid) = proc::current_ids();
            proc::set_exit_status(pid, proc::wait_status_exit(a[0] as i32));
            crate::task::exit_group();
        }
        _ => return None,
    })
}
