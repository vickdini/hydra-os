//! # Linux Compatibility: x86_64 System Call Numbers
//!
//! Defines the standard system call numbers for the Linux x86_64 ABI (`arch/x86/entry/syscalls/syscall_64.tbl`).
//! Used by the kernel's Linux ABI compatibility layer to route `syscall` instructions to their respective implementations.
//!
//! ## Architectural Role & Design Rationale
//! The x86_64 Linux ABI passes the system call number in the `rax` register before executing the `syscall`
//! instruction. Centralizing these numeric constants ensures unambiguous dispatch across VFS, process management,
//! networking, and synchronization subsystems while mirroring the upstream Linux kernel syscall table.
//!
//! ## Key Types & Interfaces
//! - `SYS_*`: `u64` constants representing individual Linux x86_64 system call numbers.
//!
//! ## Hardware & Dependency Context
//! - **Architecture**: x86_64 (`SYSCALL`/`SYSRET` instruction pair via `IA32_LSTAR`).
//! - **Dependencies**: None (pure ABI constant definitions).

/// `read(fd, buf, count)` — reads from a file descriptor.
pub const SYS_READ: u64 = 0;
/// `write(fd, buf, count)` — writes to a file descriptor.
pub const SYS_WRITE: u64 = 1;
/// `open(pathname, flags, mode)` — opens and possibly creates a file.
pub const SYS_OPEN: u64 = 2;
/// `close(fd)` — closes a file descriptor.
pub const SYS_CLOSE: u64 = 3;
/// `stat(pathname, statbuf)` — retrieves file status by path.
pub const SYS_STAT: u64 = 4;
/// `fstat(fd, statbuf)` — retrieves file status by file descriptor.
pub const SYS_FSTAT: u64 = 5;
/// `lstat(pathname, statbuf)` — retrieves file status without following symbolic links.
pub const SYS_LSTAT: u64 = 6;
/// `poll(fds, nfds, timeout)` — waits for events on file descriptors.
pub const SYS_POLL: u64 = 7;
/// `lseek(fd, offset, whence)` — repositions read/write file offset.
pub const SYS_LSEEK: u64 = 8;
/// `mmap(addr, length, prot, flags, fd, offset)` — maps files or devices into memory.
pub const SYS_MMAP: u64 = 9;
/// `mprotect(addr, len, prot)` — sets protection on a region of memory.
pub const SYS_MPROTECT: u64 = 10;
/// `munmap(addr, length)` — unmaps files or devices from memory.
pub const SYS_MUNMAP: u64 = 11;
/// `brk(addr)` — changes data segment size (program break).
pub const SYS_BRK: u64 = 12;
/// `rt_sigaction(signum, act, oldact, sigsetsize)` — examines and changes a signal action.
pub const SYS_RT_SIGACTION: u64 = 13;
/// `rt_sigprocmask(how, set, oldset, sigsetsize)` — examines and changes blocked signals.
pub const SYS_RT_SIGPROCMASK: u64 = 14;
/// `rt_sigreturn()` — returns from a signal handler and cleans up the stack frame.
pub const SYS_RT_SIGRETURN: u64 = 15;
/// `ioctl(fd, request, ...)` — manipulates underlying device parameters of special files.
pub const SYS_IOCTL: u64 = 16;
/// `pread64(fd, buf, count, offset)` — reads from a file descriptor at a given offset without changing the file offset.
pub const SYS_PREAD64: u64 = 17;
/// `pwrite64(fd, buf, count, offset)` — writes to a file descriptor at a given offset without changing the file offset.
pub const SYS_PWRITE64: u64 = 18;
/// `readv(fd, iov, iovcnt)` — reads data into multiple buffers (scatter input).
pub const SYS_READV: u64 = 19;
/// `writev(fd, iov, iovcnt)` — writes data from multiple buffers (gather output).
pub const SYS_WRITEV: u64 = 20;
/// `access(pathname, mode)` — checks user's permissions for a file.
pub const SYS_ACCESS: u64 = 21;
/// `pipe(pipefd)` — creates a unidirectional data channel (pipe).
pub const SYS_PIPE: u64 = 22;
/// `select(nfds, readfds, writefds, exceptfds, timeout)` — synchronous I/O multiplexing.
pub const SYS_SELECT: u64 = 23;
/// `sched_yield()` — yields the processor to other runnable threads.
pub const SYS_SCHED_YIELD: u64 = 24;
/// `mremap(old_address, old_size, new_size, flags, new_address)` — expands or shrinks an existing memory mapping.
pub const SYS_MREMAP: u64 = 25;
/// `msync(addr, length, flags)` — synchronizes a file with a memory map.
pub const SYS_MSYNC: u64 = 26;
/// `mincore(addr, length, vec)` — determines whether pages are resident in memory.
pub const SYS_MINCORE: u64 = 27;
/// `madvise(addr, length, advice)` — gives advice about use of memory.
pub const SYS_MADVISE: u64 = 28;
/// `dup(oldfd)` — duplicates an open file descriptor to the lowest-numbered unused descriptor.
pub const SYS_DUP: u64 = 32;
/// `dup2(oldfd, newfd)` — duplicates an open file descriptor to a specified descriptor number.
pub const SYS_DUP2: u64 = 33;
/// `nanosleep(req, rem)` — high-resolution sleep for a specified interval.
pub const SYS_NANOSLEEP: u64 = 35;
/// `getpid()` — returns the thread group ID (process ID) of the calling process.
pub const SYS_GETPID: u64 = 39;
/// `socket(domain, type, protocol)` — creates an endpoint for communication.
pub const SYS_SOCKET: u64 = 41;
/// `connect(sockfd, addr, addrlen)` — initiates a connection on a socket.
pub const SYS_CONNECT: u64 = 42;
/// `accept(sockfd, addr, addrlen)` — accepts a connection on a socket.
pub const SYS_ACCEPT: u64 = 43;
/// `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` — sends a message on a socket.
pub const SYS_SENDTO: u64 = 44;
/// `recvfrom(sockfd, buf, len, flags, src_addr, addrlen)` — receives a message from a socket.
pub const SYS_RECVFROM: u64 = 45;
/// `sendmsg(sockfd, msg, flags)` — sends a message with scatter/gather and ancillary control data on a socket.
pub const SYS_SENDMSG: u64 = 46;
/// `recvmsg(sockfd, msg, flags)` — receives a message with scatter/gather and ancillary control data from a socket.
pub const SYS_RECVMSG: u64 = 47;
/// `shutdown(sockfd, how)` — shuts down part of a full-duplex connection.
pub const SYS_SHUTDOWN: u64 = 48;
/// `bind(sockfd, addr, addrlen)` — binds a name (address) to a socket.
pub const SYS_BIND: u64 = 49;
/// `listen(sockfd, backlog)` — listens for incoming connections on a socket.
pub const SYS_LISTEN: u64 = 50;
/// `getsockname(sockfd, addr, addrlen)` — retrieves the current address to which the socket is bound.
pub const SYS_GETSOCKNAME: u64 = 51;
/// `getpeername(sockfd, addr, addrlen)` — retrieves the address of the peer connected to the socket.
pub const SYS_GETPEERNAME: u64 = 52;
/// `socketpair(domain, type, protocol, sv)` — creates a pair of connected anonymous sockets.
pub const SYS_SOCKETPAIR: u64 = 53;
/// `clone(flags, stack, parent_tid, child_tid, tls)` — creates a child process or thread.
pub const SYS_CLONE: u64 = 56;
/// `fork()` — creates a child process by duplicating the calling process.
pub const SYS_FORK: u64 = 57;
/// `vfork()` — creates a child process and blocks the parent until the child calls `execve` or exits.
pub const SYS_VFORK: u64 = 58;
/// `execve(pathname, argv, envp)` — executes a program, replacing the current process image.
pub const SYS_EXECVE: u64 = 59;
/// `exit(status)` — terminates the calling thread.
pub const SYS_EXIT: u64 = 60;
/// `wait4(pid, wstatus, options, rusage)` — waits for a process to change state and collects resource usage.
pub const SYS_WAIT4: u64 = 61;
/// `kill(pid, sig)` — sends a signal to a process or process group.
pub const SYS_KILL: u64 = 62;
/// `uname(buf)` — retrieves name and information about the current kernel.
pub const SYS_UNAME: u64 = 63;
/// `fcntl(fd, cmd, ...)` — manipulates a file descriptor.
pub const SYS_FCNTL: u64 = 72;
/// `fsync(fd)` — synchronizes a file's in-core state with storage device.
pub const SYS_FSYNC: u64 = 74;
/// `ftruncate(fd, length)` — truncates an open file to a specified length.
pub const SYS_FTRUNCATE: u64 = 77;
/// `getdents(fd, dirp, count)` — reads legacy 32-bit directory entries.
pub const SYS_GETDENTS: u64 = 78;
/// `getcwd(buf, size)` — retrieves the current working directory path.
pub const SYS_GETCWD: u64 = 79;
/// `chdir(path)` — changes the current working directory.
pub const SYS_CHDIR: u64 = 80;
/// `mkdir(pathname, mode)` — creates a directory.
pub const SYS_MKDIR: u64 = 83;
/// `rmdir(pathname)` — deletes an empty directory.
pub const SYS_RMDIR: u64 = 84;
/// `unlink(pathname)` — deletes a name and possibly the file it refers to.
pub const SYS_UNLINK: u64 = 87;
/// `readlink(pathname, buf, bufsiz)` — reads the value of a symbolic link.
pub const SYS_READLINK: u64 = 89;
/// `gettimeofday(tv, tz)` — retrieves the current wall-clock time.
pub const SYS_GETTIMEOFDAY: u64 = 96;
/// `getuid()` — returns the real user ID of the calling process.
pub const SYS_GETUID: u64 = 102;
/// `getgid()` — returns the real group ID of the calling process.
pub const SYS_GETGID: u64 = 104;
/// `setuid(uid)` — sets the effective user ID of the calling process.
pub const SYS_SETUID: u64 = 105;
/// `setgid(gid)` — sets the effective group ID of the calling process.
pub const SYS_SETGID: u64 = 106;
/// `geteuid()` — returns the effective user ID of the calling process.
pub const SYS_GETEUID: u64 = 107;
/// `getegid()` — returns the effective group ID of the calling process.
pub const SYS_GETEGID: u64 = 108;
/// `setreuid(ruid, euid)` — sets real and/or effective user IDs.
pub const SYS_SETREUID: u64 = 113;
/// `setregid(rgid, egid)` — sets real and/or effective group IDs.
pub const SYS_SETREGID: u64 = 114;
/// `getgroups(size, list)` — retrieves supplementary group IDs.
pub const SYS_GETGROUPS: u64 = 115;
/// `setgroups(size, list)` — sets supplementary group IDs.
pub const SYS_SETGROUPS: u64 = 116;
/// `setresuid(ruid, euid, suid)` — sets real, effective, and saved user IDs.
pub const SYS_SETRESUID: u64 = 117;
/// `getresuid(ruid, euid, suid)` — retrieves real, effective, and saved user IDs.
pub const SYS_GETRESUID: u64 = 118;
/// `setresgid(rgid, egid, sgid)` — sets real, effective, and saved group IDs.
pub const SYS_SETRESGID: u64 = 119;
/// `getresgid(rgid, egid, sgid)` — retrieves real, effective, and saved group IDs.
pub const SYS_GETRESGID: u64 = 120;
/// `capget(hdrp, datap)` — retrieves thread capabilities.
pub const SYS_CAPGET: u64 = 125;
/// `capset(hdrp, datap)` — sets thread capabilities.
pub const SYS_CAPSET: u64 = 126;
/// `arch_prctl(code, addr)` — sets architecture-specific thread state (e.g., `FS`/`GS` base registers).
pub const SYS_ARCH_PRCTL: u64 = 158;
/// `gettid()` — returns the caller's thread ID (TID).
pub const SYS_GETTID: u64 = 186;
/// `futex(uaddr, futex_op, val, timeout, uaddr2, val3)` — fast user-space locking primitive.
pub const SYS_FUTEX: u64 = 202;
/// `set_tid_address(tidptr)` — sets pointer to thread ID cleared upon thread exit.
pub const SYS_SET_TID_ADDRESS: u64 = 218;
/// `clock_gettime(clockid, tp)` — retrieves the time of the specified clock.
pub const SYS_CLOCK_GETTIME: u64 = 228;
/// `exit_group(status)` — terminates all threads in the calling process's thread group.
pub const SYS_EXIT_GROUP: u64 = 231;
/// `epoll_create(size)` — opens an epoll file descriptor.
pub const SYS_EPOLL_CREATE: u64 = 213;
/// `epoll_ctl(epfd, op, fd, event)` — control interface for an epoll file descriptor.
pub const SYS_EPOLL_CTL: u64 = 233;
/// `epoll_wait(epfd, events, maxevents, timeout)` — waits for an I/O event on an epoll file descriptor.
pub const SYS_EPOLL_WAIT: u64 = 232;
/// `openat(dirfd, pathname, flags, mode)` — opens a file relative to a directory file descriptor.
pub const SYS_OPENAT: u64 = 257;
/// `mkdirat(dirfd, pathname, mode)` — creates a directory relative to a directory file descriptor.
pub const SYS_MKDIRAT: u64 = 258;
/// `newfstatat(dirfd, pathname, statbuf, flags)` — retrieves file status relative to a directory file descriptor.
pub const SYS_NEWFSTATAT: u64 = 262;
/// `unlinkat(dirfd, pathname, flags)` — deletes a name or directory relative to a directory file descriptor.
pub const SYS_UNLINKAT: u64 = 263;
/// `readlinkat(dirfd, pathname, buf, bufsiz)` — reads value of a symbolic link relative to a directory file descriptor.
pub const SYS_READLINKAT: u64 = 267;
/// `ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)` — waits for events on file descriptors with atomic signal mask replacement.
pub const SYS_PPOLL: u64 = 271;
/// `eventfd(initval)` — creates a legacy file descriptor for event notification.
pub const SYS_EVENTFD: u64 = 284;
/// `epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)` — waits for an I/O event on an epoll file descriptor while atomically updating the signal mask.
pub const SYS_EPOLL_PWAIT: u64 = 281;
/// `accept4(sockfd, addr, addrlen, flags)` — accepts a connection on a socket with flags (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`).
pub const SYS_ACCEPT4: u64 = 288;
/// `eventfd2(initval, flags)` — creates a file descriptor for event notification with flags.
pub const SYS_EVENTFD2: u64 = 290;
/// `epoll_create1(flags)` — opens an epoll file descriptor with flags (`EPOLL_CLOEXEC`).
pub const SYS_EPOLL_CREATE1: u64 = 291;
/// `dup3(oldfd, newfd, flags)` — duplicates a file descriptor with flags (`O_CLOEXEC`).
pub const SYS_DUP3: u64 = 292;
/// `pipe2(pipefd, flags)` — creates a pipe with flags (`O_NONBLOCK`, `O_CLOEXEC`).
pub const SYS_PIPE2: u64 = 293;
/// `getrandom(buf, buflen, flags)` — obtains a series of random bytes from the kernel CSPRNG.
pub const SYS_GETRANDOM: u64 = 318;
/// `memfd_create(name, flags)` — creates an anonymous RAM-backed file and returns a file descriptor referring to it.
pub const SYS_MEMFD_CREATE: u64 = 319;
/// `statx(dirfd, pathname, flags, mask, statxbuf)` — retrieves extended file status information.
pub const SYS_STATX: u64 = 332;
