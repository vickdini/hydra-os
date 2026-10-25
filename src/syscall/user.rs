use crate::arch::syscall::*;

/// Invokes an x86_64 system call with 0 arguments.
#[inline(always)]
pub unsafe fn syscall0(num: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Invokes an x86_64 system call with 1 argument.
#[inline(always)]
pub unsafe fn syscall1(num: u64, arg0: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Invokes an x86_64 system call with 2 arguments.
#[inline(always)]
pub unsafe fn syscall2(num: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Invokes an x86_64 system call with 3 arguments.
#[inline(always)]
pub unsafe fn syscall3(num: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

// ---------------------------------------------------------------------------
// Safe Userland System Call Wrappers
// ---------------------------------------------------------------------------

/// Cooperatively relinquishes the remaining timeslice to the scheduler.
pub fn sys_yield() {
    unsafe {
        syscall0(SYS_YIELD);
    }
}

/// Suspends execution of the calling process for `ms` milliseconds.
pub fn sys_sleep(ms: u64) {
    unsafe {
        syscall1(SYS_SLEEP, ms);
    }
}

/// Writes data to a file descriptor (e.g. fd 1 for stdout) via `SYS_WRITE`.
pub fn sys_write(fd: usize, buf: &[u8]) -> Result<usize, i64> {
    let ret = unsafe {
        syscall3(SYS_WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64)
    };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(ret)
    }
}

/// Reads data from a file descriptor (e.g. fd 0 for stdin or a pipe) via `SYS_READ`.
pub fn sys_read(fd: usize, buf: &mut [u8]) -> Result<usize, i64> {
    let ret = unsafe {
        syscall3(SYS_READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
    };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(ret)
    }
}

/// Opens a file in ZFS via `SYS_OPEN`.
/// Flags: 0 = O_RDONLY, 1 = O_WRONLY, 2 = O_RDWR, 3 = O_APPEND.
pub fn sys_open(path: &str, flags: u64) -> Result<usize, i64> {
    let ret = unsafe {
        syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
    };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(ret)
    }
}

/// Closes a file descriptor via `SYS_CLOSE`.
pub fn sys_close(fd: usize) -> Result<(), i64> {
    let ret = unsafe {
        syscall1(SYS_CLOSE, fd as u64)
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Creates an anonymous unidirectional pipe, returning `(read_fd, write_fd)` via `SYS_PIPE`.
pub fn sys_pipe() -> Result<(usize, usize), i64> {
    let mut fds = [0u64; 2];
    let ret = unsafe {
        syscall1(SYS_PIPE, fds.as_mut_ptr() as u64)
    };
    if ret == 0 {
        Ok((fds[0] as usize, fds[1] as usize))
    } else {
        Err(ret)
    }
}

/// Duplicates `oldfd` onto `newfd` via `SYS_DUP2`.
pub fn sys_dup2(oldfd: usize, newfd: usize) -> Result<usize, i64> {
    let ret = unsafe {
        syscall2(SYS_DUP2, oldfd as u64, newfd as u64)
    };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(ret)
    }
}

/// Prints a string slice to the standard output (fd 1) via `SYS_WRITE`.
pub fn sys_print(s: &str) {
    let _ = sys_write(1, s.as_bytes());
}

/// Terminates the calling process permanently via `SYS_EXIT`.
pub fn sys_exit() -> ! {
    unsafe {
        syscall0(SYS_EXIT);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Returns the Task ID (PID) of the current calling process.
pub fn sys_getpid() -> u64 {
    unsafe { syscall0(SYS_GETPID) as u64 }
}

/// Returns the system uptime in PIT timer ticks (100 Hz = 10ms per tick).
pub fn sys_uptime() -> u64 {
    unsafe { syscall0(SYS_UPTIME) as u64 }
}

/// Sends an IPC message to a microkernel endpoint (non-blocking).
pub fn sys_ipc_send(endpoint_id: u32, msg: &crate::ipc::Message) -> Result<(), i64> {
    let res = unsafe {
        syscall3(SYS_IPC_SEND, endpoint_id as u64, msg as *const _ as usize as u64, 0)
    };
    if res >= 0 {
        Ok(())
    } else {
        Err(res)
    }
}

/// Receives an IPC message from a microkernel endpoint (non-blocking).
pub fn sys_ipc_recv(endpoint_id: u32, msg: &mut crate::ipc::Message) -> Result<(), i64> {
    let res = unsafe {
        syscall3(SYS_IPC_RECV, endpoint_id as u64, msg as *mut _ as usize as u64, 0)
    };
    if res >= 0 {
        Ok(())
    } else {
        Err(res)
    }
}

/// Sends an IPC message to a microkernel endpoint, blocking if the queue is full.
pub fn sys_ipc_send_blocking(endpoint_id: u32, msg: &crate::ipc::Message) -> Result<(), i64> {
    let res = unsafe {
        syscall3(SYS_IPC_SEND, endpoint_id as u64, msg as *const _ as usize as u64, 1)
    };
    if res >= 0 {
        Ok(())
    } else {
        Err(res)
    }
}

/// Receives an IPC message from a microkernel endpoint, blocking until a message arrives.
pub fn sys_ipc_recv_blocking(endpoint_id: u32, msg: &mut crate::ipc::Message) -> Result<(), i64> {
    let res = unsafe {
        syscall3(SYS_IPC_RECV, endpoint_id as u64, msg as *mut _ as usize as u64, 1)
    };
    if res >= 0 {
        Ok(())
    } else {
        Err(res)
    }
}
