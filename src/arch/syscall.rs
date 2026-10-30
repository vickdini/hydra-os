use core::arch::global_asm;
use spin::Mutex;

// x86_64 Model-Specific Registers for fast system calls
pub const IA32_EFER: u32 = 0xC000_0080;
pub const IA32_STAR: u32 = 0xC000_0081;
pub const IA32_LSTAR: u32 = 0xC000_0082;
pub const IA32_FMASK: u32 = 0xC000_0084;

// Standard Hydra Microkernel System Call Numbers
pub const SYS_YIELD: u64 = 1;
pub const SYS_SLEEP: u64 = 2;
pub const SYS_WRITE: u64 = 3;
pub const SYS_EXIT: u64 = 4;
pub const SYS_GETPID: u64 = 5;
pub const SYS_UPTIME: u64 = 6;
pub const SYS_IPC_SEND: u64 = 7;
pub const SYS_IPC_RECV: u64 = 8;
pub const SYS_OPEN: u64 = 9;
pub const SYS_CLOSE: u64 = 10;
pub const SYS_READ: u64 = 11;
pub const SYS_PIPE: u64 = 12;
pub const SYS_DUP2: u64 = 13;

/// Diagnostic counters for syscall activity.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallStats {
    pub total_calls: u64,
    pub yield_calls: u64,
    pub sleep_calls: u64,
    pub write_calls: u64,
    pub exit_calls: u64,
    pub getpid_calls: u64,
    pub uptime_calls: u64,
    pub ipc_calls: u64,
    pub open_calls: u64,
    pub close_calls: u64,
    pub read_calls: u64,
    pub pipe_calls: u64,
    pub dup2_calls: u64,
    pub unknown_calls: u64,
}

pub static SYSCALL_STATS: Mutex<SyscallStats> = Mutex::new(SyscallStats {
    total_calls: 0,
    yield_calls: 0,
    sleep_calls: 0,
    write_calls: 0,
    exit_calls: 0,
    getpid_calls: 0,
    uptime_calls: 0,
    ipc_calls: 0,
    open_calls: 0,
    close_calls: 0,
    read_calls: 0,
    pipe_calls: 0,
    dup2_calls: 0,
    unknown_calls: 0,
});

/// Architectural register frame passed to the syscall dispatcher.
///
/// Matches the stack layout constructed by `asm_syscall_entry`.
#[repr(C)]
pub struct SyscallFrame {
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rax: u64, // Syscall number on entry, return value on exit
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rip: u64,    // User instruction pointer (saved from RCX)
    pub rflags: u64, // User flags (saved from R11)
    pub rsp: u64,    // User stack pointer
}

/// The kernel stack pointer of the currently active task.
///
/// `asm_syscall_entry` switches RSP to this address immediately upon entering Ring 0.
#[no_mangle]
pub static mut CURRENT_KERNEL_RSP: u64 = 0;

/// Temporary scratch space for preserving user RSP before kernel stack switch.
#[no_mangle]
static mut USER_RSP_SCRATCH: u64 = 0;

/// User FPU state saved by the syscall entry stub for the syscall in progress. Valid until
/// the current syscall yields the CPU; `clone` reads it to give the child the parent's state.
pub static SYSCALL_FPU: core::sync::atomic::AtomicPtr<crate::arch::idt::FpuState> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Updates the active task's kernel stack pointer for syscall stack switching.
pub fn set_kernel_rsp(rsp: u64) {
    unsafe {
        CURRENT_KERNEL_RSP = rsp;
    }
}

/// Reads a 64-bit Model-Specific Register (MSR).
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Writes a 64-bit Model-Specific Register (MSR).
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags)
    );
}

/// Configures CPU Model-Specific Registers for fast x86_64 hardware system calls.
pub fn init() {
    unsafe {
        // 1. Enable SCE (System Call Extensions) in IA32_EFER (bit 0)
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | 1);

        // 2. Configure STAR:
        // Bits [47:32] = 0x0008 (Kernel CS). Kernel SS is automatically CS + 8 = 0x0010.
        // Bits [63:48] = 0x0013 (User CS/SS base). sysretq loads SS = 0x1B (0x13+8), CS = 0x23 (0x13+16).
        let star: u64 = (0x0013u64 << 48) | (0x0008u64 << 32);
        wrmsr(IA32_STAR, star);

        // 3. Configure LSTAR with the entry point address
        extern "C" {
            fn asm_syscall_entry();
        }
        wrmsr(IA32_LSTAR, asm_syscall_entry as *const () as usize as u64);

        // 4. Configure FMASK:
        // Mask Interrupt Flag (IF: 0x200), Trap Flag (TF: 0x100), Direction Flag (DF: 0x400),
        // Nested Task (NT: 0x4000), Alignment Check (AC: 0x40000).
        let fmask: u64 = 0x0004_4700;
        wrmsr(IA32_FMASK, fmask);
    }
}

/// High-level Rust system call dispatcher called by `asm_syscall_entry`.
#[no_mangle]
pub extern "C" fn hydra_syscall_dispatcher(frame: &mut SyscallFrame, fpu: *mut crate::arch::idt::FpuState) {
    SYSCALL_FPU.store(fpu, core::sync::atomic::Ordering::Release);

    // Release address spaces of exited processes (no locks are held at syscall entry)
    crate::memory::vm::reap_retired_mms();

    // Check if active task uses Linux ABI personality
    if crate::task::current_personality() == crate::task::TaskPersonality::Linux {
        // Like Linux, service interrupts (keyboard, timer) while a system call runs; the
        // timer never preempts kernel code outside explicit wait points (see
        // `task::preemptible`), and the entry stub disables interrupts again on return.
        x86_64::instructions::interrupts::enable();
        let tracing = crate::compat::linux::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed);
        let (num, args) = (frame.rax, [frame.rdi, frame.rsi, frame.rdx, frame.r10]);
        if tracing {
            let pid = crate::task::SCHEDULER.lock().current_task_id().0;
            crate::println!("[trace] {} > {}({:#x}, {:#x}, {:#x}, {:#x})", pid, num, args[0], args[1], args[2], args[3]);
        }
        let res = crate::compat::linux::dispatch_linux_syscall(frame);
        if tracing {
            crate::println!("[trace]   = {}", res);
        }
        frame.rax = res as u64;
        crate::compat::linux::proc::deliver_on_syscall_return(frame, fpu, num);
        return;
    }

    let num = frame.rax;
    let arg0 = frame.rdi;
    let arg1 = frame.rsi;
    let _arg2 = frame.rdx;

    let mut stats = SYSCALL_STATS.lock();
    stats.total_calls += 1;

    let result: i64 = match num {
        SYS_YIELD => {
            stats.yield_calls += 1;
            drop(stats);
            crate::task::yield_now();
            0
        }
        SYS_SLEEP => {
            stats.sleep_calls += 1;
            drop(stats);
            crate::task::sleep_ms(arg0);
            0
        }
        SYS_WRITE => {
            stats.write_calls += 1;
            drop(stats);
            // Backward-compatible:
            // If arg0 <= 15: arg0 = fd, arg1 = ptr, arg2 = len
            // If arg0 > 15:  arg0 = ptr, arg1 = len, fd = 1
            let (fd, ptr, len) = if arg0 <= 15 {
                (arg0 as usize, arg1 as *const u8, _arg2 as usize)
            } else {
                (1usize, arg0 as *const u8, arg1 as usize)
            };
            if !ptr.is_null() && len > 0 {
                let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
                crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(fd) {
                        match desc.write(slice) {
                            Ok(n) => n as i64,
                            Err(_) => -5, // -EIO
                        }
                    } else {
                        -9 // -EBADF
                    }
                })
            } else if len == 0 {
                0
            } else {
                -14 // -EFAULT
            }
        }
        SYS_OPEN => {
            stats.open_calls += 1;
            drop(stats);
            // arg0: path pointer (*const u8), arg1: path len (usize), arg2: flags (u64)
            // flags: 0 = O_RDONLY, 1 = O_WRONLY (truncate/create), 2 = O_RDWR, 3 = O_APPEND
            let ptr = arg0 as *const u8;
            let len = (arg1 as usize).min(256);
            let flags = _arg2;
            if !ptr.is_null() && len > 0 {
                let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
                if let Ok(path_str) = core::str::from_utf8(slice) {
                    let readable = flags == 0 || flags == 2;
                    let writable = flags == 1 || flags == 2 || flags == 3;
                    let append = flags == 3;

                    // If opening for write/append, ensure file exists (touch)
                    if writable {
                        let _ = crate::fs::ZfsClient::touch_file(path_str);
                    }

                    let desc = crate::fs::FileDescriptor::File {
                        path: alloc::string::String::from(path_str),
                        cursor: 0,
                        readable,
                        writable,
                        append,
                    };

                    crate::task::with_current_fds_mut(|fds| {
                        match fds.alloc_fd(desc) {
                            Ok(fd) => fd as i64,
                            Err(_) => -24, // -EMFILE
                        }
                    })
                } else {
                    -22 // -EINVAL
                }
            } else {
                -14 // -EFAULT
            }
        }
        SYS_CLOSE => {
            stats.close_calls += 1;
            drop(stats);
            // arg0: fd
            let fd = arg0 as usize;
            crate::task::with_current_fds_mut(|fds| {
                match fds.close(fd) {
                    Ok(_) => 0,
                    Err(_) => -9, // -EBADF
                }
            })
        }
        SYS_READ => {
            stats.read_calls += 1;
            drop(stats);
            // arg0: fd, arg1: buf ptr (*mut u8), arg2: count (usize)
            let fd = arg0 as usize;
            let ptr = arg1 as *mut u8;
            let count = (_arg2 as usize).min(65536);
            if !ptr.is_null() && count > 0 {
                let slice = unsafe { core::slice::from_raw_parts_mut(ptr, count) };
                crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(fd) {
                        match desc.read(slice) {
                            Ok(n) => n as i64,
                            Err(_) => -5, // -EIO
                        }
                    } else {
                        -9 // -EBADF
                    }
                })
            } else if count == 0 {
                0
            } else {
                -14 // -EFAULT
            }
        }
        SYS_PIPE => {
            stats.pipe_calls += 1;
            drop(stats);
            // arg0: pointer to [u64; 2] to receive [read_fd, write_fd]
            let pipe_fds_ptr = arg0 as *mut [u64; 2];
            if !pipe_fds_ptr.is_null() {
                let pipe = crate::fs::PipeBuffer::new();
                let read_desc = crate::fs::FileDescriptor::PipeRead(pipe.clone());
                let write_desc = crate::fs::FileDescriptor::PipeWrite(pipe);

                crate::task::with_current_fds_mut(|fds| {
                    match fds.alloc_fd(read_desc) {
                        Ok(rfd) => {
                            match fds.alloc_fd(write_desc) {
                                Ok(wfd) => {
                                    unsafe {
                                        (*pipe_fds_ptr)[0] = rfd as u64;
                                        (*pipe_fds_ptr)[1] = wfd as u64;
                                    }
                                    0
                                }
                                Err(_) => {
                                    let _ = fds.close(rfd);
                                    -24 // -EMFILE
                                }
                            }
                        }
                        Err(_) => -24, // -EMFILE
                    }
                })
            } else {
                -14 // -EFAULT
            }
        }
        SYS_DUP2 => {
            stats.dup2_calls += 1;
            drop(stats);
            // arg0: oldfd, arg1: newfd
            let oldfd = arg0 as usize;
            let newfd = arg1 as usize;
            crate::task::with_current_fds_mut(|fds| {
                match fds.dup2(oldfd, newfd) {
                    Ok(fd) => fd as i64,
                    Err(_) => -9, // -EBADF
                }
            })
        }
        SYS_EXIT => {
            stats.exit_calls += 1;
            drop(stats);
            crate::task::exit();
        }
        SYS_GETPID => {
            stats.getpid_calls += 1;
            drop(stats);
            crate::task::SCHEDULER.lock().current_task_id().0 as i64
        }
        SYS_UPTIME => {
            stats.uptime_calls += 1;
            drop(stats);
            crate::arch::pit::ticks() as i64
        }
        SYS_IPC_SEND => {
            stats.ipc_calls += 1;
            drop(stats);
            // arg0: endpoint_id, arg1: pointer to Message, arg2: flags (0 = non-blocking, 1 = blocking)
            let ep_id = arg0 as u32;
            let msg_ptr = arg1 as *const crate::ipc::Message;
            let blocking = (_arg2 & 1) != 0;
            if !msg_ptr.is_null() {
                if let Some(ep) = crate::ipc::endpoint::get_system_endpoint(ep_id) {
                    let msg = unsafe { *msg_ptr };
                    if blocking {
                        ep.send_blocking(msg);
                        0
                    } else {
                        match ep.send(msg) {
                            Ok(_) => 0,
                            Err(_) => -11, // -EAGAIN
                        }
                    }
                } else {
                    -22 // -EINVAL (unknown endpoint)
                }
            } else {
                -14 // -EFAULT
            }
        }
        SYS_IPC_RECV => {
            stats.ipc_calls += 1;
            drop(stats);
            // arg0: endpoint_id, arg1: pointer to output Message, arg2: flags (0 = non-blocking, 1 = blocking)
            let ep_id = arg0 as u32;
            let msg_ptr = arg1 as *mut crate::ipc::Message;
            let blocking = (_arg2 & 1) != 0;
            if !msg_ptr.is_null() {
                if let Some(ep) = crate::ipc::endpoint::get_system_endpoint(ep_id) {
                    if blocking {
                        let msg = ep.receive_blocking();
                        unsafe { *msg_ptr = msg; }
                        0
                    } else {
                        if let Some(msg) = ep.receive() {
                            unsafe { *msg_ptr = msg; }
                            0
                        } else {
                            -11 // -EAGAIN
                        }
                    }
                } else {
                    -22 // -EINVAL (unknown endpoint)
                }
            } else {
                -14 // -EFAULT
            }
        }
        _ => {
            stats.unknown_calls += 1;
            drop(stats);
            -38 // -ENOSYS
        }
    };

    // Store return value in rax
    frame.rax = result as u64;
}

// ---------------------------------------------------------------------------
// Low-Level Syscall Trampoline Assembly
// ---------------------------------------------------------------------------
global_asm!(
    r#"
    .global asm_syscall_entry
    asm_syscall_entry:
        // On syscall entry:
        // RCX = User RIP
        // R11 = User RFLAGS
        // RFLAGS.IF is cleared by FMASK
        // RSP is currently the User RSP

        // 1. Preserve User RSP and switch to Task Kernel Stack
        mov [rip + USER_RSP_SCRATCH], rsp
        mov rsp, [rip + CURRENT_KERNEL_RSP]

        // 2. Build SyscallFrame on kernel stack
        push qword ptr [rip + USER_RSP_SCRATCH] // User RSP
        push r11                                // User RFLAGS
        push rcx                                // User RIP
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        push rax                                // Syscall number
        push rdi                                // Arg 0
        push rsi                                // Arg 1
        push rdx                                // Arg 2
        push r10                                // Arg 3
        push r8                                 // Arg 4
        push r9                                 // Arg 5

        // 3. Save user x87/SSE state (Linux preserves it across syscalls; kernel code uses SSE).
        // RBP (already saved in the frame) keeps the frame pointer across the call.
        mov rbp, rsp
        sub rsp, 512
        and rsp, -16
        fxsave64 [rsp]

        // 4. Call Rust dispatcher: Arg 1 = SyscallFrame, Arg 2 = FPU area (Win64 + SysV)
        mov rcx, rbp
        mov rdi, rbp
        mov rdx, rsp
        mov rsi, rsp
        sub rsp, 32                             // 32-byte Win64 shadow space
        call hydra_syscall_dispatcher
        cli                                     // no interrupts while user state is restored
        add rsp, 32

        fxrstor64 [rsp]
        mov rsp, rbp

        // 5. Restore registers (dispatcher updated rax with return value)
        pop r9
        pop r8
        pop r10
        pop rdx
        pop rsi
        pop rdi
        pop rax                                 // Syscall return value in RAX
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        pop rcx                                 // Restore User RIP into RCX for sysretq
        pop r11                                 // Restore User RFLAGS into R11 for sysretq
        pop rsp                                 // Restore User RSP directly

        // 5. Return to unprivileged Ring 3
        sysretq
    "#
);
