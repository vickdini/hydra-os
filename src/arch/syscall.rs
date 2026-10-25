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
pub extern "C" fn hydra_syscall_dispatcher(frame: &mut SyscallFrame) {
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
            // arg0: buffer pointer, arg1: length
            let ptr = arg0 as *const u8;
            let len = (arg1 as usize).min(4096);
            if !ptr.is_null() && len > 0 {
                // Safely validate and print slice
                let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
                if let Ok(text) = core::str::from_utf8(slice) {
                    crate::print!("{}", text);
                    len as i64
                } else {
                    -22 // -EINVAL
                }
            } else {
                -14 // -EFAULT
            }
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

        // 3. Call Rust dispatcher
        // Pass pointer to SyscallFrame in both RCX (Win64) and RDI (SysV)
        mov rcx, rsp
        mov rdi, rsp
        sub rsp, 48                             // 32-byte Win64 shadow space + 16-byte alignment
        call hydra_syscall_dispatcher
        add rsp, 48

        // 4. Restore registers (dispatcher updated rax with return value)
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
