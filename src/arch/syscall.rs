//! # Architecture Layer: Fast x86_64 Hardware System Calls (`SYSCALL`/`SYSRET`)
//!
//! Configures CPU Model-Specific Registers (MSRs) for fast long-mode system call transitions
//! and provides the central system call entry point and dual-personality dispatcher.
//!
//! ## Architectural Role & Design Rationale
//!
//! Rather than using legacy software interrupt gates (`int 0x80`), 64-bit x86 CPUs provide the
//! `SYSCALL` instruction for low-latency transitions from Ring 3 to Ring 0. The hardware loads
//! the target RIP from `IA32_LSTAR`, loads CS/SS from `IA32_STAR`, and masks interrupt flags via
//! `IA32_FMASK`.
//!
//! Upon entry, `asm_syscall_entry` switches to the task's kernel stack (TSS RSP0), saves the
//! user registers into a `SyscallFrame`, saves the FPU context, and dispatches to
//! `hydra_syscall_dispatcher`. Depending on [`crate::task::TaskPersonality`], calls are routed
//! to either native Hydra microkernel services (IPC, endpoints, pipes) or the Linux ABI emulation layer.
//!
//! ## Key Types & Interfaces
//!
//! - `SyscallFrame`: Complete register context constructed by assembly entry.
//! - `SyscallStats`: Monotonic counters tracking system call activity.
//! - `init`: Configures `EFER`, `STAR`, `LSTAR`, and `FMASK` MSRs.
//! - `hydra_syscall_dispatcher`: Central Rust dispatcher routing system calls.
//!
//! ## Hardware & Dependency Context
//!
//! - CPU Privilege Level: Transitions from Ring 3 (User) to Ring 0 (Kernel).
//! - MSRs: `IA32_EFER` (0xC0000080), `IA32_STAR` (0xC0000081), `IA32_LSTAR` (0xC0000082), `IA32_FMASK` (0xC0000084).

use core::arch::global_asm;
use spin::Mutex;

/// Extended Feature Enable Register MSR (bit 0 enables SCE — System Call Extensions).
pub const IA32_EFER: u32 = 0xC000_0080;
/// Legacy / Long Mode System Call Target Address and Segment Selectors MSR.
pub const IA32_STAR: u32 = 0xC000_0081;
/// Long Mode System Call Target Instruction Pointer (RIP) MSR.
pub const IA32_LSTAR: u32 = 0xC000_0082;
/// IA32_CSTAR MSR address: `SYSCALL` target from 32-bit compatibility mode (AMD CPUs only).
pub const IA32_CSTAR: u32 = 0xC000_0083;
/// IA32_SYSENTER_CS MSR address: 0 makes `SYSENTER` fault (#GP) in user mode.
pub const IA32_SYSENTER_CS: u32 = 0x174;
/// System Call RFLAGS Mask Register (clears IF, TF, etc. on syscall entry).
pub const IA32_FMASK: u32 = 0xC000_0084;

/// Native Hydra system call: voluntarily yield CPU timeslice (`sys_yield`).
pub const SYS_YIELD: u64 = 1;
/// Native Hydra system call: sleep for milliseconds (`sys_sleep`).
pub const SYS_SLEEP: u64 = 2;
/// Native Hydra system call: write bytes to a file descriptor (`sys_write`).
pub const SYS_WRITE: u64 = 3;
/// Native Hydra system call: terminate the calling task (`sys_exit`).
pub const SYS_EXIT: u64 = 4;
/// Native Hydra system call: retrieve current task ID (`sys_getpid`).
pub const SYS_GETPID: u64 = 5;
/// Native Hydra system call: retrieve monotonic uptime ticks (`sys_uptime`).
pub const SYS_UPTIME: u64 = 6;
/// Native Hydra system call: send IPC message to an endpoint (`sys_ipc_send`).
pub const SYS_IPC_SEND: u64 = 7;
/// Native Hydra system call: receive IPC message from an endpoint (`sys_ipc_recv`).
pub const SYS_IPC_RECV: u64 = 8;
/// Native Hydra system call: open a file descriptor (`sys_open`).
pub const SYS_OPEN: u64 = 9;
/// Native Hydra system call: close a file descriptor (`sys_close`).
pub const SYS_CLOSE: u64 = 10;
/// Native Hydra system call: read bytes from a file descriptor (`sys_read`).
pub const SYS_READ: u64 = 11;
/// Native Hydra system call: create an anonymous unidirectional pipe (`sys_pipe`).
pub const SYS_PIPE: u64 = 12;
/// Native Hydra system call: duplicate a file descriptor (`sys_dup2`).
pub const SYS_DUP2: u64 = 13;
/// Native Hydra system call: let a driver process use I/O ports (`sys_iopl`).
pub const SYS_IOPL: u64 = 20;
/// Native Hydra system call: map device memory granted to a driver (`sys_physmap`).
pub const SYS_PHYSMAP: u64 = 21;
/// Native Hydra system call: allocate physically contiguous DMA memory (`sys_dma_alloc`).
pub const SYS_DMA_ALLOC: u64 = 22;
/// Native Hydra system call: route an interrupt line to a driver (`sys_irq_register`).
pub const SYS_IRQ_REGISTER: u64 = 23;
/// Native Hydra system call: become the server of a driver service (`sys_svc_register`).
pub const SYS_SVC_REGISTER: u64 = 24;
/// Native Hydra system call: wait for the next request to a service (`sys_svc_recv`).
pub const SYS_SVC_RECV: u64 = 25;
/// Native Hydra system call: answer the request being served (`sys_svc_reply`).
pub const SYS_SVC_REPLY: u64 = 26;
/// Native Hydra system call: call another service (`sys_svc_call`).
pub const SYS_SVC_CALL: u64 = 27;
/// Native Hydra system call: map zeroed anonymous memory (`sys_map_anon`).
pub const SYS_MAP_ANON: u64 = 28;
/// Native Hydra system call: wait for an interrupt routed to the driver (`sys_irq_wait`).
pub const SYS_IRQ_WAIT: u64 = 29;
/// Native Hydra system call: unmask a serviced interrupt without waiting (`sys_irq_ack`).
pub const SYS_IRQ_ACK: u64 = 30;
/// Native Hydra system call: wall-clock time (`sys_clock`).
pub const SYS_CLOCK: u64 = 31;
/// Native Hydra system call: map the window of a service the driver uses (`sys_svc_attach`).
pub const SYS_SVC_ATTACH: u64 = 32;
/// Native Hydra system call: the physical segments lent with a request being served
/// (`sys_svc_grant`).
pub const SYS_SVC_GRANT: u64 = 33;
/// Native Hydra system call: call another service lending it pages of the caller
/// (`sys_svc_call_grant`).
pub const SYS_SVC_CALL_GRANT: u64 = 34;
/// Native Hydra system call: a server rings its kernel client's doorbell (`sys_svc_signal`:
/// net-server's sockets changed readiness).
pub const SYS_SVC_SIGNAL: u64 = 35;

/// Native Hydra system call: start a thread in the calling native process (`sys_thread_create`:
/// entry, stack pointer, argument in `rdi`; returns its task ID). Wave 3, the Linux server.
pub const SYS_THREAD_CREATE: u64 = 50;
/// Linux server (`crate::lx`): attach a worker / go online (`sys_lx_ctl`).
pub const SYS_LX_CTL: u64 = 51;
/// Linux server: answer the call served and wait for the next (`sys_lx_reply_recv`).
pub const SYS_LX_REPLY_RECV: u64 = 52;
/// Linux server: answer a pending call (`sys_lx_complete`).
pub const SYS_LX_COMPLETE: u64 = 53;
/// Linux server: copy from the caller of a call (`sys_lx_read`: id, address, length, buffer).
pub const SYS_LX_READ: u64 = 54;
/// Linux server: copy to the caller of a call (`sys_lx_write`: id, address, length, buffer).
pub const SYS_LX_WRITE: u64 = 55;
/// Linux server: copy a string from the caller of a call (`sys_lx_read_str`: id, address,
/// maximum, buffer; returns its length).
pub const SYS_LX_READ_STR: u64 = 56;
/// Linux server: a process's parent and credentials (`sys_lx_proc_info`).
pub const SYS_LX_PROC_INFO: u64 = 57;
/// Linux server (Group 9, wave 4): an operation on its server objects (`crate::lx::obj`).
pub const SYS_LX_OBJ: u64 = 60;
/// Linux server (Group 9, wave 4): queue a signal with its siginfo (`sig_post`).
pub const SYS_LX_SIG: u64 = 61;

/// [`SYS_SVC_CALL_GRANT`]'s argument block (as `hydra_rt::sys::GrantCall`): the request
/// (the reply replaces it), the timeout in ticks (0: the default), and the ranges lent.
#[repr(C)]
#[derive(Clone, Copy)]
struct GrantCall {
    msg: crate::ipc::service::WireMessage,
    timeout: u64,
    /// Ranges used.
    n: u64,
    /// Bit 0: the server writes into the ranges (a device read).
    flags: u64,
    ranges: [[u64; 2]; crate::ipc::service::GRANT_RANGES],
}

/// Diagnostic counters for syscall activity.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallStats {
    /// Total number of system calls dispatched.
    pub total_calls: u64,
    /// Number of `SYS_YIELD` invocations.
    pub yield_calls: u64,
    /// Number of `SYS_SLEEP` invocations.
    pub sleep_calls: u64,
    /// Number of `SYS_WRITE` invocations.
    pub write_calls: u64,
    /// Number of `SYS_EXIT` invocations.
    pub exit_calls: u64,
    /// Number of `SYS_GETPID` invocations.
    pub getpid_calls: u64,
    /// Number of `SYS_UPTIME` invocations.
    pub uptime_calls: u64,
    /// Number of `SYS_IPC_SEND` and `SYS_IPC_RECV` invocations.
    pub ipc_calls: u64,
    /// Number of `SYS_OPEN` invocations.
    pub open_calls: u64,
    /// Number of `SYS_CLOSE` invocations.
    pub close_calls: u64,
    /// Number of `SYS_READ` invocations.
    pub read_calls: u64,
    /// Number of `SYS_PIPE` invocations.
    pub pipe_calls: u64,
    /// Number of `SYS_DUP2` invocations.
    pub dup2_calls: u64,
    /// Number of `SYS_IOPL` invocations.
    pub iopl_calls: u64,
    /// Number of `SYS_PHYSMAP` invocations.
    pub physmap_calls: u64,
    /// Number of `SYS_DMA_ALLOC` invocations.
    pub dma_alloc_calls: u64,
    /// Number of `SYS_IRQ_REGISTER` invocations.
    pub irq_register_calls: u64,
    /// Number of unknown or unsupported syscall numbers invoked.
    pub unknown_calls: u64,
}

/// Global system call invocation statistics instance protected by a spinlock.
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
    iopl_calls: 0,
    physmap_calls: 0,
    dma_alloc_calls: 0,
    irq_register_calls: 0,
    unknown_calls: 0,
});

/// Architectural register frame passed to the syscall dispatcher.
///
/// Matches the stack layout constructed by `asm_syscall_entry`.
#[repr(C)]
pub struct SyscallFrame {
    /// 6th syscall argument register R9.
    pub r9: u64,
    /// 5th syscall argument register R8.
    pub r8: u64,
    /// 4th syscall argument register R10.
    pub r10: u64,
    /// 3rd syscall argument register RDX.
    pub rdx: u64,
    /// 2nd syscall argument register RSI.
    pub rsi: u64,
    /// 1st syscall argument register RDI.
    pub rdi: u64,
    /// Syscall number on entry; return value placed here on exit.
    pub rax: u64,
    /// Callee-saved general-purpose register R15.
    pub r15: u64,
    /// Callee-saved general-purpose register R14.
    pub r14: u64,
    /// Callee-saved general-purpose register R13.
    pub r13: u64,
    /// Callee-saved general-purpose register R12.
    pub r12: u64,
    /// Callee-saved frame/base pointer register RBP.
    pub rbp: u64,
    /// Callee-saved general-purpose register RBX.
    pub rbx: u64,
    /// User instruction pointer (saved from RCX by hardware `SYSCALL`).
    pub rip: u64,
    /// User CPU flags (saved from R11 by hardware `SYSCALL`).
    pub rflags: u64,
    /// User stack pointer restored on `sysretq`.
    pub rsp: u64,
}

/// System calls each CPU has started (the kernel watchdog: a CPU entering new calls is not
/// stuck in one).
pub static SYSCALL_ENTRIES: crate::arch::percpu::PerCpuU64 = crate::arch::percpu::PerCpuU64::new(0);

/// User FPU state saved by the syscall entry stub for the syscall in progress (per CPU).
/// Valid until the current syscall yields the CPU; `clone` reads it to give the child the
/// parent's state.
pub static SYSCALL_FPU: crate::arch::percpu::PerCpuPtr<crate::arch::idt::FpuState> = crate::arch::percpu::PerCpuPtr::new();

/// Updates the active task's kernel stack pointer for syscall stack switching.
///
/// Written by the task scheduler when switching threads so that subsequent Ring 3
/// `syscall` instructions switch to the correct per-thread kernel stack.
///
/// # Arguments
///
/// * `rsp` - Top of the thread's allocated kernel stack page.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn set_kernel_rsp(rsp: u64) {
    crate::arch::percpu::set_kernel_rsp(rsp);
}

/// Reads a 64-bit Model-Specific Register (MSR).
///
/// # Arguments
///
/// * `msr` - The 32-bit architectural MSR address (e.g., `IA32_EFER`, `IA32_LSTAR`).
///
/// # Returns
///
/// The 64-bit value assembled from `EDX:EAX`.
///
/// # Safety
///
/// Reading an invalid or reserved MSR on x86 hardware triggers a General Protection Fault (`#GP`).
/// The caller must ensure the CPU supports the specified MSR index.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
///
/// # Arguments
///
/// * `msr` - The 32-bit architectural MSR address to update.
/// * `value` - The 64-bit value to store into `EDX:EAX`.
///
/// # Safety
///
/// Writing reserved bit combinations or accessing unsupported MSRs causes an unhandled
/// General Protection Fault (`#GP`). Caller must ensure privilege level 0 and valid bitfields.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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
///
/// Programs `IA32_EFER` to enable System Call Extensions (SCE), initializes `IA32_STAR`
/// with GDT selector bases for Ring 0 and Ring 3, configures `IA32_LSTAR` with the
/// assembly entry point `asm_syscall_entry`, and masks interrupts in `IA32_FMASK`.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn init() {
    unsafe {
        // 1. Enable SCE (System Call Extensions) in IA32_EFER (bit 0)
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | 1);

        // 2. Configure STAR:
        // Bits [47:32] = 0x0008 (Kernel CS). Kernel SS is automatically CS + 8 = 0x0010.
        // Bits [63:48] = 0x0023 (user base, Linux's layout). sysretq loads SS = 0x2b (0x23+8)
        // and the 64-bit CS = 0x33 (0x23+16); 0x23 itself is the 32-bit user code segment.
        let star: u64 = ((crate::arch::gdt::USER32_CS as u64) << 48) | ((crate::arch::gdt::KERNEL_CS as u64) << 32);
        wrmsr(IA32_STAR, star);

        // 3. Configure LSTAR with the entry point address
        extern "C" {
            fn asm_syscall_entry();
        }
        wrmsr(IA32_LSTAR, asm_syscall_entry as *const () as usize as u64);

        // 3b. Hydra has no 32-bit system call interface (32-bit code, as Wine's, calls
        // into 64-bit code instead). A SYSCALL from 32-bit code (AMD) returns -ENOSYS
        // as on Linux without IA32 emulation; Intel CPUs raise #UD for it. SYSENTER
        // faults: its code segment is null.
        extern "C" {
            fn asm_syscall32_ignore();
        }
        wrmsr(IA32_CSTAR, asm_syscall32_ignore as *const () as usize as u64);
        wrmsr(IA32_SYSENTER_CS, 0);

        // 4. Configure FMASK:
        // Mask Interrupt Flag (IF: 0x200), Trap Flag (TF: 0x100), Direction Flag (DF: 0x400),
        // Nested Task (NT: 0x4000), Alignment Check (AC: 0x40000).
        let fmask: u64 = 0x0004_4700;
        wrmsr(IA32_FMASK, fmask);
    }
}

/// Reads a [`crate::ipc::service::WireMessage`] from user memory and converts it to a kernel `Message`.
///
/// # Arguments
///
/// * `ptr` - User-space virtual address pointing to a serialized `WireMessage`.
///
/// # Returns
///
/// `Ok(Message)` containing deserialized parameters, or `Err(i64)` with negative errno on bad user pointer.
///
/// # Errors
///
/// Returns `-EFAULT` if `ptr` falls outside valid user address space or triggers a page fault.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn load_wire_message(ptr: u64) -> Result<crate::ipc::Message, i64> {
    let bytes = crate::compat::linux::vfs::copy_in(ptr, core::mem::size_of::<crate::ipc::service::WireMessage>())?;
    let wire = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const crate::ipc::service::WireMessage) };
    Ok(wire.into())
}

/// Writes `msg` to user memory as a [`crate::ipc::service::WireMessage`].
///
/// # Arguments
///
/// * `ptr` - User-space virtual address where the wire message should be stored.
/// * `msg` - The kernel `Message` to serialize into user memory.
///
/// # Returns
///
/// `0` on success, or a negative errno (`-EFAULT`) on failure.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
fn store_wire_message(ptr: u64, msg: crate::ipc::Message) -> i64 {
    let wire = crate::ipc::service::WireMessage::from(msg);
    let bytes = unsafe {
        core::slice::from_raw_parts(&wire as *const _ as *const u8, core::mem::size_of::<crate::ipc::service::WireMessage>())
    };
    crate::compat::linux::vfs::copy_out(ptr, bytes).map_or_else(|e| e, |()| 0)
}

/// High-level Rust system call dispatcher called by `asm_syscall_entry`.
///
/// # Arguments
/// * `frame` - Mutable reference to the saved userland CPU register frame.
/// * `fpu` - Raw pointer to the saved userland FPU/SSE state buffer.
#[no_mangle]
pub extern "C" fn hydra_syscall_dispatcher(frame: &mut SyscallFrame, fpu: *mut crate::arch::idt::FpuState) {
    // A task retired while it ran here (another thread's exit_group) makes no more calls
    if crate::task::current_retired() {
        crate::arch::smp::bkl_enter();
        crate::task::leave_retired();
    }
    // Calls that only read the caller's identity, and private futex wakes, run without
    // the kernel lock
    if let Some(r) = crate::compat::linux::fast_syscall(frame) {
        frame.rax = r as u64;
        // A timer tick that arrived meanwhile (interrupts are off here) is taken now, in
        // kernel mode, so its time counts as the call's (system time) rather than the
        // program's; the tick may have taken the kernel lock, which is not kept
        unsafe { core::arch::asm!("sti", "nop", "cli", options(nomem, nostack)) };
        crate::arch::smp::bkl_exit();
        return;
    }
    // Forwarded Linux calls and the Linux server's answers, without the kernel lock (wave 4:
    // `crate::lx`, "The lock-free path"); anything slow on the way takes the lock itself
    let nr = frame.rax;
    if let Some(done) = crate::lx::fast_entry(frame) {
        let (r, linux) = match done {
            crate::lx::Fast::Call(r) => (r, true),
            crate::lx::Fast::Reply(r) => (r, false),
        };
        frame.rax = r as u64;
        // Retired meanwhile (another thread's exit_group, the crash policy): no return
        if crate::task::current_retired() {
            crate::arch::smp::bkl_enter();
            crate::task::leave_retired();
        }
        // A signal or a stop for the caller: delivered the ordinary way, under the lock
        if linux && crate::lx::delivery_maybe() {
            crate::arch::smp::bkl_enter();
            SYSCALL_FPU.store(fpu, core::sync::atomic::Ordering::Release);
            x86_64::instructions::interrupts::enable();
            crate::compat::linux::proc::deliver_on_syscall_return(frame, fpu, nr);
        }
        x86_64::instructions::interrupts::disable();
        crate::arch::smp::flush_kick();
        crate::arch::smp::bkl_exit();
        return;
    }
    // The kernel runs on one CPU at a time (see arch::smp): held until the return to user
    // mode (the syscall may block and resume on another CPU, which holds it then)
    crate::arch::smp::bkl_enter();
    SYSCALL_ENTRIES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::task::scheduler::wait_out_handoff();
    let nr = frame.rax;
    dispatch(frame, fpu);
    if crate::compat::linux::changes_identity(nr) {
        crate::compat::linux::ident_changed();
    }
    // Retired during the call: no return to user mode
    if crate::task::current_retired() {
        crate::task::leave_retired();
    }
    // Interrupts off first: an interrupt between releasing the lock and the entry stub's
    // `cli` takes the lock again and keeps it (it returns to kernel code), and the CPU
    // would go back to user mode holding it, stalling every other CPU's kernel entry until
    // this one enters the kernel again (up to a timer tick)
    x86_64::instructions::interrupts::disable();
    // A wakeup kick the call deferred: the woken task needs another CPU now
    crate::arch::smp::flush_kick();
    crate::arch::smp::bkl_exit();
}

/// [`hydra_syscall_dispatcher`] under the kernel lock.
fn dispatch(frame: &mut SyscallFrame, fpu: *mut crate::arch::idt::FpuState) {
    SYSCALL_FPU.store(fpu, core::sync::atomic::Ordering::Release);

    // Release what exited processes held: no locks are held at syscall entry, except while
    // a driver serves a call (its caller may hold the file system's lock, which releasing
    // file mappings takes). Not in driver processes either: releasing files calls the file
    // server, which may be the caller itself (ordinary processes do it soon enough)
    if !crate::task::scheduler::handoff_active() && crate::task::current_service().is_none() {
        crate::task::close_retired();
        // Process accounting records of processes that ended
        crate::compat::linux::admin::flush();
        crate::memory::vm::reap_retired_mms();
        crate::task::scheduler::reap_dead_tasks();
    }

    // Check if active task uses Linux ABI personality
    if crate::task::current_personality() == crate::task::TaskPersonality::Linux {
        // Like Linux, service interrupts (keyboard, timer) while a system call runs; the
        // timer never preempts kernel code outside explicit wait points (see
        // `task::preemptible`), and the entry stub disables interrupts again on return.
        x86_64::instructions::interrupts::enable();
        let tracing = crate::compat::linux::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed)
            && crate::compat::linux::trace_matches_current()
            && frame.rax != 228 // clock_gettime
            && frame.rax != 10  // mprotect (thousands of relocation calls)
            && frame.rax != 14; // rt_sigprocmask
        let (num, args) = (frame.rax, [frame.rdi, frame.rsi, frame.rdx, frame.r10]);
        if tracing {
            let pid = crate::task::SCHEDULER.lock().current_task_id().0;
            crate::kprintln!("[trace] t={} {} > {}({:#x}, {:#x}, {:#x}, {:#x})", crate::arch::pit::ticks(), pid, num, args[0], args[1], args[2], args[3]);
            // Calls naming a file: show the path (open, stat, lstat, access, execve, readlink,
            // openat, faccessat, newfstatat, statx, faccessat2)
            let path_arg = match num {
                // ... creat, mkdir, rmdir, unlink, chdir, chroot
                2 | 4 | 6 | 21 | 59 | 89 | 85 | 83 | 84 | 87 | 80 | 161 => Some(args[0]),
                // ... mount and umount2 targets, mkdirat, unlinkat
                257 | 262 | 269 | 332 | 439 | 165 | 258 | 263 => Some(args[1]),
                166 => Some(args[0]),
                _ => None,
            };
            if let Some(p) = path_arg.filter(|&p| p != 0 && crate::memory::vm::prefault_current(p, 1, false)) {
                // Up to the end of the page the path starts in (the next may be unmapped)
                let len = (4096 - (p as usize & 4095)).min(256);
                let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, len) };
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
                crate::kprintln!("[trace]   path \"{}\"", core::str::from_utf8(&bytes[..end]).unwrap_or("?"));
            }
            // ppoll: show the timeout itself (a busy loop shows up as zero timeouts)
            if num == 271 && args[2] != 0 && crate::memory::vm::prefault_current(args[2], 16, false) {
                let ts = unsafe { core::ptr::read_unaligned(args[2] as *const [i64; 2]) };
                crate::kprintln!("[trace]   timeout {}s {}ns", ts[0], ts[1]);
            }
            if num == 271 && args[1] <= 16 && crate::memory::vm::prefault_current(args[0], args[1] * 8, false) {
                for i in 0..args[1] {
                    let pfd = unsafe { core::ptr::read_unaligned((args[0] + i * 8) as *const [i16; 4]) };
                    let fd = (pfd[0] as u16 as u32) | ((pfd[1] as u16 as u32) << 16);
                    let d = crate::task::with_current_fds_mut(|fds| fds.trace_describe(fd as usize));
                    crate::kprintln!("[trace]   pollfd {} events {:#x}", d, pfd[2]);
                }
            }
        }
        // ptrace: system call entry stop (the tracer may change or cancel the call)
        let traced = crate::compat::linux::ptrace::active() && crate::compat::linux::ptrace::is_traced(crate::compat::linux::proc::current_ids().0);
        let (num, cancelled) = if traced {
            match crate::compat::linux::ptrace::syscall_entry(frame, fpu, num) {
                Ok(n) => (n, None),
                Err(r) => (num, Some(r)),
            }
        } else {
            (num, None)
        };
        crate::task::CURRENT_SYSCALL.store(num, core::sync::atomic::Ordering::Relaxed);
        crate::task::CURRENT_SYSCALL_ARGS[0].store(args[0], core::sync::atomic::Ordering::Relaxed);
        crate::task::CURRENT_SYSCALL_ARGS[1].store(args[1], core::sync::atomic::Ordering::Relaxed);
        let res = match cancelled {
            Some(r) => r,
            None => crate::compat::linux::dispatch_linux_syscall(frame),
        };
        // ptrace: exec event and system call exit stop (the tracer may change the result)
        let res = if traced || crate::compat::linux::ptrace::is_traced(crate::compat::linux::proc::current_ids().0) {
            crate::compat::linux::ptrace::syscall_exit(frame, fpu, num, res)
        } else {
            res
        };
        crate::task::CURRENT_SYSCALL.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
        if tracing && (num == 46 || num == 47) && crate::memory::vm::prefault_current(args[1], 56, false) {
            // sendmsg/recvmsg: control (SCM_RIGHTS) bytes passed, after the call
            let h = unsafe { core::ptr::read_unaligned(args[1] as *const [u64; 7]) };
            crate::kprintln!("[trace]   controllen {} flags {:#x}", h[5], h[6] as u32);
        }
        if tracing {
            crate::kprintln!("[trace]   = {}", res);
        }
        frame.rax = res as u64;
        crate::compat::linux::proc::deliver_on_syscall_return(frame, fpu, num);
        return;
    }

    let num = frame.rax;
    let arg0 = frame.rdi;
    let arg1 = frame.rsi;
    let _arg2 = frame.rdx;
    // In a (native) system call: its wakeup kicks wait for its end (arch::smp::kick_idle);
    // shown as 0x10000 + the number by the task dump
    crate::task::CURRENT_SYSCALL.store(0x1_0000 | num, core::sync::atomic::Ordering::Relaxed);

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
            if ptr.is_null() && len > 0 {
                -14 // -EFAULT
            } else if len == 0 {
                0
            } else {
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
            if ptr.is_null() || len == 0 {
                -14 // -EFAULT
            } else {
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
                        shown: None,
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
            if ptr.is_null() && count > 0 {
                -14 // -EFAULT
            } else if count == 0 {
                0
            } else {
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
            // arg1 = 1: every thread of the process (a native program with threads that
            // panicked, as the Linux server)
            if arg1 == 1 {
                crate::task::exit_group();
            }
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
        SYS_IOPL => {
            stats.iopl_calls += 1;
            drop(stats);
            // arg0: requested IOPL (0 or 3); driver processes only
            match crate::ipc::service::iopl_allowed() {
                Ok(()) => {
                    let level = if arg0 & 3 != 0 { 3u64 } else { 0 };
                    frame.rflags = (frame.rflags & !0x3000) | (level << 12);
                    0
                }
                Err(e) => e,
            }
        }
        SYS_PHYSMAP => {
            stats.physmap_calls += 1;
            drop(stats);
            // arg0: physical address, arg1: length; returns the mapped address
            crate::ipc::service::physmap(arg0, arg1).map_or_else(|e| e, |a| a as i64)
        }
        SYS_DMA_ALLOC => {
            stats.dma_alloc_calls += 1;
            drop(stats);
            // arg0: length, arg1: where to store the physical address; returns the address
            match crate::ipc::service::dma_alloc(arg0) {
                Ok((addr, phys)) => match crate::compat::linux::vfs::copy_out(arg1, &phys.to_le_bytes()) {
                    Ok(()) => addr as i64,
                    Err(e) => e,
                },
                Err(e) => e,
            }
        }
        SYS_IRQ_REGISTER => {
            stats.irq_register_calls += 1;
            drop(stats);
            // arg0: interrupt line
            crate::ipc::service::irq_register(arg0).map_or_else(|e| e, |()| 0)
        }
        SYS_IRQ_WAIT => {
            drop(stats);
            // arg0: interrupt line, arg1: timeout in ticks (0: none); returns the count
            crate::ipc::service::irq_wait(arg0, arg1).map_or_else(|e| e, |n| n as i64)
        }
        SYS_IRQ_ACK => {
            drop(stats);
            // arg0: interrupt line; returns the count since the last wait or acknowledgement
            crate::ipc::service::irq_ack(arg0).map_or_else(|e| e, |n| n as i64)
        }
        SYS_CLOCK => {
            drop(stats);
            // arg0: where to store [seconds since 1970, nanoseconds]
            let (secs, nanos) = crate::arch::rtc::now();
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&secs.to_le_bytes());
            out[8..].copy_from_slice(&(nanos as u64).to_le_bytes());
            crate::compat::linux::vfs::copy_out(arg0, &out).map_or_else(|e| e, |()| 0)
        }
        SYS_SVC_ATTACH => {
            drop(stats);
            // arg0: endpoint whose window to map; returns its address
            crate::ipc::service::attach(arg0 as u32).map_or_else(|e| e, |a| a as i64)
        }
        SYS_SVC_REGISTER => {
            drop(stats);
            // arg0: endpoint; returns the window address
            crate::ipc::service::register(arg0 as u32).map_or_else(|e| e, |a| a as i64)
        }
        SYS_SVC_RECV => {
            drop(stats);
            // arg0: endpoint, arg1: where to store the request (`WireMessage`), arg2: 0, or
            // `RECV_NOTIFY` | timeout in ticks (notifications come back as ID 0)
            // Returns the request's ID (the reply names it)
            match crate::ipc::service::recv_with(arg0 as u32, _arg2) {
                Ok((id, m)) => match store_wire_message(arg1, m) {
                    0 => id as i64,
                    e => e,
                },
                Err(e) => e,
            }
        }
        SYS_SVC_REPLY => {
            drop(stats);
            // arg0: endpoint, arg1: the answer (`WireMessage`)
            match load_wire_message(arg1) {
                // arg2: the request's ID (0: the oldest one taken and unanswered)
                Ok(m) => crate::ipc::service::reply(arg0 as u32, _arg2, m).map_or_else(|e| e, |()| 0),
                Err(e) => e,
            }
        }
        SYS_SVC_CALL => {
            drop(stats);
            // arg0: endpoint, arg1: request in, reply out (`WireMessage`), arg2: timeout
            // in ticks (0: the default); driver processes only
            if crate::task::current_service().is_none() {
                -1 // -EPERM
            } else {
                let timeout = if _arg2 == 0 { crate::ipc::service::CALL_TIMEOUT_TICKS } else { _arg2 };
                let mode = crate::ipc::service::driver_call_mode();
                match load_wire_message(arg1).and_then(|m| crate::ipc::service::call_mode(arg0 as u32, m, timeout, mode)) {
                    Ok(r) => store_wire_message(arg1, r),
                    Err(e) => e,
                }
            }
        }
        SYS_SVC_CALL_GRANT => {
            drop(stats);
            // arg0: endpoint, arg1: a `GrantCall` (its message becomes the reply)
            if crate::task::current_service().is_none() {
                -1 // -EPERM
            } else {
                match crate::compat::linux::vfs::copy_in(arg1, core::mem::size_of::<GrantCall>()) {
                    Ok(bytes) => {
                        let gc = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const GrantCall) };
                        let mut spec = crate::ipc::service::GrantSpec {
                            ranges: [(0, 0); crate::ipc::service::GRANT_RANGES],
                            n: gc.n as usize,
                            server_writes: gc.flags & 1 != 0,
                        };
                        for (d, r) in spec.ranges.iter_mut().zip(gc.ranges.iter()) {
                            *d = (r[0], r[1]);
                        }
                        let timeout = if gc.timeout == 0 { crate::ipc::service::CALL_TIMEOUT_TICKS } else { gc.timeout };
                        let mode = crate::ipc::service::driver_call_mode();
                        match crate::ipc::service::call_with(arg0 as u32, gc.msg.into(), timeout, mode, Some(&spec)) {
                            Ok(r) => store_wire_message(arg1, r),
                            Err(e) => e,
                        }
                    }
                    Err(e) => e,
                }
            }
        }
        SYS_SVC_SIGNAL => {
            drop(stats);
            // arg0: endpoint served, arg1: bits for the client's hook
            crate::ipc::service::signal(arg0 as u32, arg1).map_or_else(|e| e, |()| 0)
        }
        SYS_SVC_GRANT => {
            drop(stats);
            // arg0: endpoint served, arg1: request ID, arg2: where to store up to
            // `GRANT_SEGMENTS_MAX` segments `[physical address, length]`; returns how many
            match crate::ipc::service::grant_segments(arg0 as u32, arg1) {
                Ok((segs, _)) => {
                    let mut out = alloc::vec::Vec::with_capacity(segs.len() * 16);
                    for (a, l) in &segs {
                        out.extend_from_slice(&a.to_le_bytes());
                        out.extend_from_slice(&l.to_le_bytes());
                    }
                    crate::compat::linux::vfs::copy_out(_arg2, &out).map_or_else(|e| e, |()| segs.len() as i64)
                }
                Err(e) => e,
            }
        }
        SYS_MAP_ANON => {
            drop(stats);
            // arg0: length; returns the address of zeroed, private, read-write memory
            match crate::task::with_current_task_mut(|t| t.mm.clone()).flatten() {
                Some(mm) => mm
                    .lock()
                    .mmap(0, arg0, 3, false, false, false, crate::memory::vm::Backing::Anon)
                    .map_or_else(|e| e, |a| a as i64),
                None => -14, // -EFAULT: no address space of its own
            }
        }
        // Wave 3 (Group 7): native threads and the Linux server's primitives (crate::lx)
        SYS_THREAD_CREATE => {
            drop(stats);
            // arg0: entry, arg1: stack pointer, arg2: argument (rdi)
            let r = x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().spawn_native_thread(frame, arg0, arg1, _arg2));
            match r {
                Ok(id) => id.0 as i64,
                Err(_) => -12, // -ENOMEM
            }
        }
        SYS_LX_CTL => {
            drop(stats);
            crate::lx::ctl(arg0)
        }
        SYS_LX_REPLY_RECV => {
            drop(stats);
            crate::lx::reply_recv(arg0 as i64, arg1)
        }
        SYS_LX_COMPLETE => {
            drop(stats);
            crate::lx::complete(arg0, arg1 as i64)
        }
        SYS_LX_READ | SYS_LX_WRITE | SYS_LX_READ_STR => {
            drop(stats);
            let op = match num {
                SYS_LX_READ => crate::lx::MemOp::Read,
                SYS_LX_WRITE => crate::lx::MemOp::Write,
                _ => crate::lx::MemOp::ReadStr,
            };
            crate::lx::client_mem(op, arg0, arg1, _arg2, frame.r10)
        }
        SYS_LX_PROC_INFO => {
            drop(stats);
            crate::lx::proc_info(arg0, arg1)
        }
        SYS_LX_OBJ => {
            drop(stats);
            crate::lx::obj::obj_ctl(arg0, arg1, _arg2, frame.r10)
        }
        SYS_LX_SIG => {
            drop(stats);
            crate::lx::obj::sig_post(arg0, arg1, _arg2, frame.r10, frame.r8)
        }
        // Group 4: the admin interface of the Ring 3 shell (authorized console only)
        crate::admin::proto::SYS_ADMIN => {
            drop(stats);
            crate::admin::syscall(arg0)
        }
        _ => {
            stats.unknown_calls += 1;
            drop(stats);
            -38 // -ENOSYS
        }
    };

    // Store return value in rax
    frame.rax = result as u64;
    crate::task::CURRENT_SYSCALL.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
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

        // 1. The kernel's GS base (per-CPU data: arch::percpu); preserve User RSP and
        // switch to the task's kernel stack
        swapgs
        mov gs:[24], rsp
        mov rsp, gs:[16]

        // 2. Build SyscallFrame on kernel stack
        push qword ptr gs:[24]                  // User RSP
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

        // 3. Save user x87/SSE/AVX state (Linux preserves it across syscalls; kernel code
        // uses SSE): an FpuState, by XSAVE or (without it) FXSAVE. RBP (already saved in the
        // frame) keeps the frame pointer across the call; RAX/RDX are in the frame.
        mov rbp, rsp
        sub rsp, 1024
        and rsp, -64
        test byte ptr [rip + hydra_use_xsave], 1
        jz 5f
        // The XSAVE header first (stack leftovers here): XSAVE writes only the XSTATE_BV bits
        // of the components it saves and nothing else of the header, and XRSTOR faults on
        // any other bit set there
        mov qword ptr [rsp + 512], 0
        mov qword ptr [rsp + 520], 0
        mov qword ptr [rsp + 528], 0
        mov qword ptr [rsp + 536], 0
        mov qword ptr [rsp + 544], 0
        mov qword ptr [rsp + 552], 0
        mov qword ptr [rsp + 560], 0
        mov qword ptr [rsp + 568], 0
        mov eax, -1
        mov edx, -1
        xsave64 [rsp]
        jmp 6f
    5:
        fxsave64 [rsp]
        // A valid XSAVE header (x87 and SSE held, nothing else) after the FXSAVE image: the
        // state may be restored with XRSTOR once XSAVE is on (a task switched out early in
        // boot), which faults on a header of stack leftovers
        mov qword ptr [rsp + 512], 3
        mov qword ptr [rsp + 520], 0
        mov qword ptr [rsp + 528], 0
        mov qword ptr [rsp + 536], 0
        mov qword ptr [rsp + 544], 0
        mov qword ptr [rsp + 552], 0
        mov qword ptr [rsp + 560], 0
        mov qword ptr [rsp + 568], 0
    6:

        // 4. Call Rust dispatcher: Arg 1 = SyscallFrame, Arg 2 = FPU area (Win64 + SysV)
        mov rcx, rbp
        mov rdi, rbp
        mov rdx, rsp
        mov rsi, rsp
        sub rsp, 32                             // 32-byte Win64 shadow space
        call hydra_syscall_dispatcher
        cli                                     // no interrupts while user state is restored
        add rsp, 32

        test byte ptr [rip + hydra_use_xsave], 1
        jz 7f
        mov eax, -1
        mov edx, -1
        xrstor64 [rsp]
        jmp 8f
    7:
        fxrstor64 [rsp]
    8:
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

        // 5. Return to unprivileged Ring 3 (with its GS base)
        swapgs
        sysretq

    // SYSCALL from 32-bit compatibility mode (IA32_CSTAR): -ENOSYS straight back, on the
    // caller's stack with interrupts off (FMASK), as Linux's entry_SYSCALL32_ignore
    .global asm_syscall32_ignore
    asm_syscall32_ignore:
        mov eax, -38
        sysret
    "#
);
