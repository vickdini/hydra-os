//! `arch/idt.rs`: the gate table, the user-copy fix-ups, and the exception and interrupt
//! dispatch (which faults signal the program, which kill it, which halt the kernel; which
//! interrupts schedule, acknowledge or wake a driver), the direct switch, XSAVE set-up.
//!
//! The trap entry calls `hydra_exception_handler` with a frame; here the tests do, with the
//! scheduler, signals and drivers stubbed (calls recorded in `stubs::CALLS`). The kernel
//! lock is global: every test holds [`serial`] and releases the lock the handler keeps.

mod common;

use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::idt::{self, ExceptionContext, FpuState};
use hydra_hosttests_t32::arch::{keyboard, smp};
use hydra_hosttests_t32::stubs::task::{self, TaskPersonality};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

unsafe fn hydra_exception_handler(ctx: &mut ExceptionContext, fpu: *mut FpuState) {
    idt::exception_handler(ctx, fpu)
}
unsafe fn hydra_direct_switch_handler(ctx: &mut ExceptionContext) {
    idt::direct_switch_handler(ctx)
}

extern "C" {
    fn hydra_uaccess_copy_insn();
    fn hydra_uaccess_copy_insn_end();
    fn hydra_uaccess_copy_fix();
    fn hydra_uaccess_str_insn();
    fn hydra_uaccess_str_fix();
}

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    host::set_cpu(0);
    // A local APIC for EOIs
    host::MMIO.with_borrow_mut(|m| *m = Some(Box::new(|_, _| 0)));
    g
}

/// Stack and code bytes a frame may point at (the breakpoint and #UD reports read them).
static mut MEM: [u64; 1024] = [0; 1024];

fn mem() -> u64 {
    core::ptr::addr_of_mut!(MEM) as u64 + 2048
}

fn ctx(vector: u64, user: bool) -> ExceptionContext {
    ExceptionContext {
        r15: 15, r14: 14, r13: 13, r12: 12, rbp: 0, rbx: 3, r11: 11, r10: 10, r9: 9, r8: 8, rdi: 5, rsi: 4, rdx: 2, rcx: 1, rax: 0,
        vector,
        error_code: 0,
        rip: mem() + 64,
        cs: if user { 0x33 } else { 0x08 },
        rflags: 0x202,
        rsp: mem(),
        ss: if user { 0x2b } else { 0x10 },
    }
}

/// Runs the handler on `c`, then lets the kernel lock go as the trap epilogue does.
fn trap(c: &mut ExceptionContext) {
    let mut fpu = FpuState::new();
    unsafe { hydra_exception_handler(c, &mut fpu) };
    smp::bkl_exit();
}

/// Like [`trap`], for a trap that ends in the kernel's halt for good (a panic here).
fn trap_halts(c: &mut ExceptionContext) -> String {
    let mut c2 = *c;
    let r = std::panic::catch_unwind(move || {
        let mut fpu = FpuState::new();
        unsafe { hydra_exception_handler(&mut c2, &mut fpu) };
    });
    smp::bkl_exit();
    hw::set_if(true);
    let e = r.expect_err("the kernel halts");
    e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_default()
}

fn calls() -> Vec<String> {
    stubs::take_calls()
}

fn has(v: &[String], s: &str) -> bool {
    v.iter().any(|l| l.contains(s))
}

// ------------------------------------------------------------------- the table

fn entry_bytes(i: usize) -> [u8; 16] {
    let idt = idt::IDT.lock();
    unsafe { core::mem::transmute::<idt::IdtEntry, [u8; 16]>(idt.entries[i]) }
}

fn handler_of(b: &[u8; 16]) -> u64 {
    u16::from_le_bytes([b[0], b[1]]) as u64 | (u16::from_le_bytes([b[6], b[7]]) as u64) << 16 | (u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as u64) << 32
}

#[test]
fn gate_table() {
    let _g = serial();
    idt::init();
    let t = hw::TABLES.with_borrow(|t| t.clone());
    assert_eq!(t.last().unwrap().0, "lidt");
    assert_eq!(t.last().unwrap().2, 256 * 16 - 1);
    let cs: u16;
    unsafe { core::arch::asm!("mov {:x}, cs", out(reg) cs) };
    for i in 0..256 {
        let b = entry_bytes(i);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), cs, "selector of {i}");
        assert_eq!(b[5] & 0x8F, 0x8E, "present interrupt gate {i}");
        assert!(handler_of(&b) != 0);
    }
    // Ring 3 may raise #BP, #OF and int 0x80; nothing else
    for i in 0..256 {
        let dpl = entry_bytes(i)[5] >> 5 & 3;
        assert_eq!(dpl, if matches!(i, 3 | 4 | 0x80) { 3 } else { 0 }, "DPL of {i}");
    }
    // Distinct handlers for the CPU exceptions, IRQs and MSIs; the rest share the default
    let default = handler_of(&entry_bytes(255));
    for i in [0, 1, 2, 3, 6, 8, 13, 14, 32, 47, 0x40, 0x42, 0x50, 0x5F, 0x80, 0x81, 0x82] {
        assert_ne!(handler_of(&entry_bytes(i)), default, "vector {i:#x}");
    }
    assert_eq!(handler_of(&entry_bytes(9)), default);
    assert_eq!(handler_of(&entry_bytes(0x60)), default);
    // The double fault on IST 1, then a new kernel selector everywhere
    idt::enable_double_fault_ist();
    assert_eq!(entry_bytes(8)[4], 1);
    assert_eq!(entry_bytes(14)[4], 0);
    idt::reload_with_kernel_cs(0x08);
    assert_eq!(u16::from_le_bytes([entry_bytes(77)[2], entry_bytes(77)[3]]), 0x08);
    idt::load_on_this_cpu();
    let mut e = idt::IdtEntry::missing();
    e.set_handler_addr(0x1122_3344_5566_7788, 0x10).set_ist(9).set_dpl(2);
    let b: [u8; 16] = unsafe { core::mem::transmute(e) };
    assert_eq!(handler_of(&b), 0x1122_3344_5566_7788);
    assert_eq!((b[4], b[5]), (1, 0x8E | 2 << 5), "IST masked to 3 bits, DPL 2");
}

#[test]
fn user_copy_fixups() {
    let _g = serial();
    let (insn, end, fix) = (hydra_uaccess_copy_insn as *const () as u64, hydra_uaccess_copy_insn_end as *const () as u64, hydra_uaccess_copy_fix as *const () as u64);
    let before = idt::UACCESS_FAULTS.load(SeqCst);
    assert_eq!(idt::uaccess_fixup(insn, false), Some(fix));
    assert_eq!(idt::uaccess_fixup(insn + 3, false), Some(fix));
    assert_eq!(idt::uaccess_fixup(end, false), None, "past the copy");
    assert_eq!(idt::uaccess_fixup(end, true), Some(fix), "a watchpoint reports the next instruction");
    assert_eq!(idt::uaccess_fixup(hydra_uaccess_str_insn as *const () as u64, false), Some(hydra_uaccess_str_fix as *const () as u64));
    assert_eq!(idt::uaccess_fixup(0x1234, false), None);
    assert_eq!(idt::UACCESS_FAULTS.load(SeqCst), before + 3, "faults counted, watchpoints not");
    // Through the handler: a kernel #PF in the copy resumes at its fix-up, no lock taken
    let mut c = ctx(14, false);
    c.rip = insn + 1;
    let mut fpu = FpuState::new();
    unsafe { hydra_exception_handler(&mut c, &mut fpu) };
    assert_eq!(c.rip, fix);
    assert_eq!(smp::bkl_owner(), usize::MAX);
    // A kernel #DB there: DR6 cleared, the copy goes on
    let mut c = ctx(1, false);
    c.rip = end;
    host::write_dr(6, 0x1);
    unsafe { hydra_exception_handler(&mut c, &mut fpu) };
    assert_eq!(c.rip, end);
    assert_eq!(host::read_dr(6), 0);
}

// ------------------------------------------------------------------- faults

#[test]
fn user_faults_signal_posix_programs() {
    let _g = serial();
    task::ACTIVE.set(true);
    for (v, sig) in [(0u64, 8u32), (6, 4), (13, 11), (14, 11), (3, 5)] {
        let mut c = ctx(v, true);
        trap(&mut c);
        let k = calls();
        assert!(has(&k, &format!("proc::force_fault_signal {sig}")), "vector {v}: {k:?}");
        assert!(has(&k, "sched::wait_out_handoff"), "user faults wait out a hand-off: {k:?}");
    }
    // The fault address survives the wait (put back in CR2)
    hw::set_cr(2, 0xDEAD_0000);
    let mut c = ctx(14, true);
    trap(&mut c);
    assert_eq!(hw::cr(2), 0xDEAD_0000);
    task::ACTIVE.set(false);
}

#[test]
fn user_faults_kill_native_programs() {
    let _g = serial();
    task::ACTIVE.set(true);
    task::PERSONALITY.set(TaskPersonality::Hydra);
    for v in [0u64, 6, 13, 14] {
        let mut c = ctx(v, true);
        c.error_code = 0b110; // user write, not present
        trap(&mut c);
        let k = calls();
        assert!(has(&k, "sched::terminate_current") && has(&k, "sched::schedule"), "vector {v}: {k:?}");
        assert!(!has(&k, "terminate_current_group"));
        let log = stubs::take_log();
        assert!(has(&log, "USER FAULT"), "{log:?}");
    }
    task::CURRENT.with_borrow_mut(|t| {
        t.exe = "/bin/tool".into();
        t.cmdline = Some(b"tool\0-x\0".to_vec());
    });
    let mut c = ctx(6, true);
    trap(&mut c);
    let log = stubs::take_log();
    assert!(has(&log, "Invalid Opcode (#UD) in Task PID 42 (/bin/tool)") && has(&log, "Command: tool -x"), "{log:?}");
    assert!(has(&log, "Stack: [") && has(&log, "Code: ["));
    // int3 in a native program: a report, the program goes on
    calls();
    let mut c = ctx(3, true);
    trap(&mut c);
    let log = stubs::take_log();
    assert!(has(&log, "CPU BREAKPOINT TRAP (#BP) in Task PID 42 (/bin/tool)") && has(&log, "Command: tool -x"), "{log:?}");
    assert!(!has(&calls(), "terminate"));
    task::PERSONALITY.set(TaskPersonality::Linux);
    task::ACTIVE.set(false);
}

#[test]
fn faults_in_linux_kernel_code_end_the_group() {
    // A Linux task's fault in kernel mode that is not a user-memory fault (e.g. #DE in a
    // system call): the whole process dies with the signal as its status
    let _g = serial();
    task::ACTIVE.set(true);
    let mut c = ctx(14, false);
    c.error_code = 0b100; // the CPU says user mode... but cs says kernel: user-space fault
    trap(&mut c);
    let k = calls();
    assert!(has(&k, "proc::set_exit_status 7 11") && has(&k, "sched::terminate_current_group"), "{k:?}");
    task::ACTIVE.set(false);
}

#[test]
fn debug_traps_and_breakpoints() {
    let _g = serial();
    task::ACTIVE.set(true);
    // A single step: TF cleared, SIGTRAP with DR6 in the error code
    host::write_dr(6, 0x4000);
    let mut c = ctx(1, true);
    c.rflags |= 0x100;
    trap(&mut c);
    assert_eq!(c.rflags & 0x100, 0);
    assert_eq!(c.error_code, 0x4000);
    assert_eq!(task::CURRENT.with_borrow(|t| t.debugregs[6]), 0x4000);
    assert!(has(&calls(), "proc::force_fault_signal 5"));
    // An instruction breakpoint (DR6 bit 0): RF set so it does not fire again at once
    host::write_dr(6, 0x1);
    let mut c = ctx(1, true);
    trap(&mut c);
    assert_eq!(c.rflags & 0x1_0000, 0x1_0000);
    // A kernel #DB outside the copies: DR6 cleared, nothing else
    calls();
    host::write_dr(6, 0x2);
    let mut c = ctx(1, false);
    trap(&mut c);
    assert_eq!(host::read_dr(6), 0);
    assert!(!has(&calls(), "force_fault_signal"));
    // #BP in the kernel with no task: the report only
    task::ACTIVE.set(false);
    let mut c = ctx(3, false);
    trap(&mut c);
    assert!(has(&stubs::take_log(), "CPU BREAKPOINT TRAP (#BP) in Task PID 0 ()"));
}

#[test]
fn int80_from_linux_programs() {
    let _g = serial();
    task::ACTIVE.set(true);
    let mut c = ctx(0x80, true);
    c.cs = 0x23; // 32-bit code
    c.rip = 0x8048000;
    c.rax = 20;
    c.rbx = 1;
    stubs::answer("ldt::int80", 1234);
    trap(&mut c);
    assert_eq!(c.rax, 1234);
    assert!(has(&calls(), "ldt::int80 20 1"));
    assert_eq!(c.cs, 0x23 | 0, "a good frame stays");
    // From a native program: nothing
    task::PERSONALITY.set(TaskPersonality::Hydra);
    let mut c = ctx(0x80, true);
    trap(&mut c);
    assert!(!has(&calls(), "ldt::int80"));
    task::PERSONALITY.set(TaskPersonality::Linux);
    task::ACTIVE.set(false);
}

#[test]
fn kernel_faults_halt() {
    let _g = serial();
    let mut buf = [0u64; 512];
    for (v, what) in [(14u64, "PAGE FAULT (#PF)"), (13, "GENERAL PROTECTION FAULT (#GP)"), (8, "DOUBLE FAULT"), (6, "INVALID OPCODE (#UD)"), (0, "DIVIDE-BY-ZERO (#DE)"), (16, "UNHANDLED CPU EXCEPTION #16")] {
        let mut c = ctx(v, false);
        c.rsp = buf.as_mut_ptr() as u64 + 8;
        c.error_code = 0x3;
        let msg = trap_halts(&mut c);
        assert!(msg.contains("hlt with interrupts off"), "{msg}");
        let log = stubs::take_log();
        assert!(has(&log, what), "vector {v}: {log:#?}");
        assert!(has(&log, "Register State"));
        let serial_out = stubs::console::take_serial();
        if matches!(v, 14 | 13 | 6) {
            assert!(serial_out.contains("[!] KERNEL"), "straight to the serial port first: {serial_out}");
        }
    }
    // A user-mode fault with no scheduler yet: also the kernel's end
    let mut c = ctx(13, true);
    trap_halts(&mut c);
    assert!(has(&stubs::take_log(), "GENERAL PROTECTION FAULT"));
}

#[test]
fn page_fault_trace_and_bus_error_paths() {
    let _g = serial();
    // Tracing on: the fault is logged (no address space here: unresolved)
    task::ACTIVE.set(true);
    hydra_hosttests_t32::compat::linux::TRACE_SYSCALLS.store(true, SeqCst);
    let mut c = ctx(14, true);
    c.error_code = 0b10110;
    hw::set_cr(2, 0x4000);
    trap(&mut c);
    hydra_hosttests_t32::compat::linux::TRACE_SYSCALLS.store(false, SeqCst);
    assert!(has(&stubs::take_log(), "[fault] addr=0x4000"));
    // A native program's fault report names the access
    task::PERSONALITY.set(TaskPersonality::Hydra);
    for (err, words) in [(0b10101u64, "exec protection, user mode"), (0b00110, "write not-present, user mode"), (0b00100, "read not-present, user mode")] {
        let mut c = ctx(14, true);
        c.error_code = err;
        trap(&mut c);
        assert!(has(&stubs::take_log(), words), "{err:#b}");
    }
    task::PERSONALITY.set(TaskPersonality::Linux);
    task::ACTIVE.set(false);
}

// ------------------------------------------------------------------- interrupts

#[test]
fn timer_tick_from_user_mode_schedules() {
    let _g = serial();
    task::ACTIVE.set(true);
    let mut c = ctx(32, true);
    trap(&mut c);
    let k = calls();
    for want in ["lx::timer::on_tick", "sched::account_tick 32", "proc::deliver_on_trap_return 32", "splash::tick", "sched::schedule 32", "tty::pump"] {
        assert!(has(&k, want), "{want}: {k:?}");
    }
    // The PIC got its EOI
    assert!(hw::port_writes().contains(&(0x20, 0x20)));
    // From kernel code outside a wait point: the pass is deferred to the call's end
    task::TICK_DEFERRED.store(0, SeqCst);
    let mut c = ctx(32, false);
    trap(&mut c);
    assert_eq!(task::TICK_DEFERRED.load(SeqCst), 1);
    assert!(!has(&calls(), "sched::schedule 32"));
    // Another CPU holds the kernel lock: the tick only counts
    host::set_cpu(1);
    assert!(smp::bkl_try_enter());
    host::set_cpu(0);
    task::TICK_DEFERRED.store(0, SeqCst);
    let mut c = ctx(32, true);
    let mut fpu = FpuState::new();
    unsafe { hydra_exception_handler(&mut c, &mut fpu) };
    assert_eq!(task::TICK_DEFERRED.load(SeqCst), 1);
    assert!(!has(&calls(), "sched::schedule"));
    host::set_cpu(1);
    smp::bkl_exit();
    host::set_cpu(0);
    // A task dump asked for (F12, NMI): done at the tick
    keyboard::TASK_DUMP_REQUESTED.store(true, SeqCst);
    let mut c = ctx(32, true);
    trap(&mut c);
    assert!(has(&calls(), "sched::dump_tasks"));
    assert!(!keyboard::TASK_DUMP_REQUESTED.load(SeqCst));
    // The frame is another task's stack after a switch: no delivery on it
    task::ON_OWN_STACK.set(false);
    let mut c = ctx(32, true);
    trap(&mut c);
    assert!(!has(&calls(), "deliver_on_trap_return"));
    task::ON_OWN_STACK.set(true);
    task::ACTIVE.set(false);
}

#[test]
fn ap_timer_and_preemption_points() {
    let _g = serial();
    task::ACTIVE.set(true);
    let mut c = ctx(idt::LAPIC_TIMER_VECTOR, true);
    trap(&mut c);
    assert!(has(&calls(), "sched::schedule 64"));
    // Kernel code at a wait point is preempted too
    task::PREEMPT_POINTS.store(1, SeqCst);
    let mut c = ctx(idt::LAPIC_TIMER_VECTOR, false);
    trap(&mut c);
    assert!(has(&calls(), "sched::schedule 64"));
    task::PREEMPT_POINTS.store(0, SeqCst);
    task::TICK_DEFERRED.store(0, SeqCst);
    let mut c = ctx(idt::LAPIC_TIMER_VECTOR, false);
    trap(&mut c);
    assert_eq!(task::TICK_DEFERRED.load(SeqCst), 1);
    // The scheduler lock busy at the tick: nothing scheduled
    task::BUSY.set(2);
    let mut c = ctx(idt::LAPIC_TIMER_VECTOR, true);
    trap(&mut c);
    assert!(!has(&calls(), "sched::schedule"));
    task::BUSY.set(0);
    task::ACTIVE.set(false);
}

#[test]
fn kernel_watchdog_reports_a_stuck_kernel() {
    let _g = serial();
    // 500 ticks in kernel code with no new system call: one report on the serial port
    for _ in 0..1001 {
        let mut c = ctx(32, false);
        trap(&mut c);
    }
    let out = stubs::console::take_serial();
    assert!(out.contains("[watchdog] kernel busy for 5 s"), "{out}");
    assert!(out.contains("[watchdog] kernel busy for 10 s"));
    // A new call resets it
    hydra_hosttests_t32::arch::syscall::SYSCALL_ENTRIES.fetch_add(1, SeqCst);
    let mut c = ctx(32, false);
    trap(&mut c);
}

#[test]
fn yield_and_direct_switch() {
    let _g = serial();
    task::ACTIVE.set(true);
    let mut c = ctx(idt::YIELD_VECTOR, false);
    trap(&mut c);
    assert!(has(&calls(), "sched::schedule_now 129"));
    task::TICK_YIELD.store(1, SeqCst);
    let mut c = ctx(idt::YIELD_VECTOR, false);
    trap(&mut c);
    assert!(has(&calls(), "sched::schedule 129"));
    stubs::task::scheduler::DIRECT_TO.store(9, SeqCst);
    let mut c = ctx(idt::YIELD_VECTOR, false);
    task::BUSY.set(3); // the scheduler lock taken elsewhere for a moment: waited for
    trap(&mut c);
    assert!(has(&calls(), "sched::direct_switch 8"));
    // The direct switch vector
    stubs::task::scheduler::DIRECT_TO.store(5, SeqCst);
    stubs::task::scheduler::DIRECT_HINT.store(2, SeqCst);
    let mut c = ctx(idt::DIRECT_VECTOR, false);
    c.rax = 0;
    unsafe { hydra_direct_switch_handler(&mut c) };
    assert!(has(&calls(), "sched::direct_call 4 2"));
    assert_eq!(c.rax, 0, "switched");
    stubs::answer("sched::direct_call", 0);
    stubs::task::scheduler::DIRECT_TO.store(5, SeqCst);
    unsafe { hydra_direct_switch_handler(&mut c) };
    assert_eq!(c.rax, 1, "not switched");
    c.rax = 0;
    unsafe { hydra_direct_switch_handler(&mut c) }; // no target
    assert_eq!(c.rax, 1);
    task::ACTIVE.set(false);
}

#[test]
fn device_interrupts() {
    let _g = serial();
    task::ACTIVE.set(true);
    // Keyboard and mouse
    hw::set_port_handler(|op| if op.port == 0x60 { 0x9E } else { 0 });
    let mut c = ctx(33, false);
    trap(&mut c);
    assert!(hw::port_writes().contains(&(0x20, 0x20)));
    hw::clear_ports();
    hw::set_port_handler(|op| if op.port == 0x60 { 0x00 } else { 0 });
    let mut c = ctx(44, false);
    trap(&mut c);
    assert_eq!(hw::port_writes(), vec![(0xA0, 0x20), (0x20, 0x20)], "IRQ 12: both PICs");
    // A driver's line, from user mode: the driver runs now
    stubs::answer("svc::irq_raised", 1);
    let mut c = ctx(43, true);
    trap(&mut c);
    let k = calls();
    assert!(has(&k, "svc::irq_raised 11") && has(&k, "sched::schedule_now 43"), "{k:?}");
    // ...and the woken server of a driver call runs at once
    stubs::answer("sched::handoff_server_ready", 1);
    let mut c = ctx(40, true);
    trap(&mut c);
    assert!(has(&calls(), "sched::apply_wakes"));
    stubs::answer("sched::handoff_server_ready", 0);
    // A hand-off in progress: not now
    stubs::answer("sched::handoff_active", 1);
    let mut c = ctx(43, true);
    trap(&mut c);
    assert!(!has(&calls(), "sched::schedule_now 43"));
    stubs::answer("sched::handoff_active", 0);
    // MSI: the line after the legacy ones, acknowledged at the local APIC
    let mut c = ctx(idt::MSI_VECTOR_BASE + 3, true);
    trap(&mut c);
    assert!(has(&calls(), "svc::irq_raised 19"));
    // Spurious vectors return quietly
    for v in [20u64, 31, 48, 0x60, 255] {
        let mut c = ctx(v, false);
        trap(&mut c);
        assert!(stubs::take_log().is_empty(), "vector {v}");
    }
    task::ACTIVE.set(false);
}

#[test]
fn tlb_ipi_and_nmi() {
    let _g = serial();
    // A flush request: served without the kernel lock
    let mut c = ctx(smp::TLB_VECTOR, false);
    let mut fpu = FpuState::new();
    unsafe { hydra_exception_handler(&mut c, &mut fpu) };
    assert_eq!(smp::bkl_owner(), usize::MAX);
    // ...but a retired task in user mode is switched away from
    task::ACTIVE.set(true);
    task::RETIRED.set(2);
    let mut c = ctx(smp::TLB_VECTOR, true);
    trap(&mut c);
    let k = calls();
    assert!(has(&k, "sched::bury_current") && has(&k, "sched::schedule_now 66"), "{k:?}");
    task::ACTIVE.set(false);
    // An NMI: where the CPU was, and a task dump asked for
    host::set_cpu(3);
    keyboard::TASK_DUMP_REQUESTED.store(false, SeqCst);
    let mut c = ctx(2, false);
    c.rip = 0xFFFF_FFFF_8012_3456;
    unsafe { hydra_exception_handler(&mut c, &mut fpu) };
    assert_eq!(idt::NMI_AT[3][0].load(SeqCst), 0xFFFF_FFFF_8012_3456);
    assert_eq!(idt::NMI_AT[3][1].load(SeqCst), 0x08);
    assert!(keyboard::TASK_DUMP_REQUESTED.load(SeqCst));
    keyboard::TASK_DUMP_REQUESTED.store(false, SeqCst);
}

#[test]
fn current_trap_fpu_is_restored() {
    let _g = serial();
    let mut outer = FpuState::new();
    idt::CURRENT_TRAP_FPU.store(&mut outer, SeqCst);
    let mut c = ctx(33, false);
    hw::set_port_handler(|_| 0);
    trap(&mut c);
    assert_eq!(idt::CURRENT_TRAP_FPU.load(SeqCst), &mut outer as *mut FpuState, "the interrupted trap's area again");
    idt::CURRENT_TRAP_FPU.store(core::ptr::null_mut(), SeqCst);
}

// ------------------------------------------------------------------- XSAVE

#[test]
fn xsave_setup() {
    let _g = serial();
    // No XSAVE: FXSAVE only
    idt::enable_xsave(true);
    assert!(!idt::use_xsave());
    // An application processor of a machine without XSAVE in use: nothing
    idt::enable_xsave(false);
    assert_eq!(host::XCR0.get(), 0);
    let mut f = FpuState::new();
    assert_eq!(&f.0[0..2], &0x037Fu16.to_le_bytes());
    assert_eq!(&f.0[24..28], &0x1F80u32.to_le_bytes());
    f.legacy_written();
    assert_eq!(f.0[512] & 3, 3);
    // XSAVE and AVX, the area fits: x87, SSE, AVX
    host::CPUID.with_borrow_mut(|c| {
        c.insert((1, 0), (0, 0, 1 << 26 | 1 << 28, 0));
        c.insert((0xD, 0), (0, 832, 0, 0));
    });
    idt::enable_xsave(true);
    assert!(idt::use_xsave());
    assert_eq!(idt::xcr0(), 0b111);
    assert_eq!(host::XCR0.get(), 0b111);
    assert_eq!(idt::xsave_size(), 832);
    assert_eq!(hw::cr(4) & (1 << 18), 1 << 18, "CR4.OSXSAVE");
    // Another CPU follows the boot processor's choice
    host::XCR0.set(0);
    hw::set_cr(4, 0x6A0);
    idt::enable_xsave(false);
    assert_eq!(host::XCR0.get(), 0b111);
    assert_eq!(hw::cr(4) & (1 << 18), 1 << 18);
    // AVX whose area would not fit an FpuState: x87 and SSE only
    host::CPUID.with_borrow_mut(|c| c.insert((0xD, 0), (0, 2048, 0, 0)));
    idt::enable_xsave(true);
    assert_eq!(idt::xcr0(), 0b011);
    // XSAVE without AVX
    host::CPUID.with_borrow_mut(|c| c.insert((1, 0), (0, 0, 1 << 26, 0)));
    host::CPUID.with_borrow_mut(|c| c.insert((0xD, 0), (0, 576, 0, 0)));
    idt::enable_xsave(true);
    assert_eq!(idt::xcr0(), 0b011);
    assert_eq!(idt::xsave_size(), 576);
}

// wave11 GD begin
#[test]
fn a_wakeup_preemption_kick_runs_a_scheduling_pass_from_user_mode() {
    let _g = serial();
    smp::host_bring_online(2);
    host::set_cpu(1);
    smp::idle_halt_ended();
    smp::set_cur_prio(2, 0);
    host::set_cpu(0);
    smp::kick_for(4, 0);
    host::set_cpu(1);
    task::ACTIVE.set(true);
    let mut c = ctx(smp::TLB_VECTOR, true);
    trap(&mut c);
    let k = calls();
    assert!(has(&k, "sched::preempt_check 66"), "{k:?}");
    // A plain flush request afterwards: none
    let mut c = ctx(smp::TLB_VECTOR, true);
    trap(&mut c);
    assert!(!has(&calls(), "sched::preempt_check 66"));
    task::ACTIVE.set(false);
    host::set_cpu(0);
    smp::host_bring_online(1);
}
// wave11 GD end
