//! # Architecture Layer: Interrupt Descriptor Table (IDT) & Hardware Exceptions
//!
//! Provides the 64-bit Interrupt Descriptor Table (IDT), low-level assembly exception
//! trampolines, IST double fault isolation, and hardware interrupt dispatchers.
//!
//! ## Architectural Role & Design Rationale
//!
//! In x86_64 long mode, hardware interrupts, processor traps, and software interrupts are routed
//! through an array of 256 16-byte gate descriptors loaded into the CPU via the `LIDT` instruction.
//! To ensure safe recovery and diagnostics, all architectural exception vectors (0..31) are routed
//! through dedicated assembly stubs (`asm_trap_*`) that construct a uniform `ExceptionContext`
//! stack frame and save the x87/SSE FPU state before invoking the Rust `hydra_exception_handler`.
//!
//! ## Key Types & Interfaces
//!
//! - `IdtEntry`: Low-level 16-byte gate descriptor conforming to the x86_64 architecture.
//! - `InterruptDescriptorTable`: 256-entry array loaded into the CPU `IDTR`.
//! - `ExceptionContext`: Complete architectural register context pushed on interrupt entry.
//! - `IDT`: Global spinlock-protected IDT instance.
//! - `init`: Populates the IDT with exception trampolines and loads it into the CPU.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Ring 0 interrupt handlers.
//! - Hardware Interaction: CPU `IDTR` register, assembly `lidt` instruction, and IST stack switching.
//! - Concurrency: Handlers execute with interrupts disabled or managed via reentrancy safeguards.

use core::arch::global_asm;
use core::sync::atomic::Ordering;
use spin::Mutex;
use uefi::proto::console::text::Color;
use x86_64::registers::control::Cr2;

use crate::console::set_color;
use crate::println;

/// IDT Entry (64-bit Interrupt Gate Descriptor).
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    /// Creates an uninitialized / non-present IDT entry.
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Sets the 64-bit handler address and GDT code segment selector.
    /// Configures the gate as Present, 64-bit Interrupt Gate (type 0xE, DPL 0).
    ///
    /// # Arguments
    /// * `handler_addr` - Linear virtual entry address of the handler.
    /// * `selector` - GDT code segment selector.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self` for chaining.
    pub fn set_handler_addr(&mut self, handler_addr: usize, selector: u16) -> &mut Self {
        let addr = handler_addr as u64;
        self.offset_low = (addr & 0xFFFF) as u16;
        self.offset_mid = ((addr >> 16) & 0xFFFF) as u16;
        self.offset_high = ((addr >> 32) & 0xFFFF_FFFF) as u32;
        self.selector = selector;
        // 0x8E = Present (1) | DPL 0 (00) | 0 | 64-bit Interrupt Gate (1110 = 0xE)
        self.type_attr = 0x8E;
        self.reserved = 0;
        self
    }

    /// Sets the Interrupt Stack Table (IST) index (1..=7).
    /// Used for stack-critical exceptions like Double Fault (`#DF`).
    ///
    /// # Arguments
    /// * `ist_index` - IST stack index in the TSS (1 to 7, or 0 to disable).
    ///
    /// # Returns
    ///
    /// A mutable reference to `self` for chaining.
    pub fn set_ist(&mut self, ist_index: u8) -> &mut Self {
        self.ist = ist_index & 0x7;
        self
    }

    /// Sets the Descriptor Privilege Level (DPL).
    /// Set DPL=3 for software interrupts callable from Ring 3 (e.g. `int3` or syscalls).
    ///
    /// # Arguments
    /// * `dpl` - Privilege level ring (0 = kernel, 3 = user).
    ///
    /// # Returns
    ///
    /// A mutable reference to `self` for chaining.
    pub fn set_dpl(&mut self, dpl: u8) -> &mut Self {
        let p_bit = self.type_attr & 0x80;
        let gate_type = self.type_attr & 0x0F;
        self.type_attr = p_bit | ((dpl & 0x3) << 5) | gate_type;
        self
    }
}

/// The 256-entry x86_64 Interrupt Descriptor Table.
#[repr(C, align(16))]
pub struct InterruptDescriptorTable {
    /// Array of 256 architectural 64-bit interrupt gate descriptors.
    pub entries: [IdtEntry; 256],
}

impl InterruptDescriptorTable {
    /// Constructs a clean, zeroed IDT.
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); 256],
        }
    }

    /// Loads this IDT into the CPU using the `lidt` assembly instruction.
    pub fn load(&self) {
        let idtr = x86_64::structures::DescriptorTablePointer {
            limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: x86_64::VirtAddr::from_ptr(self),
        };
        unsafe { x86_64::instructions::tables::lidt(&idtr) };
    }
}

/// Complete CPU execution state captured during an exception or interrupt.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    // Callee & Caller Saved GPRs
    /// Callee-saved general-purpose register R15.
    pub r15: u64,
    /// Callee-saved general-purpose register R14.
    pub r14: u64,
    /// Callee-saved general-purpose register R13.
    pub r13: u64,
    /// Callee-saved general-purpose register R12.
    pub r12: u64,
    /// Callee-saved base/frame pointer register RBP.
    pub rbp: u64,
    /// Callee-saved general-purpose register RBX.
    pub rbx: u64,
    /// Caller-saved scratch register R11.
    pub r11: u64,
    /// Caller-saved 4th syscall argument register R10.
    pub r10: u64,
    /// Caller-saved 6th argument register R9.
    pub r9: u64,
    /// Caller-saved 5th argument register R8.
    pub r8: u64,
    /// Caller-saved 1st argument register RDI.
    pub rdi: u64,
    /// Caller-saved 2nd argument register RSI.
    pub rsi: u64,
    /// Caller-saved 3rd argument register RDX.
    pub rdx: u64,
    /// Caller-saved scratch register RCX.
    pub rcx: u64,
    /// Caller-saved accumulator / syscall return value register RAX.
    pub rax: u64,
    /// Architectural interrupt or exception vector index (0..255).
    pub vector: u64,
    /// Hardware-pushed error code (or zero for exceptions that push no error code).
    pub error_code: u64,
    /// User or kernel instruction pointer at the moment of interruption (saved by hardware).
    pub rip: u64,
    /// Code segment selector at the moment of interruption (saved by hardware).
    pub cs: u64,
    /// CPU RFLAGS status register at the moment of interruption (saved by hardware).
    pub rflags: u64,
    /// Stack pointer at the moment of interruption (saved by hardware).
    pub rsp: u64,
    /// Stack segment selector at the moment of interruption (saved by hardware).
    pub ss: u64,
}

/// Global system-wide Interrupt Descriptor Table instance protected by a spinlock.
pub static IDT: Mutex<InterruptDescriptorTable> = Mutex::new(InterruptDescriptorTable::new());

// Declare external assembly trampoline symbols
extern "C" {
    fn asm_trap_divide_error();
    fn asm_trap_debug();
    fn asm_trap_nmi();
    fn asm_trap_breakpoint();
    fn asm_trap_overflow();
    fn asm_trap_bound_range();
    fn asm_trap_invalid_opcode();
    fn asm_int80();
    fn asm_trap_device_not_avail();
    fn asm_trap_double_fault();
    fn asm_trap_invalid_tss();
    fn asm_trap_segment_not_present();
    fn asm_trap_stack_segment_fault();
    fn asm_trap_general_protection();
    fn asm_trap_page_fault();
    fn asm_trap_x87_floating_point();
    fn asm_trap_alignment_check();
    fn asm_trap_machine_check();
    fn asm_trap_simd_floating_point();
    fn asm_trap_default();
    fn asm_irq_32();
    fn asm_irq_33();
    fn asm_irq_34();
    fn asm_irq_35();
    fn asm_irq_36();
    fn asm_irq_37();
    fn asm_irq_38();
    fn asm_irq_39();
    fn asm_irq_40();
    fn asm_irq_41();
    fn asm_irq_42();
    fn asm_irq_43();
    fn asm_irq_44();
    fn asm_irq_45();
    fn asm_irq_46();
    fn asm_irq_47();
    fn asm_yield();
    fn asm_direct_switch();
    fn asm_lapic_timer();
    fn asm_tlb_ipi();
    fn asm_msi_0();
    fn asm_msi_1();
    fn asm_msi_2();
    fn asm_msi_3();
    fn asm_msi_4();
    fn asm_msi_5();
    fn asm_msi_6();
    fn asm_msi_7();
    fn asm_msi_8();
    fn asm_msi_9();
    fn asm_msi_10();
    fn asm_msi_11();
    fn asm_msi_12();
    fn asm_msi_13();
    fn asm_msi_14();
    fn asm_msi_15();
}

/// Initializes Hydra's IDT, installs all exception handlers, and loads the IDT.
pub fn init() {
    let mut idt = IDT.lock();
    // Read the active 64-bit code segment currently executing in the CPU
    let kernel_cs: u16;
    unsafe {
        core::arch::asm!("mov {:x}, cs", out(reg) kernel_cs);
    }

    // Populate all 256 gates with asm_trap_default so unassigned vectors never #GP
    for entry in idt.entries.iter_mut() {
        entry.set_handler_addr(asm_trap_default as *const () as usize, kernel_cs);
    }

    // Vector 0: #DE - Divide Error
    idt.entries[0].set_handler_addr(asm_trap_divide_error as *const () as usize, kernel_cs);
    // Vector 1: #DB - Debug Exception
    idt.entries[1].set_handler_addr(asm_trap_debug as *const () as usize, kernel_cs);
    // Vector 2: NMI - Non-Maskable Interrupt
    idt.entries[2].set_handler_addr(asm_trap_nmi as *const () as usize, kernel_cs);
    // Vector 3: #BP - Breakpoint (DPL 3 so Ring 3 can trigger int3)
    idt.entries[3]
        .set_handler_addr(asm_trap_breakpoint as *const () as usize, kernel_cs)
        .set_dpl(3);
    // Vector 4: #OF - Overflow
    idt.entries[4]
        .set_handler_addr(asm_trap_overflow as *const () as usize, kernel_cs)
        .set_dpl(3);
    // Vector 5: #BR - Bound Range Exceeded
    idt.entries[5].set_handler_addr(asm_trap_bound_range as *const () as usize, kernel_cs);
    // Vector 6: #UD - Invalid Opcode
    idt.entries[6].set_handler_addr(asm_trap_invalid_opcode as *const () as usize, kernel_cs);
    // Vector 7: #NM - Device Not Available (Coprocessor)
    idt.entries[7].set_handler_addr(asm_trap_device_not_avail as *const () as usize, kernel_cs);

    // Vector 8: #DF - Double Fault
    idt.entries[8].set_handler_addr(asm_trap_double_fault as *const () as usize, kernel_cs);

    // Vector 10: #TS - Invalid TSS
    idt.entries[10].set_handler_addr(asm_trap_invalid_tss as *const () as usize, kernel_cs);
    // Vector 11: #NP - Segment Not Present
    idt.entries[11].set_handler_addr(asm_trap_segment_not_present as *const () as usize, kernel_cs);
    // Vector 12: #SS - Stack-Segment Fault
    idt.entries[12].set_handler_addr(asm_trap_stack_segment_fault as *const () as usize, kernel_cs);
    // Vector 13: #GP - General Protection Fault
    idt.entries[13].set_handler_addr(asm_trap_general_protection as *const () as usize, kernel_cs);
    // Vector 14: #PF - Page Fault
    idt.entries[14].set_handler_addr(asm_trap_page_fault as *const () as usize, kernel_cs);
    // Vector 16: #MF - x87 Floating-Point Exception
    idt.entries[16].set_handler_addr(asm_trap_x87_floating_point as *const () as usize, kernel_cs);
    // Vector 17: #AC - Alignment Check
    idt.entries[17].set_handler_addr(asm_trap_alignment_check as *const () as usize, kernel_cs);
    // Vector 18: #MC - Machine Check
    idt.entries[18].set_handler_addr(asm_trap_machine_check as *const () as usize, kernel_cs);
    // Vector 19: #XM - SIMD Floating-Point Exception
    idt.entries[19].set_handler_addr(asm_trap_simd_floating_point as *const () as usize, kernel_cs);

    // Vectors 32..=47: Hardware IRQ gates (8259 PIC timer, keyboard, cascade, etc.)
    let irq_handlers = [
        asm_irq_32 as *const () as usize,
        asm_irq_33 as *const () as usize,
        asm_irq_34 as *const () as usize,
        asm_irq_35 as *const () as usize,
        asm_irq_36 as *const () as usize,
        asm_irq_37 as *const () as usize,
        asm_irq_38 as *const () as usize,
        asm_irq_39 as *const () as usize,
        asm_irq_40 as *const () as usize,
        asm_irq_41 as *const () as usize,
        asm_irq_42 as *const () as usize,
        asm_irq_43 as *const () as usize,
        asm_irq_44 as *const () as usize,
        asm_irq_45 as *const () as usize,
        asm_irq_46 as *const () as usize,
        asm_irq_47 as *const () as usize,
    ];
    for (i, &handler) in irq_handlers.iter().enumerate() {
        idt.entries[32 + i].set_handler_addr(handler, kernel_cs);
    }

    // Vector 0x80: `int $0x80` from user mode (Linux's 32-bit system call entry; see
    // compat::linux::ldt::int80)
    idt.entries[INT80_VECTOR as usize]
        .set_handler_addr(asm_int80 as *const () as usize, kernel_cs)
        .set_dpl(3);
    // Vector 0x81: voluntary reschedule (`task::yield_now`), kernel only
    idt.entries[YIELD_VECTOR as usize].set_handler_addr(asm_yield as *const () as usize, kernel_cs);
    // Vector 0x82: the direct switch of a forwarded Linux call (`crate::lx`), kernel only
    idt.entries[DIRECT_VECTOR as usize].set_handler_addr(asm_direct_switch as *const () as usize, kernel_cs);
    // Vector 0x40: an application processor's local APIC timer
    idt.entries[LAPIC_TIMER_VECTOR as usize].set_handler_addr(asm_lapic_timer as *const () as usize, kernel_cs);
    // Vector 0x42: a TLB flush request from another CPU
    idt.entries[crate::arch::smp::TLB_VECTOR as usize].set_handler_addr(asm_tlb_ipi as *const () as usize, kernel_cs);

    // Vectors 0x50..=0x5F: message-signalled interrupts of devices whose drivers run in
    // Ring 3 (see crate::ipc::service::msi_line)
    let msi_handlers = [
        asm_msi_0 as *const () as usize,
        asm_msi_1 as *const () as usize,
        asm_msi_2 as *const () as usize,
        asm_msi_3 as *const () as usize,
        asm_msi_4 as *const () as usize,
        asm_msi_5 as *const () as usize,
        asm_msi_6 as *const () as usize,
        asm_msi_7 as *const () as usize,
        asm_msi_8 as *const () as usize,
        asm_msi_9 as *const () as usize,
        asm_msi_10 as *const () as usize,
        asm_msi_11 as *const () as usize,
        asm_msi_12 as *const () as usize,
        asm_msi_13 as *const () as usize,
        asm_msi_14 as *const () as usize,
        asm_msi_15 as *const () as usize,
    ];
    for (i, &handler) in msi_handlers.iter().enumerate() {
        idt.entries[MSI_VECTOR_BASE as usize + i].set_handler_addr(handler, kernel_cs);
    }

    // Load IDT into CPU
    idt.load();
    drop(idt);
}

/// Loads the shared IDT on the calling CPU (an application processor starting).
pub fn load_on_this_cpu() {
    IDT.lock().load();
}

/// Enables the TSS Interrupt Stack Table (IST 1) for Double Fault (#DF) exceptions.
pub fn enable_double_fault_ist() {
    let mut idt = IDT.lock();
    idt.entries[8].set_ist(1);
    idt.load();
}

/// Updates the GDT code segment selector across all IDT gates and reloads the IDTR.
///
/// # Arguments
/// * `cs` - The new 16-bit kernel code segment selector.
pub fn reload_with_kernel_cs(cs: u16) {
    let mut idt = IDT.lock();
    for entry in idt.entries.iter_mut() {
        entry.selector = cs;
    }
    idt.load();
}

// wave6 G22 begin: the fix-up table of the user-memory copies (`crate::lx::copy`)
extern "sysv64" {
    fn hydra_uaccess_copy_insn();
    fn hydra_uaccess_copy_insn_end();
    fn hydra_uaccess_copy_fix();
    fn hydra_uaccess_str_insn();
    fn hydra_uaccess_str_insn_end();
    fn hydra_uaccess_str_fix();
}

/// The instructions that touch user memory on the kernel's behalf (`[start, end)`) and where
/// a fault on one resumes: the user-memory copies of `crate::lx::copy`, as Linux's exception
/// table. A fault there never goes to the ordinary page-fault handler.
static UACCESS_FIXUPS: [(unsafe extern "sysv64" fn(), unsafe extern "sysv64" fn(), unsafe extern "sysv64" fn()); 2] = [
    (hydra_uaccess_copy_insn, hydra_uaccess_copy_insn_end, hydra_uaccess_copy_fix),
    (hydra_uaccess_str_insn, hydra_uaccess_str_insn_end, hydra_uaccess_str_fix),
];

/// wave11 GG: per CPU, the address of the last page fault resumed at a user-copy fix-up.
pub static LAST_UACCESS_FAULT: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

/// Faults counted by [`uaccess_fixup`] (page faults resumed at a fix-up).
pub static UACCESS_FAULTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The fix-up address for a fault at kernel instruction `rip`, if it is a user-memory copy
/// (`debug`: a watchpoint, not counted).
pub fn uaccess_fixup(rip: u64, debug: bool) -> Option<u64> {
    for &(start, end, fix) in UACCESS_FIXUPS.iter() {
        // A watchpoint (a trap) reports the instruction after the access: the end counts
        if rip >= start as usize as u64 && (rip < end as usize as u64 || (debug && rip == end as usize as u64)) {
            if !debug {
                UACCESS_FAULTS.fetch_add(1, Ordering::Relaxed);
            }
            return Some(fix as usize as u64);
        }
    }
    None
}
// wave6 G22 end

use crate::console::SerialOnly;
/// Writes a line straight to the serial port, without the console lock (a fault report from
/// a CPU whose console lock or scheduler lock another CPU may wait on).
macro_rules! emerg {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!(SerialOnly, $($arg)*);
    }};
}

/// The words around a kernel fault's stack pointer and the registers, straight to the serial
/// port (no lock: the fault may have come under the scheduler lock), for a fault whose
/// instruction pointer is not code (a return address that was overwritten).
fn kernel_fault_stack(ctx: &ExceptionContext) {
    emerg!(
        "[!]   rax {:#x} rbx {:#x} rcx {:#x} rdx {:#x} rsi {:#x} rdi {:#x} rbp {:#x} r8 {:#x} r12 {:#x} r13 {:#x} r14 {:#x} r15 {:#x} anchor {:#x}",
        ctx.rax, ctx.rbx, ctx.rcx, ctx.rdx, ctx.rsi, ctx.rdi, ctx.rbp, ctx.r8, ctx.r12, ctx.r13, ctx.r14, ctx.r15,
        crate::arch::syscall::hydra_syscall_dispatcher as *const () as usize
    );
    // The current task's own kernel stack (64 KiB below the TSS top): the words that look
    // like kernel code addresses, lowest first (the call chain that went deep)
    let top = crate::arch::gdt::privilege_stack();
    if top >> 47 == 0x1_FFFF && top > 0x10000 {
        let text_lo = crate::arch::relocate::KERNEL_BASE + 0x1000;
        let text_hi = crate::arch::relocate::KERNEL_BASE + 0x40_0000;
        let mut a = if ctx.rsp < top && top - ctx.rsp < 0x4_0000 { ctx.rsp & !7 } else { top - 0x10000 };
        // (the stack the CPU is really on: from rsp up to 4 KiB above)
        let mut r = ctx.rsp & !7;
        while r < (ctx.rsp & !7) + 0x1000 {
            let w = unsafe { core::ptr::read_volatile(r as *const u64) };
            if w >= text_lo && w < text_hi {
                emerg!("[!]   onstack {:x} at {:x}", w - crate::arch::relocate::KERNEL_BASE + 0x1_0000_0000, r);
            }
            r += 8;
        }
        while a < top {
            // SAFETY: the current task's kernel stack (mapped, allocated); read only
            let w = unsafe { core::ptr::read_volatile(a as *const u64) };
            if w >= text_lo && w < text_hi {
                emerg!("[!]   chain {:x} at {:x}", w - crate::arch::relocate::KERNEL_BASE + 0x1_0000_0000, a);
            }
            a += 8;
        }
    }
    let base = (ctx.rsp & !7).wrapping_sub(0x100);
    if base >> 47 != 0x1_FFFF {
        return;
    }
    for row in 0..24u64 {
        let a = base + row * 32;
        // SAFETY: kernel stack memory near the faulting stack pointer (mapped: the CPU just
        // used it); read only
        let w: [u64; 4] = unsafe { core::array::from_fn(|i| core::ptr::read_volatile((a + i as u64 * 8) as *const u64)) };
        emerg!("[!]   {:#x}: {:#018x} {:#018x} {:#018x} {:#018x}", a, w[0], w[1], w[2], w[3]);
    }
}

/// Where each CPU was when the last NMI arrived (`rip`, `cs`), for the task dump.
pub static NMI_AT: [[core::sync::atomic::AtomicU64; 2]; crate::arch::smp::MAX_CPUS] =
    [const { [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)] }; crate::arch::smp::MAX_CPUS];

/// Central Rust exception dispatcher called by assembly trampolines.
///
/// # Arguments
/// * `ctx` - Mutable reference to the saved CPU exception frame.
/// * `fpu` - Pointer to the saved FXSAVE64 register area.
#[no_mangle]
extern "C" fn hydra_exception_handler(ctx: &mut ExceptionContext, fpu: *mut FpuState) {
    exception_handler(ctx, fpu)
}

/// The body of [`hydra_exception_handler`] (a Rust function: the host tests call it, and
/// their stand-ins for the kernel's halt unwind through it).
pub fn exception_handler(ctx: &mut ExceptionContext, fpu: *mut FpuState) {
    // wave6 G22 begin: a fault in a user-memory copy of the forwarding path resumes at the
    // copy's fix-up (before anything that takes a lock: the copy may run without the kernel
    // lock, under the request table's lock); a user watchpoint hit by such a copy is cleared
    if (ctx.cs & 3) == 0 && (ctx.vector == 14 || ctx.vector == 1) {
        if let Some(fix) = uaccess_fixup(ctx.rip, ctx.vector == 1) {
            if ctx.vector == 14 {
                // wave11 GG: where it faulted, for the EFAULT report (`lx::copy`)
                LAST_UACCESS_FAULT[crate::arch::percpu::cpu() % LAST_UACCESS_FAULT.len()].store(Cr2::read_raw(), Ordering::Relaxed);
                ctx.rip = fix;
            } else {
                crate::arch::debugregs::take_dr6();
            }
            return;
        }
    }
    // wave6 G22 end
    // An NMI (QEMU's `nmi` monitor command, on every CPU): note where this CPU was and ask
    // for a task dump (at the next tick); nothing else, it may arrive anywhere
    // A TLB flush request: served without the kernel lock (its sender holds it)
    if ctx.vector == crate::arch::smp::TLB_VECTOR {
        crate::arch::smp::serve_tlb();
        crate::arch::smp::lapic_eoi();
        // A kick for a task retired while running here in user mode: on to the full path,
        // which switches away from it (below)
        if !((ctx.cs & 3) == 3 && crate::task::current_retired()) {
            return;
        }
    }
    if ctx.vector == 2 {
        let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
        NMI_AT[cpu][0].store(ctx.rip, Ordering::Relaxed);
        NMI_AT[cpu][1].store(ctx.cs, Ordering::Relaxed);
        crate::arch::keyboard::TASK_DUMP_REQUESTED.store(true, Ordering::Relaxed);
        return;
    }
    // The PIT tick counts before the kernel lock is taken: code holding it on another CPU
    // may be waiting for time to pass
    if ctx.vector == 32 {
        crate::arch::pit::on_timer_tick();
        crate::arch::pic::send_eoi(0);
        // Group 13: linux-server's timers (timer_arm)
        crate::lx::timer::on_tick();
    }
    // An application processor's tick is acknowledged at once too: signal delivery on a
    // tick (below) may block the task (a stop) before the tick's work is done
    if ctx.vector == LAPIC_TIMER_VECTOR {
        crate::arch::smp::lapic_eoi();
    }
    // CPU time, at every tick: before the kernel lock, which another CPU may hold (the
    // scheduler lock is only tried; a tick finding it busy is counted by the next)
    if ctx.vector == 32 || ctx.vector == LAPIC_TIMER_VECTOR {
        if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
            sched.account_tick(ctx);
        }
    }
    // The kernel runs on one CPU at a time (see arch::smp); kept when returning to kernel
    // code (this CPU then runs it), released when returning to user mode. A timer tick
    // never waits for it: when another CPU holds it, this tick schedules nothing (waiting
    // would stop the clock that code holding it may be waiting on)
    if ctx.vector == 32 || ctx.vector == LAPIC_TIMER_VECTOR {
        if !crate::arch::smp::bkl_try_enter() {
            // The next system call's end on this CPU runs this tick's pass
            crate::task::TICK_DEFERRED.store(1, Ordering::Relaxed);
            return;
        }
    } else {
        crate::arch::smp::bkl_enter();
    }
    // A fault in user mode is handled outside other tasks' driver calls (it may take the
    // locks their callers hold); interrupts go on
    if (ctx.cs & 3) == 3 && (ctx.vector < 32 || ctx.vector == INT80_VECTOR) {
        // The task may wait, and resume on another CPU: the faulting address (CR2) is
        // taken now and put back for the handler
        let cr2 = x86_64::registers::control::Cr2::read_raw();
        crate::task::scheduler::wait_out_handoff();
        unsafe { write_cr2(cr2) };
    }
    let prev_fpu = CURRENT_TRAP_FPU.swap(fpu, Ordering::AcqRel);
    // A tick from user mode: deliver pending signals before the tick may switch away. A
    // task switched in on another task's frame gets no delivery on that return (below), so
    // its next trap is the only chance; when that is a tick that switches again (to the
    // kernel task posting its timer signals, itimerd/ptimerd), a busy thread would see a
    // signal only on the rare tick that does not switch. The frame is its own here.
    if (ctx.cs & 3) == 3
        && (ctx.vector == 32 || ctx.vector == LAPIC_TIMER_VECTOR)
        && crate::task::is_active()
        && crate::task::on_current_kernel_stack(ctx as *const ExceptionContext as u64)
    {
        crate::compat::linux::proc::deliver_on_trap_return(ctx, fpu);
    }
    dispatch_exception(ctx);
    // A device interrupt that made a driver call's server ready (its device answered): run
    // it now rather than at the next tick, when this CPU was running a program in user mode
    // (with one CPU, every disk request would otherwise wait for a tick)
    let device_irq = (ctx.vector > 32 && ctx.vector < 48) || (MSI_VECTOR_BASE..MSI_VECTOR_BASE + 16).contains(&ctx.vector);
    if (ctx.cs & 3) == 3 && device_irq && crate::task::is_active_hint() {
        if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
            sched.apply_wakes();
            if sched.handoff_server_ready() {
                sched.schedule_now(ctx);
            }
        }
    }
    // A task retired while it ran here never returns to user mode: switch away (as the
    // yield vector does; the scheduler does not pick a dead task again), nor does the one
    // switched to if it was retired too
    while (ctx.cs & 3) == 3 && crate::task::current_retired() && crate::task::is_active() {
        loop {
            if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                sched.bury_current();
                sched.schedule_now(ctx);
                break;
            }
            crate::arch::smp::serve_tlb();
            core::hint::spin_loop();
        }
    }
    // Returning to user mode: run any pending signal handlers first
    if (ctx.cs & 3) == 3 && crate::task::is_active() {
        crate::lx::console::trap_pump(); // wave8 GT: tty.rs's pump, or (tty-server down) the console's Ctrl+C
        // After a task switch this frame is on the previous task's stack: delivering here
        // could exit or stop the new task on it. Its next trap on its own stack (a timer
        // tick within its timeslice, a system call or a fault) delivers instead.
        if crate::task::on_current_kernel_stack(ctx as *const ExceptionContext as u64) {
            crate::compat::linux::proc::deliver_on_trap_return(ctx, fpu);
        }
    }
    CURRENT_TRAP_FPU.store(prev_fpu, Ordering::Release);
    // Returning to user mode releases the kernel lock, but only in the epilogue
    // (common_trap_handler), once the frame is off this task's kernel stack: after a task
    // switch the frame is on the previous task's stack, and another CPU taking the lock may
    // resume that task there at once, overwriting the frame before this CPU's iretq
}

/// A thread's x87/SSE/AVX state: an `XSAVE` area in the standard format (the 512-byte
/// `FXSAVE` image, the 64-byte XSAVE header, then the AVX upper halves at 576), saved and
/// restored with `XSAVE64`/`XRSTOR64` where the CPU has XSAVE ([`use_xsave`]), otherwise
/// with `FXSAVE64`/`FXRSTOR64` (only the first 512 bytes).
#[repr(C, align(64))]
#[derive(Clone)]
pub struct FpuState(pub [u8; FPU_AREA]);

/// Bytes of an [`FpuState`] (x87, SSE and AVX need 832; AVX-512 is not enabled).
pub const FPU_AREA: usize = 1024;
/// XSAVE header: `XSTATE_BV`, the components the area holds (bit 0 x87, 1 SSE, 2 AVX).
const XSTATE_BV: usize = 512;

/// XSAVE is used (set at boot by [`enable_xsave`] on every CPU): 1, else 0. Read by the
/// trap and system call entries.
#[export_name = "hydra_use_xsave"]
static USE_XSAVE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// The state components enabled in XCR0 (x87 | SSE, and AVX where the CPU has it).
static XCR0: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Bytes of the XSAVE area for [`XCR0`] (CPUID 0Dh), 512 without XSAVE.
static XSAVE_SIZE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(512);

/// Whether FPU state is saved with XSAVE.
pub fn use_xsave() -> bool {
    USE_XSAVE.load(Ordering::Relaxed) != 0
}

/// The enabled XSAVE components (XCR0), 0 without XSAVE.
pub fn xcr0() -> u64 {
    XCR0.load(Ordering::Relaxed)
}

/// Bytes of the state an XSAVE writes (the signal frame's FPU area), 512 without XSAVE.
pub fn xsave_size() -> usize {
    XSAVE_SIZE.load(Ordering::Relaxed) as usize
}

/// Turns on XSAVE and the AVX registers on the calling CPU (CR4.OSXSAVE, XCR0 = x87 | SSE
/// | AVX), when the CPU has them: Windows programs use AVX after only checking that the
/// CPU has it, which faults (invalid opcode) while the OS leaves it off. The boot
/// processor decides; application processors repeat its choice. Without XSAVE (older
/// CPUs, some emulated ones) FXSAVE stays in use.
pub fn enable_xsave(boot_processor: bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let id1 = cpuid(1, 0);
    let has_xsave = id1.ecx & (1 << 26) != 0;
    let has_avx = id1.ecx & (1 << 28) != 0;
    if boot_processor {
        if !has_xsave {
            return;
        }
        unsafe { Cr4::update(|f| f.insert(Cr4Flags::OSXSAVE)) };
        let mut mask = 0b011u64;
        if has_avx {
            xsetbv(0b111);
            // The area for these components must fit an FpuState
            let size = cpuid(0xD, 0).ebx;
            if size as usize <= FPU_AREA {
                mask = 0b111;
            }
        }
        xsetbv(mask);
        let size = cpuid(0xD, 0).ebx;
        XCR0.store(mask, Ordering::Relaxed);
        XSAVE_SIZE.store(size, Ordering::Relaxed);
        USE_XSAVE.store(1, Ordering::Release);
    } else if use_xsave() && has_xsave {
        unsafe { Cr4::update(|f| f.insert(Cr4Flags::OSXSAVE)) };
        xsetbv(xcr0());
    }
}

/// Sets XCR0 (the enabled XSAVE components) on the calling CPU (CR4.OSXSAVE must be set).
#[cfg(target_os = "uefi")]
fn xsetbv(mask: u64) {
    unsafe {
        core::arch::asm!("xsetbv", in("ecx") 0u32, in("eax") mask as u32, in("edx") (mask >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// CPUID `leaf`, `sub`-leaf.
#[cfg(target_os = "uefi")]
fn cpuid(leaf: u32, sub: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid_count(leaf, sub)
}

/// Puts back CR2 (the faulting address) after a wait that may have changed CPUs.
#[cfg(target_os = "uefi")]
unsafe fn write_cr2(v: u64) {
    core::arch::asm!("mov cr2, {}", in(reg) v, options(nostack, preserves_flags));
}

// Host build (unit tests): the test thread's fake CPU (XCR0 as MSR-like state, CPUID
// answers, CR2 in the shim)
#[cfg(not(target_os = "uefi"))]
fn xsetbv(mask: u64) {
    crate::host::XCR0.set(mask)
}

#[cfg(not(target_os = "uefi"))]
fn cpuid(leaf: u32, sub: u32) -> core::arch::x86_64::CpuidResult {
    crate::host::cpuid(leaf, sub)
}

#[cfg(not(target_os = "uefi"))]
unsafe fn write_cr2(v: u64) {
    x86_64::hw::set_cr(2, v)
}

impl FpuState {
    /// Power-on state: all exceptions masked (FCW = 0x037F, MXCSR = 0x1F80), no AVX state
    /// (XSTATE_BV 0: XRSTOR loads the components' initial values, MXCSR from the area).
    ///
    /// # Returns
    ///
    /// A new initialized [`FpuState`] instance.
    pub fn new() -> Self {
        let mut area = [0u8; FPU_AREA];
        area[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        area[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        Self(area)
    }

    /// Marks the 512-byte FXSAVE image as holding the x87 and SSE state (after code wrote
    /// it, a signal frame or a debugger): XRSTOR then loads it rather than initial values.
    pub fn legacy_written(&mut self) {
        self.0[XSTATE_BV] |= 0b011;
    }
}

/// Software interrupt vector used by `task::yield_now` for voluntary rescheduling.
pub const YIELD_VECTOR: u64 = 0x81;
/// Software interrupt vector of the direct switch (`crate::lx`): to the task
/// `task::scheduler::DIRECT_TO` names, without saving or restoring FPU state (both sides
/// block only where the compiler keeps nothing in vector registers).
pub const DIRECT_VECTOR: u64 = 0x82;

/// The direct switch's handler (vector [`DIRECT_VECTOR`], from `asm_direct_switch`, which
/// saves only the general registers): `Scheduler::direct_call` to the task `DIRECT_TO`
/// names (hint `DIRECT_HINT`, guard `DIRECT_GUARD`), with or without the kernel lock. When
/// that cannot be done here, nothing changed and `rax` comes back 1.
#[no_mangle]
extern "C" fn hydra_direct_switch_handler(ctx: &mut ExceptionContext) {
    direct_switch_handler(ctx)
}

/// The body of [`hydra_direct_switch_handler`] (a Rust function, for the host tests).
pub fn direct_switch_handler(ctx: &mut ExceptionContext) {
    let target = crate::task::scheduler::DIRECT_TO.swap(0, Ordering::Relaxed);
    let hint = crate::task::scheduler::DIRECT_HINT.load(Ordering::Relaxed) as usize;
    let guard = crate::task::scheduler::DIRECT_GUARD.swap(0, Ordering::Relaxed) as *const core::sync::atomic::AtomicBool;
    let mut switched = false;
    if target != 0 && crate::task::is_active() {
        // No FPU area: the switch moves none (see DIRECT_VECTOR)
        let prev = CURRENT_TRAP_FPU.swap(core::ptr::null_mut(), Ordering::AcqRel);
        loop {
            if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                switched = sched.direct_call(ctx, target - 1, hint, guard);
                break;
            }
            crate::arch::smp::serve_tlb();
            core::hint::spin_loop();
        }
        CURRENT_TRAP_FPU.store(prev, Ordering::Release);
    }
    if !switched {
        ctx.rax = 1;
    }
}
/// `int $0x80`: Linux's 32-bit system call gate (DPL 3).
pub const INT80_VECTOR: u64 = 0x80;

/// Vector of the application processors' local APIC timers (their scheduling tick).
pub const LAPIC_TIMER_VECTOR: u64 = 0x40;
/// First of the 16 vectors of message-signalled device interrupts (MSI lines 16..32 of
/// [`crate::ipc::service`], delivered by the local APIC: acknowledged with its EOI).
pub const MSI_VECTOR_BASE: u64 = 0x50;

/// FPU save area of the innermost trap frame being handled. The scheduler swaps task FPU
/// state through it; the trap stub restores from it before `iretq`.
pub static CURRENT_TRAP_FPU: crate::arch::percpu::PerCpuPtr<FpuState> = crate::arch::percpu::PerCpuPtr::new();

/// Consecutive timer ticks spent in kernel code outside a wait point.
static KERNEL_BUSY_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reports kernel code that runs for seconds without reaching a wait point (a spinning
/// lock or an endless loop): the interrupted instruction pointer identifies the culprit.
///
/// # Arguments
/// * `ctx` - Interrupted CPU register context.
/// * `at_preempt_point` - Whether execution is at an explicit preemptible wait point.
fn kernel_watchdog(ctx: &ExceptionContext, at_preempt_point: bool) {
    // A new system call since the last tick: not stuck in one (with several CPUs a tick
    // often lands right after waiting for the kernel lock at a call's entry)
    static LAST_ENTRIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let entries = crate::arch::syscall::SYSCALL_ENTRIES.load(Ordering::Relaxed);
    let new_call = LAST_ENTRIES.swap(entries, Ordering::Relaxed) != entries;
    if at_preempt_point || new_call {
        KERNEL_BUSY_TICKS.store(0, Ordering::Relaxed);
        return;
    }
    let busy = KERNEL_BUSY_TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if busy % 500 == 0 {
        // No allocation or console lock here: either may be what the kernel is stuck on
        let mut b = crate::console::FixedBuf::new();
        let _ = core::fmt::Write::write_fmt(
            &mut b,
            // `anchor` locates the image: rip - anchor + map address of hydra_syscall_dispatcher
            format_args!(
                "[watchdog] kernel busy for {} s: rip={:#x} rsp={:#x} anchor={:#x}\n",
                busy / 100,
                ctx.rip,
                ctx.rsp,
                crate::arch::syscall::hydra_syscall_dispatcher as *const () as usize
            ),
        );
        crate::console::serial_write(b.as_str());
    }
}

/// Kills the current user task after an unrecoverable fault and switches away from it.
///
/// # Arguments
/// * `ctx` - CPU exception register context.
fn kill_current_user_task(ctx: &mut ExceptionContext) {
    kill_or_signal(ctx, 11);
}

/// Handles an unrecoverable fault of the current task. Linux processes faulting in user
/// mode receive the matching signal (their handler may recover); otherwise the task ends.
///
/// # Arguments
/// * `ctx` - CPU exception register context.
/// * `sig` - POSIX signal number (e.g. SIGSEGV=11, SIGILL=4).
fn kill_or_signal(ctx: &mut ExceptionContext, sig: u32) {
    let linux = crate::task::current_personality().is_posix();
    if linux && (ctx.cs & 3) == 3 {
        let fpu = CURRENT_TRAP_FPU.load(Ordering::Acquire);
        crate::compat::linux::proc::force_fault_signal(ctx, fpu, sig);
        return;
    }
    if linux {
        let (_, pid) = crate::compat::linux::proc::current_ids();
        crate::compat::linux::proc::set_exit_status(pid, sig as i32);
        let mut sched = crate::task::SCHEDULER.lock();
        sched.terminate_current_group();
        sched.terminate_current();
        sched.schedule(ctx);
        return;
    }
    let mut sched = crate::task::SCHEDULER.lock();
    sched.terminate_current();
    sched.schedule(ctx);
}

/// Routes CPU trap vectors to architecture handlers or userland task termination.
///
/// # Arguments
/// * `ctx` - CPU exception register context.
fn dispatch_exception(ctx: &mut ExceptionContext) {
    match ctx.vector {
        INT80_VECTOR if (ctx.cs & 3) == 3 && crate::task::current_personality() == crate::task::TaskPersonality::Linux => {
            ctx.rax = crate::compat::linux::ldt::int80(ctx.rax, ctx.rbx) as u64;
            // The call may have deleted the descriptor the caller's ss names
            crate::arch::segments::sanitize_frame(&mut ctx.cs, &mut ctx.ss, &mut ctx.rip);
        }
        1 if (ctx.cs & 3) == 3 && crate::task::current_personality().is_posix() => {
            // #DB - a single step (trap flag) or a debugger's hardware breakpoint or
            // watchpoint: SIGTRAP. DR6 says which (kept for the debugger's PEEKUSER).
            let dr6 = crate::arch::debugregs::take_dr6();
            crate::task::with_current_task_mut(|t| t.debugregs[6] = dr6);
            if dr6 & 0xf == 0 || dr6 & 0x4000 != 0 {
                ctx.rflags &= !0x100;
            } else {
                // An instruction breakpoint must not fire again on the way back (RF)
                ctx.rflags |= 0x1_0000;
            }
            ctx.error_code = dr6; // for the signal's si_code
            kill_or_signal(ctx, 5);
        }
        1 => {
            // #DB in the kernel: a user watchpoint touched by the kernel on the user's behalf
            crate::arch::debugregs::take_dr6();
        }
        3 if (ctx.cs & 3) == 3 && crate::task::current_personality().is_posix() => {
            // int3 in a Linux program: SIGTRAP (debuggers' breakpoints)
            kill_or_signal(ctx, 5);
        }
        3 => {
            // #BP - Breakpoint Exception (Int3)
            set_color(Color::LightCyan, Color::Black);
            let pid = if crate::task::is_active() { crate::task::SCHEDULER.lock().current_task_id().0 } else { 0 };
            let (exe, cmd) = if crate::task::is_active() {
                crate::task::SCHEDULER.lock().with_process(pid, |t| {
                    let cmd_str = t.cmdline.as_ref().map(|c| {
                        c.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| core::str::from_utf8(s).unwrap_or("?")).collect::<alloc::vec::Vec<_>>().join(" ")
                    });
                    (alloc::string::String::from(t.exe_path()), cmd_str)
                }).unwrap_or_default()
            } else {
                (alloc::string::String::new(), None)
            };
            println!("\n[i] CPU BREAKPOINT TRAP (#BP) in Task PID {} ({}) at RIP: {:#x}", pid, exe, ctx.rip);
            if let Some(c) = cmd {
                println!("    Command: {}", c);
            }
            println!("    RFLAGS: {:#x}, RSP: {:#x}, RAX: {:#x}, RDI: {:#x}, RSI: {:#x}", ctx.rflags, ctx.rsp, ctx.rax, ctx.rdi, ctx.rsi);
            if (ctx.cs & 3) == 3 && ctx.rsp != 0 && crate::memory::vm::prefault_current(ctx.rsp, 48, false) {
                let stack = unsafe { core::slice::from_raw_parts(ctx.rsp as *const u64, 6) };
                println!("    Stack: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]", stack[0], stack[1], stack[2], stack[3], stack[4], stack[5]);
            }
            let rip_start = ctx.rip.saturating_sub(4);
            if (ctx.cs & 3) == 3 && crate::memory::vm::prefault_current(rip_start, 16, false) {
                let code = unsafe { core::slice::from_raw_parts(rip_start as *const u8, 16) };
                println!("    Code: {:02x?}", code);
            }
        }
        14 => {
            // #PF - Page Fault Exception
            let fault_addr = Cr2::read_raw();
            let is_user = (ctx.error_code & (1 << 2)) != 0 || (ctx.cs & 3) == 3;
            let is_write = (ctx.error_code & (1 << 1)) != 0;
            let is_fetch = (ctx.error_code & (1 << 4)) != 0;

            // Demand paging and copy-on-write for processes with their own address space.
            // Kernel accesses to user memory (syscall buffers) are resolved the same way.
            // A page a userfaultfd handler supplies is waited for first (user faults only)
            if (ctx.cs & 3) == 3 {
                crate::memory::vm::uffd_resolve_current(fault_addr, is_write, false);
            }
            let resolved = crate::memory::vm::handle_current_fault(fault_addr, is_write, is_fetch);
            if crate::compat::linux::TRACE_SYSCALLS.load(Ordering::Relaxed) && is_user && crate::compat::linux::trace_matches_current() {
                static FAULTS_LOGGED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
                if FAULTS_LOGGED.fetch_add(1, Ordering::Relaxed) < 400 {
                    crate::println!(
                        "[fault] addr={:#x} rip={:#x} err={:#x} user={} -> {:?}",
                        fault_addr, ctx.rip, ctx.error_code, is_user, resolved
                    );
                }
            }
            if let Some(Ok(())) = resolved {
                if is_user && crate::compat::linux::perf::active() {
                    crate::compat::linux::perf::fault(crate::compat::linux::proc::current_ids().1);
                }
                return;
            }
            let user_space_fault = resolved.is_some();

            if (is_user || user_space_fault) && crate::task::is_active() {
                let linux_user = is_user && crate::task::current_personality().is_posix();
                if linux_user {
                    let sig = if resolved == Some(Err(crate::memory::vm::FaultError::Bus)) { 7 } else { 11 };
                    if sig == 7 {
                        // A file mapping with no page there (past the end of the file)
                        crate::kprintln!("[linux] SIGBUS: {} at {:#x}, rip {:#x}", if is_write { "write" } else { "read" }, fault_addr, ctx.rip);
                    }
                    kill_or_signal(ctx, sig);
                    return;
                }
                set_color(Color::LightRed, Color::Black);
                let pid = crate::task::SCHEDULER.lock().current_task_id();
                let reason = match resolved {
                    Some(Err(crate::memory::vm::FaultError::Bus)) => "Bus Error (SIGBUS)",
                    Some(Err(crate::memory::vm::FaultError::OutOfMemory)) => "Out of Memory",
                    _ => "Segmentation Fault (SIGSEGV)",
                };
                println!("\n[!] USER FAULT: {} (#PF) in Task PID {}", reason, pid.0);
                println!(
                    "    Faulting Address (CR2): {:#x} ({} {}, {} mode)",
                    fault_addr,
                    if is_fetch { "exec" } else if is_write { "write" } else { "read" },
                    if (ctx.error_code & 1) != 0 { "protection" } else { "not-present" },
                    if is_user { "user" } else { "kernel" }
                );
                println!("    Instruction Pointer   : {:#x}, Error Code: {:#x}, RSP: {:#x}", ctx.rip, ctx.error_code, ctx.rsp);
                kill_current_user_task(ctx);
                return;
            }

            // First straight to the serial port: the report below goes through the current
            // task's descriptors (the scheduler lock), which a fault under that lock never gets
            emerg!(
                "[!] KERNEL PAGE FAULT: cr2 {:#x} rip {:#x} err {:#x} rsp {:#x} cpu {} task {} stack top {:#x} (scheduler lock held: {})",
                fault_addr,
                ctx.rip,
                ctx.error_code,
                ctx.rsp,
                crate::arch::percpu::cpu(),
                crate::task::CURRENT_TID.load(Ordering::Relaxed),
                crate::arch::gdt::privilege_stack(),
                crate::task::SCHEDULER.is_locked()
            );
            kernel_fault_stack(ctx);
            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: PAGE FAULT (#PF)");
            println!("============================================================");
            println!("  Faulting Virtual Address (CR2): {:#x}", fault_addr);
            println!("  Instruction Pointer      (RIP): {:#x}", ctx.rip);
            println!("  Error Code                    : {:#x}", ctx.error_code);

            // Decode error code bits
            let is_present = (ctx.error_code & (1 << 0)) != 0;
            let is_write = (ctx.error_code & (1 << 1)) != 0;
            let is_inst_fetch = (ctx.error_code & (1 << 4)) != 0;

            println!("  Root Cause Details:");
            println!("    - Page Status: {}", if is_present { "Protection Violation (Present)" } else { "Not Present" });
            println!("    - Access Type: {}", if is_write { "Write" } else { "Read" });
            println!("    - Mode       : {}", if is_user { "User Mode (Ring 3)" } else { "Kernel Mode (Ring 0)" });
            println!("    - Fetch Type : {}", if is_inst_fetch { "Instruction Execution" } else { "Data Access" });
            print_cpu_dump(ctx);

            panic_halt();
        }
        13 => {
            // #GP - General Protection Fault
            let is_user = (ctx.cs & 3) == 3;

            if is_user && crate::task::is_active() {
                set_color(Color::LightRed, Color::Black);
                let pid = crate::task::SCHEDULER.lock().current_task_id();
                println!("\n[!] USER FAULT: General Protection Fault (#GP) in Task PID {}", pid.0);
                println!("    Privilege Violation at RIP: {:#x}, Selector/Error: {:#x}", ctx.rip, ctx.error_code);
                kill_or_signal(ctx, 11);
                return;
            }

            // (straight to the serial port first, as for #PF)
            emerg!("[!] KERNEL #GP: rip {:#x} err {:#x} rsp {:#x} cpu {} task {} stack top {:#x} (scheduler lock held: {})", ctx.rip, ctx.error_code, ctx.rsp, crate::arch::percpu::cpu(), crate::task::CURRENT_TID.load(Ordering::Relaxed), crate::arch::gdt::privilege_stack(), crate::task::SCHEDULER.is_locked());
            kernel_fault_stack(ctx);
            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: GENERAL PROTECTION FAULT (#GP)");
            println!("============================================================");
            println!("  Instruction Pointer (RIP): {:#x}", ctx.rip);
            // rip - anchor + map address of hydra_syscall_dispatcher (tools/symbolize.py)
            println!("  Image anchor             : {:#x}", crate::arch::syscall::hydra_syscall_dispatcher as *const () as usize);
            println!("  Segment Selector / Error : {:#x}", ctx.error_code);
            print_cpu_dump(ctx);

            panic_halt();
        }
        8 => {
            // #DF - Double Fault (IST Stack)
            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: DOUBLE FAULT (#DF - RECOVERY STACK)");
            println!("============================================================");
            println!("  Instruction Pointer (RIP): {:#x}", ctx.rip);
            println!("  Error Code               : {:#x}", ctx.error_code);
            print_cpu_dump(ctx);

            panic_halt();
        }
        6 => {
            // #UD - Invalid Opcode
            let is_user = (ctx.cs & 3) == 3;
            if is_user && crate::task::is_active() {
                set_color(Color::LightRed, Color::Black);
                let pid = crate::task::SCHEDULER.lock().current_task_id().0;
                let (exe, cmd) = crate::task::SCHEDULER.lock().with_process(pid, |t| {
                    let cmd_str = t.cmdline.as_ref().map(|c| {
                        c.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| core::str::from_utf8(s).unwrap_or("?")).collect::<alloc::vec::Vec<_>>().join(" ")
                    });
                    (alloc::string::String::from(t.exe_path()), cmd_str)
                }).unwrap_or_default();
                println!("\n[!] USER FAULT: Invalid Opcode (#UD) in Task PID {} ({})", pid, exe);
                if let Some(c) = cmd {
                    println!("    Command: {}", c);
                }
                println!("    Faulting RIP: {:#x}", ctx.rip);
                if ctx.rsp != 0 && crate::memory::vm::prefault_current(ctx.rsp, 48, false) {
                    let stack = unsafe { core::slice::from_raw_parts(ctx.rsp as *const u64, 6) };
                    println!("    Stack: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]", stack[0], stack[1], stack[2], stack[3], stack[4], stack[5]);
                }
                if crate::memory::vm::prefault_current(ctx.rip, 16, false) {
                    let code = unsafe { core::slice::from_raw_parts(ctx.rip as *const u8, 16) };
                    println!("    Code: {:02x?}", code);
                }
                kill_or_signal(ctx, 4);
                return;
            }

            emerg!("[!] KERNEL #UD: rip {:#x} rsp {:#x} cpu {} task {} stack top {:#x} (scheduler lock held: {})", ctx.rip, ctx.rsp, crate::arch::percpu::cpu(), crate::task::CURRENT_TID.load(Ordering::Relaxed), crate::arch::gdt::privilege_stack(), crate::task::SCHEDULER.is_locked());
            kernel_fault_stack(ctx);
            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: INVALID OPCODE (#UD)");
            println!("============================================================");
            println!("  Instruction Pointer (RIP): {:#x}", ctx.rip);
            print_cpu_dump(ctx);

            panic_halt();
        }
        0 => {
            // #DE - Divide Error
            let is_user = (ctx.cs & 3) == 3;
            if is_user && crate::task::is_active() {
                set_color(Color::LightRed, Color::Black);
                let pid = crate::task::SCHEDULER.lock().current_task_id();
                println!("\n[!] USER FAULT: Divide-by-Zero (#DE) in Task PID {}", pid.0);
                println!("    Faulting RIP: {:#x}", ctx.rip);
                kill_or_signal(ctx, 8);
                return;
            }

            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: DIVIDE-BY-ZERO (#DE)");
            println!("============================================================");
            println!("  Instruction Pointer (RIP): {:#x}", ctx.rip);
            print_cpu_dump(ctx);

            panic_halt();
        }
        32 => {
            // Vector 32 = IRQ 0: 8254 PIT Timer Tick (counted and acknowledged on entry)
            crate::video::splash::tick();


            // Preemptive Multitasking Round-Robin Scheduling: only user mode and kernel
            // wait points are preempted (see `task::preemptible`)
            let at_preempt_point = (ctx.cs & 3) == 3
                || crate::task::PREEMPT_POINTS.load(core::sync::atomic::Ordering::SeqCst) > 0;
            if at_preempt_point && crate::task::is_active() {
                if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                    sched.schedule(ctx);
                }
            } else if crate::task::is_active() {
                // In kernel code (a system call): its end runs this tick's pass
                // (task::tick_on_return). Also when the tick came right as the call enabled
                // interrupts, before it is marked as in a call
                crate::task::TICK_DEFERRED.store(1, Ordering::Relaxed);
            }
            kernel_watchdog(ctx, at_preempt_point);
            if crate::arch::keyboard::TASK_DUMP_REQUESTED.load(Ordering::Relaxed) && crate::task::is_active() {
                if let Some(sched) = crate::task::SCHEDULER.try_lock() {
                    crate::arch::keyboard::TASK_DUMP_REQUESTED.store(false, Ordering::Relaxed);
                    sched.dump_tasks();
                }
            }
        }
        LAPIC_TIMER_VECTOR => {
            // An application processor's tick: its tasks' timeslices (the time base and
            // the sleepers' wakeups are the boot processor's PIT; acknowledged on entry)
            let at_preempt_point = (ctx.cs & 3) == 3
                || crate::task::PREEMPT_POINTS.load(core::sync::atomic::Ordering::SeqCst) > 0;
            if at_preempt_point && crate::task::is_active() {
                if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                    sched.schedule(ctx);
                }
            } else if crate::task::is_active() {
                // In kernel code (a system call): its end runs this tick's pass
                // (task::tick_on_return). Also when the tick came right as the call enabled
                // interrupts, before it is marked as in a call
                crate::task::TICK_DEFERRED.store(1, Ordering::Relaxed);
            }
        }
        YIELD_VECTOR => {
            // Voluntary yield: the caller holds no locks, so switching is always safe. It
            // must switch (the caller may have just blocked itself): another CPU may hold
            // the scheduler lock for a moment, so wait for it rather than give up
            if crate::task::is_active() {
                // The direct switch of a forwarded Linux call names the task to run next
                let direct = crate::task::scheduler::DIRECT_TO.swap(0, Ordering::Relaxed);
                // A deferred tick's pass (task::tick_on_return): the task may go on
                let tick = crate::task::TICK_YIELD.swap(0, Ordering::Relaxed) != 0;
                loop {
                    if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                        if direct != 0 {
                            sched.direct_switch(ctx, direct - 1);
                        } else if tick {
                            sched.schedule(ctx);
                        } else {
                            sched.schedule_now(ctx);
                        }
                        break;
                    }
                    crate::arch::smp::serve_tlb();
                    core::hint::spin_loop();
                }
            }
        }
        33 => {
            // Vector 33 = IRQ 1: 8042 PS/2 Keyboard Scancode Available
            crate::arch::keyboard::on_keyboard_irq();
            crate::arch::pic::send_eoi(1);
        }
        44 => {
            // Vector 44 = IRQ 12: PS/2 mouse byte
            crate::arch::mouse::on_mouse_irq();
            crate::arch::pic::send_eoi(12);
        }
        34..=47 => {
            // Hardware IRQs from legacy 8259 PIC (Cascade, Serial, Floppy, RTC, etc.)
            let irq = (ctx.vector - 32) as u8;

            // A line routed to a driver process: masked, counted, and its driver (and the
            // kernel task that talks to it, such as the network task) woken
            let driver = crate::ipc::service::irq_raised(irq);
            crate::arch::pic::send_eoi(irq);
            // Run the woken task now rather than at the end of the current timeslice
            let at_preempt_point = (ctx.cs & 3) == 3
                || crate::task::PREEMPT_POINTS.load(core::sync::atomic::Ordering::SeqCst) > 0;
            if driver && at_preempt_point && crate::task::is_active() && !crate::task::scheduler::handoff_active() {
                if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                    sched.schedule_now(ctx);
                }
            }
        }
        v if (MSI_VECTOR_BASE..MSI_VECTOR_BASE + 16).contains(&v) => {
            // A device's message-signalled interrupt: its driver's line, as above, but
            // acknowledged at the local APIC (nothing to mask: the driver's next wait
            // finds the count)
            let irq = crate::ipc::service::MSI_FIRST_LINE + (v - MSI_VECTOR_BASE) as u8;
            let driver = crate::ipc::service::irq_raised(irq);
            crate::arch::smp::lapic_eoi();
            let at_preempt_point = (ctx.cs & 3) == 3
                || crate::task::PREEMPT_POINTS.load(core::sync::atomic::Ordering::SeqCst) > 0;
            if driver && at_preempt_point && crate::task::is_active() && !crate::task::scheduler::handoff_active() {
                if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                    sched.schedule_now(ctx);
                }
            }
        }
        20..=31 | 48..=255 => {
            // Spurious or unhandled interrupt / trap - return cleanly
        }
        unknown => {
            set_color(Color::LightRed, Color::Black);
            println!("\n[!] UNHANDLED CPU EXCEPTION #{}: Error Code={:#x}", unknown, ctx.error_code);
            println!("    RIP={:#x}, CS={:#x}, RSP={:#x}, SS={:#x}", ctx.rip, ctx.cs, ctx.rsp, ctx.ss);
            print_cpu_dump(ctx);

            panic_halt();
        }
    }
}

/// Dumps general-purpose CPU register states to standard output.
///
/// # Arguments
/// * `ctx` - The CPU exception frame to print.
fn print_cpu_dump(ctx: &ExceptionContext) {
    // Which task, and the kernel code addresses on its stack (a rough backtrace for
    // tools/symbolize.py: address - anchor + map address of hydra_syscall_dispatcher).
    // Nothing here allocates: the fault may have hit inside the heap allocator.
    let anchor = crate::arch::syscall::hydra_syscall_dispatcher as *const () as u64;
    // Copied out under the lock, printed after it (console output may need the scheduler)
    let mut name = [0u8; 64];
    let mut len = 0;
    let id = crate::task::SCHEDULER.try_lock().map(|mut sched| {
        let id = sched.current_task_id().0;
        sched.current_task_mut(|t| {
            let b = t.exe_path().as_bytes();
            len = b.len().min(64);
            name[..len].copy_from_slice(&b[..len]);
        });
        id
    });
    println!("  Task: {:?} ({})  anchor={:#x}", id, core::str::from_utf8(&name[..len]).unwrap_or("?"), anchor);
    if ctx.cs & 3 == 0 && ctx.rsp > 0x1000 {
        crate::print!("  Stack code addresses:");
        // Only to the end of the stack pointer's page: the next one may not be mapped
        let words = (0x1000 - (ctx.rsp & 0xfff)) / 8;
        for i in 0..words {
            let v = unsafe { core::ptr::read_volatile((ctx.rsp + i * 8) as *const u64) };
            if v > anchor.saturating_sub(0x10_0000) && v < anchor + 0x20_0000 {
                crate::print!(" {:#x}", v);
            }
        }
        println!();
    }
    println!("  Register State:");
    println!("    RAX={:#018x}  RBX={:#018x}  RCX={:#018x}", ctx.rax, ctx.rbx, ctx.rcx);
    println!("    RDX={:#018x}  RSI={:#018x}  RDI={:#018x}", ctx.rdx, ctx.rsi, ctx.rdi);
    println!("    RBP={:#018x}  RSP={:#018x}  RFLAGS={:#018x}", ctx.rbp, ctx.rsp, ctx.rflags);
    println!("    R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}", ctx.r8, ctx.r9, ctx.r10);
    println!("    R11={:#018x}  R12={:#018x}  R13={:#018x}", ctx.r11, ctx.r12, ctx.r13);
    println!("    R14={:#018x}  R15={:#018x}  CS:RIP={:#04x}:{:#018x}", ctx.r14, ctx.r15, ctx.cs, ctx.rip);
}

/// Disables interrupts and permanently halts the CPU.
///
/// # Returns
///
/// This function never returns (!).
fn panic_halt() -> ! {
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

// ---------------------------------------------------------------------------
// Assembly Trampolines
// Pushes dummy error code for exceptions that don't produce one, pushes GPRs,
// calls the common dispatcher, restores GPRs, and executes iretq.
// ---------------------------------------------------------------------------
global_asm!(
    r#"
    .macro TRAP_NO_ERRCODE name, vec
    .global \name
    \name:
        push 0                  // Dummy error code
        push \vec               // Vector number
        jmp common_trap_handler
    .endm

    .macro TRAP_ERRCODE name, vec
    .global \name
    \name:
        push \vec               // Vector number (error code already pushed by hardware)
        jmp common_trap_handler
    .endm

    TRAP_NO_ERRCODE asm_trap_divide_error, 0
    TRAP_NO_ERRCODE asm_trap_debug, 1
    TRAP_NO_ERRCODE asm_trap_nmi, 2
    TRAP_NO_ERRCODE asm_trap_breakpoint, 3
    TRAP_NO_ERRCODE asm_trap_overflow, 4
    TRAP_NO_ERRCODE asm_trap_bound_range, 5
    TRAP_NO_ERRCODE asm_trap_invalid_opcode, 6
    TRAP_NO_ERRCODE asm_trap_device_not_avail, 7
    TRAP_ERRCODE    asm_trap_double_fault, 8
    TRAP_ERRCODE    asm_trap_invalid_tss, 10
    TRAP_ERRCODE    asm_trap_segment_not_present, 11
    TRAP_ERRCODE    asm_trap_stack_segment_fault, 12
    TRAP_ERRCODE    asm_trap_general_protection, 13
    TRAP_ERRCODE    asm_trap_page_fault, 14
    TRAP_NO_ERRCODE asm_trap_x87_floating_point, 16
    TRAP_ERRCODE    asm_trap_alignment_check, 17
    TRAP_NO_ERRCODE asm_trap_machine_check, 18
    TRAP_NO_ERRCODE asm_trap_simd_floating_point, 19
    TRAP_NO_ERRCODE asm_trap_default, 255

    // Hardware IRQs (Vectors 32..=47)
    TRAP_NO_ERRCODE asm_irq_32, 32
    TRAP_NO_ERRCODE asm_irq_33, 33
    TRAP_NO_ERRCODE asm_irq_34, 34
    TRAP_NO_ERRCODE asm_irq_35, 35
    TRAP_NO_ERRCODE asm_irq_36, 36
    TRAP_NO_ERRCODE asm_irq_37, 37
    TRAP_NO_ERRCODE asm_irq_38, 38
    TRAP_NO_ERRCODE asm_irq_39, 39
    TRAP_NO_ERRCODE asm_irq_40, 40
    TRAP_NO_ERRCODE asm_irq_41, 41
    TRAP_NO_ERRCODE asm_irq_42, 42
    TRAP_NO_ERRCODE asm_irq_43, 43
    TRAP_NO_ERRCODE asm_irq_44, 44
    TRAP_NO_ERRCODE asm_irq_45, 45
    TRAP_NO_ERRCODE asm_irq_46, 46
    TRAP_NO_ERRCODE asm_irq_47, 47
    TRAP_NO_ERRCODE asm_yield, 0x81
    TRAP_NO_ERRCODE asm_int80, 0x80
    TRAP_NO_ERRCODE asm_lapic_timer, 0x40
    TRAP_NO_ERRCODE asm_tlb_ipi, 0x42
    TRAP_NO_ERRCODE asm_msi_0, 0x50
    TRAP_NO_ERRCODE asm_msi_1, 0x51
    TRAP_NO_ERRCODE asm_msi_2, 0x52
    TRAP_NO_ERRCODE asm_msi_3, 0x53
    TRAP_NO_ERRCODE asm_msi_4, 0x54
    TRAP_NO_ERRCODE asm_msi_5, 0x55
    TRAP_NO_ERRCODE asm_msi_6, 0x56
    TRAP_NO_ERRCODE asm_msi_7, 0x57
    TRAP_NO_ERRCODE asm_msi_8, 0x58
    TRAP_NO_ERRCODE asm_msi_9, 0x59
    TRAP_NO_ERRCODE asm_msi_10, 0x5a
    TRAP_NO_ERRCODE asm_msi_11, 0x5b
    TRAP_NO_ERRCODE asm_msi_12, 0x5c
    TRAP_NO_ERRCODE asm_msi_13, 0x5d
    TRAP_NO_ERRCODE asm_msi_14, 0x5e
    TRAP_NO_ERRCODE asm_msi_15, 0x5f

    // The direct switch (vector 0x82, kernel mode only): the general registers in an
    // ExceptionContext, no FPU state, and back to kernel mode (the task switched to is
    // always one that blocked in the kernel)
    .global asm_direct_switch
    asm_direct_switch:
        // DF clear for the Rust code below (see common_trap_handler)
        cld
        push 0
        push 0x82
        push rax
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        mov rbp, rsp
        and rsp, -16
        mov rcx, rbp
        mov rdi, rbp
        sub rsp, 32
        call hydra_direct_switch_handler
        mov rsp, rbp
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rax
        add rsp, 16
        // The frame is on the stack of the task switched away from, which another CPU may
        // resume once this CPU's LEAVING mark is gone (the lock-free forwarding path holds
        // no kernel lock): move the iretq frame into this CPU's block, then clear the mark
        mov gs:[{scratch}], rax
        mov rax, [rsp]
        mov gs:[{frame}], rax
        mov rax, [rsp + 8]
        mov gs:[{frame} + 8], rax
        mov rax, [rsp + 16]
        mov gs:[{frame} + 16], rax
        mov rax, [rsp + 24]
        mov gs:[{frame} + 24], rax
        mov rax, [rsp + 32]
        mov gs:[{frame} + 32], rax
        mov rsp, gs:[0]
        add rsp, {frame}
        mov qword ptr gs:[{leaving}], 0
        mov rax, gs:[{scratch}]
        iretq

    common_trap_handler:
        // The direction flag is not part of what an interrupt clears: the interrupted code
        // (user code, or the kernel's own backward memmove, `std; rep movs; cld`) may have
        // DF set, and Rust code assumes DF clear. Without this, every memcpy/memset of the
        // handler and the scheduler ran backwards, writing below its destination (the
        // two-load whole-system hang of waves 5-6). iretq restores the interrupted DF.
        cld
        // From user mode: the kernel's GS base (per-CPU data). [rsp+24] is the CS pushed
        // by the CPU (below it: rip, error code, vector)
        test qword ptr [rsp + 24], 3
        jz 1f
        swapgs
    1:
        // Save General-Purpose Registers (matches ExceptionContext layout)
        push rax
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15

        // Save the interrupted x87/SSE/AVX state below the frame (an FpuState: XSAVE with
        // every enabled component, or FXSAVE without XSAVE). RBP (already saved in the
        // context) keeps the context pointer across the call; RAX/RDX are saved too.
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

        // Arg 1 = ExceptionContext, Arg 2 = FPU save area (Win64: RCX/RDX, SysV: RDI/RSI)
        mov rcx, rbp
        mov rdi, rbp
        mov rdx, rsp
        mov rsi, rsp
        sub rsp, 32
        call hydra_exception_handler
        // No interrupts from here to iretq: the end of a return to user mode runs on this
        // CPU's own small stack (arch::percpu), where a task switch must not happen
        cli
        add rsp, 32

        // Restore the FPU state (possibly swapped in by the scheduler); RAX/RDX are popped
        // below
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

        // Restore General-Purpose Registers
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rax

        // An NMI returning to kernel mode irets in place: it may have come in the middle
        // of another epilogue's use of this CPU's frame block, and never switches tasks
        cmp qword ptr [rsp], 2
        jne 2f
        test qword ptr [rsp + 24], 3
        jnz 2f
        add rsp, 16
        iretq
    2:
        // Clean up vector number and error code
        add rsp, 16

        // To kernel mode: this CPU keeps the kernel lock (it goes on running kernel code).
        // The frame may be on the stack of a task switched away from: moved into this CPU's
        // block first, then the LEAVING mark cleared (see arch::percpu), then iretq
        test qword ptr [rsp + 8], 3
        jnz 3f
        mov gs:[{scratch}], rax
        mov rax, [rsp]
        mov gs:[{frame}], rax
        mov rax, [rsp + 8]
        mov gs:[{frame} + 8], rax
        mov rax, [rsp + 16]
        mov gs:[{frame} + 16], rax
        mov rax, [rsp + 24]
        mov gs:[{frame} + 24], rax
        mov rax, [rsp + 32]
        mov gs:[{frame} + 32], rax
        mov rsp, gs:[0]
        add rsp, {frame}
        mov qword ptr gs:[{leaving}], 0
        mov rax, gs:[{scratch}]
        iretq
    3:
        // To user mode. The frame may be on another task's kernel stack (the one switched
        // away from), which another CPU may resume as soon as the kernel lock is free:
        // move the iretq frame into this CPU's block (arch::percpu) first, then release the
        // lock if this CPU holds it, then iretq from there with the user's GS base
        mov gs:[{scratch}], rax
        mov rax, [rsp]
        mov gs:[{frame}], rax
        mov rax, [rsp + 8]
        mov gs:[{frame} + 8], rax
        mov rax, [rsp + 16]
        mov gs:[{frame} + 16], rax
        mov rax, [rsp + 24]
        mov gs:[{frame} + 24], rax
        mov rax, [rsp + 32]
        mov gs:[{frame} + 32], rax
        mov rsp, gs:[0]
        add rsp, {frame}
        mov qword ptr gs:[{leaving}], 0
        mov rax, gs:[8]
        cmp rax, qword ptr [rip + hydra_bkl_owner]
        jne 4f
        mov qword ptr [rip + hydra_bkl_owner], -1
        lock inc dword ptr [rip + hydra_bkl_serving]
    4:
        mov rax, gs:[{scratch}]
        swapgs
        iretq
    "#,
    scratch = const crate::arch::percpu::EXIT_SCRATCH,
    frame = const crate::arch::percpu::EXIT_FRAME,
    leaving = const crate::arch::percpu::LEAVING,
);
