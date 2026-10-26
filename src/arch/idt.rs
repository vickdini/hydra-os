use core::arch::global_asm;
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
    pub fn set_ist(&mut self, ist_index: u8) -> &mut Self {
        self.ist = ist_index & 0x7;
        self
    }

    /// Sets the Descriptor Privilege Level (DPL).
    /// Set DPL=3 for software interrupts callable from Ring 3 (e.g. `int3` or syscalls).
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
        #[repr(C, packed)]
        struct Idtr {
            limit: u16,
            base: u64,
        }

        let idtr = Idtr {
            limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: self as *const _ as u64,
        };

        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) &idtr, options(nostack, preserves_flags));
        }
    }
}

/// Complete CPU execution state captured during an exception or interrupt.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    // Callee & Caller Saved GPRs
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Exception Vector Index
    pub vector: u64,
    // Hardware Error Code or Dummy 0
    pub error_code: u64,
    // Hardware IRETQ Stack Frame
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// Global static IDT instance
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

    // Load IDT into CPU
    idt.load();
    drop(idt);
}

/// Enables the TSS Interrupt Stack Table (IST 1) for Double Fault (#DF) exceptions.
pub fn enable_double_fault_ist() {
    let mut idt = IDT.lock();
    idt.entries[8].set_ist(1);
    idt.load();
}

/// Updates the GDT code segment selector across all IDT gates and reloads the IDTR.
pub fn reload_with_kernel_cs(cs: u16) {
    let mut idt = IDT.lock();
    for entry in idt.entries.iter_mut() {
        entry.selector = cs;
    }
    idt.load();
}

/// Central Rust exception dispatcher called by assembly trampolines.
#[no_mangle]
extern "C" fn hydra_exception_handler(ctx: &mut ExceptionContext) {
    match ctx.vector {
        3 => {
            // #BP - Breakpoint Exception (Int3)
            set_color(Color::LightCyan, Color::Black);
            println!("\n[i] CPU BREAKPOINT TRAP (#BP) at RIP: {:#x}", ctx.rip);
            println!("    RFLAGS: {:#x}, RSP: {:#x}", ctx.rflags, ctx.rsp);
            // Non-fatal: returns from exception handler and resumes execution
        }
        14 => {
            // #PF - Page Fault Exception
            let fault_addr = Cr2::read_raw();
            let is_user = (ctx.error_code & (1 << 2)) != 0 || (ctx.cs & 3) == 3;

            if is_user && crate::task::is_active() {
                set_color(Color::LightRed, Color::Black);
                let pid = crate::task::SCHEDULER.lock().current_task_id();
                println!("\n[!] USER FAULT: Segmentation Fault (#PF) in Task PID {}", pid.0);
                println!("    Faulting Address (CR2): {:#x}", fault_addr);
                println!("    Instruction Pointer   : {:#x}, Error Code: {:#x}", ctx.rip, ctx.error_code);
                let mut sched = crate::task::SCHEDULER.lock();
                sched.terminate_current();
                sched.schedule(ctx);
                return;
            }

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
                let mut sched = crate::task::SCHEDULER.lock();
                sched.terminate_current();
                sched.schedule(ctx);
                return;
            }

            set_color(Color::LightRed, Color::Black);
            println!("\n============================================================");
            println!(" [!] CPU EXCEPTION: GENERAL PROTECTION FAULT (#GP)");
            println!("============================================================");
            println!("  Instruction Pointer (RIP): {:#x}", ctx.rip);
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
                let pid = crate::task::SCHEDULER.lock().current_task_id();
                println!("\n[!] USER FAULT: Invalid Opcode (#UD) in Task PID {}", pid.0);
                println!("    Faulting RIP: {:#x}", ctx.rip);
                let mut sched = crate::task::SCHEDULER.lock();
                sched.terminate_current();
                sched.schedule(ctx);
                return;
            }

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
                let mut sched = crate::task::SCHEDULER.lock();
                sched.terminate_current();
                sched.schedule(ctx);
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
            // Vector 32 = IRQ 0: 8254 PIT Timer Tick
            crate::arch::pit::on_timer_tick();
            crate::arch::pic::send_eoi(0);

            // Preemptive Multitasking Round-Robin Scheduling
            if crate::task::is_active() {
                if let Some(mut sched) = crate::task::SCHEDULER.try_lock() {
                    sched.schedule(ctx);
                }
            }
        }
        33 => {
            // Vector 33 = IRQ 1: 8042 PS/2 Keyboard Scancode Available
            crate::arch::keyboard::on_keyboard_irq();
            crate::arch::pic::send_eoi(1);
        }
        34..=47 => {
            // Hardware IRQs from legacy 8259 PIC (Cascade, Serial, Floppy, RTC, etc.)
            let irq = (ctx.vector - 32) as u8;
            crate::arch::pic::send_eoi(irq);
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

fn print_cpu_dump(ctx: &ExceptionContext) {
    println!("  Register State:");
    println!("    RAX={:#018x}  RBX={:#018x}  RCX={:#018x}", ctx.rax, ctx.rbx, ctx.rcx);
    println!("    RDX={:#018x}  RSI={:#018x}  RDI={:#018x}", ctx.rdx, ctx.rsi, ctx.rdi);
    println!("    RBP={:#018x}  RSP={:#018x}  RFLAGS={:#018x}", ctx.rbp, ctx.rsp, ctx.rflags);
    println!("    R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}", ctx.r8, ctx.r9, ctx.r10);
    println!("    R11={:#018x}  R12={:#018x}  R13={:#018x}", ctx.r11, ctx.r12, ctx.r13);
    println!("    R14={:#018x}  R15={:#018x}  CS:RIP={:#04x}:{:#018x}", ctx.r14, ctx.r15, ctx.cs, ctx.rip);
}

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

    common_trap_handler:
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

        // Pass pointer to ExceptionContext as 1st arg (RCX for Win64/UEFI, RDI for SysV)
        mov rcx, rsp
        mov rdi, rsp
        sub rsp, 32
        call hydra_exception_handler
        add rsp, 32

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

        // Clean up vector number and error code
        add rsp, 16

        // Return from interrupt
        iretq
    "#
);
