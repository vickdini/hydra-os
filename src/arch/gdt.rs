//! # Architecture Layer: Global Descriptor Table (GDT) & Task State Segment (TSS)
//!
//! Configures the 64-bit `x86_64` Global Descriptor Table, Ring 0/Ring 3 segment selectors,
//! and Task State Segment (TSS) privilege and interrupt stack tables.
//!
//! ## Architectural Role & Design Rationale
//!
//! Even though `x86_64` Long Mode uses flat 64-bit linear addressing rather than legacy segment
//! base/limit translation, the processor still requires a valid GDT and TSS for three critical mechanisms:
//! 1. **Privilege Ring Transitions**: Distinguishing Ring 0 supervisor execution (`CS = 0x08`, `SS = 0x10`)
//!    from Ring 3 userland execution (`SS = 0x1B`, `CS = 0x23`), laid out in the exact order required
//!    by the `SYSCALL` and `SYSRET` instructions (`IA32_STAR`).
//! 2. **Ring 3 -> Ring 0 Stack Switching (`RSP0`)**: When a Ring 3 task triggers a hardware interrupt or
//!    exception, the CPU loads `RSP` from `TSS.privilege_stack_table[0]`, updated on every context
//!    switch via `set_privilege_stack`.
//! 3. **Interrupt Stack Table (`IST`)**: Dedicates an isolated 20 KiB recovery stack (`IST 1`) to Double
//!    Fault (`#DF`) exceptions so a kernel stack overflow never escalates into a silent Triple Fault.
//!
//! ## Key Types & Interfaces
//!
//! - `Selectors`: Holds the initialized `SegmentSelector` values for kernel/user code/data and the TSS.
//! - `DOUBLE_FAULT_IST_INDEX`: Zero-based IST index (`0`, corresponding to hardware `IST 1`) for Double Faults.
//! - `init`: Populates the TSS stack pointers and forces lazy construction of the static GDT.
//! - `load_and_switch`: Loads `GDTR`, reloads `CS`/`DS`/`ES`/`FS`/`GS`/`SS`, and loads `TR` after `ExitBootServices`.
//! - `set_privilege_stack`: Updates `RSP0` in the TSS when switching to a Ring 3 task.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (Kernel).
//! - **Hardware Interaction**: `lgdt`, `ltr`, far return (`retfq`) to reload `CS`, and segment register moves.
//! - **Concurrency**: Initialized once via [`spin::Lazy`]; `TSS.privilege_stack_table[0]` is updated with interrupts disabled during context switches.

use spin::Lazy;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};

use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Zero-based index into `TSS.interrupt_stack_table` used for Double Fault (`#DF`) recovery (corresponds to hardware `IST 1`).
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size in bytes (20 KiB) of the static Double Fault IST stack and initial Ring 0 privilege stack.
const STACK_SIZE: usize = 4096 * 5;
/// Dedicated 20 KiB emergency stack used when a Double Fault (`#DF`) exception occurs.
static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
/// Default 20 KiB Ring 0 privilege stack (`RSP0`) configured before per-task stacks take over.
static mut PRIVILEGE_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

/// Segment selectors registered in Hydra's 64-bit Global Descriptor Table.
///
/// # Concurrency & Thread Safety
/// Initialized once inside the static [`GDT`] [`spin::Lazy`] cell and shared immutably via [`get_selectors`].
pub struct Selectors {
    /// Ring 0 64-bit kernel code segment selector (`0x08`).
    pub kernel_code_selector: SegmentSelector,
    /// Ring 0 kernel data and stack segment selector (`0x10`).
    pub kernel_data_selector: SegmentSelector,
    /// Ring 3 user data and stack segment selector (`0x1B`, RPL 3).
    pub user_data_selector: SegmentSelector,
    /// Ring 3 64-bit user code segment selector (`0x23`, RPL 3).
    pub user_code_selector: SegmentSelector,
    /// 16-byte 64-bit Task State Segment descriptor selector (`0x28`).
    pub tss_selector: SegmentSelector,
}

/// Global 64-bit Task State Segment holding `RSP0` and the Interrupt Stack Table (`IST`).
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// Lazily initialized Global Descriptor Table and its associated `Selectors`.
static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(unsafe { &*core::ptr::addr_of!(TSS) }));

    (
        gdt,
        Selectors {
            kernel_code_selector,
            kernel_data_selector,
            user_data_selector,
            user_code_selector,
            tss_selector,
        },
    )
});

/// Initializes the Task State Segment stacks (`IST 1` and `RSP0`) and constructs the static [`GDT`].
///
/// Does not load `GDTR` or switch active CPU segments yet so UEFI Boot Services remain operational
/// until `load_and_switch` is called during hardware takeover.
pub fn init() {
    unsafe {
        let stack_start = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
        let stack_end = stack_start + STACK_SIZE as u64;
        TSS.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = stack_end;

        let priv_stack_start = VirtAddr::from_ptr(&raw const PRIVILEGE_STACK);
        let priv_stack_end = priv_stack_start + STACK_SIZE as u64;
        TSS.privilege_stack_table[0] = priv_stack_end;
    }

    let _ = &*GDT;
}

/// Dynamically updates the Ring 0 Privilege Stack (`RSP0`) in the TSS for the active task.
///
/// When an interrupt or exception occurs while the CPU is executing in Ring 3 (user mode),
/// the hardware automatically switches `RSP` to `privilege_stack_table[0]`.
///
/// # Arguments
///
/// * `stack_top` - Top virtual address (highest address, 16-byte aligned) of the task's kernel stack.
pub fn set_privilege_stack(stack_top: VirtAddr) {
    unsafe {
        TSS.privilege_stack_table[0] = stack_top;
    }
}

/// Returns a static reference to the kernel, user, and TSS `Selectors`.
///
/// # Returns
///
/// Reference to the initialized `Selectors` struct.
pub fn get_selectors() -> &'static Selectors {
    &GDT.1
}

/// Loads Hydra's GDT into `GDTR`, reloads `CS` and `SS`/`DS`/`ES`/`FS`/`GS`, and loads the TSS into `TR`.
///
/// Invoked during [`crate::arch::boot_services::take_hardware_ownership`] immediately after `ExitBootServices`.
pub fn load_and_switch() {
    GDT.0.load();
    unsafe {
        // Far return to reload CS with kernel code selector (0x08)
        core::arch::asm!(
            "push {sel}",
            "lea {tmp}, [2f + rip]",
            "push {tmp}",
            "retfq",
            "2:",
            sel = in(reg) u64::from(GDT.1.kernel_code_selector.0),
            tmp = out(reg) _,
            options(preserves_flags),
        );
        // Reload data and stack segment selectors
        let data_sel = GDT.1.kernel_data_selector.0;
        core::arch::asm!(
            "mov ds, {sel:x}",
            "mov es, {sel:x}",
            "mov fs, {sel:x}",
            "mov gs, {sel:x}",
            "mov ss, {sel:x}",
            sel = in(reg) data_sel,
            options(preserves_flags),
        );
        // Load Task Register (TR) with TSS selector
        x86_64::instructions::tables::load_tss(GDT.1.tss_selector);
    }
}
