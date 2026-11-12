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
//!    from Ring 3 userland execution (`SS = 0x2b`, `CS = 0x33`, 32-bit `CS = 0x23`), laid out like
//!    Linux's table, in the order required by the `SYSCALL` and `SYSRET` instructions (`IA32_STAR`).
//! 2. **Ring 3 -> Ring 0 Stack Switching (`RSP0`)**: When a Ring 3 task triggers a hardware interrupt or
//!    exception, the CPU loads `RSP` from `TSS.privilege_stack_table[0]`, updated on every context
//!    switch via `set_privilege_stack`.
//! 3. **Interrupt Stack Table (`IST`)**: Dedicates an isolated 20 KiB recovery stack (`IST 1`) to Double
//!    Fault (`#DF`) exceptions so a kernel stack overflow never escalates into a silent Triple Fault.
//!
//! ## Key Types & Interfaces
//!
//! - `Selectors`: Holds the `SegmentSelector` values for kernel/user code/data and the TSS.
//! - `Gdt` / `CPU_GDT`: Each CPU's own table (its TSS, and per-thread entries rewritten at a switch).
//! - `DOUBLE_FAULT_IST_INDEX`: Zero-based IST index (`0`, corresponding to hardware `IST 1`) for Double Faults.
//! - `init`: Populates the TSS stack pointers.
//! - `load_and_switch`: Loads `GDTR`, reloads `CS`/`DS`/`ES`/`FS`/`GS`/`SS`, and loads `TR` after `ExitBootServices`.
//! - `set_privilege_stack`: Updates `RSP0` in the TSS when switching to a Ring 3 task.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (Kernel).
//! - **Hardware Interaction**: `lgdt`, `ltr`, far return (`retfq`) to reload `CS`, and segment register moves.
//! - **Concurrency**: Each CPU writes only its own table and TSS, with interrupts disabled during context switches.

use x86_64::structures::gdt::{Descriptor, DescriptorFlags, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::structures::DescriptorTablePointer;
use x86_64::{PrivilegeLevel, VirtAddr};

/// Zero-based index into `TSS.interrupt_stack_table` used for Double Fault (`#DF`) recovery (corresponds to hardware `IST 1`).
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size in bytes (20 KiB) of the static Double Fault IST stack and initial Ring 0 privilege stack.
const STACK_SIZE: usize = 4096 * 5;
/// Dedicated 20 KiB emergency stack used when a Double Fault (`#DF`) exception occurs.
static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
/// Default 20 KiB Ring 0 privilege stack (`RSP0`) configured before per-task stacks take over.
static mut PRIVILEGE_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

// The table follows Linux's x86-64 layout, which programs rely on: Wine runs 32-bit Windows
// code by far-jumping to selector 0x23, reads the 64-bit data selector from SS, and
// `set_thread_area` hands out entries 12-14. SYSRET needs user 32-bit code, user data and
// user 64-bit code in that order (STAR's user base is 0x23).

/// Ring 0 64-bit kernel code selector.
pub const KERNEL_CS: u16 = 0x08;
/// Ring 0 kernel data and stack selector.
pub const KERNEL_DS: u16 = 0x10;
/// Ring 3 32-bit (compatibility mode) user code selector (Linux `__USER32_CS`).
pub const USER32_CS: u16 = 0x23;
/// Ring 3 user data and stack selector (Linux `__USER_DS`).
pub const USER_DS: u16 = 0x2b;
/// Ring 3 64-bit user code selector (Linux `__USER_CS`).
pub const USER_CS: u16 = 0x33;
/// Task State Segment selector (16-byte descriptor, entries 8-9).
pub const TSS_SEL: u16 = 0x40;
/// First of the per-thread `set_thread_area` entries (Linux `GDT_ENTRY_TLS_MIN`).
pub const TLS_ENTRY_MIN: usize = 12;
/// Number of per-thread `set_thread_area` entries (Linux `GDT_ENTRY_TLS_ENTRIES`).
pub const TLS_ENTRIES: usize = 3;
/// Entries in each CPU's table.
const GDT_LEN: usize = 16;

/// One CPU's Global Descriptor Table. Each CPU has its own, so the per-thread entries
/// (TLS) can be rewritten at a context switch.
#[repr(C, align(16))]
pub struct Gdt(pub [u64; GDT_LEN]);

impl Gdt {
    /// The table with Hydra's fixed entries and the TSS descriptor of `tss`.
    fn new(tss: &'static TaskStateSegment) -> Gdt {
        let mut t = [0u64; GDT_LEN];
        t[(KERNEL_CS >> 3) as usize] = DescriptorFlags::KERNEL_CODE64.bits();
        t[(KERNEL_DS >> 3) as usize] = DescriptorFlags::KERNEL_DATA.bits();
        t[(USER32_CS >> 3) as usize] = DescriptorFlags::USER_CODE32.bits();
        t[(USER_DS >> 3) as usize] = DescriptorFlags::USER_DATA.bits();
        t[(USER_CS >> 3) as usize] = DescriptorFlags::USER_CODE64.bits();
        match Descriptor::tss_segment(tss) {
            Descriptor::SystemSegment(low, high) => {
                t[(TSS_SEL >> 3) as usize] = low;
                t[(TSS_SEL >> 3) as usize + 1] = high;
            }
            Descriptor::UserSegment(_) => unreachable!(),
        }
        Gdt(t)
    }

    /// Loads this table into `GDTR`. The table must stay where it is from then on.
    unsafe fn load(&self) {
        let ptr = DescriptorTablePointer {
            limit: (core::mem::size_of::<Gdt>() - 1) as u16,
            base: VirtAddr::from_ptr(self.0.as_ptr()),
        };
        x86_64::instructions::tables::lgdt(&ptr);
    }
}

/// Segment selectors registered in Hydra's 64-bit Global Descriptor Table.
pub struct Selectors {
    /// Ring 0 64-bit kernel code segment selector (`0x08`).
    pub kernel_code_selector: SegmentSelector,
    /// Ring 0 kernel data and stack segment selector (`0x10`).
    pub kernel_data_selector: SegmentSelector,
    /// Ring 3 user data and stack segment selector (`0x2b`, RPL 3).
    pub user_data_selector: SegmentSelector,
    /// Ring 3 64-bit user code segment selector (`0x33`, RPL 3).
    pub user_code_selector: SegmentSelector,
    /// Ring 3 32-bit user code segment selector (`0x23`, RPL 3).
    pub user32_code_selector: SegmentSelector,
    /// 16-byte 64-bit Task State Segment descriptor selector (`0x40`).
    pub tss_selector: SegmentSelector,
}

/// The selectors, the same on every CPU.
static SELECTORS: Selectors = Selectors {
    kernel_code_selector: SegmentSelector::new(KERNEL_CS >> 3, PrivilegeLevel::Ring0),
    kernel_data_selector: SegmentSelector::new(KERNEL_DS >> 3, PrivilegeLevel::Ring0),
    user_data_selector: SegmentSelector::new(USER_DS >> 3, PrivilegeLevel::Ring3),
    user_code_selector: SegmentSelector::new(USER_CS >> 3, PrivilegeLevel::Ring3),
    user32_code_selector: SegmentSelector::new(USER32_CS >> 3, PrivilegeLevel::Ring3),
    tss_selector: SegmentSelector::new(TSS_SEL >> 3, PrivilegeLevel::Ring0),
};

/// Global 64-bit Task State Segment holding `RSP0` and the Interrupt Stack Table (`IST`).
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// Each CPU's table (index: CPU), set when the CPU loads it.
pub static CPU_GDT: [core::sync::atomic::AtomicPtr<Gdt>; crate::arch::smp::MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; crate::arch::smp::MAX_CPUS];

/// The boot processor's table (filled when it is loaded; no heap needed).
static mut BSP_GDT: Gdt = Gdt([0; GDT_LEN]);

/// Fills `gdt` for CPU `cpu` with the TSS `tss`, records it in [`CPU_GDT`] and loads it.
fn install(cpu: usize, gdt: &'static mut Gdt, tss: &'static TaskStateSegment) {
    *gdt = Gdt::new(tss);
    CPU_GDT[cpu].store(gdt as *mut Gdt, core::sync::atomic::Ordering::Release);
    unsafe { gdt.load() };
    reload_segments(&SELECTORS);
}

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
    // The calling CPU's TSS
    let cpu = crate::arch::percpu::cpu();
    let ap = if cpu == 0 { core::ptr::null_mut() } else { AP_TSS[cpu].load(core::sync::atomic::Ordering::Acquire) };
    unsafe {
        if ap.is_null() {
            TSS.privilege_stack_table[0] = stack_top;
        } else {
            (*ap).privilege_stack_table[0] = stack_top;
        }
    }
}

/// Returns a static reference to the kernel, user, and TSS `Selectors`.
///
/// # Returns
///
/// Reference to the initialized `Selectors` struct.
pub fn get_selectors() -> &'static Selectors {
    &SELECTORS
}

/// Loads Hydra's GDT into `GDTR`, reloads `CS` and `SS`/`DS`/`ES`/`FS`/`GS`, and loads the TSS into `TR`.
///
/// Invoked during [`crate::arch::boot_services::take_hardware_ownership`] immediately after `ExitBootServices`.
pub fn load_and_switch() {
    unsafe { install(0, &mut *core::ptr::addr_of_mut!(BSP_GDT), &*core::ptr::addr_of!(TSS)) };
    // Loading GS reset its base: the boot processor's per-CPU data again
    crate::arch::percpu::init_this_cpu(0);
}

/// The TSS of each application processor (index: CPU), for its kernel stack pointer.
pub static AP_TSS: [core::sync::atomic::AtomicPtr<TaskStateSegment>; crate::arch::smp::MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; crate::arch::smp::MAX_CPUS];

/// Gives application processor `cpu` a GDT and TSS of its own (the same selectors as the
/// boot processor's, its own double-fault and privilege stacks) and loads them.
pub fn load_for_ap(cpu: usize) {
    let tss: &'static mut TaskStateSegment = alloc::boxed::Box::leak(alloc::boxed::Box::new(TaskStateSegment::new()));
    let df: &'static mut [u8] = alloc::vec![0u8; STACK_SIZE].leak();
    let ps: &'static mut [u8] = alloc::vec![0u8; STACK_SIZE].leak();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = VirtAddr::from_ptr(df.as_ptr()) + STACK_SIZE as u64;
    tss.privilege_stack_table[0] = VirtAddr::from_ptr(ps.as_ptr()) + STACK_SIZE as u64;
    AP_TSS[cpu].store(tss as *mut TaskStateSegment, core::sync::atomic::Ordering::Release);
    let gdt: &'static mut Gdt = alloc::boxed::Box::leak(alloc::boxed::Box::new(Gdt([0; GDT_LEN])));
    install(cpu, gdt, unsafe { &*(tss as *const TaskStateSegment) });
    crate::arch::percpu::init_this_cpu(cpu);
}

/// Reloads CS, the data segments and TR with the selectors of a freshly loaded GDT.
fn reload_segments(s: &Selectors) {
    unsafe {
        // Far return to reload CS with kernel code selector (0x08)
        core::arch::asm!(
            "push {sel}",
            "lea {tmp}, [2f + rip]",
            "push {tmp}",
            "retfq",
            "2:",
            sel = in(reg) u64::from(s.kernel_code_selector.0),
            tmp = out(reg) _,
            options(preserves_flags),
        );
        // Stack segment: kernel data. DS, ES, FS and GS hold null (64-bit code ignores
        // them): what a user thread finds there before loading its own, and what the
        // context switch saves for it (arch::segments)
        let data_sel = s.kernel_data_selector.0;
        core::arch::asm!(
            "mov ss, {sel:x}",
            "mov ds, {null:x}",
            "mov es, {null:x}",
            "mov fs, {null:x}",
            "mov gs, {null:x}",
            sel = in(reg) data_sel,
            null = in(reg) 0u16,
            options(preserves_flags),
        );
        // Load Task Register (TR) with TSS selector
        x86_64::instructions::tables::load_tss(s.tss_selector);
    }
}
