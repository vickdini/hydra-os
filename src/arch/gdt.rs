use spin::Lazy;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};

use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const STACK_SIZE: usize = 4096 * 5;
static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
static mut PRIVILEGE_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

pub struct Selectors {
    pub kernel_code_selector: SegmentSelector,
    pub kernel_data_selector: SegmentSelector,
    pub user_data_selector: SegmentSelector,
    pub user_code_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

static mut TSS: TaskStateSegment = TaskStateSegment::new();

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

/// Dynamically updates the Ring 0 Privilege Stack (RSP0) in the TSS for the active task.
///
/// When an interrupt or exception occurs while the CPU is executing in Ring 3 (user mode),
/// the hardware automatically loads RSP from privilege_stack_table[0].
pub fn set_privilege_stack(stack_top: VirtAddr) {
    unsafe {
        TSS.privilege_stack_table[0] = stack_top;
    }
}


pub fn get_selectors() -> &'static Selectors {
    &GDT.1
}

/// Loads Hydra's GDT into GDTR, reloads CS and SS/DS/ES/FS/GS, and loads TSS into TR.
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
