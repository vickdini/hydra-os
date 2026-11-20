//! *stub* `crate::arch`: the hardware side, faked. Only `segments`' descriptor logic is the
//! kernel's own code (`segments_real`); its CPU-loading functions are replaced here.

pub mod pit {
    pub use crate::fake::{clock_state, frequency_hz, now_ns, sleep_ms, tick_ns, ticks, uptime_ms};
}
pub mod random {
    pub use crate::fake::random_fill as fill;
}
pub mod percpu {
    pub use crate::fake::PerCpuPtr;
    /// The host behaves as CPU 0.
    pub fn cpu() -> usize {
        0
    }
}
pub mod smp {
    pub fn bkl_exit() {}
    pub fn bkl_owner() -> usize {
        0
    }
    pub fn flush_kick() {}
    pub fn online() -> usize {
        crate::fake::ONLINE_CPUS.get()
    }
    pub const MAX_CPUS: usize = 16;
    pub fn serve_tlb() {}
    pub fn shootdown(_cr3: Option<u64>, addr: Option<u64>) {
        match addr {
            Some(a) => x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(a)),
            None => x86_64::instructions::tlb::flush_all(),
        }
    }
}
pub mod pcid {
    pub fn enabled() -> bool {
        false
    }
    pub fn global_enabled() -> bool {
        false
    }
    pub fn load_cr3(pml4: u64) {
        crate::fake::rec(alloc::format!("load_cr3({pml4:#x})"));
    }
    pub fn forget(_pml4: u64) {}
    pub fn mark_remote(_cpu: usize, _pml4: u64) {}
    pub fn flush_all_ids() {}
    pub fn summary() -> alloc::string::String {
        "PCID off (host)".into()
    }
    pub fn without_invpcid<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}
pub mod gdt {
    pub const USER_CS: u16 = 0x2b;
    pub const USER32_CS: u16 = 0x23;
    pub const USER_DS: u16 = 0x1b;
    pub const TLS_ENTRY_MIN: usize = 12;
    pub const TLS_ENTRIES: usize = 3;
    /// *stub* A CPU's GDT (none is loaded on the host).
    pub struct Gdt(pub [u64; 16]);
    pub static CPU_GDT: [core::sync::atomic::AtomicPtr<Gdt>; crate::arch::smp::MAX_CPUS] =
        [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; crate::arch::smp::MAX_CPUS];
}
/// *mirror* of the kernel's exception frame and FXSAVE area.
pub mod idt {
    #[repr(C)]
    #[derive(Default, Clone, Debug)]
    pub struct ExceptionContext {
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
        pub vector: u64,
        pub error_code: u64,
        pub rip: u64,
        pub cs: u64,
        pub rflags: u64,
        pub rsp: u64,
        pub ss: u64,
    }
    #[derive(Clone)]
    #[repr(C, align(64))]
    pub struct FpuState(pub [u8; 1024]);
    impl FpuState {
        pub fn new() -> Self {
            let mut area = [0u8; 1024];
            area[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
            area[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
            Self(area)
        }
        pub fn legacy_written(&mut self) {
            self.0[512] |= 0b011;
        }
    }
    /// *stub* XSAVE in use when a test says so (`fake::XSAVE`): an 832-byte area, x87+SSE+AVX.
    pub fn use_xsave() -> bool {
        crate::fake::XSAVE.get()
    }
    pub fn xsave_size() -> usize {
        if crate::fake::XSAVE.get() { 832 } else { 512 }
    }
    pub fn xcr0() -> u64 {
        if crate::fake::XSAVE.get() { 7 } else { 0 }
    }
}
pub mod rtc {
    pub use crate::fake::{rtc_now as now, rtc_set_now as set_now, wall_base_ns};
}
pub mod relocate {
    pub fn image_phys() -> Option<(u64, u64)> {
        None
    }
}
#[path = "../../../src/arch/vdso.rs"]
pub mod vdso;
pub mod syscall {
    pub use crate::fake::{rdmsr, wrmsr};
    /// The saved user registers at syscall entry (same fields and order as the kernel).
    #[repr(C)]
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct SyscallFrame {
        pub r9: u64,
        pub r8: u64,
        pub r10: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rax: u64,
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub rip: u64,
        pub rflags: u64,
        pub rsp: u64,
    }
    /// The FPU area saved at system call entry (per CPU).
    pub static SYSCALL_FPU: crate::arch::percpu::PerCpuPtr<crate::arch::idt::FpuState> =
        crate::arch::percpu::PerCpuPtr::new();
}
pub mod debugregs {
    pub fn switch_to(dr: &[u64; 8]) {
        crate::fake::rec(alloc::format!("debugregs::switch_to({:#x})", dr[7]));
    }
}
pub mod power {
    pub fn power_off() -> ! {
        panic!("power_off")
    }
    pub fn reboot() -> ! {
        panic!("reboot")
    }
}

/// The kernel's segment code: descriptors are pure, CPU loads go to the stubs below.
#[path = "../../../src/arch/segments.rs"]
pub mod segments_real;

/// *stub* `arch::segments`: the kernel's types, with the CPU-side functions recorded.
pub mod segments {
    pub use super::segments_real::{Ldt, SharedLdt, UserDesc, UserSegs, LDT_ENTRIES};
    use alloc::sync::Arc;

    pub fn set_current_tls(s: &mut UserSegs, idx: usize, desc: u64) {
        s.tls[idx - super::gdt::TLS_ENTRY_MIN] = desc;
        crate::fake::rec(alloc::format!("set_current_tls({idx},{desc:#x})"));
    }
    pub fn publish_ldt(holder: &SharedLdt, new: Arc<Ldt>, changed: usize) {
        *holder.lock() = Some(new);
        crate::fake::rec(alloc::format!("publish_ldt({changed})"));
    }
    pub fn set_fs_base(s: &mut UserSegs, base: u64) {
        s.fs = 0;
        crate::fake::FS_GS.with(|c| c.set((base, c.get().1)));
    }
    pub fn set_gs_base(s: &mut UserSegs, base: u64) {
        s.gs = 0;
        s.gs_base = base;
        crate::fake::FS_GS.with(|c| c.set((c.get().0, base)));
    }
    pub fn current_bases() -> (u64, u64) {
        crate::fake::FS_GS.with(|c| c.get())
    }
    pub fn reset_current() {
        crate::fake::rec("segments::reset_current()");
    }
}
