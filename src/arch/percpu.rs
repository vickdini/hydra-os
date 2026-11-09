//! # Per-CPU data
//!
//! Each CPU has a [`PerCpu`] block at its kernel GS base (`IA32_GS_BASE` while in the
//! kernel; entries from user mode `swapgs` it in, returns `swapgs` it out). The system
//! call entry stub keeps the task's kernel stack pointer and the user stack pointer there;
//! Rust code reads the CPU's index from it ([`cpu`]).
//!
//! State that describes what a CPU is running ("the current ...") is per CPU: the
//! [`PerCpuU64`], [`PerCpuU32`] and [`PerCpuPtr`] types hold one value per CPU with the
//! methods of the atomics they replace, acting on the calling CPU's value.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use super::smp::MAX_CPUS;

/// What the entry stubs and [`cpu`] find at the kernel GS base. The field offsets are used
/// by assembly code.
#[repr(C)]
pub struct PerCpu {
    /// Its own address (gs:[0]).
    pub self_ptr: u64,
    /// The CPU's index (gs:[8]; 0: the boot processor).
    pub cpu: u64,
    /// Kernel stack top of the task running on the CPU, for `syscall` (gs:[16]).
    pub kernel_rsp: u64,
    /// The user stack pointer while `syscall` switches stacks (gs:[24]).
    pub user_rsp: u64,
}

static mut PERCPU: [PerCpu; MAX_CPUS] = [const { PerCpu { self_ptr: 0, cpu: 0, kernel_rsp: 0, user_rsp: 0 } }; MAX_CPUS];

const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Points the calling CPU's GS base at the per-CPU block of CPU `cpu` (the user GS base,
/// swapped in for user mode, is 0). Called at boot, and again after loading a GDT (which
/// resets the GS base).
pub fn init_this_cpu(cpu: usize) {
    unsafe {
        let p = core::ptr::addr_of_mut!(PERCPU[cpu]);
        (*p).self_ptr = p as u64;
        (*p).cpu = cpu as u64;
        super::syscall::wrmsr(IA32_GS_BASE, p as u64);
        super::syscall::wrmsr(IA32_KERNEL_GS_BASE, 0);
    }
}

/// The calling CPU's index.
#[inline(always)]
pub fn cpu() -> usize {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, qword ptr gs:[8]", out(reg) v, options(nostack, readonly, preserves_flags)) };
    v as usize
}

/// Sets the kernel stack the calling CPU's next `syscall` from user mode switches to.
#[inline(always)]
pub fn set_kernel_rsp(rsp: u64) {
    unsafe { core::arch::asm!("mov qword ptr gs:[16], {}", in(reg) rsp, options(nostack, preserves_flags)) };
}

/// One `u64` per CPU; the methods act on the calling CPU's.
pub struct PerCpuU64([AtomicU64; MAX_CPUS]);

impl PerCpuU64 {
    /// Every CPU's value `v`.
    pub const fn new(v: u64) -> Self {
        let mut a = [const { AtomicU64::new(0) }; MAX_CPUS];
        let mut i = 0;
        while i < MAX_CPUS {
            a[i] = AtomicU64::new(v);
            i += 1;
        }
        Self(a)
    }
    /// CPU `cpu`'s value.
    pub fn on(&self, cpu: usize) -> &AtomicU64 {
        &self.0[cpu]
    }
    /// The calling CPU's value.
    pub fn load(&self, o: Ordering) -> u64 {
        self.0[cpu()].load(o)
    }
    /// Sets the calling CPU's value.
    pub fn store(&self, v: u64, o: Ordering) {
        self.0[cpu()].store(v, o)
    }
    /// Replaces the calling CPU's value; returns the old one.
    pub fn swap(&self, v: u64, o: Ordering) -> u64 {
        self.0[cpu()].swap(v, o)
    }
    /// Adds to the calling CPU's value; returns the old one.
    pub fn fetch_add(&self, v: u64, o: Ordering) -> u64 {
        self.0[cpu()].fetch_add(v, o)
    }
}

/// One `u32` per CPU; the methods act on the calling CPU's.
pub struct PerCpuU32([AtomicU32; MAX_CPUS]);

impl PerCpuU32 {
    /// Every CPU's value 0.
    pub const fn new() -> Self {
        Self([const { AtomicU32::new(0) }; MAX_CPUS])
    }
    /// The calling CPU's value.
    pub fn load(&self, o: Ordering) -> u32 {
        self.0[cpu()].load(o)
    }
    /// Sets the calling CPU's value.
    pub fn store(&self, v: u32, o: Ordering) {
        self.0[cpu()].store(v, o)
    }
    /// Replaces the calling CPU's value; returns the old one.
    pub fn swap(&self, v: u32, o: Ordering) -> u32 {
        self.0[cpu()].swap(v, o)
    }
    /// Adds to the calling CPU's value; returns the old one.
    pub fn fetch_add(&self, v: u32, o: Ordering) -> u32 {
        self.0[cpu()].fetch_add(v, o)
    }
    /// Subtracts from the calling CPU's value; returns the old one.
    pub fn fetch_sub(&self, v: u32, o: Ordering) -> u32 {
        self.0[cpu()].fetch_sub(v, o)
    }
}

/// One pointer per CPU; the methods act on the calling CPU's.
pub struct PerCpuPtr<T>([AtomicPtr<T>; MAX_CPUS]);

impl<T> PerCpuPtr<T> {
    /// Every CPU's pointer null.
    pub const fn new() -> Self {
        Self([const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS])
    }
    /// The calling CPU's value.
    pub fn load(&self, o: Ordering) -> *mut T {
        self.0[cpu()].load(o)
    }
    /// Sets the calling CPU's value.
    pub fn store(&self, v: *mut T, o: Ordering) {
        self.0[cpu()].store(v, o)
    }
    /// Replaces the calling CPU's value; returns the old one.
    pub fn swap(&self, v: *mut T, o: Ordering) -> *mut T {
        self.0[cpu()].swap(v, o)
    }
}
