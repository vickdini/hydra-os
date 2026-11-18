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
    /// RAX while a trap's return to user mode moves its `iretq` frame (gs:[32]).
    pub exit_scratch: u64,
    /// Stack below [`Self::exit_frame`]: an NMI arriving during the last instructions of a
    /// return to user mode pushes its frame here.
    pub exit_stack: [u64; EXIT_STACK_WORDS],
    /// The `iretq` frame (RIP, CS, RFLAGS, RSP, SS) of a trap returning to user mode, moved
    /// off the task's kernel stack before the kernel lock is released: another CPU may
    /// resume that task, on that stack, as soon as it gets the lock (gs:[EXIT_FRAME]).
    pub exit_frame: [u64; 5],
    /// The task whose kernel stack this CPU is still leaving, plus one (0: none): set by a
    /// task switch, cleared by the trap epilogues once the `iretq` frame is off that stack
    /// (gs:[LEAVING]). Until then no other CPU may resume that task (it would run on the
    /// stack this CPU is still reading): the scheduler skips it ([`leaving_elsewhere`]).
    /// The kernel lock used to guarantee this alone; the lock-free forwarding path of
    /// `crate::lx` (wave 4) switches tasks without it.
    pub leaving: u64,
}

/// Words of [`PerCpu::exit_stack`] (16 KiB).
pub const EXIT_STACK_WORDS: usize = 2048;
/// Offset of [`PerCpu::exit_scratch`] (used by the trap epilogue in `arch::idt`).
pub const EXIT_SCRATCH: usize = 32;
/// Offset of [`PerCpu::exit_frame`] (used by the trap epilogue in `arch::idt`).
pub const EXIT_FRAME: usize = 40 + 8 * EXIT_STACK_WORDS;
const _: () = assert!(core::mem::offset_of!(PerCpu, exit_scratch) == EXIT_SCRATCH);
const _: () = assert!(core::mem::offset_of!(PerCpu, exit_frame) == EXIT_FRAME);
/// Offset of [`PerCpu::leaving`] (used by the trap epilogues in `arch::idt`).
pub const LEAVING: usize = EXIT_FRAME + 40;
const _: () = assert!(core::mem::offset_of!(PerCpu, leaving) == LEAVING);

static mut PERCPU: [PerCpu; MAX_CPUS] = [const {
    PerCpu { self_ptr: 0, cpu: 0, kernel_rsp: 0, user_rsp: 0, exit_scratch: 0, exit_stack: [0; EXIT_STACK_WORDS], exit_frame: [0; 5], leaving: 0 }
}; MAX_CPUS];

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

/// Records that the calling CPU is leaving task `id`'s kernel stack (see [`PerCpu::leaving`]).
#[inline(always)]
pub fn set_leaving(id: u64) {
    unsafe { core::arch::asm!("mov qword ptr gs:[{o}], {v}", o = const LEAVING, v = in(reg) id + 1, options(nostack, preserves_flags)) };
}

/// CPU `c`'s LEAVING mark (task ID plus one; 0: none), for the task dump.
pub fn leaving_of(c: usize) -> u64 {
    // SAFETY: a plain word of another CPU's block
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PERCPU[c].leaving)) }
}

/// Whether a CPU other than the calling one is still leaving task `id`'s kernel stack.
#[inline]
pub fn leaving_elsewhere(id: u64) -> bool {
    let me = cpu();
    // (only the CPUs online: each block is a cache line of its own CPU)
    (0..super::smp::online().min(MAX_CPUS)).any(|c| {
        // SAFETY: a plain word of another CPU's block, written by that CPU alone
        c != me && unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PERCPU[c].leaving)) } == id + 1
    })
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
