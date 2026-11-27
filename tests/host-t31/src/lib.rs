//! Group 31's host build of the kernel's task, scheduler, sync, native system call and
//! capability code (`src/task`, `src/sync`, `src/syscall`, `src/capability`).
//!
//! Each kernel module below is compiled from the kernel's own source through `#[path]`,
//! laid out under the same module path the kernel uses, so `crate::` and `super::`
//! references resolve unchanged. `task` is the real module tree (`mod.rs` with its
//! `scheduler`, `tcb`, `wait`, `supervisor`, `elf` and `exec`), as are `sync`, `syscall`,
//! `capability`, `memory::vm`, `memory::frame_allocator`, `arch::vdso`, `ipc::message`,
//! `ipc::protocol`, `compat::linux::types`, `lx::restart_policy` and `personality::abi`.
//!
//! Everything else the code calls is a *stub* at the same `crate::` path, backed by the
//! fake state in [`fake`]: the per-CPU block (each test thread plays one CPU, see
//! [`fake::set_cpu`]), the kernel lock and CPU kicks, the clock, the service registry,
//! PCI, the Linux process table. The x86_64 shim turns `Cr3::read`, `cli`/`sti`/`hlt`
//! and TLB flushes into per-thread fakes; the yield vector (`int 0x81`) and the native
//! `syscall` instruction become [`fake::host_yield`] and [`fake::host_syscall`].
//!
//! Paths inside an inline `mod` block are resolved relative to a directory named after
//! that module, hence the extra `../` per nesting level.

#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

extern crate alloc;

pub mod fake;

/// *stub* Kernel console output; discarded on the host.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

/// *stub* Kernel log output: kept in `fake::KLOG` for the tests to read.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        $crate::fake::klog(alloc::format!($($arg)*));
    }};
}

pub mod arch {
    /// *stub* The timer: the fake clock.
    pub mod pit {
        use core::sync::atomic::Ordering;
        pub use crate::fake::{now_ns, sleep_ticks, ticks};
        pub fn tick_ns() -> u64 {
            crate::fake::TICK_NS
        }
        pub fn frequency_hz() -> u64 {
            100
        }
        pub fn is_active() -> bool {
            crate::fake::PIT_ACTIVE.load(Ordering::SeqCst)
        }
        pub fn sleep_ms(ms: u64) {
            sleep_ticks((ms + 9) / 10);
        }
        pub fn clock_state() -> (u64, u64, u64, u64) {
            (0, 0, 0, 1)
        }
        pub fn uptime_ms() -> u64 {
            ticks() * 10
        }
    }
    /// *stub*
    pub mod rtc {
        pub fn wall_base_ns() -> i64 {
            0
        }
    }
    /// *stub* The per-CPU block: the CPU is the test thread's (`fake::set_cpu`); the
    /// per-CPU variables are arrays indexed by it, as in the kernel.
    pub mod percpu {
        use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
        use crate::fake::MAX_CPUS;

        pub fn cpu() -> usize {
            crate::fake::cpu()
        }
        pub fn set_leaving(id: u64) {
            crate::fake::LEAVING[cpu()].store(id + 1, Ordering::SeqCst);
        }
        pub fn leaving_of(c: usize) -> u64 {
            crate::fake::LEAVING[c].load(Ordering::SeqCst)
        }
        /// *mirror* of the kernel's check.
        pub fn leaving_elsewhere(id: u64) -> bool {
            let me = cpu();
            (0..super::smp::online().min(MAX_CPUS)).any(|c| c != me && leaving_of(c) == id + 1)
        }
        pub fn set_kernel_rsp(rsp: u64) {
            crate::fake::KERNEL_RSP[cpu()].store(rsp, Ordering::SeqCst);
        }

        /// *mirror*
        pub struct PerCpuU64([AtomicU64; MAX_CPUS]);
        impl PerCpuU64 {
            pub const fn new(v: u64) -> Self {
                let mut a = [const { AtomicU64::new(0) }; MAX_CPUS];
                let mut i = 0;
                while i < MAX_CPUS {
                    a[i] = AtomicU64::new(v);
                    i += 1;
                }
                Self(a)
            }
            pub fn on(&self, cpu: usize) -> &AtomicU64 {
                &self.0[cpu]
            }
            pub fn load(&self, o: Ordering) -> u64 {
                self.0[cpu()].load(o)
            }
            pub fn store(&self, v: u64, o: Ordering) {
                self.0[cpu()].store(v, o)
            }
            pub fn swap(&self, v: u64, o: Ordering) -> u64 {
                self.0[cpu()].swap(v, o)
            }
            pub fn fetch_add(&self, v: u64, o: Ordering) -> u64 {
                self.0[cpu()].fetch_add(v, o)
            }
        }
        /// *mirror*
        pub struct PerCpuU32([AtomicU32; MAX_CPUS]);
        impl PerCpuU32 {
            pub const fn new() -> Self {
                Self([const { AtomicU32::new(0) }; MAX_CPUS])
            }
            /// (host only) CPU `c`'s value.
            pub fn on(&self, c: usize) -> &AtomicU32 {
                &self.0[c]
            }
            pub fn load(&self, o: Ordering) -> u32 {
                self.0[cpu()].load(o)
            }
            pub fn store(&self, v: u32, o: Ordering) {
                self.0[cpu()].store(v, o)
            }
            pub fn swap(&self, v: u32, o: Ordering) -> u32 {
                self.0[cpu()].swap(v, o)
            }
            pub fn fetch_add(&self, v: u32, o: Ordering) -> u32 {
                self.0[cpu()].fetch_add(v, o)
            }
            pub fn fetch_sub(&self, v: u32, o: Ordering) -> u32 {
                self.0[cpu()].fetch_sub(v, o)
            }
        }
        /// *mirror*
        pub struct PerCpuPtr<T>([AtomicPtr<T>; MAX_CPUS]);
        impl<T> PerCpuPtr<T> {
            pub const fn new() -> Self {
                Self([const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS])
            }
            /// (host only) CPU `c`'s value.
            pub fn on(&self, c: usize) -> &AtomicPtr<T> {
                &self.0[c]
            }
            pub fn load(&self, o: Ordering) -> *mut T {
                self.0[cpu()].load(o)
            }
            pub fn store(&self, v: *mut T, o: Ordering) {
                self.0[cpu()].store(v, o)
            }
            pub fn swap(&self, v: *mut T, o: Ordering) -> *mut T {
                self.0[cpu()].swap(v, o)
            }
        }
    }
    /// *stub* Several CPUs: `fake::ONLINE`; the kernel lock and kicks are recorded.
    pub mod smp {
        use core::sync::atomic::{AtomicU64, Ordering};
        use crate::fake;
        pub const MAX_CPUS: usize = fake::MAX_CPUS;
        pub static LOADED_CR3: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
        pub fn online() -> usize {
            fake::ONLINE.load(Ordering::SeqCst)
        }
        pub fn bkl_exit() {
            fake::BKL_EXITS.fetch_add(1, Ordering::SeqCst);
            let hook = *fake::BKL_EXIT_HOOK.lock().unwrap();
            if let Some(h) = hook {
                h();
            }
        }
        pub fn bkl_enter() {
            fake::BKL_ENTERS.fetch_add(1, Ordering::SeqCst);
        }
        pub fn bkl_enter_idle() {
            fake::BKL_ENTERS.fetch_add(1, Ordering::SeqCst);
        }
        pub fn bkl_held() -> bool {
            fake::BKL_HELD.load(Ordering::SeqCst)
        }
        pub fn bkl_owner() -> usize {
            0
        }
        pub fn kick_idle() {
            fake::KICK_IDLE.fetch_add(1, Ordering::SeqCst);
        }
        pub fn kick_cpu(c: usize) {
            fake::KICKED_CPUS.lock().unwrap().push(c);
        }
        pub fn kick_pending() -> bool {
            fake::KICK_PENDING.load(Ordering::SeqCst)
        }
        pub fn switch_kick(others: bool, _others_prio: u8) {
            fake::SWITCH_KICKS.lock().unwrap().push(others);
        }
        // wave11 GD: wakeup preemption
        pub fn kick_for(prio: u8, _recent: u32) {
            fake::KICK_IDLE.fetch_add(1, Ordering::SeqCst);
            fake::KICK_PRIOS.lock().unwrap().push(prio);
        }
        pub fn set_cur_prio(_p: u8, _recent: u32) {}
        pub fn serve_tlb() {
            fake::SERVE_TLB.fetch_add(1, Ordering::SeqCst);
        }
        pub fn runnable_gen() -> u64 {
            7
        }
        pub fn idle_poll() -> bool {
            fake::IDLE_POLL.load(Ordering::SeqCst)
        }
        pub fn idle_halting(_gen: u64) -> bool {
            fake::IDLE_HALTING.load(Ordering::SeqCst)
        }
        pub fn idle_halt_ended() -> bool {
            fake::IDLE_HALT_ENDED.load(Ordering::SeqCst)
        }
        pub fn flush_kick() {}
        pub fn shootdown(_cr3: Option<u64>, addr: Option<u64>) {
            match addr {
                Some(a) => x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(a)),
                None => x86_64::instructions::tlb::flush_all(),
            }
        }
    }
    /// *stub* PCID off; a CR3 load sets the thread's fake CR3 and is recorded.
    pub mod pcid {
        /// *stub* wave11 GG
        pub fn must_reload(_pml4: u64) -> bool {
            false
        }
        pub fn enabled() -> bool {
            false
        }
        pub fn global_enabled() -> bool {
            false
        }
        pub fn load_cr3(pml4: u64) {
            crate::fake::CR3_LOADS.lock().unwrap().push(pml4);
            x86_64::set_cr3(pml4);
            super::smp::LOADED_CR3[super::percpu::cpu()].store(pml4, core::sync::atomic::Ordering::SeqCst);
        }
        pub fn forget(_pml4: u64) {}
        pub fn mark_remote(_cpu: usize, _pml4: u64) {}
        pub fn flush_all_ids() {}
        pub fn without_invpcid<R>(f: impl FnOnce() -> R) -> R {
            f()
        }
    }
    /// *stub*
    pub mod gdt {
        pub const USER_CS: u16 = 0x2b;
        pub const USER32_CS: u16 = 0x23;
        pub const USER_DS: u16 = 0x1b;
        pub fn set_privilege_stack(top: x86_64::VirtAddr) {
            crate::fake::RSP0[super::percpu::cpu()].store(top.as_u64(), core::sync::atomic::Ordering::SeqCst);
        }
    }
    /// *mirror* of the kernel's exception frame and FXSAVE area; the trap state the
    /// scheduler reads; the host's yield vector.
    pub mod idt {
        use core::sync::atomic::{AtomicU64, Ordering};
        #[repr(C)]
        #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
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
        }
        pub static NMI_AT: [[AtomicU64; 2]; super::smp::MAX_CPUS] = [const { [const { AtomicU64::new(0) }; 2] }; super::smp::MAX_CPUS];
        pub static CURRENT_TRAP_FPU: super::percpu::PerCpuPtr<FpuState> = super::percpu::PerCpuPtr::new();
        /// *host* The yield vector (`int 0x81`).
        pub fn host_yield() {
            crate::fake::host_yield()
        }
        /// *host*
        pub fn reset() {
            for c in 0..super::smp::MAX_CPUS {
                CURRENT_TRAP_FPU.on(c).store(core::ptr::null_mut(), Ordering::SeqCst);
                NMI_AT[c][0].store(0, Ordering::SeqCst);
                NMI_AT[c][1].store(0, Ordering::SeqCst);
            }
        }
    }
    /// *stub* User segment state: the selectors are not read on the host (`save` keeps
    /// what the task had; `load` records the FS base).
    pub mod segments {
        use alloc::boxed::Box;
        use alloc::sync::Arc;
        use spin::Mutex;
        pub const TLS_ENTRIES: usize = 3;
        #[derive(Clone, Copy, Default, Debug)]
        pub struct UserSegs {
            pub gs_base: u64,
            pub ds: u16,
            pub es: u16,
            pub fs: u16,
            pub gs: u16,
            pub tls: [u64; TLS_ENTRIES],
        }
        pub struct Ldt {
            entries: Box<[u64]>,
        }
        impl Ldt {
            pub fn new(entries: Box<[u64]>) -> Ldt {
                Ldt { entries }
            }
            pub fn entries(&self) -> &[u64] {
                &self.entries
            }
        }
        impl Clone for Ldt {
            fn clone(&self) -> Self {
                Ldt { entries: self.entries.clone() }
            }
        }
        pub type SharedLdt = Arc<Mutex<Option<Arc<Ldt>>>>;
        pub fn save(_s: &mut UserSegs) {}
        pub fn load(_s: &UserSegs, fs_base: u64, _ldt: Option<&SharedLdt>) {
            crate::fake::FS_BASE[super::percpu::cpu()].store(fs_base, core::sync::atomic::Ordering::SeqCst);
        }
        /// *mirror* of the kernel's rule for the selectors it knows.
        pub fn sanitize_frame(cs: &mut u64, ss: &mut u64, rip: &mut u64) {
            let cs_ok = *cs as u16 == super::gdt::USER_CS || (*cs as u16 == super::gdt::USER32_CS && *rip <= u32::MAX as u64);
            if !cs_ok || *ss as u16 != super::gdt::USER_DS {
                *cs = super::gdt::USER_CS as u64;
                *ss = super::gdt::USER_DS as u64;
            }
        }
    }
    /// *stub*
    pub mod debugregs {
        pub fn switch_to(_dr: &[u64; 8]) {}
    }
    /// *stub* MSRs (the FS base is the CPU's fake one), the syscall frame, the native
    /// system call numbers.
    pub mod syscall {
        use core::sync::atomic::Ordering;
        pub const SYS_YIELD: u64 = 1;
        pub const SYS_SLEEP: u64 = 2;
        pub const SYS_WRITE: u64 = 3;
        pub const SYS_EXIT: u64 = 4;
        pub const SYS_GETPID: u64 = 5;
        pub const SYS_UPTIME: u64 = 6;
        pub const SYS_IPC_SEND: u64 = 7;
        pub const SYS_IPC_RECV: u64 = 8;
        pub const SYS_OPEN: u64 = 9;
        pub const SYS_CLOSE: u64 = 10;
        pub const SYS_READ: u64 = 11;
        pub const SYS_PIPE: u64 = 12;
        pub const SYS_DUP2: u64 = 13;

        /// *stub*
        #[derive(Default, Clone, Debug)]
        pub struct SyscallStats {
            pub total_calls: u64,
        }
        pub static SYSCALL_STATS: spin::Mutex<SyscallStats> = spin::Mutex::new(SyscallStats { total_calls: 0 });

        /// The saved user registers at syscall entry (same fields and order as the kernel).
        #[repr(C)]
        #[derive(Default, Clone, Debug)]
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
        pub static SYSCALL_FPU: super::percpu::PerCpuPtr<super::idt::FpuState> = super::percpu::PerCpuPtr::new();
        pub fn set_kernel_rsp(rsp: u64) {
            super::percpu::set_kernel_rsp(rsp)
        }
        /// IA32_FS_BASE is the CPU's fake one; IA32_EFER reports NX; others read 0.
        pub unsafe fn rdmsr(msr: u32) -> u64 {
            match msr {
                0xC000_0100 => crate::fake::FS_BASE[super::percpu::cpu()].load(Ordering::SeqCst),
                0xC000_0080 => 1 << 11,
                _ => 0,
            }
        }
        pub unsafe fn wrmsr(msr: u32, value: u64) {
            if msr == 0xC000_0100 {
                crate::fake::FS_BASE[super::percpu::cpu()].store(value, Ordering::SeqCst);
            }
        }
        pub extern "C" fn hydra_syscall_dispatcher(_frame: &mut SyscallFrame, _fpu: *mut super::idt::FpuState) {}
        /// *host* The `syscall` instruction of `src/syscall/user.rs`.
        pub fn host_syscall(num: u64, args: [u64; 3]) -> i64 {
            crate::fake::host_syscall(num, args)
        }
        /// *host*
        pub fn reset() {
            for c in 0..super::smp::MAX_CPUS {
                SYSCALL_FPU.on(c).store(core::ptr::null_mut(), Ordering::SeqCst);
            }
        }
    }
    /// *stub*
    pub mod boot_services {
        pub fn is_hardware_takeover_complete() -> bool {
            crate::fake::TAKEOVER.load(core::sync::atomic::Ordering::SeqCst)
        }
    }
    /// *stub*
    pub mod relocate {
        pub fn image_phys() -> Option<(u64, u64)> {
            None
        }
    }
    #[path = "../../../../src/arch/vdso.rs"]
    pub mod vdso;
    /// *stub* PCI configuration space: the fake functions of `fake::PCI`.
    pub mod pci {
        use alloc::vec::Vec;
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PciDevice {
            pub bus: u8,
            pub device: u8,
            pub function: u8,
            pub vendor_id: u16,
            pub device_id: u16,
            pub class_id: u8,
            pub subclass_id: u8,
            pub bar0: u32,
            pub irq_line: u8,
        }
        fn with_cfg<R>(b: u8, d: u8, f: u8, op: impl FnOnce(&mut [u8; 256]) -> R) -> Option<R> {
            let mut p = crate::fake::PCI.lock().unwrap();
            p.iter_mut().find(|x| (x.dev.bus, x.dev.device, x.dev.function) == (b, d, f)).map(|x| op(&mut x.config))
        }
        pub fn pci_read_u32(b: u8, d: u8, f: u8, off: u8) -> u32 {
            let o = off as usize;
            with_cfg(b, d, f, |c| u32::from_le_bytes(c[o..o + 4].try_into().unwrap())).unwrap_or(u32::MAX)
        }
        pub fn pci_read_u16(b: u8, d: u8, f: u8, off: u8) -> u16 {
            let o = off as usize;
            with_cfg(b, d, f, |c| u16::from_le_bytes(c[o..o + 2].try_into().unwrap())).unwrap_or(u16::MAX)
        }
        pub fn pci_read_u8(b: u8, d: u8, f: u8, off: u8) -> u8 {
            with_cfg(b, d, f, |c| c[off as usize]).unwrap_or(u8::MAX)
        }
        pub fn pci_write_u32(b: u8, d: u8, f: u8, off: u8, v: u32) {
            let o = off as usize;
            with_cfg(b, d, f, |c| c[o..o + 4].copy_from_slice(&v.to_le_bytes()));
        }
        pub fn pci_write_u16(b: u8, d: u8, f: u8, off: u8, v: u16) {
            let o = off as usize;
            with_cfg(b, d, f, |c| c[o..o + 2].copy_from_slice(&v.to_le_bytes()));
        }
        pub fn enable_bus_mastering(dev: &PciDevice) {
            crate::fake::BUS_MASTERS.lock().unwrap().push((dev.bus, dev.device, dev.function));
        }
        pub fn find_all_class(class: u8, sub: u8) -> Vec<PciDevice> {
            crate::fake::PCI.lock().unwrap().iter().filter(|x| x.dev.class_id == class && x.dev.subclass_id == sub).map(|x| x.dev).collect()
        }
        pub fn find_class(class: u8, sub: u8) -> Option<PciDevice> {
            find_all_class(class, sub).into_iter().next()
        }
        fn bar(dev: &PciDevice, i: u8) -> (u64, u64) {
            let p = crate::fake::PCI.lock().unwrap();
            p.iter().find(|x| x.dev == *dev).map_or((0, 0), |x| x.bars[i as usize])
        }
        pub fn bar_address(dev: &PciDevice, i: u8) -> u64 {
            bar(dev, i).0
        }
        pub fn bar_size(dev: &PciDevice, i: u8) -> u64 {
            bar(dev, i).1
        }
        /// wave11 GG: the capability list walk, on the fake configuration space.
        pub fn find_capability(dev: &PciDevice, id: u8) -> Option<u8> {
            let (b, d, f) = (dev.bus, dev.device, dev.function);
            if pci_read_u16(b, d, f, 0x06) & 0x10 == 0 {
                return None;
            }
            let mut at = pci_read_u8(b, d, f, 0x34) & 0xFC;
            for _ in 0..48 {
                if at < 0x40 {
                    return None;
                }
                if pci_read_u8(b, d, f, at) == id {
                    return Some(at);
                }
                at = pci_read_u8(b, d, f, at + 1) & 0xFC;
            }
            None
        }
    }
    /// *stub*
    pub mod iommu {
        use core::sync::atomic::Ordering;
        pub fn attach(endpoint: u32, name: &'static str, _dev: &super::pci::PciDevice) {
            crate::fake::IOMMU_ATTACH.lock().unwrap().push((endpoint, name));
        }
        pub fn dma_test_enabled() -> bool {
            crate::fake::IOMMU_DMA_TEST.load(Ordering::SeqCst)
        }
        pub fn poll_faults() -> usize {
            crate::fake::IOMMU_POLLS.fetch_add(1, Ordering::SeqCst);
            0
        }
    }
    /// *stub*
    pub mod bootdisk {
        pub fn driver_arg() -> Option<alloc::string::String> {
            crate::fake::BOOTDISK_ARG.lock().unwrap().clone()
        }
        pub fn new_guid_id() -> Option<u64> {
            *crate::fake::NEW_GUID.lock().unwrap()
        }
    }
    /// *stub*
    pub mod usb_input {
        pub fn start() {
            crate::fake::STARTS.lock().unwrap().push("usb_input");
        }
    }
}

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

/// *stub* The serial port and console.
pub mod console {
    pub fn serial_write(s: &str) {
        crate::fake::SERIAL.lock().unwrap().push_str(s);
    }
    pub fn check_interrupt() -> bool {
        crate::fake::CTRL_C.load(core::sync::atomic::Ordering::SeqCst)
    }
    /// *mirror* A fixed-size text buffer (formatting without the heap).
    pub struct FixedBuf {
        buf: [u8; 256],
        len: usize,
    }
    impl FixedBuf {
        pub const fn new() -> Self {
            Self { buf: [0; 256], len: 0 }
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
        }
    }
    impl core::fmt::Write for FixedBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
}

pub mod compat {
    pub mod linux {
        use core::sync::atomic::Ordering;
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        /// *stub*
        pub fn ident_changed() {
            crate::fake::IDENT_CHANGED.fetch_add(1, Ordering::SeqCst);
        }
        /// *stub* The seccomp state a task carries (not evaluated here).
        pub mod seccomp {
            #[derive(Clone, Default)]
            pub struct State {
                pub no_new_privs: bool,
                pub mode: u8,
            }
        }
        /// *stub* The profiler's hooks: recorded.
        pub mod prof {
            pub const FAULT_PRESENT: usize = 0;
            pub const FAULT_ANON: usize = 1;
            pub const FAULT_OBJECT: usize = 2;
            pub const FAULT_FAILED: usize = 3;
            fn note(k: &'static str, id: u64) {
                crate::fake::PROF.lock().unwrap().push((k, id));
            }
            pub fn sample(task: u64, _rip: u64, _cs: u64) {
                note("sample", task)
            }
            pub fn slow(_nr: u64, _r: i64, _a0: u64, _a1: u64, _a2: u64, _t0: u64) {}
            pub fn wake_requested(id: u64) {
                note("wake_requested", id)
            }
            pub fn wake_applied(id: u64) {
                note("wake_applied", id)
            }
            pub fn wake_dropped(id: u64) {
                note("wake_dropped", id)
            }
            pub fn switched_in(id: u64) {
                note("switched_in", id)
            }
            pub fn start() -> u64 {
                0
            }
            pub fn fault(_kind: usize, _t0: u64) {}
        }
        /// *stub*
        pub mod perf {
            pub fn tick(tgid: u64) {
                crate::fake::PERF.lock().unwrap().push(("tick", tgid));
            }
            pub fn switched(tgid: u64) {
                crate::fake::PERF.lock().unwrap().push(("switched", tgid));
            }
        }
        /// *stub* The futex table: the clear-tid wake and robust-list walk are recorded
        /// and wake the ids the test put in `fake::FUTEX_WOKEN` / `fake::ROBUST_WOKEN`.
        pub mod futex {
            use crate::task::TaskId;
            use alloc::vec::Vec;
            pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct FutexKey {
                pub space: u64,
                pub uaddr: u64,
            }
            /// Verbatim from the kernel.
            pub fn key_for_task(task: &crate::task::Task, uaddr: u64) -> FutexKey {
                FutexKey { space: task.mm.as_ref().map_or(task.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64), uaddr }
            }
            pub fn wake_key(key: FutexKey, _max: usize, _bitset: u32) -> Vec<TaskId> {
                crate::fake::FUTEX_WAKES.lock().unwrap().push((key.space, key.uaddr));
                crate::fake::FUTEX_WOKEN.lock().unwrap().iter().map(|&i| TaskId(i)).collect()
            }
            pub fn exit_robust_list(head: u64, tid: u32, space: u64) -> Vec<TaskId> {
                crate::fake::ROBUST.lock().unwrap().push((head, tid, space));
                crate::fake::ROBUST_WOKEN.lock().unwrap().iter().map(|&i| TaskId(i)).collect()
            }
        }
        /// *stub* The Linux process table: recorded.
        pub mod proc {
            pub fn register_process(pid: u64, ppid: u64, tid: u64, inherit: Option<u64>) {
                crate::fake::REG_PROCS.lock().unwrap().push((pid, ppid, tid, inherit));
            }
            pub fn register_thread(pid: u64, tid: u64, creator: u64) {
                crate::fake::REG_THREADS.lock().unwrap().push((pid, tid, creator));
            }
            pub fn thread_exited(pid: u64, tid: u64, _run: u64, _sys: u64, _cred: (u32, u32)) {
                crate::fake::EXITED.lock().unwrap().push((pid, tid));
            }
            pub fn parent_of(pid: u64) -> u64 {
                *crate::fake::PARENTS.lock().unwrap().get(&pid).unwrap_or(&1)
            }
            /// wave11 GR: the threads the test put in `fake::SIGNALLED`.
            pub fn signal_pending_for(tid: u64, _pid: u64) -> bool {
                crate::fake::SIGNALLED.lock().unwrap().contains(&tid)
            }
        }
        /// *stub* Process accounting.
        pub mod admin {
            pub fn acct_on() -> bool {
                crate::fake::ACCT_ON.load(core::sync::atomic::Ordering::SeqCst)
            }
            pub fn note_task(tgid: u64, _uid: u32, _gid: u32, exe: &str) {
                crate::fake::ACCT.lock().unwrap().push((tgid, alloc::string::String::from(exe)));
            }
        }
        /// *stub* Program files by inode (`fake::INODES`).
        pub mod mm {
            pub fn inode_source(ino: u64) -> Result<crate::task::exec::ElfSource, i64> {
                let data = crate::fake::INODES.lock().unwrap().get(&ino).cloned().ok_or(-2i64)?;
                Ok(crate::task::exec::ElfSource::from_bytes(data.into_boxed_slice()))
            }
            pub fn cache_shrink(_pages: usize) -> usize {
                0
            }
        }
        /// *stub* No userfaultfd registrations on the host.
        pub mod userfaultfd {
            pub enum Waited {
                Again,
                Proceed,
                Refuse,
            }
            pub fn active() -> bool {
                false
            }
            pub fn wait_fault(_id: u64, _page: u64, _write: bool, _kernel: bool) -> Waited {
                Waited::Proceed
            }
        }
        /// *stub*
        pub mod snd {
            pub fn set_controller(_mmio: u64, slot: alloc::string::String, _vendor: u16, _device: u16, _subsys: u32) {
                crate::fake::SND.lock().unwrap().push(slot);
            }
            pub fn start() {
                crate::fake::STARTS.lock().unwrap().push("snd");
            }
            // wave8 GS begin: the sound service's start asks for the card (none on the host)
            pub fn probe() {}
            pub fn card() -> Option<(u32, u32, [u32; 2], alloc::string::String, u64)> {
                None
            }
            // wave8 GS end
        }
    }
}

/// *stub* The file layer: descriptor tables, the file server client, the boot volume.
pub mod fs {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    /// *stub* A descriptor table: only the parts the task code uses.
    pub struct FdTable {
        pub root_ino: u64,
        pub cwd_ino: u64,
        /// Descriptors open (a count is enough here).
        pub open: usize,
    }
    pub type SharedFdTable = Arc<spin::Mutex<FdTable>>;
    impl FdTable {
        pub const fn empty() -> Self {
            Self { root_ino: 0, cwd_ino: 0, open: 0 }
        }
        pub fn new_default() -> Self {
            Self { root_ino: 1, cwd_ino: 1, open: 3 }
        }
        pub fn init_default(&mut self) {
            if self.open == 0 {
                *self = Self::new_default();
            }
        }
        pub fn into_shared(self) -> SharedFdTable {
            Arc::new(spin::Mutex::new(self))
        }
        pub fn fork_copy(&self) -> Self {
            Self { root_ino: self.root_ino, cwd_ino: self.cwd_ino, open: self.open }
        }
        pub fn close_all(&mut self) {
            if self.open != 0 {
                crate::fake::FDS_CLOSED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
            self.open = 0;
        }
    }

    /// *stub*
    pub mod client {
        use alloc::vec::Vec;
        pub struct FileStat {
            pub size: u64,
        }
        pub struct ZfsClient;
        impl ZfsClient {
            pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
                crate::fake::FILES.lock().unwrap().get(path).map(|d| FileStat { size: d.len() as u64 }).ok_or("not found")
            }
            pub fn read_file_by_path(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
                let f = crate::fake::FILES.lock().unwrap();
                let d = f.get(path).ok_or("not found")?;
                let n = d.len().min(out.len());
                out[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            pub fn resolve(_base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
                let p = alloc::string::String::from_utf8_lossy(path).into_owned();
                crate::fake::PATHS.lock().unwrap().get(&p).copied().ok_or(-2)
            }
            pub fn resolve_in(root: u64, _base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
                let p = alloc::format!("{}:{}", root, alloc::string::String::from_utf8_lossy(path));
                crate::fake::PATHS.lock().unwrap().get(&p).copied().ok_or(-2)
            }
        }
    }
    pub use client::ZfsClient;

    /// *stub*
    pub mod bootfs {
        pub fn read_boot_file(path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
            crate::fake::BOOT_FILES.lock().unwrap().get(path).cloned().ok_or("not found")
        }
    }
    /// *stub*
    pub mod zfs {
        pub static POOL_ON_USB: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    }
}

pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    pub use message::Message;
    pub use protocol::*;

    // wave8 GS begin
    /// *stub* The sound service's kernel side: forwarded (the default boot words).
    pub mod sound {
        pub fn forwarded() -> bool {
            true
        }
    }
    // wave8 GS end

    /// *stub* The service registry: `fake::SERVERS` and friends.
    pub mod service {
        use super::Message;
        use alloc::vec::Vec;
        use crate::fake;
        pub const CALL_TIMEOUT_TICKS: u64 = 500;
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum CallMode {
            Handoff,
            Queued,
        }
        pub fn is_online(endpoint: u32) -> bool {
            fake::SERVERS.lock().unwrap().contains_key(&endpoint)
        }
        pub fn server_of(endpoint: u32) -> u64 {
            let v = *fake::SERVERS.lock().unwrap().get(&endpoint).unwrap_or(&0);
            // (wave7 GB: another driver registers right after this look, once)
            if let Some((ep, id)) = fake::REGISTER_AFTER_LOOK.lock().unwrap().take_if(|(ep, _)| *ep == endpoint) {
                fake::SERVERS.lock().unwrap().insert(ep, id);
            }
            v
        }
        pub fn primary_of(endpoint: u32) -> u32 {
            *fake::PRIMARY.lock().unwrap().get(&endpoint).unwrap_or(&endpoint)
        }
        pub fn serves_queued_for(ep: u32, waits: impl Fn(u64) -> bool) -> bool {
            let callers = fake::QUEUED.lock().unwrap().get(&ep).cloned().unwrap_or_default();
            callers.into_iter().any(|c| waits(c))
        }
        pub fn window_held_by_other(task: u64) -> bool {
            fake::WINDOW_HELD.load(core::sync::atomic::Ordering::SeqCst)
                && fake::WINDOW_HOLDERS.lock().unwrap().iter().all(|&(_, t)| t != task)
        }
        pub fn holds_window(task: u64) -> bool {
            fake::WINDOW_HOLDERS.lock().unwrap().iter().any(|&(_, t)| t == task)
        }
        pub fn window_holders() -> Vec<(u32, u64)> {
            fake::WINDOW_HOLDERS.lock().unwrap().clone()
        }
        pub fn release_windows(id: u64) {
            fake::SVC_LOG.lock().unwrap().push(("release_windows", 0, id, 0));
            fake::WINDOW_HOLDERS.lock().unwrap().retain(|&(_, t)| t != id);
        }
        /// *stub* A held window (nothing to release on the host).
        pub struct WindowGuard;
        pub fn hold_window(endpoint: u32) -> WindowGuard {
            fake::SVC_LOG.lock().unwrap().push(("hold_window", endpoint, 0, 0));
            WindowGuard
        }
        fn answer(endpoint: u32, request: Message) -> Result<Message, i64> {
            let hook = *fake::CALL_HOOK.lock().unwrap();
            match hook {
                Some(h) => h(endpoint, request),
                None => Err(-110), // ETIMEDOUT
            }
        }
        pub fn call(endpoint: u32, request: Message, _timeout: u64) -> Result<Message, i64> {
            answer(endpoint, request)
        }
        pub fn call_once_mode(endpoint: u32, request: Message, _timeout: u64, _mode: CallMode) -> Result<Message, i64> {
            answer(endpoint, request)
        }
        pub fn msi_line(dev: &crate::arch::pci::PciDevice) -> Option<u8> {
            fake::MSI.lock().unwrap().get(&(dev.bus, dev.device, dev.function)).copied()
        }
        pub fn msix_line(dev: &crate::arch::pci::PciDevice) -> Option<(u8, u64, u32, u32)> {
            fake::MSIX.lock().unwrap().get(&(dev.bus, dev.device, dev.function)).copied()
        }
        pub fn set_grants(endpoint: u32, grants: Vec<(u64, u64)>) {
            let first = grants.first().copied().unwrap_or((0, 0));
            fake::SVC_LOG.lock().unwrap().push(("set_grants", endpoint, first.0, first.1));
        }
        pub fn release_irqs(id: u64) {
            fake::SVC_LOG.lock().unwrap().push(("release_irqs", 0, id, 0));
        }
        pub fn release_irqs_of_process(tgid: u64) {
            fake::SVC_LOG.lock().unwrap().push(("release_irqs_of_process", 0, tgid, 0));
        }
        pub fn unregister(endpoint: u32) {
            fake::SVC_LOG.lock().unwrap().push(("unregister", endpoint, 0, 0));
            fake::SERVERS.lock().unwrap().remove(&endpoint);
        }
        pub fn unregister_if(endpoint: u32, expected: u64) -> bool {
            let mut s = fake::SERVERS.lock().unwrap();
            if *s.get(&endpoint).unwrap_or(&0) != expected {
                return false;
            }
            fake::SVC_LOG.lock().unwrap().push(("unregister", endpoint, 0, 0));
            s.remove(&endpoint);
            true
        }
        pub fn allow_client(endpoint: u32, client: u32) {
            fake::SVC_LOG.lock().unwrap().push(("allow_client", endpoint, client as u64, 0));
        }
        pub fn forward_irq(from: u32, to: u32) {
            fake::SVC_LOG.lock().unwrap().push(("forward_irq", from, to as u64, 0));
        }
        pub fn set_signal_hook(endpoint: u32, _hook: fn(u64)) {
            fake::SVC_LOG.lock().unwrap().push(("set_signal_hook", endpoint, 0, 0));
        }
    }
}

/// *stub* The Linux server's kernel side (`src/lx`).
pub mod lx {
    #[path = "../../../../src/lx/restart_policy.rs"]
    pub mod restart_policy;
    pub fn init() {
        crate::fake::LX_CALLS.lock().unwrap().push("init");
    }
    pub fn watch() {
        crate::fake::LX_CALLS.lock().unwrap().push("watch");
    }
    pub fn dump() {
        crate::fake::LX_CALLS.lock().unwrap().push("dump");
    }
    pub fn on_signal(_bits: u64) {}
    pub fn on_signal_for<const EP: u32>(_bits: u64) {}
    /// *stub*
    pub mod svc {
        pub type SvcId = u8;
        pub fn host_by_endpoint(ep: u32) -> Option<SvcId> {
            crate::fake::LX_HOSTS.lock().unwrap().contains(&ep).then_some(2)
        }
        // wave8 GX2 begin: *stub* the registry's endpoints (the split defaults; a test may
        // co-locate a service in linux-server with `COLOCATED`)
        pub static COLOCATED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
        pub fn endpoint_of(svc: SvcId) -> u32 {
            use crate::ipc::protocol::*;
            if COLOCATED.lock().unwrap().contains(&svc) {
                return ENDPOINT_LINUX_SERVER;
            }
            match svc {
                LXS_NET => ENDPOINT_LX_NET,
                LXS_IPC => ENDPOINT_LX_IPC,
                _ => 0,
            }
        }
        // wave8 GX2 end
    }
    /// *stub*
    pub mod timer {
        use core::sync::atomic::Ordering;
        pub fn next_due() -> u64 {
            crate::fake::LX_TIMER_DUE.load(Ordering::SeqCst)
        }
        pub fn fire() -> bool {
            crate::fake::LX_TIMER_POSTS.load(Ordering::SeqCst)
        }
    }
    /// *stub* The restart ladder: answers from `fake::LX_MAY_RESTART`, calls recorded.
    pub mod restart {
        pub use super::restart_policy::RestartClass;
        pub const SVC_LINUX: u8 = 1;
        fn note(k: &'static str, svc: u8) {
            crate::fake::LX_LOG.lock().unwrap().push((k, svc));
        }
        pub fn configure(svc: u8, _class: RestartClass) {
            note("configure", svc)
        }
        pub fn fw_cfg(svc: u8, _name: &str) {
            note("fw_cfg", svc)
        }
        pub fn deliberate(svc: u8) {
            note("deliberate", svc)
        }
        pub fn started_by_hand(svc: u8) {
            note("started_by_hand", svc)
        }
        pub fn may_restart(svc: u8) -> bool {
            note("may_restart", svc);
            crate::fake::LX_MAY_RESTART.load(core::sync::atomic::Ordering::SeqCst)
        }
    }
}

pub mod memory {
    #[path = "../../../../src/memory/frame_allocator.rs"]
    pub mod frame_allocator;

    #[path = "../../../../src/memory/vm.rs"]
    pub mod vm;

    /// *stub*
    pub mod paging {
        pub fn make_user_accessible(start: x86_64::VirtAddr, size: usize) -> Result<(), &'static str> {
            crate::fake::USER_RANGES.lock().unwrap().push((start.as_u64(), size));
            Ok(())
        }
        /// The kernel's own address space does not exist on the host.
        pub static KERNEL_SPACE: spin::Mutex<Option<AddressSpace>> = spin::Mutex::new(None);

        /// Stand-in for `paging::AddressSpace` (as `tests/host`'s): only user address
        /// spaces, a fresh PML4 whose entry 0 points at a private, empty low PDPT.
        pub struct AddressSpace {
            pml4: x86_64::PhysAddr,
        }
        impl AddressSpace {
            pub fn create_user_space(alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager) -> Result<Self, &'static str> {
                use x86_64::structures::paging::PageTableFlags as F;
                let pml4 = alloc.allocate_zeroed_frame().ok_or("Out of memory: PML4")?;
                let pdpt = alloc.allocate_zeroed_frame().ok_or("Out of memory: low PDPT")?;
                let table = unsafe { &mut *(pml4.start_address().as_u64() as *mut x86_64::structures::paging::PageTable) };
                table[0].set_addr(pdpt.start_address(), F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE);
                Ok(Self { pml4: pml4.start_address() })
            }
            pub fn pml4_physical_address(&self) -> x86_64::PhysAddr {
                self.pml4
            }
            pub const fn from_pml4(pml4: x86_64::PhysAddr) -> Self {
                Self { pml4 }
            }
            /// Never called on the host.
            pub unsafe fn leaf_entry(&self, _va: u64) -> Option<&'static mut x86_64::structures::paging::page_table::PageTableEntry> {
                None
            }
            /// Never called on the host.
            pub unsafe fn map_page(
                &mut self,
                _page: x86_64::structures::paging::Page,
                _frame: x86_64::structures::paging::PhysFrame,
                _flags: x86_64::structures::paging::PageTableFlags,
                _alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager,
            ) -> Result<(), &'static str> {
                Err("no kernel address space on the host")
            }
        }
    }
    /// *stub* The kernel heap is the host's.
    pub mod heap {
        pub struct HeapStats {
            pub start_address: u64,
            pub total_bytes: usize,
            pub used_bytes: usize,
            pub free_bytes: usize,
        }
        pub fn try_stats() -> Option<HeapStats> {
            Some(HeapStats { start_address: 0, total_bytes: 4 << 20, used_bytes: 1 << 20, free_bytes: 3 << 20 })
        }
    }
}

/// *stub*
pub mod net {
    pub mod e1000 {
        pub struct Adapter {
            pub dev: crate::arch::pci::PciDevice,
            pub bar0: u64,
            pub model: &'static str,
        }
        pub fn find_adapter() -> Option<Adapter> {
            crate::fake::E1000.lock().unwrap().map(|(dev, bar0, model)| Adapter { dev, bar0, model })
        }
    }
    pub mod client {
        pub fn on_signal(_arg: u64) {}
    }
}

/// The personality hook: its pure tables, and `choose`/`interp_agrees` as the kernel's.
pub mod personality {
    #[path = "../../../../src/personality/abi.rs"]
    pub mod abi;
    use crate::task::TaskPersonality;
    /// *stub* A personality's system call table.
    pub struct Table;
    pub static FREEBSD_TABLE: Table = Table;
    pub static CURRENT_TABLE: crate::arch::percpu::PerCpuPtr<Table> = crate::arch::percpu::PerCpuPtr::new();
    /// *mirror*: FreeBSD has a table, Linux and Hydra none.
    pub fn table_for(p: TaskPersonality) -> *mut Table {
        match p {
            TaskPersonality::FreeBsd => &FREEBSD_TABLE as *const Table as *mut Table,
            _ => core::ptr::null_mut(),
        }
    }
    /// *mirror* (without the FreeBSD test switch: FreeBSD programs are refused).
    pub fn choose(head: &[u8], _path: &str) -> Result<TaskPersonality, i64> {
        match abi::classify(head) {
            abi::Kind::Linux => Ok(TaskPersonality::Linux),
            _ => Err(-8), // ENOEXEC
        }
    }
    /// *mirror* (without its log line).
    pub fn interp_agrees(pers: TaskPersonality, interp_head: &[u8], _interp: &str) -> bool {
        let k = abi::classify(interp_head);
        match pers {
            TaskPersonality::FreeBsd => k == abi::Kind::FreeBsd,
            _ => k == abi::Kind::Linux,
        }
    }
}

#[path = "../../../src/sync/mod.rs"]
pub mod sync;

#[path = "../../../src/syscall/mod.rs"]
pub mod syscall;

#[path = "../../../src/task/mod.rs"]
pub mod task;
