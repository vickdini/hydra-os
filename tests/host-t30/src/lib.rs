//! Group 30 (test wave): host build of the lx forwarding core (`src/lx`) and IPC (`src/ipc`).
//!
//! `ipc` and `lx` are the kernel's own directories, compiled through `#[path]` with their
//! `mod.rs` (so every file of theirs comes along, unchanged). What they call elsewhere in the
//! kernel is a stand-in below, at the same `crate::` path:
//!
//! - the scheduler is [`world`]: a one-CPU simulation where every task runs on a thread of
//!   its own and gives the CPU up exactly where the kernel's would (the yield and
//!   direct-switch vectors, `wait`), so request-table races run step by step;
//! - memory, descriptor tables, the process table and the hardware hooks are [`fake`] (and
//!   the small modules here), which record what they are asked.
//!
//! The tests are `#[cfg(test)]` child modules of the kernel files (`tests/host-t30/unit/`),
//! so they reach the files' private items, plus `tests/*.rs` for the public API.

#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

extern crate alloc;

pub mod fake;
pub mod world;

/// *stub* Kernel log: recorded in `fake::Rec::log`.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        $crate::fake::rec(|r| r.log.push(s));
    }};
}

/// *stub* Console output: recorded like `kprintln!`.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        $crate::fake::rec(|r| r.log.push(s));
    }};
}

// ----------------------------------------------------------------------
// The code under test
// ----------------------------------------------------------------------

#[path = "../../../src/ipc/mod.rs"]
pub mod ipc;

#[path = "../../../src/lx/mod.rs"]
pub mod lx;

// ----------------------------------------------------------------------
// Stand-ins
// ----------------------------------------------------------------------

/// *stub* The host side of the hardware-only stubs the kernel files call on the host
/// (`#[cfg(not(target_os = "uefi"))]` branches): the yield and direct-switch vectors and the
/// user-copy routines.
pub mod host {
    /// `int 0x81`.
    pub fn yield_vector() {
        crate::world::yield_cpu();
    }
    /// `int 0x82`: 0 after a switch (this task runs again), 1 when refused.
    pub fn direct_vector() -> u64 {
        crate::world::direct_vector()
    }
    /// `hydra_uaccess_copy`.
    pub fn uaccess_copy(dst: *mut u8, src: *const u8, n: usize) -> usize {
        crate::fake::uaccess_copy(dst, src, n)
    }
    /// `hydra_uaccess_str`.
    pub fn uaccess_str(dst: *mut u8, src: *const u8, max: usize) -> isize {
        crate::fake::uaccess_str(dst, src, max)
    }
}

pub mod arch {
    pub mod smp {
        pub const MAX_CPUS: usize = 16;
        pub use crate::world::{bkl_enter, bkl_exit, bkl_held};
        /// Counts spins; a spin lock held across a switch would spin forever: fail instead.
        pub fn serve_tlb() {
            let n = crate::fake::SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            assert!(n < 50_000_000, "spinning on a lock nobody can release (held across a switch?)");
        }
        pub fn online() -> usize {
            crate::fake::ONLINE_CPUS.load(core::sync::atomic::Ordering::Relaxed)
        }
        pub fn boot_apic_id() -> u32 {
            3
        }
        pub fn bkl_owner() -> usize {
            0
        }
    }
    pub mod percpu {
        pub fn cpu() -> usize {
            0
        }
        pub fn leaving_of(_c: usize) -> u64 {
            0
        }
    }
    pub mod pit {
        use core::sync::atomic::Ordering;
        pub fn ticks() -> u64 {
            crate::world::NOW_NS.load(Ordering::Acquire) / crate::world::TICK_NS
        }
        pub fn now_ns() -> u64 {
            let step = crate::world::CLOCK_STEP_NS.load(Ordering::Relaxed);
            crate::world::NOW_NS.fetch_add(step, Ordering::AcqRel) + step
        }
        pub fn frequency_hz() -> u64 {
            100
        }
        pub fn is_active() -> bool {
            true
        }
        pub fn tick_ns() -> u64 {
            crate::world::TICK_NS
        }
    }
    pub mod syscall {
        pub const SYS_LX_REPLY_RECV: u64 = 52;
        pub const SYS_SVC_DCALL: u64 = 70;
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
    }
    pub mod idt {
        pub static UACCESS_FAULTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        pub const MSI_VECTOR_BASE: u64 = 0x50;
    }
    pub mod fwcfg {
        pub fn read_file_into(name: &str, buf: &mut [u8]) -> Option<usize> {
            crate::fake::rec(|r| {
                let d = r.fwcfg.get(name)?;
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Some(n)
            })
        }
    }
    pub mod iommu {
        pub fn map_dma(endpoint: u32, phys: u64, len: u64) -> Result<(), ()> {
            crate::fake::rec(|r| {
                if r.dma_fail > 0 {
                    r.dma_fail -= 1;
                    return Err(());
                }
                r.dma.push((true, endpoint, phys, len));
                Ok(())
            })
        }
        pub fn unmap_dma(endpoint: u32, phys: u64, len: u64) {
            crate::fake::rec(|r| r.dma.push((false, endpoint, phys, len)));
        }
    }
    pub mod pic {
        pub fn mask_irq(irq: u8) {
            crate::fake::rec(|r| r.pic.push((true, irq)));
        }
        pub fn unmask_irq(irq: u8) {
            crate::fake::rec(|r| r.pic.push((false, irq)));
        }
    }
    pub mod pci {
        pub struct PciDevice {
            pub bus: u8,
            pub device: u8,
            pub function: u8,
        }
        pub fn enable_msi(_dev: &PciDevice, _apic_id: u32, _vector: u8) -> bool {
            crate::fake::rec(|r| r.msi_ok)
        }
        pub fn enable_msix(_dev: &PciDevice) -> Option<u64> {
            crate::fake::rec(|r| r.msix_table)
        }
    }
    pub mod vdso {
        pub fn map_vvar(_mm: &mut crate::memory::vm::Mm) -> Option<u64> {
            crate::fake::rec(|r| r.vvar)
        }
    }
}

pub mod capability {
    /// *stub* An object capability (only carried by messages here).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Capability(pub u64);
}

pub mod console {
    pub fn serial_write(s: &str) {
        crate::fake::rec(|r| r.serial.push_str(s));
    }
}

pub mod admin {
    pub mod linux {
        pub fn plasma(_root: &str, _nologin: bool) {
            crate::fake::rec(|r| r.plasma += 1);
        }
        pub fn display_manager_started() -> bool {
            crate::fake::rec(|r| r.display_manager)
        }
    }
}

pub mod net {
    pub mod client {
        pub fn raw_word(sid: u32) -> u64 {
            crate::fake::rec(|r| r.net_words.get(&sid).copied().unwrap_or(0))
        }
    }
}

pub mod sync {
    use crate::task::TaskId;
    use alloc::collections::VecDeque;

    /// *stub* The scheduler-backed FIFO of blocked tasks (`src/sync/wait_queue.rs`): the same
    /// methods, waking through the world's `unblock_task`.
    pub struct WaitQueue {
        q: VecDeque<TaskId>,
    }
    impl WaitQueue {
        pub const fn new() -> Self {
            Self { q: VecDeque::new() }
        }
        pub fn enqueue(&mut self, id: TaskId) {
            if !self.q.contains(&id) {
                self.q.push_back(id);
            }
        }
        pub fn wake_one(&mut self) -> Option<TaskId> {
            while let Some(id) = self.q.pop_front() {
                if crate::task::unblock_task(id) {
                    return Some(id);
                }
            }
            None
        }
        pub fn wake_all(&mut self) -> usize {
            let mut n = 0;
            while self.wake_one().is_some() {
                n += 1;
            }
            n
        }
        pub fn len(&self) -> usize {
            self.q.len()
        }
    }
}

pub mod memory {
    pub mod frame_allocator {
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;

        pub const PAGE_SIZE: u64 = 4096;

        /// *stub* Hands out host memory ("physical" address = host address).
        pub struct FrameAllocator;
        impl FrameAllocator {
            pub fn allocate_contiguous_frames(&mut self, n: usize) -> Option<PhysFrame<Size4KiB>> {
                if crate::fake::ALLOC_FAIL.load(core::sync::atomic::Ordering::Acquire) > 0 {
                    crate::fake::ALLOC_FAIL.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                    return None;
                }
                let base = crate::fake::alloc_pages(n);
                Some(PhysFrame::containing_address(PhysAddr::new(base)))
            }
            pub fn adopt(&mut self, f: PhysFrame<Size4KiB>) {
                crate::fake::FRAME_REFS.lock().unwrap().insert(f.start_address().as_u64(), 1);
            }
        }
        pub static FRAME_ALLOCATOR: spin::Mutex<FrameAllocator> = spin::Mutex::new(FrameAllocator);

        /// Identity: the host's memory is its own "direct map".
        pub fn phys_to_virt(phys: u64) -> *mut u8 {
            phys as *mut u8
        }
        pub fn frame_ref_inc(f: PhysFrame<Size4KiB>) {
            *crate::fake::FRAME_REFS.lock().unwrap().entry(f.start_address().as_u64()).or_insert(0) += 1;
        }
        pub fn frame_ref_dec(f: PhysFrame<Size4KiB>) {
            *crate::fake::FRAME_REFS.lock().unwrap().entry(f.start_address().as_u64()).or_insert(0) -= 1;
        }
    }

    pub mod vm {
        use alloc::sync::Arc;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;

        pub const PAGE_SIZE: u64 = 4096;

        /// *stub* What a mapping's pages come from.
        pub trait MappedObject: Send + Sync {
            fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>>;
        }

        /// *stub* A mapping's backing (only objects here).
        pub enum Backing {
            Object { obj: Arc<dyn MappedObject>, pgoff: u64 },
        }

        /// *stub* Why a fault failed.
        #[derive(Debug)]
        pub struct FaultError;

        /// One mapping a fake address space made.
        pub struct Mapping {
            pub addr: u64,
            pub len: u64,
            pub prot: u32,
            pub shared: bool,
            pub fixed: bool,
            pub obj: Arc<dyn MappedObject>,
            pub pgoff: u64,
            pub name: Option<String>,
        }

        /// *stub* An address space: records mappings; user pages are host memory (their
        /// "physical" address is their host address) unless marked bad.
        pub struct Mm {
            pub maps: Vec<Mapping>,
            pub next: u64,
            /// `mmap` fails with this.
            pub mmap_err: Option<i64>,
            /// `uffd_missing` answers (a page waiting for a handler: its uffd id).
            pub uffd: Vec<(u64, u64)>,
        }

        impl Mm {
            pub fn new() -> Self {
                Self { maps: Vec::new(), next: 0x7000_0000_0000, mmap_err: None, uffd: Vec::new() }
            }
            pub fn shared() -> Arc<spin::Mutex<Mm>> {
                Arc::new(spin::Mutex::new(Mm::new()))
            }
            #[allow(clippy::too_many_arguments)]
            pub fn mmap(&mut self, addr: u64, len: u64, prot: u32, shared: bool, fixed: bool, _x: bool, backing: Backing) -> Result<u64, i64> {
                if let Some(e) = self.mmap_err {
                    return Err(e);
                }
                let a = if fixed { addr } else { self.next };
                if !fixed {
                    self.next += (len + 0xFFFF) & !0xFFFF;
                }
                let Backing::Object { obj, pgoff } = backing;
                self.maps.push(Mapping { addr: a, len, prot, shared, fixed, obj, pgoff, name: None });
                Ok(a)
            }
            pub fn set_name(&mut self, start: u64, _end: u64, name: Option<&str>) {
                if let Some(m) = self.maps.iter_mut().find(|m| m.addr == start) {
                    m.name = name.map(|s| s.to_string());
                }
            }
            pub fn handle_fault(&mut self, addr: u64, _write: bool, _exec: bool) -> Result<(), FaultError> {
                if crate::fake::prefault(addr, 1) { Ok(()) } else { Err(FaultError) }
            }
            pub fn translate(&mut self, addr: u64) -> Option<PhysAddr> {
                if crate::fake::BAD.lock().unwrap().contains(&crate::fake::page(addr)) {
                    return None;
                }
                Some(PhysAddr::new(addr))
            }
            pub fn prefault(&mut self, addr: u64, len: u64, _write: bool) -> Result<(), FaultError> {
                if crate::fake::prefault(addr, len) { Ok(()) } else { Err(FaultError) }
            }
            pub fn uffd_missing(&mut self, addr: u64) -> Option<u64> {
                let p = addr & !0xFFF;
                let i = self.uffd.iter().position(|&(a, _)| a == p)?;
                Some(self.uffd.remove(i).1)
            }
        }

        /// *stub* The current task's address space for user copies (non-null: it has one).
        pub static CURRENT_MM: core::sync::atomic::AtomicPtr<u8> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

        /// As the kernel's: below the user top, no wrap.
        pub fn is_user_range(start: u64, len: u64) -> bool {
            start != 0 && start.checked_add(len).is_some_and(|e| e <= 0x0000_8000_0000_0000)
        }

        pub fn prefault_current(addr: u64, len: u64, _write: bool) -> bool {
            crate::fake::prefault(addr, len)
        }

        /// *stub* A memory object (`vm::MemObject`): pages, optionally contiguous frames.
        pub struct MemObject {
            pages: u64,
            base: Option<u64>,
            owned: bool,
            on_drop: Option<Box<dyn Fn(u64, u64) + Send + Sync>>,
            pub resident: core::sync::atomic::AtomicU64,
        }
        impl MemObject {
            pub fn anon(pages: u64) -> Arc<Self> {
                Arc::new(Self { pages, base: None, owned: false, on_drop: None, resident: core::sync::atomic::AtomicU64::new(0) })
            }
            pub fn frames(base: u64, pages: u64, owned: bool, on_drop: Option<Box<dyn Fn(u64, u64) + Send + Sync>>) -> Arc<Self> {
                Arc::new(Self { pages, base: Some(base), owned, on_drop, resident: core::sync::atomic::AtomicU64::new(pages) })
            }
            pub fn pages(&self) -> u64 {
                self.pages
            }
            pub fn phys_base(&self) -> Option<u64> {
                self.base
            }
            pub fn resident(&self) -> u64 {
                self.resident.load(core::sync::atomic::Ordering::Relaxed)
            }
        }
        impl MappedObject for MemObject {
            fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
                let b = self.base?;
                (pgoff < self.pages).then(|| PhysFrame::containing_address(PhysAddr::new(b + pgoff * 4096)))
            }
        }
        impl Drop for MemObject {
            fn drop(&mut self) {
                if let (Some(b), Some(f)) = (self.base, self.on_drop.as_ref()) {
                    f(b, self.pages * 4096);
                }
            }
        }
    }
}

pub mod fs {
    use alloc::string::String;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// *stub* A pipe end's counts.
    #[derive(Default)]
    pub struct Pipe {
        pub readers: i64,
        pub writers: i64,
    }
    impl Pipe {
        pub fn add_reader(&mut self) {
            self.readers += 1;
        }
        pub fn add_writer(&mut self) {
            self.writers += 1;
        }
        pub fn drop_reader(&mut self) {
            self.readers -= 1;
        }
        pub fn drop_writer(&mut self) {
            self.writers -= 1;
        }
    }

    /// *stub* A file's vnode (an open file: what `lx::fileh` reads and sets).
    #[derive(Default)]
    pub struct Vnode {
        pub path: String,
        pub ino: u64,
        pub offset: u64,
        pub flags: u32,
        pub mnt: usize,
        pub is_dir: bool,
        pub foreign: Option<(u64, u64, usize)>,
    }
    impl Vnode {
        /// *stub* `OpenFile::new` (the open reference is recorded).
        pub fn new(ino: u64, flags: u32, path: String) -> Arc<spin::Mutex<Self>> {
            crate::fake::rec(|r| r.open_refs.push(ino));
            Arc::new(spin::Mutex::new(Self { path, ino, flags, ..Self::default() }))
        }
    }
    /// *stub* `fs/fd.rs`: the open file type.
    pub mod fd {
        pub type OpenFile = super::Vnode;
    }
    /// *stub* The ZFS client's cache hooks (`lx::fileh`'s `LX_FH_CHANGED`): recorded.
    pub mod zfs {
        pub fn forget_names() {
            crate::fake::rec(|r| r.fs_forgot.push((u64::MAX, 1)));
        }
        pub fn forget_all_attrs() {
            crate::fake::rec(|r| r.fs_forgot.push((u64::MAX, 2)));
        }
        pub fn forget_attr_of(ino: u64) {
            crate::fake::rec(|r| r.fs_forgot.push((ino, 3)));
        }
    }

    /// *stub* The descriptor variants the code under test matches on.
    #[derive(Clone)]
    pub enum FileDescriptor {
        Device(Arc<dyn crate::compat::linux::chardev::CharDevice>),
        PipeRead(Arc<spin::Mutex<Pipe>>),
        PipeWrite(Arc<spin::Mutex<Pipe>>),
        Vnode(Arc<spin::Mutex<Vnode>>),
        File { path: String, readable: bool, writable: bool },
    }

    /// *mirror* of the kernel's server-object bits (`fs/fd.rs`).
    pub struct SrvBits {
        low: [AtomicU64; 16],
        high: AtomicBool,
    }
    impl SrvBits {
        pub fn maybe(&self, fd: u64) -> bool {
            if (fd as usize) < 1024 {
                self.low[fd as usize / 64].load(Ordering::Acquire) & (1 << (fd % 64)) != 0
            } else {
                self.high.load(Ordering::Acquire)
            }
        }
        fn set(&self, fd: usize) {
            if fd < 1024 {
                self.low[fd / 64].fetch_or(1 << (fd % 64), Ordering::AcqRel);
            } else {
                self.high.store(true, Ordering::Release);
            }
        }
    }
    /// *stub* (`None` until the table held a server object)
    pub struct SrvPtr {
        bits: SrvBits,
        used: AtomicBool,
    }
    impl SrvPtr {
        pub fn get(&self) -> Option<&SrvBits> {
            self.used.load(Ordering::Acquire).then_some(&self.bits)
        }
    }

    /// *stub* A descriptor table.
    pub struct FdTable {
        pub fds: alloc::vec::Vec<Option<FileDescriptor>>,
        pub cloexec: alloc::collections::BTreeSet<usize>,
        pub umask: u32,
        pub max: usize,
        srv: SrvPtr,
        /// The root and working directory (wave7 G7-1: `lx::vfs_ctx` reads them; G7-2: `lx::fileh`).
        pub root_ino: u64,
        pub root_mnt: usize,
        pub cwd_ino: u64,
        pub cwd_mnt: usize,
        pub cwd_path: String,
    }
    pub type SharedFdTable = Arc<spin::Mutex<FdTable>>;

    impl FdTable {
        pub fn new() -> Self {
            Self {
                fds: alloc::vec::Vec::new(),
                cloexec: Default::default(),
                umask: 0o022,
                max: 1024,
                srv: SrvPtr { bits: SrvBits { low: Default::default(), high: AtomicBool::new(false) }, used: AtomicBool::new(false) },
                root_ino: 0,
                root_mnt: 0,
                cwd_ino: 0,
                cwd_mnt: 0,
                cwd_path: String::from("/"),
            }
        }
        pub fn srv_bits(&self) -> &SrvPtr {
            &self.srv
        }
        fn mark(&self, fd: usize, d: &FileDescriptor) {
            if let FileDescriptor::Device(dev) = d {
                if dev.as_server().is_some() {
                    self.srv.bits.set(fd);
                    self.srv.used.store(true, Ordering::Release);
                }
            }
        }
        pub fn alloc_fd(&mut self, d: FileDescriptor) -> Result<usize, &'static str> {
            let fd = match self.fds.iter().position(|s| s.is_none()) {
                Some(i) => i,
                None if self.fds.len() < self.max => {
                    self.fds.push(None);
                    self.fds.len() - 1
                }
                None => return Err("EMFILE"),
            };
            self.mark(fd, &d);
            self.fds[fd] = Some(d);
            Ok(fd)
        }
        pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
            self.fds.get(fd)?.as_ref()
        }
        pub fn set_fd(&mut self, fd: usize, d: Option<FileDescriptor>) -> Option<FileDescriptor> {
            if fd >= self.fds.len() {
                self.fds.resize(fd + 1, None);
            }
            if let Some(d) = &d {
                self.mark(fd, d);
            }
            core::mem::replace(&mut self.fds[fd], d)
        }
        pub fn set_cloexec(&mut self, fd: usize, on: bool) {
            if on {
                self.cloexec.insert(fd);
            } else {
                self.cloexec.remove(&fd);
            }
        }
        pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
            match self.fds.get_mut(fd).and_then(|s| s.take()) {
                Some(_) => Ok(()),
                None => Err("EBADF"),
            }
        }
    }
}

pub mod compat {
    pub mod linux {
        use core::sync::atomic::Ordering;

        /// *stub* System call tracing switch.
        pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        /// *stub* The identity epoch (bumped by credential changes).
        pub fn ident_epoch() -> u64 {
            crate::fake::EPOCH.load(Ordering::Acquire)
        }

        pub mod chardev {
            use alloc::string::String;
            use crate::task::wait::WaitSet;

            /// *stub* The kernel's `CharDevice`, cut down to what the code under test calls
            /// or implements.
            pub trait CharDevice: Send + Sync {
                fn read(&self, buf: &mut [u8]) -> i64;
                fn write(&self, _data: &[u8]) -> i64 {
                    -22
                }
                fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
                    -25
                }
                fn poll_events(&self) -> u32;
                fn add_wait_queues(&self, waits: &mut WaitSet);
                fn rdev(&self) -> u64;
                fn path(&self) -> String;
                fn edges(&self) -> Option<u64> {
                    None
                }
                fn set_nonblock(&self, on: bool);
                fn nonblock(&self) -> bool;
                fn stat(&self) -> crate::compat::linux::types::LinuxStat {
                    crate::compat::linux::types::LinuxStat::default()
                }
                fn deliver_notification(&self, _data: &[u8]) -> bool {
                    false
                }
                fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
                    None
                }
                fn socket_call(&self, _num: u64, _a: [u64; 6]) -> Option<i64> {
                    None
                }
                // wave7 G7-4: positions (a pseudo file of linux-server)
                fn pread(&self, _buf: &mut [u8], _offset: u64) -> Option<i64> {
                    None
                }
                fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
                    None
                }
            }
        }

        pub mod types {
            /// *stub* The `stat` fields the code under test sets.
            #[derive(Default, Debug, Clone)]
            pub struct LinuxStat {
                pub st_mode: u32,
                pub st_uid: u32,
                pub st_gid: u32,
                pub st_nlink: u64,
                pub st_ino: u64,
                pub st_size: i64,
                pub st_blksize: i64,
                /// wave7 G7-4: a pseudo file's device.
                pub st_dev: u64,
                /// wave8 GT: a terminal's device number.
                pub st_rdev: u64,
            }
        }

        pub mod proc {
            use alloc::collections::BTreeMap;
            use alloc::vec::Vec;

            /// *stub* A thread's process (wave 7, Group 7-3's chroot peers): itself.
            pub fn tgid_of(tid: u64) -> Option<u64> {
                Some(tid)
            }

            /// *stub* A process's namespaces (as the forwarding core reads them).
            #[derive(Default, Clone)]
            pub struct Ns {
                pub mnt: u64,
                pub net: u64,
                pub pid: u64,
                pub user: Option<u64>,
                pub ipc: u64,
            }
            /// *stub* A process.
            #[derive(Default, Clone)]
            pub struct Process {
                pub ppid: u64,
                pub pgid: u64,
                pub sid: u64,
                pub groups: Vec<u32>,
                pub ns: Ns,
                pub exited: bool,
                /// Pending signals of the process (bit `s - 1`), for `pending_for`/`take`.
                pub pending: u64,
                /// wave7 G7-2: `lx::fileh`'s `pivot_root` walk.
                pub pid: u64,
                pub zombie: bool,
            }
            pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

            pub const SIGCHLD: u32 = 17;
            pub const ERESTARTSYS: i64 = -512;

            /// The current thread has a signal pending (`fake::set_signal`).
            pub fn signal_pending() -> bool {
                let tid = crate::task::CURRENT_TID.load(core::sync::atomic::Ordering::Acquire);
                crate::fake::SIGNALS.lock().unwrap().contains(&tid)
            }
            pub fn signal_pending_for(tid: u64, _pid: u64) -> bool {
                crate::fake::SIGNALS.lock().unwrap().contains(&tid)
            }
            pub fn delivery_maybe(tid: u64, _pid: u64) -> bool {
                crate::fake::SIGNALS.lock().unwrap().contains(&tid)
            }
            pub fn pending_for(pid: u64, mask: u64) -> bool {
                PROCS.lock().get(&pid).is_some_and(|p| p.pending & mask != 0)
            }
            pub fn post_with_info(pid: u64, sig: u32, code: i32, spid: u32, suid: u32, value: u64) -> bool {
                crate::fake::rec(|r| r.posted.push((pid, 0, sig, code, spid, suid, value)));
                process_exists(pid)
            }
            pub fn post_thread(pid: u64, tid: u64, sig: u32) -> bool {
                crate::fake::rec(|r| r.posted.push((pid, tid, sig, 0, 0, 0, 0)));
                process_exists(pid)
            }
            pub fn process_exists(pid: u64) -> bool {
                PROCS.lock().contains_key(&pid)
            }
            pub fn has_exited_locked(pid: u64) -> bool {
                PROCS.lock().get(&pid).is_some_and(|p| p.exited)
            }
            /// *mirror* of the kernel's taken signal.
            pub struct TakenSignal {
                pub signo: u32,
                pub code: i32,
                pub pid: u32,
                pub uid: u32,
                pub value: u64,
            }
            /// Takes the lowest pending process signal in `mask` (fake: code 0, pid 7, uid 8).
            pub fn take_signal_info_of(_tid: u64, pid: u64, mask: u64) -> Option<TakenSignal> {
                let mut procs = PROCS.lock();
                let p = procs.get_mut(&pid)?;
                if p.pending & mask == 0 {
                    return None;
                }
                let sig = (p.pending & mask).trailing_zeros() + 1;
                p.pending &= !(1 << (sig - 1));
                Some(TakenSignal { signo: sig, code: -1, pid: 7, uid: 8, value: 0x1122_3344_5566_7788 })
            }
            pub fn sigchld_details(_parent: u64) -> (i32, u64, i32) {
                (1, 4242, 9)
            }
        }

        pub mod vfs {
            const EFAULT: i64 = -14;
            /// *stub* vfs-server's chroot moves the caller's CLONE_FS peers (wave 7, Group
            /// 7-3): no peers on the host.
            pub fn chroot_peers(_pid: u64, _root: u64, _root_mnt: usize) {}
            /// Host memory is user memory; null and bad pages fault.
            pub fn copy_in(ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, i64> {
                if ptr < 0x10000 || !crate::fake::prefault(ptr, len as u64) {
                    return Err(EFAULT);
                }
                let mut v = alloc::vec![0u8; len];
                // SAFETY: tests pass host buffers
                unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
                Ok(v)
            }
            pub fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
                if ptr < 0x10000 || !crate::fake::prefault(ptr, data.len() as u64) {
                    return Err(EFAULT);
                }
                // SAFETY: tests pass host buffers
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
                Ok(())
            }
        }

        pub mod ns {
            pub fn net_isolated() -> bool {
                crate::fake::NET_ISOLATED.load(core::sync::atomic::Ordering::Acquire)
            }
            pub fn ipc_ns() -> u64 {
                crate::fake::IPC_NS.load(core::sync::atomic::Ordering::Acquire)
            }
            /// wave7 G7-6: as the kernel's (the fake process table's live namespaces).
            pub fn live_mntns() -> alloc::vec::Vec<u64> {
                let set: alloc::collections::BTreeSet<u64> = super::proc::PROCS.lock().values().filter(|p| !p.zombie).map(|p| p.ns.mnt).collect();
                set.into_iter().collect()
            }
        }

        pub mod userfaultfd {
            pub enum Waited {
                Again,
                Proceed,
                Refuse,
            }
            pub fn active() -> bool {
                crate::fake::UFFD.load(core::sync::atomic::Ordering::Acquire)
            }
            /// Fake: uffd id 1 says "again", 2 "proceed", anything else "refuse".
            pub fn wait_fault(id: u64, _page: u64, _write: bool, _kernel: bool) -> Waited {
                match id {
                    1 => Waited::Again,
                    2 => Waited::Proceed,
                    _ => Waited::Refuse,
                }
            }
        }

        pub mod ptrace {
            pub fn is_traced(tid: u64) -> bool {
                crate::fake::TRACED.lock().unwrap().contains(&tid)
            }
        }

        pub mod bpf {
            pub fn set_server_device_programs(raw: &[u8]) -> i64 {
                crate::fake::rec(|r| {
                    r.bpf_programs.push(raw.to_vec());
                    raw.len() as i64
                })
            }
        }

        /// *stub* The switches `lx::fileh` reads (`fake::FS_FLAGS` bits: landlock 1,
        /// fanotify 2, inotify 4, abac 8, FUSE mounts 16).
        pub mod fanotify {
            pub fn active() -> bool {
                crate::fake::FS_FLAGS.load(core::sync::atomic::Ordering::Acquire) & 2 != 0
            }
        }
        pub mod inotify {
            pub fn active() -> bool {
                crate::fake::FS_FLAGS.load(core::sync::atomic::Ordering::Acquire) & 4 != 0
            }
        }
        pub mod abac {
            pub fn active() -> bool {
                crate::fake::FS_FLAGS.load(core::sync::atomic::Ordering::Acquire) & 8 != 0
            }
        }
        /// *stub* wave7 G7-7: the mount tables' generations and the file service's view
        /// (`fake::MNT_TABLES`: `(ns, generation, root mount, mounts)`; the initial namespace
        /// has generation 0 unless listed).
        pub mod mount {
            pub const VFS_HOLE: u32 = 0;
            pub const VFS_TREE: u32 = 1;
            pub const VFS_TMPFS: u32 = 2;
            pub const VFS_KERNEL: u32 = 3;
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
            pub struct VfsMount {
                pub kind: u32,
                pub flags: u32,
                pub parent: u32,
                pub mountpoint: u64,
                pub root: u64,
            }
            pub fn vfs_gen(ns: u64) -> Option<u64> {
                let t = crate::fake::MNT_TABLES.lock();
                match t.iter().find(|e| e.0 == ns) {
                    Some(e) => Some(e.1),
                    None if ns == 0 => Some(0),
                    None => None,
                }
            }
            pub fn vfs_table(ns: u64) -> Result<(u64, u32, alloc::vec::Vec<VfsMount>), i64> {
                crate::fake::MNT_TABLES.lock().iter().find(|e| e.0 == ns).map(|e| (e.1, e.2, e.3.clone())).ok_or(-3)
            }
        }
        pub mod fuse {
            pub fn ns0_any() -> bool {
                crate::fake::FS_FLAGS.load(core::sync::atomic::Ordering::Acquire) & 16 != 0
            }
        }
        pub mod landlock {
            pub fn active() -> bool {
                crate::fake::FS_FLAGS.load(core::sync::atomic::Ordering::Acquire) & 1 != 0
            }
            pub fn check_port_of(_tid: u64, _port: u16, _want: u64) -> Result<(), i64> {
                crate::fake::rec(|r| match r.landlock { Some(e) => Err(e), None => Ok(()) })
            }
        }

        pub mod fs {
            pub fn proc_pid_file_text(rest: &str) -> Option<alloc::vec::Vec<u8>> {
                crate::fake::rec(|r| r.proc_files.get(rest).cloned())
            }
        }

        pub mod unix {
            pub fn server_call(_dev: &alloc::sync::Arc<dyn super::chardev::CharDevice>, num: u64, a: [u64; 6]) -> i64 {
                crate::fake::rec(|r| {
                    r.unix_calls.push((num, a));
                    r.unix_answer
                })
            }
        }

        pub mod mm {
            /// *stub* wave7 G7-5: page-cache reads (nothing cached).
            pub fn cached_read(_ino: u64, _off: u64, _buf: &mut [u8]) -> Result<usize, i64> {
                Err(-5)
            }
            pub fn cache_forget(ino: u64) {
                crate::fake::rec(|r| r.fs_truncated.push((ino, u64::MAX)));
            }
            pub fn cache_truncated(ino: u64, size: u64) {
                crate::fake::rec(|r| r.fs_truncated.push((ino, size)));
            }
            pub fn sys_munmap(_mm: &spin::Mutex<crate::memory::vm::Mm>, addr: u64, len: u64) -> i64 {
                crate::fake::rec(|r| r.munmaps.push((addr, len)));
                0
            }
        }

        pub mod prof {
            pub const DISK_READ: usize = 0;
            pub const DISK_READV: usize = 1;
            pub const DISK_OTHER: usize = 2;
            pub fn start() -> u64 {
                0
            }
            pub fn disk_call(kind: usize, blocks: u64, _t0: u64) {
                crate::fake::rec(|r| r.disk_calls.push((kind, blocks)));
            }
        }
    }
}

pub mod task {
    use core::sync::atomic::{AtomicU64, Ordering};

    pub use crate::world::{Scheduler, Task};

    /// The running thread (`percpu` in the kernel; one CPU here).
    pub static CURRENT_TID: AtomicU64 = AtomicU64::new(0);
    pub static SCHEDULER: Scheduler = Scheduler;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct TaskId(pub u64);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskState {
        Running,
        Ready,
        Blocked,
        Sleeping { wake_tick: u64 },
        Dead,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum TaskPriority {
        Idle,
        Normal,
        High,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPersonality {
        Hydra,
        Linux,
        FreeBsd,
        MacOs,
    }

    pub fn is_active() -> bool {
        crate::world::active()
    }
    pub fn current_service() -> Option<u32> {
        with_current_task_mut(|t| t.service).flatten()
    }
    pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        SCHEDULER.lock().current_task_mut(f)
    }
    pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut crate::fs::FdTable) -> R) -> R {
        let fds = SCHEDULER.lock().current_fds().expect("a current task");
        let mut t = fds.lock();
        f(&mut t)
    }
    pub fn yield_now() {
        if !is_active() {
            return;
        }
        crate::world::yield_cpu();
    }
    pub fn block_current() -> TaskId {
        if !is_active() {
            return TaskId(0);
        }
        // A timer tick right here (tests ask for it): the others run first
        if crate::world::PREEMPT_BEFORE_BLOCK.load(Ordering::Acquire) > 0 {
            crate::world::PREEMPT_BEFORE_BLOCK.fetch_sub(1, Ordering::AcqRel);
            yield_now();
        }
        let id = SCHEDULER.lock().block_current();
        yield_now();
        id
    }
    pub fn unblock_task(id: TaskId) -> bool {
        SCHEDULER.lock().unblock_task(id)
    }
    pub fn is_task_alive(id: TaskId) -> bool {
        SCHEDULER.lock().is_task_alive(id)
    }
    pub fn preemptible<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
    /// Kernel tasks are recorded, not run.
    pub fn spawn(name: &'static str, _entry: fn(), _priority: TaskPriority) -> TaskId {
        crate::world::note_spawn(name);
        TaskId(0)
    }
    pub fn spawn_service(_name: &'static str, _image: &[u8], _args: &[&str], _endpoint: u32) -> Result<TaskId, &'static str> {
        Err("no services on the host")
    }
    /// The clock moves instead.
    pub fn sleep_ms(ms: u64) {
        crate::world::NOW_NS.fetch_add(ms * 1_000_000, Ordering::AcqRel);
    }
    pub fn exit() -> ! {
        panic!("task::exit")
    }
    pub fn close_retired() {}
    /// (wave7 GB) A thread tests mark as retired (ended by the supervisor, still running).
    pub static RETIRED_TID: AtomicU64 = AtomicU64::new(0);
    pub fn current_retired() -> bool {
        let r = RETIRED_TID.load(Ordering::Acquire);
        r != 0 && SCHEDULER.lock().current_task_id().0 == r
    }

    pub mod scheduler {
        use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        pub static CURRENT_IDX: AtomicU64 = AtomicU64::new(0);
        pub static HANDOFF_ACTIVE: AtomicBool = AtomicBool::new(false);
        pub static BLOCK_NOBKL: AtomicU64 = AtomicU64::new(0);
        pub static DIRECT_TO: AtomicU64 = AtomicU64::new(0);
        pub static DIRECT_HINT: AtomicU64 = AtomicU64::new(0);
        pub static DIRECT_GUARD: AtomicU64 = AtomicU64::new(0);
        pub const DIRECT_EVENT: usize = 1 << 62;
        pub fn handoff_active() -> bool {
            HANDOFF_ACTIVE.load(Ordering::Acquire)
        }
        /// One CPU: nothing to wait out.
        pub fn wait_out_handoff() {}
        pub fn call_ended() {}
    }

    pub mod supervisor {
        /// The test's answer for `endpoint` (`fake::Rec::revive`), recorded.
        /// A successful revival waits for the new server to register (as
        /// `await_registration`): the other tasks run meanwhile.
        pub fn revive(endpoint: u32) -> bool {
            let ok = crate::fake::rec(|r| {
                r.revived.push(endpoint);
                r.revive.get(&endpoint).copied().unwrap_or(false)
            });
            if ok {
                for _ in 0..5 {
                    crate::task::yield_now();
                }
            }
            ok
        }
    }

    pub mod wait {
        use alloc::sync::Arc;
        use alloc::vec::Vec;

        /// *mirror* of `task/wait.rs`'s queue: registered tasks are woken (deferred) by
        /// `wake_all`.
        pub struct WaitQueue {
            waiters: spin::Mutex<Vec<u64>>,
            wakes: core::sync::atomic::AtomicU64,
        }
        impl WaitQueue {
            pub const fn new() -> Self {
                Self { waiters: spin::Mutex::new(Vec::new()), wakes: core::sync::atomic::AtomicU64::new(0) }
            }
            pub fn new_shared() -> Arc<Self> {
                Arc::new(Self::new())
            }
            pub fn wakes(&self) -> u64 {
                self.wakes.load(core::sync::atomic::Ordering::Acquire)
            }
            pub fn register(&self) {
                let id = super::SCHEDULER.lock().current_task_id().0;
                self.register_id(id);
            }
            fn register_id(&self, id: u64) {
                let mut w = self.waiters.lock();
                if !w.contains(&id) {
                    w.push(id);
                }
            }
            pub fn unregister(&self) {
                let id = super::SCHEDULER.lock().current_task_id().0;
                self.waiters.lock().retain(|&w| w != id);
            }
            pub fn wake_all(&self) {
                self.wakes.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                let ids: Vec<u64> = core::mem::take(&mut *self.waiters.lock());
                if !ids.is_empty() {
                    crate::world::defer_wakes(ids);
                }
            }
            /// Tasks registered now (tests).
            pub fn waiters(&self) -> Vec<u64> {
                self.waiters.lock().clone()
            }
        }

        #[derive(Clone)]
        pub enum QueueRef {
            Static(&'static WaitQueue),
            Shared(Arc<WaitQueue>),
        }
        impl core::ops::Deref for QueueRef {
            type Target = WaitQueue;
            fn deref(&self) -> &WaitQueue {
                match self {
                    QueueRef::Static(q) => q,
                    QueueRef::Shared(q) => q,
                }
            }
        }

        /// *mirror* of `task/wait.rs`'s set (no deadlines objects).
        pub struct WaitSet {
            pub queues: Vec<QueueRef>,
            pub polled: bool,
        }
        impl WaitSet {
            pub fn new() -> Self {
                Self { queues: Vec::new(), polled: false }
            }
            pub fn add(&mut self, q: QueueRef) {
                self.queues.push(q);
            }
            pub fn register(&self) {
                if self.queues.is_empty() {
                    return;
                }
                let id = super::SCHEDULER.lock().current_task_id().0;
                for q in &self.queues {
                    q.register_id(id);
                }
            }
            pub fn wait(&self, deadline: Option<u64>) {
                wait(deadline);
            }
        }
        impl Drop for WaitSet {
            fn drop(&mut self) {
                if crate::world::active() {
                    for q in &self.queues {
                        q.unregister();
                    }
                }
            }
        }

        /// *mirror* of `task/wait.rs`'s `wait`.
        pub fn wait(deadline: Option<u64>) {
            if !super::is_active() {
                crate::world::NOW_NS.fetch_add(crate::world::TICK_NS, core::sync::atomic::Ordering::AcqRel);
                return;
            }
            if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
                return;
            }
            let sleeping = super::SCHEDULER.lock().event_wait_current(deadline);
            if sleeping {
                super::yield_now();
            }
        }
    }
}
