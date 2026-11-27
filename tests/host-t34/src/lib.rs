//! Group 34's host build of kernel files: the admin interface (`src/admin`), the
//! framebuffer console and splash (`src/video`), the network glue (`src/net`), the console
//! (`src/console.rs`), the emergency prompt (`src/shell`) and the boot glue (`src/main.rs`).
//!
//! As in `tests/host`, each kernel file is compiled from its own source through `#[path]`,
//! under the module path the kernel uses, so `crate::` references resolve unchanged.
//! Everything those files call outside this group is a stub below (marked *stub*), backed
//! by the thread-local fake machine in [`fake`]; UEFI's text console is a fake system
//! table ([`uefi_fake`]); privileged instructions are replaced by the `x86_64` shim.

#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

extern crate alloc;

pub mod fake;
pub mod uefi_fake;

// ----------------------------------------------------------------------------------------
// Group 34's kernel files (real)
// ----------------------------------------------------------------------------------------

/// The console (defines `print!`, `println!`, `kprintln!`).
#[macro_use]
#[path = "../../../src/console.rs"]
pub mod console;

#[path = "../../../src/admin/mod.rs"]
pub mod admin;

#[path = "../../../src/video/mod.rs"]
pub mod video;

#[path = "../../../src/net/mod.rs"]
pub mod net;

#[path = "../../../src/shell/mod.rs"]
pub mod shell;

/// The kernel's root file (`src/main.rs`): its boot reports (the boot sequence itself is
/// UEFI only).
#[allow(unused_attributes, unused_must_use)]
#[path = "../../../src/main.rs"]
pub mod kmain;

// ----------------------------------------------------------------------------------------
// Other groups' files compiled as they are (pure code)
// ----------------------------------------------------------------------------------------

#[path = "../../../src/compress/mod.rs"]
pub mod compress;

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    pub use message::Message;
    pub use protocol::*;

    /// *stub* The system endpoints (for the admin's endpoint list) and the boot's IPC test.
    pub mod endpoint {
        /// *stub* One system endpoint's counters.
        pub struct FakeEndpoint {
            pub id: usize,
        }
        impl FakeEndpoint {
            pub fn pending_count(&self) -> usize {
                self.id * 10 + 1
            }
            pub fn waiting_receivers(&self) -> usize {
                self.id * 10 + 2
            }
            pub fn waiting_senders(&self) -> usize {
                self.id * 10 + 3
            }
        }
        /// *stub* Endpoints 1, 3 and 5 exist.
        pub fn get_system_endpoint(i: usize) -> Option<FakeEndpoint> {
            [1, 3, 5].contains(&i).then_some(FakeEndpoint { id: i })
        }
    }
    pub use endpoint::get_system_endpoint;

    /// *stub* The boot's IPC test endpoint (a queue of messages).
    pub struct Endpoint {
        id: u64,
        queue: alloc::collections::VecDeque<Message>,
    }
    impl Endpoint {
        pub fn new(id: u64) -> Self {
            Endpoint { id, queue: Default::default() }
        }
        pub fn id(&self) -> u64 {
            self.id
        }
        pub fn send(&mut self, m: Message) -> Result<(), &'static str> {
            self.queue.push_back(m);
            Ok(())
        }
        pub fn receive(&mut self) -> Option<Message> {
            self.queue.pop_front()
        }
    }

    /// *stub* Service calls go to the test's handler; windows are host memory.
    pub mod service {
        use super::Message;
        use crate::fake;
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicU64;

        pub const CALL_TIMEOUT_TICKS: u64 = 500;
        pub const SIGNAL_GONE: u64 = u64::MAX;
        pub static GRANTS_MADE: AtomicU64 = AtomicU64::new(0);

        /// *mirror* How a call waits.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum CallMode {
            Handoff,
            Queued,
        }

        fn dispatch(endpoint: u32, m: Message, kind: &str) -> Result<Message, i64> {
            fake::with(|s| s.calls.push((endpoint, m.label, m.args, kind.to_string())));
            let h = fake::with(|s| s.handler.take());
            let Some(mut h) = h else { return Err(-11) };
            let r = h(endpoint, &m, kind);
            fake::with(|s| {
                if s.handler.is_none() {
                    s.handler = Some(h);
                }
            });
            r
        }
        pub fn call(endpoint: u32, m: Message, _timeout: u64) -> Result<Message, i64> {
            dispatch(endpoint, m, "call")
        }
        pub fn call_once(endpoint: u32, m: Message, _timeout: u64) -> Result<Message, i64> {
            dispatch(endpoint, m, "once")
        }
        pub fn call_queued(endpoint: u32, m: Message, _timeout: u64) -> Result<Message, i64> {
            dispatch(endpoint, m, "queued")
        }
        pub fn is_online(endpoint: u32) -> bool {
            fake::with(|s| s.online.contains(&endpoint))
        }
        pub fn server_of(endpoint: u32) -> u64 {
            fake::with(|s| s.servers.get(&endpoint).copied().unwrap_or(0))
        }
        /// Size of a fake window.
        pub const WINDOW_SIZE: usize = 4 << 20;
        /// The endpoint's window: present once the test gave the endpoint a server.
        pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
            fake::with(|s| {
                if !s.servers.contains_key(&endpoint) {
                    return None;
                }
                let p = *s.windows.entry(endpoint).or_insert_with(|| Box::leak(vec![0u8; WINDOW_SIZE].into_boxed_slice()).as_mut_ptr() as usize);
                Some(unsafe { core::slice::from_raw_parts_mut(p as *mut u8, WINDOW_SIZE) })
            })
        }
        /// *stub* The window lock.
        pub struct WindowGuard(u32);
        impl Drop for WindowGuard {
            fn drop(&mut self) {
                fake::log(format!("release_window {}", self.0));
            }
        }
        pub fn hold_window(endpoint: u32) -> WindowGuard {
            fake::log(format!("hold_window {}", endpoint));
            WindowGuard(endpoint)
        }
        pub fn notify(endpoint: u32, bits: u64) {
            fake::log(format!("notify {} {}", endpoint, bits));
        }
        pub fn request_list() -> Vec<(u64, u32, u64, &'static str, CallMode)> {
            fake::with(|s| s.requests.clone())
        }
        pub fn irq_stats() -> Vec<(u8, u64, u64, u64, u32, bool)> {
            fake::with(|s| s.irqs.clone())
        }
        /// *stub* Contiguous memory (host memory).
        pub struct ContiguousFrames {
            pub base: u64,
            mem: Box<[u8]>,
        }
        impl ContiguousFrames {
            pub fn allocate(pages: u64) -> Option<Arc<Self>> {
                if fake::with(|s| s.no_frames) {
                    return None;
                }
                let mut mem = vec![0u8; (pages * 4096) as usize].into_boxed_slice();
                Some(Arc::new(ContiguousFrames { base: mem.as_mut_ptr() as u64, mem }))
            }
            pub unsafe fn bytes(&self) -> &'static mut [u8] {
                core::slice::from_raw_parts_mut(self.base as *mut u8, self.mem.len())
            }
        }
    }
}

// ----------------------------------------------------------------------------------------
// Stubs
// ----------------------------------------------------------------------------------------

pub mod arch {
    use crate::fake;

    /// *stub* The boot sequence's steps: each logs its name.
    macro_rules! steps {
        ($($m:ident :: $f:ident),* $(,)?) => {
            $(pub mod $m {
                pub fn $f() {
                    crate::fake::log(concat!(stringify!($m), "::", stringify!($f)));
                }
            })*
        };
    }
    steps!(gdt::init, idt::init, rtc::init, mouse::init, bootdisk::detect);
    /// *stub* wave11 GG: no write-combining view on the host (the console keeps its mapping).
    pub mod pat {
        pub fn alias_wc(_phys: u64, _len: u64) -> Option<u64> {
            crate::fake::log("pat::alias_wc");
            None
        }
        pub fn identity_wc_pages() -> u64 {
            0
        }
    }
    /// *stub*
    pub mod relocate {
        /// *stub* The image is already in the higher half: returns (the caller boots).
        pub fn go_high(_f: fn() -> !) {
            crate::fake::log("relocate::go_high");
        }
        pub fn image_phys() -> Option<u64> {
            crate::fake::with(|s| s.image_phys)
        }
        /// *stub* wave11 GH: the image's load range (none on the host: the move is tried).
        pub fn load_range() -> Option<(u64, u64)> {
            None
        }
        pub fn in_kept_low_slot(_start: u64, _size: u64) -> bool {
            false
        }
        /// *stub* wave11 GH: the rest of the boot, on the same (test) stack.
        pub fn run_on_kernel_stack(next: fn() -> !) -> ! {
            next()
        }
    }
    /// *stub*
    pub mod boottime {
        pub fn mark(what: &str) {
            crate::fake::log(format!("mark {}", what));
        }
        pub fn report() {
            crate::fake::log("boottime::report");
        }
    }
    /// *stub*
    pub mod percpu {
        pub fn init_this_cpu(cpu: usize) {
            crate::fake::log(format!("percpu::init_this_cpu {}", cpu));
        }
    }
    /// *stub*
    pub mod boot_services {
        /// *stub* wave11 GH: a takeover step's screen line.
        pub fn mark(_n: u32, _what: &str) {}
        /// *stub* wave11 GH: the first half of the takeover.
        pub fn leave_firmware() -> Result<(), &'static str> {
            Ok(())
        }
        pub fn take_hardware_ownership() -> Result<(), &'static str> {
            crate::fake::log("take_hardware_ownership");
            crate::fake::with(|s| s.takeover_fail).map_or(Ok(()), Err)
        }
    }
    /// *stub* COM1 without locks: the test's serial capture.
    pub mod raw_serial {
        pub struct RawSerial;
        impl core::fmt::Write for RawSerial {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                crate::fake::with(|st| st.serial.push_str(s));
                Ok(())
            }
        }
    }

    // wave11 GH begin
    /// *stub* The boot log: nothing is kept.
    pub mod bootlog {
        pub fn early() {}
        pub fn prepare_file() {}
        pub fn start_writer() {}
        pub fn check_pool() {}
        pub fn after_panic() {}
        pub fn append(_text: &[u8]) {}
        pub fn at_power(_what: &'static str) {}
        pub fn file_on() -> bool {
            false
        }
    }
    /// The boot words' real logic.
    #[path = "../../../../src/arch/bootwords.rs"]
    pub mod bootwords;
    /// *stub* The boot words: none (the tests give theirs to `discover_with`).
    pub mod bootopts {
        pub fn init() {}
        /// *stub* wave11 GH: no early words.
        pub fn early_word(_w: &[u8]) -> bool {
            false
        }
        pub fn words() -> &'static super::bootwords::Words {
            static NONE: super::bootwords::Words = super::bootwords::Words::new();
            &NONE
        }
        pub fn say(words: &[&[u8]]) -> bool {
            words.iter().any(|w| self::words().has(w))
        }
        pub fn ucs2() -> Vec<u8> {
            words().ucs2()
        }
    }
    /// *stub* Boot breadcrumbs: none.
    pub mod crumb {
        pub fn step(_name: &str) {}
        pub fn step_fmt(_args: core::fmt::Arguments) {}
        pub fn quiet_fmt(_args: core::fmt::Arguments) {}
        pub fn read_fmt(_args: core::fmt::Arguments) {}
        pub fn force_line(_args: core::fmt::Arguments) {}
        pub fn screen_only_from_now() {}
        pub fn machine_state() {}
        pub fn end(_name: &str) {}
        pub fn high_arrived() {}
        pub fn want_high() -> bool {
            true
        }
        pub fn pick_gop() -> Option<uefi::Handle> {
            None
        }
    }
    // wave11 GH end
    /// *stub* The fake clock.
    pub mod pit {
        use crate::fake;
        pub fn ticks() -> u64 {
            fake::ticks()
        }
        pub fn uptime_ms() -> u64 {
            fake::with(|s| s.clock_ns / 1_000_000)
        }
        pub fn sleep_ms(ms: u64) {
            fake::advance(ms.max(1) * 1_000_000);
        }
        pub fn is_active() -> bool {
            true
        }
    }
    /// *stub* QEMU fw_cfg files.
    pub mod fwcfg {
        use crate::fake;
        pub fn read_file(name: &str) -> Option<Vec<u8>> {
            fake::with(|s| s.fwcfg.get(name).cloned())
        }
        pub fn read_file_into(name: &str, buf: &mut [u8]) -> Option<usize> {
            let v = read_file(name)?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Some(n)
        }
    }
    /// *stub* The PS/2 keyboard.
    pub mod keyboard {
        pub fn read_key() -> Option<uefi::proto::console::text::Key> {
            crate::fake::with(|s| s.keys.pop_front())
        }
    }
    /// *stub* Power: ends the test with a panic it can catch.
    pub mod power {
        pub fn power_off() -> ! {
            crate::fake::log("power_off");
            panic!("power_off")
        }
        pub fn reboot() -> ! {
            crate::fake::log("reboot");
            panic!("reboot")
        }
    }
    /// *stub*
    pub mod smp {
        use core::sync::atomic::{AtomicBool, AtomicU64};
        pub static DEFER_KICKS: AtomicBool = AtomicBool::new(false);
        pub static IDLE_POLL_NS: AtomicU64 = AtomicU64::new(0);
        pub fn bkl_enter() {
            crate::fake::log("smp::bkl_enter");
        }
    }
    /// *stub* MSRs and the native call counters.
    pub mod syscall {
        use crate::fake;
        pub const IA32_EFER: u32 = 0xC000_0080;
        pub const IA32_STAR: u32 = 0xC000_0081;
        pub const IA32_LSTAR: u32 = 0xC000_0082;
        pub const IA32_FMASK: u32 = 0xC000_0084;
        pub unsafe fn rdmsr(msr: u32) -> u64 {
            fake::with(|s| s.msrs.get(&msr).copied().unwrap_or(0))
        }
        pub unsafe fn wrmsr(msr: u32, v: u64) {
            fake::with(|s| {
                if !s.msr_stuck {
                    s.msrs.insert(msr, v);
                }
            });
        }
        /// *mirror*
        #[derive(Default)]
        pub struct SyscallStats {
            pub total_calls: u64,
            pub yield_calls: u64,
            pub sleep_calls: u64,
            pub write_calls: u64,
            pub exit_calls: u64,
            pub getpid_calls: u64,
            pub uptime_calls: u64,
            pub ipc_calls: u64,
        }
        pub static SYSCALL_STATS: spin::Mutex<SyscallStats> = spin::Mutex::new(SyscallStats {
            total_calls: 0,
            yield_calls: 0,
            sleep_calls: 0,
            write_calls: 0,
            exit_calls: 0,
            getpid_calls: 0,
            uptime_calls: 0,
            ipc_calls: 0,
        });
        /// *stub* The boot prints its address.
        pub extern "C" fn hydra_syscall_dispatcher() {}
    }
    /// *stub* Control registers.
    pub mod cpu {
        /// *stub* wave11 GG/GH: execute-disable on the boot processor.
        pub static BSP_FIRMWARE_EFER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        pub fn enable_nx() -> bool {
            true
        }
        use x86_64::registers::control::{Cr0Flags, Cr4Flags};
        pub struct CpuState {
            pub cr0: Cr0Flags,
            pub cr2: u64,
            pub cr3_frame: x86_64::PhysAddr,
            pub cr4: Cr4Flags,
        }
        pub fn read_state() -> CpuState {
            CpuState { cr0: Cr0Flags::PAGING | Cr0Flags::PROTECTED_MODE_ENABLE, cr2: 0xdead_b000, cr3_frame: x86_64::PhysAddr::new(0x1234_5000), cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION }
        }
    }
    /// *stub* The IOMMU.
    pub mod iommu {
        use crate::fake;
        #[derive(Clone, Copy, Debug)]
        pub struct Fault {
            pub source: u16,
            pub read: bool,
            pub address: u64,
            pub reason: u8,
        }
        #[derive(Clone, Copy, Debug)]
        pub struct FaultRecord {
            pub tick: u64,
            pub fault: Fault,
        }
        pub fn status() -> Vec<String> {
            vec!["IOMMU: 1 unit".to_string(), "translation on".to_string()]
        }
        pub fn poll_faults() {
            fake::with(|s| {
                let n = std::mem::take(&mut s.iommu_new_faults);
                s.iommu_faults.extend(n);
            });
        }
        pub fn recent_faults() -> Vec<FaultRecord> {
            fake::with(|s| s.iommu_faults.clone())
        }
        pub fn active() -> bool {
            fake::with(|s| s.iommu_on)
        }
        pub fn device_of(_endpoint: u32) -> Option<u16> {
            fake::with(|s| s.iommu_dev)
        }
        pub fn dma_test_enabled() -> bool {
            fake::with(|s| s.iommu_test)
        }
    }
    /// *stub*
    pub mod dmar {
        pub fn bdf_parts(source: u16) -> (u8, u8, u8) {
            ((source >> 8) as u8, ((source >> 3) & 0x1f) as u8, (source & 7) as u8)
        }
        pub fn reason_text(reason: u8) -> &'static str {
            if reason == 6 {
                "not present"
            } else {
                "other"
            }
        }
    }
    /// *stub* The PCI bus: devices from `fake::State::pci` (vendor, device, BAR0).
    pub mod pci {
        use crate::fake;
        #[derive(Debug, Clone, Copy)]
        pub struct PciDevice {
            pub vendor: u16,
            pub device: u16,
            pub bar0: u64,
        }
        pub fn find_device(vendor: u16, device: u16) -> Option<PciDevice> {
            fake::with(|s| s.pci.iter().find(|p| p.0 == vendor && p.1 == device).map(|p| PciDevice { vendor: p.0, device: p.1, bar0: p.2 }))
        }
        pub fn enable_bus_mastering(dev: &PciDevice) {
            fake::log(format!("bus_master {:04x}", dev.device));
        }
        pub fn bar_address(dev: &PciDevice, _bar: u8) -> u64 {
            dev.bar0
        }
    }
}

pub mod task {
    use crate::fake;
    use alloc::sync::Arc;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TaskId(pub u64);

    /// *mirror*
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPersonality {
        Hydra,
        Linux,
        FreeBsd,
        MacOs,
    }
    /// *mirror*
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPriority {
        Idle,
        Low,
        Normal,
        High,
        Realtime,
    }
    /// *mirror*
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivilegeMode {
        Kernel,
        User,
    }
    /// *mirror*
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskState {
        Ready,
        Running,
        Blocked,
        Sleeping { until: u64 },
        Dead,
    }
    /// *mirror*
    #[derive(Debug, Clone)]
    pub struct TaskSnapshot {
        pub id: TaskId,
        pub uid: u32,
        pub mode: PrivilegeMode,
        pub state: TaskState,
        pub priority: TaskPriority,
        pub ticks_run: u64,
        pub rsp: u64,
        pub name: &'static str,
    }

    /// *stub* The parts of a task the admin code touches.
    pub struct Task {
        pub personality: TaskPersonality,
        pub uid: u32,
        pub gid: u32,
        pub euid: u32,
        pub egid: u32,
        pub suid: u32,
        pub sgid: u32,
        pub fds: Arc<spin::Mutex<crate::fs::FdTable>>,
    }

    thread_local! {
        static TASKS: core::cell::RefCell<std::collections::BTreeMap<u64, Task>> = Default::default();
        static FDS: core::cell::RefCell<crate::fs::FdTable> = core::cell::RefCell::new(crate::fs::FdTable::with_capture());
    }

    /// The stub task `id` (made on first use), for tests.
    pub fn with_task<R>(id: u64, f: impl FnOnce(&mut Task) -> R) -> R {
        let mut t = TASKS.with(|m| m.borrow_mut().remove(&id)).unwrap_or_else(|| Task {
            personality: TaskPersonality::Linux,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            fds: Arc::new(spin::Mutex::new(crate::fs::FdTable::default())),
        });
        let r = f(&mut t);
        TASKS.with(|m| m.borrow_mut().insert(id, t));
        r
    }
    /// Forgets the stub tasks of this thread.
    pub fn clear_tasks() {
        TASKS.with(|m| m.borrow_mut().clear());
        FDS.with(|f| *f.borrow_mut() = crate::fs::FdTable::with_capture());
    }

    /// *stub*
    pub struct Scheduler;
    impl Scheduler {
        pub fn current_task_id(&self) -> TaskId {
            TaskId(fake::with(|s| s.current_tid))
        }
        pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
            Some(with_task(id.0, f))
        }
        pub fn spawn_linux_process(
            &mut self,
            name: &'static str,
            _loaded: scheduler::LoadedImage,
            path: &str,
            args: &[&str],
            _prio: TaskPriority,
            uid: u32,
            gid: u32,
            _x: Option<u64>,
        ) -> Result<TaskId, &'static str> {
            spawn_common(&format!("spawn_native {} {} {:?} {} {}", name, path, args, uid, gid))
        }
        pub fn task_named(&self, name: &str) -> Option<TaskId> {
            fake::with(|s| s.named.get(name).map(|&i| TaskId(i)))
        }
    }
    pub static SCHEDULER: spin::Mutex<Scheduler> = spin::Mutex::new(Scheduler);

    fn spawn_common(what: &str) -> Result<TaskId, &'static str> {
        fake::log(what.to_string());
        if let Some(e) = fake::with(|s| s.spawn_fail) {
            return Err(e);
        }
        let id = fake::with(|s| {
            let id = s.next_tid;
            s.next_tid += 1;
            s.tasks.entry(id).or_insert(fake::FakeTask { alive_checks: 1, status: Some(0) });
            id
        });
        Ok(TaskId(id))
    }

    pub fn init(cr3: u64) {
        fake::log(format!("task::init {:#x}", cr3));
    }
    pub fn supervisor_init() {
        fake::log("task::supervisor_init");
    }
    pub fn current_personality() -> TaskPersonality {
        fake::with(|s| s.personality.unwrap_or(TaskPersonality::Hydra))
    }
    pub fn is_active() -> bool {
        !fake::with(|s| s.scheduler_inactive)
    }
    pub fn get_task_snapshots() -> Vec<TaskSnapshot> {
        fake::with(|s| s.snapshots.clone())
    }
    pub fn kill(id: TaskId) -> bool {
        fake::log(format!("kill {}", id.0));
        fake::with(|s| s.tasks.remove(&id.0).is_some())
    }
    pub fn is_task_alive(id: TaskId) -> bool {
        fake::with(|s| match s.tasks.get_mut(&id.0) {
            Some(t) if t.alive_checks > 0 => {
                t.alive_checks -= 1;
                true
            }
            _ => false,
        })
    }
    pub fn sleep_ms(ms: u64) {
        crate::arch::pit::sleep_ms(ms);
    }
    pub fn spawn(name: &'static str, f: fn(), _prio: TaskPriority) {
        fake::log(format!("spawn_kernel {}", name));
        fake::with(|s| s.kernel_fns.push((name, f)));
    }
    pub fn spawn_linux_chroot(root: &str, prog: &str, argv: &[&str], uid: u32, gid: u32) -> Result<TaskId, alloc::string::String> {
        spawn_common(&format!("spawn_chroot {} {} {:?} {} {}", root, prog, argv, uid, gid)).map_err(alloc::string::String::from)
    }
    pub fn spawn_linux_elf(name: &'static str, data: &[u8], argv: &[&str], _prio: TaskPriority, uid: u32, gid: u32) -> Result<TaskId, &'static str> {
        spawn_common(&format!("spawn_linux_elf {} {} {:?} {} {}", name, data.len(), argv, uid, gid))
    }
    pub fn preemptible<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
    pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut crate::fs::FdTable) -> R) -> R {
        FDS.with(|t| f(&mut t.borrow_mut()))
    }

    /// *stub*
    pub mod scheduler {
        pub const DEFAULT_TIMESLICE_TICKS: u32 = 2;
        pub struct LoadedImage;
        pub fn load_linux_image(_src: super::exec::ElfSource, path: &str, _args: &[&str], _uid: u32, _gid: u32, _x: Option<u64>) -> Result<LoadedImage, &'static str> {
            crate::fake::log(format!("load_image {}", path));
            Ok(LoadedImage)
        }
    }
    /// *stub*
    pub mod exec {
        pub fn is_vm_loadable(image: &[u8]) -> bool {
            !image.is_empty() && !crate::fake::with(|s| s.not_loadable)
        }
        pub struct ElfSource(Box<[u8]>);
        impl ElfSource {
            pub fn from_bytes(b: Box<[u8]>) -> Self {
                ElfSource(b)
            }
        }
    }
    /// *stub* An ELF parser: 64 bytes or more; "interpreter" when the bytes name one.
    pub mod elf {
        pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
        #[derive(Debug)]
        pub struct ElfError;
        impl ElfError {
            pub fn as_str(&self) -> &'static str {
                "truncated ELF header"
            }
        }
        pub struct ElfBinary {
            interp: bool,
        }
        impl ElfBinary {
            pub fn parse(data: &[u8]) -> Result<ElfBinary, ElfError> {
                if data.len() < 64 {
                    return Err(ElfError);
                }
                Ok(ElfBinary { interp: data.windows(7).any(|w| w == b"/lib64/") })
            }
            pub fn interp_path(&self) -> Option<&str> {
                self.interp.then_some("/lib64/ld-linux-x86-64.so.2")
            }
        }
    }
    /// *stub* The supervisor.
    pub mod supervisor {
        use super::TaskId;
        use crate::fake;
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum ServiceState {
            Running,
            Restarting,
            Faulted,
            Stopped,
        }
        #[derive(Debug, Clone)]
        pub struct ServiceSnapshot {
            pub task_id: Option<u64>,
            pub endpoint_id: u32,
            pub state: ServiceState,
            pub restart_count: u32,
            pub unanswered_pings: u32,
            pub name: &'static str,
        }
        pub fn get_service_snapshots() -> Vec<ServiceSnapshot> {
            fake::with(|s| s.services.clone())
        }
        fn act(what: &str, name: &str, pid: u64) -> Result<TaskId, &'static str> {
            fake::log(format!("{} {}", what, name));
            match fake::with(|s| s.service_fail) {
                Some(e) => Err(e),
                None => Ok(TaskId(pid)),
            }
        }
        pub fn restart_service_by_name(name: &str) -> Result<TaskId, &'static str> {
            act("restart", name, 41)
        }
        pub fn kill_service_by_name(name: &str) -> Result<TaskId, &'static str> {
            act("kill_service", name, 42)
        }
        pub fn supervisor_tick() {
            fake::log("supervisor_tick");
        }
        pub struct Supervisor;
        impl Supervisor {
            pub fn start_service(&mut self, name: &str) -> Result<TaskId, &'static str> {
                act("start", name, 43)
            }
        }
        pub static SUPERVISOR: spin::Mutex<Supervisor> = spin::Mutex::new(Supervisor);
    }
    /// *stub* Waiting: the fake clock moves to the deadline.
    pub mod wait {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicUsize, Ordering};
        pub struct WaitQueue {
            pub wakes: AtomicUsize,
        }
        impl WaitQueue {
            pub const fn new() -> Self {
                WaitQueue { wakes: AtomicUsize::new(0) }
            }
            pub fn new_shared() -> Arc<WaitQueue> {
                Arc::new(WaitQueue::new())
            }
            pub fn wake_all(&self) {
                self.wakes.fetch_add(1, Ordering::Relaxed);
            }
        }
        pub enum QueueRef {
            Static(&'static WaitQueue),
        }
        pub struct WaitSet {
            queues: usize,
        }
        impl WaitSet {
            pub fn new() -> Self {
                WaitSet { queues: 0 }
            }
            pub fn add(&mut self, _q: QueueRef) {
                self.queues += 1;
            }
            pub fn register(&mut self) {}
            pub fn wait(&mut self, deadline: Option<u64>) {
                let now = crate::fake::ticks();
                let target = deadline.unwrap_or(now + 1).max(now + 1);
                crate::fake::advance((target - now) * 10_000_000);
            }
        }
    }
}

pub mod fs {
    use crate::fake;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    /// *stub* A pipe.
    #[derive(Clone, Default)]
    pub struct PipeBuffer(pub Arc<spin::Mutex<Pipe>>);
    #[derive(Default)]
    pub struct Pipe {
        pub data: Vec<u8>,
        pub writer_closed: bool,
    }
    impl Pipe {
        pub fn write(&mut self, b: &[u8]) -> Result<usize, i64> {
            self.data.extend_from_slice(b);
            Ok(b.len())
        }
        pub fn drop_writer(&mut self) {
            self.writer_closed = true;
        }
    }
    impl PipeBuffer {
        pub fn new() -> Self {
            PipeBuffer::default()
        }
        pub fn lock(&self) -> spin::MutexGuard<'_, Pipe> {
            self.0.lock()
        }
    }
    /// *stub* A file descriptor.
    pub enum FileDescriptor {
        PipeRead(PipeBuffer),
        /// Writes go to the test's output capture.
        Capture,
        Other,
    }
    impl FileDescriptor {
        pub fn write(&mut self, b: &[u8]) -> Result<usize, i64> {
            match self {
                FileDescriptor::Capture => {
                    fake::with(|s| s.out.push_str(&String::from_utf8_lossy(b)));
                    Ok(b.len())
                }
                _ => Err(-9),
            }
        }
    }
    /// *stub* A descriptor table.
    #[derive(Default)]
    pub struct FdTable {
        pub fds: alloc::collections::BTreeMap<usize, FileDescriptor>,
    }
    impl FdTable {
        pub fn with_capture() -> Self {
            let mut t = FdTable::default();
            t.fds.insert(1, FileDescriptor::Capture);
            t
        }
        pub fn close(&mut self, fd: usize) -> Result<(), i64> {
            self.fds.remove(&fd).map(|_| ()).ok_or(-9)
        }
        pub fn set_fd(&mut self, fd: usize, d: Option<FileDescriptor>) -> Result<(), i64> {
            match d {
                Some(d) => {
                    self.fds.insert(fd, d);
                }
                None => {
                    self.fds.remove(&fd);
                }
            }
            Ok(())
        }
        pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
            if fd == 1 && fake::with(|s| s.no_fd1) {
                return None;
            }
            self.fds.get_mut(&fd)
        }
    }

    pub fn init_server() {
        fake::log("fs::init_server");
    }
    /// *stub*
    pub mod firstboot {
        pub fn import_into_pool() {
            crate::fake::log("firstboot::import_into_pool");
        }
    }
    /// *stub*
    pub mod blockdev {
        pub fn scan() {
            crate::fake::log("blockdev::scan");
        }
    }
    /// *stub* The EFI partition.
    pub mod bootfs {
        pub fn file_exists(path: &str) -> bool {
            crate::fake::with(|s| s.boot_files.contains(path))
        }
    }

    pub mod zfs {
        use crate::fake;
        use core::sync::atomic::AtomicBool;
        pub static POOL_ON_USB: AtomicBool = AtomicBool::new(false);
        pub const ENDPOINT_ZFS_SERVER: u32 = 2;
        /// *mirror*
        pub mod types {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum DnodeType {
                PlainFile,
                Directory,
                Symlink,
            }
        }
        /// *mirror*
        pub mod zpl {
            #[derive(Debug, Default, Clone, Copy)]
            pub struct SetAttr {
                pub mode: Option<u32>,
                pub uid: Option<u32>,
                pub gid: Option<u32>,
                pub size: Option<u64>,
            }
        }
        /// *mirror*
        pub mod fsproto {
            pub const FS_SELFTEST: u32 = 0x30;
            pub const FS_VERIFY: u32 = 0x31;
            pub const FS_FSCK: u32 = 0x32;
        }
        /// *stub*
        pub struct DiskInfo {
            pub sectors: u64,
            pub lba48: bool,
            pub dma: bool,
            pub model: alloc::string::String,
        }
        pub fn disk_info() -> Option<DiskInfo> {
            fake::with(|s| s.disk.clone().map(|(sectors, lba48, dma, model)| DiskInfo { sectors, lba48, dma, model }))
        }
        /// *stub* The file server.
        pub struct Server;
        impl Server {
            pub fn pool_status(&mut self) -> Result<(u64, u64, u64, u64, u64), &'static str> {
                let (t, a, f, x) = fake::with(|s| s.pool).ok_or("no answer")?;
                Ok((t, a, f, x, 0))
            }
            pub fn datasets(&mut self) -> Result<Vec<(alloc::string::String, alloc::string::String, u64, bool)>, &'static str> {
                fake::with(|s| s.datasets.clone()).ok_or("no answer")
            }
            pub fn diagnostic(&mut self, op: u32, dir: &str, repair: bool) -> Result<(), &'static str> {
                fake::log(format!("diag {:#x} {} {}", op, dir, repair));
                Ok(())
            }
        }
        pub fn with_server<R>(f: impl FnOnce(&mut Server) -> Result<R, &'static str>) -> Result<R, &'static str> {
            f(&mut Server)
        }
    }

    /// *stub* A file's metadata.
    #[derive(Debug, Clone)]
    pub struct FileStat {
        pub obj_id: u64,
        pub obj_type: zfs::types::DnodeType,
        pub size: u64,
        pub birth_txg: u64,
        pub checksum: [u64; 4],
    }
    /// *stub* A directory entry.
    #[derive(Debug, Clone)]
    pub struct DirEntry {
        pub object_id: u64,
        pub is_valid: bool,
        pub obj_type: zfs::types::DnodeType,
        pub name: String,
    }
    /// *stub* Attributes.
    #[derive(Debug, Clone)]
    pub struct Attr {
        pub mode: u32,
        pub size: u64,
    }

    pub mod client {
        pub use super::ZfsClient;
        /// *stub* wave11 GH: a boot file as `read_boot_files` gives it.
        pub type BootFile = (alloc::string::String, alloc::vec::Vec<u8>);
        /// *stub* Joins `p` to `cwd` (".." and "." handled), in `buf`.
        pub fn normalize_path<'a>(cwd: &str, p: &str, buf: &'a mut [u8; 128]) -> &'a str {
            let full = if p.starts_with('/') { p.to_string() } else { format!("{}/{}", cwd.trim_end_matches('/'), p) };
            let mut parts: Vec<&str> = Vec::new();
            for c in full.split('/') {
                match c {
                    "" | "." => {}
                    ".." => {
                        parts.pop();
                    }
                    c => parts.push(c),
                }
            }
            let s = format!("/{}", parts.join("/"));
            let n = s.len().min(128);
            buf[..n].copy_from_slice(&s.as_bytes()[..n]);
            core::str::from_utf8(&buf[..n]).unwrap()
        }
    }

    /// *stub* The file server's client, on the fake pool.
    pub struct ZfsClient;
    fn fail() -> Result<(), &'static str> {
        match fake::with(|s| s.fs_fail) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn ino(path: &str) -> u64 {
        path.bytes().fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64)) & 0xFFFF
    }
    impl ZfsClient {
        pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
            fake::with(|s| {
                if let Some(d) = s.files.get(path) {
                    Ok(FileStat { obj_id: ino(path), obj_type: zfs::types::DnodeType::PlainFile, size: d.len() as u64, birth_txg: 9, checksum: [1, 2, 3, 4] })
                } else if s.dirs.contains(path) {
                    Ok(FileStat { obj_id: ino(path), obj_type: zfs::types::DnodeType::Directory, size: 0, birth_txg: 3, checksum: [0; 4] })
                } else {
                    Err("No such file or directory")
                }
            })
        }
        pub fn read_file_by_path(path: &str, buf: &mut [u8]) -> Result<usize, &'static str> {
            fail()?;
            let d = fake::with(|s| s.files.get(path).cloned()).ok_or("No such file")?;
            let n = d.len().min(buf.len());
            buf[..n].copy_from_slice(&d[..n]);
            Ok(n)
        }
        pub fn write_file_by_path(path: &str, data: &[u8]) -> Result<u64, &'static str> {
            fail()?;
            fake::log(format!("write {} {}", path, data.len()));
            fake::file(path, data);
            Ok(77)
        }
        pub fn list_dir(path: &str) -> Result<(Vec<DirEntry>, usize, &'static str), &'static str> {
            fail()?;
            fake::with(|s| {
                if !s.dirs.contains(path) {
                    return Err("not a directory");
                }
                let prefix = if path == "/" { "/".to_string() } else { format!("{}/", path) };
                let mut out = Vec::new();
                for f in s.files.keys().chain(s.dirs.iter()) {
                    if let Some(rest) = f.strip_prefix(&prefix) {
                        if !rest.is_empty() && !rest.contains('/') {
                            let dir = s.dirs.contains(f.as_str());
                            out.push(DirEntry {
                                object_id: ino(f),
                                is_valid: !rest.starts_with('~'),
                                obj_type: if dir { zfs::types::DnodeType::Directory } else if rest.ends_with(".lnk") { zfs::types::DnodeType::Symlink } else { zfs::types::DnodeType::PlainFile },
                                name: rest.to_string(),
                            });
                        }
                    }
                }
                let n = out.len();
                Ok((out, n, "hydrapool/root"))
            })
        }
        pub fn copy_file(from: &str, to: &str) -> Result<u64, &'static str> {
            fail()?;
            let d = fake::with(|s| s.files.get(from).cloned()).ok_or("source not found")?;
            fake::log(format!("copy {} {}", from, to));
            fake::file(to, &d);
            Ok(12)
        }
        pub fn create_dir(path: &str) -> Result<u64, &'static str> {
            fail()?;
            fake::log(format!("mkdir {}", path));
            fake::dir(path);
            Ok(ino(path))
        }
        pub fn create_dir_all(path: &str) -> Result<u64, &'static str> {
            fail()?;
            fake::log(format!("mkdir_all {}", path));
            fake::dir(path);
            Ok(ino(path))
        }
        pub fn remove_dir(path: &str) -> Result<(), &'static str> {
            fail()?;
            fake::log(format!("rmdir {}", path));
            Ok(())
        }
        pub fn remove_file(path: &str) -> Result<(), &'static str> {
            fail()?;
            fake::log(format!("unlink {}", path));
            fake::with(|s| s.files.remove(path)).map(|_| ()).ok_or("not found")
        }
        pub fn move_entry(from: &str, to: &str) -> Result<(), &'static str> {
            fail()?;
            fake::log(format!("rename {} {}", from, to));
            Ok(())
        }
        pub fn touch_file(path: &str) -> Result<u64, &'static str> {
            fail()?;
            fake::log(format!("touch {}", path));
            Ok(13)
        }
        pub fn sync() -> Result<(), &'static str> {
            fail()?;
            fake::log("sync");
            Ok(())
        }
        pub fn snapshot(_ds: u64) -> Result<u64, &'static str> {
            fail()?;
            fake::log("snapshot");
            Ok(14)
        }
        pub fn pool_status() -> Result<(u64, u64, u64, u64), &'static str> {
            fake::with(|s| s.pool).ok_or("the file server did not answer")
        }
        pub fn read_boot_files() -> Vec<(String, Vec<u8>)> {
            fake::log("read_boot_files");
            fake::with(|s| s.boot_files.iter().map(|f| (f.clone(), Vec::new())).collect())
        }
        pub fn import_boot_files(files: Vec<(String, Vec<u8>)>) {
            fake::log(format!("import_boot_files {}", files.len()));
        }
        pub fn resolve(_base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
            let p = String::from_utf8_lossy(path).to_string();
            fake::with(|s| s.files.contains_key(&p) || s.dirs.contains(&p)).then(|| ino(&p)).ok_or(-2)
        }
        pub fn getattr(ino_: u64) -> Result<Attr, i64> {
            fake::with(|s| {
                for (p, d) in &s.files {
                    if ino(p) == ino_ {
                        // A name ending in .lnk, or contents "symlink:<target>": a symbolic link
                        let mode = if p.ends_with(".lnk") || d.starts_with(b"symlink:") { 0o120777 } else { 0o100644 };
                        return Ok(Attr { mode, size: d.len() as u64 });
                    }
                }
                Ok(Attr { mode: 0o040755, size: 0 })
            })
        }
        pub fn setattr(ino_: u64, a: zfs::zpl::SetAttr) -> Result<(), i64> {
            fake::log(format!("setattr {:?} {:?} {:?}", a.mode.map(|m| format!("{:o}", m)), a.uid, a.gid));
            Ok(())
        }
    }
}

pub mod memory {
    /// *stub*
    pub mod vm {
        /// *stub* wave11 GH: the NXE debug words.
        pub static NX_SIM_OFF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        pub fn prefault_current(_ptr: u64, _len: u64, _write: bool) -> bool {
            !crate::fake::with(|s| s.prefault_fails)
        }
    }
    /// *stub*
    pub mod heap {
        use crate::fake;
        pub struct HeapStats {
            pub is_initialized: bool,
            pub start_address: u64,
            pub total_bytes: usize,
            pub used_bytes: usize,
            pub free_bytes: usize,
        }
        pub fn self_test() -> Result<(), &'static str> {
            fake::with(|s| s.heap_test_fail).map_or(Ok(()), Err)
        }
        pub fn stats() -> HeapStats {
            let (start, total, used, free) = fake::with(|s| s.heap);
            HeapStats { is_initialized: true, start_address: start, total_bytes: total, used_bytes: used, free_bytes: free }
        }
        pub fn is_initialized() -> bool {
            !fake::with(|s| s.heap_uninit)
        }
        pub fn init() -> Result<HeapStats, &'static str> {
            fake::log("heap::init");
            match fake::with(|s| s.heap_init_fail) {
                Some(e) => Err(e),
                None => Ok(stats()),
            }
        }
        pub fn try_stats() -> Option<HeapStats> {
            (!fake::with(|s| s.heap_uninit)).then(stats)
        }
    }
    /// *stub*
    pub mod frame_allocator {
        pub const PAGE_SIZE: u64 = 4096;
        /// *stub* wave11 GH: the boot word fwmem=old.
        pub static OLD_PATH: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        pub struct FrameAllocator;
        impl FrameAllocator {
            pub fn total_usable_memory(&self) -> u64 {
                crate::fake::with(|s| s.phys.0)
            }
            pub fn allocated_memory(&self) -> u64 {
                crate::fake::with(|s| s.phys.1)
            }
            pub fn free_memory(&self) -> u64 {
                crate::fake::with(|s| s.phys.2)
            }
            pub fn allocate_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
                let n = crate::fake::with(|s| {
                    if s.frames_left == 0 {
                        return None;
                    }
                    s.frames_left -= 1;
                    s.frames_given += 1;
                    Some(s.frames_given)
                })?;
                Some(x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(0x10_0000 + n * 4096)))
            }
        }
        pub static FRAME_ALLOCATOR: spin::Mutex<FrameAllocator> = spin::Mutex::new(FrameAllocator);
        pub fn init_memory_from_uefi() {
            crate::fake::log("frame_allocator::init_memory_from_uefi");
        }
    }
    /// *stub* Page tables.
    pub mod paging {
        use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame};
        use x86_64::{PhysAddr, VirtAddr};

        /// What `with_kernel_tables(uefi::runtime::get_time)` answers on the host.
        pub trait KernelCall {
            fn fake() -> Self;
        }
        impl KernelCall for uefi::Result<uefi::runtime::Time> {
            fn fake() -> Self {
                match crate::fake::with(|s| s.rtc) {
                    Some((year, month, day, hour, minute, second)) => Ok(uefi::runtime::Time::new(uefi::runtime::TimeParams {
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        nanosecond: 0,
                        time_zone: None,
                        daylight: uefi::runtime::Daylight::empty(),
                    })
                    .unwrap()),
                    None => Err(uefi::Status::DEVICE_ERROR.into()),
                }
            }
        }
        /// *stub* Runs nothing: answers what the test set.
        pub fn with_kernel_tables<F: FnOnce() -> R, R: KernelCall>(_f: F) -> R {
            R::fake()
        }
        pub struct AddressSpace;
        impl AddressSpace {
            pub fn active() -> Self {
                AddressSpace
            }
            pub unsafe fn translate_page(&self, _p: Page) -> Option<(PhysFrame, PageTableFlags)> {
                crate::fake::with(|s| s.translate).map(|(_, frame, f)| (PhysFrame::containing_address(PhysAddr::new(frame)), f))
            }
            pub unsafe fn translate_addr(&self, v: VirtAddr) -> Option<PhysAddr> {
                crate::fake::with(|s| s.translate).map(|(phys, _, _)| PhysAddr::new(phys + (v.as_u64() & 0xfff)))
            }
            pub unsafe fn map_range(
                &mut self,
                start: Page,
                frame: PhysFrame,
                count: usize,
                _flags: PageTableFlags,
                _alloc: &mut super::frame_allocator::FrameAllocator,
            ) -> Result<(), &'static str> {
                crate::fake::log(format!("map_range {:#x} {:#x} {}", start.start_address().as_u64(), frame.start_address().as_u64(), count));
                Ok(())
            }
        }
        /// *stub* Hydra's own page table root.
        pub fn init_kernel_space(_alloc: &mut super::frame_allocator::FrameAllocator) -> Result<PhysAddr, &'static str> {
            crate::fake::log("init_kernel_space");
            if let Some(e) = crate::fake::with(|s| s.kernel_space_fail) {
                return Err(e);
            }
            *KERNEL_SPACE.lock() = Some(AddressSpace);
            Ok(PhysAddr::new(0x20_0000))
        }
        impl AddressSpace {
            pub unsafe fn map_page(&mut self, page: Page, frame: PhysFrame, flags: PageTableFlags, _alloc: &mut super::frame_allocator::FrameAllocator) -> Result<(), &'static str> {
                crate::fake::log(format!("map_page {:#x}", page.start_address().as_u64()));
                crate::fake::with(|s| s.translate = Some((frame.start_address().as_u64(), frame.start_address().as_u64(), flags)));
                Ok(())
            }
            pub unsafe fn unmap_page(&mut self, page: Page) -> Result<(), &'static str> {
                crate::fake::log(format!("unmap_page {:#x}", page.start_address().as_u64()));
                Ok(())
            }
        }
        /// *stub* The kernel's address space (present once a test puts one in).
        pub static KERNEL_SPACE: spin::Mutex<Option<AddressSpace>> = spin::Mutex::new(None);
    }
}

pub mod compat {
    pub mod linux {
        use crate::fake;
        use core::sync::atomic::AtomicBool;

        /// *mirror*
        #[derive(Default)]
        pub struct LinuxStats {
            pub total_calls: u64,
            pub io_calls: u64,
            pub memory_calls: u64,
            pub process_calls: u64,
            pub arch_prctl_calls: u64,
            pub time_calls: u64,
            pub unknown_calls: u64,
        }
        pub static LINUX_STATS: spin::Mutex<LinuxStats> =
            spin::Mutex::new(LinuxStats { total_calls: 0, io_calls: 0, memory_calls: 0, process_calls: 0, arch_prctl_calls: 0, time_calls: 0, unknown_calls: 0 });
        pub static TRACE_FILTER: spin::Mutex<alloc::string::String> = spin::Mutex::new(alloc::string::String::new());
        pub static TRACE_SYSCALLS: AtomicBool = AtomicBool::new(false);

        /// *mirror*
        pub struct LinuxUtsname {
            pub sysname: [u8; 65],
            pub release: [u8; 65],
        }
        impl Default for LinuxUtsname {
            fn default() -> Self {
                let mut u = LinuxUtsname { sysname: [0; 65], release: [0; 65] };
                u.sysname[..5].copy_from_slice(b"Linux");
                u.release[..6].copy_from_slice(b"6.8.0h");
                u
            }
        }

        /// *stub*
        pub mod abac {
            pub fn console_login(attrs: Option<&str>) {
                crate::fake::log(format!("abac {:?}", attrs));
            }
        }
        /// *stub* The kernel log.
        pub mod admin {
            pub fn klog(args: core::fmt::Arguments) {
                let s = alloc::format!("{}", args);
                crate::fake::with(|st| st.klog.push_str(&s));
            }
        }
        /// *stub*
        pub mod devices {
            pub fn populate(root: &str) -> Result<(), &'static str> {
                crate::fake::log(format!("devices {}", root));
                crate::fake::with(|s| s.devices_fail).map_or(Ok(()), Err)
            }
        }
        /// *stub*
        pub mod fs {
            pub enum PseudoFile {
                ProcVersion,
                DevUrandom,
            }
            impl PseudoFile {
                pub fn read(&self, _off: u64, buf: &mut [u8]) -> usize {
                    match self {
                        PseudoFile::ProcVersion => {
                            let v = b"Linux version 6.8.0-hydra (host test)\n";
                            let n = v.len().min(buf.len());
                            buf[..n].copy_from_slice(&v[..n]);
                            n
                        }
                        PseudoFile::DevUrandom => {
                            for (i, b) in buf.iter_mut().enumerate() {
                                *b = 0xa0 + i as u8;
                            }
                            buf.len()
                        }
                    }
                }
            }
        }
        /// *stub*
        pub mod live {
            pub fn is_live() -> bool {
                crate::fake::with(|s| s.live)
            }
        }
        /// *stub*
        pub mod pidfd {
            pub static EXIT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
        }
        /// *stub*
        pub mod proc {
            pub fn take_status(tid: u64) -> Option<i32> {
                crate::fake::with(|s| s.tasks.get_mut(&tid).and_then(|t| t.status.take()))
            }
        }
        /// *stub* The profiler.
        pub mod prof {
            use core::sync::atomic::{AtomicBool, AtomicU64};
            pub static ON: AtomicBool = AtomicBool::new(false);
            pub static SLOW_MS: AtomicU64 = AtomicU64::new(0);
            pub fn reset() {
                crate::fake::log("prof_reset");
            }
            pub fn show(n: usize) {
                crate::fake::log(format!("prof_show {}", n));
            }
            pub fn slow_show() {
                crate::fake::log("prof_slow_show");
            }
            pub fn sample_start(id: u64, kernel: bool) {
                crate::fake::log(format!("sample_start {} {}", id, kernel));
            }
            pub fn sample_show(n: usize) {
                crate::fake::log(format!("sample_show {}", n));
            }
        }
        /// *stub*
        pub mod tty {
            pub static INPUT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
            pub fn attach_session(sid: u64, pgid: u64) {
                crate::fake::log(format!("attach {} {}", sid, pgid));
            }
            pub fn detach_session() {
                crate::fake::log("detach");
            }
        }
    }
}

/// *stub* The Linux server's switches.
pub mod lx {
    // wave8 GX2 begin: *stub* the desktop set (`src/lx/desktop.rs`)
    pub mod desktop {
        pub fn inherit(_parent: u64, _child: u64) {}
        pub fn mark(_pid: u64) {}
        pub fn root_started(_pid: u64) {}
        pub fn expect_root() {}
        pub fn cancel_root() {}
    }
    // wave8 GX2 end
    use core::sync::atomic::AtomicBool;
    /// *stub* Test switches: online, family 2 moved, relay wanted.
    pub static ONLINE: AtomicBool = AtomicBool::new(false);
    pub static NET_MOVED: AtomicBool = AtomicBool::new(false);
    pub static RELAY: AtomicBool = AtomicBool::new(false);
    pub fn set_boot_words(text: &[u8]) {
        crate::fake::log(format!("boot_words {}", String::from_utf8_lossy(text)));
    }
    pub fn is_online() -> bool {
        ONLINE.load(core::sync::atomic::Ordering::Relaxed)
    }
    pub fn family_moved(family: u64) -> bool {
        family == 2 && NET_MOVED.load(core::sync::atomic::Ordering::Relaxed)
    }
    pub fn relay_wanted() -> bool {
        RELAY.load(core::sync::atomic::Ordering::Relaxed)
    }
    pub fn net_event(handles: Option<&[u32]>) {
        crate::fake::log(format!("net_event {:?}", handles));
    }
    // wave8 GX2 begin: the registry's view of the network service (lx-net, or linux-server)
    pub mod svc {
        use core::sync::atomic::{AtomicU32, Ordering};
        /// *stub* The network service's endpoint (`ENDPOINT_LINUX_SERVER` until a test sets
        /// lx-net's).
        pub static NET_EP: AtomicU32 = AtomicU32::new(crate::ipc::protocol::ENDPOINT_LINUX_SERVER);
        pub fn online(_svc: u8) -> bool {
            super::is_online()
        }
        pub fn endpoint_of(_svc: u8) -> u32 {
            NET_EP.load(Ordering::Relaxed)
        }
    }
    // wave8 GX2 end
}

/// *stub* The personality hook.
pub mod personality {
    use core::sync::atomic::AtomicBool;
    pub static STUB_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);
    pub static OFF_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);
    pub fn init() {
        crate::fake::log("personality_init");
    }
}
