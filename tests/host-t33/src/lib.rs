//! Host build of Group 33's kernel files (test wave): the file layer (`src/fs`, the ZFS
//! client), the personalities, the package code, compression, and the Linux layer's
//! perf/prof/ABAC/admin/keys/bpf/sysv/mqueue/landlock modules.
//!
//! As in `tests/host`, each kernel file is compiled through `#[path]` under the module
//! path the kernel uses, so `crate::` and `super::` references resolve unchanged. Unlike
//! `tests/host`, the whole of `src/fs` is real here (descriptor table, ZFS client, block
//! devices): the file server it talks to is [`fakefs`], a fake ring-3 server behind a
//! fake `ipc::service`. Items marked *stub* stand in for kernel code outside this group.

#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

extern crate alloc;

pub mod fake;
pub mod fakefs;

/// *stub* Kernel console output: captured per thread ([`fake::console_take`]).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        $crate::fake::console_push(&alloc::format!($($arg)*));
    }};
}

/// *stub* Kernel log output: captured per thread ([`fake::klog_take`]).
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        $crate::fake::klog_push(&alloc::format!($($arg)*));
    }};
}

pub mod arch {
    /// *stub*
    pub mod pit {
        pub use crate::fake::{clock_state, frequency_hz, now_ns, sleep_ms, tick_ns, ticks, uptime_ms};
    }
    /// *stub* Deterministic bytes instead of RDRAND.
    pub mod random {
        pub use crate::fake::random_fill as fill;
    }
    /// *stub* The host behaves as a single CPU.
    pub mod percpu {
        pub use crate::fake::PerCpuPtr;
        pub fn cpu() -> usize {
            0
        }
    }
    /// *stub*
    pub mod smp {
        pub fn bkl_enter() {
            crate::fake::BKL.set(crate::fake::BKL.get() + 1);
        }
        pub fn bkl_exit() {
            crate::fake::BKL.set(crate::fake::BKL.get() - 1);
        }
        pub fn bkl_owner() -> usize {
            0
        }
        pub fn flush_kick() {}
        pub fn online() -> usize {
            1
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
    /// *stub* PCID is off on the host.
    pub mod pcid {
        pub fn enabled() -> bool {
            false
        }
        pub fn global_enabled() -> bool {
            false
        }
        pub fn load_cr3(_pml4: u64) {}
        pub fn forget(_pml4: u64) {}
        pub fn mark_remote(_cpu: usize, _pml4: u64) {}
        pub fn flush_all_ids() {}
        pub fn without_invpcid<R>(f: impl FnOnce() -> R) -> R {
            f()
        }
        pub fn summary() -> alloc::string::String {
            "PCID off (host)".into()
        }
    }
    /// *stub* The kernel's user selectors.
    pub mod gdt {
        pub const USER_CS: u16 = 0x2b;
        pub const USER32_CS: u16 = 0x23;
        pub const USER_DS: u16 = 0x1b;
    }
    /// *mirror* of the kernel's FXSAVE area.
    pub mod idt {
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
    }
    /// *stub*
    pub mod rtc {
        pub use crate::fake::{rtc_now as now, wall_base_ns};
    }
    /// *stub*
    pub mod relocate {
        pub fn image_phys() -> Option<(u64, u64)> {
            None
        }
    }
    /// *stub* QEMU's fw_cfg files ([`crate::fake::FWCFG`]).
    pub mod fwcfg {
        pub fn read_file_into(name: &str, buf: &mut [u8]) -> Option<usize> {
            crate::fake::FWCFG.with_borrow(|m| {
                let v = m.get(name)?;
                let n = v.len().min(buf.len());
                buf[..n].copy_from_slice(&v[..n]);
                Some(n)
            })
        }
    }
    /// *stub* Boot-time marks (recorded).
    pub mod boottime {
        pub fn mark(what: &str) {
            crate::fake::MARKS.with_borrow_mut(|v| v.push(what.into()));
        }
    }
    /// *stub*
    pub mod syscall {
        pub use crate::fake::rdmsr;

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
        pub static SYSCALL_ENTRIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        pub static SYSCALL_FPU: core::sync::atomic::AtomicPtr<crate::arch::idt::FpuState> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
        pub fn reap_retired() {}
    }
}

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

#[path = "../../../src/compress/mod.rs"]
pub mod compress;

/// *stub* The console.
pub mod console {
    pub fn read_key() -> Option<uefi::proto::console::text::Key> {
        crate::fake::KEYS.with_borrow_mut(|v| v.pop_front())
    }
    pub fn print_raw(s: &str) {
        crate::fake::console_push(s);
    }
    pub fn set_color(_fg: uefi::proto::console::text::Color, _bg: uefi::proto::console::text::Color) {}
    pub fn is_hardware_mode() -> bool {
        crate::fake::HARDWARE_MODE.get()
    }
}

pub mod compat {
    pub mod linux {
        #[path = "../../../../../src/compat/linux/abac_core.rs"]
        pub mod abac_core;
        #[path = "../../../../../src/compat/linux/abac.rs"]
        pub mod abac;
        #[path = "../../../../../src/compat/linux/admin.rs"]
        pub mod admin;
        #[path = "../../../../../src/compat/linux/bpf.rs"]
        pub mod bpf;
        #[path = "../../../../../src/compat/linux/keys.rs"]
        pub mod keys;
        #[path = "../../../../../src/compat/linux/landlock.rs"]
        pub mod landlock;
        #[path = "../../../../../src/compat/linux/mqueue.rs"]
        pub mod mqueue;
        #[path = "../../../../../src/compat/linux/perf.rs"]
        pub mod perf;
        #[path = "../../../../../src/compat/linux/prof.rs"]
        pub mod prof;
        #[path = "../../../../../src/compat/linux/sysv.rs"]
        pub mod sysv;

        // Other groups' files, compiled because the files above use them
        #[path = "../../../../../src/compat/linux/eventfd.rs"]
        pub mod eventfd;
        #[path = "../../../../../src/compat/linux/memfd.rs"]
        pub mod memfd;
        #[path = "../../../../../src/compat/linux/seccomp.rs"]
        pub mod seccomp;
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        pub use crate::fake::linux_stubs::*;

        /// *stub* The pseudo-files (`/proc`, `/dev`) as far as the code under test reads them.
        pub mod fs {
            pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
            pub fn proc_pid_file_text(rest: &str) -> Option<alloc::vec::Vec<u8>> {
                (rest == "self/comm").then(|| b"hydra-test\n".to_vec())
            }
            /// *stub* A few pseudo-files: `/dev/null`, `/dev/full`, `/dev/zero`, `/proc/version`.
            pub enum PseudoFile {
                DevNull,
                DevFull,
                DevZero,
                Text(&'static [u8]),
            }
            impl PseudoFile {
                pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
                    match self {
                        PseudoFile::DevNull => 0,
                        PseudoFile::DevFull | PseudoFile::DevZero => {
                            buf.fill(0);
                            buf.len()
                        }
                        PseudoFile::Text(t) => {
                            let start = offset.min(t.len());
                            let n = buf.len().min(t.len() - start);
                            buf[..n].copy_from_slice(&t[start..start + n]);
                            n
                        }
                    }
                }
                pub fn write(&self, data: &[u8]) -> usize {
                    data.len()
                }
            }
            pub fn match_pseudo_path(path: &str) -> Option<PseudoFile> {
                match path {
                    "/dev/null" => Some(PseudoFile::DevNull),
                    "/dev/full" => Some(PseudoFile::DevFull),
                    "/dev/zero" => Some(PseudoFile::DevZero),
                    "/proc/version" => Some(PseudoFile::Text(b"Linux version 6.8.0-hydra\n")),
                    _ => None,
                }
            }
        }
    }
}

/// The whole file layer is real: `src/fs/mod.rs` and every file under it.
#[path = "../../../src/fs/mod.rs"]
pub mod fs;

pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    pub use message::Message;
    /// *stub* The service layer: see [`crate::fakefs::service`].
    pub use crate::fakefs::service;
}

/// The personality hook (`src/personality`): real.
#[path = "../../../src/personality/mod.rs"]
pub mod personality;

/// The package code (`src/pkg`): real.
#[path = "../../../src/pkg/mod.rs"]
pub mod pkg;

/// *stub* The forwarding to the ring-3 Linux server.
pub mod lx {
    pub fn note(_kind: u64, _a: u64, _b: u64, _c: u64) {}
    /// *stub* wave10 G7b-1: lx-proc's approvals (none on the host).
    pub mod proc {
        pub fn take_approval(_tid: u64, _nr: u64) -> bool {
            false
        }
    }
    // wave10 G8-2 begin: *stub* System V shared memory in lx-ipc (`src/lx/shm.rs`): never
    // active on the host (the in-kernel copy answers)
    pub mod shm {
        pub fn active() -> bool {
            false
        }
        pub fn shmat(_id: i32, _addr: u64, _flags: u64) -> i64 {
            -38
        }
        pub fn shmdt(_addr: u64) -> i64 {
            -38
        }
        pub fn on_fork(_parent: u64, _child: u64) {}
        pub fn forget(_pid: u64) {}
    }
    // wave10 G8-2 end
    // wave9 G6b-1 begin: *stub* the kernel's events for vfs-server's inotify/fanotify
    // (`lx::notifyfwd`). wave9 G9-C: the kernel's own instances are gone, so the tests'
    // switches (`INOTIFY_ON`, `FANOTIFY_ON`) now say what vfs-server wants, and the events
    // are recorded here
    pub mod notifyfwd {
        use crate::compat::linux::{FANOTIFY_ON, INOTIFY_ON, NOTIFIED};
        pub fn want_zfs() -> bool {
            INOTIFY_ON.get() || FANOTIFY_ON.get()
        }
        pub fn want_close_write() -> bool {
            INOTIFY_ON.get()
        }
        pub fn want_fan() -> bool {
            FANOTIFY_ON.get()
        }
        pub fn zfs_event(ino: u64, mask: u32, _cookie: u32, name: &[u8]) {
            NOTIFIED.with_borrow_mut(|v| v.push(("vfs-zfs", ino, mask as u64, alloc::string::String::from_utf8_lossy(name).into_owned())));
        }
        pub fn file_event(ino: u64, _dir: u64, path: &str, mask: u64, _is_dir: bool) {
            let _ = NOTIFIED.try_with(|v| v.borrow_mut().push(("fanotify", ino, mask, path.into())));
        }
        pub fn on_open(_ino: u64, _dir: u64, _path: &str, _is_dir: bool, _exec: bool) -> Result<(), i64> {
            Ok(())
        }
        pub fn parent_of(_path: &str) -> u64 {
            0
        }
    }
    // wave9 G6b-1 end
    /// *stub* wave7 G7-2: the kernel's changes noted for vfs-server (recorded).
    pub mod fileh {
        pub static CHANGED: std::sync::Mutex<alloc::vec::Vec<u64>> = std::sync::Mutex::new(alloc::vec::Vec::new());
        pub fn kernel_changed(ino: u64) {
            CHANGED.lock().unwrap_or_else(|e| e.into_inner()).push(ino);
        }
        /// *stub* wave7 G7-7: the `[prof] vfs:` line.
        pub fn summary() -> alloc::string::String {
            alloc::string::String::from("vfs: host")
        }
        /// *stub* wave9 G9-C: the prof line of calls by number.
        pub fn kernel_by_nr(_n: usize) -> alloc::string::String {
            alloc::string::String::new()
        }
    }
    /// *stub* wave7 G7-7: the `[prof] execve` line.
    pub mod xexec {
        pub fn summary() -> alloc::string::String {
            alloc::string::String::from("execve: host")
        }
    }
    pub fn summary() -> alloc::string::String {
        alloc::string::String::from("lx: host")
    }
    pub mod mem {
        pub fn server_mmap(
            _dev: &alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>,
            _args: [u64; 6],
        ) -> Result<(alloc::sync::Arc<dyn crate::memory::vm::MappedObject>, i64, u64), i64> {
            Err(-19)
        }
    }
    pub mod obj {
        /// *stub* A linux-server object; tests make one to mark a descriptor.
        pub struct ServerObject;
        impl ServerObject {
            pub fn kind(&self) -> u32 {
                0
            }
            pub fn tag(&self) -> u64 {
                0
            }
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
        pub use crate::fake::{make_user_accessible, AddressSpace};
        pub static KERNEL_SPACE: spin::Mutex<Option<AddressSpace>> = spin::Mutex::new(None);
    }
}

/// *stub*
pub mod net {
    pub mod client {
        pub fn service_running() -> bool {
            crate::fake::NET_RUNNING.get()
        }
    }
}

pub mod task {
    pub static CURRENT_TID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    /// *stub* The running system call (task dump).
    pub static CURRENT_SYSCALL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
    /// *stub*
    pub mod elf {
        pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
    }
    /// *stub*
    pub mod scheduler {
        pub const DEFAULT_STACK_SIZE: usize = 65536;
        pub static MAX_KSTACK_USE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        pub fn wait_out_handoff() {}
    }
    /// *stub*
    pub mod supervisor {
        pub fn revive(endpoint: u32) -> bool {
            crate::fakefs::revive(endpoint)
        }
    }
    pub use crate::fake::wait;
    pub mod tcb {
        pub use crate::fake::Caps;
    }
    /// *mirror* of `src/task/tcb.rs`'s personalities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPersonality {
        Hydra,
        Linux,
        FreeBsd,
        MacOs,
    }
    impl TaskPersonality {
        pub fn as_str(&self) -> &'static str {
            match self {
                TaskPersonality::Hydra => "Hydra",
                TaskPersonality::Linux => "Linux",
                TaskPersonality::FreeBsd => "FreeBSD",
                TaskPersonality::MacOs => "macOS",
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPriority {
        Low,
        Normal,
        High,
    }
    /// *stub* Records the task that would start.
    pub fn spawn(name: &str, _entry: fn(), _prio: TaskPriority) {
        crate::fake::SPAWNED.with_borrow_mut(|v| v.push(name.into()));
    }
    pub fn sleep_ms(ms: u64) {
        crate::fake::sleep_ms(ms)
    }
    /// *stub* The fake clock moves instead.
    pub fn sleep_ticks(ticks: u64) {
        crate::fake::TICKS.set(crate::fake::TICKS.get() + ticks);
    }
    pub fn exit_group() -> ! {
        panic!("exit_group")
    }
    pub fn current_retired() -> bool {
        false
    }
    pub fn leave_retired() {}
    pub use crate::fake::{is_task_alive, with_current_fds_mut, with_current_task_mut, Task, TaskId, SCHEDULER};
}
