//! Host build of the hardware-independent Hydra kernel modules.
//!
//! Each module below compiles the kernel's own source file through `#[path]`,
//! laid out under the same module path the kernel uses, so `crate::` and
//! `super::` references inside those files resolve unchanged. Nothing is
//! copied: the tests in `tests/` exercise exactly the code that ships.
//!
//! Where a kernel file calls into the scheduler, fd table, ZFS client, NIC
//! or page tables, the callee is replaced by a stub from [`fake`], placed at
//! the same `crate::` path. Items marked *stub* below are those stand-ins;
//! everything else is real kernel code. Hardware drivers, interrupt and
//! paging code are left to the QEMU harness (`tools/hydra_run.py`) and the
//! Linux ABI programs in `tests/linux/`.
//!
//! Paths inside an inline `mod` block are resolved relative to a directory
//! named after that module, hence the extra `../` per nesting level.

#![allow(dead_code, unused_imports, clippy::all)]

extern crate alloc;

pub mod fake;

/// *stub* Kernel console output; discarded on the host.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

/// *stub* Kernel log output; discarded on the host.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
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
    /// *stub* The kernel indexes per-CPU slots by `gs:[8]`, which a host
    /// process cannot use; the host behaves as a single CPU.
    pub mod percpu {
        pub use crate::fake::PerCpuPtr;
        /// The host behaves as CPU 0.
        pub fn cpu() -> usize {
            0
        }
    }
    /// *stub* TLB shootdown on a single CPU: the local flush only (the kernel's
    /// `smp::shootdown` returns after it when one CPU is online). Flushes go to
    /// the counting shim in `shim/x86_64`.
    pub mod smp {
        /// *stub* No kernel lock on the host.
        pub fn bkl_exit() {}
        pub fn shootdown(_cr3: Option<u64>, addr: Option<u64>) {
            match addr {
                Some(a) => x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(a)),
                None => x86_64::instructions::tlb::flush_all(),
            }
        }
    }
    /// *stub* The kernel's user code and data selectors.
    pub mod gdt {
        pub const USER_CS: u16 = 0x2b;
        pub const USER32_CS: u16 = 0x23;
        pub const USER_DS: u16 = 0x1b;
    }
    /// *mirror* of the kernel's exception frame and FXSAVE area (the signal code builds
    /// and reads them; nothing traps on the host).
    pub mod idt {
        #[repr(C)]
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
        #[repr(C, align(16))]
        #[derive(Clone)]
        pub struct FpuState(pub [u8; 512]);
        impl FpuState {
            pub fn new() -> Self {
                let mut area = [0u8; 512];
                area[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
                area[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
                Self(area)
            }
        }
    }
    /// *stub*
    pub mod rtc {
        pub use crate::fake::{rtc_now as now, wall_base_ns};
    }
    /// *stub* The kernel's move to the higher half happens at boot; on the host
    /// it never did.
    pub mod relocate {
        pub fn image_phys() -> Option<(u64, u64)> {
            None
        }
    }
    #[path = "../../../../src/arch/vdso.rs"]
    pub mod vdso;
    /// *stub*
    pub mod syscall {
        pub use crate::fake::rdmsr;

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
}

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

#[path = "../../../src/compress/mod.rs"]
pub mod compress;

pub mod compat {
    pub mod linux {
        #[path = "../../../../../src/compat/linux/bpf.rs"]
        pub mod bpf;
        #[path = "../../../../../src/compat/linux/epoll.rs"]
        pub mod epoll;

        /// *stub* The two items bpf.rs reads from the kernel's pseudo-file module.
        pub mod fs {
            pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
            pub fn proc_pid_file_text(rest: &str) -> Option<alloc::vec::Vec<u8>> {
                (rest == "self/comm").then(|| b"hydra-test\n".to_vec())
            }
        }
        #[path = "../../../../../src/compat/linux/eventfd.rs"]
        pub mod eventfd;
        #[path = "../../../../../src/compat/linux/keys.rs"]
        pub mod keys;
        #[path = "../../../../../src/compat/linux/landlock.rs"]
        pub mod landlock;
        #[path = "../../../../../src/compat/linux/memfd.rs"]
        pub mod memfd;
        #[path = "../../../../../src/compat/linux/mm.rs"]
        pub mod mm;
        #[path = "../../../../../src/compat/linux/mqueue.rs"]
        pub mod mqueue;
        #[path = "../../../../../src/compat/linux/seccomp.rs"]
        pub mod seccomp;
        #[path = "../../../../../src/compat/linux/sockopt.rs"]
        pub mod sockopt;

        /// *stub*
        pub mod ptrace {
            //! *stub* Nothing is traced on the host: every hook is a no-op.
            pub fn is_traced(_tid: u64) -> bool {
                false
            }
            pub fn interrupt_pending() -> bool {
                false
            }
            pub fn interrupt_stop<F>(_frame: &mut F, _fpu: *mut crate::arch::idt::FpuState, _orig: u64) {}
            pub fn signal_stop<F>(_frame: &mut F, _fpu: *mut crate::arch::idt::FpuState, _orig: u64, _sig: u32, _info: &[u8; 128]) -> u32 {
                0
            }
            pub fn group_stop<F>(_frame: &mut F, _fpu: *mut crate::arch::idt::FpuState, _orig: u64, _sig: u32) {}
            pub fn sigreturn_exit<F>(_frame: &mut F, _fpu: *mut crate::arch::idt::FpuState) {}
            pub fn on_sigcont(_tgid: u64) {}
            pub fn on_thread_exit(_tgid: u64, _tid: u64, _status: i32, _parent: u64) -> Option<u64> {
                None
            }
            pub fn on_tracer_exit(_pid: u64) -> alloc::vec::Vec<(u64, u64)> {
                alloc::vec::Vec::new()
            }
            pub fn wait_report(_me: u64, _sel: i64, _keep: bool) -> Option<(u64, i32)> {
                None
            }
            pub fn has_tracee(_me: u64, _sel: i64) -> bool {
                false
            }
            pub use crate::fake::seccomp_stop;
        }
        #[path = "../../../../../src/compat/linux/sysv.rs"]
        pub mod sysv;
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        #[path = "../../../../../src/compat/linux/userfaultfd.rs"]
        pub mod userfaultfd;
        #[path = "../../../../../src/compat/linux/unix.rs"]
        pub mod unix;
        #[path = "../../../../../src/compat/linux/futex.rs"]
        pub mod futex;
        /// *stub* System call tracing switch (`linux trace`).
        pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        /// *stub* Identity caches of the system call fast path (none on the host).
        pub fn ident_changed() {}

        /// *stub* Per-process hooks the process table calls at exit; nothing to forget on
        /// the host.
        pub mod ptimer {
            pub const SI_TIMER: i32 = -2;
            pub fn forget_process(_pid: u64) {}
        }
        /// *stub*
        pub mod misc {
            pub fn forget_process(_pid: u64) {}
        }
        /// *stub*
        pub mod aio {
            pub fn forget_process(_pid: u64) {}
        }
        /// *stub*
        pub mod locks {
            pub fn process_exited(_pid: u64) {}
        }
        /// *stub*
        pub mod limits {
            pub fn on_exit(_pid: u64) {}
        }
        /// *stub* No process accounting on the host.
        pub mod admin {
            pub fn acct_on() -> bool {
                false
            }
            pub fn on_exit(_pid: u64, _ppid: u64, _start: u64, _status: i32, _cpu_ticks: u64, _faults: u64) {}
        }
        /// *stub* No perf events on the host.
        pub mod perf {
            pub fn own_ticks(_tgid: u64) -> (u64, u64) {
                (0, 0)
            }
            pub fn active() -> bool {
                false
            }
            pub fn exited(_pid: u64, _ancestors: &[u64]) {}
        }
        /// *stub*
        pub mod mount {
            pub fn forget_thread(_tid: u64) {}
        }

        /// The real signal and process-table code. (`proc` below stays a stub: the other
        /// modules' tests record the signals they send through it.)
        #[path = "../../../../../src/compat/linux/proc.rs"]
        pub mod proc_real;

        /// *stub* Only `install`, the call `SO_PEERPIDFD` makes.
        pub mod pidfd {
            /// *stub* Woken when a process exits (waits never sleep on the host).
            pub static EXIT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
            /// *stub* No pidfd descriptors on the host.
            pub fn pid_of(_fd: u64) -> Result<u64, i64> {
                Err(-9) // EBADF
            }
            /// Not supported on the host: no `PidFd` descriptor variant.
            pub fn install(_pid: u64, _nonblock: bool) -> i64 {
                -38 // ENOSYS
            }
        }

        /// *stub* The kernel's `CharDevice` trait, cut down to the methods the
        /// code under test calls or implements. The real `chardev.rs` pulls in
        /// most of the Linux layer (DRM, FUSE, io_uring, BPF...).
        pub mod chardev {
            use alloc::string::String;
            use alloc::sync::Arc;

            use crate::memory::vm::MappedObject;
            use crate::task::wait::WaitSet;

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
                fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
                    Err(-19)
                }
                fn set_nonblock(&self, on: bool);
                fn nonblock(&self) -> bool;
                fn stat(&self) -> crate::compat::linux::types::LinuxStat {
                    crate::compat::linux::types::LinuxStat::default()
                }
                fn deliver_notification(&self, _data: &[u8]) -> bool {
                    false
                }
                fn as_mqueue(&self) -> Option<&crate::compat::linux::mqueue::MqHandle> {
                    None
                }
                fn as_landlock(&self) -> Option<&crate::compat::linux::landlock::Ruleset> {
                    None
                }
                fn as_bpf(&self) -> Option<crate::compat::linux::bpf::Obj> {
                    None
                }
            }
        }

        /// *stub*
        pub mod proc {
            pub use crate::fake::{current_ids, die_by_signal, force_seccomp_sigsys, Process, PROCS};
            pub fn sigkill_pending() -> bool {
                crate::fake::SIGKILL_PENDING.get()
            }
            /// Verbatim from the kernel.
            pub fn in_supplementary_groups(gid: u32) -> bool {
                let (_, pid) = current_ids();
                PROCS.lock().get(&pid).map_or(false, |p| p.groups.contains(&gid))
            }
            pub fn process_exists(pid: u64) -> bool {
                PROCS.lock().contains_key(&pid)
            }
            /// Records the signal in `fake::POSTED` instead of delivering it.
            pub fn post_with_info(pid: u64, sig: u32, code: i32, spid: u32, suid: u32, value: u64) -> bool {
                crate::fake::POSTED.with_borrow_mut(|v| v.push((pid, sig, code, spid, suid, value)));
                process_exists(pid)
            }
            pub const ERESTARTSYS: i64 = -512;
            pub fn signal_pending() -> bool {
                crate::fake::SIGNAL_PENDING.get()
            }
            pub const SIGPIPE: u32 = 13;
            /// Records the signal in `fake::POSTED` (with code 0) instead of delivering it.
            pub fn post_thread(pid: u64, _tid: u64, sig: u32) -> bool {
                crate::fake::POSTED.with_borrow_mut(|v| v.push((pid, sig, 0, 0, 0, 0)));
                process_exists(pid)
            }
        }

        /// *stub*
        pub mod ns {
            /// *stub* A process's namespaces: only the PID namespace chain the process
            /// table reads (always the initial namespace on the host).
            #[derive(Clone, Default)]
            pub struct Ns {
                pub pid_inits: alloc::vec::Vec<u64>,
            }
            impl Ns {
                pub fn for_child(&self, _child: u64) -> Ns {
                    self.clone()
                }
            }
            /// No PID namespaces on the host.
            pub fn pid_from_caller(id: u64) -> u64 {
                id
            }
            pub fn ipc_ns() -> u64 {
                crate::fake::IPC_NS.get()
            }
            /// No PID namespaces on the host: ids are shown as they are.
            pub fn pid_to_caller(id: u64) -> u64 {
                id
            }
        }

        /// *stub* Only the user-memory copy helpers, written exactly like the
        /// kernel's: with no current `Mm`, user pointers are host pointers.
        pub mod vfs {
            const EFAULT: i64 = -14;

            /// *mirror* of the kernel's credential snapshot.
            pub(crate) struct Creds {
                pub uid: u32,
                pub gid: u32,
                pub euid: u32,
                pub egid: u32,
            }
            /// The current fake task's ids (root when there is none), as the kernel's.
            pub(crate) fn creds() -> Creds {
                crate::task::with_current_task_mut(|t| Creds { uid: t.uid, gid: t.gid, euid: t.euid, egid: t.egid })
                    .unwrap_or(Creds { uid: 0, gid: 0, euid: 0, egid: 0 })
            }
            /// Socket names in the file system are not supported on the host: binding or
            /// connecting to a path fails as if the directory were missing.
            pub(crate) fn socket_key(_path: &[u8]) -> Result<alloc::vec::Vec<u8>, i64> {
                Err(-2) // ENOENT
            }
            /// Verbatim from the kernel.
            pub(crate) fn socket_ino_key(ino: u64) -> alloc::vec::Vec<u8> {
                alloc::format!("ino:{}", ino).into_bytes()
            }
            pub(crate) fn make_socket_node(_path: &[u8]) -> Result<u64, i64> {
                Err(-2) // ENOENT
            }
            pub(crate) fn path_exists(_path: &[u8]) -> bool {
                false
            }
            pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
                if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
                    return Err(EFAULT);
                }
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
                Ok(())
            }
            /// Verbatim from the kernel.
            pub(crate) fn user_cstr(ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
                if ptr == 0 {
                    return Err(EFAULT);
                }
                let mut out = alloc::vec::Vec::new();
                let mut addr = ptr;
                loop {
                    let page_end = (addr | 0xFFF) + 1;
                    if !crate::memory::vm::prefault_current(addr, page_end - addr, false) {
                        return Err(EFAULT);
                    }
                    while addr < page_end {
                        let b = unsafe { *(addr as *const u8) };
                        if b == 0 {
                            return Ok(out);
                        }
                        out.push(b);
                        if out.len() >= 4096 {
                            return Err(-36); // ENAMETOOLONG
                        }
                        addr += 1;
                    }
                }
            }
            /// Verbatim from the kernel.
            pub(crate) fn user_path(ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
                let p = user_cstr(ptr)?;
                if p.is_empty() {
                    return Err(-2); // ENOENT
                }
                Ok(p)
            }
            /// Path lookup goes straight to the (fake) ZFS client; the real one
            /// also handles mount namespaces and /proc/<pid>/root.
            pub(crate) fn resolve(base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
                crate::fake::ZfsClient::resolve(base, path, follow)
            }
            /// Plain path join (the real one also maps proc/devpts mounts).
            pub(crate) fn join_path(base: &str, path: &[u8]) -> alloc::string::String {
                let p = alloc::string::String::from_utf8_lossy(path);
                if p.starts_with('/') {
                    p.into_owned()
                } else {
                    alloc::format!("{}/{}", base.trim_end_matches('/'), p)
                }
            }
            pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, i64> {
                if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
                    return Err(EFAULT);
                }
                let mut v = alloc::vec![0u8; len];
                unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
                Ok(v)
            }
        }
    }
}

pub mod fs {
    #[path = "../../../../src/fs/pipe.rs"]
    pub mod pipe;

    /// *stub* The kernel's descriptor enum has many more variants; these are
    /// the ones the code under test matches on, with the fields it reads.
    #[derive(Clone)]
    pub enum FileDescriptor {
        EventFd(alloc::sync::Arc<spin::Mutex<crate::compat::linux::eventfd::EventFd>>),
        MemFd { memfd: alloc::sync::Arc<spin::Mutex<crate::compat::linux::memfd::MemFd>>, flags: u32 },
        Vnode(alloc::sync::Arc<spin::Mutex<crate::fake::Vnode>>),
        File { path: alloc::string::String, readable: bool, writable: bool },
        Device(alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>),
        PipeRead(alloc::sync::Arc<spin::Mutex<crate::fs::pipe::PipeBuffer>>),
        PipeWrite(alloc::sync::Arc<spin::Mutex<crate::fs::pipe::PipeBuffer>>),
        Unix(alloc::sync::Arc<crate::compat::linux::unix::UnixSocket>),
    }

    impl FileDescriptor {
        /// *mirror* of the kernel's `FileDescriptor::object_id` for these variants.
        pub fn object_id(&self) -> usize {
            fn of<T: ?Sized>(a: &alloc::sync::Arc<T>) -> usize {
                alloc::sync::Arc::as_ptr(a) as *const u8 as usize
            }
            match self {
                FileDescriptor::EventFd(a) => of(a),
                FileDescriptor::MemFd { memfd, .. } => of(memfd),
                FileDescriptor::Vnode(a) => of(a),
                FileDescriptor::File { path, .. } => path.as_ptr() as usize,
                FileDescriptor::Device(a) => of(a),
                FileDescriptor::PipeRead(a) | FileDescriptor::PipeWrite(a) => of(a),
                FileDescriptor::Unix(a) => of(a),
            }
        }
    }

    /// *stub*
    pub mod client {
        pub use crate::fake::{FileStat, ZfsClient};
        /// *stub* (never called: `with_server` fails first)
        pub fn resolve_parent_in(
            _s: &mut crate::fs::zfs::ZfsServer,
            _root: u64,
            _base: u64,
            _path: &[u8],
        ) -> Result<(u64, alloc::vec::Vec<u8>), i64> {
            Err(-5)
        }
    }
    pub use client::ZfsClient;

    pub mod zfs {
        /// *stub* No pool on the host: the server is never reached.
        pub struct ZfsServer;
        impl ZfsServer {
            pub fn unlink(&mut self, _dir: u64, _name: &[u8]) -> Result<(), i64> {
                Err(-5)
            }
            pub fn mknod(&mut self, _dir: u64, _name: &[u8], _mode: u32, _rdev: u64, _uid: u32, _gid: u32) -> Result<u64, i64> {
                Err(-5)
            }
        }
        /// *stub* Fails with `EIO`, as the kernel's does before the pool is mounted.
        pub fn with_server<R>(_f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
            Err(-5)
        }
        #[path = "../../../../../src/fs/zfs/fsproto.rs"]
        pub mod fsproto;
        #[path = "../../../../../src/fs/zfs/types.rs"]
        pub mod types;
    }
}

pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

pub mod memory {
    #[path = "../../../../src/memory/frame_allocator.rs"]
    pub mod frame_allocator;

    #[path = "../../../../src/memory/vm.rs"]
    pub mod vm;

    /// *stub*
    pub mod paging {
        pub use crate::fake::{make_user_accessible, AddressSpace};
        /// The kernel's own address space does not exist on the host.
        pub static KERNEL_SPACE: spin::Mutex<Option<AddressSpace>> = spin::Mutex::new(None);
    }
}

pub mod net {
    #[path = "../../../../src/net/dns.rs"]
    pub mod dns;

    /// *stub*
    pub use crate::fake::{dhcp_acquire, Interface};
    /// *stub*
    pub static GLOBAL_INTERFACE: spin::Mutex<Interface> = spin::Mutex::new(Interface::new());
    /// *stub*
    pub mod e1000 {
        pub use crate::fake::nic_present as is_present;
    }

    #[path = "../../../../src/net/arp.rs"]
    pub mod arp;
    #[path = "../../../../src/net/dhcp.rs"]
    pub mod dhcp;
    #[path = "../../../../src/net/ethernet.rs"]
    pub mod ethernet;
    #[path = "../../../../src/net/icmp.rs"]
    pub mod icmp;
    #[path = "../../../../src/net/ipv4.rs"]
    pub mod ipv4;
    #[path = "../../../../src/net/tcp.rs"]
    pub mod tcp;
    #[path = "../../../../src/net/udp.rs"]
    pub mod udp;
}

pub mod pkg {
    #[path = "../../../../src/pkg/ar.rs"]
    pub mod ar;
    #[path = "../../../../src/pkg/tar.rs"]
    pub mod tar;
}

pub mod shell {
    /// Stand-in for the kernel's `ShellState`; `command.rs` only names the
    /// type in the `Command` trait signature.
    pub mod state {
        pub struct ShellState;
    }

    /// *stub*
    pub mod fs {
        pub use crate::fake::read_boot_file;
    }

    #[path = "../../../../src/shell/command.rs"]
    pub mod command;
    #[path = "../../../../src/shell/history.rs"]
    pub mod history;
}

pub mod task {
    #[path = "../../../../src/task/elf.rs"]
    pub mod elf;
    #[path = "../../../../src/task/exec.rs"]
    pub mod exec;

    /// *stub*
    pub mod scheduler {
        pub const DEFAULT_STACK_SIZE: usize = 65536;
    }
    /// *stub*
    pub use crate::fake::wait;
    /// *stub*
    pub mod tcb {
        pub use crate::fake::Caps;
    }
    /// *stub* The fake clock moves instead (nothing sleeps on the host).
    pub fn sleep_ticks(ticks: u64) {
        crate::fake::TICKS.set(crate::fake::TICKS.get() + ticks);
    }
    /// *stub* A thread group's exit ends the test with a panic it can catch.
    pub fn exit_group() -> ! {
        panic!("exit_group")
    }
    /// *stub*
    pub use crate::fake::{is_task_alive, with_current_fds_mut, with_current_task_mut, Task, TaskId, SCHEDULER};
}

pub mod video {
    #[path = "../../../../src/video/font.rs"]
    pub mod font;
}
