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
        pub use crate::fake::{frequency_hz, now_ns, sleep_ms, ticks, uptime_ms};
    }
    /// *stub* Deterministic bytes instead of RDRAND.
    pub mod random {
        pub use crate::fake::random_fill as fill;
    }
    /// *stub* The kernel indexes per-CPU slots by `gs:[8]`, which a host
    /// process cannot use; the host behaves as a single CPU.
    pub mod percpu {
        pub use crate::fake::PerCpuPtr;
    }
    /// *stub*
    pub mod rtc {
        pub use crate::fake::rtc_now as now;
    }
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
            pub use crate::fake::seccomp_stop;
        }
        #[path = "../../../../../src/compat/linux/sysv.rs"]
        pub mod sysv;
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        #[path = "../../../../../src/compat/linux/userfaultfd.rs"]
        pub mod userfaultfd;

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
        }

        /// *stub*
        pub mod ns {
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
        File { path: alloc::string::String, readable: bool },
        Device(alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>),
    }

    /// *stub*
    pub mod client {
        pub use crate::fake::{FileStat, ZfsClient};
    }
    pub use client::ZfsClient;

    pub mod zfs {
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
    pub use crate::fake::{with_current_fds_mut, with_current_task_mut, TaskId, SCHEDULER};
}

pub mod video {
    #[path = "../../../../src/video/font.rs"]
    pub mod font;
}
