//! Host build of Group 28's kernel files: the Linux device layer.
//!
//! Each kernel file is compiled through `#[path]` under the module path the kernel uses,
//! so `crate::` and `super::` references inside it resolve unchanged; nothing is copied.
//! Real kernel code here: `compat/linux/{blockdev, chardev, devices, drm, evdev, memfd,
//! misc, pty, snd, tty, types}.rs`, `memory/frame_allocator.rs`, `fs/gpt.rs`,
//! `fs/zfs/{fsproto, types}.rs`, `ipc/{message, protocol}.rs` and `capability/mod.rs`.
//!
//! Everything else those files call is a stand-in from [`fake`] (marked *stub*), placed at
//! the same `crate::` path: the scheduler, the descriptor table, the console and display,
//! PCI, the disks, the sound driver service and an in-memory ZFS file server.
//!
//! Paths inside an inline `mod` block are resolved relative to a directory named after
//! that module, hence the extra `../` per nesting level.

#![allow(dead_code, unused_imports, clippy::all)]

extern crate alloc;

pub mod fake;

/// *stub* Kernel log output; discarded on the host.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

/// *stub* Kernel console output; discarded on the host.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

pub mod arch {
    /// *stub*
    pub mod pit {
        pub use crate::fake::{frequency_hz, now_ns, ticks};
    }
    /// *stub*
    pub mod rtc {
        pub use crate::fake::wall_base_ns;
    }
    /// *stub* One CPU on the host.
    pub mod percpu {
        pub fn cpu() -> usize {
            0
        }
    }
    /// *stub* PCI configuration space from `fake::PCI`/`fake::PCI_CONFIG`.
    pub mod pci {
        pub use crate::fake::{find_class, pci_read_u32, pci_read_u8, PciDevice};
        pub const PCI_REG_REVISION: u8 = 0x08;
    }
    /// *stub*
    pub mod bootdisk {
        pub use crate::fake::{boot_info as info, BootInfo};
    }
    /// *stub* The QEMU absolute pointer (`fake::VMMOUSE`).
    pub mod vmmouse {
        pub const MAX: u32 = 0xFFFF;
        pub fn present() -> bool {
            crate::fake::VMMOUSE.get()
        }
    }
    /// *stub*
    pub mod iommu {
        pub fn map_dma(_endpoint: u32, _phys: u64, _len: u64) -> Result<(), ()> {
            if crate::fake::IOMMU_FAILS.get() {
                Err(())
            } else {
                Ok(())
            }
        }
    }
    /// *stub* The kernel never moved to the higher half on the host.
    pub mod relocate {
        pub fn image_phys() -> Option<(u64, u64)> {
            None
        }
    }
}

#[path = "../../../src/capability/mod.rs"]
pub mod capability;

/// *stub* The text console (`fake::CONSOLE_OUT`, `fake::KEYS`).
pub mod console {
    pub use crate::fake::{print_raw, read_key};
}

/// *stub* The boot framebuffer (`fake::DISPLAY`).
pub mod video {
    pub use crate::fake::{get_video_info, VideoModeInfo};
    pub mod console {
        pub use crate::fake::{dimensions, panicked, reclaim_display, release_display};
    }
}

/// *stub*
pub mod net {
    pub use crate::fake::{iface, IfaceInfo};
}

pub mod ipc {
    #[path = "../../../../src/ipc/message.rs"]
    pub mod message;
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
    // wave8 GI: the raw input ring (real) and a host stand-in for `ipc/input.rs`
    #[path = "../../../../src/ipc/input_ring.rs"]
    pub mod input_ring;
    pub mod input {
        include!("input_stub.rs");
        /// Never reached on the host (`forwarded()` is false).
        pub fn open(_rdev: u64, _flags: u32) -> Result<alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>, i64> {
            Err(-19)
        }
    }
    pub use message::Message;
    /// *stub* The driver service layer (`fake::SOUND`).
    pub use crate::fake::service;

    // wave8 GS begin
    /// *stub* The sound service's kernel side: its buffers (as `snd.rs` allocated them
    /// before wave 8), never forwarded (the in-kernel layer under test).
    pub mod sound {
        use super::service::ContiguousFrames;
        use alloc::sync::Arc;
        pub struct Buffers {
            pub pos: Arc<ContiguousFrames>,
            pub rings: [Option<Arc<ContiguousFrames>>; 2],
            pub status: Arc<ContiguousFrames>,
        }
        static B: spin::Once<Option<Buffers>> = spin::Once::new();
        pub fn buffers() -> Option<&'static Buffers> {
            B.call_once(|| Some(Buffers { pos: ContiguousFrames::allocate(1)?, rings: [ContiguousFrames::allocate(128), ContiguousFrames::allocate(128)], status: ContiguousFrames::allocate(1)? })).as_ref()
        }
        pub fn ring(dir: usize) -> Option<&'static Arc<ContiguousFrames>> {
            buffers()?.rings.get(dir)?.as_ref()
        }
        pub fn forwarded() -> bool {
            false
        }
        pub fn status(_dir: usize) -> Option<super::protocol::SndStatus> {
            None
        }
    }
    #[path = "../../../../src/ipc/sound_page.rs"]
    pub mod sound_page;
    // wave8 GS end
}

pub mod memory {
    #[path = "../../../../src/memory/frame_allocator.rs"]
    pub mod frame_allocator;

    /// *stub* The parts of `memory/vm.rs` the device files use: the mapped-object trait
    /// (verbatim), the page size and the user-memory check (host pointers, see
    /// `fake::prefault_current`).
    pub mod vm {
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        pub const PAGE_SIZE: u64 = 4096;
        pub const LOW_USER_END: u64 = 1 << 30;
        pub use crate::fake::prefault_current;

        pub trait MappedObject: Send + Sync {
            fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>>;
            fn tracks_writes(&self) -> bool {
                false
            }
            fn page_written(&self, _pgoff: u64) {}
            fn sync(&self) {}
        }
    }
}

pub mod fs {
    #[path = "../../../../src/fs/gpt.rs"]
    pub mod gpt;

    /// *stub* The disks (`fake::DISKS`).
    pub use crate::fake::blockdev;

    /// *stub* The descriptor kinds the device files create or look at.
    #[derive(Clone)]
    pub enum FileDescriptor {
        Device(alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>),
        /// Anything else.
        Other,
    }

    pub use crate::fake::ZfsClient;

    pub mod zfs {
        #[path = "../../../../../src/fs/zfs/fsproto.rs"]
        pub mod fsproto;
        #[path = "../../../../../src/fs/zfs/types.rs"]
        pub mod types;
        /// *stub* An in-memory file server (`fake::FS`).
        pub use crate::fake::zfs::{with_server, ZfsServer};
        /// The ZPL's types, under the path the kernel uses.
        pub mod zpl {
            pub use super::fsproto::{Attr, ReaddirEntry, SetAttr};
        }
    }
}

pub mod task {
    /// *stub* The running thread (`snd`'s driver thread boost reads it).
    pub static CURRENT_TID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    /// *mirror* of `src/task/tcb.rs`'s priorities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum TaskPriority {
        Idle = 0,
        Low = 1,
        Normal = 2,
        High = 3,
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
        /// *mirror*
        pub fn is_posix(self) -> bool {
            self != TaskPersonality::Hydra
        }
    }

    /// *stub*
    pub mod scheduler {
        pub const DEFAULT_TIMESLICE_TICKS: u32 = 5;
    }
    /// *stub*
    pub use crate::fake::wait;
    /// *stub*
    pub use crate::fake::{sleep_ms, spawn, with_current_fds_mut, with_current_task_mut, Task, TaskId, SCHEDULER};
}

/// *stub* The ring-3 Linux server's hooks.
pub mod lx {
    // wave8 GH: the device records' type (`devices.rs`)
    #[path = "../../../../src/lx/uevent.rs"]
    pub mod uevent;
    /// *stub* wave8 GT: `crate::lx::console` (the terminals are never tty-server's here, so
    /// the in-kernel copies run; the rest is never reached).
    pub mod console {
        pub fn forwarded() -> bool {
            false
        }
        pub fn attach(_sid: u64, _pgrp: u64) {}
        pub fn detach() {}
        pub fn attached() -> bool {
            false
        }
        pub fn readable() -> bool {
            false
        }
        pub fn read(_buf: u64, _len: usize, _nonblock: bool) -> i64 {
            -5
        }
        pub fn write(_buf: u64, len: usize) -> i64 {
            len as i64
        }
        pub fn ioctl(_request: u64, _arg: u64) -> i64 {
            -25
        }
        pub fn open_pty<T>(_abs: &str, _flags: u32) -> Option<Result<T, i64>> {
            None
        }
        pub fn pty_stat(_index: u64) -> Result<(u32, u32, u32), i64> {
            Err(-2)
        }
        pub fn pty_setattr(_index: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>) -> i64 {
            -2
        }
        pub fn hangup(_sid: u64) -> Option<(u64, u64)> {
            None
        }
    }
    /// *stub* A Linux service claims a major when `fake::LX_DEV_OPEN` says so.
    pub fn dev_open(_rdev: u64, _flags: u32) -> Option<Result<alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>, i64>> {
        crate::fake::LX_DEV_OPEN.get().map(Err)
    }
    pub mod obj {
        /// *stub*
        pub struct ServerObject;
    }
}

pub mod compat {
    pub mod linux {
        #[path = "../../../../../src/compat/linux/blockdev.rs"]
        pub mod blockdev;
        #[path = "../../../../../src/compat/linux/chardev.rs"]
        pub mod chardev;
        #[path = "../../../../../src/compat/linux/devices.rs"]
        pub mod devices;
        #[path = "../../../../../src/compat/linux/drm.rs"]
        pub mod drm;
        #[path = "../../../../../src/compat/linux/evdev.rs"]
        pub mod evdev;
        #[path = "../../../../../src/compat/linux/memfd.rs"]
        pub mod memfd;
        #[path = "../../../../../src/compat/linux/misc.rs"]
        pub mod misc;
        #[path = "../../../../../src/compat/linux/pty.rs"]
        pub mod pty;
        #[path = "../../../../../src/compat/linux/snd.rs"]
        pub mod snd;
        #[path = "../../../../../src/compat/linux/tty.rs"]
        pub mod tty;
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        /// *stub* System call tracing switch (`linux trace`).
        pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

        /// *stub* The user-memory copies, written as the kernel's (user pointers are host
        /// pointers), and the two calls `misc.rs` forwards.
        pub mod vfs {
            const EFAULT: i64 = -14;
            pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
                if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
                    return Err(EFAULT);
                }
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
                Ok(())
            }
            pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, i64> {
                if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
                    return Err(EFAULT);
                }
                let mut v = alloc::vec![0u8; len];
                unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
                Ok(v)
            }
            /// *stub* Records the call (`fake::SET_TIMES`).
            pub(crate) fn set_times(dirfd: i64, path_ptr: u64, times: Option<[(i64, u32); 2]>) -> i64 {
                crate::fake::SET_TIMES.with_borrow_mut(|v| v.push((dirfd, path_ptr, times)));
                0
            }
            /// *stub* Only `getdents64` (217), scripted by `fake::GETDENTS64`.
            pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
                if num != 217 {
                    return None;
                }
                let (r, data) = crate::fake::GETDENTS64.with_borrow(|g| g.clone())?;
                if r > 0 {
                    copy_out(a[1], &data).ok()?;
                }
                Some(r)
            }
        }

        /// *stub* The process table and signals.
        pub mod proc {
            pub use crate::fake::{current_ids, post_group, session_of, Process, PROCS};
            pub const ERESTARTSYS: i64 = -512;
            pub const SIGINT: u32 = 2;
            pub const SIGQUIT: u32 = 3;
            pub const SIGTSTP: u32 = 20;
            pub const SIGTTIN: u32 = 21;
            pub const SIGWINCH: u32 = 28;
            pub fn signal_pending() -> bool {
                crate::fake::SIGNAL_PENDING.get()
            }
            pub fn ignores_or_blocks(_sig: u32) -> bool {
                crate::fake::IGNORES.get()
            }
            pub fn cpu_times(_pid: u64) -> (u64, u64, u64, u64) {
                crate::fake::CPU_TIMES.get()
            }
            pub fn process_exists(pid: u64) -> bool {
                PROCS.lock().contains_key(&pid)
            }
        }

        /// *stub* No PID namespaces on the host.
        pub mod ns {
            pub fn pid_from_caller(id: u64) -> u64 {
                id
            }
        }

        /// *stub*
        pub mod extra {
            pub(crate) use crate::fake::reapply_priority;
        }

        /// *stub* The one item `devices.rs` reads from the pseudo-file module.
        pub mod fs {
            pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
        }

        /// *stub* `/dev/fuse`.
        pub mod fuse {
            pub const RDEV: u64 = super::chardev::makedev(10, 229);
            pub struct Conn;
            /// *stub* Recognisable errno: -1229.
            pub fn open(_flags: u32) -> Result<alloc::sync::Arc<dyn super::chardev::CharDevice>, i64> {
                Err(-1229)
            }
        }

        /// *stub* `/dev/kmsg`.
        pub mod admin {
            /// *stub* Recognisable errno: -1011.
            pub fn kmsg_open(_flags: u32) -> Result<alloc::sync::Arc<dyn super::chardev::CharDevice>, i64> {
                Err(-1011)
            }
        }

        /// *stub* Netlink sockets.
        pub mod netlink {
            /// *stub* Recognisable result: 4141.
            pub fn socket(_a: [u64; 6]) -> Option<i64> {
                Some(4141)
            }
        }

        /// *stub* (`fake::LIVE`)
        pub mod live {
            pub fn is_live() -> bool {
                crate::fake::LIVE.get()
            }
        }

        /// *stub* Records the root (`fake::ABAC_LOADS`).
        pub mod abac {
            pub fn boot_load(root: &str) {
                crate::fake::ABAC_LOADS.with_borrow_mut(|v| v.push(root.into()));
            }
        }

        /// *stub* The UEFI variables (`fake::EFIVARS`).
        pub mod efivars {
            pub const DIR: &str = "/sys/firmware/efi/efivars";
            pub static DIR_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            pub fn snapshot() -> Option<alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>> {
                crate::fake::EFIVARS.with_borrow(|e| e.clone())
            }
        }

        /// *stub* The page cache (nothing to shrink on the host).
        pub mod mm {
            pub fn cache_shrink(_pages: usize) {}
        }

        /// *stub* Types the `CharDevice` trait names.
        pub mod mqueue {
            pub struct MqHandle;
        }
        pub mod perf {
            pub struct Event;
        }
        pub mod fanotify {
            pub struct Group;
        }
        pub mod mount {
            pub struct MountObj;
        }
        pub mod io_uring {
            pub struct Ring;
        }
        pub mod landlock {
            pub struct Ruleset;
        }
        pub mod bpf {
            pub struct Obj;
        }
    }
}
