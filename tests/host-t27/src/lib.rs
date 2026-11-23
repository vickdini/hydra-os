//! Host build of Group 27's kernel files (test wave): Linux sockets, network, polling,
//! timers and io_uring.
//!
//! Each module below compiles the kernel's own source file through `#[path]`, laid out under
//! the same module path the kernel uses, so `crate::` and `super::` references inside those
//! files resolve unchanged. Nothing is copied: the tests in `tests/` exercise exactly the code
//! that ships.
//!
//! Where a kernel file calls into the scheduler, the descriptor table, the process table,
//! net-server's client or the frame allocator, the callee is a stand-in from [`fake`],
//! placed at the same `crate::` path. Items marked *stub* are those stand-ins; everything
//! else is real kernel code.
//!
//! Paths inside an inline `mod` block are resolved relative to a directory named after that
//! module, hence the extra `../` per nesting level.

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
    /// *stub* The fake clock (100 Hz, as the kernel programs the PIT).
    pub mod pit {
        pub use crate::fake::{frequency_hz, now_ns, tick_ns, ticks};
    }
    /// *stub* The wall clock: a fixed instant plus the fake boot clock.
    pub mod rtc {
        pub use crate::fake::rtc_now as now;
    }
    /// *stub* The saved user registers at syscall entry (same fields and order as the kernel).
    pub mod syscall {
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

pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

pub mod compat {
    pub mod linux {
        // ---------------------------------------------------------- the files under test
        #[path = "../../../../../src/compat/linux/epoll.rs"]
        pub mod epoll;
        #[path = "../../../../../src/compat/linux/eventfd.rs"]
        pub mod eventfd;
        #[path = "../../../../../src/compat/linux/inet.rs"]
        pub mod inet;
        #[path = "../../../../../src/compat/linux/io_uring.rs"]
        pub mod io_uring;
        #[path = "../../../../../src/compat/linux/itimer.rs"]
        pub mod itimer;
        #[path = "../../../../../src/compat/linux/netlink.rs"]
        pub mod netlink;
        #[path = "../../../../../src/compat/linux/pidfd.rs"]
        pub mod pidfd;
        #[path = "../../../../../src/compat/linux/ptimer.rs"]
        pub mod ptimer;
        #[path = "../../../../../src/compat/linux/rtnetlink.rs"]
        pub mod rtnetlink;
        #[path = "../../../../../src/compat/linux/select.rs"]
        pub mod select;
        #[path = "../../../../../src/compat/linux/signalfd.rs"]
        pub mod signalfd;
        #[path = "../../../../../src/compat/linux/socket.rs"]
        pub mod socket;
        #[path = "../../../../../src/compat/linux/sockopt.rs"]
        pub mod sockopt;
        #[path = "../../../../../src/compat/linux/timerfd.rs"]
        pub mod timerfd;
        #[path = "../../../../../src/compat/linux/unix.rs"]
        pub mod unix;

        // ---------------------------------------------------------- real, not ours
        #[path = "../../../../../src/compat/linux/types.rs"]
        pub mod types;

        // ---------------------------------------------------------- stand-ins
        /// *stub* A system call made from inside the kernel on the program's behalf (io_uring
        /// requests): answered by the test's handler ([`crate::fake::NESTED`]).
        pub(crate) fn nested(_frame: &crate::arch::syscall::SyscallFrame, num: u64, args: [u64; 6]) -> i64 {
            crate::fake::nested(num, args)
        }

        /// *stub* (wave9 G6b-4) The identity caches are stale: counted in
        /// [`crate::fake::IDENT_CHANGES`].
        pub fn ident_changed() {
            crate::fake::IDENT_CHANGES.set(crate::fake::IDENT_CHANGES.get() + 1);
        }

        /// *stub* `nested_routed` (wave9 G6b-4): the same handler as [`nested`] (routing
        /// is `lx::uring`, tested in host-t30).
        pub(crate) fn nested_routed(frame: &crate::arch::syscall::SyscallFrame, num: u64, args: [u64; 6]) -> i64 {
            nested(frame, num, args)
        }

        /// *stub* The process table and signal delivery, as far as these files use them.
        pub mod proc {
            pub use crate::fake::proc::*;
        }

        /// *stub*
        pub mod ns {
            pub fn net_isolated() -> bool {
                crate::fake::NET_ISOLATED.get()
            }
            /// No PID namespaces on the host.
            pub fn pid_to_caller(id: u64) -> u64 {
                id
            }
            pub fn pid_from_caller(id: u64) -> u64 {
                id
            }
        }

        /// *stub* Landlock's port rules: ports in [`crate::fake::LANDLOCK_DENY`] are refused.
        pub mod landlock {
            pub const BIND_TCP: u64 = 1;
            pub const CONNECT_TCP: u64 = 2;
            pub fn check_port(port: u16, want: u64) -> Result<(), i64> {
                if crate::fake::LANDLOCK_DENY.with_borrow(|v| v.contains(&(port, want))) {
                    Err(-13)
                } else {
                    Ok(())
                }
            }
            /// *stub* (never constructed on the host)
            pub struct Ruleset;
        }

        /// *stub* The terminal layer: `select` pumps it before each check.
        pub mod tty {
            pub fn pump() {
                crate::fake::TTY_PUMPS.set(crate::fake::TTY_PUMPS.get() + 1);
            }
        }

        /// *mirror* of the kernel's futex timeout conversion (`deadline_tick`), on the fake
        /// clock.
        pub mod futex {
            pub(crate) fn deadline_tick(ts_ptr: u64, relative: bool, realtime: bool) -> Result<Option<u64>, i64> {
                let tick = crate::arch::pit::tick_ns();
                Ok(deadline_ns(ts_ptr, relative, realtime)?.map(|d| d.div_ceil(tick)))
            }
            pub(crate) fn deadline_ns(ts_ptr: u64, relative: bool, realtime: bool) -> Result<Option<u64>, i64> {
                if ts_ptr == 0 {
                    return Ok(None);
                }
                if !crate::memory::vm::prefault_current(ts_ptr, 16, false) {
                    return Err(-14);
                }
                let s = unsafe { core::ptr::read_unaligned(ts_ptr as *const i64) };
                let ns = unsafe { core::ptr::read_unaligned((ts_ptr + 8) as *const i64) };
                if s < 0 || !(0..1_000_000_000).contains(&ns) {
                    return Err(-22);
                }
                let total_ns = s as i128 * 1_000_000_000 + ns as i128;
                let now = crate::arch::pit::now_ns() as i128;
                let target_ns = if relative {
                    now + total_ns
                } else if realtime {
                    let (rs, rns) = crate::arch::rtc::now();
                    let offset = rs as i128 * 1_000_000_000 + rns as i128 - now;
                    total_ns - offset
                } else {
                    total_ns
                };
                Ok(Some(target_ns.max(0) as u64))
            }
        }

        /// *stub* The kernel's `CharDevice` trait, cut down to the methods the code under test
        /// calls or implements (same names, signatures and defaults).
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
                fn socket_call(&self, _num: u64, _a: [u64; 6]) -> Option<i64> {
                    None
                }
                fn deliver_notification(&self, _data: &[u8]) -> bool {
                    false
                }
                fn as_io_uring(&self) -> Option<Arc<super::io_uring::Ring>> {
                    None
                }
                fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
                    None
                }
                fn edges(&self) -> Option<u64> {
                    None
                }
            }
        }

        /// *stub* The user-memory helpers and socket-name lookups, written like the kernel's:
        /// with no address space, user pointers are host pointers.
        pub mod vfs {
            pub use crate::fake::vfs::*;
        }
    }
}

pub mod fs {
    #[path = "../../../../src/fs/pipe.rs"]
    pub mod pipe;

    /// *mirror* of the kernel's descriptor-table limit.
    pub const MAX_FDS: usize = 1024;

    pub use crate::fake::fd::FileDescriptor;

    /// *stub*
    pub mod client {
        /// *stub* The parent of `path`: the root, and the last component.
        pub fn resolve_parent_in(
            _s: &mut crate::fs::zfs::ZfsServer,
            _root: u64,
            _base: u64,
            path: &[u8],
        ) -> Result<(u64, alloc::vec::Vec<u8>), i64> {
            let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
            Ok((1, name.to_vec()))
        }
    }

    pub mod zfs {
        /// *stub* The pool, when [`crate::fake::ZFS_MKNOD`] provides one.
        pub struct ZfsServer;
        impl ZfsServer {
            pub fn unlink(&mut self, _dir: u64, _name: &[u8]) -> Result<(), i64> {
                Err(-2)
            }
            pub fn mknod(&mut self, _dir: u64, _name: &[u8], _mode: u32, _rdev: u64, _uid: u32, _gid: u32) -> Result<u64, i64> {
                crate::fake::ZFS_MKNOD.get().ok_or(-5)
            }
        }
        /// *stub* Fails with `EIO`, as the kernel's does before the pool is mounted, unless
        /// a test provides a pool.
        pub fn with_server<R>(f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
            if crate::fake::ZFS_MKNOD.get().is_none() {
                return Err(-5);
            }
            f(&mut ZfsServer)
        }
    }
}

/// *stub* The forwarding to the ring-3 Linux server.
pub mod lx {
    /// *stub* Forwarded calls on server objects: recorded, answered with [`crate::fake::LX_RESULT`].
    pub fn call_obj(nr: u64, args: [u64; 6], _dev: &alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>) -> i64 {
        crate::fake::LX_CALLS.with_borrow_mut(|v| v.push((nr, args, None)));
        crate::fake::LX_RESULT.get()
    }
    /// *stub*
    pub fn call_obj_ino(nr: u64, args: [u64; 6], _dev: &alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>, ino: u64) -> i64 {
        crate::fake::LX_CALLS.with_borrow_mut(|v| v.push((nr, args, Some(ino))));
        crate::fake::LX_RESULT.get()
    }
    pub mod obj {
        /// *stub* A linux-server object: its kind and tag are what the code under test reads.
        pub struct ServerObject {
            pub kind: u32,
            pub tag: u64,
        }
        impl ServerObject {
            pub fn kind(&self) -> u32 {
                self.kind
            }
            pub fn tag(&self) -> u64 {
                self.tag
            }
        }
        /// *stub* A deferred eventfd write: recorded in [`crate::fake::LX_WRITES`].
        pub fn write_later(_dev: alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>, n: u64) {
            crate::fake::LX_WRITES.with_borrow_mut(|v| v.push(n));
        }
    }
}

pub mod memory {
    /// *stub* User memory: host memory; [`crate::fake::BAD_PTRS`] ranges fault.
    pub mod vm {
        pub use crate::fake::prefault_current;
        /// *mirror* of the kernel's mappable-object trait.
        pub trait MappedObject: Send + Sync {
            fn get_page(&self, pgoff: u64) -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>>;
        }
    }
    /// *stub* Frames are host pages (a frame's "physical" address is its host address).
    pub mod frame_allocator {
        pub use crate::fake::{alloc_user_frame, frame_ref_dec, phys_to_virt};
    }
}

/// *stub* The parts of the network client (`src/net/client.rs`) and `net::iface` the socket
/// code calls, backed by a scripted net-server ([`crate::fake::net`]).
pub mod net {
    pub use crate::fake::net::{iface, IfaceInfo};
    pub mod client {
        pub use crate::fake::net::*;
    }
}

pub mod task {
    pub use crate::fake::task::*;
    pub mod wait {
        pub use crate::fake::wait::*;
    }
}
