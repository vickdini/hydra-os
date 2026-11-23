//! *stub* `crate::lx`: the forwarding to the ring-3 Linux server. Notes and calls are
//! recorded; nothing is forwarded.

use crate::arch::syscall::SyscallFrame;

/// *stub* A notification for the Linux server (recorded).
// wave8 GX2 begin: *stub* the desktop set (`src/lx/desktop.rs`)
pub mod desktop {
    pub fn inherit(_parent: u64, _child: u64) {}
    pub fn mark(_pid: u64) {}
    pub fn root_started(_pid: u64) {}
    pub fn expect_root() {}
    pub fn cancel_root() {}
}
// wave8 GX2 end
pub fn note(kind: u64, a: u64, b: u64, c: u64) {
    crate::fake::rec(alloc::format!("lx::note({kind},{a},{b},{c})"));
}
/// *stub* Nothing is forwarded unless a test sets `fake::LX_FORWARD`.
pub fn forward(frame: &SyscallFrame) -> Option<i64> {
    crate::fake::LX_FORWARD.with_borrow(|m| m.get(&frame.rax).copied())
}
pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    crate::fake::rec(alloc::format!("lx::call_plain({nr},{:?})", args));
    crate::fake::ret("lx::call_plain")
}
pub fn step4() -> bool {
    false
}
pub fn summary() -> alloc::string::String {
    alloc::string::String::new()
}
pub mod mem {
    pub fn server_mmap(
        _dev: &alloc::sync::Arc<dyn crate::compat::linux::chardev::CharDevice>,
        _args: [u64; 6],
    ) -> Result<(alloc::sync::Arc<dyn crate::memory::vm::MappedObject>, i64, u64), i64> {
        Err(-19) // ENODEV
    }
}
pub mod obj {
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
/// *stub* `crate::lx::svc` (wave 7, Group 7-3's namespace notes ask who hosts vfs-server):
/// nothing hosts anything, unless a test sets `fake::set_ret("lx::vfs_host", host)` (then
/// vfs-server, endpoint 0x2D, hosts the file service on that host).
pub mod svc {
    pub fn host_of(_svc: crate::ipc::protocol::SvcId) -> crate::ipc::protocol::SvcId {
        crate::fake::ret("lx::vfs_host") as crate::ipc::protocol::SvcId
    }
    pub fn endpoint_of(_svc: crate::ipc::protocol::SvcId) -> u32 {
        if crate::fake::ret("lx::vfs_host") != 0 { crate::ipc::protocol::ENDPOINT_VFS_SERVER } else { 0 }
    }
}
/// *stub* A notification for one host (recorded).
pub fn note_to(h: crate::ipc::protocol::SvcId, kind: u64, a: u64, b: u64, c: u64) {
    crate::fake::rec(alloc::format!("lx::note_to({h},{kind},{a},{b},{c})"));
}

/// wave7 G7-5: `crate::lx::xexec`: the real plan type (`xplan.rs`); the front half answers
/// what a test put in `fake::EXEC_FRONT` (recorded).
#[path = "../../../src/lx/xplan.rs"]
pub mod xplan;
pub mod xexec {
    pub use super::xplan::{decode_plan, ExecPlan};
    pub fn front(dirfd: i64, path: &[u8], flags: u64) -> Option<Result<ExecPlan, i64>> {
        crate::fake::rec(alloc::format!("xexec::front({dirfd},{},{flags})", alloc::string::String::from_utf8_lossy(path)));
        crate::fake::EXEC_FRONT.with_borrow(|m| m.clone())
    }
    /// *stub* wave7 G7-7: the `[prof] execve` line.
    pub fn summary() -> alloc::string::String {
        alloc::string::String::new()
    }
}
/// *stub* wave7 G7-7: the `[prof] vfs:` line.
pub mod fileh {
    pub fn summary() -> alloc::string::String {
        alloc::string::String::new()
    }
    /// *stub* wave9 G9-C: the prof line of calls by number.
    pub fn kernel_by_nr(_n: usize) -> alloc::string::String {
        alloc::string::String::new()
    }
}

// wave9 G7a: the kernel's process-identity primitives, compiled for real
#[path = "../../../src/lx/proc.rs"]
pub mod proc;
// wave9 G6b-1 begin: *stub* the kernel's events for vfs-server's inotify/fanotify
// (`lx::notifyfwd`): vfs-server wants none here
pub mod notifyfwd {
    pub fn want_zfs() -> bool {
        false
    }
    pub fn want_close_write() -> bool {
        false
    }
    pub fn want_fan() -> bool {
        false
    }
    pub fn zfs_event(_ino: u64, _mask: u32, _cookie: u32, _name: &[u8]) {}
    pub fn file_event(_ino: u64, _dir: u64, _path: &str, _mask: u64, _is_dir: bool) {}
    pub fn on_open(_ino: u64, _dir: u64, _path: &str, _is_dir: bool, _exec: bool) -> Result<(), i64> {
        Ok(())
    }
    pub fn parent_of(_path: &str) -> u64 {
        0
    }
}
// wave9 G6b-1 end
