//! # Hydra ZFS file server
//!
//! Hydra's OpenZFS implementation (pool, DMU, ZAP directories, POSIX layer), in Ring 3 in
//! an address space of its own. It owns the pool: it imports it at startup through the disk
//! driver (`ata-driver`, whose service window it attaches) and answers the kernel's file
//! system requests on [`ENDPOINT_ZFS_SERVER`] (see `zfs/fsproto.rs` for the protocol).
//!
//! The ZFS sources were the kernel's; the modules below this comment give them what the
//! kernel gave them: 4 KiB buffers for the block cache (heap pages instead of physical
//! frames), the clock, the disk driver, and inotify (events are collected per request and
//! handed back to the kernel, which delivers them to its watchers).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use hydra_rt::protocol::ENDPOINT_ZFS_SERVER;
use hydra_rt::{sys, Message, Server};

hydra_rt::entry!(main);

/// Prints to the console (the ZFS sources' `println!`).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { hydra_rt::println!($($arg)*) };
}

/// Prints to the console (the ZFS sources' `kprintln!`).
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => { hydra_rt::println!($($arg)*) };
}

/// The OpenZFS implementation.
pub mod zfs {
    /// On-disk structures, shared with the kernel.
    #[path = "../../../../../src/fs/zfs/types.rs"]
    pub mod types;
    /// The kernel's requests and their encoding, shared with the kernel.
    #[path = "../../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
    pub mod dmu;
    pub mod selftest;
    pub mod server;
    pub mod spa;
    pub mod zap;
    pub mod zpl;
}

/// Path resolution over the server (the kernel's `fs::client` helpers).
pub mod fs {
    pub mod client {
        use crate::zfs::fsproto::{ELOOP, ENOENT, ENOTDIR, EEXIST};
        use crate::zfs::server::ZfsServer;
        use crate::zfs::types::DnodeType;
        use alloc::vec::Vec;

        /// Symbolic links followed in one path at most (Linux `MAXSYMLINKS`).
        const SYMLOOP_MAX: usize = 40;

        fn components(path: &[u8]) -> Vec<Vec<u8>> {
            path.split(|&c| c == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
        }

        /// Resolves `path` relative to `base` (the pool root for absolute paths).
        pub fn resolve_at(s: &mut ZfsServer, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
            let root = s.root_obj();
            resolve_in(s, root, base, path, follow_last)
        }

        /// Resolves `path` inside the `root` directory (a `chroot`), expanding symbolic links
        /// in every component and, when `follow_last` or with a trailing `/`, in the last.
        pub fn resolve_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
            if path.is_empty() {
                return Err(ENOENT);
            }
            let follow_last = follow_last || path.ends_with(b"/");
            let mut cur = if path[0] == b'/' { root } else { base };
            let mut pending: Vec<Vec<u8>> = components(path);
            pending.reverse();
            let mut links = 0;
            while let Some(comp) = pending.pop() {
                if comp == b".." {
                    cur = if cur == root { root } else { s.lookup(cur, b"..")? };
                    continue;
                }
                let next = s.lookup(cur, &comp)?;
                let is_last = pending.is_empty();
                let attr = s.getattr(next)?;
                if attr.kind() == DnodeType::Symlink && (!is_last || follow_last) {
                    links += 1;
                    if links > SYMLOOP_MAX {
                        return Err(ELOOP);
                    }
                    let target = s.readlink(next)?;
                    if target.first() == Some(&b'/') {
                        cur = root;
                    }
                    let mut more = components(&target);
                    more.reverse();
                    pending.extend(more);
                    continue;
                }
                if !is_last && !attr.is_dir() {
                    return Err(ENOTDIR);
                }
                cur = next;
            }
            if path.ends_with(b"/") && !s.getattr(cur)?.is_dir() {
                return Err(ENOTDIR);
            }
            Ok(cur)
        }

        /// Resolves the parent directory of `path` and returns it with the last component.
        pub fn resolve_parent_at(s: &mut ZfsServer, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
            let root = s.root_obj();
            let trimmed = {
                let mut end = path.len();
                while end > 1 && path[end - 1] == b'/' {
                    end -= 1;
                }
                &path[..end]
            };
            let (dir_part, name) = match trimmed.iter().rposition(|&c| c == b'/') {
                Some(i) => (&trimmed[..i.max(1)], &trimmed[i + 1..]),
                None => (&b"."[..], trimmed),
            };
            if name.is_empty() || name == b"/" {
                return Err(EEXIST);
            }
            let dir_path: &[u8] = if dir_part.is_empty() { b"/" } else { dir_part };
            let parent = if dir_path == b"." { base } else { resolve_in(s, root, base, dir_path, true)? };
            Ok((parent, name.to_vec()))
        }
    }
}

/// 4 KiB buffers for the block cache and dirty data. In the kernel these were physical
/// frames reached through its identity mapping; here they are page-aligned heap blocks,
/// named by their address, with the same reference counting.
pub mod memory {
    pub mod frame_allocator {
        use alloc::alloc::{alloc_zeroed, dealloc, Layout};
        use alloc::collections::BTreeMap;
        use spin::Mutex;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;

        static REFS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

        fn layout(pages: usize) -> Layout {
            Layout::from_size_align(pages * 4096, 4096).unwrap()
        }

        /// A zeroed buffer with one reference.
        pub fn alloc_user_frame() -> Option<PhysFrame<Size4KiB>> {
            let p = unsafe { alloc_zeroed(layout(1)) };
            if p.is_null() {
                return None;
            }
            REFS.lock().insert(p as u64, 1);
            Some(PhysFrame::containing_address(PhysAddr::new(p as u64)))
        }

        /// Adds a reference to a buffer.
        pub fn frame_ref_inc(frame: PhysFrame<Size4KiB>) {
            if let Some(r) = REFS.lock().get_mut(&frame.start_address().as_u64()) {
                *r += 1;
            }
        }

        /// Drops a reference; the buffer is freed with the last one.
        pub fn frame_ref_dec(frame: PhysFrame<Size4KiB>) {
            let addr = frame.start_address().as_u64();
            let mut refs = REFS.lock();
            let last = match refs.get_mut(&addr) {
                Some(r) if *r > 1 => {
                    *r -= 1;
                    false
                }
                Some(_) => true,
                None => false,
            };
            if last {
                refs.remove(&addr);
                drop(refs);
                unsafe { dealloc(addr as *mut u8, layout(1)) };
            }
        }

        /// Contiguous buffers (the RAM disk used when there is no disk).
        pub struct Contiguous;

        impl Contiguous {
            /// Allocates `pages` contiguous zeroed pages (never freed).
            pub fn allocate_contiguous_frames(&mut self, pages: usize) -> Option<PhysFrame<Size4KiB>> {
                let p = unsafe { alloc_zeroed(layout(pages)) };
                (!p.is_null()).then(|| PhysFrame::containing_address(PhysAddr::new(p as u64)))
            }
        }

        /// The kernel's frame allocator, as far as the pool uses it.
        pub static FRAME_ALLOCATOR: Mutex<Contiguous> = Mutex::new(Contiguous);
    }
}

/// The clock.
pub mod arch {
    pub mod rtc {
        /// Wall-clock time: `(seconds since 1970, nanoseconds)`.
        pub fn now() -> (u64, u32) {
            hydra_rt::sys::clock()
        }
    }
}

/// Calls to the disk driver, as the kernel's `ipc` module made them.
pub mod ipc {
    pub use hydra_rt::protocol;

    /// A service message.
    #[derive(Clone, Copy, Debug)]
    pub struct Message {
        /// Operation or reply code.
        pub label: u32,
        /// Arguments.
        pub args: [u64; 4],
    }

    impl Message {
        /// A message with no arguments.
        pub fn new(label: u32) -> Self {
            Self { label, args: [0; 4] }
        }

        /// A message with arguments.
        pub fn with_args(label: u32, args: [u64; 4]) -> Self {
            Self { label, args }
        }
    }

    pub mod service {
        use super::Message;
        use core::sync::atomic::{AtomicU64, Ordering};

        /// Pages in a service window.
        pub const WINDOW_PAGES: u64 = 64;
        /// Bytes in a service window.
        pub const WINDOW_SIZE: usize = (WINDOW_PAGES * 4096) as usize;
        /// How long the disk driver may take (5 s).
        pub const CALL_TIMEOUT_TICKS: u64 = 500;

        /// The disk driver's window, attached at startup.
        static BLOCK_WINDOW: AtomicU64 = AtomicU64::new(0);

        /// Maps the disk driver's window into this server.
        pub fn attach_block() -> Result<(), i64> {
            let addr = hydra_rt::sys::svc_attach(super::protocol::ENDPOINT_BLOCK_DEV)?;
            BLOCK_WINDOW.store(addr, Ordering::Release);
            Ok(())
        }

        /// Whether `endpoint` (the disk driver) can be called.
        pub fn is_online(endpoint: u32) -> bool {
            endpoint == super::protocol::ENDPOINT_BLOCK_DEV && BLOCK_WINDOW.load(Ordering::Acquire) != 0
        }

        /// The disk driver's window.
        pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
            let addr = BLOCK_WINDOW.load(Ordering::Acquire);
            (is_online(endpoint)).then(|| unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, WINDOW_SIZE) })
        }

        /// Calls the disk driver.
        pub fn call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
            let r = hydra_rt::sys::svc_call(endpoint, hydra_rt::Message::new(request.label as u64, request.args), timeout_ticks)?;
            Ok(Message::with_args(r.label as u32, r.args))
        }
    }
}

/// Restarting the disk driver is the kernel's business: a call to a dead driver restarts it.
pub mod task {
    pub mod supervisor {
        /// Not available here (the kernel restarts the driver when this server calls it).
        pub fn revive(_endpoint: u32) -> bool {
            false
        }
    }
}

/// inotify, as the ZPL reports to it: events are collected during a request and returned
/// to the kernel with the reply.
pub mod compat {
    pub mod linux {
        pub mod inotify {
            use crate::zfs::fsproto::Event;
            use alloc::vec::Vec;
            use core::sync::atomic::{AtomicU32, Ordering};
            use spin::Mutex;

            pub const IN_MODIFY: u32 = 0x2;
            pub const IN_ATTRIB: u32 = 0x4;
            pub const IN_CLOSE_WRITE: u32 = 0x8;
            pub const IN_MOVED_FROM: u32 = 0x40;
            pub const IN_MOVED_TO: u32 = 0x80;
            pub const IN_CREATE: u32 = 0x100;
            pub const IN_DELETE: u32 = 0x200;
            pub const IN_DELETE_SELF: u32 = 0x400;
            pub const IN_MOVE_SELF: u32 = 0x800;
            pub const IN_ISDIR: u32 = 0x4000_0000;

            static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
            static COOKIE: AtomicU32 = AtomicU32::new(1);

            /// Events are always collected (the kernel drops those nobody watches).
            pub fn active() -> bool {
                true
            }

            /// Every directory may be watched (the kernel decides).
            pub fn watched(_ino: u64) -> bool {
                true
            }

            /// A cookie pairing a rename's two events.
            pub fn cookie() -> u32 {
                COOKIE.fetch_add(1, Ordering::Relaxed)
            }

            /// Records an event for the reply.
            pub fn event(ino: u64, mask: u32, cookie: u32, name: &[u8]) {
                EVENTS.lock().push(Event { ino, mask, cookie, name: name.to_vec() });
            }

            /// The events recorded since the last call.
            pub fn take() -> Vec<Event> {
                core::mem::take(&mut *EVENTS.lock())
            }
        }
    }
}

use zfs::fsproto::*;
use zfs::server::{with_server, ZfsServer, ZFS_SERVER};

/// Copies what the request encoded (it is overwritten by the reply).
fn params(window: &[u8], len: usize) -> Vec<u8> {
    window[..len.min(window.len())].to_vec()
}

/// Serves one request: returns `(status, value, reply bytes)`, the reply data written to
/// `out`.
fn serve(op: u32, req: &[u8], out: &mut [u8]) -> (i64, u64, usize) {
    let mut r = Reader::new(req);
    let mut w = Writer::new(out);
    let res: Result<(u64, usize), i64> = match op {
        FS_ROOT => with_server(|s| Ok((s.root_obj(), 0))),
        FS_LOOKUP => {
            let dir = r.u64();
            let name = r.bytes();
            with_server(|s| s.lookup(dir, name).map(|i| (i, 0)))
        }
        FS_RESOLVE => {
            let (root, base, follow) = (r.u64(), r.u64(), r.u64() != 0);
            let path = r.bytes();
            with_server(|s| fs::client::resolve_in(s, root, base, path, follow).map(|i| (i, 0)))
        }
        FS_GETATTR => {
            let ino = r.u64();
            with_server(|s| s.getattr(ino)).map(|a| {
                w.attr(&a);
                (0, w.len())
            })
        }
        FS_SETATTR => {
            let ino = r.u64();
            let set = r.setattr();
            with_server(|s| s.setattr(ino, set)).map(|a| {
                w.attr(&a);
                (0, w.len())
            })
        }
        FS_READ => {
            let (ino, off, len) = (r.u64(), r.u64(), (r.u64() as usize).min(MAX_IO));
            with_server(|s| s.read(ino, off, &mut out[..len])).map(|n| (n as u64, n))
        }
        FS_WRITE => {
            let (ino, off) = (r.u64(), r.u64());
            let data = r.bytes();
            with_server(|s| s.write(ino, off, data)).map(|n| (n as u64, 0))
        }
        FS_CREATE | FS_MKDIR => {
            let dir = r.u64();
            let name = r.bytes();
            let (perm, uid, gid) = (r.u64() as u32, r.u64() as u32, r.u64() as u32);
            with_server(|s| if op == FS_CREATE { s.create(dir, name, perm, uid, gid) } else { s.mkdir(dir, name, perm, uid, gid) }).map(|i| (i, 0))
        }
        FS_MKNOD => {
            let dir = r.u64();
            let name = r.bytes();
            let (mode, rdev, uid, gid) = (r.u64() as u32, r.u64(), r.u64() as u32, r.u64() as u32);
            with_server(|s| s.mknod(dir, name, mode, rdev, uid, gid)).map(|i| (i, 0))
        }
        FS_SYMLINK => {
            let dir = r.u64();
            let name = r.bytes();
            let target = r.bytes();
            let (uid, gid) = (r.u64() as u32, r.u64() as u32);
            with_server(|s| s.symlink(dir, name, target, uid, gid)).map(|i| (i, 0))
        }
        FS_READLINK => {
            let ino = r.u64();
            with_server(|s| s.readlink(ino)).map(|t| {
                let n = t.len().min(out.len());
                out[..n].copy_from_slice(&t[..n]);
                (n as u64, n)
            })
        }
        FS_LINK => {
            let (ino, dir) = (r.u64(), r.u64());
            let name = r.bytes();
            with_server(|s| s.link(ino, dir, name)).map(|()| (0, 0))
        }
        FS_UNLINK | FS_RMDIR => {
            let dir = r.u64();
            let name = r.bytes();
            with_server(|s| if op == FS_UNLINK { s.unlink(dir, name) } else { s.rmdir(dir, name) }).map(|()| (0, 0))
        }
        FS_RENAME => {
            let sdir = r.u64();
            let sname = r.bytes();
            let ddir = r.u64();
            let dname = r.bytes();
            with_server(|s| s.rename(sdir, sname, ddir, dname)).map(|()| (0, 0))
        }
        FS_READDIR => {
            let (dir, cookie, max) = (r.u64(), r.u64(), r.u64() as usize);
            with_server(|s| s.readdir(dir, cookie, max)).map(|entries| {
                let mut n = 0;
                for e in &entries {
                    if !w.entry(e) {
                        break;
                    }
                    n += 1;
                }
                (n, w.len())
            })
        }
        FS_STATFS => with_server(|s| Ok(s.statfs())).map(|(a, b, c)| {
            w.u64(a);
            w.u64(b);
            w.u64(c);
            (0, w.len())
        }),
        FS_OPEN_REF => {
            let ino = r.u64();
            with_server(|s| {
                s.open_ref(ino);
                Ok((0, 0))
            })
        }
        FS_RELEASE => {
            let ino = r.u64();
            with_server(|s| {
                s.release(ino);
                Ok((0, 0))
            })
        }
        FS_NOTIFY => {
            let (ino, mask) = (r.u64(), r.u64() as u32);
            with_server(|s| {
                s.notify_file(ino, mask);
                Ok((0, 0))
            })
        }
        FS_SYNC => with_server(|s| s.sync()).map(|t| (t, 0)),
        FS_SYNC_IF_DIRTY => with_server(|s| {
            if s.dmu.has_pending_changes() {
                s.sync().map(|_| (1, 0))
            } else {
                Ok((0, 0))
            }
        }),
        FS_SNAPSHOT => {
            let idx = r.u64() as usize;
            let name = core::str::from_utf8(r.bytes()).unwrap_or("snap");
            with_server(|s| s.snapshot(idx, name)).map(|t| (t, 0))
        }
        FS_POOL_STATUS => with_server(|s| {
            w.u64(s.dmu.spa.total_capacity_bytes());
            w.u64(s.dmu.spa.allocated_bytes());
            w.u64(s.dmu.spa.free_bytes());
            w.u64(s.dmu.ub.txg);
            w.u64(s.dmu.open_txg);
            Ok((0, w.len()))
        }),
        FS_OBJECT_INFO => {
            let ino = r.u64();
            with_server(|s| {
                let dn = s.dmu.get_dnode(ino).map_err(|_| EIO)?;
                let bp = dn.blkptr[0];
                w.u64(dn.birth_txg);
                w.u64(!bp.is_hole() as u64);
                for c in [bp.checksum.a, bp.checksum.b, bp.checksum.c, bp.checksum.d] {
                    w.u64(c);
                }
                Ok((0, w.len()))
            })
        }
        FS_DATASETS => with_server(|s| {
            let mut n = 0;
            for d in &s.datasets {
                if !(w.bytes(d.name_str().as_bytes()) && w.bytes(d.mountpoint_str().as_bytes()) && w.u64(d.txg) && w.u64(d.is_snapshot as u64)) {
                    break;
                }
                n += 1;
            }
            Ok((n, w.len()))
        }),
        FS_SELFTEST => {
            zfs::selftest::run_selftest();
            Ok((0, 0))
        }
        FS_VERIFY => {
            zfs::selftest::run_verify();
            Ok((0, 0))
        }
        FS_FSCK => {
            let path = alloc::string::String::from(core::str::from_utf8(r.bytes()).unwrap_or("/"));
            let repair = r.u64() != 0;
            zfs::selftest::run_fsck(&path, repair);
            Ok((0, 0))
        }
        _ => Err(-38),
    };
    match res {
        Ok((value, len)) => (0, value, len),
        Err(e) => (e, 0, 0),
    }
}

fn main(_args: &[&str]) {
    if let Err(e) = zfs_init() {
        hydra_rt::println!("[zfs-server] {}", e);
        return;
    }
    let mut server = match Server::register(ENDPOINT_ZFS_SERVER) {
        Ok(s) => s,
        Err(e) => {
            hydra_rt::println!("[zfs-server] cannot register on endpoint {:#x}: error {}", ENDPOINT_ZFS_SERVER, e);
            return;
        }
    };
    server.serve(|srv, msg| {
        let window = srv.window();
        // The request (at most what precedes the event area) is read before the reply overwrites it
        let req = params(window, EVENT_OFFSET);
        compat::linux::inotify::take();
        let (status, value, len) = serve(msg.label as u32, &req, &mut window[..EVENT_OFFSET]);
        let events = compat::linux::inotify::take();
        let mut w = Writer::new(&mut window[EVENT_OFFSET..EVENT_OFFSET + EVENT_SPACE]);
        let mut sent = 0u64;
        for e in &events {
            if !w.event(e) {
                break;
            }
            sent += 1;
        }
        Message::new(FS_REPLY as u64, [status as u64, value, len as u64, sent])
    })
}

/// Attaches the disk driver's window and imports the pool.
fn zfs_init() -> Result<(), &'static str> {
    // The disk driver starts first; it may still be coming up
    let mut tries = 0;
    while ipc::service::attach_block().is_err() {
        tries += 1;
        if tries > 50 {
            return Err("the disk driver is not running");
        }
        sys::sleep_ms(100);
    }
    let server = ZfsServer::new();
    *ZFS_SERVER.lock() = Some(server);
    Ok(())
}
