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
    #[path = "../client.rs"]
    pub mod client;
}

/// 4 KiB buffers for the block cache and dirty data. In the kernel these were physical
/// frames reached through its identity mapping; here they are page-aligned heap blocks,
/// named by their address, with the same reference counting.
pub mod memory {
    /// Userland page buffer frame allocator compatibility shim.
    #[path = "../frames.rs"]
    pub mod frame_allocator;
}

/// The clock.
pub mod arch {
    /// Real-time clock interface.
    pub mod rtc {
        /// Wall-clock time: `(seconds since 1970, nanoseconds)`.
        ///
        /// # Returns
        /// Tuple of `(seconds, nanoseconds)`.
        pub fn now() -> (u64, u32) {
            // wave8 GZ: frozen for the request being served (and replayed)
            crate::durable::frozen().unwrap_or_else(hydra_rt::sys::clock)
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
        ///
        /// # Arguments
        /// * `label` - Message operation label.
        ///
        /// # Returns
        /// Initialized [`Message`] with zeroed arguments.
        pub fn new(label: u32) -> Self {
            Self { label, args: [0; 4] }
        }

        /// A message with arguments.
        ///
        /// # Arguments
        /// * `label` - Message operation label.
        /// * `args` - Array of 4 argument words.
        ///
        /// # Returns
        /// Initialized [`Message`].
        pub fn with_args(label: u32, args: [u64; 4]) -> Self {
            Self { label, args }
        }
    }

    /// Service communications and shared window operations.
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
        /// The endpoint the pool's disk is served on (the ATA/AHCI disk endpoint, or the
        /// USB disks'), and the disk's number there (`args[3]` of block requests).
        static DISK_ENDPOINT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(super::protocol::ENDPOINT_BLOCK_DEV);
        static DISK_NUMBER: AtomicU64 = AtomicU64::new(0);

        /// Uses disk `number` of the disks served on `endpoint` from now on (the pool code
        /// keeps calling it [`super::protocol::ENDPOINT_BLOCK_DEV`]).
        ///
        /// # Arguments
        /// * `endpoint` - Endpoint serving the disk.
        /// * `number` - The disk's number there.
        pub fn use_disk(endpoint: u32, number: u64) {
            DISK_ENDPOINT.store(endpoint, Ordering::Release);
            DISK_NUMBER.store(number, Ordering::Release);
        }

        /// Forgets the disk driver: the pool goes to a RAM disk.
        pub fn detach_block() {
            BLOCK_WINDOW.store(0, Ordering::Release);
        }

        /// Maps the disk driver's window into this server.
        ///
        /// # Returns
        /// `Ok(())` on success.
        ///
        /// # Errors
        /// Returns negative error code on attachment failure.
        pub fn attach_block() -> Result<(), i64> {
            let addr = hydra_rt::sys::svc_attach(DISK_ENDPOINT.load(Ordering::Acquire))?;
            BLOCK_WINDOW.store(addr, Ordering::Release);
            Ok(())
        }

        /// Whether `endpoint` (the disk driver) can be called.
        ///
        /// # Arguments
        /// * `endpoint` - Target endpoint ID.
        ///
        /// # Returns
        /// `true` if online, `false` otherwise.
        pub fn is_online(endpoint: u32) -> bool {
            endpoint == super::protocol::ENDPOINT_BLOCK_DEV && BLOCK_WINDOW.load(Ordering::Acquire) != 0
        }

        /// The disk driver's window.
        ///
        /// # Arguments
        /// * `endpoint` - Target endpoint ID.
        ///
        /// # Returns
        /// `Some(&mut [u8])` slice of shared window memory, or `None`.
        pub fn window(endpoint: u32) -> Option<&'static mut [u8]> {
            let addr = BLOCK_WINDOW.load(Ordering::Acquire);
            (is_online(endpoint)).then(|| unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, WINDOW_SIZE) })
        }

        /// Calls the disk driver.
        ///
        /// # Arguments
        /// * `endpoint` - Target endpoint ID.
        /// * `request` - Request message.
        /// * `timeout_ticks` - Timeout in ticks.
        ///
        /// # Returns
        /// Reply [`Message`] on success.
        ///
        /// # Errors
        /// Returns negative error code on failure or timeout.
        pub fn call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
            let (mut endpoint, mut args) = (endpoint, request.args);
            if endpoint == super::protocol::ENDPOINT_BLOCK_DEV {
                // The pool's disk, wherever it is served
                endpoint = DISK_ENDPOINT.load(Ordering::Acquire);
                args[3] = DISK_NUMBER.load(Ordering::Acquire);
            }
            let r = hydra_rt::sys::svc_call(endpoint, hydra_rt::Message::new(request.label as u64, args), timeout_ticks)?;
            Ok(Message::with_args(r.label as u32, r.args))
        }

        /// Calls the disk driver lending it `len` bytes at `addr` of this server's memory
        /// for the request (a page grant: the disk's DMA goes straight to or from them).
        ///
        /// # Arguments
        /// * `server_writes` - The driver fills the memory (a read from the disk).
        ///
        /// # Errors
        /// Returns negative error code on failure or timeout.
        pub fn call_grant(endpoint: u32, request: Message, timeout_ticks: u64, addr: u64, len: u64, server_writes: bool) -> Result<Message, i64> {
            let (mut endpoint, mut args) = (endpoint, request.args);
            if endpoint == super::protocol::ENDPOINT_BLOCK_DEV {
                endpoint = DISK_ENDPOINT.load(Ordering::Acquire);
                args[3] = DISK_NUMBER.load(Ordering::Acquire);
            }
            let m = hydra_rt::Message::new(request.label as u64, args);
            let r = hydra_rt::sys::svc_call_grant(endpoint, m, timeout_ticks, &[(addr, len)], server_writes)?;
            Ok(Message::with_args(r.label as u32, r.args))
        }
    }
}

/// Restarting the disk driver is the kernel's business: a call to a dead driver restarts it.
pub mod task {
    /// Supervisor interface shim.
    pub mod supervisor {
        /// Not available here (the kernel restarts the driver when this server calls it).
        ///
        /// # Arguments
        /// * `_endpoint` - Service endpoint ID.
        ///
        /// # Returns
        /// Always returns `false`.
        pub fn revive(_endpoint: u32) -> bool {
            false
        }
    }
}

/// inotify, as the ZPL reports to it: events are collected during a request and returned
/// to the kernel with the reply.
pub mod compat {
    /// Linux compatibility shims.
    pub mod linux {
        /// Inotify event definitions and buffer collector.
        #[path = "../../events.rs"]
        pub mod inotify;
    }
}

pub mod durable;
pub mod serve;
pub mod zil;

use serve::serve;
use zfs::fsproto::*;
use zfs::server::{ZfsServer, ZFS_SERVER};

/// Entry point of the ZFS userspace file server daemon.
///
/// # Arguments
/// * `_args` - Command-line argument strings.
fn main(args: &[&str]) {
    // cache_blocks=N: the block cache's size, which the kernel sets from the RAM
    for a in args {
        if let Some(n) = a.strip_prefix("cache_blocks=").and_then(|n| n.parse().ok()) {
            zfs::spa::set_cache_blocks(n);
        }
        // new_guid=<id>: a new pool GUID, once per id (the first boot of an installation)
        if let Some(n) = a.strip_prefix("new_guid=").and_then(|n| u64::from_str_radix(n, 16).ok()) {
            zfs::spa::set_new_guid_for(n);
        }
    }
    // disk=usb: the pool is on a USB disk (there is no ATA or SATA disk)
    let usb = args.iter().any(|a| *a == "disk=usb");
    if let Err(e) = zfs_init(usb) {
        hydra_rt::println!("[zfs-server] {}", e);
        return;
    }
    // wave8 GZ: the intent log of the instance before this one (if it was killed), replayed
    // before the endpoint is registered (the clients wait for the restart meanwhile)
    recover_log();
    let mut server = match Server::register(ENDPOINT_ZFS_SERVER) {
        Ok(s) => s,
        Err(e) => {
            hydra_rt::println!("[zfs-server] cannot register on endpoint {:#x}: error {}", ENDPOINT_ZFS_SERVER, e);
            return;
        }
    };
    // The request is copied out (the reply overwrites it) into one buffer kept across
    // requests: only the bytes the kernel encoded (args[0]; all before the event area
    // when it does not say)
    let mut req: Vec<u8> = Vec::with_capacity(EVENT_OFFSET);
    let mut handle = |srv: &mut Server, msg: &Message| -> Message {
        // wave7 G7-1 begin: vfs-server's requests are in its own window (attached here
        // the first time), the kernel's in this server's
        let vfs = msg.args[1] == FS_CLIENT_VFS;
        // SAFETY (vfs_window): used only within this request, while vfs-server waits for it
        let (window, base, data_end, events_end): (&mut [u8], usize, usize, usize) = if vfs {
            match unsafe { vfs_window() } {
                Some(w) => (w, 0, FS_VFS_EVENTS - FS_VFS_OFF, FS_VFS_END - FS_VFS_OFF),
                None => return Message::new(FS_REPLY as u64, [EIO as u64, 0, 0, 0]),
            }
        } else {
            (srv.window(), 0, EVENT_OFFSET, EVENT_OFFSET + EVENT_SPACE)
        };
        let room = data_end - base;
        let len = match msg.args[0] as usize {
            0 => room,
            n => n.min(room),
        };
        req.clear();
        req.extend_from_slice(&window[base..base + len]);
        compat::linux::inotify::take();
        // wave8 GZ: a change is in the intent log before its answer leaves
        let op = msg.label as u32;
        let before = durable::before(sys::clock());
        let (status, value, len) = serve(op, &req, &mut window[base..data_end]);
        durable::after(before, op, &req, status, value);
        let events = compat::linux::inotify::take();
        let mut w = Writer::new(&mut window[data_end..events_end]);
        // wave7 G7-1 end
        let mut sent = 0u64;
        for e in &events {
            if !w.event(e) {
                break;
            }
            sent += 1;
        }
        Message::new(FS_REPLY as u64, [status as u64, value, len as u64, sent])
    };
    // wave7 G7-1 begin: the answer goes with the next wait (`reply_recv`, one system call):
    // a caller on the kernel's direct path (vfs-server) gets the CPU back as this server
    // parks, and its next request finds it parked (Group 20's note for wave 7)
    let mut answer: Option<(u64, Message)> = None;
    loop {
        let got = match answer.take() {
            Some((id, r)) => hydra_rt::svccall::reply_recv(ENDPOINT_ZFS_SERVER, id, &r, 0),
            None => sys::svc_recv(ENDPOINT_ZFS_SERVER),
        };
        match got {
            Ok((0, _)) => {}
            // (never spin on a failing receive)
            Err(_) => sys::sleep_ms(1),
            Ok((id, m)) => {
                let r = if m.label == hydra_rt::protocol::MSG_SUPERVISOR_PING as u64 {
                    Message::new(hydra_rt::protocol::MSG_SUPERVISOR_PONG as u64, [m.args[0], 1, 0, 0])
                } else {
                    handle(&mut server, &m)
                };
                answer = Some((id, r));
            }
        }
    }
    // wave7 G7-1 end
}

// wave8 GZ begin
/// Maps the intent log's kept object and replays it ([`durable::recover`]). Without a kept
/// object (an older kernel) the server runs as before: changes since the last commit are
/// lost when it is killed.
fn recover_log() {
    let (obj, existed) = match hydra_rt::mem::MemObj::kept(durable::LOG_KEY, durable::LOG_BYTES as u64) {
        Ok(x) => x,
        Err(e) => {
            hydra_rt::println!("[zfs-server] no intent log (kept object: error {}): changes since the last commit are lost on a kill", e);
            return;
        }
    };
    let addr = match obj.map(0, durable::LOG_BYTES as u64, hydra_rt::mem::PROT_RW) {
        Ok(a) => a,
        Err(e) => {
            hydra_rt::println!("[zfs-server] no intent log (mapping: error {})", e);
            return;
        }
    };
    // (the handle stays open for the process's life: the mapping is its view of the log)
    let _ = obj.into_raw();
    // SAFETY: the mapping is this process's for its whole life and only the log uses it
    let buf = unsafe { core::slice::from_raw_parts_mut(addr, durable::LOG_BYTES) };
    let r = durable::recover(buf, existed);
    if r.matched {
        hydra_rt::println!(
            "[zfs-server] intent log: replayed {} changes ({} differed{}){}{}; committed TXG #{}",
            r.replayed.applied,
            r.replayed.mismatches,
            if r.replayed.mismatches > 0 { alloc::format!(", first #{}", r.replayed.first_mismatch) } else { alloc::string::String::new() },
            if r.torn { ", a torn last record ignored" } else { "" },
            if r.given_up { ", GIVEN UP after repeated failed starts (changes since the last commit are lost)" } else { "" },
            r.txg
        );
    }
}
// wave8 GZ end

// wave7 G7-1 begin
/// vfs-server's part for its requests to this server (`FS_VFS_OFF..FS_VFS_END` of its
/// window, attached the first time one comes; the supervisor allows it:
/// `allow_client(ENDPOINT_VFS_SERVER, ENDPOINT_ZFS_SERVER)`). The window outlives
/// vfs-server's restarts, so the mapping stays valid.
///
/// # Safety
/// The slice is for one request of vfs-server's, which holds its part for it (and waits);
/// the caller must not keep it beyond that request.
unsafe fn vfs_window<'a>() -> Option<&'a mut [u8]> {
    use core::sync::atomic::{AtomicU64, Ordering};
    static VFS_WINDOW: AtomicU64 = AtomicU64::new(0);
    let mut a = VFS_WINDOW.load(Ordering::Acquire);
    if a == 0 {
        a = sys::svc_attach(hydra_rt::protocol::ENDPOINT_VFS_SERVER).ok().filter(|&a| a != 0)?;
        VFS_WINDOW.store(a, Ordering::Release);
    }
    // SAFETY: inside the mapped 256 KiB window; see the function's contract
    Some(core::slice::from_raw_parts_mut((a as usize + FS_VFS_OFF) as *mut u8, FS_VFS_END - FS_VFS_OFF))
}
// wave7 G7-1 end

/// Attaches the disk driver's window and imports the pool.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Static error string if disk driver is unavailable.
fn zfs_init(usb: bool) -> Result<(), &'static str> {
    if usb {
        ipc::service::use_disk(ipc::protocol::ENDPOINT_USB_DISK, 0);
    }
    // The disk driver starts first; it may still be coming up
    let mut tries = 0;
    while ipc::service::attach_block().is_err() {
        tries += 1;
        if tries > 50 {
            return Err("the disk driver is not running");
        }
        sys::sleep_ms(100);
    }
    if usb {
        // The USB driver's pool view (unit 0), which it chose from the boot partition or
        // as the first USB disk holding a pool
        hydra_rt::println!("[zfs-server] the pool is on a USB disk");
    }
    let server = ZfsServer::new();
    *ZFS_SERVER.lock() = Some(server);
    Ok(())
}
