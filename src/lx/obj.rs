//! # Server-object descriptors (wave 4, step 2)
//!
//! A *server object* is an open file whose state lives in linux-server: a POSIX message
//! queue, a bpf map or program, and from step 3 on net sockets, pipes, Unix sockets. The
//! descriptor table stays in the kernel (`docs/linux-server-design.md`, section 7.1):
//!
//! - **The descriptor** is `FileDescriptor::Device` holding a [`ServerObject`], which names
//!   the server's *slot* for the object. `dup`, `fork`, `SCM_RIGHTS`, close-on-exec and
//!   process exit share and drop it like every other descriptor; when the last reference
//!   goes, [`ServerObject`]'s `Drop` posts [`LX_NOTE_CLOSE`] to the server's notification
//!   ring, exactly once.
//! - **Calls on it**: system calls the forwarding table gives to the server and that take a
//!   descriptor first (`mq_timedsend(mqd, ..)`) carry the object's slot in [`LxCall::obj`];
//!   `read`, `write`, `readv`, `writev` and `ioctl` on it are forwarded the same way
//!   ([`super::call_obj`]). The kernel holds a reference for as long as the call is in
//!   flight, so a concurrent `close` cannot overtake it.
//! - **Readiness without a call**: each slot has a readiness word in the server's window
//!   ([`LX_OBJ_OFF`]); `poll`, `select`, `epoll` and aio's poll read it. When the server
//!   changes words it marks the slots in a bitmap ([`LX_OBJ_CHANGED_OFF`]) and rings its
//!   doorbell (`SYS_SVC_SIGNAL`, [`LX_SIGNAL_OBJS`]): [`on_doorbell`] wakes the waiters of
//!   each marked object. The word's edge count makes edge-triggered epoll exact.
//! - **A restarted server** starts a new generation: objects of the old one poll as
//!   `POLLERR | POLLHUP`, their calls fail with `EBADF`, and their closes are not told to
//!   the new server. (Under the crash policy every Linux program ends anyway.)
//!
//! The server's primitives for these objects are `SYS_LX_OBJ` ([`obj_ctl`]) and the signal
//! primitive `SYS_LX_SIG` ([`sig_post`]).
//!
//! [`LxCall::obj`]: crate::ipc::protocol::LxCall::obj

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::compat::linux::chardev::CharDevice;
use crate::fs::FileDescriptor;
use crate::ipc::protocol::{
    LxObjDesc, LX_NOTE_CLOSE, LX_OBJ_BPF_DEVICE, LX_OBJ_CHANGED_OFF, LX_OBJ_COMM, LX_OBJ_FD, LX_OBJ_FDPATH, LX_OBJ_INSTALL, LX_OBJ_NAME_MAX, LX_OBJ_NOTIFY, LX_OBJ_OFF, LX_OBJ_PIN,
    LX_OBJ_SETFL, LX_OBJ_SLOTS, LX_OBJ_UNPIN, LX_OBJ_WATCHED_OFF,
};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};
use crate::task::TaskId;

const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EBUSY: i64 = -16;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u32 = 0o2000000;
/// `POLLERR | POLLHUP`: what a stale object (its server is gone) reports.
const STALE: u32 = 0x0018;

/// The server's generation: +1 each time a server goes online.
static GEN: AtomicU64 = AtomicU64::new(0);
/// Kernel address of the server's window (0: no server online).
static WINDOW: AtomicU64 = AtomicU64::new(0);

/// What the kernel and every descriptor of one object share.
pub struct ObjShared {
    /// The tasks waiting for the object's readiness to change.
    wq: Arc<WaitQueue>,
    /// `O_NONBLOCK` of the open file (shared by `dup`, as on Linux).
    nonblock: AtomicBool,
}

/// The live objects by slot (to wake them, and to set their flags).
static REG: Mutex<[Option<Arc<ObjShared>>; LX_OBJ_SLOTS]> = Mutex::new([const { None }; LX_OBJ_SLOTS]);

fn reg<R>(f: impl FnOnce(&mut [Option<Arc<ObjShared>>; LX_OBJ_SLOTS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut REG.lock()))
}

/// Kernel descriptors kept for the server ([`LX_OBJ_PIN`]), by token.
static PINS: Mutex<BTreeMap<u64, Arc<dyn CharDevice>>> = Mutex::new(BTreeMap::new());
static NEXT_PIN: AtomicU64 = AtomicU64::new(1);

/// An open server object (the device of a `FileDescriptor::Device`).
pub struct ServerObject {
    slot: u32,
    kind: u32,
    gen: u64,
    shared: Arc<ObjShared>,
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    /// Set when the server must not hear of this object's end (its install failed: the
    /// server frees the slot itself).
    quiet: AtomicBool,
    /// Counted in [`super::WATCHED_NET`] (an Internet socket someone waited on).
    watched: AtomicBool,
}

impl ServerObject {
    /// The server's slot for the object, if the object belongs to the server online now.
    pub fn slot(&self) -> Option<u64> {
        (self.gen == GEN.load(Ordering::Acquire) && WINDOW.load(Ordering::Acquire) != 0).then_some(self.slot as u64)
    }

    /// `LX_OBJ_KIND_*`.
    pub fn kind(&self) -> u32 {
        self.kind
    }

    /// The object's status flags for a forwarded call (`O_NONBLOCK`).
    pub fn flags(&self) -> u64 {
        if self.shared.nonblock.load(Ordering::Relaxed) {
            O_NONBLOCK as u64
        } else {
            0
        }
    }

    /// `(poll bits, edge count, size)` from the readiness word; `None` if stale.
    fn word(&self) -> Option<(u32, u32, u64)> {
        self.slot()?;
        let base = WINDOW.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        let p = (base + LX_OBJ_OFF as u64 + 16 * self.slot as u64) as *const u32;
        // SAFETY: the slot lies in the server's window, mapped while the server is online
        unsafe {
            let ready = core::ptr::read_volatile(p);
            let edges = core::ptr::read_volatile(p.add(1));
            let size = core::ptr::read_volatile(p.add(2) as *const u64);
            Some((ready, edges, size))
        }
    }
}

impl Drop for ServerObject {
    fn drop(&mut self) {
        if self.gen != GEN.load(Ordering::Acquire) {
            return;
        }
        if self.watched.load(Ordering::Acquire) {
            let _ = super::WATCHED_NET.try_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(1)));
        }
        let slot = self.slot as usize;
        reg(|r| {
            if r[slot].as_ref().is_some_and(|s| Arc::ptr_eq(s, &self.shared)) {
                r[slot] = None;
            }
        });
        if !self.quiet.load(Ordering::Acquire) {
            super::note(LX_NOTE_CLOSE, self.slot as u64, self.kind as u64, 0);
        }
    }
}

impl CharDevice for ServerObject {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        // Reads are forwarded before they get here (`vfs::stream_io`)
        EBADF
    }

    fn poll_events(&self) -> u32 {
        self.word().map_or(STALE, |w| w.0)
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.shared.wq.clone()));
        // Someone waits for this object: the server rings the doorbell for it from now on
        // (set before the caller reads the readiness word)
        let base = WINDOW.load(Ordering::Acquire);
        if base != 0 && self.slot().is_some() {
            let words = (base + LX_OBJ_WATCHED_OFF as u64) as *const AtomicU64;
            // SAFETY: the bitmap lies in the window, mapped while the server is online
            unsafe { (*words.add(self.slot as usize / 64)).fetch_or(1 << (self.slot % 64), Ordering::SeqCst) };
            // An Internet socket: net-server's events must reach its word from now on (the
            // main thread catches up on what it missed and rings the doorbell)
            if self.kind == crate::ipc::protocol::LX_OBJ_KIND_INET && !self.watched.swap(true, Ordering::AcqRel) {
                if super::WATCHED_NET.fetch_add(1, Ordering::AcqRel) == 0 {
                    super::relay_on();
                }
            }
        }
    }

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        self.name.clone()
    }

    fn set_nonblock(&self, on: bool) {
        self.shared.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.shared.nonblock.load(Ordering::Relaxed)
    }

    fn stat(&self) -> crate::compat::linux::types::LinuxStat {
        let mut st = crate::compat::linux::types::LinuxStat::default();
        st.st_mode = self.mode;
        st.st_uid = self.uid;
        st.st_gid = self.gid;
        st.st_nlink = 1;
        st.st_ino = 0x2_0000_0000 | (self.gen & 0xFFFF) << 16 | self.slot as u64;
        st.st_size = self.word().map_or(0, |w| w.2) as i64;
        st.st_blksize = 4096;
        st
    }

    fn as_server(&self) -> Option<&ServerObject> {
        Some(self)
    }

    fn edges(&self) -> Option<u64> {
        Some(self.word().map_or(u64::MAX - 1, |w| w.1 as u64))
    }
}

/// The server went online with its window at kernel address `window`: a new generation of
/// objects, with empty readiness slots.
pub(super) fn online(window: u64) {
    // SAFETY: the slots and the bitmap lie in the 256 KiB window
    unsafe {
        core::ptr::write_bytes((window + LX_OBJ_OFF as u64) as *mut u8, 0, 16 * LX_OBJ_SLOTS);
        core::ptr::write_bytes((window + LX_OBJ_CHANGED_OFF as u64) as *mut u8, 0, LX_OBJ_SLOTS / 8);
        core::ptr::write_bytes((window + LX_OBJ_WATCHED_OFF as u64) as *mut u8, 0, LX_OBJ_SLOTS / 8);
    }
    GEN.fetch_add(1, Ordering::AcqRel);
    WINDOW.store(window, Ordering::Release);
}

/// The server went away: every object goes stale and its waiters wake (they see
/// `POLLERR | POLLHUP`); kept descriptors are let go.
pub(super) fn offline() {
    WINDOW.store(0, Ordering::Release);
    GEN.fetch_add(1, Ordering::AcqRel);
    let mut woken: alloc::vec::Vec<Arc<ObjShared>> = alloc::vec::Vec::new();
    reg(|r| {
        for s in r.iter_mut() {
            if let Some(o) = s.take() {
                woken.push(o);
            }
        }
    });
    for o in &woken {
        o.wq.wake_all();
    }
    let pins = core::mem::take(&mut *PINS.lock());
    drop(pins);
    // The server's bpf device programs went with it
    crate::compat::linux::bpf::set_server_device_programs(&[]);
}

/// The doorbell ([`LX_SIGNAL_OBJS`]): wakes the waiters of every object the server marked
/// in the changed bitmap.
///
/// [`LX_SIGNAL_OBJS`]: crate::ipc::protocol::LX_SIGNAL_OBJS
pub(super) fn on_doorbell() {
    let base = WINDOW.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let words = (base + LX_OBJ_CHANGED_OFF as u64) as *const AtomicU64;
    let mut wake: alloc::vec::Vec<Arc<WaitQueue>> = alloc::vec::Vec::new();
    for i in 0..LX_OBJ_SLOTS / 64 {
        // SAFETY: the bitmap lies in the window; the server sets bits with atomic or
        let w = unsafe { (*words.add(i)).swap(0, Ordering::AcqRel) };
        if w == 0 {
            continue;
        }
        reg(|r| {
            let mut bits = w;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Some(o) = &r[i * 64 + b] {
                    wake.push(o.wq.clone());
                }
            }
        });
    }
    for q in wake {
        q.wake_all();
    }
}

/// The server object at descriptor `fd` of the calling thread: the descriptor (held for the
/// length of a forwarded call), its slot and its flags. `None` if `fd` is not a server
/// object of the server online now.
pub(super) fn current_fd(fd: u64) -> Option<(Arc<dyn CharDevice>, u64, u64)> {
    crate::task::with_current_fds_mut(|fds| object_in(fds, fd))
}

/// [`current_fd`] in descriptor table `fds` (locked by the caller): the lock-free path of
/// `crate::lx` takes the table's lock with `try_lock` and calls this.
pub(super) fn object_in(fds: &crate::fs::FdTable, fd: u64) -> Option<(Arc<dyn CharDevice>, u64, u64)> {
    let dev = match fds.get(fd as i32 as usize) {
        Some(FileDescriptor::Device(d)) => d.clone(),
        _ => return None,
    };
    let (slot, flags) = {
        let o = dev.as_server()?;
        (o.slot()?, o.flags())
    };
    Some((dev, slot, flags))
}

/// The descriptor table of request `id`'s caller.
fn client_fds(id: u64) -> Result<crate::fs::SharedFdTable, i64> {
    let client = super::client_of(id).ok_or(ESRCH)?;
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()).ok_or(ESRCH)
}

/// `SYS_LX_OBJ(op, a, b, c)`: the server's operations on its objects (see the `LX_OBJ_*`
/// constants in `ipc/protocol.rs`).
pub fn obj_ctl(op: u64, a: u64, b: u64, c: u64) -> i64 {
    if let Err(e) = super::server_caller() {
        return e;
    }
    match op {
        LX_OBJ_INSTALL => install(a, b),
        LX_OBJ_FD => {
            let fds = match client_fds(a) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let dev = match fds.lock().get(b as i32 as usize) {
                Some(FileDescriptor::Device(d)) => d.clone(),
                Some(_) => return EINVAL,
                None => return EBADF,
            };
            match dev.as_server().and_then(|o| o.slot().map(|s| (s, o.kind(), o.nonblock()))) {
                Some((slot, kind, nb)) => (slot | (kind as u64) << 32 | (nb as u64) << 62) as i64,
                None => EINVAL,
            }
        }
        // Group 12 (step 3): Landlock's TCP port rules and SIGPIPE, for the request's caller
        crate::ipc::protocol::LX_OBJ_NETCHECK => {
            let Some(client) = super::client_of(a) else { return ESRCH };
            match crate::compat::linux::landlock::check_port_of(client, b as u16, c) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        crate::ipc::protocol::LX_OBJ_NETWAIT => super::netwait(a, b as u32, c),
        crate::ipc::protocol::LX_OBJ_NETCANCEL => super::netcancel(a),
        crate::ipc::protocol::LX_OBJ_RELAY => super::set_relay(a != 0),
        crate::ipc::protocol::LX_OBJ_SIGTHREAD => {
            let Some(client) = super::client_of(a) else { return ESRCH };
            if !(1..=64).contains(&b) {
                return EINVAL;
            }
            let tgid = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.tgid).unwrap_or(0);
            crate::compat::linux::proc::post_thread(tgid, client, b as u32);
            0
        }
        LX_OBJ_COMM => {
            let Some(client) = super::client_of(a) else { return ESRCH };
            let tgid = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.tgid).unwrap_or(0);
            let text = crate::compat::linux::fs::proc_pid_file_text(&alloc::format!("{}/comm", tgid)).unwrap_or_default();
            let mut out = [0u8; 16];
            for (o, c) in out.iter_mut().zip(text.iter().take(15).take_while(|c| **c != b'\n')) {
                *o = *c;
            }
            let n = (c as usize).min(16);
            crate::compat::linux::vfs::copy_out(b, &out[..n]).map_or_else(|e| e, |()| 0)
        }
        LX_OBJ_FDPATH => {
            let fds = match client_fds(a) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let path = match fds.lock().get(b as i32 as usize) {
                Some(FileDescriptor::Vnode(f)) => f.lock().path.clone(),
                Some(FileDescriptor::File { path, .. }) => path.clone(),
                Some(_) => return EINVAL,
                None => return EBADF,
            };
            let p = &path.as_bytes()[..path.len().min(4096)];
            crate::compat::linux::vfs::copy_out(c, p).map_or_else(|e| e, |()| p.len() as i64)
        }
        LX_OBJ_BPF_DEVICE => {
            if b > 1 << 20 {
                return EINVAL;
            }
            let data = match crate::compat::linux::vfs::copy_in(a, b as usize) {
                Ok(d) => d,
                Err(e) => return e,
            };
            crate::compat::linux::bpf::set_server_device_programs(&data)
        }
        LX_OBJ_SETFL => {
            if a as usize >= LX_OBJ_SLOTS {
                return EINVAL;
            }
            match reg(|r| r[a as usize].clone()) {
                Some(s) => {
                    s.nonblock.store(b as u32 & O_NONBLOCK != 0, Ordering::Relaxed);
                    0
                }
                None => EBADF,
            }
        }
        LX_OBJ_PIN => {
            let fds = match client_fds(a) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let dev = match fds.lock().get(b as i32 as usize) {
                Some(FileDescriptor::Device(d)) if d.as_server().is_none() => d.clone(),
                _ => return EBADF,
            };
            let token = NEXT_PIN.fetch_add(1, Ordering::Relaxed);
            PINS.lock().insert(token, dev);
            token as i64
        }
        LX_OBJ_UNPIN => {
            let d = PINS.lock().remove(&a);
            match d {
                Some(_) => 0,
                None => EINVAL,
            }
        }
        LX_OBJ_NOTIFY => {
            if c > 4096 {
                return EINVAL;
            }
            let data = match crate::compat::linux::vfs::copy_in(b, c as usize) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let dev = PINS.lock().get(&a).cloned();
            match dev {
                Some(d) => {
                    d.deliver_notification(&data);
                    0
                }
                None => EINVAL,
            }
        }
        _ => EINVAL,
    }
}

/// [`LX_OBJ_INSTALL`]: a new descriptor for the object `desc` (in the server's memory)
/// describes, in the table of request `id`'s caller.
fn install(id: u64, desc: u64) -> i64 {
    let raw = match crate::compat::linux::vfs::copy_in(desc, core::mem::size_of::<LxObjDesc>()) {
        Ok(r) => r,
        Err(_) => return EFAULT,
    };
    // SAFETY: `raw` holds exactly one `LxObjDesc` (plain integers)
    let d: LxObjDesc = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const LxObjDesc) };
    let slot = d.slot as usize;
    if slot >= LX_OBJ_SLOTS || d.name_len as usize > LX_OBJ_NAME_MAX {
        return EINVAL;
    }
    let gen = GEN.load(Ordering::Acquire);
    if WINDOW.load(Ordering::Acquire) == 0 {
        return EINVAL;
    }
    let fds = match client_fds(id) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let shared = Arc::new(ObjShared { wq: WaitQueue::new_shared(), nonblock: AtomicBool::new(d.flags & O_NONBLOCK != 0) });
    let taken = reg(|r| {
        if r[slot].is_some() {
            return false;
        }
        r[slot] = Some(shared.clone());
        true
    });
    if !taken {
        return EBUSY;
    }
    let obj = Arc::new(ServerObject {
        slot: d.slot,
        kind: d.kind,
        gen,
        shared,
        name: String::from_utf8_lossy(&d.name[..d.name_len as usize]).into_owned(),
        mode: d.mode,
        uid: d.uid,
        gid: d.gid,
        quiet: AtomicBool::new(false),
        watched: AtomicBool::new(false),
    });
    let dev: Arc<dyn CharDevice> = obj.clone();
    let r = {
        let mut t = fds.lock();
        match t.alloc_fd(FileDescriptor::Device(dev)) {
            Ok(fd) => {
                t.set_cloexec(fd, d.flags & O_CLOEXEC != 0);
                Ok(fd)
            }
            Err(_) => Err(EMFILE),
        }
    };
    match r {
        Ok(fd) => fd as i64,
        Err(e) => {
            // The server frees the slot itself when the install fails
            obj.quiet.store(true, Ordering::Release);
            e
        }
    }
}

/// `SYS_LX_SIG(tgid, sig, code, spid | suid << 32, value)`: **sig_post**. Queues signal
/// `sig` for Linux process `tgid` with `si_code` `code`, the sender's process and user, and
/// `si_value` `value` (a message queue notification: `SI_MESGQ`). It is delivered on the
/// target's next return to user mode with the handlers the kernel keeps, and interrupts a
/// forwarded call the target is waiting in, as any signal does.
pub fn sig_post(tgid: u64, sig: u64, code: u64, ids: u64, value: u64) -> i64 {
    if let Err(e) = super::server_caller() {
        return e;
    }
    if !(1..=64).contains(&sig) {
        return EINVAL;
    }
    if !crate::compat::linux::proc::process_exists(tgid) {
        return ESRCH;
    }
    crate::compat::linux::proc::post_with_info(tgid, sig as u32, code as i32, ids as u32, (ids >> 32) as u32, value);
    0
}
