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
//! - **Per service** (wave 6, Group 19): each host (`super::svc::Host`) has its own slots,
//!   generation and object area; an object records its host (`ServerObject::svc`), and calls
//!   on it go there.
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

use super::svc::Host;
use crate::compat::linux::chardev::CharDevice;
use crate::fs::FileDescriptor;
use crate::ipc::protocol::{
    SvcId, LX_OBJ_AREA_PAGES,
    LxObjDesc, LX_NOTE_CLOSE, LX_OBJ_BPF_DEVICE, LX_OBJ_CHANGED_OFF, LX_OBJ_COMM, LX_OBJ_DROP, LX_OBJ_FD, LX_OBJ_FDPATH, LX_OBJ_GIVE, LX_OBJ_INSTALL, LX_OBJ_NAME_MAX, LX_OBJ_NOTIFY,
    LX_OBJ_OFF, LX_OBJ_PIN, LX_OBJ_REFS, LX_OBJ_SETFL, LX_OBJ_SLOTS, LX_OBJ_TAKE, LX_OBJ_UNPIN, LX_OBJ_WATCHED_OFF,
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

/// Generations of every host come from one counter (an object's generation is unique).
static GEN: AtomicU64 = AtomicU64::new(0);

/// What the kernel and every descriptor of one object share.
pub struct ObjShared {
    /// The tasks waiting for the object's readiness to change.
    wq: Arc<WaitQueue>,
    /// `O_NONBLOCK` of the open file (shared by `dup`, as on Linux).
    nonblock: AtomicBool,
    /// Group 13: the object itself, to count its references ([`LX_OBJ_REFS`]).
    me: Mutex<alloc::sync::Weak<ServerObject>>,
    // wave6 G21 begin: restart support (`super::restart`)
    /// A restarted (Transparent) service's new instance could not rebind it (`LX_SVC_DEAD`):
    /// stale from then on, like an object of a dead instance.
    dead: AtomicBool,
    // wave6 G21 end
}

/// One host's server objects (`super::svc::Host::objs`).
pub struct HostObjs {
    /// The host's generation: new each time it goes online.
    gen: AtomicU64,
    /// Kernel address of the host's object area (0: the host is offline).
    area: AtomicU64,
    /// The object area's pages (made once, kept across restarts).
    frames: Mutex<Option<Arc<crate::ipc::service::ContiguousFrames>>>,
    /// The live objects by slot (to wake them, and to set their flags).
    reg: Mutex<alloc::vec::Vec<Option<Arc<ObjShared>>>>,
    /// Kernel descriptors kept for the service ([`LX_OBJ_PIN`]), by token.
    pins: Mutex<BTreeMap<u64, Arc<dyn CharDevice>>>,
    /// Group 13: descriptors in flight in the service's Unix sockets ([`LX_OBJ_TAKE`]), by
    /// token. They hold their object as a descriptor would (a pipe end stays open while in
    /// flight).
    kept: Mutex<BTreeMap<u64, FileDescriptor>>,
}

impl HostObjs {
    /// No objects, no area.
    pub fn new() -> Self {
        Self { gen: AtomicU64::new(0), area: AtomicU64::new(0), frames: Mutex::new(None), reg: Mutex::new(alloc::vec::Vec::new()), pins: Mutex::new(BTreeMap::new()), kept: Mutex::new(BTreeMap::new()) }
    }
}

impl Default for HostObjs {
    fn default() -> Self {
        Self::new()
    }
}

fn reg<R>(x: &Host, f: impl FnOnce(&mut alloc::vec::Vec<Option<Arc<ObjShared>>>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut x.objs.reg.lock()))
}

static NEXT_PIN: AtomicU64 = AtomicU64::new(1);
/// Most descriptors kept at once (Linux limits what one user has in flight too).
const MAX_KEPT: usize = 65536;

/// An open server object (the device of a `FileDescriptor::Device`).
pub struct ServerObject {
    slot: u32,
    kind: u32,
    /// The host whose slot it is (wave 6, Group 19).
    svc: SvcId,
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
    /// Group 13: the server's value for the kernel (a pidfd's process, see `LxObjDesc::tag`).
    tag: u64,
    /// Group 13: a signalfd's signals (`LX_OBJ_SIGMASK`); its `poll` is answered here from
    /// the process's (`tag`'s) pending signals, which posting a signal wakes.
    sigmask: AtomicU64,
    // wave6 G21 begin
    /// The service's key for the object (`LxObjDesc::key`), given back by `LX_SVC_LIST`
    /// to a restarted instance so it can rebind the object.
    key: u64,
    // wave6 G21 end
}

impl ServerObject {
    /// The server's slot for the object, if the object belongs to the server online now.
    #[inline]
    pub fn slot(&self) -> Option<u64> {
        let x = super::svc::host(self.svc)?;
        (self.gen == x.objs.gen.load(Ordering::Acquire) && x.objs.area.load(Ordering::Acquire) != 0 && !self.shared.dead.load(Ordering::Relaxed)).then_some(self.slot as u64)
    }

    /// The host whose object it is (`LXS_*`: the id of the serving process).
    pub fn svc(&self) -> SvcId {
        self.svc
    }

    /// The kernel address of the object area of the object's host, if the object is live.
    fn area(&self) -> Option<u64> {
        let x = super::svc::host(self.svc)?;
        let a = x.objs.area.load(Ordering::Acquire);
        (self.gen == x.objs.gen.load(Ordering::Acquire) && a != 0 && !self.shared.dead.load(Ordering::Relaxed)).then_some(a)
    }

    /// `LX_OBJ_KIND_*`.
    pub fn kind(&self) -> u32 {
        self.kind
    }

    /// The server's value for the kernel (`LxObjDesc::tag`: a pidfd's process).
    pub fn tag(&self) -> u64 {
        self.tag
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
        let base = self.area()?;
        let p = (base + LX_OBJ_OFF as u64 + 16 * self.slot as u64) as *const u32;
        // SAFETY: the slot lies in the host's object area, which is never freed
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
        let Some(x) = super::svc::host(self.svc) else { return };
        if self.gen != x.objs.gen.load(Ordering::Acquire) {
            return;
        }
        if self.watched.load(Ordering::Acquire) {
            let _ = super::WATCHED_NET.try_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(1)));
        }
        // wave6 G21: an object the new instance gave up (its slot may be in use again)
        if self.shared.dead.load(Ordering::Acquire) {
            return;
        }
        let slot = self.slot as usize;
        reg(x, |r| {
            if r.get(slot).and_then(|s| s.as_ref()).is_some_and(|s| Arc::ptr_eq(s, &self.shared)) {
                r[slot] = None;
            }
        });
        if !self.quiet.load(Ordering::Acquire) {
            super::note_to(self.svc, LX_NOTE_CLOSE, self.slot as u64, self.kind as u64, 0);
        }
    }
}

impl ServerObject {
    /// Group 13: a transfer between the object and a kernel buffer (`splice`, `sendfile`,
    /// io_uring, aio). The server answers at once (`-EAGAIN` when not ready); a blocking
    /// descriptor waits here on the readiness word, as a call made by the program would.
    fn kernel_io(&self, write: bool, data: &[u8], out: &mut [u8]) -> i64 {
        const EAGAIN: i64 = -11;
        // POLLIN | POLLERR | POLLHUP for a read, POLLOUT | POLLERR for a write
        let want = if write { 0x0004 | 0x0008 } else { 0x0001 | 0x0008 | 0x0010 };
        let Some(dev) = self.shared.me.lock().upgrade() else { return EBADF };
        let dev: Arc<dyn CharDevice> = dev;
        let mut waits = WaitSet::new();
        let mut registered = false;
        loop {
            let r = super::call_obj_kbuf(&dev, write, data, out);
            if r != EAGAIN || self.nonblock() {
                return r;
            }
            if !registered {
                self.add_wait_queues(&mut waits);
                registered = true;
            }
            waits.register();
            if self.poll_events() & want != 0 {
                continue;
            }
            if crate::compat::linux::proc::signal_pending() {
                return crate::compat::linux::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }
}

impl CharDevice for ServerObject {
    fn read(&self, buf: &mut [u8]) -> i64 {
        // Reads of programs are forwarded before they get here (`vfs::stream_io`); this is
        // the kernel's own (Group 13: a kernel buffer, at most the copy area per call)
        let n = buf.len().min(crate::ipc::protocol::LX_DATA_SIZE);
        self.kernel_io(false, &[], &mut buf[..n])
    }

    fn write(&self, data: &[u8]) -> i64 {
        // The kernel's own writes (Group 13): in pieces of the copy area's size
        let mut done = 0usize;
        while done < data.len() || data.is_empty() {
            let n = (data.len() - done).min(crate::ipc::protocol::LX_DATA_SIZE);
            let r = self.kernel_io(true, &data[done..done + n], &mut []);
            if r < 0 {
                return if done > 0 { done as i64 } else { r };
            }
            done += r as usize;
            if r == 0 || data.is_empty() {
                break;
            }
        }
        done as i64
    }

    fn poll_events(&self) -> u32 {
        if self.kind == crate::ipc::protocol::LX_OBJ_KIND_SIGNALFD && self.slot().is_some() {
            return if crate::compat::linux::proc::pending_for(self.tag, self.sigmask.load(Ordering::Relaxed)) { 0x0001 } else { 0 };
        }
        self.word().map_or(STALE, |w| w.0)
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.shared.wq.clone()));
        // Someone waits for this object: the server rings the doorbell for it from now on
        // (set before the caller reads the readiness word)
        if let Some(base) = self.area() {
            let words = (base + LX_OBJ_WATCHED_OFF as u64) as *const AtomicU64;
            // SAFETY: the bitmap lies in the host's object area
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
        // wave8 GD begin: a device service's character device (its mode is `S_IFCHR`): the
        // device number is the object's key (libdrm finds `/sys/dev/char/226:0` by it).
        // (Groups I and S planned the same rule: this one is kept.)
        if self.mode & 0o170000 == 0o020000 && self.key != 0 && self.kind != crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            return self.key;
        }
        // wave8 GD end
        // wave8 GT begin: a terminal of tty-server: its device number (the key)
        if matches!(self.kind, crate::ipc::protocol::LX_OBJ_KIND_PTY_M | crate::ipc::protocol::LX_OBJ_KIND_PTY_S) {
            return self.key;
        }
        // wave8 GT end
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
        // (Group 13: both ends of a pipe, and a socket, report the server's inode number)
        // wave6 G24: a bpf map's tag is its key and value sizes, not an inode number
        st.st_ino = if self.tag != 0 && self.kind != crate::ipc::protocol::LX_OBJ_KIND_PIDFD && self.kind != crate::ipc::protocol::LX_OBJ_KIND_BPF_MAP { self.tag } else { 0x2_0000_0000 | (self.gen & 0xFFFF) << 16 | self.slot as u64 };
        st.st_size = self.word().map_or(0, |w| w.2) as i64;
        st.st_blksize = 4096;
        // wave8 GD begin: a device service's character device: devtmpfs, its device number
        if self.mode & 0o170000 == 0o020000 && self.key != 0 && self.kind != crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            st.st_dev = 6;
            st.st_rdev = self.key;
            st.st_ino = self.key | 0x1_0000_0000;
        }
        // wave8 GD end
        // wave7 G7-4: a pseudo file of linux-server: its file system's device (the `tag` is
        // the inode number its `stat` reports, the key the device)
        if self.kind == crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            st.st_ino = self.tag;
            st.st_dev = self.key;
        }
        // wave8 GI begin: a device service's object (a character device, its key the device
        // number): the device node's numbers (libinput and logind compare `st_rdev` with the
        // node's)
        if self.mode & 0o170000 == 0o020000 && self.key != 0 && self.kind != crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            st.st_dev = 6; // devtmpfs, as the kernel's own devices
            st.st_rdev = self.key;
            st.st_ino = self.key | 0x1_0000_0000;
        }
        // wave8 GI end
        // wave8 GT begin: a terminal of tty-server reports what `stat` of its path does
        // (devpts' device, the inode in the tag, the device number in the key), so `ttyname`
        // matches the two
        if matches!(self.kind, crate::ipc::protocol::LX_OBJ_KIND_PTY_M | crate::ipc::protocol::LX_OBJ_KIND_PTY_S) {
            st.st_dev = 0x18; // devpts (`compat::linux::pty::PTS_DEV`)
            st.st_ino = self.tag;
            st.st_rdev = self.key;
            st.st_blksize = 1024;
        }
        // wave8 GT end
        st
    }

    // wave7 G7-4 begin: `lseek` and `pread64` on a pseudo file go to its server
    fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
        if self.kind != crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            return None;
        }
        let dev: Arc<dyn CharDevice> = self.shared.me.lock().upgrade()?;
        Some(super::call_obj_pseudo(&dev, crate::ipc::protocol::LX_KCALL_PSEEK, offset as u64, whence as u64, &mut []))
    }

    fn pread(&self, buf: &mut [u8], offset: u64) -> Option<i64> {
        if self.kind != crate::ipc::protocol::LX_OBJ_KIND_PSEUDO {
            return None;
        }
        let dev: Arc<dyn CharDevice> = self.shared.me.lock().upgrade()?;
        let n = buf.len().min(crate::ipc::protocol::LX_DATA_SIZE);
        // (into a kernel buffer first: the answer is copied while interrupts are off)
        let mut tmp = alloc::vec![0u8; n];
        let r = super::call_obj_pseudo(&dev, crate::ipc::protocol::LX_KCALL_PREAD, offset, 0, &mut tmp);
        if r > 0 {
            // (never more than was asked for, whatever the server answered)
            let k = (r as usize).min(n);
            buf[..k].copy_from_slice(&tmp[..k]);
            return Some(k as i64);
        }
        Some(r)
    }
    // wave7 G7-4 end

    fn as_server(&self) -> Option<&ServerObject> {
        Some(self)
    }

    fn deliver_notification(&self, data: &[u8]) -> bool {
        // wave6 G19: an in-kernel message queue's SIGEV_THREAD cookie for a netlink socket of
        // the network service (only the IPC service switched back to the kernel)
        if self.kind != crate::ipc::protocol::LX_OBJ_KIND_NETLINK {
            return false;
        }
        let Some(me) = self.shared.me.lock().upgrade() else { return false };
        let me: Arc<dyn CharDevice> = me;
        super::call_obj_deliver(&me, data) >= 0
    }

    fn socket_call(&self, num: u64, a: [u64; 6]) -> Option<i64> {
        // Group 13: socket calls on the server's sockets go to it
        let me: Arc<dyn CharDevice> = self.shared.me.lock().upgrade()?;
        Some(crate::compat::linux::unix::server_call(&me, num, a))
    }

    fn edges(&self) -> Option<u64> {
        if self.kind == crate::ipc::protocol::LX_OBJ_KIND_SIGNALFD {
            return None;
        }
        Some(self.word().map_or(u64::MAX - 1, |w| w.1 as u64))
    }
}

/// Host `x` went online: a new generation of objects, with empty readiness slots in its
/// object area (made now if it has none). Returns 0, or `-ENOMEM`.
pub(super) fn online(x: &Host) -> i64 {
    let Some(base) = area_of(x) else { return -12 };
    // SAFETY: the slots and the bitmaps lie in the object area
    unsafe {
        core::ptr::write_bytes((base + LX_OBJ_OFF as u64) as *mut u8, 0, 16 * LX_OBJ_SLOTS);
        core::ptr::write_bytes((base + LX_OBJ_CHANGED_OFF as u64) as *mut u8, 0, LX_OBJ_SLOTS / 8);
        core::ptr::write_bytes((base + LX_OBJ_WATCHED_OFF as u64) as *mut u8, 0, LX_OBJ_SLOTS / 8);
    }
    reg(x, |r| {
        r.clear();
        r.resize(LX_OBJ_SLOTS, None);
    });
    x.objs.gen.store(GEN.fetch_add(1, Ordering::AcqRel) + 1, Ordering::Release);
    x.objs.area.store(base, Ordering::Release);
    0
}

/// The kernel address of host `x`'s object area, made the first time.
fn area_of(x: &Host) -> Option<u64> {
    let mut f = x.objs.frames.lock();
    if f.is_none() {
        *f = Some(crate::ipc::service::ContiguousFrames::allocate(LX_OBJ_AREA_PAGES)?);
    }
    f.as_ref().map(|c| crate::memory::frame_allocator::phys_to_virt(c.base) as u64)
}

/// `LX_CTL_OBJAREA`: maps host `x`'s object area into the calling process; its address.
pub(super) fn map_area(x: &Host) -> i64 {
    if area_of(x).is_none() {
        return -12;
    }
    let Some(frames) = x.objs.frames.lock().clone() else { return -12 };
    match crate::ipc::service::map_into_current(frames, LX_OBJ_AREA_PAGES) {
        Ok(a) => a as i64,
        Err(e) => e,
    }
}

/// Host `x` went away: every object of it goes stale and its waiters wake (they see
/// `POLLERR | POLLHUP`); kept descriptors are let go.
pub(super) fn offline(x: &Host) {
    x.objs.area.store(0, Ordering::Release);
    x.objs.gen.store(GEN.fetch_add(1, Ordering::AcqRel) + 1, Ordering::Release);
    let mut woken: alloc::vec::Vec<Arc<ObjShared>> = alloc::vec::Vec::new();
    reg(x, |r| {
        for s in r.iter_mut() {
            if let Some(o) = s.take() {
                woken.push(o);
            }
        }
    });
    for o in &woken {
        o.wq.wake_all();
    }
    let pins = core::mem::take(&mut *x.objs.pins.lock());
    drop(pins);
    // Descriptors in flight in the service's sockets (Group 13)
    let kept = core::mem::take(&mut *x.objs.kept.lock());
    for (_, d) in kept {
        release_kept(d);
    }
    // The bpf device programs went with the service that hosts bpf
    if super::svc::host_of(crate::ipc::protocol::LXS_SEC) == x.id {
        crate::compat::linux::bpf::set_server_device_programs(&[]);
    }
}

// wave6 G21 begin: restart support (`super::restart`, design 5.1 point 4)

/// A Transparent service's new instance (host `x`) went online after adopting the old one's
/// objects (`LX_SVC_ADOPT`): the objects keep their generation and readiness words (the
/// object area outlives the process), and their waiters wake to read the words again.
pub(super) fn online_adopt(x: &Host) -> i64 {
    let Some(base) = area_of(x) else { return -12 };
    x.objs.area.store(base, Ordering::Release);
    let woken: alloc::vec::Vec<Arc<ObjShared>> = reg(x, |r| r.iter().flatten().cloned().collect());
    for o in &woken {
        o.wq.wake_all();
    }
    0
}

/// `LX_SVC_DEAD(slot)`: host `x`'s new instance cannot rebind the object in `slot`: it goes
/// stale (its calls fail with its kind's error, it polls `POLLERR | POLLHUP`), and the new
/// instance may use the slot again (the old object's end is not told to it).
pub(super) fn mark_dead(x: &Host, slot: usize) {
    if let Some(o) = reg(x, |r| r.get_mut(slot).and_then(|s| s.take())) {
        o.dead.store(true, Ordering::Release);
        o.wq.wake_all();
    }
}

/// `LX_SVC_LIST`: host `x`'s live objects from slot `start` on (at most `cap`), as
/// `(slot, kind, key)`.
pub(super) fn list_live(x: &Host, start: usize, cap: usize, out: &mut alloc::vec::Vec<crate::ipc::protocol::LxSvcObj>) {
    let live: alloc::vec::Vec<(usize, Arc<ObjShared>)> =
        reg(x, |r| r.iter().enumerate().skip(start).filter_map(|(i, s)| s.as_ref().map(|s| (i, s.clone()))).take(cap).collect());
    for (slot, s) in live {
        // (an object whose last descriptor is going right now has no ServerObject any more)
        let Some(o) = s.me.lock().upgrade() else { continue };
        out.push(crate::ipc::protocol::LxSvcObj { slot: slot as u32, kind: o.kind, key: o.key });
    }
}

// wave8 GS begin
/// The keys of service `svc`'s live objects of kind `kind` (`/proc/asound`, kept in the
/// kernel, asks whether a sound device is still open: the service learns of the last close
/// only from its notification ring, a moment later).
pub fn live_keys(svc: crate::ipc::protocol::SvcId, kind: u32) -> alloc::vec::Vec<u64> {
    let Some(x) = super::svc::host(super::svc::host_of(svc)) else { return alloc::vec::Vec::new() };
    let mut v = alloc::vec::Vec::new();
    list_live(x, 0, usize::MAX, &mut v);
    v.into_iter().filter(|o| o.kind == kind).map(|o| o.key).collect()
}
// wave8 GS end

/// The error a call on `dev`, a server object of a dead instance, gives (design 5.2,
/// FailObjects: per kind).
pub fn stale_errno(dev: &ServerObject) -> i64 {
    super::restart_policy::stale_errno(dev.kind)
}
// wave6 G21 end

/// The doorbell ([`LX_SIGNAL_OBJS`]) of host `x`: wakes the waiters of every object the
/// service marked in the changed bitmap.
///
/// [`LX_SIGNAL_OBJS`]: crate::ipc::protocol::LX_SIGNAL_OBJS
pub(super) fn on_doorbell(x: &Host) {
    let base = x.objs.area.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let words = (base + LX_OBJ_CHANGED_OFF as u64) as *const AtomicU64;
    let mut wake: alloc::vec::Vec<Arc<WaitQueue>> = alloc::vec::Vec::new();
    for i in 0..LX_OBJ_SLOTS / 64 {
        // SAFETY: the bitmap lies in the object area; the service sets bits with atomic or
        let w = unsafe { (*words.add(i)).swap(0, Ordering::AcqRel) };
        if w == 0 {
            continue;
        }
        reg(x, |r| {
            let mut bits = w;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Some(Some(o)) = r.get(i * 64 + b) {
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
pub(super) fn current_fd(fd: u64) -> Option<super::HeldObj> {
    crate::task::with_current_fds_mut(|fds| object_in(fds, fd))
}

/// [`current_fd`] in descriptor table `fds` (locked by the caller): the lock-free path of
/// `crate::lx` takes the table's lock with `try_lock` and calls this.
pub(super) fn object_in(fds: &crate::fs::FdTable, fd: u64) -> Option<super::HeldObj> {
    let dev = match fds.get(fd as i32 as usize) {
        Some(FileDescriptor::Device(d)) => d.clone(),
        _ => return None,
    };
    let (slot, flags, svc) = {
        let o = dev.as_server()?;
        (o.slot()?, o.flags(), o.svc)
    };
    Some((dev, slot, flags, svc))
}

/// The descriptor table of request `id`'s caller.
fn client_fds(id: u64) -> Result<crate::fs::SharedFdTable, i64> {
    let client = super::client_of(id).ok_or(ESRCH)?;
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()).ok_or(ESRCH)
}

/// `SYS_LX_OBJ(op, a, b, c)`: the server's operations on its objects (see the `LX_OBJ_*`
/// constants in `ipc/protocol.rs`).
pub fn obj_ctl(op: u64, a: u64, b: u64, c: u64) -> i64 {
    let h = match super::server_caller() {
        Ok((_, _, h)) => h,
        Err(e) => return e,
    };
    // wave8 GI begin: the input service's ring and device controls (ops 62, 63; they work before the
    // service has a host)
    if op == crate::ipc::protocol::LX_OBJ_INPUT_RING || op == crate::ipc::protocol::LX_OBJ_INPUT_CTL {
        return crate::ipc::input::obj_op(h, op, a, b, c);
    }
    // wave8 GI end
    let Some(x) = super::svc::host(h) else { return ESRCH };
    // The operations naming a request: only the service's own (Group 19)
    use crate::ipc::protocol::{LX_OBJ_NETCANCEL, LX_OBJ_NETCHECK, LX_OBJ_NETWAIT, LX_OBJ_SIGTHREAD};
    if matches!(op, LX_OBJ_INSTALL | LX_OBJ_FD | LX_OBJ_NETCHECK | LX_OBJ_NETWAIT | LX_OBJ_NETCANCEL | LX_OBJ_SIGTHREAD | LX_OBJ_COMM | LX_OBJ_FDPATH | LX_OBJ_PIN | LX_OBJ_TAKE | LX_OBJ_GIVE)
        && crate::ipc::protocol::lx_req_svc(a) != h
        && !(matches!(op, LX_OBJ_INSTALL | LX_OBJ_FD) && super::dcall::may_use(a)) // wave6 G20: delegation
    {
        return ESRCH;
    }
    // wave8 GX2 begin: a request's partial answer (`LX_OBJ_PARTIAL`, the service's own
    // requests only): what its caller gets if the service dies before answering
    if op == crate::ipc::protocol::LX_OBJ_PARTIAL {
        if crate::ipc::protocol::lx_req_svc(a) != h {
            return ESRCH;
        }
        return x86_64::instructions::interrupts::without_interrupts(|| {
            x.lx(|s| match s.reqs.iter_mut().find(|r| r.id == a && matches!(r.state, super::svc::RState::Delivered | super::svc::RState::Pending)) {
                Some(r) => {
                    r.partial = b as i64;
                    0
                }
                None => ESRCH,
            })
        });
    }
    // wave8 GX2 end
    // wave7 G7-5: file bytes through the page cache for vfs-server (execve's heads)
    if op == crate::ipc::protocol::LX_FH_READ {
        return super::xexec::read(h, a, b, c);
    }
    // wave8 GT begin: tty-server's console and process-identity primitives (op 70)
    if op == crate::ipc::protocol::LX_OBJ_TTY {
        return super::console::ctl(h, a, b, c);
    }
    // wave8 GT end
    // wave7 G7-4: the info primitives (`info`, ops 56..=61)
    if super::info::glue::is_info(op) {
        return super::info::glue::ctl(h, op, a, b, c);
    }
    // wave7 G7-2: the file service's handle operations (`fileh`, ops 32..; wave7 G7-6: up to
    // 51, 7-6's 48..=51)
    // wave7 G7-7: and 7-7's LX_FH_MNTTAB (53)
    if (crate::ipc::protocol::LX_FH_INSTALL..crate::ipc::protocol::LX_FH_INSTALL + 20).contains(&op) || op == crate::ipc::protocol::LX_FH_MNTTAB {
        return super::fileh::ctl(h, op, a, b, c);
    }
    // wave8 GF begin: the mount calls' table operations (72..=74)
    if (crate::ipc::protocol::LX_FH_MNTGET..=crate::ipc::protocol::LX_FH_TMPFSID).contains(&op) {
        return super::fileh::ctl(h, op, a, b, c);
    }
    // wave8 GF end
    // wave10 G7b-1 begin: lx-proc's process-identity primitives (op 75)
    #[cfg(target_os = "uefi")]
    if op == crate::ipc::protocol::LX_OBJ_PROCID {
        return super::procsvc::ctl(h, a, b, c);
    }
    // wave10 G7b-1 end
    // wave9 G6b-3: Landlock domains and ABAC decisions for the file service (76, 77)
    if op == crate::ipc::protocol::LX_FH_LANDLOCK || op == crate::ipc::protocol::LX_FH_ABAC {
        return super::fileh::ctl(h, op, a, b, c);
    }
    // wave9 GM begin: the in-memory tmpfs files (78)
    if op == crate::ipc::protocol::LX_FH_TMEM {
        return super::fileh::ctl(h, op, a, b, c);
    }
    // wave9 GM end
    // wave10 G8-2 begin: System V shared memory's attachments (`shm`, op 79)
    if op == crate::ipc::protocol::LX_OBJ_SHM {
        return super::shm::ctl(h, a, b, c);
    }
    // wave10 G8-2 end
    // wave8 GS begin: the sound service's operations (`ipc::sound`, op 64)
    if op == crate::ipc::protocol::LX_OBJ_SND {
        return crate::ipc::sound::ctl(h, a, b, c);
    }
    // wave8 GS end
    match op {
        LX_OBJ_INSTALL => install(x, a, b),
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
            match dev.as_server().filter(|o| o.svc == h) {
                Some(o) => match o.slot() {
                    Some(slot) => (slot | (o.kind() as u64) << 32 | (o.nonblock() as u64) << 62) as i64,
                    // wave6 G24: an object of this service's previous instance (not adopted):
                    // its per-kind error (a bpf map after an lx-sec restart: EBADF)
                    None => stale_errno(o),
                },
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
            match reg(x, |r| r.get(a as usize).cloned().flatten()) {
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
                // wave8 GX2: also another service's object (lx-ipc's message queue keeps
                // lx-net's netlink socket for glibc's SIGEV_THREAD; `LX_OBJ_NOTIFY` forwards
                // the notification to its owner)
                Some(FileDescriptor::Device(d)) if d.as_server().is_none_or(|o| o.svc != h && o.kind() == crate::ipc::protocol::LX_OBJ_KIND_NETLINK) => d.clone(),
                _ => return EBADF,
            };
            let token = NEXT_PIN.fetch_add(1, Ordering::Relaxed);
            x.objs.pins.lock().insert(token, dev);
            token as i64
        }
        LX_OBJ_UNPIN => {
            let d = x.objs.pins.lock().remove(&a);
            match d {
                Some(_) => 0,
                None => EINVAL,
            }
        }
        crate::ipc::protocol::LX_OBJ_SIGMASK => {
            if a as usize >= LX_OBJ_SLOTS {
                return EINVAL;
            }
            let o = reg(x, |r| r.get(a as usize).cloned().flatten()).and_then(|s| s.me.lock().upgrade());
            match o {
                Some(o) => {
                    o.sigmask.store(b, Ordering::Relaxed);
                    0
                }
                None => EBADF,
            }
        }
        crate::ipc::protocol::LX_OBJ_PROC => {
            if !crate::compat::linux::proc::process_exists(a) {
                return ESRCH;
            }
            // (locked: the server's pidfd must not take an exited process for a running one)
            if crate::compat::linux::proc::has_exited_locked(a) {
                2
            } else {
                1
            }
        }
        LX_OBJ_TAKE => take(x, a, b, c),
        LX_OBJ_GIVE => give(x, a, b, c),
        LX_OBJ_DROP => {
            if c != 0 || b > MAX_KEPT as u64 {
                return EINVAL;
            }
            let raw = match crate::compat::linux::vfs::copy_in(a, b as usize * 8) {
                Ok(r) => r,
                Err(e) => return e,
            };
            let gone: alloc::vec::Vec<FileDescriptor> = {
                let mut kept = x.objs.kept.lock();
                raw.chunks_exact(8).filter_map(|t| kept.remove(&u64::from_le_bytes(t.try_into().unwrap()))).collect()
            };
            for d in gone {
                release_kept(d);
            }
            0
        }
        LX_OBJ_REFS => {
            if a as usize >= LX_OBJ_SLOTS {
                return EINVAL;
            }
            match reg(x, |r| r.get(a as usize).cloned().flatten()) {
                Some(s) => {
                    let n = s.me.lock().strong_count();
                    n as i64
                }
                None => 0,
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
            let dev = x.objs.pins.lock().get(&a).cloned();
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
fn install(x: &Host, id: u64, desc: u64) -> i64 {
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
    let gen = x.objs.gen.load(Ordering::Acquire);
    if x.objs.area.load(Ordering::Acquire) == 0 {
        return EINVAL;
    }
    // (the caller found once: wave6 G21 remembers the install by it)
    let Some(client) = super::client_of(id) else { return ESRCH };
    let Some(fds) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()) else { return ESRCH };
    let shared = Arc::new(ObjShared {
        wq: WaitQueue::new_shared(),
        nonblock: AtomicBool::new(d.flags & O_NONBLOCK != 0),
        me: Mutex::new(alloc::sync::Weak::new()),
        dead: AtomicBool::new(false),
    });
    let taken = reg(x, |r| {
        if r.get(slot).is_none_or(|s| s.is_some()) {
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
        svc: x.id,
        gen,
        shared,
        name: String::from_utf8_lossy(&d.name[..d.name_len as usize]).into_owned(),
        mode: d.mode,
        uid: d.uid,
        gid: d.gid,
        quiet: AtomicBool::new(false),
        watched: AtomicBool::new(false),
        tag: d.tag,
        sigmask: AtomicU64::new(0),
        key: d.key,
    });
    *obj.shared.me.lock() = Arc::downgrade(&obj);
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
        Ok(fd) => {
            // wave6 G21: remembered in case the answer is lost in a restart
            super::restart::installed(client, fd as i32);
            fd as i64
        }
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

// ----------------------------------------------------------------------
// Descriptor passing (Group 13, wave 5, step 4)
// ----------------------------------------------------------------------
//
// A Unix socket lives in the server, but what it carries (`SCM_RIGHTS`) may be any
// descriptor: a regular file, a DRM device, a memfd (Wayland's buffers), another server
// object. The server never holds descriptors itself: `LX_OBJ_TAKE` moves a reference to
// each named descriptor of the sender into the kernel's `KEPT` table under a token (the
// message carries the tokens); `LX_OBJ_GIVE` installs kept descriptors in the receiver's
// table; `LX_OBJ_DROP` lets them go (a message dropped unread, a control buffer too small:
// `MSG_CTRUNC`). A kept server object counts in `LX_OBJ_REFS`, so the server can tell
// sockets alive only through their own queues.

/// Takes another reference to `d` (a pipe end counts its readers and writers).
fn hold(d: &FileDescriptor) {
    match d {
        FileDescriptor::PipeRead(p) => p.lock().add_reader(),
        FileDescriptor::PipeWrite(p) => p.lock().add_writer(),
        _ => {}
    }
}

/// Lets a kept descriptor go (the reverse of [`hold`]).
fn release_kept(d: FileDescriptor) {
    match &d {
        FileDescriptor::PipeRead(p) => p.lock().drop_reader(),
        FileDescriptor::PipeWrite(p) => p.lock().drop_writer(),
        _ => {}
    }
    drop(d);
}

/// What descriptor `d` is to host `h`: `slot | kind << 32 | 1 << 63` for one of its
/// objects, 0 otherwise (a kernel descriptor, or another service's object).
fn describe(d: &FileDescriptor, h: SvcId) -> u64 {
    if let FileDescriptor::Device(dev) = d {
        if let Some(o) = dev.as_server().filter(|o| o.svc == h) {
            if let Some(slot) = o.slot() {
                return slot | (o.kind() as u64) << 32 | 1 << 63;
            }
        }
    }
    0
}

/// [`LX_OBJ_TAKE`]`(request id, buf, n)`.
fn take(x: &Host, id: u64, buf: u64, n: u64) -> i64 {
    if n == 0 || n > 512 {
        return EINVAL;
    }
    let raw = match crate::compat::linux::vfs::copy_in(buf, n as usize * 24) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let fds = match client_fds(id) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let mut descs = alloc::vec::Vec::with_capacity(n as usize);
    {
        let t = fds.lock();
        for e in raw.chunks_exact(24) {
            let fd = u64::from_le_bytes(e[0..8].try_into().unwrap()) as i64;
            match (fd >= 0).then(|| t.get(fd as usize)).flatten() {
                Some(d) => descs.push(d.clone()),
                None => return EBADF,
            }
        }
    }
    let mut out = raw;
    {
        let mut kept = x.objs.kept.lock();
        if kept.len() + descs.len() > MAX_KEPT {
            return -109; // ETOOMANYREFS
        }
        for (i, d) in descs.into_iter().enumerate() {
            hold(&d);
            let token = NEXT_PIN.fetch_add(1, Ordering::Relaxed);
            out[i * 24 + 8..i * 24 + 16].copy_from_slice(&token.to_le_bytes());
            out[i * 24 + 16..i * 24 + 24].copy_from_slice(&describe(&d, x.id).to_le_bytes());
            kept.insert(token, d);
        }
    }
    crate::compat::linux::vfs::copy_out(buf, &out).map_or_else(|e| e, |()| 0)
}

/// [`LX_OBJ_GIVE`]`(request id, buf, n | flags << 32)`.
fn give(x: &Host, id: u64, buf: u64, nf: u64) -> i64 {
    let n = nf & 0xFFFF_FFFF;
    let cloexec = (nf >> 32) as u32 & O_CLOEXEC != 0;
    if n == 0 || n > 512 {
        return EINVAL;
    }
    let mut raw = match crate::compat::linux::vfs::copy_in(buf, n as usize * 16) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let fds = match client_fds(id) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let mut err = 0;
    for e in raw.chunks_exact_mut(16) {
        let token = u64::from_le_bytes(e[0..8].try_into().unwrap());
        e[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        if err != 0 {
            continue;
        }
        let Some(d) = x.objs.kept.lock().remove(&token) else {
            err = EINVAL;
            continue;
        };
        let mut t = fds.lock();
        match t.alloc_fd(d.clone()) {
            Ok(fd) => {
                t.set_cloexec(fd, cloexec);
                drop(t);
                // (the kept reference moved into the table)
                drop(d);
                e[8..16].copy_from_slice(&(fd as u64).to_le_bytes());
            }
            Err(_) => {
                drop(t);
                x.objs.kept.lock().insert(token, d);
                err = EMFILE;
            }
        }
    }
    match crate::compat::linux::vfs::copy_out(buf, &raw) {
        Ok(()) => err,
        Err(e) => e,
    }
}

/// `SYS_LX_SIGTAKE(id, mask, buf)` (native 63, Group 13): **sig_take**. Takes the lowest
/// pending signal in `mask` of request `id`'s caller (its thread's first, then its
/// process's) without delivering it, and writes its 128-byte `struct signalfd_siginfo` to
/// `buf` (server memory). Returns 128, or 0 when none is pending.
pub fn sig_take(id: u64, mask: u64, buf: u64, _unused: u64) -> i64 {
    use crate::compat::linux::proc;
    if let Err(e) = super::server_caller() {
        return e;
    }
    let Some(tid) = super::client_of(id) else { return ESRCH };
    let Some(tgid) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| t.tgid) else { return ESRCH };
    let mask = mask & !((1 << 8) | (1 << 18)); // never SIGKILL or SIGSTOP
    let Some(info) = proc::take_signal_info_of(tid, tgid, mask) else { return 0 };
    let mut rec = [0u8; 128];
    let sig = info.signo;
    rec[0..4].copy_from_slice(&sig.to_le_bytes()); // ssi_signo
    rec[8..12].copy_from_slice(&info.code.to_le_bytes()); // ssi_code
    rec[12..16].copy_from_slice(&info.pid.to_le_bytes()); // ssi_pid
    rec[16..20].copy_from_slice(&info.uid.to_le_bytes()); // ssi_uid
    rec[44..48].copy_from_slice(&(info.value as u32).to_le_bytes()); // ssi_int
    rec[48..56].copy_from_slice(&info.value.to_le_bytes()); // ssi_ptr
    if sig == proc::SIGCHLD {
        // Programs check ssi_code before reaping (util-linux script)
        let (code, pid, status) = proc::sigchld_details(tgid);
        rec[8..12].copy_from_slice(&code.to_le_bytes());
        rec[12..16].copy_from_slice(&(pid as u32).to_le_bytes());
        rec[40..44].copy_from_slice(&status.to_le_bytes()); // ssi_status
    }
    crate::compat::linux::vfs::copy_out(buf, &rec).map_or_else(|e| e, |()| 128)
}

// ----------------------------------------------------------------------
// Writes the kernel makes later (Group 13): io_uring's registered eventfd
// ----------------------------------------------------------------------

/// Server objects to write a u64 to, and the kernel task that does it (the code posting
/// an io_uring completion holds the ring's lock, so it cannot wait for the server).
static LATER: Mutex<alloc::vec::Vec<(Arc<dyn CharDevice>, u64)>> = Mutex::new(alloc::vec::Vec::new());
static LATER_WQ: WaitQueue = WaitQueue::new();
static LATER_TASK: AtomicBool = AtomicBool::new(false);

/// Writes `value` (8 bytes) to server object `dev` soon, from a kernel task.
pub fn write_later(dev: Arc<dyn CharDevice>, value: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| LATER.lock().push((dev, value)));
    if !LATER_TASK.swap(true, Ordering::AcqRel) {
        crate::task::spawn("lx-later", later_task, crate::task::TaskPriority::Normal);
    }
    LATER_WQ.wake_all();
}

fn later_task() {
    loop {
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&LATER_WQ));
        waits.register();
        let work = x86_64::instructions::interrupts::without_interrupts(|| core::mem::take(&mut *LATER.lock()));
        if work.is_empty() {
            waits.wait(None);
            continue;
        }
        for (dev, v) in work {
            let _ = dev.write(&v.to_ne_bytes());
        }
    }
}

// Host tests (test wave, Group 30): tests/host-t30 compiles this file with them
#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_obj.rs"]
pub(crate) mod tests;
