//! # POSIX message queues (`mq_open` and family)
//!
//! A queue is named (per IPC namespace), holds up to `mq_maxmsg` messages of up to
//! `mq_msgsize` bytes, and hands them out highest priority first (oldest first within a
//! priority). `mq_open` returns a descriptor that `poll`/`epoll` can watch (readable while
//! a message waits, writable while there is room); reading it gives Linux's status line.
//! `mq_timedsend`/`mq_timedreceive` block (absolute `CLOCK_REALTIME` timeouts) unless the
//! descriptor is non-blocking. `mq_notify` registers one process to hear when a message
//! arrives in an empty queue nobody is waiting on: by a signal (`SI_MESGQ`), or for glibc's
//! `SIGEV_THREAD`, by a message on the netlink socket glibc passes. A queue lives until it
//! is unlinked and its last descriptor is closed.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const EMSGSIZE: i64 = -90;
const ENAMETOOLONG: i64 = -36;
const ETIMEDOUT: i64 = -110;

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
/// `si_code` of a message queue notification.
const SI_MESGQ: i32 = -3;
/// Length of glibc's `SIGEV_THREAD` cookie; its last byte says why it was sent.
const NOTIFY_COOKIE_LEN: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;

/// Limits for unprivileged callers (`/proc/sys/fs/mqueue`), and with `CAP_SYS_RESOURCE`.
const MSG_MAX: u64 = 10;
const MSGSIZE_MAX: u64 = 8192;
const HARD_MSG_MAX: u64 = 65536;
const HARD_MSGSIZE_MAX: u64 = 16 * 1024 * 1024;
const MQ_PRIO_MAX: u64 = 32768;
const QUEUES_MAX: usize = 256;

/// How the registered process hears of a message.
enum Notify {
    None,
    Signal { sig: u32, value: u64 },
    Thread { sink: Arc<dyn CharDevice>, cookie: [u8; NOTIFY_COOKIE_LEN] },
}

/// A message queue.
pub struct Queue {
    name: String,
    uid: u32,
    gid: u32,
    mode: u32,
    maxmsg: u64,
    msgsize: u64,
    /// Highest priority first, oldest first within a priority.
    msgs: Vec<(u32, Vec<u8>)>,
    bytes: u64,
    /// The registered process and how to notify it.
    notify: Option<(u64, Notify)>,
    /// Receivers blocked on the queue (a notification is only sent when there are none).
    receivers: u32,
    wq: Arc<WaitQueue>,
}

/// Queues by (IPC namespace, name).
static QUEUES: Mutex<BTreeMap<(u64, String), Arc<Mutex<Queue>>>> = Mutex::new(BTreeMap::new());

/// An open message queue descriptor.
pub struct MqHandle {
    q: Arc<Mutex<Queue>>,
    read: bool,
    write: bool,
    nonblock: AtomicBool,
}

impl CharDevice for MqHandle {
    fn read(&self, buf: &mut [u8]) -> i64 {
        // Linux's status line for the queue
        let q = self.q.lock();
        let (kind, sig, pid) = match &q.notify {
            Some((pid, Notify::Signal { sig, .. })) => (SIGEV_SIGNAL, *sig as i32, *pid),
            Some((pid, Notify::Thread { .. })) => (SIGEV_THREAD, 0, *pid),
            Some((pid, Notify::None)) => (SIGEV_NONE, 0, *pid),
            None => (0, 0, 0),
        };
        let text = alloc::format!("QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n", q.bytes, kind, sig, pid);
        let n = text.len().min(buf.len());
        buf[..n].copy_from_slice(&text.as_bytes()[..n]);
        n as i64
    }

    fn write(&self, _data: &[u8]) -> i64 {
        EINVAL
    }

    fn poll_events(&self) -> u32 {
        let q = self.q.lock();
        let mut ev = 0;
        if self.read && !q.msgs.is_empty() {
            ev |= 0x0041; // POLLIN | POLLRDNORM
        }
        if self.write && (q.msgs.len() as u64) < q.maxmsg {
            ev |= 0x0104; // POLLOUT | POLLWRNORM
        }
        ev
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.q.lock().wq.clone()));
    }

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        alloc::format!("/{}", self.q.lock().name)
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    fn stat(&self) -> super::types::LinuxStat {
        let q = self.q.lock();
        let mut st = super::types::LinuxStat::default();
        st.st_mode = 0o100000 | q.mode;
        st.st_uid = q.uid;
        st.st_gid = q.gid;
        st.st_nlink = 1;
        st.st_size = q.bytes as i64;
        st.st_blksize = 4096;
        st
    }

    fn as_mqueue(&self) -> Option<&MqHandle> {
        Some(self)
    }
}

/// The caller's `(pid, real uid, euid, egid, may exceed limits, bypasses permissions)`.
fn caller() -> (u64, u32, u32, u32, bool, bool) {
    let (_, pid) = super::proc::current_ids();
    let (uid, euid, egid, resource, override_) = crate::task::with_current_task_mut(|t| {
        (t.uid, t.euid, t.egid, t.caps.has(1 << 24), t.caps.has(1 << 1)) // CAP_SYS_RESOURCE, CAP_DAC_OVERRIDE
    })
    .unwrap_or((u32::MAX, u32::MAX, u32::MAX, false, false));
    (pid, uid, euid, egid, resource, override_)
}

/// The queue name of a user `mq_open` name (glibc has removed the leading '/').
fn queue_name(ptr: u64) -> Result<String, i64> {
    let raw = super::vfs::user_path(ptr)?;
    if raw.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    if raw.is_empty() || raw.contains(&b'/') || raw == b"." || raw == b".." {
        return Err(EINVAL);
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// Whether access mode `want` (4 read, 2 write) is allowed by `mode` for the caller.
fn allowed(q: &Queue, euid: u32, egid: u32, override_: bool, want: u32) -> bool {
    if override_ {
        return true;
    }
    let bits = if euid == q.uid {
        q.mode >> 6
    } else if egid == q.gid || super::proc::in_supplementary_groups(q.gid) {
        q.mode >> 3
    } else {
        q.mode
    } & 7;
    bits & want == want
}

/// `mq_open(name, oflag, mode, attr)`.
fn mq_open(name_ptr: u64, oflag: u64, mode: u64, attr: u64) -> i64 {
    let name = match queue_name(name_ptr) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let acc = oflag & O_ACCMODE;
    if acc == O_ACCMODE {
        return EINVAL;
    }
    let (_, _, euid, egid, resource, override_) = caller();
    let groups_ok = |q: &Queue| allowed(q, euid, egid, override_, match acc {
        0 => 4,
        1 => 2,
        _ => 6,
    });
    let ns = super::ns::ipc_ns();
    let attrs = if oflag & O_CREAT != 0 && attr != 0 {
        let raw = match copy_in(attr, 32) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let maxmsg = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        let msgsize = i64::from_le_bytes(raw[16..24].try_into().unwrap());
        let (mm, ms) = if resource { (HARD_MSG_MAX, HARD_MSGSIZE_MAX) } else { (MSG_MAX, MSGSIZE_MAX) };
        if maxmsg <= 0 || msgsize <= 0 || maxmsg as u64 > mm || msgsize as u64 > ms {
            return EINVAL;
        }
        Some((maxmsg as u64, msgsize as u64))
    } else {
        None
    };
    let q = {
        let mut all = QUEUES.lock();
        match all.get(&(ns, name.clone())) {
            Some(q) => {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    return EEXIST;
                }
                let q = q.clone();
                if !groups_ok(&q.lock()) {
                    return EACCES;
                }
                q
            }
            None if oflag & O_CREAT != 0 => {
                if all.keys().filter(|k| k.0 == ns).count() >= QUEUES_MAX && !resource {
                    return -28; // ENOSPC
                }
                let (maxmsg, msgsize) = attrs.unwrap_or((MSG_MAX, MSGSIZE_MAX));
                let umask = crate::task::with_current_fds_mut(|f| f.umask);
                let q = Arc::new(Mutex::new(Queue {
                    name: name.clone(),
                    uid: euid,
                    gid: egid,
                    mode: (mode as u32) & 0o777 & !umask,
                    maxmsg,
                    msgsize,
                    msgs: Vec::new(),
                    bytes: 0,
                    notify: None,
                    receivers: 0,
                    wq: Arc::new(WaitQueue::new()),
                }));
                all.insert((ns, name), q.clone());
                q
            }
            None => return ENOENT,
        }
    };
    let handle: Arc<dyn CharDevice> = Arc::new(MqHandle { q, read: acc != 1, write: acc != 0, nonblock: AtomicBool::new(oflag & O_NONBLOCK != 0) });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(handle)) {
        Ok(fd) => {
            fds.set_cloexec(fd, oflag & O_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// `mq_unlink(name)`: the queue goes once its last descriptor closes.
fn mq_unlink(name_ptr: u64) -> i64 {
    let name = match queue_name(name_ptr) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (_, _, euid, _, _, override_) = caller();
    let ns = super::ns::ipc_ns();
    let mut all = QUEUES.lock();
    let Some(q) = all.get(&(ns, name.clone())) else { return ENOENT };
    // The queue directory is sticky: only the owner (or a privileged caller) unlinks
    if !override_ && euid != 0 && q.lock().uid != euid {
        return EACCES;
    }
    all.remove(&(ns, name));
    0
}

/// The queue behind descriptor `fd`.
fn handle_of(fd: u64) -> Result<Arc<dyn CharDevice>, i64> {
    let dev = crate::task::with_current_fds_mut(|fds| match fds.get(fd as i32 as usize) {
        Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
        _ => None,
    });
    match dev {
        Some(d) if d.as_mqueue().is_some() => Ok(d),
        _ => Err(EBADF),
    }
}

/// Absolute `CLOCK_REALTIME` timeout as a tick deadline.
fn deadline(ptr: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let raw = copy_in(ptr, 16)?;
    let (s, ns) = (i64::from_le_bytes(raw[0..8].try_into().unwrap()), i64::from_le_bytes(raw[8..16].try_into().unwrap()));
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    let (rs, rns) = crate::arch::rtc::now();
    let left = (s as i128 * 1_000_000_000 + ns as i128) - (rs as i128 * 1_000_000_000 + rns as i128);
    let hz = crate::arch::pit::frequency_hz().max(1) as i128;
    Ok(Some(crate::arch::pit::ticks() + if left > 0 { ((left * hz + 999_999_999) / 1_000_000_000) as u64 } else { 0 }))
}

/// `mq_timedsend(mqd, msg, len, prio, timeout)`.
fn mq_timedsend(fd: u64, msg: u64, len: u64, prio: u64, timeout: u64) -> i64 {
    let dev = match handle_of(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let h = dev.as_mqueue().unwrap();
    if !h.write {
        return EBADF;
    }
    if prio >= MQ_PRIO_MAX {
        return EINVAL;
    }
    // Before copying anything, as Linux: a queue's message size never changes
    if len > h.q.lock().msgsize {
        return EMSGSIZE;
    }
    let data = match copy_in(msg, len as usize) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let deadline = match deadline(timeout) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let (pid, uid, ..) = caller();
    let wq = h.q.lock().wq.clone();
    let mut fire = None;
    let r = loop {
        wq.register();
        {
            let mut q = h.q.lock();
            if len > q.msgsize {
                break EMSGSIZE;
            }
            if (q.msgs.len() as u64) < q.maxmsg {
                let was_empty = q.msgs.is_empty();
                let at = q.msgs.iter().position(|m| m.0 < prio as u32).unwrap_or(q.msgs.len());
                q.msgs.insert(at, (prio as u32, data));
                q.bytes += len;
                // Notify only when a message reaches an empty queue nobody waits on
                if was_empty && q.receivers == 0 {
                    fire = q.notify.take();
                }
                break 0;
            }
        }
        if h.nonblock() {
            break EAGAIN;
        }
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            break ETIMEDOUT;
        }
        if super::proc::signal_pending() {
            break EINTR;
        }
        crate::task::wait::wait(deadline);
    };
    wq.unregister();
    if r == 0 {
        wq.wake_all();
        match fire {
            Some((target, Notify::Signal { sig, value })) => {
                super::proc::post_with_info(target, sig, SI_MESGQ, pid as u32, uid, value);
            }
            Some((_, Notify::Thread { sink, mut cookie })) => {
                cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_WOKENUP;
                sink.deliver_notification(&cookie);
            }
            _ => {}
        }
    }
    r
}

/// `mq_timedreceive(mqd, buf, len, prio*, timeout)`.
fn mq_timedreceive(fd: u64, buf: u64, len: u64, prio_ptr: u64, timeout: u64) -> i64 {
    let dev = match handle_of(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let h = dev.as_mqueue().unwrap();
    if !h.read {
        return EBADF;
    }
    let deadline = match deadline(timeout) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let wq = h.q.lock().wq.clone();
    let mut waiting = false;
    let r = loop {
        wq.register();
        {
            let mut q = h.q.lock();
            if len < q.msgsize {
                break Err(EMSGSIZE);
            }
            if !q.msgs.is_empty() {
                let (p, data) = q.msgs.remove(0);
                q.bytes -= data.len() as u64;
                if waiting {
                    q.receivers -= 1;
                }
                break Ok((p, data));
            }
            if !waiting {
                q.receivers += 1;
                waiting = true;
            }
        }
        let fail = if h.nonblock() {
            Some(EAGAIN)
        } else if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            Some(ETIMEDOUT)
        } else if super::proc::signal_pending() {
            Some(EINTR)
        } else {
            None
        };
        if let Some(e) = fail {
            if waiting {
                h.q.lock().receivers -= 1;
            }
            break Err(e);
        }
        crate::task::wait::wait(deadline);
    };
    wq.unregister();
    match r {
        Ok((p, data)) => {
            wq.wake_all(); // room for senders
            if copy_out(buf, &data).is_err() || (prio_ptr != 0 && copy_out(prio_ptr, &p.to_le_bytes()).is_err()) {
                return EFAULT;
            }
            data.len() as i64
        }
        Err(e) => e,
    }
}

/// `mq_notify(mqd, sigevent*)`.
fn mq_notify(fd: u64, sevp: u64) -> i64 {
    let dev = match handle_of(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let h = dev.as_mqueue().unwrap();
    let (pid, ..) = caller();
    if sevp == 0 {
        let mut q = h.q.lock();
        if q.notify.as_ref().is_some_and(|(p, _)| *p == pid) {
            q.notify = None;
        }
        return 0;
    }
    let raw = match copy_in(sevp, 24) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let value = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let signo = i32::from_le_bytes(raw[8..12].try_into().unwrap());
    let how = i32::from_le_bytes(raw[12..16].try_into().unwrap());
    let notify = match how {
        SIGEV_NONE => Notify::None,
        SIGEV_SIGNAL if (1..=64).contains(&signo) => Notify::Signal { sig: signo as u32, value },
        SIGEV_THREAD => {
            // glibc: the signal number field holds its netlink socket, the value points at
            // a cookie to send back
            let sink = crate::task::with_current_fds_mut(|fds| match fds.get(signo as u32 as usize) {
                Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
                _ => None,
            });
            let Some(sink) = sink else { return EBADF };
            let c = match copy_in(value, NOTIFY_COOKIE_LEN) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let mut cookie = [0u8; NOTIFY_COOKIE_LEN];
            cookie.copy_from_slice(&c);
            Notify::Thread { sink, cookie }
        }
        _ => return EINVAL,
    };
    let mut q = h.q.lock();
    if q.notify.as_ref().is_some_and(|(p, _)| super::proc::process_exists(*p) && *p != pid) {
        return EBUSY;
    }
    q.notify = Some((pid, notify));
    0
}

/// `mq_getsetattr(mqd, new*, old*)`: only `O_NONBLOCK` can change.
fn mq_getsetattr(fd: u64, new: u64, old: u64) -> i64 {
    let dev = match handle_of(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let h = dev.as_mqueue().unwrap();
    let flags = if h.nonblock() { O_NONBLOCK } else { 0 };
    let (maxmsg, msgsize, cur) = {
        let q = h.q.lock();
        (q.maxmsg, q.msgsize, q.msgs.len() as u64)
    };
    if new != 0 {
        let raw = match copy_in(new, 8) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let f = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        if f & !O_NONBLOCK != 0 {
            return EINVAL;
        }
        h.set_nonblock(f & O_NONBLOCK != 0);
    }
    if old != 0 {
        let mut b = [0u8; 64];
        for (i, v) in [flags, maxmsg, msgsize, cur].into_iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        if copy_out(old, &b).is_err() {
            return EFAULT;
        }
    }
    0
}

/// Handles `mq_open` (240) through `mq_getsetattr` (245).
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for these calls, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    Some(match num {
        240 => mq_open(a[0], a[1], a[2], a[3]),
        241 => mq_unlink(a[0]),
        242 => mq_timedsend(a[0], a[1], a[2], a[3], a[4]),
        243 => mq_timedreceive(a[0], a[1], a[2], a[3], a[4]),
        244 => mq_notify(a[0], a[1]),
        245 => mq_getsetattr(a[0], a[1], a[2]),
        _ => return None,
    })
}

