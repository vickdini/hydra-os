//! POSIX message queues (`mq_open` and family), moved here from the kernel's
//! `src/compat/linux/mqueue.rs` (wave 4, step 2).
//!
//! A queue is named (per IPC namespace), holds up to `mq_maxmsg` messages of up to
//! `mq_msgsize` bytes, and hands them out highest priority first (oldest first within a
//! priority). `mq_open` returns a server-object descriptor (one slot per open file): `poll`
//! and `epoll` read its readiness word in the kernel (readable while a message waits,
//! writable while there is room); reading it gives Linux's status line.
//!
//! **Blocking without tying up a worker:** `mq_timedsend` on a full queue and
//! `mq_timedreceive` on an empty one answer "pending" (`LX_REPLY_PENDING`): the caller keeps
//! sleeping in the kernel and the worker serves other calls. The call that makes room or
//! brings a message completes the waiter (`SYS_LX_COMPLETE`, after writing a received
//! message into the waiter's memory); the main thread completes waiters whose timeout
//! passed (`ETIMEDOUT`); a signal for the waiter answers `EINTR`.
//!
//! `mq_notify` registers one process to hear when a message arrives in an empty queue
//! nobody is waiting on: by a signal (`SI_MESGQ`, through the kernel's `sig_post`), or for
//! glibc's `SIGEV_THREAD` by a message on the netlink socket glibc passes (kept for us by
//! the kernel: `LX_OBJ_PIN` / `LX_OBJ_NOTIFY`). A queue lives until it is unlinked and its
//! last descriptor is closed.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;
use crate::timeout;

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const ENAMETOOLONG: i64 = -36;
const EMSGSIZE: i64 = -90;
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

const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_SYS_RESOURCE: u32 = 24;

/// How the registered process hears of a message.
enum Notify {
    None,
    Signal { sig: u32, value: u64 },
    /// A kept netlink socket (the kernel's token) and glibc's cookie.
    Thread { token: u64, cookie: [u8; NOTIFY_COOKIE_LEN] },
}

/// A receiver waiting (its call is pending).
struct Receiver {
    id: u64,
    tgid: u64,
    buf: u64,
    prio_ptr: u64,
    deadline: Option<u64>,
}

/// A sender waiting for room (its call is pending).
struct Sender {
    id: u64,
    tgid: u64,
    prio: u32,
    data: Vec<u8>,
    deadline: Option<u64>,
}

/// A message queue.
struct Queue {
    ns: u64,
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
    receivers: Vec<Receiver>,
    senders: Vec<Sender>,
    /// The open descriptors (slots) on it, with their access: `(slot, read, write)`.
    opens: Vec<(u32, bool, bool)>,
    /// Still reachable by name.
    linked: bool,
}

struct Mq {
    /// Queues by number.
    queues: BTreeMap<u64, Queue>,
    /// Names: (IPC namespace, name) -> queue number.
    names: BTreeMap<(u64, String), u64>,
    /// Open descriptors: slot -> (queue number, may read, may write).
    handles: BTreeMap<u32, (u64, bool, bool)>,
    next: u64,
}

static MQ: YLock<Mq> = YLock::new(Mq { queues: BTreeMap::new(), names: BTreeMap::new(), handles: BTreeMap::new(), next: 1 });

/// Answers to give once the lock is let go: `(request id, result)`.
type Done = Vec<(u64, i64)>;

impl Queue {
    /// Updates the readiness words of every descriptor open on the queue (`arrived`: a
    /// message came in; `left`: one was taken; edge-triggered watches report again).
    fn publish_ev(&self, arrived: bool, left: bool) {
        for &(slot, r, w) in &self.opens {
            let mut ev = 0;
            if r && !self.msgs.is_empty() {
                ev |= 0x0041; // POLLIN | POLLRDNORM
            }
            if w && (self.msgs.len() as u64) < self.maxmsg {
                ev |= 0x0104; // POLLOUT | POLLWRNORM
            }
            crate::obj::set_ready_ev(slot, ev, self.bytes, (r && arrived) || (w && left));
        }
    }

    /// [`Queue::publish_ev`] without an event.
    fn publish(&self) {
        self.publish_ev(false, false);
    }

    /// Inserts a message by priority.
    fn insert(&mut self, prio: u32, data: Vec<u8>) {
        let at = self.msgs.iter().position(|m| m.0 < prio).unwrap_or(self.msgs.len());
        self.bytes += data.len() as u64;
        self.msgs.insert(at, (prio, data));
    }

    /// Hands message `data` to the oldest waiting receiver that can take it (writing it into
    /// its memory). `Err(data)` back if none could.
    fn hand_to_receiver(&mut self, prio: u32, data: Vec<u8>, done: &mut Done) -> Result<(), Vec<u8>> {
        while !self.receivers.is_empty() {
            let w = self.receivers.remove(0);
            match sys::lx_write(w.id, w.buf, &data) {
                Ok(()) => {
                    let r = if w.prio_ptr != 0 && sys::lx_write(w.id, w.prio_ptr, &prio.to_le_bytes()).is_err() { EFAULT } else { data.len() as i64 };
                    done.push((w.id, r));
                    return Ok(());
                }
                // Its caller is gone: the next receiver gets it
                Err(e) if e == ESRCH => done.push((w.id, EINTR)),
                Err(_) => {
                    done.push((w.id, EFAULT));
                    return Ok(());
                }
            }
        }
        Err(data)
    }

    /// Room was made: the oldest waiting senders put their messages in.
    fn admit_senders(&mut self, done: &mut Done) {
        while (self.msgs.len() as u64) < self.maxmsg && !self.senders.is_empty() {
            let s = self.senders.remove(0);
            self.insert(s.prio, s.data);
            done.push((s.id, 0));
        }
    }

    /// Whether `want` (4 read, 2 write) is allowed for the caller.
    fn allowed(&self, cx: &Cx, want: u32) -> bool {
        if cx.has_cap(CAP_DAC_OVERRIDE) {
            return true;
        }
        let bits = if cx.c.euid == self.uid {
            self.mode >> 6
        } else if cx.in_group(self.gid) {
            self.mode >> 3
        } else {
            self.mode
        } & 7;
        bits & want == want
    }
}

/// Sends the answers collected while the lock was held.
fn finish(done: Done) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
    crate::obj::flush();
}

/// The queue name of a user `mq_open` name (glibc has removed the leading '/').
fn queue_name(cx: &Cx, ptr: u64) -> Result<String, i64> {
    let raw = cx.user_cstr(ptr)?;
    if raw.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    if raw.is_empty() || raw.contains(&b'/') || raw == b"." || raw == b".." {
        return Err(EINVAL);
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// `mq_open(name, oflag, mode, attr)`.
fn mq_open(cx: &Cx) -> i64 {
    let (oflag, mode, attr) = (cx.args[1], cx.args[2], cx.args[3]);
    let name = match queue_name(cx, cx.args[0]) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let acc = oflag & O_ACCMODE;
    if acc == O_ACCMODE {
        return EINVAL;
    }
    let want = match acc {
        0 => 4,
        1 => 2,
        _ => 6,
    };
    let resource = cx.has_cap(CAP_SYS_RESOURCE);
    let ns = cx.c.ipc_ns;
    let attrs = if oflag & O_CREAT != 0 && attr != 0 {
        let raw = match cx.copy_in(attr, 32) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let maxmsg = Cx::u64_at(&raw, 8) as i64;
        let msgsize = Cx::u64_at(&raw, 16) as i64;
        let (mm, ms) = if resource { (HARD_MSG_MAX, HARD_MSGSIZE_MAX) } else { (MSG_MAX, MSGSIZE_MAX) };
        if maxmsg <= 0 || msgsize <= 0 || maxmsg as u64 > mm || msgsize as u64 > ms {
            return EINVAL;
        }
        Some((maxmsg as u64, msgsize as u64))
    } else {
        None
    };
    let slot = match crate::obj::alloc(LX_OBJ_KIND_MQ) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (read, write) = (acc != 1, acc != 0);
    // The queue and the open descriptor are recorded before the descriptor exists, so a
    // close racing with this call finds them
    let (qid, uid, gid, qmode) = {
        let mut mq = MQ.lock();
        let mq = &mut *mq;
        let qid = match mq.names.get(&(ns, name.clone())) {
            Some(&qid) => {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    crate::obj::free(slot);
                    return EEXIST;
                }
                if !mq.queues[&qid].allowed(cx, want) {
                    crate::obj::free(slot);
                    return EACCES;
                }
                qid
            }
            None if oflag & O_CREAT != 0 => {
                if mq.queues.values().filter(|q| q.ns == ns && q.linked).count() >= QUEUES_MAX && !resource {
                    crate::obj::free(slot);
                    return ENOSPC;
                }
                let (maxmsg, msgsize) = attrs.unwrap_or((MSG_MAX, MSGSIZE_MAX));
                let qid = mq.next;
                mq.next += 1;
                mq.queues.insert(
                    qid,
                    Queue {
                        ns,
                        uid: cx.c.euid,
                        gid: cx.c.egid,
                        mode: (mode as u32) & 0o777 & !(cx.c.umask as u32),
                        maxmsg,
                        msgsize,
                        msgs: Vec::new(),
                        bytes: 0,
                        notify: None,
                        receivers: Vec::new(),
                        senders: Vec::new(),
                        opens: Vec::new(),
                        linked: true,
                    },
                );
                mq.names.insert((ns, name.clone()), qid);
                qid
            }
            None => {
                crate::obj::free(slot);
                return ENOENT;
            }
        };
        mq.handles.insert(slot, (qid, read, write));
        let q = mq.queues.get_mut(&qid).unwrap();
        q.opens.push((slot, read, write));
        q.publish();
        (qid, q.uid, q.gid, q.mode)
    };
    let flags = (oflag & (O_CLOEXEC | O_NONBLOCK)) as u32;
    let shown = alloc::format!("/{}", name);
    match crate::obj::install(cx, slot, LX_OBJ_KIND_MQ, flags, 0o100000 | qmode, uid, gid, shown.as_bytes()) {
        Ok(fd) => {
            crate::obj::flush();
            fd
        }
        Err(e) => {
            forget_open(slot, qid);
            crate::obj::free(slot);
            e
        }
    }
}

/// Removes open descriptor `slot` of queue `qid`; the queue goes if it was unlinked and
/// this was its last descriptor.
fn forget_open(slot: u32, qid: u64) {
    let mut mq = MQ.lock();
    mq.handles.remove(&slot);
    let gone = match mq.queues.get_mut(&qid) {
        Some(q) => {
            q.opens.retain(|o| o.0 != slot);
            !q.linked && q.opens.is_empty()
        }
        None => false,
    };
    if gone {
        if let Some(q) = mq.queues.remove(&qid) {
            unpin(&q.notify);
        }
    }
}

/// Lets a kept netlink socket go.
fn unpin(n: &Option<(u64, Notify)>) {
    if let Some((_, Notify::Thread { token, .. })) = n {
        if *token & crate::netlink::PIN_BIT != 0 {
            crate::netlink::unpin(*token);
        } else {
            let _ = sys::lx_obj(LX_OBJ_UNPIN, *token, 0, 0);
        }
    }
}

/// The last descriptor of slot `slot` went away.
pub fn closed(slot: u32) {
    let qid = MQ.lock().handles.get(&slot).map(|h| h.0);
    if let Some(qid) = qid {
        forget_open(slot, qid);
    }
}

/// `mq_unlink(name)`: the queue goes once its last descriptor closes.
fn mq_unlink(cx: &Cx) -> i64 {
    let name = match queue_name(cx, cx.args[0]) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let ns = cx.c.ipc_ns;
    let mut mq = MQ.lock();
    let Some(&qid) = mq.names.get(&(ns, name.clone())) else { return ENOENT };
    // The queue directory is sticky: only the owner (or a privileged caller) unlinks
    if !cx.has_cap(CAP_DAC_OVERRIDE) && cx.c.euid != 0 && mq.queues[&qid].uid != cx.c.euid {
        return EACCES;
    }
    mq.names.remove(&(ns, name));
    let q = mq.queues.get_mut(&qid).unwrap();
    q.linked = false;
    if q.opens.is_empty() {
        if let Some(q) = mq.queues.remove(&qid) {
            unpin(&q.notify);
        }
    }
    0
}

/// The queue and access of the call's descriptor: `(queue number, read, write)`.
fn handle(mq: &Mq, cx: &Cx) -> Result<(u64, bool, bool), i64> {
    if cx.c.obj == LX_OBJ_NONE {
        return Err(EBADF);
    }
    mq.handles.get(&(cx.c.obj as u32)).copied().ok_or(EBADF)
}

/// `mq_timedsend(mqd, msg, len, prio, timeout)`.
fn mq_timedsend(cx: &Cx) -> (i64, u64) {
    let (msg, len, prio, tptr) = (cx.args[1], cx.args[2], cx.args[3], cx.args[4]);
    let (qid, msgsize) = {
        let mq = MQ.lock();
        let (qid, _, w) = match handle(&mq, cx) {
            Ok(h) => h,
            Err(e) => return (e, 0),
        };
        if !w {
            return (EBADF, 0);
        }
        (qid, mq.queues[&qid].msgsize)
    };
    if prio >= MQ_PRIO_MAX {
        return (EINVAL, 0);
    }
    // Before copying anything, as Linux: a queue's message size never changes
    if len > msgsize {
        return (EMSGSIZE, 0);
    }
    let data = match cx.copy_in_any(msg, len as usize) {
        Ok(d) => d,
        Err(e) => return (e, 0),
    };
    let deadline = match timeout::absolute(cx, tptr) {
        Ok(d) => d,
        Err(e) => return (e, 0),
    };
    let mut done = Done::new();
    let mut fire = None;
    let r = {
        let mut mq = MQ.lock();
        let Some(q) = mq.queues.get_mut(&qid) else { return (EBADF, 0) };
        let mut arrived = false;
        let r = match q.hand_to_receiver(prio as u32, data, &mut done) {
            Ok(()) => (0, 0),
            Err(data) if (q.msgs.len() as u64) < q.maxmsg => {
                let was_empty = q.msgs.is_empty();
                q.insert(prio as u32, data);
                arrived = true;
                // Notify only when a message reaches an empty queue nobody waits on
                if was_empty {
                    fire = q.notify.take();
                }
                (0, 0)
            }
            Err(_) if cx.nonblock() => (EAGAIN, 0),
            Err(_) if timeout::passed(deadline) => (ETIMEDOUT, 0),
            Err(data) => {
                q.senders.push(Sender { id: cx.id, tgid: cx.c.tgid, prio: prio as u32, data, deadline });
                (0, LX_REPLY_PENDING)
            }
        };
        q.publish_ev(arrived, false);
        r
    };
    finish(done);
    if let Some((target, how)) = fire {
        notify(target, how, cx.c.tgid, cx.c.uid);
    }
    if r.1 == LX_REPLY_PENDING && deadline.is_some() {
        timeout::kick();
    }
    r
}

/// Tells process `target` a message arrived.
fn notify(target: u64, how: Notify, pid: u64, uid: u32) {
    match how {
        Notify::Signal { sig, value } => {
            let _ = sys::lx_sig(target, sig, SI_MESGQ, pid as u32, uid, value);
        }
        Notify::Thread { token, mut cookie } => {
            cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_WOKENUP;
            if token & crate::netlink::PIN_BIT != 0 {
                crate::netlink::deliver(token, &cookie);
                crate::netlink::unpin(token);
            } else {
                let _ = sys::lx_obj(LX_OBJ_NOTIFY, token, cookie.as_ptr() as u64, NOTIFY_COOKIE_LEN as u64);
                let _ = sys::lx_obj(LX_OBJ_UNPIN, token, 0, 0);
            }
        }
        Notify::None => {}
    }
}

/// `mq_timedreceive(mqd, buf, len, prio*, timeout)`.
fn mq_timedreceive(cx: &Cx) -> (i64, u64) {
    let (buf, len, prio_ptr, tptr) = (cx.args[1], cx.args[2], cx.args[3], cx.args[4]);
    let deadline = match timeout::absolute(cx, tptr) {
        Ok(d) => d,
        Err(e) => return (e, 0),
    };
    let mut done = Done::new();
    let got = {
        let mut mq = MQ.lock();
        let (qid, r, _) = match handle(&mq, cx) {
            Ok(h) => h,
            Err(e) => return (e, 0),
        };
        if !r {
            return (EBADF, 0);
        }
        let q = mq.queues.get_mut(&qid).unwrap();
        if len < q.msgsize {
            return (EMSGSIZE, 0);
        }
        let got = if !q.msgs.is_empty() {
            let (p, data) = q.msgs.remove(0);
            q.bytes -= data.len() as u64;
            q.admit_senders(&mut done);
            Ok((p, data))
        } else if cx.nonblock() {
            Err(EAGAIN)
        } else if timeout::passed(deadline) {
            Err(ETIMEDOUT)
        } else {
            q.receivers.push(Receiver { id: cx.id, tgid: cx.c.tgid, buf, prio_ptr, deadline });
            Err(0)
        };
        q.publish_ev(false, got.is_ok());
        got
    };
    finish(done);
    match got {
        Ok((p, data)) => {
            if cx.copy_out_any(buf, &data).is_err() || (prio_ptr != 0 && cx.copy_out(prio_ptr, &p.to_le_bytes()).is_err()) {
                return (EFAULT, 0);
            }
            (data.len() as i64, 0)
        }
        Err(0) => {
            if deadline.is_some() {
                timeout::kick();
            }
            (0, LX_REPLY_PENDING)
        }
        Err(e) => (e, 0),
    }
}

/// `mq_notify(mqd, sigevent*)`.
fn mq_notify(cx: &Cx) -> i64 {
    let sevp = cx.args[1];
    let pid = cx.c.tgid;
    let qid = {
        let mq = MQ.lock();
        match handle(&mq, cx) {
            Ok(h) => h.0,
            Err(e) => return e,
        }
    };
    if sevp == 0 {
        let mut mq = MQ.lock();
        if let Some(q) = mq.queues.get_mut(&qid) {
            if q.notify.as_ref().is_some_and(|(p, _)| *p == pid) {
                let old = q.notify.take();
                unpin(&old);
            }
        }
        return 0;
    }
    let raw = match cx.copy_in(sevp, 24) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let value = Cx::u64_at(&raw, 0);
    let signo = i32::from_le_bytes(raw[8..12].try_into().unwrap());
    let how = i32::from_le_bytes(raw[12..16].try_into().unwrap());
    let notify = match how {
        SIGEV_NONE => Notify::None,
        SIGEV_SIGNAL if (1..=64).contains(&signo) => Notify::Signal { sig: signo as u32, value },
        SIGEV_THREAD => {
            // glibc: the signal number field holds its netlink socket, the value points at
            // a cookie to send back
            let c = match cx.copy_in(value, NOTIFY_COOKIE_LEN) {
                Ok(c) => c,
                Err(e) => return e,
            };
            // Our own netlink socket (wave 5), or one the kernel keeps for us
            let token = match crate::netlink::pin(cx, signo as u32 as u64) {
                Some(t) => t,
                None => match sys::lx_obj(LX_OBJ_PIN, cx.id, signo as u32 as u64, 0) {
                    Ok(t) => t,
                    Err(_) => return EBADF,
                },
            };
            let mut cookie = [0u8; NOTIFY_COOKIE_LEN];
            cookie.copy_from_slice(&c);
            Notify::Thread { token, cookie }
        }
        _ => return EINVAL,
    };
    let mut mq = MQ.lock();
    let Some(q) = mq.queues.get_mut(&qid) else { return EBADF };
    if q.notify.as_ref().is_some_and(|(p, _)| *p != pid) {
        drop(mq);
        unpin(&Some((pid, notify)));
        return EBUSY;
    }
    let old = q.notify.replace((pid, notify));
    unpin(&old);
    0
}

/// `mq_getsetattr(mqd, new*, old*)`: only `O_NONBLOCK` can change.
fn mq_getsetattr(cx: &Cx) -> i64 {
    let (new, old) = (cx.args[1], cx.args[2]);
    let flags = if cx.nonblock() { O_NONBLOCK } else { 0 };
    let (maxmsg, msgsize, cur) = {
        let mq = MQ.lock();
        let qid = match handle(&mq, cx) {
            Ok(h) => h.0,
            Err(e) => return e,
        };
        let q = &mq.queues[&qid];
        (q.maxmsg, q.msgsize, q.msgs.len() as u64)
    };
    if new != 0 {
        let raw = match cx.copy_in(new, 8) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let f = Cx::u64_at(&raw, 0);
        if f & !O_NONBLOCK != 0 {
            return EINVAL;
        }
        if let Err(e) = sys::lx_obj(LX_OBJ_SETFL, cx.c.obj, f & O_NONBLOCK, 0) {
            return e;
        }
    }
    if old != 0 {
        let mut b = [0u8; 64];
        for (i, v) in [flags, maxmsg, msgsize, cur].into_iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        if cx.copy_out(old, &b).is_err() {
            return EFAULT;
        }
    }
    0
}

/// `read` on a queue descriptor: Linux's status line.
pub fn read(cx: &Cx) -> i64 {
    let text = {
        let mq = MQ.lock();
        let qid = match handle(&mq, cx) {
            Ok(h) => h.0,
            Err(e) => return e,
        };
        let q = &mq.queues[&qid];
        let (kind, sig, pid) = match &q.notify {
            Some((pid, Notify::Signal { sig, .. })) => (SIGEV_SIGNAL, *sig as i32, *pid),
            Some((pid, Notify::Thread { .. })) => (SIGEV_THREAD, 0, *pid),
            Some((pid, Notify::None)) => (SIGEV_NONE, 0, *pid),
            None => (0, 0, 0),
        };
        alloc::format!("QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n", q.bytes, kind, sig, pid)
    };
    let n = text.len().min(cx.args[2] as usize);
    match cx.copy_out(cx.args[1], &text.as_bytes()[..n]) {
        Ok(()) => n as i64,
        Err(e) => e,
    }
}

/// Handles `mq_open` (240) through `mq_getsetattr` (245): `(result, reply flags)`.
pub fn dispatch(cx: &Cx) -> (i64, u64) {
    match cx.nr {
        240 => (mq_open(cx), 0),
        241 => (mq_unlink(cx), 0),
        242 => mq_timedsend(cx),
        243 => mq_timedreceive(cx),
        244 => (mq_notify(cx), 0),
        245 => (mq_getsetattr(cx), 0),
        _ => (-38, 0),
    }
}

/// A signal arrived for the caller of pending call `id`: a waiting send or receive ends
/// with `EINTR`. Whether `id` was one of ours.
pub fn interrupted(id: u64) -> bool {
    let found = {
        let mut mq = MQ.lock();
        let mut found = false;
        for q in mq.queues.values_mut() {
            let (r, s) = (q.receivers.len(), q.senders.len());
            q.receivers.retain(|w| w.id != id);
            q.senders.retain(|w| w.id != id);
            if q.receivers.len() != r || q.senders.len() != s {
                found = true;
                break;
            }
        }
        found
    };
    if found {
        let _ = sys::lx_complete(id, EINTR);
    }
    found
}

/// Process `tgid` ended: its registrations go, and calls it still had waiting end.
pub fn on_exit(tgid: u64) {
    let mut done = Done::new();
    let mut pins = Vec::new();
    {
        let mut mq = MQ.lock();
        for q in mq.queues.values_mut() {
            if q.notify.as_ref().is_some_and(|(p, _)| *p == tgid) {
                pins.push(q.notify.take());
            }
            for w in q.receivers.iter().filter(|w| w.tgid == tgid) {
                done.push((w.id, EINTR));
            }
            q.receivers.retain(|w| w.tgid != tgid);
            for w in q.senders.iter().filter(|w| w.tgid == tgid) {
                done.push((w.id, EINTR));
            }
            q.senders.retain(|w| w.tgid != tgid);
        }
    }
    for p in pins {
        unpin(&p);
    }
    finish(done);
}

/// Answers the waiting calls whose timeout passed (`ETIMEDOUT`); returns the earliest
/// deadline still waiting.
pub fn tick(now: u64) -> Option<u64> {
    let mut done = Done::new();
    let mut next: Option<u64> = None;
    {
        let mut mq = MQ.lock();
        for q in mq.queues.values_mut() {
            q.receivers.retain(|w| match w.deadline {
                Some(d) if d <= now => {
                    done.push((w.id, ETIMEDOUT));
                    false
                }
                Some(d) => {
                    next = Some(next.map_or(d, |n| n.min(d)));
                    true
                }
                None => true,
            });
            q.senders.retain(|w| match w.deadline {
                Some(d) if d <= now => {
                    done.push((w.id, ETIMEDOUT));
                    false
                }
                Some(d) => {
                    next = Some(next.map_or(d, |n| n.min(d)));
                    true
                }
                None => true,
            });
        }
    }
    finish(done);
    next
}
