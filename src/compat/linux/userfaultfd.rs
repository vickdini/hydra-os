//! userfaultfd: page faults handled by the program.
//!
//! - **Registration** (`UFFDIO_REGISTER`, `MISSING` mode) marks anonymous memory ranges with
//!   the descriptor. A thread touching a page there that is not yet in memory posts a
//!   `UFFD_EVENT_PAGEFAULT` message and sleeps; a handler reads the message and fills the
//!   page with `UFFDIO_COPY` or `UFFDIO_ZEROPAGE`, which wakes it (`UFFDIO_WAKE` too).
//! - **Kernel accesses** to such pages (a system call reading the buffer) wait the same
//!   way, after the call has done nothing else; a descriptor made with
//!   `UFFD_USER_MODE_ONLY` refuses them (`EFAULT`), as on Linux.
//! - Closing the descriptor unregisters its ranges; later faults there get zeroed pages.
//!   Forked children do not inherit registrations (no `UFFD_FEATURE_EVENT_FORK`).
//! - **Not offered**: write-protect and minor-fault modes, `UFFDIO_MOVE`/`CONTINUE`/`POISON`,
//!   and events other than page faults.
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::memory::vm::Mm;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EPERM: i64 = -1;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOMEM: i64 = -12;
const ENOTTY: i64 = -25;

const UFFD_API: u64 = 0xAA;
const UFFD_USER_MODE_ONLY: u64 = 1;
const UFFD_FEATURE_THREAD_ID: u64 = 1 << 8;
const FEATURES: u64 = UFFD_FEATURE_THREAD_ID;

const UFFDIO_API: u64 = 0xc018_aa3f;
const UFFDIO_REGISTER: u64 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
const UFFDIO_WAKE: u64 = 0x8010_aa02;
const UFFDIO_COPY: u64 = 0xc028_aa03;
const UFFDIO_ZEROPAGE: u64 = 0xc020_aa04;

const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1;
const PAGE: u64 = 4096;

/// A userfaultfd.
pub struct Uffd {
    id: u64,
    user_only: bool,
    nonblock: bool,
    st: Mutex<State>,
    /// Readers wait here for messages.
    msgs_wq: Arc<WaitQueue>,
    /// Faulting threads wait here for their page.
    resolved: Arc<WaitQueue>,
}

struct State {
    api_done: bool,
    features: u64,
    /// Unread fault messages: (page, write, tid).
    queue: VecDeque<(u64, bool, u64)>,
    /// The address space its ranges are in.
    mm: Option<Weak<Mutex<Mm>>>,
    closed: bool,
}

/// The descriptor's object (closing unregisters).
struct UffdDev(Arc<Uffd>);

impl Drop for UffdDev {
    fn drop(&mut self) {
        let mm = {
            let mut st = self.0.st.lock();
            st.closed = true;
            st.mm.take()
        };
        if let Some(mm) = mm.and_then(|w| w.upgrade()) {
            let _ = mm.lock().set_uffd(0, u64::MAX, 0, Some(self.0.id));
        }
        REGISTRY.lock().remove(&self.0.id);
        self.0.resolved.wake_all();
    }
}

static REGISTRY: Mutex<BTreeMap<u64, Weak<Uffd>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ANY: AtomicBool = AtomicBool::new(false);

/// Whether any userfaultfd exists (the fault hooks' fast path).
#[inline]
pub fn active() -> bool {
    ANY.load(Ordering::Relaxed)
}

/// How waiting for a page ended.
pub enum Waited {
    /// Woken (the page may be there now: look again).
    Again,
    /// Nothing to wait for (unregistered, or the process is being killed): fault normally.
    Proceed,
    /// A kernel access the descriptor refuses (`UFFD_USER_MODE_ONLY`): fail it.
    Refuse,
}

/// A fault on missing page `page` of a range registered with userfaultfd `id`: posts the
/// message and sleeps until a handler acts. `kernel` for an access by a system call.
pub fn wait_fault(id: u64, page: u64, write: bool, kernel: bool) -> Waited {
    let Some(u) = REGISTRY.lock().get(&id).and_then(|w| w.upgrade()) else { return Waited::Proceed };
    if kernel && u.user_only {
        return Waited::Refuse;
    }
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Shared(u.resolved.clone()));
    waits.register();
    {
        let mut st = u.st.lock();
        if st.closed {
            return Waited::Proceed;
        }
        if !st.queue.iter().any(|q| q.0 == page) {
            st.queue.push_back((page, write, super::proc::current_ids().0));
        }
    }
    u.msgs_wq.wake_all();
    if super::proc::sigkill_pending() {
        return Waited::Proceed;
    }
    waits.wait(None);
    if super::proc::sigkill_pending() {
        return Waited::Proceed;
    }
    Waited::Again
}

impl CharDevice for UffdDev {
    fn read(&self, buf: &mut [u8]) -> i64 {
        // struct uffd_msg (32 bytes) per fault
        if buf.len() < 32 {
            return EINVAL;
        }
        let u = &self.0;
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(u.msgs_wq.clone()));
        loop {
            waits.register();
            {
                let mut st = u.st.lock();
                if !st.api_done {
                    return EINVAL;
                }
                if !st.queue.is_empty() {
                    let mut n = 0;
                    while n + 32 <= buf.len() {
                        let Some((page, write, tid)) = st.queue.pop_front() else { break };
                        let m = &mut buf[n..n + 32];
                        m.fill(0);
                        m[0] = UFFD_EVENT_PAGEFAULT;
                        m[8..16].copy_from_slice(&(if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 }).to_le_bytes());
                        m[16..24].copy_from_slice(&page.to_le_bytes());
                        if st.features & UFFD_FEATURE_THREAD_ID != 0 {
                            m[24..28].copy_from_slice(&(super::ns::pid_to_caller(tid) as u32).to_le_bytes());
                        }
                        n += 32;
                    }
                    return n as i64;
                }
            }
            if u.nonblock {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return EINTR;
            }
            waits.wait(None);
        }
    }
    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        self.0.ioctl(cmd, arg)
    }
    fn poll_events(&self) -> u32 {
        if self.0.st.lock().queue.is_empty() { 0 } else { 0x41 }
    }
    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.0.msgs_wq.clone()));
    }
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> alloc::string::String {
        alloc::string::String::from("anon_inode:[userfaultfd]")
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        self.0.nonblock
    }
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Uffd {
    fn mm(&self) -> Result<Arc<Mutex<Mm>>, i64> {
        self.st.lock().mm.as_ref().and_then(|w| w.upgrade()).ok_or(EINVAL)
    }

    fn range(arg: u64) -> Result<(u64, u64), i64> {
        let r = copy_in(arg, 16)?;
        let (start, len) = (u64_at(&r, 0), u64_at(&r, 8));
        if start % PAGE != 0 || len % PAGE != 0 || len == 0 || start.checked_add(len).map_or(true, |e| e > 0x0000_8000_0000_0000) {
            return Err(EINVAL);
        }
        Ok((start, start + len))
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        let r: Result<i64, i64> = (|| {
            if cmd != UFFDIO_API && !self.st.lock().api_done {
                return Err(EINVAL);
            }
            match cmd {
                UFFDIO_API => {
                    // struct uffdio_api { u64 api; u64 features; u64 ioctls; }
                    let a = copy_in(arg, 24)?;
                    let mut st = self.st.lock();
                    if st.api_done {
                        return Err(EINVAL);
                    }
                    let (api, want) = (u64_at(&a, 0), u64_at(&a, 8));
                    if api != UFFD_API || want & !FEATURES != 0 {
                        let mut out = a.clone();
                        out[8..16].copy_from_slice(&0u64.to_le_bytes());
                        let _ = copy_out(arg, &out);
                        return Err(EINVAL);
                    }
                    st.api_done = true;
                    st.features = want;
                    let mut out = Vec::with_capacity(24);
                    out.extend_from_slice(&UFFD_API.to_le_bytes());
                    out.extend_from_slice(&FEATURES.to_le_bytes());
                    out.extend_from_slice(&((1u64 << 0x00) | (1 << 0x01) | (1 << 0x3f)).to_le_bytes());
                    copy_out(arg, &out)?;
                    Ok(0)
                }
                UFFDIO_REGISTER => {
                    // struct uffdio_register { range; u64 mode; u64 ioctls; }
                    let a = copy_in(arg, 32)?;
                    let (start, end) = Self::range(arg)?;
                    let mode = u64_at(&a, 16);
                    if mode != UFFDIO_REGISTER_MODE_MISSING {
                        return Err(EINVAL); // write-protect and minor modes are not offered
                    }
                    let mm = super::mm::current_mm().ok_or(EINVAL)?;
                    {
                        let mut st = self.st.lock();
                        if let Some(old) = st.mm.as_ref().and_then(|w| w.upgrade()) {
                            if !Arc::ptr_eq(&old, &mm) {
                                return Err(EINVAL);
                            }
                        }
                        st.mm = Some(Arc::downgrade(&mm));
                    }
                    let r = mm.lock().set_uffd(start, end, self.id, None);
                    match r {
                        Ok(()) => {}
                        Err(e) => return Err(if e == -16 { EBUSY } else { e }),
                    }
                    let mut out = a.clone();
                    // UFFDIO_WAKE, UFFDIO_COPY, UFFDIO_ZEROPAGE
                    out[24..32].copy_from_slice(&((1u64 << 0x02) | (1 << 0x03) | (1 << 0x04)).to_le_bytes());
                    copy_out(arg, &out)?;
                    Ok(0)
                }
                UFFDIO_UNREGISTER => {
                    let (start, end) = Self::range(arg)?;
                    let mm = self.mm()?;
                    mm.lock().set_uffd(start, end, 0, Some(self.id)).map(|_| 0)?;
                    self.resolved.wake_all();
                    Ok(0)
                }
                UFFDIO_WAKE => {
                    Self::range(arg)?;
                    self.resolved.wake_all();
                    Ok(0)
                }
                UFFDIO_COPY | UFFDIO_ZEROPAGE => {
                    // uffdio_copy { dst; src; len; mode; s64 copy } / uffdio_zeropage { range; mode; s64 zeropage }
                    let copy = cmd == UFFDIO_COPY;
                    let a = copy_in(arg, if copy { 40 } else { 32 })?;
                    let (dst, src, len, mode) = if copy {
                        (u64_at(&a, 0), u64_at(&a, 8), u64_at(&a, 16), u64_at(&a, 24))
                    } else {
                        (u64_at(&a, 0), 0, u64_at(&a, 8), u64_at(&a, 16))
                    };
                    if dst % PAGE != 0 || len % PAGE != 0 || len == 0 || mode & !1 != 0 {
                        return Err(EINVAL);
                    }
                    let mm = self.mm()?;
                    let mut done = 0u64;
                    let mut err = 0i64;
                    while done < len {
                        // The source is read first: it may be in the same address space
                        let data = if copy {
                            match copy_in(src + done, PAGE as usize) {
                                Ok(d) => Some(d),
                                Err(e) => {
                                    err = e;
                                    break;
                                }
                            }
                        } else {
                            None
                        };
                        let r = mm.lock().fill_page(dst + done, data.as_deref(), self.id);
                        match r {
                            Ok(()) => done += PAGE,
                            Err(e) => {
                                err = e;
                                break;
                            }
                        }
                    }
                    let res = if done > 0 { done as i64 } else { err };
                    let mut out = a.clone();
                    let at = if copy { 32 } else { 24 };
                    out[at..at + 8].copy_from_slice(&res.to_le_bytes());
                    let _ = copy_out(arg, &out);
                    if mode & 1 == 0 {
                        self.resolved.wake_all(); // unless UFFDIO_COPY_MODE_DONTWAKE
                    }
                    if done == 0 {
                        return Err(err);
                    }
                    if done < len {
                        return Err(EAGAIN);
                    }
                    Ok(0)
                }
                _ => Err(ENOTTY),
            }
        })();
        r.unwrap_or_else(|e| e)
    }
}

/// `userfaultfd(flags)`: `O_CLOEXEC`, `O_NONBLOCK`, `UFFD_USER_MODE_ONLY`. Without the
/// latter it needs `CAP_SYS_PTRACE` (`vm.unprivileged_userfaultfd` is 0, as on Linux).
pub fn sys_userfaultfd(flags: u64) -> i64 {
    const O_NONBLOCK: u64 = 0o4000;
    const O_CLOEXEC: u64 = 0o2000000;
    if flags & !(O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY) != 0 {
        return EINVAL;
    }
    if flags & UFFD_USER_MODE_ONLY == 0 && !crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 19) != 0 && !t.caps.in_userns).unwrap_or(false) {
        return EPERM;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let u = Arc::new(Uffd {
        id,
        user_only: flags & UFFD_USER_MODE_ONLY != 0,
        nonblock: flags & O_NONBLOCK != 0,
        st: Mutex::new(State { api_done: false, features: 0, queue: VecDeque::new(), mm: None, closed: false }),
        msgs_wq: WaitQueue::new_shared(),
        resolved: WaitQueue::new_shared(),
    });
    REGISTRY.lock().insert(id, Arc::downgrade(&u));
    ANY.store(true, Ordering::Relaxed);
    let dev: Arc<dyn CharDevice> = Arc::new(UffdDev(u));
    let _ = (EEXIST, ENOMEM, EFAULT);
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & O_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}
