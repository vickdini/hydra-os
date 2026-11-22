//! # Kernel uevent netlink sockets (`AF_NETLINK`, `NETLINK_KOBJECT_UEVENT`)
//!
//! libudev's device monitor (used by libinput and KWin to hear about hot-plugged devices)
//! opens one of these and fails without it. Hydra's devices are fixed at boot; the only
//! messages are the "remove"/"add" announcements around a device service's restart
//! (wave 8, Group H: `crate::lx::hotplug`, [`uevent_all`]), queued on the sockets bound to
//! the message's group with the sender's address and credentials libudev checks.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EAFNOSUPPORT: i64 = -97;
const EPROTONOSUPPORT: i64 = -93;

const AF_NETLINK: u64 = 16;
const NETLINK_KOBJECT_UEVENT: u64 = 15;
const NETLINK_ROUTE: u64 = 0;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

// wave8 GH begin: queued announcements
/// Woken when a message is queued on any uevent socket.
static UEVENT_WQ: WaitQueue = WaitQueue::new();
/// Every uevent socket (dropped ones are pruned at the next announcement).
static SOCKS: Mutex<Vec<Weak<NetlinkSocket>>> = Mutex::new(Vec::new());
/// Most messages waiting on one socket (older ones are dropped first, as a full receive
/// buffer would).
const QUEUE_MAX: usize = 256;
const MSG_PEEK: u64 = 2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

/// Queues messages `(group, bytes)` on every uevent socket bound to their group and wakes
/// the receivers; returns how many sockets got at least one.
pub fn uevent_all(msgs: &[(u32, Vec<u8>)]) -> usize {
    let socks: Vec<Arc<NetlinkSocket>> = {
        let mut l = SOCKS.lock();
        l.retain(|w| w.strong_count() > 0);
        l.iter().filter_map(|w| w.upgrade()).collect()
    };
    let mut reached = 0;
    for s in socks {
        let groups = s.groups.load(Ordering::Relaxed);
        let mut any = false;
        let mut q = s.queue.lock();
        for (g, m) in msgs {
            if *g == 0 || *g > 32 || groups & (1 << (g - 1)) == 0 {
                continue;
            }
            if q.len() >= QUEUE_MAX {
                q.pop_front();
            }
            q.push_back((*g, m.clone()));
            any = true;
        }
        reached += any as usize;
    }
    UEVENT_WQ.wake_all();
    reached
}
// wave8 GH end

/// An uevent socket.
pub struct NetlinkSocket {
    pid: AtomicU32,
    groups: AtomicU32,
    nonblock: AtomicBool,
    /// wave8 GH: messages not yet received, with their group.
    queue: Mutex<VecDeque<(u32, Vec<u8>)>>,
}

/// Creates a netlink socket if domain is `AF_NETLINK` and protocol is `NETLINK_KOBJECT_UEVENT`.
///
/// # Arguments
///
/// * `a` - System call argument registers (`[domain, type, protocol, ...]`).
///
/// # Returns
///
/// * `Some(Ok(fd))` or `Some(Err(code))` if domain is `AF_NETLINK`.
/// * `None` if domain is not `AF_NETLINK`.
pub fn socket(a: [u64; 6]) -> Option<i64> {
    if a[0] != AF_NETLINK {
        return None;
    }
    if a[1] & 0xF != 3 && a[1] & 0xF != 2 {
        return Some(EPROTONOSUPPORT); // SOCK_RAW or SOCK_DGRAM
    }
    if a[2] == NETLINK_ROUTE {
        return Some(super::rtnetlink::socket(a[1]));
    }
    if a[2] != NETLINK_KOBJECT_UEVENT {
        return Some(EAFNOSUPPORT); // the other netlink families: not offered (callers cope)
    }
    let nl = Arc::new(NetlinkSocket {
        pid: AtomicU32::new(0),
        groups: AtomicU32::new(0),
        nonblock: AtomicBool::new(a[1] & SOCK_NONBLOCK != 0),
        queue: Mutex::new(VecDeque::new()),
    });
    {
        // wave8 GH: registered for announcements (closed ones pruned here too, so the list
        // stays as long as the open sockets)
        let mut l = SOCKS.lock();
        l.retain(|w| w.strong_count() > 0);
        l.push(Arc::downgrade(&nl));
    }
    let sock: Arc<dyn CharDevice> = nl;
    Some(crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(sock)) {
        Ok(fd) => {
            fds.set_cloexec(fd, a[1] & SOCK_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => -24,
    }))
}

impl NetlinkSocket {
    /// Serializes the socket address (`struct sockaddr_nl`) into a 12-byte array.
    ///
    /// # Returns
    ///
    /// A 12-byte array containing the `AF_NETLINK` family, process ID, and multicast groups mask.
    fn sockaddr(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
        b[4..8].copy_from_slice(&self.pid.load(Ordering::Relaxed).to_le_bytes());
        b[8..12].copy_from_slice(&self.groups.load(Ordering::Relaxed).to_le_bytes());
        b
    }

    /// wave8 GH: the next message `(group, bytes)` (a copy with `peek`), waiting for one
    /// unless the socket or `flags` say not to: `Err(-EAGAIN)`, or `Err(-ERESTARTSYS)` on a
    /// signal.
    fn receive(&self, flags: u64) -> Result<(u32, Vec<u8>), i64> {
        let take = || {
            let mut q = self.queue.lock();
            if flags & MSG_PEEK != 0 {
                q.front().cloned()
            } else {
                q.pop_front()
            }
        };
        if let Some(m) = take() {
            return Ok(m);
        }
        if self.nonblock() || flags & MSG_DONTWAIT != 0 {
            return Err(EAGAIN);
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&UEVENT_WQ));
        loop {
            waits.register();
            if let Some(m) = take() {
                return Ok(m);
            }
            if super::proc::signal_pending() {
                return Err(super::proc::ERESTARTSYS);
            }
            waits.wait(None);
        }
    }

    /// `recvmsg` (and the first message of `recvmmsg`): the data into the iovecs, the
    /// sender's address (`nl_groups` = the message's group, port 0: the kernel) and its
    /// credentials (`SCM_CREDENTIALS`, uid 0: libudev ignores a message without them).
    fn recvmsg(&self, msgp: u64, flags: u64) -> i64 {
        let mut msg = match copy_in(msgp, 56) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let (iov, n) = (u64_at(&msg, 16), (u64_at(&msg, 24) as usize).min(64));
        let iovs = match copy_in(iov, n * 16) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (g, d) = match self.receive(flags) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let mut done = 0;
        for c in iovs.chunks(16) {
            let (base, len) = (u64_at(c, 0), u64_at(c, 8) as usize);
            let k = len.min(d.len() - done);
            if k > 0 && copy_out(base, &d[done..done + k]).is_err() {
                return EFAULT;
            }
            done += k;
        }
        let name = u64_at(&msg, 0);
        if name != 0 && u32::from_le_bytes(msg[8..12].try_into().unwrap()) >= 12 {
            let _ = copy_out(name, &sender(g));
            msg[8..12].copy_from_slice(&12u32.to_le_bytes());
        }
        let (control, clen) = (u64_at(&msg, 32), u64_at(&msg, 40));
        let mut cl = 0u64;
        if control != 0 && clen >= 32 {
            let c = creds_cmsg();
            if copy_out(control, &c).is_ok() {
                cl = 32;
            }
        }
        msg[40..48].copy_from_slice(&cl.to_le_bytes());
        msg[48..52].copy_from_slice(&(if done < d.len() { MSG_TRUNC as u32 } else { 0 }).to_le_bytes());
        let _ = copy_out(msgp, &msg);
        if flags & MSG_TRUNC != 0 {
            d.len() as i64
        } else {
            done as i64
        }
    }
}

/// The sender's address of a message of group `g` (`struct sockaddr_nl`: the kernel, port
/// 0, `nl_groups` the group's bit).
fn sender(g: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    if (1..=32).contains(&g) {
        b[8..12].copy_from_slice(&(1u32 << (g - 1)).to_le_bytes());
    }
    b
}

/// One `SCM_CREDENTIALS` control message (`CMSG_SPACE(sizeof(struct ucred))` = 32 bytes):
/// pid, uid and gid 0, the kernel.
fn creds_cmsg() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0..8].copy_from_slice(&28u64.to_le_bytes()); // cmsg_len: header + struct ucred
    c[8..12].copy_from_slice(&1i32.to_le_bytes()); // SOL_SOCKET
    c[12..16].copy_from_slice(&2i32.to_le_bytes()); // SCM_CREDENTIALS
    c
}

/// Copies a serialized sockaddr buffer out to user space, respecting the user-provided maximum length.
///
/// # Arguments
///
/// * `addr` - User virtual pointer to write the sockaddr struct into.
/// * `lenp` - User virtual pointer to the `socklen_t` in/out length.
/// * `data` - Raw bytes of the sockaddr structure to copy out.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno (`-EFAULT`).
fn put_addr(addr: u64, lenp: u64, data: &[u8]) -> i64 {
    if addr == 0 || lenp == 0 {
        return 0;
    }
    let cap = match copy_in(lenp, 4) {
        Ok(v) => u32::from_le_bytes(v[..4].try_into().unwrap()) as usize,
        Err(e) => return e,
    };
    if copy_out(addr, &data[..cap.min(data.len())]).is_err() || copy_out(lenp, &(data.len() as u32).to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

impl CharDevice for NetlinkSocket {
    fn read(&self, buf: &mut [u8]) -> i64 {
        match self.receive(0) {
            Ok((_, d)) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                n as i64
            }
            Err(e) => e,
        }
    }

    fn write(&self, data: &[u8]) -> i64 {
        data.len() as i64
    }

    fn poll_events(&self) -> u32 {
        0x0004 | if self.queue.lock().is_empty() { 0 } else { 0x0001 }
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Static(&UEVENT_WQ));
    }

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        alloc::format!("socket:[{}]", self as *const _ as usize as u64 & 0xFFFF_FFFF)
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    fn socket_call(&self, num: u64, a: [u64; 6]) -> Option<i64> {
        Some(match num {
            49 => {
                // bind: port id 0 means "assign one" (the process id)
                let addr = match copy_in(a[1], 12) {
                    Ok(v) => v,
                    Err(e) => return Some(e),
                };
                let pid = u32::from_le_bytes(addr[4..8].try_into().unwrap());
                let pid = if pid == 0 { super::proc::current_ids().1 as u32 } else { pid };
                self.pid.store(pid, Ordering::Relaxed);
                self.groups.store(u32::from_le_bytes(addr[8..12].try_into().unwrap()), Ordering::Relaxed);
                0
            }
            51 => put_addr(a[1], a[2], &self.sockaddr()),
            52 => {
                let mut kernel = [0u8; 12];
                kernel[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
                put_addr(a[1], a[2], &kernel)
            }
            54 => 0, // setsockopt: buffer sizes, credentials, BPF filters
            55 => {
                // getsockopt
                let v: u32 = match (a[1], a[2]) {
                    (1, 3) => 3,                // SO_TYPE: SOCK_RAW
                    (1, 7) | (1, 8) => 212_992, // SO_SNDBUF / SO_RCVBUF
                    (1, 38) => NETLINK_KOBJECT_UEVENT as u32,
                    (1, 39) => AF_NETLINK as u32,
                    _ => 0,
                };
                if copy_out(a[3], &v.to_le_bytes()).is_err() || copy_out(a[4], &4u32.to_le_bytes()).is_err() {
                    EFAULT
                } else {
                    0
                }
            }
            44 => a[2] as i64, // sendto: delivered nowhere
            46 => 0,
            // wave8 GH: recvfrom, recvmsg, recvmmsg (its first message)
            45 => match self.receive(a[3]) {
                Ok((g, d)) => {
                    let n = d.len().min(a[2] as usize);
                    // (no buffer: systemd's `recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC)` asks the size)
                    if n > 0 && copy_out(a[1], &d[..n]).is_err() {
                        return Some(EFAULT);
                    }
                    let r = put_addr(a[4], a[5], &sender(g));
                    if r != 0 {
                        return Some(r);
                    }
                    if a[3] & MSG_TRUNC != 0 {
                        d.len() as i64
                    } else {
                        n as i64
                    }
                }
                Err(e) => e,
            },
            47 => self.recvmsg(a[1], a[2]),
            299 => {
                let r = self.recvmsg(a[1], a[3]);
                if r < 0 {
                    r
                } else {
                    let _ = copy_out(a[1] + 56, &(r as u32).to_le_bytes());
                    1
                }
            }
            48 => 0, // shutdown
            42 | 43 | 50 | 288 => EINVAL, // connect / accept / listen
            _ => return None,
        })
    }
}
