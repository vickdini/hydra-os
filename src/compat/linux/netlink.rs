//! # Kernel uevent netlink sockets (`AF_NETLINK`, `NETLINK_KOBJECT_UEVENT`)
//!
//! libudev's device monitor (used by libinput and KWin to hear about hot-plugged devices)
//! opens one of these and fails without it. Hydra's devices are fixed at boot, so the
//! socket binds, answers option queries and accepts filters, but never has a message.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

/// Never woken: a blocking receive waits for a signal.
static NEVER: WaitQueue = WaitQueue::new();

/// An uevent socket.
pub struct NetlinkSocket {
    pid: AtomicU32,
    groups: AtomicU32,
    nonblock: AtomicBool,
}

/// `socket(AF_NETLINK, ...)`: `None` for other domains.
pub fn socket(a: [u64; 6]) -> Option<i64> {
    if a[0] != AF_NETLINK {
        return None;
    }
    if a[2] != NETLINK_KOBJECT_UEVENT {
        return Some(EAFNOSUPPORT); // routing and the rest: not offered (callers cope)
    }
    if a[1] & 0xF != 3 && a[1] & 0xF != 2 {
        return Some(EPROTONOSUPPORT); // SOCK_RAW or SOCK_DGRAM
    }
    let sock: Arc<dyn CharDevice> =
        Arc::new(NetlinkSocket { pid: AtomicU32::new(0), groups: AtomicU32::new(0), nonblock: AtomicBool::new(a[1] & SOCK_NONBLOCK != 0) });
    Some(crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(sock)) {
        Ok(fd) => {
            fds.set_cloexec(fd, a[1] & SOCK_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => -24,
    }))
}

impl NetlinkSocket {
    fn sockaddr(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
        b[4..8].copy_from_slice(&self.pid.load(Ordering::Relaxed).to_le_bytes());
        b[8..12].copy_from_slice(&self.groups.load(Ordering::Relaxed).to_le_bytes());
        b
    }

    fn receive(&self) -> i64 {
        if self.nonblock() {
            return EAGAIN;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Static(&NEVER));
        loop {
            waits.register();
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }
}

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
    fn read(&self, _buf: &mut [u8]) -> i64 {
        self.receive()
    }

    fn write(&self, data: &[u8]) -> i64 {
        data.len() as i64
    }

    fn poll_events(&self) -> u32 {
        0x0004
    }

    fn add_wait_queues(&self, _waits: &mut WaitSet) {}

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
            45 | 47 | 299 => self.receive(),
            48 => 0, // shutdown
            42 | 43 | 50 | 288 => EINVAL, // connect / accept / listen
            _ => return None,
        })
    }
}
