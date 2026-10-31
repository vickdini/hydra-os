//! # Character devices
//!
//! Device files whose behaviour lives in a driver rather than the filesystem: the DRM/KMS
//! display (`/dev/dri/card0`, [`super::drm`]), the evdev input devices (`/dev/input/eventN`,
//! [`super::evdev`]) and the kernel-event netlink socket ([`super::netlink`]). The device
//! nodes themselves are ordinary character-device inodes in the Linux root (created by
//! [`super::devices`]); opening one looks its device number up here.
//!
//! Each open file is an `Arc<dyn CharDevice>`, shared by `dup`, `fork` and `SCM_RIGHTS`
//! like a Linux `struct file`; the driver's per-open state is released when the last
//! reference goes away.

use alloc::string::String;
use alloc::sync::Arc;

use crate::memory::vm::MappedObject;
use crate::task::wait::WaitSet;

use super::types::LinuxStat;

const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENODEV: i64 = -19;
const ENOTSOCK: i64 = -88;

/// Device number in the kernel's `dev_t` encoding (as `stat` reports it).
pub const fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
}

/// An open character device.
pub trait CharDevice: Send + Sync {
    /// `read(2)`: bytes read, or a negative errno.
    fn read(&self, buf: &mut [u8]) -> i64;

    /// `write(2)`: bytes written, or a negative errno.
    fn write(&self, _data: &[u8]) -> i64 {
        EINVAL
    }

    /// `ioctl(2)` with the request and its (user pointer) argument.
    fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
        ENOTTY
    }

    /// Current `poll` readiness (`POLLIN` = 1, `POLLOUT` = 4).
    fn poll_events(&self) -> u32;

    /// Wait queues that announce readiness changes.
    fn add_wait_queues(&self, waits: &mut WaitSet);

    /// The device number (`st_rdev`) and the node's path (for `/proc/self/fd`).
    fn rdev(&self) -> u64;

    /// Path of the device node.
    fn path(&self) -> String;

    /// The object `mmap` maps pages from, if the device can be mapped.
    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Err(ENODEV)
    }

    /// `O_NONBLOCK` as set by `open` or `fcntl(F_SETFL)`.
    fn set_nonblock(&self, on: bool);

    /// Current `O_NONBLOCK` state.
    fn nonblock(&self) -> bool;

    /// The buffer behind a DMA-BUF descriptor (for `DRM_IOCTL_PRIME_FD_TO_HANDLE`).
    fn dma_buf(&self) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        None
    }

    /// Socket calls (`bind`, `recvmsg`, ...) on devices that are sockets; `None` = `ENOTSOCK`.
    fn socket_call(&self, _num: u64, _a: [u64; 6]) -> Option<i64> {
        None
    }

    /// `stat` of the open device.
    fn stat(&self) -> LinuxStat {
        let mut st = LinuxStat::default();
        st.st_dev = 6; // devtmpfs
        st.st_ino = self.rdev() | 0x1_0000_0000;
        st.st_mode = 0o020660;
        st.st_nlink = 1;
        st.st_rdev = self.rdev();
        st.st_blksize = 4096;
        st
    }
}

/// Opens the driver behind character device `rdev`; `None` if no driver claims it.
pub fn open(rdev: u64, flags: u32) -> Option<Result<Arc<dyn CharDevice>, i64>> {
    let (major, minor) = ((rdev >> 8) & 0xFFF, (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00));
    let nonblock = flags & 0o4000 != 0;
    match major {
        226 => Some(super::drm::open(minor, nonblock)),
        13 => Some(super::evdev::open(minor, nonblock)),
        _ => None,
    }
}

/// Socket calls that belong to device-backed sockets (`AF_NETLINK`).
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    match num {
        41 => super::netlink::socket(a),
        42..=55 | 288 | 299 | 307 => {
            let dev = crate::task::with_current_fds_mut(|fds| match fds.get(a[0] as usize) {
                Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
                _ => None,
            })?;
            Some(dev.socket_call(num, a).unwrap_or(ENOTSOCK))
        }
        _ => None,
    }
}
