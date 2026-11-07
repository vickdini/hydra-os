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
    /// Reads bytes from the character device into `buf`.
    ///
    /// # Arguments
    ///
    /// * `buf` - Destination buffer to read into.
    ///
    /// # Returns
    ///
    /// Number of bytes read, or a negative Linux errno.
    fn read(&self, buf: &mut [u8]) -> i64;

    /// Writes bytes from `data` into the character device.
    ///
    /// # Arguments
    ///
    /// * `data` - Source byte slice to write.
    ///
    /// # Returns
    ///
    /// Number of bytes written, or a negative Linux errno.
    fn write(&self, _data: &[u8]) -> i64 {
        EINVAL
    }

    /// Performs an I/O control operation on the character device.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Device-specific ioctl command.
    /// * `arg` - Argument value or user virtual pointer.
    ///
    /// # Returns
    ///
    /// Result code, or negative Linux errno on error.
    fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
        ENOTTY
    }

    /// Queries current `poll` readiness events.
    ///
    /// # Returns
    ///
    /// Bitmask of poll flags (`POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`).
    fn poll_events(&self) -> u32;

    /// Registers the device's wait queues with the wait set.
    ///
    /// # Arguments
    ///
    /// * `waits` - Wait set to register queues with.
    fn add_wait_queues(&self, waits: &mut WaitSet);

    /// Returns the device number (`st_rdev`).
    ///
    /// # Returns
    ///
    /// 64-bit device number.
    fn rdev(&self) -> u64;

    /// Returns the filesystem path of the device node.
    ///
    /// # Returns
    ///
    /// String containing node path.
    fn path(&self) -> String;

    /// Returns the object backing `mmap` for this device, if mappable.
    ///
    /// # Returns
    ///
    /// Mapped memory object reference, or negative errno if unsupported.
    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Err(ENODEV)
    }

    /// Sets non-blocking I/O mode on the device.
    ///
    /// # Arguments
    ///
    /// * `on` - `true` to enable non-blocking mode; `false` to block.
    fn set_nonblock(&self, on: bool);

    /// Queries the current non-blocking I/O mode state.
    ///
    /// # Returns
    ///
    /// `true` if non-blocking mode is set; `false` otherwise.
    fn nonblock(&self) -> bool;

    /// Retrieves the buffer behind a DMA-BUF descriptor.
    ///
    /// # Returns
    ///
    /// Dynamic reference to the underlying DMA-BUF object, or `None`.
    fn dma_buf(&self) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        None
    }

    /// Dispatches socket calls on devices that represent sockets.
    ///
    /// # Arguments
    ///
    /// * `num` - System call number.
    /// * `a` - System call argument register array `[arg0..arg5]`.
    ///
    /// # Returns
    ///
    /// `Some(result)` if handled, or `None` if this device is not a socket.
    fn socket_call(&self, _num: u64, _a: [u64; 6]) -> Option<i64> {
        None
    }

    /// Returns file status metadata for the open device.
    ///
    /// # Returns
    ///
    /// Populated `LinuxStat` structure.
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

    /// Queues a kernel notification message on a netlink socket (POSIX message queue
    /// `SIGEV_THREAD` notification, which glibc receives on such a socket).
    ///
    /// # Returns
    ///
    /// `true` if this device took the message.
    fn deliver_notification(&self, _data: &[u8]) -> bool {
        false
    }

    /// The POSIX message queue behind this descriptor, if it is one.
    fn as_mqueue(&self) -> Option<&super::mqueue::MqHandle> {
        None
    }

    /// `pread` at `offset`, for a device with positions (`/proc/<pid>/mem`); `None` if it
    /// has none.
    fn pread(&self, _buf: &mut [u8], _offset: u64) -> Option<i64> {
        None
    }

    /// `pwrite` at `offset` (see [`CharDevice::pread`]).
    fn pwrite(&self, _data: &[u8], _offset: u64) -> Option<i64> {
        None
    }

    /// `lseek` (see [`CharDevice::pread`]).
    fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
        None
    }

    /// `read` outside the descriptor table's lock (a device whose reads install
    /// descriptors, like fanotify's); `None` to read the usual way.
    fn read_unlocked(&self, _buf: &mut [u8]) -> Option<i64> {
        None
    }

    /// The bpf object behind this descriptor, if it is one.
    fn as_bpf(&self) -> Option<super::bpf::Obj> {
        None
    }

    /// The perf counter behind this descriptor, if it is one.
    fn as_perf(&self) -> Option<Arc<super::perf::Event>> {
        None
    }

    /// The fanotify group behind this descriptor, if it is one.
    fn as_fanotify(&self) -> Option<Arc<super::fanotify::Group>> {
        None
    }

    /// The new mount API's object behind this descriptor, if it is one.
    fn as_mount_obj(&self) -> Option<&super::mount::MountObj> {
        None
    }

    /// The io_uring instance behind this descriptor, if it is one.
    fn as_io_uring(&self) -> Option<Arc<super::io_uring::Ring>> {
        None
    }

    /// The Landlock ruleset behind this descriptor, if it is one.
    fn as_landlock(&self) -> Option<&super::landlock::Ruleset> {
        None
    }
}

/// Opens the driver behind character device `rdev`; `None` if no driver claims it.
///
/// # Arguments
///
/// * `rdev` - Encoded 64-bit device major and minor number.
/// * `flags` - Linux open flags bitmask.
///
/// # Returns
///
/// `Some(Ok(dev))` or `Some(Err(code))` if claimed by a driver, or `None` if unhandled.
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
///
/// # Arguments
///
/// * `num` - System call number.
/// * `a` - System call argument registers.
///
/// # Returns
///
/// `Some(result)` if handled, or `None` if `num` is not a device socket call.
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
