//! # Kernel-held snapshots of open `/proc` files (wave 10, Group 7b-2)
//!
//! lx-proc serves `/proc` (`docs/src/linux-server.md`, "lx-proc"): the file service
//! redirects a lookup under `/proc` to it, and it makes an opened file's text from the
//! kernel's info primitives. The text is then handed to the kernel, which keeps it in a
//! descriptor of its own ([`ProcSnap`], a [`CharDevice`] that is *not* a server object):
//!
//! - `read`/`readv`, `lseek` (except a rewind), `pread` (except at 0), `fstat`, `poll` and
//!   close are answered here: no call reaches lx-proc, and lx-proc keeps nothing per open
//!   file (so an open `/proc` file outlives lx-proc's restarts).
//! - A **rewind** (`lseek(fd, 0, SEEK_SET)`, what `top` does with `/proc/stat`) and a `pread`
//!   at 0 make the text again, as Linux's seq_file does: the kernel sends
//!   [`LX_KCALL_PREMAKE`] with the snapshot's identity to lx-proc from the reader's context,
//!   and lx-proc gives the fresh text with `LX_OBJ_PSNAP(req, LX_PSNAP_FILL, ..)`.
//!   A rewind keeps the new text; a `pread` at 0 reads from it once.
//!
//! The rules of positions ([`seek_to`], [`piece`]) are plain functions (host-tested in
//! `tests/host-w10-7b2`); the descriptor and the operations are in [`glue`] (kernel only).
//!
//! [`CharDevice`]: crate::compat::linux::chardev::CharDevice
//! [`LX_KCALL_PREMAKE`]: crate::ipc::protocol::LX_KCALL_PREMAKE

const EINVAL: i64 = -22;

/// The new position of an `lseek(offset, whence)` from `pos` in a text of `len` bytes
/// (`SEEK_SET` 0, `SEEK_CUR` 1, `SEEK_END` 2; `SEEK_DATA` 3 and `SEEK_HOLE` 4 as on a
/// regular file without holes); `-EINVAL` for a negative result or another `whence`,
/// `-ENXIO` for `SEEK_DATA`/`SEEK_HOLE` at or past the end.
pub fn seek_to(pos: u64, len: u64, offset: i64, whence: u32) -> Result<u64, i64> {
    const ENXIO: i64 = -6;
    let new = match whence {
        0 => Some(offset),
        1 => (pos as i64).checked_add(offset),
        2 => (len as i64).checked_add(offset),
        3 | 4 => {
            if offset < 0 {
                return Err(EINVAL);
            }
            if offset as u64 >= len {
                return Err(ENXIO);
            }
            Some(if whence == 3 { offset } else { len as i64 })
        }
        _ => return Err(EINVAL),
    };
    match new {
        Some(n) if n >= 0 => Ok(n as u64),
        _ => Err(EINVAL),
    }
}

/// The byte range of a `len`-byte text that a read of `want` bytes at `pos` returns.
pub fn piece(len: usize, pos: u64, want: usize) -> core::ops::Range<usize> {
    let start = (pos.min(usize::MAX as u64) as usize).min(len);
    start..start.saturating_add(want).min(len)
}

/// Whether a seek is a rewind that makes the text again (`lseek(fd, 0, SEEK_SET)`) for a
/// snapshot of identity code `code` (0: fixed text, never made again).
pub fn remakes_on_seek(code: u64, offset: i64, whence: u32) -> bool {
    code != 0 && offset == 0 && whence == 0
}

/// The kernel's side: the descriptor, the install and the remake.
#[cfg(target_os = "uefi")]
pub mod glue {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use spin::Mutex;

    use super::*;
    use crate::compat::linux::chardev::CharDevice;
    use crate::fs::FileDescriptor;
    use crate::ipc::protocol::{lx_req_svc, LxSnapIo, SvcId, LXS_PROC, LX_KCALL_PREMAKE, LX_OBJ_NAME_MAX, LX_PSNAP_FILL, LX_PSNAP_INSTALL, LX_PSNAP_MAX};
    use crate::task::wait::WaitSet;
    use crate::task::TaskId;

    const EPERM: i64 = -1;
    const ESRCH: i64 = -3;
    const EBADF: i64 = -9;
    const EFAULT: i64 = -14;
    const EMFILE: i64 = -24;
    const ENOTTY: i64 = -25;
    const ENODEV: i64 = -19;

    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC: u32 = 0o2000000;
    /// `POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM`: a regular file is always ready.
    const READY: u32 = 0x1 | 0x4 | 0x40 | 0x100;

    /// The text and the position, shared by the descriptor's `dup`s.
    struct Text {
        text: Vec<u8>,
        pos: u64,
    }

    /// An open `/proc` file served by lx-proc: its text, kept by the kernel.
    pub struct ProcSnap {
        inner: Mutex<Text>,
        /// lx-proc's identity of the file (`LxSnapIo::ident`).
        ident: [u64; 4],
        mode: u32,
        uid: u32,
        gid: u32,
        ino: u64,
        dev: u64,
        size: u64,
        name: String,
        nonblock: AtomicBool,
    }

    /// Remakes under way: the reader's thread -> the text lx-proc gave (`None`: not yet).
    static PENDING: Mutex<BTreeMap<u64, Option<Vec<u8>>>> = Mutex::new(BTreeMap::new());

    fn pending<R>(f: impl FnOnce(&mut BTreeMap<u64, Option<Vec<u8>>>) -> R) -> R {
        x86_64::instructions::interrupts::without_interrupts(|| f(&mut PENDING.lock()))
    }

    impl ProcSnap {
        /// Fresh text from lx-proc for the current thread (the reader), or its error.
        fn remake(&self) -> Result<Vec<u8>, i64> {
            let me = crate::task::CURRENT_TID.load(Ordering::Relaxed);
            pending(|p| p.insert(me, None));
            let r = crate::lx::call_plain(LX_KCALL_PREMAKE, [self.ident[0], self.ident[1], self.ident[2], self.ident[3], 0, 0]);
            let text = pending(|p| p.remove(&me)).flatten();
            match (r, text) {
                (r, _) if r < 0 => Err(r),
                (_, Some(t)) => Ok(t),
                // (lx-proc answered without giving the text)
                (_, None) => Err(-5),
            }
        }
    }

    impl CharDevice for ProcSnap {
        fn read(&self, buf: &mut [u8]) -> i64 {
            // (the piece is taken and the position moved under one lock: two readers of
            // one open file never get the same bytes)
            let chunk = {
                let mut t = self.inner.lock();
                let r = piece(t.text.len(), t.pos, buf.len());
                t.pos += r.len() as u64;
                t.text[r].to_vec()
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            chunk.len() as i64
        }

        fn write(&self, _data: &[u8]) -> i64 {
            EBADF
        }

        fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
            ENOTTY
        }

        fn poll_events(&self) -> u32 {
            READY
        }

        fn add_wait_queues(&self, _waits: &mut WaitSet) {}

        fn rdev(&self) -> u64 {
            0
        }

        fn path(&self) -> String {
            self.name.clone()
        }

        fn mmap_object(&self) -> Result<Arc<dyn crate::memory::vm::MappedObject>, i64> {
            Err(ENODEV)
        }

        fn set_nonblock(&self, on: bool) {
            self.nonblock.store(on, Ordering::Relaxed);
        }

        fn nonblock(&self) -> bool {
            self.nonblock.load(Ordering::Relaxed)
        }

        fn stat(&self) -> crate::compat::linux::types::LinuxStat {
            let mut st = crate::compat::linux::types::LinuxStat::default();
            st.st_mode = self.mode;
            st.st_uid = self.uid;
            st.st_gid = self.gid;
            st.st_nlink = 1;
            st.st_ino = self.ino;
            st.st_dev = self.dev;
            st.st_size = self.size as i64;
            st.st_blksize = 4096;
            st
        }

        fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
            // A rewind reads fresh text: made first (outside the lock), then text and
            // position set together
            let fresh = if remakes_on_seek(self.ident[0], offset, whence) {
                match self.remake() {
                    Ok(t) => Some(t),
                    Err(e) => return Some(e),
                }
            } else {
                None
            };
            let mut t = self.inner.lock();
            Some(match seek_to(t.pos, t.text.len() as u64, offset, whence) {
                Ok(new) => {
                    if let Some(f) = fresh {
                        t.text = f;
                    }
                    t.pos = new;
                    new as i64
                }
                Err(e) => e,
            })
        }

        fn pread(&self, buf: &mut [u8], offset: u64) -> Option<i64> {
            // (at 0: fresh text for this read only; the open's own text and position stay)
            let chunk = if offset == 0 && self.ident[0] != 0 {
                match self.remake() {
                    Ok(t) => t[piece(t.len(), 0, buf.len())].to_vec(),
                    Err(e) => return Some(e),
                }
            } else {
                let t = self.inner.lock();
                t.text[piece(t.text.len(), offset, buf.len())].to_vec()
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            Some(chunk.len() as i64)
        }
    }

    /// `SYS_LX_OBJ(LX_OBJ_PSNAP, req, sub, io)` from host `h`.
    pub fn ctl(h: SvcId, req: u64, sub: u64, io: u64) -> i64 {
        if h == 0 || h != crate::lx::svc::host_of(LXS_PROC) {
            return EPERM;
        }
        if lx_req_svc(req) != h {
            return ESRCH;
        }
        let Some(client) = crate::lx::client_of(req) else { return ESRCH };
        let mut d = LxSnapIo::EMPTY;
        // SAFETY: a plain repr(C) struct of integers: any bytes are a valid value
        if crate::lx::copy::read_user(io, unsafe { core::slice::from_raw_parts_mut(&mut d as *mut LxSnapIo as *mut u8, core::mem::size_of::<LxSnapIo>()) }).is_err() {
            return EFAULT;
        }
        if d.len as usize > LX_PSNAP_MAX || d.name_len as usize > LX_OBJ_NAME_MAX {
            return EINVAL;
        }
        let mut text = alloc::vec![0u8; d.len as usize];
        if !text.is_empty() && crate::lx::copy::read_user(d.text, &mut text).is_err() {
            return EFAULT;
        }
        match sub {
            LX_PSNAP_INSTALL => install(client, &d, text),
            LX_PSNAP_FILL => pending(|p| match p.get_mut(&client) {
                Some(slot) => {
                    *slot = Some(text);
                    0
                }
                // (no remake of this thread is waiting)
                None => EINVAL,
            }),
            _ => EINVAL,
        }
    }

    /// Installs a snapshot descriptor with `text` in thread `client`'s table.
    fn install(client: u64, d: &LxSnapIo, text: Vec<u8>) -> i64 {
        let Some(fds) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()) else { return ESRCH };
        let snap = Arc::new(ProcSnap {
            inner: Mutex::new(Text { text, pos: 0 }),
            ident: d.ident,
            mode: d.mode,
            uid: d.uid,
            gid: d.gid,
            ino: d.ino,
            dev: d.dev,
            size: d.size,
            name: String::from_utf8_lossy(&d.name[..d.name_len as usize]).into_owned(),
            nonblock: AtomicBool::new(d.flags & O_NONBLOCK != 0),
        });
        let dev: Arc<dyn CharDevice> = snap;
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
                // (remembered in case the answer is lost in a restart, as server objects)
                crate::lx::restart::installed(client, fd as i32);
                fd as i64
            }
            Err(e) => e,
        }
    }
}
