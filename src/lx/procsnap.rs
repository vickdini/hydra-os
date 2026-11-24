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
//!   at 0 make the text again, as Linux's seq_file does (a rewind at the next read, so
//!   `lseek` never fails; a remake's error comes with that read): the kernel sends
//!   [`LX_KCALL_PREMAKE`] with the snapshot's identity to lx-proc from the reader's context,
//!   and lx-proc gives the fresh text with `LX_OBJ_PSNAP(req, LX_PSNAP_FILL, ..)`.
//!   A rewind keeps the new text; a `pread` at 0 reads from it once. The remake is made
//!   with the *opener's* rights (kept with the snapshot: user, capabilities, PID and IPC
//!   namespace), as Linux checks access at open.
//! - Snapshot text is counted against [`TOTAL_CAP`] and a per-user [`USER_CAP`] and
//!   allocated fallibly (`-ENOMEM`, never an abort).
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

// wave11 GP begin: directory snapshots
/// The length of a directory snapshot entry's head (`ino`, type, name length).
pub const DIRENT_HEAD: usize = 10;

/// The entries of a directory snapshot's text (`ino`, `DT_*` type, name); a cut-off entry
/// at the end is left out.
pub fn dir_entries(text: &[u8]) -> alloc::vec::Vec<(u64, u8, &[u8])> {
    let mut v = alloc::vec::Vec::new();
    let mut at = 0;
    while at + DIRENT_HEAD <= text.len() {
        let ino = u64::from_le_bytes(text[at..at + 8].try_into().unwrap_or([0; 8]));
        let (t, n) = (text[at + 8], text[at + 9] as usize);
        let Some(name) = text.get(at + DIRENT_HEAD..at + DIRENT_HEAD + n) else { break };
        v.push((ino, t, name));
        at += DIRENT_HEAD + n;
    }
    v
}

/// The `linux_dirent64` records of `text`'s entries from index `from` (with `.` and `..`
/// first: indexes 0 and 1, inode `dot`) that fit in `count` bytes, and the index after the
/// last one (`d_off` of each record is the index after it). `-EINVAL` when not even the
/// first record fits.
pub fn dirent64(text: &[u8], dot: u64, from: u64, count: usize) -> Result<(alloc::vec::Vec<u8>, u64), i64> {
    let entries = dir_entries(text);
    let total = entries.len() as u64 + 2;
    let mut out = alloc::vec::Vec::new();
    let mut i = from;
    while i < total {
        let (ino, t, name): (u64, u8, &[u8]) = match i {
            0 => (dot, 4, b"."),
            1 => (dot, 4, b".."),
            k => entries[(k - 2) as usize],
        };
        let reclen = (19 + name.len() + 1 + 7) & !7;
        if out.len() + reclen > count {
            if out.is_empty() {
                return Err(EINVAL);
            }
            break;
        }
        let start = out.len();
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&(i + 1).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(t);
        out.extend_from_slice(name);
        out.push(0);
        out.resize(start + reclen, 0);
        i += 1;
    }
    Ok((out, i))
}
// wave11 GP end

/// Whether a seek is a rewind that makes the text again (`lseek(fd, 0, SEEK_SET)`) for a
/// snapshot of identity code `code` (0: fixed text, never made again).
pub fn remakes_on_seek(code: u64, offset: i64, whence: u32) -> bool {
    code != 0 && offset == 0 && whence == 0
}

/// The most snapshot text the kernel keeps for all open `/proc` files together (bytes).
pub const TOTAL_CAP: usize = 256 << 20;
/// The most snapshot text kept for the open files of one user (bytes; root too).
pub const USER_CAP: usize = 64 << 20;

/// Whether `n` more bytes of snapshot text may be kept when `total` bytes are kept in all
/// and `mine` for the user (`-ENOMEM` otherwise, as a failed allocation).
pub fn may_charge(total: usize, mine: usize, n: usize) -> bool {
    total.checked_add(n).is_some_and(|t| t <= TOTAL_CAP) && mine.checked_add(n).is_some_and(|m| m <= USER_CAP)
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
    use crate::ipc::protocol::{lx_req_svc, LxSnapIo, SvcId, LXS_PROC, LX_KCALL_PREMAKE, LX_OBJ_NAME_MAX, LX_PSNAP_FILL, LX_PSNAP_IDENT, LX_PSNAP_INSTALL, LX_PSNAP_MAX};
    use crate::task::wait::WaitSet;
    use crate::task::TaskId;

    const EPERM: i64 = -1;
    const ESRCH: i64 = -3;
    const EIO: i64 = -5;
    const EBADF: i64 = -9;
    const ENOMEM: i64 = -12;
    const EFAULT: i64 = -14;
    const EMFILE: i64 = -24;
    const ENOTTY: i64 = -25;
    const ENODEV: i64 = -19;
    const EISDIR: i64 = -21; // wave11 GP
    const ENOTDIR: i64 = -20; // wave11 GP
    /// wave11 GP: `S_IFMT`, `S_IFDIR`.
    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;

    const O_RDONLY: u32 = 0;
    const O_WRONLY: u32 = 1;
    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC: u32 = 0o2000000;
    /// `POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM`: a regular file is always ready.
    const READY: u32 = 0x1 | 0x4 | 0x40 | 0x100;

    /// The rights of the process that opened a snapshot: a remake is answered with them (as
    /// Linux checks a `/proc` file's access at open), not with the reader's.
    #[derive(Clone, Copy, Debug)]
    pub struct Opener {
        /// Its process.
        pub tgid: u64,
        /// Its effective user and group.
        pub euid: u32,
        /// See [`Opener::euid`].
        pub egid: u32,
        /// Its effective capabilities (0 in a user namespace of its own).
        pub caps: u64,
        /// Its PID namespace's init (`None`: the first namespace).
        pub init: Option<u64>,
        /// It is in a user namespace of its own.
        pub in_userns: bool,
        /// Its IPC namespace (`/proc/sysvipc`).
        pub ipc_ns: u64,
    }

    /// The text and the position, shared by the descriptor's `dup`s.
    struct Text {
        text: Vec<u8>,
        pos: u64,
        /// Rewound: the next read makes the text again first (seq_file's rule, done lazily
        /// so `lseek` itself never fails for a remake).
        stale: bool,
    }

    /// An open `/proc` file served by lx-proc: its text, kept by the kernel.
    pub struct ProcSnap {
        inner: Mutex<Text>,
        /// lx-proc's identity of the file (`LxSnapIo::ident`).
        ident: [u64; 4],
        /// Who opened it.
        opener: Opener,
        mode: u32,
        uid: u32,
        gid: u32,
        ino: u64,
        dev: u64,
        size: u64,
        name: String,
        nonblock: AtomicBool,
        /// The open's access mode (`O_ACCMODE`).
        acc: u32,
    }

    /// Remakes under way: the reader's thread -> the opener whose rights apply and the text
    /// lx-proc gave (`None`: not yet).
    static PENDING: Mutex<BTreeMap<u64, (Opener, Option<Vec<u8>>)>> = Mutex::new(BTreeMap::new());

    fn pending<R>(f: impl FnOnce(&mut BTreeMap<u64, (Opener, Option<Vec<u8>>)>) -> R) -> R {
        x86_64::instructions::interrupts::without_interrupts(|| f(&mut PENDING.lock()))
    }

    /// Snapshot bytes kept: in all, and per opener's user.
    static CHARGED: Mutex<(usize, BTreeMap<u32, usize>)> = Mutex::new((0, BTreeMap::new()));

    /// Counts `n` more bytes for user `uid`; `-ENOMEM` past the caps.
    fn charge(uid: u32, n: usize) -> Result<(), i64> {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut c = CHARGED.lock();
            let mine = c.1.get(&uid).copied().unwrap_or(0);
            if !may_charge(c.0, mine, n) {
                return Err(ENOMEM);
            }
            c.0 += n;
            c.1.insert(uid, mine + n);
            Ok(())
        })
    }

    /// Counts `n` bytes of user `uid` no more.
    fn uncharge(uid: u32, n: usize) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut c = CHARGED.lock();
            c.0 = c.0.saturating_sub(n);
            let left = c.1.get(&uid).copied().unwrap_or(0).saturating_sub(n);
            if left == 0 {
                c.1.remove(&uid);
            } else {
                c.1.insert(uid, left);
            }
        })
    }

    /// A zeroed buffer of `n` bytes, or `-ENOMEM` (never an abort of the kernel).
    fn buffer(n: usize) -> Result<Vec<u8>, i64> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| ENOMEM)?;
        v.resize(n, 0);
        Ok(v)
    }

    /// The opener whose rights apply to the remake thread `tid` is waiting for (the info
    /// primitives ask: `lx::info`'s caller).
    pub fn opener_of(tid: u64) -> Option<Opener> {
        pending(|p| p.get(&tid).map(|e| e.0))
    }

    impl ProcSnap {
        /// Fresh text from lx-proc for the current thread (the reader), made with the
        /// opener's rights, or its error.
        fn remake(&self) -> Result<Vec<u8>, i64> {
            // (a text that fits comes back in the call's kernel buffer; a longer one
            // through `LX_PSNAP_FILL`)
            let me = crate::task::CURRENT_TID.load(Ordering::Relaxed);
            pending(|p| p.insert(me, (self.opener, None)));
            let mut kbuf = match buffer(crate::ipc::protocol::LX_DATA_SIZE) {
                Ok(b) => b,
                Err(e) => {
                    pending(|p| p.remove(&me));
                    return Err(e);
                }
            };
            let r = crate::lx::call_kbuf_plain(LX_KCALL_PREMAKE, self.ident, self.opener.ipc_ns, &mut kbuf);
            let text = pending(|p| p.remove(&me)).and_then(|e| e.1);
            match (r, text) {
                (r, _) if r < 0 => Err(r),
                (r, _) if r > 0 && (r - 1) as usize <= kbuf.len() => {
                    kbuf.truncate((r - 1) as usize);
                    Ok(kbuf)
                }
                (0, Some(t)) => Ok(t),
                // (lx-proc answered without giving the text)
                _ => Err(EIO),
            }
        }

        /// Makes the text again if the file was rewound; the error of the remake otherwise
        /// (reported by the read, as Linux's seq_file).
        fn refresh(&self) -> Result<(), i64> {
            if !self.inner.lock().stale {
                return Ok(());
            }
            let fresh = self.remake()?;
            charge(self.opener.euid, fresh.len())?;
            let old = {
                let mut t = self.inner.lock();
                if t.stale {
                    t.stale = false;
                    core::mem::replace(&mut t.text, fresh).len()
                } else {
                    // (another reader made it meanwhile)
                    fresh.len()
                }
            };
            uncharge(self.opener.euid, old);
            Ok(())
        }

        /// wave11 GP: a directory snapshot (its text is a list of entries).
        fn is_dir(&self) -> bool {
            self.mode & S_IFMT == S_IFDIR
        }

        /// A read at the position, after a pending remake.
        fn read_at_pos(&self, buf: &mut [u8]) -> i64 {
            if self.acc == O_WRONLY {
                return EBADF;
            }
            if self.is_dir() {
                return EISDIR; // wave11 GP
            }
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
    }

    impl Drop for ProcSnap {
        fn drop(&mut self) {
            let n = self.inner.lock().text.len();
            uncharge(self.opener.euid, n);
        }
    }

    impl CharDevice for ProcSnap {
        fn read(&self, buf: &mut [u8]) -> i64 {
            // (the kernel's own reads, inside the descriptor table's lock: no remake there;
            // programs' reads come through `read_unlocked`)
            self.read_at_pos(buf)
        }

        fn read_unlocked(&self, buf: &mut [u8]) -> Option<i64> {
            if self.acc == O_WRONLY {
                return Some(EBADF);
            }
            if self.is_dir() {
                return Some(EISDIR); // wave11 GP
            }
            if let Err(e) = self.refresh() {
                return Some(e);
            }
            Some(self.read_at_pos(buf))
        }

        fn write(&self, _data: &[u8]) -> i64 {
            // (opened for writing, which only root may: the file takes no writes, as Linux's
            // `/proc` files without a write handler)
            if self.acc == O_RDONLY {
                EBADF
            } else {
                EIO
            }
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

        // wave11 GP begin
        fn proc_ident(&self) -> Option<([u64; 4], u32, String)> {
            Some((self.ident, self.mode, self.name.clone()))
        }

        fn getdents64(&self, count: usize) -> Option<Result<Vec<u8>, i64>> {
            if !self.is_dir() {
                return Some(Err(ENOTDIR));
            }
            if let Err(e) = self.refresh() {
                return Some(Err(e));
            }
            let mut t = self.inner.lock();
            Some(dirent64(&t.text, self.ino, t.pos, count).map(|(out, next)| {
                t.pos = next;
                out
            }))
        }
        // wave11 GP end

        fn stat(&self) -> crate::compat::linux::types::LinuxStat {
            let mut st = crate::compat::linux::types::LinuxStat::default();
            st.st_mode = self.mode;
            st.st_uid = self.uid;
            st.st_gid = self.gid;
            st.st_nlink = if self.is_dir() { 2 } else { 1 };
            st.st_ino = self.ino;
            st.st_dev = self.dev;
            st.st_size = self.size as i64;
            st.st_blksize = 4096;
            st
        }

        fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
            // A rewind marks the text for remaking at the next read (lseek itself always
            // works, as on Linux)
            let mut t = self.inner.lock();
            // wave11 GP: a directory's position is an entry index (`d_off`, `seekdir`)
            if self.is_dir() {
                return Some(match whence {
                    0 if offset >= 0 => {
                        if remakes_on_seek(self.ident[0], offset, whence) {
                            t.stale = true;
                        }
                        t.pos = offset as u64;
                        offset
                    }
                    1 if offset == 0 => t.pos as i64,
                    _ => EINVAL,
                });
            }
            Some(match seek_to(t.pos, t.text.len() as u64, offset, whence) {
                Ok(new) => {
                    if remakes_on_seek(self.ident[0], offset, whence) {
                        t.stale = true;
                    }
                    t.pos = new;
                    new as i64
                }
                Err(e) => e,
            })
        }

        fn pread(&self, buf: &mut [u8], offset: u64) -> Option<i64> {
            if self.acc == O_WRONLY {
                return Some(EBADF);
            }
            if self.is_dir() {
                return Some(EISDIR); // wave11 GP
            }
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
        // wave11 GP: the identity of one of the caller's descriptors (`d.ident[0]`)
        if sub == LX_PSNAP_IDENT {
            return ident_of(client, d.ident[0], io);
        }
        // (a FILL only for a remake this thread is waiting for: nothing is allocated otherwise)
        if sub == LX_PSNAP_FILL && pending(|p| !p.contains_key(&client)) {
            return EINVAL;
        }
        let mut text = match buffer(d.len as usize) {
            Ok(t) => t,
            Err(e) => return e,
        };
        if !text.is_empty() && crate::lx::copy::read_user(d.text, &mut text).is_err() {
            return EFAULT;
        }
        match sub {
            LX_PSNAP_INSTALL => install(client, &d, text),
            LX_PSNAP_FILL => pending(|p| match p.get_mut(&client) {
                Some(slot) => {
                    slot.1 = Some(text);
                    0
                }
                None => EINVAL,
            }),
            _ => EINVAL,
        }
    }

    // wave11 GP begin
    /// `LX_PSNAP_IDENT`: the identity, mode and shown path of thread `client`'s descriptor
    /// `fd`, written to lx-proc's `io`.
    fn ident_of(client: u64, fd: u64, io: u64) -> i64 {
        let Some(fds) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()) else { return ESRCH };
        let dev = match fds.lock().get(fd as i32 as usize) {
            Some(FileDescriptor::Device(d)) if (fd as i32) >= 0 => d.clone(),
            Some(_) => return ENOTDIR,
            None => return EBADF,
        };
        let Some((ident, mode, name)) = dev.proc_ident() else { return ENOTDIR };
        let mut d = LxSnapIo::EMPTY;
        d.ident = ident;
        d.mode = mode;
        let n = name.len().min(LX_OBJ_NAME_MAX);
        d.name[..n].copy_from_slice(&name.as_bytes()[..n]);
        d.name_len = n as u32;
        // SAFETY: a plain repr(C) struct of integers
        let raw = unsafe { core::slice::from_raw_parts(&d as *const LxSnapIo as *const u8, core::mem::size_of::<LxSnapIo>()) };
        match crate::compat::linux::vfs::copy_out(io, raw) {
            Ok(()) => 0,
            Err(_) => EFAULT,
        }
    }
    // wave11 GP end

    /// The rights of thread `client` (a request's caller), kept with its snapshots.
    fn opener(client: u64) -> Option<Opener> {
        let (tgid, euid, egid, caps, in_userns) = crate::task::SCHEDULER
            .lock()
            .with_task_mut(TaskId(client), |t| (t.tgid, t.euid, t.egid, if t.caps.in_userns { 0 } else { t.caps.effective }, t.caps.in_userns))?;
        let init = crate::lx::proc::pid_ns_init(tgid);
        let ipc_ns = crate::compat::linux::proc::PROCS.lock().get(&tgid).map_or(0, |p| p.ns.ipc);
        Some(Opener { tgid, euid, egid, caps, init, in_userns, ipc_ns })
    }

    /// Installs a snapshot descriptor with `text` in thread `client`'s table.
    fn install(client: u64, d: &LxSnapIo, text: Vec<u8>) -> i64 {
        let Some(opener) = opener(client) else { return ESRCH };
        let Some(fds) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()) else { return ESRCH };
        if let Err(e) = charge(opener.euid, text.len()) {
            return e;
        }
        // (from here the snapshot's Drop gives the bytes back)
        let snap = Arc::new(ProcSnap {
            inner: Mutex::new(Text { text, pos: 0, stale: false }),
            ident: d.ident,
            opener,
            mode: d.mode,
            uid: d.uid,
            gid: d.gid,
            ino: d.ino,
            dev: d.dev,
            size: d.size,
            name: String::from_utf8_lossy(&d.name[..d.name_len as usize]).into_owned(),
            nonblock: AtomicBool::new(d.flags & O_NONBLOCK != 0),
            acc: d.flags & 3,
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
