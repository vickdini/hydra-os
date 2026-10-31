//! # Pseudo-Terminals (`/dev/ptmx`, `/dev/pts/N`)
//!
//! A pseudo-terminal pairs a master end, held by a terminal emulator (Konsole, `script`,
//! `ssh`, apt's dpkg log), with a slave end that looks like a real terminal to the
//! programs running on it. Bytes written to the master are input to the slave's line
//! discipline (the same one the console uses, [`super::tty`]): line editing, echo (sent
//! back to the master) and `ISIG` characters raising signals in the slave's foreground
//! process group. Bytes written to the slave get output processing (`ONLCR`) and become
//! readable on the master.
//!
//! Opening `/dev/ptmx` creates a pair; `TIOCGPTN` names the slave and `TIOCSPTLCK`
//! unlocks it for opening as `/dev/pts/N` (or `TIOCGPTPEER` opens it directly). When the
//! master closes, slave reads see end-of-file and writes fail with `EIO` (no `SIGHUP` is
//! sent); when the last slave closes, master reads fail with `EIO`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::tty::{self, Tty};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EAGAIN: i64 = -11;
const EIO: i64 = -5;
const EFAULT: i64 = -14;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

/// Device numbers: `/dev/ptmx` is 5:2, slaves are major 136 and up.
pub const PTMX_MAJOR: u64 = 5;
/// Minor device number for `/dev/ptmx`.
pub const PTMX_MINOR: u64 = 2;
/// Major device number for pseudo-terminal slave endpoints (`/dev/pts/*`).
pub const PTS_MAJOR: u64 = 136;
/// `st_dev` of the devpts file system.
pub const PTS_DEV: u64 = 0x18;
/// Most slave output buffered for the master before slave writers wait.
const OUTPUT_LIMIT: usize = 64 * 1024;

/// Linux `makedev` encoding of a device number.
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
}

struct PtyState {
    /// Slave output (and input echo) waiting for the master.
    to_master: VecDeque<u8>,
    master_open: bool,
    /// Open slave file descriptions.
    slaves: usize,
    /// A slave was opened at least once (master reads fail with EIO after it closes).
    slave_opened: bool,
    /// `TIOCSPTLCK`: the slave cannot be opened while locked.
    locked: bool,
    /// Owner, group and permissions of the slave device node (`grantpt` sets them).
    uid: u32,
    gid: u32,
    mode: u32,
}

/// One pseudo-terminal pair.
pub struct Pty {
    /// Monotonic pseudo-terminal slave index (e.g. 0 for `/dev/pts/0`).
    pub index: u32,
    tty: Mutex<Tty>,
    state: Mutex<PtyState>,
    /// Readers and writers of both ends.
    pub wq: Arc<WaitQueue>,
}

/// An open end: the open file description shared by `dup` and `fork`.
pub struct PtyFile {
    /// Reference to the underlying PTY pair state.
    pub pty: Arc<Pty>,
    /// True if this descriptor represents the master end (`/dev/ptmx`).
    pub master: bool,
    /// Atomic flag indicating whether non-blocking I/O is enabled.
    pub nonblock: AtomicBool,
}

impl Drop for PtyFile {
    fn drop(&mut self) {
        let mut st = self.pty.state.lock();
        if self.master {
            // Slave reads now see end-of-file. (Linux also sends SIGHUP to the session;
            // the last close can happen during task exit under the scheduler lock, where
            // signals cannot be posted, so programs rely on the end-of-file instead.)
            st.master_open = false;
            drop(st);
            PTYS.lock().remove(&self.pty.index);
        } else {
            st.slaves = st.slaves.saturating_sub(1);
        }
        self.pty.wq.wake_all();
    }
}

/// Live pairs by index, for opening `/dev/pts/N`.
static PTYS: Mutex<BTreeMap<u32, Weak<Pty>>> = Mutex::new(BTreeMap::new());

fn lookup(index: u32) -> Option<Arc<Pty>> {
    PTYS.lock().get(&index).and_then(|w| w.upgrade())
}

/// Opens `/dev/ptmx`: creates a pair and returns its master end.
pub fn open_master(uid: u32, nonblock: bool) -> Arc<PtyFile> {
    let mut ptys = PTYS.lock();
    ptys.retain(|_, w| w.strong_count() > 0);
    let index = (0..).find(|i| !ptys.contains_key(i)).unwrap();
    let pty = Arc::new(Pty {
        index,
        tty: Mutex::new(Tty::new()),
        state: Mutex::new(PtyState {
            to_master: VecDeque::new(),
            master_open: true,
            slaves: 0,
            slave_opened: false,
            locked: true,
            uid,
            gid: 5, // tty
            mode: 0o620,
        }),
        wq: WaitQueue::new_shared(),
    });
    ptys.insert(index, Arc::downgrade(&pty));
    Arc::new(PtyFile { pty, master: true, nonblock: AtomicBool::new(nonblock) })
}

/// Opens slave `/dev/pts/<index>`. A session leader without a controlling terminal
/// acquires it unless `noctty`.
pub fn open_slave(index: u32, nonblock: bool, noctty: bool) -> Result<Arc<PtyFile>, i64> {
    let pty = lookup(index).ok_or(ENOENT)?;
    open_slave_of(&pty, nonblock, noctty)
}

fn open_slave_of(pty: &Arc<Pty>, nonblock: bool, noctty: bool) -> Result<Arc<PtyFile>, i64> {
    {
        let mut st = pty.state.lock();
        if st.locked || !st.master_open {
            return Err(EIO);
        }
        st.slaves += 1;
        st.slave_opened = true;
    }
    if !noctty {
        let (_, pid) = super::proc::current_ids();
        if let Some((sid, pgid)) = super::proc::session_of(pid) {
            if sid == pid && controlling_tty(sid).is_none() {
                let mut t = pty.tty.lock();
                if t.session == 0 {
                    t.session = sid;
                    t.fg_pgrp = pgid;
                }
            }
        }
    }
    Ok(Arc::new(PtyFile { pty: pty.clone(), master: false, nonblock: AtomicBool::new(nonblock) }))
}

/// The pseudo-terminal that is the controlling terminal of session `sid` (`/dev/tty`).
pub fn controlling_tty(sid: u64) -> Option<Arc<Pty>> {
    PTYS.lock().values().filter_map(|w| w.upgrade()).find(|p| p.tty.lock().session == sid)
}

/// Opens `/dev/tty` for a process whose controlling terminal is a pseudo-terminal.
pub fn open_controlling(nonblock: bool) -> Option<Arc<PtyFile>> {
    let (_, pid) = super::proc::current_ids();
    let (sid, _) = super::proc::session_of(pid)?;
    let pty = controlling_tty(sid)?;
    open_slave_of(&pty, nonblock, true).ok()
}

/// Indices of the live slaves (`/dev/pts` listing).
pub fn indices() -> Vec<u32> {
    PTYS.lock().iter().filter(|(_, w)| w.strong_count() > 0).map(|(i, _)| *i).collect()
}

/// `stat` of `/dev/ptmx`, `/dev/pts` or `/dev/pts/N`; `None` for other paths.
pub fn stat_path(abs: &str) -> Option<Result<super::types::LinuxStat, i64>> {
    let mut st = super::types::LinuxStat::default();
    st.st_blksize = 1024;
    st.st_nlink = 1;
    if abs == "/dev/ptmx" {
        st.st_dev = PTS_DEV;
        st.st_ino = 2;
        st.st_mode = 0o020666;
        st.st_rdev = makedev(PTMX_MAJOR, PTMX_MINOR);
        return Some(Ok(st));
    }
    if abs == "/dev/pts" || abs == "/dev/pts/" {
        st.st_dev = PTS_DEV;
        st.st_ino = 1;
        st.st_mode = 0o040755;
        st.st_nlink = 2;
        return Some(Ok(st));
    }
    let index = slave_index(abs)?;
    Some(match lookup(index) {
        Some(pty) => {
            pty.fill_stat(&mut st);
            Ok(st)
        }
        None => Err(ENOENT),
    })
}

/// `chmod`/`chown` of `/dev/pts/N` by `euid` (the owner may change the mode and group;
/// only root may give the node away). `None` for other paths.
pub fn setattr_path(abs: &str, euid: u32, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> Option<i64> {
    let index = slave_index(abs)?;
    let pty = match lookup(index) {
        Some(p) => p,
        None => return Some(ENOENT),
    };
    let mut st = pty.state.lock();
    let owner = euid == 0 || euid == st.uid;
    if !owner || (euid != 0 && uid.map_or(false, |u| u != st.uid)) {
        return Some(-1); // EPERM
    }
    if let Some(m) = mode {
        st.mode = m & 0o7777;
    }
    if let Some(u) = uid {
        st.uid = u;
    }
    if let Some(g) = gid {
        st.gid = g;
    }
    Some(0)
}

/// The slave index named by `/dev/pts/<N>`.
pub fn slave_index(abs: &str) -> Option<u32> {
    abs.strip_prefix("/dev/pts/")?.parse().ok()
}

impl Pty {
    fn fill_stat(&self, st: &mut super::types::LinuxStat) {
        st.st_dev = PTS_DEV;
        st.st_ino = self.index as u64 + 3;
        let s = self.state.lock();
        st.st_mode = 0o020000 | s.mode;
        st.st_uid = s.uid;
        st.st_gid = s.gid;
        drop(s);
        st.st_rdev = makedev(PTS_MAJOR + (self.index as u64 >> 8), self.index as u64 & 0xFF);
        st.st_blksize = 1024;
        st.st_nlink = 1;
    }

    /// Returns the canonical path string of the associated slave device node.
    pub fn slave_path(&self) -> String {
        alloc::format!("/dev/pts/{}", self.index)
    }

    /// Feeds input (master writes) through the line discipline.
    fn input(&self, data: &[u8]) {
        let mut echo = Vec::new();
        let mut signals = Vec::new();
        let fg = {
            let mut t = self.tty.lock();
            tty::feed_input(&mut t, data, &mut echo, &mut signals);
            t.fg_pgrp
        };
        if !echo.is_empty() {
            self.state.lock().to_master.extend(echo);
        }
        if fg != 0 {
            for sig in signals {
                super::proc::post_group(fg, sig);
            }
        }
        self.wq.wake_all();
    }
}

impl PtyFile {
    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// stat of the open end.
    pub fn stat(&self) -> super::types::LinuxStat {
        let mut st = super::types::LinuxStat::default();
        if self.master {
            st = stat_path("/dev/ptmx").unwrap().unwrap();
        } else {
            self.pty.fill_stat(&mut st);
        }
        st
    }

    /// Path shown by `/proc/self/fd` (and so `ttyname`).
    pub fn path(&self) -> String {
        if self.master {
            String::from("/dev/ptmx")
        } else {
            self.pty.slave_path()
        }
    }

    /// Reads incoming bytes from the pseudo-terminal end into `buf`.
    pub fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.is_empty() {
            return 0;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.pty.wq.clone()));
        loop {
            waits.register();
            if self.master {
                let mut st = self.pty.state.lock();
                if !st.to_master.is_empty() {
                    let n = buf.len().min(st.to_master.len());
                    for (i, b) in st.to_master.drain(..n).enumerate() {
                        buf[i] = b;
                    }
                    drop(st);
                    self.pty.wq.wake_all(); // room for slave writers
                    return n as i64;
                }
                if st.slave_opened && st.slaves == 0 {
                    return EIO;
                }
            } else {
                if let Some(n) = tty::take_input(&mut self.pty.tty.lock(), buf) {
                    return n;
                }
                if !self.pty.state.lock().master_open {
                    return 0;
                }
            }
            if self.nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    /// Writes bytes to the pseudo-terminal end.
    pub fn write(&self, data: &[u8]) -> i64 {
        if self.master {
            self.pty.input(data);
            return data.len() as i64;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.pty.wq.clone()));
        loop {
            waits.register();
            {
                let mut st = self.pty.state.lock();
                if !st.master_open {
                    return EIO;
                }
                if st.to_master.len() < OUTPUT_LIMIT {
                    let mut out = Vec::with_capacity(data.len() + 8);
                    tty::process_output(&self.pty.tty.lock(), data, &mut out);
                    st.to_master.extend(out);
                    drop(st);
                    self.pty.wq.wake_all();
                    return data.len() as i64;
                }
            }
            if self.nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    /// Writes without waiting for the master to drain output (kernel messages).
    pub fn write_nowait(&self, data: &[u8]) -> usize {
        if self.master {
            self.pty.input(data);
        } else {
            let mut out = Vec::with_capacity(data.len() + 8);
            tty::process_output(&self.pty.tty.lock(), data, &mut out);
            let mut st = self.pty.state.lock();
            if st.master_open {
                st.to_master.extend(out);
            }
            drop(st);
            self.pty.wq.wake_all();
        }
        data.len()
    }

    /// `poll` events of this end.
    pub fn poll_events(&self) -> u32 {
        let st = self.pty.state.lock();
        if self.master {
            let mut ev = 0x0004; // writable
            if !st.to_master.is_empty() {
                ev |= 0x0001;
            }
            if st.slave_opened && st.slaves == 0 {
                ev |= 0x0010;
            }
            ev
        } else {
            let mut ev = if st.to_master.len() < OUTPUT_LIMIT { 0x0004 } else { 0 };
            drop(st);
            if self.pty.tty.lock().has_input() {
                ev |= 0x0001;
            }
            if !self.pty.state.lock().master_open {
                ev |= 0x0010;
            }
            ev
        }
    }

    /// Sets or clears non-blocking mode on this PTY descriptor.
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Queries whether non-blocking mode is currently enabled on this PTY descriptor.
    pub fn get_nonblock(&self) -> bool {
        self.nonblock()
    }

    /// `ioctl` on either end: the pty requests, then the terminal ones (which act on
    /// the slave's terminal from both ends, as on Linux). `open_peer` installs a slave
    /// descriptor for `TIOCGPTPEER`.
    pub fn ioctl(&self, request: u64, arg: u64, open_peer: &dyn Fn(Arc<PtyFile>, u32) -> i64) -> i64 {
        const TIOCGPTN: u64 = 0x8004_5430;
        const TIOCSPTLCK: u64 = 0x4004_5431;
        const TIOCGPTLCK: u64 = 0x8004_5439;
        const TIOCGPTPEER: u64 = 0x5441;
        const TIOCSCTTY: u64 = 0x540E;
        const TIOCPKT: u64 = 0x5420;
        match request {
            TIOCGPTN if self.master => put_u32(arg, self.pty.index),
            TIOCSPTLCK if self.master => match get_u32(arg) {
                Some(v) => {
                    self.pty.state.lock().locked = v != 0;
                    0
                }
                None => EFAULT,
            },
            TIOCGPTLCK if self.master => put_u32(arg, self.pty.state.lock().locked as u32),
            TIOCGPTPEER if self.master => {
                let flags = arg as u32;
                match open_slave_of(&self.pty, flags & 0o4000 != 0, true) {
                    Ok(f) => open_peer(f, flags),
                    Err(e) => e,
                }
            }
            TIOCPKT if self.master => {
                // Packet mode is not supported; accept turning it off
                match get_u32(arg) {
                    Some(0) => 0,
                    Some(_) => EINVAL,
                    None => EFAULT,
                }
            }
            TIOCSCTTY => {
                let (_, pid) = super::proc::current_ids();
                if let Some((sid, pgid)) = super::proc::session_of(pid) {
                    let mut t = self.pty.tty.lock();
                    t.session = sid;
                    t.fg_pgrp = pgid;
                }
                0
            }
            _ => {
                let (r, resized) = tty::tty_ioctl(&self.pty.tty, request, arg, &|| (24, 80));
                if resized {
                    let fg = self.pty.tty.lock().fg_pgrp;
                    if fg != 0 {
                        super::proc::post_group(fg, super::proc::SIGWINCH);
                    }
                }
                if r == 0 {
                    // Mode changes (e.g. leaving canonical mode) may make input readable
                    self.pty.wq.wake_all();
                }
                r
            }
        }
    }
}

fn put_u32(ptr: u64, v: u32) -> i64 {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, 4, true) {
        return EFAULT;
    }
    unsafe { core::ptr::write_unaligned(ptr as *mut u32, v) };
    0
}

fn get_u32(ptr: u64) -> Option<u32> {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, 4, false) {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(ptr as *const u32) })
}
