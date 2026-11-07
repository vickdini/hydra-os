//! Administration calls: `syslog`, `vhangup`, `ustat`, `sysfs`, `acct`, `swapon`/`swapoff`,
//! `quotactl`/`quotactl_fd`.
//!
//! - **syslog**: the kernel log (everything `kprintln` prints, in a 64 KiB ring with
//!   Linux's `<level>[seconds]` line prefixes) read, read-and-cleared, cleared and sized;
//!   `CAP_SYSLOG` or `CAP_SYS_ADMIN` (`dmesg_restrict` is 1, as on Ubuntu).
//! - **vhangup** (`CAP_SYS_TTY_CONFIG`) hangs up the caller's controlling terminal: its
//!   session leader and foreground group get `SIGHUP` and `SIGCONT`, the session loses it,
//!   and descriptors opened before read end-of-file and fail writes with `EIO`.
//! - **ustat** reports the pool's free blocks and inodes; **sysfs** lists file system types.
//! - **acct** (`CAP_SYS_PACCT`) appends a version-2 `struct acct` record (Ubuntu's kernels'
//!   format) for every process that
//!   ends: command, IDs, start time, elapsed and CPU time, exit status, fork-without-exec
//!   and signal flags. Records are written at the next system call (process exit runs where
//!   the file server must not be called).
//! - **swapon/swapoff** check the swap signature and register or remove the area (listed in
//!   `/proc/swaps` and `/proc/meminfo`); Hydra does not page memory out to it.
//! - **quotactl**: the pool keeps no per-user usage, so (after the usual checks) quotas are
//!   reported as not supported, as Linux does for a file system without quota support.
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use super::vfs::copy_out;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EACCES: i64 = -13;
const ENOTBLK: i64 = -15;
const EBUSY: i64 = -16;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

fn capable(bit: u32) -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1u64 << bit) != 0 && !t.caps.in_userns).unwrap_or(false)
}

// ----------------------------------------------------------------------
// The kernel log
// ----------------------------------------------------------------------

const KLOG_SIZE: usize = 64 * 1024;

struct Klog {
    buf: [u8; KLOG_SIZE],
    /// Bytes written ever (the ring holds the last `KLOG_SIZE`).
    written: u64,
    /// Where `SYSLOG_ACTION_READ` continues, and where a clear left off.
    read_at: u64,
    cleared_at: u64,
    line_start: bool,
}

static KLOG: Mutex<Klog> = Mutex::new(Klog { buf: [0; KLOG_SIZE], written: 0, read_at: 0, cleared_at: 0, line_start: true });
static CONSOLE_LEVEL: AtomicU32 = AtomicU32::new(7);

impl Klog {
    fn push(&mut self, b: u8) {
        self.buf[(self.written % KLOG_SIZE as u64) as usize] = b;
        self.written += 1;
    }
    /// The oldest byte still held.
    fn oldest(&self) -> u64 {
        self.written.saturating_sub(KLOG_SIZE as u64)
    }
    fn copy(&self, from: u64, to: u64) -> Vec<u8> {
        (from.max(self.oldest())..to).map(|i| self.buf[(i % KLOG_SIZE as u64) as usize]).collect()
    }
}

struct KlogWriter<'a>(&'a mut Klog);

impl fmt::Write for KlogWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.0.line_start {
                // <6>[seconds.micros] (KERN_INFO)
                let t = crate::arch::pit::ticks();
                let hz = crate::arch::pit::frequency_hz().max(1);
                let mut prefix = [0u8; 32];
                let n = {
                    let mut w = Cursor { buf: &mut prefix, at: 0 };
                    let _ = fmt::write(&mut w, format_args!("<6>[{:5}.{:06}] ", t / hz, (t % hz) * 1_000_000 / hz));
                    w.at
                };
                for &p in &prefix[..n] {
                    self.0.push(p);
                }
                self.0.line_start = false;
            }
            self.0.push(b);
            if b == b'\n' {
                self.0.line_start = true;
            }
        }
        Ok(())
    }
}

struct Cursor<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.at);
        self.buf[self.at..self.at + n].copy_from_slice(&s.as_bytes()[..n]);
        self.at += n;
        Ok(())
    }
}

/// Records kernel output (called by `kprintln`; never blocks, never allocates).
pub fn klog(args: fmt::Arguments) {
    if let Some(mut k) = KLOG.try_lock() {
        let _ = fmt::write(&mut KlogWriter(&mut k), args);
    }
}

/// `syslog(type, buf, len)`.
fn syslog(kind: u64, buf: u64, len: u64) -> i64 {
    let len = len as i32;
    // Everything but "how big" needs privilege (dmesg_restrict = 1)
    if !(capable(34) || capable(21)) {
        return EPERM;
    }
    match kind {
        0 | 1 => 0,
        2 | 3 | 4 => {
            if buf == 0 || len < 0 {
                return EINVAL;
            }
            if len == 0 {
                return 0;
            }
            let data = if kind == 2 {
                // Wait for unread output, then consume it
                loop {
                    {
                        let mut k = KLOG.lock();
                        let from = k.read_at.max(k.oldest());
                        if from < k.written {
                            let to = (from + len as u64).min(k.written);
                            let d = k.copy(from, to);
                            k.read_at = to;
                            break d;
                        }
                    }
                    if super::proc::signal_pending() {
                        return EINTR;
                    }
                    crate::task::sleep_ticks(5);
                }
            } else {
                let mut k = KLOG.lock();
                let from = k.cleared_at.max(k.oldest()).max(k.written.saturating_sub(len as u64));
                let d = k.copy(from, k.written);
                if kind == 4 {
                    k.cleared_at = k.written;
                }
                d
            };
            if copy_out(buf, &data).is_err() {
                return EFAULT;
            }
            data.len() as i64
        }
        5 => {
            let mut k = KLOG.lock();
            k.cleared_at = k.written;
            0
        }
        6 => {
            CONSOLE_LEVEL.store(1, Ordering::Relaxed);
            0
        }
        7 => {
            CONSOLE_LEVEL.store(7, Ordering::Relaxed);
            0
        }
        8 => {
            if !(1..=8).contains(&len) {
                return EINVAL;
            }
            CONSOLE_LEVEL.store(len.max(2) as u32, Ordering::Relaxed);
            0
        }
        9 => {
            let k = KLOG.lock();
            (k.written - k.read_at.max(k.oldest())) as i64
        }
        10 => KLOG_SIZE as i64,
        _ => EINVAL,
    }
}

// ----------------------------------------------------------------------
// ustat, sysfs
// ----------------------------------------------------------------------

/// File system types, in registration order (`sysfs`, `/proc/filesystems`).
pub const FS_TYPES: &[(&str, bool)] = &[
    ("sysfs", true),
    ("tmpfs", true),
    ("bdev", true),
    ("proc", true),
    ("cgroup", true),
    ("cgroup2", true),
    ("devtmpfs", true),
    ("debugfs", true),
    ("tracefs", true),
    ("securityfs", true),
    ("sockfs", true),
    ("bpf", true),
    ("pipefs", true),
    ("ramfs", true),
    ("devpts", true),
    ("mqueue", true),
    ("pstore", true),
    ("binfmt_misc", true),
    ("configfs", true),
    ("fusectl", true),
    ("zfs", false),
];

/// `/proc/filesystems`.
pub fn filesystems_text() -> String {
    let mut s = String::new();
    for (name, nodev) in FS_TYPES {
        s.push_str(if *nodev { "nodev\t" } else { "\t" });
        s.push_str(name);
        s.push('\n');
    }
    s
}

/// `sysfs(option, arg1, arg2)`.
fn sysfs(option: u64, a1: u64, a2: u64) -> i64 {
    match option {
        1 => {
            let name = match super::vfs::user_cstr(a1) {
                Ok(n) => n,
                Err(e) => return e,
            };
            FS_TYPES.iter().position(|(n, _)| n.as_bytes() == name.as_slice()).map_or(EINVAL, |i| i as i64)
        }
        2 => match FS_TYPES.get(a1 as usize) {
            Some((n, _)) => {
                let mut b = Vec::from(n.as_bytes());
                b.push(0);
                copy_out(a2, &b).map_or(EFAULT, |_| 0)
            }
            None => EINVAL,
        },
        3 => FS_TYPES.len() as i64,
        _ => EINVAL,
    }
}

/// `ustat(dev, ubuf)`: free blocks and inodes of the pool (device 8:1).
fn ustat(dev: u64, ubuf: u64) -> i64 {
    let (major, minor) = (((dev >> 8) & 0xfff) as u32, ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32);
    if (major, minor) != (8, 1) {
        return EINVAL;
    }
    let (_total, free, objs) = match crate::fs::zfs::with_server(|s| Ok(s.statfs())) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&(free.min(i32::MAX as u64) as i32).to_le_bytes());
    b[8..16].copy_from_slice(&(1_000_000u64.saturating_sub(objs.min(1_000_000))).to_le_bytes());
    copy_out(ubuf, &b).map_or(EFAULT, |_| 0)
}

// ----------------------------------------------------------------------
// vhangup
// ----------------------------------------------------------------------

/// `vhangup()`.
fn vhangup() -> i64 {
    if !capable(26) {
        return EPERM;
    }
    let pid = super::proc::current_ids().1;
    let Some((sid, _)) = super::proc::session_of(pid) else { return 0 };
    if let Some((leader, fg)) = super::pty::hangup(sid) {
        for (target, group) in [(leader, false), (fg, true)] {
            if target == 0 {
                continue;
            }
            if group {
                super::proc::post_group(target, 1);
                super::proc::post_group(target, 18);
            } else {
                super::proc::post_process(target, 1);
                super::proc::post_process(target, 18);
            }
        }
    }
    0
}

// ----------------------------------------------------------------------
// Process accounting
// ----------------------------------------------------------------------

/// The accounting file (inode) while accounting is on.
static ACCT_FILE: Mutex<Option<u64>> = Mutex::new(None);
static ACCT_ON: AtomicBool = AtomicBool::new(false);
/// What the scheduler noted about each process's last thread: (uid, gid, command).
static ACCT_TASKS: Mutex<BTreeMap<u64, (u32, u32, [u8; 16])>> = Mutex::new(BTreeMap::new());
/// Processes that exec'd since accounting began (the others get `AFORK`).
static EXECED: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
/// Records waiting to be written.
static PENDING: Mutex<VecDeque<[u8; 64]>> = Mutex::new(VecDeque::new());

/// Whether accounting is on (the hooks' fast path).
#[inline]
pub fn acct_on() -> bool {
    ACCT_ON.load(Ordering::Relaxed)
}

/// The scheduler retires a thread of `tgid` (run as `uid`/`gid`, executing `exe`).
pub fn note_task(tgid: u64, uid: u32, gid: u32, exe: &str) {
    if !acct_on() {
        return;
    }
    let mut comm = [0u8; 16];
    let name = exe.rsplit('/').next().unwrap_or("").as_bytes();
    let n = name.len().min(15);
    comm[..n].copy_from_slice(&name[..n]);
    if let Some(mut t) = ACCT_TASKS.try_lock() {
        t.insert(tgid, (uid, gid, comm));
    }
}

/// Process `pid` exec'd.
pub fn note_exec(pid: u64) {
    if acct_on() {
        EXECED.lock().insert(pid);
    }
}

/// Linux's `comp_t`: 13-bit mantissa, 3-bit base-8 exponent.
fn comp_t(mut v: u64) -> u16 {
    let mut exp = 0u16;
    let mut rnd = 0;
    while v > 0x1fff {
        rnd = v & 4;
        v >>= 3;
        exp += 1;
    }
    if rnd != 0 {
        v += 1;
        if v > 0x1fff {
            v >>= 3;
            exp += 1;
        }
    }
    (exp << 13) | v as u16
}

/// Linux's `comp2_t` (24 bits): 20-bit mantissa, binary exponent.
fn comp2_t(mut v: u64) -> u32 {
    const MANT: u32 = 20;
    const MAXFRACT: u64 = (1 << MANT) - 1;
    const MAXEXP: u32 = 31;
    let mut exp = (v > (MAXFRACT >> 1)) as u32;
    let mut rnd = 0;
    while v > MAXFRACT {
        rnd = v & 1;
        v >>= 1;
        exp += 1;
    }
    if rnd != 0 {
        v += 1;
        if v > MAXFRACT {
            v >>= 1;
            exp += 1;
        }
    }
    if exp > MAXEXP {
        return (1 << (MANT + 5 - 1)) - 1;
    }
    (v & (MAXFRACT >> 1)) as u32 | (exp << (MANT - 1))
}

/// Process `pid` (parent `ppid`, started at `start` ticks of 1/100 s since boot) ended
/// with wait status `status` after `cpu_ticks` of CPU time and `faults` page faults: its
/// record is queued, in the version-2 `struct acct` Ubuntu's kernels write.
pub fn on_exit(pid: u64, ppid: u64, start: u64, status: i32, cpu_ticks: u64, faults: u64) {
    if !acct_on() {
        return;
    }
    let _ = ppid;
    let (uid, gid, comm) = ACCT_TASKS.lock().remove(&pid).unwrap_or((0, 0, [0; 16]));
    let execed = EXECED.lock().remove(&pid);
    let now = crate::arch::pit::ticks() * 100 / crate::arch::pit::frequency_hz().max(1);
    let elapsed = now.saturating_sub(start);
    let (epoch, _) = crate::arch::rtc::now();
    let btime = epoch.saturating_sub(elapsed / 100);
    let mut r = [0u8; 64];
    let mut flag = 0u8;
    if !execed {
        flag |= 1; // AFORK
    }
    if uid == 0 {
        flag |= 2; // ASU
    }
    if status & 0x80 != 0 {
        flag |= 8; // ACORE
    }
    if status & 0x7f != 0 {
        flag |= 16; // AXSIG
    }
    let id16 = |v: u32| if v > 0xffff { 65534u16 } else { v as u16 };
    r[0] = flag;
    r[1] = 2; // ACCT_VERSION
    r[2..4].copy_from_slice(&id16(uid).to_le_bytes());
    r[4..6].copy_from_slice(&id16(gid).to_le_bytes());
    r[8..12].copy_from_slice(&(btime as u32).to_le_bytes());
    r[12..14].copy_from_slice(&comp_t(cpu_ticks).to_le_bytes()); // ac_utime
    r[16..18].copy_from_slice(&comp_t(elapsed).to_le_bytes()); // ac_etime
    r[24..26].copy_from_slice(&comp_t(faults).to_le_bytes()); // ac_minflt
    r[30..32].copy_from_slice(&100u16.to_le_bytes()); // ac_ahz
    r[32..36].copy_from_slice(&(status as u32).to_le_bytes());
    r[36..52].copy_from_slice(&comm);
    let e2 = comp2_t(elapsed);
    r[53] = (e2 >> 16) as u8;
    r[54..56].copy_from_slice(&(e2 as u16).to_le_bytes());
    r[56..60].copy_from_slice(&uid.to_le_bytes());
    r[60..64].copy_from_slice(&gid.to_le_bytes());
    PENDING.lock().push_back(r);
}

/// Writes queued records (at system call entry, where the file server may be called).
pub fn flush() {
    if !acct_on() || PENDING.lock().is_empty() {
        return;
    }
    let Some(ino) = *ACCT_FILE.lock() else { return };
    let records: Vec<[u8; 64]> = PENDING.lock().drain(..).collect();
    let mut data = Vec::with_capacity(records.len() * 64);
    for r in &records {
        data.extend_from_slice(r);
    }
    if let Ok(attr) = crate::fs::ZfsClient::getattr(ino) {
        let _ = crate::fs::ZfsClient::write_at(ino, attr.size, &data);
    }
}

/// `acct(filename)`: accounting to `filename`, or off with NULL.
fn acct(path: u64) -> i64 {
    if !capable(20) {
        return EPERM;
    }
    if path == 0 {
        ACCT_ON.store(false, Ordering::Relaxed);
        *ACCT_FILE.lock() = None;
        return 0;
    }
    let (ino, is_dir) = match super::vfs::lookup_path(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let attr = match crate::fs::ZfsClient::getattr(ino) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if is_dir || attr.mode & 0o170000 != 0o100000 {
        return EACCES;
    }
    *ACCT_FILE.lock() = Some(ino);
    ACCT_ON.store(true, Ordering::Relaxed);
    super::perf::force_active();
    0
}

// ----------------------------------------------------------------------
// Swap areas
// ----------------------------------------------------------------------

struct Swap {
    ino: u64,
    path: String,
    kind: &'static str,
    kib: u64,
    prio: i32,
}

static SWAPS: Mutex<Vec<Swap>> = Mutex::new(Vec::new());
static NEXT_PRIO: Mutex<i32> = Mutex::new(-2);

/// `(total KiB, free KiB)` of the active swap areas.
pub fn swap_kib() -> (u64, u64) {
    let t: u64 = SWAPS.lock().iter().map(|s| s.kib).sum();
    (t, t)
}

/// `/proc/swaps`.
pub fn swaps_text() -> String {
    let mut s = String::from("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n");
    for w in SWAPS.lock().iter() {
        s.push_str(&alloc::format!("{:<40}{:<16}{:<16}{:<16}{}\n", w.path, w.kind, w.kib, 0, w.prio));
    }
    s
}

/// `swapon(path, flags)`.
fn swapon(path: u64, flags: u64) -> i64 {
    const SWAP_FLAG_PREFER: u64 = 0x8000;
    const SWAP_FLAGS_VALID: u64 = 0x7fff | 0x8000 | 0x10000 | 0x20000 | 0x40000;
    if flags & !SWAP_FLAGS_VALID != 0 {
        return EINVAL;
    }
    if !capable(21) {
        return EPERM;
    }
    let p = match super::vfs::user_path(path) {
        Ok(p) => String::from_utf8_lossy(&p).into_owned(),
        Err(e) => return e,
    };
    let (ino, _) = match super::vfs::lookup_path(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let attr = match crate::fs::ZfsClient::getattr(ino) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let kind = match attr.mode & 0o170000 {
        0o100000 => "file",
        0o060000 => "partition",
        _ => return EINVAL,
    };
    if SWAPS.lock().iter().any(|s| s.ino == ino) {
        return EBUSY;
    }
    // The swap header: "SWAPSPACE2" at the end of the first page, the last page at 1028
    let mut page = [0u8; 4096];
    match crate::fs::ZfsClient::read_at(ino, 0, &mut page) {
        Ok(4096) => {}
        Ok(_) => return EINVAL,
        Err(e) => return e,
    }
    if &page[4086..4096] != b"SWAPSPACE2" {
        return EINVAL;
    }
    let last = u32::from_le_bytes(page[1028..1032].try_into().unwrap()) as u64;
    if last == 0 || (kind == "file" && attr.size < (last + 1) * 4096) {
        return EINVAL;
    }
    let prio = if flags & SWAP_FLAG_PREFER != 0 {
        (flags & 0x7fff) as i32
    } else {
        let mut n = NEXT_PRIO.lock();
        let p = *n;
        *n -= 1;
        p
    };
    SWAPS.lock().push(Swap { ino, path: p, kind, kib: last * 4, prio });
    0
}

/// `swapoff(path)`.
fn swapoff(path: u64) -> i64 {
    if !capable(21) {
        return EPERM;
    }
    let (ino, _) = match super::vfs::lookup_path(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut s = SWAPS.lock();
    let before = s.len();
    s.retain(|w| w.ino != ino);
    if s.len() == before { EINVAL } else { 0 }
}

// ----------------------------------------------------------------------
// Quotas
// ----------------------------------------------------------------------

/// `quotactl(cmd, special, id, addr)`.
fn quotactl(cmd: u64, special: u64, _id: u64, _addr: u64) -> i64 {
    const Q_SYNC: u64 = 0x80_0001;
    let sub = cmd >> 8;
    let kind = cmd & 0xff;
    if kind > 2 {
        return EINVAL;
    }
    // Q_SYNC with no device: every file system (none keep quotas)
    if sub == Q_SYNC && special == 0 {
        return 0;
    }
    let (ino, _) = match super::vfs::lookup_path(special, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let attr = match crate::fs::ZfsClient::getattr(ino) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if attr.mode & 0o170000 != 0o060000 {
        return ENOTBLK;
    }
    ENOSYS // the file system keeps no quotas
}

/// `quotactl_fd(fd, cmd, id, addr)`.
fn quotactl_fd(fd: u64, cmd: u64) -> i64 {
    if cmd & 0xff > 2 {
        return EINVAL;
    }
    let exists = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).is_some());
    if !exists {
        return -9; // EBADF
    }
    ENOSYS
}

/// System calls 103, 136, 139, 153, 163, 167, 168, 179, 443.
pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
    let _ = ENOENT;
    match num {
        103 => syslog(a[0], a[1], a[2]),
        136 => ustat(a[0], a[1]),
        139 => sysfs(a[0], a[1], a[2]),
        153 => vhangup(),
        163 => acct(a[0]),
        167 => swapon(a[0], a[1]),
        168 => swapoff(a[0]),
        179 => quotactl(a[0], a[1], a[2], a[3]),
        _ => quotactl_fd(a[0], a[1]),
    }
}

// ----------------------------------------------------------------------
// /dev/kmsg
// ----------------------------------------------------------------------

/// An open `/dev/kmsg`: one log record per read (`level,sequence,microseconds,-;text`).
pub struct Kmsg {
    /// Where the next record starts (bytes ever written to the log).
    pos: Mutex<u64>,
    /// Positioned at a line start yet.
    started: AtomicBool,
    nonblock: AtomicBool,
}

/// Opens `/dev/kmsg` (reading needs `CAP_SYSLOG` or `CAP_SYS_ADMIN`: `dmesg_restrict`).
pub fn kmsg_open(flags: u32) -> Result<alloc::sync::Arc<dyn super::chardev::CharDevice>, i64> {
    if flags & 3 != 1 && !(capable(34) || capable(21)) {
        return Err(EPERM);
    }
    Ok(alloc::sync::Arc::new(Kmsg { pos: Mutex::new(0), started: AtomicBool::new(false), nonblock: AtomicBool::new(flags & 0o4000 != 0) }))
}

impl Kmsg {
    /// The next complete line at or after `pos`: `(start, end after '\n', overwritten)`.
    fn next_line(&self, k: &Klog) -> Option<(u64, u64, bool)> {
        let mut pos = *self.pos.lock();
        let mut lost = false;
        if pos < k.oldest() || !self.started.load(Ordering::Relaxed) {
            // Start at the oldest whole line (losing some is reported once: EPIPE)
            lost = self.started.load(Ordering::Relaxed);
            pos = if k.oldest() == 0 { 0 } else { (k.oldest()..k.written).find(|&i| k.buf[((i - 1) % KLOG_SIZE as u64) as usize] == b'\n').unwrap_or(k.written) };
        }
        let end = (pos..k.written).find(|&i| k.buf[(i % KLOG_SIZE as u64) as usize] == b'\n')?;
        Some((pos, end + 1, lost))
    }
}

impl super::chardev::CharDevice for Kmsg {
    fn read(&self, buf: &mut [u8]) -> i64 {
        loop {
            {
                let k = KLOG.lock();
                if let Some((start, end, lost)) = self.next_line(&k) {
                    self.started.store(true, Ordering::Relaxed);
                    *self.pos.lock() = if lost { start } else { end };
                    if lost {
                        return -32; // EPIPE: records were overwritten
                    }
                    let line = k.copy(start, end - 1);
                    drop(k);
                    // "<6>[ secs.micros] text" -> "6,seq,usecs,-;text\n"
                    let text = String::from_utf8_lossy(&line).into_owned();
                    let (usec, body) = match text.strip_prefix("<6>[").and_then(|r| r.split_once("] ")) {
                        Some((t, b)) => {
                            let (s, u) = t.trim().split_once('.').unwrap_or((t.trim(), "0"));
                            (s.parse::<u64>().unwrap_or(0) * 1_000_000 + u.parse::<u64>().unwrap_or(0), String::from(b))
                        }
                        None => (0, text.clone()),
                    };
                    let rec = alloc::format!("6,{},{},-;{}\n", start, usec, body);
                    if buf.len() < rec.len() {
                        return EINVAL;
                    }
                    buf[..rec.len()].copy_from_slice(rec.as_bytes());
                    return rec.len() as i64;
                }
            }
            if self.nonblock.load(Ordering::Relaxed) {
                return -11; // EAGAIN
            }
            if super::proc::signal_pending() {
                return EINTR;
            }
            crate::task::sleep_ticks(5);
        }
    }
    fn write(&self, data: &[u8]) -> i64 {
        // "<priority>text": the text joins the kernel log
        let text = String::from_utf8_lossy(data);
        let body = match text.strip_prefix('<').and_then(|r| r.split_once('>')) {
            Some((_, b)) => b,
            None => &text,
        };
        klog(format_args!("{}\n", body.trim_end_matches('\n')));
        data.len() as i64
    }
    fn seek(&self, offset: i64, whence: u32) -> Option<i64> {
        if offset != 0 {
            return Some(EINVAL);
        }
        let k = KLOG.lock();
        let mut pos = self.pos.lock();
        match whence {
            0 => {
                *pos = 0;
                self.started.store(false, Ordering::Relaxed);
            }
            2 => {
                *pos = k.written;
                self.started.store(true, Ordering::Relaxed);
            }
            3 => {
                *pos = k.cleared_at.max(k.oldest());
                self.started.store(k.cleared_at >= k.oldest(), Ordering::Relaxed);
            }
            _ => return Some(EINVAL),
        }
        Some(0)
    }
    fn poll_events(&self) -> u32 {
        let k = KLOG.lock();
        if self.next_line(&k).is_some() { 0x41 } else { 0x4 }
    }
    fn add_wait_queues(&self, _waits: &mut crate::task::wait::WaitSet) {}
    fn rdev(&self) -> u64 {
        (1 << 8) | 11
    }
    fn path(&self) -> String {
        String::from("/dev/kmsg")
    }
    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }
    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}
