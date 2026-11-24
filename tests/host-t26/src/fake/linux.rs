//! *stub* The Linux layer's other modules, as far as the file layer calls them. Each keeps
//! what a test needs to steer it in thread-locals (refusals, answers, recorded calls).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::cell::{Cell, RefCell};

use crate::arch::syscall::SyscallFrame;

pub fn reset() {
    proc::reset();
    pty::reset();
    tty::reset();
    landlock::reset();
    bpf::reset();
    abac::reset();
    extra::reset();
    limits::reset();
    mm::reset();
    ptrace::reset();
    chardev::reset();
    NESTED.with_borrow_mut(|n| *n = None);
    NESTED_CALLS.with_borrow_mut(|n| n.clear());
}

// ------------------------------------------------------------------ nested

thread_local! {
    static NESTED: RefCell<Option<Box<dyn FnMut(u64, [u64; 6]) -> i64>>> = const { RefCell::new(None) };
    static NESTED_CALLS: RefCell<Vec<(u64, [u64; 6])>> = const { RefCell::new(Vec::new()) };
}

/// Answers the nested system calls (`super::nested`) with `f(number, arguments)`.
pub fn set_nested(f: impl FnMut(u64, [u64; 6]) -> i64 + 'static) {
    NESTED.with_borrow_mut(|n| *n = Some(Box::new(f)));
}

/// The nested calls made so far.
pub fn nested_calls() -> Vec<(u64, [u64; 6])> {
    NESTED_CALLS.with_borrow(|n| n.clone())
}

/// *stub* `compat::linux::nested_routed` (wave9 G6b-4): routing is the kernel's
/// (`lx::uring`, tested in host-t30); here the same handler as [`nested`] answers.
pub fn nested_routed(frame: &SyscallFrame, num: u64, args: [u64; 6]) -> i64 {
    nested(frame, num, args)
}

/// *stub* `compat::linux::nested`: one of the caller's own system calls, run by the kernel.
pub fn nested(_frame: &SyscallFrame, num: u64, args: [u64; 6]) -> i64 {
    NESTED_CALLS.with_borrow_mut(|n| n.push((num, args)));
    let f = NESTED.with_borrow_mut(|n| n.take());
    match f {
        Some(mut f) => {
            let r = f(num, args);
            NESTED.with_borrow_mut(|n| {
                if n.is_none() {
                    *n = Some(f);
                }
            });
            r
        }
        None => -38,
    }
}

// ----------------------------------------------------------------- chardev

pub mod chardev {
    //! *mirror* of the kernel's `CharDevice` trait (the methods the file layer calls or
    //! implements), and a configurable test device.
    use alloc::collections::VecDeque;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use spin::Mutex;
    use std::cell::RefCell;

    use crate::task::wait::WaitSet;

    pub fn reset() {
        OPENABLE.with_borrow_mut(|o| o.clear());
    }

    pub const fn makedev(major: u64, minor: u64) -> u64 {
        ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
    }

    pub trait CharDevice: Send + Sync {
        fn read(&self, buf: &mut [u8]) -> i64;
        fn write(&self, _data: &[u8]) -> i64 {
            -22
        }
        fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
            -25
        }
        fn poll_events(&self) -> u32;
        fn add_wait_queues(&self, waits: &mut WaitSet);
        fn rdev(&self) -> u64;
        fn path(&self) -> String;
        fn set_nonblock(&self, on: bool);
        fn nonblock(&self) -> bool;
        fn stat(&self) -> crate::compat::linux::types::LinuxStat {
            crate::compat::linux::types::LinuxStat::default()
        }
        fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
            None
        }
        fn read_unlocked(&self, _buf: &mut [u8]) -> Option<i64> {
            None
        }
        fn fsync(&self) -> Option<i64> {
            None
        }
        fn as_mount_obj(&self) -> Option<&crate::compat::linux::mount::MountObj> {
            None
        }
        fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
            None
        }
        // wave11 GP: `/proc` snapshots (none on the host)
        fn getdents64(&self, _count: usize) -> Option<Result<Vec<u8>, i64>> {
            None
        }
    }

    thread_local! {
        /// Devices `open` knows besides `/dev/fuse`: device number -> path.
        static OPENABLE: RefCell<Vec<(u64, String)>> = const { RefCell::new(Vec::new()) };
    }

    /// Makes `open` of character device `rdev` give a [`TestDev`] named `path`.
    pub fn add_openable(rdev: u64, path: &str) {
        OPENABLE.with_borrow_mut(|o| o.push((rdev, String::from(path))));
    }

    pub fn open(rdev: u64, flags: u32) -> Option<Result<Arc<dyn CharDevice>, i64>> {
        let path = OPENABLE.with_borrow(|o| o.iter().find(|(r, _)| *r == rdev).map(|(_, p)| p.clone()))?;
        let d: Arc<dyn CharDevice> = Arc::new(TestDev::new(&path, rdev));
        Some(Ok(d))
    }

    /// A device whose behaviour the test sets.
    pub struct TestDev {
        pub name: String,
        pub rdev: u64,
        /// Bytes reads return.
        pub input: Mutex<VecDeque<u8>>,
        /// Bytes written to it.
        pub output: Mutex<Vec<u8>>,
        pub nb: AtomicBool,
        pub server: Option<crate::lx::obj::ServerObject>,
        pub poll: u32,
        pub fsync_result: Option<i64>,
        pub seek_result: Option<i64>,
        pub ioctls: Mutex<Vec<(u64, u64)>>,
    }

    impl TestDev {
        pub fn new(name: &str, rdev: u64) -> Self {
            TestDev {
                name: String::from(name),
                rdev,
                input: Mutex::new(VecDeque::new()),
                output: Mutex::new(Vec::new()),
                nb: AtomicBool::new(false),
                server: None,
                poll: 0x5,
                fsync_result: None,
                seek_result: None,
                ioctls: Mutex::new(Vec::new()),
            }
        }
        /// A linux-server object of `kind` (in slot `slot`).
        pub fn server(kind: u32, slot: Option<u64>) -> Self {
            let mut d = TestDev::new("server-object", 0);
            d.server = Some(crate::lx::obj::ServerObject { kind, tag: 77, slot });
            d
        }
    }

    impl CharDevice for TestDev {
        fn read(&self, buf: &mut [u8]) -> i64 {
            let mut i = self.input.lock();
            let n = buf.len().min(i.len());
            for b in buf.iter_mut().take(n) {
                *b = i.pop_front().unwrap();
            }
            n as i64
        }
        fn write(&self, data: &[u8]) -> i64 {
            self.output.lock().extend_from_slice(data);
            data.len() as i64
        }
        fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
            self.ioctls.lock().push((cmd, arg));
            0
        }
        fn poll_events(&self) -> u32 {
            self.poll
        }
        fn add_wait_queues(&self, _waits: &mut WaitSet) {}
        fn rdev(&self) -> u64 {
            self.rdev
        }
        fn path(&self) -> String {
            self.name.clone()
        }
        fn set_nonblock(&self, on: bool) {
            self.nb.store(on, Ordering::Relaxed);
        }
        fn nonblock(&self) -> bool {
            self.nb.load(Ordering::Relaxed)
        }
        fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
            self.seek_result
        }
        fn fsync(&self) -> Option<i64> {
            self.fsync_result
        }
        fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
            self.server.as_ref()
        }
    }
}

// -------------------------------------------------------------------- proc

pub mod proc {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::cell::{Cell, RefCell};

    pub const ERESTARTSYS: i64 = -512;
    pub const SIGPIPE: u32 = 13;

    /// The parts of the kernel's `Process` the file layer reads.
    #[derive(Default)]
    pub struct Process {
        pub pid: u64,
        pub ppid: u64,
        pub pgid: u64,
        pub sid: u64,
        pub zombie: bool,
        pub start_time: u64,
        pub cgroup: Option<Arc<str>>,
        pub ns: super::ns::Ns,
        /// The process sharing its root and working directory (`CLONE_FS`).
        pub fs_peer: u64,
        pub groups: Vec<u32>,
        pub threads: Vec<u64>,
        pub oom_adj: i64,
    }

    impl Process {
        pub fn threads_alive(&self) -> usize {
            self.threads.len()
        }
    }

    pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

    thread_local! {
        pub static SIGNAL: Cell<bool> = const { Cell::new(false) };
        pub static SIGKILL: Cell<bool> = const { Cell::new(false) };
        /// Signals posted: (pid, tid, signal).
        pub static POSTED: RefCell<Vec<(u64, u64, u32)>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset() {
        PROCS.lock().clear();
        SIGNAL.set(false);
        SIGKILL.set(false);
        POSTED.with_borrow_mut(|p| p.clear());
    }

    /// Adds process `pid` (child of `ppid`) to the table.
    pub fn add(pid: u64, ppid: u64) {
        PROCS.lock().insert(pid, Process { pid, ppid, pgid: pid, sid: pid, start_time: 5, threads: alloc::vec![pid], ..Process::default() });
    }

    /// Runs `f` on process `pid`'s entry.
    pub fn with<R>(pid: u64, f: impl FnOnce(&mut Process) -> R) -> R {
        f(PROCS.lock().get_mut(&pid).expect("no such process"))
    }

    pub fn current_ids() -> (u64, u64) {
        crate::task::with_current_task_mut(|t| (t.id.0, t.tgid)).unwrap_or((0, 0))
    }
    pub fn signal_pending() -> bool {
        SIGNAL.get()
    }
    pub fn sigkill_pending() -> bool {
        SIGKILL.get()
    }
    pub fn process_exists(pid: u64) -> bool {
        PROCS.lock().get(&pid).is_some_and(|p| !p.zombie)
    }
    pub fn has_exited(pid: u64) -> bool {
        PROCS.lock().get(&pid).map_or(true, |p| p.zombie)
    }
    pub fn in_supplementary_groups(gid: u32) -> bool {
        let pid = current_ids().1;
        PROCS.lock().get(&pid).is_some_and(|p| p.groups.contains(&gid))
    }
    pub fn post_thread(pid: u64, tid: u64, sig: u32) -> bool {
        POSTED.with_borrow_mut(|p| p.push((pid, tid, sig)));
        true
    }
    /// (user, system, children's user, children's system) in ticks.
    pub fn cpu_times(_pid: u64) -> (u64, u64, u64, u64) {
        (100, 200, 300, 400)
    }
    /// Timer ticks (1000 Hz) to clock ticks (100 Hz).
    pub fn to_clock_ticks(ticks: u64) -> u64 {
        ticks / 10
    }
    pub fn thread_ids_of(pid: u64) -> Vec<u64> {
        PROCS.lock().get(&pid).map(|p| p.threads.clone()).unwrap_or_default()
    }
    pub fn visible_pids() -> Vec<u64> {
        PROCS.lock().values().filter(|p| !p.zombie).map(|p| p.pid).collect()
    }
    pub fn oom_file_text(pid: u64, file: &str) -> Option<alloc::string::String> {
        let adj = PROCS.lock().get(&pid)?.oom_adj;
        Some(match file {
            "oom_score_adj" => alloc::format!("{}\n", adj),
            _ => alloc::format!("{}\n", 666 + adj),
        })
    }
    pub fn write_oom_score_adj(pid: u64, buf: &[u8]) -> i64 {
        let Some(v) = core::str::from_utf8(buf).ok().and_then(|s| s.trim().parse::<i64>().ok()) else { return -22 };
        match PROCS.lock().get_mut(&pid) {
            Some(p) => {
                p.oom_adj = v;
                buf.len() as i64
            }
            None => -3,
        }
    }
}

// ---------------------------------------------------------------------- ns

pub mod ns {
    use alloc::string::String;
    use alloc::vec::Vec;

    /// A process's namespaces: the mount namespace id and the PID namespace chain.
    #[derive(Clone, Default)]
    pub struct Ns {
        pub mnt: u64,
        pub pid_inits: Vec<u64>,
    }
    pub fn pid_from_caller(id: u64) -> u64 {
        id
    }
    pub fn pid_to_caller(id: u64) -> u64 {
        id
    }
    pub fn is_ns_file(rest: &str) -> bool {
        let Some((who, file)) = rest.split_once('/') else { return false };
        (who == "self" || who.bytes().all(|b| b.is_ascii_digit())) && (matches!(file, "uid_map" | "gid_map" | "setgroups") || file.starts_with("ns/"))
    }
    pub fn max_user_namespaces_text() -> String {
        String::from("15000\n")
    }
    pub fn set_max_user_namespaces(buf: &[u8]) -> i64 {
        buf.len() as i64
    }
    pub fn ns_link(rest: &str) -> Option<String> {
        let kind = rest.rsplit('/').next()?;
        Some(alloc::format!("{}:[4026531840]", kind))
    }
    // wave11 GP
    pub fn ns_ino_of(_pid: u64, _kind: &str) -> Option<u64> {
        Some(4026531840)
    }
    pub fn read_file(_rest: &str) -> String {
        String::from("         0          0 4294967295\n")
    }
    pub fn write_file(_rest: &str, buf: &[u8]) -> i64 {
        buf.len() as i64
    }
}

// --------------------------------------------------------------------- pty

pub mod pty {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::cell::RefCell;

    use crate::compat::linux::types::LinuxStat;

    pub const PTS_DEV: u64 = 0x18;

    thread_local! {
        /// Slave indices that exist.
        pub static SLAVES: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        /// The caller's controlling terminal.
        pub static CONTROLLING: RefCell<Option<Arc<PtyFile>>> = const { RefCell::new(None) };
        /// `setattr_path` calls: (path, mode).
        pub static SETATTRS: RefCell<Vec<(String, Option<u32>)>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset() {
        SLAVES.with_borrow_mut(|s| s.clear());
        CONTROLLING.with_borrow_mut(|c| *c = None);
        SETATTRS.with_borrow_mut(|s| s.clear());
    }

    pub fn makedev(major: u64, minor: u64) -> u64 {
        ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
    }

    /// *stub* One end of a pseudo-terminal.
    pub struct PtyFile {
        pub name: String,
        pub nb: AtomicBool,
        pub written: spin::Mutex<Vec<u8>>,
    }

    impl PtyFile {
        pub fn named(name: &str, nonblock: bool) -> Arc<PtyFile> {
            Arc::new(PtyFile { name: String::from(name), nb: AtomicBool::new(nonblock), written: spin::Mutex::new(Vec::new()) })
        }
        pub fn stat(&self) -> LinuxStat {
            let mut st = LinuxStat::default();
            st.st_dev = PTS_DEV;
            st.st_mode = 0o020620;
            st
        }
        pub fn path(&self) -> String {
            self.name.clone()
        }
        pub fn read(&self, buf: &mut [u8]) -> i64 {
            if buf.is_empty() {
                return 0;
            }
            buf[0] = b'p';
            1
        }
        pub fn write(&self, data: &[u8]) -> i64 {
            self.written.lock().extend_from_slice(data);
            data.len() as i64
        }
        pub fn set_nonblock(&self, on: bool) {
            self.nb.store(on, Ordering::Relaxed);
        }
        pub fn get_nonblock(&self) -> bool {
            self.nb.load(Ordering::Relaxed)
        }
        /// TIOCGPTPEER (0x5441) opens the peer through `open_peer`; others answer 0.
        pub fn ioctl(&self, request: u64, arg: u64, open_peer: &dyn Fn(Arc<PtyFile>, u32) -> i64) -> i64 {
            if request == 0x5441 {
                return open_peer(PtyFile::named("/dev/pts/0", false), arg as u32);
            }
            0
        }
    }

    pub fn open_master(_uid: u32, nonblock: bool) -> Arc<PtyFile> {
        PtyFile::named("/dev/ptmx", nonblock)
    }
    pub fn open_slave(index: u32, nonblock: bool, _noctty: bool) -> Result<Arc<PtyFile>, i64> {
        if SLAVES.with_borrow(|s| s.contains(&index)) {
            Ok(PtyFile::named(&alloc::format!("/dev/pts/{}", index), nonblock))
        } else {
            Err(-5)
        }
    }
    pub fn open_controlling(_nonblock: bool) -> Option<Arc<PtyFile>> {
        CONTROLLING.with_borrow(|c| c.clone())
    }
    pub fn slave_index(abs: &str) -> Option<u32> {
        abs.strip_prefix("/dev/pts/")?.parse().ok()
    }
    pub fn stat_path(abs: &str) -> Option<Result<LinuxStat, i64>> {
        let i = slave_index(abs)?;
        Some(if SLAVES.with_borrow(|s| s.contains(&i)) {
            let mut st = LinuxStat::default();
            st.st_dev = PTS_DEV;
            st.st_mode = 0o020620;
            st.st_rdev = makedev(136, i as u64);
            Ok(st)
        } else {
            Err(-2)
        })
    }
    pub fn setattr_path(abs: &str, euid: u32, mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>) -> Option<i64> {
        slave_index(abs)?;
        SETATTRS.with_borrow_mut(|s| s.push((String::from(abs), mode)));
        Some(if euid == 0 { 0 } else { -1 })
    }
}

// --------------------------------------------------------------------- tty

pub mod tty {
    use alloc::vec::Vec;
    use std::cell::{Cell, RefCell};

    pub const NOT_A_TTY: i64 = -25;

    thread_local! {
        static NB: Cell<bool> = const { Cell::new(false) };
        pub static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        pub static IOCTLS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset() {
        NB.set(false);
        OUT.with_borrow_mut(|o| o.clear());
        IOCTLS.with_borrow_mut(|o| o.clear());
    }
    pub fn nonblock() -> bool {
        NB.get()
    }
    pub fn set_nonblock(on: bool) {
        NB.set(on);
    }
    pub fn write(data: &[u8]) -> usize {
        OUT.with_borrow_mut(|o| o.extend_from_slice(data));
        data.len()
    }
    /// The console has no input on the host: `EAGAIN` (non-blocking) or one newline.
    pub fn read(buf: &mut [u8], nonblock: bool) -> i64 {
        if nonblock {
            return -11;
        }
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'\n';
        1
    }
    pub fn ioctl(request: u64, arg: u64) -> i64 {
        IOCTLS.with_borrow_mut(|o| o.push((request, arg)));
        0
    }
}

// ----------------------------------------------------------------- sockets

pub mod inet {
    use alloc::string::String;
    use alloc::sync::Arc;
    use spin::Mutex;

    /// *stub* An internet socket.
    #[derive(Default)]
    pub struct InetSocket {
        pub nonblock: bool,
        pub pending: usize,
    }
    pub fn read(_s: &Arc<Mutex<InetSocket>>, buf: &mut [u8]) -> i64 {
        buf.len().min(3) as i64
    }
    pub fn write(_s: &Arc<Mutex<InetSocket>>, data: &[u8]) -> i64 {
        data.len() as i64
    }
    pub fn pending_bytes(s: &Arc<Mutex<InetSocket>>) -> usize {
        s.lock().pending
    }
    pub fn stamp_ioctl(_s: &Arc<Mutex<InetSocket>>, cmd: u64, _arg: u64) -> i64 {
        if cmd == 0x8906 { -2 } else { 0 }
    }
    pub fn proc_net(file: &str) -> Option<String> {
        (file == "tcp").then(|| String::from("  sl  local_address rem_address\n"))
    }
}

pub mod unix {
    use alloc::string::String;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// *stub* An `AF_UNIX` socket.
    pub struct UnixSocket {
        pub inode: u64,
        pub nb: AtomicBool,
    }
    impl UnixSocket {
        pub fn new(inode: u64) -> Arc<Self> {
            Arc::new(UnixSocket { inode, nb: AtomicBool::new(false) })
        }
        pub fn ino(&self) -> u64 {
            self.inode
        }
        pub fn read(&self, buf: &mut [u8]) -> i64 {
            buf.len().min(2) as i64
        }
        pub fn write(&self, data: &[u8]) -> i64 {
            data.len() as i64
        }
        pub fn set_nonblock(&self, on: bool) {
            self.nb.store(on, Ordering::Relaxed);
        }
        pub fn get_nonblock(&self) -> bool {
            self.nb.load(Ordering::Relaxed)
        }
    }
    pub fn ioctl(_s: &Arc<UnixSocket>, cmd: u64, _arg: u64) -> i64 {
        if cmd == 0x541B { 0 } else { -25 }
    }
    pub fn proc_net_unix() -> String {
        String::from("Num       RefCount Protocol Flags    Type St Inode Path\n")
    }
}

/// *stub* The legacy Hydra-native socket.
pub mod socket {
    #[derive(Default)]
    pub struct UnixSocket;
}

/// *stub*
pub mod epoll {
    #[derive(Default)]
    pub struct EpollInstance;
}

pub mod signalfd {
    use core::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    pub struct SignalFd {
        pub nb: AtomicBool,
    }
    impl SignalFd {
        pub fn read(&self, _buf: &mut [u8]) -> i64 {
            -11
        }
        pub fn set_nonblock(&self, on: bool) {
            self.nb.store(on, Ordering::Relaxed);
        }
        pub fn get_nonblock(&self) -> bool {
            self.nb.load(Ordering::Relaxed)
        }
    }
}

pub mod timerfd {
    use core::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    pub struct TimerFd {
        pub nb: AtomicBool,
    }
    impl TimerFd {
        pub fn read(&self, buf: &mut [u8]) -> i64 {
            if buf.len() < 8 {
                return -22;
            }
            buf[..8].copy_from_slice(&1u64.to_le_bytes());
            8
        }
        pub fn set_nonblock(&self, on: bool) {
            self.nb.store(on, Ordering::Relaxed);
        }
        pub fn get_nonblock(&self) -> bool {
            self.nb.load(Ordering::Relaxed)
        }
    }
}

pub mod eventfd {
    use alloc::sync::Arc;
    use spin::Mutex;

    use crate::task::wait::WaitQueue;

    /// *stub* An eventfd counter.
    pub struct EventFd {
        pub count: u64,
        pub nonblocking: bool,
        pub wq: Arc<WaitQueue>,
    }
    impl EventFd {
        pub fn new(count: u64) -> Arc<Mutex<EventFd>> {
            Arc::new(Mutex::new(EventFd { count, nonblocking: false, wq: WaitQueue::new_shared() }))
        }
    }
    pub fn read(e: &Arc<Mutex<EventFd>>, buf: &mut [u8]) -> i64 {
        if buf.len() < 8 {
            return -22;
        }
        let mut g = e.lock();
        if g.count == 0 {
            return -11;
        }
        buf[..8].copy_from_slice(&g.count.to_le_bytes());
        g.count = 0;
        8
    }
    pub fn write(e: &Arc<Mutex<EventFd>>, data: &[u8]) -> i64 {
        if data.len() < 8 {
            return -22;
        }
        e.lock().count += u64::from_le_bytes(data[..8].try_into().unwrap());
        8
    }
}

pub mod pidfd {
    /// *stub* A process descriptor.
    pub struct PidFd {
        pub pid: u64,
    }
    pub fn pid_of(fd: u64) -> Result<u64, i64> {
        crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
            Some(_) => Err(-22),
            None => Err(-9),
        })
    }
}

pub mod memfd {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use spin::Mutex;

    /// *stub* An anonymous RAM file.
    pub struct MemFd {
        pub name: String,
        pub data: Vec<u8>,
        pub seals: u32,
    }
    impl MemFd {
        pub fn new(name: &str) -> Arc<Mutex<MemFd>> {
            Arc::new(Mutex::new(MemFd { name: String::from(name), data: Vec::new(), seals: 0 }))
        }
        pub fn write_at(&mut self, off: usize, data: &[u8]) -> usize {
            if self.data.len() < off + data.len() {
                self.data.resize(off + data.len(), 0);
            }
            self.data[off..off + data.len()].copy_from_slice(data);
            data.len()
        }
        pub fn size(&self) -> usize {
            self.data.len()
        }
        pub fn truncate(&mut self, n: usize) -> Result<(), i64> {
            if self.seals & 0x4 != 0 {
                return Err(-1); // F_SEAL_GROW
            }
            self.data.resize(n, 0);
            Ok(())
        }
    }
}

// --------------------------------------------------------------- policies

pub mod landlock {
    use std::cell::Cell;

    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    pub const TRUNCATE: u64 = 1 << 14;

    thread_local! {
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
        /// Rights refused everywhere.
        static REFUSE: Cell<u64> = const { Cell::new(0) };
    }

    pub fn reset() {
        ACTIVE.set(false);
        REFUSE.set(0);
    }
    /// Activates a sandbox refusing `rights`.
    pub fn refuse(rights: u64) {
        ACTIVE.set(true);
        REFUSE.set(rights);
    }
    pub fn active() -> bool {
        ACTIVE.get()
    }
    pub fn refused_at(_abs: &str, _ino: u64, _is_dir: bool, _follow: bool, want: u64) -> u64 {
        want & REFUSE.get()
    }
    pub fn check_at(_abs: &str, _ino: u64, _is_dir: bool, _follow: bool, want: u64) -> Result<(), i64> {
        if want & REFUSE.get() != 0 { Err(-13) } else { Ok(()) }
    }
    pub fn check_dir(_dir: u64, want: u64) -> Result<(), i64> {
        if want & REFUSE.get() != 0 { Err(-13) } else { Ok(()) }
    }
    pub fn make_right(ftype: u32) -> u64 {
        match ftype {
            0o040000 => MAKE_DIR,
            0o020000 => MAKE_CHAR,
            0o060000 => MAKE_BLOCK,
            0o010000 => MAKE_FIFO,
            0o140000 => MAKE_SOCK,
            0o120000 => MAKE_SYM,
            _ => MAKE_REG,
        }
    }
    pub fn remove_right(ftype: u32) -> u64 {
        if ftype == 0o040000 { REMOVE_DIR } else { REMOVE_FILE }
    }
    pub fn check_move(_sdir: u64, _ddir: u64, ftype: u32, remove_src: bool, remove_dst: u64) -> Result<(), i64> {
        let want = make_right(ftype) | if remove_src { remove_right(ftype) } else { 0 } | remove_dst;
        if want & REFUSE.get() != 0 { Err(-18) } else { Ok(()) }
    }
}

pub mod bpf {
    use alloc::vec::Vec;
    use std::cell::RefCell;

    pub const DEV_MKNOD: u32 = 1;
    pub const DEV_READ: u32 = 2;
    pub const DEV_WRITE: u32 = 4;
    pub const DEV_BLOCK: u32 = 1;
    pub const DEV_CHAR: u32 = 2;

    thread_local! {
        /// Devices refused: (kind, major, minor).
        static DENY: RefCell<Vec<(u32, u32, u32)>> = const { RefCell::new(Vec::new()) };
        /// Checks made: (kind, major, minor, access).
        pub static CHECKS: RefCell<Vec<(u32, u32, u32, u32)>> = const { RefCell::new(Vec::new()) };
    }
    pub fn reset() {
        DENY.with_borrow_mut(|d| d.clear());
        CHECKS.with_borrow_mut(|d| d.clear());
    }
    pub fn deny(kind: u32, major: u32, minor: u32) {
        DENY.with_borrow_mut(|d| d.push((kind, major, minor)));
    }
    pub fn device_check(kind: u32, major: u32, minor: u32, access: u32) -> Result<(), i64> {
        CHECKS.with_borrow_mut(|c| c.push((kind, major, minor, access)));
        if DENY.with_borrow(|d| d.contains(&(kind, major, minor))) { Err(-1) } else { Ok(()) }
    }
}

pub mod abac {
    use alloc::string::String;
    use alloc::vec::Vec;
    use std::cell::{Cell, RefCell};

    use crate::fs::zfs::fsproto::Attr;

    pub const LABELS: &[u8] = b"security.hydra.labels";

    thread_local! {
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
        static DENY_ACCESS: Cell<bool> = const { Cell::new(false) };
        static DENY_DELETE: Cell<bool> = const { Cell::new(false) };
        pub static NOTED: RefCell<Vec<(u64, String)>> = const { RefCell::new(Vec::new()) };
    }
    pub fn reset() {
        ACTIVE.set(false);
        DENY_ACCESS.set(false);
        DENY_DELETE.set(false);
        NOTED.with_borrow_mut(|n| n.clear());
    }
    /// Activates a policy that refuses access (`access`) and deletion (`delete`).
    pub fn policy(access: bool, delete: bool) {
        ACTIVE.set(true);
        DENY_ACCESS.set(access);
        DENY_DELETE.set(delete);
    }
    pub fn active() -> bool {
        ACTIVE.get()
    }
    pub fn check(_attr: &Attr, _want: u32) -> bool {
        !DENY_ACCESS.get()
    }
    pub fn check_delete(_attr: &Attr) -> bool {
        !DENY_DELETE.get()
    }
    /// A directory's labels (its `LABELS` attribute) pass to what is made in it.
    pub fn inherited_labels(dir: &Attr) -> Option<Vec<u8>> {
        crate::fake::memfs::with(|fs| fs.getxattr(dir.ino, LABELS).ok())
    }
    pub fn labels_changed() {
        crate::fake::count("labels_changed");
    }
    pub fn note_path(ino: u64, path: &str) {
        NOTED.with_borrow_mut(|n| n.push((ino, String::from(path))));
    }
}

// ------------------------------------------------------------ processes

pub mod extra {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use spin::Mutex;
    use std::cell::RefCell;

    use crate::memory::vm::Mm;

    thread_local! {
        /// Processes the caller may not inspect.
        static DENY: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    }
    pub fn reset() {
        DENY.with_borrow_mut(|d| d.clear());
    }
    pub fn deny(pid: u64) {
        DENY.with_borrow_mut(|d| d.push(pid));
    }
    pub fn may_access(pid: u64) -> Result<(), i64> {
        if DENY.with_borrow(|d| d.contains(&pid)) { Err(-1) } else { Ok(()) }
    }
    /// Another process's memory is host memory here.
    pub fn remote_copy(_mm: &Arc<Mutex<Mm>>, addr: u64, _data: Option<&[u8]>, n: u64) -> Option<Vec<u8>> {
        if addr < crate::memory::vm::BAD_BELOW {
            return None;
        }
        Some(crate::fake::read(addr, n as usize))
    }
    /// (policy, nice, priority, reset on fork)
    pub fn sched_of(_tid: u64) -> (u32, i32, u32, bool) {
        (0, 5, 0, false)
    }
}

pub mod limits {
    use std::cell::Cell;
    thread_local! {
        pub static NOFILE: Cell<usize> = const { Cell::new(1024) };
    }
    pub fn reset() {
        NOFILE.set(1024);
    }
    pub fn nofile() -> usize {
        NOFILE.get()
    }
    pub fn limits_text(tgid: u64) -> alloc::string::String {
        alloc::format!("Limit for {}\n", tgid)
    }
    pub fn locked_kib(_tgid: u64) -> u64 {
        12
    }
}

pub mod mm {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use spin::Mutex;
    use std::cell::{Cell, RefCell};

    use crate::memory::vm::Mm;

    thread_local! {
        /// Mappings made: (address, length).
        pub static MAPS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
        pub static UNMAPS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
        /// Makes `sys_mmap` fail with this errno.
        pub static MMAP_FAILS: Cell<i64> = const { Cell::new(0) };
    }
    pub fn reset() {
        MAPS.with_borrow_mut(|m| m.clear());
        UNMAPS.with_borrow_mut(|m| m.clear());
        MMAP_FAILS.set(0);
    }
    pub fn current_mm() -> Option<Arc<Mutex<Mm>>> {
        crate::task::with_current_task_mut(|t| t.mm.clone()).flatten()
    }
    pub fn cache_pages() -> (usize, usize) {
        (10, 4)
    }
    /// Anonymous memory: a zeroed host allocation.
    pub fn sys_mmap(_mm: &Mutex<Mm>, _addr: u64, len: u64, _prot: u64, _flags: u64, _fd: i64, _offset: u64) -> i64 {
        if MMAP_FAILS.get() != 0 {
            return MMAP_FAILS.get();
        }
        let a = crate::fake::buf(len as usize);
        MAPS.with_borrow_mut(|m| m.push((a, len)));
        a as i64
    }
    pub fn sys_munmap(_mm: &Mutex<Mm>, addr: u64, len: u64) -> i64 {
        UNMAPS.with_borrow_mut(|m| m.push((addr, len)));
        0
    }
}

pub mod process {
    pub fn current_auxv() -> alloc::vec::Vec<u8> {
        (1..=16).collect()
    }
}

pub mod ptrace {
    use alloc::sync::Arc;
    use std::cell::Cell;
    thread_local! {
        pub static TRACER: Cell<u64> = const { Cell::new(0) };
    }
    pub fn reset() {
        TRACER.set(0);
    }
    pub fn tracer_of(_tgid: u64) -> u64 {
        TRACER.get()
    }
    pub fn open_proc_mem(pid: u64, _read: bool, _write: bool) -> Result<Arc<dyn super::chardev::CharDevice>, i64> {
        if !super::proc::process_exists(pid) {
            return Err(-3);
        }
        Ok(Arc::new(super::chardev::TestDev::new(&alloc::format!("/proc/{}/mem", pid), 0)))
    }
}

pub mod seccomp {
    pub fn status_of(_pid: u64) -> (bool, u8) {
        (true, 2)
    }
}

pub mod admin {
    use alloc::string::String;
    pub fn filesystems_text() -> String {
        String::from("nodev\tproc\n\tzfs\n")
    }
    pub fn swap_kib() -> (u64, u64) {
        (2048, 1024)
    }
    pub fn swaps_text() -> String {
        String::from("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
    }
}

pub mod keys {
    pub fn proc_keys() -> alloc::string::String {
        alloc::string::String::from("0000001 I--Q--- 1 perm 3f010000 0 0 keyring _ses: 1\n")
    }
}

pub mod snd {
    use alloc::string::String;
    pub fn proc_text(path: &str) -> Option<String> {
        (path == "cards").then(|| String::from(" 0 [Test           ]: HDA\n"))
    }
    pub fn is_proc_file(path: &str) -> bool {
        path.strip_prefix("/proc/asound/").map_or(false, |p| proc_text(p).is_some())
    }
}

pub mod rtnetlink {
    pub fn proc_net_text(file: &str) -> Option<alloc::string::String> {
        (file == "route").then(|| alloc::string::String::from("Iface\tDestination\tGateway\n"))
    }
}

pub mod blockdev {
    use alloc::sync::Arc;
    /// Block device 7:0 opens (a loop device); others are not served.
    pub fn open(rdev: u64, _flags: u32) -> Option<Result<Arc<dyn super::chardev::CharDevice>, i64>> {
        (rdev == super::chardev::makedev(7, 0)).then(|| {
            let d: Arc<dyn super::chardev::CharDevice> = Arc::new(super::chardev::TestDev::new("/dev/loop0", rdev));
            Ok(d)
        })
    }
}

pub mod devices {
    pub fn refresh_efivars() {
        crate::fake::count("refresh_efivars");
    }
}

pub mod mqueue {}
pub mod sysv {}

// Unused-import silencers for the module-level items above
#[allow(unused)]
fn _uses() -> (Option<Arc<()>>, Option<AtomicBool>, Option<Cell<u8>>, Option<String>, Ordering) {
    (None, None, None, None, Ordering::Relaxed)
}
