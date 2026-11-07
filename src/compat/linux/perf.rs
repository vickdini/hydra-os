//! perf_event_open: software counters (what `perf stat` counts without a PMU).
//!
//! - **Events**: `PERF_TYPE_SOFTWARE` task clock, CPU clock, page faults (minor; no major
//!   ones without swap), context switches, CPU migrations (none: one CPU), alignment and
//!   emulation faults (none), dummy. Hardware, cache, raw, tracepoint and breakpoint events
//!   give `ENOENT`, as on a machine (or VM) without those PMUs.
//! - **Counting** only: read() gives the value (with `TOTAL_TIME_ENABLED`/`RUNNING`, `ID`,
//!   `LOST`, and whole groups with `PERF_FORMAT_GROUP`); `ENABLE`, `DISABLE`, `RESET`,
//!   `ID` ioctls (also for the group). `disabled` + `enable_on_exec` start it at the
//!   target's exec; `inherit` adds the target's descendants as they exit. Sampling
//!   (`sample_period`/`freq`, the mmap ring) is refused (`EOPNOTSUPP`).
//! - **Accounting** per process while perf is in use: timer ticks (10 ms), context switches
//!   and page faults, kept for exited processes' ancestors that count descendants.
//! - **Permissions** as `perf_event_paranoid` = 2: the caller's own or traceable processes,
//!   user space only (`exclude_kernel`) unless `CAP_PERFMON`/`CAP_SYS_ADMIN`; system-wide
//!   (pid -1) needs those capabilities.
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::task::wait::WaitSet;

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;
const E2BIG: i64 = -7;
const ENOSPC: i64 = -28;
const EOPNOTSUPP: i64 = -95;

const PERF_TYPE_SOFTWARE: u32 = 1;

const SW_CPU_CLOCK: u64 = 0;
const SW_TASK_CLOCK: u64 = 1;
const SW_PAGE_FAULTS: u64 = 2;
const SW_CONTEXT_SWITCHES: u64 = 3;
const SW_CPU_MIGRATIONS: u64 = 4;
const SW_PAGE_FAULTS_MIN: u64 = 5;
const SW_PAGE_FAULTS_MAJ: u64 = 6;
const SW_ALIGNMENT_FAULTS: u64 = 7;
const SW_EMULATION_FAULTS: u64 = 8;
const SW_DUMMY: u64 = 9;

const FORMAT_TOTAL_TIME_ENABLED: u64 = 1;
const FORMAT_TOTAL_TIME_RUNNING: u64 = 2;
const FORMAT_ID: u64 = 4;
const FORMAT_GROUP: u64 = 8;
const FORMAT_LOST: u64 = 16;

const FLAG_FD_NO_GROUP: u64 = 1;
const FLAG_FD_OUTPUT: u64 = 2;
const FLAG_PID_CGROUP: u64 = 4;
const FLAG_FD_CLOEXEC: u64 = 8;

const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;
const IOC_RESET: u64 = 0x2403;
const IOC_ID: u64 = 0x8008_2407;
const IOC_FLAG_GROUP: u64 = 1;

/// The size of `struct perf_event_attr` this kernel knows (`PERF_ATTR_SIZE_VER8`).
const ATTR_KNOWN: usize = 136;
const TICK_NS: u64 = 10_000_000;

/// What one process did (while perf was in use).
#[derive(Clone, Copy, Default)]
struct Counts {
    ticks: u64,
    switches: u64,
    faults: u64,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.ticks += o.ticks;
        self.switches += o.switches;
        self.faults += o.faults;
    }
}

struct Proc {
    own: Counts,
    /// Exited descendants' totals (for inheriting counters).
    descendants: Counts,
}

static PROCS: Mutex<BTreeMap<u64, Proc>> = Mutex::new(BTreeMap::new());
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Turns the per-process tallies on (process accounting uses them too).
pub fn force_active() {
    ACTIVE.store(true, Ordering::Relaxed);
}

/// Timer ticks process `tgid` ran and its page faults (while tallies were on).
pub fn own_ticks(tgid: u64) -> (u64, u64) {
    PROCS.lock().get(&tgid).map_or((0, 0), |p| (p.own.ticks, p.own.faults))
}

/// Whether perf counts (the hooks' fast path).
#[inline]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

fn bump(tgid: u64, f: impl FnOnce(&mut Counts)) {
    if let Some(mut p) = PROCS.try_lock() {
        let e = p.entry(tgid).or_insert(Proc { own: Counts::default(), descendants: Counts::default() });
        f(&mut e.own);
    }
}

/// A timer tick charged to process `tgid` (scheduler).
pub fn tick(tgid: u64) {
    if active() {
        bump(tgid, |c| c.ticks += 1);
    }
}

/// Process `tgid` was switched away from (scheduler).
pub fn switched(tgid: u64) {
    if active() {
        bump(tgid, |c| c.switches += 1);
    }
}

/// A page fault of process `tgid` (fault handler).
pub fn fault(tgid: u64) {
    if active() {
        bump(tgid, |c| c.faults += 1);
    }
}

/// Process `pid` exited: its totals (and its descendants') go to its ancestors.
pub fn exited(pid: u64, ancestors: &[u64]) {
    if !active() {
        return;
    }
    // A counter on the process itself keeps its record (read after the exit, as perf stat
    // does); asked before taking the tallies' lock (counters take them in that order)
    let watched = EVENTS.lock().iter().filter_map(|w| w.upgrade()).any(|e| e.target == Some(pid));
    let mut p = PROCS.lock();
    let gone = if watched {
        match p.get(&pid) {
            Some(e) => Proc { own: e.own, descendants: e.descendants },
            None => return,
        }
    } else {
        match p.remove(&pid) {
            Some(g) => g,
            None => return,
        }
    };
    let mut total = gone.own;
    total.add(&gone.descendants);
    for a in ancestors {
        p.entry(*a).or_insert(Proc { own: Counts::default(), descendants: Counts::default() }).descendants.add(&total);
    }
}

/// Process `tgid` exec'd: its `enable_on_exec` counters start.
pub fn on_exec(tgid: u64) {
    if !active() {
        return;
    }
    for e in EVENTS.lock().iter().filter_map(|w| w.upgrade()) {
        let mut s = e.st.lock();
        if e.target == Some(tgid) && e.enable_on_exec && !s.enabled {
            s.start(&e);
        }
    }
}

fn snapshot(tgid: Option<u64>, inherit: bool) -> Counts {
    let p = PROCS.lock();
    match tgid {
        Some(t) => p.get(&t).map_or(Counts::default(), |e| {
            let mut c = e.own;
            if inherit {
                c.add(&e.descendants);
            }
            c
        }),
        // System-wide: everything
        None => p.values().fold(Counts::default(), |mut a, e| {
            a.add(&e.own);
            a
        }),
    }
}

fn now_ns() -> u64 {
    crate::arch::pit::ticks() * TICK_NS
}

/// A counter.
pub struct Event {
    id: u64,
    config: u64,
    target: Option<u64>,
    inherit: bool,
    enable_on_exec: bool,
    /// User space only: events in the kernel (context switches) are not counted.
    exclude_kernel: bool,
    read_format: u64,
    st: Mutex<EvState>,
    /// Members, if it leads a group.
    members: Mutex<Vec<Arc<Event>>>,
}

struct EvState {
    enabled: bool,
    /// Counted while enabled before (since the last reset).
    acc: u64,
    /// Where the current enabled stretch started.
    base: u64,
    acc_time: u64,
    since: u64,
}

impl EvState {
    fn start(&mut self, e: &Event) {
        self.enabled = true;
        self.base = e.raw();
        self.since = now_ns();
    }
    fn stop(&mut self, e: &Event) {
        if self.enabled {
            self.acc += e.raw().saturating_sub(self.base);
            self.acc_time += now_ns() - self.since;
            self.enabled = false;
        }
    }
}

impl Event {
    /// The underlying count now (in the event's units).
    fn raw(&self) -> u64 {
        match self.config {
            SW_CPU_CLOCK => now_ns(),
            SW_TASK_CLOCK => snapshot(self.target, self.inherit).ticks * TICK_NS,
            SW_PAGE_FAULTS | SW_PAGE_FAULTS_MIN => snapshot(self.target, self.inherit).faults,
            SW_CONTEXT_SWITCHES if self.exclude_kernel => 0,
            SW_CONTEXT_SWITCHES => snapshot(self.target, self.inherit).switches,
            _ => 0,
        }
    }

    /// `(value, time enabled, time running)`.
    fn value(&self) -> (u64, u64, u64) {
        let s = self.st.lock();
        let (mut v, mut t) = (s.acc, s.acc_time);
        if s.enabled {
            v += self.raw().saturating_sub(s.base);
            t += now_ns() - s.since;
        }
        (v, t, t)
    }
}

static EVENTS: Mutex<Vec<alloc::sync::Weak<Event>>> = Mutex::new(Vec::new());

struct PerfDev(Arc<Event>);

impl CharDevice for PerfDev {
    fn read(&self, buf: &mut [u8]) -> i64 {
        let e = &self.0;
        let f = e.read_format;
        let mut out: Vec<u8> = Vec::new();
        let push = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_le_bytes());
        if f & FORMAT_GROUP != 0 {
            let members = e.members.lock().clone();
            let (_, te, tr) = e.value();
            push(&mut out, 1 + members.len() as u64);
            if f & FORMAT_TOTAL_TIME_ENABLED != 0 {
                push(&mut out, te);
            }
            if f & FORMAT_TOTAL_TIME_RUNNING != 0 {
                push(&mut out, tr);
            }
            for m in core::iter::once(e).chain(members.iter()) {
                push(&mut out, m.value().0);
                if f & FORMAT_ID != 0 {
                    push(&mut out, m.id);
                }
                if f & FORMAT_LOST != 0 {
                    push(&mut out, 0);
                }
            }
        } else {
            let (v, te, tr) = e.value();
            push(&mut out, v);
            if f & FORMAT_TOTAL_TIME_ENABLED != 0 {
                push(&mut out, te);
            }
            if f & FORMAT_TOTAL_TIME_RUNNING != 0 {
                push(&mut out, tr);
            }
            if f & FORMAT_ID != 0 {
                push(&mut out, e.id);
            }
            if f & FORMAT_LOST != 0 {
                push(&mut out, 0);
            }
        }
        if buf.len() < out.len() {
            return -28; // ENOSPC
        }
        buf[..out.len()].copy_from_slice(&out);
        out.len() as i64
    }
    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        let e = &self.0;
        let group: Vec<Arc<Event>> = if arg & IOC_FLAG_GROUP != 0 { core::iter::once(e.clone()).chain(e.members.lock().iter().cloned()).collect() } else { alloc::vec![e.clone()] };
        match cmd {
            IOC_ENABLE => {
                for m in group {
                    let mut s = m.st.lock();
                    if !s.enabled {
                        s.start(&m);
                    }
                }
                0
            }
            IOC_DISABLE => {
                for m in group {
                    m.st.lock().stop(&m);
                }
                0
            }
            IOC_RESET => {
                for m in group {
                    let mut s = m.st.lock();
                    s.acc = 0;
                    s.acc_time = 0;
                    if s.enabled {
                        s.base = m.raw();
                        s.since = now_ns();
                    }
                }
                0
            }
            IOC_ID => copy_out(arg, &e.id.to_le_bytes()).map_or(EFAULT, |_| 0),
            _ => ENOTTY,
        }
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> alloc::string::String {
        alloc::string::String::from("anon_inode:[perf_event]")
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_perf(&self) -> Option<Arc<Event>> {
        Some(self.0.clone())
    }
}

fn caps(bit: u32) -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1 << bit) != 0 && !t.caps.in_userns).unwrap_or(false)
}

/// `perf_event_open(attr, pid, cpu, group_fd, flags)`.
pub fn sys_perf_event_open(attr: u64, pid: u64, cpu: u64, group_fd: u64, flags: u64) -> i64 {
    if flags & !(FLAG_FD_NO_GROUP | FLAG_FD_OUTPUT | FLAG_PID_CGROUP | FLAG_FD_CLOEXEC) != 0 || flags & FLAG_PID_CGROUP != 0 {
        return EINVAL;
    }
    let hdr = match copy_in(attr, 8) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let kind = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let mut size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
    if size == 0 {
        size = 64; // PERF_ATTR_SIZE_VER0
    }
    if !(64..=4096).contains(&size) {
        let _ = copy_out(attr + 4, &(ATTR_KNOWN as u32).to_le_bytes());
        return E2BIG;
    }
    let raw = match copy_in(attr, size) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if raw.len() > ATTR_KNOWN && raw[ATTR_KNOWN..].iter().any(|&b| b != 0) {
        let _ = copy_out(attr + 4, &(ATTR_KNOWN as u32).to_le_bytes());
        return E2BIG;
    }
    let u64_at = |o: usize| if o + 8 <= raw.len() { u64::from_le_bytes(raw[o..o + 8].try_into().unwrap()) } else { 0 };
    let config = u64_at(8);
    let sample = u64_at(16);
    let read_format = u64_at(32);
    let bits = u64_at(40);
    let (disabled, inherit, exclude_kernel, freq, enable_on_exec) = (bits & 1 != 0, bits & 2 != 0, bits & (1 << 5) != 0, bits & (1 << 10) != 0, bits & (1 << 12) != 0);
    if kind != PERF_TYPE_SOFTWARE {
        return ENOENT; // no hardware, cache, raw, tracepoint or breakpoint PMUs
    }
    if config > SW_DUMMY + 2 {
        return EINVAL;
    }
    if read_format & !(FORMAT_TOTAL_TIME_ENABLED | FORMAT_TOTAL_TIME_RUNNING | FORMAT_ID | FORMAT_GROUP | FORMAT_LOST) != 0 {
        return EINVAL;
    }
    if (sample != 0 || freq) && config != SW_DUMMY {
        return EOPNOTSUPP; // counting only: no sampling
    }
    let privileged = caps(38) || caps(21); // CAP_PERFMON, CAP_SYS_ADMIN
    // perf_event_paranoid = 2: user space only for the unprivileged
    if !exclude_kernel && !privileged {
        return EACCES;
    }
    let cpu = cpu as i32;
    if cpu < -1 || cpu > 0 {
        return EINVAL; // one CPU
    }
    let target = match pid as i32 {
        -1 => {
            if cpu < 0 {
                return EINVAL;
            }
            if !privileged {
                return EACCES;
            }
            None
        }
        0 => Some(super::proc::current_ids().1),
        p if p > 0 => {
            let sys = super::ns::pid_from_caller(p as u64);
            let Some(tgid) = super::proc::tgid_of(sys) else { return ESRCH };
            if let Err(e) = super::extra::may_access(tgid) {
                return if e == ESRCH { e } else { EACCES };
            }
            Some(tgid)
        }
        _ => return ESRCH,
    };
    // Group leader
    let leader = if group_fd as i32 == -1 {
        None
    } else {
        let d = crate::task::with_current_fds_mut(|fds| fds.get(group_fd as i32 as usize).cloned());
        match d {
            Some(crate::fs::FileDescriptor::Device(d)) => match d.as_perf() {
                Some(l) => Some(l),
                None => return EINVAL,
            },
            Some(_) => return EINVAL,
            None => return EBADF,
        }
    };
    ACTIVE.store(true, Ordering::Relaxed);
    let e = Arc::new(Event {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        config,
        target,
        inherit,
        enable_on_exec,
        exclude_kernel,
        read_format,
        st: Mutex::new(EvState { enabled: false, acc: 0, base: 0, acc_time: 0, since: 0 }),
        members: Mutex::new(Vec::new()),
    });
    if !disabled {
        let mut s = e.st.lock();
        s.start(&e);
    }
    if let Some(l) = leader {
        l.members.lock().push(e.clone());
    }
    EVENTS.lock().push(Arc::downgrade(&e));
    let _ = (ENOSPC, SW_CPU_MIGRATIONS, SW_PAGE_FAULTS_MAJ, SW_ALIGNMENT_FAULTS, SW_EMULATION_FAULTS);
    let dev: Arc<dyn CharDevice> = Arc::new(PerfDev(e));
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & FLAG_FD_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}
