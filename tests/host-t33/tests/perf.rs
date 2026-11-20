//! `perf_event_open` software counters (`src/compat/linux/perf.rs`): attribute checks,
//! permissions, the per-process tallies, reading (plain and group formats), the ioctls,
//! enable-on-exec and descendants.

use std::sync::{Arc, Mutex};

use hydra_hosttests_t33::compat::linux::{perf, MAY_ACCESS, TGIDS};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fs::FileDescriptor;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

const SW: u32 = 1;
const CPU_CLOCK: u64 = 0;
const TASK_CLOCK: u64 = 1;
const PAGE_FAULTS: u64 = 2;
const SWITCHES: u64 = 3;
const DUMMY: u64 = 9;
const DISABLED: u64 = 1;
const INHERIT: u64 = 2;
const EXCLUDE_KERNEL: u64 = 1 << 5;
const FREQ: u64 = 1 << 10;
const ENABLE_ON_EXEC: u64 = 1 << 12;

#[derive(Clone, Copy)]
struct A {
    kind: u32,
    size: u32,
    config: u64,
    sample: u64,
    format: u64,
    bits: u64,
}

impl A {
    fn sw(config: u64) -> A {
        A { kind: SW, size: 128, config, sample: 0, format: 0, bits: EXCLUDE_KERNEL }
    }
    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; self.size.max(64) as usize];
        b[0..4].copy_from_slice(&self.kind.to_le_bytes());
        b[4..8].copy_from_slice(&self.size.to_le_bytes());
        b[8..16].copy_from_slice(&self.config.to_le_bytes());
        b[16..24].copy_from_slice(&self.sample.to_le_bytes());
        b[32..40].copy_from_slice(&self.format.to_le_bytes());
        b[40..48].copy_from_slice(&self.bits.to_le_bytes());
        b
    }
}

fn open(a: A, pid: i64, cpu: i64, group: i64, flags: u64) -> i64 {
    let b = a.bytes();
    perf::sys_perf_event_open(b.as_ptr() as u64, pid as u64, cpu as u64, group as u64, flags)
}

fn dev(fd: i64) -> Arc<dyn hydra_hosttests_t33::compat::linux::chardev::CharDevice> {
    match fake::FDS.with_borrow(|t| t.get(fd as usize).cloned()) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("not a device"),
    }
}

fn read_u64s(fd: i64, n: usize) -> Vec<u64> {
    let mut b = vec![0u8; n * 8];
    assert_eq!(dev(fd).read(&mut b), (n * 8) as i64);
    b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

#[test]
fn attribute_and_permission_checks() {
    let _g = serial();
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, -1, 16), -22, "unknown flag");
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, -1, 4), -22, "PERF_FLAG_PID_CGROUP");
    assert_eq!(perf::sys_perf_event_open(0, 0, u64::MAX, u64::MAX, 0), -14, "EFAULT");
    // Sizes: 0 means the first version (64 bytes); too small or large is E2BIG with the size
    // written back
    let mut a = A::sw(TASK_CLOCK);
    a.size = 0;
    let fd = open(a, 0, -1, -1, 0);
    assert!(fd >= 3, "{fd}");
    let mut b = A::sw(TASK_CLOCK).bytes();
    b[4..8].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(perf::sys_perf_event_open(b.as_ptr() as u64, 0, u64::MAX, u64::MAX, 0), -7);
    assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 136);
    let mut big = A::sw(TASK_CLOCK);
    big.size = 200;
    let mut bb = big.bytes();
    bb[150] = 1; // a field this kernel does not know, not zero
    assert_eq!(perf::sys_perf_event_open(bb.as_ptr() as u64, 0, u64::MAX, u64::MAX, 0), -7);
    bb[150] = 0;
    assert!(perf::sys_perf_event_open(bb.as_ptr() as u64, 0, u64::MAX, u64::MAX, 0) >= 0, "unknown zero tail is fine");
    // Kinds and configs
    let mut hw = A::sw(0);
    hw.kind = 0;
    assert_eq!(open(hw, 0, -1, -1, 0), -2, "no hardware PMU");
    assert_eq!(open(A::sw(12), 0, -1, -1, 0), -22);
    let mut f = A::sw(TASK_CLOCK);
    f.format = 1 << 5;
    assert_eq!(open(f, 0, -1, -1, 0), -22, "unknown read_format bit");
    let mut s = A::sw(TASK_CLOCK);
    s.sample = 1000;
    assert_eq!(open(s, 0, -1, -1, 0), -95, "no sampling");
    let mut fr = A::sw(TASK_CLOCK);
    fr.bits |= FREQ;
    assert_eq!(open(fr, 0, -1, -1, 0), -95);
    let mut d = A::sw(DUMMY);
    d.sample = 1;
    assert!(open(d, 0, -1, -1, 0) >= 0, "the dummy event may sample (nothing)");
    // Kernel counting needs CAP_PERFMON or CAP_SYS_ADMIN
    let mut k = A::sw(TASK_CLOCK);
    k.bits = 0;
    assert_eq!(open(k, 0, -1, -1, 0), -13);
    fake::CAPS.set(Some(1 << 38));
    assert!(open(k, 0, -1, -1, 0) >= 0);
    fake::IN_USERNS.set(true);
    assert_eq!(open(k, 0, -1, -1, 0), -13, "capabilities of a user namespace do not count");
    fake::IN_USERNS.set(false);
    fake::CAPS.set(Some(0));
    // CPUs: one
    assert_eq!(open(A::sw(TASK_CLOCK), 0, 1, -1, 0), -22);
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -2, -1, 0), -22);
    // System-wide: a CPU and privilege
    assert_eq!(open(A::sw(TASK_CLOCK), -1, -1, -1, 0), -22);
    assert_eq!(open(A::sw(TASK_CLOCK), -1, 0, -1, 0), -13);
    fake::CAPS.set(Some(1 << 21));
    assert!(open(A::sw(TASK_CLOCK), -1, 0, -1, 0) >= 0);
    fake::CAPS.set(Some(0));
    // Other processes: must exist and be traceable
    assert_eq!(open(A::sw(TASK_CLOCK), 4242, -1, -1, 0), -3);
    TGIDS.with_borrow_mut(|m| m.insert(4242, 4240));
    MAY_ACCESS.set(-1);
    assert_eq!(open(A::sw(TASK_CLOCK), 4242, -1, -1, 0), -13);
    MAY_ACCESS.set(-3);
    assert_eq!(open(A::sw(TASK_CLOCK), 4242, -1, -1, 0), -3);
    MAY_ACCESS.set(0);
    assert!(open(A::sw(TASK_CLOCK), 4242, -1, -1, 0) >= 0);
    assert_eq!(open(A::sw(TASK_CLOCK), -5, -1, -1, 0), -3);
    // Group leaders: a perf event, nothing else
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, 1, 0), -22, "stdout is not a perf event");
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, 900, 0), -9);
    let null = Arc::new(NullDev);
    let nfd = fake::FDS.with_borrow_mut(|t| t.alloc_fd(FileDescriptor::Device(null)).unwrap());
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, nfd as i64, 0), -22, "a device that is not perf");
    // FD_CLOEXEC, and EMFILE
    let fd = open(A::sw(TASK_CLOCK), 0, -1, -1, 8);
    assert!(fake::FDS.with_borrow(|t| t.cloexec(fd as usize)));
    hydra_hosttests_t33::compat::linux::NOFILE.set(fd as usize + 1);
    assert_eq!(open(A::sw(TASK_CLOCK), 0, -1, -1, 0), -24);
    assert!(perf::active());
}

struct NullDev;
impl hydra_hosttests_t33::compat::linux::chardev::CharDevice for NullDev {
    fn read(&self, _b: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _w: &mut hydra_hosttests_t33::task::wait::WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        "/dev/null".into()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
}

#[test]
fn counting_the_callers_own_process() {
    let _g = serial();
    fake::IDS.set((501, 500));
    let mut a = A::sw(PAGE_FAULTS);
    a.format = 1 | 2 | 4 | 16;
    let fd = open(a, 0, -1, -1, 0);
    assert!(fd >= 0);
    for _ in 0..3 {
        perf::fault(500);
    }
    perf::fault(999); // another process
    perf::tick(500);
    perf::switched(500);
    assert_eq!(perf::own_ticks(500), (1, 3));
    fake::TICKS.set(fake::TICKS.get() + 10);
    let v = read_u64s(fd, 5);
    assert_eq!(v[0], 3, "faults since it started");
    assert_eq!(v[1], 10_000_000, "time enabled");
    assert_eq!(v[2], 10_000_000, "time running");
    assert!(v[3] > 0, "the id");
    assert_eq!(v[4], 0, "lost");
    // A buffer too small
    let mut small = [0u8; 8];
    assert_eq!(dev(fd).read(&mut small), -28);
    // Disable stops it, reset clears it, enable starts again
    assert_eq!(dev(fd).ioctl(0x2401, 0), 0);
    perf::fault(500);
    assert_eq!(read_u64s(fd, 5)[0], 3);
    assert_eq!(dev(fd).ioctl(0x2403, 0), 0);
    assert_eq!(read_u64s(fd, 5)[0], 0);
    assert_eq!(dev(fd).ioctl(0x2400, 0), 0);
    perf::fault(500);
    assert_eq!(read_u64s(fd, 5)[0], 1);
    assert_eq!(dev(fd).ioctl(0x2403, 0), 0, "reset while running");
    assert_eq!(read_u64s(fd, 5)[0], 0);
    // ID ioctl
    let mut id = 0u64;
    assert_eq!(dev(fd).ioctl(0x8008_2407, &mut id as *mut u64 as u64), 0);
    assert_eq!(id, read_u64s(fd, 5)[3]);
    assert_eq!(dev(fd).ioctl(0x8008_2407, 0), -14);
    assert_eq!(dev(fd).ioctl(0x1234, 0), -25);
    // The device's other answers
    let d = dev(fd);
    assert_eq!((d.poll_events(), d.rdev(), d.nonblock()), (0, 0, false));
    assert_eq!(d.path(), "anon_inode:[perf_event]");
    d.set_nonblock(true);
    let mut w = hydra_hosttests_t33::task::wait::WaitSet::new();
    d.add_wait_queues(&mut w);
    assert!(w.queues.is_empty());
}

#[test]
fn clocks_and_switches() {
    let _g = serial();
    fake::IDS.set((601, 600));
    let cpu = open(A::sw(CPU_CLOCK), 0, -1, -1, 0);
    let task = open(A::sw(TASK_CLOCK), 0, -1, -1, 0);
    let sw_user = open(A::sw(SWITCHES), 0, -1, -1, 0);
    fake::CAPS.set(Some(1 << 21));
    let mut k = A::sw(SWITCHES);
    k.bits = 0;
    let sw_all = open(k, 0, -1, -1, 0);
    let other = open(A::sw(7), 0, -1, -1, 0); // alignment faults: always 0
    fake::TICKS.set(fake::TICKS.get() + 5);
    perf::tick(600);
    perf::tick(600);
    perf::switched(600);
    assert_eq!(read_u64s(cpu, 1)[0], 5_000_000);
    assert_eq!(read_u64s(task, 1)[0], 20_000_000, "two 10 ms ticks");
    assert_eq!(read_u64s(sw_user, 1)[0], 0, "user space only: no context switches");
    assert_eq!(read_u64s(sw_all, 1)[0], 1);
    assert_eq!(read_u64s(other, 1)[0], 0);
}

#[test]
fn groups_read_and_switch_together() {
    let _g = serial();
    fake::IDS.set((701, 700));
    let mut l = A::sw(PAGE_FAULTS);
    l.format = 8 | 1 | 2 | 4 | 16; // GROUP
    l.bits |= DISABLED;
    let leader = open(l, 0, -1, -1, 0);
    let mut m = A::sw(SWITCHES);
    m.bits |= DISABLED;
    fake::CAPS.set(Some(1 << 38));
    m.bits &= !EXCLUDE_KERNEL;
    let member = open(m, 0, -1, leader, 0);
    assert!(member >= 0);
    perf::fault(700);
    // Disabled: nothing counted
    let v = read_u64s(leader, 3 + 2 * 3);
    assert_eq!(v[0], 2, "two events");
    assert_eq!((v[3], v[6]), (0, 0));
    // Enable the whole group
    assert_eq!(dev(leader).ioctl(0x2400, 1), 0);
    perf::fault(700);
    perf::switched(700);
    perf::switched(700);
    let v = read_u64s(leader, 9);
    assert_eq!((v[3], v[6]), (1, 2));
    assert!(v[7] > v[4], "ids differ");
    assert_eq!((v[5], v[8]), (0, 0), "lost");
    // Disable and reset the group
    assert_eq!(dev(leader).ioctl(0x2401, 1), 0);
    assert_eq!(dev(leader).ioctl(0x2403, 1), 0);
    let v = read_u64s(leader, 9);
    assert_eq!((v[3], v[6]), (0, 0));
}

#[test]
fn enable_on_exec_and_descendants() {
    let _g = serial();
    // Counting process 800 (not the caller): enable at its exec, with its descendants
    TGIDS.with_borrow_mut(|m| m.insert(800, 800));
    let mut a = A::sw(PAGE_FAULTS);
    a.bits |= DISABLED | ENABLE_ON_EXEC | INHERIT;
    let fd = open(a, 800, -1, -1, 0);
    perf::fault(800);
    assert_eq!(read_u64s(fd, 1)[0], 0, "not yet");
    perf::on_exec(801); // someone else
    perf::on_exec(800);
    perf::fault(800);
    assert_eq!(read_u64s(fd, 1)[0], 1);
    // A child (803) exits: its tally joins 800's descendants
    perf::fault(803);
    perf::fault(803);
    perf::exited(803, &[800, 1]);
    assert_eq!(read_u64s(fd, 1)[0], 3, "inherit: descendants count");
    assert_eq!(perf::own_ticks(803), (0, 0), "the child's record is gone");
    perf::exited(803, &[800]); // no record: nothing
    // 800 itself exits while watched: its record stays readable
    perf::exited(800, &[1]);
    assert_eq!(read_u64s(fd, 1)[0], 3);
    assert_eq!(perf::own_ticks(800).1, 2);
    perf::exited(55555, &[]);
    // A system-wide counter sums every process
    fake::CAPS.set(Some(1 << 21));
    let all = open(A::sw(PAGE_FAULTS), -1, 0, -1, 0);
    perf::fault(1);
    assert_eq!(read_u64s(all, 1)[0], 1);
}
