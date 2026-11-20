//! `chardev.rs` (device numbers, the driver switch, the trait's defaults, device socket
//! calls) and `misc.rs` (times, membarrier, personality, sched_rr_get_interval, getdents,
//! utime/utimes/futimesat, getcpu, restart_syscall).

mod common;

use std::sync::Arc;

use hydra_hosttests_t28::compat::linux::chardev::{self, makedev, CharDevice};
use hydra_hosttests_t28::compat::linux::misc;
use hydra_hosttests_t28::fake;
use hydra_hosttests_t28::fs::FileDescriptor;
use hydra_hosttests_t28::task::wait::WaitSet;

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

fn p<T>(v: &mut [T]) -> u64 {
    v.as_mut_ptr() as u64
}

// ------------------------------------------------------------------ chardev

#[test]
fn makedev_encodes_like_linux() {
    assert_eq!(makedev(226, 0), 0xE200);
    assert_eq!(makedev(13, 64), 0x0D40);
    // Minors above 255 go to bits 20 and up; majors keep 12 bits
    assert_eq!(makedev(136, 0x1234), (0x12 << 20) | (136 << 8) | 0x34 | 0);
    assert_eq!(makedev(0x1FFF, 1), (0xFFF << 8) | 1);
}

/// A device that only implements the required methods (the defaults are under test).
struct Bare;
impl CharDevice for Bare {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        7
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        makedev(4, 5)
    }
    fn path(&self) -> String {
        "/dev/bare".into()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn socket_call(&self, num: u64, a: [u64; 6]) -> Option<i64> {
        (num == 42).then_some(a[1] as i64 + 1)
    }
}

#[test]
fn trait_defaults() {
    let d = Bare;
    assert_eq!(d.write(b"x"), EINVAL);
    assert_eq!(d.ioctl(1, 2), -25);
    assert_eq!(d.mmap_object().err(), Some(-19));
    assert_eq!(d.mmap_object_at(3).err(), Some(-19));
    assert!(d.dma_buf().is_none());
    assert!(d.socket_call(41, [0; 6]).is_none());
    let st = d.stat();
    assert_eq!(st.st_dev, 6);
    assert_eq!(st.st_rdev, makedev(4, 5));
    assert_eq!(st.st_ino, makedev(4, 5) | 0x1_0000_0000);
    assert_eq!(st.st_mode, 0o020660);
    assert_eq!(st.st_nlink, 1);
    assert_eq!(st.st_blksize, 4096);
    assert!(!d.deliver_notification(b"n"));
    assert!(d.as_mqueue().is_none());
    let mut b = [0u8; 4];
    assert!(d.pread(&mut b, 0).is_none());
    assert!(d.pwrite(&b, 0).is_none());
    assert!(d.seek(0, 0).is_none());
    assert!(d.read_unlocked(&mut b).is_none());
    assert!(d.fsync().is_none());
    assert!(d.as_bpf().is_none());
    assert!(d.as_perf().is_none());
    assert!(d.as_fuse().is_none());
    assert!(d.as_fanotify().is_none());
    assert!(d.as_mount_obj().is_none());
    assert!(d.as_io_uring().is_none());
    assert!(d.as_landlock().is_none());
    assert!(d.as_server().is_none());
    assert!(d.edges().is_none());
}

#[test]
fn open_switches_on_the_major() {
    // No driver for this major
    assert!(chardev::open(makedev(250, 0), 0).is_none());
    // 1:11 kmsg and 10:229 fuse go to their modules (stubs with recognisable errnos);
    // 1:3 (/dev/null) and 10:200 are not char drivers here
    assert_eq!(chardev::open(makedev(1, 11), 0).unwrap().err(), Some(-1011));
    assert!(chardev::open(makedev(1, 3), 0).is_none());
    assert_eq!(chardev::open(makedev(10, 229), 0).unwrap().err(), Some(-1229));
    assert!(chardev::open(makedev(10, 200), 0).is_none());
    // DRM card1 and evdev minor 1 do not exist; no sound card: ENODEV
    assert_eq!(chardev::open(makedev(226, 1), 0).unwrap().err(), Some(-6));
    assert_eq!(chardev::open(makedev(13, 1), 0).unwrap().err(), Some(-6));
    assert_eq!(chardev::open(makedev(116, 0), 0).unwrap().err(), Some(-19));
    // evdev minor 64 opens, with O_NONBLOCK honoured
    let kbd = chardev::open(makedev(13, 64), 0o4000).unwrap().unwrap();
    assert!(kbd.nonblock());
    assert_eq!(kbd.path(), "/dev/input/event0");
    let kbd = chardev::open(makedev(13, 64), 0).unwrap().unwrap();
    assert!(!kbd.nonblock());
}

#[test]
fn open_asks_the_linux_services_first() {
    fake::LX_DEV_OPEN.set(Some(-77));
    assert_eq!(chardev::open(makedev(13, 64), 0).unwrap().err(), Some(-77));
    fake::LX_DEV_OPEN.set(None);
}

#[test]
fn dispatch_of_device_sockets() {
    // socket(2) goes to netlink
    assert_eq!(chardev::dispatch(41, [0; 6]), Some(4141));
    // Not a socket call
    assert_eq!(chardev::dispatch(0, [0; 6]), None);
    // A socket call on a descriptor that is not a device: not ours
    assert_eq!(chardev::dispatch(42, [3, 0, 0, 0, 0, 0]), None);
    fake::with_current_fds_mut(|f| f.install(5, FileDescriptor::Other));
    assert_eq!(chardev::dispatch(44, [5, 0, 0, 0, 0, 0]), None);
    // A device: its socket_call answers, or ENOTSOCK
    fake::with_current_fds_mut(|f| f.install(4, FileDescriptor::Device(Arc::new(Bare))));
    assert_eq!(chardev::dispatch(42, [4, 9, 0, 0, 0, 0]), Some(10));
    for num in [43, 55, 288, 299, 307] {
        assert_eq!(chardev::dispatch(num, [4, 9, 0, 0, 0, 0]), Some(-88), "call {num}");
    }
}

// --------------------------------------------------------------------- misc

#[test]
fn times_reports_user_hz_ticks() {
    fake::TICKS.set(12_345); // 12.345 s at 1000 Hz
    fake::CPU_TIMES.set((1000, 2000, 30, 0));
    let mut tms = [0u64; 4];
    assert_eq!(misc::dispatch(100, [p(&mut tms), 0, 0, 0, 0, 0]), Some(1234));
    assert_eq!(tms, [100, 200, 3, 0]);
    // A null buffer only returns the clock; a bad one faults
    assert_eq!(misc::dispatch(100, [0; 6]), Some(1234));
    assert_eq!(misc::dispatch(100, [fake::BAD_PTR, 0, 0, 0, 0, 0]), Some(EFAULT));
}

#[test]
fn membarrier_commands() {
    fake::IDS.set((7001, 7001));
    let mb = |cmd: u64, flags: u64| misc::dispatch(324, [cmd, flags, 0, 0, 0, 0]).unwrap();
    // QUERY
    assert_eq!(mb(0, 0), 1 | 2 | 4 | 8 | 16 | 128 | 256);
    assert_eq!(mb(0, 1), EINVAL);
    // GLOBAL needs nothing
    assert_eq!(mb(1, 0), 0);
    // Not a single bit, unsupported (SYNC_CORE = 32), flags on a non-RSEQ command
    assert_eq!(mb(3, 0), EINVAL);
    assert_eq!(mb(32, 0), EINVAL);
    assert_eq!(mb(8, 1), EINVAL);
    assert_eq!(mb(128, 2), EINVAL);
    // PRIVATE_EXPEDITED before and after registering
    assert_eq!(mb(8, 0), -1);
    assert_eq!(mb(16, 0), 0);
    assert_eq!(mb(8, 0), 0);
    // RSEQ (with the CPU flag) needs its own registration
    assert_eq!(mb(128, 1), -1);
    assert_eq!(mb(256, 0), 0);
    assert_eq!(mb(128, 1), 0);
    assert_eq!(mb(2, 0), 0);
    assert_eq!(mb(4, 0), 0);
    // Forgotten at exec/exit
    misc::forget_process(7001);
    assert_eq!(mb(8, 0), -1);
}

#[test]
fn personality_is_kept_per_process() {
    fake::IDS.set((7002, 7002));
    // No process entry: 0, nothing kept
    assert_eq!(misc::dispatch(135, [0x0040_0000, 0, 0, 0, 0, 0]), Some(0));
    fake::PROCS.lock().insert(7002, fake::Process::default());
    assert_eq!(misc::dispatch(135, [0x0040_0000, 0, 0, 0, 0, 0]), Some(0));
    // 0xffffffff reads without changing
    assert_eq!(misc::dispatch(135, [0xffff_ffff, 0, 0, 0, 0, 0]), Some(0x0040_0000));
    assert_eq!(misc::dispatch(135, [0, 0, 0, 0, 0, 0]), Some(0x0040_0000));
    assert_eq!(misc::dispatch(135, [0xffff_ffff, 0, 0, 0, 0, 0]), Some(0));
    fake::PROCS.lock().remove(&7002);
}

#[test]
fn sched_rr_get_interval_reports_the_time_slice() {
    let mut ts = [0i64; 2];
    // pid 0 = the caller: 5 ticks at 1000 Hz
    assert_eq!(misc::dispatch(148, [0, p(&mut ts), 0, 0, 0, 0]), Some(0));
    assert_eq!(ts, [0, 5_000_000]);
    assert_eq!(misc::dispatch(148, [987_654, p(&mut ts), 0, 0, 0, 0]), Some(-3));
    fake::PROCS.lock().insert(7003, fake::Process::default());
    assert_eq!(misc::dispatch(148, [7003, p(&mut ts), 0, 0, 0, 0]), Some(0));
    assert_eq!(misc::dispatch(148, [7003, fake::BAD_PTR, 0, 0, 0, 0]), Some(EFAULT));
    fake::PROCS.lock().remove(&7003);
}

/// One `linux_dirent64` record: ino, off, reclen, type, name, NUL, padding to 8.
fn dirent64(ino: u64, off: u64, ty: u8, name: &str) -> Vec<u8> {
    let reclen = (19 + name.len() + 1 + 7) & !7;
    let mut r = vec![0u8; reclen];
    r[0..8].copy_from_slice(&ino.to_le_bytes());
    r[8..16].copy_from_slice(&off.to_le_bytes());
    r[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    r[18] = ty;
    r[19..19 + name.len()].copy_from_slice(name.as_bytes());
    r
}

#[test]
fn getdents_converts_records_in_place() {
    let mut recs = dirent64(11, 1, 4, ".");
    recs.extend(dirent64(12, 2, 8, "hello.txt"));
    let n = recs.len() as i64;
    fake::GETDENTS64.with_borrow_mut(|g| *g = Some((n, recs.clone())));
    let mut buf = vec![0xAAu8; 256];
    assert_eq!(misc::dispatch(78, [3, p(&mut buf), 256, 0, 0, 0]), Some(n));
    // First record: name moved down over the type, type in the last byte
    let r0 = 24;
    assert_eq!(&buf[0..8], &11u64.to_le_bytes());
    assert_eq!(u16::from_le_bytes([buf[16], buf[17]]), r0 as u16);
    assert_eq!(&buf[18..20], b".\0");
    assert_eq!(buf[r0 - 1], 4);
    let r1 = &buf[r0..n as usize];
    assert_eq!(&r1[18..28], b"hello.txt\0");
    assert_eq!(r1[r1.len() - 1], 8);
    assert!(r1[28..r1.len() - 1].iter().all(|&b| b == 0));

    // Errors and end of directory pass through; no directory: EBADF
    fake::GETDENTS64.with_borrow_mut(|g| *g = Some((0, Vec::new())));
    assert_eq!(misc::dispatch(78, [3, p(&mut buf), 256, 0, 0, 0]), Some(0));
    fake::GETDENTS64.with_borrow_mut(|g| *g = Some((-20, Vec::new())));
    assert_eq!(misc::dispatch(78, [3, p(&mut buf), 256, 0, 0, 0]), Some(-20));
    fake::GETDENTS64.with_borrow_mut(|g| *g = None);
    assert_eq!(misc::dispatch(78, [3, p(&mut buf), 256, 0, 0, 0]), Some(-9));
}

#[test]
fn getdents_stops_at_a_broken_record() {
    let mut recs = dirent64(11, 1, 4, "a");
    // A record claiming more bytes than were returned is left alone
    let mut bad = dirent64(12, 2, 8, "b");
    bad[16..18].copy_from_slice(&200u16.to_le_bytes());
    recs.extend(&bad);
    let n = recs.len() as i64;
    fake::GETDENTS64.with_borrow_mut(|g| *g = Some((n, recs.clone())));
    let mut buf = vec![0u8; 128];
    assert_eq!(misc::dispatch(78, [3, p(&mut buf), 128, 0, 0, 0]), Some(n));
    assert_eq!(buf[23], 4);
    assert_eq!(&buf[24 + 16..24 + 24], &bad[16..24]);
    fake::GETDENTS64.with_borrow_mut(|g| *g = None);
}

#[test]
fn utime_utimes_futimesat() {
    fake::SET_TIMES.with_borrow_mut(|v| v.clear());
    // utime with a utimbuf: whole seconds
    let mut ub = [100i64, 200];
    assert_eq!(misc::dispatch(132, [0x1000, p(&mut ub), 0, 0, 0, 0]), Some(0));
    // utime(NULL): now
    assert_eq!(misc::dispatch(132, [0x1000, 0, 0, 0, 0, 0]), Some(0));
    assert_eq!(misc::dispatch(132, [0x1000, fake::BAD_PTR, 0, 0, 0, 0]), Some(EFAULT));
    // utimes with timevals: microseconds become nanoseconds
    let mut tv = [5i64, 7, 9, 999_999];
    assert_eq!(misc::dispatch(235, [0x2000, p(&mut tv), 0, 0, 0, 0]), Some(0));
    let mut bad = [5i64, 1_000_000, 9, 0];
    assert_eq!(misc::dispatch(235, [0x2000, p(&mut bad), 0, 0, 0, 0]), Some(EINVAL));
    let mut neg = [5i64, 0, 9, -1];
    assert_eq!(misc::dispatch(235, [0x2000, p(&mut neg), 0, 0, 0, 0]), Some(EINVAL));
    assert_eq!(misc::dispatch(235, [0x2000, fake::BAD_PTR, 0, 0, 0, 0]), Some(EFAULT));
    // futimesat(dirfd, path, NULL)
    assert_eq!(misc::dispatch(261, [5, 0x3000, 0, 0, 0, 0]), Some(0));
    assert_eq!(misc::dispatch(261, [5, 0x3000, p(&mut bad), 0, 0, 0]), Some(EINVAL));
    let calls = fake::SET_TIMES.with_borrow(|v| v.clone());
    assert_eq!(
        calls,
        vec![
            (-100, 0x1000, Some([(100, 0), (200, 0)])),
            (-100, 0x1000, None),
            (-100, 0x2000, Some([(5, 7000), (9, 999_999_000)])),
            (5, 0x3000, None),
        ]
    );
}

#[test]
fn getcpu_restart_and_unknown() {
    let mut cpu = [0xFFu32];
    let mut node = [0xFFu32];
    assert_eq!(misc::dispatch(309, [p(&mut cpu), p(&mut node), 0, 0, 0, 0]), Some(0));
    assert_eq!((cpu[0], node[0]), (0, 0));
    assert_eq!(misc::dispatch(309, [0, 0, 0, 0, 0, 0]), Some(0));
    assert_eq!(misc::dispatch(309, [fake::BAD_PTR, 0, 0, 0, 0, 0]), Some(EFAULT));
    assert_eq!(misc::dispatch(309, [0, fake::BAD_PTR, 0, 0, 0, 0]), Some(EFAULT));
    assert_eq!(misc::dispatch(219, [0; 6]), Some(-4));
    assert_eq!(misc::dispatch(1, [0; 6]), None);
}
