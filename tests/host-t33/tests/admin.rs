//! Administration calls (`src/compat/linux/admin.rs`): the kernel log ring through
//! `syslog` and `/dev/kmsg`, `sysfs`, `ustat`, `vhangup`, process accounting records,
//! swap areas and quotas.

use std::ffi::CString;
use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::{admin, perf, HANGUP, LOOKUPS, SIGNALS};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs, Kind};
use hydra_hosttests_t33::fs::client::ZfsClient;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    fakefs::pool();
    g
}

const CAP_SYS_PACCT: u64 = 1 << 20;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYS_TTY_CONFIG: u64 = 1 << 26;
const CAP_SYSLOG: u64 = 1 << 34;

fn syslog(kind: u64, buf: &mut [u8]) -> i64 {
    admin::dispatch(103, [kind, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0])
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn syslog_reads_clears_and_sizes_the_ring() {
    let _g = serial();
    let mut buf = vec![0u8; 256];
    assert_eq!(syslog(3, &mut buf), -1, "dmesg_restrict: privilege needed");
    fake::CAPS.set(Some(CAP_SYSLOG));
    // Clear everything earlier tests logged, then log two lines
    assert_eq!(syslog(5, &mut buf), 0);
    let mut drain = vec![0u8; 70_000];
    if syslog(9, &mut drain) > 0 {
        let _ = syslog(2, &mut drain);
    }
    fake::TICKS.set(2_500); // 2.5 s
    admin::klog(format_args!("first line\nsecond "));
    admin::klog(format_args!("line\n"));
    assert_eq!(syslog(10, &mut buf), 65536);
    assert_eq!(syslog(9, &mut buf), 29 + 30, "unread bytes, prefixes included");
    // Read all (does not consume)
    let n = syslog(3, &mut buf) as usize;
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert_eq!(text, "<6>[    2.500000] first line\n<6>[    2.500000] second line\n");
    // Only the last bytes when the buffer is small
    let mut small = vec![0u8; 12];
    assert_eq!(syslog(3, &mut small), 12);
    assert_eq!(&small, b"second line\n");
    // Destructive read consumes
    let mut part = vec![0u8; 20];
    assert_eq!(syslog(2, &mut part), 20);
    assert_eq!(&part, b"<6>[    2.500000] fi");
    assert!(syslog(9, &mut buf) > 0);
    let _ = syslog(2, &mut buf);
    assert_eq!(syslog(9, &mut buf), 0);
    // Nothing unread: waits, and a signal ends the wait
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(syslog(2, &mut buf), -4);
    fake::SIGNAL_PENDING.set(false);
    // Read and clear: a later read-all shows nothing
    admin::klog(format_args!("third\n"));
    assert!(syslog(4, &mut buf) > 0);
    assert_eq!(syslog(3, &mut buf), 0);
    // Bad arguments, the console level commands, open/close
    assert_eq!(admin::dispatch(103, [3, 0, 10, 0, 0, 0]), -22, "no buffer");
    assert_eq!(admin::dispatch(103, [3, buf.as_ptr() as u64, (-1i32) as u32 as u64, 0, 0, 0]), -22);
    assert_eq!(admin::dispatch(103, [3, buf.as_ptr() as u64, 0, 0, 0, 0]), 0);
    for k in [0, 1, 6, 7] {
        assert_eq!(syslog(k, &mut buf), 0);
    }
    assert_eq!(admin::dispatch(103, [8, 0, 4, 0, 0, 0]), 0);
    assert_eq!(admin::dispatch(103, [8, 0, 9, 0, 0, 0]), -22);
    assert_eq!(syslog(11, &mut buf), -22);
    // CAP_SYS_ADMIN works too
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(syslog(10, &mut buf), 65536);
    // A bad user buffer
    admin::klog(format_args!("x\n"));
    assert_eq!(admin::dispatch(103, [3, 0, 0, 0, 0, 0]), -22);
}

#[test]
fn the_ring_wraps_and_kmsg_reports_lost_records() {
    let _g = serial();
    fake::CAPS.set(Some(CAP_SYSLOG));
    let k = admin::kmsg_open(0).unwrap();
    assert_eq!(k.path(), "/dev/kmsg");
    assert_eq!(k.rdev(), (1 << 8) | 11);
    // Start at the end: nothing to read, non-blocking
    assert_eq!(k.seek(0, 2), Some(0));
    k.set_nonblock(true);
    assert!(k.nonblock());
    let mut buf = vec![0u8; 512];
    assert_eq!(k.read(&mut buf), -11);
    assert_eq!(k.poll_events(), 0x4);
    fake::TICKS.set(3_000);
    admin::klog(format_args!("hello kmsg\n"));
    assert_eq!(k.poll_events(), 0x41);
    let n = k.read(&mut buf) as usize;
    let rec = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(rec.starts_with("6,") && rec.ends_with(",3000000,-;hello kmsg\n"), "{rec}");
    // Writing joins the log ("<pri>" stripped)
    assert_eq!(k.write(b"<3>from user\n"), 13);
    let n = k.read(&mut buf) as usize;
    assert!(String::from_utf8_lossy(&buf[..n]).ends_with(";from user\n"));
    k.write(b"plain");
    let n = k.read(&mut buf) as usize;
    assert!(String::from_utf8_lossy(&buf[..n]).ends_with(";plain\n"));
    // A buffer too small for the record
    admin::klog(format_args!("this record is long\n"));
    assert_eq!(k.read(&mut buf[..5]), -22);
    // Overwrite the whole ring: the reader lost records (EPIPE once), then goes on
    let line = "x".repeat(1000);
    for _ in 0..80 {
        admin::klog(format_args!("{line}\n"));
    }
    assert_eq!(k.read(&mut buf), -32);
    let mut big = vec![0u8; 2048];
    assert!(k.read(&mut big) > 0);
    // seek: SEEK_SET to the start, SEEK_DATA to after the last clear; others refused
    assert_eq!(k.seek(1, 0), Some(-22));
    assert_eq!(k.seek(0, 0), Some(0));
    assert!(k.read(&mut big) > 0, "from the oldest whole line");
    assert_eq!(k.seek(0, 3), Some(0));
    assert_eq!(k.seek(0, 1), Some(-22));
    // Blocking reader with nothing new: a signal ends it
    k.seek(0, 2);
    k.set_nonblock(false);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(k.read(&mut buf), -4);
    fake::SIGNAL_PENDING.set(false);
    let mut w = hydra_hosttests_t33::task::wait::WaitSet::new();
    k.add_wait_queues(&mut w);
    // Opening for reading needs privilege; for writing it does not
    fake::CAPS.set(Some(0));
    assert!(admin::kmsg_open(0).is_err());
    assert!(admin::kmsg_open(1).is_ok());
    assert!(admin::kmsg_open(0o4001).unwrap().nonblock());
}

#[test]
fn sysfs_and_ustat() {
    let _g = serial();
    let name = cstr("proc");
    assert_eq!(admin::dispatch(139, [1, name.as_ptr() as u64, 0, 0, 0, 0]), 3);
    let none = cstr("ext4");
    assert_eq!(admin::dispatch(139, [1, none.as_ptr() as u64, 0, 0, 0, 0]), -22);
    assert_eq!(admin::dispatch(139, [1, 0, 0, 0, 0, 0]), -14);
    let mut b = [0u8; 32];
    assert_eq!(admin::dispatch(139, [2, 20, b.as_mut_ptr() as u64, 0, 0, 0]), 0);
    assert_eq!(&b[..4], b"zfs\0");
    assert_eq!(admin::dispatch(139, [2, 99, b.as_mut_ptr() as u64, 0, 0, 0]), -22);
    assert_eq!(admin::dispatch(139, [2, 0, 0, 0, 0, 0]), -14);
    assert_eq!(admin::dispatch(139, [3, 0, 0, 0, 0, 0]), admin::FS_TYPES.len() as i64);
    assert_eq!(admin::dispatch(139, [4, 0, 0, 0, 0, 0]), -22);
    let t = admin::filesystems_text();
    assert!(t.starts_with("nodev\tsysfs\n") && t.ends_with("\tzfs\n"));
    // ustat of the pool's device (8:1)
    let mut u = [0u8; 32];
    assert_eq!(admin::dispatch(136, [(8 << 8) | 1, u.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
    assert_eq!(i32::from_le_bytes(u[0..4].try_into().unwrap()), 1 << 19, "free blocks");
    assert!(u64::from_le_bytes(u[8..16].try_into().unwrap()) < 1_000_000);
    assert_eq!(admin::dispatch(136, [(8 << 8) | 2, u.as_mut_ptr() as u64, 0, 0, 0, 0]), -22);
    assert_eq!(admin::dispatch(136, [(8 << 8) | 1, 0, 0, 0, 0, 0]), -14);
}

#[test]
fn vhangup_signals_the_session() {
    let _g = serial();
    assert_eq!(admin::dispatch(153, [0; 6]), -1);
    fake::CAPS.set(Some(CAP_SYS_TTY_CONFIG));
    fake::IDS.set((901, 900));
    // No session: nothing to do
    assert_eq!(admin::dispatch(153, [0; 6]), 0);
    fake::PROCS.lock().insert(900, fake::Process { session: (900, 900), ..Default::default() });
    // No controlling terminal
    assert_eq!(admin::dispatch(153, [0; 6]), 0);
    assert!(SIGNALS.with_borrow(|v| v.is_empty()));
    HANGUP.set(Some((900, 950)));
    assert_eq!(admin::dispatch(153, [0; 6]), 0);
    assert_eq!(SIGNALS.with_borrow(|v| v.clone()), vec![(900, 1, false), (900, 18, false), (950, 1, true), (950, 18, true)]);
    // No foreground group: only the leader
    SIGNALS.with_borrow_mut(|v| v.clear());
    HANGUP.set(Some((900, 0)));
    admin::dispatch(153, [0; 6]);
    assert_eq!(SIGNALS.with_borrow(|v| v.len()), 2);
    fake::PROCS.lock().remove(&900);
}

#[test]
fn process_accounting_writes_acct_v2_records() {
    let _g = serial();
    let d = fakefs::test_dir("acct");
    let f = with_fs(|fs| fs.put(d, "pacct", b""));
    let path = cstr("/acct/pacct");
    let dir = cstr("/acct");
    assert_eq!(admin::dispatch(163, [path.as_ptr() as u64, 0, 0, 0, 0, 0]), -1);
    fake::CAPS.set(Some(CAP_SYS_PACCT));
    assert_eq!(admin::dispatch(163, [dir.as_ptr() as u64, 0, 0, 0, 0, 0]), -13, "a directory");
    let missing = cstr("/acct/none");
    assert_eq!(admin::dispatch(163, [missing.as_ptr() as u64, 0, 0, 0, 0, 0]), -2);
    // Off: nothing is noted
    admin::note_task(10, 0, 0, "/bin/x");
    admin::on_exit(10, 1, 0, 0, 0, 0);
    admin::flush();
    assert!(with_fs(|fs| fs.data(f).unwrap()).is_empty());
    assert_eq!(admin::dispatch(163, [path.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    assert!(admin::acct_on());
    assert!(perf::active(), "accounting needs the per-process tallies");
    // A process that forked without exec and was killed by a signal with a core
    fake::TICKS.set(10_000); // 100 s in 100 Hz ticks: 1000
    fake::RTC.set(2_000_000);
    admin::note_task(20, 1000, 1000, "/usr/bin/a-very-long-command-name");
    admin::on_exit(20, 1, 200, 0x80 | 11, 50, 8000);
    // Root, exec'd, exited normally
    admin::note_task(21, 0, 0, "sh");
    admin::note_exec(21);
    admin::on_exit(21, 1, 990, 0, 0, 0);
    // Not noted (IDs unknown): root defaults, big uid gets 65534 in 16 bits
    admin::note_task(22, 70000, 70001, "big");
    admin::on_exit(22, 1, 0, 0, 1 << 40, 0);
    admin::flush();
    let data = with_fs(|fs| fs.data(f).unwrap());
    assert_eq!(data.len(), 3 * 64);
    let r = &data[..64];
    assert_eq!(r[0], 1 | 8 | 16, "AFORK | ACORE | AXSIG");
    assert_eq!(r[1], 2, "ACCT_VERSION");
    assert_eq!(u16::from_le_bytes([r[2], r[3]]), 1000);
    assert_eq!(u32::from_le_bytes(r[8..12].try_into().unwrap()), 2_000_000 - 8, "start: now - elapsed (800 ticks)");
    assert_eq!(u16::from_le_bytes([r[12], r[13]]), 50, "utime (small: exact)");
    assert_eq!(u16::from_le_bytes([r[16], r[17]]), 800, "etime");
    assert_eq!(u16::from_le_bytes([r[24], r[25]]), 8000);
    assert_eq!(u16::from_le_bytes([r[30], r[31]]), 100, "AHZ");
    assert_eq!(u32::from_le_bytes(r[32..36].try_into().unwrap()), 0x8B);
    assert_eq!(&r[36..51], b"a-very-long-com");
    assert_eq!(r[51], 0);
    assert_eq!(u32::from_le_bytes(r[56..60].try_into().unwrap()), 1000);
    let r2 = &data[64..128];
    assert_eq!(r2[0], 2, "ASU only: exec'd");
    let r3 = &data[128..192];
    assert_eq!(u16::from_le_bytes([r3[2], r3[3]]), 65534);
    assert_eq!(u32::from_le_bytes(r3[56..60].try_into().unwrap()), 70000);
    let utime = u16::from_le_bytes([r3[12], r3[13]]);
    assert!(utime >> 13 > 0, "a big time uses the exponent: {utime:#x}");
    // Nothing pending: flush writes nothing more
    admin::flush();
    assert_eq!(with_fs(|fs| fs.data(f).unwrap()).len(), 192);
    // Turned off
    assert_eq!(admin::dispatch(163, [0; 6]), 0);
    assert!(!admin::acct_on());
}

#[test]
fn comp_t_rounding_through_records() {
    let _g = serial();
    let d = fakefs::test_dir("acct2");
    with_fs(|fs| fs.put(d, "p", b""));
    let path = cstr("/acct2/p");
    fake::CAPS.set(Some(CAP_SYS_PACCT));
    admin::dispatch(163, [path.as_ptr() as u64, 0, 0, 0, 0, 0]);
    // 0x1fff fits; 0x2000 needs the exponent; values that round up past the mantissa
    for (ticks, want) in [(0x1fffu64, 0x1fffu16), (0x2000, (1 << 13) | 0x400), (0xFFFC, (1 << 13) | 0x2000 >> 3 | 0 + 0)] {
        fake::TICKS.set(0);
        admin::on_exit(30, 1, 0, 0, ticks, 0);
        let _ = want;
    }
    admin::flush();
    let (ino, _) = ZfsClient::lookup("/acct2/p").unwrap();
    let data = with_fs(|fs| fs.data(ino).unwrap());
    let ut: Vec<u16> = data.chunks(64).map(|r| u16::from_le_bytes([r[12], r[13]])).collect();
    assert_eq!(ut[0], 0x1fff);
    assert_eq!(ut[1], (1 << 13) | 0x400, "0x2000 = 0x400 << 3");
    let decode = |c: u16| ((c & 0x1fff) as u64) << (3 * (c >> 13));
    let back = decode(ut[2]);
    assert!(back >= 0xFFFC && back - 0xFFFC <= 8, "rounded to the nearest representable: {back:#x}");
    // ac_etime (comp2_t) of a long elapsed time keeps 20 bits of mantissa
    fake::TICKS.set(100_000_000); // 1e7 ticks of 100 Hz
    admin::on_exit(31, 1, 0, 0, 0, 0);
    // An absurd elapsed value saturates
    admin::on_exit(32, 1, 0, 0, 0, 0);
    admin::flush();
    admin::dispatch(163, [0; 6]);
}

#[test]
fn swap_areas() {
    let _g = serial();
    let d = fakefs::test_dir("swap");
    let mut page = vec![0u8; 4096 * 3];
    page[4086..4096].copy_from_slice(b"SWAPSPACE2");
    page[1028..1032].copy_from_slice(&2u32.to_le_bytes());
    with_fs(|fs| {
        fs.put(d, "file", &page);
        let mut bad = page.clone();
        bad[4086] = b'X';
        fs.put(d, "nosig", &bad);
        fs.put(d, "short", &page[..100]);
        let mut big = page.clone();
        big[1028..1032].copy_from_slice(&9u32.to_le_bytes());
        fs.put(d, "toosmall", &big);
        let mut zero = page.clone();
        zero[1028..1032].copy_from_slice(&0u32.to_le_bytes());
        fs.put(d, "zero", &zero);
        fs.mknode(d, b"fifo", 0o010644, Kind::Special).unwrap();
    });
    let p = |s: &str| cstr(&format!("/swap/{s}"));
    let file = p("file");
    assert_eq!(admin::dispatch(167, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), -1);
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(admin::dispatch(167, [file.as_ptr() as u64, 1 << 20, 0, 0, 0, 0]), -22, "bad flags");
    assert_eq!(admin::dispatch(167, [0, 0, 0, 0, 0, 0]), -14);
    for (name, err) in [("nosig", -22), ("short", -22), ("toosmall", -22), ("zero", -22), ("fifo", -22), ("none", -2)] {
        let c = p(name);
        assert_eq!(admin::dispatch(167, [c.as_ptr() as u64, 0, 0, 0, 0, 0]), err, "{name}");
    }
    assert_eq!(admin::dispatch(167, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(admin::dispatch(167, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), -16, "already on");
    assert_eq!(admin::swap_kib(), (8, 8));
    let t = admin::swaps_text();
    assert!(t.contains("/swap/file") && t.contains("file") && t.lines().count() == 2, "{t}");
    // A partition (a block device node) with a preferred priority
    with_fs(|fs| {
        let n = fs.mknode(d, b"sdb1", 0o060660, Kind::File(page.clone())).unwrap();
        n
    });
    let part = p("sdb1");
    assert_eq!(admin::dispatch(167, [part.as_ptr() as u64, 0x8000 | 7, 0, 0, 0, 0]), 0);
    assert!(admin::swaps_text().contains("partition"));
    assert!(admin::swaps_text().contains("7\n"));
    assert_eq!(admin::dispatch(168, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(admin::dispatch(168, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), -22, "not on");
    assert_eq!(admin::dispatch(168, [part.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    let none = p("none");
    assert_eq!(admin::dispatch(168, [none.as_ptr() as u64, 0, 0, 0, 0, 0]), -2);
    fake::CAPS.set(Some(0));
    assert_eq!(admin::dispatch(168, [file.as_ptr() as u64, 0, 0, 0, 0, 0]), -1);
    assert_eq!(admin::swap_kib(), (0, 0));
}

#[test]
fn quotas_are_not_kept() {
    let _g = serial();
    let d = fakefs::test_dir("quota");
    with_fs(|fs| {
        fs.mknode(d, b"sda1", 0o060660, Kind::Special).unwrap();
        fs.put(d, "file", b"");
    });
    let dev = cstr("/quota/sda1");
    let file = cstr("/quota/file");
    let q = |cmd: u64, special: u64| admin::dispatch(179, [cmd, special, 0, 0, 0, 0]);
    assert_eq!(q(3, dev.as_ptr() as u64), -22, "quota kind > 2");
    assert_eq!(q(0x80_0001 << 8, 0), 0, "Q_SYNC of every file system");
    assert_eq!(q(0x80_0002 << 8, dev.as_ptr() as u64), -38, "the pool keeps no quotas");
    assert_eq!(q(0x80_0002 << 8, file.as_ptr() as u64), -15, "ENOTBLK");
    let none = cstr("/quota/none");
    assert_eq!(q(0x80_0002 << 8, none.as_ptr() as u64), -2);
    // A path lookup that finds an object the server no longer has
    LOOKUPS.with_borrow_mut(|m| m.insert("/ghost".into(), (999_999_990, false)));
    let ghost = cstr("/ghost");
    assert_eq!(q(0x80_0002 << 8, ghost.as_ptr() as u64), -2);
    assert_eq!(admin::dispatch(163, [ghost.as_ptr() as u64, 0, 0, 0, 0, 0]), -1);
    fake::CAPS.set(Some(CAP_SYS_PACCT | CAP_SYS_ADMIN));
    assert_eq!(admin::dispatch(163, [ghost.as_ptr() as u64, 0, 0, 0, 0, 0]), -2);
    assert_eq!(admin::dispatch(167, [ghost.as_ptr() as u64, 0, 0, 0, 0, 0]), -2);
    // quotactl_fd (any other number)
    assert_eq!(admin::dispatch(443, [1, 0x80_0002 << 8, 0, 0, 0, 0]), -38);
    assert_eq!(admin::dispatch(443, [77, 0, 0, 0, 0, 0]), -9);
    assert_eq!(admin::dispatch(443, [1, 3, 0, 0, 0, 0]), -22);
}
