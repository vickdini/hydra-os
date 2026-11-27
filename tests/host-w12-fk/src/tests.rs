//! Group FK's host tests (wave 12): the FreeBSD personality's pure parts.

use crate::personality::abi;
use crate::personality::fbsd_tmp as tmp;
use crate::personality::fbsd_xlat::*;

// --- the table's data ------------------------------------------------------

#[test]
fn names_sorted_unique_and_complete() {
    assert_eq!(NAMES.len(), 411, "FreeBSD 15.1's live calls (STD/NOSTD + the two SYSMUX)");
    for w in NAMES.windows(2) {
        assert!(w[0].0 < w[1].0, "sorted and unique: {:?} {:?}", w[0], w[1]);
    }
    assert_eq!(name(0), Some("syscall"));
    assert_eq!(name(454), Some("_umtx_op"));
    assert_eq!(name(455), Some("thr_new"));
    assert_eq!(name(570), Some("__sysctlbyname"));
    assert_eq!(name(602), Some("renameat2"));
    assert_eq!(name(8), None, "old creat: not live");
    assert_eq!(name(999), None);
}

#[test]
fn direct_calls_are_live_and_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for (f, l) in DIRECT {
        assert!(name(f as u64).is_some(), "D call {} is a live FreeBSD call", f);
        assert!(seen.insert(f), "D call {} listed once", f);
        assert!(l < 460, "Linux number {} plausible", l);
    }
    // The FreeBSD numbers that differ from Linux's are the point of the table
    let get = |f: u16| DIRECT.iter().find(|d| d.0 == f).map(|d| d.1);
    assert_eq!(get(39), Some(110), "FreeBSD getppid 39 is Linux getppid 110 (Linux 39 is getpid)");
    assert_eq!(get(1), Some(231), "_exit ends the process");
    assert_eq!(get(475), Some(17), "pread");
    assert_eq!(get(478), Some(8), "lseek");
    assert_eq!(get(595), Some(115), "FreeBSD 15's getgroups");
    assert_eq!(get(5), None, "open translates flags: not direct");
    assert_eq!(get(477), None, "mmap translates flags: not direct");
}

// --- open, AT_*, fcntl -----------------------------------------------------

#[test]
fn open_flags_translate() {
    assert_eq!(open_flags(0), lo::LARGEFILE);
    assert_eq!(open_flags(2), 2 | lo::LARGEFILE, "O_RDWR stays");
    let f = o::CREAT | o::TRUNC | o::EXCL | 1;
    assert_eq!(open_flags(f), lo::CREAT | lo::TRUNC | lo::EXCL | 1 | lo::LARGEFILE);
    assert_eq!(open_flags(o::CLOEXEC) & lo::CLOEXEC, lo::CLOEXEC);
    assert_eq!(open_flags(o::NONBLOCK | o::APPEND), lo::NONBLOCK | lo::APPEND | lo::LARGEFILE);
    assert_eq!(open_flags(o::DIRECTORY | o::NOFOLLOW), lo::DIRECTORY | lo::NOFOLLOW | lo::LARGEFILE);
    assert_eq!(open_flags(o::FSYNC), lo::SYNC | lo::LARGEFILE);
    assert_eq!(open_flags(o::NOCTTY), lo::NOCTTY | lo::LARGEFILE);
    // O_EXEC/O_SEARCH without access: O_PATH; with write access it is dropped
    assert_eq!(open_flags(o::EXEC) & lo::PATH, lo::PATH);
    assert_eq!(open_flags(o::EXEC | 1) & lo::PATH, 0);
    // No FreeBSD bit leaks through as an unrelated Linux bit
    assert_eq!(open_flags(o::SHLOCK | o::EXLOCK | o::TTY_INIT | o::VERIFY | o::RESOLVE_BENEATH), lo::LARGEFILE);
}

#[test]
fn getfl_flags_translate_back() {
    for f in [0, 1, 2, o::NONBLOCK, o::APPEND, o::NONBLOCK | o::APPEND | 2, o::DIRECTORY, o::CLOEXEC, o::FSYNC] {
        assert_eq!(open_flags_to_fbsd(open_flags(f)), f, "round trip of {:#x}", f);
    }
    // Linux's O_SYNC contains O_DSYNC: reported as FreeBSD's O_FSYNC (and O_DSYNC)
    assert_eq!(open_flags_to_fbsd(lo::SYNC) & o::FSYNC, o::FSYNC);
}

#[test]
fn at_flags_translate() {
    assert_eq!(at_flags(at::SYMLINK_NOFOLLOW), 0x100);
    assert_eq!(at_flags(at::EACCESS), 0x200);
    assert_eq!(at_flags(at::REMOVEDIR), 0x200);
    assert_eq!(at_flags(at::SYMLINK_FOLLOW), 0x400);
    assert_eq!(at_flags(at::EMPTY_PATH), 0x1000);
    assert_eq!(at_flags(at::RESOLVE_BENEATH), 0);
    assert_eq!(at_fd(0xFFFF_FF9C), (-100i64) as u64, "AT_FDCWD as a 32-bit int");
    assert_eq!(at_fd(3), 3);
}

#[test]
fn fcntl_commands() {
    assert_eq!(fcntl_cmd(1), Fcntl::Linux { cmd: 1, setfl: false, getfl: false });
    assert_eq!(fcntl_cmd(3), Fcntl::Linux { cmd: 3, setfl: false, getfl: true });
    assert_eq!(fcntl_cmd(4), Fcntl::Linux { cmd: 4, setfl: true, getfl: false });
    assert_eq!(fcntl_cmd(17), Fcntl::Linux { cmd: 1030, setfl: false, getfl: false }, "F_DUPFD_CLOEXEC");
    assert_eq!(fcntl_cmd(10), Fcntl::Dup2 { cloexec: false });
    assert_eq!(fcntl_cmd(18), Fcntl::Dup2 { cloexec: true });
    assert_eq!(fcntl_cmd(21), Fcntl::Zero, "F_ISUNIONSTACK");
    for lock in [11, 12, 13, 14, 22] {
        assert_eq!(fcntl_cmd(lock), Fcntl::Unsupported, "locks and F_KINFO are stage 2's ({})", lock);
    }
}

// --- mmap and friends ------------------------------------------------------

#[test]
fn mmap_anonymous_private_and_shared() {
    let p = mmap_plan(3, map::ANON | map::PRIVATE, u64::MAX).unwrap();
    assert_eq!(p, MmapPlan { flags: lmap::ANON | lmap::PRIVATE, prot: 3, align: 0 });
    let p = mmap_plan(1, map::SHARED, 5).unwrap();
    assert_eq!(p.flags, lmap::SHARED);
    // Anonymous without either: private
    assert_eq!(mmap_plan(3, map::ANON, 0xFFFF_FFFF).unwrap().flags, lmap::ANON | lmap::PRIVATE);
    // A file mapping needs one of them; anonymous needs no descriptor
    assert!(mmap_plan(1, 0, 5).is_err());
    assert!(mmap_plan(3, map::ANON | map::PRIVATE, 5).is_err());
    assert!(mmap_plan(3, map::SHARED | map::PRIVATE, 5).is_err());
    // PROT_MAX bits are dropped
    assert_eq!(mmap_plan(3 | (7 << 16), map::ANON | map::PRIVATE, u64::MAX).unwrap().prot, 3);
}

#[test]
fn mmap_stack_guard_excl() {
    // libthr: MAP_STACK alone, read-write, no descriptor
    let p = mmap_plan(3, map::STACK, u64::MAX).unwrap();
    assert_eq!(p.flags & (lmap::ANON | lmap::PRIVATE), lmap::ANON | lmap::PRIVATE);
    assert!(mmap_plan(1, map::STACK, u64::MAX).is_err(), "MAP_STACK must be read-write");
    assert!(mmap_plan(3, map::STACK, 4).is_err(), "MAP_STACK takes no descriptor");
    // MAP_GUARD: PROT_NONE, no descriptor, a reservation
    let g = mmap_plan(0, map::GUARD, u64::MAX).unwrap();
    assert_eq!(g, MmapPlan { flags: lmap::PRIVATE | lmap::ANON | lmap::NORESERVE, prot: 0, align: 0 });
    assert!(mmap_plan(1, map::GUARD, u64::MAX).is_err());
    assert!(mmap_plan(0, map::GUARD | map::ANON, u64::MAX).is_err());
    assert_eq!(mmap_plan(0, map::GUARD | map::FIXED | map::EXCL, u64::MAX).unwrap().flags & lmap::FIXED_NOREPLACE, lmap::FIXED_NOREPLACE);
    // MAP_EXCL only with MAP_FIXED, as MAP_FIXED_NOREPLACE
    assert!(mmap_plan(3, map::ANON | map::EXCL, u64::MAX).is_err());
    let e = mmap_plan(3, map::ANON | map::FIXED | map::EXCL, u64::MAX).unwrap();
    assert_eq!(e.flags & (lmap::FIXED | lmap::FIXED_NOREPLACE), lmap::FIXED_NOREPLACE);
    assert_eq!(mmap_plan(3, map::ANON | map::FIXED, u64::MAX).unwrap().flags & lmap::FIXED, lmap::FIXED);
    assert_eq!(mmap_plan(3, map::ANON | map::MAP_32BIT, u64::MAX).unwrap().flags & lmap::MAP_32BIT, lmap::MAP_32BIT);
}

#[test]
fn mmap_aligned() {
    let p = mmap_plan(3, map::ANON | (21 << map::ALIGNMENT_SHIFT), u64::MAX).unwrap();
    assert_eq!(p.align, 21);
    assert_eq!(mmap_plan(3, map::ANON | (map::ALIGNED_SUPER << map::ALIGNMENT_SHIFT), u64::MAX).unwrap().align, 21);
    assert!(mmap_plan(3, map::ANON | (5 << map::ALIGNMENT_SHIFT), u64::MAX).is_err(), "below a page");
    assert_eq!(mmap_plan(3, map::ANON | map::FIXED | (21 << map::ALIGNMENT_SHIFT), u64::MAX).unwrap().align, 0, "fixed: no alignment of ours");
    assert_eq!(aligned_start(0x7f00_0010_1000, 21), 0x7f00_0020_0000);
    assert_eq!(aligned_start(0x7f00_0020_0000, 21), 0x7f00_0020_0000);
}

#[test]
fn madvise_minherit_msync() {
    assert_eq!(madvise(4), Some(Ok(4)), "DONTNEED");
    assert_eq!(madvise(5), Some(Ok(8)), "FREE");
    assert_eq!(madvise(8), Some(Ok(16)), "NOCORE -> DONTDUMP");
    assert_eq!(madvise(9), Some(Ok(17)));
    assert_eq!(madvise(6), None, "NOSYNC: a no-op");
    assert_eq!(madvise(99), Some(Err(())));
    assert_eq!(minherit(3), Ok(18), "INHERIT_ZERO -> MADV_WIPEONFORK");
    assert_eq!(minherit(2), Ok(10));
    assert_eq!(minherit(1), Ok(11));
    assert!(minherit(0).is_err());
    assert_eq!(msync_flags(0), 4, "MS_SYNC");
    assert_eq!(msync_flags(1), 1, "MS_ASYNC");
    assert_eq!(msync_flags(2), 2 | 4, "MS_INVALIDATE (synchronously)");
}

// --- clocks, limits, waits ---------------------------------------------------

#[test]
fn clock_ids() {
    assert_eq!(clock_id(0), Some((0, false)));
    assert_eq!(clock_id(4), Some((1, false)), "MONOTONIC 4 -> 1");
    assert_eq!(clock_id(5), Some((7, false)), "UPTIME -> BOOTTIME");
    assert_eq!(clock_id(12), Some((6, false)));
    assert_eq!(clock_id(13), Some((0, true)), "SECOND: whole seconds");
    assert_eq!(clock_id(14), Some((3, false)));
    assert_eq!(clock_id(15), Some((2, false)));
    assert_eq!(clock_id(1), None, "VIRTUAL");
    assert_eq!(clock_id(0xFFFF_FFFF), None);
}

#[test]
fn rlimits() {
    assert_eq!(rlimit_resource(8), Some(7), "NOFILE");
    assert_eq!(rlimit_resource(7), Some(6), "NPROC");
    assert_eq!(rlimit_resource(6), Some(8), "MEMLOCK");
    assert_eq!(rlimit_resource(10), Some(9), "AS");
    assert_eq!(rlimit_resource(3), Some(3));
    assert_eq!(rlimit_resource(9), None);
    assert_eq!(rlim_to_fbsd(u64::MAX), FBSD_RLIM_INFINITY);
    assert_eq!(rlim_to_fbsd(1024), 1024);
    assert_eq!(rlim_from_fbsd(FBSD_RLIM_INFINITY), u64::MAX);
    assert_eq!(rlim_from_fbsd(8 << 20), 8 << 20);
    assert_eq!(sched_policy(2), Some(0));
    assert_eq!(sched_policy_to_fbsd(0), 2);
    assert_eq!(sched_policy_to_fbsd(2), 3);
}

#[test]
fn wait_options_and_status() {
    assert_eq!(wait_options(1), 1);
    assert_eq!(wait_options(2), 2);
    assert_eq!(wait_options(4), 8, "WCONTINUED");
    assert_eq!(wait_options(8), 0x0100_0000, "WNOWAIT");
    assert_eq!(wait_options(16), 4, "WEXITED");
    assert_eq!(wait_status(3 << 8), 3 << 8, "exit 3");
    assert_eq!(wait_status(10), 30, "killed by SIGUSR1 (Linux 10, FreeBSD 30)");
    assert_eq!(wait_status(11 | 0x80), 11 | 0x80, "SIGSEGV with a core");
    assert_eq!(wait_status((19 << 8) | 0x7f), (17 << 8) | 0x7f, "stopped by SIGSTOP (Linux 19, FreeBSD 17)");
    assert_eq!(wait_status(0xffff), 0x13, "continued");
}

// --- signals -------------------------------------------------------------

#[test]
fn signal_sets_round_trip() {
    for sigs in [vec![1u32], vec![10, 12], vec![17], vec![34, 64], (1..=64).filter(|s| *s != 32 && *s != 33).collect()] {
        let mask = sigs.iter().fold(0u64, |m, s| m | 1 << (s - 1));
        assert_eq!(mask_from_freebsd(&mask_to_freebsd(mask)), mask, "{:?}", sigs);
    }
    // SIGUSR1 is bit 29 (signal 30) of FreeBSD's set
    let b = mask_to_freebsd(1 << 9);
    assert_eq!(b[3], 0x20);
    assert_eq!(sigprocmask_how(1), Some(0));
    assert_eq!(sigprocmask_how(3), Some(2));
    assert_eq!(sigprocmask_how(0), None);
}

#[test]
fn stack_t_translates() {
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&0x1234_5000u64.to_le_bytes());
    b[8..16].copy_from_slice(&65536u64.to_le_bytes());
    b[16..20].copy_from_slice(&4u32.to_le_bytes()); // SS_DISABLE
    let l = stack_to_linux(&b);
    assert_eq!(u64::from_le_bytes(l[0..8].try_into().unwrap()), 0x1234_5000);
    assert_eq!(u32::from_le_bytes(l[8..12].try_into().unwrap()), 2, "Linux SS_DISABLE");
    assert_eq!(u64::from_le_bytes(l[16..24].try_into().unwrap()), 65536);
    assert_eq!(stack_to_fbsd(&l), b);
}

#[test]
fn siginfo_translates() {
    let mut l = [0u8; 128];
    l[0..4].copy_from_slice(&10i32.to_le_bytes()); // SIGUSR1
    l[8..12].copy_from_slice(&(-1i32).to_le_bytes()); // SI_QUEUE
    l[16..20].copy_from_slice(&77i32.to_le_bytes());
    l[20..24].copy_from_slice(&1000i32.to_le_bytes());
    l[24..32].copy_from_slice(&0xabcdu64.to_le_bytes());
    let b = siginfo_to_fbsd(&l);
    assert_eq!(i32::from_le_bytes(b[0..4].try_into().unwrap()), 30);
    assert_eq!(i32::from_le_bytes(b[8..12].try_into().unwrap()), si::QUEUE);
    assert_eq!(i32::from_le_bytes(b[12..16].try_into().unwrap()), 77);
    assert_eq!(i32::from_le_bytes(b[16..20].try_into().unwrap()), 1000);
    assert_eq!(u64::from_le_bytes(b[32..40].try_into().unwrap()), 0xabcd);
    // A fault: the address
    let mut l = [0u8; 128];
    l[0..4].copy_from_slice(&11i32.to_le_bytes());
    l[8..12].copy_from_slice(&1i32.to_le_bytes()); // SEGV_MAPERR
    l[16..24].copy_from_slice(&0xdead_0000u64.to_le_bytes());
    let b = siginfo_to_fbsd(&l);
    assert_eq!(u64::from_le_bytes(b[24..32].try_into().unwrap()), 0xdead_0000);
    // SIGCHLD killed by SIGTERM: the signal translated (15 is the same), stopped by SIGTSTP
    let mut l = [0u8; 128];
    l[0..4].copy_from_slice(&17i32.to_le_bytes());
    l[8..12].copy_from_slice(&5i32.to_le_bytes()); // CLD_STOPPED
    l[24..28].copy_from_slice(&20i32.to_le_bytes()); // SIGTSTP
    let b = siginfo_to_fbsd(&l);
    assert_eq!(i32::from_le_bytes(b[0..4].try_into().unwrap()), 20, "SIGCHLD is FreeBSD 20");
    assert_eq!(i32::from_le_bytes(b[20..24].try_into().unwrap()), 18, "SIGTSTP is FreeBSD 18");
    assert_eq!(si_code_to_fbsd(0), si::USER);
    assert_eq!(si_code_to_fbsd(-6), si::LWP);
    assert_eq!(si_code_to_fbsd(0x80), si::KERNEL);
}

// --- ucontext ------------------------------------------------------------

#[test]
fn mcontext_layout_and_round_trip() {
    let m = Mcontext {
        onstack: 1,
        gprs: core::array::from_fn(|i| 0x1000 + i as u64),
        rip: 0x40_1234,
        cs: 0x33,
        rflags: 0x246,
        rsp: 0x7fff_0000,
        ss: 0x2b,
        fsbase: 0x8000_1000,
        flags: 0,
    };
    let mut fx = [0u8; 512];
    for (i, b) in fx.iter_mut().enumerate() {
        *b = i as u8;
    }
    fx[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR
    let mut out = [0u8; MC_LEN];
    m.pack(Some(&fx), &mut out);
    let at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
    // FreeBSD's offsets (sys/x86/include/ucontext.h)
    assert_eq!(at(0), 1, "mc_onstack");
    assert_eq!(at(8), 0x1000, "mc_rdi");
    assert_eq!(at(56), 0x1006, "mc_rax");
    assert_eq!(at(120), 0x100e, "mc_r15");
    assert_eq!(at(160), 0x40_1234, "mc_rip");
    assert_eq!(at(168), 0x33, "mc_cs");
    assert_eq!(at(176), 0x246, "mc_rflags");
    assert_eq!(at(184), 0x7fff_0000, "mc_rsp");
    assert_eq!(at(192), 0x2b, "mc_ss");
    assert_eq!(at(200), 800, "mc_len");
    assert_eq!(at(208), FPFMT_XMM);
    assert_eq!(at(216), FPOWNED_FPU);
    assert_eq!(&out[224..736], &fx[..]);
    assert_eq!(at(736), 0x8000_1000, "mc_fsbase");
    assert_eq!(at(768), 0x8000_1000, "mc_tlsbase");
    let fl = u32::from_le_bytes(out[144..148].try_into().unwrap());
    assert_eq!(fl & (MC_HASBASES | MC_HASTLSBASE), MC_HASBASES | MC_HASTLSBASE);
    let (back, f2) = Mcontext::unpack(&out).unwrap();
    assert_eq!(back.gprs, m.gprs);
    assert_eq!((back.rip, back.rsp, back.rflags, back.fsbase), (m.rip, m.rsp, m.rflags, m.fsbase));
    assert_eq!(f2.unwrap()[..], fx[..]);
    // A wrong mc_len: EINVAL; no FPU state: none
    let mut bad = out;
    bad[200..208].copy_from_slice(&0u64.to_le_bytes());
    assert!(Mcontext::unpack(&bad).is_err());
    let mut nofp = [0u8; MC_LEN];
    m.pack(None, &mut nofp);
    assert!(Mcontext::unpack(&nofp).unwrap().1.is_none());
    // MXCSR's reserved bits are cleared on the way back (FXRSTOR would fault)
    let mut hostile = out;
    hostile[224 + 24..224 + 28].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    let f3 = Mcontext::unpack(&hostile).unwrap().1.unwrap();
    assert_eq!(u32::from_le_bytes(f3[24..28].try_into().unwrap()), 0xffff);
    // User flags: IF stays set, IOPL cleared
    assert_eq!(Mcontext::user_rflags(0x3000), 0x202);
    assert_eq!(Mcontext::user_rflags(0x1), 0x203, "carry kept");
    assert_eq!((UC_MCONTEXT, UC_LINK, UC_STACK, UC_FLAGS, UC_LEN), (16, 816, 824, 848, 880));
}

// --- _umtx_op ------------------------------------------------------------

#[test]
fn umtx_timeouts() {
    use umtx::*;
    assert_eq!(timeout_len(0), 16);
    assert_eq!(timeout_len(16), 16);
    assert_eq!(timeout_len(24), 24);
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&2i64.to_le_bytes());
    b[8..16].copy_from_slice(&500i64.to_le_bytes());
    assert_eq!(parse_timeout(&b[..16]).unwrap(), Timeout { sec: 2, nsec: 500, abs: false, clock: 0 });
    b[16..20].copy_from_slice(&UMTX_ABSTIME.to_le_bytes());
    b[20..24].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(parse_timeout(&b).unwrap(), Timeout { sec: 2, nsec: 500, abs: true, clock: 4 });
    b[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
    assert!(parse_timeout(&b).is_err());
    assert!(clock_is_realtime(0) && !clock_is_realtime(4) && !clock_is_realtime(5));
}

#[test]
fn umtx_mutex_words() {
    use umtx::*;
    assert!(mutex_wait_done(UMUTEX_UNOWNED));
    assert!(mutex_wait_done(UMUTEX_CONTESTED));
    assert!(mutex_wait_done(UMUTEX_RB_OWNERDEAD));
    assert!(!mutex_wait_done(100));
    assert!(!mutex_wait_done(100 | UMUTEX_CONTESTED));
    assert_eq!(unlock_value(0, 0), UMUTEX_UNOWNED);
    assert_eq!(unlock_value(0, 1), UMUTEX_UNOWNED, "the one waiter takes it");
    assert_eq!(unlock_value(0, 2), UMUTEX_CONTESTED, "others still wait");
    assert_eq!(unlock_value(UMUTEX_ROBUST | UMUTEX_NONCONSISTENT, 0), UMUTEX_RB_NOTRECOV);
}

#[test]
fn umtx_rwlock_words() {
    use umtx::*;
    assert_eq!(rd_block_mask(0, 0), URWLOCK_WRITE_OWNER | URWLOCK_WRITE_WAITERS);
    assert_eq!(rd_block_mask(URWLOCK_PREFER_READER as u64, 0), URWLOCK_WRITE_OWNER);
    assert_eq!(rd_block_mask(0, URWLOCK_PREFER_READER), URWLOCK_WRITE_OWNER);
    assert_eq!(rw_unlocked(URWLOCK_WRITE_OWNER | URWLOCK_READ_WAITERS), Ok(URWLOCK_READ_WAITERS));
    assert_eq!(rw_unlocked(3), Ok(2));
    assert!(rw_unlocked(URWLOCK_READ_WAITERS).is_err(), "not held: EPERM");
    assert_eq!(rw_unlock_wakes(URWLOCK_WRITE_WAITERS | URWLOCK_READ_WAITERS, 0), Some((true, 1)), "writers first");
    assert_eq!(rw_unlock_wakes(URWLOCK_WRITE_WAITERS | URWLOCK_READ_WAITERS, URWLOCK_PREFER_READER), Some((false, usize::MAX)));
    assert_eq!(rw_unlock_wakes(URWLOCK_READ_WAITERS, 0), Some((false, usize::MAX)));
    assert_eq!(rw_unlock_wakes(0, 0), None);
    assert_eq!(readers(URWLOCK_WRITE_WAITERS | 5), 5);
}

#[test]
fn umtx_struct_offsets_match_freebsd() {
    use umtx::*;
    // struct umutex { m_owner; m_flags; ... }, struct ucond { c_has_waiters; c_flags;
    // c_clockid }, struct urwlock { rw_state; rw_flags; rw_blocked_readers;
    // rw_blocked_writers }, struct _usem2 { _count; _flags }
    assert_eq!((M_OWNER, M_FLAGS), (0, 4));
    assert_eq!((C_HAS_WAITERS, C_FLAGS, C_CLOCKID), (0, 4, 8));
    assert_eq!((RW_STATE, RW_FLAGS, RW_BLOCKED_READERS, RW_BLOCKED_WRITERS), (0, 4, 8, 12));
    assert_eq!((SEM_COUNT, SEM_FLAGS), (0, 4));
    assert_eq!((OP_WAIT, OP_WAKE, OP_MUTEX_WAIT, OP_NWAKE_PRIVATE, OP_MUTEX_WAKE2, OP_SEM2_WAIT, OP_SEM2_WAKE), (2, 3, 17, 21, 22, 23, 24));
}

// --- device numbers --------------------------------------------------------

#[test]
fn dev_t_round_trip() {
    // Linux makedev(4, 1) (tty1), (136, 3) (pts/3), a big one
    for (maj, min) in [(4u64, 1u64), (136, 3), (259, 0x12345), (0x1234, 0xabcde)] {
        let l = ((maj & 0xfff) << 8) | ((maj & !0xfff) << 32) | (min & 0xff) | ((min & !0xff) << 12);
        let f = dev_to_fbsd(l);
        let fmaj = ((f >> 32) & 0xffff_ff00) | ((f >> 8) & 0xff);
        let fmin = ((f >> 24) & 0xff00) | (f & 0xffff_00ff);
        assert_eq!((fmaj, fmin), (maj, min), "FreeBSD's major()/minor() of {}:{}", maj, min);
        assert_eq!(dev_from_fbsd(f), l);
    }
}

// --- temporary: stat, dirent, statfs, sysctl --------------------------------

#[test]
fn stat_from_linux_layout() {
    let mut l = [0u8; 144];
    let put = |l: &mut [u8; 144], o: usize, v: &[u8]| l[o..o + v.len()].copy_from_slice(v);
    put(&mut l, 0, &((8u64 << 8) | 1).to_le_bytes()); // st_dev 8:1
    put(&mut l, 8, &4242u64.to_le_bytes());
    put(&mut l, 16, &3u64.to_le_bytes());
    put(&mut l, 24, &0o100755u32.to_le_bytes());
    put(&mut l, 28, &1000u32.to_le_bytes());
    put(&mut l, 32, &100u32.to_le_bytes());
    put(&mut l, 48, &12345u64.to_le_bytes()); // size
    put(&mut l, 56, &4096u64.to_le_bytes()); // blksize
    put(&mut l, 64, &24u64.to_le_bytes()); // blocks
    put(&mut l, 72, &1_700_000_001u64.to_le_bytes()); // atime
    put(&mut l, 88, &1_700_000_002u64.to_le_bytes()); // mtime
    put(&mut l, 104, &1_700_000_003u64.to_le_bytes()); // ctime
    let b = tmp::stat_from_linux(&l);
    assert_eq!(b.len(), 224);
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    assert_eq!(u64_at(8), 4242, "st_ino");
    assert_eq!(u64_at(16), 3, "st_nlink");
    assert_eq!(u16::from_le_bytes([b[24], b[25]]), 0o100755, "st_mode");
    assert_eq!(u32_at(28), 1000, "st_uid");
    assert_eq!(u32_at(32), 100, "st_gid");
    assert_eq!(u64_at(48), 1_700_000_001, "st_atim");
    assert_eq!(u64_at(64), 1_700_000_002, "st_mtim");
    assert_eq!(u64_at(80), 1_700_000_003, "st_ctim");
    assert_eq!(u64_at(96), 1_700_000_003, "st_birthtim: the change time");
    assert_eq!(u64_at(112), 12345, "st_size");
    assert_eq!(u64_at(120), 24, "st_blocks");
    assert_eq!(u32_at(128), 4096, "st_blksize");
    assert_eq!(u64_at(0), dev_to_fbsd((8 << 8) | 1));
}

fn linux_dirent(ino: u64, off: u64, ty: u8, name: &str) -> Vec<u8> {
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
fn dirents_from_linux_records() {
    let names = [".", "..", "bin", "a-much-longer-file-name.txt", "x"];
    let mut l = Vec::new();
    for (i, n) in names.iter().enumerate() {
        l.extend(linux_dirent(100 + i as u64, (i + 1) as u64 * 10, if i < 3 { 4 } else { 8 }, n));
    }
    let mut out = Vec::new();
    let (used, last) = tmp::dirents_from_linux(&l, &mut out, 4096);
    assert_eq!(used, l.len());
    assert_eq!(last, Some(50));
    let mut p = 0;
    for (i, n) in names.iter().enumerate() {
        let reclen = u16::from_le_bytes([out[p + 16], out[p + 17]]) as usize;
        assert_eq!(reclen, tmp::fbsd_dirsiz(n.len()));
        assert_eq!(reclen % 8, 0);
        assert_eq!(u64::from_le_bytes(out[p..p + 8].try_into().unwrap()), 100 + i as u64, "d_fileno");
        assert_eq!(u64::from_le_bytes(out[p + 8..p + 16].try_into().unwrap()), (i + 1) as u64 * 10, "d_off");
        assert_eq!(u16::from_le_bytes([out[p + 20], out[p + 21]]) as usize, n.len(), "d_namlen");
        assert_eq!(&out[p + 24..p + 24 + n.len()], n.as_bytes());
        assert_eq!(out[p + 24 + n.len()], 0, "NUL-terminated");
        p += reclen;
    }
    assert_eq!(p, out.len());
    // A small output buffer: whole records only
    let mut small = Vec::new();
    let (used, _) = tmp::dirents_from_linux(&l, &mut small, 70);
    assert_eq!(small.len(), 64, "two 32-byte records fit in 70");
    assert_eq!(used, linux_dirent(0, 0, 0, ".").len() + linux_dirent(0, 0, 0, "..").len());
}

#[test]
fn dirent_budget_always_fits() {
    // The worst case: Linux 24-byte records that become 32-byte FreeBSD ones
    for nbytes in [512usize, 4096, 8192, 65536] {
        let ask = tmp::linux_dirent_budget(nbytes);
        let mut l = Vec::new();
        while l.len() + 24 <= ask {
            l.extend(linux_dirent(1, 1, 8, "abcd"));
        }
        let mut out = Vec::new();
        let (used, _) = tmp::dirents_from_linux(&l, &mut out, nbytes);
        assert_eq!(used, l.len(), "every record converted for nbytes {}", nbytes);
        assert!(out.len() <= nbytes);
    }
}

#[test]
fn statfs_from_linux_layout() {
    let mut l = [0u8; 120];
    let put = |l: &mut [u8; 120], o: usize, v: u64| l[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut l, 0, 0x2fc1_2fc1); // ZFS
    put(&mut l, 8, 131072);
    put(&mut l, 16, 1000);
    put(&mut l, 24, 600);
    put(&mut l, 32, 500);
    put(&mut l, 40, 77);
    put(&mut l, 48, 66);
    put(&mut l, 64, 255);
    put(&mut l, 72, 4096);
    put(&mut l, 80, 1 | 8); // ST_RDONLY | ST_NOEXEC
    let mut out = vec![0u8; tmp::FBSD_STATFS];
    tmp::statfs_from_linux(&l, &mut out);
    let at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
    assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 0x2014_0518, "f_version");
    assert_eq!(at(8) & 0x1 , 1, "MNT_RDONLY");
    assert_eq!(at(8) & 0x4, 4, "MNT_NOEXEC (rtld refuses libraries there)");
    assert_eq!(at(16), 4096, "f_bsize: the fragment size");
    assert_eq!(at(24), 131072, "f_iosize");
    assert_eq!((at(32), at(40), at(48), at(56), at(64)), (1000, 600, 500, 77, 66));
    assert_eq!(u32::from_le_bytes(out[184..188].try_into().unwrap()), 255, "f_namemax");
    assert_eq!(&out[280..284], b"zfs\0");
    // A file system mounted without NOEXEC must not look NOEXEC
    put(&mut l, 80, 0);
    let mut out2 = vec![0u8; tmp::FBSD_STATFS];
    tmp::statfs_from_linux(&l, &mut out2);
    assert_eq!(u64::from_le_bytes(out2[8..16].try_into().unwrap()) & 0x4, 0);
}

#[test]
fn sysctl_nodes() {
    use tmp::Node;
    assert_eq!(tmp::sysctl_oid(&[1, 24]), Some(Node::Osreldate));
    assert_eq!(tmp::sysctl_oid(&[1, 37]), Some(Node::Arandom));
    assert_eq!(tmp::sysctl_oid(&[1, 33]), Some(Node::Usrstack));
    assert_eq!(tmp::sysctl_oid(&[6, 3]), Some(Node::Ncpu));
    assert_eq!(tmp::sysctl_oid(&[6, 7]), Some(Node::Pagesize));
    assert_eq!(tmp::sysctl_oid(&[2, 12]), Some(Node::Overcommit));
    assert_eq!(tmp::sysctl_oid(&[1, 14, 40, 1234]), Some(Node::ProcOsrel));
    assert_eq!(tmp::sysctl_oid(&[1, 99]), None);
    assert_eq!(tmp::sysctl_name(b"hw.pagesizes\0"), Some((&[6u32, 0x1000][..], Node::Pagesizes)));
    assert_eq!(tmp::sysctl_name(b"kern.smp.cpus").map(|n| n.1), Some(Node::Ncpu));
    assert_eq!(tmp::sysctl_name(b"kern.sched.cpusetsizemin").map(|n| n.1), Some(Node::Cpusetsizemin));
    assert_eq!(tmp::sysctl_name(b"vm.overcommit").map(|n| n.1), Some(Node::Overcommit));
    assert_eq!(tmp::sysctl_name(b"kern.nope"), None);
    // Every name's OID leads back to it
    for (name, oid, node) in tmp::NODES {
        assert_eq!(tmp::sysctl_oid(oid), Some(*node), "{}", name);
        assert_eq!(tmp::sysctl_name(name.as_bytes()).map(|n| n.1), Some(*node));
    }
    assert_eq!(tmp::sysctl_const(Node::Ostype), Some(&b"FreeBSD\0"[..]));
    assert_eq!(tmp::sysctl_fit(4, None), (0, false));
    assert_eq!(tmp::sysctl_fit(4, Some(8)), (4, false));
    assert_eq!(tmp::sysctl_fit(24, Some(8)), (8, true), "a short buffer: what fits and ENOMEM");
}

// --- abi.rs additions ------------------------------------------------------

#[test]
fn thread_start_code() {
    // mov %r13,%rdi; xor %ebp,%ebp; jmp *%r12
    assert_eq!(abi::FREEBSD_THR_START, [0x4C, 0x89, 0xEF, 0x31, 0xED, 0x41, 0xFF, 0xE4]);
    assert!(abi::FREEBSD_THR_START_ADDR >= abi::FREEBSD_SIGCODE_ADDR + abi::FREEBSD_SIGCODE.len() as u64);
    assert!(abi::FREEBSD_THR_START_ADDR + 8 <= abi::FREEBSD_SIGCODE_ADDR + 4096, "on the same page");
}
