//! Tests for restart support (wave 6, Group 21): the restart classes and the ladder
//! (`src/lx/restart_policy.rs`), the idempotent marks, the stale errors, and hydra-rt's
//! kept-state format (`userland/drivers/hydra-rt/src/kept.rs`), including torn writes and
//! corruption.

use hydra_hosttests::kept::{crc32c, Kept};
use hydra_hosttests::lx::restart_policy::{after_crash, idempotent, stale_errno, Decision, Ladder, RestartClass, LADDER_WINDOW_MS, LX_RESEND, LX_RESEND_MAYBE};

const T: RestartClass = RestartClass::Transparent;
const F: RestartClass = RestartClass::FailObjects;
const E: RestartClass = RestartClass::EndLinux;

fn d(class: RestartClass, reset_kept: bool, restart: bool) -> Decision {
    Decision { class, reset_kept, restart }
}

#[test]
fn ladder_first_crash_keeps_class() {
    let mut l = Ladder::new(T);
    assert_eq!(l.crash(1_000), d(T, false, true));
    assert_eq!(l.current, T);
}

#[test]
fn ladder_second_crash_within_window_drops_one_class_and_resets_kept() {
    let mut l = Ladder::new(T);
    assert_eq!(l.crash(1_000), d(T, false, true));
    l.restarted(1_000);
    assert_eq!(l.crash(1_000 + LADDER_WINDOW_MS - 1), d(F, true, true));
    assert_eq!(l.current, F);
}

#[test]
fn ladder_third_crash_within_window_stops() {
    let mut l = Ladder::new(T);
    l.crash(0);
    l.restarted(0);
    l.crash(5_000);
    l.restarted(5_000);
    assert_eq!(l.crash(10_000), d(F, true, false));
}

#[test]
fn ladder_crash_after_window_restores_configured_class() {
    let mut l = Ladder::new(T);
    l.crash(0);
    l.restarted(0);
    assert_eq!(l.crash(1_000).class, F);
    l.restarted(1_000);
    // A long, stable run: the next crash is a first one again
    assert_eq!(l.crash(1_000 + LADDER_WINDOW_MS), d(T, false, true));
}

#[test]
fn ladder_window_counts_from_the_last_restart() {
    let mut l = Ladder::new(T);
    l.crash(0);
    l.restarted(0);
    // 40 s later: outside the window of the first restart
    assert_eq!(l.crash(40_000), d(T, false, true));
    l.restarted(40_000);
    assert_eq!(l.crash(50_000), d(F, true, true));
}

#[test]
fn ladder_failobjects_stays_failobjects() {
    let mut l = Ladder::new(F);
    l.crash(0);
    l.restarted(0);
    assert_eq!(l.crash(1), d(F, true, true));
    l.restarted(1);
    assert_eq!(l.crash(2), d(F, true, false));
}

#[test]
fn ladder_endlinux_never_stops_restarting() {
    // Decision 6: linux-server's crash loops keep today's behaviour (the supervisor's
    // own restart limit applies)
    let mut l = Ladder::new(E);
    for t in 0..10u64 {
        let x = l.crash(t);
        assert_eq!(x.class, E);
        assert!(x.restart);
        l.restarted(t);
    }
}

#[test]
fn ladder_deliberate_restart_is_not_a_crash() {
    let mut l = Ladder::new(T);
    l.crash(0);
    l.restarted(0);
    assert_eq!(l.deliberate(1_000), d(T, false, true));
    // the window starts again at the deliberate restart: one crash is a "second" one
    assert_eq!(l.crash(2_000), d(F, true, true));
    assert_eq!(l.crashes, 2);
}

#[test]
fn ladder_reset_by_hand() {
    let mut l = Ladder::new(T);
    l.crash(0);
    l.restarted(0);
    l.crash(1);
    l.restarted(1);
    l.crash(2);
    l.reset();
    assert_eq!(l.crash(3), d(T, false, true));
}

#[test]
fn class_names_round_trip() {
    for c in [T, F, E] {
        assert_eq!(RestartClass::parse(c.name().as_bytes()), Some(c));
        assert_eq!(RestartClass::from_u8(c as u8), Some(c));
    }
    assert_eq!(RestartClass::parse(b"bogus"), None);
    assert_eq!(T.lowered(), F);
    assert_eq!(F.lowered(), F);
    assert_eq!(E.lowered(), E);
}

#[test]
fn stale_errors_per_kind() {
    assert_eq!(stale_errno(16), -32); // pipe read end: EPIPE
    assert_eq!(stale_errno(17), -32);
    assert_eq!(stale_errno(23), -32);
    assert_eq!(stale_errno(18), -104); // Unix socket: ECONNRESET
    assert_eq!(stale_errno(7), -104); // inet
    assert_eq!(stale_errno(8), -104); // netlink
    assert_eq!(stale_errno(2), -9); // mqueue: EBADF
    assert_eq!(stale_errno(3), -9); // bpf map
    assert_eq!(stale_errno(64), -19); // a device service's object: ENODEV
}

const NULL: u64 = 0x6710;

#[test]
fn idempotent_marks_test_call() {
    assert!(idempotent(NULL, &[0, 0, 0, 0, 0, 0]));
    assert!(idempotent(NULL, &[1, 100, 0, 0, 0, 0]));
    assert!(!idempotent(NULL, &[2, 0x1000, 8, 0, 0, 0]), "LX_NULL_COPY changes the caller's buffer");
    assert!(!idempotent(NULL, &[3, 0, 0, 0, 0, 0]), "LX_NULL_OBJ makes an object");
}

#[test]
fn idempotent_marks_keyctl() {
    let k = |op: u64, a2: u64, a4: u64| idempotent(250, &[op, 0, a2, 0, a4, 0]);
    assert!(k(6, 0, 0)); // DESCRIBE
    assert!(k(11, 0, 0)); // READ
    assert!(k(0, 0, 0)); // GET_KEYRING_ID, no create
    assert!(k(0, 1, 0)); // ... with create (lx-sec keeps it before answering: Group 24)
    assert!(k(31, 0, 0)); // CAPABILITIES
    assert!(k(26, 0, 0)); // PKEY_DECRYPT computes only
    assert!(k(10, 0, 0)); // SEARCH without destination
    assert!(!k(10, 0, 5)); // ... linking into a keyring
    for op in [1, 2, 3, 4, 5, 7, 8, 9, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 29, 30, 32] {
        assert!(!k(op, 0, 0), "keyctl op {} changes state", op);
    }
    assert!(!idempotent(248, &[0; 6]), "add_key");
    assert!(idempotent(249, &[0x1000, 0x2000, 0, 0, 0, 0]), "request_key without a destination");
    assert!(!idempotent(249, &[0x1000, 0x2000, 0, 0xFFFF_FFFD, 0, 0]), "request_key linking into a keyring");
}

#[test]
fn idempotent_marks_ipc() {
    // semget / msgget: named lookup or create-if-missing yes; IPC_PRIVATE or IPC_EXCL no
    assert!(idempotent(64, &[1234, 1, 0o1000, 0, 0, 0]));
    assert!(!idempotent(64, &[0, 1, 0o1000, 0, 0, 0]));
    assert!(!idempotent(64, &[1234, 1, 0o3000, 0, 0, 0]));
    assert!(idempotent(68, &[1234, 0o1000, 0, 0, 0, 0]));
    assert!(!idempotent(68, &[1234, 0o3000, 0, 0, 0, 0]));
    // semctl: GETVAL yes (with IPC_64 too), SETVAL / IPC_RMID no
    assert!(idempotent(66, &[1, 0, 12, 0, 0, 0]));
    assert!(idempotent(66, &[1, 0, 0x100 | 2, 0, 0, 0]));
    assert!(!idempotent(66, &[1, 0, 16, 0, 0, 0]));
    assert!(!idempotent(66, &[1, 0, 0, 0, 0, 0]));
    // semop, msgsnd, msgrcv never
    for nr in [65, 69, 70, 220] {
        assert!(!idempotent(nr, &[1, 0, 0, 0, 0, 0]));
    }
    // msgctl IPC_STAT yes, IPC_SET / IPC_RMID no
    assert!(idempotent(71, &[1, 2, 0, 0, 0, 0]));
    assert!(!idempotent(71, &[1, 1, 0, 0, 0, 0]));
    assert!(!idempotent(71, &[1, 0, 0, 0, 0, 0]));
    // wave10 G8-2: shmget as semget; shmat always (lx-ipc only checks); shmctl reads only
    assert!(idempotent(29, &[1234, 4096, 0o1000, 0, 0, 0]));
    assert!(!idempotent(29, &[0, 4096, 0o1000, 0, 0, 0]));
    assert!(!idempotent(29, &[1234, 4096, 0o3000, 0, 0, 0]));
    assert!(idempotent(30, &[5, 0, 0o10000, 0, 0, 0]));
    for cmd in [2u64, 3, 13, 14, 15, 0x100 | 2] {
        assert!(idempotent(31, &[5, cmd, 0, 0, 0, 0]), "shmctl {:#x}", cmd);
    }
    for cmd in [0u64, 1, 11, 12] {
        assert!(!idempotent(31, &[5, cmd, 0, 0, 0, 0]), "shmctl {}: RMID, SET, LOCK, UNLOCK", cmd);
    }
    // mq_getsetattr only without a new attribute; mq_timedsend / receive never
    assert!(idempotent(245, &[3, 0, 0x1000, 0, 0, 0]));
    assert!(!idempotent(245, &[3, 0x1000, 0, 0, 0, 0]));
    assert!(!idempotent(242, &[3; 6]));
    assert!(!idempotent(243, &[3; 6]));
}

#[test]
fn idempotent_marks_sockets_and_io() {
    assert!(idempotent(55, &[3; 6])); // getsockopt
    assert!(!idempotent(54, &[3; 6])); // setsockopt
    assert!(idempotent(45, &[3, 0, 10, 2, 0, 0])); // recvfrom MSG_PEEK
    assert!(!idempotent(45, &[3, 0, 10, 0, 0, 0]));
    assert!(idempotent(47, &[3, 0, 2, 0, 0, 0])); // recvmsg MSG_PEEK
    assert!(!idempotent(47, &[3, 0, 0, 0, 0, 0]));
    for nr in [0, 1, 19, 20, 41, 42, 43, 44, 46, 48, 49, 50, 53, 288, 299, 307] {
        assert!(!idempotent(nr, &[3, 0, 0, 0, 0, 0]), "call {} changes state", nr);
    }
    assert!(idempotent(16, &[3, 0x541B, 0, 0, 0, 0])); // FIONREAD
    assert!(!idempotent(16, &[3, 0x5421, 0, 0, 0, 0])); // FIONBIO sets
    assert!(!idempotent(16, &[3, 0x8914, 0, 0, 0, 0])); // SIOCSIFFLAGS sets
}

#[test]
fn idempotent_marks_files() {
    assert!(idempotent(2, &[0, 0, 0, 0, 0, 0])); // open O_RDONLY
    assert!(idempotent(2, &[0, 2, 0, 0, 0, 0])); // O_RDWR without create
    assert!(idempotent(2, &[0, 0o100, 0, 0, 0, 0])); // O_CREAT (wave10 GV1: create-if-missing is sent again)
    assert!(!idempotent(2, &[0, 0o300, 0, 0, 0, 0])); // O_CREAT | O_EXCL
    assert!(!idempotent(2, &[0, 0o1001, 0, 0, 0, 0])); // O_TRUNC
    assert!(!idempotent(2, &[0, 0o20200000, 0, 0, 0, 0])); // O_TMPFILE
    assert!(idempotent(257, &[u64::MAX - 99, 0, 0o2000000, 0, 0, 0])); // openat O_CLOEXEC
    assert!(!idempotent(257, &[u64::MAX - 99, 0, 0o20200002, 0, 0, 0])); // O_TMPFILE
    for nr in [4, 5, 6, 21, 79, 89, 137, 138, 191, 196, 262, 267, 269, 332, 439, 17] {
        assert!(idempotent(nr, &[0; 6]), "call {} only reads", nr);
    }
    // changes: write, rename, unlink, mkdir, rmdir, link, symlink, fsync, getdents64 (moves
    // the directory offset), lseek, XATTR_CREATE, removexattr (wave10 GV1: chmod, chown,
    // utimensat and setxattr set absolute values: sent again; truncate and ftruncate not)
    for nr in [90, 92, 280] {
        assert!(idempotent(nr, &[0; 6]), "call {} sets an absolute value", nr);
    }
    assert!(!idempotent(188, &[0, 0, 0, 0, 1, 0]), "XATTR_CREATE");
    for nr in [1, 82, 87, 83, 84, 86, 88, 76, 77, 74, 217, 8, 197, 263, 264, 316, 258] {
        assert!(!idempotent(nr, &[0; 6]), "call {} changes state", nr);
    }
}

#[test]
fn idempotent_marks_process() {
    assert!(idempotent(63, &[0; 6])); // uname
    assert!(idempotent(302, &[0, 7, 0, 0x1000, 0, 0])); // prlimit64 get
    assert!(!idempotent(302, &[0, 7, 0x1000, 0, 0, 0])); // prlimit64 set
    // wave10 G7b-1: lx-proc's changes that come out the same when made twice
    for nr in [105, 106, 113, 114, 116, 117, 119, 109, 122, 123, 160, 170, 171, 163] {
        assert!(idempotent(nr, &[0; 6]), "call {} is the same twice", nr);
    }
    assert!(idempotent(157, &[15, 0, 0, 0, 0, 0]), "prctl PR_SET_NAME");
    assert!(!idempotent(157, &[22, 0, 0, 0, 0, 0]), "prctl PR_SET_SECCOMP");
    assert!(idempotent(103, &[3, 0, 0, 0, 0, 0]) && !idempotent(103, &[2, 0, 0, 0, 0, 0]), "syslog READ_ALL yes, READ no");
    for nr in [112, 272, 308] {
        assert!(!idempotent(nr, &[0; 6]), "call {} changes state", nr);
    }
}

#[test]
fn after_crash_decides() {
    assert_eq!(after_crash(LX_RESEND, 1, &[0; 6]), Ok(()), "queued/pending calls are always sent again");
    assert_eq!(after_crash(LX_RESEND_MAYBE, 1, &[0; 6]), Err(-5), "a write being served gets EIO");
    assert_eq!(after_crash(LX_RESEND_MAYBE, 55, &[0; 6]), Ok(()));
    assert_eq!(after_crash(-5, 55, &[0; 6]), Err(-5));
}

// ---- kept state ----

fn area(n: usize) -> Vec<u64> {
    vec![0u64; n.div_ceil(8)]
}

#[test]
fn crc32c_known_value() {
    // The standard check value of CRC-32C
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
}

#[test]
fn kept_fresh_then_adopted() {
    let size = Kept::size_for(16, 40);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, a) = unsafe { Kept::open(p, size, 7, 40) };
    assert!(a.fresh);
    assert_eq!(k.count(), 16);
    assert!(k.put(3, b"keyring 42"));
    assert!(k.put(5, b"x"));
    assert!(k.put(3, b"keyring 43"));
    drop(k);
    // The next instance: same memory
    let (k, a) = unsafe { Kept::open(p, size, 7, 40) };
    assert!(!a.fresh);
    assert_eq!(a.records, 2);
    assert_eq!(a.bad_records, 0);
    assert_eq!(k.get(3), Some(&b"keyring 43"[..]));
    assert_eq!(k.get(5), Some(&b"x"[..]));
    assert_eq!(k.get(4), None);
    assert_eq!(k.free_record(), Some(0));
}

#[test]
fn kept_other_layout_resets() {
    let size = Kept::size_for(4, 16);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 1, 16) };
    k.put(0, b"old");
    let (k, a) = unsafe { Kept::open(p, size, 2, 16) };
    assert!(a.fresh, "a new layout version starts over");
    assert_eq!(k.get(0), None);
    // another record size is another layout too
    let (_, a) = unsafe { Kept::open(p, size, 2, 8) };
    assert!(a.fresh);
}

#[test]
fn kept_bad_header_resets() {
    let size = Kept::size_for(4, 16);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 1, 16) };
    k.put(1, b"data");
    unsafe { *p.add(20) ^= 0xFF }; // a stray write into the header
    let (k, a) = unsafe { Kept::open(p, size, 1, 16) };
    assert!(a.fresh);
    assert_eq!(k.get(1), None);
}

#[test]
fn kept_torn_write_keeps_the_previous_value() {
    let size = Kept::size_for(2, 32);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 1, 32) };
    k.put(0, b"first");
    k.put(0, b"second");
    // Copy layout: header 64, then record 0 copy A (16 + 32), copy B (16 + 32). "second" is
    // in copy A (the first went to B... whichever): tear the current copy's data
    let (cur_off, other_off) = {
        let a = unsafe { std::slice::from_raw_parts(p.add(64 + 16), 6) };
        if a == b"second" {
            (64usize, 64 + 48)
        } else {
            (64 + 48, 64usize)
        }
    };
    let _ = other_off;
    // A torn write of a third value into the current one's twin would be the normal case;
    // here: corrupt the newest copy's data (as a crash mid-write of a later put would leave
    // its not-yet-checksummed copy): the previous value survives
    unsafe { *p.add(cur_off + 16) = b'X' };
    let (k, a) = unsafe { Kept::open(p, size, 1, 32) };
    assert!(!a.fresh);
    assert_eq!(a.bad_records, 0, "the other copy is still valid");
    assert_eq!(k.get(0), Some(&b"first"[..]));
}

#[test]
fn kept_unfinished_write_is_ignored() {
    let size = Kept::size_for(1, 16);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 1, 16) };
    k.put(0, b"good");
    // Simulate a crash in the next put after its "done" word was cleared and the new
    // sequence written, before the checksum: find the copy that is not current
    let other = {
        let a = unsafe { std::slice::from_raw_parts(p.add(64 + 16), 4) };
        if a == b"good" {
            64 + 32
        } else {
            64
        }
    };
    unsafe {
        *(p.add(other) as *mut u32) = 99; // sequence ahead
        *(p.add(other + 4) as *mut u32) = 4;
        std::ptr::copy_nonoverlapping(b"evil".as_ptr(), p.add(other + 16), 4);
        *(p.add(other + 12) as *mut u32) = 0; // not done
    }
    let (k, a) = unsafe { Kept::open(p, size, 1, 16) };
    assert_eq!(a.bad_records, 0);
    assert_eq!(k.get(0), Some(&b"good"[..]));
}

#[test]
fn kept_both_copies_bad_drops_the_record() {
    let size = Kept::size_for(3, 16);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 1, 16) };
    k.put(1, b"a");
    k.put(1, b"b");
    k.put(2, b"keep");
    // Record 1's copies are at 64 + 2*32 and 64 + 3*32: garble both
    unsafe {
        *p.add(64 + 2 * 32 + 16) ^= 1;
        *p.add(64 + 3 * 32 + 16) ^= 1;
    }
    let (mut k, a) = unsafe { Kept::open(p, size, 1, 16) };
    assert_eq!(a.bad_records, 1);
    assert_eq!(a.records, 1);
    assert_eq!(k.get(1), None);
    assert_eq!(k.get(2), Some(&b"keep"[..]));
    // and the record is usable again
    assert!(k.put(1, b"new"));
    let (k, a) = unsafe { Kept::open(p, size, 1, 16) };
    assert_eq!(a.bad_records, 0);
    assert_eq!(k.get(1), Some(&b"new"[..]));
}

#[test]
fn kept_many_updates_and_clear() {
    let size = Kept::size_for(8, 24);
    let mut mem = area(size);
    let p = mem.as_mut_ptr() as *mut u8;
    let (mut k, _) = unsafe { Kept::open(p, size, 9, 24) };
    for n in 0..1000u32 {
        assert!(k.put((n % 8) as usize, &n.to_le_bytes()));
    }
    let (mut k, a) = unsafe { Kept::open(p, size, 9, 24) };
    assert_eq!(a.records, 8);
    for i in 0..8u32 {
        assert_eq!(k.get(i as usize), Some(&(992 + i).to_le_bytes()[..]));
    }
    assert!(k.clear(3));
    assert!(!k.put(8, b"x"), "out of range");
    assert!(!k.put(0, &[0u8; 25]), "too long");
    let (k, a) = unsafe { Kept::open(p, size, 9, 24) };
    assert_eq!(a.records, 7);
    assert_eq!(k.get(3), None);
    assert_eq!(k.free_record(), Some(3));
}

#[test]
fn kept_too_small_area() {
    let mut mem = area(64);
    let (k, a) = unsafe { Kept::open(mem.as_mut_ptr() as *mut u8, 64, 1, 16) };
    assert!(a.fresh);
    assert_eq!(k.count(), 0);
    assert_eq!(k.get(0), None);
}

// wave10 G7b-2: the kernel's remake of a `/proc` snapshot (`LX_KCALL_PREMAKE`, 0x6793)
// only makes text: sent again after an lx-proc crash
#[test]
fn idempotent_marks_proc_remake() {
    assert!(idempotent(0x6793, &[3, 0, 0, 0, 0, 0]));
    assert!(idempotent(0x6793, &[17, 1234, 0, 99, 0, 0]));
    // its neighbours are not
    assert!(!idempotent(0x6794, &[0; 6]));
}
