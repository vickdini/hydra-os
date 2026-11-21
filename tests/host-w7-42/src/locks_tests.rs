//! vfs-server's lock table: the kernel's rules (flock, POSIX ranges, OFD), releases, kept
//! state.

use crate::locks::*;

const E: u64 = u64::MAX;

#[test]
fn flock_shared_exclusive_and_conversion() {
    let mut t = LockTable::new();
    assert!(t.try_lock(5, Owner::Flock(1), false, 0, E, 10).is_ok());
    assert!(t.try_lock(5, Owner::Flock(2), false, 0, E, 11).is_ok());
    // Exclusive while another shares: the conflict is named
    let c = t.try_lock(5, Owner::Flock(3), true, 0, E, 12).unwrap_err();
    assert_eq!(c.ino, 5);
    // Another file is free; record locks do not see flocks
    assert!(t.try_lock(6, Owner::Flock(3), true, 0, E, 12).is_ok());
    assert!(t.try_lock(5, Owner::Posix(12), true, 0, 9, 12).is_ok());
    // A conversion drops first: 1 converting to exclusive still meets 2
    assert!(t.try_lock(5, Owner::Flock(1), true, 0, E, 10).is_err());
    assert!(t.conflict(5, Owner::Flock(9), true, 0, E).is_some_and(|l| l.owner == Owner::Flock(2)));
    assert!(t.locks.iter().all(|l| l.owner != Owner::Flock(1)));
    assert!(t.release_file(2));
    assert!(t.try_lock(5, Owner::Flock(1), true, 0, E, 10).is_ok());
    assert!(!t.release_file(77));
}

#[test]
fn posix_ranges_merge_split_and_conflict() {
    let mut t = LockTable::new();
    let p = Owner::Posix(100);
    t.try_lock(1, p, true, 0, 9, 100).unwrap();
    t.try_lock(1, p, true, 10, 19, 100).unwrap();
    // Touching locks of the same kind merge
    assert_eq!(t.locks.len(), 1);
    assert_eq!((t.locks[0].start, t.locks[0].end), (0, 19));
    // Unlocking the middle splits
    assert!(t.unlock(1, p, 5, 9));
    let mut r: Vec<(u64, u64)> = t.locks.iter().map(|l| (l.start, l.end)).collect();
    r.sort();
    assert_eq!(r, vec![(0, 4), (10, 19)]);
    // Another process: conflicts only where the ranges meet, readers share
    assert!(t.try_lock(1, Owner::Posix(200), false, 5, 9, 200).is_ok());
    assert!(t.try_lock(1, Owner::Posix(200), false, 4, 4, 200).is_err());
    // OFD and POSIX conflict
    assert!(t.try_lock(1, Owner::Ofd(7), true, 12, 12, 300).is_err());
    // A read lock over the own write range replaces it
    t.try_lock(1, p, false, 0, 4, 100).unwrap();
    assert!(t.locks.iter().any(|l| l.owner == p && !l.write && l.start == 0 && l.end == 4));
    t.check().unwrap();
    // Close of any descriptor of the file, then exit
    assert!(t.closed(100, 1));
    assert!(t.locks.iter().all(|l| l.owner != p));
    assert!(!t.closed(100, 1));
    assert!(t.process_exited(200));
    assert!(t.locks.is_empty());
    assert!(!t.unlock(1, p, 0, E));
}

#[test]
fn flock_ranges_as_linux() {
    assert_eq!(range(0, 0, 0), Ok((0, E)));
    assert_eq!(range(0, 10, 5), Ok((10, 14)));
    assert_eq!(range(100, -10, 0), Ok((90, E)));
    assert_eq!(range(0, 10, -5), Ok((5, 9)));
    assert_eq!(range(0, 2, -5), Err(-22));
    assert_eq!(range(0, -1, 1), Err(-22));
    assert_eq!(range(i64::MAX, 1, 1), Err(-22));
    assert_eq!(range(0, 5, i64::MAX), Ok((5, E)));
    // A start at the very bottom with a negative length: refused, no overflow
    assert_eq!(range(0, i64::MIN, -1), Err(-22));
    assert_eq!(range(0, i64::MIN, 0), Err(-22));
}

#[test]
fn the_table_survives_kept_state_and_bad_tables_are_refused() {
    let mut t = LockTable::new();
    t.try_lock(1, Owner::Posix(100), true, 0, 99, 100).unwrap();
    t.try_lock(1, Owner::Flock(8), true, 0, E, 100).unwrap();
    t.try_lock(2, Owner::Ofd(9), false, 5, E, 101).unwrap();
    t.try_lock(2, Owner::Ofd(10), false, 0, 7, 102).unwrap();
    let b = t.encode();
    assert_eq!(LockTable::decode(&b), Ok(t.clone()));
    assert!(t.proc_locks().contains("FLOCK "));
    assert_eq!(t.proc_locks().lines().count(), 4);
    // Damage anywhere is refused
    for i in 0..b.len() {
        let mut bad = b.clone();
        bad[i] ^= 1;
        assert!(LockTable::decode(&bad).is_err(), "byte {}", i);
    }
    // A table whose locks conflict (two writers on the same bytes) fails its check
    let mut c = t.clone();
    c.locks.push(Lock { ino: 1, owner: Owner::Posix(5), write: true, start: 50, end: 50, pid: 5 });
    assert!(LockTable::decode(&c.encode()).is_err());
    // A flock that is not whole-file, an empty range
    let mut f = LockTable::new();
    f.locks.push(Lock { ino: 1, owner: Owner::Flock(1), write: false, start: 1, end: E, pid: 1 });
    assert!(f.check().is_err());
    f.locks[0] = Lock { ino: 1, owner: Owner::Posix(1), write: false, start: 9, end: 3, pid: 1 };
    assert!(f.check().is_err());
    assert_eq!(LockTable::decode(&LockTable::new().encode()), Ok(LockTable::new()));
}
