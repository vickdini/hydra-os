//! vfs-server's kept state: slots, generations, sections, a full snapshot round trip, the
//! data-key sweep.

use crate::kept::*;
use crate::mtab::MountTables;
use crate::tmpfs::*;
use std::collections::BTreeMap;

/// Data objects as byte vectors (keys from DATA_KEY_BASE, as the server's).
struct Store {
    objs: BTreeMap<u64, Vec<u8>>,
    next: u64,
}

impl Store {
    fn new() -> Store {
        Store { objs: BTreeMap::new(), next: DATA_KEY_BASE }
    }
}

impl DataStore for Store {
    fn create(&mut self) -> Result<u64, i64> {
        let k = self.next;
        self.next += 1;
        self.objs.insert(k, Vec::new());
        Ok(k)
    }
    fn write(&mut self, key: u64, off: u64, data: &[u8]) -> Result<(), i64> {
        let o = self.objs.get_mut(&key).ok_or(-9i64)?;
        let end = off as usize + data.len();
        if o.len() < end {
            o.resize(end, 0);
        }
        o[off as usize..end].copy_from_slice(data);
        Ok(())
    }
    fn read(&mut self, key: u64, off: u64, buf: &mut [u8]) -> Result<(), i64> {
        let o = self.objs.get(&key).ok_or(-9i64)?;
        for (i, b) in buf.iter_mut().enumerate() {
            *b = *o.get(off as usize + i).unwrap_or(&0);
        }
        Ok(())
    }
    fn truncate(&mut self, _key: u64, _size: u64, _old: u64) -> Result<(), i64> {
        Ok(())
    }
    fn free(&mut self, key: u64) {
        self.objs.remove(&key);
    }
}

#[test]
fn a_slot_round_trips_and_any_damage_fails_it() {
    let body = b"some body bytes".to_vec();
    let s = encode_slot(7, &body);
    assert_eq!(s.len(), SLOT_HEADER + body.len());
    // A kept object is larger than the slot: trailing bytes are ignored
    let mut big = s.clone();
    big.resize(4096, 0xAA);
    assert_eq!(read_slot(&big), Some((7, &body[..])));
    // Every single changed byte (header or body) fails the slot
    for i in 0..s.len() {
        let mut bad = s.clone();
        bad[i] ^= 0x10;
        assert_eq!(read_slot(&bad), None, "byte {}", i);
    }
    // Short, zeroed (a new object), generation 0, a length past the end
    assert_eq!(read_slot(&s[..SLOT_HEADER - 1]), None);
    assert_eq!(read_slot(&[0u8; 4096]), None);
    assert_eq!(read_slot(&encode_slot(0, &body)), None);
    assert_eq!(read_slot(&s[..s.len() - 1]), None);
    // An empty body is a valid slot
    assert_eq!(read_slot(&encode_slot(1, &[])), Some((1, &[][..])));
}

#[test]
fn the_newest_valid_slot_wins_and_a_torn_write_falls_back() {
    let a = encode_slot(4, b"four");
    let b = encode_slot(5, b"five");
    // Generations alternate between the slots
    assert_eq!(slot_for(4), 0);
    assert_eq!(slot_for(5), 1);
    let v = by_age([&a, &b]);
    assert_eq!(v.iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(), vec![(1, 5), (0, 4)]);
    assert_eq!(v[0].2, b"five");
    // Generation 6 torn half way into slot 0 (the older): slot 1 (5) is used
    let six = encode_slot(6, b"six six six six");
    let mut torn = a.clone();
    torn.resize(six.len(), 0);
    torn[..six.len() / 2].copy_from_slice(&six[..six.len() / 2]);
    let v = by_age([&torn, &b]);
    assert_eq!(v.len(), 1);
    assert_eq!((v[0].0, v[0].1), (1, 5));
    // Neither valid: nothing to try
    assert!(by_age([&[0u8; 64][..], &[1u8; 64][..]]).is_empty());
}

#[test]
fn a_snapshot_round_trips_with_and_without_parts() {
    let s = Snapshot {
        counters: Counters { restarts: 3, data_next: DATA_KEY_BASE + 9, ktest_inst: 2, ktest_ino: 5 },
        mounts: Some(vec![1, 2, 3]),
        tmpfs: None,
        locks: Some(vec![]),
    };
    assert_eq!(Snapshot::decode(&s.encode()), Ok(s.clone()));
    let empty = Snapshot { counters: Counters { data_next: DATA_KEY_BASE, ..Counters::default() }, ..Snapshot::default() };
    assert_eq!(Snapshot::decode(&empty.encode()), Ok(empty));
}

#[test]
fn a_broken_snapshot_body_is_refused() {
    let s = Snapshot { counters: Counters { data_next: DATA_KEY_BASE, ..Counters::default() }, mounts: Some(vec![9; 10]), ..Snapshot::default() };
    let b = s.encode();
    // Cut anywhere: never a panic, never the whole snapshot (a cut between sections reads
    // as a snapshot without the later parts; the slot's checksum catches such cuts)
    for n in 1..b.len() {
        assert_ne!(Snapshot::decode(&b[..n]), Ok(s.clone()), "cut at {}", n);
    }
    assert!(Snapshot::decode(&b[..20]).is_err());
    // No counters
    assert!(Snapshot::decode(&[]).is_err());
    // Counters twice, a part twice
    let mut twice = b.clone();
    twice.extend_from_slice(&b);
    assert!(Snapshot::decode(&twice).is_err());
    // A data key below the base (keys there are the server's own objects)
    let low = Snapshot { counters: Counters { data_next: 5, ..Counters::default() }, ..Snapshot::default() };
    assert!(Snapshot::decode(&low.encode()).is_err());
    // A part of a newer layout is skipped
    let mut newer = b.clone();
    newer.extend_from_slice(&99u32.to_le_bytes());
    newer.extend_from_slice(&3u32.to_le_bytes());
    newer.extend_from_slice(b"new");
    assert_eq!(Snapshot::decode(&newer), Ok(s));
}

#[test]
fn mount_tables_and_tmpfs_trees_survive_a_snapshot() {
    // The server's state: a namespace copied from the initial one, a tmpfs instance with a
    // file holding data and an open-but-removed file
    let mut tables = MountTables::new();
    tables.install(0, 34, &[]);
    tables.copy_ns(0, 77, &|_| 0).unwrap();
    let mut store = Store::new();
    let mut set = TmpfsSet::new();
    let (n, root) = set.create("size=1m", 0, 0, 1 << 30, (1, 0)).unwrap();
    let t = set.get_mut(n).unwrap();
    let f = t.mknod(root, b"file", S_IFREG | 0o644, 0, 0, 0, (1, 0)).unwrap();
    t.write(f, 0, b"kept data", &mut store, (2, 0)).unwrap();
    let g = t.mknod(root, b"gone", S_IFREG | 0o644, 0, 0, 0, (1, 0)).unwrap();
    t.write(g, 0, b"x", &mut store, (2, 0)).unwrap();
    t.open(g).unwrap();
    t.unlink(root, b"gone", &mut store, (3, 0)).unwrap();
    let keys = set.data_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| *k >= DATA_KEY_BASE));

    let snap = Snapshot {
        counters: Counters { restarts: 0, data_next: store.next, ktest_inst: 0, ktest_ino: 0 },
        mounts: Some(tables.encode()),
        tmpfs: Some(set.encode()),
        locks: None,
    };
    let slot = encode_slot(1, &snap.encode());
    // The next instance
    let (gen, body) = read_slot(&slot).unwrap();
    assert_eq!(gen, 1);
    let back = Snapshot::decode(body).unwrap();
    let tables2 = MountTables::decode(back.mounts.as_ref().unwrap()).unwrap();
    let set2 = TmpfsSet::decode(back.tmpfs.as_ref().unwrap()).unwrap();
    assert_eq!(tables2.spaces.keys().copied().collect::<Vec<_>>(), vec![0, 77]);
    assert_eq!(set2.data_keys(), keys);
    let t2 = set2.get(n).unwrap();
    assert_eq!(t2.read(t2.lookup(root, b"file").unwrap(), 0, 9, &mut store).unwrap(), b"kept data");
    // The removed file lives on while open
    assert!(t2.has_open());
    assert_eq!(back.counters.data_next, DATA_KEY_BASE + 2);
}

#[test]
fn orphans_are_every_unnamed_data_key_wherever_it_lies() {
    let b = DATA_KEY_BASE;
    // Kept keys: the two slots, a named file, one let go of just before a crash (below
    // data_next), and objects made for unsaved changes far past data_next (more than any
    // fixed window)
    let kept = vec![1, 2, b, b + 1, b + 5, b + 300, b + 10_000];
    let named = vec![b + 5, b];
    let o = orphans(&named, &kept);
    assert_eq!(o, vec![b + 1, b + 300, b + 10_000]);
    // Never the server's own keys (slots), never a named file
    assert!(!o.contains(&1) && !o.contains(&2) && !o.contains(&b));
    assert!(orphans(&named, &[]).is_empty());
    assert_eq!(orphans(&[], &[1, 2]), Vec::<u64>::new());
}

#[test]
fn the_next_key_is_past_data_next_and_every_named_key() {
    let b = DATA_KEY_BASE;
    assert_eq!(next_key(&[], b + 10), b + 10);
    // A key taken while the last snapshot was made: named above data_next
    assert_eq!(next_key(&[b + 3, b + 12], b + 10), b + 13);
    // Never below the base, never wrapping
    assert_eq!(next_key(&[], 0), b);
    assert_eq!(next_key(&[u64::MAX], b), u64::MAX);
}

#[test]
fn a_restore_given_up_lets_go_only_of_objects_made_for_it() {
    let b = DATA_KEY_BASE;
    assert_eq!(rollback(&[(b, true), (b + 1, false), (b + 2, true), (b + 3, false)]), vec![b + 1, b + 3]);
    assert!(rollback(&[]).is_empty());
}

#[test]
fn data_is_unkept_only_after_the_snapshot_without_it_is_written() {
    let mut f = Frees::new();
    f.free(7);
    f.free(8);
    // The snapshot is made: these two are not in it
    let batch = f.take();
    assert_eq!(batch, vec![7, 8]);
    // A free while the snapshot is being written belongs to the next one
    f.free(9);
    // The write failed (too big): nothing is unkept, all wait for the next snapshot
    f.failed(batch);
    assert_eq!(f.len(), 3);
    let batch = f.take();
    assert_eq!(f.len(), 0);
    let unkeep = f.committed(batch);
    assert_eq!(unkeep.len(), 3);
    assert!(unkeep.contains(&9));
}

#[test]
fn a_boot_state_snapshot_is_valid_for_the_first_restart() {
    // What a first instance writes at once (counters only, parts as at boot)
    let boot = Snapshot { counters: Counters { data_next: DATA_KEY_BASE, ..Counters::default() }, mounts: None, tmpfs: None, locks: None };
    let slot = encode_slot(1, &boot.encode());
    let mut obj = vec![0u8; 8192];
    obj[..slot.len()].copy_from_slice(&slot);
    let v = by_age([&obj, &[0u8; 8192][..]]);
    assert_eq!(v.len(), 1);
    assert_eq!(Snapshot::decode(v[0].2), Ok(boot));
}

#[test]
fn a_partial_snapshot_restores_only_its_parts() {
    // Mounts present, tmpfs absent: the decoder gives exactly that (the server keeps its
    // boot tmpfs set for the absent part)
    let mut tables = MountTables::new();
    tables.install(0, 34, &[]);
    let s = Snapshot { counters: Counters { data_next: DATA_KEY_BASE, ..Counters::default() }, mounts: Some(tables.encode()), tmpfs: None, locks: None };
    let back = Snapshot::decode(&s.encode()).unwrap();
    assert!(back.tmpfs.is_none() && back.locks.is_none());
    assert!(MountTables::decode(back.mounts.as_ref().unwrap()).is_ok());
    // A damaged part is found by its own decoder (the server then tries the other slot)
    let mut bad = s.clone();
    let m = bad.mounts.as_mut().unwrap();
    let n = m.len();
    m[n - 1] ^= 1;
    let back = Snapshot::decode(&bad.encode()).unwrap();
    assert!(MountTables::decode(back.mounts.as_ref().unwrap()).is_err());
}
