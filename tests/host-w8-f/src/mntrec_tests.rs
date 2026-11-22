//! The table format: round trips, the hash, what decode refuses.

use crate::mntrec::*;
use alloc::string::String;
use alloc::vec::Vec;

fn rec(parent: u32, kind: u32, root: u64, path: &str) -> MntRec {
    MntRec {
        id: 100 + parent,
        parent,
        kind,
        tmpfs: 0,
        mountpoint: 7,
        root,
        flags: 1 << 21,
        propagation: 1 << 20,
        fstype: String::from(if kind == MK_TREE { "zfs" } else { "proc" }),
        source: String::from("src"),
        path: String::from(path),
        serves: if kind == MK_NAMED { Some(String::from("/proc")) } else { None },
    }
}

pub fn sample() -> MntTable {
    let mut t = MntTable { gen: 5, hash: 0, root: 1, system_root: 34, slots: Vec::new() };
    t.push(MntRec { parent: 0, ..rec(0, MK_TREE, 34, "/") });
    t.push(rec(1, MK_NAMED, 0, "/proc"));
    t.slots.push(None);
    t.push(MntRec { tmpfs: 3, ..rec(1, MK_TREE, 99, "/mnt") });
    t.hash = hash_of(&t);
    t
}

#[test]
fn round_trip_keeps_everything() {
    let t = sample();
    let b = encode(&t);
    let d = decode(&b).unwrap();
    assert_eq!(d, t);
    assert_eq!(&b[..4], &MNT_MAGIC.to_le_bytes());
    assert_eq!(hash_of(&d), t.hash);
}

#[test]
fn hash_follows_contents_not_gen() {
    let t = sample();
    let mut u = t.clone();
    u.gen = 99;
    u.hash = 1;
    assert_eq!(hash_of(&u), hash_of(&t));
    u.slots[0].as_mut().unwrap().flags |= 1;
    assert_ne!(hash_of(&u), hash_of(&t));
    let mut v = t.clone();
    v.root = 4;
    assert_ne!(hash_of(&v), hash_of(&t));
    let mut w = t.clone();
    w.slots.push(None);
    assert_ne!(hash_of(&w), hash_of(&t));
    let mut x = t.clone();
    x.slots[1].as_mut().unwrap().serves = None;
    assert_ne!(hash_of(&x), hash_of(&t));
}

#[test]
fn decode_refuses_damage() {
    let t = sample();
    let b = encode(&t);
    // cut anywhere
    for n in 0..b.len() {
        assert!(decode(&b[..n]).is_err(), "cut at {}", n);
    }
    // trailing byte
    let mut long = b.clone();
    long.push(0);
    assert!(decode(&long).is_err());
    // bad magic
    let mut m = b.clone();
    m[0] ^= 1;
    assert!(decode(&m).is_err());
    // bad present byte
    let mut p = b.clone();
    p[HEAD_LEN] = 7;
    assert!(decode(&p).is_err());
    // too many slots
    let mut n = b.clone();
    n[4..8].copy_from_slice(&((MAX_SLOTS as u32) + 1).to_le_bytes());
    assert!(decode(&n).is_err());
}

#[test]
fn decode_refuses_bad_utf8() {
    let mut t = sample();
    t.slots[0].as_mut().unwrap().path = String::from("/x");
    let mut b = encode(&t);
    let i = b.windows(2).position(|w| w == b"/x").unwrap();
    b[i + 1] = 0xFF;
    assert!(decode(&b).is_err());
}

#[test]
fn check_refuses_broken_tables() {
    let t = sample();
    assert!(t.check().is_ok());
    let mut no_root = t.clone();
    no_root.root = 3; // an empty slot
    assert!(no_root.check().is_err());
    let mut far = t.clone();
    far.slots[1].as_mut().unwrap().parent = 9;
    assert!(far.check().is_err());
    let mut hole_parent = t.clone();
    hole_parent.slots[1].as_mut().unwrap().parent = 3;
    assert!(hole_parent.check().is_err());
    let mut own = t.clone();
    own.slots[1].as_mut().unwrap().parent = 2;
    assert!(own.check().is_err());
    let mut cycle = t.clone();
    cycle.slots[1].as_mut().unwrap().parent = 4;
    cycle.slots[3].as_mut().unwrap().parent = 2;
    assert!(cycle.check().is_err());
    let mut kind = t.clone();
    kind.slots[1].as_mut().unwrap().kind = 9;
    assert!(kind.check().is_err());
    // and decode runs the check
    assert!(decode(&encode(&cycle)).is_err());
}

#[test]
fn long_strings_are_cut_on_encode() {
    let mut t = sample();
    let long: String = core::iter::repeat('a').take(MAX_STR + 10).collect();
    t.slots[0].as_mut().unwrap().source = long;
    let d = decode(&encode(&t)).unwrap();
    assert_eq!(d.slots[0].as_ref().unwrap().source.len(), MAX_STR);
}

#[test]
fn table_helpers() {
    let t = sample();
    assert_eq!(t.get(0), None);
    assert_eq!(t.get(3), None);
    assert_eq!(t.get(4).unwrap().path, "/mnt");
    assert_eq!(t.live().map(|(i, _)| i).collect::<Vec<_>>(), [1, 2, 4]);
    let mut s = t.subtree(1);
    s.sort();
    assert_eq!(s, [1, 2, 4]);
    assert_eq!(t.subtree(2), [2]);
    assert_eq!(tree_roots(&t), [34, 99]);
}

#[test]
fn root_changes_count_each_hold() {
    assert_eq!(root_changes(&[1, 2, 2, 3], &[2, 3, 3, 4]), (alloc::vec![3, 4], alloc::vec![1, 2]));
    assert_eq!(root_changes(&[], &[5]), (alloc::vec![5], alloc::vec![]));
    assert_eq!(root_changes(&[5, 5], &[]), (alloc::vec![], alloc::vec![5, 5]));
    assert_eq!(root_changes(&[7], &[7]), (alloc::vec![], alloc::vec![]));
}
