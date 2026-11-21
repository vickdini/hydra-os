//! vfs-server's caches: fills, hits, negative entries, invalidation, stale fills, size.

use hydra_hosttests_w7_71::cache::{name_hash, Cache, Stats};
use hydra_hosttests_w7_71::ctx::Node;
use hydra_hosttests_w7_71::fs::fsproto::Attr;

fn n(ino: u64) -> Node {
    Node::new(0, ino)
}

fn attr(ino: u64, size: u64) -> Attr {
    Attr { ino, size, ..Default::default() }
}

#[test]
fn names_positive_and_negative() {
    let c = Cache::new(100);
    assert_eq!(c.name(n(2), b"usr"), None);
    let t = c.begin();
    c.put_name(t, n(2), b"usr", Some(n(5)));
    c.put_name(t, n(2), b"nope", None);
    assert_eq!(c.name(n(2), b"usr"), Some(Some(n(5))));
    assert_eq!(c.name(n(2), b"nope"), Some(None));
    // Same name, other directory / other mount: not known
    assert_eq!(c.name(n(3), b"usr"), None);
    assert_eq!(c.name(Node::new(1, 2), b"usr"), None);
    let s = c.stats();
    assert_eq!((s.name_hits, s.name_misses), (2, 3));
}

#[test]
fn forget_name_and_dir() {
    let c = Cache::new(100);
    let t = c.begin();
    c.put_name(t, n(2), b"a", Some(n(10)));
    c.put_name(t, n(2), b"b", Some(n(11)));
    c.put_name(t, n(3), b"a", Some(n(12)));
    c.forget_name(n(2), b"a");
    assert_eq!(c.name(n(2), b"a"), None);
    assert_eq!(c.name(n(2), b"b"), Some(Some(n(11))));
    c.forget_dir(n(2));
    assert_eq!(c.name(n(2), b"b"), None);
    assert_eq!(c.name(n(3), b"a"), Some(Some(n(12))), "another directory keeps its names");
    // A fill after forget_dir is valid again
    let t = c.begin();
    c.put_name(t, n(2), b"b", Some(n(13)));
    assert_eq!(c.name(n(2), b"b"), Some(Some(n(13))));
}

#[test]
fn a_fill_racing_with_a_change_is_dropped() {
    let c = Cache::new(100);
    let t = c.begin();
    // (the request is in flight when a change comes)
    c.forget_attr(n(7));
    c.put_attr(t, n(7), attr(7, 1));
    c.put_name(t, n(2), b"x", Some(n(7)));
    c.put_link(t, n(8), b"target");
    assert!(c.attr(n(7)).is_none());
    assert_eq!(c.name(n(2), b"x"), None);
    assert_eq!(c.link(n(8)), None);
    assert_eq!(c.stats().stale_fills, 3);
    let t = c.begin();
    c.put_attr(t, n(7), attr(7, 2));
    assert_eq!(c.attr(n(7)).map(|a| a.size), Some(2));
}

#[test]
fn attributes_links_and_acls() {
    let c = Cache::new(100);
    let t = c.begin();
    c.put_attr(t, n(4), attr(4, 99));
    c.put_link(t, n(5), b"/usr/bin");
    c.put_acl(t, n(4), Some(b"acl"));
    c.put_acl(t, n(6), None);
    assert_eq!(c.attr(n(4)).map(|a| a.size), Some(99));
    assert_eq!(c.link(n(5)).as_deref(), Some(&b"/usr/bin"[..]));
    assert_eq!(c.acl(n(4)), Some(Some(b"acl".to_vec())));
    assert_eq!(c.acl(n(6)), Some(None));
    assert_eq!(c.acl(n(9)), None);
    c.forget_attr(n(4));
    assert!(c.attr(n(4)).is_none());
    assert_eq!(c.acl(n(4)), None, "an attribute change may change the ACL");
    c.forget_link(n(5));
    assert_eq!(c.link(n(5)), None);
}

#[test]
fn forget_object_reaches_every_mount() {
    let c = Cache::new(100);
    let t = c.begin();
    for m in 0..3u16 {
        c.put_attr(t, Node::new(m, 7), attr(7, m as u64));
        c.put_link(t, Node::new(m, 7), b"x");
        c.put_name(t, Node::new(m, 7), b"child", Some(Node::new(m, 8)));
    }
    c.put_attr(t, n(9), attr(9, 0));
    c.forget_object(7);
    for m in 0..3u16 {
        assert!(c.attr(Node::new(m, 7)).is_none());
        assert_eq!(c.link(Node::new(m, 7)), None);
        assert_eq!(c.name(Node::new(m, 7), b"child"), None);
    }
    assert!(c.attr(n(9)).is_some());
}

#[test]
fn forget_names_and_all() {
    let c = Cache::new(100);
    let t = c.begin();
    c.put_name(t, n(2), b"a", None);
    c.put_attr(t, n(2), attr(2, 0));
    c.forget_names();
    assert_eq!(c.name(n(2), b"a"), None);
    assert!(c.attr(n(2)).is_some());
    let t = c.begin();
    c.put_name(t, n(2), b"a", None);
    c.forget_all();
    assert_eq!(c.name(n(2), b"a"), None);
    assert!(c.attr(n(2)).is_none());
    assert_eq!(c.len(), (0, 0, 0));
    assert_eq!(c.stats().flushes, 1);
}

#[test]
fn size_is_bounded_and_recent_entries_stay() {
    let c = Cache::new(64);
    for i in 0..10_000u64 {
        let t = c.begin();
        c.put_name(t, n(2), format!("f{}", i).as_bytes(), Some(n(100 + i)));
        c.put_attr(t, n(100 + i), attr(100 + i, i));
        // One entry stays in use all along
        assert!(i < 1 || c.name(n(2), b"f0").is_some(), "f0 dropped at {}", i);
        assert!(c.attr(n(100)).is_some());
    }
    let (names, attrs, _) = c.len();
    assert!(names <= 64 + 8 && attrs <= 64 + 8, "{} names, {} attrs", names, attrs);
    assert!(names >= 32, "not emptied all at once: {}", names);
    // The newest are there
    assert!(c.name(n(2), b"f9999").is_some());
    assert!(c.attr(n(100 + 9999)).is_some());
}

#[test]
fn misses_do_not_age_entries_and_huge_caps_do_not_overflow() {
    let c = Cache::new(64);
    let t = c.begin();
    for i in 0..64u64 {
        c.put_attr(t, n(i), attr(i, 0));
    }
    // Many misses, then one more fill: nothing is dropped for the misses
    for i in 1000..100_000u64 {
        assert!(c.attr(n(i)).is_none());
    }
    for i in 0..8u64 {
        let t = c.begin();
        c.put_attr(t, n(500 + i), attr(500 + i, 0));
    }
    assert_eq!(c.len().1, 72, "all kept: within cap + cap/8");
    let big = Cache::new(usize::MAX);
    let t = big.begin();
    big.put_attr(t, n(1), attr(1, 0));
    big.put_name(t, n(1), b"x", None);
    assert!(big.attr(n(1)).is_some());
}

#[test]
fn directory_generations_are_bounded() {
    let c = Cache::new(16);
    let t = c.begin();
    c.put_name(t, n(1), b"keep", Some(n(2)));
    for d in 100..116u64 {
        c.forget_dir(n(d));
    }
    // The 17th directory generation: every name goes, the table starts over
    c.forget_dir(n(200));
    assert_eq!(c.name(n(1), b"keep"), None);
    let t = c.begin();
    c.put_name(t, n(100), b"a", Some(n(3)));
    assert_eq!(c.name(n(100), b"a"), Some(Some(n(3))));
}

#[test]
fn colliding_names_do_not_answer_for_each_other() {
    // Find two names with one hash is impractical; instead check the stored name is compared
    let c = Cache::new(100);
    let t = c.begin();
    c.put_name(t, n(2), b"abc", Some(n(3)));
    assert_eq!(c.name(n(2), b"abd"), None);
    assert_ne!(name_hash(b"abc"), name_hash(b"abd"));
    assert_eq!(name_hash(b""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn stats_reset_and_cap() {
    let c = Cache::new(10);
    assert_eq!(c.cap(), 10);
    c.set_cap(1);
    assert_eq!(c.cap(), 16, "at least 16");
    c.attr(n(1));
    c.link(n(1));
    assert_eq!(c.stats().attr_misses, 1);
    assert_eq!(c.stats().link_misses, 1);
    c.reset_stats();
    assert_eq!(c.stats(), Stats::default());
}

#[test]
fn concurrent_fills_and_forgets_stay_consistent() {
    use std::sync::Arc;
    let c = Arc::new(Cache::new(1000));
    let mut hs = Vec::new();
    for k in 0..4u64 {
        let c = c.clone();
        hs.push(std::thread::spawn(move || {
            for i in 0..2000u64 {
                let t = c.begin();
                c.put_attr(t, n(i % 50), attr(i % 50, k));
                if i % 7 == 0 {
                    c.forget_attr(n(i % 50));
                }
                if let Some(a) = c.attr(n(i % 50)) {
                    assert_eq!(a.ino, i % 50);
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert!(c.len().1 <= 50);
}
