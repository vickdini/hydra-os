//! Group 6b-3's review fixes: a file's Landlock parent comes from the call's own walk, and
//! every permission check of vfs-server's served calls asks the access policies.

use hydra_hosttests_w9_6b3::steps::LastSteps;

#[test]
fn a_files_parent_is_the_calls_own_walk_not_another_calls() {
    // File 50 has two hard links: in allowed dir 10 and in denied dir 20
    let mut s = LastSteps::new(8);
    s.record(1, 50, 20); // call 1 walked the denied link
    s.record(2, 50, 10); // call 2 then walked the allowed link
    assert_eq!(s.take(1, 50), Some(20), "call 1 keeps its own (denied) folder");
    assert_eq!(s.take(2, 50), Some(10));
    assert_eq!(s.take(1, 50), None, "taken once");
    // The last step was another object (a mount's root entered after it): unknown
    s.record(3, 60, 10);
    assert_eq!(s.take(3, 61), None);
    assert_eq!(s.take(3, 60), None, "a mismatch drops the entry");
    // Bounded
    for r in 0..8 {
        s.record(100 + r, 1, 2);
    }
    assert_eq!(s.len(), 8);
    s.record(200, 1, 2);
    assert_eq!(s.len(), 1);
    s.forget(200);
    assert_eq!(s.len(), 0);
}

#[test]
fn served_calls_check_permissions_with_the_access_policies() {
    // ctxt::may_access has no ABAC step: in the calls vfs-server serves for ABAC callers,
    // every permission check must use ctxt::allowed (xfile.rs's exec/socket paths go to the
    // kernel for them before any check: ctxt::check(.., LX_FS_ABAC))
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../userland/drivers/vfs-server/src/");
    for f in ["calls/change.rs", "calls/open.rs", "calls/stat.rs", "mountcalls.rs"] {
        let src = std::fs::read_to_string(format!("{dir}{f}")).unwrap();
        assert!(!src.contains("ctxt::may_access("), "{f} checks a permission without ABAC");
        assert!(src.contains("ctxt::allowed("), "{f}");
    }
    let x = std::fs::read_to_string(format!("{dir}xfile.rs")).unwrap();
    assert!(x.contains("LX_FS_ABAC"), "xfile.rs sends ABAC callers to the kernel");
}
