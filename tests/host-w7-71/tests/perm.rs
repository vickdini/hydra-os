//! vfs-server's permission policy: mode bits, groups, ACLs, capabilities (as the kernel's
//! `vfs::may_access` and `acl::check`).

use hydra_hosttests_w7_71::ctx::{Ctx, Node};
use hydra_hosttests_w7_71::fs::fsproto::Attr;
use hydra_hosttests_w7_71::perm::{acl_check, may, needs_acl, MAY_EXEC, MAY_READ, MAY_WRITE};
use hydra_hosttests_w7_71::proto::LxCall;

fn a(mode: u32, uid: u32, gid: u32) -> Attr {
    Attr { mode, uid, gid, ..Default::default() }
}

fn cx(uid: u32, gid: u32) -> Ctx {
    Ctx::new(uid, gid, 0, Node::new(0, 2))
}

fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for &(t, p, i) in entries {
        v.extend_from_slice(&t.to_le_bytes());
        v.extend_from_slice(&p.to_le_bytes());
        v.extend_from_slice(&i.to_le_bytes());
    }
    v
}

const DIR: u32 = 0o040000;
const REG: u32 = 0o100000;

#[test]
fn owner_group_other() {
    let f = a(REG | 0o640, 10, 20);
    assert!(may(&cx(10, 1), &f, None, MAY_READ | MAY_WRITE));
    assert!(!may(&cx(10, 1), &f, None, MAY_EXEC));
    assert!(may(&cx(11, 20), &f, None, MAY_READ));
    assert!(!may(&cx(11, 20), &f, None, MAY_WRITE));
    assert!(may(&cx(11, 1).with_group(20), &f, None, MAY_READ));
    assert!(!may(&cx(11, 1), &f, None, MAY_READ));
    // The owner's bits apply to the owner even when the group's would allow more
    let g = a(REG | 0o070, 10, 20);
    assert!(!may(&cx(10, 20), &g, None, MAY_READ));
}

#[test]
fn root_and_capabilities() {
    let f = a(REG | 0o000, 10, 20);
    let d = a(DIR | 0o000, 10, 20);
    let root = cx(0, 0);
    assert!(may(&root, &f, None, MAY_READ | MAY_WRITE));
    assert!(!may(&root, &f, None, MAY_EXEC), "execute needs some x bit, even for root");
    assert!(may(&root, &a(REG | 0o100, 10, 20), None, MAY_EXEC));
    assert!(may(&root, &d, None, MAY_EXEC), "root searches any directory");
    let override_ = Ctx::new(5, 5, 1 << 1, Node::new(0, 2));
    assert!(may(&override_, &f, None, MAY_WRITE));
    let read_search = Ctx::new(5, 5, 1 << 2, Node::new(0, 2));
    assert!(may(&read_search, &f, None, MAY_READ));
    assert!(!may(&read_search, &f, None, MAY_WRITE));
    assert!(may(&read_search, &d, None, MAY_EXEC));
    assert!(!may(&read_search, &f, None, MAY_EXEC));
}

#[test]
fn acl_entries() {
    let f = a(REG | 0o600, 10, 20);
    let l = acl(&[(0x01, 6, 0), (0x02, 4, 30), (0x04, 0, 0), (0x08, 6, 40), (0x10, 4, 0), (0x20, 0, 0)]);
    assert_eq!(acl_check(&cx(10, 1), &f, &l, MAY_READ), Some(true));
    assert_eq!(acl_check(&cx(30, 1), &f, &l, MAY_READ), Some(true));
    assert_eq!(acl_check(&cx(30, 1), &f, &l, MAY_WRITE), Some(false));
    // Named group limited by the mask (r only)
    assert_eq!(acl_check(&cx(31, 40), &f, &l, MAY_WRITE), Some(false));
    assert_eq!(acl_check(&cx(31, 40), &f, &l, MAY_READ), Some(true));
    // A group matched but not granting: denied, not "other"
    assert_eq!(acl_check(&cx(31, 20), &f, &l, MAY_READ), Some(false));
    assert_eq!(acl_check(&cx(31, 1), &f, &l, MAY_READ), Some(false));
    // Malformed or another version: the mode decides
    assert_eq!(acl_check(&cx(10, 1), &f, b"xx", MAY_READ), None);
    let mut v3 = l.clone();
    v3[0] = 3;
    assert_eq!(acl_check(&cx(10, 1), &f, &v3, MAY_READ), None);
    assert!(may(&cx(10, 1), &f, Some(b"xx"), MAY_READ));
    assert!(may(&cx(30, 1), &f, Some(&l), MAY_READ));
}

#[test]
fn when_an_acl_must_be_read() {
    let mut d = a(DIR | 0o700, 10, 20);
    assert!(!needs_acl(&cx(11, 1), &d, MAY_EXEC), "no xattrs: the mode decides");
    d.has_xattr = true;
    assert!(needs_acl(&cx(11, 1), &d, MAY_EXEC));
    assert!(!needs_acl(&cx(0, 0), &d, MAY_EXEC), "root passes anyway");
    d.mode = DIR | 0o711;
    assert!(needs_acl(&cx(11, 1), &d, MAY_EXEC), "even a mode open to all: user:bob:--- may deny");
    // ... which the ACL does
    let bob = acl(&[(0x01, 7, 0), (0x02, 0, 11), (0x04, 1, 0), (0x10, 1, 0), (0x20, 1, 0)]);
    assert!(!may(&cx(11, 1), &d, Some(&bob), MAY_EXEC));
    assert!(may(&cx(12, 1), &d, Some(&bob), MAY_EXEC));
    // An ACL with no entries is no ACL (the mode decides)
    assert_eq!(acl_check(&cx(11, 1), &d, &2u32.to_le_bytes(), MAY_EXEC), None);
}

#[test]
fn ctx_from_a_forwarded_call() {
    let mut c = LxCall::EMPTY;
    c.euid = 1000;
    c.egid = 100;
    c.caps = 1 << 2;
    c.ngroups = 2;
    c.groups[0] = 5;
    c.groups[1] = 6;
    c.mnt_ns = 3;
    let x = Ctx::from_call(&c, Node::new(0, 9));
    assert_eq!((x.uid, x.gid, x.ns, x.root), (1000, 100, 3, Node::new(0, 9)));
    assert!(x.in_group(100) && x.in_group(6) && !x.in_group(7));
    assert!(x.has_cap(2) && !x.has_cap(1));
    assert!(Ctx::new(0, 0, 0, Node::new(0, 2)).has_cap(1), "euid 0 passes as the kernel's rule");
    // More groups than fit are cut at LX_GROUPS
    c.ngroups = 10_000;
    let x = Ctx::from_call(&c, Node::new(0, 9));
    assert!(x.ngroups <= x.groups.len());
}
