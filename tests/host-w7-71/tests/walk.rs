//! vfs-server's path walk on the fake file system.

use hydra_hosttests_w7_71::ctx::{Ctx, Node};
use hydra_hosttests_w7_71::fake::{Cached, Fake, ROOT};
use hydra_hosttests_w7_71::cache::Cache;
use hydra_hosttests_w7_71::proto::{LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_DEV, LX_VFS_PSEUDO_PROC};
use hydra_hosttests_w7_71::walk::{self, BootMounts, MountInfo, MountKind, Mounts, ParentWalked, Redirect, Start, Walked, NOFOLLOW};

const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;
const EACCES: i64 = -13;
const ELOOP: i64 = -40;
const ENAMETOOLONG: i64 = -36;
const EEXIST: i64 = -17;

fn root_cx() -> Ctx {
    Ctx::new(0, 0, 0, Node::new(0, ROOT))
}

fn user_cx(uid: u32, gid: u32) -> Ctx {
    Ctx::new(uid, gid, 0, Node::new(0, ROOT))
}

fn found(r: Result<Walked, i64>) -> Result<u64, i64> {
    r.map(|w| match w {
        Walked::Found { node, .. } => node.ino,
        Walked::Redirect(r) => panic!("unexpected redirect {:?}", r),
    })
}

fn redir(r: Result<Walked, i64>) -> Redirect {
    match r.expect("walk") {
        Walked::Redirect(r) => r,
        Walked::Found { node, .. } => panic!("found {:?}, expected a redirect", node),
    }
}

/// /usr/bin/bash, /usr/lib, /bin -> usr/bin, /etc/passwd, /tmp (1777)
struct Tree {
    fs: Fake,
    usr: u64,
    bin: u64,
    bash: u64,
    lib: u64,
    etc: u64,
    passwd: u64,
    tmp: u64,
}

fn tree() -> Tree {
    let fs = Fake::new();
    let usr = fs.mkdir(ROOT, "usr", 0o755);
    let bin = fs.mkdir(usr, "bin", 0o755);
    let bash = fs.file(bin, "bash", 0o755);
    let lib = fs.mkdir(usr, "lib", 0o755);
    fs.symlink(ROOT, "bin", "usr/bin");
    let etc = fs.mkdir(ROOT, "etc", 0o755);
    let passwd = fs.file(etc, "passwd", 0o644);
    let tmp = fs.mkdir(ROOT, "tmp", 0o1777);
    Tree { fs, usr, bin, bash, lib, etc, passwd, tmp }
}

fn w(t: &Tree, cx: &Ctx, p: &str) -> Result<u64, i64> {
    found(walk::walk(&t.fs, cx, Start::Root, p.as_bytes(), 0))
}

#[test]
fn absolute_relative_and_dots() {
    let t = tree();
    let cx = root_cx();
    assert_eq!(w(&t, &cx, "/usr/bin/bash"), Ok(t.bash));
    assert_eq!(w(&t, &cx, "//usr///bin//bash"), Ok(t.bash));
    assert_eq!(w(&t, &cx, "/usr/./bin/../bin/bash"), Ok(t.bash));
    assert_eq!(w(&t, &cx, "/"), Ok(ROOT));
    assert_eq!(w(&t, &cx, "/.."), Ok(ROOT));
    assert_eq!(w(&t, &cx, "/../../usr/.."), Ok(ROOT));
    let at = Start::At(Node::new(0, t.usr));
    assert_eq!(found(walk::walk(&t.fs, &cx, at, b"bin/bash", 0)), Ok(t.bash));
    assert_eq!(found(walk::walk(&t.fs, &cx, at, b"..", 0)), Ok(ROOT));
    assert_eq!(found(walk::walk(&t.fs, &cx, at, b".", 0)), Ok(t.usr));
    assert_eq!(found(walk::walk(&t.fs, &cx, at, b"lib/", 0)), Ok(t.lib));
    // An absolute path ignores the start
    assert_eq!(found(walk::walk(&t.fs, &cx, at, b"/etc/passwd", 0)), Ok(t.passwd));
}

#[test]
fn attributes_come_with_the_answer() {
    let t = tree();
    match walk::walk(&t.fs, &root_cx(), Start::Root, b"/usr/bin/bash", 0).unwrap() {
        Walked::Found { node, attr } => {
            assert_eq!(node, Node::new(0, t.bash));
            assert_eq!(attr.ino, t.bash);
            assert_eq!(attr.mode & 0o777, 0o755);
        }
        _ => panic!(),
    }
}

#[test]
fn errors() {
    let t = tree();
    let cx = root_cx();
    assert_eq!(w(&t, &cx, ""), Err(ENOENT));
    assert_eq!(w(&t, &cx, "/nope"), Err(ENOENT));
    assert_eq!(w(&t, &cx, "/usr/nope/bash"), Err(ENOENT));
    assert_eq!(w(&t, &cx, "/etc/passwd/x"), Err(ENOTDIR));
    assert_eq!(w(&t, &cx, "/etc/passwd/"), Err(ENOTDIR));
    assert_eq!(w(&t, &cx, "/etc/passwd/."), Err(ENOTDIR));
    let long = format!("/{}", "a".repeat(256));
    assert_eq!(w(&t, &cx, &long), Err(ENAMETOOLONG));
    let ok255 = format!("/{}", "a".repeat(255));
    assert_eq!(w(&t, &cx, &ok255), Err(ENOENT));
    let huge = "/.".repeat(2048);
    assert_eq!(w(&t, &cx, &huge), Err(ENAMETOOLONG));
    // A start that is not a directory
    assert_eq!(found(walk::walk(&t.fs, &cx, Start::At(Node::new(0, t.passwd)), b"x", 0)), Err(ENOTDIR));
}

#[test]
fn symbolic_links() {
    let t = tree();
    let cx = root_cx();
    let link = t.fs.symlink(t.tmp, "abs", "/usr/bin");
    let rel = t.fs.symlink(t.tmp, "rel", "../usr/lib");
    t.fs.symlink(t.tmp, "chain", "rel/../bin/bash");
    t.fs.symlink(t.tmp, "dangling", "nowhere");
    t.fs.symlink(t.tmp, "l1", "l2");
    t.fs.symlink(t.tmp, "l2", "l1");
    t.fs.symlink(t.tmp, "empty", "");
    assert_eq!(w(&t, &cx, "/bin/bash"), Ok(t.bash));
    assert_eq!(w(&t, &cx, "/tmp/abs/bash"), Ok(t.bash));
    assert_eq!(w(&t, &cx, "/tmp/rel"), Ok(t.lib));
    assert_eq!(w(&t, &cx, "/tmp/chain"), Ok(t.bash));
    // The last component: followed unless NOFOLLOW; a trailing slash always follows
    assert_eq!(found(walk::walk(&t.fs, &cx, Start::Root, b"/tmp/abs", NOFOLLOW)), Ok(link));
    assert_eq!(found(walk::walk(&t.fs, &cx, Start::Root, b"/tmp/rel", NOFOLLOW)), Ok(rel));
    assert_eq!(found(walk::walk(&t.fs, &cx, Start::Root, b"/tmp/abs/", NOFOLLOW)), Ok(t.bin));
    assert_eq!(w(&t, &cx, "/tmp/dangling"), Err(ENOENT));
    assert!(found(walk::walk(&t.fs, &cx, Start::Root, b"/tmp/dangling", NOFOLLOW)).is_ok());
    assert_eq!(w(&t, &cx, "/tmp/l1"), Err(ELOOP));
    assert_eq!(w(&t, &cx, "/tmp/empty"), Err(ENOENT));
}

#[test]
fn forty_links_and_no_more() {
    let t = tree();
    let cx = root_cx();
    // n0 -> n1 -> ... -> n40 -> /usr/bin/bash: 41 links
    for i in 0..=40 {
        let target = if i == 40 { "/usr/bin/bash".to_string() } else { format!("n{}", i + 1) };
        t.fs.symlink(t.tmp, &format!("n{}", i), &target);
    }
    assert_eq!(w(&t, &cx, "/tmp/n1"), Ok(t.bash), "40 links are allowed");
    assert_eq!(w(&t, &cx, "/tmp/n0"), Err(ELOOP), "the 41st is too many");
}

#[test]
fn links_stay_inside_the_callers_root() {
    // A chroot at /jail: an absolute link and .. both stay inside
    let t = tree();
    let jail = t.fs.mkdir(ROOT, "jail", 0o755);
    let jbin = t.fs.mkdir(jail, "bin", 0o755);
    t.fs.symlink(jail, "abs", "/bin");
    let cx = Ctx::new(0, 0, 0, Node::new(0, jail));
    assert_eq!(w(&t, &cx, "/abs"), Ok(jbin));
    assert_eq!(w(&t, &cx, "/../../bin"), Ok(jbin));
    assert_eq!(w(&t, &cx, "/bin/../.."), Ok(jail));
    assert_eq!(w(&t, &cx, "/usr"), Err(ENOENT));
}

#[test]
fn search_permission() {
    let t = tree();
    let private = t.fs.mkdir(t.tmp, "private", 0o700);
    t.fs.chown(private, 1000, 1000);
    let f = t.fs.file(private, "f", 0o644);
    let group = t.fs.mkdir(t.tmp, "group", 0o710);
    t.fs.chown(group, 0, 50);
    let g = t.fs.file(group, "g", 0o644);
    let owner = user_cx(1000, 1000);
    let other = user_cx(1001, 1001);
    assert_eq!(w(&t, &owner, "/tmp/private/f"), Ok(f));
    assert_eq!(w(&t, &other, "/tmp/private/f"), Err(EACCES));
    // The directory itself may be named (no lookup inside it)
    assert_eq!(w(&t, &other, "/tmp/private"), Ok(private));
    // .. out of it needs search permission too
    assert_eq!(w(&t, &other, "/tmp/private/.."), Err(EACCES));
    // Group members, by primary or supplementary group
    assert_eq!(w(&t, &user_cx(5, 50), "/tmp/group/g"), Ok(g));
    assert_eq!(w(&t, &user_cx(5, 5).with_group(50), "/tmp/group/g"), Ok(g));
    assert_eq!(w(&t, &user_cx(5, 5), "/tmp/group/g"), Err(EACCES));
    // Root and the capabilities pass
    assert_eq!(w(&t, &root_cx(), "/tmp/private/f"), Ok(f));
    assert_eq!(w(&t, &Ctx::new(7, 7, 1 << 2, Node::new(0, ROOT)), "/tmp/private/f"), Ok(f));
    assert_eq!(w(&t, &Ctx::new(7, 7, 1 << 1, Node::new(0, ROOT)), "/tmp/private/f"), Ok(f));
    // A mode-0 directory: even its owner is refused (no capability)
    t.fs.chmod(private, 0);
    assert_eq!(w(&t, &owner, "/tmp/private/f"), Err(EACCES));
}

/// An ACL in Linux's encoding: version 2, then (tag, perm, id) entries.
fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for &(t, p, i) in entries {
        v.extend_from_slice(&t.to_le_bytes());
        v.extend_from_slice(&p.to_le_bytes());
        v.extend_from_slice(&i.to_le_bytes());
    }
    v
}

#[test]
fn search_permission_by_acl() {
    let t = tree();
    let d = t.fs.mkdir(t.tmp, "acl", 0o700);
    let f = t.fs.file(d, "f", 0o644);
    // user::rwx user:1234:--x group::--- mask::--x other::---
    t.fs.set_acl(d, acl(&[(0x01, 7, 0), (0x02, 1, 1234), (0x04, 0, 0), (0x10, 1, 0), (0x20, 0, 0)]));
    assert_eq!(w(&t, &user_cx(1234, 1234), "/tmp/acl/f"), Ok(f));
    assert_eq!(w(&t, &user_cx(1235, 1235), "/tmp/acl/f"), Err(EACCES));
    // The mask limits the named user's entry
    t.fs.set_acl(d, acl(&[(0x01, 7, 0), (0x02, 1, 1234), (0x04, 0, 0), (0x10, 0, 0), (0x20, 0, 0)]));
    assert_eq!(w(&t, &user_cx(1234, 1234), "/tmp/acl/f"), Err(EACCES));
    // A named group
    t.fs.set_acl(d, acl(&[(0x01, 7, 0), (0x04, 0, 0), (0x08, 1, 77), (0x10, 7, 0), (0x20, 0, 0)]));
    assert_eq!(w(&t, &user_cx(9, 9).with_group(77), "/tmp/acl/f"), Ok(f));
    assert_eq!(w(&t, &user_cx(9, 9), "/tmp/acl/f"), Err(EACCES));
}

#[test]
fn pseudo_file_systems_under_the_root_redirect() {
    let t = tree();
    let cx = root_cx();
    let mut t = t;
    t.fs.mounts.pseudo = vec![(b"proc".to_vec(), LXS_PROC, LX_VFS_PSEUDO_PROC), (b"dev".to_vec(), LXS_LINUX, LX_VFS_PSEUDO_DEV)];
    let r = redir(walk::walk(&t.fs, &cx, Start::Root, b"/proc/self/stat", 0));
    assert_eq!(r, Redirect { svc: LXS_PROC, obj: LX_VFS_PSEUDO_PROC, tail: Some(6), text: vec![] });
    // The mount itself: the rest is empty (tail at the end)
    assert_eq!(redir(walk::walk(&t.fs, &cx, Start::Root, b"/proc", 0)).tail, Some(5));
    assert_eq!(redir(walk::walk(&t.fs, &cx, Start::Root, b"/dev//null", 0)).tail, Some(6));
    // Reached through .. and from a relative start at the root
    assert_eq!(redir(walk::walk(&t.fs, &cx, Start::Root, b"/usr/../proc/1/maps", 0)).tail, Some(13));
    assert_eq!(redir(walk::walk(&t.fs, &cx, Start::At(Node::new(0, ROOT)), b"proc/1", 0)).tail, Some(5));
    // Only directly under the caller's root: /usr/proc is an ordinary (missing) name
    assert_eq!(w(&t, &cx, "/usr/proc"), Err(ENOENT));
    // A link that leads there: the rest is text
    t.fs.symlink(t.etc, "mtab", "../proc/self/mounts");
    let r = redir(walk::walk(&t.fs, &cx, Start::Root, b"/etc/mtab", 0));
    assert_eq!((r.tail, r.text.as_slice()), (None, &b"self/mounts"[..]));
    // A link to the mount, then the argument's own rest: still a suffix
    t.fs.symlink(t.tmp, "p", "/proc");
    let r = redir(walk::walk(&t.fs, &cx, Start::Root, b"/tmp/p/self/fd", 0));
    assert_eq!((r.tail, r.text.as_slice()), (Some(7), &b""[..]));
    // In a chroot, the jail's proc
    let jail = t.fs.mkdir(ROOT, "jail", 0o755);
    let jcx = Ctx::new(0, 0, 0, Node::new(0, jail));
    assert_eq!(redir(walk::walk(&t.fs, &jcx, Start::Root, b"/proc/x", 0)).svc, LXS_PROC);
    // The boot table names proc, sys, dev; off: nothing
    let b = BootMounts { pseudo: true };
    assert_eq!(b.pseudo_at_root(0, b"sys").map(|p| p.0), Some(LXS_LINUX));
    assert_eq!(b.pseudo_at_root(0, b"proc").map(|p| p.0), Some(LXS_PROC));
    assert_eq!(b.pseudo_at_root(0, b"usr"), None);
    assert_eq!(BootMounts { pseudo: false }.pseudo_at_root(0, b"proc"), None);
    assert_eq!(b.covering(0, Node::new(0, ROOT)), None);
    assert_eq!(b.mount(0, 1), None);
}

#[test]
fn mounts_are_crossed_both_ways() {
    let mut t = tree();
    let cx = root_cx();
    // /mnt covered by a bind mount of /usr (mount 1), and /mnt/lib by one of /etc (mount 2)
    let mnt = t.fs.mkdir(ROOT, "mnt", 0o755);
    t.fs.mounts.list.push(MountInfo { parent: 0, mountpoint: Node::new(0, mnt), root: Node::new(1, t.usr), kind: MountKind::Zfs });
    t.fs.mounts.list.push(MountInfo { parent: 1, mountpoint: Node::new(1, t.lib), root: Node::new(2, t.etc), kind: MountKind::Zfs });
    match walk::walk(&t.fs, &cx, Start::Root, b"/mnt/bin/bash", 0).unwrap() {
        Walked::Found { node, .. } => assert_eq!(node, Node::new(1, t.bash)),
        _ => panic!(),
    }
    match walk::walk(&t.fs, &cx, Start::Root, b"/mnt/lib/passwd", 0).unwrap() {
        Walked::Found { node, .. } => assert_eq!(node, Node::new(2, t.passwd)),
        _ => panic!(),
    }
    // .. from a mounted root goes to the covered directory's parent
    match walk::walk(&t.fs, &cx, Start::Root, b"/mnt/lib/../bin", 0).unwrap() {
        Walked::Found { node, .. } => assert_eq!(node, Node::new(1, t.bin)),
        _ => panic!(),
    }
    match walk::walk(&t.fs, &cx, Start::Root, b"/mnt/..", 0).unwrap() {
        Walked::Found { node, .. } => assert_eq!(node, Node::new(0, ROOT)),
        _ => panic!(),
    }
    // A mount another service serves: a redirect with the rest of the path
    let fuse = t.fs.mkdir(ROOT, "fuse", 0o755);
    t.fs.mounts.list.push(MountInfo { parent: 0, mountpoint: Node::new(0, fuse), root: Node::new(3, 0), kind: MountKind::Redirect { svc: 9, obj: 42 } });
    assert_eq!(redir(walk::walk(&t.fs, &cx, Start::Root, b"/fuse/a/b", 0)), Redirect { svc: 9, obj: 42, tail: Some(6), text: vec![] });
}

#[test]
fn parent_walks() {
    let t = tree();
    let cx = root_cx();
    let p = |path: &str| match walk::walk_parent(&t.fs, &cx, Start::Root, path.as_bytes()) {
        Ok(ParentWalked::Found(p)) => Ok((p.dir.ino, String::from_utf8(p.name).unwrap(), p.child.map(|c| c.ino))),
        Ok(ParentWalked::Redirect(r)) => panic!("redirect {:?}", r),
        Err(e) => Err(e),
    };
    assert_eq!(p("/usr/bin/bash"), Ok((t.bin, "bash".into(), Some(t.bash))));
    assert_eq!(p("/usr/bin/new"), Ok((t.bin, "new".into(), None)));
    assert_eq!(p("/usr/bin/"), Ok((t.usr, "bin".into(), Some(t.bin))));
    assert_eq!(p("/usr"), Ok((ROOT, "usr".into(), Some(t.usr))));
    assert_eq!(p("/usr/bin/.."), Ok((t.bin, "..".into(), None)));
    assert_eq!(p("/"), Err(EEXIST));
    assert_eq!(p("///"), Err(EEXIST));
    assert_eq!(p("/nope/x"), Err(ENOENT));
    assert_eq!(p("/etc/passwd/x"), Err(ENOTDIR));
    assert_eq!(p(""), Err(ENOENT));
    // The parent is followed (a link to a directory)
    assert_eq!(p("/bin/zsh"), Ok((t.bin, "zsh".into(), None)));
    // A relative name: the start is the directory
    match walk::walk_parent(&t.fs, &cx, Start::At(Node::new(0, t.etc)), b"passwd").unwrap() {
        ParentWalked::Found(p) => assert_eq!((p.dir.ino, p.child.map(|c| c.ino)), (t.etc, Some(t.passwd))),
        _ => panic!(),
    }
    // Search permission on the parent
    let private = t.fs.mkdir(t.tmp, "priv", 0o700);
    let _ = private;
    assert_eq!(walk::walk_parent(&t.fs, &user_cx(9, 9), Start::Root, b"/tmp/priv/x").err(), Some(EACCES));
}

#[test]
fn parent_walk_into_a_pseudo_file_system_redirects() {
    let mut t = tree();
    t.fs.mounts.pseudo = vec![(b"proc".to_vec(), LXS_PROC, LX_VFS_PSEUDO_PROC)];
    let cx = root_cx();
    match walk::walk_parent(&t.fs, &cx, Start::Root, b"/proc/self/x").unwrap() {
        ParentWalked::Redirect(r) => assert_eq!((r.svc, r.tail), (LXS_PROC, Some(6))),
        _ => panic!(),
    }
    match walk::walk_parent(&t.fs, &cx, Start::Root, b"/proc").unwrap() {
        ParentWalked::Redirect(r) => assert_eq!(r.tail, Some(5)),
        _ => panic!(),
    }
}

#[test]
fn a_warm_walk_asks_the_back_end_nothing() {
    let t = tree();
    let cache = Cache::new(1024);
    let be = Cached { fs: &t.fs, cache: &cache };
    let cx = root_cx();
    let first = found(walk::walk(&be, &cx, Start::Root, b"/bin/bash", 0));
    assert_eq!(first, Ok(t.bash));
    let n = t.fs.requests.get();
    assert!(n > 0);
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/bin/bash", 0)), Ok(t.bash));
    assert_eq!(t.fs.requests.get(), n, "the second walk is answered from the caches");
    // A missing name is remembered too
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/usr/nope", 0)), Err(ENOENT));
    let n = t.fs.requests.get();
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/usr/nope", 0)), Err(ENOENT));
    assert_eq!(t.fs.requests.get(), n);
    // After a change and its invalidation, the walk sees it
    t.fs.file(t.usr, "nope", 0o644);
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/usr/nope", 0)), Err(ENOENT), "stale until forgotten");
    cache.forget_name(Node::new(0, t.usr), b"nope");
    assert!(found(walk::walk(&be, &cx, Start::Root, b"/usr/nope", 0)).is_ok());
    t.fs.unlink(t.usr, "nope");
    cache.forget_dir(Node::new(0, t.usr));
    assert_eq!(found(walk::walk(&be, &cx, Start::Root, b"/usr/nope", 0)), Err(ENOENT));
    let s = cache.stats();
    assert!(s.name_hits > 0 && s.name_misses > 0 && s.attr_hits > 0 && s.link_hits > 0);
}

#[test]
fn a_permission_change_reaches_the_walk_after_forget_attr() {
    let t = tree();
    let cache = Cache::new(1024);
    let be = Cached { fs: &t.fs, cache: &cache };
    let d = t.fs.mkdir(t.tmp, "d", 0o755);
    let f = t.fs.file(d, "f", 0o644);
    let user = user_cx(9, 9);
    assert_eq!(found(walk::walk(&be, &user, Start::Root, b"/tmp/d/f", 0)), Ok(f));
    t.fs.chmod(d, 0o700);
    cache.forget_attr(Node::new(0, d));
    assert_eq!(found(walk::walk(&be, &user, Start::Root, b"/tmp/d/f", 0)), Err(EACCES));
    // The kernel's note names the object only: every mount's copy goes
    t.fs.chmod(d, 0o755);
    cache.forget_object(d);
    assert_eq!(found(walk::walk(&be, &user, Start::Root, b"/tmp/d/f", 0)), Ok(f));
}
