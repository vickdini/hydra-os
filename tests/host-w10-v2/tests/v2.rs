//! Group V2's host tests (wave 10): the walk's path record (`walk::Track`) and served-name
//! hook, the served names of `/sys` and `/dev`, the trees `statfs` shows, `/dev/pts` names.

use hydra_hosttests_w10_v2::calls::served::{self, Tree};
use hydra_hosttests_w10_v2::ctx::{Ctx, Node};
use hydra_hosttests_w10_v2::devpts::{self, Pts};
use hydra_hosttests_w10_v2::fake::{Fake, ROOT};
use hydra_hosttests_w10_v2::fs::fsproto::Attr;
use hydra_hosttests_w10_v2::fstree::*;
use hydra_hosttests_w10_v2::proto::{SvcId, LXS_LINUX, LXS_PROC, LXS_TTY, LX_VFS_PSEUDO_DEVPTS, LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};
use hydra_hosttests_w10_v2::walk::{self, Backend, Mounts, ParentWalked, Start, Track, Walked, NOFOLLOW};

const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;

fn root() -> Ctx {
    Ctx::new(0, 0, 0, Node::new(0, ROOT))
}

// ----------------------------------------------------------------------
// The walk's path (chdir's getcwd)
// ----------------------------------------------------------------------

/// /a/b/c, /l -> a/b (relative), /abs -> /a (absolute), /a/b/up -> .. , /a/f (file)
struct T {
    fs: Fake,
    a: u64,
    b: u64,
    c: u64,
}

fn tree() -> T {
    let fs = Fake::new();
    let a = fs.mkdir(ROOT, "a", 0o755);
    let b = fs.mkdir(a, "b", 0o755);
    let c = fs.mkdir(b, "c", 0o755);
    fs.symlink(ROOT, "l", "a/b");
    fs.symlink(ROOT, "abs", "/a");
    fs.symlink(b, "up", "..");
    fs.file(a, "f", 0o644);
    T { fs, a, b, c }
}

fn track(fs: &Fake, start: Start, path: &str) -> (u64, Track) {
    match walk::walk_track(fs, &root(), start, path.as_bytes(), 0).expect("walk") {
        (Walked::Found { node, .. }, t) => (node.ino, t),
        (Walked::Redirect(r), _) => panic!("redirect {r:?}"),
    }
}

fn text(t: &Track) -> String {
    String::from_utf8(t.text()).unwrap()
}

#[test]
fn an_absolute_walk_records_the_names_from_the_root() {
    let t = tree();
    let (n, tr) = track(&t.fs, Start::Root, "/a/b/c");
    assert_eq!(n, t.c);
    assert_eq!(text(&tr), "/a/b/c");
    assert!(tr.abs);
    let (_, tr) = track(&t.fs, Start::Root, "/a/./b//c/../c/");
    assert_eq!(text(&tr), "/a/b/c");
    let (n, tr) = track(&t.fs, Start::Root, "/");
    assert_eq!((n, text(&tr)), (ROOT, "/".into()));
    let (_, tr) = track(&t.fs, Start::Root, "/..");
    assert_eq!(text(&tr), "/");
}

#[test]
fn links_are_resolved_in_the_record() {
    let t = tree();
    // a relative link continues from the directory it is in
    let (n, tr) = track(&t.fs, Start::Root, "/l/c");
    assert_eq!(n, t.c);
    assert_eq!(text(&tr), "/a/b/c");
    // an absolute link starts again at the root
    let (n, tr) = track(&t.fs, Start::At(Node::new(0, t.c)), "../../../abs/b");
    assert_eq!(n, t.b);
    assert_eq!(text(&tr), "/a/b");
    // `..` inside a link's target
    let (n, tr) = track(&t.fs, Start::Root, "/a/b/up/b");
    assert_eq!(n, t.b);
    assert_eq!(text(&tr), "/a/b");
    // a link as the last component (followed)
    let (n, tr) = track(&t.fs, Start::Root, "/abs");
    assert_eq!((n, text(&tr)), (t.a, "/a".into()));
}

#[test]
fn a_relative_walk_records_the_climb_above_its_start() {
    let t = tree();
    let at_c = Start::At(Node::new(0, t.c));
    let (n, tr) = track(&t.fs, at_c, "..");
    assert_eq!(n, t.b);
    assert!(!tr.abs);
    assert_eq!((tr.ups, text(&tr)), (1, "../".into()));
    let (n, tr) = track(&t.fs, at_c, "../../b/c");
    assert_eq!(n, t.c);
    assert_eq!(text(&tr), "../../b/c");
    let (_, tr) = track(&t.fs, at_c, ".");
    assert_eq!(text(&tr), ".");
    // back to the root by `..`: from the root again
    let (n, tr) = track(&t.fs, at_c, "../../../a");
    assert_eq!(n, t.a);
    assert_eq!(text(&tr), "/a");
    // a start at the root is the root
    let (_, tr) = track(&t.fs, Start::At(Node::new(0, ROOT)), "a/b");
    assert_eq!(text(&tr), "/a/b");
}

#[test]
fn the_record_does_not_change_the_walk() {
    let t = tree();
    for p in ["/a/b/c", "/l/c", "/abs/b/up/f", "a/f/", "/nonexistent", "/a/f/x"] {
        let plain = walk::walk(&t.fs, &root(), Start::Root, p.as_bytes(), 0).map(|w| match w {
            Walked::Found { node, .. } => node,
            Walked::Redirect(_) => Node::new(9, 9),
        });
        let tracked = walk::walk_track(&t.fs, &root(), Start::Root, p.as_bytes(), 0).map(|(w, _)| match w {
            Walked::Found { node, .. } => node,
            Walked::Redirect(_) => Node::new(9, 9),
        });
        assert_eq!(plain, tracked, "{p}");
    }
    assert_eq!(walk::walk_track(&t.fs, &root(), Start::Root, b"/a/f/", 0).err(), Some(ENOTDIR));
    assert_eq!(walk::walk_track(&t.fs, &root(), Start::Root, b"/zz", NOFOLLOW).err(), Some(ENOENT));
}

// ----------------------------------------------------------------------
// The served-name hook in the walk
// ----------------------------------------------------------------------

/// The fake file system with /sys and /dev, served names as vfs-server's `Walker` has them.
struct WithServed<'a> {
    fs: &'a Fake,
    open: bool,
}

impl Backend for WithServed<'_> {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        self.fs.lookup(dir, name)
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        self.fs.getattr(n)
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        self.fs.readlink(n)
    }
    fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64> {
        self.fs.acl(n)
    }
    fn mounts(&self) -> &dyn Mounts {
        self.fs.mounts()
    }
    fn may_serve(&self, name: &[u8]) -> bool {
        served::may_serve(name)
    }
    fn served(&self, cx: &Ctx, dir: Node, name: &[u8], rest: &[&[u8]]) -> Option<(SvcId, u64)> {
        served::check(self, cx, dir, name, rest, self.open)
    }
}

/// /sys/class/drm, /sys/devices/platform, /sys/fs/cgroup/user, /sys/firmware/efi/efivars/V,
/// /dev/null (a file here), /dev/shm, /x/devices (not under /sys)
fn sysdev() -> Fake {
    let fs = Fake::new();
    let sys = fs.mkdir(ROOT, "sys", 0o755);
    let class = fs.mkdir(sys, "class", 0o755);
    fs.mkdir(class, "drm", 0o755);
    let dev = fs.mkdir(sys, "devices", 0o755);
    fs.mkdir(dev, "platform", 0o755);
    let fsd = fs.mkdir(sys, "fs", 0o755);
    let cg = fs.mkdir(fsd, "cgroup", 0o755);
    fs.mkdir(cg, "user", 0o755);
    let fw = fs.mkdir(sys, "firmware", 0o755);
    let efi = fs.mkdir(fw, "efi", 0o755);
    let ev = fs.mkdir(efi, "efivars", 0o755);
    fs.file(ev, "Boot0000-x", 0o644);
    let d = fs.mkdir(ROOT, "dev", 0o755);
    fs.file(d, "null", 0o666);
    fs.mkdir(d, "shm", 0o1777);
    let x = fs.mkdir(ROOT, "x", 0o755);
    fs.mkdir(x, "devices", 0o755);
    fs.mkdir(x, "pts", 0o755);
    fs.symlink(ROOT, "sl", "sys/devices");
    fs
}

fn go(fs: &Fake, open: bool, start: Start, path: &str) -> Result<Walked, i64> {
    walk::walk(&WithServed { fs, open }, &root(), start, path.as_bytes(), 0)
}

fn redirect(fs: &Fake, open: bool, path: &str) -> (SvcId, u64, Option<u32>) {
    match go(fs, open, Start::Root, path).expect(path) {
        Walked::Redirect(r) => (r.svc, r.obj, r.tail),
        Walked::Found { node, .. } => panic!("{path}: found {node:?}"),
    }
}

#[test]
fn sys_and_dev_are_walked_with_the_served_names_redirected() {
    let fs = sysdev();
    // the cpu ranges: linux-server, the tail below /sys as before
    let p = "/sys/devices/system/cpu/online";
    assert_eq!(redirect(&fs, false, p), (LXS_LINUX, LX_VFS_PSEUDO_SYS, Some(5)));
    assert_eq!(&p[5..], "devices/system/cpu/online");
    assert_eq!(redirect(&fs, false, "/sys/devices/system/cpu/possible").0, LXS_LINUX);
    // other names under devices: the pool
    assert!(matches!(go(&fs, false, Start::Root, "/sys/devices/platform"), Ok(Walked::Found { .. })));
    assert_eq!(go(&fs, false, Start::Root, "/sys/devices/system/cpu/cpu0").err(), Some(ENOENT));
    assert_eq!(go(&fs, false, Start::Root, "/sys/devices/system/cpu").err(), Some(ENOENT));
    // efivars: only an open is redirected
    assert_eq!(redirect(&fs, true, "/sys/firmware/efi/efivars/Boot0000-x"), (LXS_LINUX, LX_VFS_PSEUDO_SYS, Some(5)));
    assert!(matches!(go(&fs, false, Start::Root, "/sys/firmware/efi/efivars/Boot0000-x"), Ok(Walked::Found { .. })));
    // cgroup.procs: the kernel's
    assert_eq!(redirect(&fs, false, "/sys/fs/cgroup/user/cgroup.procs").0, 0);
    assert_eq!(redirect(&fs, false, "/sys/fs/cgroup/cgroup.procs").0, 0);
    assert!(matches!(go(&fs, false, Start::Root, "/sys/fs/cgroup/user"), Ok(Walked::Found { .. })));
    // /dev/pts: the terminal service, the tail starting at `pts`
    let p = "/dev/pts/3";
    assert_eq!(redirect(&fs, true, p), (LXS_TTY, LX_VFS_PSEUDO_DEVPTS, Some(5)));
    assert_eq!(redirect(&fs, false, "/dev/pts").2, Some(5));
    // the pool's /dev nodes
    assert!(matches!(go(&fs, true, Start::Root, "/dev/null"), Ok(Walked::Found { .. })));
    // the same names elsewhere: nothing special
    assert!(matches!(go(&fs, false, Start::Root, "/x/devices"), Ok(Walked::Found { .. })));
    assert!(matches!(go(&fs, false, Start::Root, "/x/pts"), Ok(Walked::Found { .. })));
}

#[test]
fn relative_walks_meet_the_served_names_too() {
    let fs = sysdev();
    let sys = fs.lookup(Node::new(0, ROOT), b"sys").unwrap();
    let dev = fs.lookup(Node::new(0, ROOT), b"dev").unwrap();
    // openat(sysfd, "devices/system/cpu/online"): the tail is the argument's own
    match go(&fs, false, Start::At(sys), "devices/system/cpu/online").unwrap() {
        Walked::Redirect(r) => assert_eq!((r.svc, r.tail), (LXS_LINUX, Some(0))),
        _ => panic!(),
    }
    match go(&fs, false, Start::At(dev), "pts/0").unwrap() {
        Walked::Redirect(r) => assert_eq!((r.svc, r.obj, r.tail), (LXS_TTY, LX_VFS_PSEUDO_DEVPTS, Some(0))),
        _ => panic!(),
    }
    // a walk relative to a /sys directory below the top: the pool
    let class = fs.lookup(sys, b"class").unwrap();
    assert!(matches!(go(&fs, false, Start::At(class), "drm"), Ok(Walked::Found { .. })));
    assert!(matches!(go(&fs, false, Start::At(class), "../devices/platform"), Ok(Walked::Found { .. })));
    // through a link into /sys: a redirect whose rest is text (vfs-server: the kernel)
    match go(&fs, false, Start::Root, "/sl/system/cpu/online").unwrap() {
        Walked::Redirect(r) => assert_eq!((r.svc, r.tail, r.text.as_slice()), (LXS_LINUX, None, &b"devices/system/cpu/online"[..])),
        _ => panic!(),
    }
    // the boot rule: only /proc is redirected by name under the root now
    let boot = walk::BootMounts { pseudo: true };
    assert_eq!(boot.pseudo_at_root(0, b"proc"), Some((LXS_PROC, LX_VFS_PSEUDO_PROC)));
    assert_eq!(boot.pseudo_at_root(0, b"sys"), None);
    assert_eq!(boot.pseudo_at_root(0, b"dev"), None);
}

#[test]
fn a_parent_walk_redirects_a_served_last_name() {
    let fs = sysdev();
    let be = WithServed { fs: &fs, open: false };
    match walk::walk_parent(&be, &root(), Start::Root, b"/dev/pts").unwrap() {
        ParentWalked::Redirect(r) => assert_eq!((r.svc, r.tail), (LXS_TTY, Some(5))),
        _ => panic!(),
    }
    match walk::walk_parent(&be, &root(), Start::Root, b"/dev/pts/5").unwrap() {
        ParentWalked::Redirect(r) => assert_eq!((r.svc, r.tail), (LXS_TTY, Some(5))),
        _ => panic!(),
    }
    // (cgroup.procs is matched on the whole path: a parent walk to it finds its directory;
    // making or removing that name is the pool's ENOENT/EEXIST, rare)
    assert!(matches!(walk::walk_parent(&be, &root(), Start::Root, b"/sys/fs/cgroup/user/cgroup.procs").unwrap(), ParentWalked::Found(_)));
    assert!(matches!(walk::walk_parent(&be, &root(), Start::Root, b"/dev/newnode").unwrap(), ParentWalked::Found(_)));
}

#[test]
fn the_served_names_by_themselves() {
    assert!(served::may_serve(b"devices") && served::may_serve(b"pts") && served::may_serve(b"fs") && served::may_serve(b"firmware"));
    assert!(!served::may_serve(b"class") && !served::may_serve(b"null"));
    assert_eq!(served::tree_of(b"pts"), Tree::Dev);
    assert_eq!(served::tree_of(b"devices"), Tree::Sys);
    assert_eq!(served::served(Tree::Sys, b"devices", &[b"system", b"cpu", b"present"], false), Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)));
    assert_eq!(served::served(Tree::Sys, b"devices", &[b"system", b"cpu"], false), None);
    assert_eq!(served::served(Tree::Sys, b"devices", &[b"system", b"cpu", b"online", b"x"], false), None);
    assert_eq!(served::served(Tree::Sys, b"firmware", &[b"efi", b"efivars", b"X"], true), Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)));
    assert_eq!(served::served(Tree::Sys, b"firmware", &[b"efi", b"efivars", b"X"], false), None);
    assert_eq!(served::served(Tree::Sys, b"firmware", &[b"efi", b"efivars"], true), None);
    assert_eq!(served::served(Tree::Sys, b"fs", &[b"cgroup", b"a", b"b", b"cgroup.procs"], false), Some((0, 0)));
    assert_eq!(served::served(Tree::Sys, b"fs", &[b"cgroup", b"cgroup.threads"], false), None);
    assert_eq!(served::served(Tree::Sys, b"fs", &[b"cgroup.procs"], false), None);
    assert_eq!(served::served(Tree::Dev, b"pts", &[], false), Some((LXS_TTY, LX_VFS_PSEUDO_DEVPTS)));
}

// ----------------------------------------------------------------------
// The trees statfs shows (the kernel's and vfs-server's shared rules)
// ----------------------------------------------------------------------

#[test]
fn paths_have_trees() {
    assert_eq!(class_of(b"/sys"), TREE_SYS);
    assert_eq!(class_of(b"/sys/class/drm"), TREE_SYS);
    assert_eq!(class_of(b"/sys/fs/cgroup"), TREE_CGROUP);
    assert_eq!(class_of(b"/sys/fs/cgroup/user.slice/x"), TREE_CGROUP);
    assert_eq!(class_of(b"/sys/fs/cgroupx"), TREE_SYS);
    assert_eq!(class_of(b"/sys/firmware/efi/efivars/Boot0000"), TREE_EFIVARS);
    assert_eq!(class_of(b"/dev"), TREE_DEV);
    assert_eq!(class_of(b"/dev/shm/a"), TREE_DEV);
    assert_eq!(class_of(b"/dev/pts/3"), TREE_DEVPTS);
    for p in [&b"/"[..], b"/system", b"/devices", b"/home/sys", b"/sysfoo", b"/de", b"", b"sys"] {
        assert_eq!(class_of(p), TREE_POOL, "{:?}", core::str::from_utf8(p));
    }
    assert_eq!(class_of_names(&[b"sys", b"fs", b"cgroup"]), TREE_CGROUP);
    assert_eq!(class_of_names(&[b"sys", b"fs"]), TREE_SYS);
    assert_eq!(class_of_names(&[b"sys", b"firmware", b"efi", b"efivars", b"V"]), TREE_EFIVARS);
    assert_eq!(class_of_names(&[b"dev", b"pts"]), TREE_DEVPTS);
    assert_eq!(class_of_names(&[b"dev"]), TREE_DEV);
    assert_eq!(class_of_names(&[]), TREE_POOL);
    assert_eq!(class_of_names(&[b"usr", b"sys"]), TREE_POOL);
    assert_eq!(class_below(TREE_DEV, &[b"pts", b"1"]), TREE_DEVPTS);
    assert_eq!(class_below(TREE_SYS, &[b"fs", b"cgroup"]), TREE_SYS);
    assert_eq!(class_below(TREE_POOL, &[b"sys"]), TREE_POOL);
}

#[test]
fn trees_travel_in_spare_flag_bits() {
    // a handle's open flags (below bit 23) and the kernel's marks (bits 30, 31) stay apart
    let flags = 0o2 | 0o4000 | 0o200000 | 0o10000000 | 1 << 30 | 1 << 31;
    for t in [TREE_POOL, TREE_SYS, TREE_CGROUP, TREE_EFIVARS, TREE_DEV, TREE_DEVPTS] {
        assert!(t <= MASK);
    }
    let v = flags | at_bits("/sys/fs/cgroup");
    assert_eq!(at_of(v), TREE_CGROUP);
    assert_eq!(v & !(MASK << AT_SHIFT), flags);
    // the LX_FS_* bits (up to 128) and the working directory's tree
    let fs = 0xFF | cwd_bits("/dev/pts");
    assert_eq!(cwd_of(fs), TREE_DEVPTS);
    assert_eq!(fs & 0xFF, 0xFF);
    assert_eq!(at_bits("/etc"), 0);
    assert_eq!(cwd_bits("/"), 0);
}

#[test]
fn trees_have_the_kernels_statfs_types() {
    assert_eq!(magic_of(TREE_SYS), 0x6265_6572);
    assert_eq!(magic_of(TREE_CGROUP), 0x6367_7270);
    assert_eq!(magic_of(TREE_EFIVARS), 0xde5e_81e4);
    assert_eq!(magic_of(TREE_DEVPTS), 0x1cd1);
    // the pool and /dev: the pool's own numbers
    assert_eq!(magic_of(TREE_POOL), 0);
    assert_eq!(magic_of(TREE_DEV), 0);
}

// ----------------------------------------------------------------------
// tty-server's /dev/pts names
// ----------------------------------------------------------------------

#[test]
fn pts_names() {
    assert_eq!(devpts::parse(b"pts"), Pts::Dir);
    assert_eq!(devpts::parse(b"pts/"), Pts::Dir);
    assert_eq!(devpts::parse(b"pts/."), Pts::Dir);
    assert_eq!(devpts::parse(b"pts/0"), Pts::Node(0));
    assert_eq!(devpts::parse(b"pts/17"), Pts::Node(17));
    assert_eq!(devpts::parse(b"pts//./17"), Pts::Node(17));
    assert_eq!(devpts::parse(b"pts/17/"), Pts::NotDir);
    assert_eq!(devpts::parse(b"pts/17/x"), Pts::NotDir);
    assert_eq!(devpts::parse(b"pts/017"), Pts::Missing);
    assert_eq!(devpts::parse(b"pts/ptmx"), Pts::Missing);
    assert_eq!(devpts::parse(b"pts/x/y"), Pts::Missing);
    assert_eq!(devpts::parse(b"pts/99999999"), Pts::Missing);
    assert_eq!(devpts::parse(b"pts/1048576"), Pts::Missing);
    assert_eq!(devpts::parse(b"pts/1048575"), Pts::Node(1_048_575));
    assert_eq!(devpts::parse(b"pts/../null"), Pts::Kernel);
    assert_eq!(devpts::parse(b"pts/0/.."), Pts::Kernel);
    assert_eq!(devpts::parse(b"tty"), Pts::Kernel);
    assert_eq!(devpts::parse(b""), Pts::Kernel);
}

#[test]
fn pts_permissions_and_numbers() {
    let groups = |g: u32| g == 5;
    // 0620 hydra:tty: the owner reads and writes, the tty group writes, others nothing
    assert!(devpts::may(0o620, 1000, 5, 1000, 6, &groups));
    assert!(devpts::may(0o620, 1000, 5, 1001, 2, &groups));
    assert!(!devpts::may(0o620, 1000, 5, 1001, 4, &groups));
    assert!(!devpts::may(0o620, 1000, 5, 1002, 2, &|_| false));
    assert!(devpts::may(0o620, 1000, 5, 0, 6, &|_| false));
    assert!(!devpts::may(0o620, 1000, 5, 0, 1, &|_| false));
    let b = devpts::stat_bytes(6, 0o020620, 1000, 5, (136 << 8) | 3, 1);
    assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), devpts::PTS_DEV);
    assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 6);
    assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 0o020620);
    assert_eq!(u32::from_le_bytes(b[28..32].try_into().unwrap()), 1000);
    assert_eq!(u64::from_le_bytes(b[40..48].try_into().unwrap()), (136 << 8) | 3);
    assert_eq!(u64::from_le_bytes(b[56..64].try_into().unwrap()), 1024);
    let x = devpts::statx_bytes(6, 0o020620, 1000, 5, (136 << 8) | 3, 1);
    assert_eq!(u32::from_le_bytes(x[0..4].try_into().unwrap()), 0x17FF);
    assert_eq!(u16::from_le_bytes(x[28..30].try_into().unwrap()), 0o020620);
    assert_eq!(u32::from_le_bytes(x[128..132].try_into().unwrap()), 136);
    assert_eq!(u32::from_le_bytes(x[132..136].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(x[144..152].try_into().unwrap()), 20 + devpts::PTS_DEV);
    let f = devpts::statfs_bytes();
    assert_eq!(u64::from_le_bytes(f[0..8].try_into().unwrap()), 0x1cd1);
    assert_eq!(u64::from_le_bytes(f[8..16].try_into().unwrap()), 1024);
}
