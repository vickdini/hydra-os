//! Landlock (`src/compat/linux/landlock.rs`) on the fake pool: the ruleset descriptor,
//! rules on by-name files (nearest pool directory), objects outside the pool, symbolic
//! links chased to the real place, moves between directories (REFER), ports of other
//! threads, the layer limit, mount refusal.

use std::sync::{Arc, Mutex};

use hydra_hosttests_t33::compat::linux::landlock::{self, *};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs};
use hydra_hosttests_t33::fs::fd::{OpenFile, O_RDONLY};
use hydra_hosttests_t33::fs::FileDescriptor;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    fakefs::pool();
    g
}

fn ruleset(fs: u64, net: u64) -> i64 {
    let mut a = [0u8; 16];
    a[0..8].copy_from_slice(&fs.to_le_bytes());
    a[8..16].copy_from_slice(&net.to_le_bytes());
    landlock::dispatch(444, [a.as_ptr() as u64, 16, 0, 0, 0, 0])
}

fn path_rule(rs: i64, allowed: u64, fd: i32) -> i64 {
    let mut a = [0u8; 12];
    a[0..8].copy_from_slice(&allowed.to_le_bytes());
    a[8..12].copy_from_slice(&fd.to_le_bytes());
    landlock::dispatch(445, [rs as u64, 1, a.as_ptr() as u64, 0, 0, 0])
}

fn port_rule(rs: i64, allowed: u64, port: u64) -> i64 {
    let mut a = [0u8; 16];
    a[0..8].copy_from_slice(&allowed.to_le_bytes());
    a[8..16].copy_from_slice(&port.to_le_bytes());
    landlock::dispatch(445, [rs as u64, 2, a.as_ptr() as u64, 0, 0, 0])
}

fn restrict(rs: i64) -> i64 {
    landlock::dispatch(446, [rs as u64, 0, 0, 0, 0, 0])
}

fn open_dir(ino: u64, path: &str) -> i32 {
    let f = OpenFile::new(ino, O_RDONLY, path.into());
    fake::fds_mut(|t| t.alloc_fd(FileDescriptor::Vnode(f)).unwrap()) as i32
}

fn by_name(path: &str) -> i32 {
    fake::fds_mut(|t| t.alloc_fd(FileDescriptor::File { path: path.into(), cursor: 0, readable: true, writable: false, append: false, shown: None }).unwrap()) as i32
}

fn landlocked() {
    let mut s = fake::SECCOMP.take();
    s.no_new_privs = true;
    fake::SECCOMP.set(s);
}

#[test]
fn the_ruleset_descriptor() {
    let _g = serial();
    let rs = ruleset(READ_FILE, 0);
    let d = match fake::fds(|t| t.get(rs as usize).cloned()) {
        Some(FileDescriptor::Device(d)) => d,
        _ => unreachable!(),
    };
    assert_eq!(d.read(&mut [0u8; 4]), -22);
    assert_eq!((d.poll_events(), d.rdev(), d.nonblock()), (0, 0, false));
    assert_eq!(d.path(), "anon_inode:[landlock-ruleset]");
    d.set_nonblock(true);
    let mut w = hydra_hosttests_t33::task::wait::WaitSet::new();
    d.add_wait_queues(&mut w);
    assert!(fake::fds(|t| t.cloexec(rs as usize)));
    // Version query; bad flags and sizes
    assert_eq!(landlock::dispatch(444, [0, 0, 1, 0, 0, 0]), ABI);
    assert_eq!(landlock::dispatch(444, [8, 0, 1, 0, 0, 0]), -22);
    assert_eq!(landlock::dispatch(444, [0, 0, 2, 0, 0, 0]), -22);
    let a = [0u8; 8];
    assert_eq!(landlock::dispatch(444, [a.as_ptr() as u64, 4, 0, 0, 0, 0]), -22);
    assert_eq!(landlock::dispatch(444, [a.as_ptr() as u64, 8192, 0, 0, 0, 0]), -7);
    // A rule on something that is not a ruleset, or with flags
    assert_eq!(path_rule(1, READ_FILE, 1), -77);
    assert_eq!(path_rule(400, READ_FILE, 1), -9);
    assert_eq!(landlock::dispatch(445, [rs as u64, 1, 0, 1, 0, 0]), -22);
    assert_eq!(landlock::dispatch(445, [rs as u64, 3, a.as_ptr() as u64, 0, 0, 0]), -22);
    assert_eq!(restrict(1), -1, "neither no_new_privs nor CAP_SYS_ADMIN");
    landlocked();
    assert_eq!(restrict(1), -77);
    assert_eq!(landlock::dispatch(446, [rs as u64, 1, 0, 0, 0, 0]), -22);
}

#[test]
fn rules_on_by_name_files_use_the_nearest_directory() {
    let _g = serial();
    let d = fakefs::test_dir("ll-names");
    let dev = with_fs(|fs| fs.mkdir_p(d, "dev"));
    let other = with_fs(|fs| fs.put(d, "other", b""));
    let rs = ruleset(READ_FILE | WRITE_FILE, 0);
    // /ll-names/dev/fake-node is not in the pool: the rule sits on /ll-names/dev
    assert_eq!(path_rule(rs, READ_FILE, by_name("/ll-names/dev/fake-node")), 0);
    // A file descriptor: only file rights
    let fd = open_dir(other, "/ll-names/other");
    assert_eq!(path_rule(rs, READ_FILE, fd), 0);
    assert_eq!(path_rule(rs, READ_FILE, -1), -9);
    assert_eq!(path_rule(rs, READ_FILE, 1), -77, "a console descriptor");
    landlocked();
    assert_eq!(restrict(rs), 0);
    assert!(landlock::active());
    // Outside the pool (ino 0): the nearest directory decides
    assert_eq!(landlock::refused_at("/ll-names/dev/null", 0, false, true, READ_FILE), 0);
    assert_eq!(landlock::refused_at("/ll-names/dev/null", 0, false, true, WRITE_FILE), WRITE_FILE);
    assert_eq!(landlock::refused_at("/proc/self/status", 0, false, true, READ_FILE), READ_FILE);
    assert_eq!(landlock::check_at("/ll-names/other", other, false, true, READ_FILE), Ok(()));
    assert_eq!(landlock::check_at("/ll-names/other", other, false, true, WRITE_FILE), Err(-13));
    assert_eq!(landlock::check_dir(dev, MAKE_REG), Ok(()), "not handled by this ruleset");
    assert_eq!(landlock::check_mount(), Err(-1));
    // A by-name file with nothing of the pool above it but the root
    let rs2 = ruleset(READ_FILE, 0);
    assert_eq!(path_rule(rs2, READ_FILE, by_name("/no/such/place")), 0);
}

#[test]
fn links_are_followed_to_the_real_file() {
    let _g = serial();
    let d = fakefs::test_dir("ll-links");
    let (secret, linkdir) = with_fs(|fs| {
        let s = fs.put(d, "private/secret", b"s");
        let l = fs.mkdir_p(d, "public");
        fs.link_to(l, "ln", "../private/secret");
        fs.link_to(l, "loop", "loop");
        (s, l)
    });
    let rs = ruleset(READ_FILE, 0);
    assert_eq!(path_rule(rs, READ_FILE, open_dir(linkdir, "/ll-links/public")), 0);
    landlocked();
    assert_eq!(restrict(rs), 0);
    // Reached through the link in an allowed folder: the file's own place decides
    assert_eq!(landlock::refused_at("/ll-links/public/ln", secret, false, true, READ_FILE), READ_FILE);
    // Not following: the link's folder
    assert_eq!(landlock::refused_at("/ll-links/public/ln", secret, false, false, READ_FILE), 0);
    // A missing folder: only the file's own rules, then the nearest directory
    assert_eq!(landlock::refused_at("/ll-links/missing/x", secret, false, true, READ_FILE), READ_FILE);
    // A directory: its own chain
    assert_eq!(landlock::refused_at("/ll-links/public", linkdir, true, true, READ_FILE), 0);
}

#[test]
fn moves_need_refer_and_no_new_rights() {
    let _g = serial();
    let d = fakefs::test_dir("ll-move");
    let (a, b, c) = with_fs(|fs| (fs.mkdir_p(d, "a"), fs.mkdir_p(d, "b"), fs.mkdir_p(d, "c")));
    let all = REMOVE_FILE | MAKE_REG | REFER | READ_FILE;
    let rs = ruleset(all, 0);
    assert_eq!(path_rule(rs, all, open_dir(a, "/ll-move/a")), 0);
    assert_eq!(path_rule(rs, REMOVE_FILE | MAKE_REG | REFER, open_dir(b, "/ll-move/b")), 0);
    assert_eq!(path_rule(rs, MAKE_REG, open_dir(c, "/ll-move/c")), 0);
    landlocked();
    assert_eq!(restrict(rs), 0);
    assert_eq!(landlock::check_move(a, a, 0o100000, true, 0), Ok(()), "same folder");
    assert_eq!(landlock::check_move(b, a, 0o100000, true, 0), Err(-18), "a grants READ_FILE that b does not: new rights");
    assert_eq!(landlock::check_move(a, b, 0o100000, true, 0), Ok(()));
    assert_eq!(landlock::check_move(a, c, 0o100000, true, 0), Err(-18), "no REFER in c");
    assert_eq!(landlock::check_move(c, a, 0o100000, true, 0), Err(-13), "no REMOVE_FILE in c");
    assert_eq!(landlock::check_move(a, c, 0o040000, false, 0), Err(-18), "MAKE_DIR is not handled (allowed), but c has no REFER");
    assert_eq!(landlock::check_move(b, b, 0o100000, false, READ_FILE), Err(-13), "replacing needs a right b lacks");
    assert_eq!(landlock::check_move(a, c, 0o100000, false, REMOVE_FILE), Err(-13), "replacing a file in c needs REMOVE_FILE there");
    assert_eq!(landlock::remove_right(0o040000), REMOVE_DIR);
    assert_eq!(landlock::make_right(0o140000), MAKE_SOCK);
    assert_eq!(landlock::make_right(0o060000), MAKE_BLOCK);
    assert_eq!(landlock::make_right(0o020000), MAKE_CHAR);
    assert_eq!(landlock::make_right(0o010000), MAKE_FIFO);
    assert_eq!(landlock::make_right(0o120000), MAKE_SYM);
    // A layer that handles nothing of the file system is skipped
    let net_only = ruleset(0, BIND_TCP);
    assert_eq!(restrict(net_only), 0);
    assert_eq!(landlock::check_move(a, b, 0o100000, true, 0), Ok(()));
}

#[test]
fn ports_of_this_and_other_threads_and_the_layer_limit() {
    let _g = serial();
    let rs = ruleset(0, BIND_TCP | CONNECT_TCP);
    assert_eq!(port_rule(rs, 0, 80), -42);
    assert_eq!(port_rule(rs, BIND_TCP, 70000), -22);
    assert_eq!(port_rule(rs, 4, 80), -22);
    assert_eq!(port_rule(rs, CONNECT_TCP, 443), 0);
    assert_eq!(path_rule(rs, 0, 1), -42, "no rights");
    assert_eq!(path_rule(rs, READ_FILE, 1), -22, "not handled by the ruleset");
    // Another thread, landlocked: its own rules decide
    let mut sib = fake::Task::sibling(9001);
    landlocked();
    assert_eq!(restrict(rs), 0);
    sib.seccomp.landlock = fake::SECCOMP.with_borrow(|s| s.landlock.clone());
    fake::SIBLINGS.with_borrow_mut(|v| v.push(sib));
    assert_eq!(landlock::check_port_of(9001, 443, CONNECT_TCP), Ok(()));
    assert_eq!(landlock::check_port_of(9001, 80, CONNECT_TCP), Err(-13));
    assert_eq!(landlock::check_port_of(9002, 80, CONNECT_TCP), Ok(()), "no such thread");
    assert_eq!(landlock::check_port(80, BIND_TCP), Err(-13));
    // Up to 16 layers
    for _ in 1..16 {
        assert_eq!(restrict(rs), 0);
    }
    assert_eq!(restrict(rs), -7);
    let _ = Arc::new(0);
}
