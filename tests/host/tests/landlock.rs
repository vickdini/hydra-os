//! Tests for Landlock (`src/compat/linux/landlock.rs`): the three syscalls
//! (create_ruleset, add_rule, restrict_self), stacked layers, and the access
//! checks the VFS and execve call (`check_at`, `check_dir`, `check_move`,
//! `check_port`, `check_mount`). Flatpak, systemd and browsers' utility
//! processes use Landlock to confine file system and network access.
//!
//! Paths resolve in a fake directory tree (`fake::mkdir_p`, `mkfile`,
//! `mklink`) that follows symlinks like the kernel's walker (up to 40).

use std::sync::Arc;

use hydra_hosttests::compat::linux::landlock::*;
use hydra_hosttests::compat::linux::seccomp::prctl;
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const CREATE: u64 = 444;
const ADD_RULE: u64 = 445;
const RESTRICT: u64 = 446;

const EPERM: i64 = -1;
const E2BIG: i64 = -7;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EXDEV: i64 = -18;
const EINVAL: i64 = -22;
const ENOMSG: i64 = -42;
const EBADFD: i64 = -77;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const CAP_SYS_ADMIN: u64 = 1 << 21;

// --------------------------------------------------------------- helpers

fn create(fs: u64, net: u64) -> i64 {
    let attr = [fs, net];
    dispatch(CREATE, [attr.as_ptr() as u64, 16, 0, 0, 0, 0])
}

/// LANDLOCK_RULE_PATH_BENEATH { u64 allowed_access; s32 parent_fd } (packed, 12 bytes).
fn allow_path(ruleset: i64, parent_fd: i32, rights: u64) -> i64 {
    let mut attr = [0u8; 12];
    attr[..8].copy_from_slice(&rights.to_le_bytes());
    attr[8..].copy_from_slice(&parent_fd.to_le_bytes());
    dispatch(ADD_RULE, [ruleset as u64, 1, attr.as_ptr() as u64, 0, 0, 0])
}

/// LANDLOCK_RULE_NET_PORT { u64 allowed_access; u64 port }.
fn allow_port(ruleset: i64, port: u64, rights: u64) -> i64 {
    let attr = [rights, port];
    dispatch(ADD_RULE, [ruleset as u64, 2, attr.as_ptr() as u64, 0, 0, 0])
}

fn restrict(ruleset: i64) -> i64 {
    dispatch(RESTRICT, [ruleset as u64, 0, 0, 0, 0, 0])
}

/// Open `path` (an O_PATH-style vnode descriptor) at fd `fd`.
fn open_at(fd: usize, path: &str) -> i32 {
    let ino = fake::ZfsClient::resolve(0, path.as_bytes(), true).expect("path exists");
    let v = fake::Vnode { ino, path: path.into(), readable: true };
    fake::FDS.with_borrow_mut(|f| f.install(fd, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(v)))));
    fd as i32
}

fn ino(path: &str) -> u64 {
    fake::ZfsClient::resolve(0, path.as_bytes(), true).expect("path exists")
}

/// Fresh task with no_new_privs and this tree:
/// /A/file, /A/sub/deep/file, /B/secret, /C (empty).
fn setup() {
    fake::reset();
    prctl(38, 1, 0);
    fake::mkfile("/A/file");
    fake::mkfile("/A/sub/deep/file");
    fake::mkfile("/B/secret");
    fake::mkdir_p("/C");
}

/// Enforce: handled = READ_FILE | WRITE_FILE | READ_DIR, with READ_FILE |
/// READ_DIR granted beneath /A only.
fn sandbox_read_a() {
    let rs = create(READ_FILE | WRITE_FILE | READ_DIR, 0);
    assert!(rs >= 0);
    assert_eq!(allow_path(rs, open_at(50, "/A"), READ_FILE | READ_DIR), 0);
    assert_eq!(restrict(rs), 0);
}

fn read_file(path: &str) -> Result<(), i64> {
    check_at(path, ino(path), false, true, READ_FILE)
}

// --------------------------------------------------------- create_ruleset

#[test]
fn abi_version_query() {
    fake::reset();
    assert_eq!(dispatch(CREATE, [0, 0, 1, 0, 0, 0]), ABI);
    assert_eq!(ABI, 4);
    let attr = [READ_FILE, 0];
    assert_eq!(dispatch(CREATE, [attr.as_ptr() as u64, 16, 1, 0, 0, 0]), EINVAL, "version query takes no attr");
}

#[test]
fn create_ruleset_validation() {
    fake::reset();
    let attr = [READ_FILE, 0u64, 0, 0];
    let a = attr.as_ptr() as u64;
    assert_eq!(dispatch(CREATE, [a, 16, 2, 0, 0, 0]), EINVAL, "unknown flag");
    assert_eq!(dispatch(CREATE, [a, 7, 0, 0, 0, 0]), EINVAL, "smaller than handled_access_fs");
    assert_eq!(dispatch(CREATE, [a, 4097, 0, 0, 0, 0]), E2BIG);
    assert!(dispatch(CREATE, [a, 8, 0, 0, 0, 0]) >= 0, "ABI 1 size (fs only)");
    assert!(dispatch(CREATE, [a, 32, 0, 0, 0, 0]) >= 0, "larger struct with zero tail");
    let scoped = [READ_FILE, 0u64, 1, 0];
    assert_eq!(dispatch(CREATE, [scoped.as_ptr() as u64, 24, 0, 0, 0, 0]), E2BIG, "ABI 6 `scoped` not supported");
    assert_eq!(create(1 << 15, 0), EINVAL, "unknown fs right");
    assert_eq!(create(0, 4), EINVAL, "unknown net right");
    assert_eq!(create(0, 0), ENOMSG, "handles nothing");
}

#[test]
fn ruleset_descriptor() {
    fake::reset();
    let fd = create(READ_FILE, BIND_TCP);
    assert!(fd >= 0);
    fake::FDS.with_borrow(|f| {
        assert!(f.open[&(fd as usize)].1, "always O_CLOEXEC");
        let FileDescriptor::Device(d) = &f.open[&(fd as usize)].0 else { panic!() };
        assert_eq!(d.path(), "anon_inode:[landlock-ruleset]");
    });
}

// ------------------------------------------------------------- add_rule

#[test]
fn add_rule_validation() {
    setup();
    let rs = create(READ_FILE | READ_DIR | EXECUTE, BIND_TCP);
    let a = open_at(50, "/A");
    let f = open_at(51, "/A/file");
    assert_eq!(dispatch(ADD_RULE, [rs as u64, 1, 0, 1, 0, 0]), EINVAL, "flags");
    assert_eq!(allow_path(99, a, READ_FILE), EBADF, "no such descriptor");
    let efd = hydra_hosttests::compat::linux::eventfd::EventFd::new(0, 0);
    fake::FDS.with_borrow_mut(|t| t.install(60, FileDescriptor::EventFd(efd)));
    assert_eq!(allow_path(60, a, READ_FILE), EBADFD, "not a ruleset");
    assert_eq!(dispatch(ADD_RULE, [rs as u64, 3, 0, 0, 0, 0]), EINVAL, "unknown rule type");
    assert_eq!(allow_path(rs, a, 0), ENOMSG, "no rights");
    assert_eq!(allow_path(rs, a, WRITE_FILE), EINVAL, "right not handled by the ruleset");
    assert_eq!(allow_path(rs, f, READ_DIR), EINVAL, "directory rights on a file");
    assert_eq!(allow_path(rs, f, READ_FILE | EXECUTE), 0, "file rights on a file");
    assert_eq!(allow_path(rs, 77, READ_FILE), EBADF, "bad parent_fd");
    assert_eq!(allow_port(rs, 65536, BIND_TCP), EINVAL);
    assert_eq!(allow_port(rs, 22, CONNECT_TCP), EINVAL, "net right not handled");
    assert_eq!(allow_port(rs, 22, 0), ENOMSG);
    assert_eq!(allow_port(rs, 22, BIND_TCP), 0);
}

// --------------------------------------------------------- restrict_self

#[test]
fn restrict_self_rules() {
    fake::reset();
    let rs = create(READ_FILE, 0);
    assert_eq!(dispatch(RESTRICT, [rs as u64, 1, 0, 0, 0, 0]), EINVAL, "flags");
    assert_eq!(restrict(rs), EPERM, "needs no_new_privs");
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(restrict(rs), 0, "or CAP_SYS_ADMIN");
    assert!(active());
    assert_eq!(restrict(99), EBADF);
}

#[test]
fn at_most_16_layers() {
    fake::reset();
    prctl(38, 1, 0);
    let rs = create(READ_FILE, 0);
    for i in 0..16 {
        assert_eq!(restrict(rs), 0, "layer {i}");
    }
    assert_eq!(restrict(rs), E2BIG);
}

#[test]
fn unrestricted_tasks_are_not_checked() {
    setup();
    assert!(!active());
    assert_eq!(read_file("/B/secret"), Ok(()));
    assert_eq!(check_mount(), Ok(()));
}

// ----------------------------------------------------------- path checks

#[test]
fn rights_apply_beneath_the_rule_directory() {
    setup();
    sandbox_read_a();
    assert_eq!(read_file("/A/file"), Ok(()));
    assert_eq!(read_file("/A/sub/deep/file"), Ok(()), "inherited by every descendant");
    assert_eq!(read_file("/B/secret"), Err(EACCES));
    assert_eq!(check_at("/A/file", ino("/A/file"), false, true, WRITE_FILE), Err(EACCES), "handled, not granted");
    assert_eq!(check_at("/B/secret", ino("/B/secret"), false, true, EXECUTE), Ok(()), "not handled: allowed");
    assert_eq!(check_dir(ino("/A/sub"), READ_DIR), Ok(()));
    assert_eq!(check_dir(ino("/C"), READ_DIR), Err(EACCES));
    assert_eq!(check_dir(ino("/"), READ_DIR), Err(EACCES), "the root is above the rule");
}

#[test]
fn rights_are_not_reachable_through_dot_dot_names() {
    setup();
    sandbox_read_a();
    assert_eq!(read_file("/A/../B/secret"), Err(EACCES), "checked against where the file is");
}

#[test]
fn every_layer_must_allow() {
    setup();
    sandbox_read_a();
    let rs = create(READ_FILE, 0);
    allow_path(rs, open_at(51, "/A/sub"), READ_FILE);
    assert_eq!(restrict(rs), 0);
    assert_eq!(read_file("/A/sub/deep/file"), Ok(()));
    assert_eq!(read_file("/A/file"), Err(EACCES), "the second layer only allows /A/sub");
}

#[test]
fn new_files_are_checked_against_the_nearest_existing_directory() {
    setup();
    let rs = create(MAKE_REG, 0);
    allow_path(rs, open_at(50, "/A"), MAKE_REG);
    restrict(rs);
    assert_eq!(check_at("/A/new", 0, false, true, MAKE_REG), Ok(()));
    assert_eq!(check_at("/A/missing/dir/new", 0, false, true, MAKE_REG), Ok(()), "nearest existing: /A");
    assert_eq!(check_at("/B/new", 0, false, true, MAKE_REG), Err(EACCES));
}

#[test]
fn symlinks_are_checked_at_their_target() {
    setup();
    fake::mklink("/A/link", "/B/secret");
    fake::mklink("/A/rel", "../B/secret");
    sandbox_read_a();
    let secret = ino("/B/secret");
    assert_eq!(check_at("/A/link", secret, false, true, READ_FILE), Err(EACCES), "absolute link out of /A");
    assert_eq!(check_at("/A/rel", secret, false, true, READ_FILE), Err(EACCES), "relative link out of /A");
}

#[test]
fn a_chain_of_eight_symlinks_is_followed_to_the_target() {
    setup();
    for i in 1..8 {
        fake::mklink(&format!("/A/l{i}"), &format!("l{}", i + 1));
    }
    fake::mklink("/A/l8", "/B/secret");
    sandbox_read_a();
    let secret = ino("/A/l1");
    assert_eq!(secret, ino("/B/secret"), "the kernel resolves the chain");
    assert_eq!(check_at("/A/l1", secret, false, true, READ_FILE), Err(EACCES));
}

#[test]
#[ignore = "BUG (security): Landlock's file_chain follows at most 8 symlinks, while the kernel's \
            path walker follows up to 40 (SYMLOOP_MAX). With 9+ links the check falls back to the \
            directory of the last link it reached instead of the target's, so a sandboxed process \
            can open files outside the directories it was granted \
            (src/compat/linux/landlock.rs, file_chain)"]
fn a_chain_of_nine_symlinks_cannot_escape_the_sandbox() {
    setup();
    for i in 1..9 {
        fake::mklink(&format!("/A/l{i}"), &format!("l{}", i + 1));
    }
    fake::mklink("/A/l9", "/B/secret");
    sandbox_read_a();
    let target = ino("/A/l1");
    assert_eq!(target, ino("/B/secret"), "the kernel opens /B/secret through the chain");
    assert_eq!(check_at("/A/l1", target, false, true, READ_FILE), Err(EACCES), "Landlock allowed /B/secret");
}

// ----------------------------------------------------- rename and link

#[test]
fn moves_within_a_directory() {
    setup();
    let rs = create(REMOVE_FILE | MAKE_REG | REMOVE_DIR | MAKE_DIR | REFER, 0);
    allow_path(rs, open_at(50, "/A"), REMOVE_FILE | MAKE_REG);
    restrict(rs);
    assert_eq!(check_move(ino("/A"), ino("/A"), S_IFREG, true, 0), Ok(()));
    assert_eq!(check_move(ino("/B"), ino("/B"), S_IFREG, true, 0), Err(EACCES));
    assert_eq!(check_move(ino("/A"), ino("/A"), S_IFDIR, true, 0), Err(EACCES), "directories need REMOVE_DIR/MAKE_DIR");
}

#[test]
fn moves_across_directories_need_refer_on_both_sides() {
    setup();
    let rs = create(REMOVE_FILE | MAKE_REG | REFER | READ_FILE, 0);
    allow_path(rs, open_at(50, "/A"), REMOVE_FILE | MAKE_REG | REFER | READ_FILE);
    allow_path(rs, open_at(51, "/C"), MAKE_REG | REFER);
    allow_path(rs, open_at(52, "/B"), MAKE_REG | REFER | READ_FILE);
    restrict(rs);
    assert_eq!(check_move(ino("/A"), ino("/C"), S_IFREG, true, 0), Ok(()), "C grants a subset of A");
    assert_eq!(check_move(ino("/C"), ino("/B"), S_IFREG, false, 0), Err(EXDEV), "B grants READ_FILE, C does not");
}

#[test]
fn abi_1_rulesets_forbid_cross_directory_moves() {
    setup();
    let rs = create(REMOVE_FILE | MAKE_REG, 0); // REFER not handled
    allow_path(rs, open_at(50, "/A"), REMOVE_FILE | MAKE_REG);
    allow_path(rs, open_at(51, "/C"), REMOVE_FILE | MAKE_REG);
    restrict(rs);
    assert_eq!(check_move(ino("/A"), ino("/C"), S_IFREG, true, 0), Err(EXDEV));
    assert_eq!(check_move(ino("/A"), ino("/A"), S_IFREG, true, 0), Ok(()));
}

#[test]
fn right_names() {
    assert_eq!(make_right(0o040000), MAKE_DIR);
    assert_eq!(make_right(0o120000), MAKE_SYM);
    assert_eq!(make_right(0o140000), MAKE_SOCK);
    assert_eq!(make_right(0o010000), MAKE_FIFO);
    assert_eq!(make_right(0o020000), MAKE_CHAR);
    assert_eq!(make_right(0o060000), MAKE_BLOCK);
    assert_eq!(make_right(0o100000), MAKE_REG);
    assert_eq!((remove_right(0o040000), remove_right(0o100000)), (REMOVE_DIR, REMOVE_FILE));
    assert_eq!((EXECUTE, WRITE_FILE, READ_FILE, READ_DIR, REFER, TRUNCATE), (1, 2, 4, 8, 1 << 13, 1 << 14), "Linux values");
}

// ---------------------------------------------------------------- network

#[test]
fn tcp_ports() {
    fake::reset();
    prctl(38, 1, 0);
    let rs = create(0, BIND_TCP | CONNECT_TCP);
    allow_port(rs, 443, CONNECT_TCP);
    allow_port(rs, 8080, BIND_TCP | CONNECT_TCP);
    restrict(rs);
    assert_eq!(check_port(443, CONNECT_TCP), Ok(()));
    assert_eq!(check_port(443, BIND_TCP), Err(EACCES));
    assert_eq!(check_port(80, CONNECT_TCP), Err(EACCES));
    assert_eq!(check_port(8080, BIND_TCP), Ok(()));
}

#[test]
fn file_system_only_rulesets_leave_the_network_alone() {
    setup();
    sandbox_read_a();
    assert_eq!(check_port(80, CONNECT_TCP), Ok(()));
    assert_eq!(check_port(80, BIND_TCP), Ok(()));
}

#[test]
fn sandboxed_tasks_cannot_mount() {
    setup();
    sandbox_read_a();
    assert_eq!(check_mount(), Err(EPERM));
}
