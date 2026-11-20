//! `src/admin/session.rs` (who is logged in, the login/su/sudo rules) and
//! `src/admin/proto.rs` (the record helpers of the wire format).

mod common;
use common::*;
use k::admin::proto::*;
use k::admin::session::{self, login, login_op};

// ------------------------------------------------------------------------------- proto

#[test]
fn name_fields_round_trip_and_truncate() {
    let f: [u8; 8] = name_field("alice");
    assert_eq!(&f, b"alice\0\0\0");
    assert_eq!(name_str(&f), "alice");
    // Truncated to keep one NUL
    let f: [u8; 4] = name_field("abcdef");
    assert_eq!(&f, b"abc\0");
    // No NUL at all: the whole field; invalid UTF-8: "?"
    assert_eq!(name_str(b"full"), "full");
    assert_eq!(name_str(&[0xff, 0xfe, 0]), "?");
    assert_eq!(name_str(&[]), "");
}

#[test]
fn records_are_read_back_from_their_bytes() {
    let r = TaskRecord { pid: 7, uid: 1000, mode: MODE_USER, state: STATE_SLEEPING, priority: 3, _pad: 0, ticks: 99, rsp: 0x7fff_0000, name: name_field("bash") };
    let mut buf = vec![0xAAu8; 3];
    buf.extend_from_slice(as_bytes(&r));
    assert_eq!(as_bytes(&r).len(), core::mem::size_of::<TaskRecord>());
    // At an unaligned offset
    let back: TaskRecord = read_record(&buf, 3).unwrap();
    assert_eq!((back.pid, back.uid, back.mode, back.state, back.ticks, back.rsp), (7, 1000, MODE_USER, STATE_SLEEPING, 99, 0x7fff_0000));
    assert_eq!(name_str(&back.name), "bash");
    // Too short, or an offset that overflows
    assert!(read_record::<TaskRecord>(&buf, 4).is_none());
    assert!(read_record::<u64>(&buf, usize::MAX).is_none());
}

#[test]
fn records_with_large_fields_default_to_zero() {
    let d = DirRecord::default();
    assert_eq!((d.obj, d.kind), (0, 0));
    assert!(d.name.iter().all(|&b| b == 0));
    let s = DatasetRecord::default();
    assert_eq!((s.txg, s.snapshot), (0, 0));
    assert!(s.name.iter().chain(s.mount.iter()).all(|&b| b == 0));
    let r = RunResult::default();
    assert_eq!((r.pid, r.size, r.uid, r.gid), (0, 0, 0, 0));
    assert!(r.path.iter().all(|&b| b == 0));
    // The layout the ring-3 shell relies on
    assert_eq!(core::mem::size_of::<AdminCall>(), 8 + 32 + 40);
    assert_eq!(core::mem::size_of::<DirRecord>(), 16 + DIR_NAME_LEN);
    assert_eq!(core::mem::offset_of!(AdminCall, err_len), 72);
    assert_eq!(PRIORITY_NAMES[2], "Normal");
}

// ------------------------------------------------------------------------------ session

#[test]
fn a_new_session_depends_on_the_installed_system() {
    let _g = setup();
    // Nothing to protect: the default user, logged in
    session::begin();
    assert!(session::logged_in());
    assert_eq!(session::user(), (1000, 1000, "hydra".to_string()));
    assert!(!session::protected());
    assert!(fake::logged("abac None"));
    // The live session: root at once
    fake::with(|s| s.live = true);
    session::begin();
    assert_eq!(session::user().0, 0);
    let info = session::info();
    assert_eq!((info.live, info.logged_in), (1, 1));
    assert_eq!(name_str(&info.name), "root");
    // An installed system with accounts: a login first
    fake::with(|s| s.live = false);
    accounts();
    session::begin();
    assert!(session::protected());
    assert!(!session::logged_in());
    assert_eq!(session::user(), (1000, 1000, "hydra".to_string()));
    let info = session::info();
    assert_eq!((info.logged_in, info.protected, info.sudo_fresh), (0, 1, 0));
}

#[test]
fn passwords_need_the_helper_and_the_accounts() {
    let _g = setup();
    fake::file("/ubuntu/usr/sbin/unix_chkpwd", b"x");
    assert!(!session::protected(), "no passwd file");
    fake::file("/ubuntu/etc/passwd", b"\xff\xfe");
    assert!(!session::protected(), "passwd not text");
    fake::file("/ubuntu/etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
    assert!(session::protected());
    fake::with(|s| s.files.remove("/ubuntu/usr/sbin/unix_chkpwd"));
    assert!(!session::protected(), "no helper");
}

#[test]
fn accounts_and_their_admin_rights() {
    let _g = setup();
    accounts();
    let a = session::account("alice").unwrap();
    assert_eq!((a.name.as_str(), a.uid, a.gid, a.admin), ("alice", 1000, 1000, true));
    let b = session::account("bob").unwrap();
    assert_eq!((b.uid, b.admin), (1001, false));
    // Admin by its primary group (sudo's gid 27)
    assert!(session::account("carol").unwrap().admin);
    assert!(session::account("root").unwrap().admin);
    assert!(session::account("nobody").is_none());
    // A line with a bad uid
    assert!(session::account("broken").is_none());
    // Without a group file only root administers
    fake::with(|s| s.files.remove("/ubuntu/etc/group"));
    assert!(!session::account("alice").unwrap().admin);
    assert!(session::account("root").unwrap().admin);
    // A bad gid
    fake::file("/ubuntu/etc/passwd", b"dave:x:5:zz\n");
    assert!(session::account("dave").is_none());
}

#[test]
fn the_password_goes_to_the_helper_on_its_standard_input() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "wonder")]);
    assert!(session::verify_password("alice", "wonder"));
    let line = fake::take_log().into_iter().find(|l| l.starts_with("spawn_chroot")).unwrap();
    assert_eq!(line, "spawn_chroot /ubuntu /usr/sbin/unix_chkpwd [\"/usr/sbin/unix_chkpwd\", \"alice\", \"nonull\"] 0 0");
    // Its stdin: the password and a NUL, writer closed
    let tid = fake::with(|s| s.next_tid - 1);
    k::task::with_task(tid, |t| match t.fds.lock().fds.get(&0) {
        Some(k::fs::FileDescriptor::PipeRead(p)) => {
            let p = p.lock();
            assert_eq!(p.data, b"wonder\0");
            assert!(p.writer_closed);
        }
        _ => panic!("stdin is not the pipe"),
    });
    assert!(!session::verify_password("alice", "wrong"));
    // No name: nothing is run
    assert!(!session::verify_password("", "x"));
    assert!(fake::take_log().iter().filter(|l| l.starts_with("spawn_chroot")).count() == 1);
    // The helper cannot start
    fake::with(|s| s.spawn_fail = Some("no such file"));
    assert!(!session::verify_password("alice", "wonder"));
    assert!(fake::take_klog().contains("login: cannot check passwords: no such file"));
}

#[test]
fn login_rules() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "a1"), ("bob", "b1"), ("ghost", "g1")]);
    let console = authorize();
    session::begin();
    fake::file("/ubuntu/etc/hydra/access/subjects/alice", b"role=admin\n");
    assert_eq!(login("alice", "nope"), LOGIN_INCORRECT);
    assert!(!session::logged_in());
    assert_eq!(login("bob", "b1"), LOGIN_NOT_ADMIN);
    // A password the helper accepts for a name without an account
    assert_eq!(login("ghost", "g1"), LOGIN_INCORRECT);
    assert_eq!(login("alice", "a1"), LOGIN_OK);
    assert_eq!(session::user(), (1000, 1000, "alice".to_string()));
    // Her access-control attributes go with the programs the console starts
    assert!(fake::logged("abac Some(\"role=admin\\n\")"));
    // The console task's credentials follow the user
    assert_eq!(k::task::with_task(console.0, |t| [t.uid, t.gid, t.euid, t.egid, t.suid, t.sgid]), [1000; 6]);
}

#[test]
fn login_without_protection_is_the_default_user() {
    let _g = setup();
    let r = login_op(LOGIN_LOGIN, "anyone", "x");
    assert_eq!(r.status, LOGIN_UNPROTECTED);
    assert_eq!((r.uid, name_str(&r.name)), (1000, "hydra"));
}

#[test]
fn su_switches_accounts() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "a1"), ("bob", "b1")]);
    session::begin();
    // Not logged in: nothing but the login
    assert_eq!(login_op(LOGIN_SU, "bob", "b1").status, LOGIN_INCORRECT);
    assert_eq!(login_op(LOGIN_LOGIN, "alice", "a1").status, LOGIN_OK);
    assert_eq!(login_op(LOGIN_SU, "nobody", "").status, LOGIN_NO_USER);
    assert_eq!(login_op(LOGIN_SU, "bob", "wrong").status, LOGIN_INCORRECT);
    let r = login_op(LOGIN_SU, "bob", "b1");
    assert_eq!((r.status, r.uid, name_str(&r.name)), (LOGIN_OK, 1001, "bob"));
    // root switches without a password
    fake::with(|s| s.live = true);
    session::begin();
    let before = fake::take_log().iter().filter(|l| l.contains("unix_chkpwd")).count();
    assert_eq!(login_op(LOGIN_SU, "alice", "").status, LOGIN_OK);
    assert_eq!(fake::take_log().iter().filter(|l| l.contains("unix_chkpwd")).count(), 0, "{}", before);
    assert_eq!(session::user().2, "alice");
}

#[test]
fn sudo_asks_for_the_users_own_password_every_five_minutes() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "a1"), ("bob", "b1")]);
    session::begin();
    assert_eq!(login_op(LOGIN_LOGIN, "alice", "a1").status, LOGIN_OK);
    // An empty password only asks whether one is needed
    assert_eq!(login_op(LOGIN_SUDO, "", "").status, LOGIN_NEED_PASSWORD);
    assert_eq!(login_op(LOGIN_SUDO, "", "bad").status, LOGIN_INCORRECT);
    assert_eq!(session::user().0, 1000);
    let r = login_op(LOGIN_SUDO, "", "a1");
    assert_eq!((r.status, r.uid), (LOGIN_OK, 0));
    assert_eq!(session::info().sudo_fresh, 1);
    // Already root: nothing to do
    assert_eq!(login_op(LOGIN_SUDO, "", "").status, LOGIN_OK);
    // Back to alice; within 5 minutes no password is needed
    assert_eq!(login_op(LOGIN_RESTORE, "alice", "").status, LOGIN_OK);
    assert_eq!(session::user().0, 1000);
    fake::advance(4 * 60 * 1_000_000_000);
    assert_eq!(login_op(LOGIN_SUDO, "", "").status, LOGIN_OK);
    assert_eq!(login_op(LOGIN_RESTORE, "alice", "").status, LOGIN_OK);
    // After 5 minutes it is asked again
    fake::advance(2 * 60 * 1_000_000_000);
    assert_eq!(session::info().sudo_fresh, 0);
    assert_eq!(login_op(LOGIN_SUDO, "", "").status, LOGIN_NEED_PASSWORD);
    // Not an administrator
    assert_eq!(login_op(LOGIN_SU, "bob", "b1").status, LOGIN_OK);
    assert_eq!(login_op(LOGIN_SUDO, "", "b1").status, LOGIN_NOT_ADMIN);
}

#[test]
fn sudo_without_accounts_becomes_root() {
    let _g = setup();
    session::begin();
    let r = login_op(LOGIN_SUDO, "", "");
    assert_eq!((r.status, r.uid, name_str(&r.name)), (LOGIN_OK, 0, "root"));
    // Back to the default user (no account of that name)
    let r = login_op(LOGIN_RESTORE, "hydra", "");
    assert_eq!((r.status, r.uid), (LOGIN_OK, 1000));
    // Restore only while root
    assert_eq!(login_op(LOGIN_RESTORE, "hydra", "").status, LOGIN_INCORRECT);
    login_op(LOGIN_SUDO, "", "");
    assert_eq!(login_op(LOGIN_RESTORE, "nobody", "").status, LOGIN_NO_USER);
    // Unknown modes
    assert_eq!(login_op(99, "", "").status, LOGIN_INCORRECT);
}

#[test]
fn logout_starts_a_new_session() {
    let _g = setup();
    accounts();
    passwords(&[("alice", "a1")]);
    session::begin();
    assert_eq!(login_op(LOGIN_LOGIN, "alice", "a1").status, LOGIN_OK);
    let r = login_op(LOGIN_LOGOUT, "", "");
    assert_eq!((r.status, r.uid), (LOGIN_OK, 1000));
    assert!(!session::logged_in());
}
