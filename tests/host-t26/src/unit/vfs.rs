//! vfs.rs: the `pub(crate)` helpers other modules call.
use crate::testkit::*;

#[test]
fn utimens_special_values() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    let before = memfs::attr(f);
    let t = buf(32);
    // atime UTIME_NOW, mtime UTIME_OMIT
    write(t, &[0u64.to_le_bytes(), ((1u64 << 30) - 1).to_le_bytes(), 0u64.to_le_bytes(), ((1u64 << 30) - 2).to_le_bytes()].concat());
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/f"), t, 0]), 0);
    let a = memfs::attr(f);
    assert_eq!(a.atime, (1_767_225_600, 0));
    assert_eq!(a.mtime, before.mtime);
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/f"), 16, 0]), EFAULT);
    // An empty path with a descriptor (futimens)
    let fd = open("/f", O_RDONLY);
    assert_eq!(sys(280, &[fd as u64, 0, 0, 0]), 0);
    assert_eq!(sys(280, &[1000, 0, 0, 0]), EBADF);
    // set_times (utime/utimes)
    assert_eq!(vfs::set_times(AT_FDCWD as i64, cstr("/f"), Some([(1, 2), (3, 4)])), 0);
    assert_eq!(memfs::attr(f).mtime, (3, 4));
    assert_eq!(vfs::set_times(AT_FDCWD as i64, cstr("/f"), None), 0);
    assert_eq!(vfs::set_times(AT_FDCWD as i64, cstr("/none"), None), ENOENT);
    // Pseudo files take any times; pty paths go to the pty layer
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/dev/null"), 0, 0]), 0);
    lx::pty::SLAVES.with_borrow_mut(|s| s.push(1));
    assert_eq!(sys(90, &[cstr("/dev/pts/1"), 0o600]), 0);
    assert_eq!(lx::pty::SETATTRS.with_borrow(|s| s.len()), 1);
    become_user(5);
    assert_eq!(sys(90, &[cstr("/dev/pts/1"), 0o600]), EPERM);
}

#[test]
fn socket_nodes() {
    let _e = setup();
    memfs::mkdir_p("/run/user");
    let ino = vfs::make_socket_node(b"/run/user/bus").unwrap();
    assert_eq!(memfs::attr(ino).mode, 0o140755);
    assert_eq!(vfs::socket_node_for_connect(b"/run/user/bus").unwrap(), ino);
    assert_eq!(vfs::socket_key(b"/run/user/bus").unwrap(), format!("ino:{}", ino).into_bytes());
    assert_eq!(vfs::socket_key(b"/run/user/none").unwrap(), b"0:/run/user/none".to_vec());
    assert_eq!(vfs::socket_ino_key(5), b"ino:5".to_vec());
    assert!(vfs::path_exists(b"/run/user/bus"));
    assert!(!vfs::path_exists(b"/run/user/none"));
    // connect to something that is not a socket, or missing
    memfs::mkfile("/run/user/file", b"");
    assert_eq!(vfs::socket_node_for_connect(b"/run/user/file").unwrap_err(), -111);
    assert_eq!(vfs::socket_node_for_connect(b"/run/user/none").unwrap_err(), ENOENT);
    vfs::unlink_socket_node(b"/run/user/bus");
    assert!(memfs::lookup("/run/user/bus").is_none());
    vfs::unlink_socket_node(b"/none/x");
    // Without write permission
    let ino = vfs::make_socket_node(b"/run/user/s2").unwrap();
    memfs::chmod(ino, 0o755);
    let ro = memfs::lookup("/run").unwrap();
    memfs::chmod(ro, 0o755);
    become_user(1000);
    assert_eq!(vfs::socket_node_for_connect(b"/run/user/s2").unwrap_err(), EACCES);
    assert_eq!(vfs::make_socket_node(b"/run/s3").unwrap_err(), EACCES);
}

#[test]
fn lookup_path_helper() {
    let _e = setup();
    let d = memfs::mkdir_p("/d");
    let f = memfs::mkfile("/d/f", b"");
    memfs::mklink("/d/l", "f");
    assert_eq!(vfs::lookup_path(cstr("/d"), true).unwrap(), (d, true));
    assert_eq!(vfs::lookup_path(cstr("/d/l"), true).unwrap(), (f, false));
    assert_ne!(vfs::lookup_path(cstr("/d/l"), false).unwrap().0, f);
    assert_eq!(vfs::lookup_path(cstr("/zz"), true).unwrap_err(), ENOENT);
}

#[test]
fn file_capabilities() {
    let _e = setup();
    let f = memfs::mkfile("/bin/ping", b"");
    assert_eq!(vfs::file_caps(f), None);
    let mut v2 = 0x0200_0001u32.to_le_bytes().to_vec();
    v2.extend_from_slice(&(1u32 << 13).to_le_bytes()); // permitted low
    v2.extend_from_slice(&0u32.to_le_bytes());
    v2.extend_from_slice(&1u32.to_le_bytes()); // permitted high
    v2.extend_from_slice(&0u32.to_le_bytes());
    memfs::set_xattr(f, b"security.capability", &v2);
    assert_eq!(vfs::file_caps(f), Some(((1 << 13) | (1 << 32), true)));
    // Revision 3 with a root ID other than 0 is ignored
    let mut v3 = 0x0300_0000u32.to_le_bytes().to_vec();
    v3.extend_from_slice(&[0u8; 16]);
    v3.extend_from_slice(&5u32.to_le_bytes());
    memfs::set_xattr(f, b"security.capability", &v3);
    assert_eq!(vfs::file_caps(f), None);
    v3.truncate(20);
    v3.extend_from_slice(&0u32.to_le_bytes());
    memfs::set_xattr(f, b"security.capability", &v3);
    assert_eq!(vfs::file_caps(f), Some((0, false)));
    memfs::set_xattr(f, b"security.capability", b"bad");
    assert_eq!(vfs::file_caps(f), None);
}
